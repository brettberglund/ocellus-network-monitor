//! gRPC client tasks: bidirectional packet stream ([`run_packet_stream`]) and
//! periodic heartbeat loop ([`run_heartbeat_loop`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use prost_types::Timestamp;
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use crate::proto::{
    AgentHeartbeat, PacketBatch, PacketEvent, Protocol, RegisterAgentRequest,
    monitor_ingestion_client::MonitorIngestionClient,
};
use crate::raw_packet::RawPacket;

/// Real machine hostname reported at registration (display/tracking only).
pub fn hostname_or_default() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

/// One-shot RPC — self-enroll with the backend using a registration token
/// minted from the dashboard. Called once at startup, before the packet
/// stream / heartbeat loops begin. Never fatal: callers should log and
/// continue on error, since the agent can still stream telemetry without a
/// Postgres row.
pub async fn register_agent(
    client: &mut MonitorIngestionClient<Channel>,
    token: String,
    agent_id: String,
    agent_version: String,
) -> Result<(), tonic::Status> {
    let req = RegisterAgentRequest {
        token,
        agent_id,
        hostname: hostname_or_default(),
        os_info: std::env::consts::OS.to_string(),
        agent_version,
    };

    let resp = client.register_agent(req).await?.into_inner();
    if !resp.ok {
        return Err(tonic::Status::unknown(resp.message));
    }
    info!("agent registered successfully");
    Ok(())
}

/// Shared atomic counters reported in each [`AgentHeartbeat`].
#[derive(Debug, Default)]
pub struct AgentCounters {
    pub captured: AtomicU64,
    pub flagged: AtomicU64,
    pub dropped: AtomicU64,
}

fn parse_packet(raw: &RawPacket, agent_id: &str) -> Option<PacketEvent> {
    let tm = raw.transport.as_ref()?;

    let protocol = match tm.protocol {
        6 => Protocol::Tcp as i32,
        17 => Protocol::Udp as i32,
        1 | 58 => Protocol::Icmp as i32,
        _ => Protocol::Other as i32,
    };

    let tcp_flags_strs = if let Some(flags) = tm.tcp_flags {
        decode_tcp_flags(flags)
    } else {
        Vec::new()
    };

    let payload_hash = blake3::hash(&raw.data).as_bytes().to_vec();

    let captured_at = raw
        .timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    Some(PacketEvent {
        agent_id: agent_id.to_string(),
        captured_at: Some(Timestamp {
            seconds: captured_at.as_secs() as i64,
            nanos: captured_at.subsec_nanos() as i32,
        }),
        src_ip: tm.src_ip.to_string(),
        src_port: tm.src_port.unwrap_or(0) as u32,
        dst_ip: tm.dst_ip.to_string(),
        dest_port: tm.dst_port.unwrap_or(0) as u32,
        protocol,
        bytes: raw.orig_len as u64,
        ttl: tm.ttl as u32,
        tcp_flags: tcp_flags_strs,
        flag_reason: raw.ids_flag,
        anomaly_score: raw.ids_score,
        payload_hash,
        interface: raw.interface.clone(),
        direction: "unknown".to_string(),
    })
}

fn decode_tcp_flags(flags: u8) -> Vec<String> {
    let mut out = Vec::new();
    if flags & 0x01 != 0 {
        out.push("FIN".into());
    }
    if flags & 0x02 != 0 {
        out.push("SYN".into());
    }
    if flags & 0x04 != 0 {
        out.push("RST".into());
    }
    if flags & 0x08 != 0 {
        out.push("PSH".into());
    }
    if flags & 0x10 != 0 {
        out.push("ACK".into());
    }
    if flags & 0x20 != 0 {
        out.push("URG".into());
    }
    out
}

/// Configuration for the [`run_packet_stream`] task.
#[derive(Debug, Clone)]
pub struct PacketStreamConfig {
    pub agent_id: String,
    pub batch_size: usize,
    pub flush_interval: Duration,
}

// impl Default for PacketStreamConfig {
//     fn default() -> Self {
//         Self {
//             agent_id: "agent-001".to_string(),
//             batch_size: 50,
//             flush_interval: Duration::from_millis(200),
//         }
//     }
// }

/// Long-running task that batches [`RawPacket`]s from `capture_rx` and streams them to
/// the ingestion service via the `IngestPackets` bidirectional RPC.
///
/// Packets are flushed when `batch_size` is reached or `flush_interval` elapses, whichever
/// comes first. The task exits cleanly on cancellation or when the capture channel closes.
pub async fn run_packet_stream(
    mut client: MonitorIngestionClient<Channel>,
    mut capture_rx: mpsc::Receiver<RawPacket>,
    cfg: PacketStreamConfig,
    counters: Arc<AgentCounters>,
    cancel: CancellationToken,
) {
    let (batch_tx, batch_rx) = mpsc::channel::<PacketBatch>(64);
    let batch_stream = ReceiverStream::new(batch_rx);

    let response = match client.ingest_packets(batch_stream).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "failed to open IngestPackets stream — packet stream task exiting");
            return;
        }
    };

    let mut ack_stream = response.into_inner();
    let ack_cancel = cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = ack_cancel.cancelled() => {
                    info!("ack task: cancelled");
                    break;
                }
                maybe = ack_stream.next() => {
                    match maybe {
                        Some(Ok(ack)) => info!(
                            seq = ack.seq,
                            accepted = ack.accepted,
                            rejected = ack.rejected,
                            message = %ack.message,
                            "IngestAck"
                        ),
                        Some(Err(e)) => warn!(error = %e, "error on IngestAck stream"),
                        None => {
                            info!("IngestAck stream closed");
                            break;
                        }
                    }
                }
            }
        }
    });

    let mut seq: u64 = 0;
    let mut pending = Vec::<PacketEvent>::with_capacity(cfg.batch_size);
    let mut flush_interval = tokio::time::interval(cfg.flush_interval);
    flush_interval.tick().await;

    async fn flush(
        pending: &mut Vec<PacketEvent>,
        batch_tx: &mpsc::Sender<PacketBatch>,
        seq: &mut u64,
        agent_id: &str,
    ) {
        if pending.is_empty() {
            return;
        }
        let batch = PacketBatch {
            events: std::mem::take(pending),
            seq: *seq,
            agent_id: agent_id.to_string(),
        };
        debug!(
            seq = batch.seq,
            count = batch.events.len(),
            "sending PacketBatch"
        );
        if batch_tx.send(batch).await.is_err() {
            warn!("batch channel closed — IngestPackets stream has ended");
        }
        *seq += 1;
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("packet stream: shutdown requested, flushing final batch");
                flush(&mut pending, &batch_tx, & mut seq, &cfg.agent_id).await;
                break;
            }

            maybe_raw = capture_rx.recv() => {
                match maybe_raw {
                    None => {
                        info!("capture channel closed — flushing final batch");
                        flush(&mut pending, &batch_tx, &mut seq, &cfg.agent_id).await;
                        break;
                    }
                    Some(raw) => {
                        if let Some(event) = parse_packet(&raw, &cfg.agent_id) {
                            counters.captured.fetch_add(1, Ordering::Relaxed);
                            pending.push(event);
                            if pending.len() >= cfg.batch_size {
                                flush(&mut pending, &batch_tx, &mut seq, &cfg.agent_id).await;
                            }
                        }
                    }
                }
            }

            _ = flush_interval.tick() => {
                flush(&mut pending, &batch_tx, &mut seq, &cfg.agent_id).await;
            }
        }
    }

    info!("packet stream task exiting");
}

/// Configuration for the [`run_heartbeat_loop`] task.
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    pub agent_id: String,
    pub interval: Duration,
    pub agent_version: String,
    pub hostname: String,
    pub os_info: String,
}

// impl Default for HeartbeatConfig {
//     fn default() -> Self {
//         Self {
//             agent_id: "agent-001".to_string(),
//             interval: Duration::from_secs(10),
//             agent_version: env!("CARGO_PKG_VERSION").to_string(),
//             hostname: hostname_or_default(),
//             os_info: std::env::consts::OS.to_string(),
//         }
//     }
// }

// fn hostname_or_default() -> String {
//     std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
// }

/// Long-running task that sends an [`AgentHeartbeat`] to the ingestion service on each
/// tick of `cfg.interval`. Exits cleanly on cancellation.
pub async fn run_heartbeat_loop(
    mut client: MonitorIngestionClient<Channel>,
    cfg: HeartbeatConfig,
    counters: Arc<AgentCounters>,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(cfg.interval);
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("heartbeat loop: cancelled");
                break;
            }

            _ = interval.tick() => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();

                let mem_mb = read_mem_usage_mb();

                let hb = AgentHeartbeat {
                    agent_id: cfg.agent_id.clone(),
                    ts: Some(Timestamp {
                        seconds: now.as_secs() as i64,
                        nanos: now.subsec_nanos() as i32,
                    }),
                    packets_captured: counters.captured.load(Ordering::Relaxed),
                    packets_flagged: counters.flagged.load(Ordering::Relaxed),
                    packets_dropped: counters.dropped.load(Ordering::Relaxed),
                    cpu_usage_pct: 0.0,
                    mem_usage_mb: mem_mb,
                    agent_version: cfg.agent_version.clone(),
                    hostname: cfg.hostname.clone(),
                    os_info: cfg.os_info.clone(),
                };

                match client.send_heartbeat(hb).await {
                    Ok(resp) => {
                        let ack = resp.into_inner();
                        if ack.ok {
                            debug!("heartbeat ack");
                        } else {
                            warn!(message = %ack.message, "heartbeat ack not ok");
                        }
                    }
                    Err(e) => error!(error = %e, "heartbeat RPC failed"),
                }
            }
        }
    }
}

fn read_mem_usage_mb() -> f32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let kb: f32 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0.0);
                    return kb / 1024.0;
                }
            }
        }
    }
    0.0
}
