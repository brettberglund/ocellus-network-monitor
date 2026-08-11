//! Edge capture agent: pcap → IDS analysis → gRPC stream to the ingestion service.
//!
//! Run with `--list-devices` to enumerate interfaces, then pass `--interface <name>`.
//! Use `--test-send` to generate synthetic traffic without pcap (no privileges required).

mod agent_identity;
mod analyzer;
mod capture;
mod config;
mod error;
mod grpc_client;
mod ids;
mod proto;
mod raw_packet;
mod ring_buffer;
mod tests;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use config::Config;
use grpc_client::{
    AgentCounters, HeartbeatConfig, PacketStreamConfig, hostname_or_default, register_agent,
    run_heartbeat_loop, run_packet_stream,
};
use ids::{IdsEngine, baseline::Baseline, blacklist::Blacklist, geo::GeoDetector, start_sweeper};
use proto::monitor_ingestion_client::MonitorIngestionClient;
use raw_packet::RawPacket;
use ring_buffer::RingBuffer;
use tests::test_sender::{TestSenderConfig, run_test_sender};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    eprintln!("monitor-agent starting...");

    // Default to `info` so `docker logs` shows startup/registration progress
    // even when RUST_LOG isn't set; RUST_LOG still overrides when present.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();
    if config.list_devices {
        match pcap::Device::list() {
            Ok(devices) => {
                println!("{} device(s) found:\n", devices.len());
                for (i, d) in devices.iter().enumerate() {
                    println!("[{}] Name: {}", i, d.name);
                    println!("Description: {}", d.desc.as_deref().unwrap_or("(none)"));
                    println!();
                }
            }
            Err(e) => eprintln!("Failed to list devices: {}", e),
        }
        return Ok(());
    }

    // --- Build IDS components ---
    let baseline_path = std::env::var("IDS_BASELINE_PATH").ok();
    let baseline = Arc::new(Baseline::new(
        baseline_path.as_deref().map(std::path::Path::new),
    ));

    let geo = Arc::new(GeoDetector::new());
    if let Ok(mmdb_path) = std::env::var("GEOIP_MMDB_PATH") {
        geo.load(std::path::Path::new(&mmdb_path));
    }

    let blacklist = Arc::new(Blacklist::new());
    // Optionally load blacklists from env-configured paths
    if let Ok(ip_list_path) = std::env::var("IDS_IP_BLACKLIST_PATH")
        && let Ok(content) = std::fs::read_to_string(&ip_list_path)
    {
        blacklist.load_ip_list(&content);
        info!("Loaded IP blacklist from {}", ip_list_path);
    }
    if let Ok(domain_list_path) = std::env::var("IDS_DOMAIN_BLACKLIST_PATH")
        && let Ok(content) = std::fs::read_to_string(&domain_list_path)
    {
        blacklist.load_domain_list(&content);
        info!("Loaded domain blacklist from {}", domain_list_path);
    }

    let engine = Arc::new(IdsEngine::new(
        Arc::clone(&baseline),
        Arc::clone(&geo),
        Arc::clone(&blacklist),
    ));

    // Sweeper evicts stale flow state every 30 seconds
    start_sweeper(
        engine.port_scan_handle(),
        engine.syn_flood_handle(),
        engine.rate_limiter_handle(),
        Arc::clone(&baseline),
        Duration::from_secs(30),
    );

    // --- Resolve stable identity (persisted UUID unless --agent-id overrides) ---
    let agent_id = agent_identity::resolve(config.agent_id.clone());
    info!(agent_id = %agent_id, "resolved agent identity");

    // --- gRPC channel ---
    let grpc_addr = config
        .grpc_addr
        .as_deref()
        .unwrap_or("http://127.0.0.1:50051");
    info!(addr = grpc_addr, "connecting to ingestion service");

    // Lazy connect: don't fail startup if the backend isn't reachable yet.
    // The channel dials on first RPC and reconnects per-attempt after that.
    let channel = Channel::from_shared(grpc_addr.to_string())?.connect_lazy();

    let packet_client = MonitorIngestionClient::new(channel.clone());
    let heartbeat_client = MonitorIngestionClient::new(channel.clone());

    if let Some(token) = config.register_token.clone() {
        let mut register_client = MonitorIngestionClient::new(channel);
        match register_agent(
            &mut register_client,
            token,
            agent_id.clone(),
            env!("CARGO_PKG_VERSION").to_string(),
        )
        .await
        {
            Ok(()) => info!("registration complete"),
            Err(e) => {
                error!(error = %e, "agent registration failed — continuing without it");
            }
        }
    }

    let cancel = CancellationToken::new();
    let shutdown = Arc::new(AtomicBool::new(false));

    let counters = Arc::new(AgentCounters::default());
    let counters_hb = Arc::clone(&counters);

    // mpsc channel: analyzer → gRPC stream
    let (tx, rx) = mpsc::channel::<RawPacket>(config.channel_capacity);

    let capture_handle: Option<std::thread::JoinHandle<()>> = if config.test_send {
        info!("--test-send enabled: using generated packets");
        let test_cfg = TestSenderConfig {
            packets_per_tick: config.test_packets_per_tick.unwrap_or(20),
            tick_interval: Duration::from_millis(config.test_tick_ms.unwrap_or(200)),
            max_ticks: config.test_max_ticks,
        };
        // test_sender bypasses the ring buffer and sends directly to gRPC
        tokio::spawn(run_test_sender(tx, test_cfg, cancel.clone()));
        None
    } else {
        let config_clone = config.clone();
        let shutdown_capture = Arc::clone(&shutdown);
        let engine_clone = Arc::clone(&engine);
        let tx_clone = tx.clone();

        Some(std::thread::spawn(move || {
            // Ring buffer between capture and analyzer
            let buffer = RingBuffer::new(4096);
            let analysis_buf = buffer.clone_handle();

            // Analyzer thread: IDS scoring + forward to gRPC channel
            let analysis_thread = std::thread::Builder::new()
                .name("ids-analyzer".into())
                .spawn(move || {
                    analyzer::start_analysis(analysis_buf, engine_clone, tx_clone);
                })
                .expect("failed to spawn analyzer thread");

            if let Err(e) = capture::run_capture(&config_clone, buffer, shutdown_capture) {
                error!("Capture thread exited with error: {}", e);
            }

            // Signal analyzer to exit by closing the ring buffer
            analysis_thread.join().expect("Analyzer thread panicked");
        }))
    };

    let stream_cfg = PacketStreamConfig {
        agent_id: agent_id.clone(),
        batch_size: config.grpc_batch_size.unwrap_or(50),
        flush_interval: Duration::from_millis(config.grpc_flush_ms.unwrap_or(200)),
    };

    let stream_handle = tokio::spawn(run_packet_stream(
        packet_client,
        rx,
        stream_cfg,
        Arc::clone(&counters),
        cancel.clone(),
    ));

    let hb_cfg = HeartbeatConfig {
        agent_id: agent_id.clone(),
        interval: Duration::from_secs(config.heartbeat_interval_secs.unwrap_or(10)),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        hostname: hostname_or_default(),
        os_info: std::env::consts::OS.to_string(),
    };

    let heartbeat_handle = tokio::spawn(run_heartbeat_loop(
        heartbeat_client,
        hb_cfg,
        counters_hb,
        cancel.clone(),
    ));

    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received.");

    cancel.cancel();
    shutdown.store(true, Ordering::Relaxed);

    let _ = stream_handle.await;
    let _ = heartbeat_handle.await;

    if let Some(handle) = capture_handle {
        handle.join().expect("Capture thread panicked");
    }

    baseline.persist();
    info!("Clean shutdown complete.");
    Ok(())
}
