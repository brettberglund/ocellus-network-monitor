use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use rand::{Rng, RngExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::raw_packet::{LinkType, RawPacket, TransportMeta};

#[derive(Debug, Clone)]
pub struct TestSenderConfig {
    pub packets_per_tick: usize,
    pub tick_interval: Duration,
    pub max_ticks: Option<u64>,
}

impl Default for TestSenderConfig {
    fn default() -> Self {
        Self {
            packets_per_tick: 20,
            tick_interval: Duration::from_millis(200),
            max_ticks: None,
        }
    }
}

// Wire format builder (Ethernet + IPv4 + optional TCP/UDP ports)

const ETH_HDR: usize = 14;
const IPV4_HDR: usize = 20;
const PORT_HDR: usize = 4;

fn build_frame(rng: &mut impl Rng) -> Vec<u8> {
    let proto_byte: u8 = *[1u8, 6, 17].get(rng.random_range(0..3)).unwrap();
    let payload_len: usize = rng.random_range(0..=256);
    let has_ports = proto_byte != 1;

    let total = ETH_HDR + IPV4_HDR + if has_ports { PORT_HDR } else { 0 } + payload_len;
    let mut buf = vec![0u8; total];

    // Ethernet header (dst + src MACs + EtherType 0x0800)
    for b in buf[0..12].iter_mut() {
        *b = rng.random();
    }
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IPv4
    buf[14] = 0x45; // version=4, IHL=5
    let ip_len = (total - ETH_HDR) as u16;
    buf[16] = (ip_len >> 8) as u8;
    buf[17] = (ip_len & 0xFF) as u8;
    buf[22] = rng.random_range(32_u8..=255); // TTL
    buf[23] = proto_byte;

    buf[26] = rng.random_range(1..=223);
    buf[27] = rng.random();
    buf[28] = rng.random();
    buf[29] = rng.random_range(1..=254);

    buf[30] = rng.random_range(1..=223);
    buf[31] = rng.random();
    buf[32] = rng.random();
    buf[33] = rng.random_range(1..=254);

    if has_ports && total > ETH_HDR + IPV4_HDR + 3 {
        let src: u16 = rng.random_range(1024..=65535);
        let dst: u16 = rng.random_range(1..=1023);
        buf[34] = (src >> 8) as u8;
        buf[35] = (src & 0xFF) as u8;
        buf[36] = (dst >> 8) as u8;
        buf[37] = (dst & 0xFF) as u8;
    }

    let payload_start = ETH_HDR + IPV4_HDR + if has_ports { PORT_HDR } else { 0 };
    for b in buf[payload_start..].iter_mut() {
        *b = rng.random();
    }

    buf
}

fn frame_to_raw(data: Vec<u8>) -> RawPacket {
    let len = data.len() as u32;

    // Build a minimal TransportMeta from the synthetic Ethernet/IPv4 frame
    let transport = if data.len() >= ETH_HDR + IPV4_HDR {
        let proto = data[23];
        let src_ip = IpAddr::V4(Ipv4Addr::new(data[26], data[27], data[28], data[29]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(data[30], data[31], data[32], data[33]));
        let ttl = data[22];
        let has_ports = proto != 1 && data.len() > ETH_HDR + IPV4_HDR + 3;
        let (src_port, dst_port) = if has_ports {
            let sp = u16::from_be_bytes([data[34], data[35]]);
            let dp = u16::from_be_bytes([data[36], data[37]]);
            (Some(sp), Some(dp))
        } else {
            (None, None)
        };
        Some(TransportMeta {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: proto,
            tcp_flags: if proto == 6 { Some(0x02) } else { None }, // synthetic SYN
            ttl,
            ip_flags: 0,
            ip_frag_offset: 0,
            icmp_type: if proto == 1 { Some(8) } else { None },
            icmp_code: if proto == 1 { Some(0) } else { None },
            eth_src_mac: {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&data[6..12]);
                Some(mac)
            },
            vlan_id: None,
            payload_offset: ETH_HDR + IPV4_HDR + if has_ports { PORT_HDR } else { 0 },
        })
    } else {
        None
    };

    RawPacket {
        timestamp: SystemTime::now(),
        data,
        orig_len: len,
        cap_len: len,
        is_truncated: false,
        interface: "test".to_string(),
        link_type: LinkType::Ethernet,
        transport,
        packet_id: 0,
        ids_score: 0.0,
        ids_flag: 0,
    }
}

pub async fn run_test_sender(
    tx: mpsc::Sender<RawPacket>,
    cfg: TestSenderConfig,
    cancel: CancellationToken,
) {
    let mut tick: u64 = 0;

    info!(
        packets_per_tick = cfg.packets_per_tick,
        interval_ms = cfg.tick_interval.as_millis(),
        max_ticks = ?cfg.max_ticks,
        "test sender started"
    );

    loop {
        if cfg.max_ticks.is_some_and(|max| tick >= max) {
            info!(ticks = tick, "test sender: max_ticks reached, stopping");
            break;
        }

        let packets: Vec<RawPacket> = {
            let mut rng = rand::rng();
            (0..cfg.packets_per_tick)
                .map(|_| frame_to_raw(build_frame(&mut rng)))
                .collect()
        };

        for raw in packets {
            debug!(orig_len = raw.orig_len, "synthetic packet generated");
            tokio::select! {
                _ = cancel.cancelled() => {
                    info!("test sender: cancelled");
                    return;
                }
                res = tx.send(raw) => {
                    if res.is_err() {
                        info!("capture channel closed - stopping");
                        return;
                    }
                }
            }
        }

        tick += 1;

        tokio::select! {
            _ = cancel.cancelled() => {
                info!("test sender: cancelled during sleep");
                return;
            }
            _ = tokio::time::sleep(cfg.tick_interval) => {}
        }
    }
}
