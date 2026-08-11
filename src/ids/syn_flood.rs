//! SYN-flood, half-open connection tracking, RST injection, and Xmas-scan detection.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::ids::score::{SCORE_HALF_OPEN_HIGH, SCORE_SYN_FLOOD, Signal};

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_RST: u8 = 0x04;
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_URG: u8 = 0x20;
/// Xmas scan: FIN + PSH + URG
const TCP_XMAS: u8 = TCP_FIN | TCP_PSH | TCP_URG;

struct PerIpCounters {
    syns: u64,
    acks: u64,
    last_reset: Instant,
    window: Duration,
}

impl PerIpCounters {
    fn new() -> Self {
        Self {
            syns: 0,
            acks: 0,
            last_reset: Instant::now(),
            window: Duration::from_secs(10),
        }
    }

    fn maybe_reset(&mut self) {
        if self.last_reset.elapsed() >= self.window {
            self.syns = 0;
            self.acks = 0;
            self.last_reset = Instant::now();
        }
    }

    fn syn_ack_ratio(&self) -> f32 {
        if self.acks == 0 {
            self.syns as f32
        } else {
            self.syns as f32 / self.acks as f32
        }
    }
}

type FlowKey = (IpAddr, IpAddr, u16, u16);

/// Detects SYN floods via SYN/ACK ratio, excessive half-open connections, RST injection,
/// and Xmas scans (FIN+PSH+URG).
pub struct SynFloodDetector {
    counters: DashMap<IpAddr, PerIpCounters>,
    /// (src_ip, dst_ip, src_port, dst_port) → time of SYN
    half_open: DashMap<FlowKey, Instant>,
    syn_ack_ratio_threshold: f32,
    half_open_threshold: usize,
    half_open_ttl: Duration,
}

impl SynFloodDetector {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
            half_open: DashMap::new(),
            syn_ack_ratio_threshold: 5.0,
            half_open_threshold: 200,
            half_open_ttl: Duration::from_secs(30),
        }
    }

    /// Inspect TCP flags and return any detected signals.
    pub fn inspect(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let is_syn = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
        let is_syn_ack = flags & TCP_SYN != 0 && flags & TCP_ACK != 0;
        let is_rst = flags & TCP_RST != 0;
        let is_ack = !is_syn && flags & TCP_ACK != 0;

        // Track SYN / ACK ratio
        {
            let mut c = self
                .counters
                .entry(src_ip)
                .or_insert_with(PerIpCounters::new);
            c.maybe_reset();
            if is_syn {
                c.syns += 1;
            }
            if is_ack || is_syn_ack {
                c.acks += 1;
            }
            if c.syns >= 50 && c.syn_ack_ratio() >= self.syn_ack_ratio_threshold {
                signals.push(Signal {
                    name: "syn_flood",
                    score: SCORE_SYN_FLOOD,
                    detail: format!(
                        "{} SYN/ACK ratio {:.1} ({} SYNs, {} ACKs)",
                        src_ip,
                        c.syn_ack_ratio(),
                        c.syns,
                        c.acks
                    ),
                });
            }
        }

        // Half-open connection tracking
        let flow_key = (src_ip, dst_ip, src_port, dst_port);
        let rev_key = (dst_ip, src_ip, dst_port, src_port);

        if is_syn {
            self.half_open.insert(flow_key, Instant::now());
        } else if is_syn_ack || is_rst || is_ack {
            // Complete or reset the half-open entry
            self.half_open.remove(&rev_key);
            self.half_open.remove(&flow_key);
        }

        let half_open_count = self.half_open.len();
        if half_open_count >= self.half_open_threshold {
            signals.push(Signal {
                name: "half_open_high",
                score: SCORE_HALF_OPEN_HIGH,
                detail: format!("{} half-open connections tracked", half_open_count),
            });
        }

        // RST injection / Xmas scan checks
        if is_rst {
            // RST without a matching half-open entry is suspicious
            if !self.half_open.contains_key(&flow_key) && !self.half_open.contains_key(&rev_key) {
                signals.push(Signal {
                    name: "rst_injection",
                    score: 25.0,
                    detail: format!("RST from {} with no tracked SYN", src_ip),
                });
            }
        }

        if flags == TCP_XMAS {
            signals.push(Signal {
                name: "xmas_scan",
                score: SCORE_PORT_SCAN_XMAS,
                detail: format!("Xmas scan flags (FIN+PSH+URG) from {}", src_ip),
            });
        }

        signals
    }

    /// Evict expired half-open entries; called by background sweeper.
    pub fn sweep(&self) {
        let ttl = self.half_open_ttl;
        self.half_open.retain(|_, created| created.elapsed() < ttl);
        // Also reset stale per-IP counters
        self.counters
            .retain(|_, c| c.last_reset.elapsed() < c.window * 10);
    }
}

const SCORE_PORT_SCAN_XMAS: f32 = 55.0;
