//! Intrusion Detection System engine and detector registry.
//!
//! [`IdsEngine::analyze`] is called inline on every packet by the analyzer thread pool.
//! All detectors hold only `Arc`-shared state so they are safe to call concurrently
//! from multiple rayon workers.

pub mod baseline;
pub mod blacklist;
pub mod dns;
pub mod geo;
pub mod payload;
pub mod port_scan;
pub mod rate_limit;
pub mod score;
pub mod syn_flood;

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info};

use crate::raw_packet::RawPacket;

use baseline::{Baseline, Phase};
use blacklist::Blacklist;
use dns::{DnsDetector, extract_dns_query_name};
use geo::GeoDetector;
use payload::PayloadScanner;
use port_scan::PortScanDetector;
use rate_limit::RateLimiter;
use score::{
    IdsResult, SCORE_UNUSUAL_PORT_GLOBAL, SCORE_UNUSUAL_PORT_NETWORK, Signal, THRESHOLD_INFO,
};
use syn_flood::SynFloodDetector;

/// Well-known service ports. Traffic on these using the wrong protocol is suspicious.
const WELL_KNOWN_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 194, 389, 443, 445, 464, 465, 514, 515, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521,
    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
];

/// Aggregates all detector sub-systems and orchestrates per-packet analysis.
pub struct IdsEngine {
    port_scan: Arc<PortScanDetector>,
    syn_flood: Arc<SynFloodDetector>,
    rate_limiter: Arc<RateLimiter>,
    blacklist: Arc<Blacklist>,
    payload_scanner: Arc<PayloadScanner>,
    dns: Arc<DnsDetector>,
    geo: Arc<GeoDetector>,
    pub baseline: Arc<Baseline>,
}

impl IdsEngine {
    /// Construct the engine with shared handles to the pre-loaded [`Baseline`], [`GeoDetector`],
    /// and [`Blacklist`]; remaining detectors are allocated internally.
    pub fn new(baseline: Arc<Baseline>, geo: Arc<GeoDetector>, blacklist: Arc<Blacklist>) -> Self {
        Self {
            port_scan: Arc::new(PortScanDetector::new()),
            syn_flood: Arc::new(SynFloodDetector::new()),
            rate_limiter: Arc::new(RateLimiter::new()),
            blacklist,
            payload_scanner: Arc::new(PayloadScanner::new()),
            dns: Arc::new(DnsDetector::new()),
            geo,
            baseline,
        }
    }

    /// Analyze one packet and return an IdsResult.
    /// In Learning phase returns a clean result but still updates the baseline.
    pub fn analyze(&self, pkt: &RawPacket) -> IdsResult {
        let mut signals: Vec<Signal> = Vec::new();
        let mut primary_flag: i32 = 0; // FLAG_REASON_UNSPECIFIED

        let Some(ref tm) = pkt.transport else {
            return IdsResult::from_signals(vec![], 0);
        };

        let src_ip = tm.src_ip;
        let dst_ip = tm.dst_ip;
        let is_syn = tm.tcp_flags.is_some_and(|f| f & 0x02 != 0 && f & 0x10 == 0);
        let pkt_bytes = pkt.orig_len as u64;

        // --- Blacklist (IP) ---
        if let Some(s) = self.blacklist.check_ip(src_ip) {
            primary_flag = 7; // FLAG_REASON_BLACKLISTED
            signals.push(s);
        }
        if let Some(s) = self.blacklist.check_ip(dst_ip) {
            if primary_flag == 0 {
                primary_flag = 7;
            }
            signals.push(s);
        }

        // --- Rate limiting ---
        if let Some(s) = self.rate_limiter.inspect(src_ip, pkt_bytes, is_syn) {
            if primary_flag == 0 {
                primary_flag = 6;
            } // FLAG_REASON_RATE_EXCEEDED
            signals.push(s);
        }

        // --- Port scan ---
        if let Some(dst_port) = tm.dst_port
            && let Some(s) = self.port_scan.inspect(src_ip, dst_port)
        {
            if primary_flag == 0 {
                primary_flag = 1;
            } // FLAG_REASON_PORT_SCAN
            signals.push(s);
        }

        // --- SYN flood / half-open / TCP flag anomalies ---
        if let (Some(flags), Some(src_port), Some(dst_port)) =
            (tm.tcp_flags, tm.src_port, tm.dst_port)
        {
            for s in self
                .syn_flood
                .inspect(src_ip, dst_ip, src_port, dst_port, flags)
            {
                if primary_flag == 0 {
                    primary_flag = 2;
                } // FLAG_REASON_SYN_FLOOD
                signals.push(s);
            }
        }

        // --- ICMP anomalies ---
        if tm.protocol == 1
            && let (Some(icmp_type), Some(icmp_code)) = (tm.icmp_type, tm.icmp_code)
            && icmp_type >= 30
        {
            signals.push(Signal {
                name: "icmp_unusual_type",
                score: 25.0,
                detail: format!("Unusual ICMP type {} code {}", icmp_type, icmp_code),
            });
        }

        // --- IP fragmentation / evasion ---
        let mf = tm.ip_flags & 0x01 != 0;
        let df = tm.ip_flags & 0x02 != 0;
        if tm.ip_frag_offset > 0 || mf {
            signals.push(Signal {
                name: "ip_fragmentation",
                score: 20.0,
                detail: format!(
                    "Fragmented packet: offset={}, MF={}, DF={}",
                    tm.ip_frag_offset, mf, df
                ),
            });
        }

        // --- orig_len vs cap_len (truncation / evasion) ---
        if pkt.is_truncated {
            signals.push(Signal {
                name: "packet_truncated",
                score: 10.0,
                detail: format!("Captured {} of {} bytes", pkt.cap_len, pkt.orig_len),
            });
        }

        // --- Geo anomaly ---
        let geo_country = self.geo.country_code(src_ip);
        if let Some(ref code) = geo_country
            && self.baseline.phase() == Phase::Refinement
            && !self.baseline.is_known_country(code)
        {
            if primary_flag == 0 {
                primary_flag = 4;
            } // FLAG_REASON_GEO_ANOMALY
            signals.push(Signal {
                name: "geo_new_country",
                score: score::SCORE_GEO_ANOMALY,
                detail: format!("First-seen country '{}' for IP {}", code, src_ip),
            });
        }

        // --- Payload signatures ---
        if tm.payload_offset > 0 && tm.payload_offset < pkt.data.len() {
            for s in self
                .payload_scanner
                .scan_all(&pkt.data[tm.payload_offset..])
            {
                if primary_flag == 0 {
                    primary_flag = 5;
                } // FLAG_REASON_PAYLOAD_SIG
                signals.push(s);
            }
        }

        // --- DNS: extract name once, use for blacklist + baseline + anomaly detection ---
        let dns_query_name: Option<String> = if tm.protocol == 17
            && (tm.dst_port == Some(53) || tm.src_port == Some(53))
            && tm.payload_offset > 0
            && tm.payload_offset < pkt.data.len()
        {
            extract_dns_query_name(&pkt.data[tm.payload_offset..])
        } else {
            None
        };

        if let Some(ref domain) = dns_query_name {
            // Blacklist domain check
            if let Some(s) = self.blacklist.check_domain(domain) {
                if primary_flag == 0 {
                    primary_flag = 7;
                }
                signals.push(s);
            }
            // Anomaly detection — skip if domain is in baseline (reduces false positives)
            if !self.baseline.is_known_dns(domain) {
                for s in self.dns.inspect_name(domain) {
                    if primary_flag == 0 {
                        primary_flag = 3;
                    } // FLAG_REASON_DNS_ANOMALY
                    signals.push(s);
                }
            }
            // Full payload inspection (tunnel heuristic)
            if tm.payload_offset < pkt.data.len() {
                for s in self.dns.inspect_payload(&pkt.data[tm.payload_offset..]) {
                    if primary_flag == 0 {
                        primary_flag = 3;
                    }
                    signals.push(s);
                }
            }
        }

        // --- Unusual port (adaptive baseline) ---
        if let Some(dst_port) = tm.dst_port
            && self.baseline.phase() == Phase::Refinement
            && !self.baseline.is_known_port(dst_port)
        {
            let score = if WELL_KNOWN_PORTS.contains(&dst_port) {
                SCORE_UNUSUAL_PORT_NETWORK
            } else {
                SCORE_UNUSUAL_PORT_GLOBAL
            };
            signals.push(Signal {
                name: "unusual_port",
                score,
                detail: format!("Port {} not seen in baseline", dst_port),
            });
        }

        // --- VLAN hopping ---
        if let Some(vid) = tm.vlan_id
            && (vid == 0 || vid == 4095)
        {
            signals.push(Signal {
                name: "vlan_reserved_id",
                score: 20.0,
                detail: format!("Reserved VLAN ID {}", vid),
            });
        }

        // --- Update baseline (always in Learning; in Refinement only on clean traffic) ---
        let result = IdsResult::from_signals(signals, primary_flag);
        let update_baseline = self.baseline.is_learning() || result.total_score < THRESHOLD_INFO;

        if update_baseline {
            if let Some(dst_port) = tm.dst_port {
                self.baseline.observe_port(dst_port);
            }
            self.baseline.observe_dst_ip(dst_ip);
            self.baseline.observe_protocol(tm.protocol);
            if let Some(ref code) = geo_country {
                self.baseline.observe_country(code);
            }
            if let Some(ref domain) = dns_query_name {
                self.baseline.observe_dns(domain);
            }
        }

        if !result.is_clean() {
            debug!(
                score = result.total_score,
                severity = %result.severity,
                signals = result.signals.len(),
                src = %src_ip,
                "IDS alert"
            );
        }

        result
    }

    /// Arc handle to the port-scan detector, used by the background sweeper.
    pub fn port_scan_handle(&self) -> Arc<PortScanDetector> {
        Arc::clone(&self.port_scan)
    }
    /// Arc handle to the SYN-flood detector, used by the background sweeper.
    pub fn syn_flood_handle(&self) -> Arc<SynFloodDetector> {
        Arc::clone(&self.syn_flood)
    }
    /// Arc handle to the rate limiter, used by the background sweeper.
    pub fn rate_limiter_handle(&self) -> Arc<RateLimiter> {
        Arc::clone(&self.rate_limiter)
    }
}

/// Spawn a background thread that evicts stale flow state every `interval`.
pub fn start_sweeper(
    port_scan: Arc<PortScanDetector>,
    syn_flood: Arc<SynFloodDetector>,
    rate_limiter: Arc<RateLimiter>,
    baseline: Arc<Baseline>,
    interval: Duration,
) {
    std::thread::Builder::new()
        .name("ids-sweeper".into())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                port_scan.sweep();
                syn_flood.sweep();
                rate_limiter.sweep();
                baseline.tick_phase();
                baseline.persist();
                info!("IDS sweeper tick complete");
            }
        })
        .expect("failed to spawn ids-sweeper");
}
