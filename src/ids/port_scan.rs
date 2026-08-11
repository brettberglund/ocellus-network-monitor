//! Horizontal and vertical port-scan detection using per-IP sliding windows.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::ids::score::{SCORE_PORT_SCAN, Signal};

/// Sliding-window set of unique values seen within a TTL.
struct SlidingSet {
    entries: Vec<(u16, Instant)>,
    window: Duration,
}

impl SlidingSet {
    fn new(window: Duration) -> Self {
        Self {
            entries: Vec::new(),
            window,
        }
    }

    /// Insert value, evict expired entries, return current unique count.
    fn insert(&mut self, val: u16) -> usize {
        let now = Instant::now();
        self.entries
            .retain(|(_, t)| now.duration_since(*t) < self.window);
        if !self.entries.iter().any(|(v, _)| *v == val) {
            self.entries.push((val, now));
        }
        self.entries.len()
    }

    #[allow(dead_code)]
    fn unique_count(&self) -> usize {
        self.entries.len()
    }
}

/// Detects horizontal scans (one source → many ports) and vertical scans (one port ← many sources).
pub struct PortScanDetector {
    /// src_ip → unique destination ports seen
    ports_per_src: DashMap<IpAddr, SlidingSet>,
    /// dst_port → unique source IPs seen
    srcs_per_port: DashMap<u16, SlidingSet>,
    window: Duration,
    /// Alert when one src hits this many distinct ports
    port_threshold: usize,
    /// Alert when one port sees this many distinct source IPs
    src_threshold: usize,
}

impl PortScanDetector {
    pub fn new() -> Self {
        Self {
            ports_per_src: DashMap::new(),
            srcs_per_port: DashMap::new(),
            window: Duration::from_secs(60),
            port_threshold: 20,
            src_threshold: 50,
        }
    }

    /// Record a (src_ip, dst_port) observation and return a [`Signal`] if either scan
    /// threshold is exceeded within the sliding window.
    pub fn inspect(&self, src_ip: IpAddr, dst_port: u16) -> Option<Signal> {
        // horizontal: one src → many ports
        let horizontal = {
            let mut entry = self
                .ports_per_src
                .entry(src_ip)
                .or_insert_with(|| SlidingSet::new(self.window));
            entry.insert(dst_port)
        };

        if horizontal >= self.port_threshold {
            return Some(Signal {
                name: "port_scan_horizontal",
                score: SCORE_PORT_SCAN,
                detail: format!(
                    "{} contacted {} distinct ports in {}s window",
                    src_ip,
                    horizontal,
                    self.window.as_secs()
                ),
            });
        }

        // vertical: one port ← many sources
        let vertical = {
            let mut entry = self
                .srcs_per_port
                .entry(dst_port)
                .or_insert_with(|| SlidingSet::new(self.window));
            // store src_ip as a synthetic u16 hash key (good enough for counting)
            let h = ip_hash(src_ip);
            entry.insert(h)
        };

        if vertical >= self.src_threshold {
            return Some(Signal {
                name: "port_scan_vertical",
                score: SCORE_PORT_SCAN,
                detail: format!(
                    "port {} hit by {} distinct sources in {}s window",
                    dst_port,
                    vertical,
                    self.window.as_secs()
                ),
            });
        }

        None
    }

    /// Remove stale entries; called by the background sweeper.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.ports_per_src.retain(|_, v| {
            v.entries.retain(|(_, t)| now.duration_since(*t) < v.window);
            !v.entries.is_empty()
        });
        self.srcs_per_port.retain(|_, v| {
            v.entries.retain(|(_, t)| now.duration_since(*t) < v.window);
            !v.entries.is_empty()
        });
    }
}

fn ip_hash(ip: IpAddr) -> u16 {
    use std::hash::Hash;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ip.hash(&mut h);
    (std::hash::Hasher::finish(&h) & 0xFFFF) as u16
}
