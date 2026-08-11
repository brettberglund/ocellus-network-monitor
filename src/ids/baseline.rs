//! Adaptive traffic baseline used to distinguish normal from anomalous patterns.
//!
//! During the **Learning** phase (first 30 minutes) the baseline accumulates ports,
//! destination IPs, countries, DNS domains, and protocol distribution without raising
//! any alerts. Once the learning window expires the engine switches to **Refinement**
//! phase where only clean traffic (score < [`THRESHOLD_INFO`]) updates the baseline.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const EMA_ALPHA: f64 = 0.001;
const LEARNING_DURATION: Duration = Duration::from_secs(30 * 60); // 30 min default

/// Per-hour snapshot (24 buckets for time-of-day awareness).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HourlyBucket {
    pub avg_packet_rate: f64,
    pub avg_bytes_rate: f64,
    pub samples: u64,
}

impl HourlyBucket {
    #[allow(dead_code)]
    fn update(&mut self, pkt_rate: f64, bytes_rate: f64) {
        if self.samples == 0 {
            self.avg_packet_rate = pkt_rate;
            self.avg_bytes_rate = bytes_rate;
        } else {
            self.avg_packet_rate = EMA_ALPHA * pkt_rate + (1.0 - EMA_ALPHA) * self.avg_packet_rate;
            self.avg_bytes_rate = EMA_ALPHA * bytes_rate + (1.0 - EMA_ALPHA) * self.avg_bytes_rate;
        }
        self.samples += 1;
    }
}

/// Persisted baseline state.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BaselineState {
    pub common_ports: HashSet<u16>,
    pub dst_ips: HashSet<String>,
    pub countries: HashSet<String>,
    pub common_dns_domains: HashSet<String>,
    pub protocol_dist: HashMap<u8, f64>,
    pub hourly: [HourlyBucket; 24],
    pub learned_at: u64, // Unix timestamp when learning phase ended
    pub ring_buffer_recommended: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Observing; no alerts generated, all traffic updates baseline.
    Learning,
    /// Alerts active; baseline updated only from clean traffic.
    Refinement,
}

/// Runtime baseline state with optional JSON persistence via `IDS_BASELINE_PATH`.
pub struct Baseline {
    state: RwLock<BaselineState>,
    phase: RwLock<Phase>,
    learning_started: SystemTime,
    learning_duration: Duration,
    persist_path: Option<Box<Path>>,
}

impl Baseline {
    /// Load persisted state from `persist_path` if present; otherwise start a fresh Learning phase.
    /// If a non-zero `learned_at` timestamp is found in the file, Refinement phase begins immediately.
    pub fn new(persist_path: Option<&Path>) -> Self {
        let state: BaselineState = persist_path
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let phase = if state.learned_at > 0 {
            Phase::Refinement
        } else {
            Phase::Learning
        };

        Self {
            state: RwLock::new(state),
            phase: RwLock::new(phase),
            learning_started: SystemTime::now(),
            learning_duration: LEARNING_DURATION,
            persist_path: persist_path.map(|p| p.into()),
        }
    }

    pub fn phase(&self) -> Phase {
        *self.phase.read().unwrap()
    }

    pub fn is_learning(&self) -> bool {
        self.phase() == Phase::Learning
    }

    /// Advance to Refinement phase; persist to disk.
    pub fn finish_learning(&self) {
        let mut p = self.phase.write().unwrap();
        if *p == Phase::Learning {
            *p = Phase::Refinement;
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.state.write().unwrap().learned_at = ts;
            self.persist();
            tracing::info!("Baseline learning complete — switching to Refinement phase");
        }
    }

    /// Check if learning duration has elapsed and auto-advance.
    pub fn tick_phase(&self) {
        if self.is_learning()
            && self.learning_started.elapsed().unwrap_or_default() >= self.learning_duration
        {
            self.finish_learning();
        }
    }

    // --- Observation ---

    pub fn observe_port(&self, port: u16) {
        self.state.write().unwrap().common_ports.insert(port);
    }

    pub fn observe_dst_ip(&self, ip: IpAddr) {
        self.state.write().unwrap().dst_ips.insert(ip.to_string());
    }

    pub fn observe_country(&self, code: &str) {
        self.state
            .write()
            .unwrap()
            .countries
            .insert(code.to_string());
    }

    pub fn observe_dns(&self, domain: &str) {
        self.state
            .write()
            .unwrap()
            .common_dns_domains
            .insert(domain.to_lowercase());
    }

    pub fn observe_protocol(&self, proto: u8) {
        let mut s = self.state.write().unwrap();
        let entry = s.protocol_dist.entry(proto).or_insert(0.0);
        *entry = EMA_ALPHA + (1.0 - EMA_ALPHA) * (*entry);
    }

    /// Update rate metrics for the current hour; only called on clean traffic in Refinement.
    #[allow(dead_code)]
    pub fn observe_rates(&self, pkt_rate: f64, bytes_rate: f64) {
        let hour = current_hour();
        self.state.write().unwrap().hourly[hour].update(pkt_rate, bytes_rate);
    }

    // --- Checks ---

    pub fn is_known_port(&self, port: u16) -> bool {
        self.state.read().unwrap().common_ports.contains(&port)
    }

    pub fn is_known_country(&self, code: &str) -> bool {
        self.state.read().unwrap().countries.contains(code)
    }

    pub fn is_known_dns(&self, domain: &str) -> bool {
        self.state
            .read()
            .unwrap()
            .common_dns_domains
            .contains(&domain.to_lowercase())
    }

    #[allow(dead_code)]
    pub fn current_hour_avg_pkt_rate(&self) -> f64 {
        self.state.read().unwrap().hourly[current_hour()].avg_packet_rate
    }

    // --- Persistence ---

    pub fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let s = self.state.read().unwrap();
        match serde_json::to_string_pretty(&*s) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::warn!("Failed to persist baseline: {}", e);
                }
            }
            Err(e) => tracing::warn!("Failed to serialize baseline: {}", e),
        }
    }
}

#[allow(dead_code)]
fn current_hour() -> usize {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    ((secs / 3600) % 24) as usize
}
