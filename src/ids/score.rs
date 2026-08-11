//! Scoring model: per-signal weights, severity thresholds, and the aggregated [`IdsResult`].

use std::fmt;

/// Minimum total score to classify a result as [`Severity::Info`].
pub const THRESHOLD_INFO: f32 = 30.0;
/// Minimum total score to classify a result as [`Severity::Warning`].
pub const THRESHOLD_WARNING: f32 = 60.0;
/// Minimum total score to classify a result as [`Severity::Alert`].
pub const THRESHOLD_ALERT: f32 = 85.0;

pub const SCORE_BLACKLIST_IP: f32 = 90.0;
pub const SCORE_BLACKLIST_DOMAIN: f32 = 80.0;
pub const SCORE_PAYLOAD_SIG: f32 = 70.0;
pub const SCORE_SYN_FLOOD: f32 = 65.0;
pub const SCORE_PORT_SCAN: f32 = 60.0;
pub const SCORE_HALF_OPEN_HIGH: f32 = 50.0;
pub const SCORE_DNS_ANOMALY: f32 = 45.0;
pub const SCORE_RATE_EXCEEDED: f32 = 40.0;
pub const SCORE_GEO_ANOMALY: f32 = 35.0;
pub const SCORE_UNUSUAL_PORT_NETWORK: f32 = 30.0;
pub const SCORE_UNUSUAL_PORT_GLOBAL: f32 = 20.0;

/// Added to the total when two or more independent signals fire on the same packet.
pub const CORRELATION_BONUS: f32 = 10.0;

/// Human-readable severity band derived from a packet's total IDS score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Alert,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Alert => write!(f, "ALERT"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl Severity {
    pub fn from_score(score: f32) -> Self {
        if score >= THRESHOLD_ALERT {
            if score >= 95.0 {
                Self::Critical
            } else {
                Self::Alert
            }
        } else if score >= THRESHOLD_WARNING {
            Self::Warning
        } else {
            Self::Info
        }
    }
}

/// A single scored detection signal.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Signal {
    pub name: &'static str,
    pub score: f32,
    pub detail: String,
}

/// Aggregated result for one packet.
#[derive(Debug, Clone)]
pub struct IdsResult {
    pub total_score: f32,
    pub severity: Severity,
    /// Proto FlagReason int value (highest-scoring signal wins).
    pub flag_reason: i32,
    pub signals: Vec<Signal>,
}

impl IdsResult {
    /// Build an [`IdsResult`] from a list of signals: sums scores, applies the correlation
    /// bonus for ≥2 signals, caps at 100, and sorts signals by descending score.
    pub fn from_signals(mut signals: Vec<Signal>, flag_reason: i32) -> Self {
        let base: f32 = signals.iter().map(|s| s.score).sum();
        // correlation bonus when 2+ independent signals fire
        let bonus = if signals.len() >= 2 {
            CORRELATION_BONUS
        } else {
            0.0
        };
        let total_score = (base + bonus).min(100.0);
        signals.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        Self {
            total_score,
            severity: Severity::from_score(total_score),
            flag_reason,
            signals,
        }
    }

    /// `true` when the total score is below [`THRESHOLD_INFO`] — no baseline update suppression needed.
    pub fn is_clean(&self) -> bool {
        self.total_score < THRESHOLD_INFO
    }
}
