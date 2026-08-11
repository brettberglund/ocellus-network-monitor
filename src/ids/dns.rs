//! DNS anomaly detection: DGA heuristics (entropy, label length), suspicious TLDs,
//! DNS-over-UDP tunnel detection (oversized responses), and domain blacklist checks.

use crate::ids::score::{SCORE_DNS_ANOMALY, Signal};

const ENTROPY_THRESHOLD: f64 = 3.5;
const MAX_LABEL_LEN: usize = 40;
const MAX_FQDN_LEN: usize = 128;
/// DNS TXT/NULL response size threshold for tunnel detection
const DNS_TUNNEL_BYTES: usize = 400;

/// TLDs with disproportionately high abuse rates; matching adds a low-weight signal.
const SUSPICIOUS_TLDS: &[&str] = &[
    "xyz", "top", "click", "link", "work", "date", "review", "stream", "gdn", "racing", "download",
    "win", "bid", "loan", "online", "science", "party", "trade",
];

/// Stateless DNS anomaly detector; all context is derived from the packet payload alone.
pub struct DnsDetector;

impl DnsDetector {
    pub fn new() -> Self {
        Self
    }

    /// Inspect a raw UDP payload starting at `payload`.
    /// Returns any detected signals.
    pub fn inspect_payload(&self, payload: &[u8]) -> Vec<Signal> {
        let mut signals = Vec::new();

        let Some(query_name) = extract_dns_query_name(payload) else {
            return signals;
        };

        signals.extend(self.inspect_name(&query_name));

        // DNS tunnel: large TXT/NULL response heuristic
        // Check ANCOUNT (bytes 6-7) and response bit (bit 15 of flags)
        if payload.len() > 6 {
            let flags = u16::from_be_bytes([payload[2], payload[3]]);
            let is_response = flags & 0x8000 != 0;
            let ancount = u16::from_be_bytes([payload[6], payload[7]]);
            if is_response && ancount > 0 && payload.len() >= DNS_TUNNEL_BYTES {
                signals.push(Signal {
                    name: "dns_tunnel_large_response",
                    score: SCORE_DNS_ANOMALY + 5.0,
                    detail: format!(
                        "DNS response {} bytes (≥{}) — possible tunnel",
                        payload.len(),
                        DNS_TUNNEL_BYTES
                    ),
                });
            }
        }

        signals
    }

    /// Inspect a domain name string directly (e.g. from HTTP Host header).
    pub fn inspect_name(&self, fqdn: &str) -> Vec<Signal> {
        let mut signals = Vec::new();
        let fqdn = fqdn.trim_end_matches('.');

        // Unusually long FQDN
        if fqdn.len() > MAX_FQDN_LEN {
            signals.push(Signal {
                name: "dns_long_fqdn",
                score: SCORE_DNS_ANOMALY,
                detail: format!(
                    "FQDN length {} exceeds threshold {}",
                    fqdn.len(),
                    MAX_FQDN_LEN
                ),
            });
        }

        let labels: Vec<&str> = fqdn.split('.').collect();

        // Suspicious TLD check
        if let Some(tld) = labels.last()
            && SUSPICIOUS_TLDS.contains(&tld.to_lowercase().as_str())
        {
            signals.push(Signal {
                name: "dns_suspicious_tld",
                score: 15.0,
                detail: format!("Rare/abused TLD: .{}", tld),
            });
        }

        // Per-label checks (skip TLD)
        for label in labels.iter().take(labels.len().saturating_sub(1)) {
            if label.len() > MAX_LABEL_LEN {
                signals.push(Signal {
                    name: "dns_long_label",
                    score: SCORE_DNS_ANOMALY,
                    detail: format!(
                        "DNS label '{}' length {} > {}",
                        label,
                        label.len(),
                        MAX_LABEL_LEN
                    ),
                });
            }

            let entropy = shannon_entropy(label.as_bytes());
            if entropy > ENTROPY_THRESHOLD {
                signals.push(Signal {
                    name: "dns_high_entropy",
                    score: SCORE_DNS_ANOMALY,
                    detail: format!(
                        "DNS label '{}' entropy {:.2} (threshold {:.2}) — likely DGA",
                        label, entropy, ENTROPY_THRESHOLD
                    ),
                });
            }
        }

        signals
    }
}

/// Shannon entropy of a byte slice (bits per symbol).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Extract the query name from a raw DNS payload (wire format).
/// Returns None if the packet is malformed or too short.
pub fn extract_dns_query_name(payload: &[u8]) -> Option<String> {
    // DNS header is 12 bytes; QDCOUNT at bytes 4-5
    if payload.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels = Vec::new();

    loop {
        if pos >= payload.len() {
            return None;
        }
        let len = payload[pos] as usize;
        if len == 0 {
            break;
        }
        // Pointer compression — not following for simplicity
        if len & 0xC0 == 0xC0 {
            break;
        }
        pos += 1;
        if pos + len > payload.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&payload[pos..pos + len]).into_owned());
        pos += len;
    }

    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}
