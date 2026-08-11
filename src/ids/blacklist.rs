//! IP and domain blacklist with a Bloom pre-filter for fast clean-traffic rejection.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;

use bloomfilter::Bloom;

use crate::ids::score::{SCORE_BLACKLIST_DOMAIN, SCORE_BLACKLIST_IP, Signal};

/// Prefix/CIDR entry for IP range matching.
#[derive(Debug, Clone)]
struct CidrEntry {
    base: u32,
    mask: u32,
}

impl CidrEntry {
    fn from_cidr(s: &str) -> Option<Self> {
        let (ip_str, prefix_len_str) = s.split_once('/')?;
        let prefix_len: u32 = prefix_len_str.trim().parse().ok()?;
        let ip: std::net::Ipv4Addr = ip_str.trim().parse().ok()?;
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Some(Self {
            base: u32::from(ip) & mask,
            mask,
        })
    }

    fn contains(&self, ip: u32) -> bool {
        ip & self.mask == self.base
    }
}

/// Thread-safe blacklist supporting exact IPv4 addresses, CIDR ranges, and domain suffixes.
///
/// A Bloom filter is checked before the exact HashSet to avoid lock contention on
/// clean (non-blacklisted) traffic, which represents the vast majority of packets.
pub struct Blacklist {
    /// Bloom pre-filter for IPs (reduces HashSet lookups on clean traffic)
    ip_bloom: RwLock<Bloom<u32>>,
    /// Exact IPv4 hits
    ip_exact: RwLock<HashSet<u32>>,
    /// CIDR ranges (Spamhaus DROP, abuse.ch, etc.)
    ip_cidrs: RwLock<Vec<CidrEntry>>,
    /// Domain blacklist (abuse.ch, OpenPhish, etc.)
    domains: RwLock<HashSet<String>>,
}

impl Blacklist {
    pub fn new() -> Self {
        // Bloom: 100k items, 1% false positive rate
        let ip_bloom = Bloom::new_for_fp_rate(100_000, 0.01);
        Self {
            ip_bloom: RwLock::new(ip_bloom),
            ip_exact: RwLock::new(HashSet::new()),
            ip_cidrs: RwLock::new(Vec::new()),
            domains: RwLock::new(HashSet::new()),
        }
    }

    pub fn check_ip(&self, ip: IpAddr) -> Option<Signal> {
        let ipv4 = match ip {
            IpAddr::V4(v4) => u32::from(v4),
            IpAddr::V6(_) => return None, // IPv6 blacklist not yet populated
        };

        // Bloom pre-filter
        if !self.ip_bloom.read().unwrap().check(&ipv4) {
            // Definitely not in exact set; still check CIDRs
        } else {
            // Possible match — check exact set
            if self.ip_exact.read().unwrap().contains(&ipv4) {
                return Some(Signal {
                    name: "blacklisted_ip",
                    score: SCORE_BLACKLIST_IP,
                    detail: format!("IP {} matched blacklist", ip),
                });
            }
        }

        // CIDR check
        for cidr in self.ip_cidrs.read().unwrap().iter() {
            if cidr.contains(ipv4) {
                return Some(Signal {
                    name: "blacklisted_cidr",
                    score: SCORE_BLACKLIST_IP,
                    detail: format!("IP {} matched CIDR blacklist", ip),
                });
            }
        }

        None
    }

    pub fn check_domain(&self, domain: &str) -> Option<Signal> {
        let d = domain.trim_end_matches('.').to_lowercase();
        if self.domains.read().unwrap().contains(&d) {
            return Some(Signal {
                name: "blacklisted_domain",
                score: SCORE_BLACKLIST_DOMAIN,
                detail: format!("Domain '{}' matched blacklist", domain),
            });
        }
        None
    }

    // --- Mutation helpers (called by background loader thread) ---

    pub fn add_ip(&self, ip: u32) {
        self.ip_bloom.write().unwrap().set(&ip);
        self.ip_exact.write().unwrap().insert(ip);
    }

    pub fn add_cidr(&self, cidr_str: &str) {
        if let Some(entry) = CidrEntry::from_cidr(cidr_str) {
            self.ip_cidrs.write().unwrap().push(entry);
        }
    }

    pub fn add_domain(&self, domain: &str) {
        self.domains
            .write()
            .unwrap()
            .insert(domain.trim_end_matches('.').to_lowercase());
    }

    /// Load a newline-delimited list of IPs/CIDRs from a string (e.g. Spamhaus DROP).
    pub fn load_ip_list(&self, content: &str) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if line.contains('/') {
                self.add_cidr(line);
            } else if let Ok(ip) = line.parse::<std::net::Ipv4Addr>() {
                self.add_ip(u32::from(ip));
            }
        }
    }

    /// Load a newline-delimited domain list.
    pub fn load_domain_list(&self, content: &str) {
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                self.add_domain(line);
            }
        }
    }
}
