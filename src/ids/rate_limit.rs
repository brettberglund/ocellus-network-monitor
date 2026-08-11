//! Per-source-IP rate limiting using a token-bucket algorithm.
//!
//! Three independent limits are enforced per window: packet rate, byte rate, and
//! new-connection (SYN) rate. Any breach returns a [`Signal`].

use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;

use crate::ids::score::{SCORE_RATE_EXCEEDED, Signal};

/// Token-bucket state for a single source IP.
struct Bucket {
    /// Current token count (fractional for precision).
    tokens: f64,
    last_refill: Instant,
    /// Bytes this window
    bytes: u64,
    /// Connection (SYN) count this window
    connections: u64,
    window_start: Instant,
}

impl Bucket {
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
            bytes: 0,
            connections: 0,
            window_start: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time and return true if the packet is within rate.
    fn consume(&mut self, rate_per_sec: f64, capacity: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(capacity);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Maintains a token-bucket [`Bucket`] per source IP and fires a [`Signal`] on rate breach.
pub struct RateLimiter {
    buckets: DashMap<IpAddr, Bucket>,
    /// Max packets/sec per IP before alerting.
    pkt_rate: f64,
    /// Token bucket capacity (burst headroom).
    capacity: f64,
    /// Max bytes/sec per IP.
    bytes_rate: u64,
    /// Max new connections/sec per IP.
    conn_rate: u64,
    window_secs: f64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            pkt_rate: 500.0,
            capacity: 1000.0,
            bytes_rate: 10 * 1024 * 1024, // 10 MB/s
            conn_rate: 50,
            window_secs: 1.0,
        }
    }

    /// Observe one packet from `src_ip` and return a [`Signal`] if any rate limit is exceeded.
    pub fn inspect(&self, src_ip: IpAddr, pkt_bytes: u64, is_syn: bool) -> Option<Signal> {
        let mut bucket = self
            .buckets
            .entry(src_ip)
            .or_insert_with(|| Bucket::new(self.capacity));

        // Reset per-window counters if window elapsed
        if bucket.window_start.elapsed().as_secs_f64() >= self.window_secs {
            bucket.bytes = 0;
            bucket.connections = 0;
            bucket.window_start = Instant::now();
        }

        bucket.bytes += pkt_bytes;
        if is_syn {
            bucket.connections += 1;
        }

        let within_rate = bucket.consume(self.pkt_rate, self.capacity);

        if !within_rate {
            return Some(Signal {
                name: "rate_exceeded_packets",
                score: SCORE_RATE_EXCEEDED,
                detail: format!("{} exceeded packet rate ({}/s)", src_ip, self.pkt_rate),
            });
        }

        if bucket.bytes > self.bytes_rate {
            return Some(Signal {
                name: "rate_exceeded_bytes",
                score: SCORE_RATE_EXCEEDED,
                detail: format!(
                    "{} sent {} bytes this window (limit {} B/s)",
                    src_ip, bucket.bytes, self.bytes_rate
                ),
            });
        }

        if is_syn && bucket.connections > self.conn_rate {
            return Some(Signal {
                name: "rate_exceeded_connections",
                score: SCORE_RATE_EXCEEDED,
                detail: format!(
                    "{} opened {} connections this window (limit {})",
                    src_ip, bucket.connections, self.conn_rate
                ),
            });
        }

        None
    }

    /// Drop stale buckets; called by background sweeper.
    pub fn sweep(&self) {
        self.buckets
            .retain(|_, b| b.last_refill.elapsed().as_secs() < 120);
    }
}
