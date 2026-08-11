//! MaxMind GeoLite2-Country lookup for source-IP geolocation.
//!
//! If the mmdb file is not loaded (e.g. `GEOIP_MMDB_PATH` is unset), all lookups
//! return `None` silently — geo anomaly detection is simply disabled.

use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;

/// Thread-safe GeoIP resolver wrapping a lazily-loaded MaxMind reader.
pub struct GeoDetector {
    reader: RwLock<Option<maxminddb::Reader<Vec<u8>>>>,
}

impl GeoDetector {
    pub fn new() -> Self {
        Self {
            reader: RwLock::new(None),
        }
    }

    /// Load a MaxMind GeoLite2-Country.mmdb from disk.
    /// Safe to call from a background thread; a failed load leaves the detector
    /// disabled (no signals, no panics).
    pub fn load(&self, path: &Path) {
        match maxminddb::Reader::open_readfile(path) {
            Ok(r) => {
                *self.reader.write().unwrap() = Some(r);
                tracing::info!("GeoIP database loaded from {}", path.display());
            }
            Err(e) => {
                tracing::warn!("GeoIP load failed ({}): geo detection disabled", e);
            }
        }
    }

    #[allow(dead_code)]
    pub fn is_loaded(&self) -> bool {
        self.reader.read().unwrap().is_some()
    }

    /// Look up the ISO country code for an IP address. Returns None if GeoIP is not loaded.
    pub fn country_code(&self, ip: IpAddr) -> Option<String> {
        let guard = self.reader.read().unwrap();
        let reader = guard.as_ref()?;
        let record: maxminddb::geoip2::Country = reader.lookup(ip).ok()?;
        let code = record.country?.iso_code?.to_string();
        Some(code)
    }
}
