//! Core packet types produced by the capture thread and consumed by the analyzer.

use std::net::IpAddr;
use std::time::SystemTime;

/// pcap data-link type, mapped from the raw [`pcap::Linktype`] integer at capture open.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    Loopback,
    /// Unrecognised pcap linktype code; the inner value is the raw pcap integer.
    Unknown(u32),
}

/// Transport-layer and network-layer metadata extracted cheaply at capture time.
#[derive(Debug, Clone)]
pub struct TransportMeta {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8, // 6=tcp, 17=udp, 1=icmp
    pub tcp_flags: Option<u8>,

    // IPv4 network layer extras
    pub ttl: u8,
    /// Raw IP flags byte: bit1=DF, bit2=MF (more fragments)
    pub ip_flags: u8,
    /// Fragment offset in 8-byte units (0 means first/only fragment)
    pub ip_frag_offset: u16,

    // ICMP (protocol == 1 or 58)
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,

    // Layer-2 extras (only populated for Ethernet frames)
    #[allow(dead_code)]
    pub eth_src_mac: Option<[u8; 6]>,
    pub vlan_id: Option<u16>,

    /// Offset into RawPacket::data where application payload begins (0 = unknown/unavailable)
    pub payload_offset: usize,
}

/// Raw captured packet with lightweight metadata.
/// Heavy analysis (DNS parsing, HTTP header inspection, etc.) happens in the analyzer thread.
pub struct RawPacket {
    pub timestamp: SystemTime,
    pub data: Vec<u8>,
    pub orig_len: u32,
    pub cap_len: u32,
    pub interface: String,
    #[allow(dead_code)]
    pub link_type: LinkType,
    pub transport: Option<TransportMeta>,
    pub is_truncated: bool,
    #[allow(dead_code)]
    pub packet_id: u64,

    /// Set by the IDS analyzer; 0.0 until analyzed.
    pub ids_score: f32,
    /// FlagReason proto enum value; 0 = unspecified until analyzed.
    pub ids_flag: i32,
}
