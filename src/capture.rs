//! pcap capture loop: opens the interface, applies an optional BPF filter, and pushes
//! parsed [`RawPacket`]s into the [`RingBuffer`] for the IDS analyzer.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;

use pcap::{Capture, Device};
use tracing::{error, info};

use crate::config::Config;
use crate::error::CaptureError;
use crate::raw_packet::{LinkType, RawPacket, TransportMeta};
use crate::ring_buffer::RingBuffer;

static PACKET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Open the capture interface described by `config` and loop until `shutdown` is set.
///
/// Each captured packet is parsed inline and pushed to `buffer`; the ring buffer will
/// drop the oldest packet silently if it fills up. A 1 s pcap timeout keeps the
/// shutdown check responsive without busy-spinning.
pub fn run_capture(
    config: &Config,
    buffer: RingBuffer<RawPacket>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), CaptureError> {
    let device = resolve_device(config.interface.as_deref())?;
    let interface = device.name.clone();
    info!("Capturing on interface: {}", interface);

    let mut cap = Capture::from_device(device)
        .map_err(CaptureError::DeviceOpen)?
        .timeout(1000)
        .promisc(true)
        .snaplen(65535)
        .buffer_size(10 * 1024 * 1024)
        .open()
        .map_err(CaptureError::Activate)?;

    let link_type = pcap_linktype_to_enum(cap.get_datalink());

    if let Some(filter) = &config.bpf_filter {
        info!("Applying BPF filter: \"{}\"", filter);
        cap.filter(filter, true)
            .map_err(CaptureError::FilterCompile)?;
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!("Shutdown signal received, stopping capture.");
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                let data = packet.data.to_vec();
                let orig_len = packet.header.len;
                let cap_len = packet.header.caplen;
                let transport = parse_transport(&data, link_type);

                let raw = RawPacket {
                    data,
                    orig_len,
                    cap_len,
                    is_truncated: cap_len < orig_len,
                    interface: interface.clone(),
                    link_type,
                    timestamp: system_time_from_timeval(
                        packet.header.ts.tv_sec as u64,
                        packet.header.ts.tv_usec as u32,
                    ),
                    transport,
                    packet_id: PACKET_COUNTER.fetch_add(1, Ordering::Relaxed),
                    ids_score: 0.0,
                    ids_flag: 0,
                };

                let dropped = buffer.push(raw);
                #[allow(clippy::manual_is_multiple_of)]
                // is_multiple_of is still unstable (rust#128101)
                if dropped > 0 && dropped % 1000 == 0 {
                    eprintln!(
                        "[capture] Warning: {} packets dropped from ring buffer",
                        dropped
                    );
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => {
                info!("Packet source exhausted.");
                break;
            }
            Err(e) => {
                error!("Fatal capture error: {:?}", e);
                return Err(CaptureError::Capture(e));
            }
        }
    }

    if let Ok(stats) = cap.stats() {
        info!(
            received = stats.received,
            dropped = stats.dropped,
            if_dropped = stats.if_dropped,
            "Capture session ended."
        );
    }
    Ok(())
}

fn pcap_linktype_to_enum(lt: pcap::Linktype) -> LinkType {
    match lt.0 {
        1 => LinkType::Ethernet,
        12 => LinkType::RawIp,
        0 => LinkType::Loopback,
        n => LinkType::Unknown(n as u32),
    }
}

/// Extract transport metadata at capture time.
/// Parses Ethernet/VLAN/IPv4/IPv6 headers and TCP/UDP/ICMP where present.
fn parse_transport(data: &[u8], link_type: LinkType) -> Option<TransportMeta> {
    let mut eth_src_mac: Option<[u8; 6]> = None;
    let mut vlan_id: Option<u16> = None;

    // --- Layer 2 ---
    let ip_offset = match link_type {
        LinkType::Ethernet => {
            if data.len() < 14 {
                return None;
            }
            // src MAC bytes 6..12
            if let Ok(mac) = data[6..12].try_into() {
                eth_src_mac = Some(mac);
            }
            let mut offset = 12usize;
            let mut etype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            // 802.1Q VLAN tag
            if etype == 0x8100 && data.len() > offset + 4 {
                let tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
                vlan_id = Some(tci & 0x0FFF);
                offset += 2;
                etype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
            }
            if etype != 0x0800 && etype != 0x86DD {
                return None; // not IPv4 or IPv6
            }
            offset
        }
        LinkType::Loopback => 4,
        LinkType::RawIp => 0,
        _ => return None,
    };

    let ip = data.get(ip_offset..)?;
    let version = (ip.first()? >> 4) & 0xF;

    match version {
        4 => parse_ipv4(ip, ip_offset, eth_src_mac, vlan_id),
        6 => parse_ipv6(ip, ip_offset, eth_src_mac, vlan_id),
        _ => None,
    }
}

fn parse_ipv4(
    ip: &[u8],
    ip_offset: usize,
    eth_src_mac: Option<[u8; 6]>,
    vlan_id: Option<u16>,
) -> Option<TransportMeta> {
    if ip.len() < 20 {
        return None;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }

    let ttl = ip[8];
    let proto = ip[9];
    let flags_frag = u16::from_be_bytes([ip[6], ip[7]]);
    let ip_flags = ((flags_frag >> 13) & 0x07) as u8; // 3 flag bits
    let ip_frag_offset = (flags_frag & 0x1FFF) * 8; // convert to bytes

    let src_ip = std::net::IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst_ip = std::net::IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));

    let tl = ip.get(ihl..)?;
    let payload_offset = ip_offset + ihl;

    let (src_port, dst_port, tcp_flags, icmp_type, icmp_code, app_payload_offset) = match proto {
        6 if tl.len() >= 20 => {
            // TCP: data offset in header[12] upper nibble
            let data_off = ((tl[12] >> 4) as usize) * 4;
            (
                Some(u16::from_be_bytes([tl[0], tl[1]])),
                Some(u16::from_be_bytes([tl[2], tl[3]])),
                Some(tl[13]),
                None,
                None,
                payload_offset + data_off,
            )
        }
        17 if tl.len() >= 8 => (
            Some(u16::from_be_bytes([tl[0], tl[1]])),
            Some(u16::from_be_bytes([tl[2], tl[3]])),
            None,
            None,
            None,
            payload_offset + 8,
        ),
        1 if tl.len() >= 4 => (
            None,
            None,
            None,
            Some(tl[0]),
            Some(tl[1]),
            payload_offset + 8,
        ),
        _ => (None, None, None, None, None, payload_offset),
    };

    Some(TransportMeta {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: proto,
        tcp_flags,
        ttl,
        ip_flags,
        ip_frag_offset,
        icmp_type,
        icmp_code,
        eth_src_mac,
        vlan_id,
        payload_offset: app_payload_offset,
    })
}

fn parse_ipv6(
    ip: &[u8],
    ip_offset: usize,
    eth_src_mac: Option<[u8; 6]>,
    vlan_id: Option<u16>,
) -> Option<TransportMeta> {
    if ip.len() < 40 {
        return None;
    }
    let proto = ip[6];
    let ttl = ip[7]; // hop limit
    let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&ip[8..24]).ok()?,
    ));
    let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(
        <[u8; 16]>::try_from(&ip[24..40]).ok()?,
    ));
    let tl = ip.get(40..)?;
    let payload_offset = ip_offset + 40;

    let (src_port, dst_port, tcp_flags, icmp_type, icmp_code, app_payload_offset) = match proto {
        6 if tl.len() >= 20 => {
            let data_off = ((tl[12] >> 4) as usize) * 4;
            (
                Some(u16::from_be_bytes([tl[0], tl[1]])),
                Some(u16::from_be_bytes([tl[2], tl[3]])),
                Some(tl[13]),
                None,
                None,
                payload_offset + data_off,
            )
        }
        17 if tl.len() >= 8 => (
            Some(u16::from_be_bytes([tl[0], tl[1]])),
            Some(u16::from_be_bytes([tl[2], tl[3]])),
            None,
            None,
            None,
            payload_offset + 8,
        ),
        58 if tl.len() >= 4 => (
            None,
            None,
            None,
            Some(tl[0]),
            Some(tl[1]),
            payload_offset + 8,
        ),
        _ => (None, None, None, None, None, payload_offset),
    };

    Some(TransportMeta {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: proto,
        tcp_flags,
        ttl,
        ip_flags: 0,
        ip_frag_offset: 0,
        icmp_type,
        icmp_code,
        eth_src_mac,
        vlan_id,
        payload_offset: app_payload_offset,
    })
}

fn resolve_device(interface: Option<&str>) -> Result<Device, CaptureError> {
    match interface {
        Some(name) => {
            let devices = Device::list().map_err(CaptureError::DeviceList)?;
            devices
                .into_iter()
                .find(|d| d.name == name)
                .ok_or_else(|| CaptureError::InterfaceNotFound(name.to_string()))
        }
        None => Device::lookup()
            .map_err(CaptureError::DeviceList)?
            .ok_or(CaptureError::NoDefaultDevice),
    }
}

/// Convert a pcap `timeval` (seconds + microseconds) to a [`SystemTime`].
/// `pub(crate)` so capture tests can construct [`RawPacket`]s with realistic timestamps.
pub(crate) fn system_time_from_timeval(secs: u64, micros: u32) -> SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    UNIX_EPOCH + Duration::new(secs, micros * 1000)
}
