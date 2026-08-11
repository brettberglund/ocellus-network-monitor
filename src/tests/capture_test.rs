use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use crate::capture::{run_capture, system_time_from_timeval};
use crate::config::Config;
use crate::error::CaptureError;
use crate::ring_buffer::RingBuffer;

fn find_loopback_device() -> Option<String> {
    let devices = pcap::Device::list().ok()?;

    #[cfg(target_os = "windows")]
    {
        devices
            .into_iter()
            .find(|d| {
                d.desc
                    .as_deref()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains("loopback")
            })
            .map(|d| d.name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        devices
            .into_iter()
            .find(|d| d.name == "lo" || d.name == "lo0")
            .map(|d| d.name)
    }
}

#[test]
fn test_invalid_interface_returns_error() {
    let config = Config::testing(false, Some("no_such_interface_xyz"), None);
    let shutdown = Arc::new(AtomicBool::new(false));
    let buffer = RingBuffer::new(64);

    let result = run_capture(&config, buffer, shutdown);
    assert!(
        matches!(result, Err(CaptureError::InterfaceNotFound(_))),
        "Expected InterfaceNotFound, got: {:?}",
        result
    );
}

#[test]
fn test_system_time_from_timeval_epoch() {
    let t = system_time_from_timeval(0, 0);
    assert_eq!(t, UNIX_EPOCH);
}

#[test]
fn test_system_time_form_timeval_with_micros() {
    let t = system_time_from_timeval(1, 500_000);
    let expected = UNIX_EPOCH + Duration::from_millis(1500);
    assert_eq!(t, expected);
}

#[test]
#[ignore = "requires loopback interface and libpcap privileges"]
fn test_bad_bpf_filter_returns_error() {
    let iface =
        find_loopback_device().expect("No loopback device found - is Npcap/libpcap installed?");
    let config = Config::testing(false, Some(&iface), Some("not a valid filter %%%"));
    let shutdown = Arc::new(AtomicBool::new(false));
    let buffer = RingBuffer::new(64);

    let result = run_capture(&config, buffer, shutdown);
    assert!(
        matches!(result, Err(CaptureError::FilterCompile(_))),
        "Expected FilterCompile, got: {:?}",
        result
    );
}

#[test]
#[ignore = "requires loopback interface and libpcap privileges"]
fn test_capture_starts_and_shuts_down_cleanly() {
    let iface =
        find_loopback_device().expect("No loopback device found - is Npcap/libpcap installed?");

    #[cfg(target_os = "windows")]
    let filter = None;
    #[cfg(not(target_os = "windows"))]
    let filter = Some("icmp");

    let config = Config::testing(false, Some(&iface), filter);
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);

    let buffer = RingBuffer::new(256);
    let drain_buf = buffer.clone_handle();

    // Drain packets to prevent the ring buffer from stalling capture
    std::thread::spawn(move || while drain_buf.pop_blocking().is_some() {});

    let handle = std::thread::spawn(move || run_capture(&config, buffer, shutdown_clone));

    std::thread::sleep(Duration::from_millis(1500));
    shutdown.store(true, Ordering::Relaxed);

    let result = handle.join().expect("Capture thread panicked");
    assert!(result.is_ok(), "Capture returned error: {:?}", result);
}
