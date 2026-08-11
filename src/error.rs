//! Error types for the packet capture pipeline.

use thiserror::Error;

/// Errors that can occur during packet capture setup or the capture loop.
#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("Failed to list network devices: {0}")]
    DeviceList(pcap::Error),

    #[error("Interface '{0}' not found. Check the name and permissions.")]
    InterfaceNotFound(String),

    #[error("No default network device found.")]
    NoDefaultDevice,

    #[error("failed to open device: {0}")]
    DeviceOpen(pcap::Error),

    #[error("Failed to activate capture: {0}")]
    Activate(pcap::Error),

    #[error("Failed to compile BPF filter: {0}")]
    FilterCompile(pcap::Error),

    #[error("Packet capture error: {0}")]
    Capture(pcap::Error),
}
