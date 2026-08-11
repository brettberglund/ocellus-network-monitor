//! CLI arguments parsed by [`clap`] into [`Config`] at startup.

use clap::Parser;

/// CLI configuration for the monitor agent.
#[derive(Debug, Clone, Parser)]
#[command(author, version, about)]
pub struct Config {
    /// Print available network interfaces and exit.
    #[arg(long)]
    pub list_devices: bool,

    /// Network interface to capture on (e.g. `eth0`, `\Device\NPF_{GUID}`).
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Optional BPF filter expression applied to the capture (e.g. `"tcp port 80"`).
    #[arg(short, long)]
    pub bpf_filter: Option<String>,

    /// mpsc channel capacity between the analyzer and gRPC sender (packets).
    #[arg(long, default_value_t = 1024)]
    pub channel_capacity: usize,

    /// gRPC ingestion endpoint (default: `http://127.0.0.1:50051`).
    #[arg(long, env = "GRPC_ADDR")]
    pub grpc_addr: Option<String>,

    /// Maximum [`PacketEvent`]s per [`PacketBatch`] before an early flush.
    #[arg(long)]
    pub grpc_batch_size: Option<usize>,

    /// Interval in milliseconds between periodic batch flushes.
    #[arg(long)]
    pub grpc_flush_ms: Option<u64>,

    /// Heartbeat send interval in seconds.
    #[arg(long)]
    pub heartbeat_interval_secs: Option<u64>,

    /// Logical agent identifier sent in every gRPC message. If omitted, a
    /// UUID is generated on first run and persisted to
    /// `~/.monitor-agent/agent_id` so restarts keep the same identity.
    #[arg(long)]
    pub agent_id: Option<String>,

    /// One-time registration token minted from the dashboard ("Add Agent").
    /// If set, the agent calls `RegisterAgent` once at startup before
    /// entering its normal heartbeat/packet-stream loops.
    #[arg(long, env = "REGISTER_TOKEN")]
    pub register_token: Option<String>,

    /// Bypass pcap; send synthetic packets directly to the gRPC stream (no privileges required).
    #[arg(long)]
    pub test_send: bool,

    /// Packets generated per tick in `--test-send` mode.
    #[arg(long)]
    pub test_packets_per_tick: Option<usize>,

    /// Tick interval in milliseconds in `--test-send` mode.
    #[arg(long)]
    pub test_tick_ms: Option<u64>,

    /// Stop after this many ticks in `--test-send` mode (`None` = run forever).
    #[arg(long)]
    pub test_max_ticks: Option<u64>,
}

impl Config {
    #[cfg(test)]
    pub fn testing(list_devices: bool, interface: Option<&str>, bpf_filter: Option<&str>) -> Self {
        Self {
            list_devices,
            interface: interface.map(str::to_string),
            bpf_filter: bpf_filter.map(str::to_string),
            channel_capacity: 64,
            grpc_addr: Some("http://127.0.0.1:50051".to_string()),
            grpc_batch_size: Some(10),
            grpc_flush_ms: Some(100),
            agent_id: Some("test-agent".to_string()),
            register_token: None,
            heartbeat_interval_secs: Some(10),
            test_send: true,
            test_packets_per_tick: Some(5),
            test_tick_ms: Some(100),
            test_max_ticks: Some(3),
        }
    }
}
