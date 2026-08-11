# Monitor Agent

Monitor agent is the program run inline with the network for traffic to be monitored

# Notes
Linux and macOS are untested as of 3/5/26

## Registering an agent (recommended: Docker)

The dashboard's "Add Agent" button mints a one-time registration token and
generates a copy-pasteable `docker run` command, e.g.:

```
docker run -d --name monitor-agent --restart unless-stopped \
  --network host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -e RUST_LOG=info -e GRPC_ADDR=http://<api-gateway-host>:50051 -e REGISTER_TOKEN=<token> \
  monitor-agent:latest
```

`--network host` is required (Linux only) so the container can see the
host's real network interfaces; `NET_ADMIN`/`NET_RAW` grant the raw-socket
capture access `--privileged` would otherwise be needed for. The token is
single-use and short-lived — request a new one from the dashboard if it
expires before the container starts. `RUST_LOG=info` is required for
`docker logs` to show anything past the initial `monitor-agent starting...`
line — without it, tracing's default filter suppresses all output even
though the agent is registering and capturing normally.

To build the image locally: `docker build -t monitor-agent:latest .`

## Using docker (manual / no registration)

Set environment variable (windows example)
`$env:RUST_LOG="info"`

Run tests
`docker build --target tester .`

Run with specific interface
`docker compose run --rm monitor-agent --interface eth0`

## Setup without docker:
1. Ensure rust is installed 
2. Ensure Npcap/libpcap is installed (including the SDK)
3. Run the command 'cargo build'
4.  (Windows)
5. Normal Execution and some tests require privileges (run terminal as admin or use sudo)

## Running monitor-agent (Windows):
Set env variable `$env:RUST_LOG="info"` or "debug"

See Interfaces
`cargo run -- --list-devices`

Normal Execution (privileges)
`cargo run -- --interface "\Device\NPF_{YOUR-GUID-HERE}"`

With Filter (privileges)
`cargo run -- --interface "\Device\NPF_{YOUR-GUID-HERE}" --bpf-filter "tcp"`

Testing Capture (no privileges)
`cargo test capture -- --nocapture`

Testing Capture (privileges)
`cargo test capture -- --include-ignored --nocapture`

## Running monitor-agent (Linux):
See Interfaces
`ip link show`

Normal Execution
`sudo RUST_LOG=info cargo run -- --interface eth0`

With Filter (privileges)
`sudo cargo run -- --interface "eth0" --bpf-filter "tcp"`

Testing Capture (no privileges)
`cargo test capture -- --nocapture`

Testing Capture (privileges)
`sudo cargo test capture -- --include-ignored --nocapture`

## Running monitor-agent (macOS): 
See Interfaces
`ifconfig`

Normal Execution
`sudo RUST_LOG=info cargo run --interface en0`

With Filter (privileges)
`sudo cargo run -- --interface "en0" --bpf-filter "tcp"`

Testing Capture (no privileges)
`cargo test capture -- --nocapture`

Testing Capture (privileges)
`sudo cargo test capture -- --include-ignored --nocapture`