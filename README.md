# Monitor Agent

Monitor-Agent is a part of Ocellus, a service being built that allows users to analyze traffic and view packet data using a dashboard. 
This agent is to be run in the users network and and registered to the service to view analytics such as flagged packets and events.
Monitor-Agent views all packet data and only looks for signs of threat actors or malicious activity. Feel free to view what data is 
taken from packets for analysis. There is an IDS engine that runs within the agent, it does require time (30 mins) to set up a baseline to reduce
the chance of false positives.

# Disclaimer
AI is used in all parts of development. I do run many tests to validate the code works but I understand if that is a dealbreaker.

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
