# Phase 2 completion report

## Implemented

- Generic `EventQueue<E>`, `ScheduledEvent<E>`, millisecond `SimTime`, and
  `InterfaceRef` in rios-simulator. Equal-time events preserve insertion order;
  past scheduling, skipped events, and time/sequence overflow are rejected.
- `EthernetFrame`, `EtherType`, Ethernet II encoding/decoding, and multicast/
  broadcast addressing in rios-ethernet. In-process delivery moves owned payloads.
- Device ingress/egress validation, MTU checks, destination filtering, and actual
  TX/RX/drop counters. Switch ingress accepts unknown unicast without forwarding.
- New rios-topology crate owns `Lab`, links, YAML inventory, concrete frame/link/
  timer events, `EventOutcome`, and optional metadata-only `TraceRecord` values.
- Cable and peer administrative state determine carrier. Link generations prevent
  frames crossing an outage from arriving after the link recovers.
- `rios lab <topology.yaml>` and a lab shell with `devices`, `connect`, `links`,
  `trace on/off`, `step`, `run <absolute-ms>`, `help`, and `exit`.
- Both standalone and lab device connections use the existing IOS parser and
  executor. Device hostname edits preserve stable topology names. Terminal
  completion/help and Ctrl+D follow the current connection context.

## Files

New files:

```text
crates/rios-simulator/src/queue.rs
crates/rios-ethernet/src/frame.rs
crates/rios-device/src/ethernet.rs
crates/rios-topology/Cargo.toml
crates/rios-topology/src/lib.rs
crates/rios-topology/src/lab.rs
crates/rios-topology/src/delivery.rs
crates/rios-topology/src/yaml.rs
crates/rios-topology/tests/virtual_lab.rs
crates/rios-topology/examples/ethernet.rs
src/app.rs
src/shell.rs
examples/two-routers.yaml
docs/phase2-report.md
```

Updated workspace manifests/lockfile, simulator/Ethernet/device module roots,
CLI unavailable-feature wording, root terminal/main entrypoints, executable
integration tests, README, and architecture documentation. The Phase 1 report
remains a historical record.

## Validation

- `cargo fmt --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
- `cargo test --workspace`: PASS, 28 tests total, 0 failures (13 added).
- `cargo run -p rios-topology --example ethernet`: PASS, real virtual delivery:

```text
[00:00:00.000] R1:GigabitEthernet0/0 Tx 35 bytes
[00:00:00.001] R2:GigabitEthernet0/0 Rx 35 bytes
R2:GigabitEthernet0/0 received RIOS virtual Ethernet at 00:00:00.001
```

New tests cover event tie ordering and clock errors; Ethernet envelopes; payload
ownership preservation; repeated deterministic bidirectional delivery; counters;
link and port flaps; same-time cable changes; virtual timers; unicast filtering,
broadcast acceptance, MTU/disabled-port/no-link drops; switch ingress; YAML
validation; hardware identity protection; and a full two-router CLI lab session.
The original standalone session continues to pass. A terminal smoke check
verified `connect ?` with buffer restoration, device tab completion, connecting
to R1, Ctrl+D returning to `rios>`, and exiting the lab.

## Use

```sh
cargo run -- lab examples/two-routers.yaml
cargo run -p rios-topology --example ethernet
```

This environment's toolchain remains under `/tmp`. For example:

```sh
CARGO_HOME=/tmp/rios-cargo RUSTUP_HOME=/tmp/rios-rustup /tmp/rios-cargo/bin/cargo run -- lab examples/two-routers.yaml
```

The already-built executable is also available as `./target/debug/rios`.

## Limits and next step

Frames are injected through the Rust API/example; the CLI does not generate
protocol traffic yet. `trace on` enables collection for actual events, not a
fabricated path. ARP, IPv4, ping, per-device protocol debugging, and switching
remain unimplemented. 802.1Q is recognized as an EtherType but has no VLAN policy.
Links model fixed propagation delay, without bandwidth, FCS, padding, or loss.
Counter bytes are header plus payload; multicast group subscription is not yet
modeled. Startup snapshots remain in memory.

`with_device_mut` clones one device's metadata to validate identity/hardware
preservation before committing it. There are no packet buffers in that clone.
`run_until` returns a vector of outcomes; `step` provides incremental consumption.
Trace consumers must drain records to bound retained history. No OS network
interfaces, protocol sleeps, or per-device threads are used.

Next: Phase 3 ARP request/reply and cache timers, IPv4 packets, connected routes,
ICMP echo, and real ping on a directly connected link. Keep static multi-router
forwarding for Phase 4 and MAC forwarding for Phase 5.
