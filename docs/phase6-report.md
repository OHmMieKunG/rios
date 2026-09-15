# Phase 6 implementation report

Phase 6 adds VLAN-aware switching, 802.1Q trunks, and routing between access
VLANs.

Implemented:

- Validated `VlanId` values from 1 through 4094 and single-tag 802.1Q frame
  encoding/decoding.
- Structured VLAN database entries and per-port access/trunk configuration.
- IOS-style `vlan`, `name`, `switchport mode`, `switchport access vlan`, and
  `switchport trunk allowed vlan` commands with command-tree abbreviations.
- A VLAN configuration CLI mode and deterministic running/startup configuration
  rendering and replay.
- Access ingress classification, trunk tag removal, egress tagging, allowed-list
  filtering, and rejection of tagged access traffic and untagged trunk traffic.
- VLAN-scoped MAC learning, lookup, movement, display, and aging.
- Inter-VLAN IPv4 routing through separate router access links using the existing
  ARP, routing, forwarding, and ICMP implementation.
- A reusable `examples/vlan-routing.yaml` topology.

Validation:

- `cargo fmt --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
- `cargo test --workspace`: PASS, 43 tests, 0 failures.
- Tests cover VLAN CLI/configuration replay, tag round trips, access isolation,
  trunk tagging and untagging, trunk allow-list filtering, VLAN-scoped learning,
  and successful routed ping between VLANs.

Known limits: trunk ports require tags because native VLAN behavior is deferred.
There are no router subinterfaces, SVI forwarding, dynamic trunk negotiation,
QinQ, VTP, STP, or loop prevention. Inter-VLAN routing currently uses one
physical router interface per VLAN.

Next: Phase 7 simplified OSPFv2, with adjacency and protocol timers driven only
by simulator events.
