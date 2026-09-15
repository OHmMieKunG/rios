# Phase 3 completion report

Phase 3 adds real ARP, IPv4, and ICMP behavior over the deterministic Phase 2
engine. `ping` now sends actual Ethernet frames; no CLI output is fabricated.

Implemented:

- `rios-protocol` with Ethernet/IPv4 ARP request/reply and checksummed ICMP echo
  request/reply messages.
- IPv4 packet encode/decode, header checksum validation, normalized networks,
  route sources/entries, routing tables, and longest-prefix lookup.
- Connected routes derived from configured, operational interfaces.
- Per-device dynamic ARP caches with four-hour virtual-time aging.
- Automatic ARP learning/replies and local IPv4/ICMP echo replies on received
  frames.
- Five-probe deterministic `Lab::ping`, one-second virtual deadlines, cache
  reuse, self-ping, failure output, and IOS-style summaries.
- Live `show arp`, `show ip arp`, and `show ip route` output through the existing
  typed CLI executor. `SimulationRequest` preserves the CLI/network boundary.

Validation:

- `cargo fmt --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
- `cargo test --workspace`: PASS, 36 tests, 0 failures.
- A CLI integration test configures two routers, verifies their connected route,
  completes a five-reply ping, then verifies the learned ARP entry.
- Network tests prove ARP-before-ICMP ordering, 2 ms RTT over two 1 ms link
  traversals, ARP reuse, deterministic timeouts, no-route handling, and counters.
- Unit tests cover IPv4 and ICMP checksums, packet validation, ARP wire format,
  ARP aging, route normalization, and longest-prefix selection.

Known limits: Phase 3 routes only directly connected traffic and responds only
for an address on the receiving interface. There is no IPv4 forwarding, static
route configuration, TTL decrement, ICMP error generation, fragmentation,
IPv4 options, proxy ARP, duplicate-address detection, or switch forwarding.
Specialized `debug packet/arp/icmp` remains unavailable; lab `trace on` provides
real frame metadata. These belong in the next relevant vertical slices.

Next: Phase 4 static routes and multi-router forwarding, including TTL decrement,
ICMP destination unreachable, and ICMP time exceeded.
