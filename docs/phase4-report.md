# Phase 4 completion report

Phase 4 adds static IPv4 routing and router forwarding over the deterministic
event engine.

Implemented:

- `ip route <network> <mask> <next-hop>` in the global configuration command
  tree, including abbreviations, contextual help, structured configuration,
  rendering, and replay.
- Operational static routes whose next hop resolves through an active connected
  route, with administrative distance 1 and longest-prefix lookup.
- A shared IPv4 egress path for originated packets, forwarded packets, echo
  replies, and ICMP errors. It resolves next-hop ARP or queues the packet while
  deterministic ARP resolution runs.
- Router-only multi-hop forwarding with TTL decrement and checksum regeneration.
- Checksummed ICMP destination-unreachable and time-exceeded messages that quote
  the original IPv4 header and first eight payload bytes.
- Ping result markers `U` and `T` and a three-router example topology.

Validation:

- `cargo fmt --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
- `cargo test --workspace`: PASS, 39 tests, 0 failures.
- Integration tests prove static forwarding across two routed links, exact
  deterministic RTTs, TTL expiry, remote unreachable reporting, static-route
  rendering, and configuration replay.

Known limits: static routes support one IPv4 next hop per destination prefix and
one-level resolution through connected routes. There are no interface-only or
floating static routes, ECMP, route deletion, fragmentation, proxy ARP, ICMP
redirects, or control-plane routing protocols. Pending packets use a bounded
virtual timeout and a linear queue.

Next: Phase 5 Ethernet switching with MAC learning, broadcast and unknown
unicast flooding, learned unicast forwarding, and virtual-time MAC aging.
