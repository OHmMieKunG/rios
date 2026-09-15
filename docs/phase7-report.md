# Phase 7 implementation report

Phase 7 adds a deterministic, single-area OSPFv2 implementation.

Implemented:

- A new `rios-routing` crate containing OSPF neighbor states, router LSAs, and
  checksummed OSPFv2 Hello and Link State Update wire messages.
- IPv4 protocol 89 and AllSPFRouters multicast transmission through normal
  simulated Ethernet links and switches.
- `router ospf <process-id>` and `network <address> <wildcard> area <area-id>`
  configuration through the command tree and structured running/startup state.
- `show ip ospf neighbor`, `show ip ospf interface`, and
  `show ip ospf database` from live protocol state.
- Hello and dead timers scheduled only on the simulation event queue: 10-second
  hello and 40-second dead intervals, with no sleeping threads or wall clock.
- Neighbor progression from Init to Full, sequence-numbered router LSAs,
  deterministic database flooding, shortest-hop SPF, and OSPF routes at
  administrative distance 110.
- Route withdrawal after neighbor expiry and use of learned routes by the
  existing ARP/IPv4/ICMP forwarding path.

Validation:

- `cargo fmt --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
- `cargo test --workspace`: PASS, 46 tests, 0 failures.
- A three-router integration test forms Full adjacencies, learns the remote
  transit network, completes a routed ping, fails a link, advances virtual time,
  and verifies route withdrawal.
- Wire tests round-trip and checksum Hello and Link State Update packets; CLI
  tests cover abbreviations, show commands, rendering, and replay.

Known limits: this phase supports one process and one area per device. Link cost
is one hop. It omits DR/BDR election, Database Description and Link State
Acknowledgment exchanges, retransmission lists, authentication, external routes,
summarization, virtual links, and explicit router-ID configuration. Database
updates periodically carry the known LSDB, which keeps deterministic educational
labs reliable without implementing the full OSPF reliable-flooding state machine.

Next: Phase 8 should begin with STP/RSTP because VLAN trunks currently have no
loop prevention. ACLs, DHCP, and NAT can follow as separate vertical slices.
