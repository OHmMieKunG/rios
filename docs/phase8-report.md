# Phase 8 implementation report

Phase 8 begins with deterministic, VLAN-aware 802.1D-style spanning tree so
redundant switch links no longer create frame storms. It also includes IPv4
access control and DHCP client/server slices.
The phase now also includes dynamic NAT overload/PAT.

Implemented:

- A new `rios-switching` crate with configuration BPDU wire fields, bridge-group
  multicast addressing, port roles, port states, and standard timer values.
- One spanning-tree instance per configured VLAN, deterministic bridge/root
  election, root/designated/alternate roles, and forwarding/blocking states.
- BPDU generation every two virtual seconds and received-information expiry
  after the 20-second maximum age, entirely through simulator events.
- BPDU transmission through access and tagged trunk ports using the existing VLAN
  classification path. BPDUs are consumed by switches and never learned or
  forwarded as user traffic.
- Data-plane enforcement on ingress and egress, plus MAC-table cleanup when a
  port transitions to blocking.
- Live `show spanning-tree` output through the IOS-style command tree.
- A reusable three-switch triangle topology at `examples/stp-triangle.yaml`.
- Structured standard numbered ACLs (1-99), ordered permit/deny entries, IOS
  wildcard matching, `any` and `host` syntax, and implicit final deny.
- Inbound and outbound interface bindings enforced for local and forwarded IPv4
  packets, including packets released after ARP resolution.
- ACL denials recorded in interface drop counters and optional packet traces.
- `show access-lists`, configuration rendering, and atomic configuration replay.
- UDP datagrams and standards-shaped BOOTP/DHCPv4 messages with Discover, Offer,
  Request, and Ack support.
- Structured DHCP pools, interface client configuration, deterministic address
  reservation, runtime bindings, and `show ip dhcp binding`.
- Virtual-time client retries, fixed one-hour lease expiration, and automatic
  reacquisition without sleeps or device threads.
- DHCP-provided connected and default routes shared by ARP, OSPF, display, and
  ping through the normal effective interface-address path.
- A reusable router/switch/two-client lab at `examples/dhcp-lan.yaml`.
- Structured NAT inside/outside roles and ACL-selected outside-interface
  overload configuration with IOS-style rendering and replay.
- Dynamic ICMP identifier and UDP port mappings, reverse translation, checksum
  regeneration through existing encoders, 60-second virtual-time aging, and
  `show ip nat translations`.
- A reusable private-host/router/outside-host lab at
  `examples/nat-overload.yaml`.

Validation:

- `cargo fmt --check`: PASS.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: PASS.
- `cargo test --workspace`: PASS, 57 tests, 0 failures.
- The integration test converges a VLAN across a three-switch physical loop,
  verifies exactly one alternate/blocking port, proves a broadcast reaches its
  destination once, fails the direct root link, advances through maximum age,
  and proves traffic succeeds once after reconvergence.
- A wire test validates configuration BPDU round trips.
- CLI coverage validates parsing, abbreviations, rendering, show output, and
  configuration replay. A routed topology test verifies inbound and outbound
  ACL drops across real ARP, IPv4, and ICMP paths.
- DHCP and UDP wire tests validate round trips. CLI coverage validates pool mode,
  abbreviations, rendering, and replay. A switched topology test proves two
  clients receive distinct deterministic leases, install routes, ping through
  normal ARP/ICMP, expire, and reacquire their addresses.
- The NAT topology test proves ICMP succeeds without an outside route to the
  private subnet and validates mapping aging. A device test proves UDP source
  and destination ports survive a PAT round trip. CLI coverage validates NAT
  abbreviations, rendering, show output, and replay.

Known limits: this is classic STP behavior with immediate forwarding after role
selection; Listening/Learning transition delays and RSTP handshakes are not yet
modeled. Bridge priority, path cost, PortFast, BPDU Guard, Root Guard, and
per-port STP configuration are not configurable. The Ethernet core currently
carries standard BPDU fields inside a simulator-specific Ethernet II EtherType
because IEEE 802.3 LLC envelopes are not represented yet.
ACLs are standard numbered source filters only. Named and extended ACLs,
protocol/port matching, sequence editing, remarks, per-entry counters, and
removal commands are deferred.
DHCP uses a fixed one-hour lease and directly attached clients. Renewal,
rebinding, relay agents, exclusions, reservations, conflict detection, NAK, DNS
options, and persistent bindings are deferred. UDP uses the legal zero checksum
for IPv4.
NAT supports dynamic interface overload for ICMP echo and UDP. Static mappings,
address pools, TCP, ICMP-error translation, fragments, hairpinning, configurable
timeouts, and statistics are deferred.

Next: begin Phase 9 with one remote frontend over the existing shared CLI engine;
SSH should precede Telnet.
