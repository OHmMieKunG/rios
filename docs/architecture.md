# RIOS architecture — Phase 9

RIOS implements original IOS-style behavior; it contains no Cisco software.

## Ownership and dependency direction

```text
binary → CLI → device → config → IPv4 / Ethernet / simulator primitives
binary → topology → device / Ethernet / simulator
topology → protocol / IPv4
device / topology → routing → IPv4 / simulator
device / topology → switching → Ethernet / simulator
device → protocol / IPv4
```

Device also depends on Ethernet addressing and frame validation. The simulator
core is independent of Ethernet, devices, topology, and CLI. No cycles or empty
future protocol crates are introduced.

`Device` owns inventory, runtime interface state, and structured running/startup
configurations. Interface configuration lives only in RunningConfig, keyed by
InterfaceId. Runtime interfaces hold counters and physical carrier.
StartupConfig is an independent in-memory snapshot. Device APIs validate before
mutation; ordered maps make output deterministic.

Each frontend connection owns its CLI mode. A mode-aware command tree produces
typed commands without mutation; the executor invokes Device APIs. The same
tree supplies help and completion. Configuration replay uses this executor on a
candidate device and commits only if the whole input succeeds.

## Simulation

`EventQueue<E>` owns virtual milliseconds and a stable (time, insertion sequence)
BinaryHeap. Checked arithmetic rejects past scheduling and time/sequence
overflow. Stepping moves time to the next event; idle advances cannot skip
pending events. The payload has no ordering or Clone requirement.

`Lab` owns devices, point-to-point links, and concrete frame, link-state, and
timer events. `transmit` validates the egress port, schedules delivery, then
accounts TX. `step` validates the ingress port, accounts RX or a drop, and returns
the frame to its consumer. ARP, local ICMP, and IPv4 forwarding handlers consume
the same delivered frame before it is returned, scheduling resulting traffic
through `transmit`. Point-to-point delivery moves payloads without cloning;
switch flooding makes one logical frame copy per egress port. `run_until` returns
all outcomes through an inclusive deadline; callers that want bounded retention
can consume events individually with `step`.

Switches classify untagged access ingress into the configured VLAN and decode one
802.1Q tag on trunk ingress. Learning and lookup are keyed by VLAN and MAC.
Broadcast, multicast, and unknown-unicast frames are cloned only to eligible
ports in that VLAN; trunk egress adds a tag and access egress remains untagged.
Allowed lists filter trunk traffic. Learned unicasts use one port and destinations
learned on the ingress port are filtered. Entries expire lazily after five
virtual minutes, so no wall clock or background task affects determinism.

Each VLAN runs an independent spanning-tree instance. Switches exchange
configuration BPDUs through scheduled simulator events, elect a root bridge,
and derive root, designated, and alternate port roles from deterministic bridge
and port identifiers. Data traffic only uses forwarding ports; BPDUs continue
through blocked ports so topology changes can reconverge after max age.

Carrier is up only when the cable and both ports are enabled. Changes to carrier
increment a link generation; an old frame is discarded even if the link has
recovered by its arrival time. Equal-time cable changes and deliveries follow
insertion order. Logical interfaces cannot terminate Ethernet cables.

Optional trace collection retains only time, endpoint, direction/drop reason,
EtherType, and length. Callers drain records with `take_trace`; disabling tracing
releases retained records. Application diagnostics use tracing separately.

## Topology and frontend

YAML declares device inventories and links, with optional `delay_ms` (default 1).
IDs are assigned in sorted device-name order and interface declaration order.
Each port has at most one cable. Parsing and construction finish before a lab is
returned, so malformed topologies never become partially active. YAML handling
uses serde-saphyr with deserialization only; external include/property features
are not enabled.

The root frontend owns one lab and an optional connected session. Standalone
operation creates the familiar two-port R1. `rios lab <file.yaml>` starts in the
lab shell. Terminal and stdin use the same application path; device connections
always call the existing IOS parser/executor. Stable topology names remain usable
when hostnames change.

Topology frontends associate the YAML inventory with a versioned JSON sidecar.
Only structured startup configuration rendered as replayable commands is
stored; runtime protocol state remains ephemeral. Writes use a same-directory
temporary file, file synchronization, atomic rename, and directory
synchronization on Unix. Reads are size-bounded, fully parsed, and validated on
cloned devices before any saved configuration is applied. Unknown removed
devices are ignored, allowing topology contraction without destructive state
migration.

`rios ssh <file.yaml> [base-port]` binds one loopback listener per device in
stable topology-name order. Each SSH channel owns an independent `CliSession`.
All handlers share the same lab behind a Tokio mutex and call the same
output-returning device-session function used by the local frontend. The mutex
serializes complete commands, preserving deterministic simulation ownership;
SSH transport tasks never become per-device simulation threads.

`rios telnet <file.yaml> [base-port]` uses the same ownership model and shared
remote terminal adapter. A small streaming decoder removes Telnet command,
option, and subnegotiation bytes before CLI input processing. The server
negotiates echo and suppress-go-ahead, binds only to loopback, and deliberately
provides no authentication because Telnet cannot protect credentials in transit.

Device edits use `with_device_mut` to preserve identity/hardware and synchronize
carrier afterward. It clones the edited device's metadata for rollback protection;
no packet payload is stored there. A restricted editor can replace this if large
inventories make interactive edits costly.

## IPv4 protocols

`rios-ipv4` owns IPv4 wire encoding, checksum validation, normalized networks,
route types, and longest-prefix selection. `Device::routing_table` derives
connected routes from operational interfaces and installs configured static
routes when their next hop has a connected resolution. Route text is a view of
that structured table.

`rios-protocol` owns Ethernet/IPv4 ARP, ICMP echo and errors, UDP datagrams, and
BOOTP/DHCPv4 messages. Each device
has a dynamic ARP cache aged against `SimTime`; the cache never consults wall
time. `Lab::ping` selects a connected or static route, resolves next-hop ARP when
needed, then sends five checksum-valid echoes through the normal Ethernet event
path. Routers decrement TTL and forward through the same route/ARP path;
unresolved forwarded packets wait in a bounded pending queue. It processes
events to each one-second virtual deadline and renders results from received echo
replies. Local-interface ping completes at zero simulated milliseconds.

The CLI executor returns a typed `SimulationRequest::Ping`; the root application
hands it to the owning lab. This keeps terminal/parser code free of network state
mutation and avoids coupling `rios-cli` to topology internals.

## OSPF

`rios-routing` owns OSPF wire messages and protocol types. Devices own neighbor,
LSDB, sequence, and calculated-route state; the CLI only renders or changes
structured configuration. Topology events originate multicast Hello and Link
State Update packets every ten virtual seconds and expire neighbors after forty
virtual seconds. Received packets traverse ordinary IPv4/Ethernet delivery.

Each router originates a router LSA containing enabled connected networks and
Full adjacencies. Newer LSAs merge by origin and sequence. A deterministic
shortest-hop search calculates the first Full neighbor for each remote origin;
the resulting routes enter the same longest-prefix table as connected and static
routes with administrative distance 110.

## IPv4 access lists

Structured standard numbered ACLs live in `rios-config`; generated configuration
is only a view of their ordered entries and interface bindings. `rios-device`
evaluates source addresses with IOS wildcard masks and applies the implicit final
deny. The topology layer calls that policy once after IPv4 ingress decoding and
once before the shared IPv4 Ethernet transmission path, covering local,
forwarded, and ARP-queued packets without CLI coupling. Denials increment the
affected interface drop counter and appear in optional packet traces.

## DHCP

DHCP pool and client intent are structured configuration. Server bindings,
outstanding offers, and client leases are runtime device state. The topology
layer drives Discover, Offer, Request, and Ack messages as UDP/IPv4 Ethernet
broadcasts and schedules retry and lease-expiry events on the virtual clock.
Servers reserve the first available host address deterministically, excluding
configured interface and gateway addresses. A client lease supplies the same
effective interface-address API used by connected routes, ARP, OSPF, display,
and ping; an offered default router installs a runtime default route.

## NAT overload

Interface inside/outside roles and the ACL/interface overload rule are structured
configuration. Runtime PAT mappings belong to the device and expire against
virtual time. During forwarding, reverse translation runs after inbound ACLs and
before local-address/routing decisions; source translation runs after the egress
route is selected and before the shared outbound ACL/transmission path. IPv4
headers are re-encoded by the packet layer, while ICMP identifiers and UDP ports
are decoded, rewritten, and re-encoded by their protocol owners so checksums and
lengths remain valid.

## Remaining boundary

Static next-hop resolution is one level through connected routes; there is no
recursive static routing, ECMP, fragmentation, or ICMP redirect. Ethernet omits
FCS, preamble, padding, serialization delay, native VLAN behavior, QinQ, link
aggregation, and advanced loop protection. Inter-VLAN routing uses separate
physical router access links; router subinterfaces and SVI forwarding are not
implemented. ARP retries use the ping operation's virtual deadline rather than a
background neighbor state machine.
OSPF is single-area and uses periodic database flooding; DR election, reliable
LSA exchange phases, authentication, and external routes are deferred.
Spanning tree uses immediate blocking/forwarding transitions and a
simulator-specific Ethernet II envelope for standard configuration BPDU fields;
listening/learning states, RSTP, tunable costs, PortFast, and guards are deferred.
ACL support is limited to numbered standard IPv4 lists (1-99); named and extended
ACLs, sequence editing, remarks, counters per entry, and removal commands are
deferred.
DHCP uses a fixed one-hour lease and supports directly attached clients only.
Renewal/rebinding, relay agents, exclusions, reservations, conflict detection,
NAK, DNS options, and persistent lease storage are deferred. UDP emits the legal
zero checksum for IPv4.
NAT supports dynamic interface overload for ICMP echo and UDP. Static NAT,
address pools, TCP, ICMP errors, fragments, hairpinning, overlapping realms,
configurable timeouts, and translation statistics are deferred.
SSH credentials, an optional persistent host-key path, and an optional
authorized-keys path come from environment variables; listeners are
loopback-only. Host keys at configured missing paths are generated with private
permissions. Authorized keys are parsed at startup and matched by key data;
unsupported per-key restrictions fail startup instead of being ignored. SSH
exec requests execute one User EXEC command through the shared device-session
path, translate its result to process status 0 or 1, and close the channel. Tab
completion, remote history, and a topology web frontend are deferred.

## Link transmission model

The canonical `SimTime` unit is now microseconds. CLI `run` and YAML `delay_ms`
remain milliseconds; Rust callers can use `SimTime::from_millis` explicitly.
A configured `bandwidth` adds integer, ceiling-rounded serialization of the
encoded frame bytes (without preamble, IFG, or FCS). Omitted bandwidth preserves
legacy instantaneous serialization. Each direction has its own bounded FIFO;
`queue_packets` includes the frame currently serializing. Propagation does not
occupy the transmitter. Jitter samples a symmetric interval around the configured
delay, clamps negative propagation to zero, and preserves FIFO arrival order.
Loss is sampled in integer millionths from a lab-owned seeded SplitMix64 stream.
Drops consume serialization time. An outage resets queue reservations and
invalidates outstanding traffic by generation. Removed link IDs are never reused.
`links` displays transmission policy, queue occupancy, and directional counters;
`show interfaces` displays reason-specific drop counters.

## Packet capture

`capture start <new-file.pcapng> [device <name> | interface <device:port>]`
starts an observational capture; `capture stop` flushes and closes it. The writer
streams Section Header, Interface Description, and Enhanced Packet blocks using
little-endian PCAPNG, Ethernet link type, microsecond timestamps, interface names,
and inbound/outbound packet flags. It follows the public
[PCAPNG format specification](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html).
Packets are the actual physical-interface TX/RX bytes, including VLAN headers;
logical SVI observations are excluded to avoid synthetic duplicates. TX records
use the admission time, while RX records include serialization and propagation.
The file contains both ends of each successful cable transfer unless filtered.
Capture never consumes RNG samples or schedules events. File creation refuses
overwrite. A bounded writer buffer streams to disk, capped at 1 GiB per capture;
write failures disable further recording, are available through `capture_error`,
and are reported by `capture stop` without aborting simulated forwarding.

## Routed subinterfaces and native VLANs

Physical Ethernet parents can own routed subinterfaces such as `Gi0/0.10`.
The interface stores a parent ID and structured dot1q encapsulation. Configure
`encapsulation dot1q 10 [native]` before using the interface for traffic.
Subinterfaces share the parent's MAC address, have independent IP/ACL/OSPF
configuration and counters, and require both their own administrative state and
the parent's operational state. A parent allows one mapping per VLAN and at
most one native mapping. The CLI uses `(config-subif)#`; configuration replay
uses the same validation paths.

On ingress the physical port classifies the tag before ARP, IP, ACL, and routing.
Egress uses the parent cable and its queue, with a VLAN tag unless native is set.
Switch trunks default to native VLAN 1; `switchport trunk native vlan <id>`
selects the untagged VLAN. Allowed VLAN lists apply to native traffic too.
The integration fixture `examples/router-on-a-stick.yaml` covers tagged/native
routing, subinterface ACLs, shutdown, ARP, and OSPF on the shared physical link.
Public behavioral reference:
[Catalyst subinterfaces](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/26-x/configuration_guide/vlan/b_26x_vlan_9300_cg/configuring_layer_3_subinterfaces.html).

## Named and extended access lists

`ip access-list standard|extended <name-or-number>` selects a sequenced ACL.
Entries accept optional sequence numbers, `permit`, `deny`, and `remark`;
`no <sequence>` removes an entry. Extended rules match `ip`, `icmp`, `tcp`, or
`udp`, source and destination wildcards, and numeric transport port operators
`eq`, `range`, `lt`, `gt`, and `neq`. Source and destination port tests are
independent. Interface `ip access-group <name-or-number> in|out` applies the
same policy pipeline used by legacy numbered standard lists. Numeric extended
ACLs also support `access-list <number> permit|deny ...`.

First matching rule wins; remarks do not match and every list has implicit deny.
`show access-lists` displays match counters. `log` records matching packet metadata
in a bounded 256-entry device buffer (`take_acl_logs`), with cumulative per-rule
log counts. Lists and entries are capped at 4096 each. Editing an entry resets its
counters. Legacy standard lists retain their serialized representation until
selected through named-list configuration, which promotes their existing rules.

## Simulated TCP

The TCP codec validates header length, options, and the IPv4 pseudoheader checksum
using the public [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) wire format.
A device owns bounded listener and connection tables; the lab exposes `tcp_listen`,
`tcp_connect`, `tcp_send`, `tcp_read`, and `tcp_close`. SYN/SYN-ACK/ACK, payload,
FIN/ACK, and RST traverse normal IPv4 routing, neighbor resolution, ACLs, and link
queues. No host OS sockets participate.

The initial connection engine uses stop-and-wait with at most one outstanding
segment of up to 1200 payload bytes. Busy sends return explicit backpressure.
Receive buffers are limited to 65535 bytes, duplicate bytes are acknowledged
without delivery, and reads advertise the reopened window. Per-device limits are
1024 listeners and 1024 connections. Virtual timers retransmit with bounded
exponential backoff, expire idle connections after 300 seconds, and retain
TIME-WAIT for 120 seconds. This is a deliberately limited educational TCP stack:
sliding windows, congestion algorithms, SACK, simultaneous open, option negotiation,
and out-of-order reassembly remain beyond this initial implementation.

### NAT expansion

NAT now supports TCP/UDP PAT, ICMP echo identifier translation, static address
mapping, static TCP/UDP port mapping, and bounded dynamic address pools. TCP
rewrites recompute the IPv4 pseudoheader checksum. Pool selection and PAT ports
are deterministic; exhausted allocation drops traffic with `NatFailed`.
Outside interfaces answer ARP for static global addresses and active allocations.
The wire behavior follows [traditional NAT](https://www.rfc-editor.org/rfc/rfc3022).

Configure `ip nat pool NAME FIRST LAST netmask MASK`,
`ip nat inside source list 1 pool NAME [overload]`, or
`ip nat inside source static [tcp|udp] ...`. Existing interface overload syntax
continues working. `show ip nat statistics` reports cumulative accounting;
`clear ip nat translation *` removes dynamic entries while preserving static
configuration. Rendered configuration replays through the command engine.

Dynamic transport entries expire after 60 seconds of inactivity, using simulation
time. One dynamic source policy is active per device. ICMP error quotation
rewriting, application gateways, hairpin NAT, and fragmented transport translation
remain unsupported. Tests cover TCP sessions in both directions through PAT,
outside-initiated static port forwarding, proxy ARP, ICMP through static/pool NAT,
pool exhaustion, expiration, and CLI/configuration replay.

### DHCP relay and lease lifecycle

DHCP uses BOOTP `giaddr` and simulated UDP 67/68 for routed relay, following
[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131). Transit routers forward DHCP
normally; only local/broadcast destinations enter DHCP processing. Relay replies
return to the client-facing interface. Clients renew by unicast at T1, broadcast
to rebind at T2, and remove the address/default route at expiration. Stale timers
cannot remove renewed leases.

Pools support excluded ranges, minute-granularity leases, DNS/domain options, and
MAC reservations (`host ADDRESS MASK`, `hardware-address MAC`). Configure relay
with `ip helper-address SERVER`. An ARP probe checks each offer before REQUEST;
a conflict generates DECLINE, quarantines the address for ten simulated minutes,
and delays client retry. Invalid requested addresses receive NAK. Malformed
packets/options are rejected without stopping the lab.

Tables are bounded (1,024 pools, 8,192 offers/bindings, 4,096 exclusion ranges);
offers and bindings expire. This implementation supports one helper per interface
and Ethernet MAC identity. It uses one 200 ms offer probe; full RFC 5227 probing,
option 82, DHCP authentication, DHCPINFORM, and multiple helper destinations remain
outside this milestone. Tests cover remote allocation through a transit router,
options, reservations, NAK, renewal, rebind, expiry, duplicate address detection,
configuration replay, and malformed packet decoding.

### EtherChannel and LACP

Physical Ethernet ports can join `channel-group N mode on|active|passive`.
The logical `Port-channelN` owns routed or access/trunk configuration; MAC
learning and STP use that logical identity. Egress selects exactly one available
member with a deterministic source/destination MAC hash. Each physical link
retains its own serialization queue. A bundle supports up to eight same-speed
members and survives individual member failure.

LACP uses version 1 Slow Protocol Ethernet frames (0x8809), actor/partner TLVs,
partner identity checks, synchronization, collecting, and distributing flags.
Active ports initiate negotiation; passive pairs remain suspended. Partner system
and key selection prevents merging incompatible peers. One-second periodic events
expire silent partners against a three-second timeout; expiry is processed at the
next periodic tick. Protocol semantics follow public
[IEEE link aggregation descriptions](https://1.ieee802.org/tsn/802-1ax-rev/).
LACP is consumed on physical members, independently of logical/STP forwarding.

`show etherchannel summary`, `show lacp neighbor`, and
`show interfaces port-channel1` report structured runtime state. Configuration
renders/replays through the same command engine. Tests cover codec validation,
active/passive negotiation, passive/passive inactivity, peer timeout, routed
failover, VLAN trunk forwarding, one-copy broadcast flooding, and logical MAC
learning. Marker protocol, configurable slow timers, minimum-links, resilient
hashing, and multi-chassis aggregation are not implemented.

### Spanning-tree hardening

Classic STP now uses 15-second listening and learning intervals before forwarding.
This deliberately replaces immediate startup forwarding. Configure
`spanning-tree portfast` on host/router-facing edge ports when immediate
forwarding is wanted; receiving a BPDU removes operational edge status.
Existing topology files still load. Tests for unrelated packet forwarding now
explicitly select PortFast or wait for convergence.

`spanning-tree mode rapid-pvst` enables per-VLAN RSTP with proposal/agreement
BPDUs. A proposed root transition synchronizes other nonedge designated ports
before sending agreement. Alternate ports discard user traffic. Legacy neighbors
use classic BPDU transmission and timed fallback. Bridge priority, port priority,
and explicit path cost affect selection. Root Guard holds a superior downstream
port root-inconsistent; BPDU Guard error-disables the port until a shutdown/no
shutdown cycle. These follow public
[Cisco RSTP behavior descriptions](https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/24062-146.html).

BPDUs now use IEEE 802.3 length fields and LLC instead of the old private
EtherType, so captures expose recognizable STP/RSTP packets. VLAN instances use
802.1Q encapsulation; proprietary PVST SNAP encapsulation and MST regions are
not modeled. User ingress is checked before SVI delivery, closing the previous
blocked-port bypass. MAC entries flush on local topology/state changes. Full
TCN/TC propagation is not yet modeled. Protocol state advances with simulated
time and periodic events; no sleeping threads are involved.

Unit tests cover BPDU/LLC codecs, timed transitions, synchronization, priorities,
costs, and guard recovery. Topology tests verify independent VLAN roots, rapid
triangle failover, single-copy flooding, and blocked ingress isolation from SVIs.
