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
