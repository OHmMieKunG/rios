# RIOS — Rust IOS-like Network Simulator

An original, safe Rust network simulator for educational labs. RIOS is a
CLI-first application; its simulator crates remain independent of terminal,
SSH, and Telnet frontends. No Cisco binaries or proprietary internals are used.
The current compatibility baseline follows Cisco IOS XE 26.x behavior documented
for [Catalyst 9300 interfaces](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/26-x/configuration_guide/int_hw/b_26x_int_and_hw_9300_cg/configuring_interface_characteristics.html)
and [IPv4 routing](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/26-x/configuration_guide/rtng/b_26x_rtng_9300_cg/configuring_ip_unicast_routing.html).
Existing two-part interface names remain accepted, while current three-part names
such as `GigabitEthernet1/0/1` are also supported.
Phase 9 implements device configuration, an
IOS-style CLI, deterministic virtual links, ARP, IPv4 packets, connected and
static routes, multi-router forwarding, ICMP echo/error handling, and Ethernet
switching with dynamic MAC learning, VLANs, 802.1Q trunks, single-area OSPFv2,
deterministic per-VLAN spanning tree, and standard numbered IPv4 ACLs.
Phase 8 also includes deterministic DHCPv4 clients, directly attached servers,
and dynamic NAT overload for ICMP and UDP. Phase 9 exposes the same device CLI
engine through per-device SSH listeners.

## Run

Install a current stable Rust toolchain, then:

```sh
cargo run
```

The standalone device is R1 with GigabitEthernet0/0 and GigabitEthernet0/1.

```text
R1> enable
R1# conf t
R1(config)# hostname EDGE-R1
EDGE-R1(config)# int gi0/0
EDGE-R1(config-if)# ip address 10.0.0.1 255.255.255.0
EDGE-R1(config-if)# no shut
EDGE-R1(config-if)# end
EDGE-R1# sh ip int br
EDGE-R1# show running-config
EDGE-R1# wr mem
EDGE-R1# show startup-config
EDGE-R1# exit
```

An enabled physical port reports **up/down** until a connected virtual peer is also enabled and supplies
carrier. Administrative shutdown reports **administratively down/down**.
Startup configuration is an independent structured snapshot. In topology mode,
`write memory` persists it across process restarts; standalone mode persists it
when `RIOS_STATE_FILE` is set. The initial startup configuration is absent.

Non-terminal input uses the same parser and executor:

```sh
cargo run < examples/phase1-session.txt
```

Start one SSH listener per device, beginning at port 2001:

```sh
RIOS_SSH_HOST_KEY=.rios_host_key RIOS_SSH_PASSWORD=lab \
cargo run -- ssh examples/two-routers.yaml
ssh admin@127.0.0.1 -p 2001 # R1
ssh admin@127.0.0.1 -p 2002 # R2
```

An optional final argument changes the base port. `RIOS_SSH_USERNAME` defaults
to `admin`; a host-key path and either a password or authorized keys are
required. Listeners bind to loopback only. Each connection owns its CLI mode
while all connections operate on the same virtual lab. SSH supports contextual
`?` help, backspace, Ctrl+C, and Ctrl+Z.

Set `RIOS_SSH_HOST_KEY` to load a persistent OpenSSH private host key. If that
path does not exist, RIOS creates an Ed25519 key there with mode `0600` on Unix.
`RIOS_SSH_HOST_KEY_PASSWORD` unlocks an existing encrypted host key. Set
`RIOS_SSH_AUTHORIZED_KEYS` to an OpenSSH `authorized_keys` file. Per-key options
are rejected because RIOS does not implement their restrictions. An empty
`RIOS_SSH_PASSWORD` disables password login, allowing key-only access:

```sh
RIOS_SSH_HOST_KEY=.rios_host_key \
RIOS_SSH_AUTHORIZED_KEYS="$HOME/.ssh/authorized_keys" \
RIOS_SSH_PASSWORD= \
cargo run -- ssh examples/two-routers.yaml
```

SSH exec requests run one non-interactive User EXEC command and return a useful
process status for automation:

```sh
ssh admin@127.0.0.1 -p 2001 'show ip route'
```

Valid commands exit with status 0. Parser, executor, and simulator failures exit
with status 1 and retain their IOS-style diagnostic output.

For topology modes, `write memory` atomically persists every device's startup
configuration to `<topology>.rios-state.json`. `RIOS_STATE_FILE` overrides that
path. The versioned state is validated before application and loaded through the
same configuration engine on restart. Standalone mode persists only when
`RIOS_STATE_FILE` is set.

Build a lab entirely from the CLI, then save it as a reusable topology:

```sh
cargo run -- lab
```

```text
rios> spawn router R1 2
rios> spawn switch SW1 4
rios> spawn l3-switch CORE rj45 24 sfp+ 4 console 1
rios> link R1:GigabitEthernet0/0 SW1:GigabitEthernet0/1
rios> connect R1
R1> enable
R1# configure terminal
R1(config)# interface gi0/0
R1(config-if)# ip address 10.0.0.1 255.255.255.0
R1(config-if)# no shutdown
R1(config-if)# end
R1# exit
rios> save lab.yaml
```

`save` writes `lab.yaml` and its startup-configuration sidecar. Reopen the
complete lab with `cargo run -- lab lab.yaml`. `connect` with two endpoint names
is also accepted as a cable alias; `link` is the clearer spelling.

The optional spawn inventory accepts either one RJ45 port count or repeating
`<media> <count>` pairs. Media keywords are `rj45`, `sfp`, `sfp+`, `serial`, and
`console`, and all keywords accept unambiguous prefixes. RJ45 and SFP create
GigabitEthernet ports; SFP+ creates TenGigabitEthernet ports. Ethernet links
require matching media. Serial ports are represented in inventory but their
HDLC/PPP data plane is deferred. Console ports are management-only.

Layer 3 switch Ethernet ports start enabled in Layer 2 mode. `no switchport`
places a port in routed mode; `switchport mode access|trunk` returns it to Layer
2 mode. As on current Catalyst IOS XE, global `ip routing` enables transit
forwarding. VLAN interfaces provide routed SVI gateways when their VLAN has an
active access or trunk member.

For local legacy-client labs, start one Telnet listener per device beginning at
port 3001:

```sh
cargo run -- telnet examples/two-routers.yaml
telnet 127.0.0.1 3001 # R1
telnet 127.0.0.1 3002 # R2
```

An optional final argument changes the base port. Telnet binds only to loopback
and has no authentication; use SSH when access control or transport encryption
is required. SSH and Telnet share the same remote terminal and device-session
implementation.

History and arrow keys work in the terminal. Tab completes commands and existing
interface names. `?` displays contextual help without executing or losing the
current input. Ctrl+C cancels the input, Ctrl+Z returns configuration modes to
privileged EXEC, and Ctrl+D on an empty line closes the session. History is
session-local. `exit` closes from either EXEC mode and steps out of configuration
modes. `end` returns from configuration to privileged EXEC.

## Supported commands

| Mode | Commands |
| --- | --- |
| User EXEC | `enable`, `show interfaces`, `show interfaces status`, `show vlan brief`, `show ip interface brief`, `show ip route`, `show ip ospf neighbor|interface|database`, `show ip dhcp binding`, `show ip nat translations`, `show arp`, `show mac address-table`, `show spanning-tree`, `show access-lists`, `ping <ipv4>`, `exit` |
| Privileged EXEC | Operational commands above, `disable`, `configure terminal`, `show running-config`, `show startup-config`, `copy running-config startup-config`, `write memory`, `exit` |
| Global configuration | `hostname <name>`, `interface <name>`, `interface range <first>-<last>`, `vlan <id>`, `no vlan <id>`, `ip routing`, `no ip routing`, `router ospf <process-id>`, `ip dhcp pool <name>`, `ip route <network> <mask> <next-hop>`, `no ip route <network> <mask> <next-hop>`, `ip nat inside source list <1-99> interface <name> overload`, `access-list <1-99> permit|deny any|host <address>|<address> <wildcard>`, `exit`, `end` |
| VLAN configuration | `name <name>`, `vlan <id>`, `interface <name>`, `exit`, `end` |
| Router configuration | `network <address> <wildcard> area <area-id>`, `interface <name>`, `exit`, `end` |
| DHCP pool configuration | `network <address> <mask>`, `default-router <address>`, `interface <name>`, `exit`, `end` |
| Interface configuration | `description <text>`, `no description`, `ip address <address> <mask>`, `ip address dhcp`, `no ip address`, `ip access-group <1-99> in|out`, `ip nat inside|outside`, `switchport`, `switchport mode access|trunk`, `no switchport`, `switchport access vlan <id>`, `switchport trunk allowed vlan <list>`, `shutdown`, `no shutdown`, `interface <name>`, `exit`, `end` |
| Interface range configuration | `description <text>`, `no description`, `switchport`, `switchport mode access|trunk`, `no switchport`, `switchport access vlan <id>`, `switchport trunk allowed vlan <list>`, `shutdown`, `no shutdown`, `interface <name>`, `exit`, `end` |

Keywords accept unambiguous case-insensitive prefixes, including `conf t`,
`sh ip int br`, and `no shut`. `sh i` is ambiguous. Interface families also accept
prefixes: `int gi0/1`, `int gigabitEthernet 0/1`, `int lo0`, `int vl10`.
Every configuration mode accepts `do` before supported privileged EXEC `show`,
`ping`, and save commands while retaining the current configuration mode.
Physical ports must exist; Loopback0–65535 and Vlan1–4094 can be created.
Enabled loopbacks operate locally. An enabled VLAN interface becomes
operational when its VLAN has an active switchport. GigabitEthernet,
TenGigabitEthernet, Serial, and Console hardware
families are recognized. Assigning an IPv4 address validates dotted decimal
syntax and contiguous masks, including /0, /31 and /32.

`ping <ipv4>`, `show ip route`, `show arp`, and `show ip arp` use live simulated
state. Packet, ARP, and ICMP debug commands remain recognized but unavailable;
use lab-shell `trace on` for packet metadata. Ping reports `U` for an ICMP
destination unreachable and `T` for time exceeded.

## Virtual labs

```sh
cargo run -- lab examples/two-routers.yaml
cargo run -- lab examples/two-routers.yaml < examples/phase3-session.txt
cargo run -- lab examples/three-routers.yaml
cargo run -- lab examples/switched-lan.yaml
cargo run -- lab examples/vlan-routing.yaml
cargo run -- lab examples/stp-triangle.yaml
cargo run -- lab examples/dhcp-lan.yaml
cargo run -- lab examples/nat-overload.yaml
```

```text
rios> devices
rios> connect R1
R1> enable
R1# conf t
R1(config)# int gi0/0
R1(config-if)# no shut
R1(config-if)# end
R1# exit
rios> connect R2
```

Enable R2's linked port in the same way. Both ports then report protocol up.
`exit` or Ctrl+D from a device returns to the lab shell; `exit` at `rios>` closes
the process. Lab names such as R1 stay stable even after `hostname EDGE`.

Lab commands: `spawn`, `devices`, `connect <name>`, `link`, `unlink <link-id>`,
`link-state <link-id> up|down`, `links`, `save`, `trace on|off`, `step`,
`run <absolute-milliseconds>`, `help`, and `exit`. Lab completion and `?`
help are available. Device and lab commands accept unique abbreviations; for
example, `sp rou R1` and `dev`. Simulated time advances only through `step` or
`run`.

The YAML file declares device types (`router`, `switch`, `host`), interface names,
and pairs of endpoints. `delay_ms` is optional and defaults to 1. Ports begin
administratively down. Unknown fields, duplicate devices/interfaces, missing
endpoints, logical-interface links, and multiple cables on a port are rejected.
The loader uses [serde-saphyr](https://docs.rs/serde-saphyr/latest/serde_saphyr/)
with only its deserialization feature enabled.

Enabled switch ports learn source MAC addresses, flood broadcast and unknown
unicast traffic, and forward learned unicast traffic. Dynamic entries expire
after five minutes of virtual time and are visible with `show mac address-table`.
Access ports carry one configured VLAN untagged. Trunks use 802.1Q tags and can
restrict forwarding with an allowed VLAN list. Native VLAN traffic is deferred.
Switches exchange configuration BPDUs on virtual-time timers. Each VLAN elects
a root bridge and blocks redundant paths; `show spanning-tree` displays the live
roles and states.

Routers support ordered standard numbered IPv4 ACLs. Interface bindings filter
packets inbound after IPv4 decoding or outbound before Ethernet transmission.
Rules use source addresses and wildcard masks, accept `any` and `host`, and end
with an implicit deny. Denials increment interface drop counters and tracing
reports them as ACL drops.

DHCP clients and directly attached router pools exchange real BOOTP/DHCP options
inside UDP/IPv4 broadcasts. Allocation order, four-message handshakes, retries,
one-hour lease expiry, and reacquisition use virtual time. Leased addresses feed
the normal connected-route, default-route, ARP, OSPF, and ping paths. Server
bindings are visible with `show ip dhcp binding`.

Dynamic NAT overload uses a standard ACL to select inside sources and the
configured outside interface address as the global address. ICMP identifiers
and UDP source ports are translated deterministically, replies use the reverse
mapping, and entries expire after 60 seconds of virtual inactivity. Active
mappings are visible with `show ip nat translations`.

Exercise the raw virtual Ethernet API independently of IP protocols:

```sh
cargo run -p rios-topology --example ethernet
```

```text
[00:00:00.000] R1:GigabitEthernet0/0 Tx 35 bytes
[00:00:00.001] R2:GigabitEthernet0/0 Rx 35 bytes
R2:GigabitEthernet0/0 received RIOS virtual Ethernet at 00:00:00.001
```

The Rust `Lab::transmit` API moves a frame into the queue; `Lab::step` returns the
received frame to its consumer. No OS network transmission is involved. Counter
byte totals include the 14-byte Ethernet header, without FCS or padding.

To exercise Phase 3, configure both ends of a direct link in the same subnet,
then ping from either device:

```text
R1# ping 10.0.0.2
Type escape sequence to abort.
Sending 5 ICMP Echos to 10.0.0.2, timeout is 1 second:
!!!!!
Success rate is 100 percent (5/5), round-trip min/avg/max = 2/2/2 ms
R1# show arp
Protocol  Address          Age  Hardware Addr     Interface
Internet  10.0.0.2          0  02:00:00:02:00:01 GigabitEthernet0/0
R1# show ip route
Codes: C - connected, S - static, O - OSPF

C    10.0.0.0/24 is directly connected, GigabitEthernet0/0
```

The first ping performs ARP request/reply before sending ICMP. Later pings reuse
the four-hour virtual-time ARP entry. Five unanswered requests advance only the
simulation clock and report 0 percent. IPv4 and ICMP checksums are validated.

See the [Phase 9 report](docs/phase9-report.md) for results and limits.

## Architecture

See [architecture](docs/architecture.md) for ownership and dependency boundaries
and the [Phase 1 report](docs/phase1-report.md) for the file inventory and results.
The workspace contains ten library crates plus the `rios` executable. Command
parsing never mutates device state. Device APIs validate mutations. Running
configuration is structured, with deterministic rendering. The public
`rios_cli::load_configuration` API atomically merges configuration commands via
the same executor; failures roll back all changes. It is an API, not a disk-load
CLI command. Omitted settings retain their existing values.

Application logging uses `tracing`; enable it with `RUST_LOG=debug cargo run`.
Set `RIOS_LOG_FORMAT=json` for structured JSON logs. SSH and Telnet accept
`RIOS_MAX_SESSIONS` (default 128) and `RIOS_IDLE_TIMEOUT_SECS` (default 900).
Commands are limited to 4096 bytes. SIGINT and SIGTERM stop listeners and notify
active remote sessions.
Packet tracing, topology loading, static forwarding, ARP, ICMP echo/error
handling, VLAN switching, trunks, and physical-link inter-VLAN routing are
implemented. OSPF uses virtual-time protocol events and real simulated multicast
packets. Spanning tree uses the same deterministic event queue to prevent Layer
2 loops. Standard IPv4 ACLs filter the shared forwarding path. DHCP runs through
UDP/IPv4 broadcasts and virtual timer events. Dynamic PAT uses the same IPv4 and
transport encoders. The terminal, stdin, and SSH frontends share one device-line
execution path. There are no per-device OS threads.

## Check

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Tests cover parsing, help/completion, mode restrictions, carrier state, MAC and
IPv4 validation, configuration round trips and rollback, saved snapshot
independence, isolation, and the actual binary session.

See the [production runbook](docs/production.md) for the supported deployment
scope, secure startup, state recovery, and remaining operational limits.
