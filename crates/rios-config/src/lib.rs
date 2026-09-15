//! Structured configuration and deterministic IOS-style rendering.
#![forbid(unsafe_code)]
mod acl;
mod ipv6;
pub use ipv6::{Ipv6InterfacePolicy, Ipv6StaticRoute};
mod nat;
mod ospf;
pub use ospf::{OspfDefaultRoute, OspfInterfaceConfig, OspfNetworkType, OspfRedistribute};
mod stp;
pub use acl::{AccessList, AclEntry, AclId, AclKind, AclProtocol, AddressMatch, PortMatch};
pub use nat::{NatPool, NatPoolRule, NatTransport, StaticNat};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::InterfaceId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    net::Ipv4Addr,
};
pub use stp::{StpConfig, StpPortConfig};

pub use rios_ethernet::VlanId;

/// Operator-selected interface state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminState {
    Down,
    Up,
}
/// Authoritative configuration for one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceConfig {
    #[serde(default)]
    pub ipv6: Ipv6InterfacePolicy,
    #[serde(default)]
    pub ospf: OspfInterfaceConfig,
    #[serde(default)]
    pub spanning_tree: StpPortConfig,
    #[serde(default)]
    pub channel_group: Option<ChannelMembership>,
    #[serde(default)]
    pub port_channel: Option<u16>,
    #[serde(default)]
    pub named_access_group_in: Option<AclId>,
    #[serde(default)]
    pub named_access_group_out: Option<AclId>,
    /// Physical Ethernet parent of a routed subinterface.
    #[serde(default)]
    pub parent: Option<InterfaceId>,
    #[serde(default)]
    pub dot1q: Option<Dot1qEncapsulation>,
    pub name: String,
    pub description: String,
    pub admin_state: AdminState,
    pub ipv4: Option<Ipv4InterfaceConfig>,
    /// Obtain runtime IPv4 configuration through DHCP.
    pub dhcp_client: bool,
    #[serde(default)]
    pub helper_address: Option<Ipv4Addr>,
    pub mtu: u16,
    /// Whether this hardware port can switch between Layer 2 and Layer 3 modes.
    #[serde(default)]
    pub switchport_capable: bool,
    /// Layer 2 switch-port policy; absent on routed devices.
    pub switchport: Option<SwitchportConfig>,
    /// Standard IPv4 ACL applied to received packets.
    pub access_group_in: Option<AccessListId>,
    /// Standard IPv4 ACL applied before transmission.
    pub access_group_out: Option<AccessListId>,
    /// NAT classification for routed IPv4 traffic.
    pub nat_role: Option<NatRole>,
}

/// VLAN classification and native (untagged) egress on a routed subinterface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dot1qEncapsulation {
    pub vlan: VlanId,
    pub native: bool,
}

/// Static aggregation or LACP participation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelMode {
    On,
    Active,
    Passive,
}
/// Physical member assignment; the logical port owns forwarding policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMembership {
    pub number: u16,
    pub mode: ChannelMode,
}
/// NAT side assigned to a router interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatRole {
    Inside,
    Outside,
}

/// Dynamic source NAT using one outside interface address with overload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatOverloadConfig {
    pub access_list: AccessListId,
    pub outside_interface: InterfaceId,
}

/// IOS standard numbered access-list identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccessListId(u8);

impl AccessListId {
    /// Create a standard ACL number in the IOS range 1-99.
    pub fn new(value: u8) -> Option<Self> {
        (1..=99).contains(&value).then_some(Self(value))
    }

    /// Numeric ACL identifier.
    pub fn get(self) -> u8 {
        self.0
    }
}

/// Permit or deny result attached to an access-list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessListAction {
    Permit,
    Deny,
}

/// Direction in which an interface applies an access list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessListDirection {
    In,
    Out,
}

/// One source-address rule in a standard numbered IPv4 ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardAccessListEntry {
    pub action: AccessListAction,
    pub source: Ipv4Addr,
    pub wildcard: Ipv4Addr,
}

impl StandardAccessListEntry {
    /// Match an IPv4 source address using IOS wildcard-mask semantics.
    pub fn matches(self, source: Ipv4Addr) -> bool {
        let mask = !u32::from(self.wildcard);
        u32::from(source) & mask == u32::from(self.source) & mask
    }
}

/// Operational mode of a physical switch port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwitchportMode {
    Access,
    Trunk,
}

/// VLAN policy attached to a switch interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchportConfig {
    #[serde(default = "default_native_vlan")]
    pub native_vlan: VlanId,
    pub mode: SwitchportMode,
    pub access_vlan: VlanId,
    /// `None` means every configured VLAN is allowed.
    pub trunk_allowed_vlans: Option<BTreeSet<VlanId>>,
}
fn default_native_vlan() -> VlanId {
    VlanId::DEFAULT
}

impl Default for SwitchportConfig {
    fn default() -> Self {
        Self {
            native_vlan: VlanId::DEFAULT,
            mode: SwitchportMode::Access,
            access_vlan: VlanId::DEFAULT,
            trunk_allowed_vlans: None,
        }
    }
}

/// One VLAN database entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlanConfig {
    pub name: String,
}

/// One IOS-style OSPF network selection statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OspfNetworkConfig {
    pub address: std::net::Ipv4Addr,
    pub wildcard: std::net::Ipv4Addr,
    pub area: u32,
}

impl OspfNetworkConfig {
    /// Whether this statement enables OSPF on an interface address.
    pub fn matches(self, address: std::net::Ipv4Addr) -> bool {
        let wildcard = u32::from(self.wildcard);
        (u32::from(address) & !wildcard) == (u32::from(self.address) & !wildcard)
    }
}

/// Single OSPFv2 process configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OspfConfig {
    pub process_id: u16,
    pub networks: BTreeSet<OspfNetworkConfig>,
    #[serde(default)]
    pub router_id: Option<Ipv4Addr>,
    #[serde(default)]
    pub passive_interfaces: BTreeSet<InterfaceId>,
    #[serde(default)]
    pub default_information: Option<OspfDefaultRoute>,
    #[serde(default)]
    pub redistribute_static: Option<OspfRedistribute>,
}

/// Stable identifier for a configured DHCP pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DhcpPoolId(pub u16);

/// One IOS-style DHCP server pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpPoolConfig {
    #[serde(default = "default_lease_seconds")]
    pub lease_seconds: u32,
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    #[serde(default)]
    pub domain_name: Option<String>,
    #[serde(default)]
    pub reserved_address: Option<Ipv4Addr>,
    #[serde(default)]
    pub hardware_address: Option<rios_ethernet::MacAddress>,
    pub name: String,
    pub network: Option<Ipv4Network>,
    pub default_router: Option<Ipv4Addr>,
}
fn default_lease_seconds() -> u32 {
    3600
}
/// Current structured configuration; runtime counters and carrier are separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningConfig {
    #[serde(default)]
    pub ipv6_unicast_routing: bool,
    #[serde(default)]
    pub ipv6_static_routes: BTreeSet<Ipv6StaticRoute>,
    #[serde(default)]
    pub spanning_tree: StpConfig,
    #[serde(default)]
    pub dhcp_excluded: BTreeMap<Ipv4Addr, Ipv4Addr>,
    #[serde(default)]
    pub static_nat: BTreeSet<StaticNat>,
    #[serde(default)]
    pub nat_pools: BTreeMap<String, NatPool>,
    #[serde(default)]
    pub nat_pool_rule: Option<NatPoolRule>,
    #[serde(default)]
    pub named_access_lists: BTreeMap<AclId, AccessList>,
    pub hostname: String,
    /// Global IPv4 forwarding switch used by multilayer switches.
    #[serde(default)]
    pub ip_routing: bool,
    pub interfaces: BTreeMap<InterfaceId, InterfaceConfig>,
    /// One configured next hop per static destination prefix.
    pub static_routes: BTreeMap<Ipv4Network, std::net::Ipv4Addr>,
    /// Configured VLAN database keyed by VLAN identifier.
    pub vlans: BTreeMap<VlanId, VlanConfig>,
    /// Optional single OSPFv2 process.
    pub ospf: Option<OspfConfig>,
    /// Standard numbered IPv4 access lists, evaluated in insertion order.
    pub access_lists: BTreeMap<AccessListId, Vec<StandardAccessListEntry>>,
    /// DHCP server pools keyed by stable configuration identifier.
    pub dhcp_pools: BTreeMap<DhcpPoolId, DhcpPoolConfig>,
    /// Optional dynamic source NAT overload rule.
    pub nat_overload: Option<NatOverloadConfig>,
}
/// An independent saved configuration, absent until explicitly saved.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupConfig(pub Option<RunningConfig>);
impl RunningConfig {
    /// Render stable configuration suitable for configuration-engine replay.
    pub fn render(&self) -> String {
        let mut out = format!("hostname {}\n!\n", self.hostname);
        if self.ipv6_unicast_routing {
            out.push_str("ipv6 unicast-routing\n!\n");
        }
        if self.ip_routing {
            out.push_str("ip routing\n!\n");
        }
        if self.spanning_tree.rapid {
            out.push_str("spanning-tree mode rapid-pvst\n");
        }
        for (vlan, priority) in &self.spanning_tree.priorities {
            writeln!(out, "spanning-tree vlan {} priority {priority}", vlan.get()).unwrap();
        }
        for (id, vlan) in &self.vlans {
            if *id == VlanId::DEFAULT && vlan.name.is_empty() {
                continue;
            }
            writeln!(out, "vlan {}", id.get()).unwrap();
            if !vlan.name.is_empty() {
                writeln!(out, " name {}", vlan.name).unwrap();
            }
            out.push_str("!\n");
        }
        for (id, entries) in &self.access_lists {
            for entry in entries {
                writeln!(
                    out,
                    "access-list {} {} {} {}",
                    id.get(),
                    match entry.action {
                        AccessListAction::Permit => "permit",
                        AccessListAction::Deny => "deny",
                    },
                    entry.source,
                    entry.wildcard
                )
                .unwrap();
            }
            out.push_str("!\n");
        }
        for list in self.named_access_lists.values() {
            writeln!(out, "ip access-list {} {}", list.kind, list.name).unwrap();
            for (sequence, entry) in &list.entries {
                writeln!(out, " {sequence} {}", entry.render(list.kind)).unwrap();
            }
            out.push_str("!\n");
        }
        for (first, last) in &self.dhcp_excluded {
            writeln!(out, "ip dhcp excluded-address {first} {last}").unwrap();
        }
        for pool in self.dhcp_pools.values() {
            writeln!(out, "ip dhcp pool {}", pool.name).unwrap();
            if let Some(network) = pool.network {
                writeln!(out, " network {} {}", network.address(), network.mask()).unwrap();
            }
            if let Some(address) = pool.reserved_address
                && let Some(network) = pool.network
            {
                writeln!(out, " host {address} {}", network.mask()).unwrap();
            }
            if let Some(mac) = pool.hardware_address {
                writeln!(out, " hardware-address {mac}").unwrap();
            }
            if pool.lease_seconds != 3600 {
                writeln!(
                    out,
                    " lease {} {} {}",
                    pool.lease_seconds / 86400,
                    pool.lease_seconds % 86400 / 3600,
                    pool.lease_seconds % 3600 / 60
                )
                .unwrap();
            }
            if !pool.dns_servers.is_empty() {
                writeln!(
                    out,
                    " dns-server {}",
                    pool.dns_servers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
                .unwrap();
            }
            if let Some(name) = &pool.domain_name {
                writeln!(out, " domain-name {name}").unwrap();
            }
            if let Some(router) = pool.default_router {
                writeln!(out, " default-router {router}").unwrap();
            }
            out.push_str("!\n");
        }
        let mut interfaces: Vec<_> = self.interfaces.values().collect();
        interfaces.sort_by_key(|config| config.port_channel.is_some());
        for config in interfaces {
            writeln!(out, "interface {}", config.name).unwrap();
            if let Some(encapsulation) = config.dot1q {
                writeln!(
                    out,
                    " encapsulation dot1q {}{}",
                    encapsulation.vlan.get(),
                    if encapsulation.native { " native" } else { "" }
                )
                .unwrap();
            }
            if !config.description.is_empty() {
                writeln!(out, " description {}", config.description).unwrap();
            }
            if config.switchport_capable && config.switchport.is_none() {
                out.push_str(" no switchport\n");
            }
            if let Some(helper) = config.helper_address {
                writeln!(out, " ip helper-address {helper}").unwrap();
            }
            config.ipv6.render(&mut out);
            config.ospf.render(&mut out);
            let stp = &config.spanning_tree;
            if stp.priority != 128 {
                writeln!(out, " spanning-tree port-priority {}", stp.priority).unwrap();
            }
            if let Some(cost) = stp.cost {
                writeln!(out, " spanning-tree cost {cost}").unwrap();
            }
            if stp.portfast {
                out.push_str(" spanning-tree portfast\n");
            }
            if stp.bpdu_guard {
                out.push_str(" spanning-tree bpduguard enable\n");
            }
            if stp.root_guard {
                out.push_str(" spanning-tree guard root\n");
            }
            if config.dhcp_client {
                out.push_str(" ip address dhcp\n");
            } else if let Some(ip) = config.ipv4 {
                writeln!(out, " ip address {} {}", ip.address(), ip.mask()).unwrap();
            }
            if let Some(id) = config.access_group_in {
                writeln!(out, " ip access-group {} in", id.get()).unwrap();
            }
            if let Some(id) = config.access_group_out {
                writeln!(out, " ip access-group {} out", id.get()).unwrap();
            }
            for (direction, id) in [
                ("in", config.named_access_group_in),
                ("out", config.named_access_group_out),
            ] {
                if let Some(list) = id.and_then(|id| self.named_access_lists.get(&id)) {
                    writeln!(out, " ip access-group {} {direction}", list.name).unwrap();
                }
            }
            if let Some(role) = config.nat_role {
                writeln!(
                    out,
                    " ip nat {}",
                    match role {
                        NatRole::Inside => "inside",
                        NatRole::Outside => "outside",
                    }
                )
                .unwrap();
            }
            if let Some(switchport) = &config.switchport {
                match switchport.mode {
                    SwitchportMode::Access => {
                        out.push_str(" switchport mode access\n");
                        writeln!(
                            out,
                            " switchport access vlan {}",
                            switchport.access_vlan.get()
                        )
                        .unwrap();
                    }
                    SwitchportMode::Trunk => {
                        out.push_str(" switchport mode trunk\n");
                        if switchport.native_vlan != VlanId::DEFAULT {
                            writeln!(
                                out,
                                " switchport trunk native vlan {}",
                                switchport.native_vlan.get()
                            )
                            .unwrap();
                        }
                        if let Some(allowed) = &switchport.trunk_allowed_vlans {
                            let list = allowed
                                .iter()
                                .map(|id| id.get().to_string())
                                .collect::<Vec<_>>()
                                .join(",");
                            writeln!(out, " switchport trunk allowed vlan {list}").unwrap();
                        }
                    }
                }
            }
            if let Some(group) = config.channel_group {
                writeln!(
                    out,
                    " channel-group {} mode {}",
                    group.number,
                    match group.mode {
                        ChannelMode::On => "on",
                        ChannelMode::Active => "active",
                        ChannelMode::Passive => "passive",
                    }
                )
                .unwrap();
            }
            writeln!(
                out,
                " {}\n!",
                if config.admin_state == AdminState::Up {
                    "no shutdown"
                } else {
                    "shutdown"
                }
            )
            .unwrap();
        }
        for route in &self.ipv6_static_routes {
            let interface = route
                .interface
                .and_then(|id| self.interfaces.get(&id))
                .map(|c| format!("{} ", c.name))
                .unwrap_or_default();
            writeln!(
                out,
                "ipv6 route {} {}{}\n!",
                route.prefix, interface, route.next_hop
            )
            .unwrap();
        }
        for (prefix, next_hop) in &self.static_routes {
            writeln!(
                out,
                "ip route {} {} {}\n!",
                prefix.address(),
                prefix.mask(),
                next_hop
            )
            .unwrap();
        }
        for (name, pool) in &self.nat_pools {
            if let Ok(network) = Ipv4Network::new(pool.first, pool.prefix_len) {
                writeln!(
                    out,
                    "ip nat pool {name} {} {} netmask {}",
                    pool.first,
                    pool.last,
                    network.mask()
                )
                .unwrap();
            }
        }
        for rule in &self.static_nat {
            match rule {
                StaticNat::Address { local, global } => {
                    writeln!(out, "ip nat inside source static {local} {global}").unwrap()
                }
                StaticNat::Port {
                    protocol,
                    local,
                    local_port,
                    global,
                    global_port,
                } => writeln!(
                    out,
                    "ip nat inside source static {} {local} {local_port} {global} {global_port}",
                    if *protocol == NatTransport::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    }
                )
                .unwrap(),
            }
        }
        if let Some(rule) = &self.nat_pool_rule {
            writeln!(
                out,
                "ip nat inside source list {} pool {}{}",
                rule.access_list.get(),
                rule.pool,
                if rule.overload { " overload" } else { "" }
            )
            .unwrap();
        }
        if let Some(nat) = self.nat_overload
            && let Some(interface) = self.interfaces.get(&nat.outside_interface)
        {
            writeln!(
                out,
                "ip nat inside source list {} interface {} overload\n!",
                nat.access_list.get(),
                interface.name
            )
            .unwrap();
        }
        if let Some(ospf) = &self.ospf {
            writeln!(out, "router ospf {}", ospf.process_id).unwrap();
            if let Some(id) = ospf.router_id {
                writeln!(out, " router-id {id}").unwrap();
            }
            for id in &ospf.passive_interfaces {
                if let Some(interface) = self.interfaces.get(id) {
                    writeln!(out, " passive-interface {}", interface.name).unwrap();
                }
            }
            if let Some(policy) = ospf.default_information {
                writeln!(
                    out,
                    " default-information originate{} metric {} metric-type {}",
                    if policy.always { " always" } else { "" },
                    policy.metric,
                    if policy.type_two { 2 } else { 1 }
                )
                .unwrap();
            }
            if let Some(policy) = ospf.redistribute_static {
                writeln!(
                    out,
                    " redistribute static subnets metric {} metric-type {}",
                    policy.metric,
                    if policy.type_two { 2 } else { 1 }
                )
                .unwrap();
            }
            for network in &ospf.networks {
                writeln!(
                    out,
                    " network {} {} area {}",
                    network.address, network.wildcard, network.area
                )
                .unwrap();
            }
            out.push_str("!\n");
        }
        out.push_str("end\n");
        out
    }
}
