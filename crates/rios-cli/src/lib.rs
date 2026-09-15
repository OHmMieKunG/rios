//! IOS-style command parsing, help, and execution over a frontend-independent session.
#![forbid(unsafe_code)]
mod executor;
mod parser;
mod tree;
pub use executor::{CliError, Execution, execute, execute_at, load_configuration};
pub use parser::{ParseError, ParsedInput, Suggestion, parse, suggestions};
use rios_config::{
    AccessListAction, AccessListDirection, AccessListId, DhcpPoolId, NatRole, OspfNetworkConfig,
    StandardAccessListEntry, SwitchportMode, VlanId,
};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::InterfaceId;
use std::{collections::BTreeSet, net::Ipv4Addr};

/// One IPv6 interface configuration edit; runtime Neighbor Discovery remains in Device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6PortOption {
    Enable(bool),
    Autoconfig(bool),
    Address(rios_ipv6::Ipv6InterfaceConfig, bool),
    LinkLocal(std::net::Ipv6Addr, bool),
    ClearAddresses,
    RaSuppress(bool),
}
/// One independently configurable OSPF interface setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfPortOption {
    Cost(u16),
    Priority(u8),
    Hello(u16),
    Dead(u32),
    Network(rios_config::OspfNetworkType),
}
/// Routing configuration context reserved for later protocol implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingProtocol {
    Ospf,
    Rip,
    Bgp,
}
/// Per-connection CLI state, never stored in a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CliMode {
    #[default]
    UserExec,
    PrivilegedExec,
    GlobalConfiguration,
    InterfaceConfiguration(InterfaceId),
    SubinterfaceConfiguration(InterfaceId),
    InterfaceRangeConfiguration(InterfaceId, InterfaceId),
    VlanConfiguration(VlanId),
    RouterConfiguration(RoutingProtocol),
    DhcpPoolConfiguration(DhcpPoolId),
    AccessListConfiguration(rios_config::AclId, rios_config::AclKind),
}
/// Independent CLI session. Multiple sessions may reference the same device.
#[derive(Debug, Clone, Default)]
pub struct CliSession {
    pub mode: CliMode,
}
impl CliSession {
    /// Render a prompt using the device's current hostname.
    pub fn prompt(&self, hostname: &str) -> String {
        let suffix = match self.mode {
            CliMode::UserExec => ">",
            CliMode::PrivilegedExec => "#",
            CliMode::GlobalConfiguration => "(config)#",
            CliMode::InterfaceConfiguration(_) => "(config-if)#",
            CliMode::SubinterfaceConfiguration(_) => "(config-subif)#",
            CliMode::InterfaceRangeConfiguration(_, _) => "(config-if-range)#",
            CliMode::VlanConfiguration(_) => "(config-vlan)#",
            CliMode::RouterConfiguration(_) => "(config-router)#",
            CliMode::DhcpPoolConfiguration(_) => "(dhcp-config)#",
            CliMode::AccessListConfiguration(_, kind) => {
                if kind == rios_config::AclKind::Standard {
                    "(config-std-nacl)#"
                } else {
                    "(config-ext-nacl)#"
                }
            }
        };
        format!("{hostname}{suffix} ")
    }
    /// Ctrl+Z returns configuration sessions to privileged EXEC.
    pub fn end_configuration(&mut self) {
        if matches!(
            self.mode,
            CliMode::GlobalConfiguration
                | CliMode::InterfaceConfiguration(_)
                | CliMode::SubinterfaceConfiguration(_)
                | CliMode::InterfaceRangeConfiguration(_, _)
                | CliMode::VlanConfiguration(_)
                | CliMode::RouterConfiguration(_)
                | CliMode::DhcpPoolConfiguration(_)
                | CliMode::AccessListConfiguration(_, _)
        ) {
            self.mode = CliMode::PrivilegedExec;
        }
    }
}
/// Explicitly deferred network capabilities, never represented as successful traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFeature {
    DebugPacket,
    DebugArp,
    DebugIcmp,
}
/// A validated switch-port spanning-tree setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StpPortOption {
    Priority(u8),
    Cost(u32),
    Portfast(bool),
    BpduGuard(bool),
    RootGuard(bool),
}
/// One DHCP pool option, applied through shared device validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpPoolOption {
    Lease(u32),
    Dns(Vec<Ipv4Addr>),
    Domain(String),
    Host(Ipv4InterfaceConfig),
    Hardware(rios_ethernet::MacAddress),
}
/// Validated syntax, independent of state mutation and terminal I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    SetIpv6Routing(bool),
    SetIpv6Port(Ipv6PortOption),
    SetIpv6Route {
        prefix: rios_ipv6::Ipv6Network,
        interface: Option<String>,
        next_hop: std::net::Ipv6Addr,
        present: bool,
    },
    ShowIpv6InterfaceBrief,
    ShowIpv6Neighbors,
    ShowIpv6Route,
    PingIpv6 {
        destination: std::net::Ipv6Addr,
        interface: Option<String>,
    },
    EnterAccessList {
        name: String,
        kind: rios_config::AclKind,
    },
    AddAclEntry {
        sequence: Option<u32>,
        entry: rios_config::AclEntry,
    },
    RemoveAclEntry(u32),
    SetNamedAccessGroup {
        name: String,
        direction: AccessListDirection,
    },
    AddNumberedAcl {
        name: String,
        kind: rios_config::AclKind,
        entry: rios_config::AclEntry,
    },
    Enable,
    Disable,
    ConfigureTerminal,
    Hostname(String),
    EnterInterface(String),
    EnterInterfaceRange {
        first: String,
        last: String,
    },
    Description(String),
    NoDescription,
    SetIpv4Address(Ipv4InterfaceConfig),
    SetIpv4Dhcp,
    NoIpv4Address,
    IpRouting,
    NoIpRouting,
    SetStaticRoute {
        prefix: Ipv4Network,
        next_hop: Ipv4Addr,
    },
    RemoveStaticRoute {
        prefix: Ipv4Network,
        next_hop: Ipv4Addr,
    },
    AddStandardAccessList {
        id: AccessListId,
        entry: StandardAccessListEntry,
    },
    SetAccessGroup {
        id: AccessListId,
        direction: AccessListDirection,
    },
    EnterDhcpPool(String),
    SetDhcpPoolNetwork(Ipv4Network),
    SetDhcpDefaultRouter(Ipv4Addr),
    SetDhcpPoolOption(DhcpPoolOption),
    ExcludeDhcpAddresses {
        first: Ipv4Addr,
        last: Ipv4Addr,
    },
    SetDhcpHelper(Ipv4Addr),
    SetNatRole(NatRole),
    AddStaticNat(rios_config::StaticNat),
    SetNatPool {
        name: String,
        pool: rios_config::NatPool,
    },
    SetNatPoolRule(rios_config::NatPoolRule),
    ShowIpNatStatistics,
    ClearNatTranslations,
    SetNatOverload {
        access_list: AccessListId,
        outside_interface: String,
    },
    EnterVlan(VlanId),
    RemoveVlan(VlanId),
    NameVlan(String),
    SetSwitchportMode(SwitchportMode),
    SetAccessVlan(VlanId),
    SetTrunkAllowedVlans(BTreeSet<VlanId>),
    SetNativeVlan(VlanId),
    SetDot1q {
        vlan: VlanId,
        native: bool,
    },
    EnterRouterOspf(u16),
    AddOspfNetwork(OspfNetworkConfig),
    SetOspfRouterId(Option<Ipv4Addr>),
    SetOspfDefault(Option<rios_config::OspfDefaultRoute>),
    SetOspfRedistributeStatic(Option<rios_config::OspfRedistribute>),
    SetOspfPassive {
        interface: String,
        passive: bool,
    },
    SetOspfPort(OspfPortOption),
    ShowIpOspf,
    ShowIpProtocols,
    ShowIpOspfNeighborDetail,
    Shutdown,
    NoShutdown,
    Switchport,
    NoSwitchport,
    Do(Box<Command>),
    ShowRunningConfig,
    ShowStartupConfig,
    ShowInterfaces,
    ShowInterface(String),
    ShowEtherchannelSummary,
    ShowLacpNeighbor,
    SetChannelGroup {
        number: u16,
        mode: rios_config::ChannelMode,
    },
    ClearChannelGroup,
    ShowInterfacesStatus,
    ShowIpInterfaceBrief,
    ShowIpRoute,
    ShowArp,
    ShowMacAddressTable,
    ShowVlanBrief,
    ShowIpOspfNeighbor,
    ShowIpOspfInterface,
    ShowIpOspfDatabase,
    ShowSpanningTree,
    ShowSpanningTreeVlan(VlanId),
    SetStpRapid(bool),
    SetStpPriority {
        vlan: VlanId,
        priority: u16,
    },
    SetStpPort(StpPortOption),
    ShowAccessLists,
    ShowIpDhcpBinding,
    ShowIpNatTranslations,
    SaveConfig,
    Ping(Ipv4Addr),
    NetworkUnavailable(NetworkFeature),
    Exit,
    End,
}

/// Work that requires the owning simulation lab after device-local execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulationRequest {
    PingIpv6 {
        destination: std::net::Ipv6Addr,
        interface: Option<InterfaceId>,
    },
    Ping(Ipv4Addr),
}
