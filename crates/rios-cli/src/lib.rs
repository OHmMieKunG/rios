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
    InterfaceRangeConfiguration(InterfaceId, InterfaceId),
    VlanConfiguration(VlanId),
    RouterConfiguration(RoutingProtocol),
    DhcpPoolConfiguration(DhcpPoolId),
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
            CliMode::InterfaceRangeConfiguration(_, _) => "(config-if-range)#",
            CliMode::VlanConfiguration(_) => "(config-vlan)#",
            CliMode::RouterConfiguration(_) => "(config-router)#",
            CliMode::DhcpPoolConfiguration(_) => "(dhcp-config)#",
        };
        format!("{hostname}{suffix} ")
    }
    /// Ctrl+Z returns configuration sessions to privileged EXEC.
    pub fn end_configuration(&mut self) {
        if matches!(
            self.mode,
            CliMode::GlobalConfiguration
                | CliMode::InterfaceConfiguration(_)
                | CliMode::InterfaceRangeConfiguration(_, _)
                | CliMode::VlanConfiguration(_)
                | CliMode::RouterConfiguration(_)
                | CliMode::DhcpPoolConfiguration(_)
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
/// Validated syntax, independent of state mutation and terminal I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
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
    SetNatRole(NatRole),
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
    EnterRouterOspf(u16),
    AddOspfNetwork(OspfNetworkConfig),
    Shutdown,
    NoShutdown,
    Switchport,
    NoSwitchport,
    Do(Box<Command>),
    ShowRunningConfig,
    ShowStartupConfig,
    ShowInterfaces,
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
    Ping(Ipv4Addr),
}
