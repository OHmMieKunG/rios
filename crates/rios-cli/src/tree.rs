use crate::CliMode;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Action {
    Enable,
    Disable,
    Configure,
    Hostname,
    Interface,
    Description,
    NoDescription,
    Address,
    NoAddress,
    IpRouting,
    NoIpRouting,
    StaticRoute,
    NoStaticRoute,
    AccessList,
    AccessGroup,
    DhcpPool,
    DhcpNetwork,
    DhcpDefaultRouter,
    NatInside,
    NatOutside,
    NatOverload,
    Vlan,
    NoVlan,
    VlanName,
    SwitchportAccessMode,
    SwitchportTrunkMode,
    SwitchportAccessVlan,
    SwitchportTrunkAllowed,
    RouterOspf,
    OspfNetwork,
    OspfNeighbor,
    OspfInterface,
    OspfDatabase,
    SpanningTree,
    ShowAccessLists,
    ShowDhcpBinding,
    ShowNatTranslations,
    Shutdown,
    NoShutdown,
    Switchport,
    NoSwitchport,
    Do,
    Running,
    Startup,
    Interfaces,
    InterfacesStatus,
    Brief,
    Routes,
    Arp,
    MacTable,
    VlanBrief,
    Save,
    Ping,
    Exit,
    End,
    DebugPacket,
    DebugArp,
    DebugIcmp,
}
impl Action {
    pub fn argument_help(self) -> &'static [&'static str] {
        match self {
            Self::Hostname => &["<name>"],
            Self::Interface => &[
                "range",
                "GigabitEthernet",
                "TenGigabitEthernet",
                "Serial",
                "Console",
                "Loopback",
                "Vlan",
            ],
            Self::Description => &["<text>"],
            Self::Address => &["<address> <mask>"],
            Self::StaticRoute | Self::NoStaticRoute => &["<network> <mask> <next-hop>"],
            Self::AccessList => &["<1-99> permit|deny <source> <wildcard>"],
            Self::AccessGroup => &["<1-99> in|out"],
            Self::DhcpPool => &["<name>"],
            Self::DhcpNetwork => &["<network> <mask>"],
            Self::DhcpDefaultRouter => &["<address>"],
            Self::NatOverload => &["list <1-99> interface <interface> overload"],
            Self::Vlan | Self::NoVlan | Self::SwitchportAccessVlan => &["<vlan-id>"],
            Self::Do => &["<EXEC-command>"],
            Self::SwitchportTrunkAllowed => &["<vlan-list>"],
            Self::VlanName => &["<name>"],
            Self::RouterOspf => &["<process-id>"],
            Self::OspfNetwork => &["<address> <wildcard> area <area-id>"],
            Self::Ping => &["<ipv4>"],
            _ => &["<cr>"],
        }
    }
}
pub(crate) struct Node {
    pub word: &'static str,
    pub help: &'static str,
    pub action: Option<Action>,
    pub children: Vec<Node>,
}
impl Node {
    fn root() -> Self {
        Self {
            word: "",
            help: "",
            action: None,
            children: Vec::new(),
        }
    }
    fn add(&mut self, path: &[(&'static str, &'static str)], action: Action) {
        let Some(((word, help), rest)) = path.split_first() else {
            self.action = Some(action);
            return;
        };
        let index = self
            .children
            .iter()
            .position(|n| n.word == *word)
            .unwrap_or_else(|| {
                self.children.push(Self {
                    word,
                    help,
                    action: None,
                    children: Vec::new(),
                });
                self.children.len() - 1
            });
        self.children[index].add(rest, action);
    }
}
/// All keyword spelling and mode availability is centralized here.
pub(crate) fn tree(mode: CliMode) -> Node {
    use Action::*;
    let mut root = Node::root();
    root.add(&[("exit", "Exit current mode or session")], Exit);
    match mode {
        CliMode::UserExec | CliMode::PrivilegedExec => {
            root.add(
                &[
                    ("show", "Show operational information"),
                    ("interfaces", "Interface status and counters"),
                ],
                Interfaces,
            );
            root.add(
                &[("show", ""), ("interfaces", ""), ("status", "Port status")],
                InterfacesStatus,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ip", "IP information"),
                    ("interface", "IP interface information"),
                    ("brief", "Brief interface summary"),
                ],
                Brief,
            );
            root.add(
                &[("show", ""), ("ip", ""), ("route", "IP routing table")],
                Routes,
            );
            root.add(&[("show", ""), ("ip", ""), ("arp", "IP ARP table")], Arp);
            root.add(&[("show", ""), ("arp", "IP ARP table")], Arp);
            root.add(
                &[
                    ("show", ""),
                    ("mac", "MAC forwarding information"),
                    ("address-table", "Dynamic MAC address table"),
                ],
                MacTable,
            );
            root.add(
                &[
                    ("show", ""),
                    ("vlan", "VLAN information"),
                    ("brief", "VLAN summary"),
                ],
                VlanBrief,
            );
            root.add(
                &[("show", ""), ("spanning-tree", "Spanning-tree state")],
                SpanningTree,
            );
            root.add(
                &[("show", ""), ("access-lists", "IPv4 access lists")],
                ShowAccessLists,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ip", ""),
                    ("dhcp", "DHCP information"),
                    ("binding", "DHCP server bindings"),
                ],
                ShowDhcpBinding,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ip", ""),
                    ("nat", "NAT information"),
                    ("translations", "Active NAT translations"),
                ],
                ShowNatTranslations,
            );
            for (word, help, action) in [
                ("neighbor", "OSPF neighbors", OspfNeighbor),
                ("interface", "OSPF interfaces", OspfInterface),
                ("database", "OSPF link-state database", OspfDatabase),
            ] {
                root.add(
                    &[
                        ("show", ""),
                        ("ip", ""),
                        ("ospf", "OSPF information"),
                        (word, help),
                    ],
                    action,
                );
            }
            root.add(&[("ping", "Send ICMP echo requests")], Ping);
            if mode == CliMode::UserExec {
                root.add(&[("enable", "Enter privileged EXEC")], Enable);
            } else {
                root.add(&[("disable", "Leave privileged EXEC")], Disable);
                root.add(
                    &[
                        ("configure", "Enter configuration mode"),
                        ("terminal", "Configure from terminal"),
                    ],
                    Configure,
                );
                root.add(
                    &[("show", ""), ("running-config", "Current configuration")],
                    Running,
                );
                root.add(
                    &[("show", ""), ("startup-config", "Saved configuration")],
                    Startup,
                );
                root.add(
                    &[
                        ("copy", "Copy configuration"),
                        ("running-config", "Current configuration"),
                        ("startup-config", "Save startup configuration"),
                    ],
                    Save,
                );
                root.add(
                    &[
                        ("write", "Write configuration"),
                        ("memory", "Save startup configuration"),
                    ],
                    Save,
                );
                for (word, help, action) in [
                    ("packet", "Packet debugging", DebugPacket),
                    ("arp", "ARP debugging", DebugArp),
                    ("icmp", "ICMP debugging", DebugIcmp),
                ] {
                    root.add(&[("debug", "Protocol debugging"), (word, help)], action);
                }
            }
        }
        CliMode::GlobalConfiguration
        | CliMode::InterfaceConfiguration(_)
        | CliMode::InterfaceRangeConfiguration(_, _)
        | CliMode::VlanConfiguration(_)
        | CliMode::RouterConfiguration(_)
        | CliMode::DhcpPoolConfiguration(_) => {
            root.add(&[("end", "Return to privileged EXEC")], End);
            root.add(&[("do", "Execute an EXEC command")], Do);
            root.add(&[("interface", "Select an interface")], Interface);
            if matches!(
                mode,
                CliMode::GlobalConfiguration | CliMode::VlanConfiguration(_)
            ) {
                root.add(&[("vlan", "Configure a VLAN")], Vlan);
            }
            if mode == CliMode::GlobalConfiguration {
                root.add(&[("hostname", "Set device hostname")], Hostname);
                root.add(
                    &[("ip", "IP configuration"), ("routing", "Enable IP routing")],
                    IpRouting,
                );
                root.add(
                    &[
                        ("no", "Negate a command"),
                        ("ip", "IP configuration"),
                        ("routing", "Disable IP routing"),
                    ],
                    NoIpRouting,
                );
                root.add(
                    &[
                        ("ip", "IP configuration"),
                        ("route", "Configure a static route"),
                    ],
                    StaticRoute,
                );
                root.add(
                    &[
                        ("no", "Negate a command"),
                        ("ip", "IP configuration"),
                        ("route", "Remove a static route"),
                    ],
                    NoStaticRoute,
                );
                root.add(
                    &[("no", "Negate a command"), ("vlan", "Remove a VLAN")],
                    NoVlan,
                );
                root.add(
                    &[("access-list", "Configure a standard IPv4 access list")],
                    AccessList,
                );
                root.add(
                    &[
                        ("ip", ""),
                        ("dhcp", "DHCP server configuration"),
                        ("pool", "Configure a DHCP pool"),
                    ],
                    DhcpPool,
                );
                root.add(
                    &[
                        ("ip", ""),
                        ("nat", "NAT configuration"),
                        ("inside", "Translate inside source addresses"),
                        ("source", "Dynamic source translation"),
                    ],
                    NatOverload,
                );
                root.add(
                    &[("router", "Enable a routing process"), ("ospf", "OSPFv2")],
                    RouterOspf,
                );
            }
            if matches!(mode, CliMode::VlanConfiguration(_)) {
                root.add(&[("name", "Name this VLAN")], VlanName);
            }
            if matches!(
                mode,
                CliMode::RouterConfiguration(crate::RoutingProtocol::Ospf)
            ) {
                root.add(
                    &[("network", "Enable OSPF on matching interfaces")],
                    OspfNetwork,
                );
            }
            if matches!(mode, CliMode::DhcpPoolConfiguration(_)) {
                root.add(&[("network", "Set the pool network")], DhcpNetwork);
                root.add(
                    &[("default-router", "Set the default gateway option")],
                    DhcpDefaultRouter,
                );
            }
            if matches!(
                mode,
                CliMode::InterfaceConfiguration(_) | CliMode::InterfaceRangeConfiguration(_, _)
            ) {
                root.add(&[("description", "Set interface description")], Description);
                root.add(
                    &[
                        ("no", "Negate a command"),
                        ("description", "Remove description"),
                    ],
                    NoDescription,
                );
                root.add(
                    &[("shutdown", "Administratively disable interface")],
                    Shutdown,
                );
                root.add(
                    &[
                        ("no", "Negate a command"),
                        ("shutdown", "Administratively enable interface"),
                    ],
                    NoShutdown,
                );
                root.add(
                    &[("no", ""), ("switchport", "Use this as a routed port")],
                    NoSwitchport,
                );
                root.add(&[("switchport", "Use this as a Layer 2 port")], Switchport);
                root.add(
                    &[
                        ("switchport", "Layer 2 port configuration"),
                        ("mode", "Set port mode"),
                        ("access", "Access mode"),
                    ],
                    SwitchportAccessMode,
                );
                root.add(
                    &[("switchport", ""), ("mode", ""), ("trunk", "Trunk mode")],
                    SwitchportTrunkMode,
                );
                root.add(
                    &[
                        ("switchport", ""),
                        ("access", "Access parameters"),
                        ("vlan", "Set access VLAN"),
                    ],
                    SwitchportAccessVlan,
                );
                root.add(
                    &[
                        ("switchport", ""),
                        ("trunk", "Trunk parameters"),
                        ("allowed", "Allowed VLANs"),
                        ("vlan", "Set allowed VLAN list"),
                    ],
                    SwitchportTrunkAllowed,
                );
            }
            if matches!(mode, CliMode::InterfaceConfiguration(_)) {
                root.add(
                    &[
                        ("ip", "IP configuration"),
                        ("address", "Set IPv4 address and mask"),
                    ],
                    Address,
                );
                root.add(
                    &[
                        ("no", "Negate a command"),
                        ("ip", "IP configuration"),
                        ("address", "Remove IPv4 address"),
                    ],
                    NoAddress,
                );
                root.add(
                    &[("ip", ""), ("access-group", "Apply an IPv4 access list")],
                    AccessGroup,
                );
                root.add(
                    &[
                        ("ip", ""),
                        ("nat", "NAT role"),
                        ("inside", "Inside interface"),
                    ],
                    NatInside,
                );
                root.add(
                    &[("ip", ""), ("nat", ""), ("outside", "Outside interface")],
                    NatOutside,
                );
            }
        }
    }
    root
}
