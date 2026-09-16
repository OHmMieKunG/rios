mod bgp;
mod observability;
mod ospfv3;
mod qos;
mod route_policy;
use crate::CliMode;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Action {
    QosClassMap,
    NoQosClassMap,
    QosDscp,
    NoQosDscp,
    QosPrecedence,
    NoQosPrecedence,
    QosAcl,
    NoQosAcl,
    QosPolicyMap,
    NoQosPolicyMap,
    QosPolicyClass,
    NoQosPolicyClass,
    QosBandwidth,
    NoQosBandwidth,
    QosPriority,
    NoQosPriority,
    QosPolice,
    NoQosPolice,
    QosShape,
    NoQosShape,
    QosOutput,
    NoQosOutput,
    ShowQosInterface,
    PrefixList,
    NoPrefixList,
    RouteMap,
    NoRouteMap,
    RouteMapMatch,
    NoRouteMapMatch,
    RouteMapLocalPref,
    NoRouteMapLocalPref,
    RouteMapMetric,
    NoRouteMapMetric,
    RouteMapPrepend,
    NoRouteMapPrepend,
    RouterBgp,
    NoRouterBgp,
    BgpRouterId,
    BgpClusterId,
    NoBgpClusterId,
    NoBgpRouterId,
    BgpNetwork,
    NoBgpNetwork,
    BgpNeighbor,
    NoBgpNeighbor,
    BgpTable,
    BgpSummary,
    BgpNeighbors,
    Ipv6Routing,
    NoIpv6Routing,
    Ipv6Enable,
    NoIpv6Enable,
    Ipv6Address,
    NoIpv6Address,
    Ipv6Route,
    NoIpv6Route,
    Ipv6RaSuppress,
    NoIpv6RaSuppress,
    Ipv6Brief,
    Ipv6Neighbors,
    Ipv6Routes,
    PingIpv6,
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
    NamedStandardAcl,
    NamedExtendedAcl,
    AclPermit,
    AclDeny,
    AclRemark,
    NoAclSequence,
    AccessGroup,
    DhcpPool,
    DhcpNetwork,
    DhcpDefaultRouter,
    DhcpLease,
    DhcpDns,
    DhcpDomain,
    DhcpHost,
    DhcpHardware,
    DhcpExcluded,
    DhcpHelper,
    NatInside,
    NatOutside,
    NatOverload,
    NatStatic,
    NatPool,
    ShowNatStatistics,
    ClearNatTranslations,
    Vlan,
    NoVlan,
    VlanName,
    SwitchportAccessMode,
    SwitchportTrunkMode,
    SwitchportAccessVlan,
    SwitchportTrunkAllowed,
    NativeVlan,
    Dot1q,
    RouterOspfv3,
    NoRouterOspfv3,
    BindOspfv3,
    NoBindOspfv3,
    V3Cost,
    V3Priority,
    V3Hello,
    V3Dead,
    NoV3Cost,
    NoV3Priority,
    NoV3Hello,
    NoV3Dead,
    V3PointToPoint,
    V3Broadcast,
    V3Neighbor,
    V3Interface,
    V3Database,
    RouterOspf,
    OspfNetwork,
    OspfDefault,
    NoOspfDefault,
    OspfRedistribute,
    NoOspfRedistribute,
    OspfRouterId,
    NoOspfRouterId,
    OspfPassive,
    NoOspfPassive,
    OspfCost,
    OspfPriority,
    OspfHello,
    OspfDead,
    NoOspfCost,
    NoOspfPriority,
    NoOspfHello,
    NoOspfDead,
    OspfPointToPoint,
    OspfBroadcast,
    OspfSummary,
    IpProtocols,
    OspfNeighborDetail,
    OspfNeighbor,
    OspfInterface,
    OspfDatabase,
    SpanningTree,
    SpanningTreeVlan,
    StpRapid,
    StpClassic,
    StpPriority,
    StpPortPriority,
    StpCost,
    StpPortfast,
    NoStpPortfast,
    StpBpduGuard,
    NoStpBpduGuard,
    StpRootGuard,
    NoStpRootGuard,
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
    EtherchannelSummary,
    LacpNeighbor,
    ChannelGroup,
    NoChannelGroup,
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
    Debug(rios_device::DebugTopic, bool),
    UndebugAll,
    ShowDebugging,
    ShowIpTraffic,
}
impl Action {
    pub fn argument_help(self) -> &'static [&'static str] {
        match self {
            Self::Hostname | Self::NamedStandardAcl | Self::NamedExtendedAcl => &["<name>"],
            Self::NoAclSequence => &["<sequence>"],
            Self::StpPriority | Self::SpanningTreeVlan => &["<vlan-id>"],
            Self::StpPortPriority => &["<0-240>"],
            Self::StpCost => &["<1-200000000>"],
            Self::ChannelGroup => &["<1-4096> mode on|active|passive"],
            Self::Interface | Self::Interfaces => &[
                "range",
                "Port-channel",
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
            Self::DhcpLease => &["<days> [hours] [minutes]"],
            Self::DhcpDns => &["<address> [address ...]"],
            Self::DhcpDomain => &["<domain>"],
            Self::DhcpHost => &["<address> <mask>"],
            Self::DhcpHardware => &["<mac-address>"],
            Self::DhcpExcluded => &["<first> [last]"],
            Self::DhcpHelper => &["<address>"],
            Self::DhcpDefaultRouter => &["<address>"],
            Self::NatStatic => &["<local>|tcp|udp"],
            Self::NatPool => &["<name> <first> <last> netmask <mask>"],
            Self::NatOverload => &["list <1-99> interface <interface> overload"],
            Self::Vlan
            | Self::NoVlan
            | Self::SwitchportAccessVlan
            | Self::NativeVlan
            | Self::Dot1q => &["<vlan-id>"],
            Self::Do => &["<EXEC-command>"],
            Self::SwitchportTrunkAllowed => &["<vlan-list>"],
            Self::VlanName => &["<name>"],
            Self::OspfRouterId => &["<router-id>"],
            Self::OspfPassive | Self::NoOspfPassive => &["<interface>"],
            Self::V3Cost
            | Self::V3Hello
            | Self::V3Dead
            | Self::OspfCost
            | Self::OspfHello
            | Self::OspfDead => &["<1-65535>"],
            Self::V3Priority | Self::OspfPriority => &["<0-255>"],
            Self::RouterOspfv3 | Self::NoRouterOspfv3 | Self::RouterOspf => &["<process-id>"],
            Self::BindOspfv3 | Self::NoBindOspfv3 => &["<process-id>", "area", "<area-id>"],
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
                &[("ping", ""), ("ipv6", "Send IPv6 echo requests")],
                PingIpv6,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ipv6", "IPv6 state"),
                    ("interface", "IPv6 interfaces"),
                    ("brief", "Address summary"),
                ],
                Ipv6Brief,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ipv6", ""),
                    ("neighbors", "IPv6 Neighbor Discovery cache"),
                ],
                Ipv6Neighbors,
            );
            root.add(
                &[("show", ""), ("ipv6", ""), ("route", "IPv6 routing table")],
                Ipv6Routes,
            );
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
                &[
                    ("show", ""),
                    ("spanning-tree", ""),
                    ("vlan", "VLAN spanning tree"),
                ],
                SpanningTreeVlan,
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
            root.add(
                &[
                    ("show", ""),
                    ("ip", ""),
                    ("nat", ""),
                    ("statistics", "NAT counters"),
                ],
                ShowNatStatistics,
            );
            root.add(
                &[("show", ""), ("ip", ""), ("ospf", "OSPF process")],
                OspfSummary,
            );
            root.add(
                &[("show", ""), ("ip", ""), ("protocols", "Routing protocols")],
                IpProtocols,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ip", ""),
                    ("ospf", ""),
                    ("neighbor", ""),
                    ("detail", "Adjacency details"),
                ],
                OspfNeighborDetail,
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
            root.add(
                &[
                    ("show", ""),
                    ("etherchannel", "Aggregation state"),
                    ("summary", "Bundle summary"),
                ],
                EtherchannelSummary,
            );
            root.add(
                &[
                    ("show", ""),
                    ("lacp", "LACP state"),
                    ("neighbor", "Received partners"),
                ],
                LacpNeighbor,
            );
            root.add(&[("ping", "Send ICMP echo requests")], Ping);
            if mode == CliMode::UserExec {
                root.add(&[("enable", "Enter privileged EXEC")], Enable);
            } else {
                root.add(
                    &[
                        ("clear", "Reset operational state"),
                        ("ip", ""),
                        ("nat", ""),
                        ("translation", "Clear dynamic translations"),
                        ("*", "All dynamic translations"),
                    ],
                    ClearNatTranslations,
                );
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
                observability::add(&mut root);
            }
        }
        CliMode::GlobalConfiguration
        | CliMode::InterfaceConfiguration(_)
        | CliMode::SubinterfaceConfiguration(_)
        | CliMode::InterfaceRangeConfiguration(_, _)
        | CliMode::VlanConfiguration(_)
        | CliMode::RouterConfiguration(_)
        | CliMode::DhcpPoolConfiguration(_)
        | CliMode::RouteMapConfiguration(..)
        | CliMode::QosClassConfiguration(_)
        | CliMode::QosPolicyConfiguration(_)
        | CliMode::QosPolicyClassConfiguration(..)
        | CliMode::AccessListConfiguration(_, _) => {
            root.add(&[("end", "Return to privileged EXEC")], End);
            root.add(&[("do", "Execute an EXEC command")], Do);
            root.add(&[("interface", "Select an interface")], Interface);
            if matches!(
                mode,
                CliMode::GlobalConfiguration | CliMode::VlanConfiguration(_)
            ) {
                root.add(&[("vlan", "Configure a VLAN")], Vlan);
            }
            if matches!(mode, CliMode::AccessListConfiguration(_, _)) {
                root.add(&[("permit", "Permit matching packets")], AclPermit);
                root.add(&[("deny", "Deny matching packets")], AclDeny);
                root.add(&[("remark", "Access-list comment")], AclRemark);
                root.add(&[("no", "Remove sequence")], NoAclSequence);
            }
            if mode == CliMode::GlobalConfiguration {
                root.add(
                    &[
                        ("ipv6", "IPv6 configuration"),
                        ("unicast-routing", "Forward IPv6 packets"),
                    ],
                    Ipv6Routing,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("ipv6", ""),
                        ("unicast-routing", "Disable IPv6 forwarding"),
                    ],
                    NoIpv6Routing,
                );
                root.add(&[("ipv6", ""), ("route", "Static IPv6 route")], Ipv6Route);
                root.add(
                    &[
                        ("no", ""),
                        ("ipv6", ""),
                        ("route", "Remove static IPv6 route"),
                    ],
                    NoIpv6Route,
                );

                root.add(
                    &[
                        ("ip", "IP configuration"),
                        ("access-list", "Named IPv4 access list"),
                        ("standard", "Match source address"),
                    ],
                    NamedStandardAcl,
                );
                root.add(
                    &[
                        ("ip", "IP configuration"),
                        ("access-list", "Named IPv4 access list"),
                        ("extended", "Match protocol, addresses, and ports"),
                    ],
                    NamedExtendedAcl,
                );
                root.add(
                    &[
                        ("spanning-tree", "Bridge loop prevention"),
                        ("mode", "Protocol selection"),
                        ("rapid-pvst", "Rapid per-VLAN spanning tree"),
                    ],
                    StpRapid,
                );
                root.add(
                    &[
                        ("spanning-tree", ""),
                        ("mode", ""),
                        ("pvst", "Classic per-VLAN spanning tree"),
                    ],
                    StpClassic,
                );
                root.add(
                    &[("spanning-tree", ""), ("vlan", "VLAN bridge priority")],
                    StpPriority,
                );
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
                        ("dhcp", ""),
                        ("excluded-address", "Exclude allocation range"),
                    ],
                    DhcpExcluded,
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
                    &[
                        ("ip", ""),
                        ("nat", ""),
                        ("inside", ""),
                        ("source", ""),
                        ("static", "Static address or port mapping"),
                    ],
                    NatStatic,
                );
                root.add(
                    &[
                        ("ip", ""),
                        ("nat", ""),
                        ("pool", "Define global address pool"),
                    ],
                    NatPool,
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
                    &[
                        ("default-information", "Default route origination"),
                        ("originate", "Originate default Type 5 LSA"),
                    ],
                    OspfDefault,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("default-information", ""),
                        ("originate", "Stop default origination"),
                    ],
                    NoOspfDefault,
                );
                root.add(
                    &[
                        ("redistribute", "Redistribute routes"),
                        ("static", "Reachable static routes"),
                    ],
                    OspfRedistribute,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("redistribute", ""),
                        ("static", "Stop static redistribution"),
                    ],
                    NoOspfRedistribute,
                );
                root.add(&[("router-id", "Set OSPF router ID")], OspfRouterId);
                root.add(
                    &[("no", ""), ("router-id", "Select router ID automatically")],
                    NoOspfRouterId,
                );
                root.add(
                    &[("passive-interface", "Suppress adjacency on interface")],
                    OspfPassive,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("passive-interface", "Enable adjacency on interface"),
                    ],
                    NoOspfPassive,
                );
                root.add(
                    &[("network", "Enable OSPF on matching interfaces")],
                    OspfNetwork,
                );
            }
            if matches!(
                mode,
                CliMode::InterfaceConfiguration(_)
                    | CliMode::SubinterfaceConfiguration(_)
                    | CliMode::InterfaceRangeConfiguration(_, _)
            ) {
                root.add(
                    &[
                        ("ipv6", "IPv6 interface policy"),
                        ("enable", "Enable link-local IPv6"),
                    ],
                    Ipv6Enable,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("ipv6", ""),
                        ("enable", "Remove explicit IPv6 enable"),
                    ],
                    NoIpv6Enable,
                );
                root.add(
                    &[("ipv6", ""), ("address", "IPv6 address or SLAAC")],
                    Ipv6Address,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("ipv6", ""),
                        ("address", "Remove IPv6 address configuration"),
                    ],
                    NoIpv6Address,
                );
                root.add(
                    &[
                        ("ipv6", ""),
                        ("nd", "Neighbor Discovery"),
                        ("ra", "Router advertisements"),
                        ("suppress", "Suppress advertisements"),
                    ],
                    Ipv6RaSuppress,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("ipv6", ""),
                        ("nd", ""),
                        ("ra", ""),
                        ("suppress", "Enable advertisements"),
                    ],
                    NoIpv6RaSuppress,
                );
                for (word, help, set, reset) in [
                    ("cost", "OSPF output cost", OspfCost, NoOspfCost),
                    (
                        "priority",
                        "DR election priority",
                        OspfPriority,
                        NoOspfPriority,
                    ),
                    (
                        "hello-interval",
                        "Hello interval in seconds",
                        OspfHello,
                        NoOspfHello,
                    ),
                    (
                        "dead-interval",
                        "Neighbor dead interval in seconds",
                        OspfDead,
                        NoOspfDead,
                    ),
                ] {
                    root.add(&[("ip", ""), ("ospf", "Interface OSPF"), (word, help)], set);
                    root.add(
                        &[
                            ("no", ""),
                            ("ip", ""),
                            ("ospf", ""),
                            (word, "Restore default"),
                        ],
                        reset,
                    );
                }
                root.add(
                    &[
                        ("ip", ""),
                        ("ospf", ""),
                        ("network", "Network type"),
                        ("point-to-point", "No DR election"),
                    ],
                    OspfPointToPoint,
                );
                root.add(
                    &[
                        ("ip", ""),
                        ("ospf", ""),
                        ("network", ""),
                        ("broadcast", "DR and BDR election"),
                    ],
                    OspfBroadcast,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("ip", ""),
                        ("ospf", ""),
                        ("network", "Restore broadcast type"),
                    ],
                    OspfBroadcast,
                );
            }
            if matches!(
                mode,
                CliMode::InterfaceConfiguration(_) | CliMode::SubinterfaceConfiguration(_)
            ) {
                root.add(
                    &[("ip", ""), ("helper-address", "DHCP relay server")],
                    DhcpHelper,
                );
            }
            if matches!(
                mode,
                CliMode::InterfaceConfiguration(_) | CliMode::InterfaceRangeConfiguration(_, _)
            ) {
                for (word, help, action) in [
                    (
                        "port-priority",
                        "Priority in multiples of 16",
                        StpPortPriority,
                    ),
                    ("cost", "Root path cost", StpCost),
                    ("portfast", "Edge port", StpPortfast),
                ] {
                    root.add(
                        &[("spanning-tree", "Port spanning tree"), (word, help)],
                        action,
                    );
                }
                root.add(
                    &[
                        ("no", ""),
                        ("spanning-tree", ""),
                        ("portfast", "Disable edge behavior"),
                    ],
                    NoStpPortfast,
                );
                root.add(
                    &[
                        ("spanning-tree", ""),
                        ("bpduguard", "Disable port on BPDU"),
                        ("enable", "Enable BPDU Guard"),
                    ],
                    StpBpduGuard,
                );
                root.add(
                    &[
                        ("spanning-tree", ""),
                        ("bpduguard", ""),
                        ("disable", "Disable BPDU Guard"),
                    ],
                    NoStpBpduGuard,
                );
                root.add(
                    &[
                        ("spanning-tree", ""),
                        ("guard", "Guard policy"),
                        ("root", "Reject superior roots"),
                    ],
                    StpRootGuard,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("spanning-tree", ""),
                        ("guard", ""),
                        ("root", "Remove Root Guard"),
                    ],
                    NoStpRootGuard,
                );
                root.add(&[("channel-group", "Bundle membership")], ChannelGroup);
                root.add(
                    &[("no", ""), ("channel-group", "Remove bundle membership")],
                    NoChannelGroup,
                );
            }
            if matches!(mode, CliMode::DhcpPoolConfiguration(_)) {
                root.add(&[("network", "Set the pool network")], DhcpNetwork);
                for (word, help, action) in [
                    ("lease", "Lease duration", DhcpLease),
                    ("dns-server", "DNS servers", DhcpDns),
                    ("domain-name", "Client domain", DhcpDomain),
                    ("host", "Reserved address", DhcpHost),
                    ("hardware-address", "Reservation client MAC", DhcpHardware),
                ] {
                    root.add(&[(word, help)], action);
                }
                root.add(
                    &[("default-router", "Set the default gateway option")],
                    DhcpDefaultRouter,
                );
            }
            if matches!(
                mode,
                CliMode::InterfaceConfiguration(_)
                    | CliMode::SubinterfaceConfiguration(_)
                    | CliMode::InterfaceRangeConfiguration(_, _)
            ) {
                root.add(&[("description", "Set interface description")], Description);
                root.add(
                    &[
                        ("switchport", "Layer 2 port configuration"),
                        ("trunk", "Trunk parameters"),
                        ("native", "Native VLAN"),
                        ("vlan", "Untagged VLAN"),
                    ],
                    NativeVlan,
                );
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
            if matches!(
                mode,
                CliMode::InterfaceConfiguration(_)
                    | CliMode::SubinterfaceConfiguration(_)
                    | CliMode::InterfaceRangeConfiguration(_, _)
            ) {
                for (word, help, set, reset) in [
                    ("cost", "OSPF output cost", OspfCost, NoOspfCost),
                    (
                        "priority",
                        "DR election priority",
                        OspfPriority,
                        NoOspfPriority,
                    ),
                    (
                        "hello-interval",
                        "Hello interval in seconds",
                        OspfHello,
                        NoOspfHello,
                    ),
                    (
                        "dead-interval",
                        "Neighbor dead interval in seconds",
                        OspfDead,
                        NoOspfDead,
                    ),
                ] {
                    root.add(&[("ip", ""), ("ospf", "Interface OSPF"), (word, help)], set);
                    root.add(
                        &[
                            ("no", ""),
                            ("ip", ""),
                            ("ospf", ""),
                            (word, "Restore default"),
                        ],
                        reset,
                    );
                }
                root.add(
                    &[
                        ("ip", ""),
                        ("ospf", ""),
                        ("network", "Network type"),
                        ("point-to-point", "No DR election"),
                    ],
                    OspfPointToPoint,
                );
                root.add(
                    &[
                        ("ip", ""),
                        ("ospf", ""),
                        ("network", ""),
                        ("broadcast", "DR and BDR election"),
                    ],
                    OspfBroadcast,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("ip", ""),
                        ("ospf", ""),
                        ("network", "Restore broadcast type"),
                    ],
                    OspfBroadcast,
                );
            }
            if matches!(
                mode,
                CliMode::InterfaceConfiguration(_) | CliMode::SubinterfaceConfiguration(_)
            ) {
                root.add(
                    &[
                        ("encapsulation", "Set subinterface encapsulation"),
                        ("dot1q", "IEEE 802.1Q VLAN"),
                    ],
                    Dot1q,
                );
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
    ospfv3::add(&mut root, mode);
    bgp::add(&mut root, mode);
    route_policy::add(&mut root, mode);
    qos::add(&mut root, mode);
    root
}
