use crate::*;
use rios_config::AdminState;
use rios_device::{Device, DeviceError};

/// Executor errors are independent of terminal presentation.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error("command is not available in this mode")]
    WrongMode,
    #[error("{0} is not implemented yet")]
    Unavailable(&'static str),
    #[error("configuration line {line}: {message}")]
    Configuration { line: usize, message: String },
}
/// Text output and session lifecycle result for any frontend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Execution {
    pub output: String,
    pub close: bool,
    pub request: Option<SimulationRequest>,
    /// The owning frontend should durably save startup configuration.
    pub persist: bool,
}

fn edit_interfaces(
    device: &mut Device,
    mode: CliMode,
    mut edit: impl FnMut(&mut Device, rios_simulator::InterfaceId) -> Result<(), DeviceError>,
) -> Result<(), DeviceError> {
    let interfaces = match mode {
        CliMode::InterfaceConfiguration(id) | CliMode::SubinterfaceConfiguration(id) => vec![id],
        CliMode::InterfaceRangeConfiguration(first, last) => device.interface_range(first, last)?,
        _ => return Err(DeviceError::MissingInterface),
    };
    let mut candidate = device.clone();
    for interface in interfaces {
        edit(&mut candidate, interface)?;
    }
    *device = candidate;
    Ok(())
}

fn executable_after_do(command: &Command) -> bool {
    matches!(
        command,
        Command::ShowRunningConfig
            | Command::ShowStartupConfig
            | Command::ShowInterfaces
            | Command::ShowInterface(_)
            | Command::ShowEtherchannelSummary
            | Command::ShowLacpNeighbor
            | Command::ShowInterfacesStatus
            | Command::ShowIpInterfaceBrief
            | Command::ShowIpRoute
            | Command::ShowArp
            | Command::ShowMacAddressTable
            | Command::ShowVlanBrief
            | Command::ShowIpv6InterfaceBrief
            | Command::ShowIpv6Neighbors
            | Command::ShowIpv6OspfNeighbor
            | Command::ShowIpv6OspfInterface
            | Command::ShowIpv6OspfDatabase
            | Command::ShowIpv6Route
            | Command::PingIpv6 { .. }
            | Command::ShowIpBgp
            | Command::ShowIpBgpSummary
            | Command::ShowIpBgpNeighbors
            | Command::ShowIpOspf
            | Command::ShowIpProtocols
            | Command::ShowIpOspfNeighborDetail
            | Command::ShowIpOspfNeighbor
            | Command::ShowIpOspfInterface
            | Command::ShowIpOspfDatabase
            | Command::ShowSpanningTree
            | Command::ShowSpanningTreeVlan(_)
            | Command::ShowAccessLists
            | Command::ShowIpDhcpBinding
            | Command::ShowIpNatTranslations
            | Command::ShowIpNatStatistics
            | Command::ClearNatTranslations
            | Command::SaveConfig
            | Command::Ping(_)
    )
}
/// Execute a typed command, validating mode even when the parser is bypassed.
pub fn execute(
    device: &mut Device,
    session: &mut CliSession,
    command: Command,
) -> Result<Execution, CliError> {
    execute_at(
        device,
        session,
        command,
        rios_simulator::SimTime::from_millis(0),
    )
}

/// Execute using virtual time for time-dependent operational output.
pub fn execute_at(
    device: &mut Device,
    session: &mut CliSession,
    command: Command,
    now: rios_simulator::SimTime,
) -> Result<Execution, CliError> {
    use CliMode::*;
    let mode = session.mode;
    let exec_mode = matches!(mode, UserExec | PrivilegedExec);
    let config_mode = matches!(
        mode,
        GlobalConfiguration
            | InterfaceConfiguration(_)
            | SubinterfaceConfiguration(_)
            | InterfaceRangeConfiguration(_, _)
            | VlanConfiguration(_)
            | RouterConfiguration(_)
            | DhcpPoolConfiguration(_)
            | AccessListConfiguration(_, _)
    );
    let valid = match &command {
        Command::SetIpv6Routing(_) | Command::SetIpv6Route { .. } => mode == GlobalConfiguration,
        Command::SetIpv6Port(_) => matches!(
            mode,
            InterfaceConfiguration(_)
                | SubinterfaceConfiguration(_)
                | InterfaceRangeConfiguration(_, _)
        ),

        Command::Enable => mode == UserExec,
        Command::Disable
        | Command::ConfigureTerminal
        | Command::ShowRunningConfig
        | Command::ShowStartupConfig
        | Command::SaveConfig
        | Command::ClearNatTranslations => mode == PrivilegedExec,
        Command::Hostname(_) | Command::EnterAccessList { .. } | Command::AddNumberedAcl { .. } => {
            mode == GlobalConfiguration
        }
        Command::AddAclEntry { .. } | Command::RemoveAclEntry(_) => {
            matches!(mode, AccessListConfiguration(_, _))
        }
        Command::SetStpRapid(_) | Command::SetStpPriority { .. } => mode == GlobalConfiguration,
        Command::SetStpPort(_) | Command::SetChannelGroup { .. } | Command::ClearChannelGroup => {
            matches!(
                mode,
                InterfaceConfiguration(_) | InterfaceRangeConfiguration(_, _)
            )
        }
        Command::BindOspfv3 { .. } | Command::SetOspfv3Port(_) | Command::SetOspfPort(_) => {
            matches!(
                mode,
                InterfaceConfiguration(_)
                    | SubinterfaceConfiguration(_)
                    | InterfaceRangeConfiguration(_, _)
            )
        }
        Command::SetNamedAccessGroup { .. } => matches!(
            mode,
            InterfaceConfiguration(_) | SubinterfaceConfiguration(_)
        ),
        Command::IpRouting
        | Command::NoIpRouting
        | Command::SetStaticRoute { .. }
        | Command::RemoveStaticRoute { .. }
        | Command::RemoveVlan(_) => mode == GlobalConfiguration,
        Command::AddStandardAccessList { .. } => mode == GlobalConfiguration,
        Command::EnterDhcpPool(_) => mode == GlobalConfiguration,
        Command::SetNatOverload { .. }
        | Command::AddStaticNat(_)
        | Command::SetNatPool { .. }
        | Command::SetNatPoolRule(_) => mode == GlobalConfiguration,
        Command::ExcludeDhcpAddresses { .. } => mode == GlobalConfiguration,
        Command::SetDhcpPoolNetwork(_)
        | Command::SetDhcpDefaultRouter(_)
        | Command::SetDhcpPoolOption(_) => {
            matches!(mode, DhcpPoolConfiguration(_))
        }
        Command::EnterVlan(_) => matches!(mode, GlobalConfiguration | VlanConfiguration(_)),
        Command::BgpProcess { .. } => mode == GlobalConfiguration,
        Command::SetBgpClusterId(_)
        | Command::SetBgpRouterId(_)
        | Command::SetBgpNeighbor { .. }
        | Command::SetBgpNetwork { .. } => mode == RouterConfiguration(RoutingProtocol::Bgp),
        Command::EnterRouterOspfv3(_)
        | Command::RemoveRouterOspfv3(_)
        | Command::EnterRouterOspf(_) => mode == GlobalConfiguration,
        Command::SetOspfRouterId(_) | Command::SetOspfPassive { .. } => matches!(
            mode,
            RouterConfiguration(RoutingProtocol::Ospf | RoutingProtocol::Ospfv3)
        ),
        Command::NameVlan(_) => matches!(mode, VlanConfiguration(_)),
        Command::SetOspfDefault(_)
        | Command::SetOspfRedistributeStatic(_)
        | Command::AddOspfNetwork(_) => matches!(mode, RouterConfiguration(RoutingProtocol::Ospf)),
        Command::EnterInterface(_) | Command::EnterInterfaceRange { .. } | Command::End => {
            config_mode
        }
        Command::Description(_)
        | Command::NoDescription
        | Command::Shutdown
        | Command::NoShutdown
        | Command::Switchport
        | Command::NoSwitchport
        | Command::SetSwitchportMode(_)
        | Command::SetNativeVlan(_)
        | Command::SetAccessVlan(_)
        | Command::SetTrunkAllowedVlans(_) => matches!(
            mode,
            InterfaceConfiguration(_)
                | SubinterfaceConfiguration(_)
                | InterfaceRangeConfiguration(_, _)
        ),
        Command::SetIpv4Address(_)
        | Command::SetIpv4Dhcp
        | Command::SetDot1q { .. }
        | Command::NoIpv4Address
        | Command::SetNatRole(_)
        | Command::SetDhcpHelper(_) => {
            matches!(
                mode,
                InterfaceConfiguration(_) | SubinterfaceConfiguration(_)
            )
        }
        Command::SetAccessGroup { .. } => matches!(
            mode,
            InterfaceConfiguration(_) | SubinterfaceConfiguration(_)
        ),
        Command::ShowInterfaces
        | Command::ShowInterface(_)
        | Command::ShowEtherchannelSummary
        | Command::ShowLacpNeighbor
        | Command::ShowIpInterfaceBrief
        | Command::ShowInterfacesStatus
        | Command::ShowIpRoute
        | Command::ShowArp
        | Command::ShowMacAddressTable
        | Command::ShowVlanBrief
        | Command::ShowIpv6InterfaceBrief
        | Command::ShowIpv6Neighbors
        | Command::ShowIpv6OspfNeighbor
        | Command::ShowIpv6OspfInterface
        | Command::ShowIpv6OspfDatabase
        | Command::ShowIpv6Route
        | Command::PingIpv6 { .. }
        | Command::ShowIpBgp
        | Command::ShowIpBgpSummary
        | Command::ShowIpBgpNeighbors
        | Command::ShowIpOspf
        | Command::ShowIpProtocols
        | Command::ShowIpOspfNeighborDetail
        | Command::ShowIpOspfNeighbor
        | Command::ShowIpOspfInterface
        | Command::ShowIpOspfDatabase
        | Command::ShowSpanningTree
        | Command::ShowSpanningTreeVlan(_)
        | Command::ShowAccessLists
        | Command::ShowIpDhcpBinding
        | Command::ShowIpNatTranslations
        | Command::ShowIpNatStatistics
        | Command::Ping(_) => exec_mode,
        Command::NetworkUnavailable(feature) => match feature {
            NetworkFeature::DebugPacket | NetworkFeature::DebugArp | NetworkFeature::DebugIcmp => {
                mode == PrivilegedExec
            }
        },
        Command::Do(command) => config_mode && executable_after_do(command),
        Command::Exit => true,
    };
    if !valid {
        return Err(CliError::WrongMode);
    }
    let mut result = Execution::default();
    match command {
        Command::EnterAccessList { name, kind } => {
            session.mode = AccessListConfiguration(device.ensure_acl(&name, kind)?, kind);
        }
        Command::AddAclEntry { sequence, entry } => {
            if let AccessListConfiguration(id, _) = mode {
                device.set_acl_entry(id, sequence, entry)?;
            }
        }
        Command::RemoveAclEntry(sequence) => {
            if let AccessListConfiguration(id, _) = mode {
                device.remove_acl_entry(id, sequence)?;
            }
        }
        Command::SetNamedAccessGroup { name, direction } => {
            if let InterfaceConfiguration(id) | SubinterfaceConfiguration(id) = mode {
                device.set_named_access_group(id, &name, direction)?;
            }
        }
        Command::AddNumberedAcl { name, kind, entry } => {
            let mut candidate = device.clone();
            let id = candidate.ensure_acl(&name, kind)?;
            candidate.set_acl_entry(id, None, entry)?;
            *device = candidate;
        }
        Command::Enable => session.mode = PrivilegedExec,
        Command::Disable => session.mode = UserExec,
        Command::ConfigureTerminal => session.mode = GlobalConfiguration,
        Command::Hostname(name) => device.set_hostname(&name)?,
        Command::EnterInterface(name) => {
            let id = device.ensure_interface(&name)?;
            session.mode = if device.interfaces()[&id].kind
                == rios_device::InterfaceKind::EthernetSubinterface
            {
                SubinterfaceConfiguration(id)
            } else {
                InterfaceConfiguration(id)
            };
        }
        Command::EnterInterfaceRange { first, last } => {
            let first = device
                .find_interface(&first)
                .ok_or_else(|| DeviceError::InvalidInterface(first.clone()))?;
            let last = device
                .find_interface(&last)
                .ok_or_else(|| DeviceError::InvalidInterface(last.clone()))?;
            device.interface_range(first, last)?;
            session.mode = InterfaceRangeConfiguration(first, last);
        }
        Command::Description(text) => {
            edit_interfaces(device, mode, |device, id| device.set_description(id, &text))?;
        }
        Command::NoDescription => {
            edit_interfaces(device, mode, Device::clear_description)?;
        }
        Command::SetIpv4Address(ip) => {
            if let InterfaceConfiguration(id) | SubinterfaceConfiguration(id) = mode {
                device.set_ipv4(id, ip)?;
            }
        }
        Command::SetIpv4Dhcp => {
            if let InterfaceConfiguration(id) | SubinterfaceConfiguration(id) = mode {
                device.set_dhcp_client(id)?;
            }
        }
        Command::NoIpv4Address => {
            if let InterfaceConfiguration(id) | SubinterfaceConfiguration(id) = mode {
                device.clear_ipv4(id)?;
            }
        }
        Command::IpRouting => device.set_ip_routing(true)?,
        Command::NoIpRouting => device.set_ip_routing(false)?,
        Command::SetStaticRoute { prefix, next_hop } => {
            device.set_static_route(prefix, next_hop);
        }
        Command::RemoveStaticRoute { prefix, next_hop } => {
            device.remove_static_route(prefix, next_hop);
        }
        Command::AddStandardAccessList { id, entry } => {
            device.add_access_list_entry(id, entry)?;
        }
        Command::SetAccessGroup { id, direction } => {
            if let InterfaceConfiguration(interface) | SubinterfaceConfiguration(interface) = mode {
                device.set_access_group(interface, id, direction)?;
            }
        }
        Command::EnterDhcpPool(name) => {
            let id = device.ensure_dhcp_pool(&name)?;
            session.mode = DhcpPoolConfiguration(id);
        }
        Command::SetDhcpPoolNetwork(network) => {
            if let DhcpPoolConfiguration(id) = mode {
                device.set_dhcp_pool_network(id, network)?;
            }
        }
        Command::SetDhcpHelper(address) => {
            edit_interfaces(device, mode, |device, interface| {
                device.set_dhcp_helper(interface, address)
            })?;
        }
        Command::ExcludeDhcpAddresses { first, last } => {
            device.exclude_dhcp_addresses(first, last)?
        }
        Command::SetDhcpPoolOption(option) => {
            if let DhcpPoolConfiguration(id) = mode {
                let mut config = device.running_config().dhcp_pools[&id].clone();
                match option {
                    DhcpPoolOption::Lease(seconds) => config.lease_seconds = seconds,
                    DhcpPoolOption::Dns(addresses) => config.dns_servers = addresses,
                    DhcpPoolOption::Domain(name) => config.domain_name = Some(name),
                    DhcpPoolOption::Host(ip) => {
                        config.network = Some(
                            Ipv4Network::new(ip.address(), ip.prefix_len())
                                .map_err(|_| DeviceError::InvalidDhcpNetwork)?,
                        );
                        config.reserved_address = Some(ip.address());
                    }
                    DhcpPoolOption::Hardware(mac) => config.hardware_address = Some(mac),
                }
                device.update_dhcp_pool(id, config)?;
            }
        }
        Command::SetDhcpDefaultRouter(address) => {
            if let DhcpPoolConfiguration(id) = mode {
                device.set_dhcp_default_router(id, address)?;
            }
        }
        Command::SetNatRole(role) => {
            if let InterfaceConfiguration(interface) | SubinterfaceConfiguration(interface) = mode {
                device.set_nat_role(interface, role)?;
            }
        }
        Command::AddStaticNat(rule) => device.add_static_nat(rule)?,
        Command::SetNatPool { name, pool } => device.set_nat_pool(&name, pool)?,
        Command::SetNatPoolRule(rule) => device.set_nat_pool_rule(rule)?,
        Command::ClearNatTranslations => device.clear_nat_translations(),
        Command::ShowIpNatStatistics => result.output = device.show_ip_nat_statistics(now),
        Command::SetNatOverload {
            access_list,
            outside_interface,
        } => {
            let outside_interface = device.ensure_interface(&outside_interface)?;
            device.set_nat_overload(access_list, outside_interface)?;
        }
        Command::EnterVlan(vlan) => {
            device.create_vlan(vlan)?;
            session.mode = VlanConfiguration(vlan);
        }
        Command::RemoveVlan(vlan) => device.remove_vlan(vlan)?,
        Command::BgpProcess { asn, present } => {
            if present {
                device.set_bgp_process(Some(asn))?;
                session.mode = RouterConfiguration(RoutingProtocol::Bgp);
            } else if device
                .running_config()
                .bgp
                .as_ref()
                .is_some_and(|c| c.local_as == asn)
            {
                device.set_bgp_process(None)?;
            } else {
                return Err(DeviceError::InvalidBgpConfig.into());
            }
        }
        Command::SetBgpClusterId(id) => device.set_bgp_cluster_id(id)?,
        Command::SetBgpRouterId(id) => device.set_bgp_router_id(id)?,
        Command::SetBgpNetwork { prefix, present } => device.set_bgp_network(prefix, present)?,
        Command::SetBgpNeighbor { address, option } => {
            if option == BgpNeighborOption::Remove {
                device.set_bgp_neighbor(address, None)?;
            } else {
                let mut config = device
                    .running_config()
                    .bgp
                    .as_ref()
                    .and_then(|c| c.neighbors.get(&address))
                    .cloned();
                if let BgpNeighborOption::RemoteAs(remote_as) = option {
                    config
                        .get_or_insert(rios_config::BgpNeighborConfig {
                            remote_as,
                            update_source: None,
                            next_hop_self: false,
                            route_reflector_client: false,
                        })
                        .remote_as = remote_as;
                }
                let mut config = config.ok_or(DeviceError::InvalidBgpConfig)?;
                match option {
                    BgpNeighborOption::RouteReflectorClient(value) => {
                        config.route_reflector_client = value
                    }
                    BgpNeighborOption::NextHopSelf(value) => config.next_hop_self = value,
                    BgpNeighborOption::UpdateSource(name) => {
                        config.update_source = name
                            .map(|name| {
                                device
                                    .find_interface(&name)
                                    .ok_or(DeviceError::InvalidInterface(name))
                            })
                            .transpose()?
                    }
                    _ => {}
                }
                device.set_bgp_neighbor(address, Some(config))?;
            }
        }
        Command::ShowIpBgp => result.output = device.show_ip_bgp(),
        Command::ShowIpBgpSummary => result.output = device.show_ip_bgp_summary(),
        Command::ShowIpBgpNeighbors => result.output = device.show_ip_bgp_neighbors(now),
        Command::EnterRouterOspfv3(process_id) => {
            device.set_ospfv3_process(Some(process_id))?;
            session.mode = RouterConfiguration(RoutingProtocol::Ospfv3);
        }
        Command::RemoveRouterOspfv3(process_id) => {
            if device
                .running_config()
                .ospfv3
                .as_ref()
                .is_some_and(|c| c.process_id == process_id)
            {
                device.set_ospfv3_process(None)?;
            }
        }
        Command::BindOspfv3 { binding, present } => edit_interfaces(device, mode, |d, id| {
            let policy = &d.running_config().interfaces[&id].ipv6;
            if !present && policy.ospf != Some(binding) {
                return Ok(());
            }
            d.set_ospfv3_interface(id, present.then_some(binding), policy.ospf_parameters)
        })?,
        Command::SetOspfv3Port(option) => edit_interfaces(device, mode, |d, id| {
            let c = &d.running_config().interfaces[&id].ipv6;
            let binding = c.ospf;
            let mut policy = c.ospf_parameters;
            match option {
                OspfPortOption::Cost(v) => policy.cost = v,
                OspfPortOption::Priority(v) => policy.priority = v,
                OspfPortOption::Hello(v) => policy.hello_interval = v,
                OspfPortOption::Dead(v) => policy.dead_interval = v,
                OspfPortOption::Network(v) => policy.network_type = v,
            }
            d.set_ospfv3_interface(id, binding, policy)
        })?,
        Command::ShowIpv6OspfNeighbor => result.output = device.show_ipv6_ospf_neighbor(now),
        Command::ShowIpv6OspfInterface => result.output = device.show_ipv6_ospf_interface(),
        Command::ShowIpv6OspfDatabase => result.output = device.show_ipv6_ospf_database(now),
        Command::EnterRouterOspf(process_id) => {
            device.set_ospf_process(process_id)?;
            session.mode = RouterConfiguration(RoutingProtocol::Ospf);
        }
        Command::AddOspfNetwork(network) => device.add_ospf_network(network)?,
        Command::SetOspfDefault(policy) => device.set_ospf_default(policy)?,
        Command::SetOspfRedistributeStatic(policy) => {
            device.set_ospf_redistribute_static(policy)?
        }
        Command::SetOspfRouterId(id) => {
            if mode == RouterConfiguration(RoutingProtocol::Ospfv3) {
                device.set_ospfv3_router_id(id)?
            } else {
                device.set_ospf_router_id(id)?
            }
        }
        Command::SetOspfPassive { interface, passive } => {
            let id = device
                .find_interface(&interface)
                .ok_or(rios_device::DeviceError::MissingInterface)?;
            if mode == RouterConfiguration(RoutingProtocol::Ospfv3) {
                device.set_ospfv3_passive(id, passive)?
            } else {
                device.set_ospf_passive(id, passive)?;
            }
        }
        Command::SetOspfPort(option) => edit_interfaces(device, mode, |device, id| {
            let mut policy = device.running_config().interfaces[&id].ospf;
            match option {
                OspfPortOption::Cost(v) => policy.cost = v,
                OspfPortOption::Priority(v) => policy.priority = v,
                OspfPortOption::Hello(v) => policy.hello_interval = v,
                OspfPortOption::Dead(v) => policy.dead_interval = v,
                OspfPortOption::Network(v) => policy.network_type = v,
            }
            device.set_ospf_interface(id, policy)
        })?,
        Command::ShowIpOspf => result.output = device.show_ip_ospf(),
        Command::ShowIpProtocols => result.output = device.show_ip_protocols(),
        Command::ShowIpOspfNeighborDetail => {
            result.output = device.show_ip_ospf_neighbor_detail(now)
        }
        Command::NameVlan(name) => {
            if let VlanConfiguration(vlan) = mode {
                device.set_vlan_name(vlan, &name)?;
            }
        }
        Command::SetSwitchportMode(switchport_mode) => {
            edit_interfaces(device, mode, |device, id| {
                device.set_switchport_mode(id, switchport_mode)
            })?;
        }
        Command::SetDot1q { vlan, native } => {
            if let InterfaceConfiguration(id) | SubinterfaceConfiguration(id) = mode {
                device.set_dot1q(id, vlan, native)?;
            }
        }
        Command::SetNativeVlan(vlan) => {
            edit_interfaces(device, mode, |device, id| device.set_native_vlan(id, vlan))?;
        }
        Command::SetAccessVlan(vlan) => {
            edit_interfaces(device, mode, |device, id| device.set_access_vlan(id, vlan))?;
        }
        Command::SetTrunkAllowedVlans(vlans) => {
            edit_interfaces(device, mode, |device, id| {
                device.set_trunk_allowed_vlans(id, vlans.clone())
            })?;
        }
        Command::Shutdown | Command::NoShutdown => {
            edit_interfaces(device, mode, |device, id| {
                device.set_admin_state(
                    id,
                    if command == Command::Shutdown {
                        AdminState::Down
                    } else {
                        AdminState::Up
                    },
                )
            })?;
        }
        Command::NoSwitchport => {
            edit_interfaces(device, mode, Device::disable_switchport)?;
        }
        Command::Switchport => {
            edit_interfaces(device, mode, Device::enable_switchport)?;
        }
        Command::Do(command) => {
            let mut exec_session = CliSession {
                mode: PrivilegedExec,
            };
            return execute_at(device, &mut exec_session, *command, now);
        }
        Command::ShowRunningConfig => result.output = device.running_config().render(),
        Command::ShowStartupConfig => {
            result.output = device.startup_config().0.as_ref().map_or_else(
                || "% Startup configuration is not present.\n".into(),
                |c| c.render(),
            )
        }
        Command::ShowInterfaces => result.output = device.show_interfaces(),
        Command::ShowInterface(name) => {
            let id = device
                .find_interface(&name)
                .ok_or(DeviceError::MissingInterface)?;
            result.output = device.show_interface(id)?;
        }
        Command::ShowEtherchannelSummary => result.output = device.show_etherchannel_summary(),
        Command::ShowLacpNeighbor => result.output = device.show_lacp_neighbor(),
        Command::SetChannelGroup {
            number,
            mode: channel_mode,
        } => edit_interfaces(device, mode, |device, id| {
            device.set_channel_group(id, number, channel_mode)
        })?,
        Command::ClearChannelGroup => {
            edit_interfaces(device, mode, |device, id| device.clear_channel_group(id))?
        }

        Command::ShowInterfacesStatus => result.output = device.show_interfaces_status(),
        Command::ShowIpInterfaceBrief => result.output = device.show_ip_interface_brief(),
        Command::ShowIpRoute => result.output = device.show_ip_route(),
        Command::ShowArp => result.output = device.show_arp(now),
        Command::ShowMacAddressTable => result.output = device.show_mac_address_table(now),
        Command::ShowVlanBrief => result.output = device.show_vlan_brief(),
        Command::ShowIpOspfNeighbor => result.output = device.show_ip_ospf_neighbor(now),
        Command::ShowIpOspfInterface => result.output = device.show_ip_ospf_interface(),
        Command::ShowIpOspfDatabase => result.output = device.show_ip_ospf_database(),
        Command::ShowSpanningTree => result.output = device.show_spanning_tree(None, now),
        Command::ShowSpanningTreeVlan(vlan) => {
            result.output = device.show_spanning_tree(Some(vlan), now)
        }
        Command::SetStpRapid(rapid) => device.set_stp_rapid(rapid)?,
        Command::SetStpPriority { vlan, priority } => device.set_stp_priority(vlan, priority)?,
        Command::SetStpPort(option) => edit_interfaces(device, mode, |device, id| {
            let mut policy = device.running_config().interfaces[&id]
                .spanning_tree
                .clone();
            match option {
                StpPortOption::Priority(value) => policy.priority = value,
                StpPortOption::Cost(value) => policy.cost = Some(value),
                StpPortOption::Portfast(value) => policy.portfast = value,
                StpPortOption::BpduGuard(value) => policy.bpdu_guard = value,
                StpPortOption::RootGuard(value) => policy.root_guard = value,
            }
            device.set_stp_port(id, policy)
        })?,

        Command::ShowAccessLists => result.output = device.show_access_lists(),
        Command::ShowIpDhcpBinding => result.output = device.show_ip_dhcp_binding(now),
        Command::ShowIpNatTranslations => result.output = device.show_ip_nat_translations(now),
        Command::SaveConfig => {
            device.save_config();
            result.output = "Building configuration...\n[OK]\n".into();
            result.persist = true;
        }

        Command::SetIpv6Routing(enabled) => device.set_ipv6_routing(enabled)?,
        Command::SetIpv6Port(option) => edit_interfaces(device, mode, |device, id| {
            let mut policy = device.running_config().interfaces[&id].ipv6.clone();
            match option {
                Ipv6PortOption::Enable(value) => policy.enabled = value,
                Ipv6PortOption::Autoconfig(value) => policy.autoconfig = value,
                Ipv6PortOption::RaSuppress(value) => policy.ra_suppress = value,
                Ipv6PortOption::Address(address, true) => {
                    policy
                        .addresses
                        .retain(|old| old.address() != address.address());
                    policy.addresses.insert(address);
                }
                Ipv6PortOption::Address(address, false) => {
                    policy.addresses.remove(&address);
                }
                Ipv6PortOption::LinkLocal(address, true) => policy.link_local = Some(address),
                Ipv6PortOption::LinkLocal(address, false) => {
                    if policy.link_local == Some(address) {
                        policy.link_local = None;
                    }
                }
                Ipv6PortOption::ClearAddresses => {
                    policy.addresses.clear();
                    policy.link_local = None;
                    policy.autoconfig = false;
                }
            }
            device.set_ipv6_policy(id, policy)
        })?,
        Command::SetIpv6Route {
            prefix,
            interface,
            next_hop,
            present,
        } => {
            let interface = interface
                .map(|name| {
                    device
                        .find_interface(&name)
                        .ok_or(rios_device::DeviceError::MissingInterface)
                })
                .transpose()?;
            device.set_ipv6_static_route(
                rios_config::Ipv6StaticRoute {
                    prefix,
                    next_hop,
                    interface,
                },
                present,
            )?;
        }
        Command::ShowIpv6InterfaceBrief => result.output = device.show_ipv6_interface_brief(),
        Command::ShowIpv6Neighbors => result.output = device.show_ipv6_neighbors(now),
        Command::ShowIpv6Route => result.output = device.show_ipv6_route(),
        Command::PingIpv6 {
            destination,
            interface,
        } => {
            let interface = interface
                .map(|name| {
                    device
                        .find_interface(&name)
                        .ok_or(rios_device::DeviceError::MissingInterface)
                })
                .transpose()?;
            result.request = Some(SimulationRequest::PingIpv6 {
                destination,
                interface,
            });
        }
        Command::Ping(address) => result.request = Some(SimulationRequest::Ping(address)),
        Command::NetworkUnavailable(feature) => {
            return Err(CliError::Unavailable(match feature {
                NetworkFeature::DebugPacket => "Packet debugging",
                NetworkFeature::DebugArp => "ARP debugging",
                NetworkFeature::DebugIcmp => "ICMP debugging",
            }));
        }
        Command::End => session.end_configuration(),
        Command::Exit => match mode {
            UserExec | PrivilegedExec => {
                result.close = true;
                result.output = "Connection closed.\n".into();
            }
            GlobalConfiguration => session.mode = PrivilegedExec,
            InterfaceConfiguration(_)
            | SubinterfaceConfiguration(_)
            | InterfaceRangeConfiguration(_, _)
            | VlanConfiguration(_)
            | RouterConfiguration(_)
            | DhcpPoolConfiguration(_)
            | AccessListConfiguration(_, _) => session.mode = GlobalConfiguration,
        },
    }
    Ok(result)
}
/// Atomically merge configuration commands through the normal engine.
/// Comments and blank lines are ignored; operational commands are rejected.
/// Existing runtime state and startup configuration are preserved.
pub fn load_configuration(device: &mut Device, text: &str) -> Result<(), CliError> {
    let mut candidate = device.clone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        let fail = |message: String| CliError::Configuration {
            line: index + 1,
            message,
        };
        if !matches!(
            session.mode,
            CliMode::GlobalConfiguration
                | CliMode::InterfaceConfiguration(_)
                | CliMode::SubinterfaceConfiguration(_)
                | CliMode::InterfaceRangeConfiguration(_, _)
                | CliMode::VlanConfiguration(_)
                | CliMode::RouterConfiguration(_)
                | CliMode::DhcpPoolConfiguration(_)
                | CliMode::AccessListConfiguration(_, _)
        ) {
            return Err(fail("commands after end are not allowed".into()));
        }
        let (parsed, parsed_mode) = crate::parser::parse_configuration(line, session.mode)
            .map(|parsed| (parsed, session.mode))
            .or_else(|original| {
                if matches!(
                    session.mode,
                    CliMode::InterfaceConfiguration(_)
                        | CliMode::SubinterfaceConfiguration(_)
                        | CliMode::InterfaceRangeConfiguration(_, _)
                        | CliMode::VlanConfiguration(_)
                        | CliMode::RouterConfiguration(_)
                        | CliMode::DhcpPoolConfiguration(_)
                        | CliMode::AccessListConfiguration(_, _)
                ) {
                    crate::parser::parse_configuration(line, CliMode::GlobalConfiguration)
                        .map(|parsed| (parsed, CliMode::GlobalConfiguration))
                } else {
                    Err(original)
                }
            })
            .map_err(|e| fail(e.to_string()))?;
        let ParsedInput::Command(command) = parsed else {
            return Err(fail("expected a configuration command".into()));
        };
        session.mode = parsed_mode;
        execute(&mut candidate, &mut session, command).map_err(|e| fail(e.to_string()))?;
    }
    *device = candidate;
    Ok(())
}
