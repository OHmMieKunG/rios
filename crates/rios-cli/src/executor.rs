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
            | Command::ShowIpOspfNeighbor
            | Command::ShowIpOspfInterface
            | Command::ShowIpOspfDatabase
            | Command::ShowSpanningTree
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
        Command::SetChannelGroup { .. } | Command::ClearChannelGroup => matches!(
            mode,
            InterfaceConfiguration(_) | InterfaceRangeConfiguration(_, _)
        ),
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
        Command::EnterRouterOspf(_) => mode == GlobalConfiguration,
        Command::NameVlan(_) => matches!(mode, VlanConfiguration(_)),
        Command::AddOspfNetwork(_) => matches!(mode, RouterConfiguration(RoutingProtocol::Ospf)),
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
        | Command::ShowIpOspfNeighbor
        | Command::ShowIpOspfInterface
        | Command::ShowIpOspfDatabase
        | Command::ShowSpanningTree
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
        Command::EnterRouterOspf(process_id) => {
            device.set_ospf_process(process_id)?;
            session.mode = RouterConfiguration(RoutingProtocol::Ospf);
        }
        Command::AddOspfNetwork(network) => device.add_ospf_network(network)?,
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
        Command::ShowAccessLists => result.output = device.show_access_lists(),
        Command::ShowIpDhcpBinding => result.output = device.show_ip_dhcp_binding(now),
        Command::ShowIpNatTranslations => result.output = device.show_ip_nat_translations(now),
        Command::SaveConfig => {
            device.save_config();
            result.output = "Building configuration...\n[OK]\n".into();
            result.persist = true;
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
