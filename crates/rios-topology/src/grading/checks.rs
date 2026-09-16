//! Objective evaluation against typed device state and real simulated probes.
use super::*;
use rios_config::SwitchportMode;
use rios_ipv4::Ipv4Network;
impl Objective {
    pub(super) fn label(&self) -> String {
        match self {
            Self::InterfaceAddress {
                device, interface, ..
            } => format!("{device} {interface} address"),
            Self::InterfaceState {
                device, interface, ..
            } => format!("{device} {interface} state"),
            Self::OspfNeighborCount { device, .. } => format!("{device} OSPF adjacency"),
            Self::BgpNeighborCount { device, .. } => format!("{device} BGP sessions"),
            Self::Route { device, prefix, .. } => {
                format!("{device} route {}/{}", prefix.address, prefix.prefix_len)
            }
            Self::Reachable { from, to } => format!("{from} reaches {to}"),
            Self::Unreachable { from, to } => format!("{from} isolated from {to}"),
            Self::VlanMembership {
                device,
                interface,
                vlan,
            } => format!("{device} {interface} VLAN {}", vlan.get()),
            Self::StpState {
                device, interface, ..
            } => format!("{device} {interface} STP state"),
            Self::DhcpLease {
                device, interface, ..
            } => format!("{device} {interface} DHCP lease"),
            Self::NatAllocations { device, .. } => format!("{device} NAT allocations"),
            Self::AclMatches {
                device,
                acl,
                sequence,
                ..
            } => format!("{device} ACL {acl} sequence {sequence}"),
            Self::Latency { from, to, .. } => format!("{from} -> {to} latency"),
            Self::PacketLoss { from, to, .. } => format!("{from} -> {to} packet loss"),
            Self::Http { from, to, .. } => format!("{from} HTTP {to}"),
            Self::TcpEcho { from, to, .. } => format!("{from} TCP echo {to}"),
            Self::UdpEcho { from, to, .. } => format!("{from} UDP echo {to}"),
            Self::Dns { from, name, .. } => format!("{from} DNS {name}"),
        }
    }
    pub(super) fn check(&self, lab: &mut Lab) -> Result<(bool, String), LabError> {
        Ok(match self {
            Self::InterfaceAddress {
                device,
                interface,
                address,
            } => {
                let port = lab.endpoint(&format!("{device}:{interface}"))?;
                let actual = lab.device(port.device)?.interface_ipv4(port.interface);
                (
                    actual.is_some_and(|a| {
                        a.address() == address.address && a.prefix_len() == address.prefix_len
                    }),
                    format!(
                        "expected {}/{}, observed {actual:?}",
                        address.address, address.prefix_len
                    ),
                )
            }
            Self::InterfaceState {
                device,
                interface,
                up,
            } => {
                let port = lab.endpoint(&format!("{device}:{interface}"))?;
                let actual = lab.device(port.device)?.protocol_up(port.interface);
                (
                    actual == *up,
                    format!("protocol {}", if actual { "up" } else { "down" }),
                )
            }
            Self::OspfNeighborCount { device, count } => {
                let actual = lab
                    .device(lab.device_id(device)?)?
                    .ospf_neighbors()
                    .iter()
                    .filter(|n| n.state == rios_routing::OspfNeighborState::Full)
                    .count();
                (
                    actual == *count,
                    format!("{actual} Full neighbors, expected {count}"),
                )
            }
            Self::BgpNeighborCount { device, count } => {
                let actual = lab
                    .device(lab.device_id(device)?)?
                    .bgp_neighbors()
                    .iter()
                    .filter(|n| n.state == rios_routing::BgpState::Established)
                    .count();
                (
                    actual == *count,
                    format!("{actual} Established peers, expected {count}"),
                )
            }
            Self::Route {
                device,
                prefix,
                next_hop,
            } => {
                let prefix = Ipv4Network::new(prefix.address, prefix.prefix_len)
                    .map_err(|e| LabError::Protocol(e.to_string()))?;
                let table = lab.device(lab.device_id(device)?)?.routing_table();
                let found = table.routes().iter().any(|r| {
                    r.prefix == prefix && next_hop.is_none_or(|hop| r.next_hop == Some(hop))
                });
                (
                    found,
                    format!(
                        "matching route {}",
                        if found { "present" } else { "absent" }
                    ),
                )
            }
            Self::Reachable { from, to }
            | Self::Unreachable { from, to }
            | Self::Latency { from, to, .. }
            | Self::PacketLoss { from, to, .. } => {
                let device = lab.device_id(from)?;
                let ping = match lab.ping(device, *to) {
                    Ok(ping) => ping,
                    Err(LabError::Ping(crate::PingError::NoRoute(_)))
                        if matches!(self, Self::Unreachable { .. }) =>
                    {
                        return Ok((true, "no route to destination".into()));
                    }
                    Err(error) => return Err(error),
                };
                let passed = match self {
                    Self::Reachable { .. } => ping.received == ping.transmitted,
                    Self::Unreachable { .. } => ping.received == 0,
                    Self::Latency { max_ms, .. } => {
                        ping.received == ping.transmitted
                            && ping.round_trip_ms.iter().all(|rtt| rtt <= max_ms)
                    }
                    Self::PacketLoss { max_percent, .. } => {
                        u32::from(ping.transmitted - ping.received) * 100
                            <= u32::from(*max_percent) * u32::from(ping.transmitted)
                    }
                    _ => false,
                };
                (
                    passed,
                    format!(
                        "{}/{} replies; RTT {:?} ms",
                        ping.received, ping.transmitted, ping.round_trip_ms
                    ),
                )
            }
            Self::VlanMembership {
                device,
                interface,
                vlan,
            } => {
                let port = lab.endpoint(&format!("{device}:{interface}"))?;
                let device = lab.device(port.device)?;
                let config = &device.running_config().interfaces[&port.interface];
                let member = device.is_switchport(port.interface)
                    && device.running_config().vlans.contains_key(vlan)
                    && config.switchport.as_ref().is_some_and(|s| match s.mode {
                        SwitchportMode::Access => s.access_vlan == *vlan,
                        SwitchportMode::Trunk => s
                            .trunk_allowed_vlans
                            .as_ref()
                            .is_none_or(|allowed| allowed.contains(vlan)),
                    });
                (
                    member,
                    format!(
                        "VLAN {} {}",
                        vlan.get(),
                        if member { "permitted" } else { "not a member" }
                    ),
                )
            }
            Self::StpState {
                device,
                interface,
                vlan,
                state,
            } => {
                let port = lab.endpoint(&format!("{device}:{interface}"))?;
                let actual = lab
                    .device(port.device)?
                    .stp_port_state(port.interface, *vlan)
                    .map(|(_, state)| state);
                let expected = match state {
                    GradeStpState::Blocking => rios_switching::StpPortState::Blocking,
                    GradeStpState::Listening => rios_switching::StpPortState::Listening,
                    GradeStpState::Learning => rios_switching::StpPortState::Learning,
                    GradeStpState::Forwarding => rios_switching::StpPortState::Forwarding,
                };
                (
                    actual == Some(expected),
                    format!("observed {actual:?}, expected {expected:?}"),
                )
            }
            Self::DhcpLease {
                device,
                interface,
                address,
            } => {
                let port = lab.endpoint(&format!("{device}:{interface}"))?;
                let lease = lab.device(port.device)?.dhcp_lease(port.interface);
                (
                    lease.is_some_and(|lease| {
                        lease.expires_at > lab.now() && address.is_none_or(|ip| ip == lease.address)
                    }),
                    format!("lease address {:?}", lease.map(|lease| lease.address)),
                )
            }
            Self::NatAllocations { device, minimum } => {
                let actual = lab
                    .device(lab.device_id(device)?)?
                    .nat_statistics()
                    .allocations;
                (
                    actual >= *minimum,
                    format!("{actual} allocations, minimum {minimum}"),
                )
            }
            Self::AclMatches {
                device,
                acl,
                sequence,
                minimum,
            } => {
                let device = lab.device(lab.device_id(device)?)?;
                let id = device
                    .acl_id(acl)
                    .ok_or_else(|| LabError::Protocol(format!("unknown ACL {acl}")))?;
                if !device.running_config().named_access_lists[&id]
                    .entries
                    .contains_key(sequence)
                {
                    return Err(LabError::Protocol("ACL sequence does not exist".into()));
                }
                let count = device.acl_match_count(id, *sequence);
                (
                    count >= *minimum,
                    format!("{count} matches, minimum {minimum}"),
                )
            }
            Self::Http {
                from,
                to,
                port,
                contains,
            } => {
                let bytes = lab.http_get(lab.device_id(from)?, *to, *port)?;
                let expected = contains.as_deref().unwrap_or("").as_bytes();
                let matched =
                    expected.is_empty() || bytes.windows(expected.len()).any(|w| w == expected);
                (
                    bytes.starts_with(b"HTTP/1.1 200 ") && matched,
                    format!("received {} HTTP bytes", bytes.len()),
                )
            }
            Self::TcpEcho { from, to, port } => {
                let reply = lab.tcp_echo(lab.device_id(from)?, *to, *port, b"RIOS grading")?;
                (
                    reply == b"RIOS grading",
                    format!("{} echoed bytes", reply.len()),
                )
            }
            Self::UdpEcho { from, to, port } => {
                let reply =
                    lab.udp_request(lab.device_id(from)?, *to, *port, b"RIOS grading", 5000)?;
                (
                    reply.as_deref() == Some(b"RIOS grading"),
                    format!("{} echoed bytes", reply.as_ref().map_or(0, Vec::len)),
                )
            }
            Self::Dns {
                from,
                server,
                name,
                address,
            } => {
                let reply = lab.dns_lookup(lab.device_id(from)?, *server, 53, name)?;
                (
                    reply == Some(*address),
                    format!("resolved {reply:?}, expected {address}"),
                )
            }
        })
    }
}
