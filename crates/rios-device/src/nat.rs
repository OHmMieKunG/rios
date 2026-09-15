use crate::*;
use rios_config::{NatOverloadConfig, NatRole};
use rios_ipv4::{IpProtocol, Ipv4Packet};
use rios_protocol::{IcmpEcho, UdpDatagram};
use rios_simulator::SimTime;
use std::{fmt::Write, net::Ipv4Addr};

const NAT_TIMEOUT_MS: u64 = 60_000;
const NAT_PORT_FIRST: u16 = 10_000;
const NAT_PORT_LAST: u16 = 60_000;

/// Transport discriminator displayed in the NAT translation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProtocol {
    Icmp,
    Udp,
}

/// One runtime dynamic PAT mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatTranslation {
    pub protocol: NatProtocol,
    pub inside_local_address: Ipv4Addr,
    pub inside_local_port: u16,
    pub inside_global_address: Ipv4Addr,
    pub inside_global_port: u16,
    pub outside_global_address: Ipv4Addr,
    pub outside_global_port: u16,
    pub expires_at: SimTime,
}

impl Device {
    /// Mark a router interface as the NAT inside or outside boundary.
    pub fn set_nat_role(
        &mut self,
        interface: InterfaceId,
        role: NatRole,
    ) -> Result<(), DeviceError> {
        if self.device_type != DeviceType::Router {
            return Err(DeviceError::NatUnsupported);
        }
        self.config_mut(interface)?.nat_role = Some(role);
        Ok(())
    }

    /// Configure ACL-selected dynamic source NAT through one outside interface.
    pub fn set_nat_overload(
        &mut self,
        access_list: AccessListId,
        outside_interface: InterfaceId,
    ) -> Result<(), DeviceError> {
        if self.device_type != DeviceType::Router {
            return Err(DeviceError::NatUnsupported);
        }
        if !self.running_config.access_lists.contains_key(&access_list)
            || !self
                .running_config
                .interfaces
                .contains_key(&outside_interface)
        {
            return Err(DeviceError::InvalidNatConfig);
        }
        self.running_config.nat_overload = Some(NatOverloadConfig {
            access_list,
            outside_interface,
        });
        Ok(())
    }

    /// Translate an inside packet before it leaves the configured outside interface.
    pub fn translate_nat_outbound(
        &mut self,
        ingress: InterfaceId,
        egress: InterfaceId,
        packet: &mut Ipv4Packet,
        now: SimTime,
    ) -> bool {
        let Some(config) = self.running_config.nat_overload else {
            return false;
        };
        if config.outside_interface != egress
            || self
                .running_config
                .interfaces
                .get(&ingress)
                .and_then(|interface| interface.nat_role)
                != Some(NatRole::Inside)
            || self
                .running_config
                .interfaces
                .get(&egress)
                .and_then(|interface| interface.nat_role)
                != Some(NatRole::Outside)
            || !self.access_list_permits(config.access_list, packet.source)
        {
            return false;
        }
        let Some(global_address) = self.interface_ipv4(egress).map(|ip| ip.address()) else {
            return false;
        };
        let Some((protocol, local_port, outside_port)) = outbound_transport(packet) else {
            return false;
        };
        self.expire_nat(now);
        let index = self
            .nat_translations
            .iter()
            .position(|entry| {
                entry.protocol == protocol
                    && entry.inside_local_address == packet.source
                    && entry.inside_local_port == local_port
                    && entry.outside_global_address == packet.destination
                    && entry.outside_global_port == outside_port
            })
            .or_else(|| {
                let global_port = self.allocate_nat_port()?;
                self.nat_translations.push(NatTranslation {
                    protocol,
                    inside_local_address: packet.source,
                    inside_local_port: local_port,
                    inside_global_address: global_address,
                    inside_global_port: global_port,
                    outside_global_address: packet.destination,
                    outside_global_port: outside_port,
                    expires_at: now,
                });
                Some(self.nat_translations.len() - 1)
            });
        let Some(index) = index else {
            return false;
        };
        let entry = &mut self.nat_translations[index];
        entry.expires_at = SimTime(now.0.saturating_add(NAT_TIMEOUT_MS));
        packet.source = entry.inside_global_address;
        rewrite_source_port(packet, entry.inside_global_port)
    }

    /// Reverse a matching PAT mapping on traffic arriving at the outside interface.
    pub fn translate_nat_inbound(
        &mut self,
        ingress: InterfaceId,
        packet: &mut Ipv4Packet,
        now: SimTime,
    ) -> bool {
        let Some(config) = self.running_config.nat_overload else {
            return false;
        };
        if config.outside_interface != ingress
            || self
                .running_config
                .interfaces
                .get(&ingress)
                .and_then(|interface| interface.nat_role)
                != Some(NatRole::Outside)
        {
            return false;
        }
        let Some((protocol, global_port, outside_port)) = inbound_transport(packet) else {
            return false;
        };
        self.expire_nat(now);
        let Some(entry) = self.nat_translations.iter_mut().find(|entry| {
            entry.protocol == protocol
                && entry.inside_global_address == packet.destination
                && entry.inside_global_port == global_port
                && entry.outside_global_address == packet.source
                && entry.outside_global_port == outside_port
        }) else {
            return false;
        };
        entry.expires_at = SimTime(now.0.saturating_add(NAT_TIMEOUT_MS));
        packet.destination = entry.inside_local_address;
        rewrite_destination_port(packet, entry.inside_local_port)
    }

    /// Render non-expired dynamic PAT mappings.
    pub fn show_ip_nat_translations(&mut self, now: SimTime) -> String {
        self.expire_nat(now);
        let mut output = String::from(
            "Pro  Inside global       Inside local        Outside local       Outside global\n",
        );
        for entry in &self.nat_translations {
            let protocol = match entry.protocol {
                NatProtocol::Icmp => "icmp",
                NatProtocol::Udp => "udp",
            };
            writeln!(
                output,
                "{:<4} {:<19} {:<19} {:<19} {}",
                protocol,
                endpoint(entry.inside_global_address, entry.inside_global_port),
                endpoint(entry.inside_local_address, entry.inside_local_port),
                endpoint(entry.outside_global_address, entry.outside_global_port),
                endpoint(entry.outside_global_address, entry.outside_global_port),
            )
            .unwrap();
        }
        output
    }

    fn expire_nat(&mut self, now: SimTime) {
        self.nat_translations.retain(|entry| entry.expires_at > now);
    }

    fn allocate_nat_port(&mut self) -> Option<u16> {
        for _ in NAT_PORT_FIRST..=NAT_PORT_LAST {
            let port = self.next_nat_port;
            self.next_nat_port = if port >= NAT_PORT_LAST {
                NAT_PORT_FIRST
            } else {
                port + 1
            };
            if !self
                .nat_translations
                .iter()
                .any(|entry| entry.inside_global_port == port)
            {
                return Some(port);
            }
        }
        None
    }
}

fn outbound_transport(packet: &Ipv4Packet) -> Option<(NatProtocol, u16, u16)> {
    match packet.protocol {
        IpProtocol::Icmp => IcmpEcho::decode(&packet.payload)
            .ok()
            .map(|echo| (NatProtocol::Icmp, echo.identifier, 0)),
        IpProtocol::Udp => UdpDatagram::decode(&packet.payload)
            .ok()
            .map(|udp| (NatProtocol::Udp, udp.source_port, udp.destination_port)),
        _ => None,
    }
}

fn inbound_transport(packet: &Ipv4Packet) -> Option<(NatProtocol, u16, u16)> {
    match packet.protocol {
        IpProtocol::Icmp => IcmpEcho::decode(&packet.payload)
            .ok()
            .map(|echo| (NatProtocol::Icmp, echo.identifier, 0)),
        IpProtocol::Udp => UdpDatagram::decode(&packet.payload)
            .ok()
            .map(|udp| (NatProtocol::Udp, udp.destination_port, udp.source_port)),
        _ => None,
    }
}

fn rewrite_source_port(packet: &mut Ipv4Packet, port: u16) -> bool {
    match packet.protocol {
        IpProtocol::Icmp => {
            let Ok(mut echo) = IcmpEcho::decode(&packet.payload) else {
                return false;
            };
            echo.identifier = port;
            packet.payload = echo.encode();
        }
        IpProtocol::Udp => {
            let Ok(mut udp) = UdpDatagram::decode(&packet.payload) else {
                return false;
            };
            udp.source_port = port;
            let Ok(payload) = udp.encode() else {
                return false;
            };
            packet.payload = payload;
        }
        _ => return false,
    }
    true
}

fn rewrite_destination_port(packet: &mut Ipv4Packet, port: u16) -> bool {
    match packet.protocol {
        IpProtocol::Icmp => {
            let Ok(mut echo) = IcmpEcho::decode(&packet.payload) else {
                return false;
            };
            echo.identifier = port;
            packet.payload = echo.encode();
        }
        IpProtocol::Udp => {
            let Ok(mut udp) = UdpDatagram::decode(&packet.payload) else {
                return false;
            };
            udp.destination_port = port;
            let Ok(payload) = udp.encode() else {
                return false;
            };
            packet.payload = payload;
        }
        _ => return false,
    }
    true
}

fn endpoint(address: Ipv4Addr, port: u16) -> String {
    format!("{address}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rios_config::{AccessListAction, AdminState, StandardAccessListEntry};
    use rios_simulator::{DeviceId, LinkState};

    #[test]
    fn udp_pat_round_trip_restores_address_and_port() {
        let mut router = Device::new(DeviceId(1), "R1", DeviceType::Router).unwrap();
        let inside = router.add_physical_interface("gi0/0").unwrap();
        let outside = router.add_physical_interface("gi0/1").unwrap();
        for interface in [inside, outside] {
            router.set_admin_state(interface, AdminState::Up).unwrap();
            router.set_link_state(interface, LinkState::Up).unwrap();
        }
        router
            .set_ipv4(
                outside,
                Ipv4InterfaceConfig::new("203.0.113.1".parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
        let acl = AccessListId::new(1).unwrap();
        router
            .add_access_list_entry(
                acl,
                StandardAccessListEntry {
                    action: AccessListAction::Permit,
                    source: "10.0.0.0".parse().unwrap(),
                    wildcard: "0.0.0.255".parse().unwrap(),
                },
            )
            .unwrap();
        router.set_nat_role(inside, NatRole::Inside).unwrap();
        router.set_nat_role(outside, NatRole::Outside).unwrap();
        router.set_nat_overload(acl, outside).unwrap();

        let mut outgoing = Ipv4Packet {
            source: "10.0.0.2".parse().unwrap(),
            destination: "203.0.113.2".parse().unwrap(),
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: UdpDatagram {
                source_port: 1234,
                destination_port: 53,
                payload: vec![1],
            }
            .encode()
            .unwrap(),
        };
        assert!(router.translate_nat_outbound(inside, outside, &mut outgoing, SimTime(0)));
        assert_eq!(outgoing.source, "203.0.113.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            UdpDatagram::decode(&outgoing.payload).unwrap().source_port,
            10_000
        );

        let mut reply = Ipv4Packet {
            source: "203.0.113.2".parse().unwrap(),
            destination: "203.0.113.1".parse().unwrap(),
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: UdpDatagram {
                source_port: 53,
                destination_port: 10_000,
                payload: vec![2],
            }
            .encode()
            .unwrap(),
        };
        assert!(router.translate_nat_inbound(outside, &mut reply, SimTime(1)));
        assert_eq!(reply.destination, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            UdpDatagram::decode(&reply.payload)
                .unwrap()
                .destination_port,
            1234
        );
    }
}
