//! Static address/port NAT and deterministic dynamic pool/PAT translation.
use crate::*;
use rios_config::{NatOverloadConfig, NatPool, NatPoolRule, NatRole, NatTransport, StaticNat};
use rios_ipv4::{IpProtocol, Ipv4Packet};
use rios_simulator::SimTime;
use std::{fmt::Write, net::Ipv4Addr};
mod config;
mod transport;
use transport::{inbound_transport, outbound_transport, rewrite};

const NAT_TIMEOUT_MS: u64 = 60_000;
const NAT_PORT_FIRST: u16 = 10_000;
const NAT_PORT_LAST: u16 = 60_000;
const MAX_TRANSLATIONS: usize = 16384;
/// Transport discriminator in the NAT table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProtocol {
    Icmp,
    Udp,
    Tcp,
}
/// A translation decision, including allocation failures that must not leak private traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatOutcome {
    Unchanged,
    Translated,
    Drop,
}
/// Cumulative deterministic NAT accounting.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatStatistics {
    pub hits: u64,
    pub misses: u64,
    pub allocations: u64,
    pub expired: u64,
    pub drops: u64,
}
/// One expiring dynamic transport mapping.
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
    /// Compatibility helper; forwarding should use `nat_outbound` to observe exhaustion.
    pub fn translate_nat_outbound(
        &mut self,
        ingress: InterfaceId,
        egress: InterfaceId,
        packet: &mut Ipv4Packet,
        now: SimTime,
    ) -> bool {
        self.nat_outbound(ingress, egress, packet, now) == NatOutcome::Translated
    }
    /// Translate inside-to-outside traffic or explicitly reject exhausted allocations.
    pub fn nat_outbound(
        &mut self,
        ingress: InterfaceId,
        egress: InterfaceId,
        packet: &mut Ipv4Packet,
        now: SimTime,
    ) -> NatOutcome {
        if self.nat_role(ingress) != Some(NatRole::Inside)
            || self.nat_role(egress) != Some(NatRole::Outside)
        {
            return NatOutcome::Unchanged;
        }
        if self.translate_static(packet, true) {
            return NatOutcome::Translated;
        }
        let (acl, pool, overload) = if let Some(rule) = &self.running_config.nat_pool_rule {
            (
                rule.access_list,
                self.running_config.nat_pools.get(&rule.pool).copied(),
                rule.overload,
            )
        } else if let Some(rule) = self.running_config.nat_overload {
            if rule.outside_interface != egress {
                return NatOutcome::Unchanged;
            }
            (rule.access_list, None, true)
        } else {
            return NatOutcome::Unchanged;
        };
        if !self.access_list_permits(acl, packet.source) {
            return NatOutcome::Unchanged;
        }
        let Some((protocol, local_port, outside_port)) = outbound_transport(packet) else {
            return self.nat_drop();
        };
        self.expire_nat(now);
        let existing = self.nat_translations.iter().position(|entry| {
            entry.protocol == protocol
                && entry.inside_local_address == packet.source
                && entry.inside_local_port == local_port
                && entry.outside_global_address == packet.destination
                && entry.outside_global_port == outside_port
        });
        let index = if let Some(index) = existing {
            index
        } else {
            if self.nat_translations.len() >= MAX_TRANSLATIONS {
                return self.nat_drop();
            }
            let global = if let Some(pool) = pool {
                self.pool_address(pool, packet.source, overload)
            } else {
                self.interface_ipv4(egress).map(|ip| ip.address())
            };
            let Some(global) = global else {
                return self.nat_drop();
            };
            let global_port = if overload {
                self.allocate_nat_port()
            } else {
                Some(local_port)
            };
            let Some(global_port) = global_port else {
                return self.nat_drop();
            };
            self.nat_translations.push(NatTranslation {
                protocol,
                inside_local_address: packet.source,
                inside_local_port: local_port,
                inside_global_address: global,
                inside_global_port: global_port,
                outside_global_address: packet.destination,
                outside_global_port: outside_port,
                expires_at: now,
            });
            self.nat_statistics.allocations = self.nat_statistics.allocations.saturating_add(1);
            self.nat_translations.len() - 1
        };
        let entry = &mut self.nat_translations[index];
        entry.expires_at = SimTime(now.0.saturating_add(NAT_TIMEOUT_MS * 1000));
        if rewrite(
            packet,
            entry.inside_global_address,
            Some(entry.inside_global_port),
            true,
        ) {
            self.nat_statistics.hits = self.nat_statistics.hits.saturating_add(1);
            NatOutcome::Translated
        } else {
            self.nat_drop()
        }
    }
    fn nat_drop(&mut self) -> NatOutcome {
        self.nat_statistics.drops = self.nat_statistics.drops.saturating_add(1);
        NatOutcome::Drop
    }
    fn nat_role(&self, interface: InterfaceId) -> Option<NatRole> {
        self.running_config.interfaces.get(&interface)?.nat_role
    }
    /// Reverse outside traffic before local delivery or route lookup.
    pub fn translate_nat_inbound(
        &mut self,
        ingress: InterfaceId,
        packet: &mut Ipv4Packet,
        now: SimTime,
    ) -> bool {
        if self.nat_role(ingress) != Some(NatRole::Outside) {
            return false;
        }
        if self.translate_static(packet, false) {
            return true;
        }
        self.expire_nat(now);
        let Some((protocol, global_port, outside_port)) = inbound_transport(packet) else {
            return false;
        };
        let entry = self.nat_translations.iter_mut().find(|entry| {
            entry.protocol == protocol
                && entry.inside_global_address == packet.destination
                && entry.inside_global_port == global_port
                && entry.outside_global_address == packet.source
                && entry.outside_global_port == outside_port
        });
        let Some(entry) = entry else {
            self.nat_statistics.misses = self.nat_statistics.misses.saturating_add(1);
            return false;
        };
        entry.expires_at = SimTime(now.0.saturating_add(NAT_TIMEOUT_MS * 1000));
        if rewrite(
            packet,
            entry.inside_local_address,
            Some(entry.inside_local_port),
            false,
        ) {
            self.nat_statistics.hits = self.nat_statistics.hits.saturating_add(1);
            true
        } else {
            false
        }
    }
    fn translate_static(&mut self, packet: &mut Ipv4Packet, source: bool) -> bool {
        let address = if source {
            packet.source
        } else {
            packet.destination
        };
        let transport = if source {
            outbound_transport(packet)
        } else {
            inbound_transport(packet)
        };
        let rule = self.running_config.static_nat.iter().copied().find(|rule| {
            if (if source { rule.local() } else { rule.global() }) != address {
                return false;
            }
            match *rule {
                StaticNat::Address { .. } => true,
                StaticNat::Port {
                    protocol,
                    local_port,
                    global_port,
                    ..
                } => transport.is_some_and(|(kind, port, _)| {
                    kind == if protocol == NatTransport::Tcp {
                        NatProtocol::Tcp
                    } else {
                        NatProtocol::Udp
                    } && port == if source { local_port } else { global_port }
                }),
            }
        });
        let Some(rule) = rule else {
            return false;
        };
        let port = match rule {
            StaticNat::Address { .. } => None,
            StaticNat::Port {
                local_port,
                global_port,
                ..
            } => Some(if source { global_port } else { local_port }),
        };
        if rewrite(
            packet,
            if source { rule.global() } else { rule.local() },
            port,
            source,
        ) {
            self.nat_statistics.hits = self.nat_statistics.hits.saturating_add(1);
            true
        } else {
            false
        }
    }
    fn pool_address(&self, pool: NatPool, local: Ipv4Addr, overload: bool) -> Option<Ipv4Addr> {
        if let Some(entry) = self.nat_translations.iter().find(|entry| {
            entry.inside_local_address == local
                && entry.inside_global_address >= pool.first
                && entry.inside_global_address <= pool.last
        }) {
            return Some(entry.inside_global_address);
        }
        (u32::from(pool.first)..=u32::from(pool.last))
            .map(Ipv4Addr::from)
            .find(|address| {
                !self
                    .running_config
                    .static_nat
                    .iter()
                    .any(|rule| rule.global() == *address)
                    && (overload
                        || !self
                            .nat_translations
                            .iter()
                            .any(|entry| entry.inside_global_address == *address))
            })
    }
    /// Proxy ARP for configured static global addresses and active pool allocations.
    pub fn nat_owns_address(
        &mut self,
        interface: InterfaceId,
        address: Ipv4Addr,
        now: SimTime,
    ) -> bool {
        if self.nat_role(interface) != Some(NatRole::Outside) || !self.protocol_up(interface) {
            return false;
        }
        self.expire_nat(now);
        self.running_config
            .static_nat
            .iter()
            .any(|rule| rule.global() == address)
            || self
                .nat_translations
                .iter()
                .any(|entry| entry.inside_global_address == address)
    }
    /// Clear dynamic translations; static configuration survives.
    pub fn clear_nat_translations(&mut self) {
        self.nat_translations.clear();
    }
    /// Current cumulative NAT counters.
    pub fn nat_statistics(&self) -> &NatStatistics {
        &self.nat_statistics
    }
    /// Render operational allocation and translation counters.
    pub fn show_ip_nat_statistics(&mut self, now: SimTime) -> String {
        self.expire_nat(now);
        format!(
            "Total active translations: {} ({} static, {} dynamic)\nHits: {} Misses: {} Allocations: {} Expired: {} Drops: {}\n",
            self.nat_translations.len() + self.running_config.static_nat.len(),
            self.running_config.static_nat.len(),
            self.nat_translations.len(),
            self.nat_statistics.hits,
            self.nat_statistics.misses,
            self.nat_statistics.allocations,
            self.nat_statistics.expired,
            self.nat_statistics.drops
        )
    }
    /// Render non-expired dynamic and configured static mappings.
    pub fn show_ip_nat_translations(&mut self, now: SimTime) -> String {
        self.expire_nat(now);
        let mut output = String::from(
            "Pro  Inside global       Inside local        Outside local       Outside global\n",
        );
        for rule in &self.running_config.static_nat {
            match rule {
                StaticNat::Address { local, global } => writeln!(
                    output,
                    "---  {global:<19} {local:<19} ---                 ---"
                )
                .unwrap(),
                StaticNat::Port {
                    protocol,
                    local,
                    local_port,
                    global,
                    global_port,
                } => writeln!(
                    output,
                    "{:<4} {:<19} {:<19} ---                 ---",
                    if *protocol == NatTransport::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    },
                    endpoint(*global, *global_port),
                    endpoint(*local, *local_port)
                )
                .unwrap(),
            }
        }
        for entry in &self.nat_translations {
            let protocol = match entry.protocol {
                NatProtocol::Icmp => "icmp",
                NatProtocol::Udp => "udp",
                NatProtocol::Tcp => "tcp",
            };
            writeln!(
                output,
                "{:<4} {:<19} {:<19} {:<19} {}",
                protocol,
                endpoint(entry.inside_global_address, entry.inside_global_port),
                endpoint(entry.inside_local_address, entry.inside_local_port),
                endpoint(entry.outside_global_address, entry.outside_global_port),
                endpoint(entry.outside_global_address, entry.outside_global_port)
            )
            .unwrap();
        }
        output
    }
    fn expire_nat(&mut self, now: SimTime) {
        let before = self.nat_translations.len();
        self.nat_translations.retain(|entry| entry.expires_at > now);
        self.nat_statistics.expired = self
            .nat_statistics
            .expired
            .saturating_add((before - self.nat_translations.len()) as u64);
    }
    fn allocate_nat_port(&mut self) -> Option<u16> {
        for _ in NAT_PORT_FIRST..=NAT_PORT_LAST {
            let port = self.next_nat_port;
            self.next_nat_port = if port >= NAT_PORT_LAST {
                NAT_PORT_FIRST
            } else {
                port + 1
            };
            if !self.nat_translations.iter().any(|entry| entry.inside_global_port == port) && !self.running_config.static_nat.iter().any(|rule| matches!(rule, StaticNat::Port { global_port, .. } if *global_port == port)) { return Some(port); }
        }
        None
    }
}
fn endpoint(address: Ipv4Addr, port: u16) -> String {
    format!("{address}:{port}")
}
#[cfg(test)]
mod tests {
    use super::*;
    use rios_config::{AccessListAction, AdminState, StandardAccessListEntry};
    use rios_protocol::UdpDatagram;
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
        assert!(router.translate_nat_outbound(
            inside,
            outside,
            &mut outgoing,
            SimTime::from_millis(0)
        ));
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
        assert!(router.translate_nat_inbound(outside, &mut reply, SimTime::from_millis(1)));
        assert_eq!(reply.destination, "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            UdpDatagram::decode(&reply.payload)
                .unwrap()
                .destination_port,
            1234
        );
    }
}
