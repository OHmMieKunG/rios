use crate::*;
use rios_ipv4::{Ipv4Network, Route, RouteSource, RoutingTable};
use rios_simulator::SimTime;
use std::{fmt::Write, net::Ipv4Addr};

const ARP_LIFETIME_MS: u64 = 4 * 60 * 60 * 1000;

/// A dynamically learned IPv4-to-Ethernet mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpEntry {
    pub address: Ipv4Addr,
    pub mac_address: MacAddress,
    pub interface: InterfaceId,
    pub learned_at: SimTime,
}

/// Fully resolved egress decision used by the simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRoute {
    pub interface: InterfaceId,
    pub source_ip: Ipv4Addr,
    pub source_mac: MacAddress,
    pub next_hop: Ipv4Addr,
}

impl Device {
    /// Connected routes derived from operational interface configuration.
    pub fn routing_table(&self) -> RoutingTable {
        let mut table = RoutingTable::default();
        for id in self.running_config.interfaces.keys() {
            if self.protocol_up(*id)
                && let Some(ip) = self.interface_ipv4(*id)
            {
                table.insert(Route {
                    prefix: Ipv4Network::new(ip.address(), ip.prefix_len()).unwrap(),
                    next_hop: None,
                    outgoing_interface: Some(*id),
                    administrative_distance: 0,
                    metric: 0,
                    source: RouteSource::Connected,
                });
            }
        }
        let connected = table.clone();
        for (prefix, next_hop) in &self.running_config.static_routes {
            let Some(route) = connected.lookup(*next_hop) else {
                continue;
            };
            table.insert(Route {
                prefix: *prefix,
                next_hop: Some(*next_hop),
                outgoing_interface: route.outgoing_interface,
                administrative_distance: 1,
                metric: 0,
                source: RouteSource::Static,
            });
        }
        for (interface, lease) in &self.dhcp_leases {
            let Some(next_hop) = lease.default_router else {
                continue;
            };
            if self.protocol_up(*interface) && connected.lookup(next_hop).is_some() {
                table.insert(Route {
                    prefix: Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
                    next_hop: Some(next_hop),
                    outgoing_interface: Some(*interface),
                    administrative_distance: 1,
                    metric: 0,
                    source: RouteSource::Static,
                });
            }
        }
        for route in &self.ospf_runtime.routes {
            table.insert(route.clone());
        }
        table
    }

    /// Add or replace a static next-hop route in structured configuration.
    pub fn set_static_route(&mut self, prefix: Ipv4Network, next_hop: Ipv4Addr) {
        self.running_config.static_routes.insert(prefix, next_hop);
    }

    /// Remove a static route when both destination and next hop match.
    pub fn remove_static_route(&mut self, prefix: Ipv4Network, next_hop: Ipv4Addr) {
        if self.running_config.static_routes.get(&prefix) == Some(&next_hop) {
            self.running_config.static_routes.remove(&prefix);
        }
    }

    /// Resolve connected or static forwarding to an operational egress interface.
    pub fn resolve_route(&self, destination: Ipv4Addr) -> Option<ResolvedRoute> {
        let table = self.routing_table();
        let route = table.lookup(destination)?;
        let interface = route.outgoing_interface?;
        Some(ResolvedRoute {
            interface,
            source_ip: self.interface_ipv4(interface)?.address(),
            source_mac: self.interfaces[&interface].mac_address,
            next_hop: route.next_hop.unwrap_or(destination),
        })
    }

    /// Address and MAC used to reach a directly connected destination.
    pub fn connected_source(
        &self,
        destination: Ipv4Addr,
    ) -> Option<(InterfaceId, Ipv4Addr, MacAddress)> {
        let route = self.resolve_route(destination)?;
        (route.next_hop == destination).then_some((
            route.interface,
            route.source_ip,
            route.source_mac,
        ))
    }

    /// Whether an operational interface owns this address.
    pub fn owns_ipv4(&self, interface: InterfaceId, address: Ipv4Addr) -> bool {
        self.protocol_up(interface)
            && self
                .interface_ipv4(interface)
                .is_some_and(|ip| ip.address() == address)
    }

    /// Whether any operational interface owns this address.
    pub fn owns_any_ipv4(&self, address: Ipv4Addr) -> bool {
        self.running_config
            .interfaces
            .keys()
            .any(|interface| self.owns_ipv4(*interface, address))
    }

    /// Learn or refresh a dynamic ARP mapping.
    pub fn learn_arp(
        &mut self,
        address: Ipv4Addr,
        mac_address: MacAddress,
        interface: InterfaceId,
        now: SimTime,
    ) -> Result<(), DeviceError> {
        if !self.interfaces.contains_key(&interface) {
            return Err(DeviceError::MissingInterface);
        }
        self.arp_cache.insert(
            address,
            ArpEntry {
                address,
                mac_address,
                interface,
                learned_at: now,
            },
        );
        Ok(())
    }

    /// Resolve a non-expired ARP mapping, lazily aging stale entries.
    pub fn arp_lookup(&mut self, address: Ipv4Addr, now: SimTime) -> Option<ArpEntry> {
        let entry = self.arp_cache.get(&address).copied()?;
        if now.0.saturating_sub(entry.learned_at.0) >= ARP_LIFETIME_MS * 1000 {
            self.arp_cache.remove(&address);
            None
        } else {
            Some(entry)
        }
    }

    /// Render non-expired dynamic ARP entries at virtual time `now`.
    pub fn show_arp(&mut self, now: SimTime) -> String {
        self.arp_cache
            .retain(|_, entry| now.0.saturating_sub(entry.learned_at.0) < ARP_LIFETIME_MS * 1000);
        let mut output =
            String::from("Protocol  Address          Age  Hardware Addr     Interface\n");
        for entry in self.arp_cache.values() {
            let age = now.0.saturating_sub(entry.learned_at.0) / 60_000_000;
            let name = &self.running_config.interfaces[&entry.interface].name;
            writeln!(
                output,
                "Internet  {:<16} {:>3}  {:<17} {}",
                entry.address, age, entry.mac_address, name
            )
            .unwrap();
        }
        output
    }

    /// Render connected routes from current operational interface state.
    pub fn show_ip_route(&self) -> String {
        let table = self.routing_table();
        let mut output = String::from("Codes: C - connected, S - static, O - OSPF\n\n");
        for route in table.routes() {
            let interface = route
                .outgoing_interface
                .and_then(|id| self.running_config.interfaces.get(&id))
                .map_or("unknown", |config| config.name.as_str());
            if let Some(next_hop) = route.next_hop {
                let (code, distance) = match route.source {
                    RouteSource::Ospf => ("O", 110),
                    RouteSource::OspfInterArea => ("O IA", 110),
                    RouteSource::OspfExternal1 => ("O E1", 110),
                    RouteSource::OspfExternal2 => ("O E2", 110),
                    _ => ("S", route.administrative_distance),
                };
                writeln!(
                    output,
                    "{code:<4} {}/{} [{}/{}] via {}",
                    route.prefix.address(),
                    route.prefix.prefix_len(),
                    distance,
                    route.metric,
                    next_hop
                )
                .unwrap();
            } else {
                writeln!(
                    output,
                    "C    {}/{} is directly connected, {}",
                    route.prefix.address(),
                    route.prefix.prefix_len(),
                    interface
                )
                .unwrap();
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rios_ipv4::Ipv4InterfaceConfig;

    #[test]
    fn connected_routes_and_arp_aging_follow_virtual_state() {
        let mut device = Device::standalone();
        let id = InterfaceId(1);
        device
            .set_ipv4(
                id,
                Ipv4InterfaceConfig::new(Ipv4Addr::new(10, 0, 0, 1), 24).unwrap(),
            )
            .unwrap();
        device.set_admin_state(id, AdminState::Up).unwrap();
        device.set_link_state(id, LinkState::Up).unwrap();
        assert!(
            device
                .connected_source(Ipv4Addr::new(10, 0, 0, 99))
                .is_some()
        );
        assert!(
            device
                .connected_source(Ipv4Addr::new(10, 0, 1, 1))
                .is_none()
        );
        let mac = MacAddress([2, 0, 0, 0, 0, 2]);
        device
            .learn_arp(
                Ipv4Addr::new(10, 0, 0, 2),
                mac,
                id,
                SimTime::from_millis(10),
            )
            .unwrap();
        assert!(
            device
                .show_arp(SimTime::from_millis(60_010))
                .contains("10.0.0.2")
        );
        assert!(
            device
                .arp_lookup(
                    Ipv4Addr::new(10, 0, 0, 2),
                    SimTime::from_millis(ARP_LIFETIME_MS + 10)
                )
                .is_none()
        );
    }
}
