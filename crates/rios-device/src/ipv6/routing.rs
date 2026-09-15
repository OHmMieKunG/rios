//! IPv6 forwarding selection, with explicit link-local interface scope.
use super::*;
/// Source of an installed IPv6 route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6RouteSource {
    Connected,
    Static,
    RouterAdvertisement,
}
/// A resolved IPv6 route candidate, independent of IPv4 route state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Route {
    pub prefix: Ipv6Network,
    pub next_hop: Option<Ipv6Addr>,
    pub interface: InterfaceId,
    pub administrative_distance: u8,
    pub metric: u32,
    pub source: Ipv6RouteSource,
}
/// Outgoing interface, selected source and neighbor to resolve for an IPv6 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedIpv6Route {
    pub interface: InterfaceId,
    pub source_ip: Ipv6Addr,
    pub next_hop: Ipv6Addr,
}
impl Device {
    pub fn ipv6_routes(&self) -> Vec<Ipv6Route> {
        let mut routes = Vec::new();
        for (id, runtime) in &self.ipv6.interfaces {
            if !self.protocol_up(*id) || self.ipv6_link_local(*id).is_none() {
                continue;
            }
            for entry in runtime.addresses.values().filter(|e| {
                matches!(
                    e.state,
                    Ipv6AddressState::Preferred | Ipv6AddressState::Deprecated
                ) && e.origin != Ipv6AddressOrigin::Slaac
            }) {
                routes.push(Ipv6Route {
                    prefix: entry.address.network(),
                    next_hop: None,
                    interface: *id,
                    administrative_distance: 0,
                    metric: 0,
                    source: Ipv6RouteSource::Connected,
                });
            }
        }
        for (id, prefix) in self.ipv6.prefixes.keys() {
            if self.protocol_up(*id) && self.ipv6_link_local(*id).is_some() {
                routes.push(Ipv6Route {
                    prefix: *prefix,
                    next_hop: None,
                    interface: *id,
                    administrative_distance: 0,
                    metric: 0,
                    source: Ipv6RouteSource::RouterAdvertisement,
                });
            }
        }
        let connected = routes.clone();
        for route in &self.running_config.ipv6_static_routes {
            let port = route
                .interface
                .filter(|id| self.protocol_up(*id) && self.ipv6_link_local(*id).is_some())
                .or_else(|| {
                    if route.interface.is_some() {
                        return None;
                    }
                    connected
                        .iter()
                        .filter(|r| r.prefix.contains(route.next_hop))
                        .max_by_key(|r| r.prefix.prefix_len())
                        .map(|r| r.interface)
                });
            if let Some(interface) = port {
                routes.push(Ipv6Route {
                    prefix: route.prefix,
                    next_hop: Some(route.next_hop),
                    interface,
                    administrative_distance: 1,
                    metric: 0,
                    source: Ipv6RouteSource::Static,
                });
            }
        }
        for (id, address) in self.ipv6.routers.keys() {
            if self.protocol_up(*id)
                && self.ipv6_link_local(*id).is_some()
                && let Ok(prefix) = Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 0)
            {
                routes.push(Ipv6Route {
                    prefix,
                    next_hop: Some(*address),
                    interface: *id,
                    administrative_distance: 2,
                    metric: 0,
                    source: Ipv6RouteSource::RouterAdvertisement,
                });
            }
        }
        routes
    }
    pub fn resolve_ipv6_route(
        &self,
        destination: Ipv6Addr,
        scope: Option<InterfaceId>,
    ) -> Option<ResolvedIpv6Route> {
        let routes = self.ipv6_routes();
        let eligible: Vec<_> = routes
            .iter()
            .filter(|r| r.prefix.contains(destination) && scope.is_none_or(|id| r.interface == id))
            .collect();
        if destination.is_unicast_link_local()
            && scope.is_none()
            && eligible
                .iter()
                .filter(|r| r.prefix.prefix_len() > 0)
                .map(|r| r.interface)
                .collect::<BTreeSet<_>>()
                .len()
                > 1
        {
            return None;
        }
        let route = eligible.into_iter().min_by_key(|r| {
            (
                std::cmp::Reverse(r.prefix.prefix_len()),
                r.administrative_distance,
                r.metric,
                r.interface,
            )
        })?;
        let source_ip = self.ipv6_source(route.interface, destination)?;
        Some(ResolvedIpv6Route {
            interface: route.interface,
            source_ip,
            next_hop: route.next_hop.unwrap_or(destination),
        })
    }
}
