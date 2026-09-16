use rios_simulator::InterfaceId;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// IPv4 prefix normalized to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv4Network {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Network {
    /// Normalize an address to the requested prefix.
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Result<Self, crate::AddressError> {
        let mask = if prefix_len == 0 {
            0
        } else if prefix_len <= 32 {
            u32::MAX << (32 - prefix_len)
        } else {
            return Err(crate::AddressError::InvalidPrefix);
        };
        Ok(Self {
            address: Ipv4Addr::from(u32::from(address) & mask),
            prefix_len,
        })
    }

    /// Network address with host bits cleared.
    pub fn address(self) -> Ipv4Addr {
        self.address
    }

    /// Prefix width in bits.
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Dotted-decimal subnet mask.
    pub fn mask(self) -> Ipv4Addr {
        Ipv4Addr::from(if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        })
    }

    /// Last address in the prefix.
    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.address) | !u32::from(self.mask()))
    }

    /// Whether an address belongs to this prefix.
    pub fn contains(self, address: Ipv4Addr) -> bool {
        Self::new(address, self.prefix_len).is_ok_and(|network| network == self)
    }
}

/// Source code and future protocol ownership of a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouteSource {
    Connected,
    Static,
    Ospf,
    OspfInterArea,
    OspfExternal1,
    OspfExternal2,
    Rip,
    Bgp,
}

/// One route candidate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    /// Destination prefix.
    pub prefix: Ipv4Network,
    /// Next hop, absent for directly connected routes.
    pub next_hop: Option<Ipv4Addr>,
    /// Egress interface when resolved.
    pub outgoing_interface: Option<InterfaceId>,
    /// Source preference; lower values win after prefix length.
    pub administrative_distance: u8,
    /// Protocol-specific path cost.
    pub metric: u32,
    /// Owning route source.
    pub source: RouteSource,
}

/// Deterministic route collection with longest-prefix selection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingTable(Vec<Route>);

impl RoutingTable {
    /// Add one route candidate.
    pub fn insert(&mut self, route: Route) {
        self.0.push(route);
    }

    /// Routes in deterministic insertion order.
    pub fn routes(&self) -> &[Route] {
        &self.0
    }

    /// Select longest prefix, then lowest distance and metric.
    pub fn lookup(&self, address: Ipv4Addr) -> Option<&Route> {
        self.0
            .iter()
            .filter(|route| route.prefix.contains(address))
            .min_by_key(|route| {
                (
                    std::cmp::Reverse(route.prefix.prefix_len()),
                    route.administrative_distance,
                    route.metric,
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(prefix: &str, length: u8, distance: u8) -> Route {
        Route {
            prefix: Ipv4Network::new(prefix.parse().unwrap(), length).unwrap(),
            next_hop: None,
            outgoing_interface: None,
            administrative_distance: distance,
            metric: 0,
            source: RouteSource::Connected,
        }
    }

    #[test]
    fn longest_prefix_then_distance_wins() {
        let mut table = RoutingTable::default();
        table.insert(route("0.0.0.0", 0, 1));
        table.insert(route("10.0.0.0", 8, 10));
        table.insert(route("10.1.0.0", 16, 20));
        table.insert(route("10.1.0.0", 16, 5));
        let best = table.lookup("10.1.2.3".parse().unwrap()).unwrap();
        assert_eq!(best.prefix.prefix_len(), 16);
        assert_eq!(best.administrative_distance, 5);
        assert_eq!(
            table
                .lookup("192.0.2.1".parse().unwrap())
                .unwrap()
                .prefix
                .prefix_len(),
            0
        );
    }
}
