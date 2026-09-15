//! Operational addresses, duplicate address detection and SLAAC lifetime expiry.
use super::*;
impl Device {
    pub(super) fn ipv6_prepare(&mut self, now: SimTime) {
        let active: BTreeSet<_> = self
            .running_config
            .interfaces
            .iter()
            .filter(|(id, c)| c.ipv6.active() && c.switchport.is_none() && self.protocol_up(**id))
            .map(|(id, _)| *id)
            .collect();
        self.ipv6.interfaces.retain(|id, _| active.contains(id));
        self.ipv6.neighbors.retain(|(id, _), _| active.contains(id));
        self.ipv6
            .routers
            .retain(|(id, _), until| active.contains(id) && *until > now);
        self.ipv6
            .prefixes
            .retain(|(id, _), until| active.contains(id) && *until > now);
        for id in active {
            let policy = &self.running_config.interfaces[&id].ipv6;
            let local = policy
                .link_local
                .unwrap_or_else(|| link_local(self.interfaces[&id].mac_address));
            let mut wanted: BTreeMap<_, _> = policy
                .addresses
                .iter()
                .map(|address| (address.address(), (*address, Ipv6AddressOrigin::Manual)))
                .collect();
            if let Ok(address) = Ipv6InterfaceConfig::new(local, 64) {
                wanted.insert(local, (address, Ipv6AddressOrigin::LinkLocal));
            }
            let runtime = self.ipv6.interfaces.entry(id).or_default();
            runtime.addresses.retain(|ip, entry| {
                let configured = wanted.get(ip).is_some_and(|(address, origin)| {
                    *address == entry.address && *origin == entry.origin
                });
                (configured
                    || (!wanted.contains_key(ip)
                        && entry.origin == Ipv6AddressOrigin::Slaac
                        && policy.autoconfig))
                    && entry.valid_until.is_none_or(|until| until > now)
            });
            for (ip, (address, origin)) in wanted {
                let loopback = self.interfaces[&id].kind == InterfaceKind::Loopback;
                runtime.addresses.entry(ip).or_insert(Ipv6AddressEntry {
                    address,
                    state: if loopback {
                        Ipv6AddressState::Preferred
                    } else {
                        Ipv6AddressState::Tentative
                    },
                    origin,
                    preferred_until: None,
                    valid_until: None,
                    dad_due: (!loopback).then_some(now),
                    dad_sent: false,
                });
            }
            for address in runtime.addresses.values_mut() {
                if address.state == Ipv6AddressState::Preferred
                    && address.preferred_until.is_some_and(|until| until <= now)
                {
                    address.state = Ipv6AddressState::Deprecated;
                }
            }
        }
    }
    pub(super) fn ipv6_dad(&mut self, now: SimTime) -> Vec<Ipv6ControlPacket> {
        let mut probes = Vec::new();
        for (id, runtime) in &mut self.ipv6.interfaces {
            let local_duplicate = runtime.addresses.values().any(|a| {
                a.origin == Ipv6AddressOrigin::LinkLocal && a.state == Ipv6AddressState::Duplicate
            });
            if local_duplicate {
                continue;
            }
            for (ip, address) in &mut runtime.addresses {
                if address.state != Ipv6AddressState::Tentative
                    || address.dad_due.is_none_or(|due| due > now)
                {
                    continue;
                }
                if !address.dad_sent {
                    address.dad_sent = true;
                    address.dad_due = Some(SimTime(now.0.saturating_add(RETRANS_US)));
                    probes.push((*id, *ip));
                } else {
                    address.state = if address.preferred_until.is_some_and(|until| until <= now) {
                        Ipv6AddressState::Deprecated
                    } else {
                        Ipv6AddressState::Preferred
                    };
                    address.dad_due = None;
                }
            }
        }
        probes
            .into_iter()
            .filter_map(|(id, ip)| {
                self.ipv6_control(
                    id,
                    Ipv6Addr::UNSPECIFIED,
                    solicited_node(ip),
                    None,
                    NdMessage::NeighborSolicitation {
                        target: ip,
                        options: vec![],
                    },
                )
            })
            .collect()
    }
    /// Address state for structured inspection; tentative/duplicate addresses are never sources.
    pub fn ipv6_addresses(&self, id: InterfaceId) -> Vec<Ipv6AddressEntry> {
        self.ipv6
            .interfaces
            .get(&id)
            .map_or_else(Vec::new, |r| r.addresses.values().cloned().collect())
    }
    pub fn ipv6_link_local(&self, id: InterfaceId) -> Option<Ipv6Addr> {
        self.ipv6
            .interfaces
            .get(&id)?
            .addresses
            .values()
            .find(|a| {
                a.origin == Ipv6AddressOrigin::LinkLocal
                    && matches!(
                        a.state,
                        Ipv6AddressState::Preferred | Ipv6AddressState::Deprecated
                    )
            })
            .map(|a| a.address.address())
    }
    pub fn ipv6_owns(&self, address: Ipv6Addr, scope: Option<InterfaceId>) -> bool {
        self.ipv6.interfaces.iter().any(|(id, runtime)| {
            scope.is_none_or(|scope| scope == *id)
                && self.protocol_up(*id)
                && self.ipv6_link_local(*id).is_some()
                && runtime.addresses.get(&address).is_some_and(|a| {
                    matches!(
                        a.state,
                        Ipv6AddressState::Preferred | Ipv6AddressState::Deprecated
                    )
                })
        })
    }
    pub(super) fn ipv6_duplicate(&mut self, id: InterfaceId, target: Ipv6Addr) -> bool {
        let Some(entry) = self
            .ipv6
            .interfaces
            .get_mut(&id)
            .and_then(|r| r.addresses.get_mut(&target))
        else {
            return false;
        };
        if entry.state == Ipv6AddressState::Tentative {
            entry.state = Ipv6AddressState::Duplicate;
            entry.dad_due = None;
            return true;
        }
        false
    }
    /// Select a usable unicast source on the outgoing link, preferring non-deprecated addresses.
    pub fn ipv6_source(&self, id: InterfaceId, destination: Ipv6Addr) -> Option<Ipv6Addr> {
        if destination.is_unicast_link_local() || destination.is_multicast() {
            return self.ipv6_link_local(id);
        }
        self.ipv6
            .interfaces
            .get(&id)?
            .addresses
            .values()
            .filter(|a| {
                !a.address.address().is_unicast_link_local()
                    && matches!(
                        a.state,
                        Ipv6AddressState::Preferred | Ipv6AddressState::Deprecated
                    )
            })
            .min_by_key(|a| {
                (
                    a.state == Ipv6AddressState::Deprecated,
                    std::cmp::Reverse(
                        (u128::from(a.address.address()) ^ u128::from(destination)).leading_zeros(),
                    ),
                    a.address.address(),
                )
            })
            .map(|a| a.address.address())
    }
}
