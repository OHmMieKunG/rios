//! ABR Type 3/4 summaries and ASBR Type 5 origination, all flooded as standard LSAs.
use super::*;
use rios_config::{OspfDefaultRoute, OspfRedistribute};
use rios_ipv4::RouteSource;
// More-specific prefixes reserve their exact IDs first. Other prefixes may use host bits
// in their LSA ID (RFC 2328 Appendix E); the mask still identifies the routed network.
fn insert_prefix_lsa(
    area: u32,
    prefix: Ipv4Network,
    mut lsa: Lsa,
    desired: &mut BTreeMap<(u32, LsaKey), Lsa>,
) {
    let mut free = |address| {
        lsa.link_state_id = address;
        !desired.contains_key(&(area, lsa.key()))
    };
    let chosen = if free(prefix.address()) {
        Some(prefix.address())
    } else if free(prefix.broadcast()) {
        Some(prefix.broadcast())
    } else {
        // Bounded by the number of occupied IDs, never by the IPv4 address space.
        (u32::from(prefix.address())..=u32::from(prefix.broadcast()))
            .take(desired.len() + 1)
            .map(Ipv4Addr::from)
            .find(|address| free(*address))
    };
    if let Some(address) = chosen {
        lsa.link_state_id = address;
        desired.insert((area, lsa.key()), lsa);
    }
}
impl Device {
    /// Enable or remove default-information origination; the RIB gates non-always policy.
    pub fn set_ospf_default(
        &mut self,
        policy: Option<OspfDefaultRoute>,
    ) -> Result<(), DeviceError> {
        if policy.is_some_and(|p| p.metric >= 0x00ff_ffff) {
            return Err(DeviceError::InvalidOspfConfig);
        }
        self.running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?
            .default_information = policy;
        Ok(())
    }
    /// Redistribute reachable static routes, excluding the default route.
    pub fn set_ospf_redistribute_static(
        &mut self,
        policy: Option<OspfRedistribute>,
    ) -> Result<(), DeviceError> {
        if policy.is_some_and(|p| p.metric >= 0x00ff_ffff) {
            return Err(DeviceError::InvalidOspfConfig);
        }
        self.running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?
            .redistribute_static = policy;
        Ok(())
    }
    pub(super) fn ospf_external_lsas(&self, self_id: Ipv4Addr) -> BTreeMap<(u32, LsaKey), Lsa> {
        let mut desired = BTreeMap::new();
        let Some(config) = &self.running_config.ospf else {
            return desired;
        };
        let table = self.routing_table();
        let mut external = BTreeMap::new();
        if let Some(policy) = config.redistribute_static {
            for route in table
                .routes()
                .iter()
                .filter(|r| r.source == RouteSource::Static && r.prefix.prefix_len() != 0)
            {
                external.insert(route.prefix, (policy.metric, policy.type_two));
            }
        }
        if let Some(policy) = config.default_information
            && (policy.always
                || table.routes().iter().any(|r| {
                    r.prefix.prefix_len() == 0
                        && matches!(r.source, RouteSource::Connected | RouteSource::Static)
                }))
            && let Ok(prefix) = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0)
        {
            external.insert(prefix, (policy.metric, policy.type_two));
        }
        let mut external: Vec<_> = external.into_iter().collect();
        external
            .sort_by_key(|(prefix, _)| (std::cmp::Reverse(prefix.prefix_len()), prefix.address()));
        for (prefix, (metric, type_two)) in external {
            let lsa = Lsa {
                age: 0,
                options: 2,
                link_state_id: prefix.address(),
                advertising_router: self_id,
                sequence: LSA_INITIAL_SEQUENCE,
                body: LsaBody::External {
                    mask: prefix.mask(),
                    metric,
                    type_two,
                    forwarding_address: Ipv4Addr::UNSPECIFIED,
                    tag: 0,
                },
            };
            insert_prefix_lsa(0, prefix, lsa, &mut desired);
        }
        desired
    }
    pub(super) fn ospf_summaries(
        &self,
        self_id: Ipv4Addr,
        areas: &BTreeSet<u32>,
        now: SimTime,
        desired: &mut BTreeMap<(u32, LsaKey), Lsa>,
    ) {
        if areas.len() < 2 || !areas.contains(&0) {
            return;
        }
        let mut prefixes: BTreeMap<Ipv4Network, (u32, OspfSpfRoute)> = BTreeMap::new();
        let mut asbrs: BTreeMap<Ipv4Addr, (u32, OspfAsbrPath)> = BTreeMap::new();
        for area in areas {
            // Include freshly originated local LSAs before they enter the flooding queue.
            let mut database = self.ospf_database(*area, now);
            for ((_, key), lsa) in desired.iter().filter(|((scope, _), _)| scope == area) {
                database.insert(*key, lsa.clone());
            }
            let calculation = ospf_calculate(self_id, database.values());
            for (prefix, route) in calculation.routes {
                if route.source != RouteSource::Ospf
                    && !(*area == 0 && route.source == RouteSource::OspfInterArea)
                {
                    continue;
                }
                if prefixes
                    .get(&prefix)
                    .is_none_or(|(_, old)| route.preference() < old.preference())
                {
                    prefixes.insert(prefix, (*area, route));
                }
            }
            for (id, path) in calculation.asbrs {
                if id == self_id || (path.inter_area && *area != 0) {
                    continue;
                }
                if asbrs.get(&id).is_none_or(|(_, old)| {
                    (path.inter_area, path.metric, path.first_hop)
                        < (old.inter_area, old.metric, old.first_hop)
                }) {
                    asbrs.insert(id, (*area, path));
                }
            }
        }
        let mut prefixes: Vec<_> = prefixes.into_iter().collect();
        prefixes
            .sort_by_key(|(prefix, _)| (std::cmp::Reverse(prefix.prefix_len()), prefix.address()));
        for area in areas {
            for (prefix, (source, route)) in &prefixes {
                if source == area {
                    continue;
                }
                let lsa = Lsa {
                    age: 0,
                    options: 2,
                    link_state_id: prefix.address(),
                    advertising_router: self_id,
                    sequence: LSA_INITIAL_SEQUENCE,
                    body: LsaBody::Summary {
                        mask: prefix.mask(),
                        metric: route.metric,
                    },
                };
                insert_prefix_lsa(*area, *prefix, lsa, desired);
            }
            for (id, (source, path)) in &asbrs {
                if source == area || path.metric >= 0x00ff_ffff {
                    continue;
                }
                let lsa = Lsa {
                    age: 0,
                    options: 2,
                    link_state_id: *id,
                    advertising_router: self_id,
                    sequence: LSA_INITIAL_SEQUENCE,
                    body: LsaBody::AsbrSummary {
                        metric: path.metric,
                    },
                };
                desired.insert((*area, lsa.key()), lsa);
            }
        }
    }
}
