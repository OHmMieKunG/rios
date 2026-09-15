//! Link/area/AS scoped LSDB, local advertisements, aging, reliable flooding and IPv6 RIB.
use super::*;
use std::cmp::Ordering;
impl Device {
    pub(super) fn ospfv3_database(
        &self,
        interface: InterfaceId,
        area: u32,
        now: SimTime,
    ) -> BTreeMap<OspfV3LsaKey, OspfV3Lsa> {
        self.ospfv3
            .database
            .iter()
            .filter(|((scope, _), _)| {
                matches!(scope, Scope::As)
                    || *scope == Scope::Link(interface)
                    || *scope == Scope::Area(area)
            })
            .map(|((_, key), stored)| (*key, stored.current(now)))
            .collect()
    }
    /// Database visible on one interface, preserving link-local flooding scope.
    pub fn ospfv3_lsas(&self, interface: InterfaceId, now: SimTime) -> Vec<OspfV3Lsa> {
        let Some(binding) = self
            .running_config
            .interfaces
            .get(&interface)
            .and_then(|c| c.ipv6.ospf)
        else {
            return Vec::new();
        };
        self.ospfv3_database(interface, binding.area, now)
            .into_values()
            .collect()
    }
    pub(super) fn ospfv3_flood(
        &mut self,
        scope: Scope,
        lsa: &OspfV3Lsa,
        except: Option<(InterfaceId, Ipv4Addr)>,
        now: SimTime,
        out: &mut Vec<OspfV3Transmission>,
    ) {
        let mut bodies = Vec::new();
        for (key, n) in &mut self.ospfv3.neighbors {
            if except == Some(*key)
                || self.ospfv3.ports.get(&key.0).is_none_or(|p| {
                    scope != Scope::As
                        && scope != Scope::Area(p.area)
                        && scope != Scope::Link(key.0)
                })
            {
                continue;
            }
            if let Some(exchange) = &mut n.exchange
                && let Some(body) = exchange.flood(lsa.clone(), now)
            {
                bodies.push((key.0, n.info.address, body));
            }
        }
        out.extend(
            bodies
                .into_iter()
                .filter_map(|(id, to, body)| self.ospfv3_emit(id, to, body)),
        );
    }
    pub(super) fn ospfv3_install(
        &mut self,
        scope: Scope,
        mut lsa: OspfV3Lsa,
        except: Option<(InterfaceId, Ipv4Addr)>,
        now: SimTime,
        out: &mut Vec<OspfV3Transmission>,
    ) {
        let key = (scope, lsa.key());
        let Ok(header) = lsa.header() else {
            return;
        };
        if let Some(old) = self.ospfv3.database.get(&key) {
            if old
                .current(now)
                .header()
                .is_ok_and(|h| OspfV3Lsa::compare(&header, &h) != Ordering::Greater)
            {
                return;
            }
        } else if self.ospfv3.database.len() >= OSPF_DATABASE_LIMIT {
            return;
        }
        let own = Some(lsa.advertising_router) == self.ospfv3.router_id;
        if own && except.is_some() {
            if let Some(old) = self.ospfv3.database.get(&key) {
                lsa.body = old.lsa.body.clone();
                if let Some(sequence) = lsa.sequence.checked_add(1) {
                    lsa.sequence = sequence;
                    lsa.age = 0;
                } else {
                    lsa.age = LSA_MAX_AGE;
                }
            } else {
                lsa.age = LSA_MAX_AGE;
            }
        }
        self.ospfv3.database.insert(
            key,
            Stored {
                lsa: lsa.clone(),
                installed: now,
            },
        );
        self.ospfv3_flood(scope, &lsa, if own { None } else { except }, now, out);
    }
    pub(super) fn ospfv3_prefixes(&self, id: InterfaceId, metric: u16) -> Vec<OspfV3Prefix> {
        self.ipv6_addresses(id)
            .into_iter()
            .filter(|a| {
                matches!(
                    a.state,
                    Ipv6AddressState::Preferred | Ipv6AddressState::Deprecated
                ) && !a.address.address().is_unicast_link_local()
            })
            .map(|a| {
                let loopback = self.interfaces[&id].kind == InterfaceKind::Loopback;
                OspfV3Prefix {
                    prefix: if loopback {
                        Ipv6Network::new(a.address.address(), 128).unwrap_or(a.address.network())
                    } else {
                        a.address.network()
                    },
                    options: if loopback { 2 } else { 0 },
                    metric: if loopback { 0 } else { metric },
                }
            })
            .collect()
    }
    pub(super) fn ospfv3_originate(&mut self, now: SimTime, out: &mut Vec<OspfV3Transmission>) {
        let Some(self_id) = self.ospfv3.router_id else {
            return;
        };
        let active = self.ospfv3_active();
        let areas: BTreeSet<_> = active.iter().map(|(_, _, area)| *area).collect();
        let mut desired = BTreeMap::new();
        let mut add = |scope, id, body| {
            let lsa = OspfV3Lsa {
                age: 0,
                link_state_id: id,
                advertising_router: self_id,
                sequence: LSA_INITIAL_SEQUENCE,
                body,
            };
            desired.insert((scope, lsa.key()), lsa);
        };
        for area in areas {
            let mut links = Vec::new();
            let mut stub_prefixes = Vec::new();
            for (id, address, _) in active.iter().filter(|(_, _, a)| *a == area) {
                let policy = self.running_config.interfaces[id].ipv6.ospf_parameters;
                let full: Vec<_> = self
                    .ospfv3
                    .neighbors
                    .iter()
                    .filter(|((port, _), n)| port == id && n.info.state == OspfNeighborState::Full)
                    .map(|(_, n)| n)
                    .collect();
                let port = self.ospfv3.ports.get(id);
                if port.is_some() {
                    add(
                        Scope::Link(*id),
                        id.0 as u32,
                        OspfV3LsaBody::Link {
                            priority: policy.priority,
                            options: OSPFV3_OPTIONS,
                            link_local: *address,
                            prefixes: self.ospfv3_prefixes(*id, 0),
                        },
                    );
                }
                let transit = port.filter(|p| {
                    p.policy.network_type == OspfNetworkType::Broadcast
                        && !full.is_empty()
                        && (p.dr == self_id || full.iter().any(|n| n.info.router_id == p.dr))
                });
                if let Some(p) = transit {
                    let dr_interface = if p.dr == self_id {
                        id.0 as u32
                    } else {
                        full.iter()
                            .find(|n| n.info.router_id == p.dr)
                            .map_or(0, |n| n.info.neighbor_interface_id)
                    };
                    links.push(OspfV3RouterLink {
                        kind: OspfV3LinkType::Transit,
                        metric: policy.cost,
                        interface_id: id.0 as u32,
                        neighbor_interface_id: dr_interface,
                        neighbor_router: p.dr,
                    });
                    if p.dr == self_id {
                        let mut members: Vec<_> = full.iter().map(|n| n.info.router_id).collect();
                        members.push(self_id);
                        members.sort();
                        let mut prefixes = self.ospfv3_prefixes(*id, 0);
                        for lsa in self.ospfv3_database(*id, area, now).values() {
                            if lsa.age < LSA_MAX_AGE
                                && members.contains(&lsa.advertising_router)
                                && let OspfV3LsaBody::Link {
                                    prefixes: remote, ..
                                } = &lsa.body
                            {
                                prefixes.extend(remote);
                            }
                        }
                        prefixes.sort_by_key(|p| (p.prefix, p.options));
                        prefixes.dedup_by_key(|p| p.prefix);
                        add(
                            Scope::Area(area),
                            dr_interface,
                            OspfV3LsaBody::Network {
                                options: OSPFV3_OPTIONS,
                                routers: members,
                            },
                        );
                        add(
                            Scope::Area(area),
                            dr_interface,
                            OspfV3LsaBody::IntraAreaPrefix {
                                reference: OspfV3LsaKey {
                                    kind: V3_NETWORK_LSA,
                                    link_state_id: dr_interface,
                                    advertising_router: self_id,
                                },
                                prefixes,
                            },
                        );
                    }
                } else {
                    stub_prefixes.extend(self.ospfv3_prefixes(*id, policy.cost));
                }
                if policy.network_type == OspfNetworkType::PointToPoint {
                    for n in full {
                        links.push(OspfV3RouterLink {
                            kind: OspfV3LinkType::PointToPoint,
                            metric: policy.cost,
                            interface_id: id.0 as u32,
                            neighbor_interface_id: n.info.neighbor_interface_id,
                            neighbor_router: n.info.router_id,
                        });
                    }
                }
            }
            add(
                Scope::Area(area),
                0,
                OspfV3LsaBody::Router {
                    flags: 0,
                    options: OSPFV3_OPTIONS,
                    links,
                },
            );
            // Router prefix ID 0 cannot collide with physical interface IDs (which start at 1).
            add(
                Scope::Area(area),
                0,
                OspfV3LsaBody::IntraAreaPrefix {
                    reference: OspfV3LsaKey {
                        kind: V3_ROUTER_LSA,
                        link_state_id: 0,
                        advertising_router: self_id,
                    },
                    prefixes: stub_prefixes,
                },
            );
        }
        let mut updates = Vec::new();
        for (key, wanted) in &desired {
            let mut lsa = wanted.clone();
            if let Some(old) = self.ospfv3.database.get(key) {
                if old.lsa.body == lsa.body && old.current(now).age < 1800 {
                    continue;
                }
                if let Some(sequence) = old.lsa.sequence.checked_add(1) {
                    lsa.sequence = sequence;
                } else {
                    if old.lsa.age == LSA_MAX_AGE {
                        continue;
                    }
                    lsa = old.current(now);
                    lsa.age = LSA_MAX_AGE;
                }
            }
            updates.push((key.0, lsa));
        }
        for ((scope, key), stored) in &self.ospfv3.database {
            if stored.lsa.age == LSA_MAX_AGE {
                continue;
            }
            if (key.advertising_router == self_id && !desired.contains_key(&(*scope, *key)))
                || stored.current(now).age == LSA_MAX_AGE
            {
                let mut lsa = stored.current(now);
                lsa.age = LSA_MAX_AGE;
                updates.push((*scope, lsa));
            }
        }
        for (scope, lsa) in updates {
            let key = (scope, lsa.key());
            if !self.ospfv3.database.contains_key(&key)
                && self.ospfv3.database.len() >= OSPF_DATABASE_LIMIT
            {
                continue;
            }
            self.ospfv3.database.insert(
                key,
                Stored {
                    lsa: lsa.clone(),
                    installed: now,
                },
            );
            self.ospfv3_flood(scope, &lsa, None, now, out);
        }
        if self.ospfv3.neighbors.values().all(|n| {
            n.exchange
                .as_ref()
                .is_none_or(|e| e.pending() == (0, 0) && e.state == OspfNeighborState::Full)
        }) {
            self.ospfv3.database.retain(|_, s| {
                s.lsa.age != LSA_MAX_AGE || now.0.saturating_sub(s.installed.0) < 5_000_000
            });
        }
    }
    pub(super) fn ospfv3_routes(&mut self, now: SimTime) {
        self.ospfv3.routes.clear();
        let Some(self_id) = self.ospfv3.router_id else {
            return;
        };
        let areas: BTreeSet<_> = self.ospfv3_active().iter().map(|(_, _, a)| *a).collect();
        let mut routes: BTreeMap<Ipv6Network, Ipv6Route> = BTreeMap::new();
        for area in areas {
            let lsas: Vec<_> = self
                .ospfv3
                .database
                .iter()
                .filter(|((scope, _), _)| *scope == Scope::Area(area))
                .map(|(_, s)| s.current(now))
                .collect();
            for route in ospfv3_spf(self_id, &lsas).into_values() {
                let id = InterfaceId(u64::from(route.interface_id));
                if !self.protocol_up(id) {
                    continue;
                }
                let next_hop = if route.first_hop == self_id {
                    None
                } else {
                    let Some(n) = self
                        .ospfv3
                        .neighbors
                        .get(&(id, route.first_hop))
                        .filter(|n| n.info.state != OspfNeighborState::Init)
                    else {
                        continue;
                    };
                    Some(n.info.address)
                };
                let candidate = Ipv6Route {
                    prefix: route.prefix,
                    next_hop,
                    interface: id,
                    administrative_distance: 110,
                    metric: route.metric,
                    source: Ipv6RouteSource::Ospf,
                };
                if routes.get(&route.prefix).is_none_or(|old| {
                    (candidate.metric, candidate.interface, candidate.next_hop)
                        < (old.metric, old.interface, old.next_hop)
                }) {
                    routes.insert(route.prefix, candidate);
                }
            }
        }
        self.ospfv3.routes = routes.into_values().collect();
    }
}
