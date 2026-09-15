//! Area-scoped LSDB, local LSA origination, reliable flooding and route installation.
use super::*;
use std::cmp::Ordering;
impl Device {
    pub(super) fn ospf_database(&self, area: u32, now: SimTime) -> BTreeMap<LsaKey, Lsa> {
        self.ospf_runtime
            .database
            .iter()
            .filter(|((scope, key), _)| *scope == area || key.kind == LsaType::External)
            .map(|((_, key), stored)| (*key, stored.current(now)))
            .collect()
    }
    /// Standard advertisements for structured inspection and protocol tests.
    pub fn ospf_lsas(&self, area: u32, now: SimTime) -> Vec<Lsa> {
        self.ospf_database(area, now).into_values().collect()
    }
    fn ospf_flood(
        &mut self,
        area: u32,
        lsa: &Lsa,
        except: Option<(InterfaceId, Ipv4Addr)>,
        now: SimTime,
        out: &mut Vec<OspfTransmission>,
    ) {
        let mut bodies = Vec::new();
        for (key, n) in &mut self.ospf_runtime.neighbors {
            if except == Some(*key)
                || self
                    .ospf_runtime
                    .interfaces
                    .get(&key.0)
                    .is_none_or(|r| r.area != area && !matches!(lsa.body, LsaBody::External { .. }))
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
                .filter_map(|(id, to, body)| self.ospf_emit(id, to, body)),
        );
    }
    pub(super) fn ospf_install(
        &mut self,
        area: u32,
        mut lsa: Lsa,
        except: Option<(InterfaceId, Ipv4Addr)>,
        now: SimTime,
        out: &mut Vec<OspfTransmission>,
    ) {
        let area = if matches!(lsa.body, LsaBody::External { .. }) {
            0
        } else {
            area
        };
        let key = (area, lsa.key());
        let Ok(header) = lsa.header() else {
            return;
        };
        if let Some(old) = self.ospf_runtime.database.get(&key) {
            let Ok(old_header) = old.current(now).header() else {
                return;
            };
            if compare_lsa(&header, &old_header) != Ordering::Greater {
                return;
            }
        } else if self.ospf_runtime.database.len() >= OSPF_DATABASE_LIMIT {
            return;
        }
        if Some(lsa.advertising_router) == self.ospf_runtime.router_id && except.is_some() {
            // Fight back with the locally originated body, never trust a peer's self-LSA contents.
            if let Some(old) = self.ospf_runtime.database.get(&key) {
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
        self.ospf_runtime.database.insert(
            key,
            StoredLsa {
                lsa: lsa.clone(),
                installed: now,
            },
        );
        self.ospf_flood(
            area,
            &lsa,
            if Some(lsa.advertising_router) == self.ospf_runtime.router_id {
                None
            } else {
                except
            },
            now,
            out,
        );
    }
    pub(super) fn ospf_originate(&mut self, now: SimTime, out: &mut Vec<OspfTransmission>) {
        let Some(self_id) = self.ospf_runtime.router_id else {
            return;
        };
        let active = self.ospf_interfaces();
        let areas: BTreeSet<_> = active.iter().map(|(_, _, a)| *a).collect();
        let mut desired = self.ospf_external_lsas(self_id);
        let external = !desired.is_empty();
        for area in &areas {
            let mut links = Vec::new();
            for (id, ip, _) in active.iter().filter(|(_, _, a)| a == area) {
                let policy = self.running_config.interfaces[id].ospf;
                let full: Vec<_> = self
                    .ospf_runtime
                    .neighbors
                    .iter()
                    .filter(|((port, _), n)| port == id && n.info.state == OspfNeighborState::Full)
                    .map(|(_, n)| n)
                    .collect();
                let runtime = self.ospf_runtime.interfaces.get(id);
                let transit = runtime.filter(|r| {
                    r.policy.network_type == OspfNetworkType::Broadcast
                        && !full.is_empty()
                        && (r.dr == ip.address() || full.iter().any(|n| n.info.address == r.dr))
                });
                if let Some(runtime) = transit {
                    links.push(RouterLink {
                        id: runtime.dr,
                        data: ip.address(),
                        kind: RouterLinkType::Transit,
                        metric: policy.cost,
                    });
                    if runtime.dr == ip.address() {
                        let mut routers: Vec<_> = full.iter().map(|n| n.info.router_id).collect();
                        routers.push(self_id);
                        routers.sort();
                        let lsa = Lsa {
                            age: 0,
                            options: 2,
                            link_state_id: ip.address(),
                            advertising_router: self_id,
                            sequence: LSA_INITIAL_SEQUENCE,
                            body: LsaBody::Network {
                                mask: ip.mask(),
                                routers,
                            },
                        };
                        desired.insert((*area, lsa.key()), lsa);
                    }
                } else {
                    let loopback = self.interfaces[id].kind == InterfaceKind::Loopback;
                    if let Ok(prefix) =
                        Ipv4Network::new(ip.address(), if loopback { 32 } else { ip.prefix_len() })
                    {
                        links.push(RouterLink {
                            id: prefix.address(),
                            data: if loopback {
                                Ipv4Addr::BROADCAST
                            } else {
                                ip.mask()
                            },
                            kind: RouterLinkType::Stub,
                            metric: policy.cost,
                        });
                    }
                }
                if policy.network_type == OspfNetworkType::PointToPoint {
                    for neighbor in full {
                        links.push(RouterLink {
                            id: neighbor.info.router_id,
                            data: ip.address(),
                            kind: RouterLinkType::PointToPoint,
                            metric: policy.cost,
                        });
                    }
                }
            }
            let lsa = Lsa {
                age: 0,
                options: 2,
                link_state_id: self_id,
                advertising_router: self_id,
                sequence: LSA_INITIAL_SEQUENCE,
                body: LsaBody::Router {
                    flags: u8::from(areas.len() > 1 && areas.contains(&0))
                        | if external { 2 } else { 0 },
                    links,
                },
            };
            desired.insert((*area, lsa.key()), lsa);
        }
        self.ospf_summaries(self_id, &areas, now, &mut desired);
        let mut updates = Vec::new();
        for (key, mut lsa) in desired.iter().map(|(k, v)| (*k, v.clone())) {
            if let Some(old) = self.ospf_runtime.database.get(&key) {
                if old.lsa.body == lsa.body && old.current(now).age < 1800 {
                    continue;
                }
                if old.lsa.sequence == i32::MAX {
                    if old.lsa.age == LSA_MAX_AGE {
                        continue;
                    }
                    lsa = old.current(now);
                    lsa.age = LSA_MAX_AGE;
                } else {
                    lsa.sequence = old.lsa.sequence + 1;
                }
            }
            updates.push((key.0, lsa));
        }
        for ((area, key), stored) in &self.ospf_runtime.database {
            if stored.lsa.age == LSA_MAX_AGE {
                continue;
            }
            if (key.advertising_router == self_id && !desired.contains_key(&(*area, *key)))
                || stored.current(now).age == LSA_MAX_AGE
            {
                let mut lsa = stored.current(now);
                lsa.age = LSA_MAX_AGE;
                updates.push((*area, lsa));
            }
        }
        for (area, lsa) in updates {
            // Local aging changes must flood even when computed age already equals MaxAge.
            let key = (area, lsa.key());
            if !self.ospf_runtime.database.contains_key(&key)
                && self.ospf_runtime.database.len() >= OSPF_DATABASE_LIMIT
            {
                continue;
            }
            self.ospf_runtime.database.insert(
                key,
                StoredLsa {
                    lsa: lsa.clone(),
                    installed: now,
                },
            );
            self.ospf_flood(area, &lsa, None, now, out);
        }
        let drained = self.ospf_runtime.neighbors.values().all(|n| {
            n.exchange
                .as_ref()
                .is_none_or(|e| e.pending() == (0, 0) && e.state == OspfNeighborState::Full)
        });
        if drained {
            self.ospf_runtime.database.retain(|_, stored| {
                stored.lsa.age != LSA_MAX_AGE
                    || now.0.saturating_sub(stored.installed.0) < 5_000_000
            });
        }
    }
    pub(super) fn recompute_ospf_routes(&mut self, now: SimTime) {
        self.ospf_runtime.routes.clear();
        let Some(self_id) = self.ospf_runtime.router_id else {
            return;
        };
        let areas: BTreeSet<_> = self
            .ospf_interfaces()
            .iter()
            .map(|(_, _, area)| *area)
            .collect();
        let abr = areas.len() > 1 && areas.contains(&0);
        let mut selected: BTreeMap<Ipv4Network, (OspfSpfRoute, Route)> = BTreeMap::new();
        for area in areas {
            let database = self.ospf_database(area, now);
            for route in ospf_spf(self_id, database.values()).into_values() {
                if route.first_hop == self_id
                    || (abr && area != 0 && route.source == rios_ipv4::RouteSource::OspfInterArea)
                {
                    continue;
                }
                let Some(neighbor) = self
                    .ospf_runtime
                    .neighbors
                    .values()
                    .filter(|n| {
                        n.info.router_id == route.first_hop
                            && n.info.state != OspfNeighborState::Init
                            && self
                                .ospf_runtime
                                .interfaces
                                .get(&n.info.interface)
                                .is_some_and(|r| r.area == area)
                    })
                    .min_by_key(|n| {
                        (
                            self.running_config.interfaces[&n.info.interface].ospf.cost,
                            n.info.interface,
                        )
                    })
                else {
                    continue;
                };
                if selected
                    .get(&route.prefix)
                    .is_none_or(|(old, _)| route.preference() < old.preference())
                {
                    selected.insert(
                        route.prefix,
                        (
                            route,
                            Route {
                                prefix: route.prefix,
                                next_hop: Some(neighbor.info.address),
                                outgoing_interface: Some(neighbor.info.interface),
                                administrative_distance: 110,
                                metric: route.metric,
                                source: route.source,
                            },
                        ),
                    );
                }
            }
        }
        self.ospf_runtime.routes = selected.into_values().map(|(_, route)| route).collect();
    }
}
