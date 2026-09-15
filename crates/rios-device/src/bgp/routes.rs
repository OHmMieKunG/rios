//! Adj-RIB-In selection and incremental UPDATE/withdrawal output over each selected TCP session.
use super::*;
impl Device {
    pub(super) fn bgp_recompute(&mut self, config: &BgpConfig, router_id: Ipv4Addr) {
        let rib = self.routing_table_without_bgp();
        let mut candidates: BTreeMap<Ipv4Network, Vec<BgpPath>> = BTreeMap::new();
        for prefix in &config.networks {
            if rib.routes().iter().any(|r| r.prefix == *prefix) {
                candidates.entry(*prefix).or_default().push(BgpPath {
                    prefix: *prefix,
                    attributes: BgpAttributes {
                        origin: BgpOrigin::Igp,
                        as_path: Vec::new(),
                        next_hop: Ipv4Addr::UNSPECIFIED,
                        atomic_aggregate: false,
                        med: None,
                        local_preference: Some(100),
                        originator_id: None,
                        cluster_list: Vec::new(),
                        unknown_transitive: Vec::new(),
                    },
                    learned_from: None,
                    peer_router_id: router_id,
                    external: false,
                    igp_cost: 0,
                });
            }
        }
        for (address, peer) in &self.bgp.peers {
            let Some(stream) = peer
                .selected
                .and_then(|s| peer.streams.get(&s))
                .filter(|s| s.closing.is_none() && s.fsm.state == BgpState::Established)
            else {
                continue;
            };
            let Some(peer_router_id) = stream.fsm.peer_router_id else {
                continue;
            };
            for (prefix, attributes) in &peer.received {
                if self.owns_any_ipv4(attributes.next_hop)
                    || self.resolve_non_bgp_route(attributes.next_hop).is_none()
                {
                    continue;
                }
                let Some(route) = rib.lookup(attributes.next_hop) else {
                    continue;
                };
                if candidates.len() >= ROUTE_LIMIT && !candidates.contains_key(prefix) {
                    continue;
                }
                candidates.entry(*prefix).or_default().push(BgpPath {
                    prefix: *prefix,
                    attributes: attributes.clone(),
                    learned_from: Some(*address),
                    peer_router_id,
                    external: peer.config.remote_as != config.local_as,
                    igp_cost: route.metric,
                });
            }
        }
        self.bgp.best = candidates
            .into_iter()
            .filter_map(|(prefix, paths)| bgp_best_path(&paths).cloned().map(|p| (prefix, p)))
            .collect();
        self.bgp.routes = self
            .bgp
            .best
            .values()
            .filter(|p| p.learned_from.is_some())
            .filter_map(|path| {
                let resolved = self.resolve_non_bgp_route(path.attributes.next_hop)?;
                Some(Route {
                    prefix: path.prefix,
                    next_hop: Some(path.attributes.next_hop),
                    outgoing_interface: Some(resolved.interface),
                    administrative_distance: if path.external { 20 } else { 200 },
                    metric: path.attributes.med.unwrap_or(0),
                    source: RouteSource::Bgp,
                })
            })
            .collect();
    }
    pub(super) fn bgp_advertise(&mut self, config: &BgpConfig, _router_id: Ipv4Addr, now: SimTime) {
        for (address, peer) in &mut self.bgp.peers {
            let Some(socket) = peer.selected else {
                continue;
            };
            let Some(stream) = peer
                .streams
                .get_mut(&socket)
                .filter(|s| s.closing.is_none() && s.fsm.state == BgpState::Established)
            else {
                continue;
            };
            let external = peer.config.remote_as != config.local_as;
            let mut desired = BTreeMap::new();
            for (prefix, path) in &self.bgp.best {
                if path.learned_from == Some(*address)
                    || (!external && path.learned_from.is_some() && !path.external)
                {
                    continue;
                }
                let mut attributes = path.attributes.clone();
                if external {
                    if attributes.contains_as(peer.config.remote_as) {
                        continue;
                    }
                    if attributes.prepend(&[config.local_as]).is_err() {
                        continue;
                    }
                    attributes.local_preference = None;
                    attributes.originator_id = None;
                    attributes.cluster_list.clear();
                    if path.learned_from.is_some() {
                        attributes.med = None;
                    }
                } else {
                    attributes.local_preference = Some(attributes.local_preference.unwrap_or(100));
                }
                if external || peer.config.next_hop_self || path.learned_from.is_none() {
                    attributes.next_hop = socket.local_address;
                }
                for unknown in &mut attributes.unknown_transitive {
                    unknown.flags |= 0x20;
                }
                desired.insert(*prefix, attributes);
            }
            let withdrawn: Vec<_> = stream
                .advertised
                .keys()
                .filter(|p| !desired.contains_key(p))
                .copied()
                .collect();
            for prefix in withdrawn {
                if stream.output.len() >= TX_LIMIT / 2 {
                    break;
                }
                if let Err(error) = stream.queue(BgpMessage::Update(BgpUpdate {
                    withdrawn: vec![prefix],
                    attributes: None,
                    announced: Vec::new(),
                })) {
                    stream.fail(error, now);
                    break;
                }
                stream.advertised.remove(&prefix);
            }
            for (prefix, attributes) in desired {
                if stream.output.len() >= TX_LIMIT / 2 || stream.closing.is_some() {
                    break;
                }
                if stream.advertised.get(&prefix) == Some(&attributes) {
                    continue;
                }
                if let Err(error) = stream.queue(BgpMessage::Update(BgpUpdate {
                    withdrawn: Vec::new(),
                    attributes: Some(attributes.clone()),
                    announced: vec![prefix],
                })) {
                    stream.fail(error, now);
                    break;
                }
                stream.advertised.insert(prefix, attributes);
            }
        }
    }
}
