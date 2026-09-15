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
                    attributes: policy::local_attributes(Ipv4Addr::UNSPECIFIED),
                    learned_from: None,
                    peer_router_id: router_id,
                    external: false,
                    igp_cost: 0,
                });
            }
        }
        let mut accepted = BTreeMap::<Ipv4Addr, usize>::new();
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
            for (prefix, raw) in &peer.received {
                let Some(attributes) = policy::apply(
                    &self.running_config.routing_policy,
                    &peer.config.inbound,
                    *prefix,
                    raw.clone(),
                ) else {
                    continue;
                };
                *accepted.entry(*address).or_default() += 1;
                if attributes.originator_id == Some(router_id)
                    || attributes
                        .cluster_list
                        .contains(&config.cluster_id.unwrap_or(router_id))
                    || self.owns_any_ipv4(attributes.next_hop)
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
                    attributes,
                    learned_from: Some(*address),
                    peer_router_id,
                    external: peer.config.remote_as != config.local_as,
                    igp_cost: route.metric,
                });
            }
        }
        for (address, peer) in &mut self.bgp.peers {
            peer.accepted = accepted.get(address).copied().unwrap_or(0);
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
    pub(super) fn bgp_advertise(&mut self, config: &BgpConfig, router_id: Ipv4Addr, now: SimTime) {
        let prefixes: Vec<_> = self
            .routing_table()
            .routes()
            .iter()
            .map(|r| r.prefix)
            .collect();
        let policies = &self.running_config.routing_policy;
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
                if path.learned_from == Some(*address) {
                    continue;
                }
                let reflecting = !external && path.learned_from.is_some() && !path.external;
                let source_client = path
                    .learned_from
                    .and_then(|from| config.neighbors.get(&from))
                    .is_some_and(|p| p.route_reflector_client);
                if reflecting && !source_client && !peer.config.route_reflector_client {
                    continue;
                }
                let mut attributes = path.attributes.clone();
                if reflecting {
                    if attributes.originator_id == stream.fsm.peer_router_id {
                        continue;
                    }
                    attributes.originator_id.get_or_insert(path.peer_router_id);
                    attributes
                        .cluster_list
                        .insert(0, config.cluster_id.unwrap_or(router_id));
                }
                if external {
                    attributes.originator_id = None;
                    attributes.cluster_list.clear();
                    if path.learned_from.is_some() {
                        attributes.med = None;
                    }
                } else {
                    attributes.local_preference = Some(attributes.local_preference.unwrap_or(100));
                }
                if external
                    || (peer.config.next_hop_self && !reflecting)
                    || path.learned_from.is_none()
                {
                    attributes.next_hop = socket.local_address;
                }
                let Some(mut attributes) =
                    policy::apply(policies, &peer.config.outbound, *prefix, attributes)
                else {
                    continue;
                };
                if external {
                    if attributes.contains_as(peer.config.remote_as)
                        || attributes.prepend(&[config.local_as]).is_err()
                    {
                        continue;
                    }
                    attributes.local_preference = None;
                }
                for unknown in &mut attributes.unknown_transitive {
                    unknown.flags |= 0x20;
                }
                desired.insert(*prefix, attributes);
            }
            if let Some(default) = &peer.config.default_originate {
                let mut attributes = policy::local_attributes(socket.local_address);
                let permitted = if let Some(name) = &default.route_map {
                    prefixes
                        .iter()
                        .find_map(|p| policies.route_map_match(name, *p))
                        .is_some_and(|entry| policy::set_attributes(entry, &mut attributes))
                } else {
                    true
                };
                if permitted && (!external || attributes.prepend(&[config.local_as]).is_ok()) {
                    if external {
                        attributes.local_preference = None;
                    }
                    if let Ok(prefix) = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0) {
                        desired.insert(prefix, attributes);
                    }
                }
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
