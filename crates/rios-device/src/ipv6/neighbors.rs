//! Interface-scoped neighbor resolution and reachability probes; IPv6 never uses ARP.
use super::*;
impl Device {
    pub fn ipv6_neighbors(&self) -> Vec<Ipv6Neighbor> {
        self.ipv6.neighbors.values().cloned().collect()
    }
    /// Return a cached MAC or begin bounded multicast address resolution.
    pub fn ipv6_resolve_neighbor(
        &mut self,
        id: InterfaceId,
        address: Ipv6Addr,
        now: SimTime,
    ) -> Option<MacAddress> {
        self.ipv6_link_local(id)?;
        if let Some(mac) = multicast_mac(address) {
            return Some(mac);
        }
        let key = (id, address);
        if !self.ipv6.neighbors.contains_key(&key) && self.ipv6.neighbors.len() >= NEIGHBOR_LIMIT {
            return None;
        }
        let neighbor = self.ipv6.neighbors.entry(key).or_insert(Ipv6Neighbor {
            interface: id,
            address,
            mac: None,
            state: Ipv6NeighborState::Incomplete,
            router: false,
            deadline: now,
            probes: 0,
        });
        if neighbor.state == Ipv6NeighborState::Reachable && neighbor.deadline <= now {
            neighbor.state = Ipv6NeighborState::Stale;
        }
        if neighbor.state == Ipv6NeighborState::Stale {
            neighbor.state = Ipv6NeighborState::Delay;
            neighbor.deadline = after(now, 5);
        }
        neighbor.mac
    }
    pub(super) fn ipv6_learn_neighbor(
        &mut self,
        id: InterfaceId,
        address: Ipv6Addr,
        mac: MacAddress,
        router: bool,
        now: SimTime,
    ) {
        if address.is_unspecified()
            || address.is_multicast()
            || mac.is_multicast()
            || mac == MacAddress([0; 6])
        {
            return;
        }
        let key = (id, address);
        if self.ipv6.neighbors.len() >= NEIGHBOR_LIMIT && !self.ipv6.neighbors.contains_key(&key) {
            return;
        }
        let entry = self.ipv6.neighbors.entry(key).or_insert(Ipv6Neighbor {
            interface: id,
            address,
            mac: Some(mac),
            state: Ipv6NeighborState::Stale,
            router,
            deadline: after(now, 300),
            probes: 0,
        });
        if entry.mac != Some(mac) || entry.state == Ipv6NeighborState::Incomplete {
            entry.mac = Some(mac);
            entry.state = Ipv6NeighborState::Stale;
            entry.deadline = after(now, 300);
        }
        entry.router |= router;
    }
    pub(super) fn ipv6_neighbor_timers(&mut self, now: SimTime) -> Vec<Ipv6ControlPacket> {
        let mut solicit = Vec::new();
        let mut remove = Vec::new();
        for (key, neighbor) in &mut self.ipv6.neighbors {
            if neighbor.deadline > now {
                continue;
            }
            match neighbor.state {
                Ipv6NeighborState::Reachable => {
                    neighbor.state = Ipv6NeighborState::Stale;
                    neighbor.deadline = after(now, 300);
                }
                Ipv6NeighborState::Stale => remove.push((*key, false)),
                Ipv6NeighborState::Delay => {
                    neighbor.state = Ipv6NeighborState::Probe;
                    neighbor.probes = 0;
                    neighbor.deadline = now;
                }
                _ => {}
            }
            if matches!(
                neighbor.state,
                Ipv6NeighborState::Incomplete | Ipv6NeighborState::Probe
            ) {
                if neighbor.probes >= 3 {
                    remove.push((*key, true));
                } else {
                    neighbor.probes += 1;
                    neighbor.deadline = SimTime(now.0.saturating_add(RETRANS_US));
                    solicit.push((
                        key.0,
                        key.1,
                        if neighbor.state == Ipv6NeighborState::Probe {
                            neighbor.mac
                        } else {
                            None
                        },
                    ));
                }
            }
        }
        for (key, failed) in remove {
            self.ipv6.neighbors.remove(&key);
            if failed {
                self.ipv6.routers.remove(&key);
            }
        }
        solicit
            .into_iter()
            .filter_map(|(id, target, mac)| {
                let source = self.ipv6_link_local(id)?;
                self.ipv6_control(
                    id,
                    source,
                    if mac.is_some() {
                        target
                    } else {
                        solicited_node(target)
                    },
                    mac,
                    NdMessage::NeighborSolicitation {
                        target,
                        options: vec![NdOption::SourceLinkLayer(self.interfaces[&id].mac_address)],
                    },
                )
            })
            .collect()
    }
    /// Process a validated ND message. All responses still have to cross virtual links.
    pub fn receive_ipv6_nd(
        &mut self,
        id: InterfaceId,
        packet: &Ipv6Packet,
        source_mac: MacAddress,
        message: NdMessage,
        now: SimTime,
    ) -> Vec<Ipv6ControlPacket> {
        self.ipv6_prepare(now);
        if !self.ipv6.interfaces.contains_key(&id)
            || source_mac == self.interfaces[&id].mac_address
            || message
                .validate(packet.source, packet.destination, packet.hop_limit)
                .is_err()
        {
            return vec![];
        }
        if packet.destination.is_multicast()
            && packet.destination != ALL_NODES
            && !(packet.destination == ALL_ROUTERS && self.ipv6_forwarding_enabled())
            && !self.ipv6.interfaces[&id]
                .addresses
                .keys()
                .any(|address| solicited_node(*address) == packet.destination)
        {
            return vec![];
        }
        let source_option = message.options().iter().find_map(|o| {
            if let NdOption::SourceLinkLayer(mac) = o {
                Some(*mac)
            } else {
                None
            }
        });
        let mut out = Vec::new();
        match message {
            NdMessage::NeighborSolicitation { target, .. } => {
                if self.ipv6_duplicate(id, target) {
                    return out;
                }
                if !self.ipv6_owns(target, Some(id)) {
                    return out;
                }
                if let Some(mac) = source_option {
                    self.ipv6_learn_neighbor(id, packet.source, mac, false, now);
                }
                let dad = packet.source.is_unspecified();
                if let Some(response) = self.ipv6_control(
                    id,
                    target,
                    if dad { ALL_NODES } else { packet.source },
                    (!dad).then_some(source_mac),
                    NdMessage::NeighborAdvertisement {
                        target,
                        router: self.ipv6_forwarding_enabled(),
                        solicited: !dad,
                        override_flag: true,
                        options: vec![NdOption::TargetLinkLayer(self.interfaces[&id].mac_address)],
                    },
                ) {
                    out.push(response);
                }
            }
            NdMessage::NeighborAdvertisement {
                target,
                router,
                solicited,
                override_flag,
                options,
            } => {
                if self.ipv6_duplicate(id, target) {
                    return out;
                }
                let Some(neighbor) = self.ipv6.neighbors.get_mut(&(id, target)) else {
                    return out;
                };
                let mac = options.iter().find_map(|o| {
                    if let NdOption::TargetLinkLayer(mac) = o {
                        Some(*mac)
                    } else {
                        None
                    }
                });
                if mac.is_some_and(|mac| mac.is_multicast() || mac == MacAddress([0; 6])) {
                    return out;
                }
                if neighbor.state == Ipv6NeighborState::Incomplete && mac.is_none() {
                    return out;
                }
                if !override_flag && neighbor.mac.is_some() && mac.is_some() && neighbor.mac != mac
                {
                    if neighbor.state == Ipv6NeighborState::Reachable {
                        neighbor.state = Ipv6NeighborState::Stale;
                        neighbor.deadline = after(now, 300);
                    }
                    return out;
                }
                let changed = mac.is_some() && mac != neighbor.mac;
                if mac.is_some() {
                    neighbor.mac = mac;
                }
                if solicited {
                    neighbor.state = Ipv6NeighborState::Reachable;
                    neighbor.deadline = after(now, 30);
                } else if changed || neighbor.state == Ipv6NeighborState::Incomplete {
                    neighbor.state = Ipv6NeighborState::Stale;
                    neighbor.deadline = after(now, 300);
                }
                neighbor.probes = 0;
                if neighbor.router && !router {
                    self.ipv6.routers.remove(&(id, target));
                }
                neighbor.router = router;
            }
            NdMessage::RouterSolicitation { .. } => {
                if self.ipv6_forwarding_enabled()
                    && !self.running_config.interfaces[&id].ipv6.ra_suppress
                {
                    if let Some(mac) = source_option {
                        self.ipv6_learn_neighbor(id, packet.source, mac, false, now);
                    }
                    if let Some(runtime) = self.ipv6.interfaces.get_mut(&id) {
                        runtime.ra_due = runtime
                            .ra_due
                            .min(runtime.ra_last.map_or(now, |last| after(last, 3)).max(now));
                    }
                }
            }
            advertisement @ NdMessage::RouterAdvertisement { .. } => {
                self.ipv6_receive_ra(id, packet.source, advertisement, now)
            }
        }
        out.extend(self.ipv6_tick(now));
        out
    }
}
