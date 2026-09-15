//! OSPFv3 uses the shared election algorithm with router IDs as DR/BDR identities.
use super::*;
impl Device {
    pub(super) fn ospfv3_elect(&mut self, now: SimTime, out: &mut Vec<OspfV3Transmission>) {
        let Some(self_id) = self.ospfv3.router_id else {
            return;
        };
        let ids: Vec<_> = self.ospfv3.ports.keys().copied().collect();
        for id in ids {
            let runtime = &self.ospfv3.ports[&id];
            if runtime.policy.network_type == OspfNetworkType::Broadcast {
                let mut candidates: Vec<_> = self
                    .ospfv3
                    .neighbors
                    .iter()
                    .filter(|((port, _), n)| *port == id && n.info.state != OspfNeighborState::Init)
                    .map(|(_, n)| OspfElectionCandidate {
                        priority: n.info.priority,
                        id: n.info.router_id,
                        address: n.info.router_id,
                        dr: n.hello.designated_router,
                        bdr: n.hello.backup_router,
                    })
                    .collect();
                let backup_seen = candidates
                    .iter()
                    .any(|c| c.bdr == c.address || (c.dr == c.address && c.bdr.is_unspecified()));
                if now < runtime.wait_until && !backup_seen && runtime.dr.is_unspecified() {
                    continue;
                }
                let local = OspfElectionCandidate {
                    priority: runtime.policy.priority,
                    id: self_id,
                    address: self_id,
                    dr: runtime.dr,
                    bdr: runtime.bdr,
                };
                candidates.push(local);
                let (mut dr, mut bdr) = ospf_election(&candidates);
                if (dr == local.address) != (local.dr == local.address)
                    || (bdr == local.address) != (local.bdr == local.address)
                {
                    if let Some(last) = candidates.last_mut() {
                        last.dr = dr;
                        last.bdr = bdr;
                    }
                    (dr, bdr) = ospf_election(&candidates);
                }
                if let Some(runtime) = self.ospfv3.ports.get_mut(&id) {
                    if runtime.dr != dr || runtime.bdr != bdr {
                        runtime.hello_due = now;
                    }
                    runtime.dr = dr;
                    runtime.bdr = bdr;
                    runtime.wait_until = now;
                }
            }
            let runtime = &self.ospfv3.ports[&id];
            let database = self.ospfv3_database(id, runtime.area, now);
            let mtu = self.running_config.interfaces[&id].mtu;
            let mut bodies = Vec::new();
            for ((port, rid), neighbor) in &mut self.ospfv3.neighbors {
                if *port != id || neighbor.info.state == OspfNeighborState::Init {
                    continue;
                }
                let adjacent = runtime.policy.network_type == OspfNetworkType::PointToPoint
                    || [runtime.dr, runtime.bdr].contains(&self_id)
                    || [runtime.dr, runtime.bdr].contains(&neighbor.info.router_id);
                if adjacent && neighbor.exchange.is_none() {
                    self.ospfv3.sequence = self.ospfv3.sequence.wrapping_add(1);
                    let mut exchange =
                        OspfV3Exchange::new(self_id, *rid, mtu, self.ospfv3.sequence);
                    bodies.push((neighbor.info.address, exchange.start(&database, now)));
                    neighbor.info.state = exchange.state;
                    neighbor.exchange = Some(exchange);
                } else if !adjacent {
                    neighbor.exchange = None;
                    neighbor.info.state = OspfNeighborState::TwoWay;
                }
            }
            out.extend(
                bodies
                    .into_iter()
                    .filter_map(|(to, body)| self.ospfv3_emit(id, to, body)),
            );
        }
    }
}
