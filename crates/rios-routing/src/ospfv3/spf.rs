//! Intra-area SPF uses topology identifiers; IPv6 prefixes attach only after the tree is built.
use super::*;
use crate::LSA_MAX_AGE;
use rios_ipv6::Ipv6Network;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr, u32),
}
/// A prefix's first adjacent router and local interface ID, before neighbor address resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfV3SpfRoute {
    pub prefix: Ipv6Network,
    pub metric: u32,
    pub first_hop: Ipv4Addr,
    pub interface_id: u32,
    pub origin: Ipv4Addr,
}
/// Deterministic weighted SPF with reciprocal link checks and no IPv4 address assumptions.
pub fn ospfv3_spf<'a>(
    self_id: Ipv4Addr,
    advertisements: impl IntoIterator<Item = &'a OspfV3Lsa>,
) -> BTreeMap<Ipv6Network, OspfV3SpfRoute> {
    let lsas: Vec<_> = advertisements
        .into_iter()
        .filter(|l| l.age < LSA_MAX_AGE)
        .collect();
    let mut routers: BTreeMap<Ipv4Addr, Vec<OspfV3RouterLink>> = BTreeMap::new();
    let mut networks = BTreeMap::new();
    for lsa in &lsas {
        match &lsa.body {
            OspfV3LsaBody::Router { options, links, .. } if options & 0x11 == 0x11 => {
                routers
                    .entry(lsa.advertising_router)
                    .or_default()
                    .extend(links);
            }
            OspfV3LsaBody::Network { routers, .. } => {
                networks.insert((lsa.advertising_router, lsa.link_state_id), routers);
            }
            _ => {}
        }
    }
    let root = Vertex::Router(self_id);
    let mut paths = BTreeMap::from([(root, (0u32, None))]);
    let mut pending = BinaryHeap::from([Reverse((0u32, root, None))]);
    while let Some(Reverse((cost, current, hop))) = pending.pop() {
        if paths.get(&current) != Some(&(cost, hop)) {
            continue;
        }
        let mut edges = Vec::new();
        match current {
            Vertex::Router(id) => {
                for link in routers.get(&id).into_iter().flatten() {
                    let next = match link.kind {
                        OspfV3LinkType::PointToPoint
                            if routers.get(&link.neighbor_router).is_some_and(|back| {
                                back.iter().any(|b| {
                                    b.kind == OspfV3LinkType::PointToPoint
                                        && b.neighbor_router == id
                                        && b.interface_id == link.neighbor_interface_id
                                        && b.neighbor_interface_id == link.interface_id
                                })
                            }) =>
                        {
                            Vertex::Router(link.neighbor_router)
                        }
                        OspfV3LinkType::Transit
                            if networks
                                .get(&(link.neighbor_router, link.neighbor_interface_id))
                                .is_some_and(|members| members.contains(&id)) =>
                        {
                            Vertex::Network(link.neighbor_router, link.neighbor_interface_id)
                        }
                        _ => continue,
                    };
                    edges.push((next, u32::from(link.metric), link.interface_id));
                }
            }
            Vertex::Network(dr, interface) => {
                for router in networks
                    .get(&(dr, interface))
                    .into_iter()
                    .flat_map(|v| v.iter())
                {
                    if routers.get(router).is_some_and(|links| {
                        links.iter().any(|l| {
                            l.kind == OspfV3LinkType::Transit
                                && l.neighbor_router == dr
                                && l.neighbor_interface_id == interface
                        })
                    }) {
                        edges.push((Vertex::Router(*router), 0, 0));
                    }
                }
            }
        }
        for (next, metric, interface) in edges {
            let first = match (hop, next) {
                (None, Vertex::Router(id)) => Some((id, interface)),
                (None, Vertex::Network(..)) => Some((self_id, interface)),
                (Some((id, port)), Vertex::Router(peer)) if id == self_id => Some((peer, port)),
                _ => hop,
            };
            let candidate = (cost.saturating_add(metric), first);
            if next != root && paths.get(&next).is_none_or(|old| candidate < *old) {
                paths.insert(next, candidate);
                pending.push(Reverse((candidate.0, next, first)));
            }
        }
    }
    let mut routes: BTreeMap<Ipv6Network, OspfV3SpfRoute> = BTreeMap::new();
    for lsa in lsas {
        let OspfV3LsaBody::IntraAreaPrefix {
            reference,
            prefixes,
        } = &lsa.body
        else {
            continue;
        };
        if reference.advertising_router != lsa.advertising_router {
            continue;
        }
        let vertex = match reference.kind {
            V3_ROUTER_LSA => Vertex::Router(reference.advertising_router),
            V3_NETWORK_LSA => {
                Vertex::Network(reference.advertising_router, reference.link_state_id)
            }
            _ => continue,
        };
        let Some((cost, Some((first_hop, interface_id)))) = paths.get(&vertex) else {
            continue;
        };
        for p in prefixes {
            if p.options & 1 != 0
                || p.prefix.address().is_unicast_link_local()
                || p.prefix.address().is_multicast()
            {
                continue;
            }
            let route = OspfV3SpfRoute {
                prefix: p.prefix,
                metric: cost.saturating_add(u32::from(p.metric)),
                first_hop: *first_hop,
                interface_id: *interface_id,
                origin: lsa.advertising_router,
            };
            let rank = |r: &OspfV3SpfRoute| (r.metric, r.first_hop, r.interface_id, r.origin);
            if route.metric < 0xffffff
                && routes
                    .get(&p.prefix)
                    .is_none_or(|old| rank(&route) < rank(old))
            {
                routes.insert(p.prefix, route);
            }
        }
    }
    routes
}
