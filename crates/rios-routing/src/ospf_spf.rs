//! Deterministic weighted SPF over router and transit-network LSAs.
use crate::{LSA_MAX_AGE, Lsa, LsaBody, RouterLinkType};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network, RouteSource};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap},
    net::Ipv4Addr,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Vertex {
    Router(Ipv4Addr),
    Network(Ipv4Addr),
}
/// A calculated prefix, before mapping its next-hop router to a local interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfSpfRoute {
    pub prefix: Ipv4Network,
    pub metric: u32,
    pub internal_cost: u32,
    pub first_hop: Ipv4Addr,
    pub origin: Ipv4Addr,
    pub source: RouteSource,
}
fn prefix(address: Ipv4Addr, mask: Ipv4Addr) -> Option<Ipv4Network> {
    Ipv4InterfaceConfig::from_mask(address, mask)
        .ok()
        .and_then(|ip| Ipv4Network::new(address, ip.prefix_len()).ok())
}
fn rank(source: RouteSource) -> u8 {
    match source {
        RouteSource::Ospf => 0,
        RouteSource::OspfInterArea => 1,
        RouteSource::OspfExternal1 => 2,
        _ => 3,
    }
}
impl OspfSpfRoute {
    /// OSPF path preference, including E2 internal-cost tie breaking.
    pub fn preference(&self) -> (u8, u32, u32, Ipv4Addr, Ipv4Addr) {
        (
            rank(self.source),
            self.metric,
            self.internal_cost,
            self.origin,
            self.first_hop,
        )
    }
}
fn install(routes: &mut BTreeMap<Ipv4Network, OspfSpfRoute>, route: OspfSpfRoute) {
    if route.metric < 0x00ff_ffff
        && routes
            .get(&route.prefix)
            .is_none_or(|old| route.preference() < old.preference())
    {
        routes.insert(route.prefix, route);
    }
}
/// Reachability of an ASBR, used when an ABR originates Type 4 summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfAsbrPath {
    pub metric: u32,
    pub first_hop: Ipv4Addr,
    pub inter_area: bool,
}
/// One area's prefixes and ASBR paths.
#[derive(Debug, Default)]
pub struct OspfSpfResult {
    pub routes: BTreeMap<Ipv4Network, OspfSpfRoute>,
    pub asbrs: BTreeMap<Ipv4Addr, OspfAsbrPath>,
}
/// Calculate prefix routes for callers that do not originate summaries.
pub fn ospf_spf<'a>(
    self_id: Ipv4Addr,
    lsas: impl IntoIterator<Item = &'a Lsa>,
) -> BTreeMap<Ipv4Network, OspfSpfRoute> {
    ospf_calculate(self_id, lsas).routes
}
/// Calculate one area's intra-area, summary, and external prefixes.
/// Links without a reciprocal advertisement cannot create reachability.
pub fn ospf_calculate<'a>(
    self_id: Ipv4Addr,
    lsas: impl IntoIterator<Item = &'a Lsa>,
) -> OspfSpfResult {
    let lsas: Vec<_> = lsas
        .into_iter()
        .filter(|lsa| lsa.age < LSA_MAX_AGE)
        .collect();
    let routers: BTreeMap<_, _> = lsas
        .iter()
        .filter_map(|lsa| match &lsa.body {
            LsaBody::Router { flags, links } => Some((lsa.advertising_router, (*flags, links))),
            _ => None,
        })
        .collect();
    let networks: BTreeMap<_, _> = lsas
        .iter()
        .filter_map(|lsa| match &lsa.body {
            LsaBody::Network { mask, routers } => {
                Some((lsa.link_state_id, (*mask, routers, lsa.advertising_router)))
            }
            _ => None,
        })
        .collect();
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
                if let Some((_, links)) = routers.get(&id) {
                    for link in *links {
                        match link.kind {
                            RouterLinkType::PointToPoint
                                if routers.get(&link.id).is_some_and(|(_, links)| {
                                    links.iter().any(|back| {
                                        back.kind == RouterLinkType::PointToPoint && back.id == id
                                    })
                                }) =>
                            {
                                edges.push((Vertex::Router(link.id), u32::from(link.metric)));
                            }
                            RouterLinkType::Transit
                                if networks
                                    .get(&link.id)
                                    .is_some_and(|(_, routers, _)| routers.contains(&id)) =>
                            {
                                edges.push((Vertex::Network(link.id), u32::from(link.metric)));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Vertex::Network(id) => {
                if let Some((_, members, _)) = networks.get(&id) {
                    for member in *members {
                        if routers.get(member).is_some_and(|(_, links)| {
                            links
                                .iter()
                                .any(|back| back.kind == RouterLinkType::Transit && back.id == id)
                        }) {
                            edges.push((Vertex::Router(*member), 0));
                        }
                    }
                }
            }
        }
        for (next, metric) in edges {
            let distance = cost.saturating_add(metric);
            let first = hop.or(match next {
                Vertex::Router(id) if id != self_id => Some(id),
                _ => None,
            });
            let candidate = (distance, first);
            if next != root && paths.get(&next).is_none_or(|old| candidate < *old) {
                paths.insert(next, candidate);
                pending.push(Reverse((distance, next, first)));
            }
        }
    }
    let mut routes = BTreeMap::new();
    for (vertex, (cost, hop)) in &paths {
        match *vertex {
            Vertex::Router(id) => {
                if let Some((_, links)) = routers.get(&id) {
                    for link in *links {
                        if link.kind == RouterLinkType::Stub
                            && let Some(prefix) = prefix(link.id, link.data)
                        {
                            install(
                                &mut routes,
                                OspfSpfRoute {
                                    prefix,
                                    metric: cost.saturating_add(u32::from(link.metric)),
                                    internal_cost: *cost,
                                    first_hop: hop.unwrap_or(self_id),
                                    origin: id,
                                    source: RouteSource::Ospf,
                                },
                            );
                        }
                    }
                }
            }
            Vertex::Network(id) => {
                if let Some((mask, _, origin)) = networks.get(&id)
                    && let Some(prefix) = prefix(id, *mask)
                {
                    install(
                        &mut routes,
                        OspfSpfRoute {
                            prefix,
                            metric: *cost,
                            internal_cost: *cost,
                            first_hop: hop.unwrap_or(self_id),
                            origin: *origin,
                            source: RouteSource::Ospf,
                        },
                    );
                }
            }
        }
    }
    // Resolve summaries before external forwarding addresses, independent of input order.
    let mut ordered = lsas.clone();
    ordered.sort_by_key(|lsa| lsa.key());
    let mut asbr_paths = BTreeMap::new();
    for lsa in &ordered {
        if let LsaBody::AsbrSummary { metric } = lsa.body
            && lsa.advertising_router != self_id
            && metric < 0x00ff_ffff
            && routers
                .get(&lsa.advertising_router)
                .is_some_and(|(flags, _)| flags & 1 != 0)
            && let Some((cost, Some(hop))) = paths.get(&Vertex::Router(lsa.advertising_router))
        {
            let candidate = (cost.saturating_add(metric), *hop);
            let old = asbr_paths.entry(lsa.link_state_id).or_insert(candidate);
            *old = (*old).min(candidate);
        }
    }
    for lsa in ordered {
        if lsa.advertising_router == self_id {
            continue;
        }
        let path = paths
            .get(&Vertex::Router(lsa.advertising_router))
            .and_then(|(cost, hop)| hop.map(|hop| (*cost, hop)));
        let is_asbr = routers
            .get(&lsa.advertising_router)
            .is_some_and(|(flags, _)| flags & 2 != 0);
        let path = if matches!(lsa.body, LsaBody::External { .. }) {
            path.filter(|_| is_asbr)
                .or_else(|| asbr_paths.get(&lsa.advertising_router).copied())
        } else {
            path
        };
        let Some((cost, hop)) = path else {
            continue;
        };
        let (mask, metric, source, first_hop, internal) = match lsa.body {
            LsaBody::Summary { mask, metric }
                if routers
                    .get(&lsa.advertising_router)
                    .is_some_and(|(flags, _)| flags & 1 != 0) =>
            {
                (
                    mask,
                    cost.saturating_add(metric),
                    RouteSource::OspfInterArea,
                    hop,
                    cost,
                )
            }
            LsaBody::External {
                mask,
                metric,
                type_two,
                forwarding_address,
                ..
            } => {
                let (internal, hop) = if forwarding_address.is_unspecified() {
                    (cost, hop)
                } else if let Some(route) = routes
                    .values()
                    .filter(|route| {
                        matches!(route.source, RouteSource::Ospf | RouteSource::OspfInterArea)
                            && route.prefix.contains(forwarding_address)
                    })
                    .max_by_key(|route| route.prefix.prefix_len())
                {
                    (route.metric, route.first_hop)
                } else {
                    continue;
                };
                (
                    mask,
                    if type_two {
                        metric
                    } else {
                        internal.saturating_add(metric)
                    },
                    if type_two {
                        RouteSource::OspfExternal2
                    } else {
                        RouteSource::OspfExternal1
                    },
                    hop,
                    internal,
                )
            }
            _ => continue,
        };
        if let Some(prefix) = prefix(lsa.link_state_id, mask) {
            install(
                &mut routes,
                OspfSpfRoute {
                    prefix,
                    metric,
                    internal_cost: internal,
                    first_hop,
                    origin: lsa.advertising_router,
                    source,
                },
            );
        }
    }
    let mut asbrs: BTreeMap<_, _> = asbr_paths
        .into_iter()
        .map(|(id, (metric, first_hop))| {
            (
                id,
                OspfAsbrPath {
                    metric,
                    first_hop,
                    inter_area: true,
                },
            )
        })
        .collect();
    for (id, (flags, _)) in &routers {
        if flags & 2 != 0
            && let Some((metric, hop)) = paths.get(&Vertex::Router(*id))
        {
            asbrs.insert(
                *id,
                OspfAsbrPath {
                    metric: *metric,
                    first_hop: hop.unwrap_or(self_id),
                    inter_area: false,
                },
            );
        }
    }
    OspfSpfResult { routes, asbrs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LSA_INITIAL_SEQUENCE, RouterLink};

    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, n)
    }
    fn lsa(id: u8, body: LsaBody) -> Lsa {
        Lsa {
            age: 0,
            options: 2,
            link_state_id: ip(id),
            advertising_router: ip(id),
            sequence: LSA_INITIAL_SEQUENCE,
            body,
        }
    }
    fn link(id: u8, metric: u16) -> RouterLink {
        RouterLink {
            id: ip(id),
            data: ip(0),
            kind: RouterLinkType::PointToPoint,
            metric,
        }
    }
    fn stub() -> RouterLink {
        RouterLink {
            id: Ipv4Addr::new(192, 0, 2, 0),
            data: Ipv4Addr::new(255, 255, 255, 0),
            kind: RouterLinkType::Stub,
            metric: 3,
        }
    }
    fn router(id: u8, links: Vec<RouterLink>) -> Lsa {
        lsa(id, LsaBody::Router { flags: 3, links })
    }
    fn prefix() -> Ipv4Network {
        Ipv4Network::new(stub().id, 24).unwrap()
    }

    #[test]
    fn weighted_paths_require_bidirectionality_and_are_order_independent() {
        let mut database = vec![
            router(1, vec![link(2, 50), link(3, 2)]),
            router(2, vec![link(1, 50), link(3, 2), stub()]),
            router(3, vec![link(1, 2), link(2, 2)]),
        ];
        let routes = ospf_spf(ip(1), &database);
        assert_eq!(routes[&prefix()].metric, 7);
        assert_eq!(routes[&prefix()].first_hop, ip(3));
        database.reverse();
        assert_eq!(ospf_spf(ip(1), &database), routes);
        database[0] = router(3, vec![link(1, 2)]);
        assert_eq!(ospf_spf(ip(1), &database)[&prefix()].metric, 53);
        database[1].age = LSA_MAX_AGE;
        assert!(!ospf_spf(ip(1), &database).contains_key(&prefix()));
    }

    #[test]
    fn transit_network_adds_interface_cost_once() {
        let transit = |metric| RouterLink {
            id: ip(100),
            data: ip(0),
            kind: RouterLinkType::Transit,
            metric,
        };
        let database = vec![
            router(1, vec![transit(10)]),
            router(2, vec![transit(20), stub()]),
            lsa(
                100,
                LsaBody::Network {
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    routers: vec![ip(1), ip(2)],
                },
            ),
        ];
        let route = ospf_spf(ip(1), &database)[&prefix()];
        assert_eq!((route.metric, route.first_hop), (13, ip(2)));
    }

    #[test]
    fn summaries_resolve_forwarding_addresses_before_external_routes() {
        let mut summary = lsa(
            2,
            LsaBody::Summary {
                mask: stub().data,
                metric: 5,
            },
        );
        summary.link_state_id = stub().id;
        let mut external = lsa(
            2,
            LsaBody::External {
                mask: Ipv4Addr::UNSPECIFIED,
                metric: 20,
                type_two: false,
                forwarding_address: Ipv4Addr::new(192, 0, 2, 1),
                tag: 0,
            },
        );
        external.link_state_id = Ipv4Addr::UNSPECIFIED;
        let mut database = vec![
            router(1, vec![link(2, 10)]),
            router(2, vec![link(1, 10)]),
            external,
            summary,
        ];
        let default = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
        let routes = ospf_spf(ip(1), &database);
        assert_eq!(routes[&prefix()].source, RouteSource::OspfInterArea);
        assert_eq!(routes[&default].metric, 35);
        assert_eq!(routes[&default].source, RouteSource::OspfExternal1);
        database.reverse();
        assert_eq!(ospf_spf(ip(1), &database), routes);
    }

    #[test]
    fn type_four_reaches_remote_asbr_and_e2_uses_internal_cost_tiebreak() {
        let mut summary = lsa(2, LsaBody::AsbrSummary { metric: 5 });
        summary.link_state_id = ip(9);
        assert_eq!(Lsa::decode(&summary.encode().unwrap()).unwrap(), summary);
        let external = |id| {
            let mut lsa = lsa(
                id,
                LsaBody::External {
                    mask: stub().data,
                    metric: 20,
                    type_two: true,
                    forwarding_address: Ipv4Addr::UNSPECIFIED,
                    tag: 0,
                },
            );
            lsa.link_state_id = stub().id;
            lsa
        };
        let database = vec![
            router(1, vec![link(2, 10), link(3, 20)]),
            router(2, vec![link(1, 10)]),
            router(3, vec![link(1, 20)]),
            summary,
            external(9),
            external(3),
        ];
        let route = ospf_spf(ip(1), &database)[&prefix()];
        assert_eq!(
            (route.metric, route.internal_cost, route.first_hop),
            (20, 15, ip(2))
        );
        assert_eq!(route.source, RouteSource::OspfExternal2);
    }
}
