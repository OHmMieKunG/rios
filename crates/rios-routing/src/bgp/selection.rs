//! Deterministic IPv4 BGP best-path selection before the device maps next hops into its RIB.
use super::*;
use std::{cmp::Reverse, collections::BTreeMap};
/// One eligible route candidate, after inbound policy and next-hop reachability checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpPath {
    pub prefix: Ipv4Network,
    pub attributes: BgpAttributes,
    /// None identifies a locally originated network statement.
    pub learned_from: Option<Ipv4Addr>,
    pub peer_router_id: Ipv4Addr,
    pub external: bool,
    pub igp_cost: u32,
}
/// Select one prefix's best route; MED is compared only between paths from the same neighboring AS.
/// A deterministic group reduction avoids order-dependent comparisons between three or more paths.
pub fn bgp_best_path<'a>(paths: impl IntoIterator<Item = &'a BgpPath>) -> Option<&'a BgpPath> {
    let mut candidates: Vec<_> = paths.into_iter().collect();
    let rank = |p: &&BgpPath| {
        (
            Reverse(p.attributes.local_preference.unwrap_or(100)),
            p.learned_from.is_some(),
            p.attributes.path_length(),
            p.attributes.origin,
        )
    };
    let best = candidates.iter().map(rank).min()?;
    candidates.retain(|p| rank(p) == best);
    let mut med_by_as = BTreeMap::new();
    for path in &candidates {
        let med = path.attributes.med.unwrap_or(0);
        med_by_as
            .entry(path.attributes.first_as())
            .and_modify(|old: &mut u32| *old = (*old).min(med))
            .or_insert(med);
    }
    candidates
        .into_iter()
        .filter(|p| p.attributes.med.unwrap_or(0) == med_by_as[&p.attributes.first_as()])
        .min_by_key(|p| {
            (
                !p.external,
                p.igp_cost,
                p.attributes.originator_id.unwrap_or(p.peer_router_id),
                p.attributes.cluster_list.len(),
                p.learned_from,
            )
        })
}
