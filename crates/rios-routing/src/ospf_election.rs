//! Shared non-preemptive DR/BDR selection. Identity is a v2 interface address or v3 router ID.
use std::net::Ipv4Addr;
/// A two-way participant in one broadcast election.
#[derive(Clone, Copy)]
pub struct OspfElectionCandidate {
    pub priority: u8,
    pub id: Ipv4Addr,
    pub address: Ipv4Addr,
    pub dr: Ipv4Addr,
    pub bdr: Ipv4Addr,
}
/// Select designated and backup identities by declarations, priority and router ID.
pub fn ospf_election(candidates: &[OspfElectionCandidate]) -> (Ipv4Addr, Ipv4Addr) {
    let rank = |c: &&OspfElectionCandidate| (c.priority, c.id);
    let eligible: Vec<_> = candidates.iter().filter(|c| c.priority > 0).collect();
    let bdr = eligible
        .iter()
        .copied()
        .filter(|c| c.dr != c.address && c.bdr == c.address)
        .max_by_key(rank)
        .or_else(|| {
            eligible
                .iter()
                .copied()
                .filter(|c| c.dr != c.address)
                .max_by_key(rank)
        })
        .map_or(Ipv4Addr::UNSPECIFIED, |c| c.address);
    let dr = eligible
        .iter()
        .copied()
        .filter(|c| c.dr == c.address)
        .max_by_key(rank)
        .map_or(bdr, |c| c.address);
    (dr, bdr)
}
