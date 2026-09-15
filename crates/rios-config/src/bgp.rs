//! Persistent BGP configuration, independent from TCP sessions and learned routes.
use rios_ipv4::Ipv4Network;
use rios_simulator::InterfaceId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};
/// A configured IPv4 unicast peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpNeighborConfig {
    pub remote_as: u32,
    #[serde(default)]
    pub update_source: Option<InterfaceId>,
    #[serde(default)]
    pub next_hop_self: bool,
}
/// One BGP process; routes and TCP state never appear in persistent configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpConfig {
    pub local_as: u32,
    pub router_id: Option<Ipv4Addr>,
    pub neighbors: BTreeMap<Ipv4Addr, BgpNeighborConfig>,
    pub networks: BTreeSet<Ipv4Network>,
}
impl BgpConfig {
    /// Create a process with no neighbors or originated networks.
    pub fn new(local_as: u32) -> Self {
        Self {
            local_as,
            router_id: None,
            neighbors: BTreeMap::new(),
            networks: BTreeSet::new(),
        }
    }
    pub(crate) fn render(
        &self,
        interfaces: &BTreeMap<InterfaceId, crate::InterfaceConfig>,
        out: &mut String,
    ) {
        use std::fmt::Write;
        let _ = writeln!(out, "router bgp {}", self.local_as);
        if let Some(id) = self.router_id {
            let _ = writeln!(out, " bgp router-id {id}");
        }
        for prefix in &self.networks {
            let _ = writeln!(out, " network {} mask {}", prefix.address(), prefix.mask());
        }
        for (address, peer) in &self.neighbors {
            let _ = writeln!(out, " neighbor {address} remote-as {}", peer.remote_as);
            if let Some(id) = peer.update_source
                && let Some(port) = interfaces.get(&id)
            {
                let _ = writeln!(out, " neighbor {address} update-source {}", port.name);
            }
            if peer.next_hop_self {
                let _ = writeln!(out, " neighbor {address} next-hop-self");
            }
        }
        out.push_str("!\n");
    }
}
