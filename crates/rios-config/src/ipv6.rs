//! IPv6 configuration is separate from IPv4 and from Neighbor Discovery runtime.
use rios_ipv6::{Ipv6InterfaceConfig, Ipv6Network};
use rios_simulator::InterfaceId;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Write, net::Ipv6Addr};
/// Persistent IPv6 policy for one routed interface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ipv6InterfacePolicy {
    pub enabled: bool,
    pub addresses: BTreeSet<Ipv6InterfaceConfig>,
    pub link_local: Option<Ipv6Addr>,
    pub autoconfig: bool,
    pub ra_suppress: bool,
}
impl Ipv6InterfacePolicy {
    pub fn active(&self) -> bool {
        self.enabled || self.autoconfig || self.link_local.is_some() || !self.addresses.is_empty()
    }
    pub(crate) fn render(&self, out: &mut String) {
        if self.enabled {
            out.push_str(" ipv6 enable\n");
        }
        if self.autoconfig {
            out.push_str(" ipv6 address autoconfig\n");
        }
        if self.ra_suppress {
            out.push_str(" ipv6 nd ra suppress\n");
        }
        if let Some(address) = self.link_local {
            let _ = writeln!(out, " ipv6 address {address} link-local");
        }
        for address in &self.addresses {
            let _ = writeln!(out, " ipv6 address {address}");
        }
    }
}
/// Configured static route; a link-local next hop requires an explicit interface scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv6StaticRoute {
    pub prefix: Ipv6Network,
    pub next_hop: Ipv6Addr,
    pub interface: Option<InterfaceId>,
}
