//! IPv6 displays use structured operational and persistent state.
use super::*;
use std::fmt::Write;
impl Device {
    pub fn show_ipv6_interface_brief(&self) -> String {
        let mut out = String::new();
        for (id, config) in &self.running_config.interfaces {
            if !config.ipv6.active() {
                continue;
            }
            let _ = writeln!(
                out,
                "{} [{}/{}]",
                config.name,
                if config.admin_state == AdminState::Up {
                    "up"
                } else {
                    "administratively down"
                },
                if self.protocol_up(*id) { "up" } else { "down" }
            );
            for entry in self.ipv6_addresses(*id) {
                let _ = writeln!(
                    out,
                    "  {} {:?} {:?}",
                    entry.address, entry.state, entry.origin
                );
            }
        }
        out
    }
    pub fn show_ipv6_neighbors(&self, now: SimTime) -> String {
        let mut out = String::from(
            "IPv6 Address                             State       Link-layer Address Interface\n",
        );
        for neighbor in self.ipv6.neighbors.values() {
            let name = &self.running_config.interfaces[&neighbor.interface].name;
            let _ = writeln!(
                out,
                "{:<40} {:?} {} {} (timer {} ms)",
                neighbor.address,
                neighbor.state,
                neighbor
                    .mac
                    .map_or_else(|| "Incomplete".into(), |m| m.to_string()),
                name,
                neighbor.deadline.0.saturating_sub(now.0) / 1000
            );
        }
        out
    }
    pub fn show_ipv6_route(&self) -> String {
        let mut out = String::from(
            "IPv6 Routing Table\nCodes: C - connected, S - static, ND - router advertisement\n",
        );
        for route in self.ipv6_routes() {
            let code = match route.source {
                Ipv6RouteSource::Connected => "C",
                Ipv6RouteSource::Static => "S",
                Ipv6RouteSource::RouterAdvertisement => "ND",
            };
            let _ = writeln!(
                out,
                "{code} {} [{}/{}] via {}, {}",
                route.prefix,
                route.administrative_distance,
                route.metric,
                route
                    .next_hop
                    .map_or_else(|| "directly connected".into(), |ip| ip.to_string()),
                self.running_config.interfaces[&route.interface].name
            );
        }
        out
    }
}
