//! Read-only protocol observations for shared CLI frontends.
use super::*;
use std::fmt::Write;
impl Device {
    pub fn show_ipv6_ospf_neighbor(&self, now: SimTime) -> String {
        let mut out = String::from(
            "Neighbor ID     Pri State       Dead Time Interface                Address\n",
        );
        for n in self.ospfv3_neighbors() {
            let name = self
                .running_config
                .interfaces
                .get(&n.interface)
                .map_or("?", |p| p.name.as_str());
            let _ = writeln!(
                out,
                "{:<15} {:>3} {:<11?} {:>9} {:<24} {}",
                n.router_id,
                n.priority,
                n.state,
                n.dead_at.0.saturating_sub(now.0) / 1_000_000,
                name,
                n.address
            );
        }
        out
    }
    pub fn show_ipv6_ospf_interface(&self) -> String {
        let mut out = String::new();
        for (id, p) in &self.ospfv3.ports {
            let name = self
                .running_config
                .interfaces
                .get(id)
                .map_or("?", |p| p.name.as_str());
            let _ = writeln!(
                out,
                "{name}, Interface ID {}, Area {}, {:?}, cost {}\n  Link-local {}, Hello {}, Dead {}, DR {}, BDR {}",
                id.0,
                p.area,
                p.policy.network_type,
                p.policy.cost,
                p.address,
                p.policy.hello_interval,
                p.policy.dead_interval,
                p.dr,
                p.bdr
            );
        }
        out
    }
    pub fn show_ipv6_ospf_database(&self, now: SimTime) -> String {
        let mut out = format!(
            "OSPFv3 router ID {}\nScope           Type   Link State ID Advertising Router Sequence     Age\n",
            self.ospfv3
                .router_id
                .map_or_else(|| "unassigned".into(), |id| id.to_string())
        );
        for ((scope, key), s) in &self.ospfv3.database {
            let lsa = s.current(now);
            let scope = match scope {
                Scope::Area(area) => format!("Area {area}"),
                Scope::Link(id) => format!("Link {}", id.0),
                Scope::As => "AS".into(),
            };
            let _ = writeln!(
                out,
                "{scope:<15} {:04x}   {:<13} {:<18} {:08x} {:>5}",
                key.kind, key.link_state_id, key.advertising_router, lsa.sequence, lsa.age
            );
        }
        out
    }
}
