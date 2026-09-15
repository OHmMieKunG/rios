//! OSPF displays derived from live interface, neighbor and database state.
use super::*;
use std::fmt::Write;
impl Device {
    pub fn show_ip_ospf_neighbor(&self, now: SimTime) -> String {
        let mut out = String::from(
            "Neighbor ID     Pri State           Dead Time   Address         Interface\n",
        );
        for n in self.ospf_runtime.neighbors.values() {
            let name = &self.running_config.interfaces[&n.info.interface].name;
            let _ = writeln!(
                out,
                "{:<15} {:>3} {:<15?} {:>7} ms   {:<15} {}",
                n.info.router_id,
                n.info.priority,
                n.info.state,
                n.info.dead_at.0.saturating_sub(now.0) / 1000,
                n.info.address,
                name
            );
        }
        out
    }
    pub fn show_ip_ospf_interface(&self) -> String {
        let mut out = String::new();
        for (id, ip, area) in self.ospf_interfaces() {
            let policy = self.running_config.interfaces[&id].ospf;
            let _ = writeln!(
                out,
                "{} is up, Internet Address {}/{}, Area {}\n  Network Type {:?}, Cost: {}, Priority: {}\n  Hello {}, Dead {}",
                self.running_config.interfaces[&id].name,
                ip.address(),
                ip.prefix_len(),
                area,
                policy.network_type,
                policy.cost,
                policy.priority,
                policy.hello_interval,
                policy.dead_interval
            );
            if self.ospf_passive(id) {
                out.push_str("  No Hellos (Passive interface)\n");
            }
            if let Some(runtime) = self.ospf_runtime.interfaces.get(&id) {
                let _ = writeln!(
                    out,
                    "  Designated Router {}, Backup Designated Router {}",
                    runtime.dr, runtime.bdr
                );
            }
        }
        out
    }
    pub fn show_ip_ospf_database(&self) -> String {
        let mut out = String::from(
            "            OSPF Link State Database\n\nArea  Type         Link ID         Advertising Router Sequence\n",
        );
        for ((area, key), stored) in &self.ospf_runtime.database {
            let _ = writeln!(
                out,
                "{:<5} {:<12?} {:<15} {:<18} {:08x}",
                area, key.kind, key.link_state_id, key.advertising_router, stored.lsa.sequence
            );
        }
        out
    }
}
impl Device {
    /// Process summary uses the elected runtime router ID and active area set.
    pub fn show_ip_ospf(&self) -> String {
        let Some(config) = &self.running_config.ospf else {
            return "OSPF is not configured\n".into();
        };
        let areas: BTreeSet<_> = self
            .ospf_interfaces()
            .into_iter()
            .map(|(_, _, area)| area)
            .collect();
        format!(
            "Routing Process ospf {} with ID {}\nNumber of areas: {}\nNeighbors: {}, Full: {}\n",
            config.process_id,
            self.ospf_runtime.router_id.unwrap_or(Ipv4Addr::UNSPECIFIED),
            areas.len(),
            self.ospf_runtime.neighbors.len(),
            self.ospf_runtime
                .neighbors
                .values()
                .filter(|n| n.info.state == OspfNeighborState::Full)
                .count()
        )
    }
    /// Routing process policy for the configured OSPF process.
    pub fn show_ip_protocols(&self) -> String {
        let mut out = self.show_ip_ospf();
        if let Some(config) = &self.running_config.ospf {
            for network in &config.networks {
                let _ = writeln!(
                    out,
                    "  Network {} wildcard {} area {}",
                    network.address, network.wildcard, network.area
                );
            }
            for id in &config.passive_interfaces {
                if let Some(port) = self.running_config.interfaces.get(id) {
                    let _ = writeln!(out, "  Passive interface {}", port.name);
                }
            }
        }
        out
    }
    /// Neighbor exchange details expose real request and retransmission queues.
    pub fn show_ip_ospf_neighbor_detail(&self, now: SimTime) -> String {
        let mut out = self.show_ip_ospf_neighbor(now);
        for n in self.ospf_runtime.neighbors.values() {
            let (requests, retransmit) = n.exchange.as_ref().map_or((0, 0), OspfExchange::pending);
            let _ = writeln!(
                out,
                "Neighbor {}: DR {}, BDR {}, requests {}, retransmissions {}",
                n.info.router_id,
                n.hello.designated_router,
                n.hello.backup_router,
                requests,
                retransmit
            );
        }
        out
    }
}
