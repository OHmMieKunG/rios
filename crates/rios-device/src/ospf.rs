use crate::*;
use rios_config::{OspfConfig, OspfNetworkConfig};
use rios_ipv4::{Ipv4Network, Route, RouteSource};
use rios_routing::{DEAD_INTERVAL_MS, OspfNeighbor, OspfNeighborState, OspfPacket, RouterLsa};
use rios_simulator::SimTime;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Write,
    net::Ipv4Addr,
};

impl Device {
    /// Create or select the device's single OSPF process.
    pub fn set_ospf_process(&mut self, process_id: u16) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::OspfUnsupported);
        }
        if process_id == 0 {
            return Err(DeviceError::InvalidOspfProcess);
        }
        match &mut self.running_config.ospf {
            Some(config) => config.process_id = process_id,
            None => {
                self.running_config.ospf = Some(OspfConfig {
                    process_id,
                    networks: BTreeSet::new(),
                })
            }
        }
        Ok(())
    }

    /// Add an interface-selection statement to the configured OSPF process.
    pub fn add_ospf_network(&mut self, network: OspfNetworkConfig) -> Result<(), DeviceError> {
        let ospf = self
            .running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?;
        if ospf
            .networks
            .iter()
            .any(|existing| existing.area != network.area)
        {
            return Err(DeviceError::OspfAreaMismatch);
        }
        ospf.networks.insert(network);
        Ok(())
    }

    /// Operational OSPF interfaces with their selected area.
    pub fn ospf_interfaces(&self) -> Vec<(InterfaceId, Ipv4InterfaceConfig, u32)> {
        let Some(ospf) = &self.running_config.ospf else {
            return Vec::new();
        };
        self.running_config
            .interfaces
            .keys()
            .filter_map(|id| {
                let ip = self.interface_ipv4(*id)?;
                let area = ospf
                    .networks
                    .iter()
                    .find(|network| network.matches(ip.address()))?
                    .area;
                self.protocol_up(*id).then_some((*id, ip, area))
            })
            .collect()
    }

    fn refresh_ospf_lsa(&mut self) {
        let interfaces = self.ospf_interfaces();
        let Some(router_id) = interfaces.iter().map(|(_, ip, _)| ip.address()).max() else {
            self.ospf_runtime = OspfRuntime::default();
            return;
        };
        if self.ospf_runtime.router_id != Some(router_id) {
            self.ospf_runtime = OspfRuntime {
                router_id: Some(router_id),
                ..OspfRuntime::default()
            };
        }
        let networks = interfaces
            .iter()
            .map(|(_, ip, _)| Ipv4Network::new(ip.address(), ip.prefix_len()).unwrap())
            .collect();
        let neighbors = self
            .ospf_runtime
            .neighbors
            .values()
            .filter(|neighbor| neighbor.state == OspfNeighborState::Full)
            .map(|neighbor| neighbor.router_id)
            .collect();
        let changed = self
            .ospf_runtime
            .database
            .get(&router_id)
            .is_none_or(|lsa| lsa.networks != networks || lsa.neighbors != neighbors);
        if changed {
            self.ospf_runtime.sequence = self.ospf_runtime.sequence.wrapping_add(1).max(1);
            self.ospf_runtime.database.insert(
                router_id,
                RouterLsa {
                    router_id,
                    sequence: self.ospf_runtime.sequence,
                    networks,
                    neighbors,
                },
            );
        }
        self.recompute_ospf_routes();
    }

    /// Build current Hello and database packets for one enabled interface.
    pub fn ospf_packets(&mut self, interface: InterfaceId) -> Option<(Ipv4Addr, Vec<OspfPacket>)> {
        self.refresh_ospf_lsa();
        let router_id = self.ospf_runtime.router_id?;
        let (_, ip, area) = self
            .ospf_interfaces()
            .into_iter()
            .find(|(id, _, _)| *id == interface)?;
        let neighbors = self
            .ospf_runtime
            .neighbors
            .values()
            .filter(|n| n.interface == interface)
            .map(|n| n.router_id)
            .collect();
        Some((
            ip.address(),
            vec![
                OspfPacket::Hello {
                    router_id,
                    area,
                    mask: ip.mask(),
                    neighbors,
                },
                OspfPacket::LinkStateUpdate {
                    router_id,
                    area,
                    lsas: self.ospf_runtime.database.values().cloned().collect(),
                },
            ],
        ))
    }

    /// Process one valid OSPF packet received on an enabled interface.
    pub fn receive_ospf(
        &mut self,
        interface: InterfaceId,
        source: Ipv4Addr,
        packet: OspfPacket,
        now: SimTime,
    ) -> Option<(Ipv4Addr, SimTime, bool)> {
        let (_, local, local_area) = self
            .ospf_interfaces()
            .into_iter()
            .find(|(id, _, _)| *id == interface)?;
        match packet {
            OspfPacket::Hello {
                router_id,
                area,
                mask,
                neighbors,
            } if area == local_area && mask == local.mask() => {
                let self_id = self.ospf_runtime.router_id?;
                let state = if neighbors.contains(&self_id) {
                    OspfNeighborState::Full
                } else {
                    OspfNeighborState::Init
                };
                let deadline = SimTime(now.0.saturating_add(DEAD_INTERVAL_MS * 1000));
                let changed = self
                    .ospf_runtime
                    .neighbors
                    .get(&router_id)
                    .is_none_or(|old| old.state != state);
                self.ospf_runtime.neighbors.insert(
                    router_id,
                    OspfNeighbor {
                        router_id,
                        address: source,
                        interface,
                        state,
                        dead_at: deadline,
                    },
                );
                self.refresh_ospf_lsa();
                Some((router_id, deadline, changed))
            }
            OspfPacket::LinkStateUpdate { area, lsas, .. } if area == local_area => {
                for lsa in lsas {
                    if self
                        .ospf_runtime
                        .database
                        .get(&lsa.router_id)
                        .is_none_or(|old| lsa.sequence > old.sequence)
                    {
                        self.ospf_runtime.database.insert(lsa.router_id, lsa);
                    }
                }
                self.recompute_ospf_routes();
                None
            }
            _ => None,
        }
    }

    /// Expire a neighbor only if its most recent deadline has elapsed.
    pub fn expire_ospf_neighbor(&mut self, router_id: Ipv4Addr, now: SimTime) {
        if self
            .ospf_runtime
            .neighbors
            .get(&router_id)
            .is_some_and(|n| n.dead_at <= now)
        {
            self.ospf_runtime.neighbors.remove(&router_id);
            self.refresh_ospf_lsa();
        }
    }

    fn recompute_ospf_routes(&mut self) {
        self.ospf_runtime.routes.clear();
        let Some(self_id) = self.ospf_runtime.router_id else {
            return;
        };
        let mut first = BTreeMap::from([(self_id, self_id)]);
        let mut distance = BTreeMap::from([(self_id, 0u32)]);
        let mut queue = VecDeque::from([self_id]);
        while let Some(current) = queue.pop_front() {
            let Some(lsa) = self.ospf_runtime.database.get(&current) else {
                continue;
            };
            for adjacent in &lsa.neighbors {
                if first.contains_key(adjacent) {
                    continue;
                }
                first.insert(
                    *adjacent,
                    if current == self_id {
                        *adjacent
                    } else {
                        first[&current]
                    },
                );
                distance.insert(*adjacent, distance[&current].saturating_add(1));
                queue.push_back(*adjacent);
            }
        }
        for (origin, lsa) in &self.ospf_runtime.database {
            if *origin == self_id {
                continue;
            }
            let Some(first_hop) = first.get(origin) else {
                continue;
            };
            let Some(neighbor) = self
                .ospf_runtime
                .neighbors
                .get(first_hop)
                .filter(|n| n.state == OspfNeighborState::Full)
            else {
                continue;
            };
            for prefix in &lsa.networks {
                self.ospf_runtime.routes.push(Route {
                    prefix: *prefix,
                    next_hop: Some(neighbor.address),
                    outgoing_interface: Some(neighbor.interface),
                    administrative_distance: 110,
                    metric: distance[origin],
                    source: RouteSource::Ospf,
                });
            }
        }
    }

    pub fn show_ip_ospf_neighbor(&self, now: SimTime) -> String {
        let mut out =
            String::from("Neighbor ID     State           Dead Time   Address         Interface\n");
        for neighbor in self.ospf_runtime.neighbors.values() {
            let name = &self.running_config.interfaces[&neighbor.interface].name;
            writeln!(
                out,
                "{:<15} {:<15?} {:>7} ms   {:<15} {}",
                neighbor.router_id,
                neighbor.state,
                neighbor.dead_at.0.saturating_sub(now.0) / 1000,
                neighbor.address,
                name
            )
            .unwrap();
        }
        out
    }

    pub fn show_ip_ospf_interface(&self) -> String {
        let mut out = String::new();
        for (id, ip, area) in self.ospf_interfaces() {
            writeln!(
                out,
                "{} is up, Internet Address {}/{}, Area {}",
                self.running_config.interfaces[&id].name,
                ip.address(),
                ip.prefix_len(),
                area
            )
            .unwrap();
        }
        out
    }

    pub fn show_ip_ospf_database(&self) -> String {
        let mut out = String::from(
            "            OSPF Router Link States\n\nLink ID         Sequence  Networks  Neighbors\n",
        );
        for lsa in self.ospf_runtime.database.values() {
            writeln!(
                out,
                "{:<15} {:08x} {:>8} {:>10}",
                lsa.router_id,
                lsa.sequence,
                lsa.networks.len(),
                lsa.neighbors.len()
            )
            .unwrap();
        }
        out
    }
}
