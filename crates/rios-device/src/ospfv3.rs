//! OSPFv3 adjacency, election and flooding over IPv6 link-local interfaces.
mod config;
mod database;
mod display;
mod election;
use crate::*;
use rios_config::{OspfInterfaceConfig, OspfNetworkType, OspfV3Binding};
use rios_ipv6::Ipv6Network;
use rios_routing::*;
use rios_simulator::SimTime;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
};

/// One standard OSPFv3 transmission over the simulated IPv6 stack.
#[derive(Debug, Clone)]
pub struct OspfV3Transmission {
    pub interface: InterfaceId,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub packet: OspfV3Packet,
}
/// Read-only neighbor observation for frontends and grading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfV3NeighborInfo {
    pub router_id: Ipv4Addr,
    pub address: Ipv6Addr,
    pub interface: InterfaceId,
    pub neighbor_interface_id: u32,
    pub state: OspfNeighborState,
    pub priority: u8,
    pub dead_at: SimTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Neighbor {
    info: OspfV3NeighborInfo,
    hello: OspfV3Hello,
    exchange: Option<OspfV3Exchange>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Port {
    address: Ipv6Addr,
    area: u32,
    policy: OspfInterfaceConfig,
    hello_due: SimTime,
    wait_until: SimTime,
    dr: Ipv4Addr,
    bdr: Ipv4Addr,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    Link(InterfaceId),
    Area(u32),
    As,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stored {
    lsa: OspfV3Lsa,
    installed: SimTime,
}
impl Stored {
    fn current(&self, now: SimTime) -> OspfV3Lsa {
        let mut lsa = self.lsa.clone();
        lsa.age = (u64::from(lsa.age) + now.0.saturating_sub(self.installed.0) / 1_000_000)
            .min(u64::from(LSA_MAX_AGE)) as u16;
        lsa
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct OspfV3Runtime {
    router_id: Option<Ipv4Addr>,
    ports: BTreeMap<InterfaceId, Port>,
    neighbors: BTreeMap<(InterfaceId, Ipv4Addr), Neighbor>,
    database: BTreeMap<(Scope, OspfV3LsaKey), Stored>,
    sequence: u32,
    pub(super) routes: Vec<Ipv6Route>,
}
impl Device {
    fn ospfv3_emit(
        &self,
        id: InterfaceId,
        destination: Ipv6Addr,
        body: OspfV3Body,
    ) -> Option<OspfV3Transmission> {
        let port = self.ospfv3.ports.get(&id)?;
        Some(OspfV3Transmission {
            interface: id,
            source: port.address,
            destination,
            packet: OspfV3Packet {
                router_id: self.ospfv3.router_id?,
                area: port.area,
                instance: 0,
                body,
            },
        })
    }
    pub fn ospfv3_neighbors(&self) -> Vec<OspfV3NeighborInfo> {
        self.ospfv3
            .neighbors
            .values()
            .map(|n| n.info.clone())
            .collect()
    }
    fn ospfv3_prepare(&mut self, now: SimTime) {
        if self.running_config.ospfv3.is_none() || !self.ipv6_forwarding_enabled() {
            self.ospfv3 = OspfV3Runtime::default();
            return;
        }
        if self.ospfv3.router_id.is_none() {
            self.ospfv3.router_id = self
                .running_config
                .ospfv3
                .as_ref()
                .and_then(|c| c.router_id)
                .or_else(|| {
                    self.interfaces
                        .keys()
                        .filter_map(|id| self.interface_ipv4(*id).map(|ip| ip.address()))
                        .max()
                });
        }
        let active = self.ospfv3_active();
        let ids: BTreeSet<_> = active
            .iter()
            .filter(|(id, _, _)| !self.ospfv3_passive(*id))
            .map(|(id, _, _)| *id)
            .collect();
        self.ospfv3.ports.retain(|id, _| ids.contains(id));
        for (id, address, area) in active {
            if !ids.contains(&id) {
                continue;
            }
            let policy = self.running_config.interfaces[&id].ipv6.ospf_parameters;
            let changed = self.ospfv3.ports.get(&id).is_none_or(|p| {
                p.address != address
                    || p.area != area
                    || p.policy.network_type != policy.network_type
                    || p.policy.hello_interval != policy.hello_interval
                    || p.policy.dead_interval != policy.dead_interval
            });
            if changed {
                self.ospfv3.neighbors.retain(|(port, _), _| *port != id);
                self.ospfv3.ports.insert(
                    id,
                    Port {
                        address,
                        area,
                        policy,
                        hello_due: now,
                        wait_until: SimTime(
                            now.0
                                .saturating_add(u64::from(policy.dead_interval) * 1_000_000),
                        ),
                        dr: Ipv4Addr::UNSPECIFIED,
                        bdr: Ipv4Addr::UNSPECIFIED,
                    },
                );
            } else if let Some(port) = self.ospfv3.ports.get_mut(&id) {
                port.policy = policy;
            }
        }
        self.ospfv3
            .neighbors
            .retain(|(id, _), n| ids.contains(id) && n.info.dead_at > now);
    }
    pub fn ospfv3_next_deadline(&self, now: SimTime) -> SimTime {
        let mut next = SimTime(now.0.saturating_add(1_000_000));
        let mut consider = |at: SimTime| {
            if at > now {
                next = next.min(at);
            }
        };
        for p in self.ospfv3.ports.values() {
            consider(p.hello_due);
            consider(p.wait_until);
        }
        for n in self.ospfv3.neighbors.values() {
            consider(n.info.dead_at);
            if let Some(at) = n.exchange.as_ref().and_then(OspfV3Exchange::next_deadline) {
                consider(at);
            }
        }
        for stored in self.ospfv3.database.values() {
            let age: u16 = if Some(stored.lsa.advertising_router) == self.ospfv3.router_id {
                1800
            } else {
                LSA_MAX_AGE
            };
            consider(SimTime(stored.installed.0.saturating_add(
                u64::from(age.saturating_sub(stored.lsa.age)) * 1_000_000,
            )));
        }
        next
    }
    pub fn ospfv3_tick(&mut self, now: SimTime) -> Vec<OspfV3Transmission> {
        self.ospfv3_prepare(now);
        let mut out = Vec::new();
        self.ospfv3_elect(now, &mut out);
        self.ospfv3_originate(now, &mut out);
        if self.ospfv3.router_id.is_none() {
            return out;
        }
        let mut bodies = Vec::new();
        for (id, p) in &mut self.ospfv3.ports {
            if p.hello_due <= now {
                let neighbors = self
                    .ospfv3
                    .neighbors
                    .keys()
                    .filter(|(port, _)| port == id)
                    .map(|(_, rid)| *rid)
                    .collect();
                bodies.push((
                    *id,
                    OSPFV3_ALL_ROUTERS,
                    OspfBody::Hello(OspfV3Hello {
                        interface_id: id.0 as u32,
                        priority: p.policy.priority,
                        options: OSPFV3_OPTIONS,
                        hello_interval: p.policy.hello_interval,
                        dead_interval: p.policy.dead_interval as u16,
                        designated_router: p.dr,
                        backup_router: p.bdr,
                        neighbors,
                    }),
                ));
                p.hello_due = SimTime(
                    now.0
                        .saturating_add(u64::from(p.policy.hello_interval) * 1_000_000),
                );
            }
        }
        for ((id, _), n) in &mut self.ospfv3.neighbors {
            if let Some(exchange) = &mut n.exchange {
                bodies.extend(
                    exchange
                        .tick(now)
                        .into_iter()
                        .map(|b| (*id, n.info.address, b)),
                );
            }
        }
        out.extend(
            bodies
                .into_iter()
                .filter_map(|(id, to, b)| self.ospfv3_emit(id, to, b)),
        );
        self.ospfv3_routes(now);
        out
    }
    pub fn receive_ospfv3(
        &mut self,
        interface: InterfaceId,
        source: Ipv6Addr,
        packet: OspfV3Packet,
        now: SimTime,
    ) -> Vec<OspfV3Transmission> {
        self.ospfv3_prepare(now);
        let mut out = Vec::new();
        let Some(self_id) = self.ospfv3.router_id else {
            return out;
        };
        let Some(port) = self.ospfv3.ports.get(&interface) else {
            return out;
        };
        if packet.area != port.area
            || packet.instance != 0
            || packet.router_id == self_id
            || packet.router_id.is_unspecified()
            || packet.router_id.is_multicast()
            || packet.router_id.is_broadcast()
            || !source.is_unicast_link_local()
            || source == port.address
        {
            return out;
        }
        if let OspfBody::LinkStateUpdate(lsas) = &packet.body {
            let new: BTreeSet<_> = lsas
                .iter()
                .map(|lsa| (scope(lsa, interface, packet.area), lsa.key()))
                .filter(|key| !self.ospfv3.database.contains_key(key))
                .collect();
            if self.ospfv3.database.len() + new.len() > OSPF_DATABASE_LIMIT {
                return out;
            }
        }
        let key = (interface, packet.router_id);
        if let OspfBody::Hello(hello) = packet.body {
            if hello.hello_interval != port.policy.hello_interval
                || u32::from(hello.dead_interval) != port.policy.dead_interval
                || hello.options & OSPFV3_OPTIONS != OSPFV3_OPTIONS
            {
                return out;
            }
            if !self.ospfv3.neighbors.contains_key(&key) && self.ospfv3.neighbors.len() >= 256 {
                return out;
            }
            let two_way = hello.neighbors.contains(&self_id);
            let fresh = !self.ospfv3.neighbors.contains_key(&key);
            let n = self
                .ospfv3
                .neighbors
                .entry(key)
                .or_insert_with(|| Neighbor {
                    info: OspfV3NeighborInfo {
                        router_id: packet.router_id,
                        address: source,
                        interface,
                        neighbor_interface_id: hello.interface_id,
                        state: OspfNeighborState::Init,
                        priority: hello.priority,
                        dead_at: now,
                    },
                    hello: hello.clone(),
                    exchange: None,
                });
            if n.info.address != source || n.info.neighbor_interface_id != hello.interface_id {
                n.exchange = None;
            }
            n.info.address = source;
            n.info.neighbor_interface_id = hello.interface_id;
            n.info.priority = hello.priority;
            n.info.dead_at = SimTime(
                now.0
                    .saturating_add(u64::from(hello.dead_interval) * 1_000_000),
            );
            if !two_way {
                n.exchange = None;
                n.info.state = OspfNeighborState::Init;
            } else {
                n.info.state = n
                    .exchange
                    .as_ref()
                    .map_or(OspfNeighborState::TwoWay, |e| e.state);
            }
            n.hello = hello;
            if fresh && let Some(p) = self.ospfv3.ports.get_mut(&interface) {
                p.hello_due = now;
            }
        } else {
            let database = self.ospfv3_database(interface, packet.area, now);
            let Some(n) = self
                .ospfv3
                .neighbors
                .get_mut(&key)
                .filter(|n| n.info.address == source)
            else {
                return out;
            };
            let Some(exchange) = &mut n.exchange else {
                return out;
            };
            let result = exchange.receive(packet.body, &database, now);
            n.info.state = exchange.state;
            out.extend(
                result
                    .packets
                    .into_iter()
                    .filter_map(|body| self.ospfv3_emit(interface, source, body)),
            );
            for lsa in result.advertisements {
                self.ospfv3_install(
                    scope(&lsa, interface, packet.area),
                    lsa,
                    Some(key),
                    now,
                    &mut out,
                );
            }
        }
        out.extend(self.ospfv3_tick(now));
        out
    }
}
fn scope(lsa: &OspfV3Lsa, interface: InterfaceId, area: u32) -> Scope {
    match lsa.flooding_scope() {
        0x2000 => Scope::Area(area),
        0x4000 => Scope::As,
        _ => Scope::Link(interface),
    }
}
