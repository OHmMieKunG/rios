//! OSPF device integration: interface selection, neighbors, elections and packet actions.
mod config;
mod database;
mod display;
mod election;
mod summaries;
use crate::*;
use rios_config::{OspfConfig, OspfInterfaceConfig, OspfNetworkConfig, OspfNetworkType};
use rios_ipv4::{Ipv4Network, Route};
use rios_routing::*;
use rios_simulator::SimTime;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

const NEIGHBOR_LIMIT: usize = 256;
/// One OSPF packet to transmit through the same virtual IPv4 data plane as other traffic.
#[derive(Debug, Clone)]
pub struct OspfTransmission {
    pub interface: InterfaceId,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub packet: OspfV2Packet,
}
/// Read-only neighbor state for CLI and structured lab checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfNeighborInfo {
    pub router_id: Ipv4Addr,
    pub address: Ipv4Addr,
    pub interface: InterfaceId,
    pub state: OspfNeighborState,
    pub priority: u8,
    pub dead_at: SimTime,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Neighbor {
    info: OspfNeighborInfo,
    hello: OspfHello,
    exchange: Option<OspfExchange>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceRuntime {
    policy: OspfInterfaceConfig,
    address: Ipv4InterfaceConfig,
    area: u32,
    wait_until: SimTime,
    hello_due: SimTime,
    dr: Ipv4Addr,
    bdr: Ipv4Addr,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredLsa {
    lsa: Lsa,
    installed: SimTime,
}
impl StoredLsa {
    fn current(&self, now: SimTime) -> Lsa {
        let mut lsa = self.lsa.clone();
        lsa.age = (u64::from(lsa.age) + (now.0.saturating_sub(self.installed.0) / 1_000_000))
            .min(u64::from(LSA_MAX_AGE)) as u16;
        lsa
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct OspfRuntime {
    router_id: Option<Ipv4Addr>,
    neighbors: BTreeMap<(InterfaceId, Ipv4Addr), Neighbor>,
    interfaces: BTreeMap<InterfaceId, InterfaceRuntime>,
    database: BTreeMap<(u32, LsaKey), StoredLsa>,
    pub(super) routes: Vec<Route>,
    sequence: u32,
}
impl Device {
    fn ospf_emit(
        &self,
        id: InterfaceId,
        destination: Ipv4Addr,
        body: OspfBody,
    ) -> Option<OspfTransmission> {
        let runtime = self.ospf_runtime.interfaces.get(&id)?;
        Some(OspfTransmission {
            interface: id,
            source: runtime.address.address(),
            destination,
            packet: OspfV2Packet {
                router_id: self.ospf_runtime.router_id?,
                area: runtime.area,
                body,
            },
        })
    }
    /// Current neighbors, including DROther pairs that intentionally stay at TwoWay.
    pub fn ospf_neighbors(&self) -> Vec<OspfNeighborInfo> {
        self.ospf_runtime
            .neighbors
            .values()
            .map(|n| n.info.clone())
            .collect()
    }
    fn ospf_prepare(&mut self, now: SimTime) {
        let active = self.ospf_interfaces();
        if self.running_config.ospf.is_none() {
            self.ospf_runtime = OspfRuntime::default();
            return;
        }
        if self.ospf_runtime.router_id.is_none() {
            self.ospf_runtime.router_id = self
                .running_config
                .ospf
                .as_ref()
                .and_then(|c| c.router_id)
                .or_else(|| active.iter().map(|(_, ip, _)| ip.address()).max());
        }
        let ids: BTreeSet<_> = active
            .iter()
            .filter(|(id, _, _)| !self.ospf_passive(*id))
            .map(|(id, _, _)| *id)
            .collect();
        self.ospf_runtime
            .interfaces
            .retain(|id, _| ids.contains(id));
        for (id, ip, area) in active {
            if !ids.contains(&id) {
                continue;
            }
            let policy = self.running_config.interfaces[&id].ospf;
            let changed = self.ospf_runtime.interfaces.get(&id).is_none_or(|old| {
                old.address != ip
                    || old.area != area
                    || old.policy.network_type != policy.network_type
                    || old.policy.hello_interval != policy.hello_interval
                    || old.policy.dead_interval != policy.dead_interval
            });
            if changed {
                self.ospf_runtime
                    .neighbors
                    .retain(|(interface, _), _| *interface != id);
                self.ospf_runtime.interfaces.insert(
                    id,
                    InterfaceRuntime {
                        policy,
                        address: ip,
                        area,
                        wait_until: SimTime(
                            now.0
                                .saturating_add(u64::from(policy.dead_interval) * 1_000_000),
                        ),
                        hello_due: now,
                        dr: Ipv4Addr::UNSPECIFIED,
                        bdr: Ipv4Addr::UNSPECIFIED,
                    },
                );
            } else if let Some(runtime) = self.ospf_runtime.interfaces.get_mut(&id) {
                runtime.policy = policy;
            }
        }
        self.ospf_runtime
            .neighbors
            .retain(|(id, _), neighbor| ids.contains(id) && neighbor.info.dead_at > now);
    }
    /// Earliest protocol deadline, with a one-second maintenance bound for carrier changes.
    pub fn ospf_next_deadline(&self, now: SimTime) -> SimTime {
        let mut next = SimTime(now.0.saturating_add(1_000_000));
        let mut consider = |time: SimTime| {
            if time > now {
                next = next.min(time);
            }
        };
        for runtime in self.ospf_runtime.interfaces.values() {
            consider(runtime.hello_due);
            consider(runtime.wait_until);
        }
        for neighbor in self.ospf_runtime.neighbors.values() {
            consider(neighbor.info.dead_at);
            if let Some(time) = neighbor
                .exchange
                .as_ref()
                .and_then(OspfExchange::next_deadline)
            {
                consider(time);
            }
        }
        for stored in self.ospf_runtime.database.values() {
            let age = if Some(stored.lsa.advertising_router) == self.ospf_runtime.router_id {
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
    /// Drive Hello, adjacency retransmission, database aging and election timers in virtual time.
    pub fn ospf_tick(&mut self, now: SimTime) -> Vec<OspfTransmission> {
        self.ospf_prepare(now);
        let mut out = Vec::new();
        self.ospf_elect(now, &mut out);
        self.ospf_originate(now, &mut out);
        let Some(_) = self.ospf_runtime.router_id else {
            return out;
        };
        let mut bodies = Vec::new();
        for (id, runtime) in &mut self.ospf_runtime.interfaces {
            if runtime.hello_due <= now {
                let neighbors = self
                    .ospf_runtime
                    .neighbors
                    .iter()
                    .filter(|((port, _), _)| port == id)
                    .map(|((_, rid), _)| *rid)
                    .collect();
                bodies.push((
                    *id,
                    OSPF_ALL_ROUTERS,
                    OspfBody::Hello(OspfHello {
                        mask: runtime.address.mask(),
                        hello_interval: runtime.policy.hello_interval,
                        options: 2,
                        priority: runtime.policy.priority,
                        dead_interval: runtime.policy.dead_interval,
                        designated_router: runtime.dr,
                        backup_router: runtime.bdr,
                        neighbors,
                    }),
                ));
                runtime.hello_due = SimTime(
                    now.0
                        .saturating_add(u64::from(runtime.policy.hello_interval) * 1_000_000),
                );
            }
        }
        for ((id, _), neighbor) in &mut self.ospf_runtime.neighbors {
            if let Some(exchange) = &mut neighbor.exchange {
                bodies.extend(
                    exchange
                        .tick(now)
                        .into_iter()
                        .map(|p| (*id, neighbor.info.address, p)),
                );
            }
        }
        out.extend(
            bodies
                .into_iter()
                .filter_map(|(id, to, body)| self.ospf_emit(id, to, body)),
        );
        self.recompute_ospf_routes(now);
        out
    }
    /// Receive a decoded standard OSPF packet after IPv4 and interface policy checks.
    pub fn receive_ospf_v2(
        &mut self,
        interface: InterfaceId,
        source: Ipv4Addr,
        packet: OspfV2Packet,
        now: SimTime,
    ) -> Vec<OspfTransmission> {
        self.ospf_prepare(now);
        let mut out = Vec::new();
        let Some(self_id) = self.ospf_runtime.router_id else {
            return out;
        };
        let Some(runtime) = self.ospf_runtime.interfaces.get(&interface) else {
            return out;
        };
        if packet.area != runtime.area
            || packet.router_id == self_id
            || packet.router_id.is_unspecified()
            || packet.router_id.is_multicast()
            || !Ipv4Network::new(runtime.address.address(), runtime.address.prefix_len())
                .is_ok_and(|network| network.contains(source))
            || source == runtime.address.address()
        {
            return out;
        }
        if source.is_unspecified()
            || source.is_multicast()
            || source.is_broadcast()
            || packet.router_id.is_broadcast()
        {
            return out;
        }
        if let OspfBody::LinkStateUpdate(lsas) = &packet.body {
            let new: BTreeSet<_> = lsas
                .iter()
                .map(|lsa| {
                    (
                        if matches!(lsa.body, LsaBody::External { .. }) {
                            0
                        } else {
                            packet.area
                        },
                        lsa.key(),
                    )
                })
                .filter(|key| !self.ospf_runtime.database.contains_key(key))
                .collect();
            // Do not acknowledge state that cannot enter the bounded database.
            if self.ospf_runtime.database.len() + new.len() > OSPF_DATABASE_LIMIT {
                return out;
            }
        }
        let key = (interface, packet.router_id);
        if let OspfBody::Hello(hello) = packet.body {
            if hello.hello_interval != runtime.policy.hello_interval
                || hello.dead_interval != runtime.policy.dead_interval
                || hello.options & 2 == 0
                || (runtime.policy.network_type == OspfNetworkType::Broadcast
                    && hello.mask != runtime.address.mask())
            {
                return out;
            }
            if !self.ospf_runtime.neighbors.contains_key(&key)
                && self.ospf_runtime.neighbors.len() >= NEIGHBOR_LIMIT
            {
                return out;
            }
            let two_way = hello.neighbors.contains(&self_id);
            let fresh = !self.ospf_runtime.neighbors.contains_key(&key);
            let neighbor = self
                .ospf_runtime
                .neighbors
                .entry(key)
                .or_insert_with(|| Neighbor {
                    info: OspfNeighborInfo {
                        router_id: packet.router_id,
                        address: source,
                        interface,
                        state: OspfNeighborState::Init,
                        priority: hello.priority,
                        dead_at: now,
                    },
                    hello: hello.clone(),
                    exchange: None,
                });
            if neighbor.info.address != source {
                neighbor.exchange = None;
            }
            neighbor.info.address = source;
            neighbor.info.priority = hello.priority;
            neighbor.info.dead_at = SimTime(
                now.0
                    .saturating_add(u64::from(hello.dead_interval) * 1_000_000),
            );
            if !two_way {
                neighbor.exchange = None;
                neighbor.info.state = OspfNeighborState::Init;
            } else {
                neighbor.info.state = neighbor
                    .exchange
                    .as_ref()
                    .map_or(OspfNeighborState::TwoWay, |e| e.state);
            }
            neighbor.hello = hello;
            if fresh && let Some(runtime) = self.ospf_runtime.interfaces.get_mut(&interface) {
                runtime.hello_due = now;
            }
        } else {
            let database = self.ospf_database(packet.area, now);
            let Some(neighbor) = self
                .ospf_runtime
                .neighbors
                .get_mut(&key)
                .filter(|n| n.info.address == source)
            else {
                return out;
            };
            let Some(exchange) = &mut neighbor.exchange else {
                return out;
            };
            let result = exchange.receive(packet.body, &database, now);
            neighbor.info.state = exchange.state;
            out.extend(
                result
                    .packets
                    .into_iter()
                    .filter_map(|body| self.ospf_emit(interface, source, body)),
            );
            for lsa in result.advertisements {
                self.ospf_install(packet.area, lsa, Some(key), now, &mut out);
            }
        }
        out.extend(self.ospf_tick(now));
        out
    }
}
