//! OSPF device integration: interface selection, neighbors, elections and packet actions.
mod database;
mod display;
mod election;
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
                    router_id: None,
                    passive_interfaces: BTreeSet::new(),
                })
            }
        }
        Ok(())
    }
    /// Select an area for matching interfaces. More-specific wildcard statements win.
    pub fn add_ospf_network(&mut self, network: OspfNetworkConfig) -> Result<(), DeviceError> {
        let config = self
            .running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?;
        if config.networks.len() >= 1024 && !config.networks.contains(&network) {
            return Err(DeviceError::InvalidOspfConfig);
        }
        config.networks.insert(network);
        Ok(())
    }
    /// Configure a stable process identity; changing it restarts this process runtime.
    pub fn set_ospf_router_id(&mut self, id: Option<Ipv4Addr>) -> Result<(), DeviceError> {
        if id.is_some_and(|id| id.is_unspecified() || id.is_multicast() || id.is_broadcast()) {
            return Err(DeviceError::InvalidOspfConfig);
        }
        self.running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?
            .router_id = id;
        self.ospf_runtime = OspfRuntime::default();
        Ok(())
    }
    /// Suppress Hellos and adjacencies while retaining the interface as a stub network.
    pub fn set_ospf_passive(
        &mut self,
        interface: InterfaceId,
        passive: bool,
    ) -> Result<(), DeviceError> {
        if !self.running_config.interfaces.contains_key(&interface) {
            return Err(DeviceError::MissingInterface);
        }
        let config = self
            .running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?;
        if passive {
            config.passive_interfaces.insert(interface);
        } else {
            config.passive_interfaces.remove(&interface);
        }
        Ok(())
    }
    /// Validate and update interface protocol policy. Timer/network changes restart neighbors.
    pub fn set_ospf_interface(
        &mut self,
        interface: InterfaceId,
        policy: OspfInterfaceConfig,
    ) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::OspfUnsupported);
        }
        if policy.cost == 0
            || policy.hello_interval == 0
            || policy.dead_interval == 0
            || policy.dead_interval > 65535
        {
            return Err(DeviceError::InvalidOspfConfig);
        }
        self.running_config
            .interfaces
            .get_mut(&interface)
            .ok_or(DeviceError::MissingInterface)?
            .ospf = policy;
        Ok(())
    }
    /// Operational interfaces with area assignment, including passive stub interfaces.
    pub fn ospf_interfaces(&self) -> Vec<(InterfaceId, Ipv4InterfaceConfig, u32)> {
        let Some(config) = &self.running_config.ospf else {
            return vec![];
        };
        self.running_config
            .interfaces
            .keys()
            .filter_map(|id| {
                let ip = self.interface_ipv4(*id)?;
                let area = config
                    .networks
                    .iter()
                    .filter(|network| network.matches(ip.address()))
                    .min_by_key(|n| (u32::from(n.wildcard).count_ones(), *n))?
                    .area;
                self.protocol_up(*id).then_some((*id, ip, area))
            })
            .collect()
    }
    fn ospf_passive(&self, id: InterfaceId) -> bool {
        self.interfaces
            .get(&id)
            .is_none_or(|port| port.kind == InterfaceKind::Loopback)
            || self
                .running_config
                .ospf
                .as_ref()
                .is_some_and(|c| c.passive_interfaces.contains(&id))
    }
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
    /// Compatibility timer entry point; normal maintenance removes expired neighbors on each tick.
    pub fn expire_ospf_neighbor(&mut self, router_id: Ipv4Addr, now: SimTime) {
        self.ospf_runtime
            .neighbors
            .retain(|(_, id), n| *id != router_id || n.info.dead_at > now);
        self.recompute_ospf_routes(now);
    }
}
