//! Event-boundary protocol/state diffs, computed only for devices with selected state topics.
use super::*;
use rios_device::{Device, NatStatistics};
use rios_ipv4::Route;
use rios_routing::{BgpState, OspfNeighborState};
use rios_simulator::InterfaceId;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

#[derive(Debug, Default)]
pub(crate) struct DebugSnapshot {
    routes: Option<BTreeSet<Route>>,
    ospf: Option<BTreeMap<(InterfaceId, Ipv4Addr), OspfNeighborState>>,
    bgp: Option<BTreeMap<Ipv4Addr, BgpState>>,
    nat: Option<NatStatistics>,
    stp: Option<
        BTreeMap<
            (rios_config::VlanId, InterfaceId),
            (rios_switching::StpPortRole, rios_switching::StpPortState),
        >,
    >,
    lacp: Option<BTreeMap<InterfaceId, rios_switching::Lacpdu>>,
}
impl DebugSnapshot {
    fn capture(device: &Device) -> Option<Self> {
        let topics = device.debug_topics();
        if !topics.iter().any(|t| {
            matches!(
                t,
                DebugTopic::IpRouting
                    | DebugTopic::OspfAdjacency
                    | DebugTopic::Bgp
                    | DebugTopic::Nat
                    | DebugTopic::SpanningTree
                    | DebugTopic::Lacp
            )
        }) {
            return None;
        }
        Some(Self {
            routes: topics
                .contains(&DebugTopic::IpRouting)
                .then(|| device.routing_table().routes().iter().cloned().collect()),
            ospf: topics.contains(&DebugTopic::OspfAdjacency).then(|| {
                device
                    .ospf_neighbors()
                    .into_iter()
                    .map(|n| ((n.interface, n.router_id), n.state))
                    .collect()
            }),
            bgp: topics.contains(&DebugTopic::Bgp).then(|| {
                device
                    .bgp_neighbors()
                    .into_iter()
                    .map(|n| (n.address, n.state))
                    .collect()
            }),
            nat: topics
                .contains(&DebugTopic::Nat)
                .then(|| device.nat_statistics().clone()),
            stp: topics.contains(&DebugTopic::SpanningTree).then(|| {
                device
                    .stp_port_states()
                    .map(|(vlan, port, role, state)| ((vlan, port), (role, state)))
                    .collect()
            }),
            lacp: topics.contains(&DebugTopic::Lacp).then(|| {
                device
                    .lacp_neighbors()
                    .iter()
                    .map(|(port, n)| (*port, n.pdu))
                    .collect()
            }),
        })
    }
}
impl Lab {
    pub(crate) fn observe_debug_state(&mut self) {
        for device in self.debug_snapshots.keys().copied().collect::<Vec<_>>() {
            self.observe_device_state(device);
        }
    }
    pub(crate) fn observe_device_state(&mut self, device: DeviceId) {
        let Some(current) = self.devices.get(&device).and_then(DebugSnapshot::capture) else {
            self.debug_snapshots.remove(&device);
            return;
        };
        if let Some(old) = self.debug_snapshots.remove(&device) {
            if let (Some(before), Some(after)) = (&old.routes, &current.routes) {
                for route in before.difference(after) {
                    self.push_debug(
                        device,
                        DebugEvent::Route {
                            installed: false,
                            route: route.clone(),
                        },
                    );
                }
                for route in after.difference(before) {
                    self.push_debug(
                        device,
                        DebugEvent::Route {
                            installed: true,
                            route: route.clone(),
                        },
                    );
                }
            }
            if let (Some(before), Some(after)) = (&old.ospf, &current.ospf) {
                for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
                    if before.get(key) != after.get(key) {
                        self.push_debug(
                            device,
                            DebugEvent::OspfAdjacency {
                                interface: key.0,
                                router_id: key.1,
                                before: before.get(key).copied(),
                                after: after.get(key).copied(),
                            },
                        );
                    }
                }
            }
            if let (Some(before), Some(after)) = (&old.bgp, &current.bgp) {
                for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
                    if before.get(key) != after.get(key) {
                        self.push_debug(
                            device,
                            DebugEvent::BgpState {
                                peer: *key,
                                before: before.get(key).copied(),
                                after: after.get(key).copied(),
                            },
                        );
                    }
                }
            }
            if let (Some(before), Some(after)) = (&old.nat, &current.nat)
                && before != after
            {
                self.push_debug(
                    device,
                    DebugEvent::NatStatistics {
                        before: before.clone(),
                        after: after.clone(),
                    },
                );
            }
            if let (Some(before), Some(after)) = (&old.stp, &current.stp) {
                for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
                    if before.get(key) != after.get(key) {
                        self.push_debug(
                            device,
                            DebugEvent::SpanningTree {
                                vlan: key.0,
                                interface: key.1,
                                before: before.get(key).copied(),
                                after: after.get(key).copied(),
                            },
                        );
                    }
                }
            }
            if let (Some(before), Some(after)) = (&old.lacp, &current.lacp) {
                for key in before.keys().chain(after.keys()).collect::<BTreeSet<_>>() {
                    if before.get(key) != after.get(key) {
                        self.push_debug(
                            device,
                            DebugEvent::Lacp {
                                interface: *key,
                                before: before.get(key).copied(),
                                after: after.get(key).copied(),
                            },
                        );
                    }
                }
            }
        }
        self.debug_snapshots.insert(device, current);
    }
}
