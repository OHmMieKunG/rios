//! Per-VLAN spanning-tree selection, guarded ports, and rapid synchronization.
use crate::*;
use rios_config::SwitchportMode;
use rios_simulator::SimTime;
use rios_switching::*;
use std::fmt::Write;
mod config;

impl Device {
    fn bridge_id(&self, vlan: VlanId) -> Option<u64> {
        let mac = self
            .interfaces
            .values()
            .map(|port| port.mac_address.0)
            .min()?;
        let priority = self
            .running_config
            .spanning_tree
            .priorities
            .get(&vlan)
            .copied()
            .unwrap_or(32768);
        Some(
            ((u64::from(priority) | u64::from(vlan.get())) << 48)
                | u64::from_be_bytes([0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]),
        )
    }
    fn stp_port_id(&self, port: InterfaceId) -> u16 {
        (u16::from(self.running_config.interfaces[&port].spanning_tree.priority) << 8)
            | (port.0 as u16 & 0x0fff)
    }
    fn stp_cost(&self, port: InterfaceId) -> u32 {
        self.running_config.interfaces[&port]
            .spanning_tree
            .cost
            .unwrap_or_else(|| {
                if self.interfaces[&port].kind == InterfaceKind::TenGigabitEthernet {
                    2
                } else {
                    4
                }
            })
    }
    fn stp_ports(&self) -> BTreeMap<VlanId, Vec<InterfaceId>> {
        let mut ports: BTreeMap<VlanId, Vec<InterfaceId>> = BTreeMap::new();
        for (id, config) in &self.running_config.interfaces {
            if config.channel_group.is_some() || !self.protocol_up(*id) {
                continue;
            }
            let Some(switchport) = &config.switchport else {
                continue;
            };
            match switchport.mode {
                SwitchportMode::Access
                    if self
                        .running_config
                        .vlans
                        .contains_key(&switchport.access_vlan) =>
                {
                    ports.entry(switchport.access_vlan).or_default().push(*id);
                }
                SwitchportMode::Trunk => {
                    for vlan in self.running_config.vlans.keys().filter(|vlan| {
                        switchport
                            .trunk_allowed_vlans
                            .as_ref()
                            .is_none_or(|allowed| allowed.contains(vlan))
                    }) {
                        ports.entry(*vlan).or_default().push(*id);
                    }
                }
                _ => {}
            }
        }
        ports
    }
    fn recompute_stp_instance(&mut self, vlan: VlanId, ports: &[InterfaceId], now: SimTime) {
        let Some(bridge_id) = self.bridge_id(vlan) else {
            return;
        };
        let priorities: BTreeMap<_, _> = ports
            .iter()
            .map(|port| (*port, (self.stp_port_id(*port), self.stp_cost(*port))))
            .collect();
        let rapid = self.running_config.spanning_tree.rapid;
        let instance = self.stp_runtime.entry(vlan).or_default();
        instance
            .received
            .retain(|port, received| ports.contains(port) && received.expires_at > now);
        instance.agreed.retain(|port| ports.contains(port));
        instance.transitions.retain(|port, _| ports.contains(port));
        let best = instance
            .received
            .iter()
            .filter(|(_, received)| !received.guarded)
            .map(|(port, received)| {
                let bpdu = received.bpdu.configuration;
                (
                    *port,
                    (
                        bpdu.root_id,
                        bpdu.root_cost.saturating_add(priorities[port].1),
                        bpdu.bridge_id,
                        bpdu.port_id,
                        priorities[port].0,
                    ),
                )
            })
            .min_by_key(|(_, vector)| *vector);
        let own = (bridge_id, 0, bridge_id, 0, 0);
        let (root_id, root_cost, root_port) = match best.filter(|(_, vector)| *vector < own) {
            Some((port, vector)) => (vector.0, vector.1, Some(port)),
            None => (bridge_id, 0, None),
        };
        let root_changed = instance.root_id != root_id
            || instance.root_port != root_port
            || instance.root_cost != root_cost;
        if root_changed {
            instance.agreed.clear();
            instance.transitions.clear();
        }
        instance.root_id = root_id;
        instance.root_cost = root_cost;
        instance.root_port = root_port;
        let previous = std::mem::take(&mut instance.ports);
        for port in ports {
            let received = instance.received.get(port);
            let guarded = received.is_some_and(|received| received.guarded);
            let role = if Some(*port) == root_port {
                StpPortRole::Root
            } else if guarded
                || received.is_none_or(|received| {
                    let bpdu = received.bpdu.configuration;
                    (root_id, root_cost, bridge_id, priorities[port].0)
                        < (bpdu.root_id, bpdu.root_cost, bpdu.bridge_id, bpdu.port_id)
                })
            {
                StpPortRole::Designated
            } else {
                StpPortRole::Alternate
            };
            if previous.get(port).is_none_or(|(old, _)| *old != role) {
                instance.agreed.remove(port);
                instance.transitions.insert(*port, now);
            }
            let since = *instance.transitions.entry(*port).or_insert(now);
            let edge =
                self.running_config.interfaces[port].spanning_tree.portfast && received.is_none();
            let state = if guarded || role == StpPortRole::Alternate {
                StpPortState::Blocking
            } else if edge || rapid && instance.agreed.contains(port) {
                StpPortState::Forwarding
            } else if now.0.saturating_sub(since.0) < 15_000_000 {
                if rapid {
                    StpPortState::Blocking
                } else {
                    StpPortState::Listening
                }
            } else if now.0.saturating_sub(since.0) < 30_000_000 {
                StpPortState::Learning
            } else {
                StpPortState::Forwarding
            };
            instance.ports.insert(*port, (role, state));
        }
        let changed = root_changed
            || previous
                .iter()
                .any(|(port, state)| instance.ports.get(port) != Some(state));
        if changed {
            self.mac_table
                .retain(|(entry_vlan, _), _| *entry_vlan != vlan);
        }
    }
    /// Refresh roles and elapsed forwarding states using simulation time.
    pub fn refresh_spanning_tree(&mut self, now: SimTime) {
        if !self.supports_switching() {
            return;
        }
        let ports = self.stp_ports();
        self.stp_runtime.retain(|vlan, _| ports.contains_key(vlan));
        for (vlan, members) in ports {
            self.recompute_stp_instance(vlan, &members, now);
        }
    }
    /// Produce standard BPDUs; rapid root ports also send explicit agreements.
    pub fn stp_packets(&mut self, now: SimTime) -> Vec<(InterfaceId, VlanId, StpBpdu)> {
        self.refresh_spanning_tree(now);
        let rapid = self.running_config.spanning_tree.rapid;
        let mut output = Vec::new();
        for (vlan, instance) in &self.stp_runtime {
            let Some(bridge_id) = self.bridge_id(*vlan) else {
                continue;
            };
            for (port, (role, state)) in &instance.ports {
                let rapid = rapid
                    && instance
                        .received
                        .get(port)
                        .is_none_or(|peer| peer.bpdu.rapid);
                if *role != StpPortRole::Designated && !(rapid && *role == StpPortRole::Root) {
                    continue;
                }
                let mut flags = match role {
                    StpPortRole::Root => BPDU_ROLE_ROOT,
                    StpPortRole::Designated => BPDU_ROLE_DESIGNATED,
                    StpPortRole::Alternate => BPDU_ROLE_ALTERNATE,
                };
                if rapid {
                    if *role == StpPortRole::Designated && !instance.agreed.contains(port) {
                        flags |= BPDU_PROPOSAL;
                    }
                    if *role == StpPortRole::Root && instance.agreed.contains(port) {
                        flags |= BPDU_AGREEMENT;
                    }
                } else {
                    flags = 0;
                }
                if rapid && (*state == StpPortState::Learning || *state == StpPortState::Forwarding)
                {
                    flags |= BPDU_LEARNING;
                }
                if rapid && *state == StpPortState::Forwarding {
                    flags |= BPDU_FORWARDING;
                }
                let mut packet = StpBpdu::new(
                    ConfigurationBpdu {
                        root_id: instance.root_id,
                        root_cost: instance.root_cost,
                        bridge_id,
                        port_id: self.stp_port_id(*port),
                    },
                    rapid,
                    flags,
                );
                if let Some(root) = instance
                    .root_port
                    .and_then(|root| instance.received.get(&root))
                {
                    packet.message_age = root.bpdu.message_age.saturating_add(256);
                }
                if packet.message_age < packet.max_age {
                    output.push((*port, *vlan, packet));
                }
            }
        }
        output
    }
    /// Compatibility view of the current configuration vectors.
    pub fn stp_bpdus(&mut self, now: SimTime) -> Vec<(InterfaceId, VlanId, ConfigurationBpdu)> {
        self.stp_packets(now)
            .into_iter()
            .map(|(port, vlan, packet)| (port, vlan, packet.configuration))
            .collect()
    }
    /// Consume a classic configuration vector.
    pub fn receive_stp(
        &mut self,
        interface: InterfaceId,
        vlan: VlanId,
        bpdu: ConfigurationBpdu,
        now: SimTime,
    ) {
        self.receive_stp_packet(interface, vlan, StpBpdu::new(bpdu, false, 0), now);
    }
    /// Receive a BPDU, synchronize nonedge ports before agreeing, and report state changes.
    pub fn receive_stp_packet(
        &mut self,
        interface: InterfaceId,
        vlan: VlanId,
        packet: StpBpdu,
        now: SimTime,
    ) -> bool {
        let ports = self.stp_ports();
        let Some(members) = ports.get(&vlan).filter(|ports| ports.contains(&interface)) else {
            return false;
        };
        if self.running_config.interfaces[&interface]
            .spanning_tree
            .bpdu_guard
        {
            self.stp_errdisabled.insert(interface);
            for instance in self.stp_runtime.values_mut() {
                instance.received.remove(&interface);
                instance.ports.remove(&interface);
                instance.agreed.remove(&interface);
            }
            self.mac_table
                .retain(|_, entry| entry.interface != interface);
            self.refresh_svi_states();
            return true;
        }
        let bpdu = packet.configuration;
        let Some(bridge) = self.bridge_id(vlan) else {
            return false;
        };
        if bpdu.bridge_id == bridge {
            return false;
        }
        self.refresh_spanning_tree(now);
        let previous = self.stp_runtime.get(&vlan).cloned().unwrap_or_default();
        let guarded = self.running_config.interfaces[&interface]
            .spanning_tree
            .root_guard
            && (bpdu.root_id, bpdu.root_cost, bpdu.bridge_id)
                < (previous.root_id, previous.root_cost, bridge);
        let lifetime =
            u64::from(packet.max_age.saturating_sub(packet.message_age)) * 1_000_000 / 256;
        let lifetime = if packet.rapid {
            lifetime.min(u64::from(packet.hello_time) * 3_000_000 / 256)
        } else {
            lifetime
        };
        let instance = self.stp_runtime.entry(vlan).or_default();
        if !instance.received.contains_key(&interface) {
            instance.transitions.insert(interface, now);
        }
        instance.received.insert(
            interface,
            StpReceived {
                bpdu: packet,
                guarded,
                expires_at: SimTime(now.0.saturating_add(lifetime)),
            },
        );
        self.recompute_stp_instance(vlan, members, now);
        if self.running_config.spanning_tree.rapid && packet.rapid && !guarded {
            let instance = self.stp_runtime.get_mut(&vlan).unwrap();
            let role = instance.ports.get(&interface).map(|(role, _)| *role);
            if role == Some(StpPortRole::Root) && packet.flags & BPDU_PROPOSAL != 0 {
                if !instance.agreed.contains(&interface) {
                    // Synchronize all other nonedge designated ports before opening the root.
                    for (port, (role, _)) in &instance.ports {
                        let edge = self.running_config.interfaces[port].spanning_tree.portfast
                            && !instance.received.contains_key(port);
                        if *port != interface && *role == StpPortRole::Designated && !edge {
                            instance.agreed.remove(port);
                            instance.transitions.insert(*port, now);
                        }
                    }
                    instance.agreed.insert(interface);
                }
            } else if role == Some(StpPortRole::Designated)
                && packet.flags & BPDU_AGREEMENT != 0
                && packet.flags & 12 == BPDU_ROLE_ROOT
                && bpdu.root_id == instance.root_id
                && bpdu.root_cost >= instance.root_cost
            {
                instance.agreed.insert(interface);
            }
            self.recompute_stp_instance(vlan, members, now);
        }
        let current = &self.stp_runtime[&vlan];
        previous.root_id != current.root_id
            || previous.root_port != current.root_port
            || previous.ports != current.ports
            || previous.agreed != current.agreed
            || packet.rapid
                && packet.flags & BPDU_PROPOSAL != 0
                && current.root_port == Some(interface)
    }
    /// Current structured role and state of a VLAN port.
    pub fn stp_port_state(
        &self,
        interface: InterfaceId,
        vlan: VlanId,
    ) -> Option<(StpPortRole, StpPortState)> {
        self.stp_runtime.get(&vlan)?.ports.get(&interface).copied()
    }
    /// Whether this port may learn source MAC addresses.
    pub fn stp_learning(&self, interface: InterfaceId, vlan: VlanId) -> bool {
        self.stp_port_state(interface, vlan)
            .is_some_and(|(_, state)| {
                matches!(state, StpPortState::Learning | StpPortState::Forwarding)
            })
    }
    /// Whether this port may forward user traffic.
    pub fn stp_forwarding(&self, interface: InterfaceId, vlan: VlanId) -> bool {
        self.stp_port_state(interface, vlan)
            .is_some_and(|(_, state)| state == StpPortState::Forwarding)
    }
    /// Render current per-VLAN roots, roles, states, and guard failures.
    pub fn show_spanning_tree(&mut self, vlan: Option<VlanId>, now: SimTime) -> String {
        self.refresh_spanning_tree(now);
        let mut out = String::new();
        for (id, instance) in self
            .stp_runtime
            .iter()
            .filter(|(id, _)| vlan.is_none_or(|selected| selected == **id))
        {
            let _ = writeln!(
                out,
                "VLAN{:04}\n  Protocol   {}\n  Root ID    {:016x}\n  Root Cost  {}",
                id.get(),
                if self.running_config.spanning_tree.rapid {
                    "rstp"
                } else {
                    "stp"
                },
                instance.root_id,
                instance.root_cost
            );
            for (port, (role, state)) in &instance.ports {
                let _ = writeln!(
                    out,
                    "  {:<22} {:<10?} {:?}",
                    self.running_config.interfaces[port].name, role, state
                );
                if instance
                    .received
                    .get(port)
                    .is_some_and(|received| received.guarded)
                {
                    out.push_str("    Root inconsistent\n");
                }
            }
        }
        for port in &self.stp_errdisabled {
            let _ = writeln!(
                out,
                "{} err-disabled (BPDU Guard)",
                self.running_config.interfaces[port].name
            );
        }
        out
    }
}

#[cfg(test)]
mod tests;
