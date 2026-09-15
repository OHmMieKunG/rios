use crate::*;
use rios_config::SwitchportMode;
use rios_simulator::SimTime;
use rios_switching::{ConfigurationBpdu, STP_MAX_AGE_MS, StpPortRole, StpPortState};
use std::fmt::Write;

impl Device {
    fn bridge_id(&self, vlan: VlanId) -> Option<u64> {
        let mac = self
            .interfaces
            .values()
            .map(|port| port.mac_address.0)
            .min()?;
        let system_id = 0x8000u64 | u64::from(vlan.get());
        Some(
            (system_id << 48)
                | (u64::from_be_bytes([0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]])
                    & 0x0000_ffff_ffff_ffff),
        )
    }

    fn stp_ports(&self) -> BTreeMap<VlanId, Vec<InterfaceId>> {
        let mut ports: BTreeMap<VlanId, Vec<InterfaceId>> = BTreeMap::new();
        for (id, interface) in &self.running_config.interfaces {
            if !self.protocol_up(*id) {
                continue;
            }
            let Some(switchport) = &interface.switchport else {
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
                    for vlan in self.running_config.vlans.keys().copied().filter(|vlan| {
                        switchport
                            .trunk_allowed_vlans
                            .as_ref()
                            .is_none_or(|allowed| allowed.contains(vlan))
                    }) {
                        ports.entry(vlan).or_default().push(*id);
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
        let instance = self.stp_runtime.entry(vlan).or_default();
        instance
            .received
            .retain(|port, received| ports.contains(port) && received.expires_at > now);
        let best = instance
            .received
            .iter()
            .map(|(port, received)| {
                (
                    *port,
                    (
                        received.bpdu.root_id,
                        received.bpdu.root_cost.saturating_add(4),
                        received.bpdu.bridge_id,
                        received.bpdu.port_id,
                        port.0,
                    ),
                )
            })
            .min_by_key(|(_, vector)| *vector);
        let own = (bridge_id, 0, bridge_id, 0, 0);
        let (root_id, root_cost, root_port) = match best.filter(|(_, vector)| *vector < own) {
            Some((port, vector)) => (vector.0, vector.1, Some(port)),
            None => (bridge_id, 0, None),
        };
        instance.root_id = root_id;
        instance.root_cost = root_cost;
        instance.root_port = root_port;
        let previous = instance.ports.clone();
        instance.ports.clear();
        for port in ports {
            let (role, state) = if Some(port) == root_port.as_ref() {
                (StpPortRole::Root, StpPortState::Forwarding)
            } else {
                let local = (
                    root_id,
                    root_cost,
                    bridge_id,
                    0x8000u16.saturating_add(port.0 as u16),
                );
                let designated = instance.received.get(port).is_none_or(|received| {
                    local
                        < (
                            received.bpdu.root_id,
                            received.bpdu.root_cost,
                            received.bpdu.bridge_id,
                            received.bpdu.port_id,
                        )
                });
                if designated {
                    (StpPortRole::Designated, StpPortState::Forwarding)
                } else {
                    (StpPortRole::Alternate, StpPortState::Blocking)
                }
            };
            instance.ports.insert(*port, (role, state));
        }
        let newly_blocked: Vec<_> = instance
            .ports
            .iter()
            .filter(|(port, (_, state))| {
                *state == StpPortState::Blocking
                    && previous
                        .get(port)
                        .is_none_or(|(_, old)| *old == StpPortState::Forwarding)
            })
            .map(|(port, _)| *port)
            .collect();
        self.mac_table
            .retain(|_, entry| !newly_blocked.contains(&entry.interface));
    }

    fn refresh_stp(&mut self, now: SimTime) {
        if !self.supports_switching() {
            return;
        }
        let ports = self.stp_ports();
        self.stp_runtime.retain(|vlan, _| ports.contains_key(vlan));
        for (vlan, members) in ports {
            self.recompute_stp_instance(vlan, &members, now);
        }
    }

    /// Recompute spanning-tree forwarding state before locally originated traffic.
    pub fn refresh_spanning_tree(&mut self, now: SimTime) {
        self.refresh_stp(now);
    }

    /// Produce configuration BPDUs on designated ports for every active VLAN.
    pub fn stp_bpdus(&mut self, now: SimTime) -> Vec<(InterfaceId, VlanId, ConfigurationBpdu)> {
        self.refresh_stp(now);
        let mut output = Vec::new();
        for (vlan, instance) in &self.stp_runtime {
            let bridge_id = self.bridge_id(*vlan).unwrap();
            for (port, (role, _)) in &instance.ports {
                if *role == StpPortRole::Designated {
                    output.push((
                        *port,
                        *vlan,
                        ConfigurationBpdu {
                            root_id: instance.root_id,
                            root_cost: instance.root_cost,
                            bridge_id,
                            port_id: 0x8000u16.saturating_add(port.0 as u16),
                        },
                    ));
                }
            }
        }
        output
    }

    /// Consume a BPDU received for one port and VLAN.
    pub fn receive_stp(
        &mut self,
        interface: InterfaceId,
        vlan: VlanId,
        bpdu: ConfigurationBpdu,
        now: SimTime,
    ) {
        let ports = self.stp_ports();
        let Some(members) = ports.get(&vlan) else {
            return;
        };
        if !members.contains(&interface) || self.bridge_id(vlan) == Some(bpdu.bridge_id) {
            return;
        }
        self.stp_runtime.entry(vlan).or_default().received.insert(
            interface,
            StpReceived {
                bpdu,
                expires_at: SimTime(now.0.saturating_add(STP_MAX_AGE_MS)),
            },
        );
        self.recompute_stp_instance(vlan, members, now);
    }

    /// Whether spanning tree permits data forwarding on this port and VLAN.
    pub fn stp_forwarding(&self, interface: InterfaceId, vlan: VlanId) -> bool {
        self.stp_runtime
            .get(&vlan)
            .and_then(|instance| instance.ports.get(&interface))
            .is_some_and(|(_, state)| *state == StpPortState::Forwarding)
    }

    /// Render current per-VLAN root and port state.
    pub fn show_spanning_tree(&mut self, vlan: Option<VlanId>, now: SimTime) -> String {
        self.refresh_stp(now);
        let mut out = String::new();
        for (id, instance) in self
            .stp_runtime
            .iter()
            .filter(|(id, _)| vlan.is_none_or(|selected| selected == **id))
        {
            writeln!(
                out,
                "VLAN{:04}\n  Root ID    {:016x}\n  Root Cost  {}",
                id.get(),
                instance.root_id,
                instance.root_cost
            )
            .unwrap();
            for (port, (role, state)) in &instance.ports {
                writeln!(
                    out,
                    "  {:<22} {:<10?} {:?}",
                    self.running_config.interfaces[port].name, role, state
                )
                .unwrap();
            }
        }
        out
    }
}
