use super::*;
use std::fmt::Write;
impl Device {
    /// Operational interface summary generated exclusively from device state.
    pub fn show_ip_interface_brief(&self) -> String {
        let mut out = String::from(
            "Interface              IP-Address      OK? Method Status                Protocol\n",
        );
        for (id, config) in &self.running_config.interfaces {
            let ip = self
                .interface_ipv4(*id)
                .map_or_else(|| "unassigned".into(), |v| v.address().to_string());
            let method = if config.dhcp_client {
                "DHCP"
            } else if config.ipv4.is_some() {
                "manual"
            } else {
                "unset"
            };
            let status = if config.admin_state == AdminState::Down {
                "administratively down"
            } else {
                "up"
            };
            let protocol = if self.protocol_up(*id) { "up" } else { "down" };
            writeln!(
                out,
                "{:<22} {:<15} YES {:<6} {:<21} {}",
                config.name, ip, method, status, protocol
            )
            .unwrap();
        }
        out
    }
    /// Detailed interface configuration and runtime counters.
    pub fn show_interfaces(&self) -> String {
        self.render_interfaces(None)
    }
    /// Detailed counters and configuration for one existing interface.
    pub fn show_interface(&self, id: InterfaceId) -> Result<String, DeviceError> {
        if !self.interfaces.contains_key(&id) {
            return Err(DeviceError::MissingInterface);
        }
        Ok(self.render_interfaces(Some(id)))
    }
    fn render_interfaces(&self, selected: Option<InterfaceId>) -> String {
        let mut out = String::new();
        for (id, interface) in &self.interfaces {
            if selected.is_some_and(|selected| selected != *id) {
                continue;
            }
            let config = &self.running_config.interfaces[id];
            let status = if config.admin_state == AdminState::Down {
                "administratively down"
            } else {
                "up"
            };
            writeln!(
                out,
                "{} is {}, line protocol is {}",
                config.name,
                status,
                if self.protocol_up(*id) { "up" } else { "down" }
            )
            .unwrap();
            if interface.kind.is_ethernet() {
                writeln!(
                    out,
                    "  Hardware is {}, address is {}, MTU {} bytes",
                    interface.media, interface.mac_address, config.mtu
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "  Hardware is {}, MTU {} bytes",
                    interface.media, config.mtu
                )
                .unwrap();
            }
            if !config.description.is_empty() {
                writeln!(out, "  Description: {}", config.description).unwrap();
            }
            if let Some(ip) = self.interface_ipv4(*id) {
                writeln!(
                    out,
                    "  Internet address is {}/{}",
                    ip.address(),
                    ip.prefix_len()
                )
                .unwrap();
            }
            let c = &interface.counters;
            writeln!(
                out,
                "  {} packets input, {} bytes\n  {} packets output, {} bytes\n  {} drops",
                c.rx_packets, c.rx_bytes, c.tx_packets, c.tx_bytes, c.drops
            )
            .unwrap();
            for (reason, count) in &c.drop_reasons {
                writeln!(out, "    {count} drops: {reason}").unwrap();
            }
        }
        out
    }

    /// Catalyst-style physical port status table.
    pub fn show_interfaces_status(&self) -> String {
        let mut out = String::from(
            "Port                 Name               Status       Vlan       Duplex Speed Type\n",
        );
        for (id, interface) in &self.interfaces {
            if !interface.kind.is_ethernet() {
                continue;
            }
            let config = &self.running_config.interfaces[id];
            let status = if config.admin_state == AdminState::Down {
                "disabled"
            } else if self.protocol_up(*id) {
                "connected"
            } else {
                "notconnect"
            };
            let vlan = match config.switchport.as_ref().map(|port| port.mode) {
                Some(SwitchportMode::Access) => config
                    .switchport
                    .as_ref()
                    .unwrap()
                    .access_vlan
                    .get()
                    .to_string(),
                Some(SwitchportMode::Trunk) => "trunk".into(),
                None => "routed".into(),
            };
            let speed = match interface.kind {
                InterfaceKind::TenGigabitEthernet => "10G",
                _ => "1000",
            };
            writeln!(
                out,
                "{:<20} {:<18} {:<12} {:<10} a-full {:<5} {}",
                config.name, config.description, status, vlan, speed, interface.media
            )
            .unwrap();
        }
        out
    }

    /// Catalyst-style VLAN database summary with access-port membership.
    pub fn show_vlan_brief(&self) -> String {
        let mut out = String::from(
            "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n",
        );
        for (vlan, config) in &self.running_config.vlans {
            let name = if config.name.is_empty() {
                if *vlan == VlanId::DEFAULT {
                    "default".into()
                } else {
                    format!("VLAN{:04}", vlan.get())
                }
            } else {
                config.name.clone()
            };
            let ports = self
                .running_config
                .interfaces
                .values()
                .filter_map(|interface| {
                    interface
                        .switchport
                        .as_ref()
                        .filter(|port| {
                            port.mode == SwitchportMode::Access && port.access_vlan == *vlan
                        })
                        .map(|_| interface.name.as_str())
                })
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(out, "{:<4} {:<32} active    {}", vlan.get(), name, ports).unwrap();
        }
        out
    }
}
