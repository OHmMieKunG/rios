//! Logical EtherChannel ports and deterministic member selection.
use crate::*;
use rios_config::{ChannelMembership, ChannelMode};
impl Device {
    pub(crate) fn create_port_channel(
        &mut self,
        canonical: &str,
    ) -> Result<InterfaceId, DeviceError> {
        if !self.supports_routing() && !self.supports_switching() {
            return Err(DeviceError::InvalidChannel);
        }
        let number = canonical
            .strip_prefix("Port-channel")
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(DeviceError::InvalidChannel)?;
        let id = self.insert_interface(
            canonical.into(),
            InterfaceKind::PortChannel,
            InterfaceMedia::Virtual,
        )?;
        let switching = self.supports_switching();
        let config = self.config_mut(id)?;
        config.port_channel = Some(number);
        config.admin_state = AdminState::Up;
        config.switchport_capable = switching;
        config.switchport = switching.then(SwitchportConfig::default);
        Ok(id)
    }
    /// Add a physical port to a compatible bundle (at most eight members).
    pub fn set_channel_group(
        &mut self,
        interface: InterfaceId,
        number: u16,
        mode: ChannelMode,
    ) -> Result<(), DeviceError> {
        if !(1..=4096).contains(&number)
            || !self
                .interfaces
                .get(&interface)
                .is_some_and(|port| port.kind.is_ethernet())
            || (!self.supports_routing() && !self.supports_switching())
        {
            return Err(DeviceError::InvalidChannel);
        }
        let config = self.running_config.interfaces[&interface].clone();
        if config.ipv4.is_some()
            || config.dhcp_client
            || config
                .channel_group
                .is_some_and(|group| group.number != number)
            || self
                .running_config
                .interfaces
                .values()
                .any(|other| other.parent == Some(interface))
        {
            return Err(DeviceError::InvalidChannel);
        }
        let members: Vec<_> = self
            .running_config
            .interfaces
            .iter()
            .filter(|(id, config)| {
                **id != interface
                    && config
                        .channel_group
                        .is_some_and(|group| group.number == number)
            })
            .collect();
        if members.len() >= 8
            || members.iter().any(|(id, other)| {
                self.interfaces[id].kind != self.interfaces[&interface].kind
                    || other.channel_group.is_some_and(|group| {
                        (group.mode == ChannelMode::On) != (mode == ChannelMode::On)
                    })
            })
        {
            return Err(DeviceError::InvalidChannel);
        }
        let name = format!("Port-channel{number}");
        let logical = self.find_interface(&name);
        if let Some(logical) = logical
            && self.running_config.interfaces[&logical].switchport != config.switchport
        {
            return Err(DeviceError::InvalidChannel);
        }
        let logical = if let Some(logical) = logical {
            logical
        } else {
            let logical = self.create_port_channel(&name)?;
            let aggregate = self.config_mut(logical)?;
            aggregate.switchport = config.switchport;
            aggregate.mtu = config.mtu;
            logical
        };
        if self.running_config.interfaces[&logical].mtu != config.mtu {
            return Err(DeviceError::InvalidChannel);
        }
        self.config_mut(interface)?.channel_group = Some(ChannelMembership { number, mode });
        self.mac_table
            .retain(|_, entry| entry.interface != interface);
        Ok(())
    }
    pub(crate) fn sync_channel_switchports(&mut self, id: InterfaceId) {
        let Some(number) = self
            .running_config
            .interfaces
            .get(&id)
            .and_then(|config| config.port_channel)
        else {
            return;
        };
        let policy = self.running_config.interfaces[&id].switchport.clone();
        for config in self.running_config.interfaces.values_mut() {
            if config
                .channel_group
                .is_some_and(|group| group.number == number)
            {
                config.switchport = policy.clone();
            }
        }
    }
    /// Remove membership without deleting the logical interface.
    pub fn clear_channel_group(&mut self, interface: InterfaceId) -> Result<(), DeviceError> {
        self.config_mut(interface)?.channel_group = None;
        Ok(())
    }
    /// Logical bundle associated with a physical member.
    pub fn channel_interface(&self, member: InterfaceId) -> Option<InterfaceId> {
        let number = self
            .running_config
            .interfaces
            .get(&member)?
            .channel_group?
            .number;
        self.running_config
            .interfaces
            .iter()
            .find_map(|(id, config)| (config.port_channel == Some(number)).then_some(*id))
    }
    /// Active members in stable interface-ID order.
    pub fn channel_members(&self, logical: InterfaceId) -> Vec<InterfaceId> {
        let Some(number) = self
            .running_config
            .interfaces
            .get(&logical)
            .and_then(|config| config.port_channel)
        else {
            return Vec::new();
        };
        self.running_config
            .interfaces
            .iter()
            .filter_map(|(id, config)| {
                (config
                    .channel_group
                    .is_some_and(|group| group.number == number && group.mode == ChannelMode::On)
                    && config.switchport == self.running_config.interfaces[&logical].switchport
                    && config.mtu == self.running_config.interfaces[&logical].mtu
                    && self.protocol_up(*id))
                .then_some(*id)
            })
            .collect()
    }
    /// Whether an interface is a logical aggregation endpoint.
    pub fn is_port_channel(&self, id: InterfaceId) -> bool {
        self.running_config
            .interfaces
            .get(&id)
            .is_some_and(|config| config.port_channel.is_some())
    }
    /// Select one active member; frames of a flow retain their member while the bundle is stable.
    pub fn channel_egress(
        &self,
        logical: InterfaceId,
        frame: &EthernetFrame,
    ) -> Option<InterfaceId> {
        if !self.protocol_up(logical) {
            return None;
        }
        let members = self.channel_members(logical);
        if members.is_empty() {
            return None;
        }
        let hash = frame
            .source
            .0
            .iter()
            .chain(frame.destination.0.iter())
            .fold(0u64, |hash, byte| {
                hash.wrapping_mul(31).wrapping_add(u64::from(*byte))
            });
        members.get((hash % members.len() as u64) as usize).copied()
    }
    /// Map a collecting member to its logical port.
    pub fn channel_ingress(&self, member: InterfaceId) -> Result<InterfaceId, DropReason> {
        let Some(logical) = self.channel_interface(member) else {
            return Ok(member);
        };
        if self.protocol_up(logical) && self.channel_members(logical).contains(&member) {
            Ok(logical)
        } else {
            Err(DropReason::ChannelInactive)
        }
    }
    /// Render actual group membership and forwarding state.
    pub fn show_etherchannel_summary(&self) -> String {
        use std::fmt::Write;
        let mut output = String::from("Group  Port-channel        Protocol  Ports\n");
        for (id, config) in &self.running_config.interfaces {
            let Some(number) = config.port_channel else {
                continue;
            };
            let active = self.channel_members(*id);
            let _ = write!(output, "{number:<6} {:<19} ", config.name);
            let members: Vec<_> = self
                .running_config
                .interfaces
                .iter()
                .filter(|(_, config)| {
                    config
                        .channel_group
                        .is_some_and(|group| group.number == number)
                })
                .collect();
            let lacp = members.iter().any(|(_, config)| {
                config
                    .channel_group
                    .is_some_and(|group| group.mode != ChannelMode::On)
            });
            let _ = write!(output, "{:<9} ", if lacp { "LACP" } else { "-" });
            for (id, config) in members {
                let _ = write!(
                    output,
                    "{}({}) ",
                    config.name,
                    if active.contains(id) { "P" } else { "s" }
                );
            }
            output.push('\n');
        }
        output
    }
}
