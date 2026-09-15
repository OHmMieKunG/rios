use crate::*;
use rios_ethernet::EthernetFrame;
use rios_simulator::SimTime;
use std::fmt::Write;

const MAC_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// A dynamically learned switch forwarding entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacEntry {
    pub vlan: VlanId,
    pub address: MacAddress,
    pub interface: InterfaceId,
    pub learned_at: SimTime,
}

/// Observable reasons a virtual interface discards a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DropReason {
    #[error("interface is down")]
    InterfaceDown,
    #[error("interface has no virtual link")]
    NoLink,
    #[error("link changed while frame was in flight")]
    LinkChanged,
    #[error("frame payload exceeds interface MTU")]
    MtuExceeded,
    #[error("destination MAC does not match interface")]
    NotForInterface,
    #[error("interface is not an Ethernet port")]
    NotEthernet,
    #[error("invalid Ethernet II EtherType")]
    InvalidEtherType,
    #[error("IPv4 access list denied packet")]
    AccessList,
}
impl Device {
    /// Learn or move a unicast source address on a switch port.
    pub fn learn_mac(
        &mut self,
        vlan: VlanId,
        address: MacAddress,
        interface: InterfaceId,
        now: SimTime,
    ) -> Result<(), DeviceError> {
        if !self.supports_switching() || !self.interfaces.contains_key(&interface) {
            return Err(DeviceError::MissingInterface);
        }
        if address != MacAddress([0; 6]) && !address.is_multicast() {
            self.mac_table.insert(
                (vlan, address),
                MacEntry {
                    vlan,
                    address,
                    interface,
                    learned_at: now,
                },
            );
        }
        Ok(())
    }

    /// Resolve a non-expired switch entry, lazily aging stale entries.
    pub fn mac_lookup(
        &mut self,
        vlan: VlanId,
        address: MacAddress,
        now: SimTime,
    ) -> Option<MacEntry> {
        let key = (vlan, address);
        let entry = self.mac_table.get(&key).copied()?;
        if now.0.saturating_sub(entry.learned_at.0) >= MAC_LIFETIME_MS * 1000 {
            self.mac_table.remove(&key);
            None
        } else {
            Some(entry)
        }
    }

    /// Render non-expired dynamic switch forwarding entries.
    pub fn show_mac_address_table(&mut self, now: SimTime) -> String {
        self.mac_table
            .retain(|_, entry| now.0.saturating_sub(entry.learned_at.0) < MAC_LIFETIME_MS * 1000);
        let mut output = String::from(
            "          Mac Address Table\n-------------------------------------------\n\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n",
        );
        for entry in self.mac_table.values() {
            writeln!(
                output,
                "{:<7} {:<17} DYNAMIC     {}",
                entry.vlan.get(),
                entry.address,
                self.running_config.interfaces[&entry.interface].name
            )
            .unwrap();
        }
        output
    }

    /// Validate a frame at the interface boundary without changing counters.
    pub fn check_frame(
        &self,
        id: InterfaceId,
        frame: &EthernetFrame,
        receive: bool,
    ) -> Result<(), DropReason> {
        let Some(interface) = self.interfaces.get(&id) else {
            return Err(DropReason::NotEthernet);
        };
        if !interface.kind.is_ethernet() {
            return Err(DropReason::NotEthernet);
        }
        if !self.protocol_up(id) {
            return Err(DropReason::InterfaceDown);
        }
        let payload_len = if frame.ethertype == rios_ethernet::EtherType::Dot1Q {
            frame.payload.len().saturating_sub(4)
        } else {
            frame.payload.len()
        };
        if payload_len > usize::from(self.running_config.interfaces[&id].mtu) {
            return Err(DropReason::MtuExceeded);
        }
        if u16::from(frame.ethertype) < 0x0600 {
            return Err(DropReason::InvalidEtherType);
        }
        if receive
            && !self.is_switchport(id)
            && frame.destination != interface.mac_address
            && !frame.destination.is_multicast()
        {
            return Err(DropReason::NotForInterface);
        }
        Ok(())
    }
    /// Account for an accepted frame. Called by the lab after boundary validation.
    pub fn record_frame(
        &mut self,
        id: InterfaceId,
        length: usize,
        receive: bool,
    ) -> Result<(), DeviceError> {
        let counters = &mut self
            .interfaces
            .get_mut(&id)
            .ok_or(DeviceError::MissingInterface)?
            .counters;
        // Saturate counters rather than wrapping observability state in long runs.
        if receive {
            counters.rx_packets = counters.rx_packets.saturating_add(1);
            counters.rx_bytes = counters.rx_bytes.saturating_add(length as u64);
        } else {
            counters.tx_packets = counters.tx_packets.saturating_add(1);
            counters.tx_bytes = counters.tx_bytes.saturating_add(length as u64);
        }
        Ok(())
    }
    /// Account for a discarded frame without counting it as accepted traffic.
    pub fn record_drop(&mut self, id: InterfaceId) -> Result<(), DeviceError> {
        let counters = &mut self
            .interfaces
            .get_mut(&id)
            .ok_or(DeviceError::MissingInterface)?
            .counters;
        counters.drops = counters.drops.saturating_add(1);
        Ok(())
    }
}
