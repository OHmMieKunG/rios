//! Layer 2 control-plane messages and states, independent of devices and topology.
#![forbid(unsafe_code)]

/// Simulator-specific Ethernet II encapsulation used to carry standard BPDU fields.
pub const STP_ETHERTYPE: u16 = 0x88b6;
/// IEEE bridge-group multicast destination.
pub const STP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
pub const STP_HELLO_MS: u64 = 2_000;
pub const STP_MAX_AGE_MS: u64 = 20_000;

/// Current spanning-tree role of a switch port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpPortRole {
    Root,
    Designated,
    Alternate,
}

/// Data-plane state selected by spanning tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StpPortState {
    Blocking,
    Forwarding,
}

/// IEEE 802.1D configuration BPDU fields used by the simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationBpdu {
    pub root_id: u64,
    pub root_cost: u32,
    pub bridge_id: u64,
    pub port_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BpduError {
    #[error("configuration BPDU is malformed")]
    Malformed,
}

impl ConfigurationBpdu {
    /// Encode a standard 35-byte 802.1D configuration BPDU.
    pub fn encode(self) -> [u8; 35] {
        let mut bytes = [0; 35];
        bytes[5..13].copy_from_slice(&self.root_id.to_be_bytes());
        bytes[13..17].copy_from_slice(&self.root_cost.to_be_bytes());
        bytes[17..25].copy_from_slice(&self.bridge_id.to_be_bytes());
        bytes[25..27].copy_from_slice(&self.port_id.to_be_bytes());
        bytes[29..31].copy_from_slice(&(20u16 * 256).to_be_bytes());
        bytes[31..33].copy_from_slice(&(2u16 * 256).to_be_bytes());
        bytes[33..35].copy_from_slice(&(15u16 * 256).to_be_bytes());
        bytes
    }

    /// Decode a version-zero configuration BPDU.
    pub fn decode(bytes: &[u8]) -> Result<Self, BpduError> {
        if bytes.len() != 35 || bytes[0..4] != [0, 0, 0, 0] {
            return Err(BpduError::Malformed);
        }
        Ok(Self {
            root_id: u64::from_be_bytes(bytes[5..13].try_into().unwrap()),
            root_cost: u32::from_be_bytes(bytes[13..17].try_into().unwrap()),
            bridge_id: u64::from_be_bytes(bytes[17..25].try_into().unwrap()),
            port_id: u16::from_be_bytes(bytes[25..27].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_bpdu_round_trip() {
        let bpdu = ConfigurationBpdu {
            root_id: 1,
            root_cost: 4,
            bridge_id: 2,
            port_id: 0x8001,
        };
        assert_eq!(ConfigurationBpdu::decode(&bpdu.encode()).unwrap(), bpdu);
    }
}

mod lacp;
pub use lacp::*;
