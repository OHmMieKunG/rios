//! Standard configuration and rapid-spanning-tree BPDU wire fields.
use crate::{BpduError, ConfigurationBpdu};
pub const BPDU_PROPOSAL: u8 = 2;
pub const BPDU_AGREEMENT: u8 = 64;
pub const BPDU_LEARNING: u8 = 16;
pub const BPDU_FORWARDING: u8 = 32;
pub const BPDU_ROLE_ROOT: u8 = 8;
pub const BPDU_ROLE_DESIGNATED: u8 = 12;
pub const BPDU_ROLE_ALTERNATE: u8 = 4;
pub const STP_LLC: [u8; 3] = [0x42, 0x42, 3];

/// IEEE 802.1D/802.1w BPDU with flags and timers in 1/256-second units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StpBpdu {
    pub configuration: ConfigurationBpdu,
    pub rapid: bool,
    pub flags: u8,
    pub message_age: u16,
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
}
impl StpBpdu {
    /// Wrap a configuration vector with standard timer defaults.
    pub fn new(configuration: ConfigurationBpdu, rapid: bool, flags: u8) -> Self {
        Self {
            configuration,
            rapid,
            flags,
            message_age: 0,
            max_age: 20 * 256,
            hello_time: 2 * 256,
            forward_delay: 15 * 256,
        }
    }
    /// Encode LLC plus a version 0 configuration or version 2 rapid BPDU.
    pub fn encode(self) -> Vec<u8> {
        let mut bpdu = self.configuration.encode().to_vec();
        if self.rapid {
            bpdu[2] = 2;
            bpdu[3] = 2;
            bpdu.push(0);
        }
        bpdu[4] = self.flags;
        for (offset, value) in [
            (27, self.message_age),
            (29, self.max_age),
            (31, self.hello_time),
            (33, self.forward_delay),
        ] {
            bpdu[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
        let mut bytes = STP_LLC.to_vec();
        bytes.extend(bpdu);
        bytes
    }
    /// Decode LLC and reject unsupported types, versions, lengths, or timers.
    pub fn decode(bytes: &[u8]) -> Result<Self, BpduError> {
        if !bytes.starts_with(&STP_LLC) || bytes.len() < 38 {
            return Err(BpduError::Malformed);
        }
        let bytes = &bytes[3..];
        let rapid = match bytes[..4] {
            [0, 0, 0, 0] if bytes.len() == 35 => false,
            [0, 0, 2, 2] if bytes.len() == 36 && bytes[35] == 0 => true,
            _ => return Err(BpduError::Malformed),
        };
        let mut config = bytes[..35].to_vec();
        config[2] = 0;
        config[3] = 0;
        let word = |offset| u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let packet = Self {
            configuration: ConfigurationBpdu::decode(&config)?,
            rapid,
            flags: bytes[4],
            message_age: word(27),
            max_age: word(29),
            hello_time: word(31),
            forward_delay: word(33),
        };
        if packet.max_age == 0
            || packet.hello_time == 0
            || packet.forward_delay == 0
            || packet.message_age >= packet.max_age
        {
            return Err(BpduError::Malformed);
        }
        Ok(packet)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versioned_bpdu_round_trip_and_truncations() {
        for rapid in [false, true] {
            let packet = StpBpdu::new(
                ConfigurationBpdu {
                    root_id: 1,
                    root_cost: 4,
                    bridge_id: 2,
                    port_id: 0x8001,
                },
                rapid,
                BPDU_PROPOSAL,
            );
            let wire = packet.encode();
            assert_eq!(StpBpdu::decode(&wire), Ok(packet));
            for end in 0..wire.len() {
                assert!(StpBpdu::decode(&wire[..end]).is_err());
            }
        }
    }
}
