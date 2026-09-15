//! LACP version 1 wire fields carried in Ethernet Slow Protocol frames.
pub const LACP_ETHERTYPE: u16 = 0x8809;
pub const LACP_MULTICAST: [u8; 6] = [1, 0x80, 0xc2, 0, 0, 2];
pub const LACP_ACTIVITY: u8 = 1;
pub const LACP_TIMEOUT: u8 = 2;
pub const LACP_AGGREGATION: u8 = 4;
pub const LACP_SYNC: u8 = 8;
pub const LACP_COLLECTING: u8 = 16;
pub const LACP_DISTRIBUTING: u8 = 32;
pub const LACP_DEFAULTED: u8 = 64;

/// Actor or partner information from an LACPDU.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LacpPortInfo {
    pub system_priority: u16,
    pub system: [u8; 6],
    pub key: u16,
    pub port_priority: u16,
    pub port: u16,
    pub state: u8,
}
impl LacpPortInfo {
    /// Identity and aggregation capability must agree before synchronization.
    pub fn matches(&self, other: &Self) -> bool {
        self.system_priority == other.system_priority
            && self.system == other.system
            && self.key == other.key
            && self.port_priority == other.port_priority
            && self.port == other.port
            && self.state & LACP_AGGREGATION == other.state & LACP_AGGREGATION
    }
}
/// One fixed-size LACP version 1 protocol data unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lacpdu {
    pub actor: LacpPortInfo,
    pub partner: LacpPortInfo,
    pub collector_delay: u16,
}
/// Malformed or unsupported LACP wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed LACP version 1 PDU")]
pub struct LacpError;
impl Lacpdu {
    /// Encode subtype/version and Actor, Partner, Collector, and Terminator TLVs.
    pub fn encode(self) -> [u8; 110] {
        let mut bytes = [0; 110];
        bytes[..2].copy_from_slice(&[1, 1]);
        for (offset, kind, info) in [(2, 1, self.actor), (22, 2, self.partner)] {
            bytes[offset..offset + 2].copy_from_slice(&[kind, 20]);
            bytes[offset + 2..offset + 4].copy_from_slice(&info.system_priority.to_be_bytes());
            bytes[offset + 4..offset + 10].copy_from_slice(&info.system);
            bytes[offset + 10..offset + 12].copy_from_slice(&info.key.to_be_bytes());
            bytes[offset + 12..offset + 14].copy_from_slice(&info.port_priority.to_be_bytes());
            bytes[offset + 14..offset + 16].copy_from_slice(&info.port.to_be_bytes());
            bytes[offset + 16] = info.state;
        }
        bytes[42..44].copy_from_slice(&[3, 16]);
        bytes[44..46].copy_from_slice(&self.collector_delay.to_be_bytes());
        bytes
    }
    /// Validate mandatory TLVs before accessing their fixed-width fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, LacpError> {
        if bytes.len() != 110
            || bytes[..4] != [1, 1, 1, 20]
            || bytes[22..24] != [2, 20]
            || bytes[42..44] != [3, 16]
            || bytes[58..60] != [0, 0]
        {
            return Err(LacpError);
        }
        let word = |offset| u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let info = |offset: usize| LacpPortInfo {
            system_priority: word(offset + 2),
            system: [
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
                bytes[offset + 8],
                bytes[offset + 9],
            ],
            key: word(offset + 10),
            port_priority: word(offset + 12),
            port: word(offset + 14),
            state: bytes[offset + 16],
        };
        Ok(Self {
            actor: info(2),
            partner: info(22),
            collector_delay: word(44),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lacp_round_trip_and_malformed_lengths() {
        let packet = Lacpdu {
            actor: LacpPortInfo {
                system_priority: 32768,
                system: [2, 0, 0, 0, 0, 1],
                key: 1,
                port_priority: 32768,
                port: 2,
                state: 63,
            },
            partner: LacpPortInfo::default(),
            collector_delay: 0,
        };
        let bytes = packet.encode();
        assert_eq!(Lacpdu::decode(&bytes), Ok(packet));
        for end in 0..bytes.len() {
            assert!(Lacpdu::decode(&bytes[..end]).is_err());
        }
        for offset in [0, 1, 2, 3, 22, 23, 42, 43, 58, 59] {
            let mut bad = bytes;
            bad[offset] ^= 0xff;
            assert!(Lacpdu::decode(&bad).is_err());
        }
    }
}
