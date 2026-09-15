//! Ethernet addressing and frame envelopes, independent of device and CLI state.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// A six-octet Ethernet address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

/// Valid IEEE 802.1Q VLAN identifier (1-4094).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VlanId(u16);

/// VLAN identifier outside the usable IEEE 802.1Q range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("VLAN ID must be between 1 and 4094")]
pub struct InvalidVlanId;

impl VlanId {
    pub const DEFAULT: Self = Self(1);

    /// Validate and construct a VLAN identifier.
    pub fn new(value: u16) -> Result<Self, InvalidVlanId> {
        (1..=4094)
            .contains(&value)
            .then_some(Self(value))
            .ok_or(InvalidVlanId)
    }

    /// Numeric VLAN identifier.
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Malformed Ethernet address.
#[derive(Debug, thiserror::Error)]
#[error("expected six colon-separated hexadecimal octets")]
pub struct InvalidMacAddress;

impl FromStr for MacAddress {
    type Err = InvalidMacAddress;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(InvalidMacAddress);
        }
        let mut bytes = [0; 6];
        for (out, part) in bytes.iter_mut().zip(parts) {
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InvalidMacAddress);
            }
            *out = u8::from_str_radix(part, 16).map_err(|_| InvalidMacAddress)?;
        }
        Ok(Self(bytes))
    }
}
impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_round_trip() {
        let mac: MacAddress = "02:00:aa:01:02:ff".parse().unwrap();
        assert_eq!(mac.to_string(), "02:00:aa:01:02:ff");
        for bad in ["00:00", "000:00:00:00:00:00", "zz:00:00:00:00:00"] {
            assert!(bad.parse::<MacAddress>().is_err());
        }
    }
}

mod frame;
pub use frame::{EtherType, EthernetFrame, FrameError};
impl MacAddress {
    /// Ethernet broadcast destination.
    pub const BROADCAST: Self = Self([0xff; 6]);
    /// Whether the address selects a multicast group (including broadcast).
    pub fn is_multicast(self) -> bool {
        self.0[0] & 1 != 0
    }
}
