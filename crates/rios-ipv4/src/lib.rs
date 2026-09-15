//! Validated IPv4 interface addressing, without device or CLI dependencies.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

mod packet;
mod routing;
pub use packet::{IpProtocol, Ipv4Packet, PacketError, checksum};
pub use routing::{Ipv4Network, Route, RouteSource, RoutingTable};

/// IPv4 address and a contiguous network prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AddressData", into = "AddressData")]
pub struct Ipv4InterfaceConfig {
    address: Ipv4Addr,
    prefix_len: u8,
}
#[derive(Serialize, Deserialize)]
struct AddressData {
    address: Ipv4Addr,
    prefix_len: u8,
}
impl TryFrom<AddressData> for Ipv4InterfaceConfig {
    type Error = AddressError;
    fn try_from(v: AddressData) -> Result<Self, Self::Error> {
        Self::new(v.address, v.prefix_len)
    }
}
impl From<Ipv4InterfaceConfig> for AddressData {
    fn from(v: Ipv4InterfaceConfig) -> Self {
        Self {
            address: v.address,
            prefix_len: v.prefix_len,
        }
    }
}
/// Invalid prefix or noncontiguous dotted mask.
#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("prefix length must be between 0 and 32")]
    InvalidPrefix,
    #[error("subnet mask must be contiguous")]
    InvalidMask,
}
impl Ipv4InterfaceConfig {
    /// Validate a prefix length before constructing an address.
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Result<Self, AddressError> {
        if prefix_len > 32 {
            return Err(AddressError::InvalidPrefix);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }
    /// Validate and convert a dotted decimal subnet mask.
    pub fn from_mask(address: Ipv4Addr, mask: Ipv4Addr) -> Result<Self, AddressError> {
        let bits = u32::from(mask);
        let len = bits.leading_ones() as u8;
        let result = Self::new(address, len)?;
        if result.mask() != mask {
            return Err(AddressError::InvalidMask);
        }
        Ok(result)
    }
    /// Configured host address.
    pub fn address(self) -> Ipv4Addr {
        self.address
    }
    /// Network prefix length.
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
    /// Dotted decimal mask.
    pub fn mask(self) -> Ipv4Addr {
        Ipv4Addr::from(if self.prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix_len)
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn masks() {
        for prefix in 0..=32 {
            let v = Ipv4InterfaceConfig::new(Ipv4Addr::LOCALHOST, prefix).unwrap();
            assert_eq!(
                Ipv4InterfaceConfig::from_mask(v.address(), v.mask()).unwrap(),
                v
            );
        }
        assert!(Ipv4InterfaceConfig::new(Ipv4Addr::LOCALHOST, 33).is_err());
        assert!(
            Ipv4InterfaceConfig::from_mask(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 255, 0))
                .is_err()
        );
    }
}
