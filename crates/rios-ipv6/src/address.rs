//! Validated IPv6 host prefixes, networks, and Ethernet multicast mappings.
use rios_ethernet::MacAddress;
use serde::{Deserialize, Serialize};
use std::{fmt, net::Ipv6Addr, str::FromStr};
/// Invalid IPv6 address or prefix input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("IPv6 prefix length must be 0-128")]
    Prefix,
    #[error("expected an IPv6 address followed by /prefix-length")]
    Syntax,
    #[error("interface address must be unicast and nonzero")]
    NotUnicast,
}
/// One configured unicast address retaining its host bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "AddressData", into = "AddressData")]
pub struct Ipv6InterfaceConfig {
    address: Ipv6Addr,
    prefix_len: u8,
}
#[derive(Serialize, Deserialize)]
struct AddressData {
    address: Ipv6Addr,
    prefix_len: u8,
}
impl TryFrom<AddressData> for Ipv6InterfaceConfig {
    type Error = AddressError;
    fn try_from(value: AddressData) -> Result<Self, Self::Error> {
        Self::new(value.address, value.prefix_len)
    }
}
impl From<Ipv6InterfaceConfig> for AddressData {
    fn from(value: Ipv6InterfaceConfig) -> Self {
        Self {
            address: value.address,
            prefix_len: value.prefix_len,
        }
    }
}
impl Ipv6InterfaceConfig {
    pub fn new(address: Ipv6Addr, prefix_len: u8) -> Result<Self, AddressError> {
        if prefix_len > 128 {
            return Err(AddressError::Prefix);
        }
        if address.is_unspecified() || address.is_multicast() {
            return Err(AddressError::NotUnicast);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }
    pub fn address(self) -> Ipv6Addr {
        self.address
    }
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
    pub fn network(self) -> Ipv6Network {
        Ipv6Network {
            address: Ipv6Addr::from(u128::from(self.address) & mask(self.prefix_len)),
            prefix_len: self.prefix_len,
        }
    }
}
impl fmt::Display for Ipv6InterfaceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}
impl FromStr for Ipv6InterfaceConfig {
    type Err = AddressError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = split(value)?;
        Self::new(address, prefix)
    }
}
fn split(value: &str) -> Result<(Ipv6Addr, u8), AddressError> {
    let (address, prefix) = value.split_once('/').ok_or(AddressError::Syntax)?;
    Ok((
        address.parse().map_err(|_| AddressError::Syntax)?,
        prefix.parse().map_err(|_| AddressError::Syntax)?,
    ))
}
fn mask(length: u8) -> u128 {
    if length == 0 {
        0
    } else {
        u128::MAX << (128 - length)
    }
}
/// A canonical IPv6 network; serialized input passes through prefix validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "AddressData", into = "AddressData")]
pub struct Ipv6Network {
    address: Ipv6Addr,
    prefix_len: u8,
}
impl Ipv6Network {
    pub fn new(address: Ipv6Addr, prefix_len: u8) -> Result<Self, AddressError> {
        if prefix_len > 128 {
            return Err(AddressError::Prefix);
        }
        Ok(Self {
            address: Ipv6Addr::from(u128::from(address) & mask(prefix_len)),
            prefix_len,
        })
    }
    pub fn address(self) -> Ipv6Addr {
        self.address
    }
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
    pub fn contains(self, address: Ipv6Addr) -> bool {
        (u128::from(address) & mask(self.prefix_len)) == u128::from(self.address)
    }
}
impl TryFrom<AddressData> for Ipv6Network {
    type Error = AddressError;
    fn try_from(value: AddressData) -> Result<Self, Self::Error> {
        Self::new(value.address, value.prefix_len)
    }
}
impl From<Ipv6Network> for AddressData {
    fn from(value: Ipv6Network) -> Self {
        Self {
            address: value.address,
            prefix_len: value.prefix_len,
        }
    }
}
impl fmt::Display for Ipv6Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}
impl FromStr for Ipv6Network {
    type Err = AddressError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = split(value)?;
        Self::new(address, prefix)
    }
}
/// Ethernet Modified EUI-64 interface identifier, used deterministically in this simulator.
pub fn interface_identifier(mac: MacAddress) -> u64 {
    let m = mac.0;
    u64::from_be_bytes([m[0] ^ 2, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]])
}
/// Automatic link-local address for a simulated Ethernet interface.
pub fn link_local(mac: MacAddress) -> Ipv6Addr {
    Ipv6Addr::from((0xfe80u128 << 112) | u128::from(interface_identifier(mac)))
}
/// Solicited-node multicast group for address resolution and DAD.
pub fn solicited_node(address: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(0xff0200000000000000000001ff000000u128 | (u128::from(address) & 0x00ff_ffff))
}
/// RFC 2464 Ethernet mapping for an IPv6 multicast destination.
pub fn multicast_mac(address: Ipv6Addr) -> Option<MacAddress> {
    if !address.is_multicast() {
        return None;
    }
    let a = address.octets();
    Some(MacAddress([0x33, 0x33, a[12], a[13], a[14], a[15]]))
}
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
