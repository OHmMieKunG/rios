//! Structured static translations and dynamic IPv4 address pools.
use crate::AccessListId;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
/// Transport protocol of a static port translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NatTransport {
    Tcp,
    Udp,
}
/// Static one-to-one address mapping or transport-port mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StaticNat {
    Address {
        local: Ipv4Addr,
        global: Ipv4Addr,
    },
    Port {
        protocol: NatTransport,
        local: Ipv4Addr,
        local_port: u16,
        global: Ipv4Addr,
        global_port: u16,
    },
}
impl StaticNat {
    pub fn global(self) -> Ipv4Addr {
        match self {
            Self::Address { global, .. } | Self::Port { global, .. } => global,
        }
    }
    pub fn local(self) -> Ipv4Addr {
        match self {
            Self::Address { local, .. } | Self::Port { local, .. } => local,
        }
    }
}
/// Inclusive dynamic NAT pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatPool {
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub prefix_len: u8,
}
/// ACL-selected pool rule, optionally sharing addresses using PAT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatPoolRule {
    pub access_list: AccessListId,
    pub pool: String,
    pub overload: bool,
}
