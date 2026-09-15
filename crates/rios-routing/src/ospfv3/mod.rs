//! OSPFv3 wire packets and IPv6 LSAs (RFC 5340), sharing reliable adjacency exchange.
mod lsa;
mod packet;
use crate::{ExchangeAdvertisement, OspfBody, WireError};
pub use lsa::*;
pub use packet::*;
use std::{
    cmp::Ordering,
    net::{Ipv4Addr, Ipv6Addr},
};

/// AllSPFRouters, scoped to the local IPv6 link.
pub const OSPFV3_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 5);
/// AllDRouters, scoped to the local IPv6 link.
pub const OSPFV3_ALL_DR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 6);
/// V6, E and R capabilities: IPv6 forwarding in a normal area.
pub const OSPFV3_OPTIONS: u32 = 0x13;
/// OSPFv3 packet bodies with IPv6-specific LSAs and Hello fields.
pub type OspfV3Body = OspfBody<OspfV3Lsa>;
/// Reliable OSPFv3 adjacency using the common database exchange algorithm.
pub type OspfV3Exchange = crate::OspfExchange<OspfV3Lsa>;

/// Hello interface identifiers and DR/BDR router identifiers contain no IP subnet mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfV3Hello {
    pub interface_id: u32,
    pub priority: u8,
    pub options: u32,
    pub hello_interval: u16,
    pub dead_interval: u16,
    pub designated_router: Ipv4Addr,
    pub backup_router: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}
impl ExchangeAdvertisement for OspfV3Lsa {
    type Key = OspfV3LsaKey;
    type Header = OspfV3LsaHeader;
    type Hello = OspfV3Hello;
    const OPTIONS: u32 = OSPFV3_OPTIONS;
    const PACKET_OVERHEAD: u16 = 56;
    const DD_OVERHEAD: u16 = 68;
    fn key(&self) -> Self::Key {
        self.key()
    }
    fn header(&self) -> Result<Self::Header, WireError> {
        self.header()
    }
    fn encoded_len(&self) -> Result<usize, WireError> {
        Ok(self.encode()?.len())
    }
    fn header_key(header: &Self::Header) -> Self::Key {
        header.key
    }
    fn compare(a: &Self::Header, b: &Self::Header) -> Ordering {
        crate::ospf_exchange::compare_lsa_instances(
            (a.sequence, a.checksum, a.age),
            (b.sequence, b.checksum, b.age),
        )
    }
}
fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn rid(b: &[u8], i: usize) -> Ipv4Addr {
    Ipv4Addr::from(u32_at(b, i))
}
