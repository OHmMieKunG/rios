//! Version-specific wire metadata used by the shared adjacency state machine.
use crate::{Lsa, LsaHeader, LsaKey, OspfHello, WireError};
use std::{cmp::Ordering, fmt::Debug};

/// The wire operations needed by database exchange, independent of network addresses.
pub trait ExchangeAdvertisement: Clone + Debug + PartialEq + Eq {
    type Key: Copy + Debug + Ord;
    type Header: Copy + Debug + PartialEq + Eq;
    type Hello: Clone + Debug + PartialEq + Eq;
    const OPTIONS: u32;
    /// IP header plus OSPF header in bytes.
    const PACKET_OVERHEAD: u16;
    /// IP header, OSPF header and fixed DBD fields in bytes.
    const DD_OVERHEAD: u16;
    fn key(&self) -> Self::Key;
    fn header(&self) -> Result<Self::Header, WireError>;
    fn encoded_len(&self) -> Result<usize, WireError>;
    fn header_key(header: &Self::Header) -> Self::Key;
    fn compare(a: &Self::Header, b: &Self::Header) -> Ordering;
}
impl ExchangeAdvertisement for Lsa {
    type Key = LsaKey;
    type Header = LsaHeader;
    type Hello = OspfHello;
    const OPTIONS: u32 = 2;
    const PACKET_OVERHEAD: u16 = 44;
    const DD_OVERHEAD: u16 = 52;
    fn key(&self) -> LsaKey {
        self.key()
    }
    fn header(&self) -> Result<LsaHeader, WireError> {
        self.header()
    }
    fn encoded_len(&self) -> Result<usize, WireError> {
        Ok(self.encode()?.len())
    }
    fn header_key(header: &LsaHeader) -> LsaKey {
        header.key
    }
    fn compare(a: &LsaHeader, b: &LsaHeader) -> Ordering {
        super::compare_lsa(a, b)
    }
}
