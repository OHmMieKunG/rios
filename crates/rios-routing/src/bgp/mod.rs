//! BGP-4 wire messages and bounded TCP stream framing, independent of sockets or devices.
mod attributes;
mod wire;
pub use attributes::*;
use rios_ipv4::Ipv4Network;
use std::net::Ipv4Addr;

/// Base BGP maximum message size, without the extended-message capability.
pub const BGP_MAX_MESSAGE: usize = 4096;
/// Protocol error codes suitable for a NOTIFICATION; malformed input never panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("BGP protocol error {code}/{subcode}")]
pub struct BgpError {
    pub code: u8,
    pub subcode: u8,
}
impl BgpError {
    fn new(code: u8, subcode: u8) -> Self {
        Self { code, subcode }
    }
}
/// Advertised optional protocol capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpCapability {
    FourOctetAs(u32),
    Multiprotocol { afi: u16, safi: u8 },
    RouteRefresh,
    Unknown { code: u8, value: Vec<u8> },
}
/// OPEN parameters. The legacy AS field is AS_TRANS for non-mappable four-byte ASNs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpOpen {
    pub autonomous_system: u16,
    pub hold_time: u16,
    pub router_id: Ipv4Addr,
    pub capabilities: Vec<BgpCapability>,
}
impl BgpOpen {
    pub(super) fn validate(&self) -> Result<(), BgpError> {
        if self.hold_time != 0 && self.hold_time < 3 {
            return Err(BgpError::new(2, 6));
        }
        if self.router_id.is_unspecified()
            || self.router_id.is_multicast()
            || self.router_id.is_broadcast()
        {
            return Err(BgpError::new(2, 3));
        }
        if self.effective_asn() == 0 {
            return Err(BgpError::new(2, 2));
        }
        let asns: std::collections::BTreeSet<_> = self
            .capabilities
            .iter()
            .filter_map(|c| {
                if let BgpCapability::FourOctetAs(asn) = c {
                    Some(*asn)
                } else {
                    None
                }
            })
            .collect();
        if asns.len() > 1 {
            return Err(BgpError::new(2, 4));
        }
        Ok(())
    }

    /// Effective peer AS number after RFC 6793 capability negotiation.
    pub fn effective_asn(&self) -> u32 {
        self.capabilities
            .iter()
            .find_map(|c| {
                if let BgpCapability::FourOctetAs(asn) = c {
                    Some(*asn)
                } else {
                    None
                }
            })
            .unwrap_or(u32::from(self.autonomous_system))
    }
    pub fn four_octet_as(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| matches!(c, BgpCapability::FourOctetAs(_)))
    }
}
/// Reachability changes carried by one UPDATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpUpdate {
    pub withdrawn: Vec<Ipv4Network>,
    pub attributes: Option<BgpAttributes>,
    pub announced: Vec<Ipv4Network>,
}
/// The four base BGP message kinds, encoded as actual TCP stream bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BgpMessage {
    Open(BgpOpen),
    Update(BgpUpdate),
    Notification {
        code: u8,
        subcode: u8,
        data: Vec<u8>,
    },
    Keepalive,
}
/// A bounded accumulator for partial or coalesced TCP reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpStream {
    bytes: Vec<u8>,
}
impl BgpStream {
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), BgpError> {
        if bytes.len() > BGP_MAX_MESSAGE * 2 - self.bytes.len() {
            return Err(BgpError::new(6, 8));
        }
        self.bytes.extend(bytes);
        Ok(())
    }
    /// Consume one frame so OPEN capabilities can affect decoding of the next UPDATE.
    pub fn next_message(&mut self, four_octet_as: bool) -> Result<Option<BgpMessage>, BgpError> {
        if self.bytes.len() < 19 {
            return Ok(None);
        }
        let length = message_length(&self.bytes)?;
        if self.bytes.len() < length {
            return Ok(None);
        }
        let message = BgpMessage::decode(&self.bytes[..length], four_octet_as)?;
        // ponytail: at most 8 KiB is shifted; use a ring buffer only if profiling justifies it.
        self.bytes.drain(..length);
        Ok(Some(message))
    }
    pub fn buffered_len(&self) -> usize {
        self.bytes.len()
    }
}
fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn ip(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::from(u32_at(b, 0))
}
fn message_length(bytes: &[u8]) -> Result<usize, BgpError> {
    if bytes.len() < 19 {
        return Err(BgpError::new(1, 2));
    }
    if bytes[..16] != [255; 16] {
        return Err(BgpError::new(1, 1));
    }
    let length = usize::from(u16_at(bytes, 16));
    if !(19..=BGP_MAX_MESSAGE).contains(&length) {
        return Err(BgpError::new(1, 2));
    }
    if !(1..=4).contains(&bytes[18]) {
        return Err(BgpError::new(1, 3));
    }
    Ok(length)
}
fn encode_prefixes(prefixes: &[Ipv4Network]) -> Result<Vec<u8>, BgpError> {
    let mut out = Vec::new();
    for prefix in prefixes {
        let length = usize::from(prefix.prefix_len()).div_ceil(8);
        if out.len() + 1 + length > BGP_MAX_MESSAGE {
            return Err(BgpError::new(1, 2));
        }
        out.push(prefix.prefix_len());
        out.extend(&prefix.address().octets()[..length]);
    }
    Ok(out)
}
fn decode_prefixes(mut bytes: &[u8]) -> Result<Vec<Ipv4Network>, BgpError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let prefix = bytes[0];
        if prefix > 32 {
            return Err(BgpError::new(3, 10));
        }
        let length = usize::from(prefix).div_ceil(8);
        let value = bytes.get(1..1 + length).ok_or(BgpError::new(3, 10))?;
        let mut address = [0; 4];
        address[..length].copy_from_slice(value);
        out.push(
            Ipv4Network::new(Ipv4Addr::from(address), prefix).map_err(|_| BgpError::new(3, 10))?,
        );
        bytes = &bytes[1 + length..];
    }
    Ok(out)
}
mod session;
pub use session::*;
mod selection;
pub use selection::*;
