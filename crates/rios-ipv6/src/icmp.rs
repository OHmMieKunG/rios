//! RFC 4443 echo/errors and IPv6 pseudoheader checksum validation.
use crate::{NdMessage, NextHeader, ipv6_checksum};
use std::net::Ipv6Addr;
/// ICMPv6 validation or unsupported-message failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Icmpv6Error {
    #[error("malformed ICMPv6 message or neighbor option")]
    Malformed,
    #[error("invalid ICMPv6 checksum")]
    Checksum,
    #[error("unsupported ICMPv6 message")]
    Unsupported,
    #[error("ICMPv6 message exceeds IPv6 payload limit")]
    TooLarge,
}
/// Error message types with their standard ICMPv6 numeric values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmpv6ErrorKind {
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
}
/// Supported ICMPv6 messages, including Neighbor Discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Icmpv6Message {
    Echo {
        reply: bool,
        identifier: u16,
        sequence: u16,
        payload: Vec<u8>,
    },
    Error {
        kind: Icmpv6ErrorKind,
        code: u8,
        parameter: u32,
        quoted: Vec<u8>,
    },
    Neighbor(NdMessage),
}
impl Icmpv6Message {
    /// Encode a checksum bound to the source and destination of the enclosing IPv6 packet.
    pub fn encode(&self, source: Ipv6Addr, destination: Ipv6Addr) -> Result<Vec<u8>, Icmpv6Error> {
        let mut out = match self {
            Self::Echo {
                reply,
                identifier,
                sequence,
                payload,
            } => {
                if payload.len() > 65527 {
                    return Err(Icmpv6Error::TooLarge);
                }
                let mut out = vec![if *reply { 129 } else { 128 }, 0, 0, 0];
                out.extend_from_slice(&identifier.to_be_bytes());
                out.extend_from_slice(&sequence.to_be_bytes());
                out.extend_from_slice(payload);
                out
            }
            Self::Error {
                kind,
                code,
                parameter,
                quoted,
            } => {
                if quoted.len() > 65527 {
                    return Err(Icmpv6Error::TooLarge);
                }
                let mut out = vec![*kind as u8, *code, 0, 0];
                out.extend_from_slice(&parameter.to_be_bytes());
                out.extend_from_slice(quoted);
                out
            }
            Self::Neighbor(message) => message.encode()?,
        };
        let checksum = ipv6_checksum(source, destination, NextHeader::Icmpv6, &out);
        out[2..4].copy_from_slice(&checksum.to_be_bytes());
        Ok(out)
    }
    pub fn decode(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        bytes: &[u8],
    ) -> Result<Self, Icmpv6Error> {
        if bytes.len() < 8 || bytes.len() > 65535 {
            return Err(Icmpv6Error::Malformed);
        }
        if ipv6_checksum(source, destination, NextHeader::Icmpv6, bytes) != 0 {
            return Err(Icmpv6Error::Checksum);
        }
        match bytes[0] {
            128 | 129 if bytes[1] == 0 => Ok(Self::Echo {
                reply: bytes[0] == 129,
                identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
                sequence: u16::from_be_bytes([bytes[6], bytes[7]]),
                payload: bytes[8..].to_vec(),
            }),
            1..=4 => {
                let kind = match bytes[0] {
                    1 => Icmpv6ErrorKind::DestinationUnreachable,
                    2 => Icmpv6ErrorKind::PacketTooBig,
                    3 => Icmpv6ErrorKind::TimeExceeded,
                    _ => Icmpv6ErrorKind::ParameterProblem,
                };
                Ok(Self::Error {
                    kind,
                    code: bytes[1],
                    parameter: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                    quoted: bytes[8..].to_vec(),
                })
            }
            133..=136 if bytes[1] == 0 => Ok(Self::Neighbor(NdMessage::decode(bytes)?)),
            _ => Err(Icmpv6Error::Unsupported),
        }
    }
}
