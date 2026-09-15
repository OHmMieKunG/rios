//! Bounded, standard OSPFv2 packet and LSA wire codecs (RFC 2328).
mod lsa;
pub use lsa::*;
use rios_ipv4::checksum;
use std::net::Ipv4Addr;

/// Wire-format errors are safe to drop at a simulated interface boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("malformed OSPF packet")]
    Malformed,
    #[error("unsupported OSPF packet field")]
    Unsupported,
    #[error("invalid OSPF checksum")]
    Checksum,
    #[error("OSPF packet exceeds the wire length limit")]
    TooLarge,
}
/// Standard Hello data, including election and compatibility fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfHello {
    pub mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: u8,
    pub priority: u8,
    pub dead_interval: u32,
    pub designated_router: Ipv4Addr,
    pub backup_router: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}
/// Five OSPFv2 packet bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfBody {
    Hello(OspfHello),
    DatabaseDescription {
        mtu: u16,
        options: u8,
        flags: u8,
        sequence: u32,
        headers: Vec<LsaHeader>,
    },
    LinkStateRequest(Vec<LsaKey>),
    LinkStateUpdate(Vec<Lsa>),
    LinkStateAck(Vec<LsaHeader>),
}
/// OSPFv2 packet with null authentication and a validated checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfV2Packet {
    pub router_id: Ipv4Addr,
    pub area: u32,
    pub body: OspfBody,
}
impl OspfV2Packet {
    /// Encode header and payload; fail rather than truncate oversized lengths.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut body = Vec::new();
        let kind = match &self.body {
            OspfBody::Hello(hello) => {
                if hello.neighbors.len() > (65535 - 44) / 4 {
                    return Err(WireError::TooLarge);
                }
                body.extend_from_slice(&hello.mask.octets());
                body.extend_from_slice(&hello.hello_interval.to_be_bytes());
                body.extend_from_slice(&[hello.options, hello.priority]);
                body.extend_from_slice(&hello.dead_interval.to_be_bytes());
                body.extend_from_slice(&hello.designated_router.octets());
                body.extend_from_slice(&hello.backup_router.octets());
                for neighbor in &hello.neighbors {
                    body.extend_from_slice(&neighbor.octets());
                }
                1
            }
            OspfBody::DatabaseDescription {
                mtu,
                options,
                flags,
                sequence,
                headers,
            } => {
                if headers.len() > (65535 - 32) / 20 || *flags & !7 != 0 {
                    return Err(WireError::TooLarge);
                }
                body.extend_from_slice(&mtu.to_be_bytes());
                body.extend_from_slice(&[*options, *flags]);
                body.extend_from_slice(&sequence.to_be_bytes());
                for header in headers {
                    body.extend_from_slice(&header.encode());
                }
                2
            }
            OspfBody::LinkStateRequest(keys) => {
                if keys.len() > (65535 - 24) / 12 {
                    return Err(WireError::TooLarge);
                }
                for key in keys {
                    body.extend_from_slice(&(key.kind as u32).to_be_bytes());
                    body.extend_from_slice(&key.link_state_id.octets());
                    body.extend_from_slice(&key.advertising_router.octets());
                }
                3
            }
            OspfBody::LinkStateUpdate(lsas) => {
                if lsas.len() > (65535 - 28) / 20 {
                    return Err(WireError::TooLarge);
                }
                body.extend_from_slice(&(lsas.len() as u32).to_be_bytes());
                for lsa in lsas {
                    let bytes = lsa.encode()?;
                    if body.len() + bytes.len() > 65535 - 24 {
                        return Err(WireError::TooLarge);
                    }
                    body.extend(bytes);
                }
                4
            }
            OspfBody::LinkStateAck(headers) => {
                if headers.len() > (65535 - 24) / 20 {
                    return Err(WireError::TooLarge);
                }
                for header in headers {
                    body.extend_from_slice(&header.encode());
                }
                5
            }
        };
        let length = u16::try_from(24 + body.len()).map_err(|_| WireError::TooLarge)?;
        let mut out = vec![0; 24];
        out[0] = 2;
        out[1] = kind;
        out[2..4].copy_from_slice(&length.to_be_bytes());
        out[4..8].copy_from_slice(&self.router_id.octets());
        out[8..12].copy_from_slice(&self.area.to_be_bytes());
        out.extend(body);
        let sum = checksum(&out);
        out[12..14].copy_from_slice(&sum.to_be_bytes());
        Ok(out)
    }
    /// Decode a bounded packet, checking counts against available bytes before allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 24
            || bytes[0] != 2
            || usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) != bytes.len()
        {
            return Err(WireError::Malformed);
        }
        if bytes[14..24] != [0; 10] {
            return Err(WireError::Unsupported);
        }
        if checksum(bytes) != 0 {
            return Err(WireError::Checksum);
        }
        let body = &bytes[24..];
        let headers = |data: &[u8]| -> Result<Vec<LsaHeader>, WireError> {
            if !data.len().is_multiple_of(20) {
                return Err(WireError::Malformed);
            }
            data.as_chunks::<20>()
                .0
                .iter()
                .map(|chunk| LsaHeader::decode(chunk))
                .collect()
        };
        let parsed = match bytes[1] {
            1 => {
                if body.len() < 20 || !(body.len() - 20).is_multiple_of(4) {
                    return Err(WireError::Malformed);
                }
                OspfBody::Hello(OspfHello {
                    mask: lsa::ip(&body[..4]),
                    hello_interval: u16::from_be_bytes([body[4], body[5]]),
                    options: body[6],
                    priority: body[7],
                    dead_interval: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
                    designated_router: lsa::ip(&body[12..16]),
                    backup_router: lsa::ip(&body[16..20]),
                    neighbors: body[20..]
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|chunk| lsa::ip(chunk))
                        .collect(),
                })
            }
            2 => {
                if body.len() < 8 || body[3] & !7 != 0 {
                    return Err(WireError::Malformed);
                }
                OspfBody::DatabaseDescription {
                    mtu: u16::from_be_bytes([body[0], body[1]]),
                    options: body[2],
                    flags: body[3],
                    sequence: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
                    headers: headers(&body[8..])?,
                }
            }
            3 => {
                if !body.len().is_multiple_of(12) {
                    return Err(WireError::Malformed);
                }
                let mut keys = Vec::with_capacity(body.len() / 12);
                for chunk in body.as_chunks::<12>().0 {
                    if chunk[..3] != [0; 3] {
                        return Err(WireError::Unsupported);
                    }
                    keys.push(LsaKey {
                        kind: chunk[3].try_into()?,
                        link_state_id: lsa::ip(&chunk[4..8]),
                        advertising_router: lsa::ip(&chunk[8..12]),
                    });
                }
                OspfBody::LinkStateRequest(keys)
            }
            4 => {
                if body.len() < 4 {
                    return Err(WireError::Malformed);
                }
                let count = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
                if count > (body.len() - 4) / 20 {
                    return Err(WireError::Malformed);
                }
                let mut offset = 4;
                let mut lsas = Vec::with_capacity(count);
                for _ in 0..count {
                    let header = LsaHeader::decode(&body[offset..])?;
                    let end = offset + usize::from(header.length);
                    lsas.push(Lsa::decode(
                        body.get(offset..end).ok_or(WireError::Malformed)?,
                    )?);
                    offset = end;
                }
                if offset != body.len() {
                    return Err(WireError::Malformed);
                }
                OspfBody::LinkStateUpdate(lsas)
            }
            5 => OspfBody::LinkStateAck(headers(body)?),
            _ => return Err(WireError::Unsupported),
        };
        Ok(Self {
            router_id: lsa::ip(&bytes[4..8]),
            area: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            body: parsed,
        })
    }
}

#[cfg(test)]
mod tests;
