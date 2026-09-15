//! OSPFv3 common header and all five standard packet body formats.
use super::*;
use rios_ipv6::ipv6_checksum;

/// Version 3 header with an IPv6 pseudoheader checksum and link-local instance ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfV3Packet {
    pub router_id: Ipv4Addr,
    pub area: u32,
    pub instance: u8,
    pub body: OspfV3Body,
}
impl OspfV3Packet {
    /// Encode actual protocol 89 payload; addresses participate in its checksum.
    pub fn encode(&self, source: Ipv6Addr, destination: Ipv6Addr) -> Result<Vec<u8>, WireError> {
        let mut out = vec![3, 0, 0, 0];
        out.extend(self.router_id.octets());
        out.extend(self.area.to_be_bytes());
        out.extend([0, 0, self.instance, 0]);
        out[1] = match &self.body {
            OspfBody::Hello(h) => {
                if h.options > 0xffffff || h.neighbors.len() > (65535 - 36) / 4 {
                    return Err(WireError::TooLarge);
                }
                out.extend(h.interface_id.to_be_bytes());
                out.extend(((u32::from(h.priority) << 24) | h.options).to_be_bytes());
                out.extend(h.hello_interval.to_be_bytes());
                out.extend(h.dead_interval.to_be_bytes());
                out.extend(h.designated_router.octets());
                out.extend(h.backup_router.octets());
                for id in &h.neighbors {
                    out.extend(id.octets());
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
                if *options > 0xffffff || *flags & !7 != 0 || headers.len() > (65535 - 28) / 20 {
                    return Err(WireError::Malformed);
                }
                out.extend(options.to_be_bytes());
                out.extend(mtu.to_be_bytes());
                out.extend([0, *flags]);
                out.extend(sequence.to_be_bytes());
                for h in headers {
                    out.extend(h.encode());
                }
                2
            }
            OspfBody::LinkStateRequest(keys) => {
                if keys.len() > (65535 - 16) / 12 {
                    return Err(WireError::TooLarge);
                }
                for key in keys {
                    out.extend([0, 0]);
                    out.extend(key.kind.to_be_bytes());
                    out.extend(key.link_state_id.to_be_bytes());
                    out.extend(key.advertising_router.octets());
                }
                3
            }
            OspfBody::LinkStateUpdate(lsas) => {
                if lsas.len() > (65535 - 20) / 20 {
                    return Err(WireError::TooLarge);
                }
                out.extend((lsas.len() as u32).to_be_bytes());
                for lsa in lsas {
                    let bytes = lsa.encode()?;
                    if out.len() + bytes.len() > 65535 {
                        return Err(WireError::TooLarge);
                    }
                    out.extend(bytes);
                }
                4
            }
            OspfBody::LinkStateAck(headers) => {
                if headers.len() > (65535 - 16) / 20 {
                    return Err(WireError::TooLarge);
                }
                for h in headers {
                    out.extend(h.encode());
                }
                5
            }
        };
        let length = u16::try_from(out.len()).map_err(|_| WireError::TooLarge)?;
        out[2..4].copy_from_slice(&length.to_be_bytes());
        let sum = ipv6_checksum(source, destination, rios_ipv6::NextHeader::Ospf, &out);
        out[12..14].copy_from_slice(&sum.to_be_bytes());
        Ok(out)
    }
    /// Decode bounded payload and verify the IPv6 pseudoheader checksum before allocation.
    pub fn decode(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        bytes: &[u8],
    ) -> Result<Self, WireError> {
        if bytes.len() < 16 || bytes[0] != 3 || usize::from(u16_at(bytes, 2)) != bytes.len() {
            return Err(WireError::Malformed);
        }
        if ipv6_checksum(source, destination, rios_ipv6::NextHeader::Ospf, bytes) != 0 {
            return Err(WireError::Checksum);
        }
        let b = &bytes[16..];
        let headers = |data: &[u8]| -> Result<Vec<OspfV3LsaHeader>, WireError> {
            if !data.len().is_multiple_of(20) {
                return Err(WireError::Malformed);
            }
            data.as_chunks::<20>()
                .0
                .iter()
                .map(|b| OspfV3LsaHeader::decode(b))
                .collect()
        };
        let body = match bytes[1] {
            1 => {
                if b.len() < 20 || !(b.len() - 20).is_multiple_of(4) {
                    return Err(WireError::Malformed);
                }
                OspfBody::Hello(OspfV3Hello {
                    interface_id: u32_at(b, 0),
                    priority: b[4],
                    options: u32_at(b, 4) & 0xffffff,
                    hello_interval: u16_at(b, 8),
                    dead_interval: u16_at(b, 10),
                    designated_router: rid(b, 12),
                    backup_router: rid(b, 16),
                    neighbors: b[20..]
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|b| rid(b, 0))
                        .collect(),
                })
            }
            2 => {
                if b.len() < 12 || b[7] & !7 != 0 {
                    return Err(WireError::Malformed);
                }
                OspfBody::DatabaseDescription {
                    options: u32_at(b, 0) & 0xffffff,
                    mtu: u16_at(b, 4),
                    flags: b[7],
                    sequence: u32_at(b, 8),
                    headers: headers(&b[12..])?,
                }
            }
            3 => {
                if !b.len().is_multiple_of(12) {
                    return Err(WireError::Malformed);
                }
                OspfBody::LinkStateRequest(
                    b.as_chunks::<12>()
                        .0
                        .iter()
                        .map(|c| OspfV3LsaKey {
                            kind: u16_at(c, 2),
                            link_state_id: u32_at(c, 4),
                            advertising_router: rid(c, 8),
                        })
                        .collect(),
                )
            }
            4 => {
                if b.len() < 4 || u32_at(b, 0) as usize > (b.len() - 4) / 20 {
                    return Err(WireError::Malformed);
                }
                let mut offset = 4;
                let mut lsas = Vec::new();
                for _ in 0..u32_at(b, 0) {
                    let h = OspfV3LsaHeader::decode(b.get(offset..).ok_or(WireError::Malformed)?)?;
                    let end = offset + usize::from(h.length);
                    lsas.push(OspfV3Lsa::decode(
                        b.get(offset..end).ok_or(WireError::Malformed)?,
                    )?);
                    offset = end;
                }
                if offset != b.len() {
                    return Err(WireError::Malformed);
                }
                OspfBody::LinkStateUpdate(lsas)
            }
            5 => OspfBody::LinkStateAck(headers(b)?),
            _ => return Err(WireError::Unsupported),
        };
        Ok(Self {
            router_id: rid(bytes, 4),
            area: u32_at(bytes, 8),
            instance: bytes[14],
            body,
        })
    }
}
