//! RFC 8200 fixed headers and bounded, checked extension-header traversal.
use std::net::Ipv6Addr;
/// IPv6 next-header identifiers, including the extensions this decoder recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHeader {
    HopByHop,
    Tcp,
    Udp,
    Routing,
    Fragment,
    Esp,
    Authentication,
    Icmpv6,
    NoNextHeader,
    DestinationOptions,
    Ospf,
    Other(u8),
}
impl From<u8> for NextHeader {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::HopByHop,
            6 => Self::Tcp,
            17 => Self::Udp,
            43 => Self::Routing,
            44 => Self::Fragment,
            50 => Self::Esp,
            51 => Self::Authentication,
            58 => Self::Icmpv6,
            59 => Self::NoNextHeader,
            60 => Self::DestinationOptions,
            89 => Self::Ospf,
            other => Self::Other(other),
        }
    }
}
impl From<NextHeader> for u8 {
    fn from(value: NextHeader) -> u8 {
        match value {
            NextHeader::HopByHop => 0,
            NextHeader::Tcp => 6,
            NextHeader::Udp => 17,
            NextHeader::Routing => 43,
            NextHeader::Fragment => 44,
            NextHeader::Esp => 50,
            NextHeader::Authentication => 51,
            NextHeader::Icmpv6 => 58,
            NextHeader::NoNextHeader => 59,
            NextHeader::DestinationOptions => 60,
            NextHeader::Ospf => 89,
            NextHeader::Other(other) => other,
        }
    }
}
/// Packet validation failures never require indexing untrusted data unchecked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("IPv6 packet is truncated or malformed")]
    Malformed,
    #[error("IPv6 payload exceeds 65535 bytes or flow label exceeds 20 bits")]
    TooLarge,
    #[error("too many IPv6 extension headers")]
    ExtensionLimit,
    #[error("IPv6 fragment reassembly is not supported")]
    Fragmented,
    #[error("IPv6 authentication or encryption is unsupported")]
    SecurityHeader,
    #[error("invalid IPv6 extension at byte {pointer}")]
    ParameterProblem {
        pointer: u32,
        code: u8,
        send_icmp: bool,
    },
}
/// Original IPv6 packet, including extension bytes when next_header names an extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Packet {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub hop_limit: u8,
    pub next_header: NextHeader,
    pub payload: Vec<u8>,
}
/// Borrowed upper-layer payload following validated extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpperLayer<'a> {
    pub protocol: NextHeader,
    pub payload: &'a [u8],
    pub next_header_offset: u32,
    pub had_fragment_header: bool,
}
impl Ipv6Packet {
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        if self.flow_label > 0x000f_ffff || self.payload.len() > 65535 {
            return Err(PacketError::TooLarge);
        }
        let first = 0x6000_0000 | (u32::from(self.traffic_class) << 20) | self.flow_label;
        let mut out = Vec::with_capacity(40 + self.payload.len());
        out.extend_from_slice(&first.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&[self.next_header.into(), self.hop_limit]);
        out.extend_from_slice(&self.source.octets());
        out.extend_from_slice(&self.destination.octets());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        let header = bytes.get(..40).ok_or(PacketError::Malformed)?;
        if header[0] >> 4 != 6 {
            return Err(PacketError::Malformed);
        }
        let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let payload = bytes
            .get(40..40 + length)
            .ok_or(PacketError::Malformed)?
            .to_vec();
        let mut source = [0; 16];
        source.copy_from_slice(&header[8..24]);
        let mut destination = [0; 16];
        destination.copy_from_slice(&header[24..40]);
        Ok(Self {
            source: source.into(),
            destination: destination.into(),
            traffic_class: ((header[0] & 15) << 4) | (header[1] >> 4),
            flow_label: u32::from_be_bytes([0, header[1] & 15, header[2], header[3]]),
            hop_limit: header[7],
            next_header: header[6].into(),
            payload,
        })
    }
    /// Reject unsafe/unsupported extensions rather than treating their bytes as transport data.
    pub fn upper_layer(&self) -> Result<UpperLayer<'_>, PacketError> {
        let mut offset = 0usize;
        let mut next = self.next_header;
        let mut next_offset = 6;
        let mut had_fragment_header = false;
        for _ in 0..16 {
            match next {
                NextHeader::HopByHop | NextHeader::DestinationOptions | NextHeader::Routing => {
                    if next == NextHeader::HopByHop && offset != 0 {
                        return Err(PacketError::ParameterProblem {
                            pointer: next_offset,
                            code: 1,
                            send_icmp: true,
                        });
                    }
                    let start = self
                        .payload
                        .get(offset..offset + 2)
                        .ok_or(PacketError::Malformed)?;
                    let length = (usize::from(start[1]) + 1) * 8;
                    let body = self
                        .payload
                        .get(offset..offset + length)
                        .ok_or(PacketError::Malformed)?;
                    if next == NextHeader::Routing {
                        if body[3] != 0 {
                            return Err(PacketError::ParameterProblem {
                                pointer: (40 + offset + 2) as u32,
                                code: 0,
                                send_icmp: true,
                            });
                        }
                    } else {
                        validate_options(body, 40 + offset, self.destination.is_multicast())?;
                    }
                    next = body[0].into();
                    next_offset = (40 + offset) as u32;
                    offset += length;
                }
                NextHeader::Fragment => {
                    if had_fragment_header {
                        return Err(PacketError::Malformed);
                    }
                    had_fragment_header = true;
                    let body = self
                        .payload
                        .get(offset..offset + 8)
                        .ok_or(PacketError::Malformed)?;
                    if u16::from_be_bytes([body[2], body[3]]) & 0xfff9 != 0 {
                        return Err(PacketError::Fragmented);
                    }
                    if body[1] != 0 || body[3] & 6 != 0 {
                        return Err(PacketError::Malformed);
                    }
                    next = body[0].into();
                    next_offset = (40 + offset) as u32;
                    offset += 8;
                }
                NextHeader::Authentication | NextHeader::Esp => {
                    return Err(PacketError::SecurityHeader);
                }
                NextHeader::NoNextHeader => {
                    return Ok(UpperLayer {
                        protocol: next,
                        payload: &[],
                        next_header_offset: next_offset,
                        had_fragment_header,
                    });
                }
                _ => {
                    return Ok(UpperLayer {
                        protocol: next,
                        payload: &self.payload[offset..],
                        next_header_offset: next_offset,
                        had_fragment_header,
                    });
                }
            }
        }
        Err(PacketError::ExtensionLimit)
    }
}
fn validate_options(body: &[u8], base: usize, multicast: bool) -> Result<(), PacketError> {
    let mut pos = 2;
    while pos < body.len() {
        let kind = body[pos];
        if kind == 0 {
            pos += 1;
            continue;
        }
        let length = usize::from(*body.get(pos + 1).ok_or(PacketError::Malformed)?);
        let data = body
            .get(pos + 2..pos + 2 + length)
            .ok_or(PacketError::Malformed)?;
        match kind {
            1 => {}                    // PadN contents carry no semantics.
            5 if data.len() == 2 => {} // Router Alert is safely recognized; no RSVP/MLD consumers yet.
            5 => return Err(PacketError::Malformed),
            _ if kind >> 6 == 0 => {}
            _ => {
                return Err(PacketError::ParameterProblem {
                    pointer: (base + pos) as u32,
                    code: 2,
                    send_icmp: kind >> 6 == 2 || (kind >> 6 == 3 && !multicast),
                });
            }
        }
        pos += 2 + length;
    }
    Ok(())
}
/// Internet checksum including the IPv6 pseudoheader, without allocating a second packet buffer.
pub fn ipv6_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    protocol: NextHeader,
    payload: &[u8],
) -> u16 {
    let sum = |bytes: &[u8]| -> u64 {
        let (chunks, remainder) = bytes.as_chunks::<2>();
        let sum: u64 = chunks
            .iter()
            .map(|c| u64::from(u16::from_be_bytes([c[0], c[1]])))
            .sum();
        sum + remainder.first().map_or(0, |b| u64::from(*b) << 8)
    };
    let length = payload.len() as u64;
    let mut total = sum(&source.octets())
        + sum(&destination.octets())
        + (length >> 16)
        + (length & 0xffff)
        + u64::from(u8::from(protocol))
        + sum(payload);
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}
