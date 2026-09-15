//! OSPFv3 scoped LSA headers, topology links and independently advertised IPv6 prefixes.
use super::*;
use crate::{LSA_MAX_AGE, lsa_checksum};
use rios_ipv6::Ipv6Network;

pub const V3_ROUTER_LSA: u16 = 0x2001;
pub const V3_NETWORK_LSA: u16 = 0x2002;
pub const V3_LINK_LSA: u16 = 0x0008;
pub const V3_INTRA_AREA_PREFIX_LSA: u16 = 0x2009;
/// LSA identity. Link-state ID is an opaque identifier, never an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OspfV3LsaKey {
    pub kind: u16,
    pub link_state_id: u32,
    pub advertising_router: Ipv4Addr,
}
/// Standard fixed 20-byte header shared by DBD, LSU and acknowledgment packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfV3LsaHeader {
    pub age: u16,
    pub key: OspfV3LsaKey,
    pub sequence: i32,
    pub checksum: u16,
    pub length: u16,
}
/// One IPv6 prefix and its routing options/cost (cost is zero in Link-LSAs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfV3Prefix {
    pub prefix: Ipv6Network,
    pub options: u8,
    pub metric: u16,
}
/// Router-LSA connection identifiers, independent of addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OspfV3RouterLink {
    pub kind: OspfV3LinkType,
    pub metric: u16,
    pub interface_id: u32,
    pub neighbor_interface_id: u32,
    pub neighbor_router: Ipv4Addr,
}
/// Point-to-point, transit network and virtual link descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OspfV3LinkType {
    PointToPoint = 1,
    Transit = 2,
    Virtual = 4,
}
/// Standard intra-area advertisements and opaque unknown bodies for scope-aware flooding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OspfV3LsaBody {
    Router {
        flags: u8,
        options: u32,
        links: Vec<OspfV3RouterLink>,
    },
    Network {
        options: u32,
        routers: Vec<Ipv4Addr>,
    },
    Link {
        priority: u8,
        options: u32,
        link_local: Ipv6Addr,
        prefixes: Vec<OspfV3Prefix>,
    },
    IntraAreaPrefix {
        reference: OspfV3LsaKey,
        prefixes: Vec<OspfV3Prefix>,
    },
    Unknown {
        kind: u16,
        bytes: Vec<u8>,
    },
}
/// An advertisement with a derived length and age-independent Fletcher checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfV3Lsa {
    pub age: u16,
    pub link_state_id: u32,
    pub advertising_router: Ipv4Addr,
    pub sequence: i32,
    pub body: OspfV3LsaBody,
}
impl OspfV3LsaHeader {
    pub(super) fn encode(self) -> [u8; 20] {
        let mut out = [0; 20];
        out[..2].copy_from_slice(&self.age.to_be_bytes());
        out[2..4].copy_from_slice(&self.key.kind.to_be_bytes());
        out[4..8].copy_from_slice(&self.key.link_state_id.to_be_bytes());
        out[8..12].copy_from_slice(&self.key.advertising_router.octets());
        out[12..16].copy_from_slice(&self.sequence.to_be_bytes());
        out[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        out[18..20].copy_from_slice(&self.length.to_be_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let b = bytes.get(..20).ok_or(WireError::Malformed)?;
        let h = Self {
            age: u16_at(b, 0),
            key: OspfV3LsaKey {
                kind: u16_at(b, 2),
                link_state_id: u32_at(b, 4),
                advertising_router: rid(b, 8),
            },
            sequence: u32_at(b, 12) as i32,
            checksum: u16_at(b, 16),
            length: u16_at(b, 18),
        };
        if h.age > LSA_MAX_AGE
            || h.sequence == i32::MIN
            || h.length < 20
            || h.key.kind & 0x6000 == 0x6000
        {
            return Err(WireError::Malformed);
        }
        Ok(h)
    }
}
impl OspfV3Lsa {
    pub fn key(&self) -> OspfV3LsaKey {
        OspfV3LsaKey {
            kind: match self.body {
                OspfV3LsaBody::Router { .. } => V3_ROUTER_LSA,
                OspfV3LsaBody::Network { .. } => V3_NETWORK_LSA,
                OspfV3LsaBody::Link { .. } => V3_LINK_LSA,
                OspfV3LsaBody::IntraAreaPrefix { .. } => V3_INTRA_AREA_PREFIX_LSA,
                OspfV3LsaBody::Unknown { kind, .. } => kind,
            },
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }
    /// Effective flooding scope, honoring the U-bit for unknown function codes.
    pub fn flooding_scope(&self) -> u16 {
        let kind = self.key().kind;
        if matches!(self.body, OspfV3LsaBody::Unknown { .. }) && kind & 0x8000 == 0 {
            0
        } else {
            kind & 0x6000
        }
    }
    pub fn header(&self) -> Result<OspfV3LsaHeader, WireError> {
        OspfV3LsaHeader::decode(&self.encode()?)
    }
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.age > LSA_MAX_AGE || self.sequence == i32::MIN {
            return Err(WireError::Malformed);
        }
        let mut out = OspfV3LsaHeader {
            age: self.age,
            key: self.key(),
            sequence: self.sequence,
            checksum: 0,
            length: 20,
        }
        .encode()
        .to_vec();
        match &self.body {
            OspfV3LsaBody::Router {
                flags,
                options,
                links,
            } => {
                options_word(&mut out, *flags, *options)?;
                if links.len() > (65535 - 24) / 16 {
                    return Err(WireError::TooLarge);
                }
                for l in links {
                    out.extend([l.kind as u8, 0]);
                    out.extend(l.metric.to_be_bytes());
                    out.extend(l.interface_id.to_be_bytes());
                    out.extend(l.neighbor_interface_id.to_be_bytes());
                    out.extend(l.neighbor_router.octets());
                }
            }
            OspfV3LsaBody::Network { options, routers } => {
                options_word(&mut out, 0, *options)?;
                if routers.len() > (65535 - 24) / 4 {
                    return Err(WireError::TooLarge);
                }
                for id in routers {
                    out.extend(id.octets());
                }
            }
            OspfV3LsaBody::Link {
                priority,
                options,
                link_local,
                prefixes,
            } => {
                if !link_local.is_unicast_link_local() {
                    return Err(WireError::Malformed);
                }
                options_word(&mut out, *priority, *options)?;
                out.extend(link_local.octets());
                out.extend(
                    u32::try_from(prefixes.len())
                        .map_err(|_| WireError::TooLarge)?
                        .to_be_bytes(),
                );
                encode_prefixes(&mut out, prefixes, false)?;
            }
            OspfV3LsaBody::IntraAreaPrefix {
                reference,
                prefixes,
            } => {
                if !matches!(reference.kind, V3_ROUTER_LSA | V3_NETWORK_LSA) {
                    return Err(WireError::Malformed);
                }
                out.extend(
                    u16::try_from(prefixes.len())
                        .map_err(|_| WireError::TooLarge)?
                        .to_be_bytes(),
                );
                out.extend(reference.kind.to_be_bytes());
                out.extend(reference.link_state_id.to_be_bytes());
                out.extend(reference.advertising_router.octets());
                encode_prefixes(&mut out, prefixes, true)?;
            }
            OspfV3LsaBody::Unknown { kind, bytes } => {
                if matches!(
                    *kind,
                    V3_ROUTER_LSA | V3_NETWORK_LSA | V3_LINK_LSA | V3_INTRA_AREA_PREFIX_LSA
                ) || kind & 0x6000 == 0x6000
                {
                    return Err(WireError::Malformed);
                }
                if bytes.len() > 65535 - 20 {
                    return Err(WireError::TooLarge);
                }
                out.extend(bytes);
            }
        }
        let length = u16::try_from(out.len()).map_err(|_| WireError::TooLarge)?;
        out[18..20].copy_from_slice(&length.to_be_bytes());
        lsa_checksum::insert(&mut out);
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let h = OspfV3LsaHeader::decode(bytes)?;
        if usize::from(h.length) != bytes.len() {
            return Err(WireError::Malformed);
        }
        if lsa_checksum::fletcher(&bytes[2..]) != (0, 0) {
            return Err(WireError::Checksum);
        }
        let b = &bytes[20..];
        let body = match h.key.kind {
            V3_ROUTER_LSA => {
                if b.len() < 4 || !(b.len() - 4).is_multiple_of(16) {
                    return Err(WireError::Malformed);
                }
                let mut links = Vec::new();
                for l in b[4..].as_chunks::<16>().0.iter() {
                    let kind = match l[0] {
                        1 => OspfV3LinkType::PointToPoint,
                        2 => OspfV3LinkType::Transit,
                        4 => OspfV3LinkType::Virtual,
                        _ => return Err(WireError::Unsupported),
                    };
                    links.push(OspfV3RouterLink {
                        kind,
                        metric: u16_at(l, 2),
                        interface_id: u32_at(l, 4),
                        neighbor_interface_id: u32_at(l, 8),
                        neighbor_router: rid(l, 12),
                    });
                }
                OspfV3LsaBody::Router {
                    flags: b[0],
                    options: u32_at(b, 0) & 0xffffff,
                    links,
                }
            }
            V3_NETWORK_LSA => {
                if b.len() < 4 || !b.len().is_multiple_of(4) {
                    return Err(WireError::Malformed);
                }
                OspfV3LsaBody::Network {
                    options: u32_at(b, 0) & 0xffffff,
                    routers: b[4..]
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| rid(c, 0))
                        .collect(),
                }
            }
            V3_LINK_LSA => {
                if b.len() < 24 {
                    return Err(WireError::Malformed);
                }
                let mut address = [0; 16];
                address.copy_from_slice(&b[4..20]);
                let link_local = Ipv6Addr::from(address);
                if !link_local.is_unicast_link_local() {
                    return Err(WireError::Malformed);
                }
                OspfV3LsaBody::Link {
                    priority: b[0],
                    options: u32_at(b, 0) & 0xffffff,
                    link_local,
                    prefixes: decode_prefixes(&b[24..], u32_at(b, 20) as usize, false)?,
                }
            }
            V3_INTRA_AREA_PREFIX_LSA => {
                if b.len() < 12 {
                    return Err(WireError::Malformed);
                }
                let reference = OspfV3LsaKey {
                    kind: u16_at(b, 2),
                    link_state_id: u32_at(b, 4),
                    advertising_router: rid(b, 8),
                };
                if !matches!(reference.kind, V3_ROUTER_LSA | V3_NETWORK_LSA) {
                    return Err(WireError::Malformed);
                }
                OspfV3LsaBody::IntraAreaPrefix {
                    reference,
                    prefixes: decode_prefixes(&b[12..], usize::from(u16_at(b, 0)), true)?,
                }
            }
            kind => OspfV3LsaBody::Unknown {
                kind,
                bytes: b.to_vec(),
            },
        };
        Ok(Self {
            age: h.age,
            link_state_id: h.key.link_state_id,
            advertising_router: h.key.advertising_router,
            sequence: h.sequence,
            body,
        })
    }
}
fn options_word(out: &mut Vec<u8>, flags: u8, options: u32) -> Result<(), WireError> {
    if options > 0xffffff {
        return Err(WireError::Malformed);
    }
    out.extend(((u32::from(flags) << 24) | options).to_be_bytes());
    Ok(())
}
fn encode_prefixes(
    out: &mut Vec<u8>,
    prefixes: &[OspfV3Prefix],
    metric: bool,
) -> Result<(), WireError> {
    for p in prefixes {
        if !metric && p.metric != 0 {
            return Err(WireError::Malformed);
        }
        let len = usize::from(p.prefix.prefix_len()).div_ceil(32) * 4;
        if out.len() + 4 + len > 65535 {
            return Err(WireError::TooLarge);
        }
        out.extend([p.prefix.prefix_len(), p.options]);
        out.extend(p.metric.to_be_bytes());
        out.extend(&p.prefix.address().octets()[..len]);
    }
    Ok(())
}
fn decode_prefixes(
    bytes: &[u8],
    count: usize,
    metric: bool,
) -> Result<Vec<OspfV3Prefix>, WireError> {
    if count > bytes.len() / 4 {
        return Err(WireError::Malformed);
    }
    let mut rest = bytes;
    let mut prefixes = Vec::with_capacity(count);
    for _ in 0..count {
        if rest.len() < 4 || rest[0] > 128 {
            return Err(WireError::Malformed);
        }
        let len = usize::from(rest[0]).div_ceil(32) * 4;
        let address = rest.get(4..4 + len).ok_or(WireError::Malformed)?;
        let mut octets = [0; 16];
        octets[..len].copy_from_slice(address);
        prefixes.push(OspfV3Prefix {
            prefix: Ipv6Network::new(Ipv6Addr::from(octets), rest[0])
                .map_err(|_| WireError::Malformed)?,
            options: rest[1],
            metric: if metric { u16_at(rest, 2) } else { 0 },
        });
        rest = &rest[4 + len..];
    }
    if !rest.is_empty() {
        return Err(WireError::Malformed);
    }
    Ok(prefixes)
}
