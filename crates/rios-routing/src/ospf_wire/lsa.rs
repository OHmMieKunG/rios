//! OSPFv2 LSA headers, Type 1/2/3/4/5 bodies, and Fletcher checksums.
use super::WireError;
use std::net::Ipv4Addr;

/// The supported area-local and AS-external LSA types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum LsaType {
    Router = 1,
    Network = 2,
    Summary = 3,
    AsbrSummary = 4,
    External = 5,
}
impl TryFrom<u8> for LsaType {
    type Error = WireError;
    fn try_from(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Router),
            2 => Ok(Self::Network),
            3 => Ok(Self::Summary),
            4 => Ok(Self::AsbrSummary),
            5 => Ok(Self::External),
            _ => Err(WireError::Unsupported),
        }
    }
}
/// Identity of one LSA within its flooding scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LsaKey {
    pub kind: LsaType,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
}
/// The standard 20-byte LSA header, also used in DBD and acknowledgment packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsaHeader {
    pub age: u16,
    pub options: u8,
    pub key: LsaKey,
    pub sequence: i32,
    pub checksum: u16,
    pub length: u16,
}
/// One router-LSA link, including metric and interface/router identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterLink {
    pub id: Ipv4Addr,
    pub data: Ipv4Addr,
    pub kind: RouterLinkType,
    pub metric: u16,
}
/// RFC 2328 router-LSA link types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RouterLinkType {
    PointToPoint = 1,
    Transit = 2,
    Stub = 3,
    Virtual = 4,
}
/// Standard supported link-state advertisement bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LsaBody {
    Router {
        flags: u8,
        links: Vec<RouterLink>,
    },
    Network {
        mask: Ipv4Addr,
        routers: Vec<Ipv4Addr>,
    },
    Summary {
        mask: Ipv4Addr,
        metric: u32,
    },
    AsbrSummary {
        metric: u32,
    },
    External {
        mask: Ipv4Addr,
        metric: u32,
        type_two: bool,
        forwarding_address: Ipv4Addr,
        tag: u32,
    },
}
/// An independently encoded LSA; checksum and length derive from its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lsa {
    pub age: u16,
    pub options: u8,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    pub sequence: i32,
    pub body: LsaBody,
}
pub const LSA_MAX_AGE: u16 = 3600;
pub const LSA_INITIAL_SEQUENCE: i32 = i32::MIN + 1;
pub(super) fn ip(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}
fn valid_mask(mask: Ipv4Addr) -> bool {
    rios_ipv4::Ipv4InterfaceConfig::from_mask(Ipv4Addr::UNSPECIFIED, mask).is_ok()
}
impl LsaHeader {
    pub(super) fn encode(self) -> [u8; 20] {
        let mut out = [0; 20];
        out[..2].copy_from_slice(&self.age.to_be_bytes());
        out[2] = self.options;
        out[3] = self.key.kind as u8;
        out[4..8].copy_from_slice(&self.key.link_state_id.octets());
        out[8..12].copy_from_slice(&self.key.advertising_router.octets());
        out[12..16].copy_from_slice(&self.sequence.to_be_bytes());
        out[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        out[18..20].copy_from_slice(&self.length.to_be_bytes());
        out
    }
    /// Decode and validate a complete fixed LSA header.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let bytes = bytes.get(..20).ok_or(WireError::Malformed)?;
        let header = Self {
            age: u16::from_be_bytes([bytes[0], bytes[1]]),
            options: bytes[2],
            key: LsaKey {
                kind: bytes[3].try_into()?,
                link_state_id: ip(&bytes[4..8]),
                advertising_router: ip(&bytes[8..12]),
            },
            sequence: i32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
            length: u16::from_be_bytes([bytes[18], bytes[19]]),
        };
        if header.age > LSA_MAX_AGE || header.sequence == i32::MIN || header.length < 20 {
            return Err(WireError::Malformed);
        }
        Ok(header)
    }
}
impl Lsa {
    /// Identity derived from body type and advertising router.
    pub fn key(&self) -> LsaKey {
        LsaKey {
            kind: match self.body {
                LsaBody::Router { .. } => LsaType::Router,
                LsaBody::Network { .. } => LsaType::Network,
                LsaBody::Summary { .. } => LsaType::Summary,
                LsaBody::AsbrSummary { .. } => LsaType::AsbrSummary,
                LsaBody::External { .. } => LsaType::External,
            },
            link_state_id: self.link_state_id,
            advertising_router: self.advertising_router,
        }
    }
    /// Encode standard body fields and an age-independent Fletcher checksum.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.age > LSA_MAX_AGE || self.sequence == i32::MIN {
            return Err(WireError::Malformed);
        }
        let mut body = Vec::new();
        match &self.body {
            LsaBody::Router { flags, links } => {
                if links.len() > (65535 - 24) / 12 {
                    return Err(WireError::TooLarge);
                }
                body.extend_from_slice(&[*flags, 0]);
                body.extend_from_slice(&(links.len() as u16).to_be_bytes());
                for link in links {
                    body.extend_from_slice(&link.id.octets());
                    body.extend_from_slice(&link.data.octets());
                    body.extend_from_slice(&[link.kind as u8, 0]);
                    body.extend_from_slice(&link.metric.to_be_bytes());
                }
            }
            LsaBody::Network { mask, routers } => {
                if !valid_mask(*mask) {
                    return Err(WireError::Malformed);
                }
                if routers.len() > (65535 - 24) / 4 {
                    return Err(WireError::TooLarge);
                }
                body.extend_from_slice(&mask.octets());
                for router in routers {
                    body.extend_from_slice(&router.octets());
                }
            }
            LsaBody::AsbrSummary { metric } => {
                if *metric > 0x00ff_ffff {
                    return Err(WireError::Malformed);
                }
                body.extend_from_slice(&[0; 4]);
                body.extend_from_slice(&metric.to_be_bytes());
            }
            LsaBody::Summary { mask, metric } | LsaBody::External { mask, metric, .. } => {
                if !valid_mask(*mask) || *metric > 0x00ff_ffff {
                    return Err(WireError::Malformed);
                }
                body.extend_from_slice(&mask.octets());
                let type_two = matches!(self.body, LsaBody::External { type_two: true, .. });
                body.extend_from_slice(
                    &(metric | if type_two { 0x8000_0000 } else { 0 }).to_be_bytes(),
                );
                if let LsaBody::External {
                    forwarding_address,
                    tag,
                    ..
                } = &self.body
                {
                    body.extend_from_slice(&forwarding_address.octets());
                    body.extend_from_slice(&tag.to_be_bytes());
                }
            }
        }
        let length = u16::try_from(20 + body.len()).map_err(|_| WireError::TooLarge)?;
        let header = LsaHeader {
            age: self.age,
            options: self.options,
            key: self.key(),
            sequence: self.sequence,
            checksum: 0,
            length,
        };
        let mut out = header.encode().to_vec();
        out.extend(body);
        let (c0, c1) = fletcher(&out[2..]);
        let mut x = ((out.len() as i64 - 17) * c0 - c1) % 255;
        if x <= 0 {
            x += 255;
        }
        let mut y = 510 - c0 - x;
        if y > 255 {
            y -= 255;
        }
        out[16] = x as u8;
        out[17] = y as u8;
        Ok(out)
    }
    /// Header suitable for database summaries and explicit acknowledgments.
    pub fn header(&self) -> Result<LsaHeader, WireError> {
        LsaHeader::decode(&self.encode()?)
    }
    /// Decode exactly one LSA and validate both length and Fletcher residues.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let header = LsaHeader::decode(bytes)?;
        if bytes.len() != usize::from(header.length) {
            return Err(WireError::Malformed);
        }
        if fletcher(&bytes[2..]) != (0, 0) {
            return Err(WireError::Checksum);
        }
        let body = &bytes[20..];
        let parsed = match header.key.kind {
            LsaType::Router => {
                if body.len() < 4 {
                    return Err(WireError::Malformed);
                }
                let count = usize::from(u16::from_be_bytes([body[2], body[3]]));
                if body.len() != 4 + count * 12 {
                    return Err(WireError::Malformed);
                }
                let mut links = Vec::with_capacity(count);
                for chunk in body[4..].as_chunks::<12>().0 {
                    if chunk[9] != 0 {
                        return Err(WireError::Unsupported);
                    }
                    let kind = match chunk[8] {
                        1 => RouterLinkType::PointToPoint,
                        2 => RouterLinkType::Transit,
                        3 => RouterLinkType::Stub,
                        4 => RouterLinkType::Virtual,
                        _ => return Err(WireError::Unsupported),
                    };
                    links.push(RouterLink {
                        id: ip(&chunk[..4]),
                        data: ip(&chunk[4..8]),
                        kind,
                        metric: u16::from_be_bytes([chunk[10], chunk[11]]),
                    });
                }
                LsaBody::Router {
                    flags: body[0],
                    links,
                }
            }
            LsaType::Network => {
                if body.len() < 4 || !body.len().is_multiple_of(4) || !valid_mask(ip(&body[..4])) {
                    return Err(WireError::Malformed);
                }
                LsaBody::Network {
                    mask: ip(&body[..4]),
                    routers: body[4..]
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|chunk| ip(chunk))
                        .collect(),
                }
            }
            LsaType::Summary | LsaType::AsbrSummary | LsaType::External => {
                if body.len()
                    != if header.key.kind != LsaType::External {
                        8
                    } else {
                        16
                    }
                    || !valid_mask(ip(&body[..4]))
                {
                    return Err(WireError::Malformed);
                }
                let metric = u32::from_be_bytes([0, body[5], body[6], body[7]]);
                if header.key.kind != LsaType::External {
                    if body[4] != 0 {
                        return Err(WireError::Unsupported);
                    }
                    if header.key.kind == LsaType::AsbrSummary {
                        LsaBody::AsbrSummary { metric }
                    } else {
                        LsaBody::Summary {
                            mask: ip(&body[..4]),
                            metric,
                        }
                    }
                } else {
                    if body[4] & 0x7f != 0 {
                        return Err(WireError::Unsupported);
                    }
                    LsaBody::External {
                        mask: ip(&body[..4]),
                        metric,
                        type_two: body[4] & 0x80 != 0,
                        forwarding_address: ip(&body[8..12]),
                        tag: u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
                    }
                }
            }
        };
        Ok(Self {
            age: header.age,
            options: header.options,
            link_state_id: header.key.link_state_id,
            advertising_router: header.key.advertising_router,
            sequence: header.sequence,
            body: parsed,
        })
    }
}
fn fletcher(bytes: &[u8]) -> (i64, i64) {
    bytes.iter().fold((0, 0), |(c0, c1), byte| {
        let c0 = (c0 + i64::from(*byte)) % 255;
        (c0, (c1 + c0) % 255)
    })
}
