//! Typed BGP path attributes, AS path loop inspection and bounded attribute codecs.
use super::*;
use std::collections::BTreeSet;
/// Origin ranking used after local preference and AS path length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BgpOrigin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}
/// AS_SEQUENCE and legacy AS_SET retain distinct wire semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsPathSegment {
    Sequence(Vec<u32>),
    Set(Vec<u32>),
}
impl AsPathSegment {
    pub fn members(&self) -> &[u32] {
        match self {
            Self::Sequence(v) | Self::Set(v) => v,
        }
    }
}
/// An unrecognized optional transitive attribute that must survive propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpUnknownAttribute {
    pub flags: u8,
    pub code: u8,
    pub value: Vec<u8>,
}
/// Attributes shared by all announced IPv4 prefixes in one UPDATE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpAttributes {
    pub origin: BgpOrigin,
    pub as_path: Vec<AsPathSegment>,
    pub next_hop: Ipv4Addr,
    pub atomic_aggregate: bool,
    pub med: Option<u32>,
    pub local_preference: Option<u32>,
    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list: Vec<Ipv4Addr>,
    pub unknown_transitive: Vec<BgpUnknownAttribute>,
}
impl BgpAttributes {
    pub fn contains_as(&self, asn: u32) -> bool {
        self.as_path.iter().any(|s| s.members().contains(&asn))
    }
    pub fn path_length(&self) -> usize {
        self.as_path
            .iter()
            .map(|s| match s {
                AsPathSegment::Sequence(v) => v.len(),
                AsPathSegment::Set(_) => 1,
            })
            .sum()
    }
    pub fn first_as(&self) -> Option<u32> {
        self.as_path
            .first()
            .and_then(|s| s.members().first().copied())
    }
    /// Add sequence members without producing an oversized one-byte segment count.
    pub fn prepend(&mut self, asns: &[u32]) -> Result<(), BgpError> {
        if asns.contains(&0)
            || asns.len()
                + self
                    .as_path
                    .iter()
                    .map(|s| s.members().len())
                    .sum::<usize>()
                > 1024
        {
            return Err(BgpError::new(6, 8));
        }
        let mut values = asns.to_vec();
        if matches!(self.as_path.first(), Some(AsPathSegment::Sequence(_)))
            && let AsPathSegment::Sequence(old) = self.as_path.remove(0)
        {
            values.extend(old);
        }
        for chunk in values.chunks(255).rev() {
            self.as_path
                .insert(0, AsPathSegment::Sequence(chunk.to_vec()));
        }
        Ok(())
    }
    pub(super) fn encode(&self, four: bool) -> Result<Vec<u8>, BgpError> {
        let mut out = Vec::new();
        attribute(&mut out, 0x40, 1, &[self.origin as u8])?;
        let mut path = Vec::new();
        for segment in &self.as_path {
            let values = segment.members();
            if values.is_empty() || values.len() > 255 {
                return Err(BgpError::new(3, 11));
            }
            if path.len() + 2 + values.len() * if four { 4 } else { 2 } > BGP_MAX_MESSAGE {
                return Err(BgpError::new(1, 2));
            }
            path.extend([
                if matches!(segment, AsPathSegment::Sequence(_)) {
                    2
                } else {
                    1
                },
                values.len() as u8,
            ]);
            for asn in values {
                if *asn == 0 {
                    return Err(BgpError::new(3, 11));
                }
                if four {
                    path.extend(asn.to_be_bytes());
                } else {
                    path.extend(
                        u16::try_from(*asn)
                            .map_err(|_| BgpError::new(3, 11))?
                            .to_be_bytes(),
                    );
                }
            }
        }
        attribute(&mut out, 0x40, 2, &path)?;
        attribute(&mut out, 0x40, 3, &self.next_hop.octets())?;
        if self.atomic_aggregate {
            attribute(&mut out, 0x40, 6, &[])?;
        }
        if let Some(med) = self.med {
            attribute(&mut out, 0x80, 4, &med.to_be_bytes())?;
        }
        if let Some(pref) = self.local_preference {
            attribute(&mut out, 0x40, 5, &pref.to_be_bytes())?;
        }
        if let Some(id) = self.originator_id {
            attribute(&mut out, 0x80, 9, &id.octets())?;
        }
        if !self.cluster_list.is_empty() {
            if self.cluster_list.len() > BGP_MAX_MESSAGE / 4 {
                return Err(BgpError::new(1, 2));
            }
            let bytes: Vec<_> = self
                .cluster_list
                .iter()
                .flat_map(|ip| ip.octets())
                .collect();
            attribute(&mut out, 0x80, 10, &bytes)?;
        }
        let mut seen = BTreeSet::from([1, 2, 3, 4, 5, 6, 9, 10]);
        for unknown in &self.unknown_transitive {
            if !seen.insert(unknown.code) || unknown.flags & 0xc0 != 0xc0 {
                return Err(BgpError::new(3, 4));
            }
            attribute(&mut out, unknown.flags, unknown.code, &unknown.value)?;
        }
        Ok(out)
    }
    pub(super) fn decode(mut bytes: &[u8], four: bool) -> Result<Self, BgpError> {
        let mut origin = None;
        let mut as_path = None;
        let mut next_hop = None;
        let mut atomic_aggregate = false;
        let mut med = None;
        let mut local_preference = None;
        let mut originator_id = None;
        let mut cluster_list = Vec::new();
        let mut unknown_transitive = Vec::new();
        let mut seen = BTreeSet::new();
        while !bytes.is_empty() {
            if bytes.len() < 3 {
                return Err(BgpError::new(3, 1));
            }
            let flags = bytes[0];
            let code = bytes[1];
            let (header, length) = if flags & 0x10 != 0 {
                if bytes.len() < 4 {
                    return Err(BgpError::new(3, 1));
                }
                (4, usize::from(u16_at(bytes, 2)))
            } else {
                (3, usize::from(bytes[2]))
            };
            let value = bytes
                .get(header..header + length)
                .ok_or(BgpError::new(3, 5))?;
            if !seen.insert(code) {
                return Err(BgpError::new(3, 1));
            }
            let expected = match code {
                1 | 2 | 3 | 5 | 6 => Some(0x40),
                4 | 9 | 10 => Some(0x80),
                7 | 17 | 18 => Some(0xc0),
                _ => None,
            };
            if expected.is_some_and(|e| flags & 0xc0 != e)
                || (flags & 0x20 != 0 && flags & 0xc0 != 0xc0)
            {
                return Err(BgpError::new(3, 4));
            }
            match code {
                1 => {
                    if length != 1 {
                        return Err(BgpError::new(3, 5));
                    }
                    origin = Some(match value[0] {
                        0 => BgpOrigin::Igp,
                        1 => BgpOrigin::Egp,
                        2 => BgpOrigin::Incomplete,
                        _ => return Err(BgpError::new(3, 6)),
                    });
                }
                2 => {
                    as_path = Some(decode_path(value, four)?);
                }
                3 => {
                    if length != 4 {
                        return Err(BgpError::new(3, 5));
                    }
                    let address = ip(value);
                    if address.is_unspecified() || address.is_multicast() || address.is_broadcast()
                    {
                        return Err(BgpError::new(3, 8));
                    }
                    next_hop = Some(address);
                }
                4 | 5 => {
                    if length != 4 {
                        return Err(BgpError::new(3, 5));
                    }
                    if code == 4 {
                        med = Some(u32_at(value, 0));
                    } else {
                        local_preference = Some(u32_at(value, 0));
                    }
                }
                9 => {
                    if length != 4 {
                        return Err(BgpError::new(3, 5));
                    }
                    originator_id = Some(ip(value));
                }
                10 => {
                    if !length.is_multiple_of(4) {
                        return Err(BgpError::new(3, 5));
                    }
                    cluster_list = value.as_chunks::<4>().0.iter().map(|v| ip(v)).collect();
                }
                6 => {
                    if length != 0 {
                        return Err(BgpError::new(3, 5));
                    }
                    atomic_aggregate = true;
                }
                // Four-octet peers discard legacy transition attributes, RFC 6793 section 4.1.
                17 | 18 if four => {}
                _ => {
                    if flags & 0x80 == 0 {
                        return Err(BgpError::new(3, 2));
                    }
                    if flags & 0xc0 == 0xc0 {
                        unknown_transitive.push(BgpUnknownAttribute {
                            flags: flags & 0xe0,
                            code,
                            value: value.to_vec(),
                        });
                    }
                }
            }
            bytes = &bytes[header + length..];
        }
        Ok(Self {
            origin: origin.ok_or(BgpError::new(3, 3))?,
            as_path: as_path.ok_or(BgpError::new(3, 3))?,
            next_hop: next_hop.ok_or(BgpError::new(3, 3))?,
            atomic_aggregate,
            med,
            local_preference,
            originator_id,
            cluster_list,
            unknown_transitive,
        })
    }
}
fn attribute(out: &mut Vec<u8>, flags: u8, code: u8, value: &[u8]) -> Result<(), BgpError> {
    let extended = value.len() > 255;
    if out.len() + value.len() + if extended { 4 } else { 3 } > BGP_MAX_MESSAGE {
        return Err(BgpError::new(1, 2));
    }
    out.extend([(flags & 0xe0) | if extended { 0x10 } else { 0 }, code]);
    if extended {
        out.extend((value.len() as u16).to_be_bytes());
    } else {
        out.push(value.len() as u8);
    }
    out.extend(value);
    Ok(())
}
fn decode_path(mut bytes: &[u8], four: bool) -> Result<Vec<AsPathSegment>, BgpError> {
    let mut segments = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 || bytes[1] == 0 || !matches!(bytes[0], 1 | 2) {
            return Err(BgpError::new(3, 11));
        }
        let length = usize::from(bytes[1]) * if four { 4 } else { 2 };
        let value = bytes.get(2..2 + length).ok_or(BgpError::new(3, 11))?;
        let members: Vec<_> = if four {
            value
                .as_chunks::<4>()
                .0
                .iter()
                .map(|v| u32_at(v, 0))
                .collect()
        } else {
            value
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u32::from(u16_at(v, 0)))
                .collect()
        };
        if members.contains(&0) {
            return Err(BgpError::new(3, 11));
        }
        segments.push(if bytes[0] == 1 {
            AsPathSegment::Set(members)
        } else {
            AsPathSegment::Sequence(members)
        });
        bytes = &bytes[2 + length..];
    }
    Ok(segments)
}
