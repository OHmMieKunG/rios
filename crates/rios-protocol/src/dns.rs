//! Bounded DNS question/A-record codec with safe RFC 1035 name compression decoding.
use std::net::Ipv4Addr;
/// Invalid or unsupported DNS wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or unsupported DNS message")]
pub struct DnsError;
/// A single DNS question; unknown record types remain representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub kind: u16,
    pub class: u16,
}
/// One IN A answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsARecord {
    pub name: String,
    pub ttl: u32,
    pub address: Ipv4Addr,
}
/// A single-question DNS message; only IN A answer records are retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,
    pub authoritative: bool,
    pub recursion_desired: bool,
    pub rcode: u8,
    pub question: DnsQuestion,
    pub answers: Vec<DnsARecord>,
}
/// Validate and canonicalize the hostname subset used by simulated DNS inventory.
pub fn dns_name(name: &str) -> Result<String, DnsError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty()
        || name.len() > 253
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(DnsError);
    }
    Ok(name.to_ascii_lowercase())
}
fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
    for label in dns_name(name)?.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}
fn name(bytes: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut at = *offset;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut length = 0;
    for _ in 0..128 {
        let size = *bytes.get(at).ok_or(DnsError)?;
        if size & 0xc0 == 0xc0 {
            let target =
                (usize::from(size & 0x3f) << 8) | usize::from(*bytes.get(at + 1).ok_or(DnsError)?);
            if target < 12 || target >= at {
                return Err(DnsError);
            }
            if !jumped {
                *offset = at + 2;
                jumped = true;
            }
            at = target;
            continue;
        }
        if size > 63 {
            return Err(DnsError);
        }
        at += 1;
        if size == 0 {
            if !jumped {
                *offset = at;
            }
            return dns_name(&labels.join("."));
        }
        let label = bytes.get(at..at + usize::from(size)).ok_or(DnsError)?;
        length += label.len() + 1;
        if length > 254 {
            return Err(DnsError);
        }
        labels.push(std::str::from_utf8(label).map_err(|_| DnsError)?.to_owned());
        at += label.len();
    }
    Err(DnsError)
}
fn word(bytes: &[u8], offset: &mut usize) -> Result<u16, DnsError> {
    let b = bytes.get(*offset..*offset + 2).ok_or(DnsError)?;
    *offset += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
impl DnsMessage {
    /// Construct an ordinary recursive A query.
    pub fn query(id: u16, name: &str) -> Result<Self, DnsError> {
        Ok(Self {
            id,
            response: false,
            authoritative: false,
            recursion_desired: true,
            rcode: 0,
            question: DnsQuestion {
                name: dns_name(name)?,
                kind: 1,
                class: 1,
            },
            answers: Vec::new(),
        })
    }
    /// Encode bounded classic UDP DNS (512 bytes), without compression or EDNS.
    pub fn encode(&self) -> Result<Vec<u8>, DnsError> {
        if self.rcode > 15 || self.answers.len() > 32 {
            return Err(DnsError);
        }
        let flags = (u16::from(self.response) << 15)
            | (u16::from(self.authoritative) << 10)
            | (u16::from(self.recursion_desired) << 8)
            | u16::from(self.rcode);
        let mut out = Vec::new();
        for value in [self.id, flags, 1, self.answers.len() as u16, 0, 0] {
            out.extend_from_slice(&value.to_be_bytes());
        }
        encode_name(&self.question.name, &mut out)?;
        out.extend_from_slice(&self.question.kind.to_be_bytes());
        out.extend_from_slice(&self.question.class.to_be_bytes());
        for answer in &self.answers {
            if dns_name(&answer.name)? == dns_name(&self.question.name)? {
                out.extend_from_slice(&[0xc0, 0x0c]);
            } else {
                encode_name(&answer.name, &mut out)?;
            }
            out.extend_from_slice(&[0, 1, 0, 1]);
            out.extend_from_slice(&answer.ttl.to_be_bytes());
            out.extend_from_slice(&[0, 4]);
            out.extend_from_slice(&answer.address.octets());
        }
        if out.len() > 512 {
            return Err(DnsError);
        }
        Ok(out)
    }
    /// Decode a bounded classic message; pointer cycles, truncation and excess records fail.
    pub fn decode(bytes: &[u8]) -> Result<Self, DnsError> {
        if bytes.len() > 512 {
            return Err(DnsError);
        }
        let mut at = 0;
        let id = word(bytes, &mut at)?;
        let flags = word(bytes, &mut at)?;
        if flags & 0x7a40 != 0 || word(bytes, &mut at)? != 1 {
            return Err(DnsError);
        }
        let count = word(bytes, &mut at)?;
        if count > 32 || word(bytes, &mut at)? != 0 || word(bytes, &mut at)? != 0 {
            return Err(DnsError);
        }
        let question = DnsQuestion {
            name: name(bytes, &mut at)?,
            kind: word(bytes, &mut at)?,
            class: word(bytes, &mut at)?,
        };
        let mut answers = Vec::new();
        for _ in 0..count {
            let name = name(bytes, &mut at)?;
            let kind = word(bytes, &mut at)?;
            let class = word(bytes, &mut at)?;
            let ttl = (u32::from(word(bytes, &mut at)?) << 16) | u32::from(word(bytes, &mut at)?);
            let length = usize::from(word(bytes, &mut at)?);
            let data = bytes.get(at..at + length).ok_or(DnsError)?;
            at += length;
            if kind == 1 && class == 1 {
                if data.len() != 4 {
                    return Err(DnsError);
                }
                answers.push(DnsARecord {
                    name,
                    ttl,
                    address: Ipv4Addr::new(data[0], data[1], data[2], data[3]),
                });
            }
        }
        if at != bytes.len() {
            return Err(DnsError);
        }
        Ok(Self {
            id,
            response: flags & 0x8000 != 0,
            authoritative: flags & 0x0400 != 0,
            recursion_desired: flags & 0x0100 != 0,
            rcode: (flags & 15) as u8,
            question,
            answers,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compressed_answers_roundtrip_and_bad_pointers_are_bounded() {
        let mut message = DnsMessage::query(42, "WWW.Lab.").unwrap();
        message.response = true;
        message.authoritative = true;
        message.answers.push(DnsARecord {
            name: "www.lab".into(),
            ttl: 300,
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        let bytes = message.encode().unwrap();
        assert_eq!(DnsMessage::decode(&bytes).unwrap(), message);
        for length in 0..bytes.len() {
            assert!(DnsMessage::decode(&bytes[..length]).is_err());
        }
        let mut cycle = DnsMessage::query(1, "a").unwrap().encode().unwrap();
        cycle[12..14].copy_from_slice(&[0xc0, 12]);
        assert!(DnsMessage::decode(&cycle).is_err());
        for length in 0..600 {
            let _ = DnsMessage::decode(&vec![0xff; length]);
        }
        assert!(dns_name("a..b").is_err());
    }
}
