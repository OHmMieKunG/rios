//! TCP wire format with IPv4 pseudoheader checksums (RFC 9293).
use rios_ipv4::checksum;
use std::net::Ipv4Addr;

/// TCP control flags, combined using bitwise OR.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpFlags(pub u8);
impl TcpFlags {
    pub const FIN: Self = Self(1);
    pub const SYN: Self = Self(2);
    pub const RST: Self = Self(4);
    pub const PSH: Self = Self(8);
    pub const ACK: Self = Self(16);
    /// Whether every bit in `flags` is set.
    pub fn contains(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }
}
impl std::ops::BitOr for TcpFlags {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
/// An owned TCP segment, independent of host OS sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: TcpFlags,
    pub window: u16,
    /// Raw validated-length header options, padded to four bytes.
    pub options: Vec<u8>,
    pub payload: Vec<u8>,
}
/// Invalid TCP wire input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TcpPacketError {
    #[error("TCP segment is truncated")]
    Truncated,
    #[error("invalid TCP header or segment length")]
    InvalidLength,
    #[error("invalid TCP checksum")]
    InvalidChecksum,
    #[error("unsupported TCP reserved bits or urgent pointer")]
    UnsupportedHeader,
}
fn checked_options(options: &[u8]) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => return true,
            1 => offset += 1,
            _ => {
                let Some(length) = options.get(offset + 1).copied() else {
                    return false;
                };
                if length < 2 || offset + usize::from(length) > options.len() {
                    return false;
                }
                offset += usize::from(length);
            }
        }
    }
    true
}
fn pseudoheader(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    bytes: &[u8],
) -> Result<Vec<u8>, TcpPacketError> {
    let length = u16::try_from(bytes.len()).map_err(|_| TcpPacketError::InvalidLength)?;
    let mut data = Vec::with_capacity(12 + bytes.len());
    data.extend_from_slice(&source.octets());
    data.extend_from_slice(&destination.octets());
    data.extend_from_slice(&[0, 6]);
    data.extend_from_slice(&length.to_be_bytes());
    data.extend_from_slice(bytes);
    Ok(data)
}
impl TcpSegment {
    /// Encode a segment with a mandatory checksum including both IPv4 addresses.
    pub fn encode(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<Vec<u8>, TcpPacketError> {
        if self.options.len() > 40
            || !self.options.len().is_multiple_of(4)
            || !checked_options(&self.options)
        {
            return Err(TcpPacketError::InvalidLength);
        }
        let header = 20 + self.options.len();
        let length = header
            .checked_add(self.payload.len())
            .filter(|size| *size <= 65515)
            .ok_or(TcpPacketError::InvalidLength)?;
        let mut bytes = vec![0; length];
        bytes[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.acknowledgment.to_be_bytes());
        bytes[12] = ((header / 4) as u8) << 4;
        bytes[13] = self.flags.0;
        bytes[14..16].copy_from_slice(&self.window.to_be_bytes());
        bytes[20..header].copy_from_slice(&self.options);
        bytes[header..].copy_from_slice(&self.payload);
        let sum = checksum(&pseudoheader(source, destination, &bytes)?);
        bytes[16..18].copy_from_slice(&sum.to_be_bytes());
        Ok(bytes)
    }
    /// Decode bounded header lengths and verify the IPv4 pseudoheader checksum.
    pub fn decode(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        bytes: &[u8],
    ) -> Result<Self, TcpPacketError> {
        if bytes.len() < 20 {
            return Err(TcpPacketError::Truncated);
        }
        let header = usize::from(bytes[12] >> 4) * 4;
        if header < 20
            || header > bytes.len()
            || bytes.len() > 65515
            || !checked_options(&bytes[20..header])
        {
            return Err(TcpPacketError::InvalidLength);
        }
        if bytes[12] & 0x0f != 0 || bytes[18..20] != [0, 0] {
            return Err(TcpPacketError::UnsupportedHeader);
        }
        if checksum(&pseudoheader(source, destination, bytes)?) != 0 {
            return Err(TcpPacketError::InvalidChecksum);
        }
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            sequence: u32::from_be_bytes(
                bytes[4..8]
                    .try_into()
                    .map_err(|_| TcpPacketError::Truncated)?,
            ),
            acknowledgment: u32::from_be_bytes(
                bytes[8..12]
                    .try_into()
                    .map_err(|_| TcpPacketError::Truncated)?,
            ),
            flags: TcpFlags(bytes[13]),
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            options: bytes[20..header].to_vec(),
            payload: bytes[header..].to_vec(),
        })
    }
    /// Sequence space consumed by payload and SYN/FIN flags.
    pub fn sequence_len(&self) -> u32 {
        self.payload.len() as u32
            + u32::from(self.flags.contains(TcpFlags::SYN))
            + u32::from(self.flags.contains(TcpFlags::FIN))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_checksum_options_and_every_truncated_prefix() {
        let source = "192.0.2.1".parse().unwrap();
        let destination = "192.0.2.2".parse().unwrap();
        let segment = TcpSegment {
            source_port: 40000,
            destination_port: 179,
            sequence: u32::MAX,
            acknowledgment: 55,
            flags: TcpFlags::SYN | TcpFlags::ACK,
            window: 65535,
            options: vec![2, 4, 5, 180],
            payload: b"odd".to_vec(),
        };
        let bytes = segment.encode(source, destination).unwrap();
        assert_eq!(
            TcpSegment::decode(source, destination, &bytes).unwrap(),
            segment
        );
        for end in 0..bytes.len() {
            assert!(TcpSegment::decode(source, destination, &bytes[..end]).is_err());
        }
        for index in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[index] ^= 1;
            assert!(TcpSegment::decode(source, destination, &bad).is_err());
        }
        assert!(TcpSegment::decode(destination, source, &bytes).is_ok()); // Address sum is symmetric.
        assert!(TcpSegment::decode(Ipv4Addr::LOCALHOST, destination, &bytes).is_err());
        for length in 0..128 {
            for value in 0..=255 {
                let _ = TcpSegment::decode(source, destination, &vec![value; length]);
            }
        }
    }
}
