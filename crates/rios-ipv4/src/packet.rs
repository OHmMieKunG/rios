use std::net::Ipv4Addr;

/// Protocol number carried by an IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Ospf,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            89 => Self::Ospf,
            value => Self::Other(value),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        match value {
            IpProtocol::Icmp => 1,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Ospf => 89,
            IpProtocol::Other(value) => value,
        }
    }
}

/// Minimal IPv4 packet used by the simulator. Options and fragmentation are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    /// Sender address.
    pub source: Ipv4Addr,
    /// Final destination address.
    pub destination: Ipv4Addr,
    /// Remaining hop limit.
    pub ttl: u8,
    /// Upper-layer protocol number.
    pub protocol: IpProtocol,
    /// Upper-layer message bytes.
    pub payload: Vec<u8>,
}

/// Invalid or unsupported IPv4 wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("IPv4 packet is truncated")]
    Truncated,
    #[error("unsupported IPv4 header")]
    UnsupportedHeader,
    #[error("invalid IPv4 total length")]
    InvalidLength,
    #[error("invalid IPv4 header checksum")]
    InvalidChecksum,
    #[error("IPv4 packet TTL is zero")]
    Expired,
}

impl Ipv4Packet {
    /// Encode a checksum-valid 20-byte IPv4 header followed by the payload.
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        if self.ttl == 0 {
            return Err(PacketError::Expired);
        }
        let total = 20usize
            .checked_add(self.payload.len())
            .filter(|length| *length <= u16::MAX.into())
            .ok_or(PacketError::InvalidLength)?;
        let mut bytes = vec![0; total];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        bytes[8] = self.ttl;
        bytes[9] = self.protocol.into();
        bytes[12..16].copy_from_slice(&self.source.octets());
        bytes[16..20].copy_from_slice(&self.destination.octets());
        let checksum = checksum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
        bytes[20..].copy_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decode IPv4 without accepting options or fragments in this phase.
    pub fn decode(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() < 20 {
            return Err(PacketError::Truncated);
        }
        if bytes[0] != 0x45 || bytes[6] & 0x3f != 0 || bytes[7] != 0 {
            return Err(PacketError::UnsupportedHeader);
        }
        let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total < 20 || total > bytes.len() {
            return Err(PacketError::InvalidLength);
        }
        if checksum(&bytes[..20]) != 0 {
            return Err(PacketError::InvalidChecksum);
        }
        if bytes[8] == 0 {
            return Err(PacketError::Expired);
        }
        Ok(Self {
            source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            ttl: bytes[8],
            protocol: bytes[9].into(),
            payload: bytes[20..total].to_vec(),
        })
    }
}

/// Compute the standard one's-complement Internet checksum.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip_and_checksum_validation() {
        let packet = Ipv4Packet {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ttl: 64,
            protocol: IpProtocol::Icmp,
            payload: vec![1, 2, 3],
        };
        let mut bytes = packet.encode().unwrap();
        assert_eq!(Ipv4Packet::decode(&bytes).unwrap(), packet);
        bytes[12] ^= 1;
        assert_eq!(
            Ipv4Packet::decode(&bytes),
            Err(PacketError::InvalidChecksum)
        );
        assert_eq!(
            Ipv4Packet { ttl: 0, ..packet }.encode(),
            Err(PacketError::Expired)
        );
    }
}
