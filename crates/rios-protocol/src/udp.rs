/// Minimal UDP datagram. A zero checksum is emitted for IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: Vec<u8>,
}

/// Invalid UDP wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UdpPacketError {
    #[error("UDP datagram is truncated")]
    Truncated,
    #[error("invalid UDP checksum")]
    Checksum,
    #[error("invalid UDP length")]
    InvalidLength,
}

fn checksum(source: std::net::Ipv4Addr, destination: std::net::Ipv4Addr, bytes: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + bytes.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(bytes);
    rios_ipv4::checksum(&pseudo)
}
impl UdpDatagram {
    /// Encode the optional IPv4 UDP checksum, including the pseudoheader.
    pub fn encode_ipv4(
        &self,
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
    ) -> Result<Vec<u8>, UdpPacketError> {
        let mut bytes = self.encode()?;
        let sum = checksum(source, destination, &bytes);
        bytes[6..8].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
        Ok(bytes)
    }
    /// Validate an IPv4 datagram's checksum when present; zero remains legal.
    pub fn decode_ipv4(
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        bytes: &[u8],
    ) -> Result<Self, UdpPacketError> {
        let datagram = Self::decode(bytes)?;
        let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if bytes[6..8] != [0, 0] && checksum(source, destination, &bytes[..length]) != 0 {
            return Err(UdpPacketError::Checksum);
        }
        Ok(datagram)
    }

    /// Encode an IPv4 UDP datagram with the optional checksum disabled.
    pub fn encode(&self) -> Result<Vec<u8>, UdpPacketError> {
        let length = 8usize
            .checked_add(self.payload.len())
            .filter(|length| *length <= u16::MAX.into())
            .ok_or(UdpPacketError::InvalidLength)?;
        let mut bytes = vec![0; length];
        bytes[..2].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&(length as u16).to_be_bytes());
        bytes[8..].copy_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Decode a UDP datagram, accepting the legal zero IPv4 checksum.
    pub fn decode(bytes: &[u8]) -> Result<Self, UdpPacketError> {
        if bytes.len() < 8 {
            return Err(UdpPacketError::Truncated);
        }
        let length = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if length < 8 || length > bytes.len() {
            return Err(UdpPacketError::InvalidLength);
        }
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            payload: bytes[8..length].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_checksum_rejects_corruption_but_accepts_omitted_checksum() {
        let source = "192.0.2.1".parse().unwrap();
        let destination = "192.0.2.2".parse().unwrap();
        let packet = UdpDatagram {
            source_port: 1000,
            destination_port: 7,
            payload: vec![1, 2, 3],
        };
        let bytes = packet.encode_ipv4(source, destination).unwrap();
        assert_eq!(
            UdpDatagram::decode_ipv4(source, destination, &bytes).unwrap(),
            packet
        );
        for len in 0..bytes.len() {
            assert!(UdpDatagram::decode_ipv4(source, destination, &bytes[..len]).is_err());
        }
        let mut corrupt = bytes;
        corrupt[8] ^= 1;
        assert_eq!(
            UdpDatagram::decode_ipv4(source, destination, &corrupt),
            Err(UdpPacketError::Checksum)
        );
        assert_eq!(
            UdpDatagram::decode_ipv4(source, destination, &packet.encode().unwrap()).unwrap(),
            packet
        );
    }

    #[test]
    fn udp_round_trip() {
        let datagram = UdpDatagram {
            source_port: 68,
            destination_port: 67,
            payload: vec![1, 2, 3],
        };
        assert_eq!(
            UdpDatagram::decode(&datagram.encode().unwrap()).unwrap(),
            datagram
        );
        assert_eq!(UdpDatagram::decode(&[0; 7]), Err(UdpPacketError::Truncated));
    }
}
