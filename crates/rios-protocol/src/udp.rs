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
    #[error("invalid UDP length")]
    InvalidLength,
}

impl UdpDatagram {
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
