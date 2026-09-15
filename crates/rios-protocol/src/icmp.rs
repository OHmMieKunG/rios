use rios_ipv4::checksum;

/// Supported ICMP echo message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpKind {
    EchoRequest,
    EchoReply,
}

/// ICMP errors generated while forwarding IPv4 packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    DestinationUnreachable,
    TimeExceeded,
}

/// ICMP error carrying the original IPv4 header and its first eight payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpError {
    pub kind: IcmpErrorKind,
    pub code: u8,
    pub quoted_packet: Vec<u8>,
}

/// ICMP echo message with caller-owned data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpEcho {
    /// Echo request or reply.
    pub kind: IcmpKind,
    /// Identifier used to match replies.
    pub identifier: u16,
    /// Sequence number used to match replies.
    pub sequence: u16,
    /// Echoed application bytes.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IcmpPacketError {
    #[error("ICMP echo message is truncated")]
    Truncated,
    #[error("unsupported ICMP message")]
    Unsupported,
    #[error("invalid ICMP checksum")]
    InvalidChecksum,
}

impl IcmpEcho {
    /// Encode an ICMP echo message with checksum.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0; 8 + self.payload.len()];
        bytes[0] = if self.kind == IcmpKind::EchoRequest {
            8
        } else {
            0
        };
        bytes[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[8..].copy_from_slice(&self.payload);
        let value = checksum(&bytes);
        bytes[2..4].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    /// Decode and validate an ICMP echo message.
    pub fn decode(bytes: &[u8]) -> Result<Self, IcmpPacketError> {
        if bytes.len() < 8 {
            return Err(IcmpPacketError::Truncated);
        }
        let kind = match (bytes[0], bytes[1]) {
            (8, 0) => IcmpKind::EchoRequest,
            (0, 0) => IcmpKind::EchoReply,
            _ => return Err(IcmpPacketError::Unsupported),
        };
        if checksum(bytes) != 0 {
            return Err(IcmpPacketError::InvalidChecksum);
        }
        Ok(Self {
            kind,
            identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence: u16::from_be_bytes([bytes[6], bytes[7]]),
            payload: bytes[8..].to_vec(),
        })
    }
}

impl IcmpError {
    /// Encode an ICMP destination-unreachable or time-exceeded message.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0; 8 + self.quoted_packet.len()];
        bytes[0] = match self.kind {
            IcmpErrorKind::DestinationUnreachable => 3,
            IcmpErrorKind::TimeExceeded => 11,
        };
        bytes[1] = self.code;
        bytes[8..].copy_from_slice(&self.quoted_packet);
        let value = checksum(&bytes);
        bytes[2..4].copy_from_slice(&value.to_be_bytes());
        bytes
    }

    /// Decode and validate a supported ICMP error.
    pub fn decode(bytes: &[u8]) -> Result<Self, IcmpPacketError> {
        if bytes.len() < 8 {
            return Err(IcmpPacketError::Truncated);
        }
        let kind = match bytes[0] {
            3 => IcmpErrorKind::DestinationUnreachable,
            11 => IcmpErrorKind::TimeExceeded,
            _ => return Err(IcmpPacketError::Unsupported),
        };
        if checksum(bytes) != 0 {
            return Err(IcmpPacketError::InvalidChecksum);
        }
        Ok(Self {
            kind,
            code: bytes[1],
            quoted_packet: bytes[8..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_round_trip_and_checksum() {
        let packet = IcmpEcho {
            kind: IcmpKind::EchoRequest,
            identifier: 7,
            sequence: 9,
            payload: vec![0xaa; 32],
        };
        let mut bytes = packet.encode();
        assert_eq!(IcmpEcho::decode(&bytes).unwrap(), packet);
        bytes[8] ^= 1;
        assert_eq!(
            IcmpEcho::decode(&bytes),
            Err(IcmpPacketError::InvalidChecksum)
        );
    }

    #[test]
    fn icmp_error_round_trip() {
        let packet = IcmpError {
            kind: IcmpErrorKind::TimeExceeded,
            code: 0,
            quoted_packet: vec![0x45; 28],
        };
        assert_eq!(IcmpError::decode(&packet.encode()).unwrap(), packet);
    }
}
