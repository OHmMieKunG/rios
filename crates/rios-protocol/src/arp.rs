use rios_ethernet::MacAddress;
use std::net::Ipv4Addr;

/// ARP request or reply operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

/// Ethernet/IPv4 ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    /// Request or reply opcode.
    pub operation: ArpOperation,
    /// Sender's Ethernet address.
    pub sender_mac: MacAddress,
    /// Sender's IPv4 address.
    pub sender_ip: Ipv4Addr,
    /// Target Ethernet address, zero for requests.
    pub target_mac: MacAddress,
    /// Requested or replying-to IPv4 address.
    pub target_ip: Ipv4Addr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArpPacketError {
    #[error("ARP packet must be 28 bytes")]
    InvalidLength,
    #[error("unsupported ARP hardware, protocol, or operation")]
    Unsupported,
}

impl ArpPacket {
    /// Encode the fixed Ethernet/IPv4 ARP wire format.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(28);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());
        bytes.extend_from_slice(&[6, 4]);
        bytes.extend_from_slice(
            &(if self.operation == ArpOperation::Request {
                1u16
            } else {
                2
            })
            .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.sender_mac.0);
        bytes.extend_from_slice(&self.sender_ip.octets());
        bytes.extend_from_slice(&self.target_mac.0);
        bytes.extend_from_slice(&self.target_ip.octets());
        bytes
    }

    /// Decode the fixed Ethernet/IPv4 ARP wire format.
    pub fn decode(bytes: &[u8]) -> Result<Self, ArpPacketError> {
        if bytes.len() != 28 {
            return Err(ArpPacketError::InvalidLength);
        }
        if bytes[..6] != [0, 1, 8, 0, 6, 4] {
            return Err(ArpPacketError::Unsupported);
        }
        let operation = match u16::from_be_bytes([bytes[6], bytes[7]]) {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            _ => return Err(ArpPacketError::Unsupported),
        };
        Ok(Self {
            operation,
            sender_mac: MacAddress(bytes[8..14].try_into().unwrap()),
            sender_ip: Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]),
            target_mac: MacAddress(bytes[18..24].try_into().unwrap()),
            target_ip: Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_round_trip() {
        let packet = ArpPacket {
            operation: ArpOperation::Request,
            sender_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            sender_ip: Ipv4Addr::new(10, 0, 0, 1),
            target_mac: MacAddress([0; 6]),
            target_ip: Ipv4Addr::new(10, 0, 0, 2),
        };
        assert_eq!(ArpPacket::decode(&packet.encode()).unwrap(), packet);
        assert_eq!(
            ArpPacket::decode(&[0; 27]),
            Err(ArpPacketError::InvalidLength)
        );
    }
}
