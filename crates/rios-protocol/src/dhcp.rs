use rios_ethernet::MacAddress;
use std::net::Ipv4Addr;

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Supported DHCPv4 message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 5,
}

/// BOOTP/DHCP fields used by the simulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpMessage {
    pub message_type: DhcpMessageType,
    pub transaction_id: u32,
    pub client_mac: MacAddress,
    pub your_ip: Ipv4Addr,
    pub requested_ip: Option<Ipv4Addr>,
    pub server_id: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub default_router: Option<Ipv4Addr>,
    pub lease_time_seconds: Option<u32>,
}

/// Invalid or unsupported DHCP wire data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DhcpPacketError {
    #[error("DHCP message is truncated")]
    Truncated,
    #[error("unsupported DHCP message")]
    Unsupported,
    #[error("malformed DHCP option")]
    InvalidOption,
}

impl DhcpMessage {
    /// Encode a DHCPv4 message using the standard BOOTP fixed header and options.
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = vec![0; 240];
        bytes[0] = match self.message_type {
            DhcpMessageType::Discover | DhcpMessageType::Request => 1,
            DhcpMessageType::Offer | DhcpMessageType::Ack => 2,
        };
        bytes[1] = 1;
        bytes[2] = 6;
        bytes[4..8].copy_from_slice(&self.transaction_id.to_be_bytes());
        bytes[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.your_ip.octets());
        bytes[28..34].copy_from_slice(&self.client_mac.0);
        bytes[236..240].copy_from_slice(&MAGIC_COOKIE);
        option(&mut bytes, 53, &[self.message_type as u8]);
        if let Some(value) = self.requested_ip {
            option(&mut bytes, 50, &value.octets());
        }
        if let Some(value) = self.server_id {
            option(&mut bytes, 54, &value.octets());
        }
        if let Some(value) = self.subnet_mask {
            option(&mut bytes, 1, &value.octets());
        }
        if let Some(value) = self.default_router {
            option(&mut bytes, 3, &value.octets());
        }
        if let Some(value) = self.lease_time_seconds {
            option(&mut bytes, 51, &value.to_be_bytes());
        }
        bytes.push(255);
        bytes
    }

    /// Decode the supported BOOTP header and DHCP options.
    pub fn decode(bytes: &[u8]) -> Result<Self, DhcpPacketError> {
        if bytes.len() < 241 {
            return Err(DhcpPacketError::Truncated);
        }
        if bytes[1..3] != [1, 6] || bytes[236..240] != MAGIC_COOKIE {
            return Err(DhcpPacketError::Unsupported);
        }
        let mut message_type = None;
        let mut requested_ip = None;
        let mut server_id = None;
        let mut subnet_mask = None;
        let mut default_router = None;
        let mut lease_time_seconds = None;
        let mut cursor = 240;
        while cursor < bytes.len() {
            let code = bytes[cursor];
            cursor += 1;
            if code == 255 {
                break;
            }
            if code == 0 {
                continue;
            }
            let length = *bytes.get(cursor).ok_or(DhcpPacketError::InvalidOption)? as usize;
            cursor += 1;
            let value = bytes
                .get(cursor..cursor + length)
                .ok_or(DhcpPacketError::InvalidOption)?;
            cursor += length;
            match (code, value) {
                (53, [kind]) => {
                    message_type = Some(match kind {
                        1 => DhcpMessageType::Discover,
                        2 => DhcpMessageType::Offer,
                        3 => DhcpMessageType::Request,
                        5 => DhcpMessageType::Ack,
                        _ => return Err(DhcpPacketError::Unsupported),
                    })
                }
                (50, [a, b, c, d]) => requested_ip = Some(Ipv4Addr::new(*a, *b, *c, *d)),
                (54, [a, b, c, d]) => server_id = Some(Ipv4Addr::new(*a, *b, *c, *d)),
                (1, [a, b, c, d]) => subnet_mask = Some(Ipv4Addr::new(*a, *b, *c, *d)),
                (3, [a, b, c, d]) => default_router = Some(Ipv4Addr::new(*a, *b, *c, *d)),
                (51, [a, b, c, d]) => {
                    lease_time_seconds = Some(u32::from_be_bytes([*a, *b, *c, *d]))
                }
                _ => {}
            }
        }
        let message_type = message_type.ok_or(DhcpPacketError::Unsupported)?;
        let expected_op = if matches!(
            message_type,
            DhcpMessageType::Discover | DhcpMessageType::Request
        ) {
            1
        } else {
            2
        };
        if bytes[0] != expected_op {
            return Err(DhcpPacketError::Unsupported);
        }
        Ok(Self {
            message_type,
            transaction_id: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            client_mac: MacAddress(bytes[28..34].try_into().unwrap()),
            your_ip: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
            requested_ip,
            server_id,
            subnet_mask,
            default_router,
            lease_time_seconds,
        })
    }
}

fn option(bytes: &mut Vec<u8>, code: u8, value: &[u8]) {
    bytes.extend_from_slice(&[code, value.len() as u8]);
    bytes.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_round_trip() {
        let packet = DhcpMessage {
            message_type: DhcpMessageType::Offer,
            transaction_id: 42,
            client_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            your_ip: Ipv4Addr::new(192, 168, 1, 10),
            requested_ip: None,
            server_id: Some(Ipv4Addr::new(192, 168, 1, 1)),
            subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            default_router: Some(Ipv4Addr::new(192, 168, 1, 1)),
            lease_time_seconds: Some(3600),
        };
        assert_eq!(DhcpMessage::decode(&packet.encode()).unwrap(), packet);
    }
}
