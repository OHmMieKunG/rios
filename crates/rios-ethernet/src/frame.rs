use crate::{MacAddress, VlanId};

/// Ethernet II payload identifiers, including opaque protocols not yet implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
    Dot1Q,
    Other(u16),
}
impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x8100 => Self::Dot1Q,
            v => Self::Other(v),
        }
    }
}
impl From<EtherType> for u16 {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Ipv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::Dot1Q => 0x8100,
            EtherType::Other(v) => v,
        }
    }
}
/// A logical Ethernet II frame. Payload ownership moves through virtual links.
/// Preamble, padding, inter-frame gap, and FCS are not simulated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}
/// Malformed Ethernet II envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("Ethernet II header requires at least 14 bytes")]
    Truncated,
    #[error("IEEE 802.3 length fields are not Ethernet II EtherTypes")]
    LengthField,
    #[error("malformed or unsupported 802.1Q tag")]
    InvalidVlanTag,
}
impl EthernetFrame {
    /// Logical byte count used by counters (14-byte header plus payload, no FCS).
    pub fn len(&self) -> usize {
        14 + self.payload.len()
    }
    /// Ethernet frames always contain a header.
    pub fn is_empty(&self) -> bool {
        false
    }
    /// Encode an Ethernet II envelope without padding or FCS.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let ether: u16 = self.ethertype.into();
        if ether < 0x0600 {
            return Err(FrameError::LengthField);
        }
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(&self.destination.0);
        out.extend_from_slice(&self.source.0);
        out.extend_from_slice(&ether.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
    /// Decode an Ethernet II envelope, retaining its payload bytes verbatim.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < 14 {
            return Err(FrameError::Truncated);
        }
        let ether = u16::from_be_bytes([bytes[12], bytes[13]]);
        if ether < 0x0600 {
            return Err(FrameError::LengthField);
        }
        Ok(Self {
            destination: MacAddress(bytes[..6].try_into().unwrap()),
            source: MacAddress(bytes[6..12].try_into().unwrap()),
            ethertype: ether.into(),
            payload: bytes[14..].to_vec(),
        })
    }

    /// Wrap a frame payload in a single 802.1Q tag with priority zero.
    pub fn tagged(self, vlan: VlanId) -> Self {
        let mut payload = Vec::with_capacity(self.payload.len() + 4);
        payload.extend_from_slice(&vlan.get().to_be_bytes());
        payload.extend_from_slice(&u16::from(self.ethertype).to_be_bytes());
        payload.extend_from_slice(&self.payload);
        Self {
            destination: self.destination,
            source: self.source,
            ethertype: EtherType::Dot1Q,
            payload,
        }
    }

    /// Remove one 802.1Q tag and return its VLAN and inner Ethernet frame.
    pub fn untagged(&self) -> Result<(VlanId, Self), FrameError> {
        if self.ethertype != EtherType::Dot1Q || self.payload.len() < 4 {
            return Err(FrameError::InvalidVlanTag);
        }
        let tci = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        let vlan = VlanId::new(tci & 0x0fff).map_err(|_| FrameError::InvalidVlanTag)?;
        let inner = u16::from_be_bytes([self.payload[2], self.payload[3]]);
        if inner < 0x0600 || inner == u16::from(EtherType::Dot1Q) {
            return Err(FrameError::InvalidVlanTag);
        }
        Ok((
            vlan,
            Self {
                destination: self.destination,
                source: self.source,
                ethertype: inner.into(),
                payload: self.payload[4..].to_vec(),
            },
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_round_trip_and_validation() {
        for ethertype in [
            EtherType::Ipv4,
            EtherType::Arp,
            EtherType::Dot1Q,
            EtherType::Other(0x88b5),
        ] {
            let frame = EthernetFrame {
                destination: MacAddress::BROADCAST,
                source: MacAddress([2, 0, 0, 0, 0, 1]),
                ethertype,
                payload: vec![1, 2, 3, 4],
            };
            let bytes = frame.encode().unwrap();
            assert_eq!(bytes.len(), 18);
            assert_eq!(EthernetFrame::decode(&bytes).unwrap(), frame);
        }
        assert_eq!(EthernetFrame::decode(&[0; 13]), Err(FrameError::Truncated));
        assert_eq!(
            EthernetFrame::decode(&[0; 14]),
            Err(FrameError::LengthField)
        );
        assert!(MacAddress::BROADCAST.is_multicast());
        assert!(!MacAddress([2, 0, 0, 0, 0, 1]).is_multicast());
    }

    #[test]
    fn dot1q_tag_round_trip() {
        let frame = EthernetFrame {
            destination: MacAddress::BROADCAST,
            source: MacAddress([2, 0, 0, 0, 0, 1]),
            ethertype: EtherType::Arp,
            payload: vec![1, 2, 3],
        };
        let tagged = frame.clone().tagged(VlanId::new(10).unwrap());
        assert_eq!(tagged.ethertype, EtherType::Dot1Q);
        assert_eq!(
            tagged.untagged().unwrap(),
            (VlanId::new(10).unwrap(), frame)
        );
    }
}
