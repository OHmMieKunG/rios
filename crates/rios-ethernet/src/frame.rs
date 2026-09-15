use crate::{MacAddress, VlanId};

/// Ethernet II payload identifiers, including opaque protocols not yet implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Dot1Q,
    Other(u16),
    /// IEEE 802.3 payload length, including LLC bytes.
    Length(u16),
}
impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x86dd => Self::Ipv6,
            0x0806 => Self::Arp,
            0x8100 => Self::Dot1Q,
            3..=1500 => Self::Length(value),
            v => Self::Other(v),
        }
    }
}
impl From<EtherType> for u16 {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86dd,
            EtherType::Arp => 0x0806,
            EtherType::Dot1Q => 0x8100,
            EtherType::Other(v) | EtherType::Length(v) => v,
        }
    }
}
/// A logical Ethernet II or IEEE 802.3 LLC frame. Payload ownership moves through virtual links.
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
    /// Validate the Ethernet II type or an exact IEEE 802.3 payload length.
    pub fn valid_length_or_type(&self) -> bool {
        match self.ethertype {
            EtherType::Length(length) => {
                (3..=1500).contains(&length) && usize::from(length) == self.payload.len()
            }
            _ => u16::from(self.ethertype) >= 1536,
        }
    }
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
        if !self.valid_length_or_type() {
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
        let payload = match ether {
            3..=1500 => bytes
                .get(14..14 + usize::from(ether))
                .ok_or(FrameError::Truncated)?,
            0..=1535 => return Err(FrameError::LengthField),
            _ => &bytes[14..],
        };
        Ok(Self {
            destination: MacAddress(bytes[..6].try_into().unwrap()),
            source: MacAddress(bytes[6..12].try_into().unwrap()),
            ethertype: ether.into(),
            payload: payload.to_vec(),
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
        if inner < 0x0600
            && (!(3..=1500).contains(&inner) || usize::from(inner) != self.payload.len() - 4)
            || inner == u16::from(EtherType::Dot1Q)
        {
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
    fn llc_length_fields_preserve_payload_and_allow_wire_padding() {
        let frame = EthernetFrame {
            source: MacAddress([2, 0, 0, 0, 0, 1]),
            destination: MacAddress([1, 0x80, 0xc2, 0, 0, 0]),
            ethertype: EtherType::Length(4),
            payload: vec![0x42, 0x42, 3, 0],
        };
        let mut bytes = frame.encode().unwrap();
        bytes.resize(60, 0);
        assert_eq!(EthernetFrame::decode(&bytes).unwrap(), frame);
        let tagged = frame.clone().tagged(VlanId::new(10).unwrap());
        assert_eq!(tagged.untagged().unwrap().1, frame);
        bytes[12..14].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(EthernetFrame::decode(&bytes), Err(FrameError::Truncated));
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
