//! NTPv3/v4 base packets and integer timestamps; no wall-clock dependency.
/// Malformed or unsupported NTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid NTP base packet")]
pub struct NtpError;
/// NTP seconds/fraction timestamp, with the standard 32-bit seconds era wrapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NtpTimestamp(pub u64);
impl NtpTimestamp {
    /// Map an explicitly supplied Unix epoch and elapsed simulation microseconds to NTP time.
    pub fn from_simulation(epoch_seconds: u64, elapsed_us: u64) -> Self {
        let seconds = epoch_seconds
            .wrapping_add(2_208_988_800)
            .wrapping_add(elapsed_us / 1_000_000) as u32;
        let fraction = ((u128::from(elapsed_us % 1_000_000) << 32) / 1_000_000) as u32;
        Self((u64::from(seconds) << 32) | u64::from(fraction))
    }
}
/// A 48-byte NTP base message. Extensions and authentication are not implemented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpPacket {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    pub root_delay: u32,
    pub root_dispersion: u32,
    pub reference_id: [u8; 4],
    pub reference: NtpTimestamp,
    pub origin: NtpTimestamp,
    pub receive: NtpTimestamp,
    pub transmit: NtpTimestamp,
}
impl NtpPacket {
    /// Build a client request carrying an explicit transmit timestamp.
    pub fn request(transmit: NtpTimestamp) -> Self {
        Self {
            leap: 0,
            version: 4,
            mode: 3,
            stratum: 0,
            poll: 6,
            precision: -20,
            root_delay: 0,
            root_dispersion: 0,
            reference_id: [0; 4],
            reference: NtpTimestamp(0),
            origin: NtpTimestamp(0),
            receive: NtpTimestamp(0),
            transmit,
        }
    }
    /// Encode the fixed NTP header in network byte order.
    pub fn encode(&self) -> Result<Vec<u8>, NtpError> {
        if self.leap > 3 || !matches!(self.version, 3 | 4) || self.mode > 7 {
            return Err(NtpError);
        }
        let mut bytes = vec![0; 48];
        bytes[..4].copy_from_slice(&[
            (self.leap << 6) | (self.version << 3) | self.mode,
            self.stratum,
            self.poll as u8,
            self.precision as u8,
        ]);
        bytes[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.reference_id);
        for (index, value) in [self.reference, self.origin, self.receive, self.transmit]
            .iter()
            .enumerate()
        {
            bytes[16 + index * 8..24 + index * 8].copy_from_slice(&value.0.to_be_bytes());
        }
        Ok(bytes)
    }
    /// Decode a base packet without accepting truncated timestamps or unsupported versions.
    pub fn decode(bytes: &[u8]) -> Result<Self, NtpError> {
        if bytes.len() != 48 || !matches!((bytes[0] >> 3) & 7, 3 | 4) {
            return Err(NtpError);
        }
        let word = |at| -> Result<u32, NtpError> {
            Ok(u32::from_be_bytes(
                bytes[at..at + 4].try_into().map_err(|_| NtpError)?,
            ))
        };
        let time = |at| -> Result<NtpTimestamp, NtpError> {
            Ok(NtpTimestamp(u64::from_be_bytes(
                bytes[at..at + 8].try_into().map_err(|_| NtpError)?,
            )))
        };
        Ok(Self {
            leap: bytes[0] >> 6,
            version: (bytes[0] >> 3) & 7,
            mode: bytes[0] & 7,
            stratum: bytes[1],
            poll: bytes[2] as i8,
            precision: bytes[3] as i8,
            root_delay: word(4)?,
            root_dispersion: word(8)?,
            reference_id: bytes[12..16].try_into().map_err(|_| NtpError)?,
            reference: time(16)?,
            origin: time(24)?,
            receive: time(32)?,
            transmit: time(40)?,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn integer_fraction_and_packet_roundtrip() {
        let time = NtpTimestamp::from_simulation(0, 1_500_000);
        assert_eq!(time.0, (2_208_988_801u64 << 32) | 0x80000000);
        let packet = NtpPacket::request(time);
        let bytes = packet.encode().unwrap();
        assert_eq!(NtpPacket::decode(&bytes).unwrap(), packet);
        for length in 0..48 {
            assert!(NtpPacket::decode(&bytes[..length]).is_err());
        }
        assert!(NtpPacket::decode(&[0; 49]).is_err());
    }
}
