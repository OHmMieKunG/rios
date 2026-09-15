//! RFC 4861 RS/RA/NS/NA message bodies and bounded option decoding.
use crate::{Icmpv6Error, Ipv6Network, solicited_node};
use rios_ethernet::MacAddress;
use std::net::Ipv6Addr;
/// Router-advertised prefix with independent on-link and autonomous flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixInformation {
    pub prefix: Ipv6Network,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
}
/// Standard neighbor options; unknown options are preserved and safely skipped by consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdOption {
    SourceLinkLayer(MacAddress),
    TargetLinkLayer(MacAddress),
    Prefix(PrefixInformation),
    Mtu(u32),
    Unknown { kind: u8, data: Vec<u8> },
}
/// Neighbor Discovery wire messages. Lifetimes/timers follow RFC units, not host wall time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NdMessage {
    RouterSolicitation {
        options: Vec<NdOption>,
    },
    RouterAdvertisement {
        hop_limit: u8,
        managed: bool,
        other: bool,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_timer: u32,
        options: Vec<NdOption>,
    },
    NeighborSolicitation {
        target: Ipv6Addr,
        options: Vec<NdOption>,
    },
    NeighborAdvertisement {
        target: Ipv6Addr,
        router: bool,
        solicited: bool,
        override_flag: bool,
        options: Vec<NdOption>,
    },
}
impl NdMessage {
    pub fn options(&self) -> &[NdOption] {
        match self {
            Self::RouterSolicitation { options }
            | Self::RouterAdvertisement { options, .. }
            | Self::NeighborSolicitation { options, .. }
            | Self::NeighborAdvertisement { options, .. } => options,
        }
    }
    /// Validate the enclosing IPv6 fields before changing neighbor or address state.
    pub fn validate(
        &self,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        hop_limit: u8,
    ) -> Result<(), Icmpv6Error> {
        if hop_limit != 255 || source.is_multicast() {
            return Err(Icmpv6Error::Malformed);
        }
        let source_option = self
            .options()
            .iter()
            .any(|o| matches!(o, NdOption::SourceLinkLayer(_)));
        match self {
            Self::RouterAdvertisement { .. } if !source.is_unicast_link_local() => {
                Err(Icmpv6Error::Malformed)
            }
            Self::RouterSolicitation { .. } if source.is_unspecified() && source_option => {
                Err(Icmpv6Error::Malformed)
            }
            Self::NeighborSolicitation { target, .. }
                if target.is_multicast()
                    || target.is_unspecified()
                    || (source.is_unspecified()
                        && (source_option || destination != solicited_node(*target))) =>
            {
                Err(Icmpv6Error::Malformed)
            }
            Self::NeighborAdvertisement {
                target, solicited, ..
            } if source.is_unspecified()
                || target.is_multicast()
                || target.is_unspecified()
                || (*solicited && destination.is_multicast()) =>
            {
                Err(Icmpv6Error::Malformed)
            }
            _ => Ok(()),
        }
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Icmpv6Error> {
        let mut out = match self {
            Self::RouterSolicitation { .. } => vec![133, 0, 0, 0, 0, 0, 0, 0],
            Self::RouterAdvertisement {
                hop_limit,
                managed,
                other,
                router_lifetime,
                reachable_time,
                retrans_timer,
                ..
            } => {
                let mut out = vec![
                    134,
                    0,
                    0,
                    0,
                    *hop_limit,
                    if *managed { 0x80 } else { 0 } | if *other { 0x40 } else { 0 },
                ];
                out.extend_from_slice(&router_lifetime.to_be_bytes());
                out.extend_from_slice(&reachable_time.to_be_bytes());
                out.extend_from_slice(&retrans_timer.to_be_bytes());
                out
            }
            Self::NeighborSolicitation { target, .. } => {
                let mut out = vec![135, 0, 0, 0, 0, 0, 0, 0];
                out.extend_from_slice(&target.octets());
                out
            }
            Self::NeighborAdvertisement {
                target,
                router,
                solicited,
                override_flag,
                ..
            } => {
                let flags = if *router { 0x80 } else { 0 }
                    | if *solicited { 0x40 } else { 0 }
                    | if *override_flag { 0x20 } else { 0 };
                let mut out = vec![136, 0, 0, 0, flags, 0, 0, 0];
                out.extend_from_slice(&target.octets());
                out
            }
        };
        if self.options().len() > 128 {
            return Err(Icmpv6Error::TooLarge);
        }
        for option in self.options() {
            option.encode(&mut out)?;
        }
        if out.len() > 65535 {
            return Err(Icmpv6Error::TooLarge);
        }
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Icmpv6Error> {
        if bytes.len() < 8 {
            return Err(Icmpv6Error::Malformed);
        }
        let options_at = match bytes[0] {
            133 => 8,
            134 => 16,
            135 | 136 => 24,
            _ => return Err(Icmpv6Error::Unsupported),
        };
        let rest = bytes.get(options_at..).ok_or(Icmpv6Error::Malformed)?;
        let options = NdOption::decode_all(rest)?;
        let target = || {
            let mut target = [0; 16];
            target.copy_from_slice(&bytes[8..24]);
            Ipv6Addr::from(target)
        };
        let u32_at = |i| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        match bytes[0] {
            133 => Ok(Self::RouterSolicitation { options }),
            134 => Ok(Self::RouterAdvertisement {
                hop_limit: bytes[4],
                managed: bytes[5] & 0x80 != 0,
                other: bytes[5] & 0x40 != 0,
                router_lifetime: u16::from_be_bytes([bytes[6], bytes[7]]),
                reachable_time: u32_at(8),
                retrans_timer: u32_at(12),
                options,
            }),
            135 => Ok(Self::NeighborSolicitation {
                target: target(),
                options,
            }),
            136 => Ok(Self::NeighborAdvertisement {
                target: target(),
                router: bytes[4] & 0x80 != 0,
                solicited: bytes[4] & 0x40 != 0,
                override_flag: bytes[4] & 0x20 != 0,
                options,
            }),
            _ => Err(Icmpv6Error::Unsupported),
        }
    }
}
impl NdOption {
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Icmpv6Error> {
        match self {
            Self::SourceLinkLayer(mac) | Self::TargetLinkLayer(mac) => {
                out.extend_from_slice(&[
                    if matches!(self, Self::SourceLinkLayer(_)) {
                        1
                    } else {
                        2
                    },
                    1,
                ]);
                out.extend_from_slice(&mac.0);
            }
            Self::Prefix(info) => {
                if info.preferred_lifetime > info.valid_lifetime {
                    return Err(Icmpv6Error::Malformed);
                }
                out.extend_from_slice(&[
                    3,
                    4,
                    info.prefix.prefix_len(),
                    if info.on_link { 0x80 } else { 0 } | if info.autonomous { 0x40 } else { 0 },
                ]);
                out.extend_from_slice(&info.valid_lifetime.to_be_bytes());
                out.extend_from_slice(&info.preferred_lifetime.to_be_bytes());
                out.extend_from_slice(&[0; 4]);
                out.extend_from_slice(&info.prefix.address().octets());
            }
            Self::Mtu(mtu) => {
                out.extend_from_slice(&[5, 1, 0, 0]);
                out.extend_from_slice(&mtu.to_be_bytes());
            }
            Self::Unknown { kind, data } => {
                if matches!(kind, 1 | 2 | 3 | 5)
                    || !(data.len() + 2).is_multiple_of(8)
                    || data.len() > 2038
                {
                    return Err(Icmpv6Error::Malformed);
                }
                out.extend_from_slice(&[*kind, ((data.len() + 2) / 8) as u8]);
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }
    fn decode_all(mut bytes: &[u8]) -> Result<Vec<Self>, Icmpv6Error> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            if out.len() >= 128 || bytes.len() < 2 || bytes[1] == 0 {
                return Err(Icmpv6Error::Malformed);
            }
            let length = usize::from(bytes[1]) * 8;
            let data = bytes.get(2..length).ok_or(Icmpv6Error::Malformed)?;
            let u32_at = |i| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            let option = match bytes[0] {
                1 | 2 if length == 8 => {
                    let mut mac = [0; 6];
                    mac.copy_from_slice(data);
                    if bytes[0] == 1 {
                        Self::SourceLinkLayer(MacAddress(mac))
                    } else {
                        Self::TargetLinkLayer(MacAddress(mac))
                    }
                }
                3 if length == 32 => {
                    let valid_lifetime = u32_at(2);
                    let preferred_lifetime = u32_at(6);
                    if preferred_lifetime > valid_lifetime {
                        return Err(Icmpv6Error::Malformed);
                    }
                    let mut address = [0; 16];
                    address.copy_from_slice(&data[14..30]);
                    let prefix = Ipv6Network::new(address.into(), data[0])
                        .map_err(|_| Icmpv6Error::Malformed)?;
                    Self::Prefix(PrefixInformation {
                        prefix,
                        on_link: data[1] & 0x80 != 0,
                        autonomous: data[1] & 0x40 != 0,
                        valid_lifetime,
                        preferred_lifetime,
                    })
                }
                5 if length == 8 => Self::Mtu(u32_at(2)),
                1 | 2 | 3 | 5 => return Err(Icmpv6Error::Malformed),
                kind => Self::Unknown {
                    kind,
                    data: data.to_vec(),
                },
            };
            out.push(option);
            bytes = &bytes[length..];
        }
        Ok(out)
    }
}
