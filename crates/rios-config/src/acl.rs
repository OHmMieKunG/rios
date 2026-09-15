//! Structured named and extended IPv4 access-list policy.
use crate::AccessListAction;
use rios_ipv4::Ipv4Packet;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, net::Ipv4Addr};

/// Stable configuration identity for an access list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AclId(pub u32);
/// Standard lists match sources; extended lists additionally match protocol and destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclKind {
    Standard,
    Extended,
}
impl fmt::Display for AclKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Standard => "standard",
            Self::Extended => "extended",
        })
    }
}
/// IPv4 address selection using IOS wildcard bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressMatch {
    pub address: Ipv4Addr,
    pub wildcard: Ipv4Addr,
}
impl AddressMatch {
    pub const ANY: Self = Self {
        address: Ipv4Addr::UNSPECIFIED,
        wildcard: Ipv4Addr::BROADCAST,
    };
    /// Match significant bits, including noncontiguous wildcard masks.
    pub fn matches(self, address: Ipv4Addr) -> bool {
        (u32::from(address) ^ u32::from(self.address)) & !u32::from(self.wildcard) == 0
    }
}
impl fmt::Display for AddressMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::ANY {
            f.write_str("any")
        } else if self.wildcard.is_unspecified() {
            write!(f, "host {}", self.address)
        } else {
            write!(f, "{} {}", self.address, self.wildcard)
        }
    }
}
/// Transport port selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortMatch {
    Any,
    Eq(u16),
    Range(u16, u16),
    Lt(u16),
    Gt(u16),
    Neq(u16),
}
impl PortMatch {
    /// Test a source or destination port against the configured operator.
    pub fn matches(self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Eq(value) => port == value,
            Self::Range(low, high) => (low..=high).contains(&port),
            Self::Lt(value) => port < value,
            Self::Gt(value) => port > value,
            Self::Neq(value) => port != value,
        }
    }
}
impl fmt::Display for PortMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => Ok(()),
            Self::Eq(port) => write!(f, " eq {port}"),
            Self::Range(low, high) => write!(f, " range {low} {high}"),
            Self::Lt(port) => write!(f, " lt {port}"),
            Self::Gt(port) => write!(f, " gt {port}"),
            Self::Neq(port) => write!(f, " neq {port}"),
        }
    }
}
/// IP protocol selector. `Ip` matches every IPv4 protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclProtocol {
    Ip,
    Icmp,
    Tcp,
    Udp,
}
impl fmt::Display for AclProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ip => "ip",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}
/// Ordered access-list entry, including nonmatching remarks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclEntry {
    Remark(String),
    Rule {
        action: AccessListAction,
        protocol: AclProtocol,
        source: AddressMatch,
        source_port: PortMatch,
        destination: AddressMatch,
        destination_port: PortMatch,
        log: bool,
    },
}
impl AclEntry {
    /// Return a decision only when all selectors match.
    pub fn evaluate(&self, packet: &Ipv4Packet) -> Option<AccessListAction> {
        let Self::Rule {
            action,
            protocol,
            source,
            source_port,
            destination,
            destination_port,
            ..
        } = self
        else {
            return None;
        };
        let number = u8::from(packet.protocol);
        let protocol_matches = match protocol {
            AclProtocol::Ip => true,
            AclProtocol::Icmp => number == 1,
            AclProtocol::Tcp => number == 6,
            AclProtocol::Udp => number == 17,
        };
        if !protocol_matches
            || !source.matches(packet.source)
            || !destination.matches(packet.destination)
        {
            return None;
        }
        if *source_port != PortMatch::Any || *destination_port != PortMatch::Any {
            if !matches!(number, 6 | 17) || packet.payload.len() < 4 {
                return None;
            }
            let src = u16::from_be_bytes([packet.payload[0], packet.payload[1]]);
            let dst = u16::from_be_bytes([packet.payload[2], packet.payload[3]]);
            if !source_port.matches(src) || !destination_port.matches(dst) {
                return None;
            }
        }
        Some(*action)
    }
    /// Render one entry without its sequence number.
    pub fn render(&self, kind: AclKind) -> String {
        match self {
            Self::Remark(text) => format!("remark {text}"),
            Self::Rule {
                action,
                protocol,
                source,
                source_port,
                destination,
                destination_port,
                log,
            } => {
                let action = if *action == AccessListAction::Permit {
                    "permit"
                } else {
                    "deny"
                };
                let suffix = if *log { " log" } else { "" };
                if kind == AclKind::Standard {
                    format!("{action} {source}{suffix}")
                } else {
                    format!(
                        "{action} {protocol} {source}{source_port} {destination}{destination_port}{suffix}"
                    )
                }
            }
        }
    }
}
/// Access list with stable sequence ordering and an implicit final deny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessList {
    pub name: String,
    pub kind: AclKind,
    pub entries: BTreeMap<u32, AclEntry>,
}
