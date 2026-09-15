//! Standard ARP, ICMP, UDP, and DHCP message representations used by simulated devices.
#![forbid(unsafe_code)]

mod arp;
mod dhcp;
mod icmp;
mod udp;
pub use arp::{ArpOperation, ArpPacket, ArpPacketError};
pub use dhcp::{DhcpMessage, DhcpMessageType, DhcpPacketError};
pub use icmp::{IcmpEcho, IcmpError, IcmpErrorKind, IcmpKind, IcmpPacketError};
pub use udp::{UdpDatagram, UdpPacketError};
