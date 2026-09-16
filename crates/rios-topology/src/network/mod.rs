//! Ordered protocol pipeline owned by the lab; no frontend dependencies.
use crate::lab::PendingIpv4;
use crate::*;
use rios_config::AccessListDirection;
use rios_device::{DhcpLease, DhcpOffer, ResolvedRoute};
use rios_ethernet::{EtherType, EthernetFrame, MacAddress};
use rios_ipv4::{IpProtocol, Ipv4Packet};
use rios_protocol::{
    ArpOperation, ArpPacket, DhcpMessage, DhcpMessageType, IcmpEcho, IcmpError, IcmpErrorKind,
    IcmpKind, UdpDatagram,
};
use rios_routing::{OSPF_ALL_ROUTERS, OspfV2Packet};
use rios_simulator::DeviceId;
use std::net::Ipv4Addr;

const PING_TIMEOUT_MS: u64 = 1_000;
const DHCP_RETRY_MS: u64 = 4_000;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

mod arp;
mod bgp;
mod dhcp;
mod forwarding;
mod icmp;
mod ingress;
pub(crate) mod ipv6;
mod lacp;
mod ospf;
mod ping;
mod services;
mod tcp;
mod udp;
pub use ping::{PingError, PingResult};
