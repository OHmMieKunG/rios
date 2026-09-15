//! OSPF multicast constants and neighbor states.
use std::net::Ipv4Addr;

/// OSPF AllSPFRouters multicast address.
pub const OSPF_ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);
/// Default OSPF hello interval in virtual milliseconds.
pub const HELLO_INTERVAL_MS: u64 = 10_000;
/// Default OSPF neighbor dead interval in virtual milliseconds.
pub const DEAD_INTERVAL_MS: u64 = 40_000;

/// OSPF neighbor states retained for protocol-correct progression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfNeighborState {
    Down,
    Init,
    TwoWay,
    ExStart,
    Exchange,
    Loading,
    Full,
}
