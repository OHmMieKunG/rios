//! Independent IPv6 interface lifecycle, DAD, Neighbor Discovery and routing state.
mod addresses;
mod config;
mod neighbors;
mod router_advertisement;
mod routing;
pub use routing::{Ipv6Route, Ipv6RouteSource, ResolvedIpv6Route};
mod display;
use crate::*;
use rios_ipv6::*;
use rios_simulator::SimTime;
use std::net::Ipv6Addr;

const ADDRESS_LIMIT: usize = 32;
const NEIGHBOR_LIMIT: usize = 4096;
const RETRANS_US: u64 = 1_000_000;
/// Address usability determined by DAD and SLAAC lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6AddressState {
    Tentative,
    Preferred,
    Deprecated,
    Duplicate,
}
/// Origin of an IPv6 address, independent of whether it is currently usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6AddressOrigin {
    LinkLocal,
    Manual,
    Slaac,
}
/// One address and its deterministic DAD and validity deadlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6AddressEntry {
    pub address: Ipv6InterfaceConfig,
    pub state: Ipv6AddressState,
    pub origin: Ipv6AddressOrigin,
    pub preferred_until: Option<SimTime>,
    pub valid_until: Option<SimTime>,
    dad_due: Option<SimTime>,
    dad_sent: bool,
}
/// RFC 4861 neighbor-unreachability states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6NeighborState {
    Incomplete,
    Reachable,
    Stale,
    Delay,
    Probe,
}
/// An interface-scoped cache entry; link-local addresses never share entries across links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Neighbor {
    pub interface: InterfaceId,
    pub address: Ipv6Addr,
    pub mac: Option<MacAddress>,
    pub state: Ipv6NeighborState,
    pub router: bool,
    pub deadline: SimTime,
    probes: u8,
}
/// A control packet emitted by the device for virtual Ethernet transmission.
#[derive(Debug, Clone)]
pub struct Ipv6ControlPacket {
    pub interface: InterfaceId,
    pub destination_mac: MacAddress,
    pub packet: Ipv6Packet,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceRuntime {
    addresses: BTreeMap<Ipv6Addr, Ipv6AddressEntry>,
    ra_due: SimTime,
    ra_last: Option<SimTime>,
    rs_due: Option<SimTime>,
    rs_count: u8,
}
impl Default for InterfaceRuntime {
    fn default() -> Self {
        Self {
            addresses: BTreeMap::new(),
            ra_due: SimTime(0),
            ra_last: None,
            rs_due: Some(SimTime(0)),
            rs_count: 0,
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Ipv6Runtime {
    interfaces: BTreeMap<InterfaceId, InterfaceRuntime>,
    neighbors: BTreeMap<(InterfaceId, Ipv6Addr), Ipv6Neighbor>,
    routers: BTreeMap<(InterfaceId, Ipv6Addr), SimTime>,
    prefixes: BTreeMap<(InterfaceId, Ipv6Network), SimTime>,
}
fn after(now: SimTime, seconds: u32) -> SimTime {
    SimTime(now.0.saturating_add(u64::from(seconds) * 1_000_000))
}
fn lifetime(now: SimTime, seconds: u32) -> Option<SimTime> {
    (seconds != u32::MAX).then(|| after(now, seconds))
}
impl Device {
    pub(super) fn reset_ipv6_interface(&mut self, id: InterfaceId) {
        let ids: BTreeSet<_> = self
            .running_config
            .interfaces
            .iter()
            .filter(|(port, c)| **port == id || c.parent == Some(id))
            .map(|(port, _)| *port)
            .collect();
        self.ipv6.interfaces.retain(|id, _| !ids.contains(id));
        self.ipv6.neighbors.retain(|(id, _), _| !ids.contains(id));
        self.ipv6.routers.retain(|(id, _), _| !ids.contains(id));
        self.ipv6.prefixes.retain(|(id, _), _| !ids.contains(id));
    }

    pub(super) fn ipv6_control(
        &self,
        interface: InterfaceId,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        mac: Option<MacAddress>,
        message: NdMessage,
    ) -> Option<Ipv6ControlPacket> {
        let destination_mac = mac.or_else(|| multicast_mac(destination))?;
        let payload = Icmpv6Message::Neighbor(message)
            .encode(source, destination)
            .ok()?;
        Some(Ipv6ControlPacket {
            interface,
            destination_mac,
            packet: Ipv6Packet {
                source,
                destination,
                traffic_class: 0,
                flow_label: 0,
                hop_limit: 255,
                next_header: NextHeader::Icmpv6,
                payload,
            },
        })
    }
    /// DAD, neighbor reachability and RA/RS timers produce real packets for the lab.
    pub fn ipv6_tick(&mut self, now: SimTime) -> Vec<Ipv6ControlPacket> {
        self.ipv6_prepare(now);
        let mut out = self.ipv6_dad(now);
        out.extend(self.ipv6_neighbor_timers(now));
        out.extend(self.ipv6_router_timers(now));
        out
    }
    /// Next exact deadline, with a one-second maintenance bound for physical carrier changes.
    pub fn ipv6_next_deadline(&self, now: SimTime) -> SimTime {
        let mut next = SimTime(now.0.saturating_add(RETRANS_US));
        let mut consider = |time: SimTime| {
            if time > now {
                next = next.min(time);
            }
        };
        for runtime in self.ipv6.interfaces.values() {
            consider(runtime.ra_due);
            if let Some(time) = runtime.rs_due {
                consider(time);
            }
            for entry in runtime.addresses.values() {
                for time in [entry.dad_due, entry.preferred_until, entry.valid_until]
                    .into_iter()
                    .flatten()
                {
                    consider(time);
                }
            }
        }
        for neighbor in self.ipv6.neighbors.values() {
            consider(neighbor.deadline);
        }
        for time in self
            .ipv6
            .routers
            .values()
            .chain(self.ipv6.prefixes.values())
        {
            consider(*time);
        }
        next
    }
    /// Whether the device has any IPv6-enabled interface, including currently down ports.
    pub fn has_ipv6(&self) -> bool {
        self.running_config
            .interfaces
            .values()
            .any(|c| c.ipv6.active())
    }
    /// Effective IPv6 forwarding switch; hosts and Layer 2 switches cannot route transit packets.
    pub fn ipv6_forwarding_enabled(&self) -> bool {
        self.supports_routing() && self.running_config.ipv6_unicast_routing
    }
}
