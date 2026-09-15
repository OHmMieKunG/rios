//! Validated virtual labs, YAML inventory, and deterministic Ethernet delivery.
//! Owns concrete simulation events; depends on devices but never on the CLI.
#![forbid(unsafe_code)]
mod delivery;
mod lab;
mod network;
mod yaml;
pub use lab::Lab;
pub use network::{PingError, PingResult};
use rios_device::{DeviceError, DropReason};
use rios_ethernet::{EtherType, EthernetFrame};
use rios_simulator::{InterfaceRef, LinkId, LinkState, ScheduleError, SimTime, TimerId};
pub use yaml::Topology;

/// Point-to-point virtual cable. Runtime mutation goes through Lab methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub id: LinkId,
    pub endpoint_a: InterfaceRef,
    pub endpoint_b: InterfaceRef,
    pub state: LinkState,
    pub delay_ms: u64,
    pub config: rios_simulator::LinkConfig,
    pub a_to_b: rios_simulator::DirectionalLinkRuntime,
    pub b_to_a: rios_simulator::DirectionalLinkRuntime,
    pub(crate) active: bool,
    pub(crate) generation: u64,
}
impl Link {
    /// Whether the cable and both administrative endpoints currently permit traffic.
    pub fn is_active(&self) -> bool {
        self.active
    }
}
/// Concrete internal events scheduled by the lab, with owned frame payloads.
#[derive(Debug)]
pub(crate) enum SimulationEvent {
    FrameReceived {
        link: LinkId,
        generation: u64,
        interface: InterfaceRef,
        frame: EthernetFrame,
        source: InterfaceRef,
        lost: bool,
    },
    LinkStateChanged {
        link: LinkId,
        state: LinkState,
    },
    TimerExpired {
        timer: TimerId,
    },
    OspfHello {
        device: rios_simulator::DeviceId,
        generation: u64,
    },
    OspfDead {
        device: rios_simulator::DeviceId,
        router_id: std::net::Ipv4Addr,
        deadline: SimTime,
    },
    StpHello {
        device: rios_simulator::DeviceId,
        generation: u64,
    },
    DhcpClient {
        device: rios_simulator::DeviceId,
        generation: u64,
    },
    DhcpLeaseExpired {
        device: rios_simulator::DeviceId,
        interface: rios_simulator::InterfaceId,
        address: std::net::Ipv4Addr,
        deadline: SimTime,
    },
}
/// Observable result of one simulation step. Receivers own the delivered frame.
#[derive(Debug, PartialEq, Eq)]
pub enum EventOutcome {
    FrameReceived {
        interface: InterfaceRef,
        frame: EthernetFrame,
    },
    FrameDropped {
        interface: InterfaceRef,
        reason: DropReason,
    },
    LinkStateChanged {
        link: LinkId,
        state: LinkState,
    },
    TimerExpired {
        timer: TimerId,
    },
}
/// Packet trace action at an interface boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceAction {
    Tx,
    Rx,
    Drop(DropReason),
}
/// Lightweight deterministic trace metadata; no packet buffer clones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRecord {
    pub time: SimTime,
    pub interface: InterfaceRef,
    pub action: TraceAction,
    pub ethertype: EtherType,
    pub length: usize,
}
/// Topology, device, scheduling, and delivery failures.
#[derive(Debug, thiserror::Error)]
pub enum LabError {
    #[error("invalid topology: {0}")]
    InvalidTopology(String),
    #[error("unknown device: {0}")]
    UnknownDevice(String),
    #[error("unknown endpoint: {0}")]
    UnknownEndpoint(String),
    #[error("unknown link: {0:?}")]
    UnknownLink(LinkId),
    #[error("frame dropped: {0}")]
    Dropped(#[from] DropReason),
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error(transparent)]
    Schedule(#[from] ScheduleError),
    #[error("lab identity or generation capacity exceeded")]
    Capacity,
    #[error("protocol operation failed: {0}")]
    Protocol(String),
    #[error(transparent)]
    Ping(#[from] PingError),
}
