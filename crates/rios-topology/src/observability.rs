//! Observational, bounded debug records and protocol classification.
use crate::*;
mod state;
use rios_device::{DebugTopic, PacketProtocol};
use rios_simulator::DeviceId;
pub(crate) use state::DebugSnapshot;

pub(crate) const TRACE_LIMIT: usize = 4096;
/// Structured debug event emitted without scheduling extra simulation events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugEvent {
    NatTranslation {
        interface: InterfaceRef,
        before: NatTuple,
        after: NatTuple,
    },
    Route {
        installed: bool,
        route: rios_ipv4::Route,
    },
    OspfAdjacency {
        interface: rios_simulator::InterfaceId,
        router_id: std::net::Ipv4Addr,
        before: Option<rios_routing::OspfNeighborState>,
        after: Option<rios_routing::OspfNeighborState>,
    },
    BgpState {
        peer: std::net::Ipv4Addr,
        before: Option<rios_routing::BgpState>,
        after: Option<rios_routing::BgpState>,
    },
    NatStatistics {
        before: rios_device::NatStatistics,
        after: rios_device::NatStatistics,
    },
    SpanningTree {
        vlan: rios_config::VlanId,
        interface: rios_simulator::InterfaceId,
        before: Option<(rios_switching::StpPortRole, rios_switching::StpPortState)>,
        after: Option<(rios_switching::StpPortRole, rios_switching::StpPortState)>,
    },
    Lacp {
        interface: rios_simulator::InterfaceId,
        before: Option<rios_switching::Lacpdu>,
        after: Option<rios_switching::Lacpdu>,
    },
    Packet {
        interface: InterfaceRef,
        action: TraceAction,
        protocol: PacketProtocol,
        length: usize,
        summary: String,
    },
}
/// One event timestamped by the virtual clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugRecord {
    pub time: SimTime,
    pub device: DeviceId,
    pub event: DebugEvent,
}
impl Lab {
    /// Drain only the selected device's debug records; other sessions retain theirs.
    pub fn take_debug(&mut self, device: DeviceId) -> Vec<DebugRecord> {
        let mut records = Vec::new();
        self.debug_records.retain(|record| {
            if record.device == device {
                records.push(record.clone());
                false
            } else {
                true
            }
        });
        records
    }
    /// Number of discarded oldest trace records since lab creation.
    pub fn trace_overflow(&self) -> u64 {
        self.trace_overflow
    }
    /// Number of discarded oldest device debug records since lab creation.
    pub fn debug_overflow(&self, device: DeviceId) -> u64 {
        self.debug_overflow.get(&device).copied().unwrap_or(0)
    }
    pub(crate) fn push_debug(&mut self, device: DeviceId, event: DebugEvent) {
        if self.debug_records.len() == TRACE_LIMIT
            && let Some(old) = self.debug_records.pop_front()
        {
            let count = self.debug_overflow.entry(old.device).or_default();
            *count = count.saturating_add(1);
        }
        self.debug_records.push_back(DebugRecord {
            time: self.now(),
            device,
            event,
        });
    }
    pub(crate) fn observe_packet(
        &mut self,
        interface: InterfaceRef,
        action: TraceAction,
        frame: &EthernetFrame,
    ) {
        let (protocol, bytes) = classify(frame);
        let Some(device) = self.devices.get_mut(&interface.device) else {
            return;
        };
        device.record_protocol(
            protocol,
            match action {
                TraceAction::Tx => Some(true),
                TraceAction::Rx => Some(false),
                TraceAction::Drop(_) => None,
            },
            frame.len(),
        );
        if device
            .debug_topics()
            .iter()
            .any(|topic| topic.matches(protocol))
        {
            let summary = packet_summary(protocol, bytes);
            self.push_debug(
                interface.device,
                DebugEvent::Packet {
                    interface,
                    action,
                    protocol,
                    length: frame.len(),
                    summary,
                },
            );
        }
    }
}
fn classify(frame: &EthernetFrame) -> (PacketProtocol, &[u8]) {
    use PacketProtocol as P;
    let mut kind = frame.ethertype;
    let mut bytes = frame.payload.as_slice();
    if kind == EtherType::Dot1Q {
        if bytes.len() < 4 {
            return (P::Malformed, bytes);
        }
        kind = EtherType::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        bytes = &bytes[4..];
    }
    let protocol = match kind {
        EtherType::Arp => P::Arp,
        EtherType::Ipv4 => {
            if bytes.len() < 20 || bytes[0] >> 4 != 4 {
                return (P::Malformed, bytes);
            }
            let header = usize::from(bytes[0] & 15) * 4;
            let length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            if header < 20 || header > length || length > bytes.len() {
                return (P::Malformed, bytes);
            }
            let transport = &bytes[header..length];
            match bytes[9] {
                1 => P::Icmp,
                89 => P::Ospf,
                6 | 17 if transport.len() >= 4 => {
                    let ports = [
                        u16::from_be_bytes([transport[0], transport[1]]),
                        u16::from_be_bytes([transport[2], transport[3]]),
                    ];
                    if bytes[9] == 6 {
                        if ports.contains(&179) { P::Bgp } else { P::Tcp }
                    } else if ports.iter().any(|p| matches!(p, 67 | 68)) {
                        P::Dhcp
                    } else if ports.contains(&53) {
                        P::Dns
                    } else if ports.contains(&123) {
                        P::Ntp
                    } else {
                        P::Udp
                    }
                }
                6 | 17 => P::Malformed,
                _ => P::Ipv4,
            }
        }
        EtherType::Ipv6 if bytes.len() >= 40 => match bytes[6] {
            58 => P::Icmpv6,
            89 => P::Ospf,
            _ => P::Ipv6,
        },
        EtherType::Ipv6 => P::Malformed,
        EtherType::Length(_) if frame.destination.0 == rios_switching::STP_MULTICAST => P::Stp,
        EtherType::Other(0x8809) if frame.destination.0 == rios_switching::LACP_MULTICAST => {
            P::Lacp
        }
        _ => P::Ethernet,
    };
    (protocol, bytes)
}
fn packet_summary(protocol: PacketProtocol, bytes: &[u8]) -> String {
    if protocol == PacketProtocol::Arp {
        return rios_protocol::ArpPacket::decode(bytes).map_or_else(
            |_| "malformed ARP".into(),
            |arp| {
                format!(
                    "{:?} {} ({}) -> {}",
                    arp.operation, arp.sender_ip, arp.sender_mac, arp.target_ip
                )
            },
        );
    }
    if bytes.len() >= 20 && bytes[0] >> 4 == 4 {
        let source = std::net::Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let destination = std::net::Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        return format!("{source} -> {destination}, TTL {}", bytes[8]);
    }
    format!("{protocol:?}")
}

/// IPv4 addresses and transport selectors before or after NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatTuple {
    pub source: std::net::Ipv4Addr,
    pub destination: std::net::Ipv4Addr,
    pub source_selector: Option<u16>,
    pub destination_selector: Option<u16>,
}
impl From<&rios_ipv4::Ipv4Packet> for NatTuple {
    fn from(packet: &rios_ipv4::Ipv4Packet) -> Self {
        let (source_selector, destination_selector) = match packet.protocol {
            rios_ipv4::IpProtocol::Tcp | rios_ipv4::IpProtocol::Udp
                if packet.payload.len() >= 4 =>
            {
                (
                    Some(u16::from_be_bytes([packet.payload[0], packet.payload[1]])),
                    Some(u16::from_be_bytes([packet.payload[2], packet.payload[3]])),
                )
            }
            rios_ipv4::IpProtocol::Icmp if packet.payload.len() >= 6 => (
                Some(u16::from_be_bytes([packet.payload[4], packet.payload[5]])),
                None,
            ),
            _ => (None, None),
        };
        Self {
            source: packet.source,
            destination: packet.destination,
            source_selector,
            destination_selector,
        }
    }
}
impl Lab {
    pub(crate) fn trace_nat(
        &mut self,
        interface: InterfaceRef,
        before: NatTuple,
        packet: &rios_ipv4::Ipv4Packet,
    ) {
        let after = NatTuple::from(packet);
        if before != after
            && self
                .devices
                .get(&interface.device)
                .is_some_and(|d| d.debug_topics().contains(&DebugTopic::Nat))
        {
            self.push_debug(
                interface.device,
                DebugEvent::NatTranslation {
                    interface,
                    before,
                    after,
                },
            );
        }
    }
    pub(crate) fn packet_drop(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
        reason: DropReason,
    ) -> Result<(), LabError> {
        self.devices
            .get_mut(&interface.device)
            .ok_or(DropReason::NoLink)?
            .record_drop_reason(interface.interface, reason)?;
        self.trace_frame(interface, TraceAction::Drop(reason), frame);
        Ok(())
    }
    /// Format one structured event for any frontend, using stable lab/interface names.
    pub fn render_debug(&self, record: &DebugRecord) -> String {
        let device = self
            .devices
            .get(&record.device)
            .map(|d| d.hostname())
            .unwrap_or("?");
        match &record.event {
            DebugEvent::Packet {
                interface,
                action,
                protocol,
                length,
                summary,
            } => format!(
                "[{}] {} {action:?} {protocol:?} {length} bytes: {summary}\n",
                record.time,
                self.endpoint_name(*interface)
            ),
            event => format!("[{}] {device} {event:?}\n", record.time),
        }
    }
}
