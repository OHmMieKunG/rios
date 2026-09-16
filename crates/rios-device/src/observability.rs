//! Bounded packet accounting and debug selectors, independent of terminal frontends.
use crate::Device;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};
/// Independently selectable simulator debug topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DebugTopic {
    Packet,
    Arp,
    Icmp,
    IpPacket,
    IpRouting,
    Dhcp,
    OspfPacket,
    OspfAdjacency,
    SpanningTree,
    Lacp,
    Nat,
    Bgp,
}
/// Packet classification for counters and filtering; never changes forwarding decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketProtocol {
    Ethernet,
    Arp,
    Ipv4,
    Icmp,
    Udp,
    Tcp,
    Dhcp,
    Dns,
    Ntp,
    Ospf,
    Bgp,
    Stp,
    Lacp,
    Ipv6,
    Icmpv6,
    Malformed,
}
/// Interface-boundary protocol counters; packet drops remain separately attributed by reason.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolCounters {
    pub received: u64,
    pub transmitted: u64,
    pub dropped: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Observability {
    topics: BTreeSet<DebugTopic>,
    counters: BTreeMap<PacketProtocol, ProtocolCounters>,
}
impl DebugTopic {
    /// Whether a packet class belongs to this topic; state-only topics return false.
    pub fn matches(self, protocol: PacketProtocol) -> bool {
        use PacketProtocol as P;
        match self {
            Self::Packet => true,
            Self::Arp => protocol == P::Arp,
            Self::Icmp => matches!(protocol, P::Icmp | P::Icmpv6),
            Self::IpPacket => matches!(
                protocol,
                P::Ipv4
                    | P::Icmp
                    | P::Udp
                    | P::Tcp
                    | P::Dhcp
                    | P::Dns
                    | P::Ntp
                    | P::Ospf
                    | P::Bgp
                    | P::Ipv6
                    | P::Icmpv6
            ),
            Self::Dhcp => protocol == P::Dhcp,
            Self::OspfPacket => protocol == P::Ospf,
            Self::SpanningTree => protocol == P::Stp,
            Self::Lacp => protocol == P::Lacp,
            Self::Bgp => protocol == P::Bgp,
            Self::IpRouting | Self::OspfAdjacency | Self::Nat => false,
        }
    }
}
impl Device {
    /// Current VLAN-scoped STP roles/states without timer mutation or CLI scraping.
    pub fn stp_port_states(
        &self,
    ) -> impl Iterator<
        Item = (
            rios_config::VlanId,
            rios_simulator::InterfaceId,
            rios_switching::StpPortRole,
            rios_switching::StpPortState,
        ),
    > + '_ {
        self.stp_runtime.iter().flat_map(|(vlan, instance)| {
            instance
                .ports
                .iter()
                .map(move |(port, (role, state))| (*vlan, *port, *role, *state))
        })
    }

    /// Enable/disable runtime debugging without changing structured running configuration.
    pub fn set_debug(&mut self, topic: DebugTopic, enabled: bool) {
        if enabled {
            self.observability.topics.insert(topic);
        } else {
            self.observability.topics.remove(&topic);
        }
    }
    /// Stop all device debugging.
    pub fn undebug_all(&mut self) {
        self.observability.topics.clear();
    }
    /// Read enabled topics without affecting protocol state.
    pub fn debug_topics(&self) -> &BTreeSet<DebugTopic> {
        &self.observability.topics
    }
    /// Read bounded per-protocol counters.
    pub fn protocol_counters(&self) -> &BTreeMap<PacketProtocol, ProtocolCounters> {
        &self.observability.counters
    }
    /// Account one boundary observation; None means a drop, true TX, false RX.
    pub fn record_protocol(
        &mut self,
        protocol: PacketProtocol,
        transmit: Option<bool>,
        bytes: usize,
    ) {
        let counters = self.observability.counters.entry(protocol).or_default();
        match transmit {
            Some(true) => {
                counters.transmitted = counters.transmitted.saturating_add(1);
                counters.tx_bytes = counters.tx_bytes.saturating_add(bytes as u64);
            }
            Some(false) => {
                counters.received = counters.received.saturating_add(1);
                counters.rx_bytes = counters.rx_bytes.saturating_add(bytes as u64);
            }
            None => counters.dropped = counters.dropped.saturating_add(1),
        }
    }
    /// Render actual protocol counters for the shared CLI.
    pub fn show_protocol_counters(&self) -> String {
        let mut out = String::from(
            "Protocol       RX packets   TX packets        Drops     RX bytes     TX bytes\n",
        );
        for (protocol, count) in self.protocol_counters() {
            let _ = writeln!(
                out,
                "{protocol:?}: {:>12} {:>12} {:>12} {:>12} {:>12}",
                count.received, count.transmitted, count.dropped, count.rx_bytes, count.tx_bytes
            );
        }
        out
    }
    /// Render enabled runtime selectors.
    pub fn show_debugging(&self) -> String {
        if self.debug_topics().is_empty() {
            return "All debugging is disabled.\n".into();
        }
        self.debug_topics()
            .iter()
            .map(|topic| format!("{topic:?} debugging is enabled.\n"))
            .collect()
    }
}
