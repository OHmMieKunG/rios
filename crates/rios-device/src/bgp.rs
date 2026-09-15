//! BGP over the device's simulated TCP stack, with bounded sessions and received routes.
mod config;
mod display;
mod routes;
mod transport;
use crate::*;
use rios_config::{BgpConfig, BgpNeighborConfig};
use rios_ipv4::{Ipv4Network, Ipv4Packet, Route, RouteSource};
use rios_routing::*;
use rios_simulator::SimTime;
use std::{
    collections::{BTreeMap, VecDeque},
    net::Ipv4Addr,
};
const PEER_LIMIT: usize = 256;
const ROUTE_LIMIT: usize = 4096;
const RETRY_US: u64 = 30_000_000;
const TX_LIMIT: usize = 32;

/// Operational peer observation independent of CLI output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpNeighborInfo {
    pub address: Ipv4Addr,
    pub remote_as: u32,
    pub router_id: Option<Ipv4Addr>,
    pub state: BgpState,
    pub prefixes: usize,
    pub established_since: Option<SimTime>,
    pub last_error: Option<BgpError>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stream {
    fsm: BgpSession,
    input: BgpStream,
    output: VecDeque<Vec<u8>>,
    offset: usize,
    started: bool,
    closing: Option<SimTime>,
    advertised: BTreeMap<Ipv4Network, BgpAttributes>,
}
impl Stream {
    fn new(
        config: &BgpConfig,
        remote_as: u32,
        router_id: Ipv4Addr,
        now: SimTime,
    ) -> Result<Self, BgpError> {
        let mut fsm = BgpSession::new(config.local_as, remote_as, router_id, 180, now)?;
        fsm.tick(now);
        Ok(Self {
            fsm,
            input: BgpStream::default(),
            output: VecDeque::new(),
            offset: 0,
            started: false,
            closing: None,
            advertised: BTreeMap::new(),
        })
    }
    fn queue(&mut self, message: BgpMessage) -> Result<(), BgpError> {
        if self.output.len() >= TX_LIMIT {
            return Err(BgpError {
                code: 6,
                subcode: 8,
            });
        }
        self.output
            .push_back(message.encode(self.fsm.four_octet_as)?);
        Ok(())
    }
    fn fail(&mut self, error: BgpError, now: SimTime) {
        // Finish any partially written frame before the notification; TCP has no message boundaries.
        self.output.truncate(usize::from(self.offset > 0));
        let actions = self.fsm.protocol_error(error, now);
        for message in actions.messages {
            let _ = self.queue(message);
        }
        self.closing = Some(SimTime(now.0.saturating_add(5_000_000)));
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Peer {
    config: BgpNeighborConfig,
    streams: BTreeMap<TcpSocket, Stream>,
    selected: Option<TcpSocket>,
    received: BTreeMap<Ipv4Network, BgpAttributes>,
    retry_at: SimTime,
    state: BgpState,
    last_error: Option<BgpError>,
}
impl Peer {
    fn new(config: BgpNeighborConfig, now: SimTime) -> Self {
        Self {
            config,
            streams: BTreeMap::new(),
            selected: None,
            received: BTreeMap::new(),
            retry_at: now,
            state: BgpState::Idle,
            last_error: None,
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct BgpRuntime {
    local_as: Option<u32>,
    router_id: Option<Ipv4Addr>,
    listening: bool,
    peers: BTreeMap<Ipv4Addr, Peer>,
    next_port: u16,
    pub(super) routes: Vec<Route>,
    best: BTreeMap<Ipv4Network, BgpPath>,
}
impl Device {
    /// Whether configured or retiring BGP state needs simulator events.
    pub fn has_bgp(&self) -> bool {
        self.running_config.bgp.is_some() || self.bgp.listening || !self.bgp.peers.is_empty()
    }
    /// Observe live peer sessions without parsing display text.
    pub fn bgp_neighbors(&self) -> Vec<BgpNeighborInfo> {
        self.bgp
            .peers
            .iter()
            .map(|(address, p)| {
                let selected = p.selected.and_then(|s| p.streams.get(&s));
                BgpNeighborInfo {
                    address: *address,
                    remote_as: p.config.remote_as,
                    router_id: selected.and_then(|s| s.fsm.peer_router_id),
                    state: selected.map_or(p.state, |s| s.fsm.state),
                    prefixes: p.received.len(),
                    established_since: selected.and_then(|s| s.fsm.established_since),
                    last_error: p.last_error,
                }
            })
            .collect()
    }
    /// Selected IPv4 unicast paths, including locally originated networks.
    pub fn bgp_paths(&self) -> &BTreeMap<Ipv4Network, BgpPath> {
        &self.bgp.best
    }
    /// Next protocol deadline, bounded by one-second RIB maintenance.
    pub fn bgp_next_deadline(&self, now: SimTime) -> SimTime {
        let mut next = SimTime(now.0.saturating_add(1_000_000));
        let mut consider = |at: SimTime| {
            if at > now {
                next = next.min(at);
            }
        };
        for peer in self.bgp.peers.values() {
            if peer.streams.is_empty() {
                consider(peer.retry_at);
            }
            for stream in peer.streams.values() {
                if let Some(at) = stream.closing {
                    consider(at);
                } else if stream.started
                    && let Some(at) = stream.fsm.next_deadline()
                {
                    consider(at);
                }
            }
        }
        next
    }
    /// Protocol 179 transport policy, applied to initial packets and every TCP retransmission.
    pub fn bgp_transport_ttl(&self, destination: Ipv4Addr) -> Option<u8> {
        let config = self.running_config.bgp.as_ref()?;
        let peer = config.neighbors.get(&destination)?;
        Some(if peer.remote_as == config.local_as {
            255
        } else {
            1
        })
    }
    /// Reconcile configuration, TCP streams and route selection at virtual time.
    pub fn bgp_tick(&mut self, now: SimTime) -> Vec<Ipv4Packet> {
        let mut out = Vec::new();
        let config = self.running_config.bgp.clone();
        let id = config
            .as_ref()
            .and_then(|c| c.router_id)
            .or(self.bgp.router_id)
            .or_else(|| {
                let addresses = |loopbacks: bool| {
                    self.interfaces
                        .iter()
                        .filter(|(id, p)| {
                            self.protocol_up(**id)
                                && (!loopbacks || p.kind == InterfaceKind::Loopback)
                        })
                        .filter_map(|(id, _)| self.interface_ipv4(*id).map(|a| a.address()))
                        .max()
                };
                addresses(true).or_else(|| addresses(false))
            });
        let changed =
            self.bgp.local_as != config.as_ref().map(|c| c.local_as) || self.bgp.router_id != id;
        let mut peers = std::mem::take(&mut self.bgp.peers);
        if changed || config.is_none() {
            for peer in peers.values() {
                for socket in peer.streams.keys() {
                    if let Ok(packet) = self.tcp_abort(*socket) {
                        out.push(packet);
                    }
                }
            }
            peers.clear();
            self.bgp.routes.clear();
            self.bgp.best.clear();
        }
        self.bgp.local_as = config.as_ref().map(|c| c.local_as);
        self.bgp.router_id = id;
        let Some(config) = config else {
            if self.bgp.listening {
                self.tcp_unlisten(179);
                self.bgp.listening = false;
            }
            return out;
        };
        let Some(router_id) = id else {
            self.bgp.peers = peers;
            return out;
        };
        if self.tcp_listen(179).is_err() {
            self.bgp.peers = peers;
            return out;
        }
        self.bgp.listening = true;
        let removed: Vec<_> = peers
            .keys()
            .filter(|ip| !config.neighbors.contains_key(ip))
            .copied()
            .collect();
        for address in removed {
            if let Some(peer) = peers.remove(&address) {
                for socket in peer.streams.keys() {
                    if let Ok(packet) = self.tcp_abort(*socket) {
                        out.push(packet);
                    }
                }
            }
        }
        for (address, policy) in &config.neighbors {
            let peer = peers
                .entry(*address)
                .or_insert_with(|| Peer::new(policy.clone(), now));
            if peer.config.remote_as != policy.remote_as
                || peer.config.update_source != policy.update_source
            {
                for socket in peer.streams.keys() {
                    if let Ok(packet) = self.tcp_abort(*socket) {
                        out.push(packet);
                    }
                }
                *peer = Peer::new(policy.clone(), now);
            }
            peer.config = policy.clone();
            self.bgp_transport_peer(*address, peer, &config, router_id, now, &mut out);
        }
        // Unconfigured inbound connections on the BGP listener never become protocol neighbors.
        let unwanted: Vec<_> = self
            .tcp_connections()
            .keys()
            .filter(|s| s.local_port == 179 && !config.neighbors.contains_key(&s.remote_address))
            .copied()
            .collect();
        for socket in unwanted {
            if let Ok(packet) = self.tcp_abort(socket) {
                out.push(packet);
            }
        }
        self.bgp.peers = peers;
        self.bgp_recompute(&config, router_id);
        self.bgp_advertise(&config, router_id, now);
        let mut peers = std::mem::take(&mut self.bgp.peers);
        for peer in peers.values_mut() {
            let sockets: Vec<_> = peer.streams.keys().copied().collect();
            for socket in sockets {
                let Some(stream) = peer.streams.get_mut(&socket) else {
                    continue;
                };
                if !self.bgp_flush(socket, stream, now, &mut out) {
                    peer.streams.remove(&socket);
                    if peer.selected == Some(socket) {
                        peer.selected = None;
                        peer.received.clear();
                        peer.retry_at = SimTime(now.0.saturating_add(RETRY_US));
                    }
                }
            }
        }
        self.bgp.peers = peers;
        self.bgp_recompute(&config, router_id);
        out
    }
}
