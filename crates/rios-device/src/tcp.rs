//! Bounded deterministic TCP endpoints, independent of OS sockets and frontends.
use crate::Device;
use rios_ipv4::{IpProtocol, Ipv4Packet};
use rios_protocol::{TcpFlags as Flags, TcpSegment};
use rios_simulator::SimTime;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

const MAX_CONNECTIONS: usize = 1024;
const RECEIVE_LIMIT: usize = 65535;
const MAX_PAYLOAD: usize = 1200;
const IDLE_US: u64 = 300_000_000;
const TIME_WAIT_US: u64 = 120_000_000;

/// Local and remote transport endpoints identifying a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TcpSocket {
    pub local_address: Ipv4Addr,
    pub local_port: u16,
    pub remote_address: Ipv4Addr,
    pub remote_port: u16,
}
/// Observable TCP connection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait,
    CloseWait,
    LastAck,
    TimeWait,
}
/// Rejected TCP application operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TcpError {
    #[error(transparent)]
    Packet(#[from] rios_protocol::TcpPacketError),
    #[error("TCP connection does not exist")]
    Missing,
    #[error("TCP operation is invalid in this state")]
    State,
    #[error("TCP send is waiting for an acknowledgment or peer window")]
    Busy,
    #[error("TCP capacity exceeded or payload exceeds 1200 bytes")]
    Capacity,
    #[error("TCP ports must be nonzero and local address must be operational")]
    Endpoint,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Outstanding {
    segment: TcpSegment,
    deadline: SimTime,
    retries: u8,
}
/// One bounded stream. This initial stack sends one segment at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnection {
    pub state: TcpState,
    pub retransmissions: u64,
    send_next: u32,
    receive_next: u32,
    peer_window: u16,
    received: Vec<u8>,
    outstanding: Option<Outstanding>,
    last_activity: SimTime,
    time_wait_until: Option<SimTime>,
    peer_closed: bool,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TcpRuntime {
    connections: BTreeMap<TcpSocket, TcpConnection>,
    listeners: BTreeSet<u16>,
    next_sequence: u32,
}
impl TcpConnection {
    fn new(sequence: u32, now: SimTime) -> Self {
        Self {
            state: TcpState::Closed,
            retransmissions: 0,
            send_next: sequence,
            receive_next: 0,
            peer_window: 65535,
            received: Vec::new(),
            outstanding: None,
            last_activity: now,
            time_wait_until: None,
            peer_closed: false,
        }
    }
    fn segment(&self, socket: TcpSocket, flags: Flags, payload: Vec<u8>) -> TcpSegment {
        TcpSegment {
            source_port: socket.local_port,
            destination_port: socket.remote_port,
            sequence: self.send_next,
            acknowledgment: self.receive_next,
            flags,
            window: (RECEIVE_LIMIT - self.received.len()) as u16,
            options: Vec::new(),
            payload,
        }
    }
    fn send(
        &mut self,
        socket: TcpSocket,
        flags: Flags,
        payload: Vec<u8>,
        now: SimTime,
    ) -> TcpSegment {
        let segment = self.segment(socket, flags, payload);
        self.send_next = self.send_next.wrapping_add(segment.sequence_len());
        if segment.sequence_len() != 0 {
            self.outstanding = Some(Outstanding {
                segment: segment.clone(),
                deadline: SimTime(now.0.saturating_add(1_000_000)),
                retries: 0,
            });
        }
        self.last_activity = now;
        segment
    }
    fn enter_time_wait(&mut self, now: SimTime) {
        self.state = TcpState::TimeWait;
        self.time_wait_until = Some(SimTime(now.0.saturating_add(TIME_WAIT_US)));
    }
    fn receive(
        &mut self,
        socket: TcpSocket,
        segment: TcpSegment,
        now: SimTime,
    ) -> Option<TcpSegment> {
        if self.state == TcpState::Closed {
            return None;
        }
        if segment.flags.contains(Flags::RST) {
            let valid = if self.state == TcpState::SynSent {
                segment.flags.contains(Flags::ACK) && segment.acknowledgment == self.send_next
            } else {
                segment.sequence == self.receive_next
            };
            if valid {
                self.state = TcpState::Closed;
                self.outstanding = None;
            }
            return None;
        }
        if self.state == TcpState::SynSent {
            if segment.flags.contains(Flags::SYN | Flags::ACK)
                && segment.acknowledgment == self.send_next
            {
                self.receive_next = segment.sequence.wrapping_add(1);
                self.peer_window = segment.window;
                self.outstanding = None;
                self.state = TcpState::Established;
                self.last_activity = now;
                return Some(self.segment(socket, Flags::ACK, Vec::new()));
            }
            return None;
        }
        if self.state == TcpState::SynReceived
            && segment.flags.contains(Flags::SYN)
            && segment.sequence.wrapping_add(1) == self.receive_next
        {
            return self
                .outstanding
                .as_ref()
                .map(|pending| pending.segment.clone());
        }
        if segment.sequence != self.receive_next {
            return Some(self.segment(socket, Flags::ACK, Vec::new()));
        }
        if !segment.flags.contains(Flags::ACK) {
            return None;
        }
        if segment.acknowledgment == self.send_next {
            self.outstanding = None;
            if self.state == TcpState::SynReceived {
                self.state = TcpState::Established;
            }
            if self.state == TcpState::LastAck {
                self.state = TcpState::Closed;
                return None;
            }
            if self.state == TcpState::FinWait && self.peer_closed {
                self.enter_time_wait(now);
            }
        } else if self.state == TcpState::SynReceived {
            return None;
        }
        self.last_activity = now;
        self.peer_window = segment.window;
        if self.state == TcpState::TimeWait {
            return Some(self.segment(socket, Flags::ACK, Vec::new()));
        }
        if self.peer_closed {
            return None;
        }
        if self.received.len().saturating_add(segment.payload.len()) > RECEIVE_LIMIT {
            return Some(self.segment(socket, Flags::ACK, Vec::new()));
        }
        self.receive_next = self.receive_next.wrapping_add(segment.payload.len() as u32);
        let data = !segment.payload.is_empty();
        self.received.extend_from_slice(&segment.payload);
        let fin = segment.flags.contains(Flags::FIN);
        if fin {
            self.receive_next = self.receive_next.wrapping_add(1);
            self.peer_closed = true;
            if self.state == TcpState::FinWait {
                if self.outstanding.is_none() {
                    self.enter_time_wait(now);
                }
            } else {
                self.state = TcpState::CloseWait;
            }
        }
        (data || fin).then(|| self.segment(socket, Flags::ACK, Vec::new()))
    }
}
fn packet(socket: TcpSocket, segment: TcpSegment) -> Result<Ipv4Packet, TcpError> {
    // Constructed segments always have bounded payloads and no unsupported options.
    Ok(Ipv4Packet {
        source: socket.local_address,
        destination: socket.remote_address,
        ttl: 64,
        protocol: IpProtocol::Tcp,
        payload: segment.encode(socket.local_address, socket.remote_address)?,
    })
}
impl Device {
    /// Open a simulated listener; never creates a host OS socket.
    pub fn tcp_listen(&mut self, port: u16) -> Result<(), TcpError> {
        if port == 0 {
            return Err(TcpError::Endpoint);
        }
        if self.tcp.listeners.len() >= 1024 && !self.tcp.listeners.contains(&port) {
            return Err(TcpError::Capacity);
        }
        self.tcp.listeners.insert(port);
        Ok(())
    }
    /// Read-only connection state for services and diagnostics.
    pub fn tcp_connections(&self) -> &BTreeMap<TcpSocket, TcpConnection> {
        &self.tcp.connections
    }
    fn tcp_initial_sequence(&mut self) -> u32 {
        self.tcp.next_sequence = self.tcp.next_sequence.wrapping_add(64000);
        self.tcp.next_sequence
    }
    /// Begin an active open and return its SYN for normal IPv4 transmission.
    pub fn tcp_connect(&mut self, socket: TcpSocket, now: SimTime) -> Result<Ipv4Packet, TcpError> {
        if socket.local_port == 0
            || socket.remote_port == 0
            || !self.owns_any_ipv4(socket.local_address)
            || socket.remote_address.is_unspecified()
            || socket.remote_address.is_multicast()
            || socket.remote_address == Ipv4Addr::BROADCAST
        {
            return Err(TcpError::Endpoint);
        }
        if self.tcp.connections.contains_key(&socket) {
            return Err(TcpError::State);
        }
        if self.tcp.connections.len() >= MAX_CONNECTIONS {
            return Err(TcpError::Capacity);
        }
        let mut connection = TcpConnection::new(self.tcp_initial_sequence(), now);
        connection.state = TcpState::SynSent;
        let syn = connection.send(socket, Flags::SYN, Vec::new(), now);
        self.tcp.connections.insert(socket, connection);
        packet(socket, syn)
    }
    /// Send one segment with backpressure until acknowledged; applications retain unsent bytes.
    pub fn tcp_send(
        &mut self,
        socket: TcpSocket,
        payload: &[u8],
        now: SimTime,
    ) -> Result<Ipv4Packet, TcpError> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(TcpError::Capacity);
        }
        let connection = self
            .tcp
            .connections
            .get_mut(&socket)
            .ok_or(TcpError::Missing)?;
        if !matches!(
            connection.state,
            TcpState::Established | TcpState::CloseWait
        ) {
            return Err(TcpError::State);
        }
        if connection.outstanding.is_some() || payload.len() > usize::from(connection.peer_window) {
            return Err(TcpError::Busy);
        }
        packet(
            socket,
            connection.send(socket, Flags::ACK | Flags::PSH, payload.to_vec(), now),
        )
    }
    /// Initiate a FIN exchange once pending data is acknowledged.
    pub fn tcp_close(&mut self, socket: TcpSocket, now: SimTime) -> Result<Ipv4Packet, TcpError> {
        let connection = self
            .tcp
            .connections
            .get_mut(&socket)
            .ok_or(TcpError::Missing)?;
        if connection.outstanding.is_some() {
            return Err(TcpError::Busy);
        }
        connection.state = match connection.state {
            TcpState::Established => TcpState::FinWait,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return Err(TcpError::State),
        };
        packet(
            socket,
            connection.send(socket, Flags::ACK | Flags::FIN, Vec::new(), now),
        )
    }
    /// Drain received bytes and return a window update for the peer.
    pub fn tcp_read(&mut self, socket: TcpSocket) -> Result<(Vec<u8>, Ipv4Packet), TcpError> {
        let connection = self
            .tcp
            .connections
            .get_mut(&socket)
            .ok_or(TcpError::Missing)?;
        let data = std::mem::take(&mut connection.received);
        Ok((
            data,
            packet(socket, connection.segment(socket, Flags::ACK, Vec::new()))?,
        ))
    }
    /// Process an addressed TCP packet and return at most one response.
    pub fn receive_tcp(&mut self, incoming: &Ipv4Packet, now: SimTime) -> Option<Ipv4Packet> {
        if incoming.protocol != IpProtocol::Tcp || !self.owns_any_ipv4(incoming.destination) {
            return None;
        }
        let segment =
            TcpSegment::decode(incoming.source, incoming.destination, &incoming.payload).ok()?;
        let socket = TcpSocket {
            local_address: incoming.destination,
            local_port: segment.destination_port,
            remote_address: incoming.source,
            remote_port: segment.source_port,
        };
        if let Some(connection) = self.tcp.connections.get_mut(&socket) {
            return connection
                .receive(socket, segment, now)
                .and_then(|segment| packet(socket, segment).ok());
        }
        if segment.flags.contains(Flags::RST) {
            return None;
        }
        if segment.flags == Flags::SYN
            && self.tcp.listeners.contains(&socket.local_port)
            && self.tcp.connections.len() < MAX_CONNECTIONS
        {
            let mut connection = TcpConnection::new(self.tcp_initial_sequence(), now);
            connection.state = TcpState::SynReceived;
            connection.receive_next = segment.sequence.wrapping_add(1);
            connection.peer_window = segment.window;
            let reply = connection.send(socket, Flags::SYN | Flags::ACK, Vec::new(), now);
            self.tcp.connections.insert(socket, connection);
            return packet(socket, reply).ok();
        }
        let mut reset = TcpConnection::new(0, now).segment(socket, Flags::RST, Vec::new());
        if segment.flags.contains(Flags::ACK) {
            reset.sequence = segment.acknowledgment;
        } else {
            reset.flags = Flags::RST | Flags::ACK;
            reset.acknowledgment = segment.sequence.wrapping_add(segment.sequence_len());
        }
        packet(socket, reset).ok()
    }
    /// Expire inactive streams and retransmit outstanding segments on virtual time.
    pub fn tcp_tick(&mut self, now: SimTime) -> Vec<Ipv4Packet> {
        let mut outgoing = Vec::new();
        self.tcp.connections.retain(|_, connection| {
            connection.state != TcpState::Closed
                && now.0.saturating_sub(connection.last_activity.0) < IDLE_US
                && connection
                    .time_wait_until
                    .is_none_or(|deadline| deadline > now)
        });
        for (socket, connection) in &mut self.tcp.connections {
            if let Some(pending) = &mut connection.outstanding
                && pending.deadline <= now
            {
                if pending.retries >= 5 {
                    connection.state = TcpState::Closed;
                    continue;
                }
                pending.retries += 1;
                pending.deadline = SimTime(now.0.saturating_add(1_000_000 << pending.retries));
                connection.retransmissions += 1;
                if let Ok(packet) = packet(*socket, pending.segment.clone()) {
                    outgoing.push(packet);
                }
            }
        }
        outgoing
    }
}
