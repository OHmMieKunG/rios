//! Bounded connected UDP endpoints for simulated applications and diagnostics.
use crate::Device;
use rios_ipv4::{IpProtocol, Ipv4Packet};
use rios_protocol::UdpDatagram;
use std::{
    collections::{BTreeMap, VecDeque},
    net::Ipv4Addr,
};

/// A connected UDP endpoint only accepts datagrams from its configured peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UdpSocket {
    pub local_address: Ipv4Addr,
    pub local_port: u16,
    pub remote_address: Ipv4Addr,
    pub remote_port: u16,
}
/// Rejected simulated UDP operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UdpError {
    #[error("invalid UDP endpoint")]
    Endpoint,
    #[error("UDP endpoint already exists")]
    Exists,
    #[error("UDP endpoint capacity exceeded")]
    Capacity,
    #[error("UDP endpoint does not exist")]
    Missing,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UdpRuntime {
    sockets: BTreeMap<UdpSocket, VecDeque<Vec<u8>>>,
}
impl Device {
    /// Bind a peer-filtered endpoint; at most 64 endpoints and four queued datagrams each.
    pub fn udp_open(&mut self, socket: UdpSocket) -> Result<(), UdpError> {
        if !self.owns_any_ipv4(socket.local_address)
            || socket.local_port == 0
            || socket.remote_port == 0
            || socket.remote_address.is_unspecified()
            || socket.remote_address.is_multicast()
            || socket.remote_address == Ipv4Addr::BROADCAST
            || matches!(socket.local_port, 67 | 68)
            || self
                .services()
                .iter()
                .any(|s| !s.is_tcp() && s.port() == socket.local_port)
        {
            return Err(UdpError::Endpoint);
        }
        if self.udp.sockets.contains_key(&socket) {
            return Err(UdpError::Exists);
        }
        if self.udp.sockets.len() >= 64 {
            return Err(UdpError::Capacity);
        }
        self.udp.sockets.insert(socket, VecDeque::new());
        Ok(())
    }
    /// Remove an application endpoint and its queued datagrams.
    pub fn udp_close(&mut self, socket: UdpSocket) {
        self.udp.sockets.remove(&socket);
    }
    /// Consume one actual locally delivered datagram.
    pub fn udp_read(&mut self, socket: UdpSocket) -> Result<Option<Vec<u8>>, UdpError> {
        Ok(self
            .udp
            .sockets
            .get_mut(&socket)
            .ok_or(UdpError::Missing)?
            .pop_front())
    }
    /// Observe endpoints without consuming data.
    pub fn udp_sockets(&self) -> impl Iterator<Item = (&UdpSocket, usize)> {
        self.udp
            .sockets
            .iter()
            .map(|(socket, queue)| (socket, queue.len()))
    }
    /// Deliver valid unicast UDP to an application or installed service.
    pub fn receive_udp(
        &mut self,
        packet: &Ipv4Packet,
        now: rios_simulator::SimTime,
    ) -> Option<Ipv4Packet> {
        if packet.protocol != IpProtocol::Udp || !self.owns_any_ipv4(packet.destination) {
            return None;
        }
        let datagram =
            UdpDatagram::decode_ipv4(packet.source, packet.destination, &packet.payload).ok()?;
        let socket = UdpSocket {
            local_address: packet.destination,
            local_port: datagram.destination_port,
            remote_address: packet.source,
            remote_port: datagram.source_port,
        };
        if let Some(queue) = self.udp.sockets.get_mut(&socket) {
            if queue.len() < 4 {
                queue.push_back(datagram.payload);
            }
            return None;
        }
        self.receive_service_udp(packet, now)
    }
}
