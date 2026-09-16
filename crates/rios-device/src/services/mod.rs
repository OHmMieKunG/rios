//! Bounded host applications driven by simulated packet delivery and TCP timers.
mod http;
use crate::{Device, DeviceError, DeviceType, TcpSocket, TcpState};
use rios_config::ServiceConfig;
use rios_ipv4::{IpProtocol, Ipv4Packet};
use rios_protocol::UdpDatagram;
use rios_simulator::SimTime;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServiceRuntime {
    definitions: Vec<ServiceConfig>,
    streams: BTreeMap<TcpSocket, Stream>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Stream {
    input: Vec<u8>,
    output: VecDeque<u8>,
    close: bool,
}
impl Device {
    /// Installed lab applications; these are inventory, independent of saved IOS configuration.
    pub fn services(&self) -> &[ServiceConfig] {
        &self.services.definitions
    }

    /// Install a validated host service inventory before opening any application connections.
    pub fn set_services(&mut self, definitions: Vec<ServiceConfig>) -> Result<(), DeviceError> {
        if self.device_type() != DeviceType::Host || definitions.len() > 64 {
            return Err(DeviceError::InvalidServiceConfig);
        }
        let mut ports = BTreeSet::new();
        for service in &definitions {
            if service.port() == 0
                || matches!(service.port(), 67 | 68 | 179)
                || !ports.insert((service.is_tcp(), service.port()))
                || matches!(service, ServiceConfig::Http { body, .. } if body.len() > 32768)
            {
                return Err(DeviceError::InvalidServiceConfig);
            }
        }
        // Avoid changing the owner of an existing application stream or manual listener.
        if !self.tcp_connections().is_empty() || self.udp_sockets().next().is_some() {
            return Err(DeviceError::InvalidServiceConfig);
        }
        let mut listeners = self.tcp.listeners.clone();
        for service in &self.services.definitions {
            if service.is_tcp() {
                listeners.remove(&service.port());
            }
        }
        for service in &definitions {
            if service.is_tcp() && !listeners.insert(service.port()) {
                return Err(DeviceError::InvalidServiceConfig);
            }
        }
        if listeners.len() > 1024 {
            return Err(DeviceError::InvalidServiceConfig);
        }
        self.tcp.listeners = listeners;
        self.services.definitions = definitions;
        self.services.streams.clear();
        Ok(())
    }

    /// Generate a reply only for a valid, addressed UDP service request.
    pub fn receive_service_udp(&mut self, incoming: &Ipv4Packet) -> Option<Ipv4Packet> {
        if incoming.protocol != IpProtocol::Udp
            || !self.owns_any_ipv4(incoming.destination)
            || incoming.source.is_unspecified()
            || incoming.source.is_multicast()
            || incoming.source == std::net::Ipv4Addr::BROADCAST
        {
            return None;
        }
        let request =
            UdpDatagram::decode_ipv4(incoming.source, incoming.destination, &incoming.payload)
                .ok()?;
        if request.source_port == 0 {
            return None;
        }
        self.services.definitions.iter().find(|service| matches!(service, ServiceConfig::UdpEcho { port } if *port == request.destination_port))?;
        let reply = UdpDatagram {
            source_port: request.destination_port,
            destination_port: request.source_port,
            payload: request.payload,
        };
        Some(Ipv4Packet {
            dscp_ecn: 0,
            source: incoming.destination,
            destination: incoming.source,
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: reply
                .encode_ipv4(incoming.destination, incoming.source)
                .ok()?,
        })
    }

    /// Advance accepted application streams with explicit TCP backpressure.
    pub fn service_tcp_tick(&mut self, now: SimTime) -> Vec<Ipv4Packet> {
        self.services
            .streams
            .retain(|socket, _| self.tcp.connections.contains_key(socket));
        let sockets: Vec<_> = self
            .tcp_connections()
            .iter()
            .filter(|(_, c)| {
                c.is_passive() && matches!(c.state, TcpState::Established | TcpState::CloseWait)
            })
            .map(|(socket, c)| (*socket, c.state, c.received_len(), c.send_capacity()))
            .collect();
        let mut packets = Vec::new();
        for (socket, state, received, capacity) in sockets {
            let Some(service) = self
                .services
                .definitions
                .iter()
                .find(|s| s.is_tcp() && s.port() == socket.local_port)
                .cloned()
            else {
                continue;
            };
            let mut stream = self.services.streams.remove(&socket).unwrap_or_default();
            if !stream.close
                && stream.output.is_empty()
                && received > 0
                && let Ok((bytes, ack)) = self.tcp_read(socket)
            {
                packets.push(ack);
                match service {
                    ServiceConfig::TcpEcho { .. } => stream.output.extend(bytes),
                    ServiceConfig::Http { body, .. } => {
                        if stream.input.len().saturating_add(bytes.len()) > 8192 {
                            stream.input = vec![b'X'; 8193];
                        } else {
                            stream.input.extend(bytes);
                        }
                        if let Some(response) = http::response(&stream.input, &body) {
                            stream.output.extend(response);
                            stream.input.clear();
                            stream.close = true;
                        }
                    }
                    ServiceConfig::UdpEcho { .. } => {}
                }
            }
            if capacity > 0 && !stream.output.is_empty() {
                let length = capacity.min(stream.output.len());
                let bytes: Vec<_> = stream.output.iter().take(length).copied().collect();
                if let Ok(packet) = self.tcp_send(socket, &bytes, now) {
                    stream.output.drain(..length);
                    packets.push(packet);
                }
            } else if capacity > 0
                && (stream.close || state == TcpState::CloseWait)
                && let Ok(fin) = self.tcp_close(socket, now)
            {
                packets.push(fin);
            }
            self.services.streams.insert(socket, stream);
        }
        packets
    }
}
