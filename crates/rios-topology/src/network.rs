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
use rios_routing::{OSPF_ALL_ROUTERS, OspfPacket};
use rios_simulator::DeviceId;
use std::{fmt::Write, net::Ipv4Addr};

const PING_COUNT: u16 = 5;
const PING_TIMEOUT_MS: u64 = 1_000;
const DHCP_RETRY_MS: u64 = 4_000;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// A completed deterministic ping operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResult {
    /// Requested destination.
    pub destination: Ipv4Addr,
    /// Echo requests attempted.
    pub transmitted: u16,
    /// Matching replies received.
    pub received: u16,
    /// Virtual round-trip duration for each reply.
    pub round_trip_ms: Vec<u64>,
    markers: String,
}

impl PingResult {
    /// Familiar IOS-style summary generated from actual echo replies.
    pub fn render(&self) -> String {
        let mut output = format!(
            "Type escape sequence to abort.\nSending {} ICMP Echos to {}, timeout is 1 second:\n",
            self.transmitted, self.destination
        );
        output.push_str(&self.markers);
        let success = if self.transmitted == 0 {
            0
        } else {
            u32::from(self.received) * 100 / u32::from(self.transmitted)
        };
        write!(
            output,
            "\nSuccess rate is {} percent ({}/{}), round-trip min/avg/max = ",
            success, self.received, self.transmitted
        )
        .unwrap();
        if self.round_trip_ms.is_empty() {
            output.push_str("n/a\n");
        } else {
            let min = self.round_trip_ms.iter().min().unwrap();
            let max = self.round_trip_ms.iter().max().unwrap();
            let average = self.round_trip_ms.iter().sum::<u64>() / self.round_trip_ms.len() as u64;
            writeln!(output, "{min}/{average}/{max} ms").unwrap();
        }
        output
    }
}

/// Ping setup failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PingError {
    #[error("no route to {0}")]
    NoRoute(Ipv4Addr),
    #[error("simulation time overflow")]
    TimeOverflow,
}

impl Lab {
    /// Send five echo requests, driving only virtual events until replies or timeouts.
    pub fn ping(
        &mut self,
        source_device: DeviceId,
        destination: Ipv4Addr,
    ) -> Result<PingResult, LabError> {
        self.ping_with_ttl(source_device, destination, 64)
    }

    /// Send five echo requests with an explicit initial TTL.
    pub fn ping_with_ttl(
        &mut self,
        source_device: DeviceId,
        destination: Ipv4Addr,
        ttl: u8,
    ) -> Result<PingResult, LabError> {
        let route = self
            .device(source_device)?
            .resolve_route(destination)
            .ok_or(PingError::NoRoute(destination))?;
        let identifier = self.next_ping_id;
        self.next_ping_id = self.next_ping_id.wrapping_add(1);
        let mut result = PingResult {
            destination,
            transmitted: PING_COUNT,
            received: 0,
            round_trip_ms: Vec::new(),
            markers: String::new(),
        };

        if route.source_ip == destination {
            result.received = PING_COUNT;
            result.round_trip_ms = vec![0; usize::from(PING_COUNT)];
            result.markers = "!".repeat(usize::from(PING_COUNT));
            return Ok(result);
        }

        for sequence in 0..PING_COUNT {
            let deadline = SimTime(
                self.now()
                    .0
                    .checked_add(PING_TIMEOUT_MS * 1000)
                    .ok_or(PingError::TimeOverflow)?,
            );
            if self
                .ensure_neighbor(source_device, route, deadline)?
                .is_none()
            {
                result.markers.push('.');
                continue;
            }

            let sent_at = self.now();
            let echo = IcmpEcho {
                kind: IcmpKind::EchoRequest,
                identifier,
                sequence,
                payload: vec![0; 32],
            };
            let packet = Ipv4Packet {
                source: route.source_ip,
                destination,
                ttl,
                protocol: IpProtocol::Icmp,
                payload: echo.encode(),
            };
            self.send_ipv4_packet(source_device, packet)?;
            let signal = self.drive_until(deadline, |_, outcome| {
                let EventOutcome::FrameReceived { interface, frame } = outcome else {
                    return None;
                };
                if interface.device != source_device {
                    return None;
                }
                decode_ping_signal(frame, identifier, sequence, route.source_ip)
            })?;
            match signal {
                Some(PingSignal::Reply) => {
                    result.received += 1;
                    result.round_trip_ms.push((self.now().0 - sent_at.0) / 1000);
                    result.markers.push('!');
                }
                Some(PingSignal::Unreachable) => result.markers.push('U'),
                Some(PingSignal::TimeExceeded) => result.markers.push('T'),
                None => result.markers.push('.'),
            }
        }
        Ok(result)
    }

    fn drive_until<T>(
        &mut self,
        deadline: SimTime,
        mut done: impl FnMut(&mut Self, &EventOutcome) -> Option<T>,
    ) -> Result<Option<T>, LabError> {
        while self.next_event_time().is_some_and(|time| time <= deadline) {
            let Some(outcome) = self.step()? else {
                continue;
            };
            if let Some(value) = done(self, &outcome) {
                return Ok(Some(value));
            }
        }
        self.events.advance_to(deadline)?;
        self.purge_pending();
        Ok(None)
    }

    fn ensure_neighbor(
        &mut self,
        device: DeviceId,
        route: ResolvedRoute,
        deadline: SimTime,
    ) -> Result<Option<MacAddress>, LabError> {
        let now = self.now();
        if let Some(entry) = self
            .devices
            .get_mut(&device)
            .unwrap()
            .arp_lookup(route.next_hop, now)
            && entry.interface == route.interface
        {
            return Ok(Some(entry.mac_address));
        }
        let source = InterfaceRef {
            device,
            interface: route.interface,
        };
        self.send_arp_request(source, route)?;
        self.drive_until(deadline, |lab, _| {
            let now = lab.now();
            lab.devices
                .get_mut(&device)
                .and_then(|device| device.arp_lookup(route.next_hop, now))
                .filter(|entry| entry.interface == route.interface)
                .map(|entry| entry.mac_address)
        })
    }

    fn send_arp_request(
        &mut self,
        source: InterfaceRef,
        route: ResolvedRoute,
    ) -> Result<(), LabError> {
        let request = ArpPacket {
            operation: ArpOperation::Request,
            sender_mac: route.source_mac,
            sender_ip: route.source_ip,
            target_mac: MacAddress([0; 6]),
            target_ip: route.next_hop,
        };
        self.transmit_network_frame(
            source,
            EthernetFrame {
                destination: MacAddress::BROADCAST,
                source: route.source_mac,
                ethertype: EtherType::Arp,
                payload: request.encode(),
            },
        )
    }

    fn send_ipv4_packet(&mut self, device: DeviceId, packet: Ipv4Packet) -> Result<bool, LabError> {
        let Some(route) = self.device(device)?.resolve_route(packet.destination) else {
            return Ok(false);
        };
        let source = InterfaceRef {
            device,
            interface: route.interface,
        };
        let now = self.now();
        let neighbor = self
            .devices
            .get_mut(&device)
            .unwrap()
            .arp_lookup(route.next_hop, now)
            .filter(|entry| entry.interface == route.interface);
        if let Some(neighbor) = neighbor {
            self.transmit_ipv4(source, route.source_mac, neighbor.mac_address, packet)?;
            return Ok(true);
        }

        let request_needed = !self
            .pending_ipv4
            .iter()
            .any(|pending| pending.source == source && pending.next_hop == route.next_hop);
        self.pending_ipv4.push(PendingIpv4 {
            source,
            next_hop: route.next_hop,
            packet,
            expires_at: SimTime(now.0.saturating_add(PING_TIMEOUT_MS * 1000)),
        });
        if request_needed {
            self.send_arp_request(source, route)?;
        }
        Ok(true)
    }

    fn transmit_ipv4(
        &mut self,
        source: InterfaceRef,
        source_mac: MacAddress,
        destination_mac: MacAddress,
        packet: Ipv4Packet,
    ) -> Result<(), LabError> {
        let frame = EthernetFrame {
            destination: destination_mac,
            source: source_mac,
            ethertype: EtherType::Ipv4,
            payload: packet
                .encode()
                .map_err(|error| LabError::Protocol(error.to_string()))?,
        };
        if !self.device(source.device)?.permits_ipv4(
            source.interface,
            AccessListDirection::Out,
            &packet,
        ) {
            self.devices
                .get_mut(&source.device)
                .unwrap()
                .record_drop(source.interface)?;
            self.trace_frame(source, TraceAction::Drop(DropReason::AccessList), &frame);
            return Ok(());
        }
        self.transmit_network_frame(source, frame)
    }

    fn flush_pending(
        &mut self,
        device: DeviceId,
        interface: InterfaceRef,
        next_hop: Ipv4Addr,
        destination_mac: MacAddress,
    ) -> Result<(), LabError> {
        let source_mac = self.device(device)?.interfaces()[&interface.interface].mac_address;
        let pending = std::mem::take(&mut self.pending_ipv4);
        for item in pending {
            if item.source == interface
                && item.next_hop == next_hop
                && item.expires_at >= self.now()
            {
                self.transmit_ipv4(interface, source_mac, destination_mac, item.packet)?;
            } else if item.expires_at >= self.now() {
                self.pending_ipv4.push(item);
            }
        }
        Ok(())
    }

    pub(crate) fn purge_pending(&mut self) {
        let now = self.now();
        // ponytail: linear queue is sufficient until concurrent unresolved flows are measured in bulk.
        self.pending_ipv4.retain(|packet| packet.expires_at >= now);
    }

    pub(crate) fn handle_protocol_frame(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<(), LabError> {
        match frame.ethertype {
            EtherType::Arp => self.handle_arp(interface, frame),
            EtherType::Ipv4 => self.handle_ipv4(interface, frame),
            _ => Ok(()),
        }
    }

    fn handle_arp(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<(), LabError> {
        let Ok(packet) = ArpPacket::decode(&frame.payload) else {
            return Ok(());
        };
        if packet.sender_mac != frame.source
            || packet.sender_mac.is_multicast()
            || packet.sender_ip.is_unspecified()
        {
            return Ok(());
        }
        if !self
            .device(interface.device)?
            .owns_ipv4(interface.interface, packet.target_ip)
        {
            return Ok(());
        }
        let now = self.now();
        self.devices.get_mut(&interface.device).unwrap().learn_arp(
            packet.sender_ip,
            packet.sender_mac,
            interface.interface,
            now,
        )?;
        if packet.operation == ArpOperation::Request {
            let local_mac =
                self.device(interface.device)?.interfaces()[&interface.interface].mac_address;
            let reply = ArpPacket {
                operation: ArpOperation::Reply,
                sender_mac: local_mac,
                sender_ip: packet.target_ip,
                target_mac: packet.sender_mac,
                target_ip: packet.sender_ip,
            };
            self.transmit_network_frame(
                interface,
                EthernetFrame {
                    destination: packet.sender_mac,
                    source: local_mac,
                    ethertype: EtherType::Arp,
                    payload: reply.encode(),
                },
            )?;
        }
        self.flush_pending(
            interface.device,
            interface,
            packet.sender_ip,
            packet.sender_mac,
        )?;
        Ok(())
    }

    fn handle_ipv4(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<(), LabError> {
        let Ok(mut packet) = Ipv4Packet::decode(&frame.payload) else {
            return Ok(());
        };
        if !self.device(interface.device)?.permits_ipv4(
            interface.interface,
            AccessListDirection::In,
            &packet,
        ) {
            self.devices
                .get_mut(&interface.device)
                .unwrap()
                .record_drop(interface.interface)?;
            self.trace_frame(interface, TraceAction::Drop(DropReason::AccessList), frame);
            return Ok(());
        }
        if packet.protocol == IpProtocol::Udp
            && let Ok(datagram) = UdpDatagram::decode(&packet.payload)
            && matches!(
                (datagram.source_port, datagram.destination_port),
                (DHCP_CLIENT_PORT, DHCP_SERVER_PORT) | (DHCP_SERVER_PORT, DHCP_CLIENT_PORT)
            )
        {
            self.handle_dhcp(interface, datagram)?;
            return Ok(());
        }
        if packet.protocol == IpProtocol::Ospf && packet.destination == OSPF_ALL_ROUTERS {
            return self.handle_ospf(interface, packet);
        }
        if self.device(interface.device)?.ipv4_forwarding_enabled() {
            let now = self.now();
            self.devices
                .get_mut(&interface.device)
                .unwrap()
                .translate_nat_inbound(interface.interface, &mut packet, now);
        }
        if self
            .device(interface.device)?
            .owns_any_ipv4(packet.destination)
        {
            return self.handle_local_ipv4(interface.device, packet);
        }
        if !self.device(interface.device)?.ipv4_forwarding_enabled() {
            return Ok(());
        }
        if packet.ttl <= 1 {
            return self.send_icmp_error(interface.device, &packet, IcmpErrorKind::TimeExceeded);
        }
        let Some(route) = self
            .device(interface.device)?
            .resolve_route(packet.destination)
        else {
            return self.send_icmp_error(
                interface.device,
                &packet,
                IcmpErrorKind::DestinationUnreachable,
            );
        };
        let mut forwarded = packet;
        let now = self.now();
        self.devices
            .get_mut(&interface.device)
            .unwrap()
            .translate_nat_outbound(interface.interface, route.interface, &mut forwarded, now);
        forwarded.ttl -= 1;
        self.send_ipv4_packet(interface.device, forwarded)?;
        Ok(())
    }

    pub(crate) fn send_dhcp_discovers(
        &mut self,
        device: DeviceId,
        generation: u64,
    ) -> Result<(), LabError> {
        if self.dhcp_generations.get(&device) != Some(&generation) {
            return Ok(());
        }
        for interface in self.device(device)?.dhcp_client_interfaces() {
            self.next_dhcp_xid = self.next_dhcp_xid.wrapping_add(1).max(1);
            let endpoint = InterfaceRef { device, interface };
            let client_mac = self.device(device)?.interfaces()[&interface].mac_address;
            self.dhcp_transactions.insert(endpoint, self.next_dhcp_xid);
            self.send_dhcp_message(
                endpoint,
                Ipv4Addr::UNSPECIFIED,
                DHCP_CLIENT_PORT,
                DHCP_SERVER_PORT,
                DhcpMessage {
                    message_type: DhcpMessageType::Discover,
                    transaction_id: self.next_dhcp_xid,
                    client_mac,
                    your_ip: Ipv4Addr::UNSPECIFIED,
                    requested_ip: None,
                    server_id: None,
                    subnet_mask: None,
                    default_router: None,
                    lease_time_seconds: None,
                },
            )?;
        }
        if self.device(device)?.has_pending_dhcp_client() {
            self.events.schedule_after(
                DHCP_RETRY_MS,
                SimulationEvent::DhcpClient { device, generation },
            )?;
        }
        Ok(())
    }

    fn handle_dhcp(
        &mut self,
        interface: InterfaceRef,
        datagram: UdpDatagram,
    ) -> Result<(), LabError> {
        let Ok(message) = DhcpMessage::decode(&datagram.payload) else {
            return Ok(());
        };
        match message.message_type {
            DhcpMessageType::Discover => {
                let now = self.now();
                let Some(offer) = self.devices.get_mut(&interface.device).unwrap().offer_dhcp(
                    interface.interface,
                    message.client_mac,
                    now,
                ) else {
                    return Ok(());
                };
                self.send_dhcp_message(
                    interface,
                    offer.server_id,
                    DHCP_SERVER_PORT,
                    DHCP_CLIENT_PORT,
                    dhcp_response(DhcpMessageType::Offer, message, offer),
                )?;
            }
            DhcpMessageType::Offer => {
                if self.dhcp_transactions.get(&interface) != Some(&message.transaction_id)
                    || self.device(interface.device)?.interfaces()[&interface.interface].mac_address
                        != message.client_mac
                    || message.server_id.is_none()
                {
                    return Ok(());
                }
                self.send_dhcp_message(
                    interface,
                    Ipv4Addr::UNSPECIFIED,
                    DHCP_CLIENT_PORT,
                    DHCP_SERVER_PORT,
                    DhcpMessage {
                        message_type: DhcpMessageType::Request,
                        transaction_id: message.transaction_id,
                        client_mac: message.client_mac,
                        your_ip: Ipv4Addr::UNSPECIFIED,
                        requested_ip: Some(message.your_ip),
                        server_id: message.server_id,
                        subnet_mask: None,
                        default_router: None,
                        lease_time_seconds: None,
                    },
                )?;
            }
            DhcpMessageType::Request => {
                let (Some(address), Some(server_id)) = (message.requested_ip, message.server_id)
                else {
                    return Ok(());
                };
                let now = self.now();
                let Some(offer) = self
                    .devices
                    .get_mut(&interface.device)
                    .unwrap()
                    .commit_dhcp(message.client_mac, address, server_id, now)
                else {
                    return Ok(());
                };
                self.send_dhcp_message(
                    interface,
                    offer.server_id,
                    DHCP_SERVER_PORT,
                    DHCP_CLIENT_PORT,
                    dhcp_response(DhcpMessageType::Ack, message, offer),
                )?;
            }
            DhcpMessageType::Ack => {
                if self.dhcp_transactions.get(&interface) != Some(&message.transaction_id)
                    || self.device(interface.device)?.interfaces()[&interface.interface].mac_address
                        != message.client_mac
                {
                    return Ok(());
                }
                let (Some(mask), Some(server_id), Some(seconds)) = (
                    message.subnet_mask,
                    message.server_id,
                    message.lease_time_seconds,
                ) else {
                    return Ok(());
                };
                let prefix_len = rios_ipv4::Ipv4InterfaceConfig::from_mask(message.your_ip, mask)
                    .map_err(|error| LabError::Protocol(error.to_string()))?
                    .prefix_len();
                let deadline = SimTime(
                    self.now()
                        .0
                        .saturating_add(u64::from(seconds).saturating_mul(1_000_000)),
                );
                self.devices
                    .get_mut(&interface.device)
                    .unwrap()
                    .install_dhcp_lease(
                        interface.interface,
                        DhcpLease {
                            address: message.your_ip,
                            prefix_len,
                            default_router: message.default_router,
                            server_id,
                            expires_at: deadline,
                        },
                    )?;
                self.dhcp_transactions.remove(&interface);
                self.events.schedule_at(
                    deadline,
                    SimulationEvent::DhcpLeaseExpired {
                        device: interface.device,
                        interface: interface.interface,
                        address: message.your_ip,
                        deadline,
                    },
                )?;
            }
        }
        Ok(())
    }

    fn send_dhcp_message(
        &mut self,
        interface: InterfaceRef,
        source_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        message: DhcpMessage,
    ) -> Result<(), LabError> {
        let source_mac =
            self.device(interface.device)?.interfaces()[&interface.interface].mac_address;
        let datagram = UdpDatagram {
            source_port,
            destination_port,
            payload: message.encode(),
        };
        let packet = Ipv4Packet {
            source: source_ip,
            destination: Ipv4Addr::BROADCAST,
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: datagram
                .encode()
                .map_err(|error| LabError::Protocol(error.to_string()))?,
        };
        self.transmit_ipv4(interface, source_mac, MacAddress::BROADCAST, packet)
    }

    fn handle_ospf(&mut self, interface: InterfaceRef, packet: Ipv4Packet) -> Result<(), LabError> {
        let Ok(ospf) = OspfPacket::decode(&packet.payload) else {
            return Ok(());
        };
        let now = self.now();
        if let Some((router_id, deadline, changed)) = self
            .devices
            .get_mut(&interface.device)
            .unwrap()
            .receive_ospf(interface.interface, packet.source, ospf, now)
        {
            self.events.schedule_at(
                deadline,
                SimulationEvent::OspfDead {
                    device: interface.device,
                    router_id,
                    deadline,
                },
            )?;
            if changed {
                self.schedule_ospf_now(interface.device)?;
            }
        }
        Ok(())
    }

    fn handle_local_ipv4(&mut self, device: DeviceId, packet: Ipv4Packet) -> Result<(), LabError> {
        if packet.protocol != IpProtocol::Icmp {
            return Ok(());
        }
        let Ok(echo) = IcmpEcho::decode(&packet.payload) else {
            return Ok(());
        };
        if echo.kind != IcmpKind::EchoRequest {
            return Ok(());
        }
        let reply = IcmpEcho {
            kind: IcmpKind::EchoReply,
            identifier: echo.identifier,
            sequence: echo.sequence,
            payload: echo.payload,
        };
        let response = Ipv4Packet {
            source: packet.destination,
            destination: packet.source,
            ttl: 64,
            protocol: IpProtocol::Icmp,
            payload: reply.encode(),
        };
        self.send_ipv4_packet(device, response)?;
        Ok(())
    }

    fn send_icmp_error(
        &mut self,
        device: DeviceId,
        original: &Ipv4Packet,
        kind: IcmpErrorKind,
    ) -> Result<(), LabError> {
        if original.source.is_unspecified()
            || original.source.is_multicast()
            || original.protocol == IpProtocol::Icmp && IcmpError::decode(&original.payload).is_ok()
        {
            return Ok(());
        }
        let Some(route) = self.device(device)?.resolve_route(original.source) else {
            return Ok(());
        };
        let mut quoted = original
            .encode()
            .map_err(|error| LabError::Protocol(error.to_string()))?;
        quoted.truncate(28);
        let error = IcmpError {
            kind,
            code: 0,
            quoted_packet: quoted,
        };
        self.send_ipv4_packet(
            device,
            Ipv4Packet {
                source: route.source_ip,
                destination: original.source,
                ttl: 64,
                protocol: IpProtocol::Icmp,
                payload: error.encode(),
            },
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum PingSignal {
    Reply,
    Unreachable,
    TimeExceeded,
}

fn dhcp_response(
    message_type: DhcpMessageType,
    request: DhcpMessage,
    offer: DhcpOffer,
) -> DhcpMessage {
    DhcpMessage {
        message_type,
        transaction_id: request.transaction_id,
        client_mac: request.client_mac,
        your_ip: offer.address,
        requested_ip: None,
        server_id: Some(offer.server_id),
        subnet_mask: Some(
            rios_ipv4::Ipv4InterfaceConfig::new(offer.address, offer.prefix_len)
                .unwrap()
                .mask(),
        ),
        default_router: offer.default_router,
        lease_time_seconds: Some(offer.lease_time_seconds),
    }
}

fn decode_ping_signal(
    frame: &EthernetFrame,
    identifier: u16,
    sequence: u16,
    local_ip: Ipv4Addr,
) -> Option<PingSignal> {
    if frame.ethertype != EtherType::Ipv4 {
        return None;
    }
    let packet = Ipv4Packet::decode(&frame.payload).ok()?;
    if packet.destination != local_ip || packet.protocol != IpProtocol::Icmp {
        return None;
    }
    if let Ok(echo) = IcmpEcho::decode(&packet.payload) {
        return (echo.kind == IcmpKind::EchoReply
            && echo.identifier == identifier
            && echo.sequence == sequence)
            .then_some(PingSignal::Reply);
    }
    let error = IcmpError::decode(&packet.payload).ok()?;
    match error.kind {
        IcmpErrorKind::DestinationUnreachable => Some(PingSignal::Unreachable),
        IcmpErrorKind::TimeExceeded => Some(PingSignal::TimeExceeded),
    }
}
