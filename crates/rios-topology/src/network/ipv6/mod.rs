//! IPv6 Ethernet ingress, virtual protocol timers and bounded neighbor-resolution queues.
mod forwarding;
mod icmp;
mod ospfv3;
mod ping;
use super::*;
pub use ping::Ping6Result;
use rios_device::ResolvedIpv6Route;
use rios_ipv6::*;
use std::net::Ipv6Addr;

#[derive(Debug)]
pub(crate) struct PendingIpv6 {
    source: InterfaceRef,
    next_hop: Ipv6Addr,
    packet: Ipv6Packet,
    expires_at: SimTime,
}
impl Lab {
    pub(super) fn purge_ipv6_pending(&mut self) {
        let now = self.now();
        self.pending_ipv6.retain(|packet| packet.expires_at > now);
    }
    pub(crate) fn schedule_ipv6_now(&mut self, device: DeviceId) -> Result<(), LabError> {
        self.schedule_ipv6_at(device, self.now())
    }
    fn schedule_ipv6_at(&mut self, device: DeviceId, deadline: SimTime) -> Result<(), LabError> {
        if !self.device(device)?.has_ipv6() {
            return Ok(());
        }
        let generation = self.ipv6_generations.entry(device).or_default();
        *generation = generation.checked_add(1).ok_or(LabError::Capacity)?;
        self.events.schedule_at(
            deadline,
            SimulationEvent::Ipv6Timer {
                device,
                generation: *generation,
            },
        )?;
        Ok(())
    }
    pub(crate) fn tick_ipv6(&mut self, device: DeviceId, generation: u64) -> Result<(), LabError> {
        if self.ipv6_generations.get(&device) != Some(&generation) {
            return Ok(());
        }
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .ipv6_tick(now);
        self.emit_ipv6_control(device, packets)?;
        self.flush_ipv6_pending(device)?;
        let packets = self
            .devices
            .get_mut(&device)
            .ok_or(DropReason::NoLink)?
            .ospfv3_tick(now);
        self.emit_ospfv3(device, packets)?;
        let deadline = self
            .device(device)?
            .ipv6_next_deadline(self.now())
            .min(self.device(device)?.ospfv3_next_deadline(self.now()));
        self.schedule_ipv6_at(device, deadline)
    }
    fn emit_ipv6_control(
        &mut self,
        device: DeviceId,
        packets: Vec<rios_device::Ipv6ControlPacket>,
    ) -> Result<(), LabError> {
        for packet in packets {
            self.transmit_ipv6(
                InterfaceRef {
                    device,
                    interface: packet.interface,
                },
                packet.destination_mac,
                packet.packet,
            )?;
        }
        Ok(())
    }
    pub(super) fn handle_ipv6(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<(), LabError> {
        let Ok(packet) = Ipv6Packet::decode(&frame.payload) else {
            return self.ipv6_bad_packet(interface);
        };
        if !self
            .device(interface.device)?
            .running_config()
            .interfaces
            .get(&interface.interface)
            .is_some_and(|c| c.ipv6.active())
        {
            return Ok(());
        }
        let local = self.device(interface.device)?.ipv6_owns(
            packet.destination,
            packet
                .destination
                .is_unicast_link_local()
                .then_some(interface.interface),
        );
        let upper = match packet.upper_layer() {
            Ok(upper) => upper,
            Err(PacketError::Fragmented | PacketError::SecurityHeader)
                if !local && !packet.destination.is_multicast() =>
            {
                return self.forward_ipv6(interface, packet);
            }
            Err(PacketError::ParameterProblem {
                pointer,
                code,
                send_icmp,
            }) => {
                if send_icmp {
                    self.send_icmpv6_error(
                        interface,
                        &packet,
                        Icmpv6ErrorKind::ParameterProblem,
                        code,
                        pointer,
                    )?;
                }
                return self.ipv6_bad_packet(interface);
            }
            Err(_) => return self.ipv6_bad_packet(interface),
        };
        if upper.protocol == NextHeader::Ospf {
            if local
                || packet.destination == rios_routing::OSPFV3_ALL_ROUTERS
                || packet.destination == rios_routing::OSPFV3_ALL_DR
            {
                return self.handle_ospfv3(interface, &packet, upper.payload);
            }
            return Ok(());
        }
        if upper.protocol == NextHeader::Icmpv6 {
            let Ok(message) =
                Icmpv6Message::decode(packet.source, packet.destination, upper.payload)
            else {
                return self.ipv6_bad_packet(interface);
            };
            if let Icmpv6Message::Neighbor(message) = message {
                if upper.had_fragment_header
                    || message
                        .validate(packet.source, packet.destination, packet.hop_limit)
                        .is_err()
                {
                    return self.ipv6_bad_packet(interface);
                }

                if !packet.destination.is_multicast() && !local {
                    return Ok(());
                }
                let now = self.now();
                let packets = self
                    .devices
                    .get_mut(&interface.device)
                    .ok_or_else(|| LabError::UnknownDevice(interface.device.0.to_string()))?
                    .receive_ipv6_nd(interface.interface, &packet, frame.source, message, now);
                self.emit_ipv6_control(interface.device, packets)?;
                self.flush_ipv6_pending(interface.device)?;
                let deadline = self
                    .device(interface.device)?
                    .ipv6_next_deadline(self.now())
                    .min(
                        self.device(interface.device)?
                            .ospfv3_next_deadline(self.now()),
                    );
                return self.schedule_ipv6_at(interface.device, deadline);
            }
            if local {
                return self.local_icmpv6(interface, &packet, message);
            }
        }
        if local {
            if upper.protocol != NextHeader::NoNextHeader {
                self.send_icmpv6_error(
                    interface,
                    &packet,
                    Icmpv6ErrorKind::ParameterProblem,
                    1,
                    upper.next_header_offset,
                )?;
            }
            return Ok(());
        }
        self.forward_ipv6(interface, packet)
    }
    fn ipv6_bad_packet(&mut self, interface: InterfaceRef) -> Result<(), LabError> {
        self.devices
            .get_mut(&interface.device)
            .ok_or_else(|| LabError::UnknownDevice(interface.device.0.to_string()))?
            .record_drop_reason(interface.interface, DropReason::MalformedPacket)?;
        Ok(())
    }
    fn transmit_ipv6(
        &mut self,
        source: InterfaceRef,
        destination: MacAddress,
        packet: Ipv6Packet,
    ) -> Result<(), LabError> {
        let payload = packet
            .encode()
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        let mac = self.device(source.device)?.interfaces()[&source.interface].mac_address;
        self.transmit_network_frame(
            source,
            EthernetFrame {
                source: mac,
                destination,
                ethertype: EtherType::Ipv6,
                payload,
            },
        )
    }
    fn flush_ipv6_pending(&mut self, device: DeviceId) -> Result<(), LabError> {
        let pending = std::mem::take(&mut self.pending_ipv6);
        let now = self.now();
        for p in pending {
            if p.expires_at <= now {
                if let Some(device) = self.devices.get_mut(&p.source.device) {
                    device
                        .record_drop_reason(p.source.interface, DropReason::NeighborUnreachable)?;
                }
                continue;
            }
            if p.source.device != device {
                self.pending_ipv6.push(p);
                continue;
            }
            let mac = self
                .devices
                .get_mut(&device)
                .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
                .ipv6_resolve_neighbor(p.source.interface, p.next_hop, now);
            if let Some(mac) = mac {
                self.transmit_ipv6(p.source, mac, p.packet)?;
            } else {
                self.pending_ipv6.push(p);
            }
        }
        Ok(())
    }
}
