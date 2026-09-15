//! Route resolution, outbound policy, and Ethernet transmission.
use super::*;

impl Lab {
    /// Transit stage: forwarding capability, TTL, route lookup, and source NAT.
    pub(super) fn forward_ipv4(
        &mut self,
        interface: InterfaceRef,
        packet: Ipv4Packet,
    ) -> Result<(), LabError> {
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
        let translated = self
            .devices
            .get_mut(&interface.device)
            .unwrap()
            .nat_outbound(interface.interface, route.interface, &mut forwarded, now);
        if translated == rios_device::NatOutcome::Drop {
            self.devices
                .get_mut(&interface.device)
                .ok_or(DropReason::NatFailed)?
                .record_drop_reason(interface.interface, DropReason::NatFailed)?;
            return Ok(());
        }
        forwarded.ttl -= 1;
        self.send_ipv4_packet(interface.device, forwarded)?;
        Ok(())
    }

    pub(super) fn send_ipv4_packet(
        &mut self,
        device: DeviceId,
        packet: Ipv4Packet,
    ) -> Result<bool, LabError> {
        let Some(route) = self.device(device)?.resolve_route(packet.destination) else {
            return Ok(false);
        };
        self.send_ipv4_via(device, route, packet)
    }

    /// Resolve a neighbor on an explicitly selected interface, including link-local protocols.
    pub(super) fn send_ipv4_via(
        &mut self,
        device: DeviceId,
        route: ResolvedRoute,
        packet: Ipv4Packet,
    ) -> Result<bool, LabError> {
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

        self.pending_ipv4.retain(|pending| pending.expires_at > now);
        if self.pending_ipv4.len() >= 4096
            || self
                .pending_ipv4
                .iter()
                .filter(|pending| pending.source == source)
                .count()
                >= 256
        {
            self.devices
                .get_mut(&device)
                .ok_or(DropReason::QueueFull)?
                .record_drop_reason(source.interface, DropReason::QueueFull)?;
            return Ok(false);
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

    pub(super) fn transmit_ipv4(
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
        if !self
            .devices
            .get_mut(&source.device)
            .ok_or_else(|| LabError::UnknownDevice(source.device.0.to_string()))?
            .permits_ipv4(source.interface, AccessListDirection::Out, &packet)
        {
            self.devices
                .get_mut(&source.device)
                .unwrap()
                .record_drop_reason(source.interface, DropReason::AccessList)?;
            self.trace_frame(source, TraceAction::Drop(DropReason::AccessList), &frame);
            return Ok(());
        }
        self.transmit_network_frame(source, frame)
    }
}
