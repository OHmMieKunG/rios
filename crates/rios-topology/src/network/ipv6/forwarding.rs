//! IPv6 forwarding preserves packets, decrements hop limit, and resolves IPv6 neighbors.
use super::*;
impl Lab {
    pub(super) fn send_ipv6_packet(
        &mut self,
        device: DeviceId,
        packet: Ipv6Packet,
        scope: Option<rios_simulator::InterfaceId>,
    ) -> Result<bool, LabError> {
        let Some(route) = self
            .device(device)?
            .resolve_ipv6_route(packet.destination, scope)
        else {
            return Ok(false);
        };
        self.send_ipv6_via(device, route, packet)
    }
    fn send_ipv6_via(
        &mut self,
        device: DeviceId,
        route: ResolvedIpv6Route,
        packet: Ipv6Packet,
    ) -> Result<bool, LabError> {
        let source = InterfaceRef {
            device,
            interface: route.interface,
        };
        let now = self.now();
        if let Some(mac) = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .ipv6_resolve_neighbor(route.interface, route.next_hop, now)
        {
            self.transmit_ipv6(source, mac, packet)?;
            return Ok(true);
        }
        self.pending_ipv6.retain(|p| p.expires_at > now);
        if self.pending_ipv6.len() >= 4096
            || self
                .pending_ipv6
                .iter()
                .filter(|p| p.source == source)
                .count()
                >= 256
        {
            self.devices
                .get_mut(&device)
                .ok_or(DropReason::QueueFull)?
                .record_drop_reason(route.interface, DropReason::QueueFull)?;
            return Ok(false);
        }
        self.pending_ipv6.push(PendingIpv6 {
            source,
            next_hop: route.next_hop,
            packet,
            expires_at: SimTime(now.0.saturating_add(3_000_000)),
        });
        self.schedule_ipv6_now(device)?;
        Ok(true)
    }
    pub(super) fn forward_ipv6(
        &mut self,
        ingress: InterfaceRef,
        mut packet: Ipv6Packet,
    ) -> Result<(), LabError> {
        if !self.device(ingress.device)?.ipv6_forwarding_enabled()
            || packet.destination.is_multicast()
            || packet.source.is_multicast()
            || packet.source.is_unspecified()
            || packet.source.is_unicast_link_local()
            || packet.destination.is_unicast_link_local()
        {
            return Ok(());
        }
        if packet.hop_limit <= 1 {
            return self.send_icmpv6_error(ingress, &packet, Icmpv6ErrorKind::TimeExceeded, 0, 0);
        }
        let Some(route) = self
            .device(ingress.device)?
            .resolve_ipv6_route(packet.destination, None)
        else {
            return self.send_icmpv6_error(
                ingress,
                &packet,
                Icmpv6ErrorKind::DestinationUnreachable,
                0,
                0,
            );
        };
        let mtu = self.device(ingress.device)?.running_config().interfaces[&route.interface].mtu;
        if packet.payload.len() + 40 > usize::from(mtu) {
            return self.send_icmpv6_error(
                ingress,
                &packet,
                Icmpv6ErrorKind::PacketTooBig,
                0,
                u32::from(mtu),
            );
        }
        packet.hop_limit -= 1;
        self.send_ipv6_via(ingress.device, route, packet)?;
        Ok(())
    }
}
