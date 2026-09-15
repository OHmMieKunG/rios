//! Ethernet protocol dispatch and ordered IPv4 ingress stages.
use super::*;

impl Lab {
    pub(crate) fn handle_protocol_frame(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<(), LabError> {
        match frame.ethertype {
            EtherType::Arp => self.handle_arp(interface, frame),
            EtherType::Ipv4 => self.handle_ipv4(interface, frame),
            EtherType::Ipv6 => self.handle_ipv6(interface, frame),
            _ => Ok(()),
        }
    }

    pub(super) fn handle_ipv4(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<(), LabError> {
        let Ok(mut packet) = Ipv4Packet::decode(&frame.payload) else {
            return Ok(());
        };
        if !self
            .devices
            .get_mut(&interface.device)
            .ok_or_else(|| LabError::UnknownDevice(interface.device.0.to_string()))?
            .permits_ipv4(interface.interface, AccessListDirection::In, &packet)
        {
            self.devices
                .get_mut(&interface.device)
                .unwrap()
                .record_drop_reason(interface.interface, DropReason::AccessList)?;
            self.trace_frame(interface, TraceAction::Drop(DropReason::AccessList), frame);
            return Ok(());
        }
        if packet.protocol == IpProtocol::Udp
            && let Ok(datagram) = UdpDatagram::decode(&packet.payload)
            && matches!(
                (datagram.source_port, datagram.destination_port),
                (DHCP_CLIENT_PORT, DHCP_SERVER_PORT)
                    | (DHCP_SERVER_PORT, DHCP_CLIENT_PORT)
                    | (DHCP_SERVER_PORT, DHCP_SERVER_PORT)
            )
            && (packet.destination == Ipv4Addr::BROADCAST
                || self
                    .device(interface.device)?
                    .owns_any_ipv4(packet.destination))
        {
            self.handle_dhcp(interface, datagram)?;
            return Ok(());
        }
        if packet.protocol == IpProtocol::Ospf
            && (packet.destination == OSPF_ALL_ROUTERS
                || packet.destination == Ipv4Addr::new(224, 0, 0, 6)
                || self
                    .device(interface.device)?
                    .owns_any_ipv4(packet.destination))
        {
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
        self.forward_ipv4(interface, packet)
    }
}
