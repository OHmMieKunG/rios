//! Neighbor resolution and pending IPv4 traffic.
use super::*;

impl Lab {
    pub(super) fn ensure_neighbor(
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

    pub(super) fn send_arp_request(
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

    pub(super) fn flush_pending(
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

    pub(super) fn handle_arp(
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
}
