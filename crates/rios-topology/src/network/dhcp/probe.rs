//! Probe offered addresses with ARP before requesting a lease.
use super::*;
impl Lab {
    pub(super) fn begin_dhcp_probe(
        &mut self,
        interface: InterfaceRef,
        message: DhcpMessage,
    ) -> Result<(), LabError> {
        if message.your_ip.is_unspecified()
            || message.your_ip.is_multicast()
            || message.your_ip == Ipv4Addr::BROADCAST
        {
            return Ok(());
        }
        let xid = message.transaction_id;
        let mac = message.client_mac;
        let request = ArpPacket {
            operation: ArpOperation::Request,
            sender_mac: mac,
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: MacAddress([0; 6]),
            target_ip: message.your_ip,
        };
        self.dhcp_probes.insert(interface, message);
        self.transmit_network_frame(
            interface,
            EthernetFrame {
                source: mac,
                destination: MacAddress::BROADCAST,
                ethertype: EtherType::Arp,
                payload: request.encode(),
            },
        )?;
        self.events
            .schedule_after(200, SimulationEvent::DhcpProbe { interface, xid })?;
        Ok(())
    }
    pub(crate) fn finish_dhcp_probe(
        &mut self,
        interface: InterfaceRef,
        xid: u32,
    ) -> Result<(), LabError> {
        if !self
            .dhcp_probes
            .get(&interface)
            .is_some_and(|message| message.transaction_id == xid)
            || self.dhcp_transactions.get(&interface) != Some(&xid)
        {
            return Ok(());
        }
        let Some(message) = self.dhcp_probes.remove(&interface) else {
            return Ok(());
        };
        if !self
            .device(interface.device)?
            .protocol_up(interface.interface)
        {
            return Ok(());
        }
        let mut request = client_message(DhcpMessageType::Request, xid, message.client_mac);
        request.requested_ip = Some(message.your_ip);
        request.server_id = message.server_id;
        self.send_dhcp_message(
            interface,
            Ipv4Addr::UNSPECIFIED,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            request,
        )
    }
    pub(crate) fn observe_dhcp_conflict(
        &mut self,
        interface: InterfaceRef,
        arp: &ArpPacket,
    ) -> Result<(), LabError> {
        let conflict = self.dhcp_probes.get(&interface).is_some_and(|message| {
            arp.sender_mac != message.client_mac
                && (arp.sender_ip == message.your_ip
                    || arp.sender_ip.is_unspecified() && arp.target_ip == message.your_ip)
        });
        if !conflict {
            return Ok(());
        }
        let Some(message) = self.dhcp_probes.remove(&interface) else {
            return Ok(());
        };
        let mut decline = client_message(
            DhcpMessageType::Decline,
            message.transaction_id,
            message.client_mac,
        );
        decline.requested_ip = Some(message.your_ip);
        decline.server_id = message.server_id;
        self.dhcp_transactions.remove(&interface);
        self.dhcp_retry_after
            .insert(interface, SimTime(self.now().0.saturating_add(10_000_000)));
        self.send_dhcp_message(
            interface,
            Ipv4Addr::UNSPECIFIED,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            decline,
        )
    }
}
