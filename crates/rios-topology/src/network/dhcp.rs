//! DHCP client/server packet exchange over the simulated network.
use super::*;

impl Lab {
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

    pub(super) fn handle_dhcp(
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

    pub(super) fn send_dhcp_message(
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
