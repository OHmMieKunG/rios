//! DHCP client/server and relay exchange over simulated UDP.
use super::*;
mod probe;

fn client_message(kind: DhcpMessageType, xid: u32, mac: MacAddress) -> DhcpMessage {
    DhcpMessage {
        message_type: kind,
        transaction_id: xid,
        client_mac: mac,
        your_ip: Ipv4Addr::UNSPECIFIED,
        client_ip: Ipv4Addr::UNSPECIFIED,
        relay_ip: Ipv4Addr::UNSPECIFIED,
        hops: 0,
        requested_ip: None,
        server_id: None,
        subnet_mask: None,
        default_router: None,
        lease_time_seconds: None,
        dns_servers: Vec::new(),
        domain_name: None,
        renewal_seconds: None,
        rebinding_seconds: None,
    }
}
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
            let endpoint = InterfaceRef { device, interface };
            if self.dhcp_probes.contains_key(&endpoint)
                || self
                    .dhcp_retry_after
                    .get(&endpoint)
                    .is_some_and(|at| *at > self.now())
            {
                continue;
            }
            self.dhcp_retry_after.remove(&endpoint);
            self.next_dhcp_xid = self.next_dhcp_xid.wrapping_add(1).max(1);
            self.dhcp_transactions.insert(endpoint, self.next_dhcp_xid);
            let mac = self.device(device)?.interfaces()[&interface].mac_address;
            self.send_dhcp_message(
                endpoint,
                Ipv4Addr::UNSPECIFIED,
                DHCP_CLIENT_PORT,
                DHCP_SERVER_PORT,
                client_message(DhcpMessageType::Discover, self.next_dhcp_xid, mac),
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
        let Ok(mut message) = DhcpMessage::decode(&datagram.payload) else {
            return Ok(());
        };
        let device = self.device(interface.device)?;
        // Relays preserve the transaction and client MAC, and route UDP 67 to the server.
        if datagram.source_port == DHCP_CLIENT_PORT
            && message.relay_ip.is_unspecified()
            && matches!(
                message.message_type,
                DhcpMessageType::Discover | DhcpMessageType::Request | DhcpMessageType::Decline
            )
            && let Some(helper) =
                device.running_config().interfaces[&interface.interface].helper_address
            && let Some(ip) = device.interface_ipv4(interface.interface)
        {
            if message.hops >= 16 {
                return Ok(());
            }
            message.hops += 1;
            message.relay_ip = ip.address();
            return self.send_dhcp_unicast(
                interface.device,
                ip.address(),
                helper,
                DHCP_SERVER_PORT,
                DHCP_SERVER_PORT,
                message,
            );
        }
        if datagram.destination_port == DHCP_SERVER_PORT
            && datagram.source_port == DHCP_SERVER_PORT
            && matches!(
                message.message_type,
                DhcpMessageType::Offer | DhcpMessageType::Ack | DhcpMessageType::Nak
            )
        {
            let endpoint = device
                .running_config()
                .interfaces
                .iter()
                .find_map(|(id, config)| {
                    (config.helper_address == message.server_id
                        && device
                            .interface_ipv4(*id)
                            .is_some_and(|ip| ip.address() == message.relay_ip)
                        && device.protocol_up(*id))
                    .then_some(InterfaceRef {
                        device: interface.device,
                        interface: *id,
                    })
                });
            if let Some(endpoint) = endpoint {
                return self.send_dhcp_message(
                    endpoint,
                    message.server_id.unwrap_or(message.relay_ip),
                    DHCP_SERVER_PORT,
                    DHCP_CLIENT_PORT,
                    message,
                );
            }
            return Ok(());
        }
        match message.message_type {
            DhcpMessageType::Discover | DhcpMessageType::Request => {
                if message.hops > 16 {
                    return Ok(());
                }
                if message
                    .server_id
                    .is_some_and(|server| !device.owns_any_ipv4(server))
                {
                    return Ok(());
                }
                let Some(local) = device.interface_ipv4(interface.interface) else {
                    return Ok(());
                };
                let subnet = if !message.relay_ip.is_unspecified() {
                    message.relay_ip
                } else if !message.client_ip.is_unspecified() {
                    message.client_ip
                } else {
                    local.address()
                };
                let now = self.now();
                let offer = self
                    .devices
                    .get_mut(&interface.device)
                    .ok_or(LabError::Capacity)?
                    .offer_dhcp_on_network(interface.interface, message.client_mac, subnet, now);
                let Some(offer) = offer else {
                    return Ok(());
                };
                let response = if message.message_type == DhcpMessageType::Discover {
                    self.dhcp_response(interface.device, DhcpMessageType::Offer, &message, offer)?
                } else {
                    let address = message.requested_ip.unwrap_or(message.client_ip);
                    let committed = self
                        .devices
                        .get_mut(&interface.device)
                        .ok_or(LabError::Capacity)?
                        .commit_dhcp(message.client_mac, address, offer.server_id, now);
                    self.dhcp_response(
                        interface.device,
                        if committed.is_some() {
                            DhcpMessageType::Ack
                        } else {
                            DhcpMessageType::Nak
                        },
                        &message,
                        committed.unwrap_or(offer),
                    )?
                };
                self.send_dhcp_response(interface, response)?;
            }
            DhcpMessageType::Offer => {
                if !self.dhcp_for_client(interface, &message) || message.server_id.is_none() {
                    return Ok(());
                }
                if !self.dhcp_probes.contains_key(&interface) {
                    self.begin_dhcp_probe(interface, message)?;
                }
            }
            DhcpMessageType::Ack => {
                if !self.dhcp_for_client(interface, &message) {
                    return Ok(());
                }
                let (Some(mask), Some(server_id), Some(seconds)) = (
                    message.subnet_mask,
                    message.server_id,
                    message.lease_time_seconds,
                ) else {
                    return Ok(());
                };
                let Ok(ip) = rios_ipv4::Ipv4InterfaceConfig::from_mask(message.your_ip, mask)
                else {
                    return Ok(());
                };
                if seconds < 3
                    || message.your_ip.is_unspecified()
                    || message.your_ip.is_multicast()
                    || message.your_ip == Ipv4Addr::BROADCAST
                {
                    return Ok(());
                }
                let t1 = message.renewal_seconds.unwrap_or(seconds / 2);
                let t2 = message
                    .rebinding_seconds
                    .unwrap_or((u64::from(seconds) * 7 / 8) as u32);
                if t1 == 0 || t1 >= t2 || t2 >= seconds {
                    return Ok(());
                }
                let at = |seconds: u32| {
                    SimTime(self.now().0.saturating_add(u64::from(seconds) * 1_000_000))
                };
                let lease = DhcpLease {
                    address: message.your_ip,
                    prefix_len: ip.prefix_len(),
                    default_router: message.default_router,
                    server_id,
                    expires_at: at(seconds),
                    dns_servers: message.dns_servers,
                    domain_name: message.domain_name,
                    renew_at: at(t1),
                    rebind_at: at(t2),
                };
                let deadline = lease.expires_at;
                let renew_at = lease.renew_at;
                self.devices
                    .get_mut(&interface.device)
                    .ok_or(LabError::Capacity)?
                    .install_dhcp_lease(interface.interface, lease)?;
                self.dhcp_transactions.remove(&interface);
                self.events.schedule_at(
                    renew_at,
                    SimulationEvent::DhcpRenew {
                        interface,
                        deadline,
                    },
                )?;
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
            DhcpMessageType::Nak => {
                if self.dhcp_for_client(interface, &message) {
                    let lease = self
                        .device(interface.device)?
                        .dhcp_lease(interface.interface)
                        .cloned();
                    if let Some(lease) = lease {
                        self.devices
                            .get_mut(&interface.device)
                            .ok_or(LabError::Capacity)?
                            .expire_dhcp_lease(
                                interface.interface,
                                lease.address,
                                lease.expires_at,
                            );
                    }
                    self.schedule_dhcp_now(interface.device)?;
                }
            }
            DhcpMessageType::Decline => {
                if let Some(address) = message.requested_ip {
                    let now = self.now();
                    self.devices
                        .get_mut(&interface.device)
                        .ok_or(LabError::Capacity)?
                        .decline_dhcp(message.client_mac, address, now);
                }
            }
        }
        Ok(())
    }

    fn dhcp_for_client(&self, interface: InterfaceRef, message: &DhcpMessage) -> bool {
        self.dhcp_transactions.get(&interface) == Some(&message.transaction_id)
            && self
                .devices
                .get(&interface.device)
                .and_then(|device| device.interfaces().get(&interface.interface))
                .is_some_and(|port| port.mac_address == message.client_mac)
    }

    pub(crate) fn renew_dhcp(
        &mut self,
        interface: InterfaceRef,
        deadline: SimTime,
    ) -> Result<(), LabError> {
        let Some(lease) = self
            .device(interface.device)?
            .dhcp_lease(interface.interface)
            .cloned()
            .filter(|lease| lease.expires_at == deadline && deadline > self.now())
        else {
            return Ok(());
        };
        let rebind = self.now() >= lease.rebind_at;
        if self
            .device(interface.device)?
            .protocol_up(interface.interface)
        {
            let xid = if let Some(xid) = self.dhcp_transactions.get(&interface) {
                *xid
            } else {
                self.next_dhcp_xid = self.next_dhcp_xid.wrapping_add(1).max(1);
                self.dhcp_transactions.insert(interface, self.next_dhcp_xid);
                self.next_dhcp_xid
            };
            let mac = self.device(interface.device)?.interfaces()[&interface.interface].mac_address;
            let mut request = client_message(DhcpMessageType::Request, xid, mac);
            request.client_ip = lease.address;
            if rebind {
                self.send_dhcp_message(
                    interface,
                    lease.address,
                    DHCP_CLIENT_PORT,
                    DHCP_SERVER_PORT,
                    request,
                )?;
            } else {
                self.send_dhcp_unicast(
                    interface.device,
                    lease.address,
                    lease.server_id,
                    DHCP_CLIENT_PORT,
                    DHCP_SERVER_PORT,
                    request,
                )?;
            }
        }
        let boundary = if rebind { deadline } else { lease.rebind_at };
        let retry = SimTime(
            self.now()
                .0
                .saturating_add(((boundary.0 - self.now().0) / 2).max(1_000_000))
                .min(boundary.0),
        );
        if retry < deadline {
            self.events.schedule_at(
                retry,
                SimulationEvent::DhcpRenew {
                    interface,
                    deadline,
                },
            )?;
        }
        Ok(())
    }

    fn dhcp_response(
        &self,
        device: DeviceId,
        kind: DhcpMessageType,
        request: &DhcpMessage,
        offer: DhcpOffer,
    ) -> Result<DhcpMessage, LabError> {
        let mut response = client_message(kind, request.transaction_id, request.client_mac);
        response.relay_ip = request.relay_ip;
        response.hops = request.hops;
        response.client_ip = request.client_ip;
        response.server_id = Some(offer.server_id);
        if kind != DhcpMessageType::Nak {
            response.your_ip = offer.address;
            response.subnet_mask =
                rios_ipv4::Ipv4InterfaceConfig::new(offer.address, offer.prefix_len)
                    .ok()
                    .map(|ip| ip.mask());
            response.default_router = offer.default_router;
            response.lease_time_seconds = Some(offer.lease_time_seconds);
            response.renewal_seconds = Some(offer.lease_time_seconds / 2);
            response.rebinding_seconds = Some((u64::from(offer.lease_time_seconds) * 7 / 8) as u32);
            if let Some(pool) = self
                .device(device)?
                .running_config()
                .dhcp_pools
                .get(&offer.pool)
            {
                response.dns_servers = pool.dns_servers.clone();
                response.domain_name = pool.domain_name.clone();
            }
        }
        Ok(response)
    }

    fn send_dhcp_response(
        &mut self,
        interface: InterfaceRef,
        message: DhcpMessage,
    ) -> Result<(), LabError> {
        let source = message.server_id.unwrap_or(Ipv4Addr::UNSPECIFIED);
        if !message.relay_ip.is_unspecified() {
            self.send_dhcp_unicast(
                interface.device,
                source,
                message.relay_ip,
                DHCP_SERVER_PORT,
                DHCP_SERVER_PORT,
                message,
            )
        } else if !message.client_ip.is_unspecified()
            && message.message_type != DhcpMessageType::Nak
        {
            self.send_dhcp_unicast(
                interface.device,
                source,
                message.client_ip,
                DHCP_SERVER_PORT,
                DHCP_CLIENT_PORT,
                message,
            )
        } else {
            self.send_dhcp_message(
                interface,
                source,
                DHCP_SERVER_PORT,
                DHCP_CLIENT_PORT,
                message,
            )
        }
    }

    fn dhcp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        message: DhcpMessage,
    ) -> Result<Ipv4Packet, LabError> {
        let datagram = UdpDatagram {
            source_port,
            destination_port,
            payload: message
                .encode()
                .map_err(|error| LabError::Protocol(error.to_string()))?,
        };
        Ok(Ipv4Packet {
            source,
            destination,
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: datagram
                .encode()
                .map_err(|error| LabError::Protocol(error.to_string()))?,
        })
    }
    fn send_dhcp_unicast(
        &mut self,
        device: DeviceId,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        message: DhcpMessage,
    ) -> Result<(), LabError> {
        let packet =
            Self::dhcp_packet(source, destination, source_port, destination_port, message)?;
        self.send_ipv4_packet(device, packet).map(|_| ())
    }
    pub(super) fn send_dhcp_message(
        &mut self,
        interface: InterfaceRef,
        source: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        message: DhcpMessage,
    ) -> Result<(), LabError> {
        let mac = self.device(interface.device)?.interfaces()[&interface.interface].mac_address;
        let packet = Self::dhcp_packet(
            source,
            Ipv4Addr::BROADCAST,
            source_port,
            destination_port,
            message,
        )?;
        self.transmit_ipv4(interface, mac, MacAddress::BROADCAST, packet)
    }
}
