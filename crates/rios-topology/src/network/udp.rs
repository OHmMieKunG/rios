//! Application datagrams traverse normal routing, ACL, NAT, ARP and link queues.
use super::*;
impl Lab {
    /// Send one checksummed simulated IPv4 UDP datagram from the route's source address.
    pub fn udp_send(
        &mut self,
        device: DeviceId,
        local_port: u16,
        remote: Ipv4Addr,
        remote_port: u16,
        payload: &[u8],
    ) -> Result<(), LabError> {
        if local_port == 0
            || remote_port == 0
            || payload.len() > 65507
            || remote.is_unspecified()
            || remote.is_multicast()
            || remote == Ipv4Addr::BROADCAST
        {
            return Err(LabError::Protocol(
                "invalid UDP application endpoint or payload".into(),
            ));
        }
        let route = self
            .device(device)?
            .resolve_route(remote)
            .ok_or(PingError::NoRoute(remote))?;
        let datagram = UdpDatagram {
            source_port: local_port,
            destination_port: remote_port,
            payload: payload.to_vec(),
        };
        let packet = Ipv4Packet {
            dscp_ecn: 0,
            source: route.source_ip,
            destination: remote,
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: datagram
                .encode_ipv4(route.source_ip, remote)
                .map_err(|e| LabError::Protocol(e.to_string()))?,
        };
        self.send_ipv4_via(device, route, packet).map(|_| ())
    }
}

impl Lab {
    /// Exchange one datagram through a bounded endpoint, returning only locally accepted data.
    pub fn udp_request(
        &mut self,
        device: DeviceId,
        remote: Ipv4Addr,
        port: u16,
        payload: &[u8],
        timeout_ms: u64,
    ) -> Result<Option<Vec<u8>>, LabError> {
        let deadline = SimTime(
            self.now()
                .0
                .checked_add(
                    timeout_ms
                        .checked_mul(1000)
                        .ok_or(PingError::TimeOverflow)?,
                )
                .ok_or(PingError::TimeOverflow)?,
        );
        let route = self
            .device(device)?
            .resolve_route(remote)
            .ok_or(PingError::NoRoute(remote))?;
        let local_port = (49152..=65535)
            .find(|port| {
                !self.device(device).is_ok_and(|d| {
                    d.udp_sockets().any(|(s, _)| s.local_port == *port)
                        || d.services()
                            .iter()
                            .any(|s| !s.is_tcp() && s.port() == *port)
                })
            })
            .ok_or(rios_device::UdpError::Capacity)?;
        let socket = rios_device::UdpSocket {
            local_address: route.source_ip,
            local_port,
            remote_address: remote,
            remote_port: port,
        };
        self.devices
            .get_mut(&device)
            .ok_or(DropReason::NoLink)?
            .udp_open(socket)?;
        let result = (|| {
            self.udp_send(device, local_port, remote, port, payload)?;
            self.drive_until(deadline, |lab, _| {
                lab.devices
                    .get_mut(&device)?
                    .udp_read(socket)
                    .ok()
                    .flatten()
            })
        })();
        if let Some(device) = self.devices.get_mut(&device) {
            device.udp_close(socket);
        }
        result
    }
}
