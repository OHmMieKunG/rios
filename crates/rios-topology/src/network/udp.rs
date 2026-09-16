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
