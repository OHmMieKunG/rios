//! Local ICMP handling and routed error responses.
use super::*;

impl Lab {
    pub(super) fn handle_local_ipv4(
        &mut self,
        device: DeviceId,
        packet: Ipv4Packet,
    ) -> Result<(), LabError> {
        if packet.protocol == IpProtocol::Tcp {
            return self.handle_tcp(device, packet);
        }
        if packet.protocol == IpProtocol::Udp {
            let now = self.now();
            if let Some(reply) = self
                .devices
                .get_mut(&device)
                .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
                .receive_udp(&packet, now)
            {
                self.send_ipv4_packet(device, reply)?;
            }
            return Ok(());
        }
        if packet.protocol != IpProtocol::Icmp {
            return Ok(());
        }
        if IcmpError::decode(&packet.payload).is_ok() {
            self.last_local_icmp = Some((device, packet));
            return Ok(());
        }
        let Ok(echo) = IcmpEcho::decode(&packet.payload) else {
            return Ok(());
        };
        if echo.kind == IcmpKind::EchoReply {
            self.last_local_icmp = Some((device, packet));
            return Ok(());
        }
        let reply = IcmpEcho {
            kind: IcmpKind::EchoReply,
            identifier: echo.identifier,
            sequence: echo.sequence,
            payload: echo.payload,
        };
        let response = Ipv4Packet {
            dscp_ecn: 0,
            source: packet.destination,
            destination: packet.source,
            ttl: 64,
            protocol: IpProtocol::Icmp,
            payload: reply.encode(),
        };
        self.send_ipv4_packet(device, response)?;
        Ok(())
    }

    pub(super) fn send_icmp_error(
        &mut self,
        device: DeviceId,
        original: &Ipv4Packet,
        kind: IcmpErrorKind,
    ) -> Result<(), LabError> {
        if original.source.is_unspecified()
            || original.source.is_multicast()
            || original.protocol == IpProtocol::Icmp && IcmpError::decode(&original.payload).is_ok()
        {
            return Ok(());
        }
        let Some(route) = self.device(device)?.resolve_route(original.source) else {
            return Ok(());
        };
        let mut quoted = original
            .encode()
            .map_err(|error| LabError::Protocol(error.to_string()))?;
        quoted.truncate(28);
        let error = IcmpError {
            kind,
            code: 0,
            quoted_packet: quoted,
        };
        self.send_ipv4_packet(
            device,
            Ipv4Packet {
                dscp_ecn: 0,
                source: route.source_ip,
                destination: original.source,
                ttl: 64,
                protocol: IpProtocol::Icmp,
                payload: error.encode(),
            },
        )?;
        Ok(())
    }
}
