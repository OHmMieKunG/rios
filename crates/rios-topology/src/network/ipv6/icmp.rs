//! Local IPv6 echo and real ICMPv6 forwarding errors with bounded packet quotation.
use super::*;
impl Lab {
    pub(super) fn local_icmpv6(
        &mut self,
        interface: InterfaceRef,
        packet: &Ipv6Packet,
        message: Icmpv6Message,
    ) -> Result<(), LabError> {
        if packet.source.is_unspecified() || packet.source.is_multicast() {
            return Ok(());
        }
        let Icmpv6Message::Echo {
            reply: false,
            identifier,
            sequence,
            payload,
        } = message
        else {
            return Ok(());
        };
        let reply = Icmpv6Message::Echo {
            reply: true,
            identifier,
            sequence,
            payload,
        };
        let payload = reply
            .encode(packet.destination, packet.source)
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        self.send_ipv6_packet(
            interface.device,
            Ipv6Packet {
                source: packet.destination,
                destination: packet.source,
                traffic_class: 0,
                flow_label: 0,
                hop_limit: 64,
                next_header: NextHeader::Icmpv6,
                payload,
            },
            packet
                .source
                .is_unicast_link_local()
                .then_some(interface.interface),
        )?;
        Ok(())
    }
    pub(super) fn send_icmpv6_error(
        &mut self,
        ingress: InterfaceRef,
        original: &Ipv6Packet,
        kind: Icmpv6ErrorKind,
        code: u8,
        parameter: u32,
    ) -> Result<(), LabError> {
        if original.source.is_unspecified() || original.source.is_multicast() {
            return Ok(());
        }
        if original.destination.is_multicast()
            && kind != Icmpv6ErrorKind::PacketTooBig
            && !(kind == Icmpv6ErrorKind::ParameterProblem && code == 2)
        {
            return Ok(());
        }
        if original.upper_layer().is_ok_and(|upper| {
            upper.protocol == NextHeader::Icmpv6
                && upper.payload.first().is_some_and(|kind| *kind < 128)
        }) {
            return Ok(());
        }
        let scope = original
            .source
            .is_unicast_link_local()
            .then_some(ingress.interface);
        let Some(route) = self
            .device(ingress.device)?
            .resolve_ipv6_route(original.source, scope)
        else {
            return Ok(());
        };
        let mut quoted = original
            .encode()
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        quoted.truncate(1232);
        let payload = Icmpv6Message::Error {
            kind,
            code,
            parameter,
            quoted,
        }
        .encode(route.source_ip, original.source)
        .map_err(|e| LabError::Protocol(e.to_string()))?;
        self.send_ipv6_packet(
            ingress.device,
            Ipv6Packet {
                source: route.source_ip,
                destination: original.source,
                traffic_class: 0,
                flow_label: 0,
                hop_limit: 64,
                next_header: NextHeader::Icmpv6,
                payload,
            },
            scope,
        )?;
        Ok(())
    }
}
