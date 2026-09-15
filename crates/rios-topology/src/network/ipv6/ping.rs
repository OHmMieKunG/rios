//! ICMPv6 probes observe actual replies and quoted forwarding errors.
use super::*;
/// IPv6 ping result uses the same statistics renderer as IPv4.
pub type Ping6Result = super::super::ping::PingResult<Ipv6Addr>;
impl Lab {
    pub fn ping_ipv6(
        &mut self,
        device: DeviceId,
        destination: Ipv6Addr,
        scope: Option<rios_simulator::InterfaceId>,
    ) -> Result<Ping6Result, LabError> {
        self.ping_ipv6_with_hop_limit(device, destination, scope, 64)
    }
    pub fn ping_ipv6_with_hop_limit(
        &mut self,
        device: DeviceId,
        destination: Ipv6Addr,
        scope: Option<rios_simulator::InterfaceId>,
        hop_limit: u8,
    ) -> Result<Ping6Result, LabError> {
        // Permit initial DAD and SLAAC to finish through normal events, without inventing readiness.
        let ready_by = SimTime(
            self.now()
                .0
                .checked_add(3_000_000)
                .ok_or(LabError::Capacity)?,
        );
        while self
            .device(device)?
            .resolve_ipv6_route(destination, scope)
            .is_none()
            && self.next_event_time().is_some_and(|next| next <= ready_by)
        {
            self.step()?;
        }
        let route = self
            .device(device)?
            .resolve_ipv6_route(destination, scope)
            .ok_or(LabError::NoIpv6Route(destination))?;
        let mut result = Ping6Result {
            destination,
            transmitted: 5,
            received: 0,
            round_trip_ms: Vec::new(),
            markers: String::new(),
        };
        if self.device(device)?.ipv6_owns(destination, scope) {
            result.received = 5;
            result.round_trip_ms = vec![0; 5];
            result.markers = "!!!!!".into();
            return Ok(result);
        }
        let identifier = self.next_ping_id;
        self.next_ping_id = self.next_ping_id.wrapping_add(1);
        for sequence in 0..5 {
            let now = self.now();
            let deadline = SimTime(now.0.checked_add(1_000_000).ok_or(LabError::Capacity)?);
            let message = Icmpv6Message::Echo {
                reply: false,
                identifier,
                sequence,
                payload: vec![0; 32],
            };
            let payload = message
                .encode(route.source_ip, destination)
                .map_err(|e| LabError::Protocol(e.to_string()))?;
            self.send_ipv6_packet(
                device,
                Ipv6Packet {
                    source: route.source_ip,
                    destination,
                    traffic_class: 0,
                    flow_label: 0,
                    hop_limit,
                    next_header: NextHeader::Icmpv6,
                    payload,
                },
                scope,
            )?;
            let signal = self.drive_until(deadline, |_, outcome| {
                let EventOutcome::FrameReceived { interface, frame } = outcome else {
                    return None;
                };
                if interface.device != device {
                    return None;
                }
                signal(frame, route.source_ip, destination, identifier, sequence)
            })?;
            match signal {
                Some('!') => {
                    result.received += 1;
                    result.round_trip_ms.push((self.now().0 - now.0) / 1000);
                    result.markers.push('!');
                }
                Some(marker) => result.markers.push(marker),
                None => result.markers.push('.'),
            }
        }
        Ok(result)
    }
}
fn signal(
    frame: &EthernetFrame,
    local: Ipv6Addr,
    target: Ipv6Addr,
    identifier: u16,
    sequence: u16,
) -> Option<char> {
    let untagged;
    let frame = if frame.ethertype == EtherType::Dot1Q {
        untagged = frame.untagged().ok()?.1;
        &untagged
    } else {
        frame
    };
    if frame.ethertype != EtherType::Ipv6 {
        return None;
    }
    let packet = Ipv6Packet::decode(&frame.payload).ok()?;
    if packet.destination != local {
        return None;
    }
    let upper = packet.upper_layer().ok()?;
    if upper.protocol != NextHeader::Icmpv6 {
        return None;
    }
    match Icmpv6Message::decode(packet.source, packet.destination, upper.payload).ok()? {
        Icmpv6Message::Echo {
            reply: true,
            identifier: id,
            sequence: seq,
            ..
        } if id == identifier && seq == sequence && packet.source == target => Some('!'),
        Icmpv6Message::Error { kind, quoted, .. } => {
            let original = Ipv6Packet::decode(&quoted).ok()?;
            if original.source != local || original.destination != target {
                return None;
            }
            let upper = original.upper_layer().ok()?;
            if upper.protocol != NextHeader::Icmpv6 {
                return None;
            }
            let echo = Icmpv6Message::decode(local, target, upper.payload).ok()?;
            if !matches!(echo,Icmpv6Message::Echo {reply:false,identifier:id,sequence:seq,..} if id==identifier && seq==sequence)
            {
                return None;
            }
            Some(match kind {
                Icmpv6ErrorKind::TimeExceeded => 'T',
                Icmpv6ErrorKind::DestinationUnreachable => 'U',
                Icmpv6ErrorKind::PacketTooBig => 'M',
                Icmpv6ErrorKind::ParameterProblem => '?',
            })
        }
        _ => None,
    }
}
