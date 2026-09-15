//! ICMP probe driving and results.
use super::*;
use std::fmt::Write;
const PING_COUNT: u16 = 5;
/// A completed deterministic ping operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResult<A = Ipv4Addr> {
    /// Requested destination.
    pub destination: A,
    /// Echo requests attempted.
    pub transmitted: u16,
    /// Matching replies received.
    pub received: u16,
    /// Virtual round-trip duration for each reply.
    pub round_trip_ms: Vec<u64>,
    pub(super) markers: String,
}

impl<A: std::fmt::Display> PingResult<A> {
    /// Familiar IOS-style summary generated from actual echo replies.
    pub fn render(&self) -> String {
        let mut output = format!(
            "Type escape sequence to abort.\nSending {} ICMP Echos to {}, timeout is 1 second:\n",
            self.transmitted, self.destination
        );
        output.push_str(&self.markers);
        let success = if self.transmitted == 0 {
            0
        } else {
            u32::from(self.received) * 100 / u32::from(self.transmitted)
        };
        write!(
            output,
            "\nSuccess rate is {} percent ({}/{}), round-trip min/avg/max = ",
            success, self.received, self.transmitted
        )
        .unwrap();
        if self.round_trip_ms.is_empty() {
            output.push_str("n/a\n");
        } else {
            let min = self.round_trip_ms.iter().min().unwrap();
            let max = self.round_trip_ms.iter().max().unwrap();
            let average = self.round_trip_ms.iter().sum::<u64>() / self.round_trip_ms.len() as u64;
            writeln!(output, "{min}/{average}/{max} ms").unwrap();
        }
        output
    }
}

/// Ping setup failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PingError {
    #[error("no route to {0}")]
    NoRoute(Ipv4Addr),
    #[error("simulation time overflow")]
    TimeOverflow,
}

impl Lab {
    /// Send five echo requests using virtual events.
    pub fn ping(
        &mut self,
        source_device: DeviceId,
        destination: Ipv4Addr,
    ) -> Result<PingResult, LabError> {
        self.ping_with_ttl(source_device, destination, 64)
    }

    /// Send five echo requests with an explicit initial TTL.
    pub fn ping_with_ttl(
        &mut self,
        source_device: DeviceId,
        destination: Ipv4Addr,
        ttl: u8,
    ) -> Result<PingResult, LabError> {
        let route = self
            .device(source_device)?
            .resolve_route(destination)
            .ok_or(PingError::NoRoute(destination))?;
        let identifier = self.next_ping_id;
        self.next_ping_id = self.next_ping_id.wrapping_add(1);
        let mut result = PingResult {
            destination,
            transmitted: PING_COUNT,
            received: 0,
            round_trip_ms: Vec::new(),
            markers: String::new(),
        };

        if route.source_ip == destination {
            result.received = PING_COUNT;
            result.round_trip_ms = vec![0; usize::from(PING_COUNT)];
            result.markers = "!".repeat(usize::from(PING_COUNT));
            return Ok(result);
        }

        for sequence in 0..PING_COUNT {
            let deadline = SimTime(
                self.now()
                    .0
                    .checked_add(PING_TIMEOUT_MS * 1000)
                    .ok_or(PingError::TimeOverflow)?,
            );
            if self
                .ensure_neighbor(source_device, route, deadline)?
                .is_none()
            {
                result.markers.push('.');
                continue;
            }

            let sent_at = self.now();
            let echo = IcmpEcho {
                kind: IcmpKind::EchoRequest,
                identifier,
                sequence,
                payload: vec![0; 32],
            };
            let packet = Ipv4Packet {
                dscp_ecn: 0,
                source: route.source_ip,
                destination,
                ttl,
                protocol: IpProtocol::Icmp,
                payload: echo.encode(),
            };
            self.send_ipv4_packet(source_device, packet)?;
            let signal = self.drive_until(deadline, |_, outcome| {
                let EventOutcome::FrameReceived { interface, frame } = outcome else {
                    return None;
                };
                if interface.device != source_device {
                    return None;
                }
                decode_ping_signal(frame, identifier, sequence, route.source_ip)
            })?;
            match signal {
                Some(PingSignal::Reply) => {
                    result.received += 1;
                    result.round_trip_ms.push((self.now().0 - sent_at.0) / 1000);
                    result.markers.push('!');
                }
                Some(PingSignal::Unreachable) => result.markers.push('U'),
                Some(PingSignal::TimeExceeded) => result.markers.push('T'),
                None => result.markers.push('.'),
            }
        }
        Ok(result)
    }

    pub(super) fn drive_until<T>(
        &mut self,
        deadline: SimTime,
        mut done: impl FnMut(&mut Self, &EventOutcome) -> Option<T>,
    ) -> Result<Option<T>, LabError> {
        while self.next_event_time().is_some_and(|time| time <= deadline) {
            let Some(outcome) = self.step()? else {
                continue;
            };
            if let Some(value) = done(self, &outcome) {
                return Ok(Some(value));
            }
        }
        self.events.advance_to(deadline)?;
        self.purge_pending();
        Ok(None)
    }
}
#[derive(Debug, Clone, Copy)]
enum PingSignal {
    Reply,
    Unreachable,
    TimeExceeded,
}

fn decode_ping_signal(
    frame: &EthernetFrame,
    identifier: u16,
    sequence: u16,
    local_ip: Ipv4Addr,
) -> Option<PingSignal> {
    let untagged;
    let frame = if frame.ethertype == EtherType::Dot1Q {
        untagged = frame.untagged().ok()?.1;
        &untagged
    } else {
        frame
    };
    if frame.ethertype != EtherType::Ipv4 {
        return None;
    }
    let packet = Ipv4Packet::decode(&frame.payload).ok()?;
    if packet.destination != local_ip || packet.protocol != IpProtocol::Icmp {
        return None;
    }
    if let Ok(echo) = IcmpEcho::decode(&packet.payload) {
        return (echo.kind == IcmpKind::EchoReply
            && echo.identifier == identifier
            && echo.sequence == sequence)
            .then_some(PingSignal::Reply);
    }
    let error = IcmpError::decode(&packet.payload).ok()?;
    match error.kind {
        IcmpErrorKind::DestinationUnreachable => Some(PingSignal::Unreachable),
        IcmpErrorKind::TimeExceeded => Some(PingSignal::TimeExceeded),
    }
}
