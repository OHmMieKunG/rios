//! Stateless DNS/NTP responses derived solely from inventory and simulation time.
use rios_config::ServiceConfig;
use rios_protocol::{DnsARecord, DnsMessage, NtpPacket, NtpTimestamp};
use rios_simulator::SimTime;

pub(super) fn reply(service: &ServiceConfig, bytes: &[u8], now: SimTime) -> Option<Vec<u8>> {
    match service {
        ServiceConfig::UdpEcho { .. } => Some(bytes.to_vec()),
        ServiceConfig::Dns { records, ttl, .. } => {
            let mut message = DnsMessage::decode(bytes).ok()?;
            if message.response || !message.answers.is_empty() || message.rcode != 0 {
                return None;
            }
            message.response = true;
            message.authoritative = true;
            if message.question.class != 1 {
                message.rcode = 4;
            } else if let Some(address) = records.get(&message.question.name) {
                if message.question.kind == 1 || message.question.kind == 255 {
                    message.answers.push(DnsARecord {
                        name: message.question.name.clone(),
                        ttl: *ttl,
                        address: *address,
                    });
                }
            } else {
                message.rcode = 3;
            }
            message.encode().ok()
        }
        ServiceConfig::Ntp { epoch_seconds, .. } => {
            let request = NtpPacket::decode(bytes).ok()?;
            if request.mode != 3 {
                return None;
            }
            let time = NtpTimestamp::from_simulation(*epoch_seconds, now.0);
            let mut response = NtpPacket::request(time);
            response.version = request.version;
            response.mode = 4;
            response.stratum = 1;
            response.poll = request.poll.clamp(4, 17);
            response.reference_id = *b"RIOS";
            response.reference = time;
            response.origin = request.transmit;
            response.receive = time;
            response.encode().ok()
        }
        _ => None,
    }
}
