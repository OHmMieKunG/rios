//! Validated transport rewrites; checksum calculation uses the translated addresses.
use super::*;
use rios_protocol::{IcmpEcho, TcpSegment, UdpDatagram};

pub(super) fn outbound_transport(packet: &Ipv4Packet) -> Option<(NatProtocol, u16, u16)> {
    match packet.protocol {
        IpProtocol::Icmp => IcmpEcho::decode(&packet.payload)
            .ok()
            .map(|echo| (NatProtocol::Icmp, echo.identifier, 0)),
        IpProtocol::Udp => UdpDatagram::decode(&packet.payload)
            .ok()
            .map(|udp| (NatProtocol::Udp, udp.source_port, udp.destination_port)),
        IpProtocol::Tcp => TcpSegment::decode(packet.source, packet.destination, &packet.payload)
            .ok()
            .map(|tcp| (NatProtocol::Tcp, tcp.source_port, tcp.destination_port)),
        _ => None,
    }
}
pub(super) fn inbound_transport(packet: &Ipv4Packet) -> Option<(NatProtocol, u16, u16)> {
    let (protocol, source, destination) = outbound_transport(packet)?;
    Some(if protocol == NatProtocol::Icmp {
        (protocol, source, 0)
    } else {
        (protocol, destination, source)
    })
}
pub(super) fn rewrite(
    packet: &mut Ipv4Packet,
    address: Ipv4Addr,
    port: Option<u16>,
    source: bool,
) -> bool {
    let new_source = if source { address } else { packet.source };
    let new_destination = if source { packet.destination } else { address };
    let payload = match packet.protocol {
        IpProtocol::Tcp => {
            let Ok(mut tcp) =
                TcpSegment::decode(packet.source, packet.destination, &packet.payload)
            else {
                return false;
            };
            if let Some(port) = port {
                if source {
                    tcp.source_port = port;
                } else {
                    tcp.destination_port = port;
                }
            }
            let Ok(bytes) = tcp.encode(new_source, new_destination) else {
                return false;
            };
            bytes
        }
        IpProtocol::Udp => {
            let Ok(mut udp) = UdpDatagram::decode(&packet.payload) else {
                return false;
            };
            if let Some(port) = port {
                if source {
                    udp.source_port = port;
                } else {
                    udp.destination_port = port;
                }
            }
            let Ok(bytes) = udp.encode() else {
                return false;
            };
            bytes
        }
        IpProtocol::Icmp if port.is_some() => {
            let Ok(mut echo) = IcmpEcho::decode(&packet.payload) else {
                return false;
            };
            if let Some(port) = port {
                echo.identifier = port;
            }
            echo.encode()
        }
        _ if port.is_none() => std::mem::take(&mut packet.payload),
        _ => return false,
    };
    packet.source = new_source;
    packet.destination = new_destination;
    packet.payload = payload;
    true
}
