//! OSPFv3 uses protocol 89, IPv6 multicast and scoped ND for reliable unicast packets.
use super::*;
use rios_routing::OspfV3Packet;
impl Lab {
    pub(super) fn handle_ospfv3(
        &mut self,
        interface: InterfaceRef,
        packet: &Ipv6Packet,
        payload: &[u8],
    ) -> Result<(), LabError> {
        if packet.hop_limit != 1 || !packet.source.is_unicast_link_local() {
            return Ok(());
        }
        let Ok(ospf) = OspfV3Packet::decode(packet.source, packet.destination, payload) else {
            return self.ipv6_bad_packet(interface);
        };
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&interface.device)
            .ok_or(DropReason::NoLink)?
            .receive_ospfv3(interface.interface, packet.source, ospf, now);
        self.emit_ospfv3(interface.device, packets)?;
        let device = self.device(interface.device)?;
        let deadline = device
            .ipv6_next_deadline(now)
            .min(device.ospfv3_next_deadline(now));
        self.schedule_ipv6_at(interface.device, deadline)
    }
    pub(super) fn emit_ospfv3(
        &mut self,
        device: DeviceId,
        packets: Vec<rios_device::OspfV3Transmission>,
    ) -> Result<(), LabError> {
        for action in packets {
            let Ok(payload) = action.packet.encode(action.source, action.destination) else {
                continue;
            };
            let packet = Ipv6Packet {
                source: action.source,
                destination: action.destination,
                traffic_class: 0,
                flow_label: 0,
                hop_limit: 1,
                next_header: NextHeader::Ospf,
                payload,
            };
            if let Some(mac) = multicast_mac(action.destination) {
                self.transmit_ipv6(
                    InterfaceRef {
                        device,
                        interface: action.interface,
                    },
                    mac,
                    packet,
                )?;
            } else {
                self.send_ipv6_via(
                    device,
                    ResolvedIpv6Route {
                        interface: action.interface,
                        source_ip: action.source,
                        next_hop: action.destination,
                    },
                    packet,
                )?;
            }
        }
        Ok(())
    }
}
