//! Standard OSPF packets use virtual Ethernet, IPv4 and ARP, including reliable unicast exchanges.
use super::*;
impl Lab {
    pub(super) fn handle_ospf(
        &mut self,
        interface: InterfaceRef,
        packet: Ipv4Packet,
    ) -> Result<(), LabError> {
        if packet.ttl != 1 {
            return Ok(());
        }
        let Ok(ospf) = OspfV2Packet::decode(&packet.payload) else {
            return Ok(());
        };
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&interface.device)
            .ok_or_else(|| LabError::UnknownDevice(interface.device.0.to_string()))?
            .receive_ospf_v2(interface.interface, packet.source, ospf, now);
        self.emit_ospf(interface.device, packets)
    }
    pub(crate) fn emit_ospf(
        &mut self,
        device: DeviceId,
        packets: Vec<rios_device::OspfTransmission>,
    ) -> Result<(), LabError> {
        for action in packets {
            let Ok(payload) = action.packet.encode() else {
                continue;
            };
            let packet = Ipv4Packet {
                source: action.source,
                destination: action.destination,
                ttl: 1,
                protocol: IpProtocol::Ospf,
                payload,
            };
            if action.destination == OSPF_ALL_ROUTERS {
                let source = InterfaceRef {
                    device,
                    interface: action.interface,
                };
                let mac = self.device(device)?.interfaces()[&action.interface].mac_address;
                self.transmit_ipv4(source, mac, MacAddress([1, 0, 0x5e, 0, 0, 5]), packet)?;
            } else {
                let mac = self.device(device)?.interfaces()[&action.interface].mac_address;
                self.send_ipv4_via(
                    device,
                    ResolvedRoute {
                        interface: action.interface,
                        source_ip: action.source,
                        source_mac: mac,
                        next_hop: action.destination,
                    },
                    packet,
                )?;
            }
        }
        Ok(())
    }
}
