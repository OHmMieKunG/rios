//! OSPF packet ingress and virtual neighbor expiry.
use super::*;

impl Lab {
    pub(super) fn handle_ospf(
        &mut self,
        interface: InterfaceRef,
        packet: Ipv4Packet,
    ) -> Result<(), LabError> {
        let Ok(ospf) = OspfPacket::decode(&packet.payload) else {
            return Ok(());
        };
        let now = self.now();
        if let Some((router_id, deadline, changed)) = self
            .devices
            .get_mut(&interface.device)
            .unwrap()
            .receive_ospf(interface.interface, packet.source, ospf, now)
        {
            self.events.schedule_at(
                deadline,
                SimulationEvent::OspfDead {
                    device: interface.device,
                    router_id,
                    deadline,
                },
            )?;
            if changed {
                self.schedule_ospf_now(interface.device)?;
            }
        }
        Ok(())
    }
}
