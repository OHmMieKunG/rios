//! LACP transmission over physical links, independent of bundle forwarding state.
use super::*;
use rios_switching::{LACP_ETHERTYPE, LACP_MULTICAST, Lacpdu};
impl Lab {
    pub(crate) fn schedule_lacp(&mut self, device: DeviceId) -> Result<(), LabError> {
        if self.device(device)?.has_lacp() && self.lacp_timers.insert(device) {
            self.events
                .schedule_at(self.now(), SimulationEvent::LacpTick { device })?;
        }
        Ok(())
    }
    pub(crate) fn lacp_timer(&mut self, device: DeviceId) -> Result<(), LabError> {
        self.lacp_timers.remove(&device);
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&device)
            .ok_or(DropReason::NoLink)?
            .lacp_tick(now);
        for (interface, pdu) in packets {
            self.send_lacp(InterfaceRef { device, interface }, pdu)?;
        }
        if self.device(device)?.has_lacp() && self.lacp_timers.insert(device) {
            self.events
                .schedule_after(1000, SimulationEvent::LacpTick { device })?;
        }
        Ok(())
    }
    pub(crate) fn handle_lacp_frame(
        &mut self,
        interface: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<bool, LabError> {
        if frame.ethertype != EtherType::Other(LACP_ETHERTYPE)
            || frame.destination != MacAddress(LACP_MULTICAST)
        {
            return Ok(false);
        }
        if let Ok(pdu) = Lacpdu::decode(&frame.payload) {
            let now = self.now();
            let response = self
                .devices
                .get_mut(&interface.device)
                .ok_or(DropReason::NoLink)?
                .receive_lacp(interface.interface, pdu, now);
            if let Some(response) = response {
                self.send_lacp(interface, response)?;
            }
        }
        Ok(true)
    }
    fn send_lacp(&mut self, interface: InterfaceRef, pdu: Lacpdu) -> Result<(), LabError> {
        let source = self.device(interface.device)?.interfaces()[&interface.interface].mac_address;
        let frame = EthernetFrame {
            source,
            destination: MacAddress(LACP_MULTICAST),
            ethertype: EtherType::Other(LACP_ETHERTYPE),
            payload: pdu.encode().to_vec(),
        };
        self.transmit_network_frame(interface, frame)
    }
}
