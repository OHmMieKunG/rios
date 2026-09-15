//! BGP owns application deadlines; TCP owns reliable delivery over the ordinary IPv4 pipeline.
use super::*;

impl Lab {
    pub(crate) fn schedule_bgp_now(&mut self, device: DeviceId) -> Result<(), LabError> {
        self.schedule_bgp_at(device, self.now())
    }
    fn schedule_bgp_at(&mut self, device: DeviceId, deadline: SimTime) -> Result<(), LabError> {
        if !self.device(device)?.has_bgp() {
            return Ok(());
        }
        let generation = self.bgp_generations.entry(device).or_default();
        *generation = generation.checked_add(1).ok_or(LabError::Capacity)?;
        self.events.schedule_at(
            deadline,
            SimulationEvent::BgpTimer {
                device,
                generation: *generation,
            },
        )?;
        Ok(())
    }
    pub(crate) fn tick_bgp(&mut self, device: DeviceId, generation: u64) -> Result<(), LabError> {
        if self.bgp_generations.get(&device) != Some(&generation) {
            return Ok(());
        }
        self.pump_bgp(device)
    }
    pub(super) fn pump_bgp(&mut self, device: DeviceId) -> Result<(), LabError> {
        if !self.device(device)?.has_bgp() {
            return Ok(());
        }
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .bgp_tick(now);
        for packet in packets {
            self.transmit_tcp_packet(device, packet)?;
        }
        self.ensure_tcp_timer(device)?;
        let deadline = self.device(device)?.bgp_next_deadline(now);
        self.schedule_bgp_at(device, deadline)
    }
}
