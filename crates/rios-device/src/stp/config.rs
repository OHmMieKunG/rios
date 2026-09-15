//! Shared validation for bridge priorities and port policy.
use super::*;
use rios_config::StpPortConfig;
impl Device {
    /// Configure an IEEE bridge priority in multiples of 4096.
    pub fn set_stp_priority(&mut self, vlan: VlanId, priority: u16) -> Result<(), DeviceError> {
        if !self.supports_switching() || !priority.is_multiple_of(4096) {
            return Err(DeviceError::InvalidSpanningTree);
        }
        self.running_config
            .spanning_tree
            .priorities
            .insert(vlan, priority);
        Ok(())
    }
    /// Apply validated spanning-tree port policy.
    pub fn set_stp_port(
        &mut self,
        id: InterfaceId,
        policy: StpPortConfig,
    ) -> Result<(), DeviceError> {
        if !self.is_switchport(id)
            || !policy.priority.is_multiple_of(16)
            || policy
                .cost
                .is_some_and(|cost| cost == 0 || cost > 200_000_000)
        {
            return Err(DeviceError::InvalidSpanningTree);
        }
        if !policy.root_guard {
            for instance in self.stp_runtime.values_mut() {
                if let Some(peer) = instance.received.get_mut(&id) {
                    peer.guarded = false;
                }
            }
        }
        self.config_mut(id)?.spanning_tree = policy;
        Ok(())
    }
    /// Select rapid per-VLAN spanning tree.
    pub fn set_stp_rapid(&mut self, rapid: bool) -> Result<(), DeviceError> {
        if !self.supports_switching() {
            return Err(DeviceError::InvalidSpanningTree);
        }
        self.running_config.spanning_tree.rapid = rapid;
        self.stp_runtime.clear();
        Ok(())
    }
}
