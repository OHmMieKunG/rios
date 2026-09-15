//! OSPFv3 configuration validation and operational interface selection.
use super::*;
impl Device {
    pub fn set_ospfv3_process(&mut self, process_id: Option<u16>) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::OspfUnsupported);
        }
        if process_id == Some(0) {
            return Err(DeviceError::InvalidOspfProcess);
        }
        match process_id {
            None => {
                self.running_config.ospfv3 = None;
                self.ospfv3 = OspfV3Runtime::default();
            }
            Some(id) => {
                if self
                    .running_config
                    .ospfv3
                    .as_ref()
                    .is_none_or(|c| c.process_id != id)
                {
                    self.running_config.ospfv3 = Some(rios_config::OspfV3Config {
                        process_id: id,
                        router_id: None,
                        passive_interfaces: BTreeSet::new(),
                    });
                    self.ospfv3 = OspfV3Runtime::default();
                }
            }
        }
        Ok(())
    }
    pub fn set_ospfv3_router_id(&mut self, id: Option<Ipv4Addr>) -> Result<(), DeviceError> {
        if id.is_some_and(|id| id.is_unspecified() || id.is_multicast() || id.is_broadcast()) {
            return Err(DeviceError::InvalidOspfConfig);
        }
        self.running_config
            .ospfv3
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?
            .router_id = id;
        self.ospfv3 = OspfV3Runtime::default();
        Ok(())
    }
    pub fn set_ospfv3_passive(
        &mut self,
        id: InterfaceId,
        passive: bool,
    ) -> Result<(), DeviceError> {
        if !self.interfaces.contains_key(&id) {
            return Err(DeviceError::MissingInterface);
        }
        let config = self
            .running_config
            .ospfv3
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?;
        if passive {
            config.passive_interfaces.insert(id);
        } else {
            config.passive_interfaces.remove(&id);
        }
        Ok(())
    }
    pub fn set_ospfv3_interface(
        &mut self,
        id: InterfaceId,
        binding: Option<OspfV3Binding>,
        parameters: OspfInterfaceConfig,
    ) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::OspfUnsupported);
        }
        if binding.is_some_and(|b| b.process_id == 0)
            || parameters.cost == 0
            || parameters.hello_interval == 0
            || parameters.dead_interval == 0
            || parameters.dead_interval > 65535
            || u32::try_from(id.0).is_err()
        {
            return Err(DeviceError::InvalidOspfConfig);
        }
        let port = self
            .running_config
            .interfaces
            .get_mut(&id)
            .ok_or(DeviceError::MissingInterface)?;
        if port.switchport.is_some() || port.channel_group.is_some() {
            return Err(DeviceError::InvalidOspfConfig);
        }
        port.ipv6.ospf = binding;
        port.ipv6.ospf_parameters = parameters;
        Ok(())
    }
    pub(super) fn ospfv3_active(&self) -> Vec<(InterfaceId, Ipv6Addr, u32)> {
        let Some(process) = &self.running_config.ospfv3 else {
            return Vec::new();
        };
        if !self.ipv6_forwarding_enabled() {
            return Vec::new();
        }
        self.running_config
            .interfaces
            .iter()
            .filter_map(|(id, c)| {
                let binding = c.ipv6.ospf?;
                let local = self.ipv6_link_local(*id)?;
                (binding.process_id == process.process_id
                    && c.ipv6.active()
                    && c.switchport.is_none()
                    && self.protocol_up(*id))
                .then_some((*id, local, binding.area))
            })
            .collect()
    }
    pub(super) fn ospfv3_passive(&self, id: InterfaceId) -> bool {
        self.interfaces
            .get(&id)
            .is_none_or(|p| p.kind == InterfaceKind::Loopback)
            || self
                .running_config
                .ospfv3
                .as_ref()
                .is_some_and(|p| p.passive_interfaces.contains(&id))
    }
}
