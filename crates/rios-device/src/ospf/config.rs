//! Validated process and interface configuration, with no protocol runtime mutation in the parser.
use super::*;
impl Device {
    /// Create or select the device's single OSPF process.
    pub fn set_ospf_process(&mut self, process_id: u16) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::OspfUnsupported);
        }
        if process_id == 0 {
            return Err(DeviceError::InvalidOspfProcess);
        }
        match &mut self.running_config.ospf {
            Some(config) => config.process_id = process_id,
            None => {
                self.running_config.ospf = Some(OspfConfig {
                    process_id,
                    networks: BTreeSet::new(),
                    router_id: None,
                    passive_interfaces: BTreeSet::new(),
                    default_information: None,
                    redistribute_static: None,
                })
            }
        }
        Ok(())
    }
    /// Select an area for matching interfaces. More-specific wildcard statements win.
    pub fn add_ospf_network(&mut self, network: OspfNetworkConfig) -> Result<(), DeviceError> {
        let config = self
            .running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?;
        if config.networks.len() >= 1024 && !config.networks.contains(&network) {
            return Err(DeviceError::InvalidOspfConfig);
        }
        config.networks.insert(network);
        Ok(())
    }
    /// Configure a stable process identity; changing it restarts this process runtime.
    pub fn set_ospf_router_id(&mut self, id: Option<Ipv4Addr>) -> Result<(), DeviceError> {
        if id.is_some_and(|id| id.is_unspecified() || id.is_multicast() || id.is_broadcast()) {
            return Err(DeviceError::InvalidOspfConfig);
        }
        self.running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?
            .router_id = id;
        self.ospf_runtime = OspfRuntime::default();
        Ok(())
    }
    /// Suppress Hellos and adjacencies while retaining the interface as a stub network.
    pub fn set_ospf_passive(
        &mut self,
        interface: InterfaceId,
        passive: bool,
    ) -> Result<(), DeviceError> {
        if !self.running_config.interfaces.contains_key(&interface) {
            return Err(DeviceError::MissingInterface);
        }
        let config = self
            .running_config
            .ospf
            .as_mut()
            .ok_or(DeviceError::InvalidOspfProcess)?;
        if passive {
            config.passive_interfaces.insert(interface);
        } else {
            config.passive_interfaces.remove(&interface);
        }
        Ok(())
    }
    /// Validate and update interface protocol policy. Timer/network changes restart neighbors.
    pub fn set_ospf_interface(
        &mut self,
        interface: InterfaceId,
        policy: OspfInterfaceConfig,
    ) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::OspfUnsupported);
        }
        if policy.cost == 0
            || policy.hello_interval == 0
            || policy.dead_interval == 0
            || policy.dead_interval > 65535
        {
            return Err(DeviceError::InvalidOspfConfig);
        }
        self.running_config
            .interfaces
            .get_mut(&interface)
            .ok_or(DeviceError::MissingInterface)?
            .ospf = policy;
        Ok(())
    }
    /// Operational interfaces with area assignment, including passive stub interfaces.
    pub fn ospf_interfaces(&self) -> Vec<(InterfaceId, Ipv4InterfaceConfig, u32)> {
        let Some(config) = &self.running_config.ospf else {
            return vec![];
        };
        self.running_config
            .interfaces
            .keys()
            .filter_map(|id| {
                let ip = self.interface_ipv4(*id)?;
                let area = config
                    .networks
                    .iter()
                    .filter(|network| network.matches(ip.address()))
                    .min_by_key(|n| (u32::from(n.wildcard).count_ones(), *n))?
                    .area;
                self.protocol_up(*id).then_some((*id, ip, area))
            })
            .collect()
    }
    pub(super) fn ospf_passive(&self, id: InterfaceId) -> bool {
        self.interfaces
            .get(&id)
            .is_none_or(|port| port.kind == InterfaceKind::Loopback)
            || self
                .running_config
                .ospf
                .as_ref()
                .is_some_and(|c| c.passive_interfaces.contains(&id))
    }
}
