//! Validated structured IPv6 configuration updates.
use super::*;
use rios_config::{Ipv6InterfacePolicy, Ipv6StaticRoute};
impl Device {
    pub fn set_ipv6_routing(&mut self, enabled: bool) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::InvalidIpv6Config);
        }
        self.running_config.ipv6_unicast_routing = enabled;
        Ok(())
    }
    pub fn set_ipv6_policy(
        &mut self,
        id: InterfaceId,
        policy: Ipv6InterfacePolicy,
    ) -> Result<(), DeviceError> {
        let interface = self
            .interfaces
            .get(&id)
            .ok_or(DeviceError::MissingInterface)?;
        if matches!(
            interface.kind,
            InterfaceKind::Serial | InterfaceKind::Console
        ) || self.channel_interface(id).is_some()
        {
            return Err(DeviceError::InvalidIpv6Config);
        }
        let config = self
            .running_config
            .interfaces
            .get(&id)
            .ok_or(DeviceError::MissingInterface)?;
        if config.switchport.is_some() {
            return Err(DeviceError::NotRoutedPort);
        }
        if config.mtu < 1280
            || policy.addresses.len() > ADDRESS_LIMIT - 1
            || policy
                .addresses
                .iter()
                .any(|a| a.address().is_unicast_link_local())
            || policy
                .link_local
                .is_some_and(|ip| !ip.is_unicast_link_local())
        {
            return Err(DeviceError::InvalidIpv6Config);
        }
        if !policy.active() {
            self.reset_ipv6_interface(id);
        } else if let Some(runtime) = self.ipv6.interfaces.get_mut(&id) {
            runtime.addresses.retain(|_, entry| match entry.origin {
                Ipv6AddressOrigin::Manual => policy.addresses.contains(&entry.address),
                Ipv6AddressOrigin::Slaac => policy.autoconfig,
                Ipv6AddressOrigin::LinkLocal => {
                    entry.address.address()
                        == policy
                            .link_local
                            .unwrap_or_else(|| link_local(self.interfaces[&id].mac_address))
                }
            });
        }
        self.running_config
            .interfaces
            .get_mut(&id)
            .ok_or(DeviceError::MissingInterface)?
            .ipv6 = policy;
        Ok(())
    }
    pub fn set_ipv6_address(
        &mut self,
        id: InterfaceId,
        address: Ipv6InterfaceConfig,
    ) -> Result<(), DeviceError> {
        let mut policy = self
            .running_config
            .interfaces
            .get(&id)
            .ok_or(DeviceError::MissingInterface)?
            .ipv6
            .clone();
        policy
            .addresses
            .retain(|old| old.address() != address.address());
        policy.addresses.insert(address);
        self.set_ipv6_policy(id, policy)
    }
    pub fn set_ipv6_static_route(
        &mut self,
        route: Ipv6StaticRoute,
        present: bool,
    ) -> Result<(), DeviceError> {
        if (!self.supports_routing() && self.device_type != DeviceType::Host)
            || route.next_hop.is_unspecified()
            || route.next_hop.is_multicast()
            || (route.next_hop.is_unicast_link_local() && route.interface.is_none())
            || route
                .interface
                .is_some_and(|id| !self.interfaces.contains_key(&id))
        {
            return Err(DeviceError::InvalidIpv6Config);
        }
        if present {
            if self.running_config.ipv6_static_routes.len() >= 4096
                && !self.running_config.ipv6_static_routes.contains(&route)
            {
                return Err(DeviceError::InvalidIpv6Config);
            }
            self.running_config.ipv6_static_routes.insert(route);
        } else {
            self.running_config.ipv6_static_routes.remove(&route);
        }
        Ok(())
    }
}
