//! Shared validation for DHCP configuration, independent of CLI syntax.
use super::*;
impl Device {
    /// Replace pool options after validating allocation and wire constraints.
    pub fn update_dhcp_pool(
        &mut self,
        id: DhcpPoolId,
        pool: DhcpPoolConfig,
    ) -> Result<(), DeviceError> {
        let old = self
            .running_config
            .dhcp_pools
            .get(&id)
            .ok_or(DeviceError::MissingDhcpPool)?;
        if pool.name != old.name
            || pool.lease_seconds < 60
            || pool.lease_seconds > 365 * 86400
            || !pool.lease_seconds.is_multiple_of(60)
            || pool.dns_servers.len() > 8
            || pool.dns_servers.iter().any(|ip| !valid_address(*ip))
            || pool.default_router.is_some_and(|ip| !valid_address(ip))
            || pool.domain_name.as_ref().is_some_and(|name| {
                name.is_empty()
                    || name.len() > 253
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte))
            })
            || pool
                .network
                .is_some_and(|network| network.prefix_len() > 30)
            || pool.reserved_address.is_some_and(|address| {
                !pool.network.is_some_and(|network| {
                    network.contains(address)
                        && address != network.address()
                        && address != network.broadcast()
                })
            })
            || pool
                .hardware_address
                .is_some_and(|mac| mac.0[0] & 1 != 0 || mac.0 == [0; 6])
        {
            return Err(DeviceError::InvalidDhcpNetwork);
        }
        self.running_config.dhcp_pools.insert(id, pool);
        self.dhcp_offers.retain(|_, offer| offer.pool != id);
        Ok(())
    }
    /// Exclude an inclusive address range from dynamic allocation.
    pub fn exclude_dhcp_addresses(
        &mut self,
        first: Ipv4Addr,
        last: Ipv4Addr,
    ) -> Result<(), DeviceError> {
        if !self.supports_routing() && self.device_type() != DeviceType::Host {
            return Err(DeviceError::DhcpUnsupported);
        }
        if first > last
            || !valid_address(first)
            || !valid_address(last)
            || self.running_config.dhcp_excluded.len() >= 4096
                && !self.running_config.dhcp_excluded.contains_key(&first)
        {
            return Err(DeviceError::InvalidDhcpNetwork);
        }
        self.running_config.dhcp_excluded.insert(first, last);
        self.dhcp_offers
            .retain(|_, offer| offer.address < first || offer.address > last);
        Ok(())
    }
    /// Relay client broadcasts toward a remote DHCP server.
    pub fn set_dhcp_helper(
        &mut self,
        interface: InterfaceId,
        address: Ipv4Addr,
    ) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::DhcpUnsupported);
        }
        if !valid_address(address) {
            return Err(DeviceError::InvalidDhcpNetwork);
        }
        self.config_mut(interface)?.helper_address = Some(address);
        Ok(())
    }
}
fn valid_address(address: Ipv4Addr) -> bool {
    address.octets()[0] != 0 && address.octets()[0] < 224 && !address.is_loopback()
}
