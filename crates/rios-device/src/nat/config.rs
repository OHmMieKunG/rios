//! Validated NAT configuration APIs.
use super::*;
impl Device {
    /// Classify an interface as NAT inside or outside.
    pub fn set_nat_role(
        &mut self,
        interface: InterfaceId,
        role: NatRole,
    ) -> Result<(), DeviceError> {
        if self.device_type != DeviceType::Router {
            return Err(DeviceError::NatUnsupported);
        }
        self.config_mut(interface)?.nat_role = Some(role);
        Ok(())
    }
    fn validate_nat_acl(&self, id: AccessListId) -> Result<(), DeviceError> {
        if self.device_type != DeviceType::Router {
            return Err(DeviceError::NatUnsupported);
        }
        if !self.running_config.access_lists.contains_key(&id)
            && self.acl_id(&id.get().to_string()).is_none()
        {
            return Err(DeviceError::InvalidNatConfig);
        }
        Ok(())
    }
    /// Configure dynamic source PAT using an outside interface address.
    pub fn set_nat_overload(
        &mut self,
        access_list: AccessListId,
        outside_interface: InterfaceId,
    ) -> Result<(), DeviceError> {
        self.validate_nat_acl(access_list)?;
        if !self
            .running_config
            .interfaces
            .contains_key(&outside_interface)
        {
            return Err(DeviceError::InvalidNatConfig);
        }
        self.running_config.nat_overload = Some(NatOverloadConfig {
            access_list,
            outside_interface,
        });
        self.running_config.nat_pool_rule = None;
        self.clear_nat_translations();
        Ok(())
    }
    /// Add a nonconflicting static address or port translation.
    pub fn add_static_nat(&mut self, rule: StaticNat) -> Result<(), DeviceError> {
        if self.device_type != DeviceType::Router {
            return Err(DeviceError::NatUnsupported);
        }
        if matches!(
            rule,
            StaticNat::Port { local_port: 0, .. } | StaticNat::Port { global_port: 0, .. }
        ) {
            return Err(DeviceError::InvalidNatConfig);
        }
        if self.running_config.static_nat.contains(&rule) {
            return Ok(());
        }
        if self.running_config.static_nat.len() >= 4096
            || [rule.local(), rule.global()]
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast() || *ip == Ipv4Addr::BROADCAST)
        {
            return Err(DeviceError::InvalidNatConfig);
        }
        if self
            .running_config
            .static_nat
            .iter()
            .any(|old| match (*old, rule) {
                (
                    StaticNat::Port {
                        protocol: a,
                        global_port: ap,
                        local_port: al,
                        ..
                    },
                    StaticNat::Port {
                        protocol: b,
                        global_port: bp,
                        local_port: bl,
                        ..
                    },
                ) => {
                    a == b
                        && (old.global() == rule.global() && ap == bp
                            || old.local() == rule.local() && al == bl)
                }
                _ => old.global() == rule.global() || old.local() == rule.local(),
            })
        {
            return Err(DeviceError::InvalidNatConfig);
        }
        self.running_config.static_nat.insert(rule);
        self.clear_nat_translations();
        Ok(())
    }
    /// Define a bounded inclusive pool inside one subnet.
    pub fn set_nat_pool(&mut self, name: &str, pool: NatPool) -> Result<(), DeviceError> {
        if self.device_type != DeviceType::Router {
            return Err(DeviceError::NatUnsupported);
        }
        let network = rios_ipv4::Ipv4Network::new(pool.first, pool.prefix_len)
            .map_err(|_| DeviceError::InvalidNatConfig)?;
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
            || pool.first > pool.last
            || u32::from(pool.last) - u32::from(pool.first) > 65535
            || !network.contains(pool.last)
            || [pool.first, pool.last].iter().any(|address| {
                let value = u32::from(*address);
                let host_mask = u32::MAX
                    .checked_shr(u32::from(pool.prefix_len))
                    .unwrap_or(0);
                address.octets()[0] == 0
                    || address.is_loopback()
                    || address.octets()[0] >= 224
                    || (pool.prefix_len < 31
                        && (value & host_mask == 0 || value & host_mask == host_mask))
            })
            || self.running_config.nat_pools.len() >= 256
                && !self.running_config.nat_pools.contains_key(name)
        {
            return Err(DeviceError::InvalidNatConfig);
        }
        self.running_config.nat_pools.insert(name.into(), pool);
        self.clear_nat_translations();
        Ok(())
    }
    /// Select a configured pool for dynamic NAT, optionally with PAT.
    pub fn set_nat_pool_rule(&mut self, rule: NatPoolRule) -> Result<(), DeviceError> {
        self.validate_nat_acl(rule.access_list)?;
        if !self.running_config.nat_pools.contains_key(&rule.pool) {
            return Err(DeviceError::InvalidNatConfig);
        }
        self.running_config.nat_pool_rule = Some(rule);
        self.running_config.nat_overload = None;
        self.clear_nat_translations();
        Ok(())
    }
}
