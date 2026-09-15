//! Bounded MQC inventory and physical-interface policy binding.
use super::*;
use crate::route_policy::policy_name_valid;
const INVENTORY_LIMIT: usize = 256;
impl Device {
    /// Create or select a class map; match mode can be changed without rewriting its criteria.
    pub fn ensure_qos_class(
        &mut self,
        name: &str,
        match_all: bool,
    ) -> Result<QosClassId, DeviceError> {
        if !(self.supports_routing() || self.supports_switching())
            || !policy_name_valid(name)
            || name == "class-default"
        {
            return Err(DeviceError::InvalidQosConfig);
        }
        if let Some((id, class)) = self
            .running_config
            .qos
            .classes
            .iter_mut()
            .find(|(_, c)| c.name == name)
        {
            class.match_all = match_all;
            return Ok(*id);
        }
        let classes = &mut self.running_config.qos.classes;
        if classes.len() >= INVENTORY_LIMIT {
            return Err(DeviceError::InvalidQosConfig);
        }
        let id = QosClassId(
            classes
                .last_key_value()
                .map_or(Some(1), |(id, _)| id.0.checked_add(1))
                .ok_or(DeviceError::InvalidQosConfig)?,
        );
        classes.insert(
            id,
            QosClassMap {
                name: name.into(),
                match_all,
                dscp: Default::default(),
                precedence: Default::default(),
                access_lists: Default::default(),
            },
        );
        Ok(id)
    }
    /// Validate and replace class selectors; the stable identity and name cannot be changed.
    pub fn set_qos_class(&mut self, id: QosClassId, class: QosClassMap) -> Result<(), DeviceError> {
        if class.dscp.iter().any(|n| *n > 63)
            || class.precedence.iter().any(|n| *n > 7)
            || class.access_lists.len() > 64
            || class.access_lists.iter().any(|n| !policy_name_valid(n))
        {
            return Err(DeviceError::InvalidQosConfig);
        }
        let target = self
            .running_config
            .qos
            .classes
            .get_mut(&id)
            .ok_or(DeviceError::InvalidQosConfig)?;
        if target.name != class.name {
            return Err(DeviceError::InvalidQosConfig);
        }
        *target = class;
        Ok(())
    }
    /// Remove an unused class map. Referenced classes must first be removed from their policies.
    pub fn remove_qos_class(&mut self, name: &str) -> Result<(), DeviceError> {
        let Some(id) = self
            .running_config
            .qos
            .classes
            .iter()
            .find_map(|(id, c)| (c.name == name).then_some(*id))
        else {
            return Ok(());
        };
        if self
            .running_config
            .qos
            .policies
            .values()
            .any(|p| p.classes.iter().any(|c| c.class == Some(id)))
        {
            return Err(DeviceError::InvalidQosConfig);
        }
        self.running_config.qos.classes.remove(&id);
        Ok(())
    }
    /// Create/select a policy. Its implicit class-default always remains last.
    pub fn ensure_qos_policy(&mut self, name: &str) -> Result<QosPolicyId, DeviceError> {
        if !(self.supports_routing() || self.supports_switching()) || !policy_name_valid(name) {
            return Err(DeviceError::InvalidQosConfig);
        }
        let policies = &mut self.running_config.qos.policies;
        if let Some(id) = policies
            .iter()
            .find_map(|(id, p)| (p.name == name).then_some(*id))
        {
            return Ok(id);
        }
        if policies.len() >= INVENTORY_LIMIT {
            return Err(DeviceError::InvalidQosConfig);
        }
        let id = QosPolicyId(
            policies
                .last_key_value()
                .map_or(Some(1), |(id, _)| id.0.checked_add(1))
                .ok_or(DeviceError::InvalidQosConfig)?,
        );
        policies.insert(
            id,
            QosPolicyMap {
                name: name.into(),
                classes: vec![QosPolicyClass::default()],
            },
        );
        Ok(id)
    }
    /// Select/add a named class in a policy, returning None for class-default.
    pub fn ensure_qos_policy_class(
        &mut self,
        policy: QosPolicyId,
        name: &str,
    ) -> Result<Option<QosClassId>, DeviceError> {
        let id = if name == "class-default" {
            None
        } else {
            Some(
                self.running_config
                    .qos
                    .classes
                    .iter()
                    .find_map(|(id, c)| (c.name == name).then_some(*id))
                    .ok_or(DeviceError::InvalidQosConfig)?,
            )
        };
        let policy = self
            .running_config
            .qos
            .policies
            .get_mut(&policy)
            .ok_or(DeviceError::InvalidQosConfig)?;
        if !policy.classes.iter().any(|c| c.class == id) {
            if policy.classes.len() >= 64 {
                return Err(DeviceError::InvalidQosConfig);
            }
            policy.classes.insert(
                policy.classes.len().saturating_sub(1),
                QosPolicyClass {
                    class: id,
                    ..Default::default()
                },
            );
        }
        Ok(id)
    }
    /// Validate and edit one existing policy class's real scheduling actions.
    pub fn set_qos_policy_class(
        &mut self,
        id: QosPolicyId,
        class: QosPolicyClass,
    ) -> Result<(), DeviceError> {
        if class
            .bandwidth_kbps
            .is_some_and(|kbps| !(1..=1_000_000_000).contains(&kbps))
            || class.bandwidth_kbps.is_some() && class.priority.is_some()
            || class
                .priority
                .is_some_and(|r| r.bits_per_second % 1000 != 0)
            || [class.priority, class.police, class.shape]
                .into_iter()
                .flatten()
                .any(|r| !r.valid())
        {
            return Err(DeviceError::InvalidQosConfig);
        }
        let policy = self
            .running_config
            .qos
            .policies
            .get_mut(&id)
            .ok_or(DeviceError::InvalidQosConfig)?;
        let target = policy
            .classes
            .iter_mut()
            .find(|c| c.class == class.class)
            .ok_or(DeviceError::InvalidQosConfig)?;
        *target = class;
        Ok(())
    }
    /// Remove a policy class, or reset the implicit class-default's actions.
    pub fn remove_qos_policy_class(
        &mut self,
        id: QosPolicyId,
        name: &str,
    ) -> Result<(), DeviceError> {
        let class = if name == "class-default" {
            None
        } else {
            Some(
                self.running_config
                    .qos
                    .classes
                    .iter()
                    .find_map(|(id, c)| (c.name == name).then_some(*id))
                    .ok_or(DeviceError::InvalidQosConfig)?,
            )
        };
        let policy = self
            .running_config
            .qos
            .policies
            .get_mut(&id)
            .ok_or(DeviceError::InvalidQosConfig)?;
        if class.is_none() {
            if let Some(default) = policy.classes.iter_mut().find(|c| c.class.is_none()) {
                *default = QosPolicyClass::default();
            }
        } else {
            policy.classes.retain(|c| c.class != class);
        }
        Ok(())
    }
    /// Remove an unattached policy; interface references never become dangling.
    pub fn remove_qos_policy(&mut self, name: &str) -> Result<(), DeviceError> {
        let Some(id) = self
            .running_config
            .qos
            .policies
            .iter()
            .find_map(|(id, p)| (p.name == name).then_some(*id))
        else {
            return Ok(());
        };
        if self
            .running_config
            .interfaces
            .values()
            .any(|i| i.service_policy_output == Some(id))
        {
            return Err(DeviceError::InvalidQosConfig);
        }
        self.running_config.qos.policies.remove(&id);
        Ok(())
    }
    /// Bind an output queueing policy to a physical Ethernet interface.
    pub fn set_service_policy_output(
        &mut self,
        interface: InterfaceId,
        policy: Option<QosPolicyId>,
    ) -> Result<(), DeviceError> {
        if !self
            .interfaces
            .get(&interface)
            .is_some_and(|i| i.kind.is_ethernet())
            || policy.is_some_and(|id| !self.running_config.qos.policies.contains_key(&id))
        {
            return Err(DeviceError::InvalidQosConfig);
        }
        self.config_mut(interface)?.service_policy_output = policy;
        Ok(())
    }
}
