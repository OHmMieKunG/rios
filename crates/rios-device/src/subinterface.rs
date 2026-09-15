//! Routed Ethernet subinterface configuration and VLAN demultiplexing.
use crate::*;
use rios_config::Dot1qEncapsulation;
use rios_ethernet::EtherType;
use std::borrow::Cow;

impl Device {
    pub(crate) fn create_subinterface(
        &mut self,
        canonical: &str,
    ) -> Result<InterfaceId, DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::NotRoutedPort);
        }
        let (parent_name, _) = canonical
            .split_once('.')
            .ok_or_else(|| DeviceError::InvalidInterface(canonical.into()))?;
        let parent = self
            .find_interface(parent_name)
            .ok_or_else(|| DeviceError::InvalidInterface(parent_name.into()))?;
        if self.is_switchport(parent) {
            return Err(DeviceError::NotRoutedPort);
        }
        let mac = self.interfaces[&parent].mac_address;
        let id = self.insert_interface(
            canonical.into(),
            InterfaceKind::EthernetSubinterface,
            InterfaceMedia::Virtual,
        )?;
        self.config_mut(id)?.parent = Some(parent);
        self.config_mut(id)?.admin_state = AdminState::Up;
        self.interfaces
            .get_mut(&id)
            .ok_or(DeviceError::MissingInterface)?
            .mac_address = mac;
        Ok(id)
    }

    /// Configure a unique VLAN and at most one native subinterface per parent.
    pub fn set_dot1q(
        &mut self,
        id: InterfaceId,
        vlan: VlanId,
        native: bool,
    ) -> Result<(), DeviceError> {
        let parent = self
            .running_config
            .interfaces
            .get(&id)
            .and_then(|config| config.parent)
            .ok_or(DeviceError::NotSubinterface)?;
        if self
            .running_config
            .interfaces
            .iter()
            .any(|(other, config)| {
                *other != id
                    && config.parent == Some(parent)
                    && config
                        .dot1q
                        .is_some_and(|tag| tag.vlan == vlan || tag.native && native)
            })
        {
            return Err(DeviceError::DuplicateEncapsulation);
        }
        self.config_mut(id)?.dot1q = Some(Dot1qEncapsulation { vlan, native });
        self.arp_cache.retain(|_, entry| entry.interface != id);
        Ok(())
    }
    /// Select the VLAN used for untagged traffic on a trunk.
    pub fn set_native_vlan(&mut self, id: InterfaceId, vlan: VlanId) -> Result<(), DeviceError> {
        self.switchport_mut(id)?.native_vlan = vlan;
        self.sync_channel_switchports(id);
        self.mac_table.retain(|_, entry| entry.interface != id);
        Ok(())
    }
    /// Return physical egress and wire encapsulation for a routed subinterface.
    pub fn subinterface_egress(
        &self,
        id: InterfaceId,
        frame: EthernetFrame,
    ) -> Option<(InterfaceId, EthernetFrame)> {
        let config = self.running_config.interfaces.get(&id)?;
        let tag = config.dot1q?;
        let parent = config.parent?;
        self.protocol_up(id).then(|| {
            (
                parent,
                if tag.native {
                    frame
                } else {
                    frame.tagged(tag.vlan)
                },
            )
        })
    }
    /// Classify a routed parent's received frame, preserving the logical interface identity.
    pub fn routed_ingress<'a>(
        &self,
        parent: InterfaceId,
        frame: &'a EthernetFrame,
    ) -> Option<(InterfaceId, Cow<'a, EthernetFrame>)> {
        let tagged = frame.ethertype == EtherType::Dot1Q;
        let (vlan, inner) = if tagged {
            let (vlan, frame) = frame.untagged().ok()?;
            (Some(vlan), Cow::Owned(frame))
        } else {
            (None, Cow::Borrowed(frame))
        };
        let selected = self.running_config.interfaces.iter().find(|(_, config)| {
            config.parent == Some(parent)
                && config
                    .dot1q
                    .is_some_and(|tag| vlan.map_or(tag.native, |vlan| tag.vlan == vlan))
        });
        match selected {
            Some((id, _)) if self.protocol_up(*id) => Some((*id, inner)),
            Some(_) => None,
            None if !tagged => Some((parent, inner)),
            None => None,
        }
    }
}
