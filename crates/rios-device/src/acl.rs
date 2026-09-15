use crate::*;
use rios_config::{AccessListAction, StandardAccessListEntry};
use rios_ipv4::Ipv4Packet;
use std::fmt::Write;

impl Device {
    /// Append an entry to a standard numbered IPv4 access list.
    pub fn add_access_list_entry(
        &mut self,
        id: AccessListId,
        entry: StandardAccessListEntry,
    ) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::AccessListUnsupported);
        }
        self.running_config
            .access_lists
            .entry(id)
            .or_default()
            .push(entry);
        Ok(())
    }

    /// Apply an existing standard ACL to an interface direction.
    pub fn set_access_group(
        &mut self,
        interface: InterfaceId,
        id: AccessListId,
        direction: AccessListDirection,
    ) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::AccessListUnsupported);
        }
        if !self.running_config.access_lists.contains_key(&id) {
            return Err(DeviceError::MissingAccessList);
        }
        let config = self.config_mut(interface)?;
        match direction {
            AccessListDirection::In => config.access_group_in = Some(id),
            AccessListDirection::Out => config.access_group_out = Some(id),
        }
        Ok(())
    }

    /// Evaluate an interface ACL. A configured list has an implicit final deny.
    pub fn permits_ipv4(
        &self,
        interface: InterfaceId,
        direction: AccessListDirection,
        packet: &Ipv4Packet,
    ) -> bool {
        let Some(config) = self.running_config.interfaces.get(&interface) else {
            return false;
        };
        let id = match direction {
            AccessListDirection::In => config.access_group_in,
            AccessListDirection::Out => config.access_group_out,
        };
        let Some(id) = id else {
            return true;
        };
        self.access_list_permits(id, packet.source)
    }

    /// Evaluate a configured standard ACL against one source address.
    pub fn access_list_permits(&self, id: AccessListId, source: std::net::Ipv4Addr) -> bool {
        self.running_config
            .access_lists
            .get(&id)
            .and_then(|entries| entries.iter().find(|entry| entry.matches(source)))
            .is_some_and(|entry| entry.action == AccessListAction::Permit)
    }

    /// Render configured standard numbered IPv4 access lists.
    pub fn show_access_lists(&self) -> String {
        let mut output = String::new();
        for (id, entries) in &self.running_config.access_lists {
            writeln!(output, "Standard IP access list {}", id.get()).unwrap();
            for entry in entries {
                writeln!(
                    output,
                    "    {} {} {}",
                    match entry.action {
                        AccessListAction::Permit => "permit",
                        AccessListAction::Deny => "deny",
                    },
                    entry.source,
                    entry.wildcard
                )
                .unwrap();
            }
        }
        output
    }
}
