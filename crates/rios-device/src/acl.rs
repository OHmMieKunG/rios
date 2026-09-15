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
        if let Some(named) = self.acl_id(&id.get().to_string()) {
            return self.set_acl_entry(
                named,
                None,
                rios_config::AclEntry::Rule {
                    action: entry.action,
                    protocol: rios_config::AclProtocol::Ip,
                    source: rios_config::AddressMatch {
                        address: entry.source,
                        wildcard: entry.wildcard,
                    },
                    source_port: rios_config::PortMatch::Any,
                    destination: rios_config::AddressMatch::ANY,
                    destination_port: rios_config::PortMatch::Any,
                    log: false,
                },
            );
        }
        if self
            .running_config
            .access_lists
            .get(&id)
            .is_some_and(|entries| entries.len() >= 4096)
        {
            return Err(DeviceError::AccessListCapacity);
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
        if self.acl_id(&id.get().to_string()).is_some() {
            return self.set_named_access_group(interface, &id.get().to_string(), direction);
        }
        if !self.running_config.access_lists.contains_key(&id) {
            return Err(DeviceError::MissingAccessList);
        }
        let config = self.config_mut(interface)?;
        match direction {
            AccessListDirection::In => {
                config.access_group_in = Some(id);
                config.named_access_group_in = None;
            }
            AccessListDirection::Out => {
                config.access_group_out = Some(id);
                config.named_access_group_out = None;
            }
        }
        Ok(())
    }

    /// Evaluate an interface ACL. A configured list has an implicit final deny.
    pub fn permits_ipv4(
        &mut self,
        interface: InterfaceId,
        direction: AccessListDirection,
        packet: &Ipv4Packet,
    ) -> bool {
        let Some(config) = self.running_config.interfaces.get(&interface) else {
            return false;
        };
        let named = match direction {
            AccessListDirection::In => config.named_access_group_in,
            AccessListDirection::Out => config.named_access_group_out,
        };
        if let Some(id) = named {
            return self.evaluate_named_acl(id, packet);
        }
        let id = match direction {
            AccessListDirection::In => config.access_group_in,
            AccessListDirection::Out => config.access_group_out,
        };
        let Some(id) = id else {
            return true;
        };
        if let Some(named) = self.acl_id(&id.get().to_string()) {
            return self.evaluate_named_acl(named, packet);
        }
        let matched = self
            .running_config
            .access_lists
            .get(&id)
            .and_then(|entries| {
                entries
                    .iter()
                    .enumerate()
                    .find(|(_, entry)| entry.matches(packet.source))
            });
        if let Some((index, entry)) = matched {
            let action = entry.action;
            let counter = self.legacy_acl_matches.entry((id, index)).or_default();
            *counter = counter.saturating_add(1);
            action == AccessListAction::Permit
        } else {
            false
        }
    }

    /// Evaluate a configured standard ACL against one source address.
    pub fn access_list_permits(&self, id: AccessListId, source: std::net::Ipv4Addr) -> bool {
        if let Some(named) = self.acl_id(&id.get().to_string()) {
            let packet = Ipv4Packet {
                dscp_ecn: 0,
                source,
                destination: std::net::Ipv4Addr::UNSPECIFIED,
                ttl: 64,
                protocol: rios_ipv4::IpProtocol::Other(0),
                payload: Vec::new(),
            };
            return self.running_config.named_access_lists[&named]
                .entries
                .values()
                .find_map(|entry| entry.evaluate(&packet))
                == Some(AccessListAction::Permit);
        }
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
            for (index, entry) in entries.iter().enumerate() {
                writeln!(
                    output,
                    "    {} {} {} ({} matches)",
                    match entry.action {
                        AccessListAction::Permit => "permit",
                        AccessListAction::Deny => "deny",
                    },
                    entry.source,
                    entry.wildcard,
                    self.legacy_acl_matches
                        .get(&(*id, index))
                        .copied()
                        .unwrap_or(0)
                )
                .unwrap();
            }
        }
        for (id, list) in &self.running_config.named_access_lists {
            writeln!(output, "{} IP access list {}", list.kind, list.name).unwrap();
            for (sequence, entry) in &list.entries {
                writeln!(
                    output,
                    "    {sequence} {} ({} matches, {} logged)",
                    entry.render(list.kind),
                    self.acl_match_count(*id, *sequence),
                    self.acl_logs.get(&(*id, *sequence)).copied().unwrap_or(0)
                )
                .unwrap();
            }
        }
        output
    }
}
