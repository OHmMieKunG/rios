//! Validated sequenced ACL configuration and match accounting.
use crate::*;
use rios_config::{
    AccessList, AccessListAction, AclEntry, AclId, AclKind, AclProtocol, AddressMatch, PortMatch,
};
use rios_ipv4::Ipv4Packet;

impl Device {
    /// Resolve a named or extended numbered access list.
    pub fn acl_id(&self, name: &str) -> Option<AclId> {
        self.running_config
            .named_access_lists
            .iter()
            .find_map(|(id, list)| (list.name == name).then_some(*id))
    }
    /// Create or select a list. Numeric names must match IOS ACL ranges.
    pub fn ensure_acl(&mut self, name: &str, kind: AclKind) -> Result<AclId, DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::AccessListUnsupported);
        }
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(DeviceError::InvalidAccessList);
        }
        if name.bytes().all(|byte| byte.is_ascii_digit()) {
            let number = name
                .parse::<u16>()
                .map_err(|_| DeviceError::InvalidAccessList)?;
            let valid = match kind {
                AclKind::Standard => (1..=99).contains(&number) || (1300..=1999).contains(&number),
                AclKind::Extended => {
                    (100..=199).contains(&number) || (2000..=2699).contains(&number)
                }
            };
            if !valid || name != number.to_string() {
                return Err(DeviceError::InvalidAccessList);
            }
        }
        if let Some(id) = self.acl_id(name) {
            return if self.running_config.named_access_lists[&id].kind == kind {
                Ok(id)
            } else {
                Err(DeviceError::InvalidAccessList)
            };
        }
        if self.running_config.named_access_lists.len() >= 4096 {
            return Err(DeviceError::AccessListCapacity);
        }
        let id = AclId(
            self.running_config
                .named_access_lists
                .last_key_value()
                .map_or(Ok(1), |(id, _)| {
                    id.0.checked_add(1).ok_or(DeviceError::AccessListCapacity)
                })?,
        );
        let mut entries = BTreeMap::new();
        // Promote an existing legacy numbered standard list without losing its rules.
        if kind == AclKind::Standard
            && let Ok(number) = name.parse::<u8>()
            && let Some(old_id) = AccessListId::new(number)
            && let Some(old) = self.running_config.access_lists.remove(&old_id)
        {
            for (index, entry) in old.into_iter().enumerate() {
                entries.insert(
                    (index as u32 + 1) * 10,
                    AclEntry::Rule {
                        action: entry.action,
                        protocol: AclProtocol::Ip,
                        source: AddressMatch {
                            address: entry.source,
                            wildcard: entry.wildcard,
                        },
                        source_port: PortMatch::Any,
                        destination: AddressMatch::ANY,
                        destination_port: PortMatch::Any,
                        log: false,
                    },
                );
            }
        }
        self.running_config.named_access_lists.insert(
            id,
            AccessList {
                name: name.into(),
                kind,
                entries,
            },
        );
        Ok(id)
    }
    /// Insert or replace a validated sequence; absent sequence appends in steps of ten.
    pub fn set_acl_entry(
        &mut self,
        id: AclId,
        sequence: Option<u32>,
        entry: AclEntry,
    ) -> Result<(), DeviceError> {
        let list = self
            .running_config
            .named_access_lists
            .get_mut(&id)
            .ok_or(DeviceError::MissingAccessList)?;
        let sequence = sequence.unwrap_or(
            list.entries
                .last_key_value()
                .map_or(10, |(last, _)| last.saturating_add(10)),
        );
        if sequence == 0 || sequence == u32::MAX {
            return Err(DeviceError::InvalidAccessList);
        }
        if list.entries.len() >= 4096 && !list.entries.contains_key(&sequence) {
            return Err(DeviceError::AccessListCapacity);
        }
        match &entry {
            AclEntry::Remark(text) if text.len() > 240 || text.chars().any(char::is_control) => {
                return Err(DeviceError::InvalidAccessList);
            }
            AclEntry::Rule {
                protocol,
                source_port,
                destination,
                destination_port,
                ..
            } => {
                if [source_port, destination_port]
                    .iter()
                    .any(|port| matches!(port, PortMatch::Range(a, b) if a > b))
                {
                    return Err(DeviceError::InvalidAccessList);
                }
                if !matches!(protocol, AclProtocol::Tcp | AclProtocol::Udp)
                    && (*source_port != PortMatch::Any || *destination_port != PortMatch::Any)
                {
                    return Err(DeviceError::InvalidAccessList);
                }
                if list.kind == AclKind::Standard
                    && (*protocol != AclProtocol::Ip || *destination != AddressMatch::ANY)
                {
                    return Err(DeviceError::InvalidAccessList);
                }
            }
            _ => {}
        }
        list.entries.insert(sequence, entry);
        self.acl_matches.remove(&(id, sequence));
        self.acl_logs.remove(&(id, sequence));
        Ok(())
    }
    /// Remove one sequence and its runtime counters.
    pub fn remove_acl_entry(&mut self, id: AclId, sequence: u32) -> Result<(), DeviceError> {
        self.running_config
            .named_access_lists
            .get_mut(&id)
            .ok_or(DeviceError::MissingAccessList)?
            .entries
            .remove(&sequence);
        self.acl_matches.remove(&(id, sequence));
        self.acl_logs.remove(&(id, sequence));
        Ok(())
    }
    /// Apply a named list to one ingress or egress direction.
    pub fn set_named_access_group(
        &mut self,
        interface: InterfaceId,
        name: &str,
        direction: AccessListDirection,
    ) -> Result<(), DeviceError> {
        let id = self.acl_id(name).ok_or(DeviceError::MissingAccessList)?;
        let config = self.config_mut(interface)?;
        match direction {
            AccessListDirection::In => {
                config.named_access_group_in = Some(id);
                config.access_group_in = None;
            }
            AccessListDirection::Out => {
                config.named_access_group_out = Some(id);
                config.access_group_out = None;
            }
        }
        Ok(())
    }
    /// Number of packets matching one sequence since it was last edited.
    pub fn acl_match_count(&self, id: AclId, sequence: u32) -> u64 {
        self.acl_matches.get(&(id, sequence)).copied().unwrap_or(0)
    }
    pub(crate) fn evaluate_named_acl(&mut self, id: AclId, packet: &Ipv4Packet) -> bool {
        let found = self
            .running_config
            .named_access_lists
            .get(&id)
            .and_then(|list| {
                list.entries.iter().find_map(|(sequence, entry)| {
                    entry.evaluate(packet).map(|action| {
                        (
                            *sequence,
                            action,
                            matches!(entry, AclEntry::Rule { log: true, .. }),
                        )
                    })
                })
            });
        let Some((sequence, action, log)) = found else {
            return false;
        };
        let count = self.acl_matches.entry((id, sequence)).or_default();
        *count = count.saturating_add(1);
        if log {
            let count = self.acl_logs.entry((id, sequence)).or_default();
            *count = count.saturating_add(1);
        }
        action == AccessListAction::Permit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rios_ipv4::IpProtocol;
    #[test]
    fn ordered_extended_rules_enforce_ports_count_matches_and_remove_sequences() {
        let mut device = Device::standalone();
        let list = device.ensure_acl("WEB-IN", AclKind::Extended).unwrap();
        device
            .set_acl_entry(list, Some(5), AclEntry::Remark("Web service".into()))
            .unwrap();
        let rule = AclEntry::Rule {
            action: AccessListAction::Permit,
            protocol: AclProtocol::Tcp,
            source: AddressMatch::ANY,
            source_port: PortMatch::Range(1000, 2000),
            destination: AddressMatch {
                address: "192.0.2.10".parse().unwrap(),
                wildcard: std::net::Ipv4Addr::UNSPECIFIED,
            },
            destination_port: PortMatch::Eq(443),
            log: true,
        };
        device.set_acl_entry(list, Some(10), rule).unwrap();
        device
            .set_named_access_group(InterfaceId(1), "WEB-IN", AccessListDirection::In)
            .unwrap();
        let mut packet = Ipv4Packet {
            source: "10.0.0.1".parse().unwrap(),
            destination: "192.0.2.10".parse().unwrap(),
            protocol: IpProtocol::Other(6),
            ttl: 64,
            payload: vec![0x05, 0xdc, 1, 0xbb],
        };
        assert!(device.permits_ipv4(InterfaceId(1), AccessListDirection::In, &packet));
        assert_eq!(device.acl_match_count(list, 10), 1);
        packet.payload[3] = 80;
        assert!(!device.permits_ipv4(InterfaceId(1), AccessListDirection::In, &packet));
        packet.payload.truncate(2);
        assert!(!device.permits_ipv4(InterfaceId(1), AccessListDirection::In, &packet));
        device.remove_acl_entry(list, 10).unwrap();
        assert_eq!(device.acl_match_count(list, 10), 0);
        assert!(!device.permits_ipv4(InterfaceId(1), AccessListDirection::In, &packet));
    }
}
