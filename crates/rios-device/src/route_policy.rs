//! Validated, bounded configuration APIs for prefix lists and route maps.
use crate::*;
use rios_config::{AccessListAction, PrefixListEntry, RouteMap, RouteMapEntry, RouteMapId};
const POLICY_LIMIT: usize = 256;
const ENTRY_LIMIT: usize = 4096;
pub(crate) fn policy_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
impl Device {
    /// Insert or replace a prefix rule; omitted sequences advance by five.
    pub fn set_prefix_list_entry(
        &mut self,
        name: &str,
        sequence: Option<u32>,
        entry: PrefixListEntry,
    ) -> Result<u32, DeviceError> {
        if !self.supports_routing() || !policy_name_valid(name) || !entry.valid() {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        let lists = &mut self.running_config.routing_policy.prefix_lists;
        let existing = lists.get(name);
        let seq = sequence
            .or_else(|| {
                existing
                    .and_then(|l| l.last_key_value())
                    .map_or(Some(5), |(n, _)| n.checked_add(5))
            })
            .filter(|n| *n > 0 && *n < u32::MAX)
            .ok_or(DeviceError::InvalidRoutingPolicy)?;
        if existing.is_none() && lists.len() >= POLICY_LIMIT
            || existing.is_some_and(|l| l.len() >= ENTRY_LIMIT && !l.contains_key(&seq))
        {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        lists.entry(name.into()).or_default().insert(seq, entry);
        Ok(seq)
    }
    /// Remove a sequence or an entire list. Bound references remain and deny unmatched routes.
    pub fn remove_prefix_list(
        &mut self,
        name: &str,
        sequence: Option<u32>,
    ) -> Result<(), DeviceError> {
        if !policy_name_valid(name) {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        let lists = &mut self.running_config.routing_policy.prefix_lists;
        if let Some(seq) = sequence {
            if let Some(entries) = lists.get_mut(name) {
                entries.remove(&seq);
                if entries.is_empty() {
                    lists.remove(name);
                }
            }
        } else {
            lists.remove(name);
        }
        Ok(())
    }
    /// Create/select a route-map clause; existing match and set statements are retained.
    pub fn ensure_route_map(
        &mut self,
        name: &str,
        action: AccessListAction,
        sequence: u32,
    ) -> Result<RouteMapId, DeviceError> {
        if !self.supports_routing()
            || !policy_name_valid(name)
            || sequence == 0
            || sequence == u32::MAX
        {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        let maps = &mut self.running_config.routing_policy.route_maps;
        let existing = maps
            .iter()
            .find_map(|(id, map)| (map.name == name).then_some(*id));
        if existing.is_none() && maps.len() >= POLICY_LIMIT {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        let id = match existing {
            Some(id) => id,
            None => RouteMapId(
                maps.last_key_value()
                    .map_or(Some(1), |(id, _)| id.0.checked_add(1))
                    .ok_or(DeviceError::InvalidRoutingPolicy)?,
            ),
        };
        if maps.get(&id).is_some_and(|map| {
            map.entries.len() >= ENTRY_LIMIT && !map.entries.contains_key(&sequence)
        }) {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        let map = maps.entry(id).or_insert_with(|| RouteMap {
            name: name.into(),
            entries: Default::default(),
        });
        map.entries
            .entry(sequence)
            .or_insert_with(|| RouteMapEntry::new(action))
            .action = action;
        Ok(id)
    }
    /// Replace a validated existing clause atomically.
    pub fn set_route_map_entry(
        &mut self,
        id: RouteMapId,
        sequence: u32,
        entry: RouteMapEntry,
    ) -> Result<(), DeviceError> {
        if entry.prefix_lists.len() > POLICY_LIMIT
            || entry.prefix_lists.iter().any(|n| !policy_name_valid(n))
            || entry.as_prepend.len() > 64
            || entry.as_prepend.iter().any(|n| *n == 0 || *n == u32::MAX)
        {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        let target = self
            .running_config
            .routing_policy
            .route_maps
            .get_mut(&id)
            .and_then(|map| map.entries.get_mut(&sequence))
            .ok_or(DeviceError::InvalidRoutingPolicy)?;
        *target = entry;
        Ok(())
    }
    /// Remove a clause or whole route map without rewriting references in peer configuration.
    pub fn remove_route_map(
        &mut self,
        name: &str,
        sequence: Option<u32>,
    ) -> Result<(), DeviceError> {
        if !policy_name_valid(name) {
            return Err(DeviceError::InvalidRoutingPolicy);
        }
        let maps = &mut self.running_config.routing_policy.route_maps;
        let Some(id) = maps
            .iter()
            .find_map(|(id, map)| (map.name == name).then_some(*id))
        else {
            return Ok(());
        };
        if let Some(seq) = sequence {
            if let Some(map) = maps.get_mut(&id) {
                map.entries.remove(&seq);
                if map.entries.is_empty() {
                    maps.remove(&id);
                }
            }
        } else {
            maps.remove(&id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validated_policy_edits_preserve_state_on_error_and_bound_tables() {
        let mut d = Device::standalone();
        let permit = AccessListAction::Permit;
        let prefix = rios_ipv4::Ipv4Network::new("10.0.0.0".parse().unwrap(), 8).unwrap();
        let entry = PrefixListEntry {
            action: permit,
            prefix,
            ge: Some(16),
            le: Some(24),
        };
        assert_eq!(
            d.set_prefix_list_entry("TEN", None, entry.clone()).unwrap(),
            5
        );
        assert_eq!(
            d.set_prefix_list_entry("TEN", None, entry.clone()).unwrap(),
            10
        );
        let saved = d.running_config().clone();
        assert!(
            d.set_prefix_list_entry("bad name", None, entry.clone())
                .is_err()
        );
        assert!(
            d.set_prefix_list_entry("TEN", Some(0), entry.clone())
                .is_err()
        );
        let mut bad = entry.clone();
        bad.ge = Some(30);
        assert!(d.set_prefix_list_entry("TEN", Some(5), bad).is_err());
        assert_eq!(d.running_config(), &saved);
        for n in 1..POLICY_LIMIT {
            d.set_prefix_list_entry(&format!("P{n}"), None, entry.clone())
                .unwrap();
        }
        assert!(d.set_prefix_list_entry("OVERFLOW", None, entry).is_err());
        d.remove_prefix_list("TEN", Some(5)).unwrap();
        assert!(!d.running_config().routing_policy.prefix_lists["TEN"].contains_key(&5));
        let id = d.ensure_route_map("IN", permit, 10).unwrap();
        let mut rule = RouteMapEntry::new(permit);
        rule.as_prepend = vec![0];
        assert!(d.set_route_map_entry(id, 10, rule).is_err());
        assert!(
            d.running_config().routing_policy.route_maps[&id].entries[&10]
                .as_prepend
                .is_empty()
        );
        d.remove_route_map("IN", Some(10)).unwrap();
        assert!(
            !d.running_config()
                .routing_policy
                .route_maps
                .contains_key(&id)
        );
    }
}
