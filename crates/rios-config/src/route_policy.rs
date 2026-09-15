//! Ordered IPv4 prefix filters and route-map clauses, independent of any routing protocol.
use crate::AccessListAction;
use rios_ipv4::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Stable identity used by route-map CLI sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RouteMapId(pub u32);
/// Prefix containment plus optional longer-prefix bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixListEntry {
    pub action: AccessListAction,
    pub prefix: Ipv4Network,
    pub ge: Option<u8>,
    pub le: Option<u8>,
}
impl PrefixListEntry {
    /// Reject contradictory or impossible prefix-length bounds.
    pub fn valid(&self) -> bool {
        let bits = self.prefix.prefix_len();
        bits <= 32
            && self.ge.is_none_or(|ge| ge > bits && ge <= 32)
            && self.le.is_none_or(|le| le >= bits && le <= 32)
            && self.ge.zip(self.le).is_none_or(|(ge, le)| ge <= le)
    }
    /// Match the exact prefix unless ge/le explicitly permits more-specific networks.
    pub fn matches(&self, prefix: Ipv4Network) -> bool {
        self.valid()
            && self.prefix.contains(prefix.address())
            && prefix.prefix_len() >= self.ge.unwrap_or(self.prefix.prefix_len())
            && prefix.prefix_len()
                <= self.le.unwrap_or(if self.ge.is_some() {
                    32
                } else {
                    self.prefix.prefix_len()
                })
    }
}
/// A first-match route-map clause. Empty match criteria match every route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMapEntry {
    pub action: AccessListAction,
    pub prefix_lists: BTreeSet<String>,
    pub local_preference: Option<u32>,
    pub metric: Option<u32>,
    pub as_prepend: Vec<u32>,
}
impl RouteMapEntry {
    /// Create a permit/deny clause with no match constraints or attribute edits.
    pub fn new(action: AccessListAction) -> Self {
        Self {
            action,
            prefix_lists: BTreeSet::new(),
            local_preference: None,
            metric: None,
            as_prepend: Vec::new(),
        }
    }
}
/// Named, ordered route-map clauses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMap {
    pub name: String,
    pub entries: BTreeMap<u32, RouteMapEntry>,
}
/// Persistent routing policy shared by protocol configuration consumers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingPolicyConfig {
    pub prefix_lists: BTreeMap<String, BTreeMap<u32, PrefixListEntry>>,
    pub route_maps: BTreeMap<RouteMapId, RouteMap>,
}
impl RoutingPolicyConfig {
    /// Ordered prefix-list evaluation, with implicit deny including missing lists.
    pub fn prefix_permits(&self, name: &str, prefix: Ipv4Network) -> bool {
        self.prefix_lists
            .get(name)
            .and_then(|list| list.values().find(|e| e.matches(prefix)))
            .is_some_and(|entry| entry.action == AccessListAction::Permit)
    }
    /// Return the first permitted clause; a matching deny or absent match rejects the route.
    pub fn route_map_match(&self, name: &str, prefix: Ipv4Network) -> Option<&RouteMapEntry> {
        let map = self.route_maps.values().find(|map| map.name == name)?;
        let entry = map.entries.values().find(|entry| {
            entry.prefix_lists.is_empty()
                || entry
                    .prefix_lists
                    .iter()
                    .any(|name| self.prefix_permits(name, prefix))
        })?;
        (entry.action == AccessListAction::Permit).then_some(entry)
    }
    /// Render replayable configuration from structured rules.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let action = |a| {
            if a == AccessListAction::Permit {
                "permit"
            } else {
                "deny"
            }
        };
        let mut out = String::new();
        for (name, entries) in &self.prefix_lists {
            for (seq, entry) in entries {
                let _ = write!(
                    out,
                    "ip prefix-list {name} seq {seq} {} {}/{}",
                    action(entry.action),
                    entry.prefix.address(),
                    entry.prefix.prefix_len()
                );
                if let Some(ge) = entry.ge {
                    let _ = write!(out, " ge {ge}");
                }
                if let Some(le) = entry.le {
                    let _ = write!(out, " le {le}");
                }
                out.push('\n');
            }
        }
        for map in self.route_maps.values() {
            for (seq, entry) in &map.entries {
                let _ = writeln!(out, "route-map {} {} {seq}", map.name, action(entry.action));
                if !entry.prefix_lists.is_empty() {
                    out.push_str(" match ip address prefix-list");
                    for name in &entry.prefix_lists {
                        let _ = write!(out, " {name}");
                    }
                    out.push('\n');
                }
                if let Some(value) = entry.local_preference {
                    let _ = writeln!(out, " set local-preference {value}");
                }
                if let Some(value) = entry.metric {
                    let _ = writeln!(out, " set metric {value}");
                }
                if !entry.as_prepend.is_empty() {
                    out.push_str(" set as-path prepend");
                    for asn in &entry.as_prepend {
                        let _ = write!(out, " {asn}");
                    }
                    out.push('\n');
                }
                out.push_str("!\n");
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prefix(address: &str, bits: u8) -> Ipv4Network {
        Ipv4Network::new(address.parse().unwrap(), bits).unwrap()
    }
    #[test]
    fn ordered_prefix_filters_and_route_map_implicit_deny() {
        let entry = |action, ge, le| PrefixListEntry {
            action,
            prefix: prefix("10.0.0.0", 8),
            ge,
            le,
        };
        let permit = AccessListAction::Permit;
        let deny = AccessListAction::Deny;
        assert!(!entry(permit, Some(8), None).valid());
        assert!(!entry(permit, Some(24), Some(16)).valid());
        assert!(!entry(permit, None, Some(33)).valid());
        assert!(entry(permit, None, None).matches(prefix("10.0.0.0", 8)));
        assert!(!entry(permit, None, None).matches(prefix("10.1.0.0", 16)));
        let mut policy = RoutingPolicyConfig::default();
        policy.prefix_lists.insert(
            "TEN".into(),
            BTreeMap::from([
                (5, entry(deny, Some(25), None)),
                (10, entry(permit, Some(16), Some(24))),
            ]),
        );
        assert!(policy.prefix_permits("TEN", prefix("10.1.0.0", 16)));
        assert!(!policy.prefix_permits("TEN", prefix("10.1.0.0", 25)));
        assert!(!policy.prefix_permits("TEN", prefix("11.1.0.0", 16)));
        assert!(!policy.prefix_permits("missing", prefix("10.1.0.0", 16)));
        let mut rule = RouteMapEntry::new(permit);
        rule.prefix_lists.insert("TEN".into());
        rule.local_preference = Some(250);
        policy.route_maps.insert(
            RouteMapId(1),
            RouteMap {
                name: "IN".into(),
                entries: BTreeMap::from([(10, rule)]),
            },
        );
        assert_eq!(
            policy
                .route_map_match("IN", prefix("10.1.0.0", 16))
                .unwrap()
                .local_preference,
            Some(250)
        );
        assert!(
            policy
                .route_map_match("IN", prefix("10.1.0.0", 25))
                .is_none()
        );
        policy
            .route_maps
            .get_mut(&RouteMapId(1))
            .unwrap()
            .entries
            .insert(5, RouteMapEntry::new(deny));
        assert!(
            policy
                .route_map_match("IN", prefix("10.1.0.0", 16))
                .is_none()
        );
    }
}
