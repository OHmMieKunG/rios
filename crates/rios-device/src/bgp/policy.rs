//! BGP attribute edits consume protocol-independent routing policy without changing stored updates.
use super::*;
use rios_config::{BgpPolicy, RouteMapEntry, RoutingPolicyConfig};
pub(super) fn local_attributes(next_hop: Ipv4Addr) -> BgpAttributes {
    BgpAttributes {
        origin: BgpOrigin::Igp,
        as_path: Vec::new(),
        next_hop,
        atomic_aggregate: false,
        med: None,
        local_preference: Some(100),
        originator_id: None,
        cluster_list: Vec::new(),
        unknown_transitive: Vec::new(),
    }
}
pub(super) fn set_attributes(entry: &RouteMapEntry, attributes: &mut BgpAttributes) -> bool {
    if let Some(value) = entry.local_preference {
        attributes.local_preference = Some(value);
    }
    if let Some(value) = entry.metric {
        attributes.med = Some(value);
    }
    attributes.prepend(&entry.as_prepend).is_ok()
}
pub(super) fn apply(
    config: &RoutingPolicyConfig,
    policy: &BgpPolicy,
    prefix: Ipv4Network,
    mut attributes: BgpAttributes,
) -> Option<BgpAttributes> {
    if policy
        .prefix_list
        .as_ref()
        .is_some_and(|name| !config.prefix_permits(name, prefix))
    {
        return None;
    }
    if let Some(name) = &policy.route_map
        && !set_attributes(config.route_map_match(name, prefix)?, &mut attributes)
    {
        return None;
    }
    Some(attributes)
}
