//! Routing policy syntax uses the same command tree and prefix resolver as device commands.
use super::*;
pub(super) fn add(root: &mut Node, mode: CliMode) {
    use Action::*;
    match mode {
        CliMode::GlobalConfiguration => {
            root.add(
                &[("ip", ""), ("prefix-list", "IPv4 route prefix filter")],
                PrefixList,
            );
            root.add(
                &[
                    ("no", ""),
                    ("ip", ""),
                    ("prefix-list", "Remove prefix list or sequence"),
                ],
                NoPrefixList,
            );
            root.add(&[("route-map", "Ordered routing policy")], RouteMap);
            root.add(
                &[("no", ""), ("route-map", "Remove route map or clause")],
                NoRouteMap,
            );
        }
        CliMode::RouteMapConfiguration(..) => {
            root.add(
                &[
                    ("match", "Route match criteria"),
                    ("ip", ""),
                    ("address", ""),
                    ("prefix-list", "Match a permitted prefix in any named list"),
                ],
                RouteMapMatch,
            );
            root.add(
                &[
                    ("no", ""),
                    ("match", ""),
                    ("ip", ""),
                    ("address", ""),
                    ("prefix-list", "Remove prefix match criteria"),
                ],
                NoRouteMapMatch,
            );
            root.add(
                &[
                    ("set", "Set route attributes"),
                    ("local-preference", "BGP local preference"),
                ],
                RouteMapLocalPref,
            );
            root.add(
                &[
                    ("no", ""),
                    ("set", ""),
                    ("local-preference", "Remove local preference edit"),
                ],
                NoRouteMapLocalPref,
            );
            root.add(&[("set", ""), ("metric", "BGP MED")], RouteMapMetric);
            root.add(
                &[("no", ""), ("set", ""), ("metric", "Remove metric edit")],
                NoRouteMapMetric,
            );
            root.add(
                &[
                    ("set", ""),
                    ("as-path", ""),
                    ("prepend", "Prepend AS numbers"),
                ],
                RouteMapPrepend,
            );
            root.add(
                &[
                    ("no", ""),
                    ("set", ""),
                    ("as-path", ""),
                    ("prepend", "Remove AS prepend edit"),
                ],
                NoRouteMapPrepend,
            );
        }
        _ => {}
    }
}
