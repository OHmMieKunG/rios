//! BGP paths share normal command-tree abbreviation and help resolution.
use super::*;
pub(super) fn add(root: &mut Node, mode: CliMode) {
    use Action::*;
    match mode {
        CliMode::UserExec | CliMode::PrivilegedExec => {
            root.add(
                &[("show", ""), ("ip", ""), ("bgp", "IPv4 BGP table")],
                BgpTable,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ip", ""),
                    ("bgp", ""),
                    ("summary", "BGP session summary"),
                ],
                BgpSummary,
            );
            root.add(
                &[
                    ("show", ""),
                    ("ip", ""),
                    ("bgp", ""),
                    ("neighbors", "BGP peer state"),
                ],
                BgpNeighbors,
            );
        }
        CliMode::GlobalConfiguration => {
            root.add(
                &[("router", ""), ("bgp", "BGP autonomous system")],
                RouterBgp,
            );
            root.add(
                &[("no", ""), ("router", ""), ("bgp", "Remove BGP process")],
                NoRouterBgp,
            );
        }
        CliMode::RouterConfiguration(crate::RoutingProtocol::Bgp) => {
            root.add(
                &[
                    ("bgp", "BGP configuration"),
                    ("router-id", "BGP router identifier"),
                ],
                BgpRouterId,
            );
            root.add(
                &[
                    ("no", ""),
                    ("bgp", ""),
                    ("router-id", "Automatic router identifier"),
                ],
                NoBgpRouterId,
            );
            root.add(
                &[
                    ("bgp", ""),
                    ("cluster-id", "Route reflector cluster identifier"),
                ],
                BgpClusterId,
            );
            root.add(
                &[
                    ("no", ""),
                    ("bgp", ""),
                    ("cluster-id", "Use router ID as cluster identifier"),
                ],
                NoBgpClusterId,
            );
            root.add(&[("neighbor", "Configure a BGP peer")], BgpNeighbor);
            root.add(
                &[("no", ""), ("neighbor", "Remove a BGP peer or option")],
                NoBgpNeighbor,
            );
            root.add(
                &[("network", "Originate an exact matching route")],
                BgpNetwork,
            );
            root.add(
                &[("no", ""), ("network", "Withdraw an originated network")],
                NoBgpNetwork,
            );
        }
        _ => {}
    }
}
