//! OSPFv3 syntax in the shared command tree.
use super::*;
pub(super) fn add(root: &mut Node, mode: CliMode) {
    use Action::*;
    match mode {
        CliMode::UserExec | CliMode::PrivilegedExec => {
            for (word, action) in [
                ("neighbor", V3Neighbor),
                ("interface", V3Interface),
                ("database", V3Database),
            ] {
                root.add(
                    &[
                        ("show", ""),
                        ("ipv6", ""),
                        ("ospf", "OSPFv3 information"),
                        (word, "IPv6 OSPF state"),
                    ],
                    action,
                );
            }
        }
        CliMode::GlobalConfiguration => {
            root.add(
                &[
                    ("ipv6", ""),
                    ("router", "Routing process"),
                    ("ospf", "OSPFv3 process"),
                ],
                RouterOspfv3,
            );
            root.add(
                &[
                    ("no", ""),
                    ("ipv6", ""),
                    ("router", ""),
                    ("ospf", "Remove OSPFv3 process"),
                ],
                NoRouterOspfv3,
            );
        }
        CliMode::RouterConfiguration(crate::RoutingProtocol::Ospfv3) => {
            root.add(&[("router-id", "Set 32-bit OSPF router ID")], OspfRouterId);
            root.add(
                &[("no", ""), ("router-id", "Select router ID automatically")],
                NoOspfRouterId,
            );
            root.add(
                &[("passive-interface", "Suppress adjacency on interface")],
                OspfPassive,
            );
            root.add(
                &[
                    ("no", ""),
                    ("passive-interface", "Enable adjacency on interface"),
                ],
                NoOspfPassive,
            );
        }
        CliMode::InterfaceConfiguration(_)
        | CliMode::SubinterfaceConfiguration(_)
        | CliMode::InterfaceRangeConfiguration(..) => {
            root.add(
                &[("ipv6", ""), ("ospf", "OSPFv3 interface configuration")],
                BindOspfv3,
            );
            root.add(
                &[("no", ""), ("ipv6", ""), ("ospf", "Remove OSPFv3 binding")],
                NoBindOspfv3,
            );
            for (word, set, clear) in [
                ("cost", V3Cost, NoV3Cost),
                ("priority", V3Priority, NoV3Priority),
                ("hello-interval", V3Hello, NoV3Hello),
                ("dead-interval", V3Dead, NoV3Dead),
            ] {
                root.add(
                    &[
                        ("ipv6", ""),
                        ("ospf", ""),
                        (word, "OSPFv3 interface policy"),
                    ],
                    set,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("ipv6", ""),
                        ("ospf", ""),
                        (word, "Restore default policy"),
                    ],
                    clear,
                );
            }
            for (word, action) in [
                ("point-to-point", V3PointToPoint),
                ("broadcast", V3Broadcast),
            ] {
                root.add(
                    &[
                        ("ipv6", ""),
                        ("ospf", ""),
                        ("network", "Network type"),
                        (word, "OSPFv3 network type"),
                    ],
                    action,
                );
            }
            root.add(
                &[
                    ("no", ""),
                    ("ipv6", ""),
                    ("ospf", ""),
                    ("network", "Restore broadcast network type"),
                ],
                V3Broadcast,
            );
        }
        _ => {}
    }
}
