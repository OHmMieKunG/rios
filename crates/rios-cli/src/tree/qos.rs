//! MQC command keywords feed the common abbreviation resolver.
use super::*;
pub(super) fn add(root: &mut Node, mode: CliMode) {
    use Action::*;
    match mode {
        CliMode::GlobalConfiguration => {
            for (word, yes, no, help) in [
                (
                    "class-map",
                    QosClassMap,
                    NoQosClassMap,
                    "Packet classification",
                ),
                (
                    "policy-map",
                    QosPolicyMap,
                    NoQosPolicyMap,
                    "Output queueing policy",
                ),
            ] {
                root.add(&[(word, help)], yes);
                root.add(&[("no", ""), (word, "Remove unused definition")], no);
            }
        }
        CliMode::QosClassConfiguration(_) => {
            for (word, yes, no) in [
                ("dscp", QosDscp, NoQosDscp),
                ("precedence", QosPrecedence, NoQosPrecedence),
            ] {
                root.add(
                    &[
                        ("match", "Packet criteria"),
                        ("ip", ""),
                        (word, "Match DS field"),
                    ],
                    yes,
                );
                root.add(
                    &[
                        ("no", ""),
                        ("match", ""),
                        ("ip", ""),
                        (word, "Clear criteria"),
                    ],
                    no,
                );
            }
            root.add(
                &[
                    ("match", ""),
                    ("access-group", "Match a permitted ACL packet"),
                ],
                QosAcl,
            );
            root.add(
                &[
                    ("no", ""),
                    ("match", ""),
                    ("access-group", "Remove ACL criterion"),
                ],
                NoQosAcl,
            );
        }
        CliMode::QosPolicyConfiguration(_) | CliMode::QosPolicyClassConfiguration(..) => {
            root.add(
                &[("class", "Select class-map or class-default")],
                QosPolicyClass,
            );
            root.add(
                &[("no", ""), ("class", "Remove a policy class")],
                NoQosPolicyClass,
            );
            if matches!(mode, CliMode::QosPolicyClassConfiguration(..)) {
                for (word, yes, no) in [
                    ("bandwidth", QosBandwidth, NoQosBandwidth),
                    ("priority", QosPriority, NoQosPriority),
                    ("police", QosPolice, NoQosPolice),
                ] {
                    root.add(&[(word, "Configure class service rate")], yes);
                    root.add(&[("no", ""), (word, "Remove class service rate")], no);
                }
                root.add(
                    &[
                        ("shape", "Delay excess traffic"),
                        ("average", "Bit rate and optional burst in bits"),
                    ],
                    QosShape,
                );
                root.add(
                    &[("no", ""), ("shape", ""), ("average", "Remove shaper")],
                    NoQosShape,
                );
            }
        }
        CliMode::InterfaceConfiguration(_) | CliMode::InterfaceRangeConfiguration(..) => {
            root.add(
                &[
                    ("service-policy", "Attach QoS policy"),
                    ("output", "Physical egress queue"),
                ],
                QosOutput,
            );
            root.add(
                &[
                    ("no", ""),
                    ("service-policy", ""),
                    ("output", "Detach output policy"),
                ],
                NoQosOutput,
            );
        }
        CliMode::UserExec | CliMode::PrivilegedExec => {
            root.add(
                &[
                    ("show", ""),
                    ("policy-map", "QoS policy state"),
                    ("interface", "Output policy counters"),
                ],
                ShowQosInterface,
            );
        }
        _ => {}
    }
}
