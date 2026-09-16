//! Shared command-tree definitions for runtime debug selectors.
use super::*;
use rios_device::DebugTopic;
pub(super) fn add(root: &mut Node) {
    for (words, topic) in [
        (&["packet"][..], DebugTopic::Packet),
        (&["arp"][..], DebugTopic::Arp),
        (&["icmp"][..], DebugTopic::Icmp),
        (&["ip", "packet"][..], DebugTopic::IpPacket),
        (&["ip", "routing"][..], DebugTopic::IpRouting),
        (&["dhcp"][..], DebugTopic::Dhcp),
        (&["ospf", "packet"][..], DebugTopic::OspfPacket),
        (&["ospf", "adjacency"][..], DebugTopic::OspfAdjacency),
        (&["spanning-tree"][..], DebugTopic::SpanningTree),
        (&["lacp"][..], DebugTopic::Lacp),
        (&["nat"][..], DebugTopic::Nat),
        (&["bgp"][..], DebugTopic::Bgp),
    ] {
        let suffix: Vec<_> = words
            .iter()
            .map(|word| (*word, "Select debug topic"))
            .collect();
        for (prefix, enabled) in [
            (&[("debug", "Enable protocol debugging")][..], true),
            (&[("undebug", "Disable protocol debugging")][..], false),
            (
                &[
                    ("no", "Negate a command"),
                    ("debug", "Disable protocol debugging"),
                ][..],
                false,
            ),
        ] {
            let mut path = prefix.to_vec();
            path.extend_from_slice(&suffix);
            root.add(&path, Action::Debug(topic, enabled));
        }
    }
    root.add(
        &[
            ("undebug", "Disable protocol debugging"),
            ("all", "Disable all debugging"),
        ],
        Action::UndebugAll,
    );
    root.add(
        &[
            ("no", "Negate a command"),
            ("debug", "Disable protocol debugging"),
            ("all", "Disable all debugging"),
        ],
        Action::UndebugAll,
    );
    root.add(
        &[
            ("show", "Show device state"),
            ("debugging", "Enabled debug topics"),
        ],
        Action::ShowDebugging,
    );
    root.add(
        &[
            ("show", "Show device state"),
            ("ip", "IPv4 information"),
            ("traffic", "Protocol packet and byte counters"),
        ],
        Action::ShowIpTraffic,
    );
}
