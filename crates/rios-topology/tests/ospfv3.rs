use rios_config::{AdminState, OspfInterfaceConfig, OspfNetworkType, OspfV3Binding};
use rios_device::Ipv6RouteSource;
use rios_ipv6::{Ipv6Packet, NextHeader};
use rios_routing::{OspfNeighborState, OspfV3Packet, V3_LINK_LSA};
use rios_simulator::SimTime;
use rios_topology::{EventOutcome, Lab, Topology};
use std::{collections::BTreeSet, net::Ipv4Addr};
fn configure(lab: &mut Lab, endpoint: &str, address: Option<&str>, area: u32, broadcast: bool) {
    let port = lab.endpoint(endpoint).unwrap();
    lab.with_device_mut(port.device, |d| {
        d.set_ipv6_routing(true).unwrap();
        d.set_ospfv3_process(Some(1)).unwrap();
        d.set_ospfv3_router_id(Some(Ipv4Addr::new(1, 1, 1, d.id().0 as u8)))
            .unwrap();
        let mut p = d.running_config().interfaces[&port.interface].ipv6.clone();
        p.enabled = true;
        if let Some(address) = address {
            p.addresses.insert(address.parse().unwrap());
        }
        d.set_ipv6_policy(port.interface, p).unwrap();
        d.set_ospfv3_interface(
            port.interface,
            Some(OspfV3Binding {
                process_id: 1,
                area,
            }),
            OspfInterfaceConfig {
                network_type: if broadcast {
                    OspfNetworkType::Broadcast
                } else {
                    OspfNetworkType::PointToPoint
                },
                ..Default::default()
            },
        )
        .unwrap();
        d.set_admin_state(port.interface, AdminState::Up).unwrap();
    })
    .unwrap();
}
fn chain() -> Lab {
    Topology::from_yaml("devices:\n  R1: {type: router, interfaces: [gi0/0, lo0]}\n  R2: {type: router, interfaces: [gi0/0, gi0/1]}\n  R3: {type: router, interfaces: [gi0/0, lo0]}\nlinks:\n - endpoints: [R1:gi0/0, R2:gi0/0]\n - endpoints: [R2:gi0/1, R3:gi0/0]\n").unwrap().build().unwrap()
}
#[test]
fn ospfv3_converges_over_link_local_only_transit_and_forwards_ipv6() {
    let mut lab = chain();
    for ep in ["R1:gi0/0", "R2:gi0/0", "R2:gi0/1", "R3:gi0/0"] {
        configure(&mut lab, ep, None, 0, false);
    }
    configure(&mut lab, "R1:lo0", Some("2001:db8:1::1/128"), 0, false);
    configure(&mut lab, "R3:lo0", Some("2001:db8:3::1/128"), 0, false);
    let events = lab.run_until(SimTime::from_millis(30_000)).unwrap();
    let mut kinds = BTreeSet::new();
    for event in events {
        if let EventOutcome::FrameReceived { frame, .. } = event
            && let Ok(ip) = Ipv6Packet::decode(&frame.payload)
            && ip.next_header == NextHeader::Ospf
        {
            assert!(ip.source.is_unicast_link_local());
            assert_eq!(ip.hop_limit, 1);
            OspfV3Packet::decode(ip.source, ip.destination, &ip.payload).unwrap();
            kinds.insert(ip.payload[1]);
        }
    }
    assert_eq!(kinds, BTreeSet::from([1, 2, 3, 4, 5]));
    for (name, count) in [("R1", 1), ("R2", 2), ("R3", 1)] {
        let d = lab.device(lab.device_id(name).unwrap()).unwrap();
        assert_eq!(d.ospfv3_neighbors().len(), count);
        assert!(
            d.ospfv3_neighbors()
                .iter()
                .all(|n| n.state == OspfNeighborState::Full),
            "{name}: {:?}",
            d.ospfv3_neighbors()
        );
    }
    let r1 = lab.device_id("R1").unwrap();
    let routes = lab.device(r1).unwrap().ipv6_routes();
    let route = routes
        .iter()
        .find(|r| r.prefix.to_string() == "2001:db8:3::1/128" && r.source == Ipv6RouteSource::Ospf)
        .unwrap();
    assert_eq!(route.metric, 2);
    assert!(route.next_hop.unwrap().is_unicast_link_local());
    assert_eq!(
        lab.ping_ipv6(r1, "2001:db8:3::1".parse().unwrap(), None)
            .unwrap()
            .received,
        5
    );
    // A link LSA from R3 must not leak past R2's other link.
    let r3 = lab.device_id("R3").unwrap();
    let port = lab.endpoint("R1:gi0/0").unwrap();
    assert!(
        !lab.device(r1)
            .unwrap()
            .ospfv3_lsas(port.interface, lab.now())
            .iter()
            .any(|l| l.key().kind == V3_LINK_LSA
                && l.advertising_router == Ipv4Addr::new(1, 1, 1, r3.0 as u8))
    );
    let edge = lab.endpoint("R2:gi0/1").unwrap();
    lab.with_device_mut(edge.device, |d| {
        d.set_admin_state(edge.interface, AdminState::Down).unwrap()
    })
    .unwrap();
    lab.run_until(SimTime(lab.now().0 + 2_000_000)).unwrap();
    assert!(
        !lab.device(r1)
            .unwrap()
            .ipv6_routes()
            .iter()
            .any(|r| r.prefix.to_string() == "2001:db8:3::1/128")
    );
}
#[test]
fn area_mismatch_prevents_adjacency() {
    let mut lab = chain();
    configure(&mut lab, "R1:gi0/0", None, 0, false);
    configure(&mut lab, "R2:gi0/0", None, 1, false);
    lab.run_until(SimTime::from_millis(30_000)).unwrap();
    for name in ["R1", "R2"] {
        assert!(
            lab.device(lab.device_id(name).unwrap())
                .unwrap()
                .ospfv3_neighbors()
                .is_empty()
        );
    }
}
#[test]
fn broadcast_elects_dr_bdr_and_keeps_other_pair_two_way() {
    let mut yaml =
        String::from("devices:\n  SW: {type: switch, interfaces: [gi0/1, gi0/2, gi0/3, gi0/4]}\n");
    for i in 1..=4 {
        yaml.push_str(&format!(
            "  R{i}: {{type: router, interfaces: [gi0/0, lo0]}}\n"
        ));
    }
    yaml.push_str("links:\n");
    for i in 1..=4 {
        yaml.push_str(&format!(" - endpoints: [R{i}:gi0/0, SW:gi0/{i}]\n"));
    }
    let mut lab = Topology::from_yaml(&yaml).unwrap().build().unwrap();
    for i in 1..=4 {
        configure(&mut lab, &format!("R{i}:gi0/0"), None, 0, true);
        configure(
            &mut lab,
            &format!("R{i}:lo0"),
            Some(&format!("2001:db8:{i}::1/128")),
            0,
            true,
        );
        let p = lab.endpoint(&format!("SW:gi0/{i}")).unwrap();
        lab.with_device_mut(p.device, |d| {
            d.set_admin_state(p.interface, AdminState::Up).unwrap()
        })
        .unwrap();
    }
    lab.run_until(SimTime::from_millis(65_000)).unwrap();
    let r1 = lab.device_id("R1").unwrap();
    let neighbors = lab.device(r1).unwrap().ospfv3_neighbors();
    assert_eq!(
        neighbors
            .iter()
            .filter(|n| n.state == OspfNeighborState::Full)
            .count(),
        2,
        "{neighbors:?}"
    );
    assert_eq!(
        neighbors
            .iter()
            .filter(|n| n.state == OspfNeighborState::TwoWay)
            .count(),
        1
    );
    assert_eq!(
        lab.ping_ipv6(r1, "2001:db8:2::1".parse().unwrap(), None)
            .unwrap()
            .received,
        5
    );
    let dr = lab.endpoint("R4:gi0/0").unwrap();
    lab.with_device_mut(dr.device, |d| {
        d.set_admin_state(dr.interface, AdminState::Down).unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(120_000)).unwrap();
    let neighbors = lab.device(r1).unwrap().ospfv3_neighbors();
    assert_eq!(neighbors.len(), 2);
    assert!(neighbors.iter().all(|n| n.state == OspfNeighborState::Full));
    assert_eq!(
        lab.ping_ipv6(r1, "2001:db8:2::1".parse().unwrap(), None)
            .unwrap()
            .received,
        5
    );
}

#[test]
fn ospfv3_loss_retransmission_and_deadlines_are_repeatable() {
    fn run() -> (Vec<EventOutcome>, Vec<rios_device::Ipv6Route>) {
        let mut lab=Topology::from_yaml("seed: 123\ndevices:\n  R1: {type: router, interfaces: [gi0/0, lo0]}\n  R2: {type: router, interfaces: [gi0/0, lo0]}\nlinks:\n - endpoints: [R1:gi0/0, R2:gi0/0]\n   loss_percent: 12\n   jitter_ms: 2\n   delay_ms: 3\n").unwrap().build().unwrap();
        for name in ["R1", "R2"] {
            configure(&mut lab, &format!("{name}:gi0/0"), None, 0, false);
        }
        configure(&mut lab, "R1:lo0", Some("2001:db8:1::1/128"), 0, false);
        configure(&mut lab, "R2:lo0", Some("2001:db8:2::1/128"), 0, false);
        let events = lab.run_until(SimTime::from_millis(150_000)).unwrap();
        let r1 = lab.device(lab.device_id("R1").unwrap()).unwrap();
        assert_eq!(r1.ospfv3_neighbors()[0].state, OspfNeighborState::Full);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EventOutcome::FrameDropped { .. }))
        );
        let routes = r1.ipv6_routes();
        assert!(
            routes.iter().any(|r| r.source == Ipv6RouteSource::Ospf
                && r.prefix.to_string() == "2001:db8:2::1/128")
        );
        (events, routes)
    }
    assert_eq!(run(), run());
}

#[test]
fn mismatched_hello_timer_then_repair_and_passive_interface() {
    let mut lab = chain();
    configure(&mut lab, "R1:gi0/0", None, 0, false);
    configure(&mut lab, "R2:gi0/0", None, 0, false);
    let port = lab.endpoint("R2:gi0/0").unwrap();
    let policy = OspfInterfaceConfig {
        hello_interval: 5,
        network_type: OspfNetworkType::PointToPoint,
        ..Default::default()
    };
    lab.with_device_mut(port.device, |d| {
        d.set_ospfv3_interface(
            port.interface,
            Some(OspfV3Binding {
                process_id: 1,
                area: 0,
            }),
            policy,
        )
        .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(20_000)).unwrap();
    assert!(
        lab.device(port.device)
            .unwrap()
            .ospfv3_neighbors()
            .is_empty()
    );
    lab.with_device_mut(port.device, |d| {
        d.set_ospfv3_interface(
            port.interface,
            Some(OspfV3Binding {
                process_id: 1,
                area: 0,
            }),
            OspfInterfaceConfig {
                hello_interval: 10,
                ..policy
            },
        )
        .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(45_000)).unwrap();
    assert_eq!(
        lab.device(port.device).unwrap().ospfv3_neighbors()[0].state,
        OspfNeighborState::Full
    );
    lab.with_device_mut(port.device, |d| {
        d.set_ospfv3_passive(port.interface, true).unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(46_000)).unwrap();
    assert!(
        lab.device(port.device)
            .unwrap()
            .ospfv3_neighbors()
            .is_empty()
    );
    lab.run_until(SimTime::from_millis(90_000)).unwrap();
    assert!(
        lab.device(lab.device_id("R1").unwrap())
            .unwrap()
            .ospfv3_neighbors()
            .is_empty()
    );
}
