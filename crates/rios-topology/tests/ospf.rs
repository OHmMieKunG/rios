use rios_config::{
    AdminState, OspfInterfaceConfig, OspfNetworkConfig, OspfNetworkType, StpPortConfig,
};
use rios_ipv4::{IpProtocol, Ipv4InterfaceConfig, Ipv4Packet};
use rios_routing::{LsaBody, OspfBody, OspfNeighborState, OspfV2Packet};
use rios_simulator::{LinkId, LinkState, SimTime};
use rios_topology::{EventOutcome, Lab, Topology};
use std::{collections::BTreeSet, net::Ipv4Addr};
fn broadcast() -> Lab {
    let mut yaml = String::from(
        "devices:\n  SW:\n    type: switch\n    interfaces: [gi0/1, gi0/2, gi0/3, gi0/4]\n",
    );
    for n in 1..=4 {
        yaml.push_str(&format!(
            "  R{n}:\n    type: router\n    interfaces: [gi0/0]\n"
        ));
    }
    yaml.push_str("links:\n");
    for n in 1..=4 {
        yaml.push_str(&format!("  - endpoints: [R{n}:gi0/0, SW:gi0/{n}]\n"));
    }
    let mut lab = Topology::from_yaml(&yaml).unwrap().build().unwrap();
    let sw = lab.device_id("SW").unwrap();
    lab.with_device_mut(sw, |d| {
        for id in d.interfaces().keys().copied().collect::<Vec<_>>() {
            d.set_stp_port(
                id,
                StpPortConfig {
                    portfast: true,
                    ..Default::default()
                },
            )
            .unwrap();
        }
    })
    .unwrap();
    for n in 1..=4 {
        let port = lab.endpoint(&format!("R{n}:gi0/0")).unwrap();
        lab.with_device_mut(port.device, |d| {
            d.set_ipv4(
                port.interface,
                Ipv4InterfaceConfig::new(Ipv4Addr::new(10, 0, 0, n), 24).unwrap(),
            )
            .unwrap();
            d.set_admin_state(port.interface, AdminState::Up).unwrap();
            d.set_ospf_process(1).unwrap();
            d.set_ospf_router_id(Some(Ipv4Addr::new(1, 1, 1, n)))
                .unwrap();
            d.add_ospf_network(OspfNetworkConfig {
                address: Ipv4Addr::UNSPECIFIED,
                wildcard: Ipv4Addr::BROADCAST,
                area: 0,
            })
            .unwrap();
        })
        .unwrap();
    }
    lab
}
#[test]
fn broadcast_elects_dr_bdr_exchanges_standard_packets_and_preserves_two_way_pairs() {
    let mut lab = broadcast();
    let events = lab.run_until(SimTime::from_millis(45_000)).unwrap();
    let mut kinds = BTreeSet::new();
    for event in events {
        if let EventOutcome::FrameReceived { frame, .. } = event
            && let Ok(ip) = Ipv4Packet::decode(&frame.payload)
            && ip.protocol == IpProtocol::Ospf
            && let Ok(packet) = OspfV2Packet::decode(&ip.payload)
        {
            kinds.insert(match packet.body {
                OspfBody::Hello(_) => 1,
                OspfBody::DatabaseDescription { .. } => 2,
                OspfBody::LinkStateRequest(_) => 3,
                OspfBody::LinkStateUpdate(_) => 4,
                OspfBody::LinkStateAck(_) => 5,
            });
        }
    }
    assert_eq!(kinds, BTreeSet::from([1, 2, 3, 4, 5]));
    for n in 1..=4 {
        let d = lab
            .device(lab.device_id(&format!("R{n}")).unwrap())
            .unwrap();
        let neighbors = d.ospf_neighbors();
        assert_eq!(neighbors.len(), 3);
        assert_eq!(
            neighbors
                .iter()
                .filter(|n| n.state == OspfNeighborState::Full)
                .count(),
            if n <= 2 { 2 } else { 3 }
        );
        let network = d
            .ospf_lsas(0, lab.now())
            .into_iter()
            .find(|lsa| matches!(lsa.body, LsaBody::Network { .. }))
            .unwrap();
        assert_eq!(network.advertising_router, Ipv4Addr::new(1, 1, 1, 4));
        assert!(matches!(network.body,LsaBody::Network{routers,..} if routers.len()==4));
    }
    lab.set_link_state(LinkId(4), LinkState::Down).unwrap();
    lab.run_until(SimTime::from_millis(90_000)).unwrap();
    let d = lab.device(lab.device_id("R1").unwrap()).unwrap();
    assert!(
        d.ospf_neighbors()
            .iter()
            .all(|n| n.router_id != Ipv4Addr::new(1, 1, 1, 4))
    );
    assert!(
        d.ospf_lsas(0, lab.now())
            .iter()
            .any(|lsa| lsa.advertising_router == Ipv4Addr::new(1, 1, 1, 3)
                && matches!(lsa.body, LsaBody::Network { .. }))
    );
}
#[test]
fn hello_mismatch_and_passive_interfaces_prevent_adjacency() {
    let mut lab = broadcast();
    let r1 = lab.endpoint("R1:gi0/0").unwrap();
    let r2 = lab.endpoint("R2:gi0/0").unwrap();
    lab.with_device_mut(r1.device, |d| {
        d.set_ospf_passive(r1.interface, true).unwrap()
    })
    .unwrap();
    lab.with_device_mut(r2.device, |d| {
        d.set_ospf_interface(
            r2.interface,
            OspfInterfaceConfig {
                hello_interval: 2,
                ..Default::default()
            },
        )
        .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(45_000)).unwrap();
    assert!(lab.device(r1.device).unwrap().ospf_neighbors().is_empty());
    assert!(lab.device(r2.device).unwrap().ospf_neighbors().is_empty());
    for name in ["R3", "R4"] {
        assert_eq!(
            lab.device(lab.device_id(name).unwrap())
                .unwrap()
                .ospf_neighbors()
                .len(),
            1
        );
    }
}
#[test]
fn point_to_point_adjacency_skips_election_wait() {
    let mut lab=Topology::from_yaml("devices:\n  R1: {type: router, interfaces: [gi0/0]}\n  R2: {type: router, interfaces: [gi0/0]}\nlinks:\n - endpoints: [R1:gi0/0, R2:gi0/0]\n").unwrap().build().unwrap();
    for n in 1..=2 {
        let p = lab.endpoint(&format!("R{n}:gi0/0")).unwrap();
        lab.with_device_mut(p.device, |d| {
            d.set_ipv4(
                p.interface,
                Ipv4InterfaceConfig::new(Ipv4Addr::new(10, 0, 0, n), 24).unwrap(),
            )
            .unwrap();
            d.set_admin_state(p.interface, AdminState::Up).unwrap();
            d.set_ospf_process(1).unwrap();
            d.add_ospf_network(OspfNetworkConfig {
                address: Ipv4Addr::UNSPECIFIED,
                wildcard: Ipv4Addr::BROADCAST,
                area: 0,
            })
            .unwrap();
            d.set_ospf_interface(
                p.interface,
                OspfInterfaceConfig {
                    network_type: OspfNetworkType::PointToPoint,
                    ..Default::default()
                },
            )
            .unwrap();
        })
        .unwrap();
    }
    lab.run_until(SimTime::from_millis(100)).unwrap();
    for name in ["R1", "R2"] {
        assert_eq!(
            lab.device(lab.device_id(name).unwrap())
                .unwrap()
                .ospf_neighbors()[0]
                .state,
            OspfNeighborState::Full
        );
    }
}

fn triangle(loss: u8) -> Lab {
    let mut yaml = String::from("seed: 123\ndevices:\n");
    for n in 1..=3 {
        yaml.push_str(&format!(
            "  R{n}: {{type: router, interfaces: [gi0/0, gi0/1]}}\n"
        ));
    }
    yaml.push_str("links:\n");
    for endpoints in [
        "R1:gi0/0, R2:gi0/0",
        "R2:gi0/1, R3:gi0/0",
        "R1:gi0/1, R3:gi0/1",
    ] {
        yaml.push_str(&format!(
            " - endpoints: [{endpoints}]\n   loss_percent: {loss}\n"
        ));
    }
    let mut lab = Topology::from_yaml(&yaml).unwrap().build().unwrap();
    for (name, address, cost) in [
        ("R1:gi0/0", "10.0.12.1", 1),
        ("R2:gi0/0", "10.0.12.2", 1),
        ("R2:gi0/1", "10.0.23.2", 1),
        ("R3:gi0/0", "10.0.23.3", 1),
        ("R1:gi0/1", "10.0.13.1", 50),
        ("R3:gi0/1", "10.0.13.3", 1),
    ] {
        let port = lab.endpoint(name).unwrap();
        lab.with_device_mut(port.device, |d| {
            d.set_ipv4(
                port.interface,
                Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
            d.set_admin_state(port.interface, AdminState::Up).unwrap();
            d.set_ospf_interface(
                port.interface,
                OspfInterfaceConfig {
                    cost,
                    network_type: OspfNetworkType::PointToPoint,
                    ..Default::default()
                },
            )
            .unwrap();
        })
        .unwrap();
    }
    for n in 1..=3 {
        lab.with_device_mut(lab.device_id(&format!("R{n}")).unwrap(), |d| {
            let lo = d.ensure_interface("Loopback0").unwrap();
            d.set_ipv4(
                lo,
                Ipv4InterfaceConfig::new(Ipv4Addr::new(192, 0, 2, n), 32).unwrap(),
            )
            .unwrap();
            d.set_admin_state(lo, AdminState::Up).unwrap();
            d.set_ospf_process(1).unwrap();
            d.set_ospf_router_id(Some(Ipv4Addr::new(1, 1, 1, n)))
                .unwrap();
            d.add_ospf_network(OspfNetworkConfig {
                address: Ipv4Addr::UNSPECIFIED,
                wildcard: Ipv4Addr::BROADCAST,
                area: 0,
            })
            .unwrap();
        })
        .unwrap();
    }
    lab
}
#[test]
fn interface_cost_changes_real_routes_and_ping_path() {
    let mut lab = triangle(0);
    lab.run_until(SimTime::from_millis(100)).unwrap();
    let r1 = lab.device_id("R1").unwrap();
    let target = Ipv4Addr::new(192, 0, 2, 3);
    let route = lab
        .device(r1)
        .unwrap()
        .routing_table()
        .lookup(target)
        .unwrap()
        .clone();
    assert_eq!(
        (route.metric, route.next_hop),
        (3, Some("10.0.12.2".parse().unwrap()))
    );
    assert_eq!(lab.ping(r1, target).unwrap().received, 5);
    let port = lab.endpoint("R1:gi0/1").unwrap();
    lab.with_device_mut(r1, |d| {
        let mut policy = d.running_config().interfaces[&port.interface].ospf;
        policy.cost = 1;
        d.set_ospf_interface(port.interface, policy).unwrap();
    })
    .unwrap();
    lab.run_until(SimTime(lab.now().0 + 100_000)).unwrap();
    let route = lab
        .device(r1)
        .unwrap()
        .routing_table()
        .lookup(target)
        .unwrap()
        .clone();
    assert_eq!(
        (route.metric, route.next_hop),
        (2, Some("10.0.13.3".parse().unwrap()))
    );
    assert_eq!(lab.ping(r1, target).unwrap().received, 5);
}
#[test]
fn loss_recovery_is_deterministic_and_older_lsas_cannot_replace_newer_ones() {
    let mut first = triangle(10);
    let mut second = triangle(10);
    let a = first.run_until(SimTime::from_millis(120_000)).unwrap();
    let b = second.run_until(SimTime::from_millis(120_000)).unwrap();
    assert_eq!(a, b);
    let port = first.endpoint("R1:gi0/0").unwrap();
    let mut device = first.device(port.device).unwrap().clone();
    assert!(
        device
            .ospf_neighbors()
            .iter()
            .all(|n| n.state == OspfNeighborState::Full)
    );
    let target = Ipv4Addr::new(192, 0, 2, 3);
    assert!(device.routing_table().lookup(target).is_some());
    let original = device
        .ospf_lsas(0, first.now())
        .into_iter()
        .find(|lsa| {
            lsa.advertising_router == Ipv4Addr::new(1, 1, 1, 3)
                && matches!(lsa.body, LsaBody::Router { .. })
        })
        .unwrap();
    let mut old = original.clone();
    old.sequence -= 1;
    let packet = |lsa| OspfV2Packet {
        router_id: Ipv4Addr::new(1, 1, 1, 2),
        area: 0,
        body: OspfBody::LinkStateUpdate(vec![lsa]),
    };
    device.receive_ospf_v2(
        port.interface,
        "10.0.12.2".parse().unwrap(),
        packet(old),
        first.now(),
    );
    assert_eq!(
        device
            .ospf_lsas(0, first.now())
            .iter()
            .find(|l| l.key() == original.key()),
        Some(&original)
    );
    let mut aged = original.clone();
    aged.sequence += 1;
    aged.age = 3599;
    device.receive_ospf_v2(
        port.interface,
        "10.0.12.2".parse().unwrap(),
        packet(aged),
        first.now(),
    );
    device.ospf_tick(SimTime(first.now().0 + 2_000_000));
    assert!(device.routing_table().lookup(target).is_none());
}

#[test]
fn neighbor_expires_at_exact_received_hello_deadline() {
    let mut lab = broadcast();
    lab.run_until(SimTime::from_millis(45_000)).unwrap();
    let r1 = lab.device_id("R1").unwrap();
    let r4 = lab.endpoint("R4:gi0/0").unwrap();
    let rid = Ipv4Addr::new(1, 1, 1, 4);
    let deadline = lab
        .device(r1)
        .unwrap()
        .ospf_neighbors()
        .iter()
        .find(|n| n.router_id == rid)
        .unwrap()
        .dead_at;
    lab.with_device_mut(r4.device, |d| {
        d.set_ospf_passive(r4.interface, true).unwrap()
    })
    .unwrap();
    lab.run_until(SimTime(deadline.0 - 1)).unwrap();
    assert!(
        lab.device(r1)
            .unwrap()
            .ospf_neighbors()
            .iter()
            .any(|n| n.router_id == rid)
    );
    lab.run_until(deadline).unwrap();
    assert!(
        lab.device(r1)
            .unwrap()
            .ospf_neighbors()
            .iter()
            .all(|n| n.router_id != rid)
    );
}
