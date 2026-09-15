use rios_config::{AdminState, BgpNeighborConfig};
use rios_ipv4::RouteSource;
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network, Ipv4Packet};
use rios_protocol::TcpSegment;
use rios_routing::{BgpMessage, BgpState, BgpStream};
use rios_simulator::SimTime;
use rios_topology::{EventOutcome, Lab, Topology};
use std::collections::{BTreeMap, BTreeSet};

fn address(lab: &mut Lab, endpoint: &str, ip: &str, prefix: u8) {
    let port = lab.endpoint(endpoint).unwrap();
    lab.with_device_mut(port.device, |d| {
        d.set_ipv4(
            port.interface,
            Ipv4InterfaceConfig::new(ip.parse().unwrap(), prefix).unwrap(),
        )
        .unwrap();
        d.set_admin_state(port.interface, AdminState::Up).unwrap();
    })
    .unwrap();
}
fn peer(lab: &mut Lab, name: &str, asn: u32, remote: &str, remote_as: u32) {
    let id = lab.device_id(name).unwrap();
    lab.with_device_mut(id, |d| {
        d.set_bgp_process(Some(asn)).unwrap();
        d.set_bgp_neighbor(
            remote.parse().unwrap(),
            Some(BgpNeighborConfig {
                remote_as,
                update_source: None,
                next_hop_self: false,
                route_reflector_client: false,
            }),
        )
        .unwrap();
    })
    .unwrap();
}
fn pair() -> Lab {
    pair_with_loss(0)
}
fn pair_with_loss(loss: u8) -> Lab {
    let mut lab = Topology::from_yaml(&format!("devices:\n  R1: {{type: router, interfaces: [gi0/0, lo0]}}\n  R2: {{type: router, interfaces: [gi0/0, lo0]}}\nlinks:\n - endpoints: [R1:gi0/0, R2:gi0/0]\n   loss_percent: {loss}\n")).unwrap().build().unwrap();
    address(&mut lab, "R1:gi0/0", "10.0.0.1", 24);
    address(&mut lab, "R2:gi0/0", "10.0.0.2", 24);
    address(&mut lab, "R1:lo0", "192.0.2.1", 32);
    address(&mut lab, "R2:lo0", "192.0.2.2", 32);
    peer(&mut lab, "R1", 65001, "10.0.0.2", 65002);
    peer(&mut lab, "R2", 65002, "10.0.0.1", 65001);
    for (name, ip) in [("R1", "192.0.2.1"), ("R2", "192.0.2.2")] {
        let id = lab.device_id(name).unwrap();
        lab.with_device_mut(id, |d| {
            d.set_bgp_network(Ipv4Network::new(ip.parse().unwrap(), 32).unwrap(), true)
                .unwrap()
        })
        .unwrap();
    }
    lab
}
#[test]
fn ebgp_tcp_collision_updates_forwarding_and_withdrawal() {
    let mut lab = pair();
    let events = lab.run_until(SimTime::from_millis(5000)).unwrap();
    let mut streams = BTreeMap::new();
    let mut kinds = BTreeSet::new();
    for event in events {
        if let EventOutcome::FrameReceived { frame, .. } = event
            && let Ok(ip) = Ipv4Packet::decode(&frame.payload)
            && let Ok(tcp) = TcpSegment::decode(ip.source, ip.destination, &ip.payload)
            && (tcp.source_port == 179 || tcp.destination_port == 179)
        {
            assert_eq!(ip.ttl, 1);
            if tcp.payload.is_empty() {
                continue;
            }
            let stream = streams
                .entry((
                    ip.source,
                    ip.destination,
                    tcp.source_port,
                    tcp.destination_port,
                ))
                .or_insert_with(BgpStream::default);
            stream.push(&tcp.payload).unwrap();
            while let Some(message) = stream.next_message(true).unwrap() {
                kinds.insert(match message {
                    BgpMessage::Open(_) => 1,
                    BgpMessage::Update(_) => 2,
                    BgpMessage::Notification { .. } => 3,
                    BgpMessage::Keepalive => 4,
                });
            }
        }
    }
    assert!(kinds.is_superset(&BTreeSet::from([1, 2, 4])), "{kinds:?}");
    for name in ["R1", "R2"] {
        let d = lab.device(lab.device_id(name).unwrap()).unwrap();
        assert_eq!(
            d.bgp_neighbors()[0].state,
            BgpState::Established,
            "{}",
            d.show_ip_bgp_neighbors(lab.now())
        );
        assert_eq!(
            d.tcp_connections()
                .values()
                .filter(|c| c.state == rios_device::TcpState::Established)
                .count(),
            1
        );
        assert!(
            d.routing_table()
                .routes()
                .iter()
                .any(|r| r.source == RouteSource::Bgp && r.administrative_distance == 20)
        );
    }
    let r1 = lab.device_id("R1").unwrap();
    let r2 = lab.device_id("R2").unwrap();
    assert_eq!(
        lab.ping(r1, "192.0.2.2".parse().unwrap()).unwrap().received,
        5
    );
    lab.with_device_mut(r2, |d| {
        d.set_bgp_network(
            Ipv4Network::new("192.0.2.2".parse().unwrap(), 32).unwrap(),
            false,
        )
        .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(8000)).unwrap();
    assert!(
        lab.device(r1)
            .unwrap()
            .bgp_paths()
            .values()
            .all(|p| p.prefix.address() != "192.0.2.2".parse::<std::net::Ipv4Addr>().unwrap())
    );
}

#[test]
fn wrong_remote_as_sends_notification_and_never_installs_routes() {
    let mut lab = pair();
    peer(&mut lab, "R1", 65001, "10.0.0.2", 65123);
    let events = lab.run_until(SimTime::from_millis(5000)).unwrap();
    assert!(events.iter().any(|e| {
        let EventOutcome::FrameReceived { frame, .. } = e else {
            return false;
        };
        let Ok(ip) = Ipv4Packet::decode(&frame.payload) else {
            return false;
        };
        let Ok(tcp) = TcpSegment::decode(ip.source, ip.destination, &ip.payload) else {
            return false;
        };
        matches!(
            BgpMessage::decode(&tcp.payload, true),
            Ok(BgpMessage::Notification {
                code: 2,
                subcode: 2,
                ..
            })
        )
    }));
    for name in ["R1", "R2"] {
        let d = lab.device(lab.device_id(name).unwrap()).unwrap();
        assert_ne!(d.bgp_neighbors()[0].state, BgpState::Established);
        assert!(
            d.routing_table()
                .routes()
                .iter()
                .all(|r| r.source != RouteSource::Bgp)
        );
    }
}
fn chain() -> Lab {
    let mut lab = Topology::from_yaml("devices:\n  R1: {type: router, interfaces: [gi0/0, lo0]}\n  R2: {type: router, interfaces: [gi0/0, gi0/1]}\n  R3: {type: router, interfaces: [gi0/0, lo0]}\nlinks:\n - endpoints: [R1:gi0/0, R2:gi0/0]\n - endpoints: [R2:gi0/1, R3:gi0/0]\n").unwrap().build().unwrap();
    for (ep, ip, prefix) in [
        ("R1:gi0/0", "10.0.12.1", 24),
        ("R2:gi0/0", "10.0.12.2", 24),
        ("R2:gi0/1", "10.0.23.2", 24),
        ("R3:gi0/0", "10.0.23.3", 24),
        ("R1:lo0", "192.0.2.1", 32),
        ("R3:lo0", "192.0.2.3", 32),
    ] {
        address(&mut lab, ep, ip, prefix);
    }
    lab
}
fn route(lab: &mut Lab, name: &str, network: &str, bits: u8, next: &str) {
    let id = lab.device_id(name).unwrap();
    lab.with_device_mut(id, |d| {
        d.set_static_route(
            Ipv4Network::new(network.parse().unwrap(), bits).unwrap(),
            next.parse().unwrap(),
        )
    })
    .unwrap();
}
#[test]
fn ibgp_preserves_next_hop_and_resolves_it_through_igp() {
    let mut lab = chain();
    peer(&mut lab, "R1", 65000, "10.0.12.2", 65000);
    peer(&mut lab, "R2", 65000, "10.0.12.1", 65000);
    peer(&mut lab, "R2", 65000, "10.0.23.3", 65003);
    peer(&mut lab, "R3", 65003, "10.0.23.2", 65000);
    let r1 = lab.device_id("R1").unwrap();
    let r3 = lab.device_id("R3").unwrap();
    for (id, ip) in [(r1, "192.0.2.1"), (r3, "192.0.2.3")] {
        lab.with_device_mut(id, |d| {
            d.set_bgp_network(Ipv4Network::new(ip.parse().unwrap(), 32).unwrap(), true)
                .unwrap()
        })
        .unwrap();
    }
    route(&mut lab, "R1", "10.0.23.0", 24, "10.0.12.2");
    route(&mut lab, "R3", "10.0.12.0", 24, "10.0.23.2");
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    let prefix = Ipv4Network::new("192.0.2.3".parse().unwrap(), 32).unwrap();
    let d = lab.device(r1).unwrap();
    assert_eq!(
        d.bgp_paths()[&prefix].attributes.next_hop.to_string(),
        "10.0.23.3"
    );
    assert_eq!(
        d.bgp_paths()[&prefix].attributes.as_path[0].members(),
        &[65003]
    );
    assert_eq!(
        d.routing_table()
            .lookup(prefix.address())
            .unwrap()
            .administrative_distance,
        200
    );
    assert_eq!(
        d.resolve_route(prefix.address())
            .unwrap()
            .next_hop
            .to_string(),
        "10.0.12.2"
    );
    assert_eq!(lab.ping(r1, prefix.address()).unwrap().received, 5);
    let r2 = lab.device_id("R2").unwrap();
    lab.with_device_mut(r2, |d| {
        let address = "10.0.12.1".parse().unwrap();
        let mut peer = d.running_config().bgp.as_ref().unwrap().neighbors[&address].clone();
        peer.next_hop_self = true;
        d.set_bgp_neighbor(address, Some(peer)).unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(8000)).unwrap();
    assert_eq!(
        lab.device(r1).unwrap().bgp_paths()[&prefix]
            .attributes
            .next_hop
            .to_string(),
        "10.0.12.2"
    );
}
#[test]
fn ebgp_retransmissions_cannot_cross_an_intermediate_router() {
    let mut lab = chain();
    route(&mut lab, "R1", "10.0.23.0", 24, "10.0.12.2");
    route(&mut lab, "R3", "10.0.12.0", 24, "10.0.23.2");
    peer(&mut lab, "R1", 65001, "10.0.23.3", 65003);
    peer(&mut lab, "R3", 65003, "10.0.12.1", 65001);
    let events = lab.run_until(SimTime::from_millis(65_000)).unwrap();
    let mut packets = 0;
    for e in events {
        if let EventOutcome::FrameReceived { frame, interface } = e
            && let Ok(ip) = Ipv4Packet::decode(&frame.payload)
            && let Ok(tcp) = TcpSegment::decode(ip.source, ip.destination, &ip.payload)
            && tcp.destination_port == 179
        {
            packets += 1;
            assert_eq!(ip.ttl, 1);
            assert_eq!(interface.device, lab.device_id("R2").unwrap());
        }
    }
    assert!(packets > 4, "must exercise retransmission");
    for name in ["R1", "R3"] {
        assert_ne!(
            lab.device(lab.device_id(name).unwrap())
                .unwrap()
                .bgp_neighbors()[0]
                .state,
            BgpState::Established
        );
    }
}

#[test]
fn seeded_loss_is_repeatable_and_sessions_recover_after_link_failure() {
    let mut a = pair_with_loss(5);
    let mut b = pair_with_loss(5);
    assert_eq!(
        a.run_until(SimTime::from_millis(60_000)).unwrap(),
        b.run_until(SimTime::from_millis(60_000)).unwrap()
    );
    for name in ["R1", "R2"] {
        let id = a.device_id(name).unwrap();
        assert_eq!(
            a.device(id).unwrap().bgp_neighbors()[0].state,
            BgpState::Established
        );
        assert_eq!(
            a.device(id).unwrap().bgp_paths(),
            b.device(id).unwrap().bgp_paths()
        );
    }
    a.set_link_state(rios_simulator::LinkId(1), rios_simulator::LinkState::Down)
        .unwrap();
    a.run_until(SimTime::from_millis(300_000)).unwrap();
    for name in ["R1", "R2"] {
        let d = a.device(a.device_id(name).unwrap()).unwrap();
        assert_ne!(d.bgp_neighbors()[0].state, BgpState::Established);
        assert!(d.bgp_paths().values().all(|p| p.learned_from.is_none()));
    }
    a.set_link_state(rios_simulator::LinkId(1), rios_simulator::LinkState::Up)
        .unwrap();
    a.run_until(SimTime::from_millis(380_000)).unwrap();
    for name in ["R1", "R2"] {
        let d = a.device(a.device_id(name).unwrap()).unwrap();
        assert_eq!(
            d.bgp_neighbors()[0].state,
            BgpState::Established,
            "{name}: {:?}",
            d.bgp_neighbors()
        );
        assert!(d.bgp_paths().values().any(|p| p.learned_from.is_some()));
    }
}
#[test]
fn ibgp_split_horizon_prevents_internal_route_readvertisement() {
    let mut lab = chain();
    for (name, remote) in [
        ("R1", "10.0.12.2"),
        ("R2", "10.0.12.1"),
        ("R2", "10.0.23.3"),
        ("R3", "10.0.23.2"),
    ] {
        peer(&mut lab, name, 65000, remote, 65000);
    }
    let r3 = lab.device_id("R3").unwrap();
    let prefix = Ipv4Network::new("192.0.2.3".parse().unwrap(), 32).unwrap();
    lab.with_device_mut(r3, |d| d.set_bgp_network(prefix, true).unwrap())
        .unwrap();
    route(&mut lab, "R1", "10.0.23.0", 24, "10.0.12.2");
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    let r1 = lab.device(lab.device_id("R1").unwrap()).unwrap();
    let r2 = lab.device(lab.device_id("R2").unwrap()).unwrap();
    assert_eq!(r1.bgp_neighbors()[0].state, BgpState::Established);
    assert!(r2.bgp_paths().contains_key(&prefix));
    assert!(!r1.bgp_paths().contains_key(&prefix));
}

#[test]
fn route_reflector_exchanges_client_routes_and_rejects_cluster_loops() {
    let mut lab = chain();
    for (name, remote) in [
        ("R1", "10.0.12.2"),
        ("R2", "10.0.12.1"),
        ("R2", "10.0.23.3"),
        ("R3", "10.0.23.2"),
    ] {
        peer(&mut lab, name, 65000, remote, 65000);
    }
    route(&mut lab, "R1", "10.0.23.0", 24, "10.0.12.2");
    route(&mut lab, "R3", "10.0.12.0", 24, "10.0.23.2");
    let r1 = lab.device_id("R1").unwrap();
    let rr = lab.device_id("R2").unwrap();
    let r3 = lab.device_id("R3").unwrap();
    let p1 = Ipv4Network::new("192.0.2.1".parse().unwrap(), 32).unwrap();
    let p3 = Ipv4Network::new("192.0.2.3".parse().unwrap(), 32).unwrap();
    lab.with_device_mut(r1, |d| d.set_bgp_network(p1, true).unwrap())
        .unwrap();
    lab.with_device_mut(r3, |d| d.set_bgp_network(p3, true).unwrap())
        .unwrap();
    let cluster = "9.9.9.9".parse().unwrap();
    lab.with_device_mut(rr, |d| {
        d.set_bgp_cluster_id(Some(cluster)).unwrap();
        for (ip, client) in [("10.0.12.1", false), ("10.0.23.3", true)] {
            let address = ip.parse().unwrap();
            let mut p = d.running_config().bgp.as_ref().unwrap().neighbors[&address].clone();
            p.route_reflector_client = client;
            p.next_hop_self = true;
            d.set_bgp_neighbor(address, Some(p)).unwrap();
        }
    })
    .unwrap();
    let events = lab.run_until(SimTime::from_millis(5000)).unwrap();
    assert!(events.iter().any(|e| {
        let EventOutcome::FrameReceived { frame, .. } = e else {
            return false;
        };
        let Ok(ip) = Ipv4Packet::decode(&frame.payload) else {
            return false;
        };
        let Ok(tcp) = TcpSegment::decode(ip.source, ip.destination, &ip.payload) else {
            return false;
        };
        let Ok(BgpMessage::Update(update)) = BgpMessage::decode(&tcp.payload, true) else {
            return false;
        };
        update
            .attributes
            .is_some_and(|a| a.cluster_list == vec![cluster] && a.originator_id.is_some())
    }));
    for (id, prefix, origin, hop) in [
        (r1, p3, "192.0.2.3", "10.0.23.3"),
        (r3, p1, "192.0.2.1", "10.0.12.1"),
    ] {
        let a = &lab.device(id).unwrap().bgp_paths()[&prefix].attributes;
        assert_eq!(a.originator_id.unwrap().to_string(), origin);
        assert_eq!(a.cluster_list, vec![cluster]);
        assert_eq!(
            a.next_hop.to_string(),
            hop,
            "reflection must preserve next hop despite next-hop-self"
        );
        assert!(a.as_path.is_empty());
    }
    assert_eq!(lab.ping(r1, p3.address()).unwrap().received, 5);
    lab.with_device_mut(r1, |d| d.set_bgp_cluster_id(Some(cluster)).unwrap())
        .unwrap();
    lab.run_until(SimTime::from_millis(8000)).unwrap();
    assert!(!lab.device(r1).unwrap().bgp_paths().contains_key(&p3));
    assert_eq!(
        lab.device(r1).unwrap().bgp_neighbors()[0].state,
        BgpState::Established
    );
    lab.with_device_mut(rr, |d| {
        let address = "10.0.23.3".parse().unwrap();
        let mut p = d.running_config().bgp.as_ref().unwrap().neighbors[&address].clone();
        p.remote_as = 65003;
        assert!(d.set_bgp_neighbor(address, Some(p.clone())).is_err());
        p.remote_as = 65000;
        p.route_reflector_client = false;
        d.set_bgp_neighbor(address, Some(p)).unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(10_000)).unwrap();
    assert!(!lab.device(r3).unwrap().bgp_paths().contains_key(&p1));
}
