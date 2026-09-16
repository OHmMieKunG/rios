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
                inbound: Default::default(),
                outbound: Default::default(),
                default_originate: None,
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

fn policy(
    lab: &mut Lab,
    name: &str,
    map: &str,
    edit: impl FnOnce(&mut rios_config::RouteMapEntry),
) {
    let id = lab.device_id(name).unwrap();
    lab.with_device_mut(id, |d| {
        let id = d
            .ensure_route_map(map, rios_config::AccessListAction::Permit, 10)
            .unwrap();
        let mut entry = d.running_config().routing_policy.route_maps[&id].entries[&10].clone();
        edit(&mut entry);
        d.set_route_map_entry(id, 10, entry).unwrap();
    })
    .unwrap();
}
fn neighbor_edit(
    lab: &mut Lab,
    name: &str,
    remote: &str,
    edit: impl FnOnce(&mut BgpNeighborConfig),
) {
    let id = lab.device_id(name).unwrap();
    let address = remote.parse().unwrap();
    lab.with_device_mut(id, |d| {
        let mut peer = d.running_config().bgp.as_ref().unwrap().neighbors[&address].clone();
        edit(&mut peer);
        d.set_bgp_neighbor(address, Some(peer)).unwrap();
    })
    .unwrap();
}
#[test]
fn bgp_route_maps_change_best_path_using_local_preference_med_and_as_prepend() {
    let mut lab = chain();
    address(&mut lab, "R1:lo0", "192.0.2.100", 32);
    address(&mut lab, "R3:lo0", "192.0.2.100", 32);
    let prefix = Ipv4Network::new("192.0.2.100".parse().unwrap(), 32).unwrap();
    for (name, asn, remote, remote_as) in [
        ("R1", 65001, "10.0.12.2", 65000),
        ("R2", 65000, "10.0.12.1", 65001),
        ("R2", 65000, "10.0.23.3", 65001),
        ("R3", 65001, "10.0.23.2", 65000),
    ] {
        peer(&mut lab, name, asn, remote, remote_as);
    }
    for (name, remote, med) in [("R1", "10.0.12.2", 20), ("R3", "10.0.23.2", 30)] {
        let id = lab.device_id(name).unwrap();
        lab.with_device_mut(id, |d| d.set_bgp_network(prefix, true).unwrap())
            .unwrap();
        policy(&mut lab, name, "OUT", |e| e.metric = Some(med));
        neighbor_edit(&mut lab, name, remote, |p| {
            p.outbound.route_map = Some("OUT".into())
        });
    }
    let r2 = lab.device_id("R2").unwrap();
    let selected = |lab: &Lab| {
        lab.device(r2).unwrap().bgp_paths()[&prefix]
            .learned_from
            .unwrap()
            .to_string()
    };
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    assert_eq!(selected(&lab), "10.0.12.1");
    let since = lab
        .device(r2)
        .unwrap()
        .bgp_neighbors()
        .iter()
        .map(|p| p.established_since)
        .collect::<Vec<_>>();
    policy(&mut lab, "R2", "IN", |e| e.local_preference = Some(250));
    neighbor_edit(&mut lab, "R2", "10.0.23.3", |p| {
        p.inbound.route_map = Some("IN".into())
    });
    lab.run_until(SimTime::from_millis(8000)).unwrap();
    assert_eq!(selected(&lab), "10.0.23.3");
    assert_eq!(
        lab.device(r2).unwrap().bgp_paths()[&prefix]
            .attributes
            .local_preference,
        Some(250)
    );
    policy(&mut lab, "R2", "IN", |e| e.local_preference = None);
    policy(&mut lab, "R3", "OUT", |e| e.metric = Some(10));
    lab.run_until(SimTime::from_millis(10_000)).unwrap();
    assert_eq!(selected(&lab), "10.0.23.3");
    policy(&mut lab, "R3", "OUT", |e| e.as_prepend = vec![65001, 65001]);
    let events = lab.run_until(SimTime::from_millis(12_000)).unwrap();
    assert_eq!(selected(&lab), "10.0.12.1");
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
            .is_some_and(|a| a.path_length() == 3 && a.med == Some(10))
    }));
    assert_eq!(
        since,
        lab.device(r2)
            .unwrap()
            .bgp_neighbors()
            .iter()
            .map(|p| p.established_since)
            .collect::<Vec<_>>()
    );
}
#[test]
fn prefix_filter_changes_withdraw_routes_and_conditional_default_uses_real_rib() {
    use rios_config::{AccessListAction, BgpDefaultRoute, PrefixListEntry};
    let mut lab = pair();
    let r1 = lab.device_id("R1").unwrap();
    let r2 = lab.device_id("R2").unwrap();
    let network = Ipv4Network::new("192.0.2.2".parse().unwrap(), 32).unwrap();
    let default = Ipv4Network::new("0.0.0.0".parse().unwrap(), 0).unwrap();
    neighbor_edit(&mut lab, "R2", "10.0.0.1", |p| {
        p.outbound.prefix_list = Some("EXPORT".into())
    });
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    assert!(!lab.device(r1).unwrap().bgp_paths().contains_key(&network));
    lab.with_device_mut(r2, |d| {
        d.set_prefix_list_entry(
            "EXPORT",
            Some(10),
            PrefixListEntry {
                action: AccessListAction::Permit,
                prefix: network,
                ge: None,
                le: None,
            },
        )
        .unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(7000)).unwrap();
    assert!(lab.device(r1).unwrap().bgp_paths().contains_key(&network));
    lab.with_device_mut(r2, |d| {
        d.set_prefix_list_entry(
            "EXPORT",
            Some(5),
            PrefixListEntry {
                action: AccessListAction::Deny,
                prefix: network,
                ge: None,
                le: None,
            },
        )
        .unwrap();
    })
    .unwrap();
    neighbor_edit(&mut lab, "R2", "10.0.0.1", |p| {
        p.default_originate = Some(BgpDefaultRoute::default())
    });
    lab.run_until(SimTime::from_millis(9000)).unwrap();
    assert!(!lab.device(r1).unwrap().bgp_paths().contains_key(&network));
    assert!(
        lab.device(r1).unwrap().bgp_paths().contains_key(&default),
        "per-neighbor default bypasses ordinary outbound prefix filter"
    );
    policy(&mut lab, "R2", "DEFAULT", |e| {
        e.prefix_lists.insert("CONDITION".into());
        e.metric = Some(77);
    });
    neighbor_edit(&mut lab, "R2", "10.0.0.1", |p| {
        p.default_originate = Some(BgpDefaultRoute {
            route_map: Some("DEFAULT".into()),
        })
    });
    lab.run_until(SimTime::from_millis(11_000)).unwrap();
    assert!(!lab.device(r1).unwrap().bgp_paths().contains_key(&default));
    lab.with_device_mut(r2, |d| {
        d.set_prefix_list_entry(
            "CONDITION",
            Some(5),
            PrefixListEntry {
                action: AccessListAction::Permit,
                prefix: network,
                ge: None,
                le: None,
            },
        )
        .unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(13_000)).unwrap();
    assert_eq!(
        lab.device(r1).unwrap().bgp_paths()[&default].attributes.med,
        Some(77)
    );
    let loopback = lab.endpoint("R2:lo0").unwrap();
    lab.with_device_mut(r2, |d| {
        d.set_admin_state(loopback.interface, AdminState::Down)
            .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(15_000)).unwrap();
    assert!(!lab.device(r1).unwrap().bgp_paths().contains_key(&default));
    neighbor_edit(&mut lab, "R2", "10.0.0.1", |p| {
        p.default_originate = Some(BgpDefaultRoute::default())
    });
    neighbor_edit(&mut lab, "R1", "10.0.0.2", |p| {
        p.inbound.prefix_list = Some("DEFAULT-IN".into())
    });
    lab.run_until(SimTime::from_millis(17_000)).unwrap();
    assert!(!lab.device(r1).unwrap().bgp_paths().contains_key(&default));
    assert_eq!(
        lab.device(r1).unwrap().bgp_neighbors()[0].received_prefixes,
        1
    );
    assert_eq!(lab.device(r1).unwrap().bgp_neighbors()[0].prefixes, 0);
    lab.with_device_mut(r1, |d| {
        d.set_prefix_list_entry(
            "DEFAULT-IN",
            None,
            PrefixListEntry {
                action: AccessListAction::Permit,
                prefix: default,
                ge: None,
                le: None,
            },
        )
        .unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(19_000)).unwrap();
    assert!(lab.device(r1).unwrap().bgp_paths().contains_key(&default));
    assert_eq!(lab.device(r1).unwrap().bgp_neighbors()[0].prefixes, 1);
}

#[test]
fn received_as_loop_is_rejected_without_resetting_the_session() {
    let mut lab = pair();
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    let r1 = lab.device_id("R1").unwrap();
    let r2 = lab.device_id("R2").unwrap();
    let socket = *lab
        .device(r2)
        .unwrap()
        .tcp_connections()
        .iter()
        .find(|(_, c)| c.state == rios_device::TcpState::Established)
        .unwrap()
        .0;
    let mut attributes = lab
        .device(r1)
        .unwrap()
        .bgp_paths()
        .values()
        .find(|p| p.learned_from.is_some())
        .unwrap()
        .attributes
        .clone();
    attributes.as_path = vec![rios_routing::AsPathSegment::Sequence(vec![65002, 65001])];
    let prefix = Ipv4Network::new("192.0.2.99".parse().unwrap(), 32).unwrap();
    let update = BgpMessage::Update(rios_routing::BgpUpdate {
        withdrawn: Vec::new(),
        attributes: Some(attributes),
        announced: vec![prefix],
    })
    .encode(true)
    .unwrap();
    lab.tcp_send(r2, socket, &update).unwrap();
    lab.run_until(SimTime::from_millis(6000)).unwrap();
    assert!(!lab.device(r1).unwrap().bgp_paths().contains_key(&prefix));
    assert_eq!(
        lab.device(r1).unwrap().bgp_neighbors()[0].state,
        BgpState::Established
    );
    assert_eq!(
        lab.device(r1).unwrap().bgp_neighbors()[0].received_prefixes,
        1
    );
}

#[test]
fn bgp_debug_reports_transport_driven_state_transitions() {
    let mut lab = pair();
    let r1 = lab.device_id("R1").unwrap();
    lab.with_device_mut(r1, |d| d.set_debug(rios_device::DebugTopic::Bgp, true))
        .unwrap();
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    let records = lab.take_debug(r1);
    assert!(records.iter().any(|r| matches!(
        r.event,
        rios_topology::DebugEvent::BgpState {
            after: Some(BgpState::Established),
            ..
        }
    )));
    assert!(records.iter().any(|r| matches!(
        r.event,
        rios_topology::DebugEvent::Packet {
            protocol: rios_device::PacketProtocol::Bgp,
            ..
        }
    )));
}
