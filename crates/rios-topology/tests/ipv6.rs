use rios_config::{AdminState, Ipv6InterfacePolicy, Ipv6StaticRoute};
use rios_device::{Ipv6AddressOrigin, Ipv6AddressState, Ipv6NeighborState};
use rios_ethernet::EtherType;
use rios_ipv6::{Icmpv6Message, Ipv6InterfaceConfig, Ipv6Packet, NdMessage};
use rios_simulator::SimTime;
use rios_topology::{EventOutcome, Lab, Topology};
use std::{collections::BTreeSet, net::Ipv6Addr};
fn pair() -> Lab {
    Topology::from_yaml("devices:\n  R1: {type: router, interfaces: [gi0/0]}\n  PC: {type: host, interfaces: [gi0/0]}\nlinks:\n - endpoints: [R1:gi0/0, PC:gi0/0]\n").unwrap().build().unwrap()
}
fn address(lab: &mut Lab, endpoint: &str, address: &str) {
    let port = lab.endpoint(endpoint).unwrap();
    lab.with_device_mut(port.device, |d| {
        d.set_ipv6_address(
            port.interface,
            address.parse::<Ipv6InterfaceConfig>().unwrap(),
        )
        .unwrap();
        d.set_admin_state(port.interface, AdminState::Up).unwrap();
    })
    .unwrap();
}
#[test]
fn ipv6_ping_uses_dad_neighbor_solicitation_and_advertisement_not_arp() {
    let mut lab = pair();
    address(&mut lab, "R1:gi0/0", "2001:db8:1::1/64");
    address(&mut lab, "PC:gi0/0", "2001:db8:1::2/64");
    let events = lab.run_until(SimTime::from_millis(1100)).unwrap();
    assert!(events.iter().all(|event|!matches!(event,EventOutcome::FrameReceived {frame,..} if frame.ethertype==EtherType::Arp)));
    assert!(events.iter().any(|event|matches!(event,EventOutcome::FrameReceived {frame,..} if Ipv6Packet::decode(&frame.payload).is_ok_and(|p|p.source.is_unspecified()))));
    let pc = lab.device_id("PC").unwrap();
    let ping = lab
        .ping_ipv6(pc, "2001:db8:1::1".parse().unwrap(), None)
        .unwrap();
    assert_eq!(ping.received, 5);
    let neighbor = lab
        .device(pc)
        .unwrap()
        .ipv6_neighbors()
        .into_iter()
        .find(|n| n.address == "2001:db8:1::1".parse::<Ipv6Addr>().unwrap())
        .unwrap();
    assert_eq!(neighbor.state, Ipv6NeighborState::Reachable);
    assert!(
        !lab.device(pc)
            .unwrap()
            .clone()
            .show_arp(lab.now())
            .contains("Internet")
    );
}
#[test]
fn router_advertisements_create_slaac_addresses_and_default_routes() {
    let mut lab = pair();
    address(&mut lab, "R1:gi0/0", "2001:db8:10::1/64");
    let r = lab.endpoint("R1:gi0/0").unwrap();
    let pc = lab.endpoint("PC:gi0/0").unwrap();
    lab.with_device_mut(r.device, |d| d.set_ipv6_routing(true).unwrap())
        .unwrap();
    lab.with_device_mut(pc.device, |d| {
        d.set_ipv6_policy(
            pc.interface,
            Ipv6InterfacePolicy {
                autoconfig: true,
                ..Default::default()
            },
        )
        .unwrap();
        d.set_admin_state(pc.interface, AdminState::Up).unwrap();
    })
    .unwrap();
    let events = lab.run_until(SimTime::from_millis(2100)).unwrap();
    let mut seen = BTreeSet::new();
    for event in events {
        if let EventOutcome::FrameReceived { frame, .. } = event
            && frame.ethertype == EtherType::Ipv6
            && let Ok(p) = Ipv6Packet::decode(&frame.payload)
            && let Ok(Icmpv6Message::Neighbor(nd)) =
                Icmpv6Message::decode(p.source, p.destination, &p.payload)
        {
            seen.insert(match nd {
                NdMessage::RouterSolicitation { .. } => 133,
                NdMessage::RouterAdvertisement { .. } => 134,
                NdMessage::NeighborSolicitation { .. } => 135,
                NdMessage::NeighborAdvertisement { .. } => 136,
            });
        }
    }
    assert!(seen.contains(&133) && seen.contains(&134) && seen.contains(&135));
    let d = lab.device(pc.device).unwrap();
    let addr = d
        .ipv6_addresses(pc.interface)
        .into_iter()
        .find(|a| a.origin == Ipv6AddressOrigin::Slaac)
        .unwrap();
    assert_eq!(addr.state, Ipv6AddressState::Preferred);
    assert!(
        "2001:db8:10::/64"
            .parse::<rios_ipv6::Ipv6Network>()
            .unwrap()
            .contains(addr.address.address())
    );
    assert!(
        d.ipv6_routes().iter().any(|r| r.prefix.prefix_len() == 0
            && r.next_hop.is_some_and(|ip| ip.is_unicast_link_local()))
    );
    assert_eq!(
        lab.ping_ipv6(pc.device, "2001:db8:10::1".parse().unwrap(), None)
            .unwrap()
            .received,
        5
    );
    assert_eq!(
        lab.ping_ipv6(r.device, addr.address.address(), None)
            .unwrap()
            .received,
        5
    );
}
#[test]
fn dad_conflict_keeps_duplicate_addresses_unusable() {
    let mut lab = pair();
    address(&mut lab, "R1:gi0/0", "2001:db8::1/64");
    address(&mut lab, "PC:gi0/0", "2001:db8::1/64");
    lab.run_until(SimTime::from_millis(1100)).unwrap();
    for name in ["R1:gi0/0", "PC:gi0/0"] {
        let port = lab.endpoint(name).unwrap();
        let device = lab.device(port.device).unwrap();
        let entry = device
            .ipv6_addresses(port.interface)
            .into_iter()
            .find(|a| !a.address.address().is_unicast_link_local())
            .unwrap();
        assert_eq!(entry.state, Ipv6AddressState::Duplicate);
        assert!(!device.ipv6_owns(entry.address.address(), None));
    }
}
fn routed() -> Lab {
    let mut lab=Topology::from_yaml("devices:\n  PC1: {type: host, interfaces: [gi0/0]}\n  R1: {type: router, interfaces: [gi0/0, gi0/1]}\n  R2: {type: router, interfaces: [gi0/0, gi0/1]}\n  PC2: {type: host, interfaces: [gi0/0]}\nlinks:\n - endpoints: [PC1:gi0/0, R1:gi0/0]\n - endpoints: [R1:gi0/1, R2:gi0/0]\n - endpoints: [R2:gi0/1, PC2:gi0/0]\n").unwrap().build().unwrap();
    for (port, ip) in [
        ("PC1:gi0/0", "2001:db8:1::10/64"),
        ("R1:gi0/0", "2001:db8:1::1/64"),
        ("R1:gi0/1", "2001:db8:12::1/64"),
        ("R2:gi0/0", "2001:db8:12::2/64"),
        ("R2:gi0/1", "2001:db8:2::1/64"),
        ("PC2:gi0/0", "2001:db8:2::10/64"),
    ] {
        address(&mut lab, port, ip);
    }
    for (name, prefix, next) in [
        ("R1", "2001:db8:2::/64", "2001:db8:12::2"),
        ("R2", "2001:db8:1::/64", "2001:db8:12::1"),
    ] {
        lab.with_device_mut(lab.device_id(name).unwrap(), |d| {
            d.set_ipv6_routing(true).unwrap();
            d.set_ipv6_static_route(
                Ipv6StaticRoute {
                    prefix: prefix.parse().unwrap(),
                    next_hop: next.parse().unwrap(),
                    interface: None,
                },
                true,
            )
            .unwrap();
        })
        .unwrap();
    }
    lab.run_until(SimTime::from_millis(1100)).unwrap();
    lab
}
#[test]
fn multi_router_ipv6_forwarding_and_hop_limit_errors_use_packets() {
    let mut lab = routed();
    let pc = lab.device_id("PC1").unwrap();
    let dest = "2001:db8:2::10".parse().unwrap();
    assert_eq!(lab.ping_ipv6(pc, dest, None).unwrap().received, 5);
    let expired = lab.ping_ipv6_with_hop_limit(pc, dest, None, 1).unwrap();
    assert_eq!(expired.received, 0);
    assert!(expired.render().contains("TTTTT"));
    let unreachable = lab
        .ping_ipv6(pc, "2001:db8:999::1".parse().unwrap(), None)
        .unwrap();
    assert_eq!(unreachable.received, 0);
    assert!(unreachable.render().contains("UUUUU"));
    let r1 = lab.device_id("R1").unwrap();
    let r2port = lab.endpoint("R2:gi0/0").unwrap();
    let ll = lab
        .device(r2port.device)
        .unwrap()
        .ipv6_link_local(r2port.interface)
        .unwrap();
    assert!(
        lab.device(r1)
            .unwrap()
            .resolve_ipv6_route(ll, None)
            .is_none()
    );
    let local = lab.endpoint("R1:gi0/1").unwrap();
    assert_eq!(
        lab.ping_ipv6(r1, ll, Some(local.interface))
            .unwrap()
            .received,
        5
    );
}

#[test]
fn duplicate_address_retries_after_shutdown_without_restarting_device() {
    let mut lab = pair();
    address(&mut lab, "R1:gi0/0", "2001:db8::1/64");
    address(&mut lab, "PC:gi0/0", "2001:db8::1/64");
    lab.run_until(SimTime::from_millis(1100)).unwrap();
    let pc = lab.endpoint("PC:gi0/0").unwrap();
    let r = lab.endpoint("R1:gi0/0").unwrap();
    lab.with_device_mut(pc.device, |d| {
        let mut policy = d.running_config().interfaces[&pc.interface].ipv6.clone();
        policy.addresses.clear();
        policy.addresses.insert("2001:db8::2/64".parse().unwrap());
        d.set_ipv6_policy(pc.interface, policy).unwrap();
    })
    .unwrap();
    lab.with_device_mut(r.device, |d| {
        d.set_admin_state(r.interface, AdminState::Down).unwrap();
        d.set_admin_state(r.interface, AdminState::Up).unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(2200)).unwrap();
    assert_eq!(
        lab.ping_ipv6(pc.device, "2001:db8::1".parse().unwrap(), None)
            .unwrap()
            .received,
        5
    );
}
fn advertise(lab: &mut Lab, valid: u32, preferred: u32) {
    use rios_ipv6::{ALL_NODES, NdOption, NextHeader, PrefixInformation, multicast_mac};
    let port = lab.endpoint("R1:gi0/0").unwrap();
    let device = lab.device(port.device).unwrap();
    let source = device.ipv6_link_local(port.interface).unwrap();
    let mac = device.interfaces()[&port.interface].mac_address;
    let message = Icmpv6Message::Neighbor(NdMessage::RouterAdvertisement {
        hop_limit: 64,
        managed: false,
        other: false,
        router_lifetime: 4,
        reachable_time: 0,
        retrans_timer: 0,
        options: vec![
            NdOption::SourceLinkLayer(mac),
            NdOption::Prefix(PrefixInformation {
                prefix: "2001:db8:20::/64".parse().unwrap(),
                on_link: true,
                autonomous: true,
                valid_lifetime: valid,
                preferred_lifetime: preferred,
            }),
        ],
    });
    let packet = Ipv6Packet {
        source,
        destination: ALL_NODES,
        traffic_class: 0,
        flow_label: 0,
        hop_limit: 255,
        next_header: NextHeader::Icmpv6,
        payload: message.encode(source, ALL_NODES).unwrap(),
    };
    lab.transmit(
        port,
        rios_ethernet::EthernetFrame {
            source: mac,
            destination: multicast_mac(ALL_NODES).unwrap(),
            ethertype: EtherType::Ipv6,
            payload: packet.encode().unwrap(),
        },
    )
    .unwrap();
}
#[test]
fn slaac_deprecates_expires_and_applies_two_hour_rule() {
    let mut lab = pair();
    let r = lab.endpoint("R1:gi0/0").unwrap();
    let pc = lab.endpoint("PC:gi0/0").unwrap();
    for port in [r, pc] {
        lab.with_device_mut(port.device, |d| {
            d.set_ipv6_policy(
                port.interface,
                Ipv6InterfacePolicy {
                    enabled: true,
                    autoconfig: port == pc,
                    ..Default::default()
                },
            )
            .unwrap();
            d.set_admin_state(port.interface, AdminState::Up).unwrap();
        })
        .unwrap();
    }
    lab.run_until(SimTime::from_millis(1100)).unwrap();
    advertise(&mut lab, 3, 2);
    lab.run_until(SimTime::from_millis(2200)).unwrap();
    let addr = lab
        .device(pc.device)
        .unwrap()
        .ipv6_addresses(pc.interface)
        .into_iter()
        .find(|a| a.origin == Ipv6AddressOrigin::Slaac)
        .unwrap()
        .address
        .address();
    lab.run_until(SimTime::from_millis(3200)).unwrap();
    assert_eq!(
        lab.device(pc.device)
            .unwrap()
            .ipv6_addresses(pc.interface)
            .iter()
            .find(|a| a.address.address() == addr)
            .unwrap()
            .state,
        Ipv6AddressState::Deprecated
    );
    lab.run_until(SimTime::from_millis(4200)).unwrap();
    assert!(
        !lab.device(pc.device)
            .unwrap()
            .ipv6_addresses(pc.interface)
            .iter()
            .any(|a| a.address.address() == addr)
    );
    lab.run_until(SimTime::from_millis(5200)).unwrap();
    assert!(
        !lab.device(pc.device)
            .unwrap()
            .ipv6_routes()
            .iter()
            .any(|r| r.prefix.prefix_len() == 0)
    );
    advertise(&mut lab, 86400, 3600);
    lab.run_until(SimTime::from_millis(6300)).unwrap();
    advertise(&mut lab, 0, 0);
    lab.run_until(SimTime::from_millis(6310)).unwrap();
    let entry = lab
        .device(pc.device)
        .unwrap()
        .ipv6_addresses(pc.interface)
        .into_iter()
        .find(|a| a.address.address() == addr)
        .unwrap();
    assert_eq!(entry.state, Ipv6AddressState::Deprecated);
    let remaining = entry.valid_until.unwrap().0 - lab.now().0;
    assert!((7_199_000_000..=7_200_000_000).contains(&remaining));
}
#[test]
fn stale_neighbor_enters_delay_and_unicast_probe_before_becoming_reachable() {
    let mut lab = pair();
    address(&mut lab, "R1:gi0/0", "2001:db8::1/64");
    address(&mut lab, "PC:gi0/0", "2001:db8::2/64");
    let pc = lab.device_id("PC").unwrap();
    let target = "2001:db8::1".parse().unwrap();
    assert_eq!(lab.ping_ipv6(pc, target, None).unwrap().received, 5);
    lab.run_until(SimTime(lab.now().0 + 31_000_000)).unwrap();
    assert_eq!(
        lab.device(pc)
            .unwrap()
            .ipv6_neighbors()
            .into_iter()
            .find(|n| n.address == target)
            .unwrap()
            .state,
        Ipv6NeighborState::Stale
    );
    lab.ping_ipv6(pc, target, None).unwrap();
    assert_eq!(
        lab.device(pc)
            .unwrap()
            .ipv6_neighbors()
            .into_iter()
            .find(|n| n.address == target)
            .unwrap()
            .state,
        Ipv6NeighborState::Delay
    );
    let events = lab.run_until(SimTime(lab.now().0 + 6_000_000)).unwrap();
    assert!(events.iter().any(|event|matches!(event,EventOutcome::FrameReceived {frame,..} if Ipv6Packet::decode(&frame.payload).is_ok_and(|p|p.destination==target && Icmpv6Message::decode(p.source,p.destination,&p.payload).is_ok_and(|m|matches!(m,Icmpv6Message::Neighbor(NdMessage::NeighborSolicitation {..})))))));
    assert_eq!(
        lab.device(pc)
            .unwrap()
            .ipv6_neighbors()
            .into_iter()
            .find(|n| n.address == target)
            .unwrap()
            .state,
        Ipv6NeighborState::Reachable
    );
}

#[test]
fn tagged_subinterfaces_route_ipv6_and_keep_dad_vlan_scoped() {
    use rios_config::{StpPortConfig, SwitchportMode, VlanId};
    let mut lab = Topology::from_yaml(include_str!("../../../examples/router-on-a-stick.yaml"))
        .unwrap()
        .build()
        .unwrap();
    lab.with_device_mut(lab.device_id("SW1").unwrap(), |d| {
        for v in [10, 20] {
            d.create_vlan(VlanId::new(v).unwrap()).unwrap();
        }
        for (name, vlan) in [("GigabitEthernet0/1", 10), ("GigabitEthernet0/2", 20)] {
            let id = d.find_interface(name).unwrap();
            d.set_access_vlan(id, VlanId::new(vlan).unwrap()).unwrap();
        }
        let trunk = d.find_interface("GigabitEthernet0/3").unwrap();
        d.set_switchport_mode(trunk, SwitchportMode::Trunk).unwrap();
        d.set_trunk_allowed_vlans(
            trunk,
            [VlanId::new(10).unwrap(), VlanId::new(20).unwrap()].into(),
        )
        .unwrap();
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
    let r1 = lab.device_id("R1").unwrap();
    lab.with_device_mut(r1, |d| {
        d.set_ipv6_routing(true).unwrap();
        let parent = d.find_interface("GigabitEthernet0/0").unwrap();
        d.set_admin_state(parent, AdminState::Up).unwrap();
        for v in [10, 20] {
            let id = d.ensure_interface(&format!("gi0/0.{v}")).unwrap();
            d.set_dot1q(id, VlanId::new(v).unwrap(), false).unwrap();
            d.set_ipv6_address(id, format!("2001:db8:{v}::1/64").parse().unwrap())
                .unwrap();
            d.set_admin_state(id, AdminState::Up).unwrap();
        }
    })
    .unwrap();
    for v in [10, 20] {
        let port = lab.endpoint(&format!("H{v}:gi0/0")).unwrap();
        lab.with_device_mut(port.device, |d| {
            d.set_ipv6_policy(
                port.interface,
                Ipv6InterfacePolicy {
                    addresses: [format!("2001:db8:{v}::{v}/64").parse().unwrap()].into(),
                    link_local: Some("fe80::10".parse().unwrap()),
                    ..Default::default()
                },
            )
            .unwrap();
            d.set_admin_state(port.interface, AdminState::Up).unwrap();
        })
        .unwrap();
    }
    let events = lab.run_until(SimTime::from_millis(2100)).unwrap();
    assert!(events.iter().any(|event|matches!(event,EventOutcome::FrameReceived {frame,..} if frame.ethertype==EtherType::Dot1Q && frame.untagged().is_ok_and(|(_,f)|f.ethertype==EtherType::Ipv6))));
    for v in [10, 20] {
        let port = lab.endpoint(&format!("H{v}:gi0/0")).unwrap();
        assert!(
            lab.device(port.device)
                .unwrap()
                .ipv6_addresses(port.interface)
                .iter()
                .all(|a| a.state == Ipv6AddressState::Preferred)
        );
    }
    let h10 = lab.device_id("H10").unwrap();
    assert_eq!(
        lab.ping_ipv6(h10, "2001:db8:20::20".parse().unwrap(), None)
            .unwrap()
            .received,
        5
    );
    let neighbors = lab.device(r1).unwrap().ipv6_neighbors();
    assert_eq!(
        neighbors
            .iter()
            .filter(|n| n.address == "fe80::10".parse::<Ipv6Addr>().unwrap())
            .map(|n| n.interface)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
}
