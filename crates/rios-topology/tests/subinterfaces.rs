use rios_config::{
    AccessListAction, AccessListDirection, AccessListId, AdminState, OspfNetworkConfig,
    StandardAccessListEntry, SwitchportMode, VlanId,
};
use rios_device::Device;
use rios_ethernet::EtherType;
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network, RouteSource};
use rios_simulator::{DeviceId, InterfaceId, SimTime};
use rios_topology::{Lab, Topology, TraceAction};

fn vlan(id: u16) -> VlanId {
    VlanId::new(id).unwrap()
}
fn address(device: &mut Device, name: &str, address: &str) -> InterfaceId {
    let interface = device.ensure_interface(name).unwrap();
    device
        .set_ipv4(
            interface,
            Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
        )
        .unwrap();
    device.set_admin_state(interface, AdminState::Up).unwrap();
    interface
}
fn setup() -> Lab {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/router-on-a-stick.yaml"))
        .unwrap()
        .build()
        .unwrap();
    for (name, ip, gateway) in [
        ("H10", "10.10.10.10", "10.10.10.1"),
        ("H20", "10.20.20.20", "10.20.20.1"),
    ] {
        let id = lab.device_id(name).unwrap();
        lab.with_device_mut(id, |device| {
            address(device, "gi0/0", ip);
            device.set_static_route(
                Ipv4Network::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
                gateway.parse().unwrap(),
            );
        })
        .unwrap();
    }
    let sw = lab.device_id("SW1").unwrap();
    lab.with_device_mut(sw, |device| {
        for id in device.interfaces().keys().copied().collect::<Vec<_>>() {
            device
                .set_stp_port(
                    id,
                    rios_config::StpPortConfig {
                        portfast: true,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        device.create_vlan(vlan(10)).unwrap();
        device.create_vlan(vlan(20)).unwrap();
        for (name, vid) in [("gi0/1", 10), ("gi0/2", 20), ("gi0/4", 10)] {
            let id = device.ensure_interface(name).unwrap();
            device.set_access_vlan(id, vlan(vid)).unwrap();
        }
        let id = device.ensure_interface("gi0/3").unwrap();
        device
            .set_switchport_mode(id, SwitchportMode::Trunk)
            .unwrap();
        device.set_native_vlan(id, vlan(20)).unwrap();
    })
    .unwrap();
    let r1 = lab.device_id("R1").unwrap();
    lab.with_device_mut(r1, |device| {
        let parent = device.ensure_interface("gi0/0").unwrap();
        device.set_admin_state(parent, AdminState::Up).unwrap();
        for (vid, ip) in [(10, "10.10.10.1"), (20, "10.20.20.1")] {
            let id = address(device, &format!("gi0/0.{vid}"), ip);
            device.set_dot1q(id, vlan(vid), vid == 20).unwrap();
        }
    })
    .unwrap();
    lab
}
#[test]
fn router_on_a_stick_routes_tagged_and_native_vlans_and_applies_acl() {
    let mut lab = setup();
    let h10 = lab.device_id("H10").unwrap();
    let r1 = lab.device_id("R1").unwrap();
    lab.set_tracing(true);
    assert_eq!(
        lab.ping(h10, "10.20.20.20".parse().unwrap())
            .unwrap()
            .received,
        5
    );
    let parent = lab.endpoint("R1:gi0/0").unwrap();
    let trace = lab.take_trace();
    for ether in [EtherType::Dot1Q, EtherType::Ipv4] {
        assert!(trace.iter().any(|record| record.interface == parent
            && record.ethertype == ether
            && record.action == TraceAction::Tx));
    }
    let now = lab.now();
    lab.with_device_mut(r1, |device| {
        let table = device.show_arp(now);
        assert!(table.contains("GigabitEthernet0/0.10"));
        assert!(table.contains("GigabitEthernet0/0.20"));
        let acl = AccessListId::new(10).unwrap();
        device
            .add_access_list_entry(
                acl,
                StandardAccessListEntry {
                    action: AccessListAction::Deny,
                    source: "0.0.0.0".parse().unwrap(),
                    wildcard: "255.255.255.255".parse().unwrap(),
                },
            )
            .unwrap();
        let interface = device.ensure_interface("gi0/0.10").unwrap();
        device
            .set_access_group(interface, acl, AccessListDirection::In)
            .unwrap();
    })
    .unwrap();
    assert_eq!(
        lab.ping(h10, "10.20.20.20".parse().unwrap())
            .unwrap()
            .received,
        0
    );
}
#[test]
fn subinterface_and_parent_shutdown_preserve_sibling_semantics() {
    let mut lab = setup();
    let r1 = lab.device_id("R1").unwrap();
    lab.with_device_mut(r1, |device| {
        let a = device.ensure_interface("gi0/0.10").unwrap();
        let b = device.ensure_interface("gi0/0.20").unwrap();
        device.set_admin_state(a, AdminState::Down).unwrap();
        assert!(!device.protocol_up(a));
        assert!(device.protocol_up(b));
        let parent = device.ensure_interface("gi0/0").unwrap();
        device.set_admin_state(parent, AdminState::Down).unwrap();
        assert!(!device.protocol_up(b));
        device.set_admin_state(parent, AdminState::Up).unwrap();
        assert!(device.protocol_up(b));
        assert!(!device.protocol_up(a));
    })
    .unwrap();
}
fn ospf(lab: &mut Lab, device: DeviceId) {
    lab.with_device_mut(device, |device| {
        device.set_ospf_process(1).unwrap();
        device
            .add_ospf_network(OspfNetworkConfig {
                address: "0.0.0.0".parse().unwrap(),
                wildcard: "255.255.255.255".parse().unwrap(),
                area: 0,
            })
            .unwrap();
    })
    .unwrap();
}
#[test]
fn ospf_and_router_originated_ping_use_subinterface_identity() {
    let mut lab = setup();
    let r1 = lab.device_id("R1").unwrap();
    let r2 = lab.device_id("R2").unwrap();
    lab.with_device_mut(r2, |device| {
        address(device, "gi0/0", "10.10.10.2");
        address(device, "lo0", "192.0.2.1");
    })
    .unwrap();
    ospf(&mut lab, r1);
    ospf(&mut lab, r2);
    lab.run_until(SimTime::from_millis(20_100)).unwrap();
    let route = lab
        .device(r1)
        .unwrap()
        .routing_table()
        .lookup("192.0.2.1".parse().unwrap())
        .unwrap()
        .clone();
    assert_eq!(route.source, RouteSource::Ospf);
    assert_eq!(
        route.outgoing_interface,
        lab.device(r1)
            .unwrap()
            .find_interface("GigabitEthernet0/0.10")
    );
    assert_eq!(
        lab.ping(r1, "192.0.2.1".parse().unwrap()).unwrap().received,
        5
    );
    assert_eq!(
        lab.ping(r2, "10.20.20.20".parse().unwrap())
            .unwrap()
            .received,
        5
    );
}

#[test]
fn extended_acl_filters_udp_ports_in_actual_routed_frames() {
    use rios_config::{AclEntry, AclKind, AclProtocol, AddressMatch, PortMatch};
    use rios_ethernet::EthernetFrame;
    use rios_ipv4::{IpProtocol, Ipv4Packet};
    use rios_protocol::UdpDatagram;
    use rios_topology::EventOutcome;
    let mut lab = setup();
    let source = lab.endpoint("H10:gi0/0").unwrap();
    let target = lab.endpoint("H20:gi0/0").unwrap();
    let router = lab.endpoint("R1:gi0/0").unwrap();
    let acl = lab
        .with_device_mut(router.device, |device| {
            let acl = device.ensure_acl("DNS", AclKind::Extended).unwrap();
            device
                .set_acl_entry(
                    acl,
                    Some(10),
                    AclEntry::Rule {
                        action: AccessListAction::Permit,
                        protocol: AclProtocol::Udp,
                        source: AddressMatch::ANY,
                        source_port: PortMatch::Range(1000, 2000),
                        destination: AddressMatch::ANY,
                        destination_port: PortMatch::Eq(53),
                        log: true,
                    },
                )
                .unwrap();
            let id = device.ensure_interface("gi0/0.10").unwrap();
            device
                .set_named_access_group(id, "DNS", AccessListDirection::In)
                .unwrap();
            acl
        })
        .unwrap();
    for (port, expected) in [(53, true), (80, false)] {
        let packet = Ipv4Packet {
            source: "10.10.10.10".parse().unwrap(),
            destination: "10.20.20.20".parse().unwrap(),
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: UdpDatagram {
                source_port: 1500,
                destination_port: port,
                payload: vec![1, 2, 3],
            }
            .encode()
            .unwrap(),
        };
        let frame = EthernetFrame {
            source: lab.device(source.device).unwrap().interfaces()[&source.interface].mac_address,
            destination: lab.device(router.device).unwrap().interfaces()[&router.interface]
                .mac_address,
            ethertype: EtherType::Ipv4,
            payload: packet.encode().unwrap(),
        };
        lab.transmit(source, frame).unwrap();
        let outcomes = lab.run_until(SimTime(lab.now().0 + 10_000)).unwrap();
        let delivered = outcomes.iter().any(|event| matches!(event, EventOutcome::FrameReceived { interface, frame } if *interface == target && frame.ethertype == EtherType::Ipv4));
        assert_eq!(delivered, expected);
    }
    assert_eq!(
        lab.device(router.device).unwrap().acl_match_count(acl, 10),
        1
    );
    let logs = lab
        .with_device_mut(router.device, |device| device.take_acl_logs())
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].destination.to_string(), "10.20.20.20");
}
