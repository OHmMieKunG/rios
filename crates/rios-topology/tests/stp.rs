use rios_config::{AdminState, StpPortConfig, SwitchportMode, VlanId};
use rios_ethernet::{EtherType, EthernetFrame, MacAddress};
use rios_simulator::{LinkId, LinkState, SimTime};
use rios_switching::{StpPortRole, StpPortState};
use rios_topology::{EventOutcome, Lab, Topology};
fn triangle() -> Lab {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/stp-triangle.yaml"))
        .unwrap()
        .build()
        .unwrap();
    for name in ["SW1", "SW2", "SW3"] {
        lab.with_device_mut(lab.device_id(name).unwrap(), |device| {
            device.set_stp_rapid(true).unwrap();
            for vid in [10, 20] {
                let vlan = VlanId::new(vid).unwrap();
                device.create_vlan(vlan).unwrap();
                if name == "SW1" && vid == 10 || name == "SW2" && vid == 20 {
                    device.set_stp_priority(vlan, 0).unwrap();
                }
            }
            let ports: Vec<_> = device
                .running_config()
                .interfaces
                .iter()
                .map(|(id, config)| (*id, config.name.clone()))
                .collect();
            for (id, name) in ports {
                if name.ends_with("0/1") {
                    device
                        .set_access_vlan(id, VlanId::new(10).unwrap())
                        .unwrap();
                    device
                        .set_stp_port(
                            id,
                            StpPortConfig {
                                portfast: true,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                } else {
                    device
                        .set_switchport_mode(id, SwitchportMode::Trunk)
                        .unwrap();
                    device
                        .set_trunk_allowed_vlans(
                            id,
                            [VlanId::new(10).unwrap(), VlanId::new(20).unwrap()].into(),
                        )
                        .unwrap();
                }
            }
        })
        .unwrap();
    }
    for name in ["H1:gi0/0", "H2:gi0/0"] {
        let endpoint = lab.endpoint(name).unwrap();
        lab.with_device_mut(endpoint.device, |device| {
            device
                .set_admin_state(endpoint.interface, AdminState::Up)
                .unwrap()
        })
        .unwrap();
    }
    lab
}
fn flood(lab: &mut Lab) {
    let source = lab.endpoint("H1:gi0/0").unwrap();
    let target = lab.endpoint("H2:gi0/0").unwrap();
    let frame = EthernetFrame {
        source: lab.device(source.device).unwrap().interfaces()[&source.interface].mac_address,
        destination: MacAddress::BROADCAST,
        ethertype: EtherType::Other(0x9000),
        payload: vec![1],
    };
    lab.transmit(source, frame).unwrap();
    let events = lab.run_until(SimTime(lab.now().0 + 20_000)).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(event,EventOutcome::FrameReceived { interface,.. } if *interface == target)).count(),1);
}
#[test]
fn rapid_vlan_roots_converge_and_recover_without_duplicate_floods() {
    let mut lab = triangle();
    lab.run_until(SimTime::from_millis(100)).unwrap();
    for vlan in [VlanId::new(10).unwrap(), VlanId::new(20).unwrap()] {
        let mut roots = Vec::new();
        let mut alternate = 0;
        for name in ["SW1", "SW2", "SW3"] {
            let device = lab.device(lab.device_id(name).unwrap()).unwrap();
            let roles: Vec<_> = device
                .interfaces()
                .keys()
                .filter_map(|id| device.stp_port_state(*id, vlan))
                .collect();
            if !roles.iter().any(|(role, _)| *role == StpPortRole::Root) {
                roots.push(name);
            }
            alternate += roles
                .iter()
                .filter(|(role, state)| {
                    *role == StpPortRole::Alternate && *state == StpPortState::Blocking
                })
                .count();
        }
        assert_eq!(
            roots,
            if vlan.get() == 10 {
                vec!["SW1"]
            } else {
                vec!["SW2"]
            }
        );
        assert_eq!(alternate, 1);
    }
    flood(&mut lab);
    lab.set_link_state(LinkId(3), LinkState::Down).unwrap();
    lab.run_until(SimTime::from_millis(3100)).unwrap();
    flood(&mut lab);
}

#[test]
fn blocked_port_cannot_bypass_spanning_tree_through_an_svi() {
    use rios_ipv4::Ipv4InterfaceConfig;
    use rios_protocol::{ArpOperation, ArpPacket};
    use rios_simulator::InterfaceRef;
    let mut lab = triangle();
    lab.run_until(SimTime::from_millis(100)).unwrap();
    let vlan = VlanId::new(10).unwrap();
    let blocked = ["SW1", "SW2", "SW3"]
        .iter()
        .find_map(|name| {
            let id = lab.device_id(name).unwrap();
            lab.device(id)
                .unwrap()
                .interfaces()
                .keys()
                .find_map(|port| {
                    (lab.device(id).unwrap().stp_port_state(*port, vlan)
                        == Some((StpPortRole::Alternate, StpPortState::Blocking)))
                    .then_some(InterfaceRef {
                        device: id,
                        interface: *port,
                    })
                })
        })
        .unwrap();
    lab.with_device_mut(blocked.device, |device| {
        let svi = device.ensure_interface("vlan10").unwrap();
        device
            .set_ipv4(
                svi,
                Ipv4InterfaceConfig::new("10.0.0.1".parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
        device.set_admin_state(svi, AdminState::Up).unwrap();
    })
    .unwrap();
    let peer = lab
        .links()
        .values()
        .find_map(|link| {
            if link.endpoint_a == blocked {
                Some(link.endpoint_b)
            } else if link.endpoint_b == blocked {
                Some(link.endpoint_a)
            } else {
                None
            }
        })
        .unwrap();
    let source = MacAddress([2, 0xff, 0, 0, 0, 1]);
    let arp = ArpPacket {
        operation: ArpOperation::Request,
        sender_mac: source,
        sender_ip: "10.0.0.99".parse().unwrap(),
        target_mac: MacAddress([0; 6]),
        target_ip: "10.0.0.1".parse().unwrap(),
    };
    let frame = EthernetFrame {
        source,
        destination: MacAddress::BROADCAST,
        ethertype: EtherType::Arp,
        payload: arp.encode(),
    }
    .tagged(vlan);
    lab.transmit(peer, frame).unwrap();
    lab.run_until(SimTime::from_millis(120)).unwrap();
    let now = lab.now();
    lab.with_device_mut(blocked.device, |device| {
        assert!(
            device
                .arp_lookup("10.0.0.99".parse().unwrap(), now)
                .is_none()
        );
        assert!(
            device.interfaces()[&blocked.interface]
                .counters
                .drop_reasons
                .get(&rios_device::DropReason::StpBlocking)
                .is_some_and(|count| *count > 0)
        );
    })
    .unwrap();
}
