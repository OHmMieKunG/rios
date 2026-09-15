use rios_config::{AdminState, ChannelMode, SwitchportMode};
use rios_ipv4::Ipv4InterfaceConfig;
use rios_simulator::{LinkState, SimTime};
use rios_topology::{Lab, Topology};
fn setup(kind: &str) -> Lab {
    let yaml = format!(
        r#"
devices:
  A: {{type: {kind}, interfaces: [GigabitEthernet0/0, GigabitEthernet0/1]}}
  B: {{type: {kind}, interfaces: [GigabitEthernet0/0, GigabitEthernet0/1]}}
links:
  - endpoints: ["A:GigabitEthernet0/0", "B:GigabitEthernet0/0"]
  - endpoints: ["A:GigabitEthernet0/1", "B:GigabitEthernet0/1"]
"#
    );
    let mut lab = Topology::from_yaml(&yaml).unwrap().build().unwrap();
    for name in ["A", "B"] {
        let device = lab.device_id(name).unwrap();
        lab.with_device_mut(device, |device| {
            for port in ["gi0/0", "gi0/1"] {
                let id = device.ensure_interface(port).unwrap();
                device.set_admin_state(id, AdminState::Up).unwrap();
                device.set_channel_group(id, 1, ChannelMode::On).unwrap();
            }
        })
        .unwrap();
    }
    lab
}
#[test]
fn routed_static_bundle_survives_member_failure() {
    let mut lab = setup("router");
    for (name, address) in [("A", "10.0.0.1"), ("B", "10.0.0.2")] {
        lab.with_device_mut(lab.device_id(name).unwrap(), |device| {
            let po = device.ensure_interface("po1").unwrap();
            assert_eq!(device.channel_members(po).len(), 2);
            device
                .set_ipv4(
                    po,
                    Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
                )
                .unwrap();
        })
        .unwrap();
    }
    let a = lab.device_id("A").unwrap();
    assert_eq!(
        lab.ping(a, "10.0.0.2".parse().unwrap()).unwrap().received,
        5
    );
    lab.set_link_state(rios_simulator::LinkId(1), LinkState::Down)
        .unwrap();
    assert_eq!(
        lab.ping(a, "10.0.0.2".parse().unwrap()).unwrap().received,
        5
    );
    lab.set_link_state(rios_simulator::LinkId(2), LinkState::Down)
        .unwrap();
    let device = lab.device(a).unwrap();
    assert!(!device.protocol_up(device.find_interface("Port-channel1").unwrap()));
}

#[test]
fn switched_bundle_is_one_stp_port_and_one_flood_destination() {
    let mut lab = setup("switch");
    for name in ["A", "B"] {
        lab.with_device_mut(lab.device_id(name).unwrap(), |device| {
            let po = device.ensure_interface("po1").unwrap();
            device
                .set_switchport_mode(po, SwitchportMode::Trunk)
                .unwrap();
            let svi = device.ensure_interface("vlan1").unwrap();
            device.set_admin_state(svi, AdminState::Up).unwrap();
            device
                .set_ipv4(
                    svi,
                    Ipv4InterfaceConfig::new(
                        if name == "A" { "10.0.0.1" } else { "10.0.0.2" }
                            .parse()
                            .unwrap(),
                        24,
                    )
                    .unwrap(),
                )
                .unwrap();
        })
        .unwrap();
    }
    lab.run_until(SimTime::from_millis(100)).unwrap();
    let a = lab.device_id("A").unwrap();
    assert_eq!(
        lab.ping(a, "10.0.0.2".parse().unwrap()).unwrap().received,
        5
    );
    let device = lab.device(a).unwrap();
    let summary = device.show_etherchannel_summary();
    assert!(summary.contains("GigabitEthernet0/0(P)"));
    assert!(summary.contains("GigabitEthernet0/1(P)"));
}

fn configure_lacp(lab: &mut Lab, name: &str, mode: ChannelMode) {
    lab.with_device_mut(lab.device_id(name).unwrap(), |device| {
        for port in ["gi0/0", "gi0/1"] {
            let id = device.ensure_interface(port).unwrap();
            device.clear_channel_group(id).unwrap();
        }
        for port in ["gi0/0", "gi0/1"] {
            let id = device.ensure_interface(port).unwrap();
            device.set_channel_group(id, 1, mode).unwrap();
        }
        let po = device.ensure_interface("po1").unwrap();
        device
            .set_ipv4(
                po,
                Ipv4InterfaceConfig::new(
                    if name == "A" { "10.0.0.1" } else { "10.0.0.2" }
                        .parse()
                        .unwrap(),
                    24,
                )
                .unwrap(),
            )
            .unwrap();
    })
    .unwrap();
}

#[test]
fn lacp_active_passive_negotiates_on_wire_and_fails_over() {
    use rios_ethernet::EtherType;
    use rios_switching::{LACP_DISTRIBUTING, LACP_ETHERTYPE, Lacpdu};
    use rios_topology::EventOutcome;
    let mut lab = setup("router");
    configure_lacp(&mut lab, "A", ChannelMode::Active);
    configure_lacp(&mut lab, "B", ChannelMode::Passive);
    let events = lab.run_until(SimTime::from_millis(100)).unwrap();
    assert!(events.iter().any(|event| {
        let EventOutcome::FrameReceived { frame, .. } = event else {
            return false;
        };
        frame.ethertype == EtherType::Other(LACP_ETHERTYPE)
            && Lacpdu::decode(&frame.payload)
                .is_ok_and(|pdu| pdu.actor.state & LACP_DISTRIBUTING != 0)
    }));
    for name in ["A", "B"] {
        let device = lab.device(lab.device_id(name).unwrap()).unwrap();
        assert_eq!(
            device
                .channel_members(device.find_interface("Port-channel1").unwrap())
                .len(),
            2
        );
    }
    let a = lab.device_id("A").unwrap();
    assert_eq!(
        lab.ping(a, "10.0.0.2".parse().unwrap()).unwrap().received,
        5
    );
    lab.set_link_state(rios_simulator::LinkId(1), LinkState::Down)
        .unwrap();
    assert_eq!(
        lab.ping(a, "10.0.0.2".parse().unwrap()).unwrap().received,
        5
    );
}

#[test]
fn passive_pairs_do_not_bundle_and_silent_partners_expire() {
    let mut lab = setup("router");
    configure_lacp(&mut lab, "A", ChannelMode::Passive);
    configure_lacp(&mut lab, "B", ChannelMode::Passive);
    lab.run_until(SimTime::from_millis(100)).unwrap();
    let a = lab.device_id("A").unwrap();
    let po = lab
        .device(a)
        .unwrap()
        .find_interface("Port-channel1")
        .unwrap();
    assert!(!lab.device(a).unwrap().protocol_up(po));
    configure_lacp(&mut lab, "A", ChannelMode::Active);
    lab.run_until(SimTime::from_millis(1500)).unwrap();
    assert!(lab.device(a).unwrap().protocol_up(po));
    lab.with_device_mut(lab.device_id("B").unwrap(), |device| {
        for name in ["gi0/0", "gi0/1"] {
            device
                .clear_channel_group(
                    device
                        .find_interface(&format!(
                            "GigabitEthernet{}",
                            name.trim_start_matches("gi")
                        ))
                        .unwrap(),
                )
                .unwrap();
        }
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(5500)).unwrap();
    assert!(!lab.device(a).unwrap().protocol_up(po));
    assert!(lab.device(a).unwrap().lacp_neighbors().is_empty());
}

#[test]
fn lacp_switch_bundle_floods_once_and_learns_logical_port() {
    use rios_ethernet::{EtherType, EthernetFrame, MacAddress, VlanId};
    use rios_topology::EventOutcome;
    let mut lab = Topology::from_yaml(
        r#"
devices:
  H1: {type: host, interfaces: [GigabitEthernet0/0]}
  H2: {type: host, interfaces: [GigabitEthernet0/0]}
  SW1: {type: switch, interfaces: [GigabitEthernet0/0, GigabitEthernet0/1, GigabitEthernet0/2]}
  SW2: {type: switch, interfaces: [GigabitEthernet0/0, GigabitEthernet0/1, GigabitEthernet0/2]}
links:
  - endpoints: ["H1:GigabitEthernet0/0", "SW1:GigabitEthernet0/2"]
  - endpoints: ["SW1:GigabitEthernet0/0", "SW2:GigabitEthernet0/0"]
  - endpoints: ["SW1:GigabitEthernet0/1", "SW2:GigabitEthernet0/1"]
  - endpoints: ["H2:GigabitEthernet0/0", "SW2:GigabitEthernet0/2"]
"#,
    )
    .unwrap()
    .build()
    .unwrap();
    for name in ["SW1", "SW2"] {
        lab.with_device_mut(lab.device_id(name).unwrap(), |device| {
            for name in ["gi0/0", "gi0/1"] {
                let id = device.ensure_interface(name).unwrap();
                device
                    .set_channel_group(id, 1, ChannelMode::Active)
                    .unwrap();
            }
            let po = device.ensure_interface("po1").unwrap();
            device
                .set_switchport_mode(po, SwitchportMode::Trunk)
                .unwrap();
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
    lab.run_until(SimTime::from_millis(2500)).unwrap();
    let source = lab.endpoint("H1:gi0/0").unwrap();
    let target = lab.endpoint("H2:gi0/0").unwrap();
    let mac = lab.device(source.device).unwrap().interfaces()[&source.interface].mac_address;
    lab.transmit(
        source,
        EthernetFrame {
            source: mac,
            destination: MacAddress::BROADCAST,
            ethertype: EtherType::Other(0x9000),
            payload: vec![1, 2, 3],
        },
    )
    .unwrap();
    let events = lab.run_until(SimTime::from_millis(2520)).unwrap();
    assert_eq!(events.iter().filter(|event| matches!(event,EventOutcome::FrameReceived { interface,frame } if *interface == target && frame.ethertype == EtherType::Other(0x9000))).count(),1);
    let now = lab.now();
    lab.with_device_mut(lab.device_id("SW2").unwrap(), |device| {
        let learned = device.mac_lookup(VlanId::DEFAULT, mac, now).unwrap();
        assert_eq!(
            learned.interface,
            device.find_interface("Port-channel1").unwrap()
        );
    })
    .unwrap();
}
