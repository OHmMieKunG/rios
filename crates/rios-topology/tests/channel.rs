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
