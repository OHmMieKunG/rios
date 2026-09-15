use rios_config::{
    AccessListAction, AccessListDirection, AccessListId, AdminState, NatRole, OspfNetworkConfig,
    StandardAccessListEntry, SwitchportMode, VlanId,
};
use rios_device::{Device, DeviceType, DropReason, InterfaceMedia};
use rios_ethernet::{EtherType, EthernetFrame, MacAddress};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::{DeviceId, InterfaceId, InterfaceRef, LinkId, LinkState, SimTime, TimerId};
use rios_topology::*;
const YAML: &str = include_str!("../../../examples/two-routers.yaml");
fn enable(lab: &mut Lab, endpoint: InterfaceRef, state: AdminState) {
    lab.with_device_mut(endpoint.device, |device| {
        device.set_admin_state(endpoint.interface, state)
    })
    .unwrap()
    .unwrap();
}
fn setup() -> (Lab, InterfaceRef, InterfaceRef) {
    let mut lab = Topology::from_yaml(YAML).unwrap().build().unwrap();
    let a = lab.endpoint("R1:gi0/0").unwrap();
    let b = lab.endpoint("R2:gi0/0").unwrap();
    enable(&mut lab, a, AdminState::Up);
    enable(&mut lab, b, AdminState::Up);
    (lab, a, b)
}
fn address(lab: &mut Lab, endpoint: InterfaceRef, address: &str) {
    let address = address.parse().unwrap();
    lab.with_device_mut(endpoint.device, |device| {
        device.set_ipv4(
            endpoint.interface,
            Ipv4InterfaceConfig::new(address, 24).unwrap(),
        )
    })
    .unwrap()
    .unwrap();
}

fn address_prefix(lab: &mut Lab, endpoint: InterfaceRef, address: &str, prefix_len: u8) {
    let address = address.parse().unwrap();
    lab.with_device_mut(endpoint.device, |device| {
        device.set_ipv4(
            endpoint.interface,
            Ipv4InterfaceConfig::new(address, prefix_len).unwrap(),
        )
    })
    .unwrap()
    .unwrap();
    enable(lab, endpoint, AdminState::Up);
}

fn static_route(lab: &mut Lab, device: DeviceId, prefix: &str, length: u8, next_hop: &str) {
    lab.with_device_mut(device, |device| {
        device.set_static_route(
            Ipv4Network::new(prefix.parse().unwrap(), length).unwrap(),
            next_hop.parse().unwrap(),
        );
    })
    .unwrap();
}
fn frame(lab: &Lab, a: InterfaceRef, b: InterfaceRef) -> EthernetFrame {
    EthernetFrame {
        source: lab.device(a.device).unwrap().interfaces()[&a.interface].mac_address,
        destination: lab.device(b.device).unwrap().interfaces()[&b.interface].mac_address,
        ethertype: EtherType::Other(0x88b5),
        payload: vec![1, 2, 3, 4],
    }
}
#[test]
fn virtual_delivery_moves_payload_and_accounts_exactly_once() {
    let (mut lab, a, b) = setup();
    lab.set_tracing(true);
    let packet = frame(&lab, a, b);
    let pointer = packet.payload.as_ptr();
    lab.transmit(a, packet).unwrap();
    assert_eq!(lab.now(), SimTime(0));
    assert_eq!(lab.pending_events(), 1);
    assert!(lab.run_until(SimTime(0)).unwrap().is_empty());
    assert_eq!(
        lab.device(b.device).unwrap().interfaces()[&b.interface]
            .counters
            .rx_packets,
        0
    );
    let EventOutcome::FrameReceived { interface, frame } = lab.step().unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(interface, b);
    assert_eq!(frame.payload.as_ptr(), pointer);
    assert_eq!(frame.payload, [1, 2, 3, 4]);
    assert_eq!(lab.now(), SimTime(1));
    assert!(lab.step().unwrap().is_none());
    let tx = &lab.device(a.device).unwrap().interfaces()[&a.interface].counters;
    let rx = &lab.device(b.device).unwrap().interfaces()[&b.interface].counters;
    assert_eq!((tx.tx_packets, tx.tx_bytes, tx.rx_packets), (1, 18, 0));
    assert_eq!((rx.rx_packets, rx.rx_bytes, rx.tx_packets), (1, 18, 0));
    let trace = lab.take_trace();
    assert_eq!(trace.len(), 2);
    assert_eq!(
        (trace[0].time, trace[0].action),
        (SimTime(0), TraceAction::Tx)
    );
    assert_eq!(
        (trace[1].time, trace[1].action),
        (SimTime(1), TraceAction::Rx)
    );
    assert!(lab.take_trace().is_empty());
}
#[test]
fn bidirectional_delivery_and_repeated_runs_are_deterministic() {
    fn run() -> Vec<TraceRecord> {
        let (mut lab, a, b) = setup();
        lab.set_tracing(true);
        lab.transmit(a, frame(&lab, a, b)).unwrap();
        lab.transmit(b, frame(&lab, b, a)).unwrap();
        let outcomes = lab.run_until(SimTime(10)).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(outcomes[0],EventOutcome::FrameReceived {interface,..} if interface == b));
        assert!(matches!(outcomes[1],EventOutcome::FrameReceived {interface,..} if interface == a));
        assert_eq!(lab.now(), SimTime(10));
        lab.take_trace()
    }
    assert_eq!(run(), run());
}
#[test]
fn link_and_port_flaps_invalidate_in_flight_frames() {
    let (mut lab, a, b) = setup();
    let link = LinkId(1);
    lab.transmit(a, frame(&lab, a, b)).unwrap();
    lab.set_link_state(link, LinkState::Down).unwrap();
    assert!(!lab.device(a.device).unwrap().protocol_up(a.interface));
    lab.set_link_state(link, LinkState::Up).unwrap();
    assert_eq!(
        lab.step().unwrap(),
        Some(EventOutcome::FrameDropped {
            interface: b,
            reason: DropReason::LinkChanged
        })
    );
    lab.transmit(a, frame(&lab, a, b)).unwrap();
    enable(&mut lab, b, AdminState::Down);
    enable(&mut lab, b, AdminState::Up);
    assert_eq!(
        lab.step().unwrap(),
        Some(EventOutcome::FrameDropped {
            interface: b,
            reason: DropReason::LinkChanged
        })
    );
    lab.transmit(a, frame(&lab, a, b)).unwrap();
    assert!(matches!(
        lab.step().unwrap(),
        Some(EventOutcome::FrameReceived { .. })
    ));
    assert_eq!(
        lab.device(b.device).unwrap().interfaces()[&b.interface]
            .counters
            .drops,
        2
    );
}

#[test]
fn disconnect_removes_link_and_carrier() {
    let (mut lab, a, b) = setup();
    lab.disconnect(LinkId(1)).unwrap();
    assert!(lab.links().is_empty());
    assert!(!lab.device(a.device).unwrap().protocol_up(a.interface));
    assert!(!lab.device(b.device).unwrap().protocol_up(b.interface));
    assert!(matches!(
        lab.disconnect(LinkId(1)),
        Err(LabError::UnknownLink(LinkId(1)))
    ));
}
#[test]
fn same_time_link_events_obey_insertion_order_and_timers_use_virtual_time() {
    for outage_first in [true, false] {
        let (mut lab, a, b) = setup();
        if outage_first {
            lab.schedule_link_state(LinkId(1), LinkState::Down, SimTime(1))
                .unwrap();
        }
        lab.transmit(a, frame(&lab, a, b)).unwrap();
        if !outage_first {
            lab.schedule_link_state(LinkId(1), LinkState::Down, SimTime(1))
                .unwrap();
        }
        let outcomes = lab.run_until(SimTime(1)).unwrap();
        assert_eq!(
            outcomes
                .iter()
                .any(|v| matches!(v, EventOutcome::FrameDropped { .. })),
            outage_first
        );
        lab.schedule_timer(TimerId(7), 5000).unwrap();
        assert_eq!(
            lab.step().unwrap(),
            Some(EventOutcome::TimerExpired { timer: TimerId(7) })
        );
        assert_eq!(lab.now(), SimTime(5001));
    }
}
#[test]
fn filtering_mtu_and_disabled_ports_have_real_drop_counters() {
    let (mut lab, a, b) = setup();
    let mut unknown = frame(&lab, a, b);
    unknown.destination = MacAddress([2, 1, 2, 3, 4, 5]);
    lab.transmit(a, unknown).unwrap();
    assert_eq!(
        lab.step().unwrap(),
        Some(EventOutcome::FrameDropped {
            interface: b,
            reason: DropReason::NotForInterface
        })
    );
    let mut broadcast = frame(&lab, a, b);
    broadcast.destination = MacAddress::BROADCAST;
    lab.transmit(a, broadcast).unwrap();
    assert!(matches!(
        lab.step().unwrap(),
        Some(EventOutcome::FrameReceived { .. })
    ));
    let mut oversize = frame(&lab, a, b);
    oversize.payload = vec![0; 1501];
    assert!(matches!(
        lab.transmit(a, oversize),
        Err(LabError::Dropped(DropReason::MtuExceeded))
    ));
    enable(&mut lab, b, AdminState::Down);
    assert!(matches!(
        lab.transmit(a, frame(&lab, a, b)),
        Err(LabError::Dropped(DropReason::InterfaceDown))
    ));
    let unlinked = lab.endpoint("R1:gi0/1").unwrap();
    assert!(matches!(
        lab.transmit(unlinked, frame(&lab, a, b)),
        Err(LabError::Dropped(DropReason::NoLink))
    ));
    assert!(lab.take_trace().is_empty());
    assert_eq!(lab.pending_events(), 0);
    let counters = &lab.device(a.device).unwrap().interfaces()[&a.interface].counters;
    assert_eq!((counters.tx_packets, counters.drops), (2, 2));
}
#[test]
fn switch_learns_floods_forwards_and_ages_in_virtual_time() {
    let mut lab = Topology::from_yaml(
        "devices:\n  H1: {type: host, interfaces: [gi0/0]}\n  H2: {type: host, interfaces: [gi0/0]}\n  H3: {type: host, interfaces: [gi0/0]}\n  SW1: {type: switch, interfaces: [gi0/1, gi0/2, gi0/3]}\nlinks:\n  - endpoints: [H1:gi0/0, SW1:gi0/1]\n  - endpoints: [H2:gi0/0, SW1:gi0/2]\n  - endpoints: [H3:gi0/0, SW1:gi0/3]\n",
    )
    .unwrap()
    .build()
    .unwrap();
    let h1 = lab.endpoint("H1:gi0/0").unwrap();
    let h2 = lab.endpoint("H2:gi0/0").unwrap();
    let h3 = lab.endpoint("H3:gi0/0").unwrap();
    for endpoint in [
        h1,
        h2,
        h3,
        lab.endpoint("SW1:gi0/1").unwrap(),
        lab.endpoint("SW1:gi0/2").unwrap(),
        lab.endpoint("SW1:gi0/3").unwrap(),
    ] {
        enable(&mut lab, endpoint, AdminState::Up);
    }

    lab.transmit(h1, frame(&lab, h1, h2)).unwrap();
    let flooded = lab.run_until(SimTime(2)).unwrap();
    assert_eq!(flooded.len(), 3);
    assert!(flooded.iter().any(
        |event| matches!(event, EventOutcome::FrameReceived { interface, .. } if *interface == h2)
    ));
    assert!(flooded.iter().any(|event| matches!(
        event,
        EventOutcome::FrameDropped {
            interface,
            reason: DropReason::NotForInterface
        } if *interface == h3
    )));

    lab.transmit(h2, frame(&lab, h2, h1)).unwrap();
    let learned = lab.run_until(SimTime(4)).unwrap();
    assert_eq!(learned.len(), 2);
    assert!(learned.iter().any(
        |event| matches!(event, EventOutcome::FrameReceived { interface, .. } if *interface == h1)
    ));

    let mut broadcast = frame(&lab, h1, h2);
    broadcast.destination = MacAddress::BROADCAST;
    lab.transmit(h1, broadcast).unwrap();
    let broadcast = lab.run_until(SimTime(6)).unwrap();
    assert!(broadcast.iter().any(
        |event| matches!(event, EventOutcome::FrameReceived { interface, .. } if *interface == h2)
    ));
    assert!(broadcast.iter().any(
        |event| matches!(event, EventOutcome::FrameReceived { interface, .. } if *interface == h3)
    ));

    lab.run_until(SimTime(300_005)).unwrap();
    lab.transmit(h2, frame(&lab, h2, h1)).unwrap();
    let aged = lab.run_until(SimTime(300_007)).unwrap();
    assert!(aged.iter().any(|event| matches!(
        event,
        EventOutcome::FrameDropped {
            interface,
            reason: DropReason::NotForInterface
        } if *interface == h3
    )));
}

#[test]
fn vlans_isolate_access_ports_and_trunks_carry_tags() {
    let mut lab = Topology::from_yaml(
        "devices:\n  H10A: {type: host, interfaces: [gi0/0]}\n  H10B: {type: host, interfaces: [gi0/0]}\n  H20A: {type: host, interfaces: [gi0/0]}\n  H20B: {type: host, interfaces: [gi0/0]}\n  SW1: {type: switch, interfaces: [gi0/1, gi0/2, gi0/24]}\n  SW2: {type: switch, interfaces: [gi0/1, gi0/2, gi0/24]}\nlinks:\n  - endpoints: [H10A:gi0/0, SW1:gi0/1]\n  - endpoints: [H20A:gi0/0, SW1:gi0/2]\n  - endpoints: [SW1:gi0/24, SW2:gi0/24]\n  - endpoints: [H10B:gi0/0, SW2:gi0/1]\n  - endpoints: [H20B:gi0/0, SW2:gi0/2]\n",
    )
    .unwrap()
    .build()
    .unwrap();
    let h10a = lab.endpoint("H10A:gi0/0").unwrap();
    let h10b = lab.endpoint("H10B:gi0/0").unwrap();
    let h20a = lab.endpoint("H20A:gi0/0").unwrap();
    let h20b = lab.endpoint("H20B:gi0/0").unwrap();
    let sw1 = lab.device_id("SW1").unwrap();
    let sw2 = lab.device_id("SW2").unwrap();
    let sw1_access10 = lab.endpoint("SW1:gi0/1").unwrap();
    let sw1_access20 = lab.endpoint("SW1:gi0/2").unwrap();
    let sw1_trunk = lab.endpoint("SW1:gi0/24").unwrap();
    let sw2_access10 = lab.endpoint("SW2:gi0/1").unwrap();
    let sw2_access20 = lab.endpoint("SW2:gi0/2").unwrap();
    let sw2_trunk = lab.endpoint("SW2:gi0/24").unwrap();
    let vlan10 = VlanId::new(10).unwrap();
    let vlan20 = VlanId::new(20).unwrap();
    for (device, access10, access20, trunk, allowed) in [
        (sw1, sw1_access10, sw1_access20, sw1_trunk, [vlan10, vlan20]),
        (sw2, sw2_access10, sw2_access20, sw2_trunk, [vlan10, vlan10]),
    ] {
        lab.with_device_mut(device, |switch| {
            switch.create_vlan(vlan10).unwrap();
            switch.create_vlan(vlan20).unwrap();
            switch.set_access_vlan(access10.interface, vlan10).unwrap();
            switch.set_access_vlan(access20.interface, vlan20).unwrap();
            switch
                .set_switchport_mode(trunk.interface, SwitchportMode::Trunk)
                .unwrap();
            switch
                .set_trunk_allowed_vlans(trunk.interface, allowed.into_iter().collect())
                .unwrap();
        })
        .unwrap();
    }
    for endpoint in [
        h10a,
        h10b,
        h20a,
        h20b,
        sw1_access10,
        sw1_access20,
        sw1_trunk,
        sw2_access10,
        sw2_access20,
        sw2_trunk,
    ] {
        enable(&mut lab, endpoint, AdminState::Up);
    }

    let mut vlan10_broadcast = frame(&lab, h10a, h10b);
    vlan10_broadcast.destination = MacAddress::BROADCAST;
    lab.transmit(h10a, vlan10_broadcast).unwrap();
    let outcomes = lab.run_until(SimTime(3)).unwrap();
    assert!(outcomes.iter().any(|event| matches!(event,
        EventOutcome::FrameReceived { interface, frame }
            if *interface == sw2_trunk
                && frame.ethertype == EtherType::Dot1Q
                && frame.untagged().unwrap().0 == vlan10
    )));
    assert!(outcomes.iter().any(|event| matches!(event,
        EventOutcome::FrameReceived { interface, frame }
            if *interface == h10b && frame.ethertype != EtherType::Dot1Q
    )));
    assert!(!outcomes.iter().any(|event| matches!(event,
        EventOutcome::FrameReceived { interface, .. } if *interface == h20a || *interface == h20b
    )));

    let mut vlan20_broadcast = frame(&lab, h20a, h20b);
    vlan20_broadcast.destination = MacAddress::BROADCAST;
    lab.transmit(h20a, vlan20_broadcast).unwrap();
    let outcomes = lab.run_until(SimTime(6)).unwrap();
    assert!(outcomes.iter().any(|event| matches!(event,
        EventOutcome::FrameReceived { interface, frame }
            if *interface == sw2_trunk && frame.ethertype == EtherType::Dot1Q
    )));
    assert!(!outcomes.iter().any(|event| matches!(event,
        EventOutcome::FrameReceived { interface, .. } if *interface == h20b
    )));
    let now = lab.now();
    assert!(
        lab.with_device_mut(sw1, |switch| switch.show_mac_address_table(now))
            .unwrap()
            .contains("10")
    );
}

#[test]
fn router_forwards_between_access_vlans() {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/vlan-routing.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let h10 = lab.endpoint("H10:gi0/0").unwrap();
    let h20 = lab.endpoint("H20:gi0/0").unwrap();
    let r10 = lab.endpoint("R1:gi0/0").unwrap();
    let r20 = lab.endpoint("R1:gi0/1").unwrap();
    let s10_host = lab.endpoint("SW1:gi0/1").unwrap();
    let s20_host = lab.endpoint("SW1:gi0/2").unwrap();
    let s10_router = lab.endpoint("SW1:gi0/3").unwrap();
    let s20_router = lab.endpoint("SW1:gi0/4").unwrap();
    let vlan10 = VlanId::new(10).unwrap();
    let vlan20 = VlanId::new(20).unwrap();
    lab.with_device_mut(s10_host.device, |switch| {
        switch.create_vlan(vlan10).unwrap();
        switch.create_vlan(vlan20).unwrap();
        for port in [s10_host, s10_router] {
            switch.set_access_vlan(port.interface, vlan10).unwrap();
        }
        for port in [s20_host, s20_router] {
            switch.set_access_vlan(port.interface, vlan20).unwrap();
        }
    })
    .unwrap();
    for endpoint in [s10_host, s20_host, s10_router, s20_router] {
        enable(&mut lab, endpoint, AdminState::Up);
    }
    for (endpoint, address) in [
        (h10, "192.168.10.10"),
        (h20, "192.168.20.20"),
        (r10, "192.168.10.1"),
        (r20, "192.168.20.1"),
    ] {
        address_prefix(&mut lab, endpoint, address, 24);
    }
    static_route(&mut lab, h10.device, "192.168.20.0", 24, "192.168.10.1");
    static_route(&mut lab, h20.device, "192.168.10.0", 24, "192.168.20.1");

    let result = lab
        .ping(h10.device, "192.168.20.20".parse().unwrap())
        .unwrap();
    assert_eq!(result.received, 5);
    assert!(result.render().contains("!!!!!"));
}

#[test]
fn ospf_forms_neighbors_installs_routes_and_expires_them() {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/three-routers.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let r1 = lab.device_id("R1").unwrap();
    let r2 = lab.device_id("R2").unwrap();
    let r3 = lab.device_id("R3").unwrap();
    for (name, address) in [
        ("R1:gi0/0", "10.0.12.1"),
        ("R2:gi0/0", "10.0.12.2"),
        ("R2:gi0/1", "10.0.23.1"),
        ("R3:gi0/0", "10.0.23.2"),
    ] {
        let endpoint = lab.endpoint(name).unwrap();
        address_prefix(&mut lab, endpoint, address, 30);
    }
    for router in [r1, r2, r3] {
        lab.with_device_mut(router, |device| {
            device.set_ospf_process(1).unwrap();
            device
                .add_ospf_network(OspfNetworkConfig {
                    address: "10.0.0.0".parse().unwrap(),
                    wildcard: "0.0.255.255".parse().unwrap(),
                    area: 0,
                })
                .unwrap();
        })
        .unwrap();
    }
    lab.run_until(SimTime(20_010)).unwrap();
    assert!(
        lab.device(r1)
            .unwrap()
            .show_ip_ospf_neighbor(lab.now())
            .contains("Full")
    );
    assert!(
        lab.device(r1)
            .unwrap()
            .show_ip_ospf_database()
            .contains("10.0.23.2")
    );
    assert!(
        lab.device(r1)
            .unwrap()
            .show_ip_route()
            .contains("O    10.0.23.0/30")
    );
    assert_eq!(
        lab.ping(r1, "10.0.23.2".parse().unwrap()).unwrap().received,
        5
    );

    lab.set_link_state(LinkId(1), LinkState::Down).unwrap();
    lab.run_until(SimTime(61_000)).unwrap();
    assert!(
        !lab.device(r1)
            .unwrap()
            .show_ip_route()
            .contains("O    10.0.23.0/30")
    );
}

#[test]
fn spanning_tree_blocks_a_vlan_loop_and_prevents_duplicate_delivery() {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/stp-triangle.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let h1 = lab.endpoint("H1:gi0/0").unwrap();
    let h2 = lab.endpoint("H2:gi0/0").unwrap();
    let vlan = VlanId::new(10).unwrap();
    for name in ["SW1", "SW2", "SW3"] {
        let device = lab.device_id(name).unwrap();
        let ports: Vec<_> = lab
            .device(device)
            .unwrap()
            .interfaces()
            .keys()
            .copied()
            .collect();
        lab.with_device_mut(device, |switch| {
            switch.create_vlan(vlan).unwrap();
            for port in ports {
                let is_host_port = (name == "SW1" || name == "SW2") && port == InterfaceId(1);
                if is_host_port {
                    switch.set_access_vlan(port, vlan).unwrap();
                } else {
                    switch
                        .set_switchport_mode(port, SwitchportMode::Trunk)
                        .unwrap();
                    switch.set_trunk_allowed_vlans(port, [vlan].into()).unwrap();
                }
            }
        })
        .unwrap();
    }
    let endpoints = [
        h1,
        h2,
        lab.endpoint("SW1:gi0/1").unwrap(),
        lab.endpoint("SW1:gi0/2").unwrap(),
        lab.endpoint("SW1:gi0/3").unwrap(),
        lab.endpoint("SW2:gi0/1").unwrap(),
        lab.endpoint("SW2:gi0/2").unwrap(),
        lab.endpoint("SW2:gi0/3").unwrap(),
        lab.endpoint("SW3:gi0/2").unwrap(),
        lab.endpoint("SW3:gi0/3").unwrap(),
    ];
    for endpoint in endpoints {
        enable(&mut lab, endpoint, AdminState::Up);
    }
    lab.run_until(SimTime(6_000)).unwrap();

    let now = lab.now();
    let states = ["SW1", "SW2", "SW3"]
        .into_iter()
        .map(|name| {
            let id = lab.device_id(name).unwrap();
            lab.with_device_mut(id, |switch| switch.show_spanning_tree(Some(vlan), now))
                .unwrap()
        })
        .collect::<String>();
    assert_eq!(states.matches("Alternate").count(), 1);
    assert!(states.contains("Blocking"));

    let mut broadcast = frame(&lab, h1, h2);
    broadcast.destination = MacAddress::BROADCAST;
    lab.transmit(h1, broadcast).unwrap();
    let outcomes = lab.run_until(SimTime(6_010)).unwrap();
    assert_eq!(
        outcomes
            .iter()
            .filter(|event| matches!(event, EventOutcome::FrameReceived { interface, .. } if *interface == h2))
            .count(),
        1
    );
    assert!(outcomes.len() < 10);

    lab.set_link_state(LinkId(3), LinkState::Down).unwrap();
    lab.run_until(SimTime(32_000)).unwrap();
    let mut broadcast = frame(&lab, h1, h2);
    broadcast.destination = MacAddress::BROADCAST;
    lab.transmit(h1, broadcast).unwrap();
    let reconverged = lab.run_until(SimTime(32_010)).unwrap();
    let reconverged_count =
        reconverged
            .iter()
            .filter(|event| matches!(event, EventOutcome::FrameReceived { interface, .. } if *interface == h2))
            .count();
    let now = lab.now();
    let states = ["SW1", "SW2", "SW3"]
        .into_iter()
        .map(|name| {
            let id = lab.device_id(name).unwrap();
            lab.with_device_mut(id, |switch| switch.show_spanning_tree(Some(vlan), now))
                .unwrap()
        })
        .collect::<String>();
    assert_eq!(reconverged_count, 1, "{states}\n{reconverged:#?}");
}
#[test]
fn topology_validation_and_stable_ids() {
    let lab = Topology::from_yaml(YAML).unwrap().build().unwrap();
    assert_eq!(
        lab.device_names().collect::<Vec<_>>(),
        [("R1", DeviceId(1)), ("R2", DeviceId(2))]
    );
    assert!(!lab.links()[&LinkId(1)].is_active());
    for invalid in [
        "devices: {}".into(),
        YAML.replace("type: router","type: typo"),
        YAML.replace("delay_ms: 1","delay_ms: -1"),
        YAML.replace("delay_ms: 1","typo: 1"),
        YAML.replace("R2:GigabitEthernet0/0","MISSING:GigabitEthernet0/0"),
        YAML.replace("R2:GigabitEthernet0/0","R2:GigabitEthernet9/9"),
        YAML.replace("R2:GigabitEthernet0/0","R1:GigabitEthernet0/0"),
        YAML.replace("      - GigabitEthernet0/1","      - gi0/0"),
        format!("{YAML}\n  - endpoints: ['R1:gi0/0', 'R2:gi0/1']"),
        "devices:\n  R1: {type: router, interfaces: []}\n  R1: {type: host, interfaces: []}".into(),
        "devices:\n  R1: {type: router, interfaces: [Loopback0]}\n  R2: {type: router, interfaces: [gi0/0]}\nlinks:\n  - endpoints: ['R1:lo0', 'R2:gi0/0']".into(),
    ] {assert!(Topology::from_yaml(&invalid).and_then(Topology::build).is_err(),"accepted: {invalid}");}
}
#[test]
fn failed_link_or_identity_changes_do_not_corrupt_lab() {
    let (mut lab, a, b) = setup();
    assert!(lab.connect(a, b, 1).is_err());
    assert_eq!(lab.links().len(), 1);
    let original = lab.device(a.device).unwrap().clone();
    assert!(
        lab.with_device_mut(a.device, |d| *d =
            Device::new(DeviceId(999), "OTHER", DeviceType::Router).unwrap())
            .is_err()
    );
    assert_eq!(lab.device(a.device).unwrap(), &original);
    lab.with_device_mut(a.device, |d| d.set_hostname("EDGE"))
        .unwrap()
        .unwrap();
    assert_eq!(lab.device_id("R1").unwrap(), a.device);
    assert!(lab.endpoint_name(a).starts_with("EDGE:"));
    lab.run_until(SimTime(u64::MAX)).unwrap();
    assert!(lab.transmit(a, frame(&lab, a, b)).is_err());
    assert_eq!(lab.pending_events(), 0);
    assert_eq!(
        lab.device(a.device).unwrap().interfaces()[&a.interface]
            .counters
            .tx_packets,
        0
    );
}

#[test]
fn ping_resolves_arp_then_exchanges_real_icmp_frames() {
    let (mut lab, a, b) = setup();
    address(&mut lab, a, "10.0.0.1");
    address(&mut lab, b, "10.0.0.2");
    lab.set_tracing(true);

    let local = lab.ping(a.device, "10.0.0.1".parse().unwrap()).unwrap();
    assert_eq!(local.received, 5);
    assert_eq!(local.round_trip_ms, [0, 0, 0, 0, 0]);
    assert_eq!(lab.now(), SimTime(0));

    let result = lab.ping(a.device, "10.0.0.2".parse().unwrap()).unwrap();
    assert_eq!(result.received, 5);
    assert_eq!(result.round_trip_ms, [2, 2, 2, 2, 2]);
    assert!(
        result
            .render()
            .contains("!!!!!\nSuccess rate is 100 percent (5/5)")
    );
    assert_eq!(lab.now(), SimTime(12));
    assert!(
        lab.device(a.device)
            .unwrap()
            .show_ip_route()
            .contains("10.0.0.0/24")
    );
    let arp = lab
        .with_device_mut(a.device, |device| device.show_arp(SimTime(12)))
        .unwrap();
    assert!(arp.contains("10.0.0.2"));
    assert_eq!(lab.take_trace().len(), 24);

    let before = lab.device(a.device).unwrap().interfaces()[&a.interface]
        .counters
        .tx_packets;
    let second = lab.ping(a.device, "10.0.0.2".parse().unwrap()).unwrap();
    assert_eq!(second.received, 5);
    assert_eq!(lab.now(), SimTime(22));
    assert_eq!(
        lab.device(a.device).unwrap().interfaces()[&a.interface]
            .counters
            .tx_packets
            - before,
        5
    );
}

#[test]
fn ping_timeout_and_no_route_are_deterministic() {
    let (mut lab, a, b) = setup();
    address(&mut lab, a, "10.0.0.1");
    address(&mut lab, b, "10.0.0.2");

    let no_route = lab.ping(a.device, "192.0.2.1".parse().unwrap());
    assert!(matches!(
        no_route,
        Err(LabError::Ping(PingError::NoRoute(address)))
            if address == "192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()
    ));
    assert_eq!(lab.now(), SimTime(0));

    let timeout = lab.ping(a.device, "10.0.0.99".parse().unwrap()).unwrap();
    assert_eq!(timeout.received, 0);
    assert_eq!(timeout.round_trip_ms, []);
    assert!(
        timeout
            .render()
            .contains(".....\nSuccess rate is 0 percent (0/5)")
    );
    assert_eq!(lab.now(), SimTime(5_000));
    assert_eq!(lab.pending_events(), 0);
    assert_eq!(
        lab.device(a.device).unwrap().interfaces()[&a.interface]
            .counters
            .tx_packets,
        5
    );
}

fn routed_lab() -> (Lab, DeviceId, DeviceId, DeviceId) {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/three-routers.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let r1 = lab.device_id("R1").unwrap();
    let r2 = lab.device_id("R2").unwrap();
    let r3 = lab.device_id("R3").unwrap();
    for (name, address) in [
        ("R1:gi0/0", "10.0.12.1"),
        ("R2:gi0/0", "10.0.12.2"),
        ("R2:gi0/1", "10.0.23.1"),
        ("R3:gi0/0", "10.0.23.2"),
    ] {
        let endpoint = lab.endpoint(name).unwrap();
        address_prefix(&mut lab, endpoint, address, 30);
    }
    static_route(&mut lab, r1, "10.0.23.0", 30, "10.0.12.2");
    static_route(&mut lab, r3, "10.0.12.0", 30, "10.0.23.1");
    (lab, r1, r2, r3)
}

#[test]
fn static_routes_forward_across_multiple_routers() {
    let (mut lab, r1, _, _) = routed_lab();
    let result = lab.ping(r1, "10.0.23.2".parse().unwrap()).unwrap();
    assert_eq!(result.received, 5);
    assert!(result.render().contains("!!!!!"));
    assert_eq!(result.round_trip_ms, [6, 4, 4, 4, 4]);
    assert!(
        lab.device(r1)
            .unwrap()
            .show_ip_route()
            .contains("S    10.0.23.0/30 [1/0] via 10.0.12.2")
    );
}

#[test]
fn layer3_switch_routes_between_routed_ethernet_ports() {
    let mut lab = Topology::from_yaml(
        "devices:\n  R1: {type: router, interfaces: [gi0/0]}\n  CORE: {type: layer3-switch, interfaces: [gi0/0, gi0/1]}\n  R2: {type: router, interfaces: [gi0/0]}\nlinks:\n  - endpoints: [R1:gi0/0, CORE:gi0/0]\n  - endpoints: [CORE:gi0/1, R2:gi0/0]\n",
    )
    .unwrap()
    .build()
    .unwrap();
    let core = lab.device_id("CORE").unwrap();
    let core_ports = [
        lab.endpoint("CORE:gi0/0").unwrap().interface,
        lab.endpoint("CORE:gi0/1").unwrap().interface,
    ];
    lab.with_device_mut(core, |device| {
        for port in core_ports {
            device.disable_switchport(port).unwrap();
        }
    })
    .unwrap();
    for (name, address) in [
        ("R1:gi0/0", "10.0.12.1"),
        ("CORE:gi0/0", "10.0.12.2"),
        ("CORE:gi0/1", "10.0.23.1"),
        ("R2:gi0/0", "10.0.23.2"),
    ] {
        let endpoint = lab.endpoint(name).unwrap();
        address_prefix(&mut lab, endpoint, address, 30);
    }
    let r1 = lab.device_id("R1").unwrap();
    let r2 = lab.device_id("R2").unwrap();
    lab.with_device_mut(core, |device| device.set_ip_routing(true))
        .unwrap()
        .unwrap();
    assert_eq!(
        lab.device(core).unwrap().device_type(),
        DeviceType::Layer3Switch
    );
    static_route(&mut lab, r1, "10.0.23.0", 30, "10.0.12.2");
    static_route(&mut lab, r2, "10.0.12.0", 30, "10.0.23.1");
    assert_eq!(
        lab.ping(r1, "10.0.23.2".parse().unwrap()).unwrap().received,
        5
    );
}

#[test]
fn layer3_switch_svis_route_between_access_vlans() {
    let mut lab = Topology::from_yaml(
        "devices:\n  H10: {type: host, interfaces: [gi0/0]}\n  H20: {type: host, interfaces: [gi0/0]}\n  CORE: {type: layer3-switch, interfaces: [gi0/1, gi0/2]}\nlinks:\n  - endpoints: [H10:gi0/0, CORE:gi0/1]\n  - endpoints: [H20:gi0/0, CORE:gi0/2]\n",
    )
    .unwrap()
    .build()
    .unwrap();
    let h10 = lab.endpoint("H10:gi0/0").unwrap();
    let h20 = lab.endpoint("H20:gi0/0").unwrap();
    let core10 = lab.endpoint("CORE:gi0/1").unwrap();
    let core20 = lab.endpoint("CORE:gi0/2").unwrap();
    let core = core10.device;
    let vlan10 = VlanId::new(10).unwrap();
    let vlan20 = VlanId::new(20).unwrap();
    lab.with_device_mut(core, |device| {
        device.create_vlan(vlan10).unwrap();
        device.create_vlan(vlan20).unwrap();
        device
            .set_switchport_mode(core10.interface, SwitchportMode::Access)
            .unwrap();
        device
            .set_switchport_mode(core20.interface, SwitchportMode::Access)
            .unwrap();
        device.set_access_vlan(core10.interface, vlan10).unwrap();
        device.set_access_vlan(core20.interface, vlan20).unwrap();
        device
            .set_admin_state(core10.interface, AdminState::Up)
            .unwrap();
        device
            .set_admin_state(core20.interface, AdminState::Up)
            .unwrap();
        for (name, address) in [("Vlan10", "192.168.10.1"), ("Vlan20", "192.168.20.1")] {
            let svi = device.ensure_interface(name).unwrap();
            device
                .set_ipv4(
                    svi,
                    Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
                )
                .unwrap();
            device.set_admin_state(svi, AdminState::Up).unwrap();
        }
        device.set_ip_routing(true).unwrap();
    })
    .unwrap();
    address_prefix(&mut lab, h10, "192.168.10.10", 24);
    address_prefix(&mut lab, h20, "192.168.20.20", 24);
    static_route(&mut lab, h10.device, "192.168.20.0", 24, "192.168.10.1");
    static_route(&mut lab, h20.device, "192.168.10.0", 24, "192.168.20.1");

    assert!(
        lab.device(core)
            .unwrap()
            .protocol_up(lab.device(core).unwrap().find_interface("Vlan10").unwrap())
    );
    assert_eq!(
        lab.ping(h10.device, "192.168.20.20".parse().unwrap())
            .unwrap()
            .received,
        5
    );
    enable(&mut lab, core10, AdminState::Down);
    assert!(
        !lab.device(core)
            .unwrap()
            .protocol_up(lab.device(core).unwrap().find_interface("Vlan10").unwrap())
    );
}

#[test]
fn topology_round_trips_explicit_port_media() {
    let lab = Topology::from_yaml(
        "devices:\n  EDGE:\n    type: router\n    interfaces:\n      - {name: gi0/0, media: rj45}\n      - {name: gi0/1, media: sfp}\n      - {name: te0/0, media: sfp+}\n      - {name: se0/0, media: serial}\n      - {name: con0, media: console}\n",
    )
    .unwrap()
    .build()
    .unwrap();
    let edge = lab.device(lab.device_id("EDGE").unwrap()).unwrap();
    assert_eq!(
        edge.interfaces()
            .values()
            .map(|interface| interface.media)
            .collect::<Vec<_>>(),
        [
            InterfaceMedia::Rj45,
            InterfaceMedia::Sfp,
            InterfaceMedia::SfpPlus,
            InterfaceMedia::Serial,
            InterfaceMedia::Console,
        ]
    );
    let restored = Topology::from_yaml(&lab.render_yaml())
        .unwrap()
        .build()
        .unwrap();
    let edge = restored
        .device(restored.device_id("EDGE").unwrap())
        .unwrap();
    assert_eq!(
        edge.interfaces().values().nth(1).unwrap().media,
        InterfaceMedia::Sfp
    );
}

#[test]
fn standard_access_lists_filter_inbound_and_outbound_ipv4() {
    let (mut lab, r1, r2, _) = routed_lab();
    assert_eq!(
        lab.ping(r1, "10.0.23.2".parse().unwrap()).unwrap().received,
        5
    );

    let r2_left = lab.endpoint("R2:gi0/0").unwrap();
    let inbound = AccessListId::new(10).unwrap();
    lab.with_device_mut(r2, |device| {
        device
            .add_access_list_entry(
                inbound,
                StandardAccessListEntry {
                    action: AccessListAction::Deny,
                    source: "10.0.12.1".parse().unwrap(),
                    wildcard: std::net::Ipv4Addr::UNSPECIFIED,
                },
            )
            .and_then(|()| {
                device.add_access_list_entry(
                    inbound,
                    StandardAccessListEntry {
                        action: AccessListAction::Permit,
                        source: std::net::Ipv4Addr::UNSPECIFIED,
                        wildcard: "255.255.255.255".parse().unwrap(),
                    },
                )
            })
            .and_then(|()| {
                device.set_access_group(r2_left.interface, inbound, AccessListDirection::In)
            })
    })
    .unwrap()
    .unwrap();
    assert_eq!(
        lab.ping(r1, "10.0.23.2".parse().unwrap()).unwrap().received,
        0
    );
    assert!(
        lab.device(r2).unwrap().interfaces()[&r2_left.interface]
            .counters
            .drops
            >= 5
    );

    let r2_right = lab.endpoint("R2:gi0/1").unwrap();
    let outbound = AccessListId::new(11).unwrap();
    lab.with_device_mut(r2, |device| {
        device
            .add_access_list_entry(
                outbound,
                StandardAccessListEntry {
                    action: AccessListAction::Permit,
                    source: "192.0.2.1".parse().unwrap(),
                    wildcard: std::net::Ipv4Addr::UNSPECIFIED,
                },
            )
            .and_then(|()| {
                device.set_access_group(r2_right.interface, outbound, AccessListDirection::Out)
            })
    })
    .unwrap()
    .unwrap();
    assert_eq!(
        lab.ping(r2, "10.0.23.2".parse().unwrap()).unwrap().received,
        0
    );
    assert!(
        lab.device(r2).unwrap().interfaces()[&r2_right.interface]
            .counters
            .drops
            >= 5
    );
}

#[test]
fn dhcp_assigns_and_expires_a_usable_address_over_a_switch() {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/dhcp-lan.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let router = lab.endpoint("R1:gi0/0").unwrap();
    let client = lab.endpoint("H1:gi0/0").unwrap();
    let client_two = lab.endpoint("H2:gi0/0").unwrap();
    let switch_router = lab.endpoint("SW1:gi0/1").unwrap();
    let switch_client = lab.endpoint("SW1:gi0/2").unwrap();
    let switch_client_two = lab.endpoint("SW1:gi0/3").unwrap();
    for endpoint in [
        router,
        client,
        client_two,
        switch_router,
        switch_client,
        switch_client_two,
    ] {
        enable(&mut lab, endpoint, AdminState::Up);
    }
    address_prefix(&mut lab, router, "192.168.1.1", 24);
    lab.with_device_mut(router.device, |device| {
        let pool = device.ensure_dhcp_pool("LAN").unwrap();
        device
            .set_dhcp_pool_network(
                pool,
                Ipv4Network::new("192.168.1.0".parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
        device
            .set_dhcp_default_router(pool, "192.168.1.1".parse().unwrap())
            .unwrap();
    })
    .unwrap();
    lab.with_device_mut(client.device, |device| {
        device.set_dhcp_client(client.interface)
    })
    .unwrap()
    .unwrap();
    lab.with_device_mut(client_two.device, |device| {
        device.set_dhcp_client(client_two.interface)
    })
    .unwrap()
    .unwrap();

    lab.run_until(SimTime(20)).unwrap();
    let leased = lab
        .device(client.device)
        .unwrap()
        .interface_ipv4(client.interface)
        .unwrap();
    assert_eq!(
        leased.address(),
        "192.168.1.2".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        lab.device(client_two.device)
            .unwrap()
            .interface_ipv4(client_two.interface)
            .unwrap()
            .address(),
        "192.168.1.3".parse::<std::net::Ipv4Addr>().unwrap()
    );
    let brief = lab.device(client.device).unwrap().show_ip_interface_brief();
    assert!(brief.contains("192.168.1.2"));
    assert!(brief.contains("YES DHCP"));
    assert_eq!(
        lab.device(client.device)
            .unwrap()
            .resolve_route("203.0.113.1".parse().unwrap())
            .unwrap()
            .next_hop,
        "192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()
    );
    let now = lab.now();
    let bindings = lab
        .with_device_mut(router.device, |device| device.show_ip_dhcp_binding(now))
        .unwrap();
    assert!(bindings.contains("192.168.1.2"));
    assert!(bindings.contains("192.168.1.3"));
    assert_eq!(
        lab.ping(client.device, "192.168.1.1".parse().unwrap())
            .unwrap()
            .received,
        5
    );

    lab.run_until(SimTime(3_600_008)).unwrap();
    assert!(
        lab.device(client.device)
            .unwrap()
            .interface_ipv4(client.interface)
            .is_none()
    );
    assert!(
        lab.device(client_two.device)
            .unwrap()
            .interface_ipv4(client_two.interface)
            .is_none()
    );
    lab.run_until(SimTime(3_600_020)).unwrap();
    assert_eq!(
        lab.device(client.device)
            .unwrap()
            .interface_ipv4(client.interface)
            .unwrap()
            .address(),
        "192.168.1.2".parse::<std::net::Ipv4Addr>().unwrap()
    );
    assert_eq!(
        lab.device(client_two.device)
            .unwrap()
            .interface_ipv4(client_two.interface)
            .unwrap()
            .address(),
        "192.168.1.3".parse::<std::net::Ipv4Addr>().unwrap()
    );
}

#[test]
fn nat_overload_translates_and_reverses_icmp_without_an_outside_private_route() {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/nat-overload.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let inside_host = lab.endpoint("H1:gi0/0").unwrap();
    let router_inside = lab.endpoint("R1:gi0/0").unwrap();
    let router_outside = lab.endpoint("R1:gi0/1").unwrap();
    let outside_host = lab.endpoint("H2:gi0/0").unwrap();
    for (endpoint, address) in [
        (inside_host, "10.0.0.2"),
        (router_inside, "10.0.0.1"),
        (router_outside, "203.0.113.1"),
        (outside_host, "203.0.113.2"),
    ] {
        address_prefix(&mut lab, endpoint, address, 24);
    }
    static_route(&mut lab, inside_host.device, "0.0.0.0", 0, "10.0.0.1");
    let acl = AccessListId::new(1).unwrap();
    lab.with_device_mut(router_inside.device, |device| {
        device
            .add_access_list_entry(
                acl,
                StandardAccessListEntry {
                    action: AccessListAction::Permit,
                    source: "10.0.0.0".parse().unwrap(),
                    wildcard: "0.0.0.255".parse().unwrap(),
                },
            )
            .and_then(|()| device.set_nat_role(router_inside.interface, NatRole::Inside))
            .and_then(|()| device.set_nat_role(router_outside.interface, NatRole::Outside))
            .and_then(|()| device.set_nat_overload(acl, router_outside.interface))
    })
    .unwrap()
    .unwrap();

    assert!(
        lab.device(outside_host.device)
            .unwrap()
            .resolve_route("10.0.0.2".parse().unwrap())
            .is_none()
    );
    assert_eq!(
        lab.ping(inside_host.device, "203.0.113.2".parse().unwrap())
            .unwrap()
            .received,
        5
    );
    let now = lab.now();
    let translations = lab
        .with_device_mut(router_inside.device, |device| {
            device.show_ip_nat_translations(now)
        })
        .unwrap();
    assert!(translations.contains("icmp"));
    assert!(translations.contains("203.0.113.1:10000"));
    assert!(translations.contains("10.0.0.2:"));

    lab.run_until(SimTime(now.0 + 60_000)).unwrap();
    let now = lab.now();
    let expired = lab
        .with_device_mut(router_inside.device, |device| {
            device.show_ip_nat_translations(now)
        })
        .unwrap();
    assert!(!expired.contains("10.0.0.2:"));
}

#[test]
fn routers_return_ttl_exceeded_and_destination_unreachable() {
    let (mut lab, r1, r2, _) = routed_lab();
    let expired = lab
        .ping_with_ttl(r1, "10.0.23.2".parse().unwrap(), 1)
        .unwrap();
    assert_eq!(expired.received, 0);
    assert!(expired.render().contains("TTTTT"));

    static_route(&mut lab, r1, "192.0.2.0", 24, "10.0.12.2");
    let unreachable = lab.ping(r1, "192.0.2.1".parse().unwrap()).unwrap();
    assert_eq!(unreachable.received, 0);
    assert!(unreachable.render().contains("UUUUU"));
    assert!(
        lab.device(r2)
            .unwrap()
            .resolve_route("192.0.2.1".parse().unwrap())
            .is_none()
    );
}
