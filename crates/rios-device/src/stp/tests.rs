use super::*;
use rios_config::StpPortConfig;
fn switch() -> (Device, InterfaceId, InterfaceId) {
    let mut switch = Device::new(DeviceId(1), "SW", DeviceType::Switch).unwrap();
    let a = switch.add_physical_interface("gi0/1").unwrap();
    let b = switch.add_physical_interface("gi0/2").unwrap();
    for port in [a, b] {
        switch.set_link_state(port, LinkState::Up).unwrap();
    }
    (switch, a, b)
}
fn superior(rapid: bool, flags: u8) -> StpBpdu {
    StpBpdu::new(
        ConfigurationBpdu {
            root_id: 1,
            root_cost: 0,
            bridge_id: 1,
            port_id: 0x8001,
        },
        rapid,
        flags,
    )
}
#[test]
fn classic_timers_and_edge_policy_control_forwarding() {
    let (mut sw, a, b) = switch();
    sw.set_stp_port(
        b,
        StpPortConfig {
            portfast: true,
            ..Default::default()
        },
    )
    .unwrap();
    for (seconds, state) in [
        (0, StpPortState::Listening),
        (15, StpPortState::Learning),
        (30, StpPortState::Forwarding),
    ] {
        sw.refresh_spanning_tree(SimTime(seconds * 1_000_000));
        assert_eq!(sw.stp_port_state(a, VlanId::DEFAULT).unwrap().1, state);
        assert!(sw.stp_forwarding(b, VlanId::DEFAULT));
    }
}
#[test]
fn priorities_cost_and_guards_change_actual_selection() {
    let (mut sw, a, b) = switch();
    assert!(sw.set_stp_priority(VlanId::DEFAULT, 123).is_err());
    sw.set_stp_priority(VlanId::DEFAULT, 24576).unwrap();
    sw.set_stp_port(
        a,
        StpPortConfig {
            cost: Some(99),
            priority: 64,
            root_guard: true,
            ..Default::default()
        },
    )
    .unwrap();
    sw.receive_stp_packet(a, VlanId::DEFAULT, superior(false, 0), SimTime(0));
    assert!(!sw.stp_forwarding(a, VlanId::DEFAULT));
    assert!(
        sw.show_spanning_tree(None, SimTime(0))
            .contains("Root inconsistent")
    );
    assert_eq!(sw.stp_runtime[&VlanId::DEFAULT].root_port, None);
    sw.set_stp_port(
        a,
        StpPortConfig {
            cost: Some(99),
            priority: 64,
            ..Default::default()
        },
    )
    .unwrap();
    sw.receive_stp_packet(a, VlanId::DEFAULT, superior(false, 0), SimTime(1));
    assert_eq!(sw.stp_runtime[&VlanId::DEFAULT].root_cost, 99);
    sw.set_stp_port(
        b,
        StpPortConfig {
            bpdu_guard: true,
            ..Default::default()
        },
    )
    .unwrap();
    sw.receive_stp_packet(b, VlanId::DEFAULT, superior(false, 0), SimTime(2));
    assert!(!sw.protocol_up(b));
    assert!(sw.show_interfaces().contains("err-disabled"));
    sw.set_admin_state(b, AdminState::Down).unwrap();
    sw.set_admin_state(b, AdminState::Up).unwrap();
    assert!(sw.protocol_up(b));
}
#[test]
fn rapid_agreement_opens_root_only_after_other_nonedge_ports_synchronize() {
    let (mut sw, a, b) = switch();
    sw.set_stp_rapid(true).unwrap();
    sw.refresh_spanning_tree(SimTime(0));
    assert!(!sw.stp_forwarding(a, VlanId::DEFAULT));
    sw.receive_stp_packet(
        a,
        VlanId::DEFAULT,
        superior(true, BPDU_PROPOSAL | BPDU_ROLE_DESIGNATED),
        SimTime(1),
    );
    assert!(sw.stp_forwarding(a, VlanId::DEFAULT));
    assert!(!sw.stp_forwarding(b, VlanId::DEFAULT));
    assert!(
        sw.stp_packets(SimTime(1))
            .iter()
            .any(|(port, _, bpdu)| *port == a && bpdu.flags & BPDU_AGREEMENT != 0)
    );
    let mut agreement = superior(true, BPDU_AGREEMENT | BPDU_ROLE_ROOT);
    agreement.configuration.bridge_id = 2;
    agreement.configuration.root_cost = 8;
    sw.receive_stp_packet(b, VlanId::DEFAULT, agreement, SimTime(2));
    assert!(sw.stp_forwarding(b, VlanId::DEFAULT));
}
