use rios_config::AdminState;
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_topology::{GradePlan, Lab, Topology};
fn lab() -> Lab {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/services.yaml"))
        .unwrap()
        .build()
        .unwrap();
    for (name, ip) in [
        ("PC1:gi0/0", "10.0.0.2"),
        ("R1:gi0/0", "10.0.0.1"),
        ("R1:gi0/1", "203.0.113.1"),
        ("WEB1:gi0/0", "203.0.113.2"),
    ] {
        let p = lab.endpoint(name).unwrap();
        lab.with_device_mut(p.device, |d| {
            d.set_ipv4(
                p.interface,
                Ipv4InterfaceConfig::new(ip.parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
            d.set_admin_state(p.interface, AdminState::Up).unwrap();
        })
        .unwrap();
    }
    for (name, gateway) in [("PC1", "10.0.0.1"), ("WEB1", "203.0.113.1")] {
        lab.with_device_mut(lab.device_id(name).unwrap(), |d| {
            d.set_static_route(
                Ipv4Network::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
                gateway.parse().unwrap(),
            )
        })
        .unwrap();
    }
    lab
}
#[test]
fn yaml_objectives_grade_configuration_and_real_services_deterministically() {
    let plan =
        GradePlan::from_yaml(include_str!("../../../examples/services-objectives.yaml")).unwrap();
    let mut first = lab();
    let mut second = lab();
    let report = plan.evaluate(&mut first).unwrap();
    assert!(report.success(), "{}", report.render());
    assert_eq!(report.passed, 8);
    assert_eq!(report, plan.evaluate(&mut second).unwrap());
    assert_eq!(first.now(), second.now());
    assert!(report.render().contains("Score: 8/8"));
    let server = first.device(first.device_id("WEB1").unwrap()).unwrap();
    assert!(server.protocol_counters()[&rios_device::PacketProtocol::Tcp].received > 0);
}
#[test]
fn failure_error_and_isolation_are_distinguished_without_short_circuiting() {
    let plan = GradePlan::from_yaml(
        r#"
settle_ms: 0
objectives:
  - interface_address: {device: PC1, interface: gi0/0, address: 10.0.0.99/24}
  - unreachable: {from: MISSING, to: 203.0.113.2}
  - unreachable: {from: PC1, to: 203.0.113.2}
  - reachable: {from: PC1, to: 203.0.113.2}
  - packet_loss: {from: PC1, to: 203.0.113.2, max_percent: 0}
  - latency: {from: PC1, to: 203.0.113.2, max_ms: 10}
"#,
    )
    .unwrap();
    let report = plan.evaluate(&mut lab()).unwrap();
    assert_eq!(report.passed, 3, "{}", report.render());
    assert!(!report.results[0].error);
    assert!(report.results[1].error && !report.results[1].passed);
    assert!(!report.results[2].error && !report.results[2].passed);
    assert!(report.results[3].passed);
}
#[test]
fn invalid_objective_documents_are_rejected() {
    for yaml in [
        "objectives: []",
        "objectives: [{unreachable: {from: PC1, to: typo}}]",
        "objectives: [{interface_address: {device: R1, interface: gi0/0, address: 10.0.0.1/33}}]",
        "objectives: [{packet_loss: {from: PC1, to: 10.0.0.1, max_percent: 101}}]",
        "objectives: [{reachable: {from: PC1, to: 10.0.0.1, fake: true}}]",
        "objectives: [{http: {from: PC1, to: 10.0.0.1, port: 0}}]",
    ] {
        assert!(GradePlan::from_yaml(yaml).is_err(), "accepted {yaml}");
    }
}

#[test]
fn vlan_and_stp_objectives_inspect_vlan_scoped_state() {
    let mut lab = Topology::from_yaml("devices:\n  SW: {type: switch, interfaces: [gi0/1]}\n  PC: {type: host, interfaces: [gi0/0]}\nlinks:\n - endpoints: [SW:gi0/1, PC:gi0/0]\n").unwrap().build().unwrap();
    for endpoint in ["SW:gi0/1", "PC:gi0/0"] {
        let p = lab.endpoint(endpoint).unwrap();
        lab.with_device_mut(p.device, |d| {
            d.set_admin_state(p.interface, AdminState::Up).unwrap()
        })
        .unwrap();
    }
    let port = lab.endpoint("SW:gi0/1").unwrap();
    lab.with_device_mut(port.device, |d| {
        d.create_vlan(rios_config::VlanId::new(20).unwrap())
            .unwrap();
        d.set_access_vlan(port.interface, rios_config::VlanId::new(20).unwrap())
            .unwrap();
    })
    .unwrap();
    let report = GradePlan::from_yaml("settle_ms: 31000\nobjectives:\n - vlan_membership: {device: SW, interface: gi0/1, vlan: 20}\n - vlan_membership: {device: SW, interface: gi0/1, vlan: 1}\n - stp_state: {device: SW, interface: gi0/1, vlan: 20, state: forwarding}\n").unwrap().evaluate(&mut lab).unwrap();
    assert_eq!(report.passed, 2, "{}", report.render());
    assert!(!report.results[1].passed);
}

#[test]
fn ping_grading_never_counts_a_reply_rejected_by_the_source_inbound_acl() {
    let mut lab = lab();
    let server = lab.endpoint("WEB1:gi0/0").unwrap();
    // R1 probes WEB1, but its returning ICMP is rejected on the source router's ingress.
    let router = lab.endpoint("R1:gi0/1").unwrap();
    lab.with_device_mut(router.device, |d| {
        let acl = rios_config::AccessListId::new(10).unwrap();
        d.add_access_list_entry(
            acl,
            rios_config::StandardAccessListEntry {
                action: rios_config::AccessListAction::Deny,
                source: "203.0.113.2".parse().unwrap(),
                wildcard: "0.0.0.0".parse().unwrap(),
            },
        )
        .unwrap();
        d.set_access_group(router.interface, acl, rios_config::AccessListDirection::In)
            .unwrap();
    })
    .unwrap();
    let report = GradePlan::from_yaml("settle_ms: 0\nobjectives:\n - reachable: {from: R1, to: 203.0.113.2}\n - unreachable: {from: R1, to: 203.0.113.2}\n").unwrap().evaluate(&mut lab).unwrap();
    assert!(!report.results[0].passed, "{}", report.render());
    assert!(report.results[1].passed);
    assert_eq!(
        lab.device(server.device).unwrap().protocol_counters()[&rios_device::PacketProtocol::Icmp]
            .transmitted,
        10
    );
    assert_eq!(
        lab.device(router.device).unwrap().interfaces()[&router.interface]
            .counters
            .drop_reasons[&rios_device::DropReason::AccessList],
        10
    );
}
