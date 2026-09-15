use rios_config::AdminState;
use rios_ethernet::{EtherType, EthernetFrame};
use rios_ipv4::{IpProtocol, Ipv4InterfaceConfig, Ipv4Packet};
use rios_simulator::SimTime;
use rios_topology::{EventOutcome, Lab, Topology};

fn address(lab: &mut Lab, endpoint: &str, address: &str) {
    let port = lab.endpoint(endpoint).unwrap();
    lab.with_device_mut(port.device, |d| {
        d.set_ipv4(
            port.interface,
            Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
        )
        .unwrap();
        d.set_admin_state(port.interface, AdminState::Up).unwrap();
    })
    .unwrap();
}
#[test]
fn routed_packets_preserve_dscp_and_ecn_while_decrementing_ttl() {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/three-routers.yaml"))
        .unwrap()
        .build()
        .unwrap();
    for (ep, ip) in [
        ("R1:gi0/0", "10.0.12.1"),
        ("R2:gi0/0", "10.0.12.2"),
        ("R2:gi0/1", "10.0.23.2"),
        ("R3:gi0/0", "10.0.23.3"),
    ] {
        address(&mut lab, ep, ip);
    }
    let source = lab.endpoint("R1:gi0/0").unwrap();
    let next = lab.endpoint("R2:gi0/0").unwrap();
    let target = lab.endpoint("R3:gi0/0").unwrap();
    let frame = EthernetFrame {
        source: lab.device(source.device).unwrap().interfaces()[&source.interface].mac_address,
        destination: lab.device(next.device).unwrap().interfaces()[&next.interface].mac_address,
        ethertype: EtherType::Ipv4,
        payload: Ipv4Packet {
            dscp_ecn: (46 << 2) | 3,
            source: "10.0.12.1".parse().unwrap(),
            destination: "10.0.23.3".parse().unwrap(),
            ttl: 9,
            protocol: IpProtocol::Other(253),
            payload: b"expedited forwarding".to_vec(),
        }
        .encode()
        .unwrap(),
    };
    lab.transmit(source, frame).unwrap();
    let events = lab.run_until(SimTime::from_millis(100)).unwrap();
    let packet = events
        .iter()
        .find_map(|event| {
            let EventOutcome::FrameReceived { interface, frame } = event else {
                return None;
            };
            if *interface != target || frame.ethertype != EtherType::Ipv4 {
                return None;
            }
            Ipv4Packet::decode(&frame.payload).ok()
        })
        .unwrap();
    assert_eq!(packet.dscp(), 46);
    assert_eq!(packet.dscp_ecn & 3, 3);
    assert_eq!(packet.precedence(), 5);
    assert_eq!(packet.ttl, 8);
}

fn pair(rate: &str, capacity: usize) -> Lab {
    let mut lab = Topology::from_yaml(&format!("devices:\n  R1: {{type: router, interfaces: [gi0/0]}}\n  R2: {{type: router, interfaces: [gi0/0]}}\nlinks:\n - endpoints: [R1:gi0/0, R2:gi0/0]\n   bandwidth: {rate}\n   delay_ms: 0\n   queue_packets: {capacity}\n")).unwrap().build().unwrap();
    address(&mut lab, "R1:gi0/0", "10.0.0.1");
    address(&mut lab, "R2:gi0/0", "10.0.0.2");
    lab
}
fn frame(lab: &Lab, marker: u8, dscp: u8) -> EthernetFrame {
    let a = lab.endpoint("R1:gi0/0").unwrap();
    let b = lab.endpoint("R2:gi0/0").unwrap();
    EthernetFrame {
        source: lab.device(a.device).unwrap().interfaces()[&a.interface].mac_address,
        destination: lab.device(b.device).unwrap().interfaces()[&b.interface].mac_address,
        ethertype: EtherType::Ipv4,
        payload: Ipv4Packet {
            dscp_ecn: dscp << 2,
            source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            ttl: 64,
            protocol: IpProtocol::Other(253),
            payload: vec![marker; 66],
        }
        .encode()
        .unwrap(),
    }
}
fn policy(
    lab: &mut Lab,
    priority: bool,
    edit_default: impl FnOnce(&mut rios_config::QosPolicyClass),
) -> rios_config::QosPolicyId {
    let port = lab.endpoint("R1:gi0/0").unwrap();
    lab.with_device_mut(port.device, |d| {
        let id = d.ensure_qos_policy("WAN").unwrap();
        if priority {
            let class = d.ensure_qos_class("VOICE", false).unwrap();
            let mut criteria = d.running_config().qos.classes[&class].clone();
            criteria.dscp.insert(46);
            d.set_qos_class(class, criteria).unwrap();
            d.ensure_qos_policy_class(id, "VOICE").unwrap();
            let rule = rios_config::QosPolicyClass {
                class: Some(class),
                priority: Some(rios_config::QosRate {
                    bits_per_second: 8000,
                    burst_bytes: Some(1000),
                }),
                ..Default::default()
            };
            d.set_qos_policy_class(id, rule).unwrap();
        }
        let mut default = rios_config::QosPolicyClass::default();
        edit_default(&mut default);
        d.set_qos_policy_class(id, default).unwrap();
        d.set_service_policy_output(port.interface, Some(id))
            .unwrap();
        id
    })
    .unwrap()
}
fn send(lab: &mut Lab, marker: u8, dscp: u8) -> Result<(), rios_topology::LabError> {
    let source = lab.endpoint("R1:gi0/0").unwrap();
    lab.transmit(source, frame(lab, marker, dscp))
}
fn arrivals(lab: &mut Lab, end: SimTime) -> Vec<(SimTime, u8)> {
    let target = lab.endpoint("R2:gi0/0").unwrap();
    let mut arrivals = Vec::new();
    while lab.now() < end {
        if let Some(EventOutcome::FrameReceived { interface, frame }) = lab.step().unwrap()
            && interface == target
            && frame.ethertype == EtherType::Ipv4
        {
            let ip = Ipv4Packet::decode(&frame.payload).unwrap();
            if ip.protocol == IpProtocol::Other(253) {
                arrivals.push((lab.now(), ip.payload[0]));
            }
        }
        if lab.pending_events() == 0 {
            break;
        }
    }
    arrivals
}
#[test]
fn real_link_serialization_is_nonpreemptive_but_priority_overtakes_waiting_bulk() {
    let mut lab = pair("8kbps", 10);
    policy(&mut lab, true, |_| {});
    for (marker, dscp) in [(0, 0), (1, 0), (2, 0), (3, 46)] {
        send(&mut lab, marker, dscp).unwrap();
    }
    assert_eq!(
        arrivals(&mut lab, SimTime::from_millis(500)),
        vec![
            (SimTime(100_000), 0),
            (SimTime(200_000), 3),
            (SimTime(300_000), 1),
            (SimTime(400_000), 2)
        ]
    );
    let id = lab.device_id("R1").unwrap();
    assert!(
        lab.show_policy_map_interface(id)
            .unwrap()
            .contains("1 packets, 100 bytes; 1 dequeued, 0 queued")
    );
    assert_eq!(
        lab.device(id)
            .unwrap()
            .interfaces()
            .values()
            .next()
            .unwrap()
            .counters
            .tx_packets,
        4
    );
}
#[test]
fn shaping_changes_delivery_time_and_policing_drops_real_frames() {
    let mut shaped = pair("80kbps", 10);
    policy(&mut shaped, false, |c| {
        c.shape = Some(rios_config::QosRate {
            bits_per_second: 8000,
            burst_bytes: Some(100),
        })
    });
    for marker in 0..3 {
        send(&mut shaped, marker, 0).unwrap();
    }
    assert_eq!(
        arrivals(&mut shaped, SimTime::from_millis(300)),
        vec![
            (SimTime(10_000), 0),
            (SimTime(110_000), 1),
            (SimTime(210_000), 2)
        ]
    );
    let mut policed = pair("80kbps", 10);
    policy(&mut policed, false, |c| {
        c.police = Some(rios_config::QosRate {
            bits_per_second: 8000,
            burst_bytes: Some(100),
        })
    });
    send(&mut policed, 0, 0).unwrap();
    assert!(matches!(
        send(&mut policed, 1, 0),
        Err(rios_topology::LabError::Dropped(
            rios_device::DropReason::QosPoliced
        ))
    ));
    assert_eq!(
        arrivals(&mut policed, SimTime::from_millis(50)),
        vec![(SimTime(10_000), 0)]
    );
    policed.run_until(SimTime::from_millis(100)).unwrap();
    send(&mut policed, 2, 0).unwrap();
    assert_eq!(
        arrivals(&mut policed, SimTime::from_millis(150)),
        vec![(SimTime(110_000), 2)]
    );
}
#[test]
fn qos_queue_bound_counts_inflight_and_link_flaps_clear_waiting_frames() {
    let mut lab = pair("8kbps", 2);
    policy(&mut lab, false, |_| {});
    send(&mut lab, 0, 0).unwrap();
    send(&mut lab, 1, 0).unwrap();
    assert!(matches!(
        send(&mut lab, 2, 0),
        Err(rios_topology::LabError::Dropped(
            rios_device::DropReason::QueueFull
        ))
    ));
    assert_eq!(
        lab.links()
            .values()
            .next()
            .unwrap()
            .a_to_b
            .counters
            .queue_drops,
        1
    );
    let source = lab.endpoint("R1:gi0/0").unwrap();
    assert_eq!(lab.qos_statistics(source.device)[0].classes[0].1, 1);
    lab.set_link_state(rios_simulator::LinkId(1), rios_simulator::LinkState::Down)
        .unwrap();
    lab.set_link_state(rios_simulator::LinkId(1), rios_simulator::LinkState::Up)
        .unwrap();
    assert!(lab.qos_statistics(source.device).is_empty());
    assert!(arrivals(&mut lab, SimTime::from_millis(300)).is_empty());
    assert_eq!(
        lab.device(source.device).unwrap().interfaces()[&source.interface]
            .counters
            .drop_reasons[&rios_device::DropReason::LinkChanged],
        1
    );
}

#[test]
fn bandwidth_allocation_changes_real_link_throughput() {
    let mut lab = pair("80kbps", 300);
    let id = policy(&mut lab, true, |_| {});
    let source = lab.endpoint("R1:gi0/0").unwrap();
    lab.with_device_mut(source.device, |d| {
        let mut rule = d.running_config().qos.policies[&id].classes[0].clone();
        rule.priority = None;
        rule.bandwidth_kbps = Some(60);
        d.set_qos_policy_class(id, rule).unwrap();
    })
    .unwrap();
    for _ in 0..100 {
        send(&mut lab, 0, 0).unwrap();
        send(&mut lab, 1, 46).unwrap();
    }
    let events = lab.run_until(SimTime::from_millis(810)).unwrap();
    let mut bytes = [0, 0];
    let mut received = 0;
    for e in events {
        if let EventOutcome::FrameReceived { frame, .. } = e
            && frame.ethertype == EtherType::Ipv4
        {
            let ip = Ipv4Packet::decode(&frame.payload).unwrap();
            if ip.protocol == IpProtocol::Other(253) {
                received += 1;
                // The first packet started on an idle link before either class was backlogged.
                if received == 1 {
                    continue;
                }
                bytes[usize::from(ip.payload[0])] += frame.len();
            }
        }
    }
    assert_eq!(received, 81);
    assert_eq!(bytes, [2000, 6000]);
}
#[test]
fn policy_edits_drop_waiting_frames_and_capture_does_not_change_scheduling() {
    fn run(capture: bool) -> (Vec<EventOutcome>, Vec<EventOutcome>) {
        let mut lab = pair("80kbps", 10);
        let id = policy(&mut lab, false, |c| {
            c.shape = Some(rios_config::QosRate {
                bits_per_second: 8000,
                burst_bytes: Some(100),
            })
        });
        let path = std::env::temp_dir().join(format!("rios-qos-{}.pcapng", std::process::id()));
        if capture {
            lab.start_capture(&path, rios_topology::CaptureFilter::All)
                .unwrap();
        }
        for marker in 0..3 {
            send(&mut lab, marker, 0).unwrap();
        }
        let first = lab.run_until(SimTime::from_millis(1)).unwrap();
        let source = lab.endpoint("R1:gi0/0").unwrap();
        lab.with_device_mut(source.device, |d| {
            d.set_qos_policy_class(id, rios_config::QosPolicyClass::default())
                .unwrap()
        })
        .unwrap();
        send(&mut lab, 3, 0).unwrap();
        let events = lab.run_until(SimTime::from_millis(300)).unwrap();
        assert_eq!(
            lab.device(source.device).unwrap().interfaces()[&source.interface]
                .counters
                .drop_reasons[&rios_device::DropReason::QosPolicyChanged],
            2
        );
        let markers: Vec<_> = events
            .iter()
            .filter_map(|e| {
                let EventOutcome::FrameReceived { frame, .. } = e else {
                    return None;
                };
                let ip = Ipv4Packet::decode(&frame.payload).ok()?;
                (ip.protocol == IpProtocol::Other(253)).then_some(ip.payload[0])
            })
            .collect();
        assert_eq!(markers, [0, 3]);
        if capture {
            lab.stop_capture().unwrap();
            std::fs::remove_file(path).unwrap();
        }
        (first, events)
    }
    assert_eq!(run(false), run(true));
}
#[test]
fn queued_switch_frames_cannot_escape_after_stp_returns_to_blocking() {
    let mut lab = Topology::from_yaml("devices:\n  R1: {type: switch, interfaces: [gi0/0]}\n  R2: {type: router, interfaces: [gi0/0]}\nlinks:\n - endpoints: [R1:gi0/0, R2:gi0/0]\n   bandwidth: 80kbps\n   delay_ms: 0\n").unwrap().build().unwrap();
    let source = lab.endpoint("R1:gi0/0").unwrap();
    lab.with_device_mut(source.device, |d| {
        d.set_admin_state(source.interface, AdminState::Up).unwrap()
    })
    .unwrap();
    address(&mut lab, "R2:gi0/0", "10.0.0.2");
    lab.run_until(SimTime::from_millis(31_000)).unwrap();
    assert!(
        lab.device(source.device)
            .unwrap()
            .stp_forwarding(source.interface, rios_config::VlanId::new(1).unwrap())
    );
    lab.with_device_mut(source.device, |d| {
        let class = d.ensure_qos_class("DATA", true).unwrap();
        let mut criteria = d.running_config().qos.classes[&class].clone();
        criteria.dscp.insert(0);
        d.set_qos_class(class, criteria).unwrap();
        let id = d.ensure_qos_policy("OUT").unwrap();
        d.ensure_qos_policy_class(id, "DATA").unwrap();
        d.set_qos_policy_class(
            id,
            rios_config::QosPolicyClass {
                class: Some(class),
                shape: Some(rios_config::QosRate {
                    bits_per_second: 8000,
                    burst_bytes: Some(100),
                }),
                ..Default::default()
            },
        )
        .unwrap();
        d.set_service_policy_output(source.interface, Some(id))
            .unwrap();
    })
    .unwrap();
    for marker in 0..3 {
        send(&mut lab, marker, 0).unwrap();
    }
    lab.with_device_mut(source.device, |d| d.set_stp_rapid(false).unwrap())
        .unwrap();
    // A user packet addressed to a reserved bridge MAC is still user traffic.
    let mut forged = frame(&lab, 4, 0);
    forged.destination = rios_ethernet::MacAddress(rios_switching::STP_MULTICAST);
    lab.transmit(source, forged).unwrap();
    let events = lab.run_until(SimTime::from_millis(32_000)).unwrap();
    let markers: Vec<_> = events
        .iter()
        .filter_map(|e| {
            let EventOutcome::FrameReceived { frame, .. } = e else {
                return None;
            };
            let ip = Ipv4Packet::decode(&frame.payload).ok()?;
            (ip.protocol == IpProtocol::Other(253)).then_some(ip.payload[0])
        })
        .collect();
    assert_eq!(markers, [0]);
    assert_eq!(
        lab.device(source.device).unwrap().interfaces()[&source.interface]
            .counters
            .drop_reasons[&rios_device::DropReason::StpBlocking],
        3
    );
}

#[test]
fn repeated_bulk_service_does_not_accumulate_stale_shaping_timers() {
    let mut lab = pair("80kbps", 10);
    let id = policy(&mut lab, true, |c| {
        c.shape = Some(rios_config::QosRate {
            bits_per_second: 1,
            burst_bytes: Some(100),
        })
    });
    let source = lab.endpoint("R1:gi0/0").unwrap();
    lab.with_device_mut(source.device, |d| {
        let mut class = d.running_config().qos.policies[&id].classes[0].clone();
        class.priority = None;
        d.set_qos_policy_class(id, class).unwrap();
    })
    .unwrap();
    send(&mut lab, 0, 0).unwrap();
    send(&mut lab, 1, 0).unwrap();
    lab.run_until(SimTime::from_millis(10)).unwrap();
    for _ in 0..100 {
        send(&mut lab, 2, 46).unwrap();
        send(&mut lab, 3, 46).unwrap();
        lab.run_until(SimTime(lab.now().0 + 20_000)).unwrap();
        assert!(
            lab.pending_events() <= 2,
            "obsolete shaper deadlines must not accumulate"
        );
    }
    assert_eq!(lab.qos_statistics(source.device)[0].classes[1].1, 1);
}
