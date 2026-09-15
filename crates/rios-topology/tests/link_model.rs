use rios_config::AdminState;
use rios_device::DropReason;
use rios_ethernet::{EtherType, EthernetFrame, MacAddress};
use rios_simulator::{InterfaceRef, LinkId, LinkState, SimTime};
use rios_topology::{EventOutcome, Lab, LabError, Topology, TraceAction, TraceRecord};

fn setup(seed: u64, options: &str) -> (Lab, InterfaceRef, InterfaceRef) {
    let yaml = format!(
        "seed: {seed}\ndevices:\n  A:\n    type: router\n    interfaces: [gi0/0]\n  B:\n    type: router\n    interfaces: [gi0/0]\nlinks:\n  - endpoints: ['A:gi0/0', 'B:gi0/0']\n{options}"
    );
    let mut lab = Topology::from_yaml(&yaml).unwrap().build().unwrap();
    let a = lab.endpoint("A:gi0/0").unwrap();
    let b = lab.endpoint("B:gi0/0").unwrap();
    for port in [a, b] {
        lab.with_device_mut(port.device, |device| {
            device.set_admin_state(port.interface, AdminState::Up)
        })
        .unwrap()
        .unwrap();
    }
    lab.set_tracing(true);
    (lab, a, b)
}
fn frame(sequence: u8) -> EthernetFrame {
    EthernetFrame {
        source: MacAddress([2, 0, 0, 0, 0, 1]),
        destination: MacAddress::BROADCAST,
        ethertype: EtherType::Other(0x88b5),
        payload: vec![sequence; 1486],
    }
}
#[test]
fn rates_fifo_full_duplex_and_queue_overflow() {
    for (rate, serialization) in [("100mbps", 120), ("1gbps", 12)] {
        let (mut lab, a, b) = setup(0, &format!("    bandwidth: {rate}\n    queue_packets: 2\n"));
        lab.transmit(a, frame(1)).unwrap();
        lab.transmit(a, frame(2)).unwrap();
        assert!(matches!(
            lab.transmit(a, frame(3)),
            Err(LabError::Dropped(DropReason::QueueFull))
        ));
        lab.transmit(b, frame(4)).unwrap();
        let events = lab.run_until(SimTime::from_millis(10)).unwrap();
        let sequence: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                EventOutcome::FrameReceived { frame, .. } => Some(frame.payload[0]),
                _ => None,
            })
            .collect();
        assert_eq!(sequence, [1, 4, 2]);
        let arrivals: Vec<_> = lab
            .take_trace()
            .into_iter()
            .filter(|trace| trace.action == TraceAction::Rx)
            .map(|trace| trace.time.0)
            .collect();
        assert_eq!(
            arrivals,
            [
                1000 + serialization,
                1000 + serialization,
                1000 + serialization * 2
            ]
        );
        let link = &lab.links()[&LinkId(1)];
        assert_eq!(link.a_to_b.counters.queue_drops, 1);
        assert_eq!(link.a_to_b.counters.rx_bytes, 3000);
        assert!(
            lab.device(a.device)
                .unwrap()
                .show_interfaces()
                .contains("1 drops: transmit queue is full")
        );
    }
}
fn impaired(seed: u64) -> Vec<TraceRecord> {
    let (mut lab, a, _) = setup(
        seed,
        "    bandwidth: 100mbps\n    delay_ms: 10\n    jitter_ms: 2\n    loss_percent: 35\n",
    );
    for i in 0..100 {
        lab.transmit(a, frame(i)).unwrap();
    }
    lab.run_until(SimTime::from_millis(100)).unwrap();
    let link = &lab.links()[&LinkId(1)];
    assert!(link.a_to_b.counters.loss_drops > 0);
    assert!(link.a_to_b.counters.loss_drops < 100);
    assert_eq!(
        link.a_to_b.counters.rx_packets + link.a_to_b.counters.loss_drops,
        100
    );
    lab.take_trace()
}
#[test]
fn jitter_loss_and_seed_are_reproducible() {
    assert_eq!(impaired(42), impaired(42));
    assert_ne!(impaired(42), impaired(43));
}
#[test]
fn flap_invalidates_frames_and_releases_reservations() {
    let (mut lab, a, _) = setup(0, "    bandwidth: 1mbps\n    queue_packets: 1\n");
    lab.transmit(a, frame(1)).unwrap();
    lab.set_link_state(LinkId(1), LinkState::Down).unwrap();
    assert!(matches!(
        lab.transmit(a, frame(2)),
        Err(LabError::Dropped(DropReason::LinkDown))
    ));
    lab.set_link_state(LinkId(1), LinkState::Up).unwrap();
    lab.transmit(a, frame(3)).unwrap();
    let events = lab.run_until(SimTime::from_millis(100)).unwrap();
    assert!(matches!(
        events[0],
        EventOutcome::FrameDropped {
            reason: DropReason::LinkChanged,
            ..
        }
    ));
    assert!(
        matches!(&events[1], EventOutcome::FrameReceived { frame, .. } if frame.payload[0] == 3)
    );
}
#[test]
fn policy_roundtrip_and_validation() {
    let (lab, _, _) = setup(
        999,
        "    bandwidth: 100mbps\n    delay_ms: 10\n    jitter_ms: 2\n    loss_percent: 0.1\n    queue_packets: 50\n",
    );
    let restored = Topology::from_yaml(&lab.render_yaml())
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        restored.links()[&LinkId(1)].config,
        lab.links()[&LinkId(1)].config
    );
    for invalid in [
        "loss_percent: 101",
        "loss_percent: -1",
        "queue_packets: 0",
        "bandwidth: 0mbps",
        "delay_ms: 18446744073709551615",
    ] {
        let yaml = lab.render_yaml();
        let index = yaml.find("    delay_ms:").unwrap();
        let yaml = format!("{}    {invalid}\n", &yaml[..index]);
        assert!(
            Topology::from_yaml(&yaml).unwrap().build().is_err(),
            "{invalid}"
        );
    }
}
