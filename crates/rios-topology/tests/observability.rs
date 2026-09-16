use rios_config::{AdminState, OspfNetworkConfig};
use rios_device::{DebugTopic, PacketProtocol};
use rios_ethernet::{EtherType, EthernetFrame, MacAddress};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::{DeviceId, SimTime};
use rios_topology::{DebugEvent, Lab, Topology};

fn pair() -> (Lab, DeviceId, DeviceId) {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/two-routers.yaml"))
        .unwrap()
        .build()
        .unwrap();
    for (name, address) in [("R1:gi0/0", "10.0.0.1"), ("R2:gi0/0", "10.0.0.2")] {
        let port = lab.endpoint(name).unwrap();
        lab.with_device_mut(port.device, |d| {
            d.set_admin_state(port.interface, AdminState::Up).unwrap();
            d.set_ipv4(
                port.interface,
                Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
        })
        .unwrap();
    }
    let a = lab.device_id("R1").unwrap();
    let b = lab.device_id("R2").unwrap();
    (lab, a, b)
}
#[test]
fn debug_filters_real_packets_and_does_not_change_forwarding_or_timing() {
    let mut observations = Vec::new();
    for enabled in [false, true] {
        let (mut lab, a, b) = pair();
        lab.with_device_mut(a, |d| d.set_debug(DebugTopic::Arp, enabled))
            .unwrap();
        lab.with_device_mut(b, |d| d.set_debug(DebugTopic::Icmp, enabled))
            .unwrap();
        lab.set_tracing(enabled);
        let ping = lab.ping(a, "10.0.0.2".parse().unwrap()).unwrap();
        assert_eq!(ping.received, 5);
        let records = lab.take_debug(a);
        if enabled {
            assert_eq!(records.len(), 2);
            assert!(records.iter().all(|r| matches!(
                r.event,
                DebugEvent::Packet {
                    protocol: PacketProtocol::Arp,
                    ..
                }
            )));
            assert_eq!(lab.take_debug(b).len(), 10);
        } else {
            assert!(records.is_empty());
        }
        observations.push((
            ping,
            lab.now(),
            lab.device(a).unwrap().interfaces().clone(),
            lab.device(a).unwrap().protocol_counters().clone(),
        ));
    }
    assert_eq!(observations[0], observations[1]);
    assert_eq!(observations[0].3[&PacketProtocol::Icmp].transmitted, 5);
}
#[test]
fn state_debug_records_actual_route_and_ospf_changes() {
    let (mut lab, a, b) = pair();
    lab.with_device_mut(a, |d| {
        d.set_debug(DebugTopic::IpRouting, true);
        d.set_debug(DebugTopic::OspfAdjacency, true);
    })
    .unwrap();
    lab.with_device_mut(a, |d| {
        d.set_static_route(
            Ipv4Network::new("192.0.2.0".parse().unwrap(), 24).unwrap(),
            "10.0.0.2".parse().unwrap(),
        )
    })
    .unwrap();
    assert!(lab.take_debug(a).iter().any(|r| matches!(
        r.event,
        DebugEvent::Route {
            installed: true,
            ..
        }
    )));
    for id in [a, b] {
        lab.with_device_mut(id, |d| {
            d.set_ospf_process(1).unwrap();
            d.add_ospf_network(OspfNetworkConfig {
                address: "10.0.0.0".parse().unwrap(),
                wildcard: "0.0.0.255".parse().unwrap(),
                area: 0,
            })
            .unwrap();
        })
        .unwrap();
    }
    lab.run_until(SimTime::from_millis(45000)).unwrap();
    let records = lab.take_debug(a);
    assert!(
        records.iter().any(|r| matches!(
            r.event,
            DebugEvent::OspfAdjacency {
                after: Some(rios_routing::OspfNeighborState::Full),
                ..
            }
        )),
        "{records:?}"
    );
    assert!(lab.device(a).unwrap().protocol_counters()[&PacketProtocol::Ospf].received > 0);
    lab.with_device_mut(a, |d| d.undebug_all()).unwrap();
    lab.take_debug(a);
    lab.run_until(SimTime::from_millis(50000)).unwrap();
    assert!(lab.take_debug(a).is_empty());
}
#[test]
fn debug_and_trace_retention_are_bounded_without_losing_packet_counters() {
    let (mut lab, a, _) = pair();
    lab.with_device_mut(a, |d| d.set_debug(DebugTopic::Packet, true))
        .unwrap();
    lab.set_tracing(true);
    let source = lab.endpoint("R1:gi0/0").unwrap();
    let frame = EthernetFrame {
        source: MacAddress([2, 0, 0, 1, 0, 1]),
        destination: MacAddress::BROADCAST,
        ethertype: EtherType::Other(0x9999),
        payload: vec![0],
    };
    for index in 0..4200 {
        lab.transmit(source, frame.clone()).unwrap();
        lab.run_until(SimTime::from_millis(index + 1)).unwrap();
    }
    assert_eq!(lab.take_trace().len(), 4096);
    assert_eq!(lab.trace_overflow(), 4304);
    assert_eq!(lab.take_debug(a).len(), 4096);
    assert_eq!(lab.debug_overflow(a), 104);
    assert_eq!(
        lab.device(a).unwrap().protocol_counters()[&PacketProtocol::Ethernet].transmitted,
        4200
    );
}
