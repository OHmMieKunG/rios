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
