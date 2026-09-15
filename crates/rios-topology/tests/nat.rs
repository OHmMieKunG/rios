use rios_config::{
    AccessListAction, AccessListId, AdminState, NatPool, NatPoolRule, NatRole, NatTransport,
    StandardAccessListEntry, StaticNat,
};
use rios_device::{TcpSocket, TcpState};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::{DeviceId, SimTime};
use rios_topology::{Lab, Topology};
fn setup() -> (Lab, DeviceId, DeviceId, DeviceId) {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/nat-overload.yaml"))
        .unwrap()
        .build()
        .unwrap();
    for (name, address) in [
        ("H1:gi0/0", "10.0.0.2"),
        ("R1:gi0/0", "10.0.0.1"),
        ("R1:gi0/1", "203.0.113.1"),
        ("H2:gi0/0", "203.0.113.2"),
    ] {
        let endpoint = lab.endpoint(name).unwrap();
        lab.with_device_mut(endpoint.device, |device| {
            device
                .set_admin_state(endpoint.interface, AdminState::Up)
                .unwrap();
            device
                .set_ipv4(
                    endpoint.interface,
                    Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
                )
                .unwrap();
        })
        .unwrap();
    }
    let inside = lab.device_id("H1").unwrap();
    let outside = lab.device_id("H2").unwrap();
    let router = lab.device_id("R1").unwrap();
    lab.with_device_mut(inside, |device| {
        device.set_static_route(
            Ipv4Network::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
            "10.0.0.1".parse().unwrap(),
        )
    })
    .unwrap();
    lab.with_device_mut(router, |device| {
        let first = device.ensure_interface("gi0/0").unwrap();
        let second = device.ensure_interface("gi0/1").unwrap();
        device.set_nat_role(first, NatRole::Inside).unwrap();
        device.set_nat_role(second, NatRole::Outside).unwrap();
        device
            .add_access_list_entry(
                AccessListId::new(1).unwrap(),
                StandardAccessListEntry {
                    action: AccessListAction::Permit,
                    source: "10.0.0.0".parse().unwrap(),
                    wildcard: "0.0.0.255".parse().unwrap(),
                },
            )
            .unwrap();
    })
    .unwrap();
    (lab, inside, outside, router)
}
#[test]
fn tcp_pat_connects_without_private_route_on_outside_host() {
    let (mut lab, inside, outside, router) = setup();
    lab.with_device_mut(router, |device| {
        let interface = device.ensure_interface("gi0/1").unwrap();
        device
            .set_nat_overload(AccessListId::new(1).unwrap(), interface)
            .unwrap();
    })
    .unwrap();
    lab.tcp_listen(outside, 80).unwrap();
    let socket = lab
        .tcp_connect(inside, 49152, "203.0.113.2".parse().unwrap(), 80)
        .unwrap();
    lab.run_until(SimTime::from_millis(50)).unwrap();
    assert_eq!(
        lab.device(inside).unwrap().tcp_connections()[&socket].state,
        TcpState::Established
    );
    let peer = *lab
        .device(outside)
        .unwrap()
        .tcp_connections()
        .keys()
        .next()
        .unwrap();
    assert_eq!(peer.remote_address.to_string(), "203.0.113.1");
    assert_eq!(peer.remote_port, 10000);
    lab.tcp_send(inside, socket, b"TCP through PAT").unwrap();
    lab.run_until(SimTime::from_millis(70)).unwrap();
    assert_eq!(lab.tcp_read(outside, peer).unwrap(), b"TCP through PAT");
    lab.tcp_send(outside, peer, b"response").unwrap();
    lab.run_until(SimTime::from_millis(90)).unwrap();
    assert_eq!(lab.tcp_read(inside, socket).unwrap(), b"response");
}
#[test]
fn static_pat_accepts_outside_connection_and_proxy_arps() {
    let (mut lab, inside, outside, router) = setup();
    lab.with_device_mut(router, |device| {
        device
            .add_static_nat(StaticNat::Port {
                protocol: NatTransport::Tcp,
                local: "10.0.0.2".parse().unwrap(),
                local_port: 80,
                global: "203.0.113.10".parse().unwrap(),
                global_port: 8080,
            })
            .unwrap()
    })
    .unwrap();
    lab.tcp_listen(inside, 80).unwrap();
    let socket = lab
        .tcp_connect(outside, 49152, "203.0.113.10".parse().unwrap(), 8080)
        .unwrap();
    lab.run_until(SimTime::from_millis(50)).unwrap();
    assert_eq!(
        lab.device(outside).unwrap().tcp_connections()[&socket].state,
        TcpState::Established
    );
    lab.tcp_send(outside, socket, b"forwarded port").unwrap();
    lab.run_until(SimTime::from_millis(70)).unwrap();
    let peer = TcpSocket {
        local_address: "10.0.0.2".parse().unwrap(),
        local_port: 80,
        remote_address: "203.0.113.2".parse().unwrap(),
        remote_port: 49152,
    };
    assert_eq!(lab.tcp_read(inside, peer).unwrap(), b"forwarded port");
    assert!(lab.device(router).unwrap().nat_statistics().hits >= 4);
}
#[test]
fn static_address_and_pool_nat_route_icmp_and_clear_dynamic_state() {
    for pool in [false, true] {
        let (mut lab, inside, outside, router) = setup();
        lab.with_device_mut(router, |device| {
            if pool {
                device
                    .set_nat_pool(
                        "PUBLIC",
                        NatPool {
                            first: "203.0.113.10".parse().unwrap(),
                            last: "203.0.113.11".parse().unwrap(),
                            prefix_len: 24,
                        },
                    )
                    .unwrap();
                device
                    .set_nat_pool_rule(NatPoolRule {
                        access_list: AccessListId::new(1).unwrap(),
                        pool: "PUBLIC".into(),
                        overload: false,
                    })
                    .unwrap();
            } else {
                device
                    .add_static_nat(StaticNat::Address {
                        local: "10.0.0.2".parse().unwrap(),
                        global: "203.0.113.10".parse().unwrap(),
                    })
                    .unwrap();
            }
        })
        .unwrap();
        assert_eq!(
            lab.ping(inside, "203.0.113.2".parse().unwrap())
                .unwrap()
                .received,
            5
        );
        if !pool {
            assert_eq!(
                lab.ping(outside, "203.0.113.10".parse().unwrap())
                    .unwrap()
                    .received,
                5
            );
        }
        let now = lab.now();
        lab.with_device_mut(router, |device| {
            assert!(
                device
                    .show_ip_nat_translations(now)
                    .contains("203.0.113.10")
            );
            device.clear_nat_translations();
            assert_eq!(
                device
                    .show_ip_nat_translations(now)
                    .contains("203.0.113.10"),
                !pool
            );
        })
        .unwrap();
    }
}

#[test]
fn exhausted_pool_drops_without_leaking_and_expired_address_is_reusable() {
    use rios_device::NatOutcome;
    use rios_ipv4::{IpProtocol, Ipv4Packet};
    use rios_protocol::UdpDatagram;
    let (mut lab, _, _, router) = setup();
    lab.with_device_mut(router, |device| {
        device
            .set_nat_pool(
                "ONE",
                NatPool {
                    first: "203.0.113.10".parse().unwrap(),
                    last: "203.0.113.10".parse().unwrap(),
                    prefix_len: 24,
                },
            )
            .unwrap();
        device
            .set_nat_pool_rule(NatPoolRule {
                access_list: AccessListId::new(1).unwrap(),
                pool: "ONE".into(),
                overload: false,
            })
            .unwrap();
        let inside = device.ensure_interface("gi0/0").unwrap();
        let outside = device.ensure_interface("gi0/1").unwrap();
        let packet = |source: &str| Ipv4Packet {
            source: source.parse().unwrap(),
            destination: "203.0.113.2".parse().unwrap(),
            ttl: 64,
            protocol: IpProtocol::Udp,
            payload: UdpDatagram {
                source_port: 1234,
                destination_port: 53,
                payload: vec![1],
            }
            .encode()
            .unwrap(),
        };
        let mut first = packet("10.0.0.2");
        assert_eq!(
            device.nat_outbound(inside, outside, &mut first, SimTime(0)),
            NatOutcome::Translated
        );
        assert_eq!(
            UdpDatagram::decode(&first.payload).unwrap().source_port,
            1234
        );
        let mut second = packet("10.0.0.3");
        let before = second.clone();
        assert_eq!(
            device.nat_outbound(inside, outside, &mut second, SimTime(1)),
            NatOutcome::Drop
        );
        assert_eq!(second, before);
        assert_eq!(device.nat_statistics().drops, 1);
        assert_eq!(
            device.nat_outbound(inside, outside, &mut second, SimTime::from_millis(60001)),
            NatOutcome::Translated
        );
        assert_eq!(device.nat_statistics().expired, 1);
    })
    .unwrap();
}
