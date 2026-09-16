use rios_config::{
    AccessListAction, AccessListDirection, AccessListId, AdminState, NatRole, ServiceConfig,
    StandardAccessListEntry,
};
use rios_device::TcpState;
use rios_ipv4::{IpProtocol, Ipv4InterfaceConfig, Ipv4Network, Ipv4Packet};
use rios_protocol::UdpDatagram;
use rios_simulator::{DeviceId, SimTime};
use rios_topology::{EventOutcome, Lab, Topology};

fn setup(nat: bool) -> (Lab, DeviceId, DeviceId, DeviceId) {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/services.yaml"))
        .unwrap()
        .build()
        .unwrap();
    for (name, address) in [
        ("PC1:gi0/0", "10.0.0.2"),
        ("R1:gi0/0", "10.0.0.1"),
        ("R1:gi0/1", "203.0.113.1"),
        ("WEB1:gi0/0", "203.0.113.2"),
    ] {
        let p = lab.endpoint(name).unwrap();
        lab.with_device_mut(p.device, |d| {
            d.set_admin_state(p.interface, AdminState::Up).unwrap();
            d.set_ipv4(
                p.interface,
                Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
        })
        .unwrap();
    }
    let client = lab.device_id("PC1").unwrap();
    let server = lab.device_id("WEB1").unwrap();
    let router = lab.device_id("R1").unwrap();
    for (device, gateway) in [(client, "10.0.0.1"), (server, "203.0.113.1")] {
        if nat && device == server {
            continue;
        }
        lab.with_device_mut(device, |d| {
            d.set_static_route(
                Ipv4Network::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
                gateway.parse().unwrap(),
            )
        })
        .unwrap();
    }
    if nat {
        lab.with_device_mut(router, |d| {
            let inside = d.ensure_interface("gi0/0").unwrap();
            let outside = d.ensure_interface("gi0/1").unwrap();
            d.set_nat_role(inside, NatRole::Inside).unwrap();
            d.set_nat_role(outside, NatRole::Outside).unwrap();
            d.add_access_list_entry(
                AccessListId::new(1).unwrap(),
                StandardAccessListEntry {
                    action: AccessListAction::Permit,
                    source: "10.0.0.0".parse().unwrap(),
                    wildcard: "0.0.0.255".parse().unwrap(),
                },
            )
            .unwrap();
            d.set_nat_overload(AccessListId::new(1).unwrap(), outside)
                .unwrap();
        })
        .unwrap();
    }
    (lab, client, server, router)
}
#[test]
fn service_inventory_roundtrips_and_invalid_changes_are_atomic() {
    let (mut lab, _, server, _) = setup(false);
    let definitions = vec![
        ServiceConfig::Http {
            port: 8080,
            body: "quoted \"\\\n\t\u{1} λ".into(),
        },
        ServiceConfig::TcpEcho { port: 7 },
        ServiceConfig::UdpEcho { port: 7 },
    ];
    lab.with_device_mut(server, |d| d.set_services(definitions.clone()).unwrap())
        .unwrap();
    let restored = Topology::from_yaml(&lab.render_yaml())
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(restored.device(server).unwrap().services(), &definitions);
    lab.with_device_mut(server, |d| {
        let before = d.clone();
        assert!(
            d.set_services(vec![
                ServiceConfig::Http {
                    port: 7,
                    body: "x".into()
                },
                ServiceConfig::TcpEcho { port: 7 }
            ])
            .is_err()
        );
        assert_eq!(*d, before);
        d.tcp_listen(9999).unwrap();
        let before = d.clone();
        assert!(
            d.set_services(vec![ServiceConfig::TcpEcho { port: 9999 }])
                .is_err()
        );
        assert_eq!(*d, before);
    })
    .unwrap();
}
#[test]
fn udp_echo_crosses_router_and_pat_with_valid_checksum() {
    for nat in [false, true] {
        let (mut lab, client, _, _) = setup(nat);
        lab.udp_send(
            client,
            50000,
            "203.0.113.2".parse().unwrap(),
            7,
            b"simulated echo",
        )
        .unwrap();
        let events = lab.run_until(SimTime::from_millis(50)).unwrap();
        let replies: Vec<_> = events
            .iter()
            .filter_map(|event| {
                let EventOutcome::FrameReceived {
                    interface, frame, ..
                } = event
                else {
                    return None;
                };
                if interface.device != client {
                    return None;
                }
                let ip = Ipv4Packet::decode(&frame.payload).ok()?;
                if ip.protocol != IpProtocol::Udp {
                    return None;
                }
                UdpDatagram::decode_ipv4(ip.source, ip.destination, &ip.payload).ok()
            })
            .collect();
        assert_eq!(
            replies,
            [UdpDatagram {
                source_port: 7,
                destination_port: 50000,
                payload: b"simulated echo".to_vec()
            }]
        );
    }
}
#[test]
fn tcp_echo_and_fragmented_http_use_routed_streams_and_orderly_close() {
    for nat in [false, true] {
        let (mut lab, client, server, _) = setup(nat);
        let echo = lab
            .tcp_connect(client, 50000, "203.0.113.2".parse().unwrap(), 7)
            .unwrap();
        lab.run_until(SimTime::from_millis(50)).unwrap();
        for index in 0..5 {
            let payload = vec![index; 1200];
            lab.tcp_send(client, echo, &payload).unwrap();
            lab.run_until(SimTime::from_millis(100 + u64::from(index) * 50))
                .unwrap();
            assert_eq!(lab.tcp_read(client, echo).unwrap(), payload);
        }
        lab.tcp_close(client, echo).unwrap();
        lab.run_until(SimTime::from_millis(350)).unwrap();
        assert_eq!(
            lab.device(client).unwrap().tcp_connections()[&echo].state,
            TcpState::TimeWait
        );
        let http = lab
            .tcp_connect(client, 50001, "203.0.113.2".parse().unwrap(), 80)
            .unwrap();
        lab.run_until(SimTime::from_millis(400)).unwrap();
        lab.tcp_send(client, http, b"GET / HTTP/1.1\r\nHost: lab\r\n")
            .unwrap();
        lab.run_until(SimTime::from_millis(450)).unwrap();
        assert!(lab.tcp_read(client, http).unwrap().is_empty());
        lab.tcp_send(client, http, b"\r\n").unwrap();
        lab.run_until(SimTime::from_millis(500)).unwrap();
        let response = String::from_utf8(lab.tcp_read(client, http).unwrap()).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("Hello from RIOS!\n"));
        assert_eq!(
            lab.device(client).unwrap().tcp_connections()[&http].state,
            TcpState::CloseWait
        );
        lab.tcp_close(client, http).unwrap();
        lab.run_until(SimTime::from_millis(122000)).unwrap();
        assert!(lab.device(client).unwrap().tcp_connections().is_empty());
        assert!(lab.device(server).unwrap().tcp_connections().is_empty());
    }
}
#[test]
fn router_acl_blocks_service_delivery() {
    let (mut lab, client, server, router) = setup(false);
    lab.with_device_mut(router, |d| {
        d.add_access_list_entry(
            AccessListId::new(10).unwrap(),
            StandardAccessListEntry {
                action: AccessListAction::Deny,
                source: "0.0.0.0".parse().unwrap(),
                wildcard: "255.255.255.255".parse().unwrap(),
            },
        )
        .unwrap();
        let interface = d.ensure_interface("gi0/0").unwrap();
        d.set_access_group(
            interface,
            AccessListId::new(10).unwrap(),
            AccessListDirection::In,
        )
        .unwrap();
    })
    .unwrap();
    let socket = lab
        .tcp_connect(client, 50000, "203.0.113.2".parse().unwrap(), 80)
        .unwrap();
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    assert_eq!(
        lab.device(client).unwrap().tcp_connections()[&socket].state,
        TcpState::SynSent
    );
    assert!(lab.device(server).unwrap().tcp_connections().is_empty());
}

#[test]
fn large_http_response_respects_tcp_backpressure_and_retransmission() {
    let (mut lab, client, server, _) = setup(false);
    let body = "abcdefgh".repeat(4096);
    lab.with_device_mut(server, |d| {
        d.set_services(vec![ServiceConfig::Http {
            port: 80,
            body: body.clone(),
        }])
        .unwrap()
    })
    .unwrap();
    let socket = lab
        .tcp_connect(client, 51000, "203.0.113.2".parse().unwrap(), 80)
        .unwrap();
    lab.run_until(SimTime::from_millis(50)).unwrap();
    lab.tcp_send(client, socket, b"GET / HTTP/1.1\r\nHost: lab\r\n\r\n")
        .unwrap();
    lab.run_until(SimTime::from_millis(52)).unwrap();
    // The server has accepted the request; lose its first response and ACK on the cable.
    lab.set_link_state(rios_simulator::LinkId(2), rios_simulator::LinkState::Down)
        .unwrap();
    lab.set_link_state(rios_simulator::LinkId(2), rios_simulator::LinkState::Up)
        .unwrap();
    lab.run_until(SimTime::from_millis(5000)).unwrap();
    let response = String::from_utf8(lab.tcp_read(client, socket).unwrap()).unwrap();
    let (header, received) = response.split_once("\r\n\r\n").unwrap();
    assert!(header.contains("Content-Length: 32768"));
    assert_eq!(received, body);
    assert!(
        lab.device(server)
            .unwrap()
            .tcp_connections()
            .values()
            .any(|c| c.retransmissions > 0)
    );
}

#[test]
fn application_probes_use_accepted_transport_data_and_release_resources() {
    for nat in [false, true] {
        let (mut lab, client, _, _) = setup(nat);
        let remote = "203.0.113.2".parse().unwrap();
        assert_eq!(
            lab.udp_request(client, remote, 7, b"udp probe", 5000)
                .unwrap(),
            Some(b"udp probe".to_vec())
        );
        assert_eq!(lab.device(client).unwrap().udp_sockets().count(), 0);
        assert_eq!(
            lab.tcp_echo(client, remote, 7, b"tcp probe").unwrap(),
            b"tcp probe"
        );
        let response = lab.http_get(client, remote, 80).unwrap();
        assert!(response.ends_with(b"Hello from RIOS!\n"));
        assert!(lab.http_get(client, remote, 8080).is_err());
        assert!(
            lab.udp_request(client, remote, 9999, b"timeout", 100)
                .unwrap()
                .is_none()
        );
        assert_eq!(lab.device(client).unwrap().udp_sockets().count(), 0);
    }
}

#[test]
fn udp_endpoint_peer_filter_and_queue_bounds_hold() {
    let (mut lab, client, _, _) = setup(false);
    let socket = rios_device::UdpSocket {
        local_address: "10.0.0.2".parse().unwrap(),
        local_port: 52000,
        remote_address: "203.0.113.2".parse().unwrap(),
        remote_port: 7,
    };
    lab.with_device_mut(client, |d| d.udp_open(socket).unwrap())
        .unwrap();
    for index in 0..8 {
        lab.udp_send(client, 52000, socket.remote_address, 7, &[index])
            .unwrap();
    }
    lab.run_until(SimTime::from_millis(50)).unwrap();
    lab.with_device_mut(client, |d| {
        assert_eq!(d.udp_sockets().next().unwrap().1, 4);
        for index in 0..4 {
            assert_eq!(d.udp_read(socket).unwrap(), Some(vec![index]));
        }
        assert_eq!(d.udp_read(socket).unwrap(), None);
        let forged = UdpDatagram {
            source_port: 8,
            destination_port: 52000,
            payload: b"wrong peer".to_vec(),
        };
        d.receive_udp(
            &Ipv4Packet {
                dscp_ecn: 0,
                source: socket.remote_address,
                destination: socket.local_address,
                ttl: 64,
                protocol: IpProtocol::Udp,
                payload: forged
                    .encode_ipv4(socket.remote_address, socket.local_address)
                    .unwrap(),
            },
            SimTime(0),
        );
        assert_eq!(d.udp_read(socket).unwrap(), None);
        for port in 52001..52064 {
            d.udp_open(rios_device::UdpSocket {
                local_port: port,
                ..socket
            })
            .unwrap();
        }
        assert_eq!(
            d.udp_open(rios_device::UdpSocket {
                local_port: 52064,
                ..socket
            }),
            Err(rios_device::UdpError::Capacity)
        );
    })
    .unwrap();
}

#[test]
fn dns_and_ntp_cross_routing_and_pat_with_deterministic_timestamps() {
    for nat in [false, true] {
        let mut outcomes = Vec::new();
        for _ in 0..2 {
            let (mut lab, client, server, _) = setup(nat);
            let remote = "203.0.113.2".parse().unwrap();
            assert_eq!(
                lab.dns_lookup(client, remote, 53, "WWW.LAB.").unwrap(),
                Some(remote)
            );
            assert_eq!(
                lab.dns_lookup(client, remote, 53, "missing.lab").unwrap(),
                None
            );
            let mut query = rios_protocol::DnsMessage::query(400, "www.lab").unwrap();
            query.question.kind = 28;
            let response = lab
                .udp_request(client, remote, 53, &query.encode().unwrap(), 1000)
                .unwrap()
                .unwrap();
            let response = rios_protocol::DnsMessage::decode(&response).unwrap();
            assert_eq!(response.rcode, 0);
            assert!(response.answers.is_empty());
            let before = lab.now();
            let ntp = lab.ntp_query(client, remote, 123).unwrap();
            assert_eq!(
                ntp.origin,
                rios_protocol::NtpTimestamp::from_simulation(1_704_067_200, before.0)
            );
            assert_eq!(
                ntp.receive,
                rios_protocol::NtpTimestamp::from_simulation(1_704_067_200, before.0 + 2000)
            );
            assert_eq!(ntp.receive, ntp.transmit);
            assert_eq!(lab.now().0, before.0 + 4000);
            outcomes.push((ntp, lab.now()));
            let restored = Topology::from_yaml(&lab.render_yaml())
                .unwrap()
                .build()
                .unwrap();
            assert_eq!(
                restored.device(server).unwrap().services(),
                lab.device(server).unwrap().services()
            );
            assert!(
                lab.udp_request(client, remote, 53, &[0xff; 80], 50)
                    .unwrap()
                    .is_none()
            );
            assert!(
                lab.udp_request(client, remote, 123, &[0xff; 48], 50)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }
}

#[test]
fn dns_inventory_rejects_invalid_and_duplicate_canonical_names() {
    let (mut lab, _, server, _) = setup(false);
    lab.with_device_mut(server, |d| {
        let before = d.clone();
        for names in [vec!["bad..name"], vec!["WWW.lab", "www.lab."]] {
            let records = names
                .into_iter()
                .map(|n| (n.to_owned(), "192.0.2.1".parse().unwrap()))
                .collect();
            assert!(
                d.set_services(vec![ServiceConfig::Dns {
                    port: 53,
                    ttl: 300,
                    records
                }])
                .is_err()
            );
            assert_eq!(*d, before);
        }
    })
    .unwrap();
}
