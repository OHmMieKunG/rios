use rios_config::AdminState;
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::SimTime;
use rios_topology::{Lab, Topology};

fn relay_lab() -> Lab {
    let mut lab = Topology::from_yaml(
        r#"
devices:
  PC: {type: host, interfaces: [GigabitEthernet0/0]}
  R1: {type: router, interfaces: [GigabitEthernet0/0, GigabitEthernet0/1]}
  R2: {type: router, interfaces: [GigabitEthernet0/0, GigabitEthernet0/1]}
  SERVER: {type: router, interfaces: [GigabitEthernet0/0]}
links:
  - endpoints: ["PC:GigabitEthernet0/0", "R1:GigabitEthernet0/0"]
  - endpoints: ["R1:GigabitEthernet0/1", "R2:GigabitEthernet0/0"]
  - endpoints: ["R2:GigabitEthernet0/1", "SERVER:GigabitEthernet0/0"]
"#,
    )
    .unwrap()
    .build()
    .unwrap();
    for (endpoint, address) in [
        ("R1:gi0/0", "10.10.0.1"),
        ("R1:gi0/1", "10.12.0.1"),
        ("R2:gi0/0", "10.12.0.2"),
        ("R2:gi0/1", "10.100.0.1"),
        ("SERVER:gi0/0", "10.100.0.10"),
    ] {
        let endpoint = lab.endpoint(endpoint).unwrap();
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
    for (name, gateway) in [
        ("R1", "10.12.0.2"),
        ("R2", "10.12.0.1"),
        ("SERVER", "10.100.0.1"),
    ] {
        lab.with_device_mut(lab.device_id(name).unwrap(), |device| {
            device.set_static_route(
                Ipv4Network::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
                gateway.parse().unwrap(),
            );
        })
        .unwrap();
    }
    let relay = lab.endpoint("R1:gi0/0").unwrap();
    lab.with_device_mut(relay.device, |device| {
        device
            .set_dhcp_helper(relay.interface, "10.100.0.10".parse().unwrap())
            .unwrap()
    })
    .unwrap();
    let server = lab.device_id("SERVER").unwrap();
    lab.with_device_mut(server, |device| {
        let pool = device.ensure_dhcp_pool("CLIENTS").unwrap();
        device
            .set_dhcp_pool_network(
                pool,
                Ipv4Network::new("10.10.0.0".parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
        device
            .set_dhcp_default_router(pool, "10.10.0.1".parse().unwrap())
            .unwrap();
        device
            .exclude_dhcp_addresses("10.10.0.1".parse().unwrap(), "10.10.0.19".parse().unwrap())
            .unwrap();
        let mut config = device.running_config().dhcp_pools[&pool].clone();
        config.lease_seconds = 60;
        config.dns_servers = vec!["10.100.0.10".parse().unwrap()];
        config.domain_name = Some("lab.test".into());
        device.update_dhcp_pool(pool, config).unwrap();
    })
    .unwrap();
    let client = lab.endpoint("PC:gi0/0").unwrap();
    lab.with_device_mut(client.device, |device| {
        device
            .set_admin_state(client.interface, AdminState::Up)
            .unwrap();
        device.set_dhcp_client(client.interface).unwrap();
    })
    .unwrap();
    lab
}

#[test]
fn relay_crosses_transit_router_and_renews_without_losing_address() {
    let mut lab = relay_lab();
    let client = lab.endpoint("PC:gi0/0").unwrap();
    lab.run_until(SimTime::from_millis(500)).unwrap();
    let lease = lab
        .device(client.device)
        .unwrap()
        .dhcp_lease(client.interface)
        .unwrap()
        .clone();
    assert_eq!(lease.address.to_string(), "10.10.0.20");
    assert_eq!(lease.domain_name.as_deref(), Some("lab.test"));
    assert_eq!(lease.dns_servers[0].to_string(), "10.100.0.10");
    assert_eq!(
        lab.ping(client.device, "10.100.0.10".parse().unwrap())
            .unwrap()
            .received,
        5
    );
    lab.run_until(SimTime::from_millis(65_000)).unwrap();
    let renewed = lab
        .device(client.device)
        .unwrap()
        .dhcp_lease(client.interface)
        .unwrap();
    assert_eq!(renewed.address, lease.address);
    assert!(renewed.expires_at > lease.expires_at);
}

#[test]
fn relay_client_expires_when_server_unavailable() {
    let mut lab = relay_lab();
    let client = lab.endpoint("PC:gi0/0").unwrap();
    lab.run_until(SimTime::from_millis(500)).unwrap();
    let server = lab.endpoint("SERVER:gi0/0").unwrap();
    lab.with_device_mut(server.device, |device| {
        device
            .set_admin_state(server.interface, AdminState::Down)
            .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(61_000)).unwrap();
    assert!(
        lab.device(client.device)
            .unwrap()
            .dhcp_lease(client.interface)
            .is_none()
    );
}

#[test]
fn rebinding_broadcast_uses_relay_after_unicast_renewal_fails() {
    use rios_ipv4::Ipv4Packet;
    use rios_protocol::{DhcpMessage, DhcpMessageType, UdpDatagram};
    use rios_topology::EventOutcome;
    let mut lab = relay_lab();
    let client = lab.endpoint("PC:gi0/0").unwrap();
    lab.run_until(SimTime::from_millis(500)).unwrap();
    let lease = lab
        .device(client.device)
        .unwrap()
        .dhcp_lease(client.interface)
        .unwrap()
        .clone();
    let server = lab.endpoint("SERVER:gi0/0").unwrap();
    lab.with_device_mut(server.device, |device| {
        device
            .set_admin_state(server.interface, AdminState::Down)
            .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime(lease.rebind_at.0 - 1)).unwrap();
    lab.with_device_mut(server.device, |device| {
        device
            .set_admin_state(server.interface, AdminState::Up)
            .unwrap()
    })
    .unwrap();
    let events = lab.run_until(SimTime(lease.rebind_at.0 + 100_000)).unwrap();
    assert!(events.iter().any(|event| {
        let EventOutcome::FrameReceived { interface, frame } = event else {
            return false;
        };
        if interface.device != server.device {
            return false;
        }
        let Ok(ip) = Ipv4Packet::decode(&frame.payload) else {
            return false;
        };
        let Ok(udp) = UdpDatagram::decode(&ip.payload) else {
            return false;
        };
        let Ok(message) = DhcpMessage::decode(&udp.payload) else {
            return false;
        };
        message.message_type == DhcpMessageType::Request
            && message.client_ip == lease.address
            && message.relay_ip.to_string() == "10.10.0.1"
    }));
    assert!(
        lab.device(client.device)
            .unwrap()
            .dhcp_lease(client.interface)
            .unwrap()
            .expires_at
            > lease.expires_at
    );
}

#[test]
fn conflicting_offer_is_declined_and_next_address_is_allocated() {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/dhcp-lan.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let server = lab.endpoint("R1:gi0/0").unwrap();
    let client = lab.endpoint("H1:gi0/0").unwrap();
    let occupied = lab.endpoint("H2:gi0/0").unwrap();
    for name in [
        "R1:gi0/0",
        "H1:gi0/0",
        "H2:gi0/0",
        "SW1:gi0/1",
        "SW1:gi0/2",
        "SW1:gi0/3",
    ] {
        let port = lab.endpoint(name).unwrap();
        lab.with_device_mut(port.device, |device| {
            if device.is_switchport(port.interface) {
                device
                    .set_stp_port(
                        port.interface,
                        rios_config::StpPortConfig {
                            portfast: true,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            device
                .set_admin_state(port.interface, AdminState::Up)
                .unwrap()
        })
        .unwrap();
    }
    for (port, address) in [(server, "192.168.1.1"), (occupied, "192.168.1.2")] {
        lab.with_device_mut(port.device, |device| {
            device
                .set_ipv4(
                    port.interface,
                    Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
                )
                .unwrap()
        })
        .unwrap();
    }
    lab.with_device_mut(server.device, |device| {
        let id = device.ensure_dhcp_pool("LAN").unwrap();
        device
            .set_dhcp_pool_network(
                id,
                Ipv4Network::new("192.168.1.0".parse().unwrap(), 24).unwrap(),
            )
            .unwrap();
    })
    .unwrap();
    lab.with_device_mut(client.device, |device| {
        device.set_dhcp_client(client.interface).unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(500)).unwrap();
    assert!(
        lab.device(client.device)
            .unwrap()
            .dhcp_lease(client.interface)
            .is_none()
    );
    lab.run_until(SimTime::from_millis(13_000)).unwrap();
    assert_eq!(
        lab.device(client.device)
            .unwrap()
            .dhcp_lease(client.interface)
            .unwrap()
            .address
            .to_string(),
        "192.168.1.3"
    );
}

#[test]
fn reserved_client_receives_fixed_address_and_wrong_request_gets_nak() {
    use rios_ethernet::{EtherType, EthernetFrame, MacAddress};
    use rios_ipv4::{IpProtocol, Ipv4Packet};
    use rios_protocol::{DhcpMessage, DhcpMessageType, UdpDatagram};
    use rios_topology::EventOutcome;
    use std::net::Ipv4Addr;
    let mut lab = relay_lab();
    let client = lab.endpoint("PC:gi0/0").unwrap();
    let mac = lab.device(client.device).unwrap().interfaces()[&client.interface].mac_address;
    let server = lab.device_id("SERVER").unwrap();
    lab.with_device_mut(server, |device| {
        let id = *device.running_config().dhcp_pools.keys().next().unwrap();
        let mut pool = device.running_config().dhcp_pools[&id].clone();
        pool.reserved_address = Some("10.10.0.99".parse().unwrap());
        pool.hardware_address = Some(mac);
        device.update_dhcp_pool(id, pool).unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(500)).unwrap();
    assert_eq!(
        lab.device(client.device)
            .unwrap()
            .dhcp_lease(client.interface)
            .unwrap()
            .address
            .to_string(),
        "10.10.0.99"
    );
    let request = DhcpMessage {
        message_type: DhcpMessageType::Request,
        transaction_id: 123456,
        client_mac: mac,
        your_ip: Ipv4Addr::UNSPECIFIED,
        client_ip: Ipv4Addr::UNSPECIFIED,
        relay_ip: Ipv4Addr::UNSPECIFIED,
        hops: 0,
        requested_ip: Some("10.10.0.50".parse().unwrap()),
        server_id: Some("10.100.0.10".parse().unwrap()),
        subnet_mask: None,
        default_router: None,
        lease_time_seconds: None,
        dns_servers: vec![],
        domain_name: None,
        renewal_seconds: None,
        rebinding_seconds: None,
    };
    let ip = Ipv4Packet {
        dscp_ecn: 0,
        source: Ipv4Addr::UNSPECIFIED,
        destination: Ipv4Addr::BROADCAST,
        ttl: 64,
        protocol: IpProtocol::Udp,
        payload: UdpDatagram {
            source_port: 68,
            destination_port: 67,
            payload: request.encode().unwrap(),
        }
        .encode()
        .unwrap(),
    };
    lab.transmit(
        client,
        EthernetFrame {
            source: mac,
            destination: MacAddress::BROADCAST,
            ethertype: EtherType::Ipv4,
            payload: ip.encode().unwrap(),
        },
    )
    .unwrap();
    let events = lab.run_until(SimTime::from_millis(550)).unwrap();
    assert!(events.iter().any(|event| {
        let EventOutcome::FrameReceived { interface, frame } = event else {
            return false;
        };
        if *interface != client {
            return false;
        }
        let Ok(ip) = Ipv4Packet::decode(&frame.payload) else {
            return false;
        };
        let Ok(udp) = UdpDatagram::decode(&ip.payload) else {
            return false;
        };
        let Ok(message) = DhcpMessage::decode(&udp.payload) else {
            return false;
        };
        message.message_type == DhcpMessageType::Nak && message.transaction_id == 123456
    }));
}
