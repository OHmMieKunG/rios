use rios_config::AdminState;
use rios_device::{TcpError, TcpSocket, TcpState};
use rios_ethernet::EtherType;
use rios_ipv4::{IpProtocol, Ipv4InterfaceConfig, Ipv4Packet};
use rios_protocol::{TcpFlags, TcpSegment};
use rios_simulator::{DeviceId, LinkId, LinkState, SimTime};
use rios_topology::{EventOutcome, Lab, LabError, Topology};

fn setup() -> (Lab, DeviceId, DeviceId) {
    let mut lab = Topology::from_yaml(include_str!("../../../examples/two-routers.yaml"))
        .unwrap()
        .build()
        .unwrap();
    let a = lab.endpoint("R1:gi0/0").unwrap();
    let b = lab.endpoint("R2:gi0/0").unwrap();
    for (port, address) in [(a, "10.0.0.1"), (b, "10.0.0.2")] {
        lab.with_device_mut(port.device, |device| {
            device
                .set_admin_state(port.interface, AdminState::Up)
                .unwrap();
            device
                .set_ipv4(
                    port.interface,
                    Ipv4InterfaceConfig::new(address.parse().unwrap(), 24).unwrap(),
                )
                .unwrap();
        })
        .unwrap();
    }
    (lab, a.device, b.device)
}
fn reverse(socket: TcpSocket) -> TcpSocket {
    TcpSocket {
        local_address: socket.remote_address,
        local_port: socket.remote_port,
        remote_address: socket.local_address,
        remote_port: socket.local_port,
    }
}
#[test]
fn handshake_transfer_and_orderly_close_use_tcp_packets() {
    let (mut lab, a, b) = setup();
    lab.tcp_listen(b, 179).unwrap();
    let socket = lab
        .tcp_connect(a, 49152, "10.0.0.2".parse().unwrap(), 179)
        .unwrap();
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&socket].state,
        TcpState::SynSent
    );
    let events = lab.run_until(SimTime::from_millis(20)).unwrap();
    let flags: Vec<_> = events
        .iter()
        .filter_map(|event| {
            let EventOutcome::FrameReceived { frame, .. } = event else {
                return None;
            };
            if frame.ethertype != EtherType::Ipv4 {
                return None;
            }
            let ip = Ipv4Packet::decode(&frame.payload).ok()?;
            if ip.protocol != IpProtocol::Tcp {
                return None;
            }
            Some(
                TcpSegment::decode(ip.source, ip.destination, &ip.payload)
                    .ok()?
                    .flags,
            )
        })
        .collect();
    assert_eq!(
        flags,
        [TcpFlags::SYN, TcpFlags::SYN | TcpFlags::ACK, TcpFlags::ACK]
    );
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&socket].state,
        TcpState::Established
    );
    assert_eq!(
        lab.device(b).unwrap().tcp_connections()[&reverse(socket)].state,
        TcpState::Established
    );
    lab.tcp_send(a, socket, b"original simulated bytes")
        .unwrap();
    assert!(matches!(
        lab.tcp_send(a, socket, b"busy"),
        Err(LabError::Tcp(TcpError::Busy))
    ));
    lab.run_until(SimTime::from_millis(30)).unwrap();
    assert_eq!(
        lab.tcp_read(b, reverse(socket)).unwrap(),
        b"original simulated bytes"
    );
    lab.tcp_send(b, reverse(socket), b"reply").unwrap();
    lab.run_until(SimTime::from_millis(40)).unwrap();
    assert_eq!(lab.tcp_read(a, socket).unwrap(), b"reply");
    lab.tcp_close(a, socket).unwrap();
    lab.run_until(SimTime::from_millis(50)).unwrap();
    assert_eq!(
        lab.device(b).unwrap().tcp_connections()[&reverse(socket)].state,
        TcpState::CloseWait
    );
    lab.tcp_close(b, reverse(socket)).unwrap();
    lab.run_until(SimTime::from_millis(60)).unwrap();
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&socket].state,
        TcpState::TimeWait
    );
    lab.run_until(SimTime::from_millis(121_000)).unwrap();
    assert!(lab.device(a).unwrap().tcp_connections().is_empty());
    assert!(lab.device(b).unwrap().tcp_connections().is_empty());
}
#[test]
fn loss_retransmits_without_delivering_duplicate_bytes() {
    let (mut lab, a, b) = setup();
    lab.tcp_listen(b, 80).unwrap();
    let socket = lab
        .tcp_connect(a, 50000, "10.0.0.2".parse().unwrap(), 80)
        .unwrap();
    lab.run_until(SimTime::from_millis(20)).unwrap();
    lab.tcp_send(a, socket, b"one copy").unwrap();
    // Deliver data, then invalidate its ACK already in flight.
    lab.step().unwrap();
    lab.set_link_state(LinkId(1), LinkState::Down).unwrap();
    lab.set_link_state(LinkId(1), LinkState::Up).unwrap();
    lab.run_until(SimTime::from_millis(3000)).unwrap();
    assert_eq!(lab.tcp_read(b, reverse(socket)).unwrap(), b"one copy");
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&socket].retransmissions,
        1
    );
    lab.tcp_send(a, socket, b"next").unwrap();
    lab.run_until(SimTime::from_millis(3010)).unwrap();
    assert_eq!(lab.tcp_read(b, reverse(socket)).unwrap(), b"next");
}
#[test]
fn closed_port_resets_and_failed_connections_expire() {
    let (mut lab, a, _) = setup();
    let socket = lab
        .tcp_connect(a, 50000, "10.0.0.2".parse().unwrap(), 9999)
        .unwrap();
    lab.run_until(SimTime::from_millis(20)).unwrap();
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&socket].state,
        TcpState::Closed
    );
    lab.run_until(SimTime::from_millis(1000)).unwrap();
    assert!(lab.device(a).unwrap().tcp_connections().is_empty());
    let socket = lab
        .tcp_connect(a, 50001, "10.0.0.99".parse().unwrap(), 80)
        .unwrap();
    lab.run_until(SimTime::from_millis(70_000)).unwrap();
    assert!(
        !lab.device(a)
            .unwrap()
            .tcp_connections()
            .contains_key(&socket)
    );
}

#[test]
fn protocol_owned_idle_timeout_backpressure_and_abort_use_real_tcp_state() {
    let (mut lab, a, b) = setup();
    lab.tcp_listen(b, 179).unwrap();
    let pinned = lab
        .tcp_connect(a, 50000, "10.0.0.2".parse().unwrap(), 179)
        .unwrap();
    let ordinary = lab
        .tcp_connect(a, 50001, "10.0.0.2".parse().unwrap(), 179)
        .unwrap();
    lab.run_until(SimTime::from_millis(20)).unwrap();
    for (device, socket) in [(a, pinned), (b, reverse(pinned))] {
        lab.with_device_mut(device, |d| d.tcp_set_idle_timeout(socket, None).unwrap())
            .unwrap();
        assert_eq!(
            lab.device(device).unwrap().tcp_connections()[&socket].send_capacity(),
            1200
        );
    }
    lab.tcp_send(a, pinned, b"bgp").unwrap();
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&pinned].send_capacity(),
        0
    );
    lab.run_until(SimTime::from_millis(30)).unwrap();
    assert_eq!(
        lab.device(b).unwrap().tcp_connections()[&reverse(pinned)].received_len(),
        3
    );
    assert_eq!(lab.tcp_read(b, reverse(pinned)).unwrap(), b"bgp");
    lab.run_until(SimTime::from_millis(301_000)).unwrap();
    assert!(
        !lab.device(a)
            .unwrap()
            .tcp_connections()
            .contains_key(&ordinary)
    );
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&pinned].state,
        TcpState::Established
    );
    lab.tcp_abort(a, pinned).unwrap();
    let events = lab.run_until(SimTime::from_millis(301_010)).unwrap();
    assert!(events.iter().any(|event| {
        let EventOutcome::FrameReceived { frame, .. } = event else {
            return false;
        };
        let Ok(packet) = Ipv4Packet::decode(&frame.payload) else {
            return false;
        };
        TcpSegment::decode(packet.source, packet.destination, &packet.payload)
            .is_ok_and(|segment| segment.flags.contains(TcpFlags::RST))
    }));
    assert!(
        !lab.device(a)
            .unwrap()
            .tcp_connections()
            .contains_key(&pinned)
    );
    // A due transport timer may already reclaim the closed peer after receiving RST.
    assert!(
        lab.device(b)
            .unwrap()
            .tcp_connections()
            .get(&reverse(pinned))
            .is_none_or(|connection| connection.state == TcpState::Closed)
    );
    lab.with_device_mut(b, |d| d.tcp_unlisten(179)).unwrap();
    let refused = lab
        .tcp_connect(a, 50002, "10.0.0.2".parse().unwrap(), 179)
        .unwrap();
    lab.run_until(SimTime::from_millis(301_020)).unwrap();
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&refused].state,
        TcpState::Closed
    );
}

#[test]
fn simultaneous_close_reaches_time_wait_without_an_ack_storm() {
    let (mut lab, a, b) = setup();
    lab.tcp_listen(b, 80).unwrap();
    let socket = lab
        .tcp_connect(a, 53000, "10.0.0.2".parse().unwrap(), 80)
        .unwrap();
    lab.run_until(SimTime::from_millis(20)).unwrap();
    lab.tcp_close(a, socket).unwrap();
    lab.tcp_close(b, reverse(socket)).unwrap();
    let events = lab.run_until(SimTime::from_millis(1000)).unwrap();
    let received = events
        .iter()
        .filter(|event| matches!(event, EventOutcome::FrameReceived { .. }))
        .count();
    assert_eq!(received, 4, "two FINs and two ACKs, then silence");
    assert_eq!(
        lab.device(a).unwrap().tcp_connections()[&socket].state,
        TcpState::TimeWait
    );
    assert_eq!(
        lab.device(b).unwrap().tcp_connections()[&reverse(socket)].state,
        TcpState::TimeWait
    );
    lab.run_until(SimTime::from_millis(122000)).unwrap();
    assert!(lab.device(a).unwrap().tcp_connections().is_empty());
    assert!(lab.device(b).unwrap().tcp_connections().is_empty());
}
