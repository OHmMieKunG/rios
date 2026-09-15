use rios_ipv4::Ipv4Network;
use rios_routing::*;
use rios_simulator::SimTime;
use std::{collections::VecDeque, net::Ipv4Addr};
fn rid(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(n, n, n, n)
}
fn connected(hold_a: u16, hold_b: u16) -> [BgpSession; 2] {
    let mut peers = [
        BgpSession::new(65001, 65002, rid(1), hold_a, SimTime(0)).unwrap(),
        BgpSession::new(65002, 65001, rid(2), hold_b, SimTime(0)).unwrap(),
    ];
    let mut messages = VecDeque::new();
    for (id, peer) in peers.iter_mut().enumerate() {
        assert!(peer.tick(SimTime(0)).connect_transport);
        assert_eq!(peer.state, BgpState::Connect);
        messages.extend(
            peer.transport_connected(SimTime(1000))
                .messages
                .into_iter()
                .map(|m| (id, m)),
        );
        assert_eq!(peer.state, BgpState::OpenSent);
    }
    while let Some((from, message)) = messages.pop_front() {
        let bytes = message.encode(peers[from].four_octet_as).unwrap();
        let to = 1 - from;
        let message = BgpMessage::decode(&bytes, peers[to].four_octet_as).unwrap();
        let result = peers[to].receive(message, SimTime(2000));
        assert!(!result.close_transport);
        messages.extend(result.messages.into_iter().map(|m| (to, m)));
    }
    for peer in &peers {
        assert_eq!(peer.state, BgpState::Established);
        assert!(peer.four_octet_as);
    }
    peers
}
#[test]
fn negotiation_keepalive_and_hold_expiry_follow_exact_simulation_time() {
    let mut peers = connected(90, 30);
    assert_eq!(peers[0].negotiated_hold_time, 30);
    assert_eq!(peers[0].next_deadline(), Some(SimTime(10_002_000)));
    assert!(peers[0].tick(SimTime(10_001_999)).messages.is_empty());
    let keepalive = peers[0].tick(SimTime(10_002_000));
    assert_eq!(keepalive.messages, vec![BgpMessage::Keepalive]);
    peers[1].receive(BgpMessage::Keepalive, SimTime(10_003_000));
    let expired = peers[0].tick(SimTime(30_002_000));
    assert!(expired.close_transport);
    assert_eq!(
        expired.messages,
        vec![BgpMessage::Notification {
            code: 4,
            subcode: 0,
            data: vec![]
        }]
    );
    assert_eq!(peers[0].state, BgpState::Idle);
    assert!(peers[0].tick(SimTime(60_001_999)).messages.is_empty());
    assert!(peers[0].tick(SimTime(60_002_000)).connect_transport);
    assert_eq!(peers[0].state, BgpState::Connect);
    peers[0].transport_failed(SimTime(60_003_000));
    assert_eq!(peers[0].state, BgpState::Active);
}
#[test]
fn zero_hold_time_disables_periodic_liveness_and_updates_require_established() {
    let mut peers = connected(0, 90);
    assert_eq!(peers[0].next_deadline(), None);
    assert!(peers[0].tick(SimTime(u64::MAX)).messages.is_empty());
    let update = BgpUpdate {
        withdrawn: vec![Ipv4Network::new(rid(10), 24).unwrap()],
        attributes: None,
        announced: vec![],
    };
    assert_eq!(
        peers[0]
            .receive(BgpMessage::Update(update.clone()), SimTime(20_000))
            .update,
        Some(update.clone())
    );
    let mut idle = BgpSession::new(65001, 65002, rid(1), 180, SimTime(0)).unwrap();
    assert!(
        idle.receive(BgpMessage::Update(update), SimTime(0))
            .close_transport
    );
    assert_eq!(
        idle.last_error,
        Some(BgpError {
            code: 5,
            subcode: 0
        })
    );
}
#[test]
fn wrong_as_open_and_notification_close_without_installing_routes() {
    let mut a = BgpSession::new(65001, 65002, rid(1), 180, SimTime(0)).unwrap();
    a.transport_connected(SimTime(0));
    let open = BgpOpen {
        autonomous_system: 65003,
        hold_time: 180,
        router_id: rid(2),
        capabilities: vec![],
    };
    let result = a.receive(BgpMessage::Open(open), SimTime(1));
    assert!(result.close_transport);
    assert_eq!(
        a.last_error,
        Some(BgpError {
            code: 2,
            subcode: 2
        })
    );
    let mut peers = connected(90, 90);
    let result = peers[0].receive(
        BgpMessage::Notification {
            code: 6,
            subcode: 0,
            data: vec![],
        },
        SimTime(10000),
    );
    assert!(result.close_transport && result.messages.is_empty());
    assert_eq!(peers[0].state, BgpState::Idle);
    assert!(BgpSession::new(0, 1, rid(1), 90, SimTime(0)).is_err());
    assert!(BgpSession::new(1, 2, rid(1), 2, SimTime(0)).is_err());
}
fn path(peer: u8, asn: u32, med: u32) -> BgpPath {
    BgpPath {
        prefix: Ipv4Network::new(rid(10), 24).unwrap(),
        attributes: BgpAttributes {
            origin: BgpOrigin::Igp,
            as_path: vec![AsPathSegment::Sequence(vec![asn])],
            next_hop: rid(peer),
            atomic_aggregate: false,
            med: Some(med),
            local_preference: None,
            originator_id: None,
            cluster_list: vec![],
            unknown_transitive: vec![],
        },
        learned_from: Some(rid(peer)),
        peer_router_id: rid(peer),
        external: true,
        igp_cost: 1,
    }
}
#[test]
fn best_path_is_stable_with_conditional_med_and_policy_attributes() {
    let a = path(1, 65001, 100);
    let b = path(2, 65001, 20);
    let c = path(3, 65003, 0);
    for order in [
        [&a, &b, &c],
        [&a, &c, &b],
        [&b, &a, &c],
        [&b, &c, &a],
        [&c, &a, &b],
        [&c, &b, &a],
    ] {
        assert_eq!(bgp_best_path(order), Some(&b));
    }
    let mut preferred = c.clone();
    preferred.attributes.local_preference = Some(200);
    assert_eq!(bgp_best_path([&a, &b, &preferred]), Some(&preferred));
    let mut long = b.clone();
    long.attributes.prepend(&[65001]).unwrap();
    assert_eq!(bgp_best_path([&long, &c]), Some(&c));
    let mut internal = a.clone();
    internal.external = false;
    assert_eq!(bgp_best_path([&internal, &c]), Some(&c));
    let mut local = c.clone();
    local.learned_from = None;
    local.attributes.as_path.clear();
    assert_eq!(bgp_best_path([&a, &local]), Some(&local));
}
