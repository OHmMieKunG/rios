use super::*;
use crate::LsaKey;
use crate::{LSA_INITIAL_SEQUENCE, LsaBody, OspfV2Packet};
use std::collections::{BTreeSet, VecDeque};
fn id(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(1, 1, 1, n)
}
fn database(router: u8) -> BTreeMap<LsaKey, Lsa> {
    (0..40)
        .map(|n| {
            let lsa = Lsa {
                age: 0,
                options: 2,
                link_state_id: Ipv4Addr::new(10, router, n, 0),
                advertising_router: id(router),
                sequence: LSA_INITIAL_SEQUENCE + 1,
                body: LsaBody::Summary {
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    metric: 10,
                },
            };
            (lsa.key(), lsa)
        })
        .collect()
}
fn kind(body: &OspfBody) -> u8 {
    match body {
        OspfBody::Hello(_) => 1,
        OspfBody::DatabaseDescription { .. } => 2,
        OspfBody::LinkStateRequest(_) => 3,
        OspfBody::LinkStateUpdate(_) => 4,
        OspfBody::LinkStateAck(_) => 5,
    }
}

#[test]
fn multi_page_exchange_recovers_dropped_packets_and_acks() {
    for lost in [None, Some(2), Some(3), Some(4), Some(5)] {
        let mut peers = [
            OspfExchange::new(id(1), id(2), 256, 100),
            OspfExchange::new(id(2), id(1), 256, 200),
        ];
        let mut databases = [database(1), database(2)];
        let mut queue = VecDeque::from([
            (0, peers[0].start(&databases[0], SimTime(0))),
            (1, peers[1].start(&databases[1], SimTime(0))),
        ]);
        let mut dropped = false;
        let mut observed = BTreeSet::new();
        let mut states = BTreeSet::new();
        for second in 0..60 {
            let now = SimTime::from_millis(second * 1000);
            for (n, peer) in peers.iter_mut().enumerate() {
                queue.extend(peer.tick(now).into_iter().map(|p| (n, p)));
            }
            let mut processed = 0;
            while let Some((from, body)) = queue.pop_front() {
                processed += 1;
                assert!(processed < 1000, "packet loop {lost:?}");
                observed.insert(kind(&body));
                if !dropped && Some(kind(&body)) == lost {
                    dropped = true;
                    continue;
                }
                // Every exchange body crosses the actual standard codec.
                let wire = OspfV2Packet {
                    router_id: id(from as u8 + 1),
                    area: 0,
                    body,
                }
                .encode()
                .unwrap();
                assert!(wire.len() + 20 <= 256);
                let body = OspfV2Packet::decode(&wire).unwrap().body;
                let to = 1 - from;
                let result = peers[to].receive(body, &databases[to], now);
                states.insert(format!("{:?}", peers[to].state));
                for lsa in result.advertisements {
                    databases[to].insert(lsa.key(), lsa);
                }
                queue.extend(result.packets.into_iter().map(|p| (to, p)));
            }
        }
        assert_eq!(databases[0], databases[1], "lost {lost:?}");
        assert_eq!(databases[0].len(), 80);
        for peer in &peers {
            assert_eq!(peer.state, OspfNeighborState::Full, "lost {lost:?}");
            assert_eq!(peer.pending(), (0, 0));
        }
        assert_eq!(observed, BTreeSet::from([2, 3, 4, 5]));
        assert!(
            states.contains("Exchange") && states.contains("Loading") && states.contains("Full")
        );
    }
}

#[test]
fn older_advertisement_cannot_satisfy_request_or_replace_newer_instance() {
    let database = database(1);
    let lsa = database.values().next().unwrap().clone();
    let mut old = lsa.clone();
    old.sequence -= 1;
    let mut exchange = OspfExchange::new(id(1), id(2), 1500, 1);
    exchange.state = OspfNeighborState::Loading;
    exchange.requests.insert(lsa.key(), lsa.header().unwrap());
    let result = exchange.receive(
        OspfBody::LinkStateUpdate(vec![old.clone()]),
        &BTreeMap::new(),
        SimTime(0),
    );
    assert!(result.advertisements.is_empty());
    assert_eq!(exchange.pending().0, 1);
    exchange.requests.clear();
    let result = exchange.receive(OspfBody::LinkStateUpdate(vec![old]), &database, SimTime(0));
    assert!(result.advertisements.is_empty());
    assert_eq!(
        result.packets,
        vec![OspfBody::LinkStateUpdate(vec![lsa.clone()])]
    );
    let mut stale_ack = lsa.header().unwrap();
    stale_ack.sequence -= 1;
    exchange.receive(
        OspfBody::LinkStateAck(vec![stale_ack]),
        &database,
        SimTime(0),
    );
    assert_eq!(exchange.pending().1, 1);
    exchange.receive(
        OspfBody::LinkStateAck(vec![lsa.header().unwrap()]),
        &database,
        SimTime(0),
    );
    assert_eq!(exchange.pending().1, 0);
}

#[test]
fn lsa_instance_order_obeys_signed_sequence_checksum_and_age() {
    let db = database(1);
    let a = db.values().next().unwrap().header().unwrap();
    let mut b = a;
    b.sequence = 1;
    assert_eq!(compare_lsa(&b, &a), Ordering::Greater);
    b = a;
    b.age = LSA_MAX_AGE;
    assert_eq!(compare_lsa(&b, &a), Ordering::Greater);
    b.age = 1000;
    assert_eq!(compare_lsa(&b, &a), Ordering::Less);
    b.age = 899;
    assert_eq!(compare_lsa(&b, &a), Ordering::Equal);
}

#[test]
fn mtu_mismatch_and_premature_updates_do_not_establish_adjacency() {
    let db = database(1);
    let mut peer = OspfExchange::new(id(1), id(2), 1500, 1);
    peer.start(&db, SimTime(0));
    let out = peer.receive(
        OspfBody::DatabaseDescription {
            mtu: 9000,
            options: 2,
            flags: 7,
            sequence: 1,
            headers: vec![],
        },
        &db,
        SimTime(0),
    );
    assert!(out.packets.is_empty());
    let out = peer.receive(
        OspfBody::LinkStateUpdate(db.values().cloned().collect()),
        &db,
        SimTime(0),
    );
    assert!(out.advertisements.is_empty());
    assert_eq!(peer.state, OspfNeighborState::ExStart);
}
