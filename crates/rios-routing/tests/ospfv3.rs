use rios_ipv6::{Ipv6Network, NextHeader, ipv6_checksum};
use rios_routing::*;
use rios_simulator::SimTime;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{Ipv4Addr, Ipv6Addr},
};
fn id(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(1, 1, 1, n)
}
fn ip(n: u8) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, u16::from(n))
}
fn advertisement(router: u8, n: u32, body: OspfV3LsaBody) -> OspfV3Lsa {
    OspfV3Lsa {
        age: 0,
        link_state_id: n,
        advertising_router: id(router),
        sequence: LSA_INITIAL_SEQUENCE,
        body,
    }
}
fn prefixes() -> Vec<OspfV3Prefix> {
    (0..=128)
        .map(|len| OspfV3Prefix {
            prefix: Ipv6Network::new("2001:db8:1234::".parse().unwrap(), len).unwrap(),
            options: 0,
            metric: 0,
        })
        .collect()
}
#[test]
fn lsa_prefixes_scopes_and_checksums_round_trip() {
    let reference = OspfV3LsaKey {
        kind: V3_ROUTER_LSA,
        link_state_id: 0,
        advertising_router: id(1),
    };
    let bodies = vec![
        OspfV3LsaBody::Router {
            flags: 0,
            options: OSPFV3_OPTIONS,
            links: vec![OspfV3RouterLink {
                kind: OspfV3LinkType::PointToPoint,
                metric: 42,
                interface_id: 1,
                neighbor_interface_id: 2,
                neighbor_router: id(2),
            }],
        },
        OspfV3LsaBody::Network {
            options: OSPFV3_OPTIONS,
            routers: vec![id(1), id(2)],
        },
        OspfV3LsaBody::Link {
            priority: 1,
            options: OSPFV3_OPTIONS,
            link_local: ip(1),
            prefixes: prefixes(),
        },
        OspfV3LsaBody::IntraAreaPrefix {
            reference,
            prefixes: prefixes(),
        },
        OspfV3LsaBody::Unknown {
            kind: 0xa123,
            bytes: vec![1, 2, 3],
        },
        OspfV3LsaBody::Unknown {
            kind: 0x2123,
            bytes: vec![],
        },
    ];
    for body in bodies {
        let lsa = advertisement(1, 123, body);
        let bytes = lsa.encode().unwrap();
        assert_eq!(OspfV3Lsa::decode(&bytes).unwrap(), lsa);
        for end in 0..bytes.len() {
            assert!(OspfV3Lsa::decode(&bytes[..end]).is_err());
        }
        let mut aged = lsa.clone();
        aged.age = 999;
        assert_eq!(
            aged.header().unwrap().checksum,
            lsa.header().unwrap().checksum
        );
        let mut corrupt = bytes;
        corrupt[19] ^= 1;
        assert!(OspfV3Lsa::decode(&corrupt).is_err());
        if let OspfV3LsaBody::Unknown { kind, .. } = lsa.body {
            assert_eq!(
                lsa.flooding_scope(),
                if kind & 0x8000 == 0 { 0 } else { 0x2000 }
            );
        }
    }
}
#[test]
fn hello_wire_layout_and_pseudoheader_are_standard() {
    let p = OspfV3Packet {
        router_id: id(1),
        area: 42,
        instance: 3,
        body: OspfBody::Hello(OspfV3Hello {
            interface_id: 7,
            priority: 1,
            options: OSPFV3_OPTIONS,
            hello_interval: 10,
            dead_interval: 40,
            designated_router: id(2),
            backup_router: id(3),
            neighbors: vec![id(2), id(3)],
        }),
    };
    let bytes = p.encode(ip(1), OSPFV3_ALL_ROUTERS).unwrap();
    assert_eq!(&bytes[..4], &[3, 1, 0, 44]);
    assert_eq!(
        &bytes[14..28],
        &[3, 0, 0, 0, 0, 7, 1, 0, 0, 0x13, 0, 10, 0, 40]
    );
    assert_eq!(
        ipv6_checksum(ip(1), OSPFV3_ALL_ROUTERS, NextHeader::Ospf, &bytes),
        0
    );
    assert_eq!(
        OspfV3Packet::decode(ip(1), OSPFV3_ALL_ROUTERS, &bytes).unwrap(),
        p
    );
    assert_eq!(
        OspfV3Packet::decode(ip(2), OSPFV3_ALL_ROUTERS, &bytes),
        Err(WireError::Checksum)
    );
}
fn database(router: u8) -> BTreeMap<OspfV3LsaKey, OspfV3Lsa> {
    (0..80)
        .map(|n| {
            let lsa = advertisement(
                router,
                n,
                OspfV3LsaBody::IntraAreaPrefix {
                    reference: OspfV3LsaKey {
                        kind: V3_ROUTER_LSA,
                        link_state_id: 0,
                        advertising_router: id(router),
                    },
                    prefixes: vec![OspfV3Prefix {
                        prefix: format!("2001:db8:{router}:{n}::/64").parse().unwrap(),
                        options: 0,
                        metric: 10,
                    }],
                },
            );
            (lsa.key(), lsa)
        })
        .collect()
}
#[test]
fn v3_database_exchange_recovers_each_packet_kind_loss_with_ipv6_mtu() {
    for lost in [2, 3, 4, 5] {
        let mut peers = [
            OspfV3Exchange::new(id(1), id(2), 1280, 1),
            OspfV3Exchange::new(id(2), id(1), 1280, 2),
        ];
        let mut db = [database(1), database(2)];
        let mut queue = VecDeque::from([
            (0, peers[0].start(&db[0], SimTime(0))),
            (1, peers[1].start(&db[1], SimTime(0))),
        ]);
        let mut dropped = false;
        let mut observed = BTreeSet::new();
        for second in 0..40 {
            let now = SimTime::from_millis(second * 1000);
            for (i, peer) in peers.iter_mut().enumerate() {
                queue.extend(peer.tick(now).into_iter().map(|b| (i, b)));
            }
            let mut count = 0;
            while let Some((from, body)) = queue.pop_front() {
                count += 1;
                assert!(count < 2000);
                let to = 1 - from;
                let packet = OspfV3Packet {
                    router_id: id(from as u8 + 1),
                    area: 0,
                    instance: 0,
                    body,
                };
                let bytes = packet.encode(ip(from as u8 + 1), ip(to as u8 + 1)).unwrap();
                assert!(bytes.len() + 40 <= 1280);
                observed.insert(bytes[1]);
                if !dropped && bytes[1] == lost {
                    dropped = true;
                    continue;
                }
                let body = OspfV3Packet::decode(ip(from as u8 + 1), ip(to as u8 + 1), &bytes)
                    .unwrap()
                    .body;
                let result = peers[to].receive(body, &db[to], now);
                for lsa in result.advertisements {
                    db[to].insert(lsa.key(), lsa);
                }
                queue.extend(result.packets.into_iter().map(|b| (to, b)));
            }
        }
        assert!(dropped);
        assert_eq!(observed, BTreeSet::from([2, 3, 4, 5]));
        assert_eq!(db[0], db[1]);
        assert_eq!(db[0].len(), 160);
        for peer in peers {
            assert_eq!(peer.state, OspfNeighborState::Full);
            assert_eq!(peer.pending(), (0, 0));
        }
    }
}
#[test]
fn arbitrary_bodies_with_valid_packet_checksums_are_safe() {
    let mut random = 1u64;
    for length in 16..1024 {
        let mut b = vec![0; length];
        for byte in &mut b {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            *byte = random as u8;
        }
        b[0] = 3;
        b[1] = (length % 5 + 1) as u8;
        b[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        b[12..14].fill(0);
        let sum = ipv6_checksum(ip(1), ip(2), NextHeader::Ospf, &b);
        b[12..14].copy_from_slice(&sum.to_be_bytes());
        let _ = OspfV3Packet::decode(ip(1), ip(2), &b);
        let _ = OspfV3Lsa::decode(&b);
    }
}
