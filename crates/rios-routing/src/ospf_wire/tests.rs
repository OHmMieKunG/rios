use super::*;
fn lsas() -> Vec<Lsa> {
    [
        LsaBody::Router {
            flags: 1,
            links: vec![RouterLink {
                id: "2.2.2.2".parse().unwrap(),
                data: "10.0.0.1".parse().unwrap(),
                kind: RouterLinkType::PointToPoint,
                metric: 10,
            }],
        },
        LsaBody::Network {
            mask: "255.255.255.0".parse().unwrap(),
            routers: vec!["1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap()],
        },
        LsaBody::Summary {
            mask: "255.255.255.0".parse().unwrap(),
            metric: 42,
        },
        LsaBody::External {
            mask: "0.0.0.0".parse().unwrap(),
            metric: 20,
            type_two: true,
            forwarding_address: Ipv4Addr::UNSPECIFIED,
            tag: 65001,
        },
    ]
    .into_iter()
    .map(|body| Lsa {
        age: 1,
        options: 2,
        link_state_id: "1.1.1.1".parse().unwrap(),
        advertising_router: "1.1.1.1".parse().unwrap(),
        sequence: LSA_INITIAL_SEQUENCE,
        body,
    })
    .collect()
}
#[test]
fn all_lsa_types_round_trip_with_age_independent_fletcher_checksums() {
    for lsa in lsas() {
        let bytes = lsa.encode().unwrap();
        assert_eq!(Lsa::decode(&bytes).unwrap(), lsa);
        for end in 0..bytes.len() {
            assert!(Lsa::decode(&bytes[..end]).is_err());
        }
        for offset in 2..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[offset] ^= 1;
            assert!(Lsa::decode(&damaged).is_err(), "offset {offset}");
        }
        let mut older = lsa.clone();
        older.age = LSA_MAX_AGE;
        assert_eq!(
            older.header().unwrap().checksum,
            lsa.header().unwrap().checksum
        );
    }
}
#[test]
fn five_packet_types_round_trip_and_truncations_are_safe() {
    let lsas = lsas();
    let headers: Vec<_> = lsas.iter().map(|lsa| lsa.header().unwrap()).collect();
    let bodies = vec![
        OspfBody::Hello(OspfHello {
            mask: "255.255.255.0".parse().unwrap(),
            hello_interval: 10,
            options: 2,
            priority: 1,
            dead_interval: 40,
            designated_router: "10.0.0.1".parse().unwrap(),
            backup_router: "10.0.0.2".parse().unwrap(),
            neighbors: vec!["2.2.2.2".parse().unwrap()],
        }),
        OspfBody::DatabaseDescription {
            mtu: 1500,
            options: 2,
            flags: 7,
            sequence: 123,
            headers: headers.clone(),
        },
        OspfBody::LinkStateRequest(lsas.iter().map(Lsa::key).collect()),
        OspfBody::LinkStateUpdate(lsas),
        OspfBody::LinkStateAck(headers),
    ];
    for body in bodies {
        let packet = OspfV2Packet {
            router_id: "1.1.1.1".parse().unwrap(),
            area: 0,
            body,
        };
        let bytes = packet.encode().unwrap();
        assert_eq!(OspfV2Packet::decode(&bytes).unwrap(), packet);
        for end in 0..bytes.len() {
            assert!(OspfV2Packet::decode(&bytes[..end]).is_err());
        }
    }
}
#[test]
fn hostile_lsa_count_is_rejected_before_allocation() {
    let packet = OspfV2Packet {
        router_id: Ipv4Addr::LOCALHOST,
        area: 0,
        body: OspfBody::LinkStateUpdate(vec![]),
    };
    let mut bytes = packet.encode().unwrap();
    bytes[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes[12..14].fill(0);
    let sum = checksum(&bytes);
    bytes[12..14].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(OspfV2Packet::decode(&bytes), Err(WireError::Malformed));
    // The legacy decoder is still used by the device until the runtime migration.
    assert!(crate::OspfPacket::decode(&bytes).is_err());
}
#[test]
fn arbitrary_byte_buffers_never_panic() {
    let mut seed = 123u64;
    for length in 0..512 {
        let bytes: Vec<_> = (0..length)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as u8
            })
            .collect();
        let _ = OspfV2Packet::decode(&bytes);
        let _ = Lsa::decode(&bytes);
    }
}
