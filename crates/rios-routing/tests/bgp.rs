use rios_ipv4::Ipv4Network;
use rios_routing::*;
use std::net::Ipv4Addr;
fn prefix(n: u8, len: u8) -> Ipv4Network {
    Ipv4Network::new(Ipv4Addr::new(10, n, 0, 0), len).unwrap()
}
fn attrs() -> BgpAttributes {
    BgpAttributes {
        origin: BgpOrigin::Igp,
        as_path: vec![AsPathSegment::Sequence(vec![65001, 65002])],
        next_hop: Ipv4Addr::new(192, 0, 2, 1),
        atomic_aggregate: false,
        med: Some(20),
        local_preference: Some(200),
        originator_id: Some(Ipv4Addr::new(1, 1, 1, 1)),
        cluster_list: vec![Ipv4Addr::new(2, 2, 2, 2)],
        unknown_transitive: vec![BgpUnknownAttribute {
            flags: 0xe0,
            code: 99,
            value: vec![1, 2, 3],
        }],
    }
}
fn open() -> BgpMessage {
    BgpMessage::Open(BgpOpen {
        autonomous_system: 23456,
        hold_time: 90,
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        capabilities: vec![
            BgpCapability::FourOctetAs(4200000001),
            BgpCapability::Multiprotocol { afi: 1, safi: 1 },
        ],
    })
}
#[test]
fn all_base_messages_match_header_and_round_trip_both_as_widths() {
    for four in [false, true] {
        let messages = vec![
            open(),
            BgpMessage::Keepalive,
            BgpMessage::Notification {
                code: 2,
                subcode: 2,
                data: vec![],
            },
            BgpMessage::Update(BgpUpdate {
                withdrawn: vec![prefix(20, 24)],
                attributes: Some(attrs()),
                announced: (0..=32).map(|len| prefix(10, len)).collect(),
            }),
            BgpMessage::Update(BgpUpdate {
                withdrawn: vec![prefix(10, 24)],
                attributes: None,
                announced: vec![],
            }),
        ];
        for message in messages {
            let bytes = message.encode(four).unwrap();
            assert_eq!(&bytes[..16], &[255; 16]);
            assert_eq!(
                u16::from_be_bytes([bytes[16], bytes[17]]) as usize,
                bytes.len()
            );
            assert_eq!(BgpMessage::decode(&bytes, four).unwrap(), message);
            for end in 0..bytes.len() {
                assert!(BgpMessage::decode(&bytes[..end], four).is_err());
            }
            let mut corrupt = bytes.clone();
            corrupt[0] = 0;
            assert_eq!(BgpMessage::decode(&corrupt, four).unwrap_err().code, 1);
        }
    }
    let bytes = BgpMessage::Keepalive.encode(true).unwrap();
    assert_eq!(&bytes[16..], &[0, 19, 4]);
    let bytes = open().encode(true).unwrap();
    assert_eq!(&bytes[19..29], &[4, 0x5b, 0xa0, 0, 90, 1, 1, 1, 1, 14]);
    let BgpMessage::Open(decoded) = BgpMessage::decode(&bytes, true).unwrap() else {
        panic!()
    };
    assert_eq!(decoded.effective_asn(), 4200000001);
    assert!(decoded.four_octet_as());
}
#[test]
fn tcp_stream_splits_and_coalescing_preserve_message_boundaries() {
    let messages = [
        open(),
        BgpMessage::Keepalive,
        BgpMessage::Update(BgpUpdate {
            withdrawn: vec![],
            attributes: Some(attrs()),
            announced: vec![prefix(7, 24)],
        }),
    ];
    let bytes: Vec<_> = messages
        .iter()
        .flat_map(|m| m.encode(true).unwrap())
        .collect();
    for size in 1..=bytes.len() {
        let mut stream = BgpStream::default();
        let mut decoded = Vec::new();
        for chunk in bytes.chunks(size) {
            stream.push(chunk).unwrap();
            while let Some(message) = stream.next_message(true).unwrap() {
                decoded.push(message);
            }
        }
        assert_eq!(decoded, messages);
        assert_eq!(stream.buffered_len(), 0);
    }
    let mut stream = BgpStream::default();
    assert!(stream.push(&vec![0; 8193]).is_err());
    stream.push(&[0; 19]).unwrap();
    assert!(stream.next_message(true).is_err());
}
#[test]
fn long_as_paths_extended_attributes_and_as_loop_inspection() {
    let mut a = attrs();
    a.prepend(&vec![4200000001; 300]).unwrap();
    a.atomic_aggregate = true;
    assert_eq!(a.path_length(), 302);
    assert_eq!(a.first_as(), Some(4200000001));
    assert!(a.contains_as(65002));
    assert!(!a.contains_as(65003));
    assert!(a.as_path.iter().all(|s| s.members().len() <= 255));
    a.unknown_transitive[0].value = vec![42; 300];
    let message = BgpMessage::Update(BgpUpdate {
        withdrawn: vec![],
        attributes: Some(a),
        announced: vec![prefix(0, 8)],
    });
    let bytes = message.encode(true).unwrap();
    assert!(bytes.windows(4).any(|w| w == [0xf0, 99, 1, 44]));
    assert_eq!(BgpMessage::decode(&bytes, true).unwrap(), message);
    assert!(message.encode(false).is_err());
}
fn update(attributes: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut b = vec![255; 16];
    b.extend([0, 0, 2, 0, 0]);
    b.extend((attributes.len() as u16).to_be_bytes());
    b.extend(attributes);
    b.extend(nlri);
    let len = b.len() as u16;
    b[16..18].copy_from_slice(&len.to_be_bytes());
    b
}
#[test]
fn malformed_lengths_flags_duplicates_and_prefixes_return_protocol_errors() {
    let required = [0x40, 1, 1, 0, 0x40, 2, 0, 0x40, 3, 4, 192, 0, 2, 1];
    assert!(BgpMessage::decode(&update(&required, &[24, 10, 1, 0]), true).is_ok());
    for attrs in [
        &required[..4],
        &required[..8],
        &[0x40, 1, 1, 4][..],
        &[0x40, 1, 1, 0, 0x40, 1, 1, 0][..],
        &[0xc0, 1, 1, 0][..],
        &[0x40, 99, 0][..],
        &[0x50, 1, 255][..],
    ] {
        assert!(BgpMessage::decode(&update(attrs, &[0]), true).is_err());
    }
    for nlri in [&[33][..], &[32, 1, 2, 3][..]] {
        assert!(BgpMessage::decode(&update(&required, nlri), true).is_err());
    }
    assert!(BgpMessage::decode(&update(&[], &[0]), true).is_err());
    let mut b = BgpMessage::Keepalive.encode(true).unwrap();
    b[16..18].copy_from_slice(&4097u16.to_be_bytes());
    assert!(BgpMessage::decode(&b, true).is_err());
}
#[test]
fn arbitrary_framed_bodies_never_panic() {
    let mut random = 7u64;
    for len in 19..=4096 {
        let mut b = vec![0; len];
        for byte in &mut b {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            *byte = random as u8;
        }
        b[..16].fill(255);
        b[16..18].copy_from_slice(&(len as u16).to_be_bytes());
        b[18] = (len % 4 + 1) as u8;
        if len >= 29 && b[18] == 1 {
            b[19] = 4;
            b[28] = (len - 29).min(255) as u8;
        }
        for four in [false, true] {
            let _ = BgpMessage::decode(&b, four);
        }
    }
}
