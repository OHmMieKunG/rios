use rios_ethernet::{EtherType, EthernetFrame, MacAddress};
use rios_ipv6::*;
use std::net::Ipv6Addr;
fn source() -> Ipv6Addr {
    "2001:db8::1".parse().unwrap()
}
fn destination() -> Ipv6Addr {
    "2001:db8::2".parse().unwrap()
}
fn packet(next_header: NextHeader, payload: Vec<u8>) -> Ipv6Packet {
    Ipv6Packet {
        source: source(),
        destination: destination(),
        traffic_class: 0xab,
        flow_label: 0x12345,
        hop_limit: 64,
        next_header,
        payload,
    }
}
#[test]
fn ipv6_ethernet_and_icmp_match_wire_fields_and_pseudoheader_checksum() {
    let echo = Icmpv6Message::Echo {
        reply: false,
        identifier: 0x1234,
        sequence: 1,
        payload: b"abc".to_vec(),
    };
    let bytes = echo.encode(source(), destination()).unwrap();
    assert_eq!(
        bytes,
        vec![128, 0, 0x4d, 0xad, 0x12, 0x34, 0, 1, b'a', b'b', b'c']
    );
    let original = packet(NextHeader::Icmpv6, bytes.clone());
    let wire = original.encode().unwrap();
    assert_eq!(&wire[..8], &[0x6a, 0xb1, 0x23, 0x45, 0, 11, 58, 64]);
    assert_eq!(Ipv6Packet::decode(&wire).unwrap(), original);
    assert_eq!(
        Icmpv6Message::decode(source(), destination(), &bytes).unwrap(),
        echo
    );
    assert_eq!(
        Icmpv6Message::decode(destination(), destination(), &bytes),
        Err(Icmpv6Error::Checksum)
    );
    let frame = EthernetFrame {
        source: MacAddress([2, 0, 0, 0, 0, 1]),
        destination: MacAddress([2, 0, 0, 0, 0, 2]),
        ethertype: EtherType::Ipv6,
        payload: wire.clone(),
    };
    assert_eq!(&frame.encode().unwrap()[12..14], &[0x86, 0xdd]);
    assert_eq!(
        EthernetFrame::decode(&frame.encode().unwrap()).unwrap(),
        frame
    );
    for end in 0..wire.len() {
        assert!(Ipv6Packet::decode(&wire[..end]).is_err());
    }
    let mut corrupt = bytes;
    corrupt[8] ^= 1;
    assert!(Icmpv6Message::decode(source(), destination(), &corrupt).is_err());
}
#[test]
fn prefix_boundaries_and_deterministic_multicast_mapping() {
    for width in 0..=128 {
        let ip = Ipv6InterfaceConfig::new(source(), width).unwrap();
        assert!(ip.network().contains(source()));
        assert_eq!(ip.to_string().parse::<Ipv6InterfaceConfig>().unwrap(), ip);
        assert_eq!(
            ip.network().to_string().parse::<Ipv6Network>().unwrap(),
            ip.network()
        );
    }
    assert!(Ipv6Network::new(source(), 129).is_err());
    assert!(Ipv6InterfaceConfig::new(ALL_NODES, 64).is_err());
    let mac = MacAddress([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(
        link_local(mac),
        "fe80::11:22ff:fe33:4455".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        solicited_node(link_local(mac)),
        "ff02::1:ff33:4455".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        multicast_mac(solicited_node(link_local(mac))),
        Some(MacAddress([0x33, 0x33, 0xff, 0x33, 0x44, 0x55]))
    );
    assert!(multicast_mac(source()).is_none());
}
#[test]
fn extension_options_fragments_and_chain_bounds_are_checked() {
    let p = packet(
        NextHeader::HopByHop,
        vec![
            60, 0, 0, 1, 3, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0,
        ],
    );
    let upper = p.upper_layer().unwrap();
    assert_eq!(upper.protocol, NextHeader::Icmpv6);
    assert_eq!(upper.payload, &[128, 0, 0, 0]);
    assert_eq!(upper.next_header_offset, 48);
    for bad in [vec![], vec![58, 1, 0, 0], vec![58, 0, 1, 8, 0, 0, 0, 0]] {
        assert!(packet(NextHeader::HopByHop, bad).upper_layer().is_err());
    }
    let discard = packet(NextHeader::HopByHop, vec![58, 0, 0xc2, 0, 0, 0, 0, 0]);
    assert_eq!(
        discard.upper_layer(),
        Err(PacketError::ParameterProblem {
            pointer: 42,
            send_icmp: true
        })
    );
    let mut multicast = discard;
    multicast.destination = ALL_NODES;
    assert_eq!(
        multicast.upper_layer(),
        Err(PacketError::ParameterProblem {
            pointer: 42,
            send_icmp: false
        })
    );
    let atomic = packet(
        NextHeader::Fragment,
        vec![58, 0, 0, 0, 0, 0, 0, 1, 128, 0, 0, 0],
    );
    assert_eq!(atomic.upper_layer().unwrap().payload, &[128, 0, 0, 0]);
    let mut fragmented = atomic;
    fragmented.payload[3] = 1;
    assert_eq!(fragmented.upper_layer(), Err(PacketError::Fragmented));
    let chain = packet(
        NextHeader::DestinationOptions,
        [60, 0, 0, 0, 0, 0, 0, 0].repeat(17),
    );
    assert_eq!(chain.upper_layer(), Err(PacketError::ExtensionLimit));
    let bad_order = packet(
        NextHeader::DestinationOptions,
        vec![0, 0, 0, 0, 0, 0, 0, 0, 58, 0, 0, 0, 0, 0, 0, 0],
    );
    assert!(bad_order.upper_layer().is_err());
}
fn messages() -> Vec<NdMessage> {
    let options = vec![
        NdOption::SourceLinkLayer(MacAddress([2, 0, 0, 0, 0, 1])),
        NdOption::Mtu(1500),
        NdOption::Prefix(PrefixInformation {
            prefix: "2001:db8:1::/64".parse().unwrap(),
            on_link: true,
            autonomous: true,
            valid_lifetime: 3600,
            preferred_lifetime: 1800,
        }),
        NdOption::Unknown {
            kind: 100,
            data: vec![0; 6],
        },
    ];
    vec![
        NdMessage::RouterSolicitation { options: vec![] },
        NdMessage::RouterAdvertisement {
            hop_limit: 64,
            managed: false,
            other: true,
            router_lifetime: 1800,
            reachable_time: 30000,
            retrans_timer: 1000,
            options,
        },
        NdMessage::NeighborSolicitation {
            target: destination(),
            options: vec![NdOption::SourceLinkLayer(MacAddress([2, 0, 0, 0, 0, 1]))],
        },
        NdMessage::NeighborAdvertisement {
            target: source(),
            router: true,
            solicited: true,
            override_flag: true,
            options: vec![NdOption::TargetLinkLayer(MacAddress([2, 0, 0, 0, 0, 1]))],
        },
    ]
}
#[test]
fn nd_round_trip_and_dad_validation() {
    for nd in messages() {
        let message = Icmpv6Message::Neighbor(nd);
        let bytes = message.encode(source(), destination()).unwrap();
        assert_eq!(
            Icmpv6Message::decode(source(), destination(), &bytes).unwrap(),
            message
        );
        for length in 0..bytes.len() {
            assert!(Icmpv6Message::decode(source(), destination(), &bytes[..length]).is_err());
        }
    }
    let dad = NdMessage::NeighborSolicitation {
        target: source(),
        options: vec![],
    };
    assert!(
        dad.validate(Ipv6Addr::UNSPECIFIED, solicited_node(source()), 255)
            .is_ok()
    );
    assert!(dad.validate(Ipv6Addr::UNSPECIFIED, ALL_NODES, 255).is_err());
    assert!(dad.validate(source(), destination(), 254).is_err());
    let ra = messages().remove(1);
    assert!(ra.validate(source(), ALL_NODES, 255).is_err());
    assert!(
        ra.validate("fe80::1".parse().unwrap(), ALL_NODES, 255)
            .is_ok()
    );
    let na = messages().remove(3);
    assert!(na.validate(source(), ALL_NODES, 255).is_err());
}
#[test]
fn zero_length_nd_options_and_arbitrary_buffers_never_loop_or_panic() {
    let rs = Icmpv6Message::Neighbor(NdMessage::RouterSolicitation {
        options: vec![NdOption::SourceLinkLayer(MacAddress([2, 0, 0, 0, 0, 1]))],
    });
    let mut bytes = rs.encode(source(), destination()).unwrap();
    bytes[9] = 0;
    bytes[2..4].fill(0);
    let checksum = ipv6_checksum(source(), destination(), NextHeader::Icmpv6, &bytes);
    bytes[2..4].copy_from_slice(&checksum.to_be_bytes());
    assert_eq!(
        Icmpv6Message::decode(source(), destination(), &bytes),
        Err(Icmpv6Error::Malformed)
    );
    let mut seed = 1u64;
    for length in 0..1024 {
        let mut bytes: Vec<_> = (0..length)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                (seed >> 32) as u8
            })
            .collect();
        let _ = Ipv6Packet::decode(&bytes);
        for next in [
            NextHeader::HopByHop,
            NextHeader::Routing,
            NextHeader::Fragment,
            NextHeader::DestinationOptions,
        ] {
            let _ = packet(next, bytes.clone()).upper_layer();
        }
        if length >= 8 {
            bytes[0] = 133 + (length % 4) as u8;
            bytes[1] = 0;
            bytes[2..4].fill(0);
            let checksum = ipv6_checksum(source(), destination(), NextHeader::Icmpv6, &bytes);
            bytes[2..4].copy_from_slice(&checksum.to_be_bytes());
            let _ = Icmpv6Message::decode(source(), destination(), &bytes);
        }
    }
}
