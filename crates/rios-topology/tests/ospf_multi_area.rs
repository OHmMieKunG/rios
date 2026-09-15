use rios_config::{AdminState, OspfInterfaceConfig, OspfNetworkConfig, OspfNetworkType};
use rios_ipv4::Ipv4InterfaceConfig;
use rios_routing::LsaBody;
use rios_simulator::SimTime;
use rios_topology::{Lab, Topology};
use std::net::Ipv4Addr;
fn multi_area() -> Lab {
    let mut yaml = String::from("devices:\n");
    for name in ["R1", "R2", "R3", "R4", "EXT"] {
        yaml.push_str(&format!(
            "  {name}: {{type: router, interfaces: [gi0/0, gi0/1]}}\n"
        ));
    }
    yaml.push_str("links:\n");
    for link in [
        "R1:gi0/0, R2:gi0/0",
        "R2:gi0/1, R3:gi0/0",
        "R3:gi0/1, R4:gi0/0",
        "R1:gi0/1, EXT:gi0/0",
    ] {
        yaml.push_str(&format!(" - endpoints: [{link}]\n"));
    }
    let mut lab = Topology::from_yaml(&yaml).unwrap().build().unwrap();
    for (endpoint, address, area) in [
        ("R1:gi0/0", "10.0.12.1", Some(1)),
        ("R2:gi0/0", "10.0.12.2", Some(1)),
        ("R2:gi0/1", "10.0.23.2", Some(0)),
        ("R3:gi0/0", "10.0.23.3", Some(0)),
        ("R3:gi0/1", "10.0.34.3", Some(2)),
        ("R4:gi0/0", "10.0.34.4", Some(2)),
        ("R1:gi0/1", "10.9.0.1", None),
        ("EXT:gi0/0", "10.9.0.2", None),
    ] {
        let p = lab.endpoint(endpoint).unwrap();
        lab.with_device_mut(p.device, |d| {
            let address = address.parse().unwrap();
            d.set_ipv4(p.interface, Ipv4InterfaceConfig::new(address, 24).unwrap())
                .unwrap();
            d.set_admin_state(p.interface, AdminState::Up).unwrap();
            if let Some(area) = area {
                d.set_ospf_process(1).unwrap();
                d.add_ospf_network(OspfNetworkConfig {
                    address,
                    wildcard: Ipv4Addr::UNSPECIFIED,
                    area,
                })
                .unwrap();
                d.set_ospf_interface(
                    p.interface,
                    OspfInterfaceConfig {
                        network_type: OspfNetworkType::PointToPoint,
                        ..Default::default()
                    },
                )
                .unwrap();
            }
        })
        .unwrap();
    }
    for n in 1..=4 {
        lab.with_device_mut(lab.device_id(&format!("R{n}")).unwrap(), |d| {
            d.set_ospf_router_id(Some(Ipv4Addr::new(1, 1, 1, n)))
                .unwrap();
            let id = d.ensure_interface("lo0").unwrap();
            let address = Ipv4Addr::new(172, 16, n, 1);
            d.set_ipv4(id, Ipv4InterfaceConfig::new(address, 32).unwrap())
                .unwrap();
            d.set_admin_state(id, AdminState::Up).unwrap();
            d.add_ospf_network(OspfNetworkConfig {
                address,
                wildcard: Ipv4Addr::UNSPECIFIED,
                area: match n {
                    1 => 1,
                    4 => 2,
                    _ => 0,
                },
            })
            .unwrap();
        })
        .unwrap();
    }
    lab.with_device_mut(lab.device_id("EXT").unwrap(), |d| {
        let lo = d.ensure_interface("lo0").unwrap();
        d.set_ipv4(
            lo,
            Ipv4InterfaceConfig::new("192.0.2.99".parse().unwrap(), 32).unwrap(),
        )
        .unwrap();
        d.set_admin_state(lo, AdminState::Up).unwrap();
        d.set_static_route(
            rios_ipv4::Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
            "10.9.0.1".parse().unwrap(),
        );
    })
    .unwrap();
    lab
}
#[test]
fn backbone_summaries_and_asbr_routes_cross_multiple_areas() {
    use rios_config::OspfRedistribute;
    use rios_ipv4::{Ipv4Network, RouteSource};
    let mut lab = multi_area();
    let r1 = lab.device_id("R1").unwrap();
    let r4 = lab.device_id("R4").unwrap();
    let prefix = Ipv4Network::new("192.0.2.99".parse().unwrap(), 32).unwrap();
    lab.with_device_mut(r1, |d| {
        d.set_static_route(prefix, "10.9.0.2".parse().unwrap());
        d.set_ospf_redistribute_static(Some(OspfRedistribute {
            metric: 20,
            type_two: false,
        }))
        .unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(1000)).unwrap();
    let route = lab
        .device(r4)
        .unwrap()
        .routing_table()
        .lookup("172.16.1.1".parse().unwrap())
        .unwrap()
        .clone();
    assert_eq!(route.source, RouteSource::OspfInterArea);
    assert_eq!(route.metric, 4);
    let route = lab
        .device(r4)
        .unwrap()
        .routing_table()
        .lookup(prefix.address())
        .unwrap()
        .clone();
    assert_eq!(
        (route.source, route.metric),
        (RouteSource::OspfExternal1, 23)
    );
    assert!(
        lab.device(r4)
            .unwrap()
            .ospf_lsas(2, lab.now())
            .iter()
            .any(|lsa| matches!(lsa.body, LsaBody::AsbrSummary { metric: 2 }))
    );
    assert_eq!(
        lab.ping(r4, "172.16.1.1".parse().unwrap())
            .unwrap()
            .received,
        5
    );
    assert_eq!(lab.ping(r4, prefix.address()).unwrap().received, 5);
    lab.with_device_mut(r1, |d| {
        d.set_ospf_redistribute_static(Some(OspfRedistribute::default()))
            .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime(lab.now().0 + 100_000)).unwrap();
    let route = lab
        .device(r4)
        .unwrap()
        .routing_table()
        .lookup(prefix.address())
        .unwrap()
        .clone();
    assert_eq!(
        (route.source, route.metric),
        (RouteSource::OspfExternal2, 20)
    );
    lab.with_device_mut(r1, |d| {
        d.remove_static_route(prefix, "10.9.0.2".parse().unwrap())
    })
    .unwrap();
    lab.run_until(SimTime(lab.now().0 + 100_000)).unwrap();
    assert!(
        lab.device(r4)
            .unwrap()
            .routing_table()
            .lookup(prefix.address())
            .is_none()
    );
}
#[test]
fn default_information_tracks_rib_and_always_policy() {
    use rios_config::OspfDefaultRoute;
    use rios_ipv4::{Ipv4Network, RouteSource};
    let mut lab = multi_area();
    let r1 = lab.device_id("R1").unwrap();
    let r4 = lab.device_id("R4").unwrap();
    let default = Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).unwrap();
    let target = "203.0.113.1".parse().unwrap();
    lab.with_device_mut(r1, |d| {
        d.set_ospf_default(Some(OspfDefaultRoute::default()))
            .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(1000)).unwrap();
    assert!(
        lab.device(r4)
            .unwrap()
            .routing_table()
            .lookup(target)
            .is_none()
    );
    lab.with_device_mut(r1, |d| {
        d.set_static_route(default, "10.9.0.2".parse().unwrap())
    })
    .unwrap();
    lab.run_until(SimTime(lab.now().0 + 100_000)).unwrap();
    let route = lab
        .device(r4)
        .unwrap()
        .routing_table()
        .lookup(target)
        .unwrap()
        .clone();
    assert_eq!(
        (route.source, route.metric),
        (RouteSource::OspfExternal2, 1)
    );
    lab.with_device_mut(r1, |d| {
        d.remove_static_route(default, "10.9.0.2".parse().unwrap())
    })
    .unwrap();
    lab.run_until(SimTime(lab.now().0 + 100_000)).unwrap();
    assert!(
        lab.device(r4)
            .unwrap()
            .routing_table()
            .lookup(target)
            .is_none()
    );
    lab.with_device_mut(r1, |d| {
        d.set_ospf_default(Some(OspfDefaultRoute {
            always: true,
            metric: 7,
            type_two: false,
        }))
        .unwrap()
    })
    .unwrap();
    lab.run_until(SimTime(lab.now().0 + 100_000)).unwrap();
    let route = lab
        .device(r4)
        .unwrap()
        .routing_table()
        .lookup(target)
        .unwrap()
        .clone();
    assert_eq!(
        (route.source, route.metric),
        (RouteSource::OspfExternal1, 10)
    );
}

#[test]
fn overlapping_external_prefixes_keep_distinct_lsa_ids() {
    let mut lab = multi_area();
    let r1 = lab.device_id("R1").unwrap();
    let r4 = lab.device_id("R4").unwrap();
    lab.with_device_mut(r1, |d| {
        for length in [8, 16, 24] {
            d.set_static_route(
                rios_ipv4::Ipv4Network::new("198.0.0.0".parse().unwrap(), length).unwrap(),
                "10.9.0.2".parse().unwrap(),
            );
        }
        d.set_ospf_redistribute_static(Some(rios_config::OspfRedistribute::default()))
            .unwrap();
    })
    .unwrap();
    lab.run_until(SimTime::from_millis(1000)).unwrap();
    let routes = lab.device(r4).unwrap().routing_table();
    for length in [8, 16, 24] {
        assert!(routes.routes().iter().any(|route| route.prefix
            == rios_ipv4::Ipv4Network::new("198.0.0.0".parse().unwrap(), length).unwrap()
            && route.source == rios_ipv4::RouteSource::OspfExternal2));
    }
}
