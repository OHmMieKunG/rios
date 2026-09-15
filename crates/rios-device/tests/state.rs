use rios_config::AdminState;
use rios_device::*;
use rios_simulator::{DeviceId, InterfaceId, LinkState};
#[test]
fn carrier_admin_and_logical_interfaces() {
    let mut d = Device::standalone();
    let id = InterfaceId(1);
    d.set_admin_state(id, AdminState::Up).unwrap();
    assert!(!d.protocol_up(id));
    d.set_link_state(id, LinkState::Up).unwrap();
    assert!(d.protocol_up(id));
    d.set_admin_state(id, AdminState::Down).unwrap();
    assert!(!d.protocol_up(id));
    for (name, up) in [("lo0", true), ("vlan10", false)] {
        let id = d.ensure_interface(name).unwrap();
        d.set_admin_state(id, AdminState::Up).unwrap();
        assert_eq!(d.protocol_up(id), up);
    }
    assert_eq!(d.ensure_interface("Gi0/01").unwrap(), InterfaceId(2));
    for bad in [
        "gi9/9",
        "loopback1/1",
        "vlan0",
        "vlan4095",
        "gi-1/0",
        "gi0/+1",
    ] {
        assert!(d.ensure_interface(bad).is_err(), "{bad}");
    }
}
#[test]
fn independent_snapshots_and_validated_mutations() {
    let mut d = Device::standalone();
    assert!(d.startup_config().0.is_none());
    d.save_config();
    let saved = d.startup_config().clone();
    d.set_hostname("EDGE").unwrap();
    assert_eq!(d.startup_config(), &saved);
    let before = d.clone();
    assert!(d.set_hostname("bad\nname").is_err());
    assert!(d.set_description(InterfaceId(1), "bad\nend").is_err());
    assert!(d.set_description(InterfaceId(99), "test").is_err());
    assert_eq!(d, before);
}
#[test]
fn deterministic_distinct_macs_and_device_classes() {
    let first = Device::standalone();
    assert_eq!(first, Device::standalone());
    let mut second = Device::new(DeviceId(2), "SW1", DeviceType::Switch).unwrap();
    let id = second.add_physical_interface("gi0/0").unwrap();
    assert_ne!(
        first.interfaces()[&id].mac_address,
        second.interfaces()[&id].mac_address
    );
    assert_eq!(second.device_type(), DeviceType::Switch);
    assert!(Device::new(DeviceId(1 << 24), "R", DeviceType::Router).is_err());
}
