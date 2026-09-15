use rios_cli::*;
use rios_config::{AccessListDirection, AdminState, VlanId};
use rios_device::{Device, DeviceType};
use rios_simulator::{DeviceId, InterfaceId};

fn run(device: &mut Device, session: &mut CliSession, input: &str) -> Result<Execution, CliError> {
    let ParsedInput::Command(command) = parse(input, session.mode).unwrap() else {
        panic!("expected command")
    };
    execute(device, session, command)
}
#[test]
fn abbreviations_and_mode_rules() {
    let cases = [
        (
            CliMode::PrivilegedExec,
            "configure terminal",
            Command::ConfigureTerminal,
        ),
        (
            CliMode::PrivilegedExec,
            "conf t",
            Command::ConfigureTerminal,
        ),
        (
            CliMode::PrivilegedExec,
            "sh ip int br",
            Command::ShowIpInterfaceBrief,
        ),
        (
            CliMode::GlobalConfiguration,
            "int gi0/1",
            Command::EnterInterface("GigabitEthernet0/1".into()),
        ),
        (
            CliMode::GlobalConfiguration,
            "interface gigabitEthernet 0/1",
            Command::EnterInterface("GigabitEthernet0/1".into()),
        ),
        (
            CliMode::InterfaceConfiguration(InterfaceId(1)),
            "no shut",
            Command::NoShutdown,
        ),
        (CliMode::PrivilegedExec, "wr mem", Command::SaveConfig),
        (
            CliMode::PrivilegedExec,
            "sh mac add",
            Command::ShowMacAddressTable,
        ),
        (
            CliMode::GlobalConfiguration,
            "ip route 192.168.2.7 255.255.255.0 10.0.0.2",
            Command::SetStaticRoute {
                prefix: rios_ipv4::Ipv4Network::new("192.168.2.0".parse().unwrap(), 24).unwrap(),
                next_hop: "10.0.0.2".parse().unwrap(),
            },
        ),
    ];
    for (mode, input, expected) in cases {
        assert_eq!(parse(input, mode).unwrap(), ParsedInput::Command(expected));
    }
    assert!(parse("conf t", CliMode::UserExec).is_err());
    assert!(
        parse(
            "ip address 1.2.3.4 255.255.255.0",
            CliMode::GlobalConfiguration
        )
        .is_err()
    );
    assert!(matches!(
        parse("sh i", CliMode::PrivilegedExec),
        Err(ParseError::Ambiguous(_))
    ));
    assert_eq!(
        parse("configure", CliMode::PrivilegedExec),
        Err(ParseError::Incomplete)
    );
    assert!(parse("enable extra", CliMode::UserExec).is_err());
    let error = parse("hello", CliMode::PrivilegedExec).unwrap_err();
    assert!(error.render("R1# ", "hello").starts_with("    ^\n"));
    assert!(parse("int gi0/ 1", CliMode::GlobalConfiguration).is_err());
    assert!(parse("enable\0", CliMode::UserExec).is_err());
}
#[test]
fn help_and_completion_share_tree() {
    let ParsedInput::Help(help) = parse("show ip ?", CliMode::PrivilegedExec).unwrap() else {
        panic!()
    };
    for keyword in ["arp", "interface", "route"] {
        assert!(help.contains(keyword));
    }
    assert!(!help.contains("running-config"));
    let ParsedInput::Help(help) = parse("interface ?", CliMode::GlobalConfiguration).unwrap()
    else {
        panic!()
    };
    for keyword in ["GigabitEthernet", "Loopback", "Vlan"] {
        assert!(help.contains(keyword));
    }
    assert_eq!(
        parse("int gi1/0/1", CliMode::GlobalConfiguration).unwrap(),
        ParsedInput::Command(Command::EnterInterface("GigabitEthernet1/0/1".into()))
    );
    let words = suggestions("sh ip int b", CliMode::PrivilegedExec, &[]).unwrap();
    assert_eq!(words[0].word, "brief");
    assert_eq!(words[0].start, 10);
    let device = Device::standalone();
    let words = suggestions(
        "int gi0/",
        CliMode::GlobalConfiguration,
        &device
            .running_config()
            .interfaces
            .values()
            .map(|c| c.name.clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        words.iter().map(|s| s.word.as_str()).collect::<Vec<_>>(),
        ["GigabitEthernet0/0", "GigabitEthernet0/1"]
    );
    assert!(suggestions("conf ", CliMode::UserExec, &[]).is_err());
    assert_eq!(
        suggestions(
            "ip address 1.2.3.4 ",
            CliMode::InterfaceConfiguration(InterfaceId(1)),
            &[]
        )
        .unwrap()[0]
            .word,
        "<mask>"
    );
}
#[test]
fn complete_session_and_snapshot() {
    let mut device = Device::standalone();
    let mut session = CliSession::default();
    assert_eq!(session.prompt(device.hostname()), "R1> ");
    for line in [
        "enable",
        "conf t",
        "hostname EDGE-R1",
        "int gi0/0",
        "description Uplink  to LAB",
        "ip address 10.0.0.1 255.255.255.0",
        "no shut",
        "end",
    ] {
        run(&mut device, &mut session, line).unwrap();
    }
    assert_eq!(session.prompt(device.hostname()), "EDGE-R1# ");
    let brief = run(&mut device, &mut session, "sh ip int br")
        .unwrap()
        .output;
    assert!(brief.contains("10.0.0.1"));
    assert!(brief.lines().nth(1).unwrap().ends_with("down"));
    let rendered = run(&mut device, &mut session, "sh run").unwrap().output;
    assert!(rendered.contains(" description Uplink  to LAB\n"));
    assert!(rendered.contains(" ip address 10.0.0.1 255.255.255.0\n no shutdown\n"));
    run(&mut device, &mut session, "copy run start").unwrap();
    run(&mut device, &mut session, "conf t").unwrap();
    run(&mut device, &mut session, "hostname CHANGED").unwrap();
    run(&mut device, &mut session, "end").unwrap();
    assert_eq!(
        run(&mut device, &mut session, "sh start").unwrap().output,
        rendered
    );
    assert!(run(&mut device, &mut session, "exit").unwrap().close);
}
#[test]
fn failed_commands_are_atomic_and_executor_checks_modes() {
    let mut device = Device::standalone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    let before = device.clone();
    assert!(run(&mut device, &mut session, "hostname bad_name").is_err());
    assert!(run(&mut device, &mut session, "int gi0/99").is_err());
    assert_eq!(device, before);
    assert_eq!(session.mode, CliMode::GlobalConfiguration);
    assert!(execute(&mut device, &mut session, Command::SaveConfig).is_err());
    run(&mut device, &mut session, "int gi0/0").unwrap();
    assert!(parse("ip address 10.0.0.1 255.0.255.0", session.mode).is_err());
    assert!(parse("ip address 999.0.0.1 255.255.255.0", session.mode).is_err());
    assert_eq!(device, before);
}
#[test]
fn config_replay_round_trip_and_rollback() {
    let mut original = Device::standalone();
    load_configuration(&mut original,"hostname EDGE\ninterface gi0/0\n description WAN\n ip address 10.0.0.1 255.255.255.0\n no shutdown\ninterface Loopback0\n ip address 1.1.1.1 255.255.255.255\n no shutdown\nexit\nip route 192.168.2.0 255.255.255.0 10.0.0.2\nend\n").unwrap();
    let mut restored = Device::standalone();
    load_configuration(&mut restored, &original.running_config().render()).unwrap();
    assert_eq!(restored, original);
    restored.save_config();
    let before = restored.clone();
    for invalid in [
        "hostname NEW\ninterface gi0/0\nip address bad mask",
        "hostname NEW\nend\nshow interfaces",
        "hostname NEW\ninterface Vlan4095",
        "hostname NEW\n?",
        "hostname NEW\nwrite memory",
    ] {
        assert!(load_configuration(&mut restored, invalid).is_err());
        assert_eq!(restored, before);
    }
}
#[test]
fn session_navigation_and_isolation() {
    let mut a = Device::standalone();
    let b = Device::standalone();
    let mut one = CliSession::default();
    let two = CliSession::default();
    for line in ["enable", "conf t", "hostname A", "int loopback0", "exit"] {
        run(&mut a, &mut one, line).unwrap();
    }
    assert_eq!(one.mode, CliMode::GlobalConfiguration);
    one.end_configuration();
    assert_eq!(one.mode, CliMode::PrivilegedExec);
    run(&mut a, &mut one, "disable").unwrap();
    assert_eq!(one.mode, CliMode::UserExec);
    one.end_configuration();
    assert_eq!(one.mode, CliMode::UserExec);
    assert_eq!(two.mode, CliMode::UserExec);
    assert_eq!(b.hostname(), "R1");
}
#[test]
fn deferred_features_do_not_fake_success() {
    let mut device = Device::standalone();
    let before = device.clone();
    let mut session = CliSession {
        mode: CliMode::PrivilegedExec,
    };
    for input in ["debug packet", "debug arp", "debug icmp"] {
        assert!(matches!(
            run(&mut device, &mut session, input),
            Err(CliError::Unavailable(_))
        ));
        assert_eq!(device, before);
    }
    assert!(
        run(&mut device, &mut session, "show ip route")
            .unwrap()
            .output
            .contains("Codes:")
    );
    assert!(
        run(&mut device, &mut session, "show arp")
            .unwrap()
            .output
            .contains("Protocol")
    );
    assert!(
        run(&mut device, &mut session, "show ip arp")
            .unwrap()
            .output
            .contains("Protocol")
    );
    assert!(
        run(&mut device, &mut session, "ping 1.2.3.4")
            .unwrap()
            .request
            .is_some()
    );
}

#[test]
fn vlan_and_switchport_configuration_round_trip() {
    let mut switch = Device::new(DeviceId(7), "SW1", DeviceType::Switch).unwrap();
    switch.add_physical_interface("gi0/1").unwrap();
    switch.add_physical_interface("gi0/24").unwrap();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    for line in [
        "vlan 10",
        "name USERS",
        "exit",
        "vlan 20",
        "exit",
        "int gi0/1",
        "sw mo ac",
        "sw ac vl 10",
        "exit",
        "int gi0/24",
        "sw mo tr",
        "sw tr al vl 10,20",
        "end",
    ] {
        run(&mut switch, &mut session, line).unwrap();
    }
    let rendered = switch.running_config().render();
    assert!(rendered.contains("vlan 10\n name USERS\n"));
    assert!(rendered.contains(" switchport access vlan 10\n"));
    assert!(rendered.contains(" switchport trunk allowed vlan 10,20\n"));

    let mut restored = Device::new(DeviceId(7), "SW1", DeviceType::Switch).unwrap();
    restored.add_physical_interface("gi0/1").unwrap();
    restored.add_physical_interface("gi0/24").unwrap();
    load_configuration(&mut restored, &rendered).unwrap();
    assert_eq!(restored, switch);
    assert!(parse("vlan 0", CliMode::GlobalConfiguration).is_err());
}

#[test]
fn layer3_switch_ports_change_between_routed_and_switchport_modes() {
    let mut switch = Device::new(DeviceId(8), "CORE", DeviceType::Layer3Switch).unwrap();
    switch.add_physical_interface("gi0/0").unwrap();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    run(&mut switch, &mut session, "ip routi").unwrap();
    assert!(switch.ipv4_forwarding_enabled());
    run(&mut switch, &mut session, "int gi0/0").unwrap();
    assert!(
        run(
            &mut switch,
            &mut session,
            "ip address 10.0.0.1 255.255.255.0"
        )
        .is_err()
    );
    run(&mut switch, &mut session, "no sw").unwrap();
    run(
        &mut switch,
        &mut session,
        "ip address 10.0.0.1 255.255.255.0",
    )
    .unwrap();
    run(&mut switch, &mut session, "switchport mode access").unwrap();
    assert!(
        run(
            &mut switch,
            &mut session,
            "ip address 10.0.0.1 255.255.255.0"
        )
        .is_err()
    );
    run(&mut switch, &mut session, "no sw").unwrap();
    run(
        &mut switch,
        &mut session,
        "ip address 10.0.0.1 255.255.255.0",
    )
    .unwrap();
    run(&mut switch, &mut session, "end").unwrap();
    let rendered = switch.running_config().render();
    assert!(rendered.contains("ip routing\n"));
    let mut restored = Device::new(DeviceId(8), "CORE", DeviceType::Layer3Switch).unwrap();
    restored.add_physical_interface("gi0/0").unwrap();
    load_configuration(&mut restored, &rendered).unwrap();
    assert_eq!(restored, switch);
}

#[test]
fn interface_ranges_configure_catalyst_ports_and_status_tables() {
    let mut switch = Device::new(DeviceId(9), "ACCESS", DeviceType::Switch).unwrap();
    for port in 1..=4 {
        switch
            .add_physical_interface(&format!("gi1/0/{port}"))
            .unwrap();
    }
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    run(&mut switch, &mut session, "vlan 10").unwrap();
    run(&mut switch, &mut session, "name USERS").unwrap();
    run(&mut switch, &mut session, "exit").unwrap();
    run(&mut switch, &mut session, "int range gi1/0/1 - 3").unwrap();
    assert!(matches!(
        session.mode,
        CliMode::InterfaceRangeConfiguration(_, _)
    ));
    assert_eq!(
        session.prompt(switch.hostname()),
        "ACCESS(config-if-range)# "
    );
    for command in [
        "description USER-ACCESS",
        "switchport mode access",
        "switchport access vlan 10",
        "shutdown",
    ] {
        run(&mut switch, &mut session, command).unwrap();
    }
    run(&mut switch, &mut session, "end").unwrap();
    for port in 1..=3 {
        let id = switch
            .find_interface(&format!("GigabitEthernet1/0/{port}"))
            .unwrap();
        let config = &switch.running_config().interfaces[&id];
        assert_eq!(config.description, "USER-ACCESS");
        assert_eq!(config.admin_state, AdminState::Down);
        assert_eq!(
            config.switchport.as_ref().unwrap().access_vlan,
            VlanId::new(10).unwrap()
        );
    }
    let fourth = switch.find_interface("GigabitEthernet1/0/4").unwrap();
    assert_eq!(
        switch.running_config().interfaces[&fourth].admin_state,
        AdminState::Up
    );
    let status = run(&mut switch, &mut session, "show interfaces status")
        .unwrap()
        .output;
    assert!(status.contains("GigabitEthernet1/0/1"));
    assert!(status.contains("disabled"));
    let vlans = run(&mut switch, &mut session, "sh vlan br").unwrap().output;
    assert!(vlans.contains("10   USERS"));
    assert!(vlans.contains("GigabitEthernet1/0/3"));
    assert!(parse("int range gi1/0/4-1", CliMode::GlobalConfiguration).is_err());
}

#[test]
fn ospf_configuration_and_show_commands_use_the_command_tree() {
    let mut router = Device::standalone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    run(&mut router, &mut session, "router ospf 10").unwrap();
    assert_eq!(
        session.mode,
        CliMode::RouterConfiguration(RoutingProtocol::Ospf)
    );
    run(&mut router, &mut session, "net 10.0.0.0 0.0.0.255 ar 0").unwrap();
    run(&mut router, &mut session, "end").unwrap();
    for command in ["sh ip ospf nei", "sh ip ospf int", "sh ip ospf data"] {
        run(&mut router, &mut session, command).unwrap();
    }
    assert_eq!(
        parse("sh span", CliMode::PrivilegedExec).unwrap(),
        ParsedInput::Command(Command::ShowSpanningTree)
    );
    let rendered = router.running_config().render();
    assert!(rendered.contains("router ospf 10\n network 10.0.0.0 0.0.0.255 area 0\n"));
    let mut restored = Device::standalone();
    load_configuration(&mut restored, &rendered).unwrap();
    assert_eq!(restored, router);
}

#[test]
fn standard_access_lists_configure_render_and_replay() {
    let mut router = Device::standalone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    for line in [
        "access-list 10 deny host 192.0.2.1",
        "access-list 10 permit any",
        "int gi0/0",
        "ip access-group 10 in",
        "end",
    ] {
        run(&mut router, &mut session, line).unwrap();
    }
    let shown = run(&mut router, &mut session, "sh access-lists")
        .unwrap()
        .output;
    assert!(shown.contains("Standard IP access list 10"));
    assert!(shown.contains("deny 192.0.2.1 0.0.0.0"));
    let rendered = router.running_config().render();
    assert!(rendered.contains("access-list 10 permit 0.0.0.0 255.255.255.255"));
    assert!(rendered.contains(" ip access-group 10 in"));

    let mut restored = Device::standalone();
    load_configuration(&mut restored, &rendered).unwrap();
    assert_eq!(restored, router);
    assert_eq!(
        parse(
            "ip access-group 10 o",
            CliMode::InterfaceConfiguration(InterfaceId(1))
        )
        .unwrap(),
        ParsedInput::Command(Command::SetAccessGroup {
            id: rios_config::AccessListId::new(10).unwrap(),
            direction: AccessListDirection::Out,
        })
    );
    assert!(parse("access-list 100 permit any", CliMode::GlobalConfiguration).is_err());
    assert_eq!(
        suggestions("access-list 10 ", CliMode::GlobalConfiguration, &[]).unwrap()[0].word,
        "permit|deny"
    );
}

#[test]
fn dhcp_configuration_uses_dedicated_pool_mode_and_replays() {
    let mut router = Device::standalone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    run(&mut router, &mut session, "ip dhcp pool LAN").unwrap();
    assert!(matches!(session.mode, CliMode::DhcpPoolConfiguration(_)));
    for line in [
        "network 192.168.1.0 255.255.255.0",
        "default-router 192.168.1.1",
        "exit",
        "interface gi0/0",
        "ip address dhcp",
        "no shutdown",
        "end",
    ] {
        run(&mut router, &mut session, line).unwrap();
    }
    let rendered = router.running_config().render();
    assert!(rendered.contains("ip dhcp pool LAN\n network 192.168.1.0 255.255.255.0"));
    assert!(rendered.contains(" default-router 192.168.1.1"));
    assert!(rendered.contains("interface GigabitEthernet0/0\n ip address dhcp"));
    assert!(
        run(&mut router, &mut session, "show ip dhcp binding")
            .unwrap()
            .output
            .contains("IP address")
    );

    let mut restored = Device::standalone();
    load_configuration(&mut restored, &rendered).unwrap();
    assert_eq!(restored, router);
    assert_eq!(
        parse(
            "ip address dh",
            CliMode::InterfaceConfiguration(InterfaceId(1))
        )
        .unwrap(),
        ParsedInput::Command(Command::SetIpv4Dhcp)
    );
}

#[test]
fn nat_overload_configuration_renders_and_replays() {
    let mut router = Device::standalone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    for line in [
        "access-list 1 permit 10.0.0.0 0.0.0.255",
        "interface gi0/0",
        "ip nat inside",
        "exit",
        "interface gi0/1",
        "ip nat outside",
        "exit",
        "ip nat inside source list 1 interface gi0/1 overload",
        "end",
    ] {
        run(&mut router, &mut session, line).unwrap();
    }
    let rendered = router.running_config().render();
    assert!(rendered.contains(" ip nat inside"));
    assert!(rendered.contains(" ip nat outside"));
    assert!(rendered.contains("ip nat inside source list 1 interface GigabitEthernet0/1 overload"));
    assert!(
        run(&mut router, &mut session, "show ip nat translations")
            .unwrap()
            .output
            .contains("Inside global")
    );

    let mut restored = Device::standalone();
    load_configuration(&mut restored, &rendered).unwrap();
    assert_eq!(restored, router);
    assert!(
        parse(
            "ip nat in so l 1 int gi0/1 ov",
            CliMode::GlobalConfiguration
        )
        .is_ok()
    );
}

#[test]
fn help_validates_arguments_and_completes_separated_interfaces() {
    assert_eq!(
        suggestions("int gi0/0 ", CliMode::GlobalConfiguration, &[]).unwrap()[0].word,
        "<cr>"
    );
    assert!(suggestions("enable extra ", CliMode::UserExec, &[]).is_err());
    assert!(
        suggestions(
            "ip address bad ",
            CliMode::InterfaceConfiguration(InterfaceId(1)),
            &[]
        )
        .is_err()
    );
    assert!(suggestions("int missing ", CliMode::GlobalConfiguration, &[]).is_err());
    assert_eq!(
        suggestions(
            "int gi 0/",
            CliMode::GlobalConfiguration,
            &["GigabitEthernet0/0".into()]
        )
        .unwrap()[0]
            .word,
        "0/0"
    );
}

#[test]
fn descriptions_with_question_marks_replay_as_data() {
    let mut original = Device::standalone();
    original
        .set_description(InterfaceId(1), "  WAN café?  ")
        .unwrap();
    let mut restored = Device::standalone();
    load_configuration(&mut restored, &original.running_config().render()).unwrap();
    assert_eq!(original, restored);
    let error = ParseError::Invalid {
        offset: 1,
        reason: "invalid".into(),
    };
    assert!(error.render("R# ", "é").starts_with("   ^"));
}

#[test]
fn do_and_common_no_forms_use_contextual_commands() {
    let mut device = Device::new(DeviceId(10), "CORE", DeviceType::Layer3Switch).unwrap();
    device.add_physical_interface("gi0/1").unwrap();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    for command in [
        "vlan 10",
        "exit",
        "ip route 192.0.2.0 255.255.255.0 10.0.0.2",
    ] {
        run(&mut device, &mut session, command).unwrap();
    }
    run(&mut device, &mut session, "interface gi0/1").unwrap();
    for command in [
        "description UPLINK",
        "no switchport",
        "ip address 10.0.0.1 255.255.255.0",
    ] {
        run(&mut device, &mut session, command).unwrap();
    }
    let output = run(&mut device, &mut session, "do sh ip int br")
        .unwrap()
        .output;
    assert!(output.contains("10.0.0.1"));
    assert!(matches!(session.mode, CliMode::InterfaceConfiguration(_)));
    for command in ["no description", "no ip address", "switchport", "exit"] {
        run(&mut device, &mut session, command).unwrap();
    }
    for command in ["no ip route 192.0.2.0 255.255.255.0 10.0.0.2", "no vlan 10"] {
        run(&mut device, &mut session, command).unwrap();
    }
    let rendered = device.running_config().render();
    for removed in [
        "description UPLINK",
        "ip address 10.0.0.1",
        "ip route",
        "vlan 10",
    ] {
        assert!(!rendered.contains(removed));
    }
    assert!(rendered.contains(" switchport mode access"));
    assert!(parse("do configure terminal", session.mode).is_err());
    let ParsedInput::Help(help) = parse("do show ip ?", session.mode).unwrap() else {
        panic!("expected contextual help")
    };
    for command in ["arp", "interface", "route"] {
        assert!(help.contains(command));
    }
}

#[test]
fn dot1q_subinterface_configuration_replays_and_checks_duplicates() {
    let mut router = Device::standalone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    for line in [
        "int gi0/0",
        "no shut",
        "int gi0/0.10",
        "enc dot 10",
        "ip address 10.0.10.1 255.255.255.0",
    ] {
        run(&mut router, &mut session, line).unwrap();
    }
    assert_eq!(session.prompt(router.hostname()), "R1(config-subif)# ");
    let ParsedInput::Help(help) = parse("enc dot 10 ?", session.mode).unwrap() else {
        panic!()
    };
    assert!(help.contains("native") && help.contains("<cr>"));
    run(&mut router, &mut session, "int gi0/0.20").unwrap();
    assert!(run(&mut router, &mut session, "enc dot 10").is_err());
    run(&mut router, &mut session, "enc dot 20 nat").unwrap();
    run(
        &mut router,
        &mut session,
        "ip address 10.0.20.1 255.255.255.0",
    )
    .unwrap();
    let mut restored = Device::standalone();
    load_configuration(&mut restored, &router.running_config().render()).unwrap();
    assert_eq!(restored, router);
    for bad in ["int gi0/0.0", "int lo0.1", "int gi0/0.1.2"] {
        assert!(parse(bad, session.mode).is_err());
    }
    assert!(run(&mut router, &mut session, "int gi0/99.10").is_err());
}

#[test]
fn named_and_numbered_extended_acls_parse_help_replay_and_delete() {
    use rios_config::{AclEntry, AclKind, AclProtocol, PortMatch};
    let mut router = Device::standalone();
    let mut session = CliSession {
        mode: CliMode::GlobalConfiguration,
    };
    for line in [
        "ip access-list ext WEB-IN",
        "5 remark inbound service policy",
        "10 permit tcp 10.10.0.0 0.0.255.255 host 192.168.1.10 eq 443",
        "20 permit icmp any any",
        "30 deny ip any any log",
    ] {
        run(&mut router, &mut session, line).unwrap();
    }
    assert_eq!(session.prompt(router.hostname()), "R1(config-ext-nacl)# ");
    let ParsedInput::Help(help) =
        parse("40 permit tcp any host 192.0.2.1 ?", session.mode).unwrap()
    else {
        panic!()
    };
    for word in ["eq", "range", "log", "<cr>"] {
        assert!(help.contains(word));
    }
    run(&mut router, &mut session, "no 20").unwrap();
    assert!(
        !router.running_config().named_access_lists[&router.acl_id("WEB-IN").unwrap()]
            .entries
            .contains_key(&20)
    );
    for line in [
        "exit",
        "int gi0/0",
        "ip access-group WEB-IN in",
        "exit",
        "access-list 101 permit udp any range 1000 2000 any eq 53",
    ] {
        run(&mut router, &mut session, line).unwrap();
    }
    let extended = &router.running_config().named_access_lists[&router.acl_id("101").unwrap()];
    assert_eq!(extended.kind, AclKind::Extended);
    assert!(matches!(
        extended.entries[&10],
        AclEntry::Rule {
            protocol: AclProtocol::Udp,
            source_port: PortMatch::Range(1000, 2000),
            destination_port: PortMatch::Eq(53),
            ..
        }
    ));
    let mut restored = Device::standalone();
    load_configuration(&mut restored, &router.running_config().render()).unwrap();
    assert_eq!(restored, router);
    run(&mut router, &mut session, "ip access-list extended WEB-IN").unwrap();
    assert!(parse("40 permit tcp any any range 2000 1000", session.mode).is_err());
    assert!(parse("40 permit ip any any eq 80", session.mode).is_err());
}
