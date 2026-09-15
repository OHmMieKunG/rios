use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn command_help_lists_frontends() {
    let output = Command::new(env!("CARGO_BIN_EXE_rios"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for command in ["lab", "ssh", "telnet"] {
        assert!(text.contains(command), "missing {command}:\n{text}");
    }
}
#[test]
fn standalone_binary_session() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rios"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"enable\nconf t\nhostname EDGE-R1\ninterface gigabitEthernet0/0\nip address 10.0.0.1 255.255.255.0\nno shutdown\nend\nsh ip int br\nshow running-config\nwrite memory\nshow startup-config\nhello\nexit\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "RIOS Network Simulator",
        "R1> enable",
        "EDGE-R1(config-if)#",
        "GigabitEthernet0/0",
        "10.0.0.1",
        "administratively down",
        "hostname EDGE-R1\n!\n",
        " ip address 10.0.0.1 255.255.255.0\n no shutdown",
        "[OK]",
        "% Invalid input detected",
        "Connection closed.",
    ] {
        assert!(text.contains(expected), "missing {expected}:\n{text}");
    }
    assert_eq!(text.matches("hostname EDGE-R1\n!\n").count(), 2);
}

#[test]
fn lab_shell_reuses_device_cli_and_updates_both_carriers() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rios"))
        .args([
            "lab",
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/two-routers.yaml"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"devices\nconnect R1\nenable\nconf t\nhostname EDGE\nint gi0/0\nno shut\nend\nexit\nconnect R2\nenable\nconf t\nint gi0/0\nno shut\nend\nsh ip int br\nexit\nlinks\nconnect R1\nsh ip int br\nexit\ntrace on\nstep\nrun 100\ntrace off\nexit\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Topology loaded.",
        "rios> devices",
        "EDGE(config-if)#",
        "R2(config-if)#",
        "rios> connect R1",
        "EDGE> sh ip int br",
        "protocol up, delay 1 ms",
        "Packet tracing enabled.",
        "No pending events.",
        "00:00:00.100",
        "Packet tracing disabled.",
    ] {
        assert!(text.contains(expected), "missing {expected}:\n{text}");
    }
    let up_rows = text
        .lines()
        .filter(|s| s.starts_with("GigabitEthernet0/0") && s.trim_end().ends_with("up"))
        .count();
    assert_eq!(up_rows, 2);
    assert_eq!(text.matches("Connection closed.").count(), 3);
}

#[test]
fn missing_topology_fails_before_entering_shell() {
    let output = Command::new(env!("CARGO_BIN_EXE_rios"))
        .args(["lab", "/nonexistent/rios-topology.yaml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Topology loaded"));
}

#[test]
fn cli_ping_populates_arp_and_shows_connected_route() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rios"))
        .args([
            "lab",
            concat!(env!("CARGO_MANIFEST_DIR"), "/examples/two-routers.yaml"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"connect R1\nenable\nconf t\nint gi0/0\nip address 10.0.0.1 255.255.255.0\nno shut\nend\nexit\nconnect R2\nenable\nconf t\nint gi0/0\nip address 10.0.0.2 255.255.255.0\nno shut\nend\nexit\nconnect R1\nenable\nshow ip route\nping 10.0.0.2\nshow arp\nexit\nexit\n",
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "C    10.0.0.0/24 is directly connected, GigabitEthernet0/0",
        "!!!!!",
        "Success rate is 100 percent (5/5)",
        "Internet  10.0.0.2",
    ] {
        assert!(text.contains(expected), "missing {expected}:\n{text}");
    }
}

#[test]
fn write_memory_survives_process_restart() {
    let state =
        std::env::temp_dir().join(format!("rios-session-state-{}.json", std::process::id()));
    let topology = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/two-routers.yaml");
    let run = |commands: &[u8]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rios"))
            .args(["lab", topology])
            .env("RIOS_STATE_FILE", &state)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(commands).unwrap();
        child.wait_with_output().unwrap()
    };

    let saved = run(b"connect R1\nenable\nconf t\nhostname SAVED\nend\nwrite memory\nexit\nexit\n");
    assert!(
        saved.status.success(),
        "{}",
        String::from_utf8_lossy(&saved.stderr)
    );
    assert!(String::from_utf8_lossy(&saved.stdout).contains("[OK]"));

    let restored = run(b"devices\nexit\n");
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert!(String::from_utf8_lossy(&restored.stdout).contains("hostname SAVED"));
    std::fs::remove_file(state).unwrap();
}

#[test]
fn interactive_builder_saves_and_reloads_a_lab() {
    let stem = std::env::temp_dir().join(format!("rios-builder-{}", std::process::id()));
    let topology = stem.with_extension("yaml");
    let state = stem.with_extension("json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rios"))
        .args(["lab"])
        .env("RIOS_STATE_FILE", &state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            format!(
                "spawn router R1 2\nspawn switch SW1 2\nlink R1:GigabitEthernet0/0 SW1:GigabitEthernet0/0\nlink-state 1 down\nlink-state 1 up\nunlink 1\nlink R1:GigabitEthernet0/0 SW1:GigabitEthernet0/0\nconnect R1\nenable\nconf t\nint gi0/0\nip address 10.0.0.1 255.255.255.0\nno shut\nend\nexit\nsave {}\nexit\n",
                topology.display()
            )
            .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("Topology and startup configuration saved")
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Removed link 1."));

    let mut restored = Command::new(env!("CARGO_BIN_EXE_rios"))
        .args(["lab", topology.to_str().unwrap()])
        .env("RIOS_STATE_FILE", &state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    restored
        .stdin
        .take()
        .unwrap()
        .write_all(b"connect R1\nenable\nshow ip interface brief\nexit\nexit\n")
        .unwrap();
    let restored_output = restored.wait_with_output().unwrap();
    assert!(restored_output.status.success());
    let text = String::from_utf8_lossy(&restored_output.stdout);
    assert!(text.contains("10.0.0.1"), "{text}");
    assert!(text.contains("SW1"), "{text}");
    std::fs::remove_file(topology).unwrap();
    std::fs::remove_file(state).unwrap();
}

#[test]
fn lab_shell_uses_unique_abbreviations_and_contextual_help() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rios"))
        .arg("lab")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"sp?\nsp ?\nsp rou?\nsp rou ?\nsp rou R1 ?\nsp rou R1\nsp l3 CORE rj 2 sfp 1 sfp+ 1 ser 1 con 1\ndev\ncon CORE\nena\nsh int\nexit\nl\nexit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "spawn                Create a router",
        "router               Create a router",
        "<name>               Device name",
        "<ports>              Physical port count",
        "Created router R1 with 2 ports.",
        "Created l3-switch CORE with 6 ports.",
        "R1               Router",
        "CORE             L3 Switch",
        "Hardware is SFP+",
        "Serial0/0",
        "Console0",
        "% Ambiguous command: \"l\"",
    ] {
        assert!(text.contains(expected), "missing {expected}:\n{text}");
    }
}

#[test]
fn lab_links_expose_transmission_policy_and_counters() {
    let output = Command::new(env!("CARGO_BIN_EXE_rios"))
        .args(["lab", "examples/two-routers.yaml"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let mut child = output.unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"links\nexit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("bandwidth unlimited"));
    assert!(text.contains("queue 100 packets/direction"));
    assert!(text.contains("A->B: queued 0, TX 0, RX 0"));
}

#[test]
fn capture_commands_create_and_close_pcapng() {
    let path = std::env::temp_dir().join(format!("rios-cli-capture-{}.pcapng", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut child = Command::new(env!("CARGO_BIN_EXE_rios"))
        .args(["lab", "examples/two-routers.yaml"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let commands = format!(
        "cap ?\ncap start {} int R1:gi0/0\ncap stop\nexit\n",
        path.display()
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(commands.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Capture started:"));
    assert!(text.contains("Capture stopped."));
    assert!(text.contains("Stop and flush capture"));
    assert_eq!(
        &std::fs::read(&path).unwrap()[..4],
        &0x0a0d0d0au32.to_le_bytes()
    );
    std::fs::remove_file(path).unwrap();
}
