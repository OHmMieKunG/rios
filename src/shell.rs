use crate::app::App;
use rios_cli::Suggestion;
use rios_device::{DeviceType, InterfaceMedia};
use rios_simulator::LinkState;
use std::path::Path;

const COMMANDS: &[(&str, &str)] = &[
    ("spawn", "Create a router, switch, or host"),
    ("link", "Connect two physical interfaces"),
    ("unlink", "Remove a virtual link"),
    ("link-state", "Set a virtual link up or down"),
    ("save", "Save the lab topology and configuration"),
    ("devices", "List devices"),
    ("connect", "Connect to a device"),
    ("links", "Show virtual links"),
    ("trace", "Enable or disable packet tracing"),
    ("capture", "Record Ethernet packets in a PCAPNG file"),
    ("http", "Fetch / over simulated TCP from a device"),
    ("tcp-echo", "Probe a simulated TCP echo service"),
    ("udp-echo", "Probe a simulated UDP echo service"),
    ("step", "Process one event"),
    ("run", "Advance to an absolute simulated millisecond"),
    ("help", "Show lab commands"),
    ("exit", "Exit simulator"),
];
const CAPTURE_ACTIONS: &[(&str, &str)] = &[
    ("start", "Start capture"),
    ("stop", "Stop and flush capture"),
];
const CAPTURE_FILTERS: &[(&str, &str)] = &[
    ("device", "Capture one device"),
    ("interface", "Capture one interface"),
];
const DEVICE_TYPES: &[(&str, &str)] = &[
    ("router", "Create a router"),
    ("switch", "Create a Layer 2 switch"),
    ("l3-switch", "Create a routed Layer 3 switch"),
    ("host", "Create a host"),
];
const PORT_MEDIA: &[(&str, &str)] = &[
    ("rj45", "Copper GigabitEthernet port"),
    ("sfp", "1 Gbit/s SFP Ethernet port"),
    ("sfp+", "10 Gbit/s SFP+ Ethernet port"),
    ("serial", "Serial port (inventory only)"),
    ("console", "Console port (management only)"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResolveError {
    Invalid,
    Ambiguous,
}

fn resolve<'a>(token: &str, candidates: &'a [(&str, &str)]) -> Result<&'a str, ResolveError> {
    if let Some((word, _)) = candidates
        .iter()
        .find(|(word, _)| word.eq_ignore_ascii_case(token))
    {
        return Ok(word);
    }
    let lowercase = token.to_ascii_lowercase();
    let mut matches = candidates
        .iter()
        .filter(|(word, _)| word.starts_with(&lowercase));
    match (matches.next(), matches.next()) {
        (Some((word, _)), None) => Ok(word),
        (Some(_), Some(_)) => Err(ResolveError::Ambiguous),
        _ => Err(ResolveError::Invalid),
    }
}

fn matching(candidates: &[(&str, &str)], partial: &str, start: usize) -> Vec<Suggestion> {
    let partial = partial.to_ascii_lowercase();
    candidates
        .iter()
        .filter(|(word, _)| word.starts_with(&partial))
        .map(|(word, help)| Suggestion {
            word: (*word).into(),
            help: (*help).into(),
            start,
        })
        .collect()
}

fn placeholder(word: &str, help: &str, start: usize) -> Vec<Suggestion> {
    vec![Suggestion {
        word: word.into(),
        help: help.into(),
        start,
    }]
}

pub fn complete(input: &str, names: &[String]) -> Vec<Suggestion> {
    let tokens: Vec<_> = input.split_whitespace().collect();
    let trailing = input.chars().last().is_some_and(char::is_whitespace);
    let (prior, partial, start) = if trailing || tokens.is_empty() {
        (&tokens[..], "", input.len())
    } else {
        (
            &tokens[..tokens.len() - 1],
            *tokens.last().unwrap(),
            input.rfind(tokens.last().unwrap()).unwrap(),
        )
    };
    if prior.is_empty() {
        return matching(COMMANDS, partial, start);
    }
    let Ok(command) = resolve(prior[0], COMMANDS) else {
        return matching(COMMANDS, prior[0], 0);
    };
    let args = &prior[1..];
    match command {
        "http" | "tcp-echo" | "udp-echo" if args.is_empty() => names
            .iter()
            .filter(|name| {
                name.to_ascii_lowercase()
                    .starts_with(&partial.to_ascii_lowercase())
            })
            .map(|name| Suggestion {
                word: name.clone(),
                help: "Source device".into(),
                start,
            })
            .collect(),
        "http" | "tcp-echo" | "udp-echo" if args.len() == 1 => {
            placeholder("<ipv4>", "Destination address", start)
        }
        "http" | "tcp-echo" | "udp-echo" if args.len() == 2 => {
            placeholder("<port>", "Optional service port (HTTP 80, echo 7)", start)
        }
        "capture" if args.is_empty() => matching(CAPTURE_ACTIONS, partial, start),
        "capture" if resolve(args[0], CAPTURE_ACTIONS) == Ok("start") && args.len() == 1 => {
            placeholder("<path>", "New PCAPNG file", start)
        }
        "capture" if resolve(args[0], CAPTURE_ACTIONS) == Ok("start") && args.len() == 2 => {
            let mut choices = matching(CAPTURE_FILTERS, partial, start);
            if partial.is_empty() {
                choices.extend(placeholder("<cr>", "Capture all devices", start));
            }
            choices
        }
        "capture" if args.len() == 3 => {
            placeholder("<name>", "Device name or device:interface", start)
        }
        "spawn" if args.is_empty() => matching(DEVICE_TYPES, partial, start),
        "spawn" if args.len() == 1 && resolve(args[0], DEVICE_TYPES).is_err() => {
            matching(DEVICE_TYPES, args[0], input.find(args[0]).unwrap_or(start))
        }
        "spawn" if args.len() == 1 => placeholder("<name>", "Device name", start),
        "spawn" if args.len() == 2 => {
            let mut suggestions = placeholder("<ports>", "Physical port count", start);
            suggestions.extend(matching(PORT_MEDIA, partial, start));
            suggestions.push(Suggestion {
                word: "<cr>".into(),
                help: "Use the default port count".into(),
                start,
            });
            suggestions
        }
        "spawn" if args.len() == 3 && args[2].parse::<usize>().is_ok() => {
            placeholder("<cr>", "Create device with this port count", start)
        }
        "spawn" if args.len() >= 3 && args.len() % 2 == 1 => {
            placeholder("<count>", "Number of ports using this media", start)
        }
        "spawn" if args.len() >= 4 && args.len() % 2 == 0 => {
            let mut suggestions = matching(PORT_MEDIA, partial, start);
            suggestions.push(Suggestion {
                word: "<cr>".into(),
                help: "Create device with this port inventory".into(),
                start,
            });
            suggestions
        }
        "connect" if args.is_empty() => names
            .iter()
            .filter(|name| {
                name.to_ascii_lowercase()
                    .starts_with(&partial.to_ascii_lowercase())
            })
            .map(|name| Suggestion {
                word: name.clone(),
                help: "Device name or first endpoint".into(),
                start,
            })
            .collect(),
        "connect" if args.len() == 1 => placeholder(
            "<endpoint>",
            "Second endpoint, or <cr> to open device",
            start,
        ),
        "link" if args.is_empty() => placeholder("<endpoint>", "First endpoint", start),
        "link" if args.len() == 1 => placeholder("<endpoint>", "Second endpoint", start),
        "link" if args.len() == 2 => placeholder("<delay-ms>", "Optional link delay", start),
        "unlink" if args.is_empty() => placeholder("<link-id>", "Link number", start),
        "link-state" if args.is_empty() => placeholder("<link-id>", "Link number", start),
        "link-state" if args.len() == 1 => matching(
            &[("up", "Enable cable"), ("down", "Disable cable")],
            partial,
            start,
        ),
        "save" if args.is_empty() => placeholder("<path>", "Topology output path", start),
        "trace" if args.is_empty() => matching(
            &[("on", "Enable tracing"), ("off", "Disable tracing")],
            partial,
            start,
        ),
        "run" if args.is_empty() => {
            placeholder("<milliseconds>", "Absolute simulation deadline", start)
        }
        _ => placeholder("<cr>", "", start),
    }
}
pub fn process(app: &mut App, input: &str) -> bool {
    let input = input.trim();
    if input.ends_with('?') {
        for suggestion in complete(input.strip_suffix('?').unwrap(), &app.completion().names) {
            println!("  {:<20} {}", suggestion.word, suggestion.help);
        }
        return false;
    }
    let tokens: Vec<_> = input.split_whitespace().collect();
    if tokens.is_empty() {
        return false;
    }
    let command = match resolve(tokens[0], COMMANDS) {
        Ok(command) => command,
        Err(ResolveError::Ambiguous) => {
            println!("% Ambiguous command: \"{input}\"");
            return false;
        }
        Err(ResolveError::Invalid) => {
            println!("% Invalid lab command. Use help or ?.");
            return false;
        }
    };
    let args = &tokens[1..];
    let result = match (command, args) {
        ("capture", args) => capture(app, args),
        ("http" | "tcp-echo" | "udp-echo", args) => service_probe(app, command, args),
        ("spawn", args) => spawn(app, args),
        ("connect", [first, second]) => link(app, first, second, 1),
        ("link", [first, second]) => link(app, first, second, 1),
        ("link", [first, second, delay]) => match delay.parse::<u64>() {
            Ok(delay) => link(app, first, second, delay),
            Err(_) => {
                println!("% Delay must be an integer number of milliseconds.");
                Ok(())
            }
        },
        ("unlink", [id]) => match id.parse::<u64>() {
            Ok(id) => app.unlink(id).map(|()| {
                println!("Removed link {id}.");
            }),
            Err(_) => {
                println!("% Link ID must be an integer.");
                Ok(())
            }
        },
        ("link-state", [id, state]) => match (
            id.parse::<u64>(),
            resolve(state, &[("up", ""), ("down", "")]),
        ) {
            (Ok(id), Ok(state)) => {
                let state = if state == "up" {
                    LinkState::Up
                } else {
                    LinkState::Down
                };
                app.set_link_state(id, state).map(|()| {
                    println!("Link {id} is {state:?}.");
                })
            }
            (Err(_), _) => {
                println!("% Link ID must be an integer.");
                Ok(())
            }
            (_, _) => {
                println!("% Link state must be up or down.");
                Ok(())
            }
        },
        ("save", [path]) => match app.save_topology(Path::new(path)) {
            Ok(()) => {
                println!("Topology and startup configuration saved to {path}.");
                Ok(())
            }
            Err(error) => {
                println!("% Could not save lab: {error}");
                Ok(())
            }
        },
        ("devices", []) => {
            for (name, id) in app.lab.device_names() {
                let device = app.lab.device(id).unwrap();
                println!(
                    "  {name:<16} {} (hostname {})",
                    device.device_type(),
                    device.hostname()
                );
            }
            Ok(())
        }
        ("connect", [name]) => app.connect(name),
        ("links", []) => {
            for link in app.lab.links().values() {
                println!(
                    "{}: {} <-> {}  {:?}, protocol {}, delay {} ms",
                    link.id.0,
                    app.lab.endpoint_name(link.endpoint_a),
                    app.lab.endpoint_name(link.endpoint_b),
                    link.state,
                    if link.is_active() { "up" } else { "down" },
                    link.delay_ms
                );
                println!(
                    "  bandwidth {}, jitter {} us, loss {} ppm, queue {} packets/direction",
                    link.config.bandwidth.map_or_else(
                        || "unlimited".into(),
                        |rate| format!("{} bps", rate.bits_per_second())
                    ),
                    link.config.jitter_us,
                    link.config.loss_ppm,
                    link.config.queue_packets
                );
                for (name, direction) in [("A->B", &link.a_to_b), ("B->A", &link.b_to_a)] {
                    println!(
                        "  {name}: queued {}, TX {}, RX {}, queue drops {}, loss drops {}, flap drops {}",
                        direction.queued(app.lab.now()),
                        direction.counters.tx_packets,
                        direction.counters.rx_packets,
                        direction.counters.queue_drops,
                        direction.counters.loss_drops,
                        direction.counters.changed_drops
                    );
                }
            }
            Ok(())
        }
        ("trace", [state]) if resolve(state, &[("on", ""), ("off", "")]) == Ok("on") => {
            app.lab.set_tracing(true);
            println!("Packet tracing enabled.");
            Ok(())
        }
        ("trace", [state]) if resolve(state, &[("on", ""), ("off", "")]) == Ok("off") => {
            app.lab.set_tracing(false);
            println!("Packet tracing disabled.");
            Ok(())
        }
        ("step", []) => app.step(),
        ("run", [time]) => match time.parse::<u64>() {
            Ok(time) => app.run_until(time),
            Err(_) => {
                println!("% Expected absolute simulated milliseconds.");
                Ok(())
            }
        },
        ("help", []) => {
            for (word, help) in COMMANDS {
                println!("  {word:<12} {help}");
            }
            Ok(())
        }
        ("exit", []) => return true,
        _ => {
            println!("% Incomplete or invalid lab command. Use ? for available syntax.");
            Ok(())
        }
    };
    if let Err(error) = result {
        println!("% {error}");
    }
    false
}

fn spawn(app: &mut App, args: &[&str]) -> Result<(), rios_topology::LabError> {
    if args.len() < 2 {
        println!("% Incomplete command. Expected device type and name.");
        return Ok(());
    }
    let kind = args[0];
    let name = args[1];
    let kind = match resolve(kind, DEVICE_TYPES) {
        Ok(kind) => kind,
        Err(ResolveError::Ambiguous) => {
            println!("% Ambiguous device type: \"{kind}\"");
            return Ok(());
        }
        Err(ResolveError::Invalid) => {
            println!("% Device type must be router, switch, l3-switch, or host.");
            return Ok(());
        }
    };
    let (device_type, default_ports) = match kind {
        "router" => (DeviceType::Router, vec![(InterfaceMedia::Rj45, 2)]),
        "switch" => (DeviceType::Switch, vec![(InterfaceMedia::Rj45, 4)]),
        "l3-switch" => (DeviceType::Layer3Switch, vec![(InterfaceMedia::Rj45, 4)]),
        "host" => (DeviceType::Host, vec![(InterfaceMedia::Rj45, 1)]),
        _ => unreachable!(),
    };
    let ports = match &args[2..] {
        [] => default_ports,
        [count] if count.parse::<usize>().is_ok() => {
            vec![(InterfaceMedia::Rj45, count.parse().unwrap())]
        }
        specifications if specifications.len() % 2 == 0 => {
            let mut ports = Vec::new();
            for [medium, count] in specifications.as_chunks::<2>().0 {
                let media = match resolve(medium, PORT_MEDIA) {
                    Ok("rj45") => InterfaceMedia::Rj45,
                    Ok("sfp") => InterfaceMedia::Sfp,
                    Ok("sfp+") => InterfaceMedia::SfpPlus,
                    Ok("serial") => InterfaceMedia::Serial,
                    Ok("console") => InterfaceMedia::Console,
                    Ok(_) => unreachable!(),
                    Err(ResolveError::Ambiguous) => {
                        println!("% Ambiguous port media: \"{medium}\"");
                        return Ok(());
                    }
                    Err(ResolveError::Invalid) => {
                        println!("% Unknown port media: \"{medium}\"");
                        return Ok(());
                    }
                };
                let Ok(count) = count.parse::<usize>() else {
                    println!("% Port count must be a positive integer.");
                    return Ok(());
                };
                ports.push((media, count));
            }
            ports
        }
        _ => {
            println!("% Expected either <ports> or repeating <media> <count> pairs.");
            return Ok(());
        }
    };
    let total = ports
        .iter()
        .fold(0usize, |total, (_, count)| total.saturating_add(*count));
    app.spawn_with_ports(name, device_type, &ports)?;
    println!("Created {kind} {name} with {total} ports.");
    Ok(())
}

fn link(
    app: &mut App,
    first: &str,
    second: &str,
    delay: u64,
) -> Result<(), rios_topology::LabError> {
    app.link(first, second, delay)?;
    println!("Connected {first} <-> {second} (delay {delay} ms).");
    Ok(())
}

fn capture(app: &mut App, args: &[&str]) -> Result<(), rios_topology::LabError> {
    use rios_topology::{CaptureFilter, LabError};
    match args {
        [action] if resolve(action, CAPTURE_ACTIONS) == Ok("stop") => {
            app.lab.stop_capture()?;
            println!("Capture stopped.");
        }
        [action, path, rest @ ..] if resolve(action, CAPTURE_ACTIONS) == Ok("start") => {
            let filter = match rest {
                [] => CaptureFilter::All,
                [kind, name] if resolve(kind, CAPTURE_FILTERS) == Ok("device") => {
                    CaptureFilter::Device(app.lab.device_id(name)?)
                }
                [kind, name] if resolve(kind, CAPTURE_FILTERS) == Ok("interface") => {
                    CaptureFilter::Interface(app.lab.endpoint(name)?)
                }
                _ => {
                    return Err(LabError::Capture(
                        "expected [device <name> | interface <device:interface>]".into(),
                    ));
                }
            };
            app.lab.start_capture(Path::new(path), filter)?;
            println!("Capture started: {path}");
        }
        _ => {
            return Err(LabError::Capture(
                "expected start <file.pcapng> or stop".into(),
            ));
        }
    }
    Ok(())
}

fn service_probe(
    app: &mut App,
    command: &str,
    args: &[&str],
) -> Result<(), rios_topology::LabError> {
    use rios_topology::LabError;
    if !(2..=3).contains(&args.len()) {
        return Err(LabError::Protocol(
            "expected source device, IPv4 address and optional port".into(),
        ));
    }
    let device = app.lab.device_id(args[0])?;
    let address = args[1]
        .parse()
        .map_err(|_| LabError::Protocol("invalid IPv4 address".into()))?;
    let port = args
        .get(2)
        .map(|p| p.parse::<u16>())
        .transpose()
        .map_err(|_| LabError::Protocol("invalid service port".into()))?
        .unwrap_or(if command == "http" { 80 } else { 7 });
    let sent = b"RIOS echo probe";
    let response = match command {
        "http" => app.lab.http_get(device, address, port)?,
        "tcp-echo" => app.lab.tcp_echo(device, address, port, sent)?,
        _ => app
            .lab
            .udp_request(device, address, port, sent, 5000)?
            .ok_or_else(|| LabError::Protocol("UDP echo timed out".into()))?,
    };
    if command == "http" {
        println!("{}", String::from_utf8_lossy(&response));
    } else if response == sent {
        println!("Echo reply: {} bytes", response.len());
    } else {
        return Err(LabError::Protocol("echo payload mismatch".into()));
    }
    Ok(())
}
