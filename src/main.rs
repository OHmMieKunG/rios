//! Terminal and scripted frontends for the shared RIOS device CLI and virtual labs.
#![forbid(unsafe_code)]
mod app;
mod device_session;
mod remote;
mod shell;
mod ssh;
mod storage;
mod telnet;
mod terminal;
use app::App;
use clap::{Parser, Subcommand};
use rios_topology::{Lab, Topology};
use std::{
    io::{self, BufRead, IsTerminal},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(name = "rios", version, about = "Rust IOS-like Network Simulator")]
struct Arguments {
    #[command(subcommand)]
    command: Option<Frontend>,
}

#[derive(Subcommand)]
enum Frontend {
    /// Grade saved device configuration and real simulated network behavior.
    Grade {
        topology: PathBuf,
        objectives: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Open an interactive topology shell.
    Lab { topology: Option<PathBuf> },
    /// Serve one SSH listener per device.
    Ssh {
        topology: PathBuf,
        #[arg(default_value_t = 2001)]
        base_port: u16,
    },
    /// Serve one local Telnet listener per device.
    Telnet {
        topology: PathBuf,
        #[arg(default_value_t = 3001)]
        base_port: u16,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let (mut app, topology_mode, loaded_topology) = match Arguments::parse().command {
        None => (App::standalone()?, false, false),
        Some(Frontend::Grade {
            topology,
            objectives,
            json,
        }) => {
            let (mut lab, _) = load_lab(&topology)?;
            let plan = rios_topology::GradePlan::from_yaml(&std::fs::read_to_string(objectives)?)?;
            let report = plan.evaluate(&mut lab)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render());
            }
            if !report.success() {
                return Err("lab objectives failed".into());
            }
            return Ok(());
        }
        Some(Frontend::Lab { topology }) => match topology {
            Some(topology) => {
                let (lab, state) = load_lab(&topology)?;
                (App::from_lab(lab, state), true, true)
            }
            None => (App::builder(), true, false),
        },
        Some(Frontend::Ssh {
            topology,
            base_port,
        }) => {
            let (lab, state) = load_lab(&topology)?;
            println!("RIOS Network Simulator\n\nSSH device listeners:");
            tokio::runtime::Runtime::new()?.block_on(ssh::run(lab, state, base_port))?;
            return Ok(());
        }
        Some(Frontend::Telnet {
            topology,
            base_port,
        }) => {
            let (lab, state) = load_lab(&topology)?;
            println!("RIOS Network Simulator\n\nTelnet device listeners:");
            tokio::runtime::Runtime::new()?.block_on(telnet::run(lab, state, base_port))?;
            return Ok(());
        }
    };
    println!("RIOS Network Simulator\n");
    if topology_mode {
        if loaded_topology {
            println!("Topology loaded.\n\nDevices:");
        } else {
            println!(
                "Interactive lab shell. Use 'spawn' and 'save' to build a topology.\n\nDevices:"
            );
        }
        for (name, _) in app.lab.device_names() {
            println!("  {name}");
        }
        println!();
    }
    tracing::debug!(
        devices = app.lab.device_names().count(),
        "created virtual lab"
    );
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        terminal::run(&mut app)?;
    } else {
        for line in io::stdin().lock().lines() {
            let line = line?;
            println!("{}{line}", app.prompt());
            if app.process(&line) {
                break;
            }
        }
    }
    Ok(())
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    if std::env::var("RIOS_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .init();
    }
}

fn load_lab(path: &Path) -> Result<(Lab, storage::StateStore), Box<dyn std::error::Error>> {
    let mut lab = Topology::from_yaml(&std::fs::read_to_string(path)?)?.build()?;
    let state = storage::StateStore::for_topology(path);
    state.load(&mut lab)?;
    Ok((lab, state))
}
