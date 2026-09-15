use crate::storage::StateStore;
use rios_cli::{CliMode, CliSession, ParseError, Suggestion, suggestions};
use rios_device::Device;
use rios_device::{DeviceType, InterfaceMedia};
use rios_simulator::{DeviceId, LinkId, LinkState, SimTime};
use rios_topology::{EventOutcome, Lab};
use std::path::Path;

/// Frontend-owned lab and current connection, shared by terminal and stdin paths.
pub struct App {
    pub lab: Lab,
    connection: Option<(DeviceId, CliSession)>,
    standalone: bool,
    state: Option<StateStore>,
}
/// Small read-only editor snapshot; never clones device or packet state.
pub struct CompletionContext {
    pub device: Option<(CliMode, Vec<String>)>,
    pub names: Vec<String>,
}
impl CompletionContext {
    pub fn suggestions(&self, input: &str) -> Result<Vec<Suggestion>, ParseError> {
        match &self.device {
            Some((mode, names)) => suggestions(input, *mode, names),
            None => Ok(crate::shell::complete(input, &self.names)),
        }
    }
}
impl App {
    pub fn standalone() -> Result<Self, crate::storage::StorageError> {
        let mut lab = Lab::default();
        let device = Device::standalone();
        let id = device.id();
        lab.add_device("R1", device).unwrap();
        let state =
            std::env::var_os("RIOS_STATE_FILE").map(|path| StateStore::from_path(path.into()));
        if let Some(state) = &state {
            state.load(&mut lab)?;
        }
        Ok(Self {
            lab,
            connection: Some((id, CliSession::default())),
            standalone: true,
            state,
        })
    }
    pub fn from_lab(lab: Lab, state: StateStore) -> Self {
        Self {
            lab,
            connection: None,
            standalone: false,
            state: Some(state),
        }
    }
    pub fn builder() -> Self {
        Self {
            lab: Lab::default(),
            connection: None,
            standalone: false,
            state: None,
        }
    }
    pub fn prompt(&self) -> String {
        match &self.connection {
            Some((id, session)) => crate::device_session::prompt(&self.lab, *id, session),
            None => "rios> ".into(),
        }
    }
    pub fn completion(&self) -> CompletionContext {
        CompletionContext {
            device: self.connection.as_ref().map(|(id, session)| {
                (
                    session.mode,
                    self.lab
                        .device(*id)
                        .unwrap()
                        .running_config()
                        .interfaces
                        .values()
                        .map(|c| c.name.clone())
                        .collect(),
                )
            }),
            names: self
                .lab
                .device_names()
                .map(|(name, _)| name.to_owned())
                .collect(),
        }
    }
    pub fn connect(&mut self, name: &str) -> Result<(), rios_topology::LabError> {
        self.connection = Some((self.lab.device_id(name)?, CliSession::default()));
        Ok(())
    }
    pub fn spawn_with_ports(
        &mut self,
        name: &str,
        device_type: DeviceType,
        ports: &[(InterfaceMedia, usize)],
    ) -> Result<(), rios_topology::LabError> {
        self.lab
            .spawn_device_with_ports(name, device_type, ports)
            .map(|_| ())
    }
    pub fn link(
        &mut self,
        first: &str,
        second: &str,
        delay_ms: u64,
    ) -> Result<(), rios_topology::LabError> {
        let first = self.lab.endpoint(first)?;
        let second = self.lab.endpoint(second)?;
        self.lab.connect(first, second, delay_ms).map(|_| ())
    }
    pub fn unlink(&mut self, id: u64) -> Result<(), rios_topology::LabError> {
        self.lab.disconnect(LinkId(id))
    }
    pub fn set_link_state(
        &mut self,
        id: u64,
        state: LinkState,
    ) -> Result<(), rios_topology::LabError> {
        self.lab.set_link_state(LinkId(id), state)
    }
    pub fn save_topology(&mut self, path: &Path) -> Result<(), String> {
        if self.lab.device_names().next().is_none() {
            return Err("cannot save an empty lab".into());
        }
        std::fs::write(path, self.lab.render_yaml()).map_err(|error| error.to_string())?;
        let ids: Vec<_> = self.lab.device_names().map(|(_, id)| id).collect();
        for id in ids {
            self.lab
                .with_device_mut(id, |device| device.save_config())
                .map_err(|error| error.to_string())?;
        }
        let state = StateStore::for_topology(path);
        state.save(&self.lab).map_err(|error| error.to_string())?;
        self.state = Some(state);
        Ok(())
    }
    pub fn end_configuration(&mut self) {
        if let Some((_, session)) = &mut self.connection {
            session.end_configuration();
        }
    }
    pub fn close_connection(&mut self) -> bool {
        if self.connection.take().is_some() {
            println!("Connection closed.");
            self.standalone
        } else {
            true
        }
    }
    pub fn process(&mut self, line: &str) -> bool {
        if let Some((id, session)) = &mut self.connection {
            let result = crate::device_session::process(
                &mut self.lab,
                *id,
                session,
                line,
                self.state.as_ref(),
            );
            print!("{}", result.output);
            if result.close {
                self.connection = None;
                return self.standalone;
            }
        } else if crate::shell::process(self, line) {
            return true;
        }
        if self.connection.is_none() {
            self.print_trace();
        }
        false
    }
    pub fn print_trace(&mut self) {
        for record in self.lab.take_trace() {
            println!(
                "[{}] {} {:?} {:?} {} bytes",
                record.time,
                self.lab.endpoint_name(record.interface),
                record.action,
                record.ethertype,
                record.length
            );
        }
    }
    pub fn step(&mut self) -> Result<(), rios_topology::LabError> {
        match self.lab.step()? {
            Some(event) => {
                let summary = match event {
                    EventOutcome::FrameReceived { interface, frame } => format!(
                        "{} received {} bytes",
                        self.lab.endpoint_name(interface),
                        frame.len()
                    ),
                    EventOutcome::FrameDropped { interface, reason } => format!(
                        "{} dropped frame: {reason}",
                        self.lab.endpoint_name(interface)
                    ),
                    EventOutcome::LinkStateChanged { link, state } => {
                        format!("Link {} is {state:?}", link.0)
                    }
                    EventOutcome::TimerExpired { timer } => format!("Timer {} expired", timer.0),
                };
                println!("[{}] {summary}", self.lab.now());
            }
            None => println!("No pending events."),
        };
        Ok(())
    }
    pub fn run_until(&mut self, millis: u64) -> Result<(), rios_topology::LabError> {
        // Discard consumed Phase 2 outcomes; trace records retain packet-path metadata when enabled.
        let outcomes = self.lab.run_until(SimTime(millis))?;
        println!(
            "Simulated time: {} ({} events processed)",
            self.lab.now(),
            outcomes.len()
        );
        Ok(())
    }
}
