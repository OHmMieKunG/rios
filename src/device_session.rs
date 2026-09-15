use crate::storage::StateStore;
use rios_cli::{CliSession, ParsedInput, SimulationRequest, execute_at, parse};
use rios_simulator::DeviceId;
use rios_topology::Lab;

pub struct LineResult {
    pub output: String,
    pub close: bool,
    pub success: bool,
}

pub fn prompt(lab: &Lab, id: DeviceId, session: &CliSession) -> String {
    session.prompt(lab.device(id).expect("connected device exists").hostname())
}

pub fn process(
    lab: &mut Lab,
    id: DeviceId,
    session: &mut CliSession,
    line: &str,
    state: Option<&StateStore>,
) -> LineResult {
    let current_prompt = prompt(lab, id, session);
    let mut output = String::new();
    let mut close = false;
    let mut success = true;

    match parse(line, session.mode) {
        Ok(ParsedInput::Empty) => {}
        Ok(ParsedInput::Help(help)) => output.push_str(&help),
        Ok(ParsedInput::Command(command)) => {
            let now = lab.now();
            match lab.with_device_mut(id, |device| execute_at(device, session, command, now)) {
                Ok(Ok(mut result)) => {
                    output.push_str(&result.output);
                    if let Some(request) = result.request.take() {
                        let ping = match request {
                            SimulationRequest::ShowPolicyInterface(interface) => {
                                lab.show_policy_map_port(id, interface)
                            }
                            SimulationRequest::Ping(destination) => {
                                lab.ping(id, destination).map(|ping| ping.render())
                            }
                            SimulationRequest::PingIpv6 {
                                destination,
                                interface,
                            } => lab
                                .ping_ipv6(id, destination, interface)
                                .map(|ping| ping.render()),
                        };
                        match ping {
                            Ok(rendered) => output.push_str(&rendered),
                            Err(error) => {
                                output.push_str(&format!("% {error}\n"));
                                success = false;
                            }
                        }
                    }
                    close = result.close;
                    if result.persist
                        && let Some(state) = state
                        && let Err(error) = state.save(lab)
                    {
                        output = format!("Building configuration...\n% {error}\n");
                        success = false;
                    }
                }
                Ok(Err(error)) => {
                    output.push_str(&format!("% {error}\n"));
                    success = false;
                }
                Err(error) => {
                    output.push_str(&format!("% {error}\n"));
                    success = false;
                }
            }
        }
        Err(error) => {
            output.push_str(&error.render(&current_prompt, line));
            success = false;
        }
    }

    for record in lab.take_trace() {
        output.push_str(&format!(
            "[{}] {} {:?} {:?} {} bytes\n",
            record.time,
            lab.endpoint_name(record.interface),
            record.action,
            record.ethertype,
            record.length
        ));
    }
    LineResult {
        output,
        close,
        success,
    }
}
