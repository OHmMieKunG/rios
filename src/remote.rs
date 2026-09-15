use crate::device_session;
use crate::storage::StateStore;
use rios_cli::{CliSession, suggestions};
use rios_simulator::DeviceId;
use rios_topology::Lab;
use std::time::Duration;

pub const MAX_COMMAND_BYTES: usize = 4096;

pub struct RemoteOutput {
    pub text: String,
    pub close: bool,
}

#[derive(Default)]
pub struct RemoteCli {
    pub session: CliSession,
    line: String,
    skip_lf: bool,
    discard_line: bool,
}

impl RemoteCli {
    pub fn prompt(&self, lab: &Lab, device: DeviceId) -> String {
        device_session::prompt(lab, device, &self.session)
    }

    pub fn input(
        &mut self,
        lab: &mut Lab,
        device: DeviceId,
        data: &[u8],
        state: Option<&StateStore>,
    ) -> RemoteOutput {
        let mut text = String::new();
        let mut close = false;
        for byte in data {
            match *byte {
                b'\n' if self.skip_lf => self.skip_lf = false,
                b'\r' | b'\n' => {
                    self.skip_lf = *byte == b'\r';
                    text.push_str("\r\n");
                    if self.discard_line {
                        self.discard_line = false;
                        text.push_str(&self.prompt(lab, device));
                        continue;
                    }
                    let result =
                        device_session::process(lab, device, &mut self.session, &self.line, state);
                    self.line.clear();
                    text.push_str(&crlf(&result.output));
                    close = result.close;
                    if !close {
                        text.push_str(&self.prompt(lab, device));
                    }
                }
                3 => {
                    self.line.clear();
                    self.discard_line = false;
                    text.push_str("^C\r\n");
                    text.push_str(&self.prompt(lab, device));
                }
                26 => {
                    self.line.clear();
                    self.discard_line = false;
                    self.session.end_configuration();
                    text.push_str("\r\n");
                    text.push_str(&self.prompt(lab, device));
                }
                _ if self.discard_line => {}
                8 | 127 if !self.line.is_empty() => {
                    self.line.pop();
                    text.push_str("\x08 \x08");
                }
                b'?' => {
                    text.push_str("?\r\n");
                    let names = lab
                        .device(device)
                        .expect("remote frontend device exists")
                        .running_config()
                        .interfaces
                        .values()
                        .map(|interface| interface.name.clone())
                        .collect::<Vec<_>>();
                    match suggestions(&self.line, self.session.mode, &names) {
                        Ok(items) => {
                            for item in items {
                                text.push_str(&format!("  {:<20} {}\r\n", item.word, item.help));
                            }
                        }
                        Err(error) => text
                            .push_str(&crlf(&error.render(&self.prompt(lab, device), &self.line))),
                    }
                    text.push_str(&self.prompt(lab, device));
                    text.push_str(&self.line);
                }
                byte @ 0x20..=0x7e => {
                    if self.line.len() == MAX_COMMAND_BYTES {
                        self.line.clear();
                        self.discard_line = true;
                        text.push_str("\r\n% Input line exceeds 4096 bytes");
                    } else {
                        self.line.push(byte as char);
                        text.push(byte as char);
                    }
                }
                _ => {}
            }
            if close {
                break;
            }
        }
        RemoteOutput { text, close }
    }
}

pub fn max_sessions() -> Result<usize, String> {
    let value = std::env::var("RIOS_MAX_SESSIONS").unwrap_or_else(|_| "128".into());
    value
        .parse::<usize>()
        .ok()
        .filter(|limit| *limit > 0)
        .ok_or_else(|| "RIOS_MAX_SESSIONS must be a positive integer".into())
}

pub fn idle_timeout() -> Result<Duration, String> {
    let value = std::env::var("RIOS_IDLE_TIMEOUT_SECS").unwrap_or_else(|_| "900".into());
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| "RIOS_IDLE_TIMEOUT_SECS must be a positive integer".into())
}

pub async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

pub fn crlf(text: &str) -> String {
    text.replace('\n', "\r\n")
}
