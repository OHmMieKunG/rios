use crate::{
    remote::{RemoteCli, idle_timeout, max_sessions, shutdown_signal},
    storage::StateStore,
};
use rios_simulator::DeviceId;
use rios_topology::Lab;
use std::{io, net::Ipv4Addr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
};

const IAC: u8 = 255;
const WILL: u8 = 251;
const ECHO: u8 = 1;
const SUPPRESS_GO_AHEAD: u8 = 3;
const NEGOTIATION: &[u8] = &[IAC, WILL, ECHO, IAC, WILL, SUPPRESS_GO_AHEAD];
const BANNER: &str = "RIOS Network Simulator\r\n\r\n";

#[derive(Default)]
enum TelnetState {
    #[default]
    Data,
    Command,
    Option,
    Subnegotiation,
    SubnegotiationIac,
}

#[derive(Default)]
struct TelnetDecoder(TelnetState);

impl TelnetDecoder {
    fn decode(&mut self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        for byte in input {
            self.0 = match (&self.0, *byte) {
                (TelnetState::Data, IAC) => TelnetState::Command,
                (TelnetState::Data, byte) => {
                    output.push(byte);
                    TelnetState::Data
                }
                (TelnetState::Command, IAC) => {
                    output.push(IAC);
                    TelnetState::Data
                }
                (TelnetState::Command, 250) => TelnetState::Subnegotiation,
                (TelnetState::Command, 251..=254) => TelnetState::Option,
                (TelnetState::Command, _) => TelnetState::Data,
                (TelnetState::Option, _) => TelnetState::Data,
                (TelnetState::Subnegotiation, IAC) => TelnetState::SubnegotiationIac,
                (TelnetState::Subnegotiation, _) => TelnetState::Subnegotiation,
                (TelnetState::SubnegotiationIac, 240) => TelnetState::Data,
                (TelnetState::SubnegotiationIac, _) => TelnetState::Subnegotiation,
            };
        }
        output
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    lab: Arc<Mutex<Lab>>,
    device: DeviceId,
    state: Option<Arc<StateStore>>,
    mut shutdown: watch::Receiver<bool>,
    idle_timeout: std::time::Duration,
) -> io::Result<()> {
    stream.write_all(NEGOTIATION).await?;
    let mut cli = RemoteCli::default();
    let prompt = {
        let lab = lab.lock().await;
        cli.prompt(&lab, device)
    };
    stream
        .write_all(format!("{BANNER}{prompt}").as_bytes())
        .await?;

    let mut decoder = TelnetDecoder::default();
    let mut buffer = [0; 1024];
    loop {
        let length = tokio::select! {
            length = tokio::time::timeout(idle_timeout, stream.read(&mut buffer)) => {
                match length {
                    Ok(length) => length?,
                    Err(_) => {
                        stream.write_all(b"\r\n% Idle timeout\r\n").await?;
                        stream.shutdown().await?;
                        return Ok(());
                    }
                }
            },
            _ = shutdown.changed() => {
                stream.write_all(b"\r\n% RIOS is shutting down\r\n").await?;
                stream.shutdown().await?;
                return Ok(());
            }
        };
        if length == 0 {
            return Ok(());
        }
        let input = decoder.decode(&buffer[..length]);
        if input.is_empty() {
            continue;
        }
        let output = {
            let mut lab = lab.lock().await;
            cli.input(&mut lab, device, &input, state.as_deref())
        };
        stream.write_all(output.text.as_bytes()).await?;
        if output.close {
            stream.write_all(b"Connection closed.\r\n").await?;
            stream.shutdown().await?;
            return Ok(());
        }
    }
}

pub async fn run(
    lab: Lab,
    state: StateStore,
    base_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let devices = lab
        .device_names()
        .map(|(name, id)| (name.to_owned(), id))
        .collect::<Vec<_>>();
    if devices.is_empty() {
        return Err("topology has no devices".into());
    }
    // ponytail: one lock serializes commands; use a lab actor if contention matters.
    let lab = Arc::new(Mutex::new(lab));
    let state = Arc::new(state);
    let capacity = Arc::new(Semaphore::new(max_sessions()?));
    let idle_timeout = idle_timeout()?;
    let (shutdown_sender, _) = watch::channel(false);
    let mut servers = JoinSet::new();
    for (offset, (name, device)) in devices.into_iter().enumerate() {
        let port = base_port
            .checked_add(u16::try_from(offset)?)
            .ok_or("Telnet port range exceeds 65535")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        println!("  {name}: telnet 127.0.0.1 {port}");
        let lab = Arc::clone(&lab);
        let state = Arc::clone(&state);
        let capacity = Arc::clone(&capacity);
        let mut shutdown = shutdown_sender.subscribe();
        servers.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (mut stream, peer) = tokio::select! {
                    accepted = listener.accept() => accepted?,
                    _ = shutdown.changed() => break,
                };
                let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                    stream.write_all(b"% Session limit reached\r\n").await?;
                    continue;
                };
                let lab = Arc::clone(&lab);
                let state = Arc::clone(&state);
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(
                        stream,
                        lab,
                        device,
                        Some(state),
                        connection_shutdown,
                        idle_timeout,
                    )
                    .await
                    {
                        tracing::debug!(%peer, %error, "Telnet session ended with an error");
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                result.map_err(io::Error::other)?;
            }
            Ok::<(), io::Error>(())
        });
    }
    println!("\nTelnet listeners are local and unauthenticated.\n");
    tokio::select! {
        signal = shutdown_signal() => signal?,
        result = servers.join_next() => match result {
            Some(result) => result??,
            None => return Ok(()),
        },
    }
    let _ = shutdown_sender.send(true);
    while let Some(result) = servers.join_next().await {
        result??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rios_device::Device;
    use tokio::time::{Duration, timeout};

    #[test]
    fn decoder_removes_negotiation_and_subnegotiation() {
        let mut decoder = TelnetDecoder::default();
        assert_eq!(
            decoder.decode(&[IAC, 253, ECHO, b's', IAC, 250, 31, 0, 80]),
            b"s"
        );
        assert_eq!(decoder.decode(&[0, 24, IAC, 240, b'h']), b"h");
    }

    #[tokio::test]
    async fn connection_uses_the_shared_device_cli() {
        let mut lab = Lab::default();
        let device = Device::standalone();
        let id = device.id();
        lab.add_device("R1", device).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_shutdown_sender, shutdown) = watch::channel(false);
            serve_connection(
                stream,
                Arc::new(Mutex::new(lab)),
                id,
                None,
                shutdown,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        let mut input = vec![b'x'; crate::remote::MAX_COMMAND_BYTES + 1];
        input.extend_from_slice(b"\renable\rshow ip interface brief\rexit\r");
        client.write_all(&input).await.unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("RIOS Network Simulator\r\n"), "{output}");
        assert!(output.contains("Input line exceeds 4096 bytes"), "{output}");
        assert!(output.contains("R1# "), "{output}");
        assert!(output.contains("GigabitEthernet0/0"), "{output}");
        assert!(output.contains("Connection closed."), "{output}");
    }

    #[tokio::test]
    async fn graceful_shutdown_notifies_an_active_connection() {
        let mut lab = Lab::default();
        let device = Device::standalone();
        let id = device.id();
        lab.add_device("R1", device).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown) = watch::channel(false);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            serve_connection(
                stream,
                Arc::new(Mutex::new(lab)),
                id,
                None,
                shutdown,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        shutdown_sender.send(true).unwrap();
        let mut output = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut output))
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();
        assert!(
            String::from_utf8_lossy(&output).contains("RIOS is shutting down"),
            "{}",
            String::from_utf8_lossy(&output)
        );
    }
}
