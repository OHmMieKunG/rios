use crate::{
    device_session,
    remote::{MAX_COMMAND_BYTES, RemoteCli, crlf, idle_timeout, max_sessions, shutdown_signal},
    storage::StateStore,
};
use rios_simulator::DeviceId;
use rios_topology::Lab;
use russh::{
    Channel, ChannelId, Pty,
    keys::{Algorithm, PrivateKey, PublicKey, load_secret_key, ssh_key},
    server::{self, Auth, Msg, Server as _, Session},
};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

const BANNER: &str = "RIOS Network Simulator\r\n\r\n";
const MAX_CHANNELS_PER_CONNECTION: usize = 8;
const MAX_HOST_KEY_BYTES: u64 = 64 * 1024;
const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1024 * 1024;

#[derive(Clone)]
struct SshServer {
    lab: Arc<Mutex<Lab>>,
    device: DeviceId,
    username: Arc<str>,
    password: Option<Arc<str>>,
    authorized_keys: Arc<[PublicKey]>,
    state: Option<Arc<StateStore>>,
    capacity: Arc<Semaphore>,
}

struct Handler {
    server: SshServer,
    channels: HashMap<ChannelId, RemoteCli>,
    permit: Option<OwnedSemaphorePermit>,
}

impl server::Server for SshServer {
    type Handler = Handler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        Handler {
            server: self.clone(),
            channels: HashMap::new(),
            permit: None,
        }
    }

    fn handle_session_error(&mut self, error: russh::Error) {
        tracing::debug!(%error, "SSH session ended with an error");
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(
            if user == &*self.server.username && self.server.password.as_deref() == Some(password) {
                if self.reserve_capacity() {
                    Auth::Accept
                } else {
                    Auth::reject()
                }
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(
            if self.public_key_allowed(user, key) && self.server.capacity.available_permits() > 0 {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        Ok(
            if self.public_key_allowed(user, key) && self.reserve_capacity() {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channels.len() >= MAX_CHANNELS_PER_CONNECTION {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
            return Ok(());
        }
        self.channels.insert(channel.id(), RemoteCli::default());
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let cli = self.channels.entry(channel).or_default();
        let lab = self.server.lab.lock().await;
        let prompt = device_session::prompt(&lab, self.server.device, &cli.session);
        session.data(channel, format!("{BANNER}{prompt}"))
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(command) = std::str::from_utf8(data) else {
            session.channel_failure(channel)?;
            session.data(channel, "% SSH command is not valid UTF-8\r\n")?;
            session.exit_status_request(channel, 1)?;
            session.eof(channel)?;
            session.close(channel)?;
            self.channels.remove(&channel);
            return Ok(());
        };
        if data.len() > MAX_COMMAND_BYTES {
            session.channel_failure(channel)?;
            session.data(channel, "% SSH command exceeds 4096 bytes\r\n")?;
            session.exit_status_request(channel, 1)?;
            session.eof(channel)?;
            session.close(channel)?;
            self.channels.remove(&channel);
            return Ok(());
        }
        session.channel_success(channel)?;
        let cli = self.channels.entry(channel).or_default();
        let mut lab = self.server.lab.lock().await;
        let result = device_session::process(
            &mut lab,
            self.server.device,
            &mut cli.session,
            command,
            self.server.state.as_deref(),
        );
        session.data(channel, crlf(&result.output))?;
        session.exit_status_request(channel, u32::from(!result.success))?;
        session.eof(channel)?;
        session.close(channel)?;
        self.channels.remove(&channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(mut cli) = self.channels.remove(&channel) else {
            return Ok(());
        };
        let mut lab = self.server.lab.lock().await;
        let output = cli.input(
            &mut lab,
            self.server.device,
            data,
            self.server.state.as_deref(),
        );
        drop(lab);
        session.data(channel, output.text)?;
        if output.close {
            session.data(channel, "Connection closed.\r\n")?;
            session.eof(channel)?;
            session.close(channel)?;
        } else {
            self.channels.insert(channel, cli);
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
}

impl Handler {
    fn public_key_allowed(&self, user: &str, key: &PublicKey) -> bool {
        user == &*self.server.username
            && self
                .server
                .authorized_keys
                .iter()
                .any(|allowed| allowed.key_data() == key.key_data())
    }

    fn reserve_capacity(&mut self) -> bool {
        if self.permit.is_none() {
            self.permit = Arc::clone(&self.server.capacity).try_acquire_owned().ok();
        }
        self.permit.is_some()
    }
}

fn host_key(
    path: Option<&Path>,
    passphrase: Option<&str>,
) -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?);
    };
    if path.exists() {
        ensure_file_size(path, MAX_HOST_KEY_BYTES)?;
        return Ok(load_secret_key(path, passphrase)?);
    }
    if passphrase.is_some() {
        return Err("cannot generate an encrypted SSH host key; create it with ssh-keygen".into());
    }
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    key.write_openssh_file(path, ssh_key::LineEnding::LF)?;
    Ok(key)
}

fn authorized_keys(path: Option<&Path>) -> Result<Vec<PublicKey>, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    ensure_file_size(path, MAX_AUTHORIZED_KEYS_BYTES)?;
    ssh_key::AuthorizedKeys::read_file(path)?
        .into_iter()
        .map(|entry| {
            if !entry.config_opts().is_empty() {
                return Err(format!(
                    "authorized_keys options are not supported: {}",
                    entry.config_opts()
                )
                .into());
            }
            Ok(entry.public_key().clone())
        })
        .collect()
}

fn ensure_file_size(path: &Path, maximum: u64) -> Result<(), Box<dyn std::error::Error>> {
    let length = std::fs::metadata(path)?.len();
    if length > maximum {
        return Err(format!("{} exceeds {maximum} bytes", path.display()).into());
    }
    Ok(())
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
    let username: Arc<str> = std::env::var("RIOS_SSH_USERNAME")
        .unwrap_or_else(|_| "admin".into())
        .into();
    let password = std::env::var("RIOS_SSH_PASSWORD").unwrap_or_default();
    let password: Option<Arc<str>> = (!password.is_empty()).then(|| password.into());
    let host_key_path = std::env::var_os("RIOS_SSH_HOST_KEY")
        .map(PathBuf::from)
        .ok_or("RIOS_SSH_HOST_KEY is required for stable server identity")?;
    let host_key_passphrase = std::env::var("RIOS_SSH_HOST_KEY_PASSWORD").ok();
    let authorized_keys_path = std::env::var_os("RIOS_SSH_AUTHORIZED_KEYS").map(PathBuf::from);
    let authorized_keys: Arc<[PublicKey]> =
        authorized_keys(authorized_keys_path.as_deref())?.into();
    if password.is_none() && authorized_keys.is_empty() {
        return Err("SSH password is disabled and no authorized keys are configured".into());
    }
    let key = host_key(Some(&host_key_path), host_key_passphrase.as_deref())?;
    let config = Arc::new(server::Config {
        inactivity_timeout: Some(idle_timeout()?),
        max_auth_attempts: 5,
        nodelay: true,
        keys: vec![key],
        ..Default::default()
    });
    // ponytail: one lock serializes commands; use a lab actor if SSH command contention matters.
    let lab = Arc::new(Mutex::new(lab));
    let state = Arc::new(state);
    let capacity = Arc::new(Semaphore::new(max_sessions()?));
    let mut servers = JoinSet::new();
    let mut shutdown_handles = Vec::new();

    for (offset, (name, device)) in devices.into_iter().enumerate() {
        let port = base_port
            .checked_add(u16::try_from(offset)?)
            .ok_or("SSH port range exceeds 65535")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        println!("  {name}: ssh {username}@127.0.0.1 -p {port}");
        let mut server = SshServer {
            lab: Arc::clone(&lab),
            device,
            username: Arc::clone(&username),
            password: password.clone(),
            authorized_keys: Arc::clone(&authorized_keys),
            state: Some(Arc::clone(&state)),
            capacity: Arc::clone(&capacity),
        };
        let config = Arc::clone(&config);
        let (handle_sender, handle_receiver) = oneshot::channel();
        servers.spawn(async move {
            let running = server.run_on_socket(config, &listener);
            let _ = handle_sender.send(running.handle());
            running.await
        });
        shutdown_handles.push(handle_receiver.await?);
    }
    println!(
        "\nSSH authentication: {} password, {} authorized key(s).\n",
        if password.is_some() {
            "enabled"
        } else {
            "disabled"
        },
        authorized_keys.len()
    );

    tokio::select! {
        signal = shutdown_signal() => signal?,
        result = servers.join_next() => match result {
            Some(result) => result??,
            None => return Ok(()),
        },
    }
    for handle in shutdown_handles {
        handle.shutdown("RIOS is shutting down".into());
    }
    while let Some(result) = servers.join_next().await {
        result??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{SshServer, authorized_keys, crlf, host_key};
    use rios_device::Device;
    use rios_topology::Lab;
    use russh::{
        ChannelMsg, client,
        keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate},
        server::Server as _,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{fs, net::Ipv4Addr, sync::Arc, time::Duration};
    use tokio::{
        net::TcpListener,
        sync::{Mutex, Semaphore},
    };

    struct TestClient;

    impl client::Handler for TestClient {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _: &PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    async fn channel_output(mut channel: russh::Channel<client::Msg>) -> (String, Option<u32>) {
        let mut output = Vec::new();
        let mut status = None;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => output.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
        (String::from_utf8(output).unwrap(), status)
    }

    #[test]
    fn converts_cli_lines_for_an_ssh_terminal() {
        assert_eq!(crlf("one\ntwo\n"), "one\r\ntwo\r\n");
    }

    #[test]
    fn persistent_host_and_authorized_keys_use_openssh_files() {
        let directory = std::env::temp_dir().join(format!("rios-ssh-keys-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let host_path = directory.join("host_key");
        let first = host_key(Some(&host_path), None).unwrap();
        let second = host_key(Some(&host_path), None).unwrap();
        assert_eq!(
            first.public_key().key_data(),
            second.public_key().key_data()
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&host_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let authorized_path = directory.join("authorized_keys");
        fs::write(
            &authorized_path,
            format!("{}\n", first.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        let loaded = authorized_keys(Some(&authorized_path)).unwrap();
        assert_eq!(loaded[0].key_data(), first.public_key().key_data());
        fs::write(
            &authorized_path,
            format!(
                "no-port-forwarding {}\n",
                first.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        assert!(authorized_keys(Some(&authorized_path)).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn encrypted_session_uses_the_device_cli() {
        let mut lab = Lab::default();
        let device = Device::standalone();
        let id = device.id();
        lab.add_device("R1", device).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let client_key =
            russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let mut server = SshServer {
            lab: Arc::new(Mutex::new(lab)),
            device: id,
            username: "admin".into(),
            password: Some("test-password".into()),
            authorized_keys: vec![client_key.public_key().clone()].into(),
            state: None,
            capacity: Arc::new(Semaphore::new(1)),
        };
        let config = Arc::new(russh::server::Config {
            keys: vec![
                russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
                    .unwrap(),
            ],
            ..Default::default()
        });
        let server_task =
            tokio::spawn(async move { server.run_on_socket(config, &listener).await });

        let mut client = client::connect(Arc::new(client::Config::default()), address, TestClient)
            .await
            .unwrap();
        assert!(
            client
                .authenticate_password("admin", "test-password")
                .await
                .unwrap()
                .success()
        );
        let mut rejected =
            client::connect(Arc::new(client::Config::default()), address, TestClient)
                .await
                .unwrap();
        assert!(
            !rejected
                .authenticate_password("admin", "test-password")
                .await
                .unwrap()
                .success()
        );
        rejected
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await
            .unwrap();

        let exec = client.channel_open_session().await.unwrap();
        exec.exec(true, "show ip interface brief").await.unwrap();
        let (exec_output, status) =
            tokio::time::timeout(Duration::from_secs(5), channel_output(exec))
                .await
                .unwrap();
        assert_eq!(status, Some(0));
        assert!(exec_output.contains("GigabitEthernet0/0"), "{exec_output}");

        let invalid = client.channel_open_session().await.unwrap();
        invalid.exec(true, "hello").await.unwrap();
        let (invalid_output, status) =
            tokio::time::timeout(Duration::from_secs(5), channel_output(invalid))
                .await
                .unwrap();
        assert_eq!(status, Some(1));
        assert!(invalid_output.contains("Invalid input"), "{invalid_output}");

        let channel = client.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        channel
            .data(&b"enable\rshow ip interface brief\rexit\r"[..])
            .await
            .unwrap();

        let (output, status) =
            tokio::time::timeout(Duration::from_secs(5), channel_output(channel))
                .await
                .unwrap();
        assert_eq!(status, None);
        assert!(output.contains("RIOS Network Simulator\r\n"), "{output}");
        assert!(output.contains("R1# "), "{output}");
        assert!(output.contains("GigabitEthernet0/0"), "{output}");
        assert!(output.contains("Connection closed."), "{output}");
        client
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await
            .unwrap();

        let mut key_client =
            client::connect(Arc::new(client::Config::default()), address, TestClient)
                .await
                .unwrap();
        assert!(
            key_client
                .authenticate_publickey(
                    "admin",
                    PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
                )
                .await
                .unwrap()
                .success()
        );
        key_client
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await
            .unwrap();
        server_task.abort();
    }
}
