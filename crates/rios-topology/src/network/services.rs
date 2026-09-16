//! Bounded application probes driven by actual transport state and virtual time.
use super::*;
use rios_device::{TcpSocket, TcpState};
impl Lab {
    /// Send a single HTTP GET over simulated TCP and collect the close-delimited response.
    pub fn http_get(
        &mut self,
        device: DeviceId,
        remote: Ipv4Addr,
        port: u16,
    ) -> Result<Vec<u8>, LabError> {
        let request = format!("GET / HTTP/1.1\r\nHost: {remote}\r\nConnection: close\r\n\r\n");
        self.tcp_request(device, remote, port, request.as_bytes(), None)
    }
    /// Probe an echo stream, requiring exactly the sent bytes before closing.
    pub fn tcp_echo(
        &mut self,
        device: DeviceId,
        remote: Ipv4Addr,
        port: u16,
        bytes: &[u8],
    ) -> Result<Vec<u8>, LabError> {
        let response = self.tcp_request(device, remote, port, bytes, Some(bytes.len()))?;
        if response != bytes {
            return Err(LabError::Protocol("TCP echo payload mismatch".into()));
        }
        Ok(response)
    }
    fn tcp_request(
        &mut self,
        device: DeviceId,
        remote: Ipv4Addr,
        port: u16,
        bytes: &[u8],
        expected: Option<usize>,
    ) -> Result<Vec<u8>, LabError> {
        if bytes.is_empty() || bytes.len() > 1200 {
            return Err(rios_device::TcpError::Capacity.into());
        }
        let deadline = SimTime(
            self.now()
                .0
                .checked_add(10_000_000)
                .ok_or(PingError::TimeOverflow)?,
        );
        let local_port = (49152..=65535)
            .find(|port| {
                !self
                    .device(device)
                    .is_ok_and(|d| d.tcp_connections().keys().any(|s| s.local_port == *port))
            })
            .ok_or(rios_device::TcpError::Capacity)?;
        let socket = self.tcp_connect(device, local_port, remote, port)?;
        let result = self.tcp_exchange(device, socket, bytes, expected, deadline);
        match &result {
            Ok(_) => {
                self.tcp_close(device, socket)?;
            }
            Err(_) => {
                let _ = self.tcp_abort(device, socket);
            }
        }
        result
    }
    fn tcp_exchange(
        &mut self,
        device: DeviceId,
        socket: TcpSocket,
        bytes: &[u8],
        expected: Option<usize>,
        deadline: SimTime,
    ) -> Result<Vec<u8>, LabError> {
        self.drive_until(deadline, |lab, _| {
            let state = lab
                .device(device)
                .ok()?
                .tcp_connections()
                .get(&socket)?
                .state;
            (state != TcpState::SynSent).then_some(())
        })?
        .ok_or_else(|| LabError::Protocol("TCP connect timed out".into()))?;
        self.tcp_send(device, socket, bytes)?;
        let mut response = Vec::new();
        loop {
            let connection = self
                .device(device)?
                .tcp_connections()
                .get(&socket)
                .ok_or(rios_device::TcpError::Missing)?;
            let state = connection.state;
            if connection.received_len() > 0 {
                let data = self.tcp_read(device, socket)?;
                if response.len() + data.len() > 65535 {
                    return Err(rios_device::TcpError::Capacity.into());
                }
                response.extend(data);
            }
            if expected.is_some_and(|length| response.len() >= length)
                || state == TcpState::CloseWait
            {
                return Ok(response);
            }
            if matches!(state, TcpState::Closed | TcpState::TimeWait) {
                return Err(rios_device::TcpError::State.into());
            }
            if self
                .drive_until(deadline, |lab, _| {
                    let c = lab.device(device).ok()?.tcp_connections().get(&socket)?;
                    (c.received_len() > 0 || c.state != TcpState::Established).then_some(())
                })?
                .is_none()
            {
                return Err(LabError::Protocol("TCP response timed out".into()));
            }
        }
    }
}
