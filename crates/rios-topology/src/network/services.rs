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

impl Lab {
    /// Resolve one A record with an actual UDP DNS exchange; NXDOMAIN returns None.
    pub fn dns_lookup(
        &mut self,
        device: DeviceId,
        server: Ipv4Addr,
        port: u16,
        name: &str,
    ) -> Result<Option<Ipv4Addr>, LabError> {
        let id = self.next_ping_id;
        self.next_ping_id = self.next_ping_id.wrapping_add(1);
        let query = rios_protocol::DnsMessage::query(id, name)
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        let bytes = query
            .encode()
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        let bytes = self
            .udp_request(device, server, port, &bytes, 5000)?
            .ok_or_else(|| LabError::Protocol("DNS request timed out".into()))?;
        let response = rios_protocol::DnsMessage::decode(&bytes)
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        if !response.response || response.id != id || response.question != query.question {
            return Err(LabError::Protocol(
                "DNS response does not match query".into(),
            ));
        }
        if response.rcode == 3 {
            return Ok(None);
        }
        if response.rcode != 0 {
            return Err(LabError::Protocol(format!(
                "DNS response code {}",
                response.rcode
            )));
        }
        Ok(response
            .answers
            .into_iter()
            .find(|a| a.name == query.question.name)
            .map(|a| a.address))
    }
    /// Query a simulated NTP server without changing the event clock or host OS clock.
    pub fn ntp_query(
        &mut self,
        device: DeviceId,
        server: Ipv4Addr,
        port: u16,
    ) -> Result<rios_protocol::NtpPacket, LabError> {
        let request = rios_protocol::NtpPacket::request(
            rios_protocol::NtpTimestamp::from_simulation(1_704_067_200, self.now().0),
        );
        let bytes = request
            .encode()
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        let bytes = self
            .udp_request(device, server, port, &bytes, 5000)?
            .ok_or_else(|| LabError::Protocol("NTP request timed out".into()))?;
        let response = rios_protocol::NtpPacket::decode(&bytes)
            .map_err(|e| LabError::Protocol(e.to_string()))?;
        if response.mode != 4
            || response.origin != request.transmit
            || response.leap == 3
            || !(1..=15).contains(&response.stratum)
        {
            return Err(LabError::Protocol("invalid NTP server response".into()));
        }
        Ok(response)
    }
}
