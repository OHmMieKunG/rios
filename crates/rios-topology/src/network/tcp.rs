//! TCP applications and timers use the same IPv4 forwarding path as other traffic.
use super::*;
use rios_device::TcpSocket;

impl Lab {
    /// Listen inside a simulated device without opening an OS socket.
    pub fn tcp_listen(&mut self, device: DeviceId, port: u16) -> Result<(), LabError> {
        self.devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .tcp_listen(port)?;
        Ok(())
    }
    /// Start a routed simulated TCP connection, returning its stable endpoint tuple.
    pub fn tcp_connect(
        &mut self,
        device: DeviceId,
        local_port: u16,
        remote_address: Ipv4Addr,
        remote_port: u16,
    ) -> Result<TcpSocket, LabError> {
        let route = self
            .device(device)?
            .resolve_route(remote_address)
            .ok_or(PingError::NoRoute(remote_address))?;
        let socket = TcpSocket {
            local_address: route.source_ip,
            local_port,
            remote_address,
            remote_port,
        };
        let now = self.now();
        let packet = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .tcp_connect(socket, now)?;
        self.send_ipv4_packet(device, packet)?;
        self.ensure_tcp_timer(device)?;
        Ok(socket)
    }
    /// Send up to 1200 bytes; a busy stream applies explicit application backpressure.
    pub fn tcp_send(
        &mut self,
        device: DeviceId,
        socket: TcpSocket,
        payload: &[u8],
    ) -> Result<(), LabError> {
        let now = self.now();
        let packet = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .tcp_send(socket, payload, now)?;
        self.send_ipv4_packet(device, packet)?;
        Ok(())
    }
    /// Read received bytes and advertise the newly available receive window.
    pub fn tcp_read(&mut self, device: DeviceId, socket: TcpSocket) -> Result<Vec<u8>, LabError> {
        let (bytes, packet) = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .tcp_read(socket)?;
        self.send_ipv4_packet(device, packet)?;
        Ok(bytes)
    }
    /// Abort a stream with a simulated RST; no operating-system socket is involved.
    pub fn tcp_abort(&mut self, device: DeviceId, socket: TcpSocket) -> Result<(), LabError> {
        let packet = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .tcp_abort(socket)?;
        self.send_ipv4_packet(device, packet)?;
        Ok(())
    }
    /// Close a stream using simulated FIN and ACK packets.
    pub fn tcp_close(&mut self, device: DeviceId, socket: TcpSocket) -> Result<(), LabError> {
        let now = self.now();
        let packet = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .tcp_close(socket, now)?;
        self.send_ipv4_packet(device, packet)?;
        Ok(())
    }
    pub(super) fn handle_tcp(
        &mut self,
        device: DeviceId,
        packet: Ipv4Packet,
    ) -> Result<(), LabError> {
        let now = self.now();
        if let Some(reply) = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .receive_tcp(&packet, now)
        {
            self.send_ipv4_packet(device, reply)?;
        }
        self.ensure_tcp_timer(device)
    }
    fn ensure_tcp_timer(&mut self, device: DeviceId) -> Result<(), LabError> {
        if self.device(device)?.tcp_connections().is_empty() || self.tcp_timers.contains(&device) {
            return Ok(());
        }
        self.events
            .schedule_after(1000, SimulationEvent::TcpTick { device })?;
        self.tcp_timers.insert(device);
        Ok(())
    }
    pub(crate) fn tcp_timer(&mut self, device: DeviceId) -> Result<(), LabError> {
        self.tcp_timers.remove(&device);
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .tcp_tick(now);
        for packet in packets {
            self.send_ipv4_packet(device, packet)?;
        }
        self.ensure_tcp_timer(device)
    }
}
