//! TCP accepts, active opens, collision resolution, stream framing and application backpressure.
use super::*;
impl Device {
    pub(super) fn bgp_transport_peer(
        &mut self,
        address: Ipv4Addr,
        peer: &mut Peer,
        config: &BgpConfig,
        router_id: Ipv4Addr,
        now: SimTime,
        out: &mut Vec<Ipv4Packet>,
    ) {
        let stale: Vec<_> = peer
            .streams
            .keys()
            .filter(|socket| {
                self.tcp_connections().get(socket).is_none_or(|c| {
                    matches!(
                        c.state,
                        TcpState::Closed
                            | TcpState::TimeWait
                            | TcpState::LastAck
                            | TcpState::FinWait
                    )
                })
            })
            .copied()
            .collect();
        for socket in stale {
            peer.streams.remove(&socket);
            if peer.selected == Some(socket) {
                peer.selected = None;
                peer.received.clear();
            }
            peer.retry_at = SimTime(now.0.saturating_add(RETRY_US));
            peer.state = BgpState::Active;
        }
        let incoming: Vec<_> = self
            .tcp_connections()
            .iter()
            .filter(|(s, c)| {
                s.remote_address == address
                    && s.local_port == 179
                    && matches!(
                        c.state,
                        TcpState::SynReceived | TcpState::Established | TcpState::CloseWait
                    )
                    && !peer.streams.contains_key(s)
            })
            .map(|(s, _)| *s)
            .collect();
        for socket in incoming {
            if peer.streams.len() >= 2 {
                if let Ok(packet) = self.tcp_abort(socket) {
                    out.push(packet);
                }
                continue;
            }
            if let Ok(stream) = Stream::new(config, peer.config.remote_as, router_id, now) {
                let _ = self.tcp_set_idle_timeout(socket, None);
                peer.streams.insert(socket, stream);
            }
        }
        if peer.streams.is_empty() && peer.retry_at <= now {
            peer.retry_at = SimTime(now.0.saturating_add(RETRY_US));
            peer.state = BgpState::Active;
            if let Some(route) = self.resolve_non_bgp_route(address) {
                let source = match peer.config.update_source {
                    Some(id) => self
                        .protocol_up(id)
                        .then(|| self.interface_ipv4(id))
                        .flatten()
                        .map(|ip| ip.address()),
                    None => Some(route.source_ip),
                };
                if let Some(local_address) = source {
                    let mut socket = None;
                    for _ in 0..16384 {
                        self.bgp.next_port =
                            if self.bgp.next_port < 49152 || self.bgp.next_port == 65535 {
                                49152
                            } else {
                                self.bgp.next_port + 1
                            };
                        let candidate = TcpSocket {
                            local_address,
                            local_port: self.bgp.next_port,
                            remote_address: address,
                            remote_port: 179,
                        };
                        if !self.tcp_connections().contains_key(&candidate) {
                            socket = Some(candidate);
                            break;
                        }
                    }
                    if let Some(socket) = socket
                        && let Ok(stream) =
                            Stream::new(config, peer.config.remote_as, router_id, now)
                        && let Ok(packet) = self.tcp_connect(socket, now)
                    {
                        let _ = self.tcp_set_idle_timeout(socket, None);
                        out.push(packet);
                        peer.streams.insert(socket, stream);
                        peer.state = BgpState::Connect;
                    }
                }
            }
        }
        let mut updates = Vec::new();
        for (socket, stream) in &mut peer.streams {
            let Some(connection) = self.tcp_connections().get(socket) else {
                continue;
            };
            let state = connection.state;
            let received = connection.received_len();
            if state == TcpState::CloseWait && stream.closing.is_none() {
                stream.closing = Some(now);
                stream.fsm.transport_failed(now);
            }
            if state != TcpState::Established || stream.closing.is_some() {
                continue;
            }
            if !stream.started {
                stream.started = true;
                for message in stream.fsm.transport_connected(now).messages {
                    if let Err(error) = stream.queue(message) {
                        stream.fail(error, now);
                    }
                }
            }
            if received > 0
                && let Ok((bytes, window)) = self.tcp_read(*socket)
            {
                out.push(window);
                if let Err(error) = stream.input.push(&bytes) {
                    stream.fail(error, now);
                }
                while stream.closing.is_none() {
                    let message = match stream.input.next_message(stream.fsm.four_octet_as) {
                        Ok(Some(m)) => m,
                        Ok(None) => break,
                        Err(error) => {
                            stream.fail(error, now);
                            break;
                        }
                    };
                    let actions = stream.fsm.receive(message, now);
                    if let Some(update) = actions.update {
                        updates.push((*socket, update));
                    }
                    for message in actions.messages {
                        if let Err(error) = stream.queue(message) {
                            stream.fail(error, now);
                        }
                    }
                    if actions.close_transport {
                        stream.closing = Some(SimTime(now.0.saturating_add(5_000_000)));
                    }
                }
            }
            if stream.closing.is_none() {
                let actions = stream.fsm.tick(now);
                for message in actions.messages {
                    if let Err(error) = stream.queue(message) {
                        stream.fail(error, now);
                    }
                }
                if actions.close_transport {
                    stream.closing = Some(SimTime(now.0.saturating_add(5_000_000)));
                }
            }
            if let Some(error) = stream.fsm.last_error {
                peer.last_error = Some(error);
            }
        }
        // A collision only exists once both TCP transports have completed their handshakes.
        let candidates: Vec<_> = peer
            .streams
            .iter()
            .filter(|(_, s)| s.started && s.closing.is_none())
            .map(|(socket, _)| *socket)
            .collect();
        if candidates.len() > 1
            && let Some(remote_id) = candidates
                .iter()
                .find_map(|s| peer.streams[s].fsm.peer_router_id)
        {
            let established = candidates
                .iter()
                .find(|s| peer.streams[s].fsm.state == BgpState::Established)
                .copied();
            let winner = established.or_else(|| {
                candidates
                    .iter()
                    .find(|socket| {
                        (socket.remote_port == 179)
                            == ((router_id, socket.local_address) > (remote_id, address))
                    })
                    .copied()
            });
            if let Some(winner) = winner {
                for socket in &candidates {
                    if *socket != winner
                        && let Some(stream) = peer.streams.get_mut(socket)
                    {
                        stream.fail(
                            BgpError {
                                code: 6,
                                subcode: 7,
                            },
                            now,
                        );
                    }
                }
            }
        }
        let selected = peer
            .selected
            .filter(|s| {
                peer.streams
                    .get(s)
                    .is_some_and(|s| s.closing.is_none() && s.fsm.state == BgpState::Established)
            })
            .or_else(|| {
                peer.streams
                    .iter()
                    .find(|(_, s)| s.closing.is_none() && s.fsm.state == BgpState::Established)
                    .map(|(s, _)| *s)
            });
        if selected != peer.selected {
            peer.received.clear();
            peer.selected = selected;
        }
        peer.state = peer
            .streams
            .values()
            .find(|s| s.closing.is_none())
            .map_or(BgpState::Active, |s| s.fsm.state);
        for (socket, update) in updates {
            if selected != Some(socket) {
                continue;
            }
            let Some(stream) = peer.streams.get_mut(&socket) else {
                continue;
            };
            if stream.closing.is_some() {
                continue;
            }
            for prefix in update.withdrawn {
                peer.received.remove(&prefix);
            }
            let Some(mut attrs) = update.attributes else {
                continue;
            };
            let external = peer.config.remote_as != config.local_as;
            if external && attrs.first_as() != Some(peer.config.remote_as) {
                stream.fail(
                    BgpError {
                        code: 3,
                        subcode: 11,
                    },
                    now,
                );
                peer.received.clear();
                continue;
            }
            if !external && attrs.local_preference.is_none() {
                stream.fail(
                    BgpError {
                        code: 3,
                        subcode: 3,
                    },
                    now,
                );
                peer.received.clear();
                continue;
            }
            if external {
                attrs.local_preference = None;
            }
            let looped = attrs.contains_as(config.local_as)
                || attrs.originator_id == Some(router_id)
                || attrs
                    .cluster_list
                    .contains(&config.cluster_id.unwrap_or(router_id));
            for prefix in update.announced {
                if looped {
                    peer.received.remove(&prefix);
                    continue;
                }
                if peer.received.len() >= ROUTE_LIMIT && !peer.received.contains_key(&prefix) {
                    stream.fail(
                        BgpError {
                            code: 6,
                            subcode: 1,
                        },
                        now,
                    );
                    peer.received.clear();
                    break;
                }
                peer.received.insert(prefix, attrs.clone());
            }
        }
        for stream in peer.streams.values() {
            if let Some(error) = stream.fsm.last_error {
                peer.last_error = Some(error);
            }
        }
        if selected
            .and_then(|s| peer.streams.get(&s))
            .is_none_or(|s| s.closing.is_some() || s.fsm.state != BgpState::Established)
        {
            peer.received.clear();
            peer.selected = None;
        }
    }
    pub(super) fn bgp_flush(
        &mut self,
        socket: TcpSocket,
        stream: &mut Stream,
        now: SimTime,
        out: &mut Vec<Ipv4Packet>,
    ) -> bool {
        if stream.closing.is_some_and(|deadline| deadline <= now) {
            if let Ok(packet) = self.tcp_abort(socket) {
                out.push(packet);
            }
            return false;
        }
        let Some(connection) = self.tcp_connections().get(&socket) else {
            return false;
        };
        let capacity = connection.send_capacity();
        if capacity == 0 {
            return true;
        }
        if let Some(message) = stream.output.front() {
            let end = (stream.offset + capacity).min(message.len());
            if let Ok(packet) = self.tcp_send(socket, &message[stream.offset..end], now) {
                out.push(packet);
                stream.offset = end;
                if end == message.len() {
                    stream.output.pop_front();
                    stream.offset = 0;
                }
            }
        } else if stream.closing.is_some()
            && let Ok(packet) = self.tcp_close(socket, now)
        {
            out.push(packet);
            return false;
        }
        true
    }
}
