use crate::*;
use rios_ethernet::MacAddress;
use rios_switching::{STP_HELLO_MS, STP_MULTICAST, StpBpdu};
impl Lab {
    /// Move a frame into a virtual cable. Delivery occurs only when events are stepped.
    pub fn transmit(&mut self, source: InterfaceRef, frame: EthernetFrame) -> Result<(), LabError> {
        self.device(source.device)?
            .interfaces()
            .get(&source.interface)
            .ok_or_else(|| LabError::UnknownEndpoint(format!("{source:?}")))?;
        let link_id = self.ports.get(&source).copied();
        let check = if link_id.is_none() {
            Err(DropReason::NoLink)
        } else if link_id
            .and_then(|id| self.links.get(&id))
            .is_some_and(|link| link.state == LinkState::Down)
        {
            Err(DropReason::LinkDown)
        } else {
            self.device(source.device)?
                .check_frame(source.interface, &frame, false)
        };
        if let Err(reason) = check {
            self.devices
                .get_mut(&source.device)
                .unwrap()
                .record_drop_reason(source.interface, reason)?;
            self.trace_frame(source, TraceAction::Drop(reason), &frame);
            return Err(reason.into());
        }
        let now = self.now();
        let jitter = self.rng.sample();
        let loss = self.rng.sample();
        let link = self
            .links
            .get_mut(&link_id.ok_or(DropReason::NoLink)?)
            .ok_or(DropReason::NoLink)?;
        let (target, runtime) = if source == link.endpoint_a {
            (link.endpoint_b, &mut link.a_to_b)
        } else {
            (link.endpoint_a, &mut link.b_to_a)
        };
        let length = frame.len();
        let admission = runtime.admit(&link.config, now, length, jitter, loss)?;
        let rios_simulator::Admission::Scheduled { arrival, lost } = admission else {
            self.devices
                .get_mut(&source.device)
                .ok_or(DropReason::NoLink)?
                .record_drop_reason(source.interface, DropReason::QueueFull)?;
            self.trace_frame(source, TraceAction::Drop(DropReason::QueueFull), &frame);
            return Err(DropReason::QueueFull.into());
        };
        let id = link.id;
        let generation = link.generation;
        self.trace_frame(source, TraceAction::Tx, &frame);
        self.events.schedule_at(
            arrival,
            SimulationEvent::FrameReceived {
                link: id,
                generation,
                interface: target,
                source,
                lost,
                frame,
            },
        )?;
        self.devices.get_mut(&source.device).unwrap().record_frame(
            source.interface,
            length,
            false,
        )?;
        Ok(())
    }

    fn transmit_protocol(
        &mut self,
        source: InterfaceRef,
        frame: EthernetFrame,
    ) -> Result<(), LabError> {
        let source = if self
            .device(source.device)?
            .is_port_channel(source.interface)
        {
            let Some(member) = self
                .device(source.device)?
                .channel_egress(source.interface, &frame)
            else {
                self.devices
                    .get_mut(&source.device)
                    .ok_or(DropReason::NoLink)?
                    .record_drop_reason(source.interface, DropReason::ChannelInactive)?;
                return Ok(());
            };
            self.devices
                .get_mut(&source.device)
                .ok_or(DropReason::NoLink)?
                .record_frame(source.interface, frame.len(), false)?;
            InterfaceRef {
                device: source.device,
                interface: member,
            }
        } else {
            source
        };
        match self.transmit(source, frame) {
            Err(LabError::Dropped(_)) => Ok(()),
            other => other,
        }
    }

    pub(crate) fn transmit_network_frame(
        &mut self,
        source: InterfaceRef,
        frame: EthernetFrame,
    ) -> Result<(), LabError> {
        if self
            .device(source.device)?
            .running_config()
            .interfaces
            .get(&source.interface)
            .is_some_and(|config| config.parent.is_some())
        {
            let length = frame.len();
            let Some((parent, wire)) = self
                .device(source.device)?
                .subinterface_egress(source.interface, frame)
            else {
                self.devices
                    .get_mut(&source.device)
                    .ok_or(DropReason::NoLink)?
                    .record_drop_reason(source.interface, DropReason::InterfaceDown)?;
                return Ok(());
            };
            self.devices
                .get_mut(&source.device)
                .ok_or(DropReason::NoLink)?
                .record_frame(source.interface, length, false)?;
            return self.transmit_protocol(
                InterfaceRef {
                    device: source.device,
                    interface: parent,
                },
                wire,
            );
        }
        let Some(vlan) = self.device(source.device)?.svi_vlan(source.interface) else {
            return self.transmit_protocol(source, frame);
        };
        if !self.device(source.device)?.protocol_up(source.interface) {
            self.devices
                .get_mut(&source.device)
                .unwrap()
                .record_drop_reason(source.interface, DropReason::InterfaceDown)?;
            self.trace_frame(source, TraceAction::Drop(DropReason::InterfaceDown), &frame);
            return Err(DropReason::InterfaceDown.into());
        }

        let now = self.now();
        let connected = &self.ports;
        let device = self.devices.get_mut(&source.device).unwrap();
        device.refresh_spanning_tree(now);
        let learned = if frame.destination.is_multicast() {
            None
        } else {
            device.mac_lookup(vlan, frame.destination, now)
        };
        let egress: Vec<_> = device
            .interfaces()
            .keys()
            .copied()
            .filter(|port| {
                learned.is_none_or(|entry| entry.interface == *port)
                    && device.protocol_up(*port)
                    && device.stp_forwarding(*port, vlan)
                    && device.channel_interface(*port).is_none()
                    && (device.is_port_channel(*port)
                        || connected.contains_key(&InterfaceRef {
                            device: source.device,
                            interface: *port,
                        }))
            })
            .map(|interface| InterfaceRef {
                device: source.device,
                interface,
            })
            .collect();
        let length = frame.len();
        for port in egress {
            if let Some(frame) =
                self.device(port.device)?
                    .prepare_switch_egress(port.interface, vlan, frame.clone())
            {
                self.transmit_protocol(port, frame)?;
            }
        }
        self.devices.get_mut(&source.device).unwrap().record_frame(
            source.interface,
            length,
            false,
        )?;
        self.trace_frame(source, TraceAction::Tx, &frame);
        Ok(())
    }
    /// Process one event, advancing simulated time and returning delivery ownership.
    pub fn step(&mut self) -> Result<Option<EventOutcome>, LabError> {
        self.purge_pending();
        let Some(scheduled) = self.events.step() else {
            return Ok(None);
        };
        let outcome = match scheduled.event {
            SimulationEvent::LacpTick { device } => {
                self.lacp_timer(device)?;
                return Ok(None);
            }
            SimulationEvent::TcpTick { device } => {
                self.tcp_timer(device)?;
                return Ok(None);
            }
            SimulationEvent::FrameReceived {
                link,
                generation,
                interface,
                frame,
                source,
                lost,
            } => {
                let check = if !self
                    .links
                    .get(&link)
                    .is_some_and(|l| l.active && l.generation == generation)
                {
                    Err(DropReason::LinkChanged)
                } else if lost {
                    Err(DropReason::SimulatedLoss)
                } else {
                    self.device(interface.device)?
                        .check_frame(interface.interface, &frame, true)
                };
                if let Some(cable) = self.links.get_mut(&link) {
                    let counters = if cable.endpoint_a == source {
                        &mut cable.a_to_b.counters
                    } else {
                        &mut cable.b_to_a.counters
                    };
                    match check {
                        Ok(()) => {
                            counters.rx_packets = counters.rx_packets.saturating_add(1);
                            counters.rx_bytes =
                                counters.rx_bytes.saturating_add(frame.len() as u64);
                        }
                        Err(DropReason::SimulatedLoss) => {
                            counters.loss_drops = counters.loss_drops.saturating_add(1)
                        }
                        Err(DropReason::LinkChanged) => {
                            counters.changed_drops = counters.changed_drops.saturating_add(1)
                        }
                        _ => {}
                    }
                }
                match check {
                    Ok(()) => {
                        self.devices
                            .get_mut(&interface.device)
                            .unwrap()
                            .record_frame(interface.interface, frame.len(), true)?;
                        self.trace_frame(interface, TraceAction::Rx, &frame);
                        if self.handle_lacp_frame(interface, &frame)? {
                            return Ok(Some(EventOutcome::FrameReceived { interface, frame }));
                        }
                        let logical_interface = match self
                            .device(interface.device)?
                            .channel_ingress(interface.interface)
                        {
                            Ok(logical) => InterfaceRef {
                                device: interface.device,
                                interface: logical,
                            },
                            Err(reason) => {
                                self.devices
                                    .get_mut(&interface.device)
                                    .ok_or(reason)?
                                    .record_drop_reason(interface.interface, reason)?;
                                return Ok(Some(EventOutcome::FrameDropped { interface, reason }));
                            }
                        };
                        if logical_interface != interface {
                            self.devices
                                .get_mut(&interface.device)
                                .ok_or(DropReason::NoLink)?
                                .record_frame(logical_interface.interface, frame.len(), true)?;
                        }
                        if self
                            .device(interface.device)?
                            .is_switchport(logical_interface.interface)
                        {
                            self.handle_switch_frame(logical_interface, &frame)?;
                        } else {
                            if let Some((logical, inner)) = self
                                .device(interface.device)?
                                .routed_ingress(logical_interface.interface, &frame)
                            {
                                let logical = InterfaceRef {
                                    device: interface.device,
                                    interface: logical,
                                };
                                if logical != logical_interface {
                                    self.devices
                                        .get_mut(&logical.device)
                                        .ok_or(DropReason::NoLink)?
                                        .record_frame(logical.interface, inner.len(), true)?;
                                }
                                self.handle_protocol_frame(logical, &inner)?;
                            }
                        }
                        if is_stp_frame(&frame) {
                            return Ok(None);
                        }
                        EventOutcome::FrameReceived { interface, frame }
                    }
                    Err(reason) => {
                        self.devices
                            .get_mut(&interface.device)
                            .ok_or_else(|| LabError::UnknownDevice(interface.device.0.to_string()))?
                            .record_drop_reason(interface.interface, reason)?;
                        self.trace_frame(interface, TraceAction::Drop(reason), &frame);
                        EventOutcome::FrameDropped { interface, reason }
                    }
                }
            }
            SimulationEvent::LinkStateChanged { link, state } => {
                self.set_link_state(link, state)?;
                EventOutcome::LinkStateChanged { link, state }
            }
            SimulationEvent::TimerExpired { timer } => EventOutcome::TimerExpired { timer },
            SimulationEvent::Ipv6Timer { device, generation } => {
                self.tick_ipv6(device, generation)?;
                return Ok(None);
            }
            SimulationEvent::OspfHello { device, generation } => {
                self.send_ospf_packets(device, generation)?;
                return Ok(None);
            }
            SimulationEvent::StpHello { device, generation } => {
                self.send_stp_bpdus(device, generation)?;
                return Ok(None);
            }
            SimulationEvent::DhcpClient { device, generation } => {
                self.send_dhcp_discovers(device, generation)?;
                return Ok(None);
            }
            SimulationEvent::DhcpProbe { interface, xid } => {
                self.finish_dhcp_probe(interface, xid)?;
                return Ok(None);
            }
            SimulationEvent::DhcpRenew {
                interface,
                deadline,
            } => {
                self.renew_dhcp(interface, deadline)?;
                return Ok(None);
            }
            SimulationEvent::DhcpLeaseExpired {
                device,
                interface,
                address,
                deadline,
            } => {
                if self
                    .devices
                    .get_mut(&device)
                    .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
                    .expire_dhcp_lease(interface, address, deadline)
                {
                    self.schedule_dhcp_now(device)?;
                }
                return Ok(None);
            }
        };
        Ok(Some(outcome))
    }

    fn send_ospf_packets(
        &mut self,
        device: rios_simulator::DeviceId,
        generation: u64,
    ) -> Result<(), LabError> {
        if self.ospf_generations.get(&device) != Some(&generation) {
            return Ok(());
        }
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&device)
            .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
            .ospf_tick(now);
        self.emit_ospf(device, packets)?;
        self.schedule_ospf_timer(device)
    }

    fn send_stp_bpdus(
        &mut self,
        device: rios_simulator::DeviceId,
        generation: u64,
    ) -> Result<(), LabError> {
        if self.stp_generations.get(&device) != Some(&generation) {
            return Ok(());
        }
        self.emit_stp_bpdus(device)?;
        let next = self
            .now()
            .0
            .checked_add(STP_HELLO_MS * 1000)
            .ok_or(LabError::Capacity)?;
        self.events.schedule_at(
            SimTime(next),
            SimulationEvent::StpHello { device, generation },
        )?;
        Ok(())
    }

    fn emit_stp_bpdus(&mut self, device: rios_simulator::DeviceId) -> Result<(), LabError> {
        let now = self.now();
        let packets = self
            .devices
            .get_mut(&device)
            .ok_or(DropReason::NoLink)?
            .stp_packets(now);
        for (interface, vlan, packet) in packets {
            let source = InterfaceRef { device, interface };
            let payload = packet.encode();
            let frame = EthernetFrame {
                destination: MacAddress(STP_MULTICAST),
                source: self.device(device)?.interfaces()[&interface].mac_address,
                ethertype: EtherType::Length(payload.len() as u16),
                payload,
            };
            if let Some(frame) = self
                .device(device)?
                .prepare_switch_egress(interface, vlan, frame)
            {
                self.transmit_protocol(source, frame)?;
            }
        }
        Ok(())
    }

    fn handle_switch_frame(
        &mut self,
        ingress: InterfaceRef,
        frame: &EthernetFrame,
    ) -> Result<(), LabError> {
        let Some((vlan, frame)) = self
            .device(ingress.device)?
            .classify_switch_ingress(ingress.interface, frame)
        else {
            return Ok(());
        };
        if frame.destination == MacAddress(STP_MULTICAST) {
            if let Ok(bpdu) = StpBpdu::decode(&frame.payload) {
                let now = self.now();
                let changed = self
                    .devices
                    .get_mut(&ingress.device)
                    .ok_or(DropReason::NoLink)?
                    .receive_stp_packet(ingress.interface, vlan, bpdu, now);
                if changed {
                    self.emit_stp_bpdus(ingress.device)?;
                }
            }
            return Ok(());
        }
        let now = self.now();
        let device = self
            .devices
            .get_mut(&ingress.device)
            .ok_or(DropReason::NoLink)?;
        device.refresh_spanning_tree(now);
        if !device.stp_forwarding(ingress.interface, vlan) {
            if device.stp_learning(ingress.interface, vlan) {
                device.learn_mac(vlan, frame.source, ingress.interface, now)?;
            }
            device.record_drop_reason(ingress.interface, DropReason::StpBlocking)?;
            self.trace_frame(ingress, TraceAction::Drop(DropReason::StpBlocking), &frame);
            return Ok(());
        }
        if let Some(svi) = self.device(ingress.device)?.active_svi(vlan) {
            let svi = InterfaceRef {
                device: ingress.device,
                interface: svi,
            };
            let local_mac = self.device(svi.device)?.interfaces()[&svi.interface].mac_address;
            if frame.destination == local_mac || frame.destination.is_multicast() {
                self.handle_protocol_frame(svi, &frame)?;
            }
            if frame.destination == local_mac {
                return Ok(());
            }
        }
        self.forward_switch_frame(ingress, vlan, frame)
    }

    fn forward_switch_frame(
        &mut self,
        ingress: InterfaceRef,
        vlan: rios_ethernet::VlanId,
        frame: EthernetFrame,
    ) -> Result<(), LabError> {
        let now = self.now();
        let connected = &self.ports;
        let device = self.devices.get_mut(&ingress.device).unwrap();
        if !device.stp_forwarding(ingress.interface, vlan) {
            device.record_drop_reason(ingress.interface, DropReason::StpBlocking)?;
            self.trace_frame(ingress, TraceAction::Drop(DropReason::StpBlocking), &frame);
            return Ok(());
        }
        device.learn_mac(vlan, frame.source, ingress.interface, now)?;
        let learned = if frame.destination.is_multicast() {
            None
        } else {
            device.mac_lookup(vlan, frame.destination, now)
        };
        let egress: Vec<_> = device
            .interfaces()
            .keys()
            .copied()
            .filter(|port| {
                *port != ingress.interface
                    && learned.is_none_or(|entry| entry.interface == *port)
                    && device.protocol_up(*port)
                    && device.stp_forwarding(*port, vlan)
                    && device.channel_interface(*port).is_none()
                    && (device.is_port_channel(*port)
                        || connected.contains_key(&InterfaceRef {
                            device: ingress.device,
                            interface: *port,
                        }))
            })
            .map(|interface| InterfaceRef {
                device: ingress.device,
                interface,
            })
            .collect();
        for port in egress {
            if let Some(frame) =
                self.device(port.device)?
                    .prepare_switch_egress(port.interface, vlan, frame.clone())
            {
                self.transmit_protocol(port, frame)?;
            }
        }
        Ok(())
    }
    /// Process events through an inclusive deadline, then advance through idle time.
    pub fn run_until(&mut self, time: SimTime) -> Result<Vec<EventOutcome>, LabError> {
        if time < self.now() {
            return Err(rios_simulator::ScheduleError::Past.into());
        }
        let mut out = Vec::new();
        while self.events.next_time().is_some_and(|next| next <= time) {
            if let Some(event) = self.step()? {
                out.push(event);
            }
        }
        self.events.advance_to(time)?;
        self.purge_pending();
        Ok(out)
    }
}

fn is_stp_frame(frame: &EthernetFrame) -> bool {
    let frame = if frame.ethertype == EtherType::Dot1Q {
        let Ok((_, inner)) = frame.untagged() else {
            return false;
        };
        inner
    } else {
        frame.clone()
    };
    frame.destination == MacAddress(STP_MULTICAST) && StpBpdu::decode(&frame.payload).is_ok()
}
