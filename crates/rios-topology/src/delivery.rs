use crate::*;
use rios_ethernet::MacAddress;
use rios_ipv4::{IpProtocol, Ipv4Packet};
use rios_routing::{HELLO_INTERVAL_MS, OSPF_ALL_ROUTERS};
use rios_switching::{ConfigurationBpdu, STP_ETHERTYPE, STP_HELLO_MS, STP_MULTICAST};
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
        } else {
            self.device(source.device)?
                .check_frame(source.interface, &frame, false)
        };
        if let Err(reason) = check {
            self.devices
                .get_mut(&source.device)
                .unwrap()
                .record_drop(source.interface)?;
            self.trace_frame(source, TraceAction::Drop(reason), &frame);
            return Err(reason.into());
        }
        let link = &self.links[&link_id.unwrap()];
        let target = if source == link.endpoint_a {
            link.endpoint_b
        } else {
            link.endpoint_a
        };
        let time = self
            .now()
            .0
            .checked_add(link.delay_ms)
            .ok_or(rios_simulator::ScheduleError::Overflow)?;
        let length = frame.len();
        let trace = TraceRecord {
            time: self.now(),
            interface: source,
            action: TraceAction::Tx,
            ethertype: frame.ethertype,
            length,
        };
        let event = SimulationEvent::FrameReceived {
            link: link.id,
            generation: link.generation,
            interface: target,
            frame,
        };
        // Schedule before updating TX counters; a scheduling error is not a transmission.
        self.events.schedule_at(SimTime(time), event)?;
        if self.tracing {
            self.trace.push(trace);
        }
        self.devices.get_mut(&source.device).unwrap().record_frame(
            source.interface,
            length,
            false,
        )?;
        Ok(())
    }

    pub(crate) fn transmit_network_frame(
        &mut self,
        source: InterfaceRef,
        frame: EthernetFrame,
    ) -> Result<(), LabError> {
        let Some(vlan) = self.device(source.device)?.svi_vlan(source.interface) else {
            return self.transmit(source, frame);
        };
        if !self.device(source.device)?.protocol_up(source.interface) {
            self.devices
                .get_mut(&source.device)
                .unwrap()
                .record_drop(source.interface)?;
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
                    && connected.contains_key(&InterfaceRef {
                        device: source.device,
                        interface: *port,
                    })
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
                self.transmit(port, frame)?;
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
            SimulationEvent::FrameReceived {
                link,
                generation,
                interface,
                frame,
            } => {
                let check = if !self
                    .links
                    .get(&link)
                    .is_some_and(|l| l.active && l.generation == generation)
                {
                    Err(DropReason::LinkChanged)
                } else {
                    self.device(interface.device)?
                        .check_frame(interface.interface, &frame, true)
                };
                match check {
                    Ok(()) => {
                        self.devices
                            .get_mut(&interface.device)
                            .unwrap()
                            .record_frame(interface.interface, frame.len(), true)?;
                        self.trace_frame(interface, TraceAction::Rx, &frame);
                        if self
                            .device(interface.device)?
                            .is_switchport(interface.interface)
                        {
                            self.handle_switch_frame(interface, &frame)?;
                        } else {
                            self.handle_protocol_frame(interface, &frame)?;
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
                            .record_drop(interface.interface)?;
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
            SimulationEvent::OspfHello { device, generation } => {
                self.send_ospf_packets(device, generation)?;
                return Ok(None);
            }
            SimulationEvent::OspfDead {
                device,
                router_id,
                deadline,
            } => {
                self.devices
                    .get_mut(&device)
                    .ok_or_else(|| LabError::UnknownDevice(device.0.to_string()))?
                    .expire_ospf_neighbor(router_id, deadline);
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
        let interfaces: Vec<_> = self
            .device(device)?
            .ospf_interfaces()
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        for interface in interfaces {
            let Some((source, packets)) = self
                .devices
                .get_mut(&device)
                .unwrap()
                .ospf_packets(interface)
            else {
                continue;
            };
            let endpoint = InterfaceRef { device, interface };
            let source_mac = self.device(device)?.interfaces()[&interface].mac_address;
            for packet in packets {
                let ipv4 = Ipv4Packet {
                    source,
                    destination: OSPF_ALL_ROUTERS,
                    ttl: 1,
                    protocol: IpProtocol::Ospf,
                    payload: packet.encode(),
                };
                self.transmit_network_frame(
                    endpoint,
                    EthernetFrame {
                        destination: MacAddress([0x01, 0x00, 0x5e, 0x00, 0x00, 0x05]),
                        source: source_mac,
                        ethertype: EtherType::Ipv4,
                        payload: ipv4
                            .encode()
                            .map_err(|error| LabError::Protocol(error.to_string()))?,
                    },
                )?;
            }
        }
        let next = self
            .now()
            .0
            .checked_add(HELLO_INTERVAL_MS)
            .ok_or(LabError::Capacity)?;
        self.events.schedule_at(
            SimTime(next),
            SimulationEvent::OspfHello { device, generation },
        )?;
        Ok(())
    }

    fn send_stp_bpdus(
        &mut self,
        device: rios_simulator::DeviceId,
        generation: u64,
    ) -> Result<(), LabError> {
        if self.stp_generations.get(&device) != Some(&generation) {
            return Ok(());
        }
        let now = self.now();
        let bpdus = self.devices.get_mut(&device).unwrap().stp_bpdus(now);
        for (interface, vlan, bpdu) in bpdus {
            let source = InterfaceRef { device, interface };
            let source_mac = self.device(device)?.interfaces()[&interface].mac_address;
            let frame = EthernetFrame {
                destination: MacAddress(STP_MULTICAST),
                source: source_mac,
                ethertype: EtherType::Other(STP_ETHERTYPE),
                payload: bpdu.encode().to_vec(),
            };
            if let Some(frame) = self
                .device(device)?
                .prepare_switch_egress(interface, vlan, frame)
            {
                self.transmit(source, frame)?;
            }
        }
        let next = self
            .now()
            .0
            .checked_add(STP_HELLO_MS)
            .ok_or(LabError::Capacity)?;
        self.events.schedule_at(
            SimTime(next),
            SimulationEvent::StpHello { device, generation },
        )?;
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
        if frame.destination == MacAddress(STP_MULTICAST)
            && frame.ethertype == EtherType::Other(STP_ETHERTYPE)
        {
            if let Ok(bpdu) = ConfigurationBpdu::decode(&frame.payload) {
                let now = self.now();
                self.devices.get_mut(&ingress.device).unwrap().receive_stp(
                    ingress.interface,
                    vlan,
                    bpdu,
                    now,
                );
            }
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
                    && connected.contains_key(&InterfaceRef {
                        device: ingress.device,
                        interface: *port,
                    })
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
                self.transmit(port, frame)?;
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
    frame.destination == MacAddress(STP_MULTICAST)
        && frame.ethertype == EtherType::Other(STP_ETHERTYPE)
}
