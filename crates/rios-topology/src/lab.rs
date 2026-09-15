use crate::*;
use rios_config::AdminState;
use rios_device::{Device, DeviceType, InterfaceMedia};
use rios_ipv4::Ipv4Packet;
use rios_simulator::{DeviceId, EventQueue, InterfaceRef, SimTime};
use std::collections::BTreeMap;

/// Single owner of a lab's devices, links, clock, and pending traffic.
#[derive(Debug, Default)]
pub struct Lab {
    pub(crate) lacp_timers: std::collections::BTreeSet<DeviceId>,
    pub(crate) tcp_timers: std::collections::BTreeSet<DeviceId>,
    pub(crate) capture: Option<crate::capture::Capture>,
    pub(crate) seed: u64,
    pub(crate) rng: rios_simulator::SimulationRng,
    next_link_id: u64,
    pub(crate) devices: BTreeMap<DeviceId, Device>,
    pub(crate) names: BTreeMap<String, DeviceId>,
    pub(crate) links: BTreeMap<LinkId, Link>,
    pub(crate) ports: BTreeMap<InterfaceRef, LinkId>,
    pub(crate) events: EventQueue<SimulationEvent>,
    pub(crate) tracing: bool,
    pub(crate) trace: Vec<TraceRecord>,
    pub(crate) next_ping_id: u16,
    pub(crate) pending_ipv4: Vec<PendingIpv4>,
    pub(crate) ospf_generations: BTreeMap<DeviceId, u64>,
    pub(crate) stp_generations: BTreeMap<DeviceId, u64>,
    pub(crate) dhcp_generations: BTreeMap<DeviceId, u64>,
    pub(crate) dhcp_transactions: BTreeMap<InterfaceRef, u32>,
    pub(crate) next_dhcp_xid: u32,
    pub(crate) dhcp_probes: BTreeMap<InterfaceRef, rios_protocol::DhcpMessage>,
    pub(crate) dhcp_retry_after: BTreeMap<InterfaceRef, SimTime>,
}

#[derive(Debug)]
pub(crate) struct PendingIpv4 {
    pub(crate) source: InterfaceRef,
    pub(crate) next_hop: std::net::Ipv4Addr,
    pub(crate) packet: Ipv4Packet,
    pub(crate) expires_at: SimTime,
}
impl Lab {
    /// Construct a lab with a reproducible random stream for link impairments.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            seed,
            rng: rios_simulator::SimulationRng(seed),
            ..Self::default()
        }
    }
    /// Add a device with generated GigabitEthernet ports for interactive lab building.
    pub fn spawn_device(
        &mut self,
        name: &str,
        device_type: DeviceType,
        ports: usize,
    ) -> Result<DeviceId, LabError> {
        self.spawn_device_with_ports(name, device_type, &[(InterfaceMedia::Rj45, ports)])
    }

    /// Add a device with an explicit deterministic physical port inventory.
    pub fn spawn_device_with_ports(
        &mut self,
        name: &str,
        device_type: DeviceType,
        ports: &[(InterfaceMedia, usize)],
    ) -> Result<DeviceId, LabError> {
        let total = ports.iter().try_fold(0usize, |total, (_, count)| {
            total.checked_add(*count).ok_or(LabError::Capacity)
        })?;
        if total == 0 || total > 4096 {
            return Err(LabError::InvalidTopology(
                "physical port count must be between 1 and 4096".into(),
            ));
        }
        let id = self
            .devices
            .last_key_value()
            .map_or(Ok(DeviceId(1)), |(id, _)| {
                id.0.checked_add(1).map(DeviceId).ok_or(LabError::Capacity)
            })?;
        let mut device = Device::new(id, name, device_type)?;
        let (mut gigabit, mut ten_gigabit, mut serial, mut console) = (0, 0, 0, 0);
        for (media, count) in ports {
            for _ in 0..*count {
                let name = match media {
                    InterfaceMedia::Rj45 | InterfaceMedia::Sfp => {
                        let name = format!("GigabitEthernet0/{gigabit}");
                        gigabit += 1;
                        name
                    }
                    InterfaceMedia::SfpPlus => {
                        let name = format!("TenGigabitEthernet0/{ten_gigabit}");
                        ten_gigabit += 1;
                        name
                    }
                    InterfaceMedia::Serial => {
                        let name = format!("Serial0/{serial}");
                        serial += 1;
                        name
                    }
                    InterfaceMedia::Console => {
                        let name = format!("Console{console}");
                        console += 1;
                        name
                    }
                    InterfaceMedia::Virtual => {
                        return Err(LabError::InvalidTopology(
                            "virtual interfaces cannot be hardware ports".into(),
                        ));
                    }
                };
                device.add_port(&name, *media)?;
            }
        }
        self.add_device(name, device).map(|()| id)
    }

    /// Render the current inventory and cables as a reusable YAML topology.
    pub fn render_yaml(&self) -> String {
        let mut output = format!("seed: {}\ndevices:\n", self.seed);
        for (name, id) in self.device_names() {
            let device = self.devices.get(&id).expect("device name index is valid");
            let kind = match device.device_type() {
                DeviceType::Router => "router",
                DeviceType::Switch => "switch",
                DeviceType::Layer3Switch => "layer3-switch",
                DeviceType::Host => "host",
            };
            output.push_str(&format!(
                "  {}:\n    type: {kind}\n    interfaces:\n",
                yaml_quote(name)
            ));
            for (id, config) in &device.running_config().interfaces {
                let interface = &device.interfaces()[id];
                if interface.media == InterfaceMedia::Rj45
                    || interface.media == InterfaceMedia::Virtual
                {
                    output.push_str(&format!("      - {}\n", yaml_quote(&config.name)));
                } else if interface.kind.is_physical() {
                    let media = match interface.media {
                        InterfaceMedia::Rj45 => "rj45",
                        InterfaceMedia::Sfp => "sfp",
                        InterfaceMedia::SfpPlus => "sfp+",
                        InterfaceMedia::Serial => "serial",
                        InterfaceMedia::Console => "console",
                        InterfaceMedia::Virtual => unreachable!(),
                    };
                    output.push_str(&format!(
                        "      - name: {}\n        media: {media}\n",
                        yaml_quote(&config.name)
                    ));
                }
            }
            if device.running_config().interfaces.is_empty() {
                output.push_str("      []\n");
            }
        }
        if self.links.is_empty() {
            return output;
        }
        output.push_str("links:\n");
        for link in self.links.values() {
            output.push_str("  - endpoints:\n");
            output.push_str(&format!(
                "      - {}\n      - {}\n    delay_ms: {}\n",
                yaml_quote(&self.endpoint_inventory_name(link.endpoint_a)),
                yaml_quote(&self.endpoint_inventory_name(link.endpoint_b)),
                link.delay_ms
            ));
            if let Some(rate) = link.config.bandwidth {
                output.push_str(&format!("    bandwidth: {}bps\n", rate.bits_per_second()));
            }
            output.push_str(&format!(
                "    jitter_ms: {}\n    loss_percent: {}.{:04}\n    queue_packets: {}\n",
                link.config.jitter_us / 1000,
                link.config.loss_ppm / 10_000,
                link.config.loss_ppm % 10_000,
                link.config.queue_packets
            ));
        }
        output
    }

    fn endpoint_inventory_name(&self, endpoint: InterfaceRef) -> String {
        let device = self
            .devices
            .get(&endpoint.device)
            .expect("endpoint device exists");
        let name = self
            .names
            .iter()
            .find_map(|(name, id)| (*id == endpoint.device).then_some(name.as_str()))
            .expect("endpoint device has an inventory name");
        let interface = device
            .running_config()
            .interfaces
            .get(&endpoint.interface)
            .expect("endpoint interface exists");
        format!("{name}:{}", interface.name)
    }

    /// Add inventory using a stable lab name independent of the editable hostname.
    pub fn add_device(&mut self, name: &str, mut device: Device) -> Result<(), LabError> {
        if name.is_empty()
            || name
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == ':')
        {
            return Err(LabError::InvalidTopology("invalid device name".into()));
        }
        if self.names.contains_key(name) || self.devices.contains_key(&device.id()) {
            return Err(LabError::InvalidTopology(
                "duplicate device name or ID".into(),
            ));
        }
        for id in device.interfaces().keys().copied().collect::<Vec<_>>() {
            device.set_link_state(id, LinkState::Down)?;
        }
        let id = device.id();
        self.names.insert(name.into(), id);
        self.devices.insert(id, device);
        self.schedule_lacp(id)?;
        self.schedule_stp_now(id)?;
        self.schedule_dhcp_now(id)?;
        Ok(())
    }
    /// Stable lab names in sorted order.
    pub fn device_names(&self) -> impl Iterator<Item = (&str, DeviceId)> {
        self.names.iter().map(|(name, id)| (name.as_str(), *id))
    }
    /// Resolve a lab name; renaming a device hostname does not change this key.
    pub fn device_id(&self, name: &str) -> Result<DeviceId, LabError> {
        self.names
            .get(name)
            .copied()
            .ok_or_else(|| LabError::UnknownDevice(name.into()))
    }
    /// Read-only device state.
    pub fn device(&self, id: DeviceId) -> Result<&Device, LabError> {
        self.devices
            .get(&id)
            .ok_or_else(|| LabError::UnknownDevice(id.0.to_string()))
    }
    /// Edit device configuration through existing device APIs, then synchronize carrier.
    /// Identity or existing hardware replacement is rejected without committing edits.
    pub fn with_device_mut<R>(
        &mut self,
        id: DeviceId,
        edit: impl FnOnce(&mut Device) -> R,
    ) -> Result<R, LabError> {
        let original = self.device(id)?;
        // ponytail: clone metadata per edit; use a restricted editor if large inventories make this costly.
        let mut candidate = original.clone();
        let result = edit(&mut candidate);
        if candidate.id() != id
            || candidate.device_type() != original.device_type()
            || original.interfaces().iter().any(|(id, old)| {
                candidate.interfaces().get(id).is_none_or(|new| {
                    new.id != old.id || new.kind != old.kind || new.mac_address != old.mac_address
                }) || candidate
                    .running_config()
                    .interfaces
                    .get(id)
                    .is_none_or(|new| new.name != original.running_config().interfaces[id].name)
            })
        {
            return Err(LabError::InvalidTopology(
                "device edits cannot replace existing hardware or identity".into(),
            ));
        }
        for interface in candidate.interfaces().keys().copied().collect::<Vec<_>>() {
            if !self.ports.contains_key(&InterfaceRef {
                device: id,
                interface,
            }) {
                candidate.set_link_state(interface, LinkState::Down)?;
            }
        }
        self.devices.insert(id, candidate);
        self.refresh_carriers()?;
        self.schedule_lacp(id)?;
        self.schedule_ospf_now(id)?;
        self.schedule_stp_now(id)?;
        self.schedule_dhcp_now(id)?;
        Ok(result)
    }
    /// Current virtual time in milliseconds.
    pub fn now(&self) -> SimTime {
        self.events.now()
    }
    /// Pending event count.
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }
    pub(crate) fn next_event_time(&self) -> Option<SimTime> {
        self.events.next_time()
    }
    /// Read-only link inventory.
    pub fn links(&self) -> &BTreeMap<LinkId, Link> {
        &self.links
    }
    /// Resolve DEVICE:INTERFACE, accepting the device API's interface abbreviations.
    pub fn endpoint(&self, name: &str) -> Result<InterfaceRef, LabError> {
        let (device, interface) = name
            .split_once(':')
            .ok_or_else(|| LabError::UnknownEndpoint(name.into()))?;
        let id = self.device_id(device)?;
        let (canonical, _) = rios_device::canonical_interface(interface)?;
        let interface = self
            .device(id)?
            .find_interface(&canonical)
            .ok_or_else(|| LabError::UnknownEndpoint(name.into()))?;
        Ok(InterfaceRef {
            device: id,
            interface,
        })
    }
    /// Human-readable endpoint using the current hostname and canonical interface name.
    pub fn endpoint_name(&self, endpoint: InterfaceRef) -> String {
        match self.device(endpoint.device) {
            Ok(device) => match device.running_config().interfaces.get(&endpoint.interface) {
                Some(interface) => format!("{}:{}", device.hostname(), interface.name),
                None => format!("{:?}", endpoint),
            },
            Err(_) => format!("{:?}", endpoint),
        }
    }
    /// Attach one cable to two distinct physical interfaces, initially cable-up.
    pub fn connect(
        &mut self,
        a: InterfaceRef,
        b: InterfaceRef,
        delay_ms: u64,
    ) -> Result<LinkId, LabError> {
        let delay_us = delay_ms.checked_mul(1000).ok_or(ScheduleError::Overflow)?;
        self.connect_configured(
            a,
            b,
            rios_simulator::LinkConfig {
                delay_us,
                ..Default::default()
            },
        )
    }

    /// Attach a full-duplex cable with validated transmission policy.
    pub fn connect_configured(
        &mut self,
        a: InterfaceRef,
        b: InterfaceRef,
        config: rios_simulator::LinkConfig,
    ) -> Result<LinkId, LabError> {
        config
            .validate()
            .map_err(|error| LabError::InvalidTopology(error.into()))?;
        if a == b {
            return Err(LabError::InvalidTopology(
                "link endpoints must differ".into(),
            ));
        }
        for endpoint in [a, b] {
            let interface = self
                .device(endpoint.device)?
                .interfaces()
                .get(&endpoint.interface)
                .ok_or_else(|| LabError::UnknownEndpoint(format!("{endpoint:?}")))?;
            if !interface.kind.is_ethernet() {
                return Err(LabError::InvalidTopology(
                    "links require physical Ethernet interfaces".into(),
                ));
            }
            if self.ports.contains_key(&endpoint) {
                return Err(LabError::InvalidTopology(
                    "interface already has a link".into(),
                ));
            }
        }
        let media_a = self.device(a.device)?.interfaces()[&a.interface].media;
        let media_b = self.device(b.device)?.interfaces()[&b.interface].media;
        if media_a != media_b {
            return Err(LabError::InvalidTopology(format!(
                "incompatible port media: {media_a} and {media_b}"
            )));
        }
        let id = LinkId(self.next_link_id.checked_add(1).ok_or(LabError::Capacity)?);
        self.next_link_id = id.0;
        self.links.insert(
            id,
            Link {
                id,
                endpoint_a: a,
                endpoint_b: b,
                state: LinkState::Up,
                delay_ms: config.delay_us / 1000,
                config,
                a_to_b: Default::default(),
                b_to_a: Default::default(),
                active: false,
                generation: 0,
            },
        );
        self.ports.insert(a, id);
        self.ports.insert(b, id);
        self.refresh_carriers()?;
        Ok(id)
    }

    /// Remove a virtual cable and drop carrier on both endpoints.
    pub fn disconnect(&mut self, id: LinkId) -> Result<(), LabError> {
        let link = self.links.remove(&id).ok_or(LabError::UnknownLink(id))?;
        self.ports.remove(&link.endpoint_a);
        self.ports.remove(&link.endpoint_b);
        for endpoint in [link.endpoint_a, link.endpoint_b] {
            self.devices
                .get_mut(&endpoint.device)
                .ok_or_else(|| LabError::UnknownDevice(endpoint.device.0.to_string()))?
                .set_link_state(endpoint.interface, LinkState::Down)?;
        }
        self.refresh_carriers()
    }
    pub(crate) fn refresh_carriers(&mut self) -> Result<(), LabError> {
        for link in self.links.values_mut() {
            let enabled = |endpoint: InterfaceRef| {
                self.devices
                    .get(&endpoint.device)
                    .and_then(|d| d.running_config().interfaces.get(&endpoint.interface))
                    .is_some_and(|c| c.admin_state == AdminState::Up)
            };
            let active =
                link.state == LinkState::Up && enabled(link.endpoint_a) && enabled(link.endpoint_b);
            if active != link.active {
                link.generation = link.generation.checked_add(1).ok_or(LabError::Capacity)?;
                link.active = active;
                link.a_to_b.reset();
                link.b_to_a.reset();
            }
            for endpoint in [link.endpoint_a, link.endpoint_b] {
                self.devices
                    .get_mut(&endpoint.device)
                    .ok_or_else(|| LabError::UnknownDevice(endpoint.device.0.to_string()))?
                    .set_link_state(
                        endpoint.interface,
                        if active {
                            LinkState::Up
                        } else {
                            LinkState::Down
                        },
                    )?;
            }
        }
        for device in self.devices.values_mut() {
            device.refresh_svi_states();
        }
        Ok(())
    }
    pub(crate) fn schedule_ospf_now(&mut self, device: DeviceId) -> Result<(), LabError> {
        if self.device(device)?.running_config().ospf.is_none() {
            return Ok(());
        }
        let generation = self.ospf_generations.entry(device).or_default();
        *generation = generation.checked_add(1).ok_or(LabError::Capacity)?;
        let generation = *generation;
        self.events.schedule_at(
            self.now(),
            SimulationEvent::OspfHello { device, generation },
        )?;
        Ok(())
    }
    pub(crate) fn schedule_stp_now(&mut self, device: DeviceId) -> Result<(), LabError> {
        if !self.device(device)?.supports_switching() {
            return Ok(());
        }
        let generation = self.stp_generations.entry(device).or_default();
        *generation = generation.checked_add(1).ok_or(LabError::Capacity)?;
        let generation = *generation;
        self.events
            .schedule_at(self.now(), SimulationEvent::StpHello { device, generation })?;
        Ok(())
    }
    pub(crate) fn schedule_dhcp_now(&mut self, device: DeviceId) -> Result<(), LabError> {
        let generation = self.dhcp_generations.entry(device).or_default();
        *generation = generation.checked_add(1).ok_or(LabError::Capacity)?;
        let generation = *generation;
        self.dhcp_probes
            .retain(|interface, _| interface.device != device);
        self.dhcp_transactions
            .retain(|interface, _| interface.device != device);
        if !self.device(device)?.has_pending_dhcp_client() {
            return Ok(());
        }
        self.events.schedule_at(
            self.now(),
            SimulationEvent::DhcpClient { device, generation },
        )?;
        Ok(())
    }
    /// Apply a cable state change now; invalidates traffic crossing an outage.
    pub fn set_link_state(&mut self, id: LinkId, state: LinkState) -> Result<(), LabError> {
        self.links
            .get_mut(&id)
            .ok_or(LabError::UnknownLink(id))?
            .state = state;
        self.refresh_carriers()
    }
    /// Schedule a future cable state change on the same deterministic event queue.
    pub fn schedule_link_state(
        &mut self,
        id: LinkId,
        state: LinkState,
        time: SimTime,
    ) -> Result<(), LabError> {
        if !self.links.contains_key(&id) {
            return Err(LabError::UnknownLink(id));
        }
        self.events
            .schedule_at(time, SimulationEvent::LinkStateChanged { link: id, state })?;
        Ok(())
    }
    /// Schedule a protocol-neutral timer, without sleeping or spawning a thread.
    pub fn schedule_timer(&mut self, timer: TimerId, delay_ms: u64) -> Result<(), LabError> {
        self.events
            .schedule_after(delay_ms, SimulationEvent::TimerExpired { timer })?;
        Ok(())
    }
    /// Enable optional packet trace collection. Disabling releases retained records.
    pub fn set_tracing(&mut self, enabled: bool) {
        self.tracing = enabled;
        if !enabled {
            self.trace.clear();
        }
    }
    /// Drain collected metadata so frontends control trace retention.
    pub fn take_trace(&mut self) -> Vec<TraceRecord> {
        std::mem::take(&mut self.trace)
    }
    pub(crate) fn trace_frame(
        &mut self,
        interface: InterfaceRef,
        action: TraceAction,
        frame: &EthernetFrame,
    ) {
        self.capture_frame(interface, action, frame);
        if self.tracing {
            self.trace.push(TraceRecord {
                time: self.now(),
                interface,
                action,
                ethertype: frame.ethertype,
                length: frame.len(),
            });
        }
    }
}

fn yaml_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
