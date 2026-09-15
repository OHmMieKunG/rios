//! Physical output queues feed the existing deterministic cable serializer and capture path.
use crate::*;
use rios_device::QosProfile;
use rios_simulator::{DeviceId, QosClassCounters, QosScheduler, QueueRejectReason};

#[derive(Debug)]
pub(crate) struct QosPortRuntime {
    profile: QosProfile,
    link: LinkId,
    generation: u64,
    capacity: usize,
    queue: QosScheduler<EthernetFrame>,
    wakes: std::collections::BTreeMap<SimTime, u64>,
}
/// Structured queue observations, also usable by grading and nonterminal frontends.
#[derive(Debug, Clone)]
pub struct QosPortStatistics {
    pub interface: InterfaceRef,
    pub profile: QosProfile,
    pub classes: Vec<(QosClassCounters, usize)>,
}
impl Lab {
    /// Observe class counters and waiting depths without changing queue state or time.
    pub fn qos_statistics(&self, device: DeviceId) -> Vec<QosPortStatistics> {
        self.qos_queues
            .iter()
            .filter(|(port, _)| port.device == device)
            .map(|(interface, runtime)| QosPortStatistics {
                interface: *interface,
                profile: runtime.profile.clone(),
                classes: runtime
                    .queue
                    .statistics()
                    .map(|(c, depth)| (c.clone(), depth))
                    .collect(),
            })
            .collect()
    }
    /// Render physical-interface service policy and real queue counters.
    pub fn show_policy_map_interface(&self, device: DeviceId) -> Result<String, LabError> {
        self.show_policy_map_port(device, None)
    }
    /// Render all physical policies or one selected interface.
    pub fn show_policy_map_port(
        &self,
        device: DeviceId,
        interface: Option<rios_simulator::InterfaceId>,
    ) -> Result<String, LabError> {
        use std::fmt::Write;
        let selected = interface;
        let mut out = String::new();
        for (id, interface) in self.device(device)?.running_config().interfaces.iter() {
            if selected.is_some_and(|selected| selected != *id) {
                continue;
            }
            let source = InterfaceRef {
                device,
                interface: *id,
            };
            let rate = self
                .ports
                .get(&source)
                .and_then(|id| self.links.get(id))
                .and_then(|l| l.config.bandwidth)
                .map(|b| b.bits_per_second());
            let Some(profile) = self.device(device)?.qos_profile(*id, rate) else {
                continue;
            };
            let _ = writeln!(
                out,
                "{}\n  Service-policy output: {}",
                interface.name, profile.name
            );
            let stats: Vec<_> = self
                .qos_queues
                .get(&source)
                .filter(|r| r.profile == profile)
                .map(|r| r.queue.statistics().collect())
                .unwrap_or_default();
            for (index, class) in profile.classes.iter().enumerate() {
                let empty = QosClassCounters::default();
                let (count, depth) = stats.get(index).copied().unwrap_or((&empty, 0));
                let _ = writeln!(
                    out,
                    "    Class-map: {}\n      {} packets, {} bytes; {} dequeued, {} queued\n      Drops: queue {}, police {}, priority {}, shape {}",
                    class.name,
                    count.matched_packets,
                    count.matched_bytes,
                    count.transmitted_packets,
                    depth,
                    count.queue_drops,
                    count.police_drops,
                    count.priority_drops,
                    count.shape_drops
                );
            }
        }
        Ok(out)
    }
    pub(crate) fn qos_drop(
        &mut self,
        source: InterfaceRef,
        frame: &EthernetFrame,
        reason: DropReason,
    ) -> Result<(), LabError> {
        self.devices
            .get_mut(&source.device)
            .ok_or(DropReason::NoLink)?
            .record_drop_reason(source.interface, reason)?;
        if reason == DropReason::QueueFull
            && let Some(link) = self
                .ports
                .get(&source)
                .and_then(|id| self.links.get_mut(id))
        {
            let counters = if link.endpoint_a == source {
                &mut link.a_to_b.counters
            } else {
                &mut link.b_to_a.counters
            };
            counters.queue_drops = counters.queue_drops.saturating_add(1);
        }
        self.trace_frame(source, TraceAction::Drop(reason), frame);
        Ok(())
    }
    pub(crate) fn refresh_qos(&mut self) -> Result<(), LabError> {
        let stale: Vec<_> = self
            .qos_queues
            .iter()
            .filter_map(|(source, runtime)| {
                let link = self.ports.get(source).and_then(|id| self.links.get(id));
                let reason = if link
                    .is_none_or(|l| l.id != runtime.link || l.generation != runtime.generation)
                {
                    Some(DropReason::LinkChanged)
                } else {
                    let rate = link
                        .and_then(|l| l.config.bandwidth)
                        .map(|b| b.bits_per_second());
                    (self
                        .devices
                        .get(&source.device)
                        .and_then(|d| d.qos_profile(source.interface, rate))
                        .as_ref()
                        != Some(&runtime.profile)
                        || link.is_some_and(|l| l.config.queue_packets != runtime.capacity))
                    .then_some(DropReason::QosPolicyChanged)
                };
                reason.map(|reason| (*source, reason))
            })
            .collect();
        for (source, reason) in stale {
            if let Some(mut runtime) = self.qos_queues.remove(&source) {
                for frame in runtime.queue.drain() {
                    self.qos_drop(source, &frame, reason)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn enqueue_qos(
        &mut self,
        source: InterfaceRef,
        profile: QosProfile,
        frame: EthernetFrame,
    ) -> Result<(), LabError> {
        let Some(link) = self.ports.get(&source).and_then(|id| self.links.get(id)) else {
            self.qos_drop(source, &frame, DropReason::NoLink)?;
            return Err(DropReason::NoLink.into());
        };
        let now = self.now();
        let in_flight = if link.endpoint_a == source {
            link.a_to_b.queued(now)
        } else {
            link.b_to_a.queued(now)
        };
        let class = self
            .device(source.device)?
            .qos_classify(profile.id, &frame)
            .ok_or(rios_device::DeviceError::InvalidQosConfig)?;
        if let std::collections::btree_map::Entry::Vacant(entry) = self.qos_queues.entry(source) {
            let queue = QosScheduler::new(
                profile
                    .classes
                    .iter()
                    .map(|c| c.scheduling.clone())
                    .collect(),
                link.config.queue_packets,
                now,
            )
            .map_err(|_| rios_device::DeviceError::InvalidQosConfig)?;
            entry.insert(QosPortRuntime {
                profile,
                link: link.id,
                generation: link.generation,
                capacity: link.config.queue_packets,
                queue,
                wakes: Default::default(),
            });
        }
        let length = frame.len();
        let runtime = self.qos_queues.get_mut(&source).ok_or(DropReason::NoLink)?;
        if let Err(rejected) = runtime.queue.enqueue(class, now, frame, length, in_flight) {
            let reason = match rejected.reason {
                QueueRejectReason::Full => DropReason::QueueFull,
                QueueRejectReason::Policed => DropReason::QosPoliced,
                QueueRejectReason::PriorityExceeded => DropReason::QosPriorityExceeded,
                QueueRejectReason::ShapeBurstExceeded => DropReason::QosBurstExceeded,
                QueueRejectReason::UnknownClass => DropReason::QosPolicyChanged,
            };
            self.qos_drop(source, &rejected.packet, reason)?;
            return Err(reason.into());
        }
        self.service_qos(source)
    }
    fn schedule_qos(&mut self, source: InterfaceRef) -> Result<(), LabError> {
        let now = self.now();
        let Some(link) = self.ports.get(&source).and_then(|id| self.links.get(id)) else {
            return Ok(());
        };
        let available = if link.endpoint_a == source {
            link.a_to_b.available_at(now)
        } else {
            link.b_to_a.available_at(now)
        };
        let Some(runtime) = self.qos_queues.get_mut(&source) else {
            return Ok(());
        };
        let Some(at) = runtime.queue.next_ready(now)?.map(|at| at.max(available)) else {
            return Ok(());
        };
        // Keep previously scheduled shaping deadlines when an earlier class becomes ready.
        // An existing earlier wake can re-evaluate eligibility without adding another timer.
        if runtime
            .wakes
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= at)
        {
            return Ok(());
        }
        self.qos_epoch = self.qos_epoch.checked_add(1).ok_or(LabError::Capacity)?;
        self.events.schedule_at(
            at,
            SimulationEvent::QosTransmit {
                source,
                epoch: self.qos_epoch,
            },
        )?;
        runtime.wakes.insert(at, self.qos_epoch);
        Ok(())
    }
    pub(crate) fn qos_timer(&mut self, source: InterfaceRef, epoch: u64) -> Result<(), LabError> {
        let now = self.now();
        let Some(runtime) = self.qos_queues.get_mut(&source) else {
            return Ok(());
        };
        if runtime.wakes.get(&now) != Some(&epoch) {
            return Ok(());
        }
        runtime.wakes.remove(&now);
        self.service_qos(source)
    }
    fn service_qos(&mut self, source: InterfaceRef) -> Result<(), LabError> {
        let now = self.now();
        let Some(link) = self.ports.get(&source).and_then(|id| self.links.get(id)) else {
            return Ok(());
        };
        let available = if link.endpoint_a == source {
            link.a_to_b.available_at(now)
        } else {
            link.b_to_a.available_at(now)
        };
        if available <= now
            && let Some(departure) = self
                .qos_queues
                .get_mut(&source)
                .and_then(|r| r.queue.dequeue_ready(now))
        {
            let device = self.device(source.device)?;
            let logical = device
                .channel_interface(source.interface)
                .unwrap_or(source.interface);
            // Recheck a queued user frame against VLAN/STP state when it actually leaves.
            let kind = if departure.packet.ethertype == EtherType::Dot1Q
                && departure.packet.payload.len() >= 4
            {
                EtherType::from(u16::from_be_bytes([
                    departure.packet.payload[2],
                    departure.packet.payload[3],
                ]))
            } else {
                departure.packet.ethertype
            };
            let control = (departure.packet.destination.0 == rios_switching::STP_MULTICAST
                && matches!(kind, EtherType::Length(_)))
                || (departure.packet.destination.0 == rios_switching::LACP_MULTICAST
                    && kind == EtherType::Other(0x8809));
            let blocked = if device.is_switchport(logical) && !control {
                match device.classify_switch_ingress(logical, &departure.packet) {
                    Some((vlan, _)) if device.stp_forwarding(logical, vlan) => None,
                    Some(_) => Some(DropReason::StpBlocking),
                    None => Some(DropReason::VlanFiltered),
                }
            } else {
                None
            };
            if let Some(reason) = blocked {
                self.qos_drop(source, &departure.packet, reason)?;
            } else {
                match self.transmit_on_link(source, departure.packet) {
                    Ok(()) | Err(LabError::Dropped(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        self.schedule_qos(source)
    }
}
