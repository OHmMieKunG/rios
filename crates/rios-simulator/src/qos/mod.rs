//! Bounded class queues, integer token buckets and deterministic packet scheduling.
//! Owns generic packet values; knows nothing about Ethernet, devices or CLI syntax.
mod bucket;
use crate::{ScheduleError, SimTime};
use bucket::TokenBucket;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// A byte burst and bit rate used by a policer, shaper or congested priority class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub bits_per_second: u64,
    pub burst_bytes: u64,
}
impl RateLimit {
    /// Bounds also keep queue arithmetic and configuration mistakes predictable.
    pub fn valid(self) -> bool {
        (1..=1_000_000_000_000).contains(&self.bits_per_second)
            && (1..=1_073_741_824).contains(&self.burst_bytes)
    }
}
/// One class's scheduling and traffic-conditioning policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueClassConfig {
    /// Relative byte-service share among non-priority classes.
    pub weight: u64,
    /// Strict priority, policed to this rate only while the link or queue is busy.
    pub priority: Option<RateLimit>,
    pub police: Option<RateLimit>,
    pub shape: Option<RateLimit>,
}
impl Default for QueueClassConfig {
    fn default() -> Self {
        Self {
            weight: 1,
            priority: None,
            police: None,
            shape: None,
        }
    }
}
/// Explicit rejection; admission returns the original owned packet to its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueRejectReason {
    Full,
    Policed,
    PriorityExceeded,
    ShapeBurstExceeded,
    UnknownClass,
}
/// Packet ownership retained when queue admission fails.
#[derive(Debug)]
pub struct QueueRejected<T> {
    pub reason: QueueRejectReason,
    pub packet: T,
}
/// Cumulative class observations. Reading counters never changes scheduling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QosClassCounters {
    pub matched_packets: u64,
    pub matched_bytes: u64,
    pub transmitted_packets: u64,
    pub transmitted_bytes: u64,
    pub queue_drops: u64,
    pub police_drops: u64,
    pub priority_drops: u64,
    pub shape_drops: u64,
}
#[derive(Debug, Clone)]
struct Queued<T> {
    packet: T,
    bytes: usize,
    finish: u128,
}
#[derive(Debug, Clone)]
struct Class<T> {
    config: QueueClassConfig,
    priority: Option<TokenBucket>,
    police: Option<TokenBucket>,
    shape: Option<TokenBucket>,
    packets: VecDeque<Queued<T>>,
    last_finish: u128,
    counters: QosClassCounters,
}
/// A packet selected for serialization; ownership moves out of the queue.
#[derive(Debug)]
pub struct QosDeparture<T> {
    pub class: usize,
    pub bytes: usize,
    pub packet: T,
}
/// Packetized weighted-fair service with FIFO classes and non-preemptive strict priority.
#[derive(Debug, Clone)]
pub struct QosScheduler<T> {
    classes: Vec<Class<T>>,
    capacity: usize,
    length: usize,
    virtual_time: u128,
}
impl<T> QosScheduler<T> {
    /// Validate bounds before allocating queues. No per-packet buffer is cloned.
    pub fn new(
        configs: Vec<QueueClassConfig>,
        capacity: usize,
        now: SimTime,
    ) -> Result<Self, &'static str> {
        if configs.is_empty()
            || configs.len() > 64
            || !(1..=1_000_000).contains(&capacity)
            || configs.iter().any(|c| {
                !(1..=1_000_000_000_000).contains(&c.weight)
                    || [c.priority, c.police, c.shape]
                        .into_iter()
                        .flatten()
                        .any(|rate| !rate.valid())
            })
        {
            return Err("invalid class count, queue capacity, weight or rate limit");
        }
        Ok(Self {
            classes: configs
                .into_iter()
                .map(|config| Class {
                    priority: config.priority.map(|r| TokenBucket::new(r, now)),
                    police: config.police.map(|r| TokenBucket::new(r, now)),
                    shape: config.shape.map(|r| TokenBucket::new(r, now)),
                    config,
                    packets: VecDeque::new(),
                    last_finish: 0,
                    counters: QosClassCounters::default(),
                })
                .collect(),
            capacity,
            length: 0,
            virtual_time: 0,
        })
    }
    /// Total waiting packets, excluding frames already serializing on the link.
    pub fn len(&self) -> usize {
        self.length
    }
    /// Whether every class is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    /// Per-class counters and current waiting depth in configuration order.
    pub fn statistics(&self) -> impl Iterator<Item = (&QosClassCounters, usize)> {
        self.classes.iter().map(|c| (&c.counters, c.packets.len()))
    }
    /// Admit a frame using arrival-time policing and a shared waiting-plus-in-flight bound.
    pub fn enqueue(
        &mut self,
        class: usize,
        now: SimTime,
        packet: T,
        bytes: usize,
        in_flight: usize,
    ) -> Result<(), QueueRejected<T>> {
        if self.is_empty() {
            self.virtual_time = 0;
            for class in &mut self.classes {
                class.last_finish = 0;
            }
        }
        let congested = self.length > 0 || in_flight > 0;
        let Some(class) = self.classes.get_mut(class) else {
            return Err(QueueRejected {
                reason: QueueRejectReason::UnknownClass,
                packet,
            });
        };
        class.counters.matched_packets = class.counters.matched_packets.saturating_add(1);
        class.counters.matched_bytes = class.counters.matched_bytes.saturating_add(bytes as u64);
        let reason = if class
            .police
            .as_mut()
            .is_some_and(|bucket| !bucket.take(now, bytes))
        {
            class.counters.police_drops = class.counters.police_drops.saturating_add(1);
            Some(QueueRejectReason::Policed)
        } else if class
            .priority
            .as_mut()
            .is_some_and(|bucket| !bucket.take(now, bytes))
            && congested
        {
            class.counters.priority_drops = class.counters.priority_drops.saturating_add(1);
            Some(QueueRejectReason::PriorityExceeded)
        } else if class
            .config
            .shape
            .is_some_and(|rate| bytes as u128 > u128::from(rate.burst_bytes))
        {
            class.counters.shape_drops = class.counters.shape_drops.saturating_add(1);
            Some(QueueRejectReason::ShapeBurstExceeded)
        } else if self.length.saturating_add(in_flight) >= self.capacity {
            class.counters.queue_drops = class.counters.queue_drops.saturating_add(1);
            Some(QueueRejectReason::Full)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(QueueRejected { reason, packet });
        }
        // Fixed-point finish tags preserve byte shares without floating-point clock state.
        let service = (bytes as u128 * 1_000_000_000_000).div_ceil(u128::from(class.config.weight));
        let finish = class
            .last_finish
            .max(self.virtual_time)
            .saturating_add(service);
        class.last_finish = finish;
        class.packets.push_back(Queued {
            packet,
            bytes,
            finish,
        });
        self.length += 1;
        Ok(())
    }
    /// Earliest class eligibility; the caller also waits for its physical transmitter.
    pub fn next_ready(&mut self, now: SimTime) -> Result<Option<SimTime>, ScheduleError> {
        let mut next = None;
        for class in &mut self.classes {
            let Some(packet) = class.packets.front() else {
                continue;
            };
            let at = match &mut class.shape {
                Some(bucket) => bucket.ready_at(now, packet.bytes)?,
                None => now,
            };
            next = Some(next.map_or(at, |old: SimTime| old.min(at)));
        }
        Ok(next)
    }
    /// Select an eligible FIFO head. A priority packet cannot interrupt a frame in flight.
    pub fn dequeue_ready(&mut self, now: SimTime) -> Option<QosDeparture<T>> {
        let selected = self
            .classes
            .iter_mut()
            .enumerate()
            .filter_map(|(index, class)| {
                let packet = class.packets.front()?;
                if class
                    .shape
                    .as_mut()
                    .is_some_and(|bucket| !bucket.available(now, packet.bytes))
                {
                    return None;
                }
                Some((
                    (
                        class.priority.is_none(),
                        if class.priority.is_some() {
                            0
                        } else {
                            packet.finish
                        },
                        index,
                    ),
                    index,
                ))
            })
            .min_by_key(|(key, _)| *key)
            .map(|(_, index)| index)?;
        let class = &mut self.classes[selected];
        let packet = class.packets.pop_front()?;
        if let Some(bucket) = &mut class.shape {
            bucket.take(now, packet.bytes);
        }
        if class.priority.is_none() {
            self.virtual_time = self.virtual_time.max(packet.finish);
        }
        self.length -= 1;
        class.counters.transmitted_packets = class.counters.transmitted_packets.saturating_add(1);
        class.counters.transmitted_bytes = class
            .counters
            .transmitted_bytes
            .saturating_add(packet.bytes as u64);
        Some(QosDeparture {
            class: selected,
            bytes: packet.bytes,
            packet: packet.packet,
        })
    }
    /// Drain on link/configuration invalidation; the owner records each packet's drop reason.
    pub fn drain(&mut self) -> Vec<T> {
        self.length = 0;
        self.classes
            .iter_mut()
            .flat_map(|class| class.packets.drain(..).map(|p| p.packet))
            .collect()
    }
}
