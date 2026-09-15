//! Integer link parameters and bounded, full-duplex transmission scheduling.
use crate::{ScheduleError, SimTime};
use std::{collections::VecDeque, num::NonZeroU64, str::FromStr};

/// Validated link rate in bits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bandwidth(NonZeroU64);
impl Bandwidth {
    /// A zero rate is invalid; use link state to disable transmission.
    pub fn new(bits_per_second: u64) -> Option<Self> {
        NonZeroU64::new(bits_per_second).map(Self)
    }
    /// Link rate in bits per second.
    pub fn bits_per_second(self) -> u64 {
        self.0.get()
    }
    /// Serialization duration rounded up to a microsecond.
    pub fn serialization_us(self, bytes: usize) -> Result<u64, ScheduleError> {
        let duration = (bytes as u128 * 8 * 1_000_000).div_ceil(self.0.get() as u128);
        u64::try_from(duration).map_err(|_| ScheduleError::Overflow)
    }
}
impl FromStr for Bandwidth {
    type Err = &'static str;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let text = input.trim().to_ascii_lowercase();
        for (suffix, multiplier) in [
            ("gbps", 1_000_000_000u64),
            ("mbps", 1_000_000),
            ("kbps", 1000),
            ("bps", 1),
        ] {
            if let Some(number) = text.strip_suffix(suffix) {
                return number
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|value| value.checked_mul(multiplier))
                    .and_then(Self::new)
                    .ok_or("invalid bandwidth");
            }
        }
        Err("expected a positive integer followed by bps, kbps, mbps, or gbps")
    }
}

/// Link policy. An absent rate preserves legacy instantaneous serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfig {
    pub bandwidth: Option<Bandwidth>,
    pub delay_us: u64,
    pub jitter_us: u64,
    /// Loss probability in millionths: 1000 means 0.1 percent.
    pub loss_ppm: u32,
    /// Maximum frames serializing or waiting, per direction.
    pub queue_packets: usize,
}
impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            bandwidth: None,
            delay_us: 1000,
            jitter_us: 0,
            loss_ppm: 0,
            queue_packets: 100,
        }
    }
}
impl LinkConfig {
    /// Validate externally supplied policy before changing a link.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.loss_ppm > 1_000_000 {
            return Err("loss must be between 0 and 100 percent");
        }
        if self.queue_packets == 0 || self.queue_packets > 1_000_000 {
            return Err("queue_packets must be 1..=1000000");
        }
        if self.jitter_us > (u64::MAX - 1) / 2 {
            return Err("jitter is too large");
        }
        Ok(())
    }
}

/// Cumulative accounting for one direction of a cable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkCounters {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub queue_drops: u64,
    pub loss_drops: u64,
    pub changed_drops: u64,
}
/// Independent transmitter state; timestamps avoid cloning packet buffers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectionalLinkRuntime {
    finishes: VecDeque<SimTime>,
    last_arrival: SimTime,
    pub counters: LinkCounters,
}
/// Admission result, separating queue overflow from scheduler errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Full,
    Scheduled { arrival: SimTime, lost: bool },
}
impl DirectionalLinkRuntime {
    /// Number of frames still serializing or waiting at the specified time.
    pub fn queued(&self, now: SimTime) -> usize {
        self.finishes.iter().filter(|finish| **finish > now).count()
    }
    /// Invalidate transmitter reservations after an outage; counters survive.
    pub fn reset(&mut self) {
        self.finishes.clear();
        self.last_arrival = SimTime(0);
    }
    /// Reserve a FIFO transmission. Random samples come from the owning lab.
    pub fn admit(
        &mut self,
        config: &LinkConfig,
        now: SimTime,
        bytes: usize,
        jitter_sample: u64,
        loss_sample: u64,
    ) -> Result<Admission, ScheduleError> {
        while self.finishes.front().is_some_and(|finish| *finish <= now) {
            self.finishes.pop_front();
        }
        if self.finishes.len() >= config.queue_packets {
            self.counters.queue_drops = self.counters.queue_drops.saturating_add(1);
            return Ok(Admission::Full);
        }
        let start = self.finishes.back().copied().unwrap_or(now).max(now);
        let serialization = config
            .bandwidth
            .map_or(Ok(0), |rate| rate.serialization_us(bytes))?;
        let finish = start
            .0
            .checked_add(serialization)
            .ok_or(ScheduleError::Overflow)?;
        let jitter = jitter_sample % (config.jitter_us * 2 + 1);
        let propagation =
            (config.delay_us as u128 + jitter as u128).saturating_sub(config.jitter_us as u128);
        let arrival =
            u64::try_from(finish as u128 + propagation).map_err(|_| ScheduleError::Overflow)?;
        let arrival = SimTime(arrival).max(self.last_arrival);
        self.finishes.push_back(SimTime(finish));
        self.last_arrival = arrival;
        self.counters.tx_packets = self.counters.tx_packets.saturating_add(1);
        self.counters.tx_bytes = self.counters.tx_bytes.saturating_add(bytes as u64);
        Ok(Admission::Scheduled {
            arrival,
            lost: loss_sample % 1_000_000 < u64::from(config.loss_ppm),
        })
    }
}

/// Reproducible SplitMix64 stream owned by the lab; never uses wall time.
#[derive(Debug, Clone, Default)]
pub struct SimulationRng(pub u64);
impl SimulationRng {
    /// Next deterministic 64-bit sample.
    pub fn sample(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rates_fifo_bounds_and_independent_transmitters() {
        assert_eq!(
            "100mbps"
                .parse::<Bandwidth>()
                .unwrap()
                .serialization_us(1500),
            Ok(120)
        );
        assert_eq!(
            "1gbps".parse::<Bandwidth>().unwrap().serialization_us(1500),
            Ok(12)
        );
        for bad in ["0mbps", "-1mbps", "100", "1xbps"] {
            assert!(bad.parse::<Bandwidth>().is_err());
        }
        let policy = LinkConfig {
            bandwidth: Some("100mbps".parse().unwrap()),
            queue_packets: 2,
            ..Default::default()
        };
        let mut a = DirectionalLinkRuntime::default();
        let mut b = DirectionalLinkRuntime::default();
        assert_eq!(
            a.admit(&policy, SimTime(0), 1500, 0, 0).unwrap(),
            Admission::Scheduled {
                arrival: SimTime(1120),
                lost: false
            }
        );
        assert_eq!(
            a.admit(&policy, SimTime(0), 1500, 0, 0).unwrap(),
            Admission::Scheduled {
                arrival: SimTime(1240),
                lost: false
            }
        );
        assert_eq!(
            a.admit(&policy, SimTime(0), 1500, 0, 0).unwrap(),
            Admission::Full
        );
        assert_eq!(a.queued(SimTime(120)), 1);
        assert_eq!(
            b.admit(&policy, SimTime(0), 1500, 0, 0).unwrap(),
            Admission::Scheduled {
                arrival: SimTime(1120),
                lost: false
            }
        );
        a.reset();
        assert_eq!(a.queued(SimTime(0)), 0);
    }
}
