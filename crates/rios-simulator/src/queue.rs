use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::BinaryHeap, fmt};

/// Monotonic virtual time in milliseconds; unrelated to wall-clock time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SimTime(pub u64);
impl fmt::Display for SimTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}:{:02}:{:02}.{:03}",
            self.0 / 3_600_000,
            (self.0 / 60_000) % 60,
            (self.0 / 1000) % 60,
            self.0 % 1000
        )
    }
}
/// An event with a stable insertion sequence; payloads need not implement Ord.
#[derive(Debug)]
pub struct ScheduledEvent<E> {
    pub time: SimTime,
    pub event: E,
    sequence: u64,
}
impl<E> PartialEq for ScheduledEvent<E> {
    fn eq(&self, other: &Self) -> bool {
        (self.time, self.sequence) == (other.time, other.sequence)
    }
}
impl<E> Eq for ScheduledEvent<E> {}
impl<E> PartialOrd for ScheduledEvent<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<E> Ord for ScheduledEvent<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse keys because BinaryHeap pops the largest element.
        (other.time, other.sequence).cmp(&(self.time, self.sequence))
    }
}
/// Scheduling failures never advance time or remove queued events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScheduleError {
    #[error("cannot schedule or advance into the simulated past")]
    Past,
    #[error("simulated time or insertion sequence overflow")]
    Overflow,
    #[error("advancing would skip a pending event")]
    PendingEvent,
}
/// Single-owner deterministic event queue, with no threads or protocol dependencies.
#[derive(Debug)]
pub struct EventQueue<E> {
    now: SimTime,
    next_sequence: u64,
    pending: BinaryHeap<ScheduledEvent<E>>,
}
impl<E> Default for EventQueue<E> {
    fn default() -> Self {
        Self {
            now: SimTime(0),
            next_sequence: 0,
            pending: BinaryHeap::new(),
        }
    }
}
impl<E> EventQueue<E> {
    /// Current simulated time.
    pub fn now(&self) -> SimTime {
        self.now
    }
    /// Number of pending events.
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    /// Whether no events are pending.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    /// Timestamp of the next event without changing the queue.
    pub fn next_time(&self) -> Option<SimTime> {
        self.pending.peek().map(|event| event.time)
    }
    /// Queue an event at an absolute virtual time; equal times preserve insertion order.
    pub fn schedule_at(&mut self, time: SimTime, event: E) -> Result<(), ScheduleError> {
        if time < self.now {
            return Err(ScheduleError::Past);
        }
        let next = self
            .next_sequence
            .checked_add(1)
            .ok_or(ScheduleError::Overflow)?;
        self.pending.push(ScheduledEvent {
            time,
            event,
            sequence: self.next_sequence,
        });
        self.next_sequence = next;
        Ok(())
    }
    /// Queue a timer or other event relative to the current virtual clock.
    pub fn schedule_after(&mut self, delay_ms: u64, event: E) -> Result<(), ScheduleError> {
        let time = self
            .now
            .0
            .checked_add(delay_ms)
            .ok_or(ScheduleError::Overflow)?;
        self.schedule_at(SimTime(time), event)
    }
    /// Pop one event and move the virtual clock to its timestamp.
    pub fn step(&mut self) -> Option<ScheduledEvent<E>> {
        let event = self.pending.pop()?;
        self.now = event.time;
        Some(event)
    }
    /// Advance through idle time only. Process earlier events with step first.
    pub fn advance_to(&mut self, time: SimTime) -> Result<(), ScheduleError> {
        if time < self.now {
            return Err(ScheduleError::Past);
        }
        if self.next_time().is_some_and(|next| next <= time) {
            return Err(ScheduleError::PendingEvent);
        }
        self.now = time;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_time_and_tie_order_without_ordered_payloads() {
        struct Payload(u8);
        let mut q = EventQueue::default();
        for (time, value) in [(10, 1), (5, 2), (10, 3), (0, 4)] {
            q.schedule_at(SimTime(time), Payload(value)).unwrap();
        }
        assert_eq!(q.now(), SimTime(0));
        let mut seen = Vec::new();
        while let Some(event) = q.step() {
            seen.push((q.now().0, event.event.0));
        }
        assert_eq!(seen, [(0, 4), (5, 2), (10, 1), (10, 3)]);
        assert!(q.is_empty());
        assert_eq!(q.now(), SimTime(10));
    }
    #[test]
    fn zero_delay_and_error_atomicity() {
        let mut q = EventQueue::default();
        q.schedule_at(SimTime(10), 1).unwrap();
        assert_eq!(q.advance_to(SimTime(10)), Err(ScheduleError::PendingEvent));
        assert_eq!(q.now(), SimTime(0));
        assert_eq!(q.len(), 1);
        q.step();
        q.schedule_after(0, 2).unwrap();
        q.schedule_after(0, 3).unwrap();
        assert_eq!(q.schedule_at(SimTime(9), 4), Err(ScheduleError::Past));
        assert_eq!(q.step().unwrap().event, 2);
        assert_eq!(q.step().unwrap().event, 3);
        q.advance_to(SimTime(u64::MAX)).unwrap();
        assert_eq!(q.schedule_after(1, 5), Err(ScheduleError::Overflow));
        assert!(q.is_empty());
        assert_eq!(q.advance_to(SimTime(0)), Err(ScheduleError::Past));
        q.next_sequence = u64::MAX;
        assert_eq!(q.schedule_after(0, 6), Err(ScheduleError::Overflow));
        assert!(q.is_empty());
    }
}
