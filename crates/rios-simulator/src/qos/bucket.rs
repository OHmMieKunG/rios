//! Fractional-bit credits use integer units, so repeated small refills never lose precision.
use super::*;
const BYTE_CREDITS: u128 = 8_000_000;
#[derive(Debug, Clone)]
pub(super) struct TokenBucket {
    rate: RateLimit,
    credit: u128,
    updated: SimTime,
}
impl TokenBucket {
    pub(super) fn new(rate: RateLimit, now: SimTime) -> Self {
        Self {
            credit: u128::from(rate.burst_bytes) * BYTE_CREDITS,
            rate,
            updated: now,
        }
    }
    fn refill(&mut self, now: SimTime) {
        let elapsed = now.0.saturating_sub(self.updated.0);
        self.credit = self
            .credit
            .saturating_add(u128::from(elapsed) * u128::from(self.rate.bits_per_second))
            .min(u128::from(self.rate.burst_bytes) * BYTE_CREDITS);
        self.updated = now.max(self.updated);
    }
    pub(super) fn available(&mut self, now: SimTime, bytes: usize) -> bool {
        self.refill(now);
        self.credit >= bytes as u128 * BYTE_CREDITS
    }
    pub(super) fn take(&mut self, now: SimTime, bytes: usize) -> bool {
        if !self.available(now, bytes) {
            return false;
        }
        self.credit -= bytes as u128 * BYTE_CREDITS;
        true
    }
    pub(super) fn ready_at(
        &mut self,
        now: SimTime,
        bytes: usize,
    ) -> Result<SimTime, ScheduleError> {
        self.refill(now);
        let missing = (bytes as u128 * BYTE_CREDITS).saturating_sub(self.credit);
        let wait = u64::try_from(missing.div_ceil(u128::from(self.rate.bits_per_second)))
            .map_err(|_| ScheduleError::Overflow)?;
        now.0
            .checked_add(wait)
            .map(SimTime)
            .ok_or(ScheduleError::Overflow)
    }
}
