//! Deterministic virtual clock, generic event queue, identities, and carrier primitives.
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

macro_rules! id {
    ($name:ident) => {
        #[doc = "Stable simulator identity."]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(pub u64);
    };
}
id!(DeviceId);
id!(InterfaceId);
id!(LinkId);
id!(TimerId);

/// Physical or virtual carrier state, independent of administrative state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkState {
    Down,
    Up,
}

mod queue;
pub use queue::{EventQueue, ScheduleError, ScheduledEvent, SimTime};

/// Globally identifies an interface within a lab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InterfaceRef {
    pub device: DeviceId,
    pub interface: InterfaceId,
}
