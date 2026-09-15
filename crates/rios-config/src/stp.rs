//! Structured bridge and interface spanning-tree policy.
use crate::VlanId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Per-VLAN priorities and protocol selection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StpConfig {
    pub rapid: bool,
    pub priorities: BTreeMap<VlanId, u16>,
}
/// Port priority, optional explicit cost, edge status, and loop-protection guards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StpPortConfig {
    pub priority: u8,
    pub cost: Option<u32>,
    pub portfast: bool,
    pub bpdu_guard: bool,
    pub root_guard: bool,
}
impl Default for StpPortConfig {
    fn default() -> Self {
        Self {
            priority: 128,
            cost: None,
            portfast: false,
            bpdu_guard: false,
            root_guard: false,
        }
    }
}
