//! Structured Modular QoS CLI policy; runtime queues live in the simulator.
use rios_simulator::{QueueClassConfig, RateLimit};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Stable class-map identity used by configuration sessions and policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QosClassId(pub u32);
/// Stable service-policy identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QosPolicyId(pub u32);
/// Values in one criterion are ORed; match-all combines distinct criteria with AND.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosClassMap {
    pub name: String,
    pub match_all: bool,
    pub dscp: BTreeSet<u8>,
    pub precedence: BTreeSet<u8>,
    pub access_lists: BTreeSet<String>,
}
/// A bit rate and optional explicit byte burst; omitted bursts are resolved against interface MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosRate {
    pub bits_per_second: u64,
    pub burst_bytes: Option<u64>,
}
impl QosRate {
    /// Resolve the default 100ms burst, with room for a full Ethernet frame.
    pub fn resolve(self, mtu: u16) -> RateLimit {
        RateLimit {
            bits_per_second: self.bits_per_second,
            burst_bytes: self.burst_bytes.unwrap_or_else(|| {
                (self.bits_per_second / 80)
                    .max(u64::from(mtu) + 18)
                    .min(1_073_741_824)
            }),
        }
    }
    /// Validate both explicit and default burst forms.
    pub fn valid(self) -> bool {
        self.resolve(1500).valid()
    }
}
/// One ordered policy class. None denotes the implicit final class-default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosPolicyClass {
    pub class: Option<QosClassId>,
    pub bandwidth_kbps: Option<u64>,
    pub priority: Option<QosRate>,
    pub police: Option<QosRate>,
    pub shape: Option<QosRate>,
}
impl QosPolicyClass {
    /// Translate policy rates to deterministic queue configuration.
    pub fn scheduling(&self, mtu: u16, default_weight: u64) -> QueueClassConfig {
        QueueClassConfig {
            weight: self
                .bandwidth_kbps
                .map_or(default_weight, |kbps| kbps.saturating_mul(1000)),
            priority: self.priority.map(|r| r.resolve(mtu)),
            police: self.police.map(|r| r.resolve(mtu)),
            shape: self.shape.map(|r| r.resolve(mtu)),
        }
    }
}
/// Policy classes retain insertion order; class-default is always last.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosPolicyMap {
    pub name: String,
    pub classes: Vec<QosPolicyClass>,
}
/// Persistent class and policy inventory, independent of packet queues and statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosConfig {
    pub classes: BTreeMap<QosClassId, QosClassMap>,
    pub policies: BTreeMap<QosPolicyId, QosPolicyMap>,
}
impl QosConfig {
    /// Render replayable IOS-style class and policy definitions.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for class in self.classes.values() {
            let _ = writeln!(
                out,
                "class-map {} {}",
                if class.match_all {
                    "match-all"
                } else {
                    "match-any"
                },
                class.name
            );
            for (word, values) in [("dscp", &class.dscp), ("precedence", &class.precedence)] {
                if !values.is_empty() {
                    let _ = write!(out, " match ip {word}");
                    for value in values {
                        let _ = write!(out, " {value}");
                    }
                    out.push('\n');
                }
            }
            for name in &class.access_lists {
                let _ = writeln!(out, " match access-group name {name}");
            }
            out.push_str("!\n");
        }
        for policy in self.policies.values() {
            let _ = writeln!(out, "policy-map {}", policy.name);
            for class in &policy.classes {
                let name = class
                    .class
                    .and_then(|id| self.classes.get(&id))
                    .map_or("class-default", |c| &c.name);
                let _ = writeln!(out, " class {name}");
                if let Some(kbps) = class.bandwidth_kbps {
                    let _ = writeln!(out, "  bandwidth {kbps}");
                }
                for (word, rate, kbps, bits) in [
                    ("priority", class.priority, true, false),
                    ("police", class.police, false, false),
                    ("shape average", class.shape, false, true),
                ] {
                    if let Some(rate) = rate {
                        let _ = write!(
                            out,
                            "  {word} {}",
                            if kbps {
                                rate.bits_per_second / 1000
                            } else {
                                rate.bits_per_second
                            }
                        );
                        if let Some(burst) = rate.burst_bytes {
                            let _ = write!(
                                out,
                                " {}",
                                if bits {
                                    u128::from(burst) * 8
                                } else {
                                    u128::from(burst)
                                }
                            );
                        }
                        out.push('\n');
                    }
                }
            }
            out.push_str("!\n");
        }
        out
    }
}
