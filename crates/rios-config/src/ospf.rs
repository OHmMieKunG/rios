//! OSPF interface policy, independent of neighbor and link-state runtime.
use serde::{Deserialize, Serialize};

/// OSPF network type; Ethernet defaults to broadcast election behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfNetworkType {
    #[default]
    Broadcast,
    PointToPoint,
}
/// Timers are seconds; costs and priority affect real OSPF advertisements and elections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OspfInterfaceConfig {
    pub cost: u16,
    pub priority: u8,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub network_type: OspfNetworkType,
}
impl Default for OspfInterfaceConfig {
    fn default() -> Self {
        Self {
            cost: 1,
            priority: 1,
            hello_interval: 10,
            dead_interval: 40,
            network_type: OspfNetworkType::Broadcast,
        }
    }
}

impl OspfInterfaceConfig {
    pub(crate) fn render(&self, out: &mut String) {
        self.render_for(out, "ip ospf");
    }
    pub(crate) fn render_for(&self, out: &mut String, command: &str) {
        use std::fmt::Write;
        let default = Self::default();
        for (name, value, normal) in [
            ("cost", u32::from(self.cost), u32::from(default.cost)),
            (
                "priority",
                u32::from(self.priority),
                u32::from(default.priority),
            ),
            (
                "hello-interval",
                u32::from(self.hello_interval),
                u32::from(default.hello_interval),
            ),
            ("dead-interval", self.dead_interval, default.dead_interval),
        ] {
            if value != normal {
                let _ = writeln!(out, " {command} {name} {value}");
            }
        }
        if self.network_type == OspfNetworkType::PointToPoint {
            let _ = writeln!(out, " {command} network point-to-point");
        }
    }
}

/// Default-information policy and the metric of the originated Type 5 LSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OspfDefaultRoute {
    pub always: bool,
    pub metric: u32,
    pub type_two: bool,
}
impl Default for OspfDefaultRoute {
    fn default() -> Self {
        Self {
            always: false,
            metric: 1,
            type_two: true,
        }
    }
}
/// Metric policy for static-route redistribution into OSPF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OspfRedistribute {
    pub metric: u32,
    pub type_two: bool,
}
impl Default for OspfRedistribute {
    fn default() -> Self {
        Self {
            metric: 20,
            type_two: true,
        }
    }
}
