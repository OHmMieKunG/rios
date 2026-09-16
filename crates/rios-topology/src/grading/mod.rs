//! Structured lab grading; configuration checks inspect state and probes send real packets.
mod checks;
use crate::{Lab, LabError};
use rios_simulator::SimTime;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Validated IPv4 address/prefix notation, retaining interface host bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct GradeAddress {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}
impl TryFrom<String> for GradeAddress {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (address, prefix) = value.split_once('/').ok_or("expected IPv4/prefix")?;
        let address = address.parse().map_err(|_| "invalid IPv4 address")?;
        let prefix_len = prefix.parse::<u8>().map_err(|_| "invalid IPv4 prefix")?;
        if prefix_len > 32 {
            return Err("IPv4 prefix exceeds 32");
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }
}
/// Explicit STP state expectation in objective YAML.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GradeStpState {
    Blocking,
    Listening,
    Learning,
    Forwarding,
}
/// A check on structured configuration/runtime state or a simulated packet exchange.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Objective {
    InterfaceAddress {
        device: String,
        interface: String,
        address: GradeAddress,
    },
    InterfaceState {
        device: String,
        interface: String,
        up: bool,
    },
    OspfNeighborCount {
        device: String,
        count: usize,
    },
    BgpNeighborCount {
        device: String,
        count: usize,
    },
    Route {
        device: String,
        prefix: GradeAddress,
        #[serde(default)]
        next_hop: Option<Ipv4Addr>,
    },
    Reachable {
        from: String,
        to: Ipv4Addr,
    },
    Unreachable {
        from: String,
        to: Ipv4Addr,
    },
    VlanMembership {
        device: String,
        interface: String,
        vlan: rios_config::VlanId,
    },
    StpState {
        device: String,
        interface: String,
        vlan: rios_config::VlanId,
        state: GradeStpState,
    },
    DhcpLease {
        device: String,
        interface: String,
        #[serde(default)]
        address: Option<Ipv4Addr>,
    },
    NatAllocations {
        device: String,
        minimum: u64,
    },
    AclMatches {
        device: String,
        acl: String,
        sequence: u32,
        minimum: u64,
    },
    Latency {
        from: String,
        to: Ipv4Addr,
        max_ms: u64,
    },
    PacketLoss {
        from: String,
        to: Ipv4Addr,
        max_percent: u8,
    },
    Http {
        from: String,
        to: Ipv4Addr,
        #[serde(default = "http_port")]
        port: u16,
        #[serde(default)]
        contains: Option<String>,
    },
    TcpEcho {
        from: String,
        to: Ipv4Addr,
        #[serde(default = "echo_port")]
        port: u16,
    },
    UdpEcho {
        from: String,
        to: Ipv4Addr,
        #[serde(default = "echo_port")]
        port: u16,
    },
    Dns {
        from: String,
        server: Ipv4Addr,
        name: String,
        address: Ipv4Addr,
    },
}
fn http_port() -> u16 {
    80
}
fn echo_port() -> u16 {
    7
}
fn settle_ms() -> u64 {
    60_000
}
/// A bounded objective document; checks execute in document order after convergence time.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GradePlan {
    #[serde(default = "settle_ms")]
    pub settle_ms: u64,
    pub objectives: Vec<Objective>,
}
/// One explicit pass/fail; errors never count as successful isolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GradeResult {
    pub label: String,
    pub passed: bool,
    pub error: bool,
    pub detail: String,
}
/// Deterministic report suitable for CLI or structured automation output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GradeReport {
    pub results: Vec<GradeResult>,
    pub passed: usize,
}
impl GradeReport {
    /// Whether every objective passed.
    pub fn success(&self) -> bool {
        self.passed == self.results.len()
    }
    /// Render results without scraping any device CLI output.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        for result in &self.results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            let _ = writeln!(
                text,
                "[{status}] {} — {}{}",
                result.label,
                if result.error { "error: " } else { "" },
                result.detail
            );
        }
        let _ = writeln!(text, "\nScore: {}/{}", self.passed, self.results.len());
        text
    }
}
impl GradePlan {
    /// Parse strict YAML, rejecting unknown fields, empty/oversized plans and invalid bounds.
    pub fn from_yaml(text: &str) -> Result<Self, LabError> {
        if text.len() > 1_048_576 {
            return Err(LabError::InvalidTopology(
                "objective file exceeds 1 MiB".into(),
            ));
        }
        let plan: Self =
            serde_saphyr::from_str(text).map_err(|e| LabError::InvalidTopology(e.to_string()))?;
        plan.validate()?;
        Ok(plan)
    }
    fn validate(&self) -> Result<(), LabError> {
        if self.objectives.is_empty()
            || self.objectives.len() > 4096
            || self.settle_ms > 86_400_000
            || self.objectives.iter().any(|o| {
                matches!(o, Objective::PacketLoss { max_percent, .. } if *max_percent > 100)
                    || matches!(
                        o,
                        Objective::Http { port: 0, .. }
                            | Objective::TcpEcho { port: 0, .. }
                            | Objective::UdpEcho { port: 0, .. }
                    )
            })
        {
            return Err(LabError::InvalidTopology(
                "invalid objective count, settle time, loss percentage or service port".into(),
            ));
        }
        Ok(())
    }
    /// Grade live state; packet objectives advance simulation time and may populate runtime tables.
    pub fn evaluate(&self, lab: &mut Lab) -> Result<GradeReport, LabError> {
        self.validate()?;
        let deadline = SimTime(
            lab.now()
                .0
                .checked_add(self.settle_ms * 1000)
                .ok_or(crate::PingError::TimeOverflow)?,
        );
        lab.advance_until(deadline)?;
        let mut results = Vec::with_capacity(self.objectives.len());
        for objective in &self.objectives {
            let label = objective.label();
            let result = match objective.check(lab) {
                Ok((passed, detail)) => GradeResult {
                    label,
                    passed,
                    error: false,
                    detail,
                },
                Err(error) => GradeResult {
                    label,
                    passed: false,
                    error: true,
                    detail: error.to_string(),
                },
            };
            results.push(result);
        }
        let passed = results.iter().filter(|r| r.passed).count();
        Ok(GradeReport { results, passed })
    }
}
