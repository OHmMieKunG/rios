use crate::*;
use rios_device::{Device, DeviceType, InterfaceMedia, canonical_interface};
use rios_simulator::DeviceId;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Declarative YAML inventory. Build validates all references before returning a lab.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    #[serde(default)]
    seed: u64,
    devices: BTreeMap<String, DeviceDefinition>,
    #[serde(default)]
    links: Vec<LinkDefinition>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceDefinition {
    #[serde(rename = "type")]
    kind: DeviceKind,
    interfaces: Vec<InterfaceDefinition>,
    #[serde(default)]
    services: Vec<rios_config::ServiceConfig>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DeviceKind {
    Router,
    Switch,
    Layer3Switch,
    Host,
}
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InterfaceDefinition {
    Name(String),
    Port { name: String, media: PortMedia },
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PortMedia {
    Rj45,
    Sfp,
    #[serde(rename = "sfp+")]
    SfpPlus,
    Serial,
    Console,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkDefinition {
    endpoints: [String; 2],
    #[serde(default = "default_delay")]
    delay_ms: u64,
    #[serde(default)]
    bandwidth: Option<String>,
    #[serde(default)]
    jitter_ms: u64,
    #[serde(default)]
    loss_percent: f64,
    #[serde(default = "default_queue")]
    queue_packets: usize,
}
fn default_queue() -> usize {
    100
}
fn default_delay() -> u64 {
    1
}
impl Topology {
    /// Parse a single YAML document with unknown fields and duplicate keys rejected.
    pub fn from_yaml(input: &str) -> Result<Self, LabError> {
        serde_saphyr::from_str(input).map_err(|e| LabError::InvalidTopology(e.to_string()))
    }
    /// Construct devices in sorted name order and connect validated physical endpoints.
    pub fn build(self) -> Result<Lab, LabError> {
        if self.devices.is_empty() {
            return Err(LabError::InvalidTopology(
                "at least one device is required".into(),
            ));
        }
        let mut lab = Lab::with_seed(self.seed);
        for (index, (name, definition)) in self.devices.into_iter().enumerate() {
            let kind = match definition.kind {
                DeviceKind::Router => DeviceType::Router,
                DeviceKind::Switch => DeviceType::Switch,
                DeviceKind::Layer3Switch => DeviceType::Layer3Switch,
                DeviceKind::Host => DeviceType::Host,
            };
            let mut device = Device::new(DeviceId(index as u64 + 1), &name, kind)?;
            let mut names = BTreeSet::new();
            for interface in definition.interfaces {
                let (interface, media) = match interface {
                    InterfaceDefinition::Name(name) => (name, None),
                    InterfaceDefinition::Port { name, media } => (
                        name,
                        Some(match media {
                            PortMedia::Rj45 => InterfaceMedia::Rj45,
                            PortMedia::Sfp => InterfaceMedia::Sfp,
                            PortMedia::SfpPlus => InterfaceMedia::SfpPlus,
                            PortMedia::Serial => InterfaceMedia::Serial,
                            PortMedia::Console => InterfaceMedia::Console,
                        }),
                    ),
                };
                let (canonical, kind) = canonical_interface(&interface)?;
                if !names.insert(canonical.clone()) {
                    return Err(LabError::InvalidTopology(format!(
                        "duplicate interface {name}:{canonical}"
                    )));
                }
                if let Some(media) = media {
                    device.add_port(&canonical, media)?;
                } else if kind.is_physical() {
                    device.add_physical_interface(&canonical)?;
                } else {
                    device.ensure_interface(&canonical)?;
                }
            }
            if !definition.services.is_empty() {
                device.set_services(definition.services)?;
            }
            lab.add_device(&name, device)?;
        }
        for link in self.links {
            let a = lab.endpoint(&link.endpoints[0])?;
            let b = lab.endpoint(&link.endpoints[1])?;
            if !link.loss_percent.is_finite() || !(0.0..=100.0).contains(&link.loss_percent) {
                return Err(LabError::InvalidTopology(
                    "loss_percent must be 0..=100".into(),
                ));
            }
            let config = rios_simulator::LinkConfig {
                bandwidth: link
                    .bandwidth
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(|error: &str| LabError::InvalidTopology(error.into()))?,
                delay_us: link
                    .delay_ms
                    .checked_mul(1000)
                    .ok_or(ScheduleError::Overflow)?,
                jitter_us: link
                    .jitter_ms
                    .checked_mul(1000)
                    .ok_or(ScheduleError::Overflow)?,
                loss_ppm: (link.loss_percent * 10_000.0).round() as u32,
                queue_packets: link.queue_packets,
            };
            lab.connect_configured(a, b, config)?;
        }
        Ok(lab)
    }
}
