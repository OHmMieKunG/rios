use crate::*;
use rios_device::{Device, DeviceType, InterfaceMedia, canonical_interface};
use rios_simulator::DeviceId;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Declarative YAML inventory. Build validates all references before returning a lab.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Topology {
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
        let mut lab = Lab::default();
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
            lab.add_device(&name, device)?;
        }
        for link in self.links {
            let a = lab.endpoint(&link.endpoints[0])?;
            let b = lab.endpoint(&link.endpoints[1])?;
            lab.connect(a, b, link.delay_ms)?;
        }
        Ok(lab)
    }
}
