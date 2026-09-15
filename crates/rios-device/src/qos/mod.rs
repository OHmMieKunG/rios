//! QoS configuration validation and frame classification; the lab owns queued packet buffers.
mod config;
use crate::*;
use rios_config::*;
use rios_ethernet::{EtherType, EthernetFrame};
use rios_ipv4::Ipv4Packet;
use rios_simulator::QueueClassConfig;

/// A named class and its resolved physical-interface scheduling settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosProfileClass {
    pub class: Option<QosClassId>,
    pub name: String,
    pub scheduling: QueueClassConfig,
}
/// Immutable queue configuration, used to detect policy changes at a physical transmitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosProfile {
    pub mtu: u16,
    pub id: QosPolicyId,
    pub name: String,
    pub classes: Vec<QosProfileClass>,
}
impl Device {
    /// Resolve an attached output policy and unreserved bandwidth shares for a physical link.
    pub fn qos_profile(&self, interface: InterfaceId, link_bps: Option<u64>) -> Option<QosProfile> {
        let port = self.running_config.interfaces.get(&interface)?;
        let id = port.service_policy_output?;
        let policy = self.running_config.qos.policies.get(&id)?;
        let link_bps = link_bps.unwrap_or(
            if self.interfaces.get(&interface)?.kind == InterfaceKind::TenGigabitEthernet {
                10_000_000_000
            } else {
                1_000_000_000
            },
        );
        let reserved: u64 = policy
            .classes
            .iter()
            .map(|c| {
                c.bandwidth_kbps
                    .unwrap_or(0)
                    .saturating_mul(1000)
                    .saturating_add(c.priority.map_or(0, |r| r.bits_per_second))
            })
            .fold(0u64, u64::saturating_add);
        let unreserved = policy
            .classes
            .iter()
            .filter(|c| c.bandwidth_kbps.is_none() && c.priority.is_none())
            .count()
            .max(1) as u64;
        let default_weight =
            (link_bps.saturating_sub(reserved) / unreserved).clamp(1, 1_000_000_000_000);
        Some(QosProfile {
            mtu: port.mtu,
            id,
            name: policy.name.clone(),
            classes: policy
                .classes
                .iter()
                .map(|c| QosProfileClass {
                    class: c.class,
                    name: c
                        .class
                        .and_then(|id| self.running_config.qos.classes.get(&id))
                        .map_or_else(|| "class-default".into(), |c| c.name.clone()),
                    scheduling: c.scheduling(port.mtu, default_weight),
                })
                .collect(),
        })
    }
    /// Classify an actual frame, including a single 802.1Q tag. Empty classes never match.
    pub fn qos_classify(&self, policy: QosPolicyId, frame: &EthernetFrame) -> Option<usize> {
        let policy = self.running_config.qos.policies.get(&policy)?;
        let (kind, payload) = if frame.ethertype == EtherType::Dot1Q && frame.payload.len() >= 4 {
            (
                EtherType::from(u16::from_be_bytes([frame.payload[2], frame.payload[3]])),
                &frame.payload[4..],
            )
        } else {
            (frame.ethertype, frame.payload.as_slice())
        };
        let ipv4 = (kind == EtherType::Ipv4)
            .then(|| Ipv4Packet::decode(payload).ok())
            .flatten();
        let ds = ipv4.as_ref().map(|ip| ip.dscp_ecn).or_else(|| {
            (kind == EtherType::Ipv6 && payload.len() >= 40 && payload[0] >> 4 == 6)
                .then(|| (payload[0] << 4) | (payload[1] >> 4))
        });
        policy.classes.iter().position(|entry| {
            let Some(id) = entry.class else {
                return true;
            };
            let Some(class) = self.running_config.qos.classes.get(&id) else {
                return false;
            };
            let criteria = [
                (!class.dscp.is_empty())
                    .then(|| ds.is_some_and(|ds| class.dscp.contains(&(ds >> 2)))),
                (!class.precedence.is_empty()).then(|| {
                    ipv4.as_ref()
                        .is_some_and(|ip| class.precedence.contains(&ip.precedence()))
                }),
                (!class.access_lists.is_empty()).then(|| {
                    ipv4.as_ref().is_some_and(|ip| {
                        class
                            .access_lists
                            .iter()
                            .any(|name| self.qos_acl_permits(name, ip))
                    })
                }),
            ];
            let mut matches = criteria.into_iter().flatten().peekable();
            if matches.peek().is_none() {
                return false;
            }
            if class.match_all {
                matches.all(|m| m)
            } else {
                matches.any(|m| m)
            }
        })
    }
    fn qos_acl_permits(&self, name: &str, packet: &Ipv4Packet) -> bool {
        if let Some(id) = self.acl_id(name) {
            return self.running_config.named_access_lists[&id]
                .entries
                .values()
                .find_map(|entry| entry.evaluate(packet))
                == Some(AccessListAction::Permit);
        }
        name.parse::<u8>()
            .ok()
            .and_then(AccessListId::new)
            .is_some_and(|id| self.access_list_permits(id, packet.source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn class_maps_match_real_dscp_precedence_acl_ports_and_vlan_tags() {
        let mut d = Device::standalone();
        let class = d.ensure_qos_class("DNS", true).unwrap();
        let acl = d.ensure_acl("DNS", AclKind::Extended).unwrap();
        d.set_acl_entry(
            acl,
            None,
            AclEntry::Rule {
                action: AccessListAction::Permit,
                protocol: AclProtocol::Udp,
                source: AddressMatch::ANY,
                source_port: PortMatch::Any,
                destination: AddressMatch::ANY,
                destination_port: PortMatch::Eq(53),
                log: false,
            },
        )
        .unwrap();
        let mut criteria = d.running_config.qos.classes[&class].clone();
        criteria.dscp.insert(46);
        criteria.access_lists.insert("DNS".into());
        d.set_qos_class(class, criteria.clone()).unwrap();
        let policy = d.ensure_qos_policy("OUT").unwrap();
        d.ensure_qos_policy_class(policy, "DNS").unwrap();
        let mut ip = Ipv4Packet {
            dscp_ecn: 46 << 2,
            source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            ttl: 64,
            protocol: rios_ipv4::IpProtocol::Udp,
            payload: vec![0x12, 0x34, 0, 53, 0, 8, 0, 0],
        };
        let frame = |ip: &Ipv4Packet| EthernetFrame {
            source: MacAddress([2, 0, 0, 0, 0, 1]),
            destination: MacAddress([2, 0, 0, 0, 0, 2]),
            ethertype: EtherType::Ipv4,
            payload: ip.encode().unwrap(),
        };
        assert_eq!(d.qos_classify(policy, &frame(&ip)), Some(0));
        assert_eq!(
            d.qos_classify(policy, &frame(&ip).tagged(VlanId::new(10).unwrap())),
            Some(0)
        );
        ip.payload[3] = 54;
        assert_eq!(d.qos_classify(policy, &frame(&ip)), Some(1));
        criteria.match_all = false;
        d.set_qos_class(class, criteria.clone()).unwrap();
        assert_eq!(d.qos_classify(policy, &frame(&ip)), Some(0));
        criteria.dscp.clear();
        criteria.access_lists.clear();
        criteria.precedence.insert(5);
        d.set_qos_class(class, criteria.clone()).unwrap();
        assert_eq!(d.qos_classify(policy, &frame(&ip)), Some(0));
        ip.dscp_ecn = 0;
        assert_eq!(d.qos_classify(policy, &frame(&ip)), Some(1));
        let mut invalid = criteria;
        invalid.dscp.insert(64);
        assert!(d.set_qos_class(class, invalid).is_err());
        assert!(d.remove_qos_class("DNS").is_err());
        let port = d.find_interface("GigabitEthernet0/0").unwrap();
        d.set_service_policy_output(port, Some(policy)).unwrap();
        assert!(d.remove_qos_policy("OUT").is_err());
        assert!(
            d.set_qos_policy_class(
                policy,
                QosPolicyClass {
                    class: Some(class),
                    police: Some(QosRate {
                        bits_per_second: 0,
                        burst_bytes: None
                    }),
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
}
