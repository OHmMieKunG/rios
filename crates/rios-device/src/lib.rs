//! Device inventory and validated state transitions, independent of CLI syntax.
#![forbid(unsafe_code)]
mod acl;
mod bgp;
mod qos;
mod route_policy;
pub use bgp::BgpNeighborInfo;
pub use qos::{QosProfile, QosProfileClass};
mod ospfv3;
pub use ospfv3::{OspfV3NeighborInfo, OspfV3Transmission};
mod ipv6;
pub use ipv6::{
    Ipv6AddressEntry, Ipv6AddressOrigin, Ipv6AddressState, Ipv6ControlPacket, Ipv6Neighbor,
    Ipv6NeighborState, Ipv6Route, Ipv6RouteSource, ResolvedIpv6Route,
};
mod channel;
mod lacp;
pub use lacp::LacpNeighbor;
mod dhcp;
mod display;
mod ethernet;
mod named_acl;
pub use named_acl::AclLog;
mod nat;
mod network;
mod ospf;
use ospf::OspfRuntime;
pub use ospf::{OspfNeighborInfo, OspfTransmission};
mod stp;
mod subinterface;
mod tcp;
pub use dhcp::{DhcpBinding, DhcpLease, DhcpOffer};
pub use ethernet::{DropReason, MacEntry};
pub use nat::{NatOutcome, NatProtocol, NatStatistics, NatTranslation};
pub use network::{ArpEntry, ResolvedRoute};
use rios_config::{
    AccessListDirection, AccessListId, AdminState, InterfaceConfig, RunningConfig, StartupConfig,
    SwitchportConfig, SwitchportMode, VlanConfig, VlanId,
};
use rios_ethernet::{EthernetFrame, MacAddress};
use rios_ipv4::Ipv4InterfaceConfig;
use rios_simulator::{DeviceId, InterfaceId, LinkState};
use rios_switching::{StpPortRole, StpPortState};
use std::collections::{BTreeMap, BTreeSet};
pub use tcp::{TcpConnection, TcpError, TcpSocket, TcpState};

/// Supported classes of simulated device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Router,
    Switch,
    Layer3Switch,
    Host,
}
impl std::fmt::Display for DeviceType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Router => "Router",
            Self::Switch => "Switch",
            Self::Layer3Switch => "L3 Switch",
            Self::Host => "Host",
        })
    }
}
/// Interface medium and its carrier behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind {
    GigabitEthernet,
    TenGigabitEthernet,
    EthernetSubinterface,
    PortChannel,
    Serial,
    Console,
    Loopback,
    Vlan,
}
impl InterfaceKind {
    /// Whether this interface carries Ethernet frames through virtual links.
    pub fn is_ethernet(self) -> bool {
        matches!(self, Self::GigabitEthernet | Self::TenGigabitEthernet)
    }

    /// Whether this interface represents installed hardware rather than a logical interface.
    pub fn is_physical(self) -> bool {
        !matches!(
            self,
            Self::Loopback | Self::Vlan | Self::EthernetSubinterface | Self::PortChannel
        )
    }
}
/// Physical connector or transceiver presented by an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMedia {
    Rj45,
    Sfp,
    SfpPlus,
    Serial,
    Console,
    Virtual,
}
impl std::fmt::Display for InterfaceMedia {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Rj45 => "RJ45",
            Self::Sfp => "SFP",
            Self::SfpPlus => "SFP+",
            Self::Serial => "Serial",
            Self::Console => "Console",
            Self::Virtual => "Virtual",
        })
    }
}
/// Runtime traffic counters. Configuration changes do not reset them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterfaceCounters {
    pub drop_reasons: BTreeMap<DropReason, u64>,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub drops: u64,
}
/// Runtime interface state; configuration is stored by ID in RunningConfig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub id: InterfaceId,
    pub kind: InterfaceKind,
    pub media: InterfaceMedia,
    pub mac_address: MacAddress,
    pub link_state: LinkState,
    pub counters: InterfaceCounters,
}
/// A virtual device with privately owned runtime and configuration state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    ipv6: ipv6::Ipv6Runtime,
    bgp: bgp::BgpRuntime,
    ospfv3: ospfv3::OspfV3Runtime,
    stp_errdisabled: BTreeSet<InterfaceId>,
    lacp_neighbors: BTreeMap<InterfaceId, LacpNeighbor>,
    tcp: tcp::TcpRuntime,
    acl_matches: BTreeMap<(rios_config::AclId, u32), u64>,
    acl_logs: BTreeMap<(rios_config::AclId, u32), u64>,
    acl_log_records: std::collections::VecDeque<AclLog>,
    legacy_acl_matches: BTreeMap<(AccessListId, usize), u64>,
    id: DeviceId,
    device_type: DeviceType,
    interfaces: BTreeMap<InterfaceId, Interface>,
    running_config: RunningConfig,
    startup_config: StartupConfig,
    arp_cache: BTreeMap<std::net::Ipv4Addr, ArpEntry>,
    mac_table: BTreeMap<(VlanId, MacAddress), MacEntry>,
    ospf_runtime: OspfRuntime,
    stp_runtime: BTreeMap<VlanId, StpInstance>,
    dhcp_conflicts: BTreeMap<std::net::Ipv4Addr, rios_simulator::SimTime>,
    dhcp_leases: BTreeMap<InterfaceId, DhcpLease>,
    dhcp_bindings: BTreeMap<MacAddress, DhcpBinding>,
    dhcp_offers: BTreeMap<MacAddress, DhcpOffer>,
    nat_translations: Vec<NatTranslation>,
    nat_statistics: NatStatistics,
    next_nat_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StpReceived {
    bpdu: rios_switching::StpBpdu,
    guarded: bool,
    expires_at: rios_simulator::SimTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StpInstance {
    agreed: BTreeSet<InterfaceId>,
    transitions: BTreeMap<InterfaceId, rios_simulator::SimTime>,
    root_id: u64,
    root_cost: u32,
    root_port: Option<InterfaceId>,
    ports: BTreeMap<InterfaceId, (StpPortRole, StpPortState)>,
    received: BTreeMap<InterfaceId, StpReceived>,
}
/// Rejected state changes leave the device unchanged.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error("invalid BGP process, peer, or routing policy")]
    InvalidBgpConfig,
    #[error("invalid routing policy name, sequence, rule, or capacity")]
    InvalidRoutingPolicy,
    #[error("invalid QoS policy, class, rate, interface, or capacity")]
    InvalidQosConfig,
    #[error("invalid spanning-tree priority, cost, or port policy")]
    InvalidSpanningTree,
    #[error("invalid EtherChannel member or incompatible port configuration")]
    InvalidChannel,
    #[error("invalid access-list name, kind, sequence, or rule")]
    InvalidAccessList,
    #[error("access-list capacity exceeded")]
    AccessListCapacity,
    #[error("operation requires an Ethernet subinterface")]
    NotSubinterface,
    #[error("VLAN or native encapsulation already belongs to another subinterface")]
    DuplicateEncapsulation,
    #[error("hostname must be 1–63 ASCII letters, digits, or hyphens, starting with a letter")]
    InvalidHostname,
    #[error("invalid or unavailable interface: {0}")]
    InvalidInterface(String),
    #[error("interface does not exist")]
    MissingInterface,
    #[error("description must be at most 240 characters and contain no control characters")]
    InvalidDescription,
    #[error("device ID must fit in 24 bits for deterministic MAC allocation")]
    InvalidDeviceId,
    #[error("operation requires a physical switch port")]
    NotSwitchport,
    #[error("operation requires a routed interface")]
    NotRoutedPort,
    #[error("IPv4 is not available on this interface type")]
    UnsupportedIpv4Interface,
    #[error("VLAN name must be 1-32 non-whitespace printable ASCII characters")]
    InvalidVlanName,
    #[error("default VLAN 1 cannot be removed")]
    DefaultVlan,
    #[error("OSPF process ID must be nonzero")]
    InvalidOspfProcess,
    #[error("invalid OSPF interface timers, cost, router ID, or capacity")]
    InvalidOspfConfig,
    #[error("invalid IPv6 policy, address, route, or capacity")]
    InvalidIpv6Config,
    #[error("OSPF requires a routing-capable device")]
    OspfUnsupported,
    #[error("access lists require a routing-capable device")]
    AccessListUnsupported,
    #[error("access list does not exist")]
    MissingAccessList,
    #[error("DHCP is supported only on routers and hosts")]
    DhcpUnsupported,
    #[error("DHCP pool name must be 1-32 printable non-whitespace characters")]
    InvalidDhcpPoolName,
    #[error("DHCP pool does not exist")]
    MissingDhcpPool,
    #[error("DHCP pool network cannot use /31 or /32")]
    InvalidDhcpNetwork,
    #[error("NAT is supported only on router devices")]
    NatUnsupported,
    #[error("NAT overload requires an existing access list and outside interface")]
    InvalidNatConfig,
}

impl Device {
    /// Whether this device can bridge Ethernet switchports.
    pub fn supports_switching(&self) -> bool {
        matches!(
            self.device_type,
            DeviceType::Switch | DeviceType::Layer3Switch
        )
    }

    /// Whether this device can route IPv4 packets.
    pub fn supports_routing(&self) -> bool {
        matches!(
            self.device_type,
            DeviceType::Router | DeviceType::Layer3Switch
        )
    }

    /// Whether this device forwards transit IPv4 packets.
    pub fn ipv4_forwarding_enabled(&self) -> bool {
        self.device_type == DeviceType::Router
            || (self.device_type == DeviceType::Layer3Switch && self.running_config.ip_routing)
    }

    /// Enable or disable global IPv4 forwarding on a routing-capable device.
    pub fn set_ip_routing(&mut self, enabled: bool) -> Result<(), DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::NotRoutedPort);
        }
        self.running_config.ip_routing = enabled;
        Ok(())
    }

    /// Construct an isolated device with no interfaces. IDs must be unique in a lab.
    pub fn new(id: DeviceId, hostname: &str, device_type: DeviceType) -> Result<Self, DeviceError> {
        validate_hostname(hostname)?;
        if id.0 > 0xff_ffff {
            return Err(DeviceError::InvalidDeviceId);
        }
        let mut vlans = BTreeMap::new();
        if matches!(device_type, DeviceType::Switch | DeviceType::Layer3Switch) {
            vlans.insert(VlanId::DEFAULT, VlanConfig::default());
        }
        Ok(Self {
            stp_errdisabled: BTreeSet::new(),
            lacp_neighbors: BTreeMap::new(),
            tcp: tcp::TcpRuntime::default(),
            acl_matches: BTreeMap::new(),
            acl_logs: BTreeMap::new(),
            acl_log_records: Default::default(),
            legacy_acl_matches: BTreeMap::new(),
            id,
            device_type,
            interfaces: BTreeMap::new(),
            ipv6: ipv6::Ipv6Runtime::default(),
            bgp: bgp::BgpRuntime::default(),
            ospfv3: ospfv3::OspfV3Runtime::default(),
            running_config: RunningConfig {
                bgp: None,
                routing_policy: Default::default(),
                qos: Default::default(),
                ospfv3: None,
                ipv6_unicast_routing: false,
                ipv6_static_routes: BTreeSet::new(),
                spanning_tree: rios_config::StpConfig::default(),
                dhcp_excluded: BTreeMap::new(),
                static_nat: BTreeSet::new(),
                nat_pools: BTreeMap::new(),
                nat_pool_rule: None,
                named_access_lists: BTreeMap::new(),
                hostname: hostname.into(),
                ip_routing: false,
                interfaces: BTreeMap::new(),
                static_routes: BTreeMap::new(),
                vlans,
                ospf: None,
                access_lists: BTreeMap::new(),
                dhcp_pools: BTreeMap::new(),
                nat_overload: None,
            },
            startup_config: StartupConfig::default(),
            arp_cache: BTreeMap::new(),
            mac_table: BTreeMap::new(),
            ospf_runtime: OspfRuntime::default(),
            stp_runtime: BTreeMap::new(),
            dhcp_conflicts: BTreeMap::new(),
            dhcp_leases: BTreeMap::new(),
            dhcp_bindings: BTreeMap::new(),
            dhcp_offers: BTreeMap::new(),
            nat_translations: Vec::new(),
            nat_statistics: NatStatistics::default(),
            next_nat_port: 10_000,
        })
    }
    /// Default two-port router used by the standalone frontend.
    pub fn standalone() -> Self {
        let mut device = Self::new(DeviceId(1), "R1", DeviceType::Router).unwrap();
        device.add_physical_interface("GigabitEthernet0/0").unwrap();
        device.add_physical_interface("GigabitEthernet0/1").unwrap();
        device
    }
    /// Stable device ID.
    pub fn id(&self) -> DeviceId {
        self.id
    }
    /// Device capability class.
    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }
    /// Current prompt hostname.
    pub fn hostname(&self) -> &str {
        &self.running_config.hostname
    }
    /// Read-only current configuration.
    pub fn running_config(&self) -> &RunningConfig {
        &self.running_config
    }
    /// Read-only independent saved snapshot.
    pub fn startup_config(&self) -> &StartupConfig {
        &self.startup_config
    }
    /// Read-only runtime inventory.
    pub fn interfaces(&self) -> &BTreeMap<InterfaceId, Interface> {
        &self.interfaces
    }
    /// Change a validated hostname.
    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), DeviceError> {
        validate_hostname(hostname)?;
        self.running_config.hostname = hostname.into();
        Ok(())
    }
    /// Add hardware inventory; CLI cannot fabricate physical ports.
    pub fn add_physical_interface(&mut self, name: &str) -> Result<InterfaceId, DeviceError> {
        let (canonical, kind) = canonical_interface(name)?;
        if !kind.is_physical() {
            return Err(DeviceError::InvalidInterface(name.into()));
        }
        let media = match kind {
            InterfaceKind::GigabitEthernet => InterfaceMedia::Rj45,
            InterfaceKind::TenGigabitEthernet => InterfaceMedia::SfpPlus,
            InterfaceKind::Serial => InterfaceMedia::Serial,
            InterfaceKind::Console => InterfaceMedia::Console,
            InterfaceKind::Loopback
            | InterfaceKind::Vlan
            | InterfaceKind::EthernetSubinterface
            | InterfaceKind::PortChannel => {
                unreachable!()
            }
        };
        self.insert_interface(canonical, kind, media)
    }
    /// Add validated hardware with an explicit connector or transceiver type.
    pub fn add_port(
        &mut self,
        name: &str,
        media: InterfaceMedia,
    ) -> Result<InterfaceId, DeviceError> {
        let (canonical, kind) = canonical_interface(name)?;
        let valid = matches!(
            (kind, media),
            (
                InterfaceKind::GigabitEthernet,
                InterfaceMedia::Rj45 | InterfaceMedia::Sfp
            ) | (InterfaceKind::TenGigabitEthernet, InterfaceMedia::SfpPlus)
                | (InterfaceKind::Serial, InterfaceMedia::Serial)
                | (InterfaceKind::Console, InterfaceMedia::Console)
        );
        if !valid {
            return Err(DeviceError::InvalidInterface(name.into()));
        }
        self.insert_interface(canonical, kind, media)
    }
    fn insert_interface(
        &mut self,
        name: String,
        kind: InterfaceKind,
        media: InterfaceMedia,
    ) -> Result<InterfaceId, DeviceError> {
        if let Some(id) = self.find_interface(&name) {
            return Ok(id);
        }
        let next = self
            .interfaces
            .last_key_value()
            .map_or(1, |(id, _)| id.0 + 1);
        if next > u16::MAX.into() {
            return Err(DeviceError::InvalidInterface(name));
        }
        let id = InterfaceId(next);
        let d = self.id.0.to_be_bytes();
        let p = next.to_be_bytes();
        self.interfaces.insert(
            id,
            Interface {
                id,
                kind,
                media,
                mac_address: MacAddress([2, d[5], d[6], d[7], p[6], p[7]]),
                link_state: LinkState::Down,
                counters: InterfaceCounters::default(),
            },
        );
        self.running_config.interfaces.insert(
            id,
            InterfaceConfig {
                service_policy_output: None,
                ipv6: rios_config::Ipv6InterfacePolicy::default(),
                ospf: rios_config::OspfInterfaceConfig::default(),
                spanning_tree: rios_config::StpPortConfig::default(),
                channel_group: None,
                port_channel: None,
                helper_address: None,
                named_access_group_in: None,
                named_access_group_out: None,
                parent: None,
                dot1q: None,
                name,
                description: String::new(),
                admin_state: if self.supports_switching() && kind.is_ethernet() {
                    AdminState::Up
                } else {
                    AdminState::Down
                },
                ipv4: None,
                dhcp_client: false,
                mtu: 1500,
                switchport_capable: self.supports_switching() && kind.is_ethernet(),
                switchport: (self.supports_switching() && kind.is_ethernet())
                    .then(SwitchportConfig::default),
                access_group_in: None,
                access_group_out: None,
                nat_role: None,
            },
        );
        Ok(id)
    }
    /// Resolve a normalized full interface name without mutation.
    pub fn find_interface(&self, canonical: &str) -> Option<InterfaceId> {
        self.running_config
            .interfaces
            .iter()
            .find(|(_, c)| c.name.eq_ignore_ascii_case(canonical))
            .map(|(id, _)| *id)
    }

    /// Resolve a same-family, same-slot inclusive interface range.
    pub fn interface_range(
        &self,
        first: InterfaceId,
        last: InterfaceId,
    ) -> Result<Vec<InterfaceId>, DeviceError> {
        let first_name = &self
            .running_config
            .interfaces
            .get(&first)
            .ok_or(DeviceError::MissingInterface)?
            .name;
        let last_name = &self
            .running_config
            .interfaces
            .get(&last)
            .ok_or(DeviceError::MissingInterface)?
            .name;
        let (first_stem, first_number) = interface_sequence(first_name)
            .ok_or_else(|| DeviceError::InvalidInterface(first_name.clone()))?;
        let (last_stem, last_number) = interface_sequence(last_name)
            .ok_or_else(|| DeviceError::InvalidInterface(last_name.clone()))?;
        if first_stem != last_stem || first_number > last_number {
            return Err(DeviceError::InvalidInterface(format!(
                "{first_name}-{last_name}"
            )));
        }
        Ok(self
            .running_config
            .interfaces
            .iter()
            .filter_map(|(id, config)| {
                let (stem, number) = interface_sequence(&config.name)?;
                (stem == first_stem && (first_number..=last_number).contains(&number))
                    .then_some(*id)
            })
            .collect())
    }
    /// Enter an existing interface or create a validated logical interface.
    pub fn ensure_interface(&mut self, name: &str) -> Result<InterfaceId, DeviceError> {
        let (canonical, kind) = canonical_interface(name)?;
        if let Some(id) = self.find_interface(&canonical) {
            return Ok(id);
        }
        if kind.is_physical() {
            return Err(DeviceError::InvalidInterface(name.into()));
        }
        if kind == InterfaceKind::EthernetSubinterface {
            return self.create_subinterface(&canonical);
        }
        if kind == InterfaceKind::PortChannel {
            return self.create_port_channel(&canonical);
        }
        self.insert_interface(canonical, kind, InterfaceMedia::Virtual)
    }
    fn config_mut(&mut self, id: InterfaceId) -> Result<&mut InterfaceConfig, DeviceError> {
        self.running_config
            .interfaces
            .get_mut(&id)
            .ok_or(DeviceError::MissingInterface)
    }
    /// Set a description after validating printable input.
    pub fn set_description(&mut self, id: InterfaceId, text: &str) -> Result<(), DeviceError> {
        if text.chars().count() > 240 || text.chars().any(char::is_control) {
            return Err(DeviceError::InvalidDescription);
        }
        self.config_mut(id)?.description = text.trim().into();
        Ok(())
    }
    /// Remove an interface description.
    pub fn clear_description(&mut self, id: InterfaceId) -> Result<(), DeviceError> {
        self.config_mut(id)?.description.clear();
        Ok(())
    }
    /// Set a validated IPv4 address.
    pub fn set_ipv4(
        &mut self,
        id: InterfaceId,
        ip: Ipv4InterfaceConfig,
    ) -> Result<(), DeviceError> {
        if self.interfaces.get(&id).is_some_and(|interface| {
            matches!(
                interface.kind,
                InterfaceKind::Serial | InterfaceKind::Console
            )
        }) {
            return Err(DeviceError::UnsupportedIpv4Interface);
        }
        if self.channel_interface(id).is_some() {
            return Err(DeviceError::InvalidChannel);
        }
        if self
            .running_config
            .interfaces
            .get(&id)
            .is_some_and(|config| config.switchport.is_some())
        {
            return Err(DeviceError::NotRoutedPort);
        }
        let config = self.config_mut(id)?;
        config.ipv4 = Some(ip);
        config.dhcp_client = false;
        self.dhcp_leases.remove(&id);
        Ok(())
    }
    /// Remove static or DHCP IPv4 configuration from an interface.
    pub fn clear_ipv4(&mut self, id: InterfaceId) -> Result<(), DeviceError> {
        let config = self.config_mut(id)?;
        config.ipv4 = None;
        config.dhcp_client = false;
        self.dhcp_leases.remove(&id);
        Ok(())
    }
    /// Change administrative state without inventing carrier.
    pub fn set_admin_state(
        &mut self,
        id: InterfaceId,
        state: AdminState,
    ) -> Result<(), DeviceError> {
        self.config_mut(id)?.admin_state = state;
        if state == AdminState::Down {
            self.reset_ipv6_interface(id);
            self.stp_errdisabled.remove(&id);
            self.lacp_neighbors.remove(&id);
            for instance in self.stp_runtime.values_mut() {
                instance.received.remove(&id);
                instance.ports.remove(&id);
            }
        }
        Ok(())
    }
    /// Create a VLAN database entry on a switch.
    pub fn create_vlan(&mut self, vlan: VlanId) -> Result<(), DeviceError> {
        if !self.supports_switching() {
            return Err(DeviceError::NotSwitchport);
        }
        self.running_config.vlans.entry(vlan).or_default();
        Ok(())
    }

    /// Remove a non-default VLAN and its learned runtime state.
    pub fn remove_vlan(&mut self, vlan: VlanId) -> Result<(), DeviceError> {
        if !self.supports_switching() {
            return Err(DeviceError::NotSwitchport);
        }
        if vlan == VlanId::DEFAULT {
            return Err(DeviceError::DefaultVlan);
        }
        self.running_config.vlans.remove(&vlan);
        self.mac_table
            .retain(|(entry_vlan, _), _| *entry_vlan != vlan);
        self.stp_runtime.remove(&vlan);
        Ok(())
    }

    /// Set a validated VLAN name.
    pub fn set_vlan_name(&mut self, vlan: VlanId, name: &str) -> Result<(), DeviceError> {
        if name.is_empty() || name.len() > 32 || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(DeviceError::InvalidVlanName);
        }
        self.running_config
            .vlans
            .get_mut(&vlan)
            .ok_or(DeviceError::NotSwitchport)?
            .name = name.into();
        Ok(())
    }

    fn switchport_mut(&mut self, id: InterfaceId) -> Result<&mut SwitchportConfig, DeviceError> {
        self.config_mut(id)?
            .switchport
            .as_mut()
            .ok_or(DeviceError::NotSwitchport)
    }

    /// Whether an interface currently participates in Layer 2 switching.
    pub fn is_switchport(&self, id: InterfaceId) -> bool {
        self.running_config
            .interfaces
            .get(&id)
            .is_some_and(|interface| interface.switchport.is_some())
    }

    /// Put an Ethernet port into Layer 2 switchport mode.
    pub fn enable_switchport(&mut self, id: InterfaceId) -> Result<(), DeviceError> {
        if !self.supports_switching()
            || !self.interfaces.get(&id).is_some_and(|interface| {
                interface.kind.is_ethernet() || interface.kind == InterfaceKind::PortChannel
            })
        {
            return Err(DeviceError::NotSwitchport);
        }
        let config = self.config_mut(id)?;
        config.ipv4 = None;
        config.ipv6 = rios_config::Ipv6InterfacePolicy::default();
        config.dhcp_client = false;
        config.switchport.get_or_insert_default();
        self.reset_ipv6_interface(id);
        self.sync_channel_switchports(id);
        Ok(())
    }

    /// Put a Layer 3 switch Ethernet port into routed mode.
    pub fn disable_switchport(&mut self, id: InterfaceId) -> Result<(), DeviceError> {
        if self.device_type != DeviceType::Layer3Switch
            || !self.interfaces.get(&id).is_some_and(|interface| {
                interface.kind.is_ethernet() || interface.kind == InterfaceKind::PortChannel
            })
        {
            return Err(DeviceError::NotRoutedPort);
        }
        self.config_mut(id)?.switchport = None;
        self.sync_channel_switchports(id);
        self.mac_table.retain(|_, entry| entry.interface != id);
        Ok(())
    }

    /// Select access or trunk mode on a physical switch port.
    pub fn set_switchport_mode(
        &mut self,
        id: InterfaceId,
        mode: SwitchportMode,
    ) -> Result<(), DeviceError> {
        if self.device_type == DeviceType::Layer3Switch && !self.is_switchport(id) {
            self.enable_switchport(id)?;
        }
        self.switchport_mut(id)?.mode = mode;
        self.sync_channel_switchports(id);
        self.mac_table.retain(|_, entry| entry.interface != id);
        Ok(())
    }

    /// Assign the untagged access VLAN for a physical switch port.
    pub fn set_access_vlan(&mut self, id: InterfaceId, vlan: VlanId) -> Result<(), DeviceError> {
        self.switchport_mut(id)?.access_vlan = vlan;
        self.sync_channel_switchports(id);
        self.mac_table.retain(|_, entry| entry.interface != id);
        Ok(())
    }

    /// Replace the VLAN allow-list for a trunk port.
    pub fn set_trunk_allowed_vlans(
        &mut self,
        id: InterfaceId,
        vlans: BTreeSet<VlanId>,
    ) -> Result<(), DeviceError> {
        self.switchport_mut(id)?.trunk_allowed_vlans = Some(vlans);
        self.sync_channel_switchports(id);
        self.mac_table.retain(|_, entry| entry.interface != id);
        Ok(())
    }

    /// Classify switch ingress and remove a permitted trunk tag.
    pub fn classify_switch_ingress(
        &self,
        id: InterfaceId,
        frame: &EthernetFrame,
    ) -> Option<(VlanId, EthernetFrame)> {
        let port = self
            .running_config
            .interfaces
            .get(&id)?
            .switchport
            .as_ref()?;
        let (vlan, frame) = match port.mode {
            SwitchportMode::Access if frame.ethertype != rios_ethernet::EtherType::Dot1Q => {
                (port.access_vlan, frame.clone())
            }
            SwitchportMode::Trunk if frame.ethertype == rios_ethernet::EtherType::Dot1Q => {
                frame.untagged().ok()?
            }
            SwitchportMode::Trunk => (port.native_vlan, frame.clone()),
            SwitchportMode::Access => return None,
        };
        let allowed = port.mode == SwitchportMode::Access
            || port
                .trunk_allowed_vlans
                .as_ref()
                .is_none_or(|allowed| allowed.contains(&vlan));
        (allowed && self.running_config.vlans.contains_key(&vlan)).then_some((vlan, frame))
    }

    /// Apply access/trunk encapsulation for a permitted switch egress.
    pub fn prepare_switch_egress(
        &self,
        id: InterfaceId,
        vlan: VlanId,
        frame: EthernetFrame,
    ) -> Option<EthernetFrame> {
        let port = self
            .running_config
            .interfaces
            .get(&id)?
            .switchport
            .as_ref()?;
        match port.mode {
            SwitchportMode::Access if port.access_vlan == vlan => Some(frame),
            SwitchportMode::Trunk
                if port
                    .trunk_allowed_vlans
                    .as_ref()
                    .is_none_or(|allowed| allowed.contains(&vlan)) =>
            {
                Some(if port.native_vlan == vlan {
                    frame
                } else {
                    frame.tagged(vlan)
                })
            }
            _ => None,
        }
    }

    /// Return the VLAN represented by an SVI.
    pub fn svi_vlan(&self, id: InterfaceId) -> Option<VlanId> {
        let interface = self.interfaces.get(&id)?;
        if interface.kind != InterfaceKind::Vlan {
            return None;
        }
        let name = &self.running_config.interfaces.get(&id)?.name;
        VlanId::new(name.strip_prefix("Vlan")?.parse().ok()?).ok()
    }

    /// Find an operational SVI for a VLAN.
    pub fn active_svi(&self, vlan: VlanId) -> Option<InterfaceId> {
        self.interfaces
            .keys()
            .copied()
            .find(|id| self.svi_vlan(*id) == Some(vlan) && self.protocol_up(*id))
    }

    /// Recompute SVI autostate from active access and trunk membership.
    pub fn refresh_svi_states(&mut self) {
        let states: Vec<_> = self
            .interfaces
            .iter()
            .filter(|(_, interface)| interface.kind == InterfaceKind::Vlan)
            .map(|(id, _)| {
                let vlan = self.svi_vlan(*id).expect("validated SVI name");
                let up = self.running_config.vlans.contains_key(&vlan)
                    && self
                        .running_config
                        .interfaces
                        .iter()
                        .any(|(port_id, config)| {
                            let Some(switchport) = &config.switchport else {
                                return false;
                            };
                            config.channel_group.is_none()
                                && self.protocol_up(*port_id)
                                && match switchport.mode {
                                    SwitchportMode::Access => switchport.access_vlan == vlan,
                                    SwitchportMode::Trunk => switchport
                                        .trunk_allowed_vlans
                                        .as_ref()
                                        .is_none_or(|allowed| allowed.contains(&vlan)),
                                }
                        });
                (*id, up)
            })
            .collect();
        for (id, up) in states {
            self.interfaces.get_mut(&id).unwrap().link_state =
                if up { LinkState::Up } else { LinkState::Down };
        }
    }

    /// Update physical carrier from the simulation layer.
    pub fn set_link_state(&mut self, id: InterfaceId, state: LinkState) -> Result<(), DeviceError> {
        if state == LinkState::Down
            && self
                .interfaces
                .get(&id)
                .is_some_and(|port| port.link_state != state)
        {
            self.reset_ipv6_interface(id);
        }
        self.interfaces
            .get_mut(&id)
            .ok_or(DeviceError::MissingInterface)?
            .link_state = state;
        if state == LinkState::Down {
            self.lacp_neighbors.remove(&id);
            for instance in self.stp_runtime.values_mut() {
                instance.received.remove(&id);
                instance.agreed.remove(&id);
                instance.transitions.remove(&id);
            }
            self.mac_table.retain(|_, entry| entry.interface != id);
        }
        Ok(())
    }
    /// Effective line protocol state includes administrative and carrier state.
    pub fn protocol_up(&self, id: InterfaceId) -> bool {
        let Some(interface) = self.interfaces.get(&id) else {
            return false;
        };
        !self.stp_errdisabled.contains(&id)
            && self.running_config.interfaces[&id].admin_state == AdminState::Up
            && match interface.kind {
                InterfaceKind::Loopback => true,
                InterfaceKind::PortChannel => !self.channel_members(id).is_empty(),
                InterfaceKind::EthernetSubinterface => self
                    .running_config
                    .interfaces
                    .get(&id)
                    .is_some_and(|config| {
                        config.dot1q.is_some()
                            && config.parent.is_some_and(|parent| {
                                self.protocol_up(parent) && !self.is_switchport(parent)
                            })
                    }),
                InterfaceKind::GigabitEthernet | InterfaceKind::TenGigabitEthernet => {
                    interface.link_state == LinkState::Up
                }
                InterfaceKind::Vlan => interface.link_state == LinkState::Up,
                InterfaceKind::Serial | InterfaceKind::Console => false,
            }
    }
    /// Save an independent in-memory startup snapshot.
    pub fn save_config(&mut self) {
        self.startup_config.0 = Some(self.running_config.clone());
    }
}

fn validate_hostname(name: &str) -> Result<(), DeviceError> {
    if name.is_empty()
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(DeviceError::InvalidHostname);
    }
    Ok(())
}

fn interface_sequence(name: &str) -> Option<(&str, u16)> {
    let split = name.rfind(|c: char| !c.is_ascii_digit())? + 1;
    Some((&name[..split], name[split..].parse().ok()?))
}
/// Normalize an unambiguous interface-family prefix and validate its numeric suffix.
pub fn canonical_interface(input: &str) -> Result<(String, InterfaceKind), DeviceError> {
    let parts: Vec<_> = input.split_whitespace().collect();
    if parts.len() > 2
        || (parts.len() == 2
            && !parts[0]
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'-'))
    {
        return Err(DeviceError::InvalidInterface(input.into()));
    }
    let compact: String = parts.concat();
    if let Some((parent, number)) = compact.split_once('.') {
        if parent.is_empty()
            || number.is_empty()
            || !number.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(DeviceError::InvalidInterface(input.into()));
        }
        let number = number
            .parse::<u32>()
            .ok()
            .filter(|number| *number > 0)
            .ok_or_else(|| DeviceError::InvalidInterface(input.into()))?;
        let (parent, kind) = canonical_interface(parent)?;
        if !kind.is_ethernet() {
            return Err(DeviceError::InvalidInterface(input.into()));
        }
        return Ok((
            format!("{parent}.{number}"),
            InterfaceKind::EthernetSubinterface,
        ));
    }
    let split = compact
        .find(|c: char| c.is_ascii_digit())
        .ok_or_else(|| DeviceError::InvalidInterface(input.into()))?;
    let (family, suffix) = compact.split_at(split);
    let candidates = [
        ("GigabitEthernet", InterfaceKind::GigabitEthernet),
        ("TenGigabitEthernet", InterfaceKind::TenGigabitEthernet),
        ("Serial", InterfaceKind::Serial),
        ("Console", InterfaceKind::Console),
        ("Port-channel", InterfaceKind::PortChannel),
        ("Loopback", InterfaceKind::Loopback),
        ("Vlan", InterfaceKind::Vlan),
    ];
    let found: Vec<_> = candidates
        .into_iter()
        .filter(|(name, _)| {
            !family.is_empty()
                && name
                    .to_ascii_lowercase()
                    .starts_with(&family.to_ascii_lowercase())
        })
        .collect();
    if found.len() != 1 {
        return Err(DeviceError::InvalidInterface(input.into()));
    }
    let (name, kind) = found[0];
    if !suffix.bytes().all(|b| b.is_ascii_digit() || b == b'/') {
        return Err(DeviceError::InvalidInterface(input.into()));
    }
    let numbers: Result<Vec<u16>, _> = suffix.split('/').map(str::parse).collect();
    let numbers = numbers.map_err(|_| DeviceError::InvalidInterface(input.into()))?;
    let valid = match kind {
        InterfaceKind::GigabitEthernet
        | InterfaceKind::TenGigabitEthernet
        | InterfaceKind::Serial => (2..=3).contains(&numbers.len()),
        InterfaceKind::EthernetSubinterface => false,
        InterfaceKind::PortChannel => numbers.len() == 1 && (1..=4096).contains(&numbers[0]),
        InterfaceKind::Console => numbers.len() == 1,
        InterfaceKind::Loopback => numbers.len() == 1,
        InterfaceKind::Vlan => numbers.len() == 1 && (1..=4094).contains(&numbers[0]),
    };
    if !valid {
        return Err(DeviceError::InvalidInterface(input.into()));
    }
    Ok((
        format!(
            "{name}{}",
            numbers
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("/")
        ),
        kind,
    ))
}
