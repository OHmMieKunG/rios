//! DHCP address allocation, validated options, and lease state.
use crate::*;
mod config;
use rios_config::{DhcpPoolConfig, DhcpPoolId};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::SimTime;
use std::{collections::BTreeSet, fmt::Write, net::Ipv4Addr};

const MAX_DHCP_BINDINGS: usize = 8192;
const DHCP_OFFER_MS: u64 = 60_000;

/// Runtime IPv4 lease installed on a DHCP client interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpLease {
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub renew_at: SimTime,
    pub rebind_at: SimTime,
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub default_router: Option<Ipv4Addr>,
    pub server_id: Ipv4Addr,
    pub expires_at: SimTime,
}

/// Runtime server binding committed to a client MAC address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpBinding {
    pub address: Ipv4Addr,
    pub client_mac: MacAddress,
    pub pool_name: String,
    pub expires_at: SimTime,
}

/// Address and options reserved by a DHCP server offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpOffer {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub default_router: Option<Ipv4Addr>,
    pub server_id: Ipv4Addr,
    pub lease_time_seconds: u32,
    pub pool: DhcpPoolId,
    pub expires_at: SimTime,
}

impl Device {
    /// Create or select a DHCP server pool.
    pub fn ensure_dhcp_pool(&mut self, name: &str) -> Result<DhcpPoolId, DeviceError> {
        if !self.supports_routing() {
            return Err(DeviceError::DhcpUnsupported);
        }
        if name.is_empty() || name.len() > 32 || !name.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(DeviceError::InvalidDhcpPoolName);
        }
        if let Some((id, _)) = self
            .running_config
            .dhcp_pools
            .iter()
            .find(|(_, pool)| pool.name.eq_ignore_ascii_case(name))
        {
            return Ok(*id);
        }
        if self.running_config.dhcp_pools.len() >= 1024 {
            return Err(DeviceError::InvalidDhcpNetwork);
        }
        let id = DhcpPoolId(
            self.running_config
                .dhcp_pools
                .last_key_value()
                .map_or(1, |(id, _)| id.0.saturating_add(1)),
        );
        self.running_config.dhcp_pools.insert(
            id,
            DhcpPoolConfig {
                lease_seconds: 3600,
                dns_servers: Vec::new(),
                domain_name: None,
                reserved_address: None,
                hardware_address: None,
                name: name.into(),
                network: None,
                default_router: None,
            },
        );
        Ok(id)
    }

    /// Set the allocatable network for a DHCP pool.
    pub fn set_dhcp_pool_network(
        &mut self,
        id: DhcpPoolId,
        network: Ipv4Network,
    ) -> Result<(), DeviceError> {
        if network.prefix_len() > 30 {
            return Err(DeviceError::InvalidDhcpNetwork);
        }
        let mut pool = self
            .running_config
            .dhcp_pools
            .get(&id)
            .ok_or(DeviceError::MissingDhcpPool)?
            .clone();
        pool.network = Some(network);
        self.update_dhcp_pool(id, pool)
    }

    /// Set the default-router option for a DHCP pool.
    pub fn set_dhcp_default_router(
        &mut self,
        id: DhcpPoolId,
        address: Ipv4Addr,
    ) -> Result<(), DeviceError> {
        let mut pool = self
            .running_config
            .dhcp_pools
            .get(&id)
            .ok_or(DeviceError::MissingDhcpPool)?
            .clone();
        pool.default_router = Some(address);
        self.update_dhcp_pool(id, pool)
    }

    /// Configure an interface as a DHCP client and clear any static or old lease address.
    pub fn set_dhcp_client(&mut self, interface: InterfaceId) -> Result<(), DeviceError> {
        if !matches!(
            self.device_type,
            DeviceType::Router | DeviceType::Host | DeviceType::Layer3Switch
        ) {
            return Err(DeviceError::DhcpUnsupported);
        }
        if self.interfaces.get(&interface).is_some_and(|interface| {
            matches!(
                interface.kind,
                InterfaceKind::Serial | InterfaceKind::Console
            )
        }) {
            return Err(DeviceError::UnsupportedIpv4Interface);
        }
        let config = self.config_mut(interface)?;
        let was_dhcp = config.dhcp_client;
        config.ipv4 = None;
        config.dhcp_client = true;
        if !was_dhcp {
            self.dhcp_leases.remove(&interface);
        }
        Ok(())
    }

    /// Effective static or DHCP-provided interface address.
    pub fn interface_ipv4(&self, interface: InterfaceId) -> Option<Ipv4InterfaceConfig> {
        let config = self.running_config.interfaces.get(&interface)?;
        config.ipv4.or_else(|| {
            self.dhcp_leases
                .get(&interface)
                .and_then(|lease| Ipv4InterfaceConfig::new(lease.address, lease.prefix_len).ok())
        })
    }

    /// Operational client interfaces that do not currently have a lease.
    pub fn dhcp_client_interfaces(&self) -> Vec<InterfaceId> {
        self.running_config
            .interfaces
            .iter()
            .filter_map(|(id, config)| {
                (config.dhcp_client && self.protocol_up(*id) && !self.dhcp_leases.contains_key(id))
                    .then_some(*id)
            })
            .collect()
    }

    /// Whether a configured client still needs an address, even while its link is down.
    pub fn has_pending_dhcp_client(&self) -> bool {
        self.running_config
            .interfaces
            .iter()
            .any(|(id, config)| config.dhcp_client && !self.dhcp_leases.contains_key(id))
    }

    /// Reserve the first deterministic available address in a matching pool.
    pub fn offer_dhcp(
        &mut self,
        interface: InterfaceId,
        client_mac: MacAddress,
        now: SimTime,
    ) -> Option<DhcpOffer> {
        let subnet = self.interface_ipv4(interface)?.address();
        self.offer_dhcp_on_network(interface, client_mac, subnet, now)
    }

    /// Select a pool by relay giaddr (or the directly attached subnet).
    pub fn offer_dhcp_on_network(
        &mut self,
        interface: InterfaceId,
        client_mac: MacAddress,
        subnet: Ipv4Addr,
        now: SimTime,
    ) -> Option<DhcpOffer> {
        let server_id = self.interface_ipv4(interface)?.address();
        self.expire_dhcp_server_state(now);
        let (pool_id, pool) = self
            .running_config
            .dhcp_pools
            .iter()
            .filter(|(_, pool)| {
                pool.network.is_some_and(|network| network.contains(subnet))
                    && (pool.hardware_address.is_none()
                        || pool.hardware_address == Some(client_mac))
                    && (pool.reserved_address.is_none()
                        || pool.hardware_address == Some(client_mac))
            })
            .min_by_key(|(id, pool)| (pool.reserved_address.is_none(), **id))?;
        let pool_id = *pool_id;
        let pool = pool.clone();
        let network = pool.network?;
        if let Some(offer) = self.dhcp_offers.get(&client_mac).copied()
            && offer.pool == pool_id
        {
            return Some(offer);
        }
        let previous = self
            .dhcp_bindings
            .get(&client_mac)
            .filter(|binding| binding.pool_name == pool.name)
            .map(|binding| binding.address);
        if self.dhcp_offers.len() + self.dhcp_bindings.len() >= MAX_DHCP_BINDINGS
            && previous.is_none()
        {
            return None;
        }
        let used: BTreeSet<_> = self
            .dhcp_bindings
            .iter()
            .filter(|(mac, _)| **mac != client_mac)
            .map(|(_, binding)| binding.address)
            .chain(
                self.dhcp_offers
                    .iter()
                    .filter(|(mac, _)| **mac != client_mac)
                    .map(|(_, offer)| offer.address),
            )
            .chain(
                self.running_config
                    .interfaces
                    .keys()
                    .filter_map(|id| self.interface_ipv4(*id).map(|ip| ip.address())),
            )
            .chain(
                self.running_config
                    .dhcp_pools
                    .values()
                    .filter(|pool| pool.hardware_address != Some(client_mac))
                    .filter_map(|pool| pool.reserved_address),
            )
            .chain(self.dhcp_conflicts.keys().copied())
            .collect();
        let allowed = |address: Ipv4Addr| {
            network.contains(address)
                && address != network.address()
                && address != network.broadcast()
                && !used.contains(&address)
                && pool.default_router != Some(address)
                && !self
                    .running_config
                    .dhcp_excluded
                    .iter()
                    .any(|(first, last)| address >= *first && address <= *last)
        };
        let address = if let Some(address) = pool.reserved_address {
            if !allowed(address) {
                return None;
            }
            address
        } else if let Some(address) = previous.filter(|address| allowed(*address)) {
            address
        } else {
            let mut candidate = u32::from(network.address()).saturating_add(1);
            let last = u32::from(network.broadcast()).saturating_sub(1);
            loop {
                if candidate > last {
                    return None;
                }
                let address = Ipv4Addr::from(candidate);
                if let Some(end) = self
                    .running_config
                    .dhcp_excluded
                    .iter()
                    .filter(|(first, last)| address >= **first && address <= **last)
                    .map(|(_, last)| *last)
                    .max()
                {
                    candidate = u32::from(end).checked_add(1)?;
                } else if allowed(address) {
                    break address;
                } else {
                    candidate = candidate.checked_add(1)?;
                }
            }
        };
        let offer = DhcpOffer {
            address,
            prefix_len: network.prefix_len(),
            default_router: pool.default_router,
            server_id,
            lease_time_seconds: pool.lease_seconds,
            pool: pool_id,
            expires_at: SimTime(now.0.saturating_add(DHCP_OFFER_MS * 1000)),
        };
        self.dhcp_offers.insert(client_mac, offer);
        Some(offer)
    }

    /// Commit a previously offered address and return its lease options.
    pub fn commit_dhcp(
        &mut self,
        client_mac: MacAddress,
        address: Ipv4Addr,
        server_id: Ipv4Addr,
        now: SimTime,
    ) -> Option<DhcpOffer> {
        self.expire_dhcp_server_state(now);
        let mut offer = *self.dhcp_offers.get(&client_mac)?;
        if offer.address != address || offer.server_id != server_id {
            return None;
        }
        self.dhcp_offers.remove(&client_mac);
        offer.expires_at = SimTime(
            now.0
                .saturating_add(u64::from(offer.lease_time_seconds) * 1_000_000),
        );
        let pool_name = self
            .running_config
            .dhcp_pools
            .get(&offer.pool)?
            .name
            .clone();
        self.dhcp_bindings.insert(
            client_mac,
            DhcpBinding {
                address,
                client_mac,
                pool_name,
                expires_at: offer.expires_at,
            },
        );
        Some(offer)
    }

    /// Install an acknowledged DHCP lease on a configured client interface.
    pub fn install_dhcp_lease(
        &mut self,
        interface: InterfaceId,
        lease: DhcpLease,
    ) -> Result<(), DeviceError> {
        if !self
            .running_config
            .interfaces
            .get(&interface)
            .is_some_and(|config| config.dhcp_client)
        {
            return Err(DeviceError::DhcpUnsupported);
        }
        self.dhcp_leases.insert(interface, lease);
        Ok(())
    }

    /// Expire one matching client lease and report whether it was removed.
    pub fn expire_dhcp_lease(
        &mut self,
        interface: InterfaceId,
        address: Ipv4Addr,
        deadline: SimTime,
    ) -> bool {
        if self
            .dhcp_leases
            .get(&interface)
            .is_some_and(|lease| lease.address == address && lease.expires_at <= deadline)
        {
            self.dhcp_leases.remove(&interface);
            true
        } else {
            false
        }
    }

    /// Inspect a client's current operational lease.
    pub fn dhcp_lease(&self, interface: InterfaceId) -> Option<&DhcpLease> {
        self.dhcp_leases.get(&interface)
    }

    /// Quarantine a declined address for ten simulated minutes.
    pub fn decline_dhcp(&mut self, mac: MacAddress, address: Ipv4Addr, now: SimTime) {
        let valid = self
            .dhcp_bindings
            .get(&mac)
            .is_some_and(|binding| binding.address == address)
            || self
                .dhcp_offers
                .get(&mac)
                .is_some_and(|offer| offer.address == address);
        if valid {
            self.dhcp_bindings.remove(&mac);
            self.dhcp_offers.remove(&mac);
            if self.dhcp_conflicts.len() < MAX_DHCP_BINDINGS {
                self.dhcp_conflicts
                    .insert(address, SimTime(now.0.saturating_add(600_000_000)));
            }
        }
    }

    /// Render current non-expired server bindings.
    pub fn show_ip_dhcp_binding(&mut self, now: SimTime) -> String {
        self.expire_dhcp_server_state(now);
        let mut output =
            String::from("IP address       Client-ID/Hardware address  Lease expiration\n");
        for binding in self.dhcp_bindings.values() {
            writeln!(
                output,
                "{:<16} {:<27} {}",
                binding.address,
                binding.client_mac,
                binding.expires_at.as_millis()
            )
            .unwrap();
        }
        output
    }

    fn expire_dhcp_server_state(&mut self, now: SimTime) {
        self.dhcp_conflicts.retain(|_, deadline| *deadline > now);
        self.dhcp_offers.retain(|_, offer| offer.expires_at > now);
        self.dhcp_bindings
            .retain(|_, binding| binding.expires_at > now);
    }
}
