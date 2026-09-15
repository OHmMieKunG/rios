use crate::*;
use rios_config::{DhcpPoolConfig, DhcpPoolId};
use rios_ipv4::{Ipv4InterfaceConfig, Ipv4Network};
use rios_simulator::SimTime;
use std::{collections::BTreeSet, fmt::Write, net::Ipv4Addr};

const DHCP_LEASE_MS: u64 = 3_600_000;
const DHCP_OFFER_MS: u64 = 60_000;

/// Runtime IPv4 lease installed on a DHCP client interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpLease {
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
        let id = DhcpPoolId(
            self.running_config
                .dhcp_pools
                .last_key_value()
                .map_or(1, |(id, _)| id.0.saturating_add(1)),
        );
        self.running_config.dhcp_pools.insert(
            id,
            DhcpPoolConfig {
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
        self.running_config
            .dhcp_pools
            .get_mut(&id)
            .ok_or(DeviceError::MissingDhcpPool)?
            .network = Some(network);
        Ok(())
    }

    /// Set the default-router option for a DHCP pool.
    pub fn set_dhcp_default_router(
        &mut self,
        id: DhcpPoolId,
        address: Ipv4Addr,
    ) -> Result<(), DeviceError> {
        self.running_config
            .dhcp_pools
            .get_mut(&id)
            .ok_or(DeviceError::MissingDhcpPool)?
            .default_router = Some(address);
        Ok(())
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
        let server_id = self.interface_ipv4(interface)?.address();
        self.expire_dhcp_server_state(now);
        if let Some(offer) = self.dhcp_offers.get(&client_mac).copied() {
            return Some(offer);
        }
        if let Some(binding) = self.dhcp_bindings.get(&client_mac) {
            let (pool, config) = self
                .running_config
                .dhcp_pools
                .iter()
                .find(|(_, pool)| pool.name == binding.pool_name)?;
            let network = config.network?;
            return Some(DhcpOffer {
                address: binding.address,
                prefix_len: network.prefix_len(),
                default_router: config.default_router,
                server_id,
                lease_time_seconds: (DHCP_LEASE_MS / 1000) as u32,
                pool: *pool,
                expires_at: binding.expires_at,
            });
        }
        let (pool_id, pool) = self.running_config.dhcp_pools.iter().find(|(_, pool)| {
            pool.network
                .is_some_and(|network| network.contains(server_id))
        })?;
        let pool_id = *pool_id;
        let pool = pool.clone();
        let network = pool.network?;
        let used: BTreeSet<_> = self
            .dhcp_bindings
            .values()
            .map(|binding| binding.address)
            .chain(self.dhcp_offers.values().map(|offer| offer.address))
            .chain(
                self.running_config
                    .interfaces
                    .keys()
                    .filter_map(|id| self.interface_ipv4(*id).map(|ip| ip.address())),
            )
            .collect();
        let first = u32::from(network.address()).saturating_add(1);
        let last = u32::from(network.broadcast()).saturating_sub(1);
        let address = (first..=last)
            .map(Ipv4Addr::from)
            .find(|address| !used.contains(address) && pool.default_router != Some(*address))?;
        let offer = DhcpOffer {
            address,
            prefix_len: network.prefix_len(),
            default_router: pool.default_router,
            server_id,
            lease_time_seconds: (DHCP_LEASE_MS / 1000) as u32,
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
        let mut offer = self.dhcp_offers.remove(&client_mac)?;
        if offer.address != address || offer.server_id != server_id {
            return None;
        }
        offer.expires_at = SimTime(now.0.saturating_add(DHCP_LEASE_MS * 1000));
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
        self.dhcp_offers.retain(|_, offer| offer.expires_at > now);
        self.dhcp_bindings
            .retain(|_, binding| binding.expires_at > now);
    }
}
