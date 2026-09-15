//! BGP input validation. Configuration edits are reconciled by the next simulator event.
use super::*;
impl Device {
    /// Configure a shared route-reflector cluster identifier; default is the local router ID.
    pub fn set_bgp_cluster_id(&mut self, id: Option<Ipv4Addr>) -> Result<(), DeviceError> {
        if id.is_some_and(|id| id.is_unspecified() || id.is_multicast() || id.is_broadcast()) {
            return Err(DeviceError::InvalidBgpConfig);
        }
        self.running_config
            .bgp
            .as_mut()
            .ok_or(DeviceError::InvalidBgpConfig)?
            .cluster_id = id;
        Ok(())
    }

    /// Enable, replace or remove the single IPv4 BGP process.
    pub fn set_bgp_process(&mut self, asn: Option<u32>) -> Result<(), DeviceError> {
        if !self.supports_routing() || asn.is_some_and(|n| n == 0 || n == u32::MAX) {
            return Err(DeviceError::InvalidBgpConfig);
        }
        match asn {
            None => self.running_config.bgp = None,
            Some(asn) => {
                if self
                    .running_config
                    .bgp
                    .as_ref()
                    .is_none_or(|c| c.local_as != asn)
                {
                    self.running_config.bgp = Some(BgpConfig::new(asn));
                }
            }
        }
        Ok(())
    }
    /// Configure a unicast router identifier or restore automatic selection.
    pub fn set_bgp_router_id(&mut self, id: Option<Ipv4Addr>) -> Result<(), DeviceError> {
        if id.is_some_and(|id| id.is_unspecified() || id.is_multicast() || id.is_broadcast()) {
            return Err(DeviceError::InvalidBgpConfig);
        }
        self.running_config
            .bgp
            .as_mut()
            .ok_or(DeviceError::InvalidBgpConfig)?
            .router_id = id;
        if id.is_none() {
            self.bgp.router_id = None;
        }
        Ok(())
    }
    /// Validate and insert or remove a peer without directly changing remote state.
    pub fn set_bgp_neighbor(
        &mut self,
        address: Ipv4Addr,
        peer: Option<BgpNeighborConfig>,
    ) -> Result<(), DeviceError> {
        if address.is_unspecified()
            || address.is_multicast()
            || address.is_broadcast()
            || peer.as_ref().is_some_and(|p| {
                p.remote_as == 0
                    || p.remote_as == u32::MAX
                    || p.update_source
                        .is_some_and(|id| !self.interfaces.contains_key(&id))
            })
        {
            return Err(DeviceError::InvalidBgpConfig);
        }
        let config = self
            .running_config
            .bgp
            .as_mut()
            .ok_or(DeviceError::InvalidBgpConfig)?;
        if let Some(peer) = peer {
            let names = [
                &peer.inbound.prefix_list,
                &peer.inbound.route_map,
                &peer.outbound.prefix_list,
                &peer.outbound.route_map,
            ];
            if names
                .into_iter()
                .flatten()
                .any(|name| !crate::route_policy::policy_name_valid(name))
                || peer
                    .default_originate
                    .as_ref()
                    .and_then(|d| d.route_map.as_ref())
                    .is_some_and(|name| !crate::route_policy::policy_name_valid(name))
                || peer.route_reflector_client && peer.remote_as != config.local_as
            {
                return Err(DeviceError::InvalidBgpConfig);
            }
            if config.neighbors.len() >= PEER_LIMIT && !config.neighbors.contains_key(&address) {
                return Err(DeviceError::InvalidBgpConfig);
            }
            config.neighbors.insert(address, peer);
        } else {
            config.neighbors.remove(&address);
        }
        Ok(())
    }
    /// Originate only when an exact non-BGP route exists; removal causes withdrawal.
    pub fn set_bgp_network(
        &mut self,
        prefix: Ipv4Network,
        present: bool,
    ) -> Result<(), DeviceError> {
        if prefix.address().is_multicast() || prefix.address().is_broadcast() {
            return Err(DeviceError::InvalidBgpConfig);
        }
        let config = self
            .running_config
            .bgp
            .as_mut()
            .ok_or(DeviceError::InvalidBgpConfig)?;
        if present {
            if config.networks.len() >= ROUTE_LIMIT && !config.networks.contains(&prefix) {
                return Err(DeviceError::InvalidBgpConfig);
            }
            config.networks.insert(prefix);
        } else {
            config.networks.remove(&prefix);
        }
        Ok(())
    }
}
