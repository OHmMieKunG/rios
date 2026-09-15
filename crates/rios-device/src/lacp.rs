//! LACP receive, partner selection, and collecting/distributing state.
use crate::*;
use rios_config::ChannelMode;
use rios_simulator::SimTime;
use rios_switching::*;

/// Latest partner advertisement on one physical member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LacpNeighbor {
    pub pdu: Lacpdu,
    pub expires_at: SimTime,
}
impl Device {
    fn lacp_actor(&self, id: InterfaceId) -> Option<LacpPortInfo> {
        let config = self.running_config.interfaces.get(&id)?;
        let group = config.channel_group?;
        if group.mode == ChannelMode::On || !self.protocol_up(id) {
            return None;
        }
        let system = self
            .interfaces
            .values()
            .filter(|port| port.kind.is_ethernet())
            .map(|port| port.mac_address.0)
            .min()?;
        Some(LacpPortInfo {
            system_priority: 32768,
            system,
            key: group.number,
            port_priority: 32768,
            port: u16::try_from(id.0).ok()?,
            state: LACP_TIMEOUT
                | LACP_AGGREGATION
                | if group.mode == ChannelMode::Active {
                    LACP_ACTIVITY
                } else {
                    0
                },
        })
    }
    fn selected_partner(&self, number: u16) -> Option<(u16, [u8; 6], u16)> {
        self.lacp_neighbors
            .iter()
            .filter(|(id, _)| {
                self.protocol_up(**id)
                    && self
                        .running_config
                        .interfaces
                        .get(id)
                        .is_some_and(|config| {
                            config
                                .channel_group
                                .is_some_and(|group| group.number == number)
                        })
            })
            .map(|(_, neighbor)| {
                (
                    neighbor.pdu.actor.system_priority,
                    neighbor.pdu.actor.system,
                    neighbor.pdu.actor.key,
                )
            })
            .min()
    }
    /// Build an advertisement from received partner state, never another device's configuration.
    pub fn lacp_advertisement(&self, id: InterfaceId) -> Option<Lacpdu> {
        let mut actor = self.lacp_actor(id)?;
        let neighbor = self.lacp_neighbors.get(&id);
        if actor.state & LACP_ACTIVITY == 0
            && neighbor.is_none_or(|peer| peer.pdu.actor.state & LACP_ACTIVITY == 0)
        {
            return None;
        }
        let partner = neighbor.map_or(LacpPortInfo::default(), |peer| peer.pdu.actor);
        let selected = self.selected_partner(actor.key)
            == Some((partner.system_priority, partner.system, partner.key));
        if let Some(peer) = neighbor {
            if selected && peer.pdu.partner.matches(&actor) && partner.state & LACP_AGGREGATION != 0
            {
                actor.state |= LACP_SYNC;
                if partner.state & LACP_SYNC != 0 {
                    actor.state |= LACP_COLLECTING;
                    if partner.state & LACP_COLLECTING != 0 {
                        actor.state |= LACP_DISTRIBUTING;
                    }
                }
            }
        } else {
            actor.state |= LACP_DEFAULTED;
        }
        Some(Lacpdu {
            actor,
            partner,
            collector_delay: 0,
        })
    }
    /// Learn one physical peer; return an immediate advertisement only when state changes.
    pub fn receive_lacp(&mut self, id: InterfaceId, pdu: Lacpdu, now: SimTime) -> Option<Lacpdu> {
        let actor = self.lacp_actor(id)?;
        if pdu.actor.system == actor.system
            || pdu.actor.system == [0; 6]
            || pdu.actor.system[0] & 1 != 0
            || pdu.actor.port == 0
            || pdu.actor.state & LACP_AGGREGATION == 0
        {
            return None;
        }
        let before = self.lacp_advertisement(id);
        self.lacp_neighbors.insert(
            id,
            LacpNeighbor {
                pdu,
                expires_at: SimTime(now.0.saturating_add(3_000_000)),
            },
        );
        self.refresh_svi_states();
        let after = self.lacp_advertisement(id);
        if before != after { after } else { None }
    }
    /// Expire silent peers and generate fast-periodic advertisements in interface order.
    pub fn lacp_tick(&mut self, now: SimTime) -> Vec<(InterfaceId, Lacpdu)> {
        self.lacp_neighbors.retain(|_, peer| peer.expires_at > now);
        self.refresh_svi_states();
        self.running_config
            .interfaces
            .keys()
            .filter_map(|id| self.lacp_advertisement(*id).map(|pdu| (*id, pdu)))
            .collect()
    }
    pub(crate) fn lacp_distributing(&self, id: InterfaceId) -> bool {
        self.lacp_advertisement(id)
            .is_some_and(|pdu| pdu.actor.state & LACP_DISTRIBUTING != 0)
    }
    /// Current observed peers, keyed by physical interface.
    pub fn lacp_neighbors(&self) -> &BTreeMap<InterfaceId, LacpNeighbor> {
        &self.lacp_neighbors
    }
    /// Whether any member needs an LACP timer.
    pub fn has_lacp(&self) -> bool {
        self.running_config.interfaces.values().any(|config| {
            config
                .channel_group
                .is_some_and(|group| group.mode != ChannelMode::On)
        })
    }
    /// Render received LACP identities and collector/distributor flags.
    pub fn show_lacp_neighbor(&self) -> String {
        use std::fmt::Write;
        let mut output =
            String::from("Port                 Partner             Key   Port  State\n");
        for (id, peer) in &self.lacp_neighbors {
            let actor = peer.pdu.actor;
            let _ = writeln!(
                output,
                "{:<20} {} {:<5} {:<5} 0x{:02x}",
                self.running_config.interfaces[id].name,
                MacAddress(actor.system),
                actor.key,
                actor.port,
                actor.state
            );
        }
        output
    }
}
