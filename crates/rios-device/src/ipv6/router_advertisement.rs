//! Router solicitation/advertisement exchange and RFC 4862 SLAAC lifetimes.
use super::*;
impl Device {
    pub(super) fn ipv6_router_timers(&mut self, now: SimTime) -> Vec<Ipv6ControlPacket> {
        let forwarding = self.ipv6_forwarding_enabled();
        let ids: Vec<_> = self.ipv6.interfaces.keys().copied().collect();
        let mut out = Vec::new();
        for id in ids {
            let Some(source) = self.ipv6_link_local(id) else {
                continue;
            };
            if self.interfaces[&id].kind == InterfaceKind::Loopback {
                continue;
            }
            let config = &self.running_config.interfaces[&id];
            let runtime = self.ipv6.interfaces.get_mut(&id).unwrap();
            let message = if forwarding && !config.ipv6.ra_suppress && runtime.ra_due <= now {
                runtime.ra_last = Some(now);
                runtime.ra_due = after(now, 200);
                let mut options = vec![
                    NdOption::SourceLinkLayer(self.interfaces[&id].mac_address),
                    NdOption::Mtu(u32::from(config.mtu)),
                ];
                let prefixes: BTreeSet<_> = runtime
                    .addresses
                    .values()
                    .filter(|a| {
                        a.origin == Ipv6AddressOrigin::Manual
                            && matches!(
                                a.state,
                                Ipv6AddressState::Preferred | Ipv6AddressState::Deprecated
                            )
                    })
                    .map(|a| a.address.network())
                    .collect();
                options.extend(prefixes.into_iter().map(|prefix| {
                    NdOption::Prefix(PrefixInformation {
                        prefix,
                        on_link: true,
                        autonomous: prefix.prefix_len() == 64,
                        valid_lifetime: 86400,
                        preferred_lifetime: 14400,
                    })
                }));
                Some((
                    ALL_NODES,
                    NdMessage::RouterAdvertisement {
                        hop_limit: 64,
                        managed: false,
                        other: false,
                        router_lifetime: 1800,
                        reachable_time: 0,
                        retrans_timer: 0,
                        options,
                    },
                ))
            } else if !forwarding
                && runtime.rs_count < 3
                && runtime.rs_due.is_some_and(|due| due <= now)
            {
                runtime.rs_count += 1;
                runtime.rs_due = Some(after(now, 4));
                Some((
                    ALL_ROUTERS,
                    NdMessage::RouterSolicitation {
                        options: vec![NdOption::SourceLinkLayer(self.interfaces[&id].mac_address)],
                    },
                ))
            } else {
                None
            };
            if let Some((destination, message)) = message
                && let Some(packet) = self.ipv6_control(id, source, destination, None, message)
            {
                out.push(packet);
            }
        }
        out
    }
    pub(super) fn ipv6_receive_ra(
        &mut self,
        id: InterfaceId,
        source: Ipv6Addr,
        message: NdMessage,
        now: SimTime,
    ) {
        if self.ipv6_forwarding_enabled() {
            return;
        }
        let NdMessage::RouterAdvertisement {
            router_lifetime,
            options,
            ..
        } = message
        else {
            return;
        };
        let key = (id, source);
        if router_lifetime == 0 {
            self.ipv6.routers.remove(&key);
        } else if self.ipv6.routers.len() < 256 || self.ipv6.routers.contains_key(&key) {
            self.ipv6
                .routers
                .insert(key, after(now, u32::from(router_lifetime)));
        }
        for option in options {
            match option {
                NdOption::SourceLinkLayer(mac) => {
                    self.ipv6_learn_neighbor(id, source, mac, true, now)
                }
                NdOption::Prefix(info) => {
                    if info.prefix.address().is_unicast_link_local()
                        || info.prefix.address().is_multicast()
                        || info.preferred_lifetime > info.valid_lifetime
                    {
                        continue;
                    }
                    if info.on_link {
                        let key = (id, info.prefix);
                        if info.valid_lifetime == 0 {
                            self.ipv6.prefixes.remove(&key);
                        } else if self.ipv6.prefixes.len() < 4096
                            || self.ipv6.prefixes.contains_key(&key)
                        {
                            self.ipv6.prefixes.insert(
                                key,
                                lifetime(now, info.valid_lifetime).unwrap_or(SimTime(u64::MAX)),
                            );
                        }
                    }
                    if !self.running_config.interfaces[&id].ipv6.autoconfig
                        || !info.autonomous
                        || info.prefix.prefix_len() != 64
                    {
                        continue;
                    }
                    let address = Ipv6Addr::from(
                        u128::from(info.prefix.address())
                            | u128::from(interface_identifier(self.interfaces[&id].mac_address)),
                    );
                    let Some(runtime) = self.ipv6.interfaces.get_mut(&id) else {
                        continue;
                    };
                    if let Some(existing) = runtime.addresses.get_mut(&address) {
                        if existing.origin != Ipv6AddressOrigin::Slaac {
                            continue;
                        }
                        let remaining = existing
                            .valid_until
                            .map_or(u64::MAX, |until| until.0.saturating_sub(now.0) / 1_000_000);
                        if info.valid_lifetime > 7200 || u64::from(info.valid_lifetime) > remaining
                        {
                            existing.valid_until = lifetime(now, info.valid_lifetime);
                        } else if remaining > 7200 {
                            existing.valid_until = Some(after(now, 7200));
                        }
                        existing.preferred_until = lifetime(now, info.preferred_lifetime);
                        if matches!(
                            existing.state,
                            Ipv6AddressState::Preferred | Ipv6AddressState::Deprecated
                        ) {
                            existing.state = if info.preferred_lifetime == 0 {
                                Ipv6AddressState::Deprecated
                            } else {
                                Ipv6AddressState::Preferred
                            };
                        }
                    } else if info.valid_lifetime > 0
                        && runtime.addresses.len() < ADDRESS_LIMIT
                        && let Ok(address) = Ipv6InterfaceConfig::new(address, 64)
                    {
                        runtime.addresses.insert(
                            address.address(),
                            Ipv6AddressEntry {
                                address,
                                state: Ipv6AddressState::Tentative,
                                origin: Ipv6AddressOrigin::Slaac,
                                preferred_until: lifetime(now, info.preferred_lifetime),
                                valid_until: lifetime(now, info.valid_lifetime),
                                dad_due: Some(now),
                                dad_sent: false,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
        if let Some(runtime) = self.ipv6.interfaces.get_mut(&id) {
            runtime.rs_due = None;
            runtime.rs_count = 3;
        }
    }
}
