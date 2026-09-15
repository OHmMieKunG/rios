//! Bounded OSPF database exchange and reliable LSA transmission for one adjacency.
mod advertisement;
use crate::{LSA_MAX_AGE, Lsa, LsaHeader, OspfBody, OspfNeighborState};
pub use advertisement::ExchangeAdvertisement;
use rios_simulator::SimTime;
use std::{cmp::Ordering, collections::BTreeMap, net::Ipv4Addr};

const RETRANSMIT_US: u64 = 5_000_000;
/// Maximum advertisements retained by an adjacency or database.
pub const OSPF_DATABASE_LIMIT: usize = 4096;

/// Compare instances using RFC 2328 sequence, checksum, MaxAge and MaxAgeDiff.
pub fn compare_lsa(a: &LsaHeader, b: &LsaHeader) -> Ordering {
    compare_lsa_instances(
        (a.sequence, a.checksum, a.age),
        (b.sequence, b.checksum, b.age),
    )
}

pub(crate) fn compare_lsa_instances(a: (i32, u16, u16), b: (i32, u16, u16)) -> Ordering {
    a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then_with(|| {
        if a.2 == LSA_MAX_AGE || b.2 == LSA_MAX_AGE {
            (a.2 == LSA_MAX_AGE).cmp(&(b.2 == LSA_MAX_AGE))
        } else if a.2.abs_diff(b.2) > 900 {
            b.2.cmp(&a.2)
        } else {
            Ordering::Equal
        }
    })
}

/// Packet responses and validated advertisements offered to the owning LSDB.
#[derive(Debug)]
pub struct OspfExchangeResult<L: ExchangeAdvertisement = Lsa> {
    pub packets: Vec<OspfBody<L>>,
    pub advertisements: Vec<L>,
}
impl<L: ExchangeAdvertisement> Default for OspfExchangeResult<L> {
    fn default() -> Self {
        Self {
            packets: Vec::new(),
            advertisements: Vec::new(),
        }
    }
}

/// One master/slave database exchange; the device owns Hellos, elections and the LSDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfExchange<L: ExchangeAdvertisement = Lsa> {
    pub state: OspfNeighborState,
    master: bool,
    mtu: u16,
    sequence: u32,
    summary: Vec<L::Header>,
    offset: usize,
    last_dd: Option<OspfBody<L>>,
    dd_due: SimTime,
    requests: BTreeMap<L::Key, L::Header>,
    request_due: SimTime,
    retransmit: BTreeMap<L::Key, (L, SimTime)>,
}
impl<L: ExchangeAdvertisement> OspfExchange<L> {
    /// Begin ExStart with a deterministic sequence supplied by the owning device.
    pub fn new(local: Ipv4Addr, peer: Ipv4Addr, mtu: u16, sequence: u32) -> Self {
        Self {
            state: OspfNeighborState::ExStart,
            master: local > peer,
            mtu,
            sequence,
            summary: Vec::new(),
            offset: 0,
            last_dd: None,
            dd_due: SimTime(0),
            requests: BTreeMap::new(),
            request_due: SimTime(0),
            retransmit: BTreeMap::new(),
        }
    }
    /// Number of outstanding explicit requests and unacknowledged updates.
    pub fn pending(&self) -> (usize, usize) {
        (self.requests.len(), self.retransmit.len())
    }
    /// Snapshot database headers and send the initial empty I/M/MS packet.
    pub fn start(&mut self, database: &BTreeMap<L::Key, L>, now: SimTime) -> OspfBody<L> {
        self.state = OspfNeighborState::ExStart;
        self.summary = database
            .values()
            .filter_map(|lsa| lsa.header().ok())
            .take(OSPF_DATABASE_LIMIT)
            .collect();
        self.offset = 0;
        self.requests.clear();
        self.retransmit.clear();
        self.send_dd(7, Vec::new(), now)
    }
    fn send_dd(&mut self, flags: u8, headers: Vec<L::Header>, now: SimTime) -> OspfBody<L> {
        let body = OspfBody::DatabaseDescription {
            mtu: self.mtu,
            options: L::OPTIONS,
            flags,
            sequence: self.sequence,
            headers,
        };
        self.last_dd = Some(body.clone());
        self.dd_due = SimTime(now.0.saturating_add(RETRANSMIT_US));
        body
    }
    fn next_dd(&mut self, now: SimTime) -> OspfBody<L> {
        let count = usize::from(self.mtu.saturating_sub(L::DD_OVERHEAD)) / 20;
        let end = self
            .offset
            .saturating_add(count.max(1))
            .min(self.summary.len());
        let headers = self.summary[self.offset..end].to_vec();
        self.offset = end;
        let flags = u8::from(self.master) | if end < self.summary.len() { 2 } else { 0 };
        self.send_dd(flags, headers, now)
    }
    fn request_headers(&mut self, headers: Vec<L::Header>, database: &BTreeMap<L::Key, L>) {
        for header in headers {
            if database
                .get(&L::header_key(&header))
                .and_then(|lsa| lsa.header().ok())
                .is_none_or(|old| L::compare(&header, &old) == Ordering::Greater)
                && (self.requests.len() < OSPF_DATABASE_LIMIT
                    || self.requests.contains_key(&L::header_key(&header)))
            {
                self.requests
                    .entry(L::header_key(&header))
                    .and_modify(|old| {
                        if L::compare(&header, old) == Ordering::Greater {
                            *old = header;
                        }
                    })
                    .or_insert(header);
            }
        }
    }
    fn finish(&mut self, now: SimTime, packets: &mut Vec<OspfBody<L>>) {
        self.state = if self.requests.is_empty() {
            OspfNeighborState::Full
        } else {
            OspfNeighborState::Loading
        };
        if !self.requests.is_empty() {
            packets.extend(self.request_packets());
            self.request_due = SimTime(now.0.saturating_add(RETRANSMIT_US));
        }
    }
    fn request_packets(&self) -> Vec<OspfBody<L>> {
        let keys: Vec<_> = self.requests.keys().copied().collect();
        let size = (usize::from(self.mtu.saturating_sub(L::PACKET_OVERHEAD)) / 12).max(1);
        keys.chunks(size)
            .map(|keys| OspfBody::LinkStateRequest(keys.to_vec()))
            .collect()
    }
    /// Queue a reliable update. Oversized advertisements cannot be sent without fragmentation.
    pub fn flood(&mut self, lsa: L, now: SimTime) -> Option<OspfBody<L>> {
        if !matches!(
            self.state,
            OspfNeighborState::Exchange | OspfNeighborState::Loading | OspfNeighborState::Full
        ) || lsa.encoded_len().ok()? + usize::from(L::PACKET_OVERHEAD) + 4
            > usize::from(self.mtu)
            || (self.retransmit.len() >= OSPF_DATABASE_LIMIT
                && !self.retransmit.contains_key(&lsa.key()))
        {
            return None;
        }
        self.retransmit.insert(
            lsa.key(),
            (lsa.clone(), SimTime(now.0.saturating_add(RETRANSMIT_US))),
        );
        Some(OspfBody::LinkStateUpdate(vec![lsa]))
    }
    /// Consume an authenticated neighbor's body. The caller must first validate area and source.
    pub fn receive(
        &mut self,
        body: OspfBody<L>,
        database: &BTreeMap<L::Key, L>,
        now: SimTime,
    ) -> OspfExchangeResult<L> {
        let mut out = OspfExchangeResult::default();
        match body {
            OspfBody::DatabaseDescription {
                mtu,
                options,
                flags,
                sequence,
                headers,
            } => {
                if mtu > self.mtu || flags & !7 != 0 || options & L::OPTIONS != L::OPTIONS {
                    return out;
                }
                if self.state == OspfNeighborState::ExStart {
                    if !self.master && flags == 7 && headers.is_empty() {
                        self.sequence = sequence;
                        self.state = OspfNeighborState::Exchange;
                        out.packets.push(self.next_dd(now));
                    } else if self.master && flags & 5 == 0 && sequence == self.sequence {
                        self.state = OspfNeighborState::Exchange;
                        self.request_headers(headers, database);
                        self.sequence = self.sequence.wrapping_add(1);
                        out.packets.push(self.next_dd(now));
                    }
                    return out;
                }
                if !matches!(
                    self.state,
                    OspfNeighborState::Exchange
                        | OspfNeighborState::Loading
                        | OspfNeighborState::Full
                ) {
                    return out;
                }
                if !self.master && sequence == self.sequence {
                    if let Some(last) = &self.last_dd {
                        out.packets.push(last.clone());
                    }
                    return out;
                }
                if self.master
                    && matches!(
                        self.state,
                        OspfNeighborState::Loading | OspfNeighborState::Full
                    )
                    && sequence == self.sequence
                    && flags & 5 == 0
                {
                    return out;
                }
                // The master discards a duplicate slave acknowledgment; its timer resends if needed.
                if self.master && sequence == self.sequence.wrapping_sub(1) {
                    return out;
                }
                let expected = if self.master {
                    self.sequence
                } else {
                    self.sequence.wrapping_add(1)
                };
                if flags & 4 != 0
                    || (flags & 1 != 0) == self.master
                    || sequence != expected
                    || self.state != OspfNeighborState::Exchange
                {
                    self.sequence = self.sequence.wrapping_add(1);
                    out.packets.push(self.start(database, now));
                    return out;
                }
                self.request_headers(headers, database);
                if self.master {
                    let sent_more = matches!(&self.last_dd,Some(OspfBody::DatabaseDescription{flags,..}) if flags&2!=0);
                    if !sent_more && flags & 2 == 0 {
                        self.finish(now, &mut out.packets);
                    } else {
                        self.sequence = self.sequence.wrapping_add(1);
                        out.packets.push(self.next_dd(now));
                    }
                } else {
                    self.sequence = sequence;
                    out.packets.push(self.next_dd(now));
                    if self.offset == self.summary.len() && flags & 2 == 0 {
                        self.finish(now, &mut out.packets);
                    }
                }
            }
            OspfBody::LinkStateRequest(keys) if self.can_exchange() => {
                for key in keys {
                    let Some(lsa) = database.get(&key) else {
                        self.sequence = self.sequence.wrapping_add(1);
                        out.packets.clear();
                        out.packets.push(self.start(database, now));
                        return out;
                    };
                    if let Some(packet) = self.flood(lsa.clone(), now) {
                        out.packets.push(packet);
                    }
                }
            }
            OspfBody::LinkStateUpdate(lsas) if self.can_exchange() => {
                let mut ack = Vec::new();
                for lsa in lsas {
                    let Ok(header) = lsa.header() else {
                        continue;
                    };
                    if let Some(request) = self.requests.get(&L::header_key(&header)) {
                        if L::compare(&header, request) == Ordering::Less {
                            continue;
                        }
                        self.requests.remove(&L::header_key(&header));
                    }
                    let old = database
                        .get(&L::header_key(&header))
                        .and_then(|lsa| lsa.header().ok());
                    if old.is_none_or(|old| L::compare(&header, &old) != Ordering::Less) {
                        ack.push(header);
                        out.advertisements.push(lsa);
                    } else if let Some(lsa) = database.get(&L::header_key(&header))
                        && let Some(packet) = self.flood(lsa.clone(), now)
                    {
                        out.packets.push(packet);
                    }
                }
                let size = (usize::from(self.mtu.saturating_sub(L::PACKET_OVERHEAD)) / 20).max(1);
                out.packets.extend(
                    ack.chunks(size)
                        .map(|headers| OspfBody::LinkStateAck(headers.to_vec())),
                );
                if self.state == OspfNeighborState::Loading && self.requests.is_empty() {
                    self.state = OspfNeighborState::Full;
                }
            }
            OspfBody::LinkStateAck(headers) if self.can_exchange() => {
                for header in headers {
                    if self
                        .retransmit
                        .get(&L::header_key(&header))
                        .and_then(|(lsa, _)| lsa.header().ok())
                        .is_some_and(|sent| L::compare(&header, &sent) == Ordering::Equal)
                    {
                        self.retransmit.remove(&L::header_key(&header));
                    }
                }
            }
            _ => {}
        }
        out
    }
    fn can_exchange(&self) -> bool {
        matches!(
            self.state,
            OspfNeighborState::Exchange | OspfNeighborState::Loading | OspfNeighborState::Full
        )
    }
    /// Earliest active retransmission deadline for the owning simulator event queue.
    pub fn next_deadline(&self) -> Option<SimTime> {
        let dd = (self.state == OspfNeighborState::ExStart
            || (self.state == OspfNeighborState::Exchange && self.master))
            .then_some(self.dd_due);
        let request = (self.state == OspfNeighborState::Loading).then_some(self.request_due);
        dd.into_iter()
            .chain(request)
            .chain(self.retransmit.values().map(|(_, due)| *due))
            .min()
    }
    /// Generate only due retransmissions; no wall clock or background thread is used.
    pub fn tick(&mut self, now: SimTime) -> Vec<OspfBody<L>> {
        let mut out = Vec::new();
        if (self.state == OspfNeighborState::ExStart
            || (self.state == OspfNeighborState::Exchange && self.master))
            && self.dd_due <= now
            && let Some(last) = &self.last_dd
        {
            out.push(last.clone());
            self.dd_due = SimTime(now.0.saturating_add(RETRANSMIT_US));
        }
        if self.state == OspfNeighborState::Loading && self.request_due <= now {
            out.extend(self.request_packets());
            self.request_due = SimTime(now.0.saturating_add(RETRANSMIT_US));
        }
        for (lsa, due) in self.retransmit.values_mut() {
            if *due <= now {
                out.push(OspfBody::LinkStateUpdate(vec![lsa.clone()]));
                *due = SimTime(now.0.saturating_add(RETRANSMIT_US));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests;
