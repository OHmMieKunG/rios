//! Deterministic BGP connection FSM. The owner supplies TCP lifecycle and transports emitted bytes.
use super::*;
use rios_simulator::SimTime;
const RETRY_US: u64 = 30_000_000;
const OPEN_WAIT_US: u64 = 240_000_000;
/// Base BGP session states, distinct from TCP's connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}
/// Effects for the transport owner; no route structures are exchanged with another router.
#[derive(Debug, Default)]
pub struct BgpSessionActions {
    pub messages: Vec<BgpMessage>,
    pub update: Option<BgpUpdate>,
    pub connect_transport: bool,
    pub close_transport: bool,
}
/// One BGP session, including negotiated capabilities and exact virtual deadlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpSession {
    pub state: BgpState,
    pub peer_router_id: Option<Ipv4Addr>,
    pub four_octet_as: bool,
    pub negotiated_hold_time: u16,
    pub established_since: Option<SimTime>,
    pub last_error: Option<BgpError>,
    local_as: u32,
    remote_as: u32,
    router_id: Ipv4Addr,
    configured_hold_time: u16,
    retry_at: SimTime,
    hold_at: Option<SimTime>,
    keepalive_at: Option<SimTime>,
}
impl BgpSession {
    pub fn new(
        local_as: u32,
        remote_as: u32,
        router_id: Ipv4Addr,
        hold_time: u16,
        now: SimTime,
    ) -> Result<Self, BgpError> {
        if local_as == 0 || remote_as == 0 {
            return Err(BgpError::new(2, 2));
        }
        let session = Self {
            state: BgpState::Idle,
            peer_router_id: None,
            four_octet_as: false,
            negotiated_hold_time: 0,
            established_since: None,
            last_error: None,
            local_as,
            remote_as,
            router_id,
            configured_hold_time: hold_time,
            retry_at: now,
            hold_at: None,
            keepalive_at: None,
        };
        session.open().validate()?;
        Ok(session)
    }
    fn open(&self) -> BgpOpen {
        BgpOpen {
            autonomous_system: u16::try_from(self.local_as).unwrap_or(23456),
            hold_time: self.configured_hold_time,
            router_id: self.router_id,
            capabilities: vec![BgpCapability::FourOctetAs(self.local_as)],
        }
    }
    /// Called only after the simulated TCP handshake completes, including passive accepts.
    pub fn transport_connected(&mut self, now: SimTime) -> BgpSessionActions {
        self.state = BgpState::OpenSent;
        self.peer_router_id = None;
        self.four_octet_as = false;
        self.negotiated_hold_time = 0;
        self.established_since = None;
        self.hold_at = Some(SimTime(now.0.saturating_add(OPEN_WAIT_US)));
        self.keepalive_at = None;
        BgpSessionActions {
            messages: vec![BgpMessage::Open(self.open())],
            ..Default::default()
        }
    }
    /// Failed TCP connect or established transport loss enters Active with a bounded retry cadence.
    pub fn transport_failed(&mut self, now: SimTime) -> BgpSessionActions {
        self.reset(now);
        self.state = BgpState::Active;
        BgpSessionActions {
            close_transport: true,
            ..Default::default()
        }
    }
    fn reset(&mut self, now: SimTime) {
        self.state = BgpState::Idle;
        self.established_since = None;
        self.hold_at = None;
        self.keepalive_at = None;
        self.retry_at = SimTime(now.0.saturating_add(RETRY_US));
    }
    /// Report a codec or policy protocol error through a real NOTIFICATION before closing TCP.
    pub fn protocol_error(&mut self, error: BgpError, now: SimTime) -> BgpSessionActions {
        self.last_error = Some(error);
        self.reset(now);
        BgpSessionActions {
            messages: vec![BgpMessage::Notification {
                code: error.code,
                subcode: error.subcode,
                data: Vec::new(),
            }],
            close_transport: true,
            ..Default::default()
        }
    }
    fn reset_hold(&mut self, now: SimTime) {
        self.hold_at = (self.negotiated_hold_time != 0).then_some(SimTime(
            now.0
                .saturating_add(u64::from(self.negotiated_hold_time) * 1_000_000),
        ));
    }
    fn next_keepalive(&mut self, now: SimTime) {
        self.keepalive_at = (self.negotiated_hold_time != 0)
            .then_some(SimTime(now.0.saturating_add(
                u64::from(self.negotiated_hold_time / 3) * 1_000_000,
            )));
    }
    /// Consume one completely framed message. Only Established sessions can deliver UPDATEs.
    pub fn receive(&mut self, message: BgpMessage, now: SimTime) -> BgpSessionActions {
        if let BgpMessage::Notification { code, subcode, .. } = message {
            self.last_error = Some(BgpError { code, subcode });
            self.reset(now);
            return BgpSessionActions {
                close_transport: true,
                ..Default::default()
            };
        }
        match (self.state, message) {
            (BgpState::OpenSent, BgpMessage::Open(open)) => {
                if let Err(error) = open.validate() {
                    return self.protocol_error(error, now);
                }
                if open.effective_asn() != self.remote_as {
                    return self.protocol_error(BgpError::new(2, 2), now);
                }
                if self.local_as == self.remote_as && open.router_id == self.router_id {
                    return self.protocol_error(BgpError::new(2, 3), now);
                }
                if !open.four_octet_as() && self.local_as > u32::from(u16::MAX) {
                    return self.protocol_error(BgpError::new(2, 2), now);
                }
                self.peer_router_id = Some(open.router_id);
                self.four_octet_as = open.four_octet_as();
                self.negotiated_hold_time = self.configured_hold_time.min(open.hold_time);
                self.reset_hold(now);
                self.next_keepalive(now);
                self.state = BgpState::OpenConfirm;
                BgpSessionActions {
                    messages: vec![BgpMessage::Keepalive],
                    ..Default::default()
                }
            }
            (BgpState::OpenConfirm | BgpState::Established, BgpMessage::Keepalive) => {
                if self.state != BgpState::Established {
                    self.established_since = Some(now);
                }
                self.state = BgpState::Established;
                self.reset_hold(now);
                BgpSessionActions::default()
            }
            (BgpState::Established, BgpMessage::Update(update)) => {
                self.reset_hold(now);
                BgpSessionActions {
                    update: Some(update),
                    ..Default::default()
                }
            }
            _ => self.protocol_error(BgpError::new(5, 0), now),
        }
    }
    /// Earliest retry, hold or keepalive deadline; the simulation owns scheduling.
    pub fn next_deadline(&self) -> Option<SimTime> {
        let retry = matches!(
            self.state,
            BgpState::Idle | BgpState::Active | BgpState::Connect
        )
        .then_some(self.retry_at);
        retry
            .into_iter()
            .chain(self.hold_at)
            .chain(self.keepalive_at)
            .min()
    }
    pub fn tick(&mut self, now: SimTime) -> BgpSessionActions {
        if matches!(
            self.state,
            BgpState::Idle | BgpState::Active | BgpState::Connect
        ) && self.retry_at <= now
        {
            self.state = BgpState::Connect;
            self.retry_at = SimTime(now.0.saturating_add(RETRY_US));
            return BgpSessionActions {
                connect_transport: true,
                ..Default::default()
            };
        }
        if self.hold_at.is_some_and(|deadline| deadline <= now) {
            return self.protocol_error(BgpError::new(4, 0), now);
        }
        if self.keepalive_at.is_some_and(|deadline| deadline <= now) {
            self.next_keepalive(now);
            return BgpSessionActions {
                messages: vec![BgpMessage::Keepalive],
                ..Default::default()
            };
        }
        BgpSessionActions::default()
    }
}
