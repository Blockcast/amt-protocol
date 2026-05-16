//! Subscription Manager — Sans-I/O bookkeeping above AmtGateway.

pub mod event;
pub mod inner_packet;

pub use event::Event;

pub mod group;
pub use group::GroupState;

pub mod report;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::AmtConfig;
use crate::error::{AmtError, Result};
use crate::gateway::{AmtGateway, GatewayState, GroupKey};
use crate::messages::AmtMessage;
use crate::platform::Platform;

/// Hard cap mirroring the IWA TS SharedAmtGateway limit.
pub const MAX_GROUPS_PER_TUNNEL: usize = 64;

/// Default timeouts (callers override via builder)
pub const DISCOVERY_TIMEOUT_MS: u64 = 5_000;
pub const REQUEST_TIMEOUT_MS:   u64 = 5_000;
pub const MAX_DISCOVERY_RETRIES: u32 = 3;

pub struct SubscriptionManager<P: Platform> {
    inner: AmtGateway<P>,
    cfg: AmtConfig,
    groups: HashMap<GroupKey, GroupState>,
    pending: VecDeque<GroupKey>,
    last_update_at_ms: Option<u64>,
    last_discovery_at_ms: Option<u64>,
    last_request_at_ms: Option<u64>,
    discovery_retries: u32,
    out_queue: VecDeque<Event>,
    shutting_down: bool,
    /// True after shutdown() has been called. AsyncAmtGateway runtime uses
    /// this — not the inner AmtGateway state — to detect end-of-life,
    /// because the inner state machine only reaches Closed on the Active-
    /// path teardown.
    closed: bool,
}

impl<P: Platform> SubscriptionManager<P> {
    pub fn new(cfg: AmtConfig, platform: Arc<P>) -> Self {
        let inner = AmtGateway::new(cfg.clone(), platform);
        Self {
            inner,
            cfg,
            groups: HashMap::new(),
            pending: VecDeque::new(),
            last_update_at_ms: None,
            last_discovery_at_ms: None,
            last_request_at_ms: None,
            discovery_retries: 0,
            out_queue: VecDeque::new(),
            shutting_down: false,
            closed: false,
        }
    }

    pub fn state(&self) -> GatewayState { self.inner.state() }
    pub fn relay_address(&self) -> Option<IpAddr> { self.inner.relay_address() }
    pub fn relay_port(&self) -> u16 { self.inner.relay_port() }
    pub fn groups(&self) -> &HashMap<GroupKey, GroupState> { &self.groups }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.out_queue.pop_front()
    }

    /// Subscribe to (group, source). Behavior depends on current state:
    /// - Idle: queues group, emits RelayDiscovery Transmit, transitions to Discovering.
    /// - Discovering / Requesting / Querying: queues group; will flush on HandshakeComplete.
    /// - Active: announces immediately via ALLOW_NEW_SOURCES Update (Task 1.10).
    pub fn subscribe(&mut self, key: GroupKey, now_ms: u64) -> Result<()> {
        if self.shutting_down || self.inner.state() == GatewayState::Closed {
            return Err(AmtError::ShutdownInProgress);
        }
        self.check_family(&key)?;
        // Dedup BEFORE cap — re-subscribing an existing (S,G) at cap must be
        // idempotent, not TunnelFull.
        let already_known =
            self.pending.iter().any(|k| k == &key) || self.groups.contains_key(&key);
        if !already_known {
            if self.groups.len() + self.pending.len() >= MAX_GROUPS_PER_TUNNEL {
                return Err(AmtError::TunnelFull);
            }
            self.pending.push_back(key);
        }
        match self.inner.state() {
            GatewayState::Idle => self.start_discovery(now_ms)?,
            GatewayState::Discovering
            | GatewayState::Requesting
            | GatewayState::Querying => { /* queued; handshake in flight */ }
            GatewayState::Active => {
                // Move newly-queued group(s) from pending into groups + emit ALLOW Update.
                while let Some(key) = self.pending.pop_front() {
                    let mut state = GroupState::new(key.clone(), now_ms);
                    state.announced = true;
                    self.groups.insert(key.clone(), state);
                    self.emit_incremental_allow(&key, now_ms)?;
                }
            }
            GatewayState::Closed => return Err(AmtError::ShutdownInProgress),
        }
        Ok(())
    }

    fn check_family(&self, key: &GroupKey) -> Result<()> {
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let relay_is_v4 = matches!(relay, IpAddr::V4(_));
        let group_is_v4 = matches!(key.group, IpAddr::V4(_));
        if relay_is_v4 != group_is_v4 {
            return Err(AmtError::FamilyMismatch);
        }
        if let Some(src) = key.source {
            let src_is_v4 = matches!(src, IpAddr::V4(_));
            if src_is_v4 != group_is_v4 {
                return Err(AmtError::FamilyMismatch);
            }
        }
        Ok(())
    }

    fn start_discovery(&mut self, now_ms: u64) -> Result<()> {
        let msg = self.inner.start_discovery()?;
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_discovery_at_ms = Some(now_ms);
        Ok(())
    }

    /// Feed a raw datagram (received on the AMT control socket) into the manager.
    /// Drives state transitions and produces output events.
    pub fn handle_datagram(&mut self, bytes: &[u8], now_ms: u64) -> Result<()> {
        let msg = match AmtMessage::decode(bytes) {
            Ok(m) => m,
            Err(e) => {
                self.out_queue.push_back(Event::Warning(e));
                return Ok(());
            }
        };
        match msg {
            AmtMessage::RelayAdvertisement { nonce, relay_address } => {
                self.handle_advertisement(nonce, relay_address, now_ms)?;
            }
            AmtMessage::MembershipQuery { request_nonce, response_mac, query_data } => {
                self.handle_query(request_nonce, response_mac, query_data, now_ms)?;
            }
            AmtMessage::MulticastData { ip_packet } => {
                if self.inner.state() != GatewayState::Active {
                    self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
                    return Ok(());
                }
                match crate::subscription::inner_packet::parse_inner(&ip_packet) {
                    Ok(p) => {
                        // Filter by subscribed (S,G). The relay can deliver
                        // data for any (S,G) on the tunnel, including ones
                        // we have NOT subscribed to (stale state from another
                        // gateway sharing the tunnel, ASM noise, or a
                        // misconfigured relay). Drop silently if not subscribed
                        // — the manager's groups map is the source of truth.
                        let asm_key = GroupKey { group: p.dst, source: None };
                        let ssm_key = GroupKey { group: p.dst, source: Some(p.src) };
                        if !self.groups.contains_key(&ssm_key)
                            && !self.groups.contains_key(&asm_key)
                        {
                            // Not a subscription we care about. No event.
                            return Ok(());
                        }
                        self.out_queue.push_back(Event::Data {
                            src: p.src,
                            group: p.dst,
                            src_port: p.src_port,
                            dst_port: p.dst_port,
                            payload: p.payload.to_vec(),
                        });
                    }
                    Err(_) => {
                        self.out_queue.push_back(Event::Warning(AmtError::MalformedInner));
                    }
                }
            }
            _ => {
                self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            }
        }
        Ok(())
    }

    fn handle_advertisement(
        &mut self,
        nonce: u32,
        relay_address: IpAddr,
        now_ms: u64,
    ) -> Result<()> {
        if self.inner.state() != GatewayState::Discovering {
            self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            return Ok(());
        }
        match self.inner.handle_advertisement(nonce, relay_address) {
            Ok(()) => {
                // Reset retry counter on successful Discovery — a later
                // re-Discovery should start its budget at 0, not at the
                // count left over from a previous successful handshake.
                self.discovery_retries = 0;
                self.last_discovery_at_ms = None;
                self.send_request(now_ms)
            }
            Err(e) => {
                self.out_queue.push_back(Event::Warning(e));
                Ok(())
            }
        }
    }

    fn send_request(&mut self, now_ms: u64) -> Result<()> {
        // RFC 7450 §5.1.3.1 — P-flag selects the inner-protocol family of
        // the Membership Query the relay returns:
        //   false → IGMPv3 (for IPv4 SSM subscriptions)
        //   true  → MLDv2  (for IPv6 SSM subscriptions)
        // The relay's address family is the source of truth; mismatching it
        // makes the relay emit a Query the gateway can't reconcile with its
        // configured group/source, surfacing as QueryFailed.
        let want_mld = matches!(self.inner.relay_address(), Some(IpAddr::V6(_)));
        let msg = self.inner.request_membership(want_mld)?;
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_request_at_ms = Some(now_ms);
        Ok(())
    }

    fn handle_query(
        &mut self,
        nonce: u32,
        mac: [u8; 6],
        query_data: Vec<u8>,
        now_ms: u64,
    ) -> Result<()> {
        if self.inner.state() != GatewayState::Requesting {
            self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            return Ok(());
        }
        if let Err(e) = self.inner.handle_query(nonce, mac, query_data) {
            self.out_queue.push_back(Event::Warning(e));
            return Ok(());
        }
        // Flush pending into groups map.
        while let Some(key) = self.pending.pop_front() {
            self.groups.insert(key.clone(), GroupState::new(key, now_ms));
        }
        // Event-emit ORDER is part of the public contract: Transmit(Update)
        // FIRST, HandshakeComplete SECOND. Consumers that want to know "tunnel
        // is up" via HandshakeComplete must drain in-order; they will have
        // already enqueued the Update for transmission by the time they see
        // the signal. Consumers that want "tunnel is up AND Update sent"
        // semantics get exactly that. Flipping this order would let a consumer
        // gate on HandshakeComplete and then drop the Update.
        self.send_current_state_update(now_ms)?;
        self.out_queue.push_back(Event::HandshakeComplete);
        Ok(())
    }

    fn send_current_state_update(&mut self, now_ms: u64) -> Result<()> {
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let port = self.inner.relay_port();
        let report = match relay {
            IpAddr::V4(_) => crate::subscription::report::build_current_state_v4(self.groups.keys())?,
            IpAddr::V6(_) => crate::subscription::report::build_current_state_v6(self.groups.keys())?,
        };
        let msg = self.inner.send_update(report)?;
        for g in self.groups.values_mut() {
            g.announced = true;
        }
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port,
            payload: msg.encode(),
        });
        self.last_update_at_ms = Some(now_ms);
        Ok(())
    }

    /// Unsubscribe from a (group, source). In Active state, emits an incremental
    /// BLOCK_OLD_SOURCES Update. In all other states, just removes from groups/pending.
    /// Unknown keys are a silent no-op.
    pub fn unsubscribe(&mut self, key: &GroupKey, now_ms: u64) -> Result<()> {
        if self.shutting_down {
            return Err(AmtError::ShutdownInProgress);
        }
        // Drop from pending first (covers pre-handshake removal).
        self.pending.retain(|k| k != key);
        let was_announced = self.groups.remove(key).map(|g| g.announced).unwrap_or(false);
        if !was_announced || self.inner.state() != GatewayState::Active {
            return Ok(());
        }
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let report = match relay {
            IpAddr::V4(_) => crate::subscription::report::build_block_v4(key)?,
            IpAddr::V6(_) => crate::subscription::report::build_block_v6(key)?,
        };
        let msg = self.inner.send_update(report)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_update_at_ms = Some(now_ms);
        Ok(())
    }

    fn emit_incremental_allow(&mut self, key: &GroupKey, now_ms: u64) -> Result<()> {
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let report = match relay {
            IpAddr::V4(_) => crate::subscription::report::build_allow_v4(key)?,
            IpAddr::V6(_) => crate::subscription::report::build_allow_v6(key)?,
        };
        let msg = self.inner.send_update(report)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_update_at_ms = Some(now_ms);
        Ok(())
    }

    /// Advance time-driven state: keep-alive Updates, Discovery/Request retries.
    pub fn tick(&mut self, now_ms: u64) -> Result<()> {
        if self.shutting_down {
            return Ok(());
        }
        // 1. Discovery retry / give-up.
        if self.inner.state() == GatewayState::Discovering {
            if let Some(t) = self.last_discovery_at_ms {
                if now_ms.saturating_sub(t) >= DISCOVERY_TIMEOUT_MS {
                    if self.discovery_retries < MAX_DISCOVERY_RETRIES {
                        // Re-send by resetting the inner gateway to Idle then starting again.
                        self.inner.reset();
                        self.discovery_retries += 1;
                        self.start_discovery(now_ms)?;
                        return Ok(());
                    } else {
                        self.inner.reset();
                        self.discovery_retries = 0;
                        self.last_discovery_at_ms = None;
                        self.out_queue.push_back(Event::Warning(AmtError::DiscoveryFailed));
                        return Ok(());
                    }
                }
            }
            return Ok(());
        }
        // 2. Request retry: if no Query within REQUEST_TIMEOUT_MS, give up to Idle.
        if self.inner.state() == GatewayState::Requesting {
            if let Some(t) = self.last_request_at_ms {
                if now_ms.saturating_sub(t) >= REQUEST_TIMEOUT_MS {
                    self.inner.reset();
                    self.last_request_at_ms = None;
                    self.out_queue.push_back(Event::Warning(AmtError::QueryFailed));
                }
            }
            return Ok(());
        }
        // 3. Active keep-alive.
        if self.inner.state() == GatewayState::Active && !self.groups.is_empty() {
            let interval_ms = (self.cfg.keepalive_interval_secs as u64) * 1000;
            if interval_ms == 0 { return Ok(()); }
            let due = match self.last_update_at_ms {
                Some(t) => now_ms.saturating_sub(t) >= interval_ms,
                None => false,
            };
            if due {
                self.send_current_state_update(now_ms)?;
            }
        }
        Ok(())
    }

    /// Earliest future wall-clock (ms) at which a `tick(now_ms)` call would emit work,
    /// or `None` if no timer is armed. Caller uses this to drive `sleep_until`.
    pub fn next_wakeup_ms(&self) -> Option<u64> {
        let mut candidates: Vec<u64> = Vec::with_capacity(3);
        if self.inner.state() == GatewayState::Discovering {
            if let Some(t) = self.last_discovery_at_ms {
                candidates.push(t + DISCOVERY_TIMEOUT_MS);
            }
        }
        if self.inner.state() == GatewayState::Requesting {
            if let Some(t) = self.last_request_at_ms {
                candidates.push(t + REQUEST_TIMEOUT_MS);
            }
        }
        if self.inner.state() == GatewayState::Active && !self.groups.is_empty() {
            let interval_ms = (self.cfg.keepalive_interval_secs as u64) * 1000;
            if interval_ms > 0 {
                if let Some(t) = self.last_update_at_ms {
                    candidates.push(t + interval_ms);
                }
            }
        }
        candidates.into_iter().min()
    }

    /// Initiate teardown. If currently Active, emits a Teardown Transmit and
    /// transitions to Closed. From any non-Active state, transitions straight
    /// to Closed without emitting wire traffic. Subsequent subscribe()/unsubscribe()
    /// calls return ShutdownInProgress. After shutdown(), `is_closed()` returns
    /// true so the AsyncAmtGateway runtime can break out of its select loop.
    pub fn shutdown(&mut self, _now_ms: u64) -> Result<()> {
        self.shutting_down = true;
        if self.inner.state() == GatewayState::Active {
            let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
            let msg = self.inner.send_teardown()?;
            self.out_queue.push_back(Event::Transmit {
                dst: relay,
                port: self.inner.relay_port(),
                payload: msg.encode(),
            });
            // inner.send_teardown() already advanced inner state to Closed.
        } else {
            // No wire traffic — but the manager must still expose "Closed"
            // semantics to its caller. inner.reset() returns to Idle (the
            // AmtGateway primitive has no public set-Closed). Track the
            // shutdown completion in the manager itself.
            self.inner.reset();
        }
        self.closed = true;
        Ok(())
    }

    /// True once `shutdown()` has been called.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    // Test helpers (only compiled into the test binary).
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize { self.pending.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::AmtMessage;
    use crate::platform::test_platform::TestPlatform;

    fn mgr() -> SubscriptionManager<TestPlatform> {
        let cfg = AmtConfig::new("192.0.2.96".parse::<IpAddr>().unwrap(), Some(2268));
        SubscriptionManager::new(cfg, Arc::new(TestPlatform::new()))
    }

    #[test]
    fn manager_starts_idle_empty() {
        let m = mgr();
        assert_eq!(m.state(), GatewayState::Idle);
        assert!(m.groups().is_empty());
        assert_eq!(m.relay_address(), Some("192.0.2.96".parse::<IpAddr>().unwrap()));
        assert_eq!(m.relay_port(), 2268);
    }

    #[test]
    fn poll_event_empty_initially() {
        let mut m = mgr();
        assert!(m.poll_event().is_none());
    }

    #[test]
    fn subscribe_in_idle_queues_and_starts_discovery() {
        let mut m = mgr();
        let group: IpAddr = "232.0.0.1".parse().unwrap();
        let source: IpAddr = "10.0.0.1".parse().unwrap();
        m.subscribe(GroupKey { group, source: Some(source) }, 1000).unwrap();

        assert_eq!(m.state(), GatewayState::Discovering);
        assert_eq!(m.groups().len(), 0, "group not announced yet");
        // pending queue has the group:
        assert_eq!(m.pending_len(), 1);

        // First event must be a Transmit of RelayDiscovery to the relay.
        let ev = m.poll_event().expect("expected one Transmit event");
        match ev {
            Event::Transmit { dst, port, payload } => {
                assert_eq!(dst, "192.0.2.96".parse::<IpAddr>().unwrap());
                assert_eq!(port, 2268);
                assert_eq!(payload[0], 0x01, "expected RelayDiscovery message type");
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn subscribe_family_mismatch_rejected() {
        let mut m = mgr();
        let v6_group: IpAddr = "ff0e::1".parse().unwrap();
        let v4_source: IpAddr = "10.0.0.1".parse().unwrap();
        let err = m.subscribe(
            GroupKey { group: v6_group, source: Some(v4_source) },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::FamilyMismatch);
    }

    #[test]
    fn subscribe_relay_family_mismatch_rejected() {
        let mut m = mgr(); // v4 relay
        let v6_group: IpAddr = "ff3e::1234".parse().unwrap();
        let v6_source: IpAddr = "2001:db8::1".parse().unwrap();
        let err = m.subscribe(
            GroupKey { group: v6_group, source: Some(v6_source) },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::FamilyMismatch);
    }

    #[test]
    fn subscribe_when_full_returns_tunnelfull() {
        let mut m = mgr();
        for i in 0..MAX_GROUPS_PER_TUNNEL {
            let group: IpAddr = format!("232.0.0.{}", i + 1).parse().unwrap();
            m.subscribe(
                GroupKey { group, source: Some("10.0.0.1".parse().unwrap()) },
                1000,
            ).unwrap();
        }
        let group: IpAddr = "232.0.1.1".parse().unwrap();
        let err = m.subscribe(
            GroupKey { group, source: Some("10.0.0.1".parse().unwrap()) },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::TunnelFull);
    }

    #[test]
    fn subscribe_idempotent_at_cap() {
        // Fill to cap, then re-subscribe the FIRST one. Must succeed (idempotent),
        // not return TunnelFull.
        let mut m = mgr();
        let first_key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(first_key.clone(), 1000).unwrap();
        for i in 1..MAX_GROUPS_PER_TUNNEL {
            let group: IpAddr = format!("232.0.0.{}", i + 1).parse().unwrap();
            m.subscribe(
                GroupKey { group, source: Some("10.0.0.1".parse().unwrap()) },
                1000,
            ).unwrap();
        }
        // At cap. Re-sub of an existing key must be Ok and a no-op.
        m.subscribe(first_key, 2000).expect("idempotent re-sub at cap must succeed");
    }

    #[test]
    fn subscribe_after_shutdown_rejected() {
        let mut m = mgr();
        m.shutdown(1000).unwrap();
        let err = m.subscribe(
            GroupKey {
                group: "232.0.0.1".parse().unwrap(),
                source: Some("10.0.0.1".parse().unwrap()),
            },
            1100,
        ).unwrap_err();
        assert_eq!(err, AmtError::ShutdownInProgress);
    }

    fn drain(m: &mut SubscriptionManager<TestPlatform>) -> Vec<Event> {
        let mut v = Vec::new();
        while let Some(ev) = m.poll_event() { v.push(ev); }
        v
    }

    fn discovery_nonce_from(events: &[Event]) -> u32 {
        for ev in events {
            if let Event::Transmit { payload, .. } = ev {
                if payload[0] == 0x01 {
                    return u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                }
            }
        }
        panic!("no RelayDiscovery transmit in events: {:?}", events);
    }

    #[test]
    fn advertisement_advances_to_requesting() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(key, 1000).unwrap();
        let initial = drain(&mut m);
        let nonce = discovery_nonce_from(&initial);

        let advert = AmtMessage::RelayAdvertisement {
            nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();

        assert_eq!(m.state(), GatewayState::Requesting);
        let events = drain(&mut m);
        let req = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x03 => Some(payload.clone()),
            _ => None,
        }).expect("expected a Request transmit");
        // Relay address is IPv4 (192.0.2.96) → P-flag MUST be 0 per RFC 7450
        // §5.1.3.1 so the relay returns an IGMPv3 General Query, not MLDv2.
        assert_eq!(req[1] & 0x80, 0x00, "P-flag MUST be 0 for IPv4 relay");
    }

    #[test]
    fn advertisement_with_wrong_nonce_warns_no_transition() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(key, 1000).unwrap();
        drain(&mut m);

        let advert = AmtMessage::RelayAdvertisement {
            nonce: 0xDEAD_BEEF,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        assert_eq!(m.state(), GatewayState::Discovering, "state must not advance on bad nonce");
        let events = drain(&mut m);
        assert!(events.iter().any(|ev| matches!(ev, Event::Warning(_))));
    }

    #[test]
    fn query_with_wrong_nonce_warns_no_transition() {
        // The spec's "mac_drift_on_data_warns" was misnamed:
        // AmtMessage::MulticastData carries no nonce / response_mac on the wire
        // (per messages.rs:167-174 — just type/reserved/ip_packet). The validation
        // we DO want is on MembershipQuery: a Query whose request_nonce does not
        // match our outstanding nonce must Warning + leave state in Requesting.
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(key, 1000).unwrap();
        let initial = drain(&mut m);
        let disc_nonce = discovery_nonce_from(&initial);
        let advert = AmtMessage::RelayAdvertisement {
            nonce: disc_nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        let _ = drain(&mut m);

        // Inject a Query with the WRONG nonce.
        let bad_query = AmtMessage::MembershipQuery {
            request_nonce: 0xDEAD_BEEF,
            response_mac: [0xAA; 6],
            query_data: vec![0; 12],
        };
        m.handle_datagram(&bad_query.encode(), 1200).unwrap();

        assert_eq!(m.state(), GatewayState::Requesting, "state must not advance");
        let events = drain(&mut m);
        assert!(events.iter().any(|ev| matches!(ev, Event::Warning(_))));
        assert!(!events.iter().any(|ev| matches!(ev, Event::HandshakeComplete)));
    }

    #[test]
    fn query_flushes_pending_into_one_update_v4() {
        let mut m = mgr();
        let k1 = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        let k2 = GroupKey {
            group: "232.0.0.2".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k1.clone(), 1000).unwrap();
        m.subscribe(k2.clone(), 1010).unwrap();
        let initial = drain(&mut m);
        let disc_nonce = discovery_nonce_from(&initial);

        let advert = AmtMessage::RelayAdvertisement {
            nonce: disc_nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        let after_advert = drain(&mut m);
        let req_nonce = after_advert.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x03 => {
                Some(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]))
            }
            _ => None,
        }).expect("expected Request transmit");

        // Synthesize a MembershipQuery and feed it in.
        let query = AmtMessage::MembershipQuery {
            request_nonce: req_nonce,
            response_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            query_data: vec![0x11; 12],
        };
        m.handle_datagram(&query.encode(), 1200).unwrap();

        assert_eq!(m.state(), GatewayState::Active);
        assert_eq!(m.groups().len(), 2, "pending must flush to groups");
        assert_eq!(m.pending_len(), 0);

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected MembershipUpdate transmit");
        // Update layout: 12B AMT header + 24B IPv4(RA) envelope + IGMPv3 body.
        // Skip AMT + IPv4 to land on the IGMPv3 report.
        let report = &update[12 + 24..];
        assert_eq!(report[0], 0x22, "IGMPv3 report type");
        assert_eq!(u16::from_be_bytes([report[6], report[7]]), 2);

        assert!(events.iter().any(|ev| matches!(ev, Event::HandshakeComplete)));
    }

    fn drive_to_active(m: &mut SubscriptionManager<TestPlatform>, key: GroupKey) {
        m.subscribe(key, 1000).unwrap();
        let initial = drain(m);
        let disc_nonce = discovery_nonce_from(&initial);
        let advert = AmtMessage::RelayAdvertisement {
            nonce: disc_nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        let after_advert = drain(m);
        let req_nonce = after_advert.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x03 => {
                Some(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]))
            }
            _ => None,
        }).unwrap();
        let query = AmtMessage::MembershipQuery {
            request_nonce: req_nonce,
            response_mac: [0; 6],
            query_data: vec![0x11; 12],
        };
        m.handle_datagram(&query.encode(), 1200).unwrap();
        drain(m);
    }

    fn synth_v4_udp_packet(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + 8 + payload.len()) as u16;
        let mut buf = vec![0x45, 0x00];
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 17, 0, 0]);
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&sp.to_be_bytes());
        buf.extend_from_slice(&dp.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf.extend_from_slice(&udp_len.to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn multicast_data_emits_data_event_with_demux() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, key);

        let inner = synth_v4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"abcd");
        let data_msg = AmtMessage::MulticastData { ip_packet: inner };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();

        let events = drain(&mut m);
        let data = events.iter().find_map(|ev| match ev {
            Event::Data { src, group, src_port, dst_port, payload } =>
                Some((*src, *group, *src_port, *dst_port, payload.clone())),
            _ => None,
        }).expect("expected Event::Data");
        assert_eq!(data.0, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(data.1, "232.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(data.2, 5004);
        assert_eq!(data.3, 5005);
        assert_eq!(data.4, b"abcd");
    }

    #[test]
    fn malformed_inner_warns_not_panics() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, key);

        let data_msg = AmtMessage::MulticastData { ip_packet: vec![0x45, 0x00] };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();
        assert_eq!(m.state(), GatewayState::Active);
        let events = drain(&mut m);
        assert!(events.iter().any(|ev| matches!(ev, Event::Warning(AmtError::MalformedInner))));
        assert!(!events.iter().any(|ev| matches!(ev, Event::Data { .. })));
    }

    #[test]
    fn unsubscribed_multicast_data_dropped_silently() {
        let mut m = mgr();
        let subscribed = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, subscribed);

        // Inner packet for an UNSUBSCRIBED (S,G).
        let inner = synth_v4_udp_packet([10, 0, 0, 2], [232, 0, 0, 99], 5004, 5005, b"junk");
        let data_msg = AmtMessage::MulticastData { ip_packet: inner };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();

        let events = drain(&mut m);
        assert!(
            !events.iter().any(|ev| matches!(ev, Event::Data { .. })),
            "expected no Data event for unsubscribed (S,G); got: {:?}",
            events
        );
        // Also no Warning — silent drop is the intent.
        assert!(events.is_empty(), "expected zero events; got: {:?}", events);
    }

    #[test]
    fn wrong_source_for_subscribed_group_dropped() {
        let mut m = mgr();
        let subscribed = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, subscribed);

        // Right group, WRONG source.
        let inner = synth_v4_udp_packet([10, 0, 0, 99], [232, 0, 0, 1], 5004, 5005, b"x");
        let data_msg = AmtMessage::MulticastData { ip_packet: inner };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();
        let events = drain(&mut m);
        assert!(!events.iter().any(|ev| matches!(ev, Event::Data { .. })));
    }

    #[test]
    fn subscribe_in_active_emits_incremental_allow_update() {
        let mut m = mgr();
        let k1 = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k1);

        let k2 = GroupKey {
            group: "232.0.0.2".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k2.clone(), 1400).unwrap();
        assert_eq!(m.state(), GatewayState::Active);
        assert_eq!(m.groups().len(), 2);
        assert_eq!(m.pending_len(), 0);

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected MembershipUpdate transmit");
        // Skip AMT (12B) + IPv4(RA) (24B) to reach the IGMPv3 body.
        let report = &update[12 + 24..];
        assert_eq!(report[0], 0x22, "IGMPv3 report type");
        assert_eq!(u16::from_be_bytes([report[6], report[7]]), 1, "single ALLOW record");
        assert_eq!(report[8], 5, "record type = ALLOW_NEW_SOURCES");
    }

    #[test]
    fn unsubscribe_in_active_emits_block_update() {
        let mut m = mgr();
        let k1 = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k1.clone());

        m.unsubscribe(&k1, 1400).unwrap();
        assert_eq!(m.groups().len(), 0);

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected MembershipUpdate transmit");
        // Skip AMT (12B) + IPv4(RA) (24B) to reach the IGMPv3 body.
        let report = &update[12 + 24..];
        assert_eq!(report[8], 6, "record type = BLOCK_OLD_SOURCES");
    }

    #[test]
    fn unsubscribe_unknown_key_is_noop() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.99".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        // Not subscribed first; manager in Idle.
        m.unsubscribe(&k, 1000).unwrap();
        let events = drain(&mut m);
        assert!(events.is_empty(), "no events on unsubscribe of unknown key");
    }

    #[test]
    fn tick_emits_keepalive_update_after_interval() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        let _ = drain(&mut m);

        // Default keep-alive is 60s. Advance just past it.
        let ka_ms = (AmtConfig::DEFAULT_KEEPALIVE_SECS as u64) * 1000;
        m.tick(1200 + ka_ms + 1).unwrap();

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected keep-alive Update");
        // Skip AMT (12B) + IPv4(RA) (24B) to reach the IGMPv3 body.
        let report = &update[12 + 24..];
        assert_eq!(report[0], 0x22);
        assert_eq!(u16::from_be_bytes([report[6], report[7]]), 1);
    }

    #[test]
    fn next_wakeup_ms_returns_keepalive_deadline_in_active() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        // After drive_to_active, last_update_at_ms is 1200 (the synthesized
        // Query timestamp). next_wakeup_ms = last_update_at + 60s.
        let ka_ms = (AmtConfig::DEFAULT_KEEPALIVE_SECS as u64) * 1000;
        assert_eq!(m.next_wakeup_ms(), Some(1200 + ka_ms));
    }

    #[test]
    fn next_wakeup_ms_idle_returns_none() {
        let m = mgr();
        assert_eq!(m.next_wakeup_ms(), None);
    }

    #[test]
    fn next_wakeup_ms_discovering_returns_timeout_deadline() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k, 1000).unwrap();
        let _ = drain(&mut m);
        assert_eq!(m.next_wakeup_ms(), Some(1000 + DISCOVERY_TIMEOUT_MS));
    }

    #[test]
    fn tick_no_keepalive_before_interval() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        let _ = drain(&mut m);
        m.tick(1200 + 1_000).unwrap();
        assert!(drain(&mut m).is_empty(), "no events before interval");
    }

    #[test]
    fn tick_retries_discovery_then_gives_up() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k, 1000).unwrap();
        let _ = drain(&mut m); // consume initial Discovery

        // 3 retries (default MAX_DISCOVERY_RETRIES).
        let mut t = 1000 + DISCOVERY_TIMEOUT_MS + 1;
        for _ in 0..MAX_DISCOVERY_RETRIES {
            m.tick(t).unwrap();
            let events = drain(&mut m);
            assert!(events.iter().any(|ev| matches!(ev,
                Event::Transmit { payload, .. } if payload[0] == 0x01)));
            t += DISCOVERY_TIMEOUT_MS + 1;
        }

        // One more tick: should give up.
        m.tick(t).unwrap();
        let events = drain(&mut m);
        assert!(events.iter().any(|ev|
            matches!(ev, Event::Warning(AmtError::DiscoveryFailed))));
        assert_eq!(m.state(), GatewayState::Idle, "manager parks in Idle on give-up");
    }

    #[test]
    fn shutdown_emits_teardown_from_active() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        let _ = drain(&mut m);

        m.shutdown(1500).unwrap();
        assert_eq!(m.state(), GatewayState::Closed);
        let events = drain(&mut m);
        let teardown = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x07 => Some(payload.clone()),
            _ => None,
        }).expect("expected Teardown transmit");
        assert_eq!(teardown.len(), 12, "Teardown is 12 bytes");
    }

    #[test]
    fn shutdown_in_idle_is_noop() {
        let mut m = mgr();
        m.shutdown(1500).unwrap();
        assert!(drain(&mut m).is_empty());
    }

    #[test]
    fn subscribe_after_shutdown_rejected_real() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k.clone());
        drain(&mut m);
        m.shutdown(1500).unwrap();
        let err = m.subscribe(k, 1600).unwrap_err();
        assert_eq!(err, AmtError::ShutdownInProgress);
    }
}
