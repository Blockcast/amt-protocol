//! Subscription Manager — Sans-I/O bookkeeping above AmtGateway.

pub mod event;
pub mod inner_packet;

pub use event::Event;

pub mod group;
pub use group::GroupState;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::AmtConfig;
use crate::error::{AmtError, Result};
use crate::gateway::{AmtGateway, GatewayState, GroupKey};
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
            GatewayState::Active => { /* incremental Allow lands in Task 1.10 */ }
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

    // Test helpers (only compiled into the test binary).
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize { self.pending.len() }
    #[cfg(test)]
    pub(crate) fn shutting_down_for_test(&mut self) { self.shutting_down = true; }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        m.shutting_down_for_test();
        let err = m.subscribe(
            GroupKey {
                group: "232.0.0.1".parse().unwrap(),
                source: Some("10.0.0.1".parse().unwrap()),
            },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::ShutdownInProgress);
    }
}
