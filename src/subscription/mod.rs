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
}
