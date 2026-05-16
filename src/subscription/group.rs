//! Per-(S,G) subscription state, used by SubscriptionManager.

use crate::gateway::GroupKey;

#[derive(Debug, Clone)]
pub struct GroupState {
    pub key: GroupKey,
    /// Unix ms when the caller asked us to subscribe.
    pub requested_at_ms: u64,
    /// True once this group has been sent to the relay in an Update.
    pub announced: bool,
}

impl GroupState {
    pub fn new(key: GroupKey, requested_at_ms: u64) -> Self {
        Self { key, requested_at_ms, announced: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn new_group_state_unannounced() {
        let key = GroupKey {
            group: "232.0.0.1".parse::<IpAddr>().unwrap(),
            source: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
        };
        let st = GroupState::new(key.clone(), 1234);
        assert_eq!(st.requested_at_ms, 1234);
        assert!(!st.announced);
        assert_eq!(st.key, key);
    }
}
