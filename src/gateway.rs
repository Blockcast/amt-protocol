//! AMT Gateway State Machine (RFC 7450 Section 5.2)
//!
//! Implements the AMT gateway control plane state machine for establishing
//! and maintaining multicast group memberships through AMT tunnels.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use crate::error::{AmtError, Result};
use crate::messages::AmtMessage;
use crate::config::AmtConfig;
use crate::platform::{Platform, generate_nonce};

/// AMT Gateway States (RFC 7450 Section 5.2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayState {
    /// Initial state - no active discovery or membership
    Idle,

    /// Sent Relay Discovery, waiting for Advertisement
    Discovering,

    /// Sent Request, waiting for Membership Query
    Requesting,

    /// Received Query, processing or sent Update
    Querying,

    /// Active membership, receiving multicast data
    Active,

    /// Teardown sent or received
    Closed,
}

/// Multicast group identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupKey {
    /// Multicast group address (IPv4 or IPv6)
    pub group: IpAddr,

    /// Source address for SSM (None for ASM)
    pub source: Option<IpAddr>,
}

/// Multicast group membership information
#[derive(Debug, Clone)]
pub struct GroupInfo {
    /// Group identifier
    pub key: GroupKey,

    /// When this membership was requested
    pub requested_at: u64, // Unix timestamp

    /// Whether this is a SSM (source-specific) or ASM (any-source) join
    pub is_ssm: bool,
}

/// AMT Gateway Instance
///
/// Manages the AMT protocol state machine for multicast group memberships.
/// Generic over Platform to support WASM, FFI, and other targets.
pub struct AmtGateway<P: Platform> {
    /// Platform abstraction for random/logging/time
    platform: Arc<P>,

    /// Current state
    state: GatewayState,

    /// Configuration
    config: AmtConfig,

    /// Current relay address (may be discovered via DRIAD)
    relay_address: Option<IpAddr>,

    /// Current relay port
    relay_port: u16,

    /// Discovery nonce (used in Discovery/Advertisement exchange)
    discovery_nonce: Option<u32>,

    /// Nonce of the Request currently in flight, awaiting its Membership Query.
    ///
    /// RFC 7450 §5.2.3.5.6 requires a **fresh** nonce each time the gateway
    /// starts the membership query process, so this is minted per cycle — both
    /// at bootstrap and on each keepalive re-Request. It is matched against the
    /// nonce in the incoming Query and then *promoted* into `request_nonce` by
    /// `handle_query`. Keeping it separate is what lets a keepalive mint a new
    /// nonce without invalidating a Membership Update built during the round
    /// trip: `send_update` reads the confirmed pair below, never this slot.
    pending_request_nonce: Option<u32>,

    /// Last nonce **confirmed** by a Membership Query.
    ///
    /// RFC 7450 §4.2.1.2 step 5 and §5.2.3.5.4: a Membership Update and a
    /// Teardown carry the nonce/MAC of the *last Query received*, not of the
    /// newest Request. This is that value, and it stays valid until a new
    /// Query supersedes it.
    request_nonce: Option<u32>,

    /// Response MAC from the last Membership Query.
    /// Paired with `request_nonce` in subsequent Update, Data, and Teardown
    /// messages (RFC 7450 §5.2.3.5.4).
    response_mac: Option<[u8; 6]>,

    /// Active multicast group memberships
    groups: HashMap<GroupKey, GroupInfo>,

    /// P flag value (prefer native multicast)
    p_flag: bool,
}

impl<P: Platform> AmtGateway<P> {
    /// Create new AMT Gateway with configuration and platform
    pub fn new(config: AmtConfig, platform: Arc<P>) -> Self {
        Self {
            platform,
            state: GatewayState::Idle,
            relay_port: config.relay_port,
            relay_address: Some(config.relay_address),
            config,
            discovery_nonce: None,
            pending_request_nonce: None,
            request_nonce: None,
            response_mac: None,
            groups: HashMap::new(),
            p_flag: false,
        }
    }

    /// Get current state
    pub fn state(&self) -> GatewayState {
        self.state
    }

    /// Get current relay address
    pub fn relay_address(&self) -> Option<IpAddr> {
        self.relay_address
    }

    /// Get current relay port
    pub fn relay_port(&self) -> u16 {
        self.relay_port
    }

    /// Get active group memberships
    pub fn groups(&self) -> &HashMap<GroupKey, GroupInfo> {
        &self.groups
    }

    /// Get configuration
    pub fn config(&self) -> &AmtConfig {
        &self.config
    }

    /// Set relay address (from DRIAD discovery)
    pub fn set_relay(&mut self, address: IpAddr, port: u16) {
        self.relay_address = Some(address);
        self.relay_port = port;
    }

    /// Start relay discovery process
    ///
    /// Returns RelayDiscovery message to send to anycast discovery address
    pub fn start_discovery(&mut self) -> Result<AmtMessage> {
        if self.state != GatewayState::Idle {
            return Err(AmtError::InvalidState);
        }

        // Generate discovery nonce
        let nonce = generate_nonce(self.platform.as_ref());
        self.discovery_nonce = Some(nonce);
        self.state = GatewayState::Discovering;

        // Debug logging
        self.platform.log_info(&format!("[AMT] Generated discovery nonce: 0x{:08x}", nonce));

        Ok(AmtMessage::RelayDiscovery { nonce })
    }

    /// Process Relay Advertisement response
    ///
    /// Validates nonce and extracts relay address
    pub fn handle_advertisement(&mut self, nonce: u32, relay_address: IpAddr) -> Result<()> {
        if self.state != GatewayState::Discovering {
            return Err(AmtError::InvalidState);
        }

        // Debug logging
        self.platform.log_info(&format!("[AMT] Received advertisement nonce: 0x{:08x}", nonce));
        self.platform.log_info(&format!("[AMT] Expected discovery nonce: 0x{:08x}", self.discovery_nonce.unwrap_or(0)));

        // Validate nonce matches our discovery nonce
        if Some(nonce) != self.discovery_nonce {
            self.platform.log_error("[AMT] ❌ NONCE MISMATCH!");
            return Err(AmtError::InvalidNonce);
        }

        self.platform.log_info("[AMT] ✅ Nonce validated");

        // Store relay address from advertisement
        self.relay_address = Some(relay_address);
        self.state = GatewayState::Idle;
        self.discovery_nonce = None;

        Ok(())
    }

    /// Request membership (send AMT Request)
    ///
    /// Valid in two states, which differ in more than the guard:
    ///
    /// * `Idle` — bootstrap. Moves to `Requesting` to await the relay's
    ///   Membership Query.
    /// * `Active` — keepalive re-Request. RFC 7450 §4.2.1.2 describes the
    ///   keepalive timer firing as triggering *"the start of a new
    ///   Request->Membership Query message exchange"*, and §4.2.1.2 notes the
    ///   cycle *"may continue indefinitely once started."* This is the other
    ///   half of `handle_query` accepting `Active`: a Query can only arrive
    ///   while Active if a Request could be sent from Active in the first
    ///   place.
    ///
    /// Both paths mint a **fresh** nonce, per RFC 7450 §5.2.3.5.6: *"A new
    /// nonce MUST be generated each time the gateway starts the membership
    /// query process. The same nonce SHOULD be used when retransmitting a
    /// Request message."* A keepalive re-Request starts a new query process,
    /// not a retransmission, so it takes a new nonce. (Retransmission of an
    /// in-flight Request is not reachable through this method — the guard
    /// refuses `Requesting` — so the SHOULD does not apply here.)
    ///
    /// Minting a fresh nonce is safe for an Update built during the round trip
    /// because the new nonce lands in `pending_request_nonce`, leaving the
    /// `request_nonce`/`response_mac` pair confirmed by the *last* Query intact
    /// for `send_update` and `send_teardown` — which is what §4.2.1.2 step 5
    /// and §5.2.3.5.4 require them to carry. `handle_query` promotes the
    /// pending nonce only once the relay answers it.
    ///
    /// The state also stays `Active`, so multicast data arriving during the
    /// query round trip is still accepted by `handle_data`. Dropping back to
    /// `Requesting` would blackhole data once per keepalive interval. Note the
    /// window is not fully closed: `handle_query` moves `Active -> Querying`,
    /// and `handle_data` refuses `Querying` until `send_update` runs. The
    /// `subscription` driver closes that gap synchronously, but an FFI/WASM
    /// embedder driving `AmtGateway` directly does have a real gap there.
    ///
    /// `p_flag` may not change while `Active`: RFC 7450 §5.2.3.5.4 requires the
    /// Query's encapsulated protocol to match the P flag of the Request it
    /// answers, so flipping between IGMPv3 and MLDv2 mid-tunnel is refused
    /// rather than put on the wire.
    pub fn request_membership(&mut self, p_flag: bool) -> Result<AmtMessage> {
        if self.state != GatewayState::Idle && self.state != GatewayState::Active {
            return Err(AmtError::InvalidState);
        }

        if self.relay_address.is_none() {
            return Err(AmtError::InvalidState);
        }

        if self.state == GatewayState::Active && p_flag != self.p_flag {
            return Err(AmtError::InvalidState);
        }

        // RFC 7450 §5.2.3.5.6: a new nonce for each membership query process.
        // It goes to the pending slot so the confirmed pair used by
        // send_update/send_teardown survives the round trip.
        let nonce = generate_nonce(self.platform.as_ref());
        self.pending_request_nonce = Some(nonce);
        if self.state == GatewayState::Idle {
            self.state = GatewayState::Requesting;
        }
        self.p_flag = p_flag;

        Ok(AmtMessage::Request {
            request_nonce: nonce,
            p_flag,
        })
    }

    /// Process an initial or active-tunnel Membership Query.
    ///
    /// Validates the nonce and promotes it, with its response MAC, into the
    /// confirmed pair that `send_update` and `send_teardown` carry (RFC 7450
    /// §4.2.1.2 step 5, §5.2.3.5.4).
    ///
    /// A Query is accepted when its nonce matches either:
    ///
    /// * the Request currently in flight (`pending_request_nonce`) — the normal
    ///   bootstrap and keepalive case; or
    /// * the already-confirmed `request_nonce`, when no Request is in flight —
    ///   a relay re-Querying an established tunnel unsolicited.
    ///
    /// A Query bearing a superseded nonce (an answer to an earlier keepalive
    /// that a later one has already replaced) is rejected as `InvalidNonce`.
    pub fn handle_query(
        &mut self,
        request_nonce: u32,
        response_mac: [u8; 6],
        query_data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if self.state != GatewayState::Requesting && self.state != GatewayState::Active {
            self.platform.log_error("[AMT handle_query] Error: InvalidState");
            return Err(AmtError::InvalidState);
        }

        // Debug logging
        self.platform.log_debug(&format!("[AMT handle_query] Pending request_nonce: {:?}", self.pending_request_nonce));
        self.platform.log_debug(&format!("[AMT handle_query] Confirmed request_nonce: {:?}", self.request_nonce));
        self.platform.log_debug(&format!("[AMT handle_query] Received request_nonce: 0x{:08x}", request_nonce));

        // Validate nonce against the in-flight Request, or against the
        // confirmed tunnel nonce when nothing is in flight.
        let answers_pending = self.pending_request_nonce == Some(request_nonce);
        let refreshes_active =
            self.pending_request_nonce.is_none() && self.request_nonce == Some(request_nonce);
        if !answers_pending && !refreshes_active {
            self.platform.log_error("[AMT handle_query] ❌ NONCE MISMATCH!");
            return Err(AmtError::InvalidNonce);
        }
        self.platform.log_info("[AMT handle_query] ✅ Nonce validated");

        // Promote: this nonce/MAC pair now backs Updates and Teardowns.
        self.request_nonce = Some(request_nonce);
        self.response_mac = Some(response_mac);
        self.pending_request_nonce = None;
        self.state = GatewayState::Querying;

        // Return query data (IGMP/MLD query) for processing
        Ok(query_data)
    }

    /// Send membership update (IGMP/MLD report)
    ///
    /// Returns MembershipUpdate message to send to relay.
    /// Valid in Querying (initial handshake) and Active (keep-alive refresh).
    /// RFC 7450 §5.2.3.4: gateway re-sends Membership Update before the
    /// relay's AMT query timer expires to maintain tunnel state.
    pub fn send_update(&mut self, report_data: Vec<u8>) -> Result<AmtMessage> {
        if self.state != GatewayState::Querying && self.state != GatewayState::Active {
            return Err(AmtError::InvalidState);
        }

        let request_nonce = self.request_nonce.ok_or(AmtError::InvalidState)?;
        let response_mac = self.response_mac.ok_or(AmtError::NoResponseMac)?;

        self.state = GatewayState::Active;

        Ok(AmtMessage::MembershipUpdate {
            request_nonce,
            response_mac,
            report_data,
        })
    }

    /// Process multicast data packet
    ///
    /// Validates nonce and response MAC, returns IP packet payload
    pub fn handle_data(&self, ip_packet: Vec<u8>) -> Result<Vec<u8>> {
        if self.state != GatewayState::Active {
            return Err(AmtError::InvalidState);
        }

        // In Active state, just forward the IP packet
        // (Data messages don't include nonce/MAC, handled at UDP layer)
        Ok(ip_packet)
    }

    /// Add multicast group membership
    pub fn add_group(&mut self, group: IpAddr, source: Option<IpAddr>, timestamp: u64) {
        let key = GroupKey { group, source };
        let info = GroupInfo {
            key: key.clone(),
            requested_at: timestamp,
            is_ssm: source.is_some(),
        };
        self.groups.insert(key, info);
    }

    /// Remove multicast group membership
    pub fn remove_group(&mut self, group: &IpAddr, source: &Option<IpAddr>) -> Option<GroupInfo> {
        let key = GroupKey {
            group: *group,
            source: *source,
        };
        self.groups.remove(&key)
    }

    /// Send teardown message
    ///
    /// Returns Teardown message to send to relay
    pub fn send_teardown(&mut self) -> Result<AmtMessage> {
        if self.state != GatewayState::Active {
            return Err(AmtError::InvalidState);
        }

        let request_nonce = self.request_nonce.ok_or(AmtError::InvalidState)?;
        let response_mac = self.response_mac.ok_or(AmtError::NoResponseMac)?;

        self.state = GatewayState::Closed;

        Ok(AmtMessage::Teardown {
            request_nonce,
            response_mac,
        })
    }

    /// Reset gateway to idle state
    pub fn reset(&mut self) {
        self.state = GatewayState::Idle;
        self.discovery_nonce = None;
        self.pending_request_nonce = None;
        self.request_nonce = None;
        self.response_mac = None;
        self.groups.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_platform::TestPlatform;

    fn test_config() -> AmtConfig {
        AmtConfig::new("192.0.2.1".parse().unwrap(), Some(2268))
    }

    fn test_platform() -> Arc<TestPlatform> {
        Arc::new(TestPlatform::new())
    }

    /// Drive a gateway through discovery -> request -> query -> update so it
    /// sits in `Active` with a confirmed nonce/MAC pair and nothing in flight.
    fn active_gateway() -> AmtGateway<TestPlatform> {
        let mut gw = AmtGateway::new(test_config(), test_platform());
        let discovery_nonce = match gw.start_discovery().unwrap() {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap()).unwrap();
        let nonce = match gw.request_membership(false).unwrap() {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        gw.handle_query(nonce, [1, 2, 3, 4, 5, 6], vec![0x11]).unwrap();
        gw.send_update(vec![0x22]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);
        gw
    }

    #[test]
    fn test_initial_state() {
        let gw = AmtGateway::new(test_config(), test_platform());
        assert_eq!(gw.state(), GatewayState::Idle);
        assert!(gw.groups().is_empty());
    }

    #[test]
    fn test_discovery_flow() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        // Start discovery
        let msg = gw.start_discovery().unwrap();
        assert_eq!(gw.state(), GatewayState::Discovering);

        let nonce = match msg {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };

        // Handle advertisement
        let relay_addr: IpAddr = "198.51.100.1".parse().unwrap();
        gw.handle_advertisement(nonce, relay_addr).unwrap();
        assert_eq!(gw.state(), GatewayState::Idle);
        assert_eq!(gw.relay_address(), Some(relay_addr));
    }

    #[test]
    fn test_discovery_invalid_nonce() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        gw.start_discovery().unwrap();

        // Try to handle advertisement with wrong nonce
        let relay_addr: IpAddr = "198.51.100.1".parse().unwrap();
        let result = gw.handle_advertisement(0x12345678, relay_addr);
        assert_eq!(result, Err(AmtError::InvalidNonce));
    }

    #[test]
    fn test_request_flow() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        // Request membership
        let msg = gw.request_membership(false).unwrap();
        assert_eq!(gw.state(), GatewayState::Requesting);

        let nonce = match msg {
            AmtMessage::Request { request_nonce, p_flag } => {
                assert!(!p_flag);
                request_nonce
            },
            _ => panic!("Expected Request"),
        };

        // Handle query
        let response_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let query_data = vec![0x11, 0x22, 0x33];
        gw.handle_query(nonce, response_mac, query_data.clone()).unwrap();
        assert_eq!(gw.state(), GatewayState::Querying);
    }

    #[test]
    fn test_request_invalid_nonce() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        gw.request_membership(false).unwrap();

        // Try to handle query with wrong nonce
        let response_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let query_data = vec![0x11, 0x22, 0x33];
        let result = gw.handle_query(0x87654321, response_mac, query_data);
        assert_eq!(result, Err(AmtError::InvalidNonce));
    }

    #[test]
    fn test_full_membership_flow() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        // Discovery
        let disc_msg = gw.start_discovery().unwrap();
        let disc_nonce = match disc_msg {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(disc_nonce, "198.51.100.1".parse().unwrap()).unwrap();

        // Request
        let req_msg = gw.request_membership(true).unwrap();
        let req_nonce = match req_msg {
            AmtMessage::Request { request_nonce, p_flag } => {
                assert!(p_flag);
                request_nonce
            },
            _ => panic!("Expected Request"),
        };

        // Query
        let response_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let query_data = vec![0x11, 0x22];
        gw.handle_query(req_nonce, response_mac, query_data).unwrap();

        // Update
        let report_data = vec![0x33, 0x44, 0x55];
        let update_msg = gw.send_update(report_data.clone()).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);

        match update_msg {
            AmtMessage::MembershipUpdate { request_nonce, response_mac: mac, report_data: data } => {
                assert_eq!(request_nonce, req_nonce);
                assert_eq!(mac, response_mac);
                assert_eq!(data, report_data);
            },
            _ => panic!("Expected MembershipUpdate"),
        };

        // Keep-alive: send_update from Active state (RFC 7450 §5.2.3.4)
        let keepalive_data = vec![0x66, 0x77];
        let keepalive_msg = gw.send_update(keepalive_data.clone()).unwrap();
        assert_eq!(gw.state(), GatewayState::Active); // stays Active
        match keepalive_msg {
            AmtMessage::MembershipUpdate { request_nonce, response_mac: mac, report_data: data } => {
                assert_eq!(request_nonce, req_nonce); // same nonce
                assert_eq!(mac, response_mac);        // same MAC
                assert_eq!(data, keepalive_data);
            },
            _ => panic!("Expected MembershipUpdate for keep-alive"),
        };

        // Teardown
        let teardown_msg = gw.send_teardown().unwrap();
        assert_eq!(gw.state(), GatewayState::Closed);

        match teardown_msg {
            AmtMessage::Teardown { request_nonce, response_mac: mac } => {
                assert_eq!(request_nonce, req_nonce);
                assert_eq!(mac, response_mac);
            },
            _ => panic!("Expected Teardown"),
        };
    }

    #[test]
    fn test_active_membership_query_refreshes_response_state() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        let discovery = gw.start_discovery().unwrap();
        let discovery_nonce = match discovery {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap()).unwrap();

        let request = gw.request_membership(false).unwrap();
        let request_nonce = match request {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        gw.handle_query(request_nonce, [1, 2, 3, 4, 5, 6], vec![0x11]).unwrap();
        gw.send_update(vec![0x22]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);

        let refreshed_mac = [6, 5, 4, 3, 2, 1];
        let query_data = vec![0x33, 0x44];
        let parsed = gw
            .handle_query(request_nonce, refreshed_mac, query_data.clone())
            .unwrap();
        assert_eq!(parsed, query_data);
        assert_eq!(gw.state(), GatewayState::Querying);

        let refreshed_report = vec![0x55, 0x66];
        let update = gw.send_update(refreshed_report.clone()).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);
        match update {
            AmtMessage::MembershipUpdate {
                request_nonce: nonce,
                response_mac,
                report_data,
            } => {
                assert_eq!(nonce, request_nonce);
                assert_eq!(response_mac, refreshed_mac);
                assert_eq!(report_data, refreshed_report);
            },
            _ => panic!("Expected MembershipUpdate"),
        }
    }

    /// A keepalive Request is what makes an active-tunnel Membership Query
    /// reachable, so this covers the other half of
    /// `test_active_membership_query_refreshes_response_state`.
    ///
    /// The load-bearing assertion is the mid-round-trip Update: it must still
    /// carry the pair confirmed by the *previous* Query (RFC 7450 §4.2.1.2
    /// step 5, §5.2.3.5.4) even though the keepalive has already minted a new
    /// nonce per §5.2.3.5.6. That is precisely what the pending/confirmed split
    /// buys, and it is what a single nonce slot would break.
    #[test]
    fn test_keepalive_request_from_active_mints_nonce_without_invalidating_updates() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        let discovery = gw.start_discovery().unwrap();
        let discovery_nonce = match discovery {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap()).unwrap();

        let request = gw.request_membership(false).unwrap();
        let first_nonce = match request {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        let first_mac = [1, 2, 3, 4, 5, 6];
        gw.handle_query(first_nonce, first_mac, vec![0x11]).unwrap();
        gw.send_update(vec![0x22]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);

        // The keepalive re-Request: permitted from Active, mints a FRESH nonce
        // (§5.2.3.5.6 — a new membership query process, not a retransmission),
        // and does NOT drop back to Requesting.
        let keepalive = gw.request_membership(false).unwrap();
        let keepalive_nonce = match keepalive {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request for keepalive"),
        };
        assert_ne!(
            keepalive_nonce, first_nonce,
            "a keepalive starts a new query process, so §5.2.3.5.6 requires a new nonce"
        );
        assert_eq!(gw.state(), GatewayState::Active, "keepalive must not leave Active");

        // Data arriving during the query round trip is still accepted. This is
        // what the state-preserving branch buys: dropping to Requesting would
        // blackhole data once per keepalive interval.
        let payload = vec![0xAA, 0xBB];
        assert_eq!(gw.handle_data(payload.clone()).unwrap(), payload);

        // THE INVALIDATION GUARD: an Update built between the keepalive Request
        // and the Query answering it still carries the pair confirmed by the
        // LAST Query, not the freshly-minted pending nonce. A single nonce slot
        // would have put `keepalive_nonce` on the wire here, paired with a MAC
        // the relay never issued for it, and the relay would drop it.
        let in_flight = gw.send_update(vec![0x33]).unwrap();
        match in_flight {
            AmtMessage::MembershipUpdate { request_nonce, response_mac, .. } => {
                assert_eq!(
                    request_nonce, first_nonce,
                    "mid-round-trip Update must use the last CONFIRMED nonce"
                );
                assert_eq!(response_mac, first_mac);
            },
            _ => panic!("Expected MembershipUpdate"),
        }

        // The relay answers the keepalive with a Query bearing the NEW nonce and
        // a refreshed MAC. That promotes the pending pair, and the cycle
        // continues.
        let refreshed_mac = [9, 8, 7, 6, 5, 4];
        gw.handle_query(keepalive_nonce, refreshed_mac, vec![0x44]).unwrap();
        assert_eq!(gw.state(), GatewayState::Querying);

        let update = gw.send_update(vec![0x55]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);
        match update {
            AmtMessage::MembershipUpdate { request_nonce, response_mac, .. } => {
                assert_eq!(request_nonce, keepalive_nonce, "promoted nonce must now be in use");
                assert_eq!(response_mac, refreshed_mac);
            },
            _ => panic!("Expected MembershipUpdate"),
        }
    }

    /// A Query answering a keepalive that a later keepalive already superseded
    /// must be refused, so a stale relay reply cannot roll the tunnel back onto
    /// an orphaned nonce.
    #[test]
    fn test_superseded_keepalive_query_is_rejected() {
        let mut gw = active_gateway();
        let confirmed = gw.request_nonce.expect("handshake confirmed a nonce");

        let stale = match gw.request_membership(false).unwrap() {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        // A second keepalive replaces the first before the relay answers.
        let current = match gw.request_membership(false).unwrap() {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        assert_ne!(stale, current);

        assert!(
            matches!(gw.handle_query(stale, [7; 6], vec![0x01]), Err(AmtError::InvalidNonce)),
            "a superseded keepalive's Query must not be accepted"
        );
        // The confirmed pair is untouched, so Updates keep working.
        assert_eq!(gw.request_nonce, Some(confirmed));
        assert!(gw.send_update(vec![0x02]).is_ok());
    }

    /// An established tunnel with no Request in flight still accepts a relay
    /// re-Query on the confirmed nonce (the behaviour #6 introduced).
    #[test]
    fn test_unsolicited_active_query_on_confirmed_nonce_is_accepted() {
        let mut gw = active_gateway();
        let confirmed = gw.request_nonce.expect("handshake confirmed a nonce");
        assert_eq!(gw.pending_request_nonce, None, "nothing in flight");

        let refreshed_mac = [0xAB; 6];
        gw.handle_query(confirmed, refreshed_mac, vec![0x09]).unwrap();
        match gw.send_update(vec![0x0A]).unwrap() {
            AmtMessage::MembershipUpdate { request_nonce, response_mac, .. } => {
                assert_eq!(request_nonce, confirmed);
                assert_eq!(response_mac, refreshed_mac);
            },
            _ => panic!("Expected MembershipUpdate"),
        }
    }

    /// §5.2.3.5.4 requires the Query's encapsulated protocol to match the P
    /// flag of the Request it answers, so an embedder must not flip between
    /// IGMPv3 and MLDv2 on an established tunnel.
    #[test]
    fn test_keepalive_cannot_flip_p_flag() {
        let mut gw = active_gateway();
        assert!(matches!(gw.request_membership(true), Err(AmtError::InvalidState)));
        // The same flag is still fine.
        assert!(gw.request_membership(false).is_ok());
    }

    /// The relaxation is scoped to Active. Every other state must still be
    /// refused, so a second Request cannot race the first.
    #[test]
    fn test_request_membership_still_rejects_intermediate_states() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        // Discovering: covered by test_state_validation, restated here so this
        // test reads as the complete boundary for the relaxed guard.
        let discovery = gw.start_discovery().unwrap();
        assert_eq!(gw.state(), GatewayState::Discovering);
        assert!(matches!(gw.request_membership(false), Err(AmtError::InvalidState)));

        let discovery_nonce = match discovery {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap()).unwrap();

        // Requesting: a Query is already outstanding, so re-Requesting here
        // would mint a second nonce and orphan the first.
        let nonce = match gw.request_membership(false).unwrap() {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        assert_eq!(gw.state(), GatewayState::Requesting);
        assert!(matches!(gw.request_membership(false), Err(AmtError::InvalidState)));

        // Querying: the Query has landed but no Update has gone out yet. This is
        // the one intermediate state a keepalive could plausibly race.
        gw.handle_query(nonce, [1, 2, 3, 4, 5, 6], vec![0x11]).unwrap();
        assert_eq!(gw.state(), GatewayState::Querying);
        assert!(matches!(gw.request_membership(false), Err(AmtError::InvalidState)));

        // Closed: the tunnel is torn down; a Request must not resurrect it.
        gw.send_update(vec![0x22]).unwrap();
        gw.send_teardown().unwrap();
        assert_eq!(gw.state(), GatewayState::Closed);
        assert!(matches!(gw.request_membership(false), Err(AmtError::InvalidState)));
    }

    #[test]
    fn test_group_management() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        let group1: IpAddr = "232.0.0.1".parse().unwrap();
        let source1: IpAddr = "69.25.95.10".parse().unwrap();

        // Add SSM group
        gw.add_group(group1, Some(source1), 1000);
        assert_eq!(gw.groups().len(), 1);

        let key = GroupKey {
            group: group1,
            source: Some(source1),
        };
        let info = gw.groups().get(&key).unwrap();
        assert!(info.is_ssm);
        assert_eq!(info.requested_at, 1000);

        // Add ASM group
        let group2: IpAddr = "224.0.0.1".parse().unwrap();
        gw.add_group(group2, None, 2000);
        assert_eq!(gw.groups().len(), 2);

        // Remove group
        gw.remove_group(&group1, &Some(source1));
        assert_eq!(gw.groups().len(), 1);
    }

    #[test]
    fn test_state_validation() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        // Can't request membership while discovering
        gw.start_discovery().unwrap();
        assert_eq!(gw.request_membership(false), Err(AmtError::InvalidState));

        // Reset and try again
        gw.reset();
        assert_eq!(gw.state(), GatewayState::Idle);

        // Can't send update before querying
        assert_eq!(gw.send_update(vec![]), Err(AmtError::InvalidState));

        // Can't teardown before active
        assert_eq!(gw.send_teardown(), Err(AmtError::InvalidState));
    }

    #[test]
    fn test_set_relay() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        let new_relay: IpAddr = "203.0.113.1".parse().unwrap();
        gw.set_relay(new_relay, 3000);

        assert_eq!(gw.relay_address(), Some(new_relay));
        assert_eq!(gw.relay_port(), 3000);
    }

    #[test]
    fn test_config_getter() {
        let gw = AmtGateway::new(test_config(), test_platform());
        let cfg = gw.config();
        assert_eq!(cfg.relay_port, 2268);
        assert!(!cfg.enable_driad);
    }

    #[test]
    fn test_data_handling() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        // Can't handle data when not active
        assert_eq!(gw.handle_data(vec![]), Err(AmtError::InvalidState));

        // Go through full flow to get to Active state
        let disc_msg = gw.start_discovery().unwrap();
        let disc_nonce = match disc_msg {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(disc_nonce, "198.51.100.1".parse().unwrap()).unwrap();

        let req_msg = gw.request_membership(false).unwrap();
        let req_nonce = match req_msg {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };

        let response_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        gw.handle_query(req_nonce, response_mac, vec![0x11]).unwrap();
        gw.send_update(vec![0x22]).unwrap();

        // Now we can handle data
        let ip_packet = vec![0x45, 0x00, 0x00, 0x1C]; // IPv4 header start
        let result = gw.handle_data(ip_packet.clone()).unwrap();
        assert_eq!(result, ip_packet);
    }
}
