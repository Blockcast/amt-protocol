//! AMT Gateway State Machine (RFC 7450 Section 5.2)
//!
//! Implements the AMT gateway control plane state machine for establishing
//! and maintaining multicast group memberships through AMT tunnels.

use crate::config::AmtConfig;
use crate::error::{AmtError, Result};
use crate::messages::{AmtMessage, GatewayAddress};
use crate::platform::{generate_nonce, Platform};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

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

/// The Request Nonce, Response MAC and Gateway Address fields of one
/// Membership Query: what a later Membership Update or Teardown copies from it
/// (RFC 7450 §5.2.3.5.4). `gateway_address` is `None` when that Query left the
/// G flag unset.
#[derive(Debug, Clone, Copy)]
struct QueryFields {
    request_nonce: u32,
    response_mac: [u8; 6],
    gateway_address: Option<GatewayAddress>,
}

impl QueryFields {
    /// The Teardown that copies this Query (RFC 7450 §5.2.3.7.2), or `None`
    /// when it lacked the Gateway Address fields the relay authenticates a
    /// Teardown against (§5.3.3.5).
    fn teardown(&self) -> Option<AmtMessage> {
        self.gateway_address
            .map(|gateway_address| AmtMessage::Teardown {
                request_nonce: self.request_nonce,
                response_mac: self.response_mac,
                gateway_address,
            })
    }
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

    /// Request nonce (used in Request/Query/Update/Data exchanges)
    request_nonce: Option<u32>,

    /// Response MAC from Membership Query
    /// Used in subsequent Update, Data, and Teardown messages
    response_mac: Option<[u8; 6]>,

    /// Gateway Address fields of the Membership Query that supplied
    /// `response_mac`, or `None` when that Query did not carry them (G flag
    /// unset). Stored with the MAC, never on its own: a Teardown copies the
    /// nonce, MAC and gateway endpoint of one and the same Query (RFC 7450
    /// §5.2.3.7.2), and the relay authenticates the three together.
    gateway_address: Option<GatewayAddress>,

    /// The fields of the Membership Query that provided the Response MAC for
    /// the last Membership Update sent, recorded by `send_update`. A Teardown
    /// copies these (§5.2.3.7.2), not the latest Query's. The two differ from
    /// `handle_query` until the `send_update` answering it: then the latest
    /// Query may report a new gateway endpoint while the relay still forwards
    /// to the tunnel these name, which is what `rebind_teardown` tears down.
    last_update_query: Option<QueryFields>,

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
            request_nonce: None,
            response_mac: None,
            gateway_address: None,
            last_update_query: None,
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
        self.platform
            .log_info(&format!("[AMT] Generated discovery nonce: 0x{:08x}", nonce));

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
        self.platform.log_info(&format!(
            "[AMT] Received advertisement nonce: 0x{:08x}",
            nonce
        ));
        self.platform.log_info(&format!(
            "[AMT] Expected discovery nonce: 0x{:08x}",
            self.discovery_nonce.unwrap_or(0)
        ));

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
    /// * `Idle` — bootstrap. Mints a fresh request nonce and moves to
    ///   `Requesting` to await the relay's Membership Query.
    /// * `Active` — keepalive re-Request, continuing the query cycle of
    ///   RFC 7450 §4.2.1.2 on a live tunnel. This is the other half of
    ///   `handle_query` accepting `Active`: a Query can only arrive while
    ///   Active if a Request could be sent from Active in the first place.
    ///
    /// This is a library primitive for embedders, not something the in-crate
    /// driver reaches. `subscription`'s only caller of `send_request` is
    /// `handle_advertisement`, where the gateway is `Idle`, and `tick()`'s
    /// Active branch emits a Membership *Update* via
    /// `send_current_state_update` rather than a Request — so nothing in this
    /// crate takes the `Active` arm. The callers that do are the FFI, JNI and
    /// WASM bindings; go-amt's `keepaliveLoop` drives it through
    /// `amt_gateway_request_membership`, which is what BLO-28805 needed.
    /// Wiring the crate's own `tick()` to re-Request on the QQIC-derived
    /// timer is a separate change.
    ///
    /// # Nonce reuse here is a deliberate deviation, not what the RFC says
    ///
    /// On the keepalive path the nonce is **reused**. The RFC asks for the
    /// opposite — §5.2.3.5.6: *"A new nonce MUST be generated each time the
    /// gateway starts the membership query process. The same nonce SHOULD be
    /// used when retransmitting a Request message."* The retransmission-only
    /// carve-out is the tell: it would be redundant if reuse were correct for
    /// every later Request. §4.2.1.2 agrees, calling the query timer firing
    /// the start of a *new* Request/Query exchange. (An earlier version of
    /// this comment cited §4.2.1.2's *"this query cycle may continue
    /// indefinitely once started"* as licensing reuse. It does not — that
    /// sentence is about the cycle persisting, not about nonce identity.)
    ///
    /// We deviate because `request_nonce` is a single slot with two readers:
    /// `handle_query` matches the incoming Query against it, and
    /// `send_update` stamps outgoing Updates with it. (A Teardown copies the
    /// nonce the last Update carried, recorded in `last_update_query`, so it
    /// is unaffected by what the slot holds.) §4.2.1.2 step 5 and §5.2.3.5.4
    /// require an Update to carry the nonce/MAC of the *last Membership Query
    /// received*, so minting here would invalidate any Update built between
    /// this Request and the Query answering it. Reuse is the lesser wrong
    /// until the field is split into a pending request nonce (matched by
    /// `handle_query`) plus the last-received Query's nonce/MAC pair that
    /// Updates keep using. That split is the real fix, tracked in BLO-29418.
    ///
    /// # Data during the round trip
    ///
    /// The state stays `Active`, so data arriving before the Query is still
    /// accepted by `handle_data`; dropping back to `Requesting` would
    /// blackhole data once per keepalive interval. The gap is narrowed rather
    /// than closed: `handle_query` moves `Active` to `Querying` and
    /// `handle_data` refuses in `Querying`, so data is still refused between
    /// the Query and the `send_update` that answers it. In the `subscription`
    /// driver that window is zero-width — `handle_query` is followed
    /// synchronously by `send_current_state_update` — but an embedder driving
    /// `AmtGateway` directly through the bindings does have a real gap there.
    ///
    /// `p_flag` is applied unconditionally, including from `Active`, so an
    /// embedder can flip the requested inner protocol (IGMPv3 to MLDv2, or
    /// back) mid-tunnel while the nonce and MAC stay fixed. §5.2.3.5.4
    /// expects a Query's encapsulated protocol to match the P flag of the
    /// Request it answers, so that is an odd wire state. `subscription`
    /// derives `want_mld` from the relay family and cannot reach it; direct
    /// embedders must not flip it on a live tunnel.
    pub fn request_membership(&mut self, p_flag: bool) -> Result<AmtMessage> {
        if self.state != GatewayState::Idle && self.state != GatewayState::Active {
            return Err(AmtError::InvalidState);
        }

        if self.relay_address.is_none() {
            return Err(AmtError::InvalidState);
        }

        let nonce = if self.state == GatewayState::Active {
            // Keepalive: reuse the tunnel's nonce and stay Active. Reuse is a
            // deliberate deviation from §5.2.3.5.6 forced by this being a
            // single nonce slot -- see the doc comment, and BLO-29418.
            self.request_nonce.ok_or(AmtError::InvalidState)?
        } else {
            // Bootstrap: mint a nonce and wait for the Query.
            let nonce = generate_nonce(self.platform.as_ref());
            self.request_nonce = Some(nonce);
            self.state = GatewayState::Requesting;
            nonce
        };
        self.p_flag = p_flag;

        Ok(AmtMessage::Request {
            request_nonce: nonce,
            p_flag,
        })
    }

    /// Process an initial or active-tunnel Membership Query.
    ///
    /// Validates nonce and extracts response MAC and query data.
    ///
    /// `gateway_address` is the Query's Gateway Address fields, `None` when
    /// its G flag is unset. It replaces the stored value together with the
    /// MAC, so a Query without the fields also clears any a previous Query
    /// supplied: they described a different MAC. What the last Update was
    /// built from is kept apart, so a Query reporting a new endpoint leaves
    /// the old one available to `rebind_teardown`: call that next, before the
    /// `send_update` answering this Query.
    pub fn handle_query(
        &mut self,
        request_nonce: u32,
        response_mac: [u8; 6],
        query_data: Vec<u8>,
        gateway_address: Option<GatewayAddress>,
    ) -> Result<Vec<u8>> {
        if self.state != GatewayState::Requesting && self.state != GatewayState::Active {
            self.platform
                .log_error("[AMT handle_query] Error: InvalidState");
            return Err(AmtError::InvalidState);
        }

        // Debug logging
        self.platform.log_debug(&format!(
            "[AMT handle_query] Stored request_nonce: {:?}",
            self.request_nonce
        ));
        self.platform.log_debug(&format!(
            "[AMT handle_query] Received request_nonce: 0x{:08x}",
            request_nonce
        ));

        // Validate nonce matches our request nonce
        if Some(request_nonce) != self.request_nonce {
            self.platform
                .log_error("[AMT handle_query] ❌ NONCE MISMATCH!");
            return Err(AmtError::InvalidNonce);
        }
        self.platform
            .log_info("[AMT handle_query] ✅ Nonce validated");

        // Store response MAC for future messages
        self.response_mac = Some(response_mac);
        self.gateway_address = gateway_address;
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

        // This Query now provides the MAC for the last Update sent: from here
        // on a Teardown copies it (§5.2.3.7.2).
        self.last_update_query = Some(QueryFields {
            request_nonce,
            response_mac,
            gateway_address: self.gateway_address,
        });
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
    /// Returns the Teardown to send to the relay (RFC 7450 §5.2.3.7.2). It
    /// copies the Request Nonce, Response MAC and Gateway Address fields of
    /// the Membership Query that provided the MAC for the last Membership
    /// Update, as `send_update` recorded them. Reaching `Active` takes a
    /// `send_update` after the latest Query, so here that is also the latest
    /// Query.
    ///
    /// Fails with [`AmtError::NoGatewayAddress`] when that Query did not carry
    /// the Gateway Address fields. The relay authenticates a Teardown against
    /// those fields, not against the datagram's source (§5.3.3.5), and a relay
    /// that omits them does not support the Teardown procedure (§5.1.4.5):
    /// there is then no Teardown it could accept, so none is built. The state
    /// is left unchanged, as on every other refusal here.
    pub fn send_teardown(&mut self) -> Result<AmtMessage> {
        if self.state != GatewayState::Active {
            return Err(AmtError::InvalidState);
        }

        let behind_last_update = self.last_update_query.ok_or(AmtError::InvalidState)?;
        let teardown = behind_last_update
            .teardown()
            .ok_or(AmtError::NoGatewayAddress)?;

        self.state = GatewayState::Closed;

        Ok(teardown)
    }

    /// The Teardown owed once a Membership Query reports a gateway endpoint
    /// other than the one the last Membership Update was sent from (RFC 7450
    /// §5.2.3.7.1), or `None` when none is owed.
    ///
    /// A relay that supports Teardown reports, in every Query with the G flag
    /// set, the source address and port of the Request that Query answers
    /// (§5.1.4.9). A different value means this gateway's endpoint moved --
    /// a NAT rebinding, or an interface or address change -- while the relay
    /// still forwards to the tunnel the last Update created at the old one
    /// (§4.2.1.3). This Teardown copies the Query behind that Update
    /// (§5.2.3.7.2), so the relay authenticates it against the old endpoint
    /// and stops that tunnel, not the one the next Update creates.
    ///
    /// Call it after `handle_query` and before the `send_update` answering
    /// the Query, and send the Teardown to the relay first (Figure 8). It
    /// changes no state, so asking again returns the same Teardown, which may
    /// be resent (§5.2.3.7.2). `send_update` records the new Query as the one
    /// behind the last Update, and from then on nothing is owed.
    ///
    /// The comparison is with the Query behind the last Update. That is the
    /// previous Query §5.2.3.7.1 names whenever each Query is answered by an
    /// Update, and it is the endpoint the relay is forwarding to. Nothing is
    /// owed when either Query lacks the Gateway Address fields: without the
    /// old ones no Teardown could pass the relay's check (§5.3.3.5), and one
    /// without the new ones has no G flag, which §5.2.3.7.1 requires.
    /// §5.2.3.7.1 also limits the MUST to a gateway that "has reported active
    /// group subscriptions". Reports are opaque here, so a Teardown is owed
    /// after any Update; where that Update reported none, the relay processes
    /// it as a report deleting every group record of an endpoint that has
    /// none (§5.3.3.5), which changes nothing.
    pub fn rebind_teardown(&self) -> Option<AmtMessage> {
        let behind_last_update = self.last_update_query?;
        let tunnel_endpoint = behind_last_update.gateway_address?;
        let reported_endpoint = self.gateway_address?;
        if reported_endpoint == tunnel_endpoint {
            return None;
        }
        behind_last_update.teardown()
    }

    /// Reset gateway to idle state
    pub fn reset(&mut self) {
        self.state = GatewayState::Idle;
        self.discovery_nonce = None;
        self.request_nonce = None;
        self.response_mac = None;
        self.gateway_address = None;
        self.last_update_query = None;
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

    /// The Gateway Address fields a Teardown-capable relay returns for a
    /// gateway it saw at `endpoint` (post-NAT).
    fn relay_observed(endpoint: &str) -> GatewayAddress {
        GatewayAddress::from(endpoint.parse::<std::net::SocketAddr>().unwrap())
    }

    /// Discovery, Request and a Query answered by one Update: the shortest
    /// path to `Active`. Returns the request nonce.
    fn drive_to_active(
        gw: &mut AmtGateway<TestPlatform>,
        response_mac: [u8; 6],
        gateway_address: Option<GatewayAddress>,
    ) -> u32 {
        let discovery_nonce = match gw.start_discovery().unwrap() {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap())
            .unwrap();
        let request_nonce = match gw.request_membership(false).unwrap() {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        gw.handle_query(request_nonce, response_mac, vec![0x11], gateway_address)
            .unwrap();
        gw.send_update(vec![0x22]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);
        request_nonce
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
            AmtMessage::Request {
                request_nonce,
                p_flag,
            } => {
                assert!(!p_flag);
                request_nonce
            }
            _ => panic!("Expected Request"),
        };

        // Handle query
        let response_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let query_data = vec![0x11, 0x22, 0x33];
        gw.handle_query(nonce, response_mac, query_data.clone(), None)
            .unwrap();
        assert_eq!(gw.state(), GatewayState::Querying);
    }

    #[test]
    fn test_request_invalid_nonce() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        gw.request_membership(false).unwrap();

        // Try to handle query with wrong nonce
        let response_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let query_data = vec![0x11, 0x22, 0x33];
        let result = gw.handle_query(0x87654321, response_mac, query_data, None);
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
        gw.handle_advertisement(disc_nonce, "198.51.100.1".parse().unwrap())
            .unwrap();

        // Request
        let req_msg = gw.request_membership(true).unwrap();
        let req_nonce = match req_msg {
            AmtMessage::Request {
                request_nonce,
                p_flag,
            } => {
                assert!(p_flag);
                request_nonce
            }
            _ => panic!("Expected Request"),
        };

        // Query, from a relay that supports Teardown (G flag set)
        let response_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let query_data = vec![0x11, 0x22];
        let observed = relay_observed("203.0.113.9:40001");
        gw.handle_query(req_nonce, response_mac, query_data, Some(observed))
            .unwrap();

        // Update
        let report_data = vec![0x33, 0x44, 0x55];
        let update_msg = gw.send_update(report_data.clone()).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);

        match update_msg {
            AmtMessage::MembershipUpdate {
                request_nonce,
                response_mac: mac,
                report_data: data,
            } => {
                assert_eq!(request_nonce, req_nonce);
                assert_eq!(mac, response_mac);
                assert_eq!(data, report_data);
            }
            _ => panic!("Expected MembershipUpdate"),
        };

        // Keep-alive: send_update from Active state (RFC 7450 §5.2.3.4)
        let keepalive_data = vec![0x66, 0x77];
        let keepalive_msg = gw.send_update(keepalive_data.clone()).unwrap();
        assert_eq!(gw.state(), GatewayState::Active); // stays Active
        match keepalive_msg {
            AmtMessage::MembershipUpdate {
                request_nonce,
                response_mac: mac,
                report_data: data,
            } => {
                assert_eq!(request_nonce, req_nonce); // same nonce
                assert_eq!(mac, response_mac); // same MAC
                assert_eq!(data, keepalive_data);
            }
            _ => panic!("Expected MembershipUpdate for keep-alive"),
        };

        // Teardown
        let teardown_msg = gw.send_teardown().unwrap();
        assert_eq!(gw.state(), GatewayState::Closed);

        match teardown_msg {
            AmtMessage::Teardown {
                request_nonce,
                response_mac: mac,
                gateway_address,
            } => {
                assert_eq!(request_nonce, req_nonce);
                assert_eq!(mac, response_mac);
                assert_eq!(gateway_address, observed);
            }
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
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap())
            .unwrap();

        let request = gw.request_membership(false).unwrap();
        let request_nonce = match request {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        gw.handle_query(request_nonce, [1, 2, 3, 4, 5, 6], vec![0x11], None)
            .unwrap();
        gw.send_update(vec![0x22]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);

        let refreshed_mac = [6, 5, 4, 3, 2, 1];
        let query_data = vec![0x33, 0x44];
        let parsed = gw
            .handle_query(request_nonce, refreshed_mac, query_data.clone(), None)
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
            }
            _ => panic!("Expected MembershipUpdate"),
        }
    }

    /// A keepalive Request is what makes an active-tunnel Membership Query
    /// reachable, so this covers the other half of
    /// `test_active_membership_query_refreshes_response_state`.
    #[test]
    fn test_keepalive_request_from_active_reuses_nonce_and_keeps_data_flowing() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        let discovery = gw.start_discovery().unwrap();
        let discovery_nonce = match discovery {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap())
            .unwrap();

        let request = gw.request_membership(false).unwrap();
        let request_nonce = match request {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        gw.handle_query(request_nonce, [1, 2, 3, 4, 5, 6], vec![0x11], None)
            .unwrap();
        gw.send_update(vec![0x22]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);

        // The keepalive re-Request itself: permitted from Active, carries the
        // tunnel's existing nonce, and does NOT drop back to Requesting.
        let keepalive = gw.request_membership(false).unwrap();
        match keepalive {
            AmtMessage::Request {
                request_nonce: nonce,
                ..
            } => {
                assert_eq!(
                    nonce, request_nonce,
                    "keepalive Request must reuse the tunnel nonce"
                );
            }
            _ => panic!("Expected Request for keepalive"),
        }
        assert_eq!(
            gw.state(),
            GatewayState::Active,
            "keepalive must not leave Active"
        );

        // Data arriving during the query round trip is still accepted. This is
        // what the state-preserving branch buys: dropping to Requesting would
        // blackhole data once per keepalive interval.
        let payload = vec![0xAA, 0xBB];
        assert_eq!(gw.handle_data(payload.clone()).unwrap(), payload);

        // The relay answers the keepalive with a Query bearing the same nonce
        // and a refreshed MAC, and the cycle continues.
        let refreshed_mac = [9, 8, 7, 6, 5, 4];
        gw.handle_query(request_nonce, refreshed_mac, vec![0x33], None)
            .unwrap();
        assert_eq!(gw.state(), GatewayState::Querying);

        let update = gw.send_update(vec![0x44]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);
        match update {
            AmtMessage::MembershipUpdate {
                request_nonce: nonce,
                response_mac,
                ..
            } => {
                assert_eq!(nonce, request_nonce);
                assert_eq!(response_mac, refreshed_mac);
            }
            _ => panic!("Expected MembershipUpdate"),
        }
    }

    /// The relaxation is scoped to `Idle` and `Active`. Every other state must
    /// still be refused, so a second Request cannot race the first and a
    /// closed tunnel cannot be revived in place. All four are asserted, so
    /// this reads as the complete boundary for the relaxed guard.
    #[test]
    fn test_request_membership_still_rejects_intermediate_states() {
        let mut gw = AmtGateway::new(test_config(), test_platform());

        // Discovering: covered by test_state_validation, restated here so this
        // test reads as the complete boundary for the relaxed guard.
        let discovery = gw.start_discovery().unwrap();
        assert_eq!(gw.state(), GatewayState::Discovering);
        assert!(matches!(
            gw.request_membership(false),
            Err(AmtError::InvalidState)
        ));

        let discovery_nonce = match discovery {
            AmtMessage::RelayDiscovery { nonce } => nonce,
            _ => panic!("Expected RelayDiscovery"),
        };
        gw.handle_advertisement(discovery_nonce, "198.51.100.1".parse().unwrap())
            .unwrap();

        // Requesting: a Query is already outstanding, so re-Requesting here
        // would mint a second nonce and orphan the first.
        let request = gw.request_membership(false).unwrap();
        assert_eq!(gw.state(), GatewayState::Requesting);
        assert!(matches!(
            gw.request_membership(false),
            Err(AmtError::InvalidState)
        ));

        let request_nonce = match request {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };

        // Querying: the Query has landed but has not been answered yet. This
        // is the one intermediate state a keepalive could plausibly race, so
        // it is the most load-bearing case here -- a Request accepted from
        // Querying would abandon an Update the caller still owes the relay.
        gw.handle_query(
            request_nonce,
            [1, 2, 3, 4, 5, 6],
            vec![0x11],
            Some(relay_observed("203.0.113.9:40001")),
        )
        .unwrap();
        assert_eq!(gw.state(), GatewayState::Querying);
        assert!(matches!(
            gw.request_membership(false),
            Err(AmtError::InvalidState)
        ));

        // Closed: a torn-down tunnel is not re-Requestable. Reaching Active
        // first is the only way in, which also proves the guard does not
        // simply admit anything that has ever been Active.
        gw.send_update(vec![0x22]).unwrap();
        assert_eq!(gw.state(), GatewayState::Active);
        gw.send_teardown().unwrap();
        assert_eq!(gw.state(), GatewayState::Closed);
        assert!(matches!(
            gw.request_membership(false),
            Err(AmtError::InvalidState)
        ));
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
        gw.handle_advertisement(disc_nonce, "198.51.100.1".parse().unwrap())
            .unwrap();

        let req_msg = gw.request_membership(false).unwrap();
        let req_nonce = match req_msg {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };

        let response_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        gw.handle_query(req_nonce, response_mac, vec![0x11], None)
            .unwrap();
        gw.send_update(vec![0x22]).unwrap();

        // Now we can handle data
        let ip_packet = vec![0x45, 0x00, 0x00, 0x1C]; // IPv4 header start
        let result = gw.handle_data(ip_packet.clone()).unwrap();
        assert_eq!(result, ip_packet);
    }

    /// RFC 7450 §5.2.3.7.2, at shutdown: a Teardown copies the Request Nonce,
    /// Response MAC and Gateway Address fields of the Query that provided the
    /// MAC for the LAST Membership Update. Once the Update answering a Query
    /// that reported a new endpoint has gone out, the tunnel lives at that
    /// endpoint and its Query is the one to copy; pairing either value with
    /// the first Query's would fail the relay's check (§5.3.3.5). Tearing
    /// down the old endpoint when the move is reported is a different
    /// Teardown: `a_query_reporting_a_new_endpoint_owes_a_teardown_for_the_old_one`.
    #[test]
    fn teardown_copies_the_query_behind_the_last_update() {
        let mut gw = AmtGateway::new(test_config(), test_platform());
        let request_nonce = drive_to_active(
            &mut gw,
            [1, 2, 3, 4, 5, 6],
            Some(relay_observed("203.0.113.9:40001")),
        );

        gw.request_membership(false).unwrap();
        let rebound = relay_observed("[2001:db8::9]:40002");
        let refreshed_mac = [6, 5, 4, 3, 2, 1];
        gw.handle_query(request_nonce, refreshed_mac, vec![0x33], Some(rebound))
            .unwrap();
        gw.send_update(vec![0x44]).unwrap();

        assert_eq!(
            gw.send_teardown().unwrap(),
            AmtMessage::Teardown {
                request_nonce,
                response_mac: refreshed_mac,
                gateway_address: rebound,
            }
        );
        assert_eq!(gw.state(), GatewayState::Closed);
    }

    /// Without the relay's Gateway Address fields no Teardown could pass the
    /// relay's check (§5.3.3.5), so none is built and nothing changes.
    #[test]
    fn teardown_is_refused_when_the_relay_sent_no_gateway_address() {
        let mut gw = AmtGateway::new(test_config(), test_platform());
        drive_to_active(&mut gw, [1, 2, 3, 4, 5, 6], None);

        assert_eq!(gw.send_teardown(), Err(AmtError::NoGatewayAddress));
        assert_eq!(gw.state(), GatewayState::Active);
    }

    /// The fields belong to one Query: a later Query without them clears an
    /// earlier Query's instead of pairing them with its own MAC.
    #[test]
    fn a_query_without_gateway_address_clears_the_previous_one() {
        let mut gw = AmtGateway::new(test_config(), test_platform());
        let request_nonce = drive_to_active(
            &mut gw,
            [1, 2, 3, 4, 5, 6],
            Some(relay_observed("203.0.113.9:40001")),
        );

        gw.request_membership(false).unwrap();
        gw.handle_query(request_nonce, [6, 5, 4, 3, 2, 1], vec![0x33], None)
            .unwrap();
        gw.send_update(vec![0x44]).unwrap();

        assert_eq!(gw.send_teardown(), Err(AmtError::NoGatewayAddress));
    }

    /// RFC 7450 §5.2.3.7.1, Figure 8 [5]-[7]: a Query reporting a different
    /// Gateway IP Address or Port Number means the relay still forwards to
    /// the tunnel at the old endpoint. The Teardown owed names that endpoint
    /// with the nonce and MAC of the Query behind the last Update -- what the
    /// relay authenticates it against (§5.3.3.5) -- and is owed until the
    /// Update answering the new Query is built, which it leaves untouched.
    #[test]
    fn a_query_reporting_a_new_endpoint_owes_a_teardown_for_the_old_one() {
        let tunnel = relay_observed("203.0.113.9:40001");
        // A NAT rebinding usually keeps the address and moves the port; an
        // interface change moves the address. §5.2.3.7.1 covers "either".
        for moved in [
            relay_observed("203.0.113.9:40002"),
            relay_observed("[2001:db8::9]:40001"),
        ] {
            let mut gw = AmtGateway::new(test_config(), test_platform());
            let tunnel_mac = [1, 2, 3, 4, 5, 6];
            let request_nonce = drive_to_active(&mut gw, tunnel_mac, Some(tunnel));
            assert_eq!(gw.rebind_teardown(), None, "no Query has reported a move");

            gw.request_membership(false).unwrap();
            let moved_mac = [6, 5, 4, 3, 2, 1];
            gw.handle_query(request_nonce, moved_mac, vec![0x33], Some(moved))
                .unwrap();

            let owed = Some(AmtMessage::Teardown {
                request_nonce,
                response_mac: tunnel_mac,
                gateway_address: tunnel,
            });
            assert_eq!(gw.rebind_teardown(), owed, "moved to {moved:?}");
            assert_eq!(gw.rebind_teardown(), owed, "asking again changes nothing");
            assert_eq!(gw.state(), GatewayState::Querying);

            match gw.send_update(vec![0x44]).unwrap() {
                AmtMessage::MembershipUpdate { response_mac, .. } => {
                    assert_eq!(response_mac, moved_mac, "the Update answers the new Query")
                }
                other => panic!("Expected MembershipUpdate, got {other:?}"),
            }
            assert_eq!(
                gw.rebind_teardown(),
                None,
                "the tunnel is at the new endpoint once its Update is built"
            );
        }
    }

    /// Only a changed Gateway IP Address or Port Number owes a Teardown
    /// (§5.2.3.7.1): not a new MAC from the same endpoint, and not a pair of
    /// Queries either of which lacks the fields. Without the old ones no
    /// Teardown could pass the relay's check (§5.3.3.5); a Query without the
    /// new ones has no G flag, which §5.2.3.7.1 requires.
    #[test]
    fn no_teardown_is_owed_unless_a_query_reports_a_move() {
        let endpoint = relay_observed("203.0.113.9:40001");
        for (before, after) in [
            (Some(endpoint), Some(endpoint)),
            (None, Some(endpoint)),
            (Some(endpoint), None),
        ] {
            let mut gw = AmtGateway::new(test_config(), test_platform());
            let request_nonce = drive_to_active(&mut gw, [1, 2, 3, 4, 5, 6], before);

            gw.request_membership(false).unwrap();
            gw.handle_query(request_nonce, [6, 5, 4, 3, 2, 1], vec![0x33], after)
                .unwrap();
            assert_eq!(gw.rebind_teardown(), None, "{before:?} then {after:?}");
        }
    }

    /// Before any Update there is no tunnel to tear down, whatever the Query
    /// reports, and `reset` forgets the last one.
    #[test]
    fn no_teardown_is_owed_without_an_update_behind_it() {
        let mut gw = AmtGateway::new(test_config(), test_platform());
        let request_nonce = match gw.request_membership(false).unwrap() {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        gw.handle_query(
            request_nonce,
            [1, 2, 3, 4, 5, 6],
            vec![0x11],
            Some(relay_observed("203.0.113.9:40001")),
        )
        .unwrap();
        assert_eq!(gw.rebind_teardown(), None, "first Query of the tunnel");

        gw.send_update(vec![0x22]).unwrap();
        gw.reset();
        let request_nonce = match gw.request_membership(false).unwrap() {
            AmtMessage::Request { request_nonce, .. } => request_nonce,
            _ => panic!("Expected Request"),
        };
        gw.handle_query(
            request_nonce,
            [6, 5, 4, 3, 2, 1],
            vec![0x11],
            Some(relay_observed("203.0.113.9:40002")),
        )
        .unwrap();
        assert_eq!(gw.rebind_teardown(), None, "first Query after reset");
    }
}
