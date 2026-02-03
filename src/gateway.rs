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

    /// Request nonce (used in Request/Query/Update/Data exchanges)
    request_nonce: Option<u32>,

    /// Response MAC from Membership Query
    /// Used in subsequent Update, Data, and Teardown messages
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
    /// Returns Request message to send to relay
    pub fn request_membership(&mut self, p_flag: bool) -> Result<AmtMessage> {
        if self.state != GatewayState::Idle {
            return Err(AmtError::InvalidState);
        }

        if self.relay_address.is_none() {
            return Err(AmtError::InvalidState);
        }

        // Generate request nonce
        let nonce = generate_nonce(self.platform.as_ref());
        self.request_nonce = Some(nonce);
        self.p_flag = p_flag;
        self.state = GatewayState::Requesting;

        Ok(AmtMessage::Request {
            request_nonce: nonce,
            p_flag,
        })
    }

    /// Process Membership Query response
    ///
    /// Validates nonce and extracts response MAC and query data
    pub fn handle_query(
        &mut self,
        request_nonce: u32,
        response_mac: [u8; 6],
        query_data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if self.state != GatewayState::Requesting {
            self.platform.log_error("[AMT handle_query] Error: InvalidState");
            return Err(AmtError::InvalidState);
        }

        // Debug logging
        self.platform.log_debug(&format!("[AMT handle_query] Stored request_nonce: {:?}", self.request_nonce));
        self.platform.log_debug(&format!("[AMT handle_query] Received request_nonce: 0x{:08x}", request_nonce));

        // Validate nonce matches our request nonce
        if Some(request_nonce) != self.request_nonce {
            self.platform.log_error("[AMT handle_query] ❌ NONCE MISMATCH!");
            return Err(AmtError::InvalidNonce);
        }
        self.platform.log_info("[AMT handle_query] ✅ Nonce validated");

        // Store response MAC for future messages
        self.response_mac = Some(response_mac);
        self.state = GatewayState::Querying;

        // Return query data (IGMP/MLD query) for processing
        Ok(query_data)
    }

    /// Send membership update (IGMP/MLD report)
    ///
    /// Returns MembershipUpdate message to send to relay
    pub fn send_update(&mut self, report_data: Vec<u8>) -> Result<AmtMessage> {
        if self.state != GatewayState::Querying {
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
