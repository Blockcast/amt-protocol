//! WASM Bindings for AMT Protocol
//!
//! Exposes Rust AMT protocol implementation to JavaScript/TypeScript.

use wasm_bindgen::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use crate::gateway::{AmtGateway, GatewayState};
use crate::config::AmtConfig;
use crate::messages::AmtMessage;
use crate::igmp::{IgmpV3Report, IgmpRecord};
use crate::mld::{MldV2Report, MldRecord};
use crate::driad::DriadResolver;
use crate::platform::wasm_platform::WasmPlatform;

/// Gateway state exposed to JavaScript
#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsGatewayState {
    Idle = 0,
    Discovering = 1,
    Requesting = 2,
    Querying = 3,
    Active = 4,
    Closed = 5,
}

impl From<GatewayState> for JsGatewayState {
    fn from(state: GatewayState) -> Self {
        match state {
            GatewayState::Idle => JsGatewayState::Idle,
            GatewayState::Discovering => JsGatewayState::Discovering,
            GatewayState::Requesting => JsGatewayState::Requesting,
            GatewayState::Querying => JsGatewayState::Querying,
            GatewayState::Active => JsGatewayState::Active,
            GatewayState::Closed => JsGatewayState::Closed,
        }
    }
}

/// AMT Gateway wrapper for WASM
#[wasm_bindgen]
pub struct JsAmtGateway {
    inner: AmtGateway<WasmPlatform>,
}

#[wasm_bindgen]
impl JsAmtGateway {
    /// Create new AMT Gateway
    ///
    /// @param relay_address - IP address as string (e.g., "192.0.2.1" or "2001:db8::1")
    /// @param relay_port - Optional port number (default: 2268)
    /// @param enable_driad - Enable DRIAD discovery
    /// @param keepalive_interval_secs - Keep-alive interval in seconds (default: 60, 0 to disable)
    #[wasm_bindgen(constructor)]
    pub fn new(
        relay_address: &str,
        relay_port: Option<u16>,
        enable_driad: bool,
        keepalive_interval_secs: Option<u32>
    ) -> Result<JsAmtGateway, JsValue> {
        let addr: IpAddr = relay_address
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid IP address: {}", e)))?;

        let mut config = if enable_driad {
            AmtConfig::with_driad(addr, relay_port)
        } else {
            AmtConfig::new(addr, relay_port)
        };

        if let Some(interval) = keepalive_interval_secs {
            config = config.with_keepalive(interval);
        }

        let platform = Arc::new(WasmPlatform::new());

        Ok(JsAmtGateway {
            inner: AmtGateway::new(config, platform),
        })
    }

    /// Get keep-alive interval in seconds
    #[wasm_bindgen(getter, js_name = keepaliveIntervalSecs)]
    pub fn keepalive_interval_secs(&self) -> u32 {
        self.inner.config().keepalive_interval_secs
    }

    /// Get current gateway state
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> JsGatewayState {
        self.inner.state().into()
    }

    /// Get current relay address as string
    #[wasm_bindgen(getter, js_name = relayAddress)]
    pub fn relay_address(&self) -> Option<String> {
        self.inner.relay_address().map(|addr| addr.to_string())
    }

    /// Get current relay port
    #[wasm_bindgen(getter, js_name = relayPort)]
    pub fn relay_port(&self) -> u16 {
        self.inner.relay_port()
    }

    /// Set relay address and port (from DRIAD discovery)
    #[wasm_bindgen(js_name = setRelay)]
    pub fn set_relay(&mut self, address: &str, port: u16) -> Result<(), JsValue> {
        let addr: IpAddr = address
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid IP address: {}", e)))?;

        self.inner.set_relay(addr, port);
        Ok(())
    }

    /// Start relay discovery
    ///
    /// Returns encoded RelayDiscovery message as Uint8Array
    #[wasm_bindgen(js_name = startDiscovery)]
    pub fn start_discovery(&mut self) -> Result<Vec<u8>, JsValue> {
        let msg = self.inner
            .start_discovery()
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        Ok(msg.encode())
    }

    /// Handle Relay Advertisement response
    ///
    /// @param data - Raw message bytes
    #[wasm_bindgen(js_name = handleAdvertisement)]
    pub fn handle_advertisement(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let msg = AmtMessage::decode(data)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        match msg {
            AmtMessage::RelayAdvertisement { nonce, relay_address } => {
                self.inner
                    .handle_advertisement(nonce, relay_address)
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
                Ok(())
            }
            _ => Err(JsValue::from_str("Expected RelayAdvertisement message")),
        }
    }

    /// Request membership
    ///
    /// @param p_flag - Prefer native multicast flag
    /// Returns encoded Request message as Uint8Array
    #[wasm_bindgen(js_name = requestMembership)]
    pub fn request_membership(&mut self, p_flag: bool) -> Result<Vec<u8>, JsValue> {
        let msg = self.inner
            .request_membership(p_flag)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        Ok(msg.encode())
    }

    /// Handle Membership Query response
    ///
    /// @param data - Raw message bytes
    /// Returns query data (IGMP/MLD query) as Uint8Array
    #[wasm_bindgen(js_name = handleQuery)]
    pub fn handle_query(&mut self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let msg = AmtMessage::decode(data)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        match msg {
            AmtMessage::MembershipQuery { request_nonce, response_mac, query_data } => {
                // Debug logging via platform
                web_sys::console::log_1(&format!("[WASM handleQuery] Parsed nonce from packet: 0x{:08x}", request_nonce).into());

                self.inner
                    .handle_query(request_nonce, response_mac, query_data)
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
            }
            _ => Err(JsValue::from_str("Expected MembershipQuery message")),
        }
    }

    /// Send membership update
    ///
    /// @param report_data - IGMP/MLD report bytes
    /// Returns encoded MembershipUpdate message as Uint8Array
    #[wasm_bindgen(js_name = sendUpdate)]
    pub fn send_update(&mut self, report_data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let msg = self.inner
            .send_update(report_data.to_vec())
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        Ok(msg.encode())
    }

    /// Handle multicast data packet
    ///
    /// @param data - Raw message bytes
    /// Returns IP packet payload as Uint8Array
    #[wasm_bindgen(js_name = handleData)]
    pub fn handle_data(&self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let msg = AmtMessage::decode(data)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        match msg {
            AmtMessage::MulticastData { ip_packet } => {
                self.inner
                    .handle_data(ip_packet)
                    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))
            }
            _ => Err(JsValue::from_str("Expected MulticastData message")),
        }
    }

    /// Add multicast group membership
    ///
    /// @param group - Multicast group address
    /// @param source - Optional source address for SSM (null for ASM)
    /// @param timestamp - Unix timestamp in milliseconds
    #[wasm_bindgen(js_name = addGroup)]
    pub fn add_group(&mut self, group: &str, source: Option<String>, timestamp: f64) -> Result<(), JsValue> {
        let group_addr: IpAddr = group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid group address: {}", e)))?;

        let source_addr = if let Some(s) = source {
            Some(s.parse()
                .map_err(|e| JsValue::from_str(&format!("Invalid source address: {}", e)))?)
        } else {
            None
        };

        self.inner.add_group(group_addr, source_addr, timestamp as u64);
        Ok(())
    }

    /// Send teardown message
    ///
    /// Returns encoded Teardown message as Uint8Array
    #[wasm_bindgen(js_name = sendTeardown)]
    pub fn send_teardown(&mut self) -> Result<Vec<u8>, JsValue> {
        let msg = self.inner
            .send_teardown()
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        Ok(msg.encode())
    }

    /// Reset gateway to idle state
    #[wasm_bindgen]
    pub fn reset(&mut self) {
        self.inner.reset();
    }
}

/// IGMPv3 Report Builder for WASM
#[wasm_bindgen]
pub struct JsIgmpReport {
    inner: IgmpV3Report,
}

#[wasm_bindgen]
impl JsIgmpReport {
    /// Create new IGMP report
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsIgmpReport {
        JsIgmpReport {
            inner: IgmpV3Report::new(),
        }
    }

    /// Add SSM (source-specific) join record
    ///
    /// @param group - Multicast group address (e.g., "232.0.0.1")
    /// @param source - Source address (e.g., "69.25.95.10")
    #[wasm_bindgen(js_name = addSsmJoin)]
    pub fn add_ssm_join(&mut self, group: &str, source: &str) -> Result<(), JsValue> {
        let group_addr: Ipv4Addr = group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid group address: {}", e)))?;

        let source_addr: Ipv4Addr = source
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid source address: {}", e)))?;

        self.inner.add_record(IgmpRecord::ssm_join(group_addr, source_addr));
        Ok(())
    }

    /// Add ASM (any-source) join record
    ///
    /// @param group - Multicast group address (e.g., "224.0.0.1")
    #[wasm_bindgen(js_name = addAsmJoin)]
    pub fn add_asm_join(&mut self, group: &str) -> Result<(), JsValue> {
        let group_addr: Ipv4Addr = group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid group address: {}", e)))?;

        self.inner.add_record(IgmpRecord::asm_join(group_addr));
        Ok(())
    }

    /// Encode report to bytes (raw IGMP, no IP header)
    ///
    /// Returns Uint8Array ready for IP encapsulation
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode()
    }

    /// Encode report with IPv4 encapsulation for AMT Membership Update
    ///
    /// AMT Membership Update (RFC 7450) requires the IGMP report to be
    /// encapsulated in an IPv4 packet. This method creates the full
    /// IPv4+IGMP packet ready to be included in the AMT Membership Update.
    ///
    /// For SSM, go-amt uses the multicast source as IPv4 SrcIP and
    /// the multicast group as IPv4 DstIP.
    ///
    /// @param multicast_source - The multicast source address (sender)
    /// @param multicast_group - The multicast group address
    /// @returns Uint8Array containing IPv4 header + IGMP report
    #[wasm_bindgen(js_name = encodeWithIp)]
    pub fn encode_with_ip(&self, multicast_source: &str, multicast_group: &str) -> Result<Vec<u8>, JsValue> {
        use std::net::Ipv4Addr;

        let src_addr: Ipv4Addr = multicast_source.parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid multicast source: {}", e)))?;

        let dst_addr: Ipv4Addr = multicast_group.parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid multicast group: {}", e)))?;

        Ok(self.inner.encode_with_ip(src_addr, dst_addr))
    }
}

/// MLDv2 Report Builder for WASM
#[wasm_bindgen]
pub struct JsMldReport {
    inner: MldV2Report,
}

#[wasm_bindgen]
impl JsMldReport {
    /// Create new MLD report
    #[wasm_bindgen(constructor)]
    pub fn new() -> JsMldReport {
        JsMldReport {
            inner: MldV2Report::new(),
        }
    }

    /// Add SSM (source-specific) join record
    ///
    /// @param group - Multicast group address (e.g., "ff3e::1234:5678")
    /// @param source - Source address (e.g., "2001:db8::1")
    #[wasm_bindgen(js_name = addSsmJoin)]
    pub fn add_ssm_join(&mut self, group: &str, source: &str) -> Result<(), JsValue> {
        let group_addr: Ipv6Addr = group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid group address: {}", e)))?;

        let source_addr: Ipv6Addr = source
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid source address: {}", e)))?;

        self.inner.add_record(MldRecord::ssm_join(group_addr, source_addr));
        Ok(())
    }

    /// Add ASM (any-source) join record
    ///
    /// @param group - Multicast group address (e.g., "ff05::1")
    #[wasm_bindgen(js_name = addAsmJoin)]
    pub fn add_asm_join(&mut self, group: &str) -> Result<(), JsValue> {
        let group_addr: Ipv6Addr = group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid group address: {}", e)))?;

        self.inner.add_record(MldRecord::asm_join(group_addr));
        Ok(())
    }

    /// Encode report to bytes
    ///
    /// Returns Uint8Array (ICMPv6 payload)
    #[wasm_bindgen]
    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode()
    }
}

/// DRIAD query builder and DNS parser for WASM (RFC 8777)
///
/// DRIAD discovers AMT relays based on the **source address**, not the group.
/// The source network operator configures DNS records for their source IPs.
///
/// Provides DNS wire-format query building and response parsing so that
/// the caller (JS/IWA) only needs to handle UDP transport.
#[wasm_bindgen]
pub struct JsDriad;

#[wasm_bindgen]
impl JsDriad {
    /// Build DRIAD query name for multicast source address (RFC 8777)
    ///
    /// @param source - Multicast source address (IPv4 or IPv6) - NOT the group!
    /// @returns DNS query name (e.g., "10.95.25.69.in-addr.arpa" for source 69.25.95.10)
    #[wasm_bindgen(js_name = buildQuery)]
    pub fn build_query(source: &str) -> Result<String, JsValue> {
        let addr: IpAddr = source
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid IP address: {}", e)))?;

        Ok(DriadResolver::build_query(addr))
    }

    /// Build a DNS wire-format query packet for AMTRELAY (TYPE260) lookup.
    ///
    /// Returns a complete DNS query packet (RFC 1035) as Uint8Array, ready to
    /// send over UDP to a DNS resolver (e.g., 8.8.8.8:53).
    ///
    /// @param source - Multicast source IP address
    /// @param transaction_id - DNS transaction ID for matching responses
    /// @returns Uint8Array containing the DNS query packet
    #[wasm_bindgen(js_name = buildDnsQuery)]
    pub fn build_dns_query(source: &str, transaction_id: u16) -> Result<Vec<u8>, JsValue> {
        let addr: IpAddr = source
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid IP address: {}", e)))?;

        Ok(DriadResolver::build_dns_query(addr, transaction_id))
    }

    /// Parse a DNS response packet and extract the AMT relay address.
    ///
    /// Looks for TYPE260 (AMTRELAY) answer records and returns the relay
    /// address from the first valid record. May return an IP address string
    /// (for type 1/2) or a DNS hostname (for type 3) that needs further resolution.
    ///
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns Relay address as string (IP or hostname), or null if no AMTRELAY record found
    #[wasm_bindgen(js_name = parseDnsResponse)]
    pub fn parse_dns_response(data: &[u8]) -> Option<String> {
        DriadResolver::parse_dns_response(data).map(|addr| addr.to_string())
    }

    /// Build a DNS A record query for a hostname.
    ///
    /// Used to resolve DRIAD type=3 DNS name relays to IPv4 addresses.
    ///
    /// @param hostname - The hostname to resolve (e.g., "sfo12.bcast.id")
    /// @param transaction_id - DNS transaction ID for matching responses
    /// @returns Uint8Array containing the DNS A query packet
    #[wasm_bindgen(js_name = buildDnsAQuery)]
    pub fn build_dns_a_query(hostname: &str, transaction_id: u16) -> Vec<u8> {
        DriadResolver::build_dns_a_query(hostname, transaction_id)
    }

    /// Parse a DNS A record response and extract the first IPv4 address.
    ///
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns IPv4 address as string, or null if no A record found
    #[wasm_bindgen(js_name = parseDnsAResponse)]
    pub fn parse_dns_a_response(data: &[u8]) -> Option<String> {
        DriadResolver::parse_dns_a_response(data).map(|addr| addr.to_string())
    }
}

/// Decode AMT message from bytes
///
/// @param data - Raw message bytes
/// @returns Message type as string ("RelayDiscovery", "RelayAdvertisement", etc.)
#[wasm_bindgen(js_name = decodeAmtMessage)]
pub fn decode_amt_message(data: &[u8]) -> Result<String, JsValue> {
    let msg = AmtMessage::decode(data)
        .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

    let msg_type = match msg {
        AmtMessage::RelayDiscovery { .. } => "RelayDiscovery",
        AmtMessage::RelayAdvertisement { .. } => "RelayAdvertisement",
        AmtMessage::Request { .. } => "Request",
        AmtMessage::MembershipQuery { .. } => "MembershipQuery",
        AmtMessage::MembershipUpdate { .. } => "MembershipUpdate",
        AmtMessage::MulticastData { .. } => "MulticastData",
        AmtMessage::Teardown { .. } => "Teardown",
    };

    Ok(msg_type.to_string())
}
