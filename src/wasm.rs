//! WASM Bindings for AMT Protocol
//!
//! Exposes Rust AMT protocol implementation to JavaScript/TypeScript.

use crate::config::AmtConfig;
use crate::driad::{DriadAddress, DriadCandidate, DriadRelayAddress, DriadResolver};
use crate::gateway::{AmtGateway, GatewayState};
use crate::igmp::{IgmpRecord, IgmpV3Report};
use crate::messages::AmtMessage;
use crate::mld::{MldRecord, MldV2Report};
use crate::platform::wasm_platform::WasmPlatform;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

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
        keepalive_interval_secs: Option<u32>,
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
        let msg = self
            .inner
            .start_discovery()
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        Ok(msg.encode())
    }

    /// Handle Relay Advertisement response
    ///
    /// @param data - Raw message bytes
    #[wasm_bindgen(js_name = handleAdvertisement)]
    pub fn handle_advertisement(&mut self, data: &[u8]) -> Result<(), JsValue> {
        let msg = AmtMessage::decode(data).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        match msg {
            AmtMessage::RelayAdvertisement {
                nonce,
                relay_address,
            } => {
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
        let msg = self
            .inner
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
        let msg = AmtMessage::decode(data).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        match msg {
            AmtMessage::MembershipQuery {
                request_nonce,
                response_mac,
                query_data,
                gateway_address,
            } => {
                // Debug logging via platform
                web_sys::console::log_1(
                    &format!(
                        "[WASM handleQuery] Parsed nonce from packet: 0x{:08x}",
                        request_nonce
                    )
                    .into(),
                );

                self.inner
                    .handle_query(request_nonce, response_mac, query_data, gateway_address)
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
        let msg = self
            .inner
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
        let msg = AmtMessage::decode(data).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        match msg {
            AmtMessage::MulticastData { ip_packet } => self
                .inner
                .handle_data(ip_packet)
                .map_err(|e| JsValue::from_str(&format!("{:?}", e))),
            _ => Err(JsValue::from_str("Expected MulticastData message")),
        }
    }

    /// Add multicast group membership
    ///
    /// @param group - Multicast group address
    /// @param source - Optional source address for SSM (null for ASM)
    /// @param timestamp - Unix timestamp in milliseconds
    #[wasm_bindgen(js_name = addGroup)]
    pub fn add_group(
        &mut self,
        group: &str,
        source: Option<String>,
        timestamp: f64,
    ) -> Result<(), JsValue> {
        let group_addr: IpAddr = group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid group address: {}", e)))?;

        let source_addr = if let Some(s) = source {
            Some(
                s.parse()
                    .map_err(|e| JsValue::from_str(&format!("Invalid source address: {}", e)))?,
            )
        } else {
            None
        };

        self.inner
            .add_group(group_addr, source_addr, timestamp as u64);
        Ok(())
    }

    /// Send teardown message
    ///
    /// Returns encoded Teardown message as Uint8Array. Throws `NoGatewayAddress`
    /// when the relay's last Membership Query did not set the G flag: it does
    /// not support Teardown, so there is nothing to send (RFC 7450 §5.2.3.7).
    #[wasm_bindgen(js_name = sendTeardown)]
    pub fn send_teardown(&mut self) -> Result<Vec<u8>, JsValue> {
        let msg = self
            .inner
            .send_teardown()
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        Ok(msg.encode())
    }

    /// Teardown owed after a Membership Query that reported a new gateway
    /// endpoint
    ///
    /// Returns the encoded Teardown RFC 7450 §5.2.3.7.1 requires as a
    /// Uint8Array once the relay's Query reports a gateway endpoint other than
    /// the one the last Membership Update was sent from, or undefined when
    /// none is owed. Call after `handleQuery` and before the `sendUpdate`
    /// answering that Query, and send the Teardown to the relay first. The
    /// gateway state is unchanged.
    #[wasm_bindgen(js_name = rebindTeardown)]
    pub fn rebind_teardown(&self) -> Option<Vec<u8>> {
        self.inner.rebind_teardown().map(|msg| msg.encode())
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

impl Default for JsIgmpReport {
    fn default() -> Self {
        Self::new()
    }
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
    /// @param source - Source address (e.g., "192.0.2.10")
    #[wasm_bindgen(js_name = addSsmJoin)]
    pub fn add_ssm_join(&mut self, group: &str, source: &str) -> Result<(), JsValue> {
        let group_addr: Ipv4Addr = group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid group address: {}", e)))?;

        let source_addr: Ipv4Addr = source
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid source address: {}", e)))?;

        self.inner
            .add_record(IgmpRecord::ssm_join(group_addr, source_addr));
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
    pub fn encode_with_ip(
        &self,
        multicast_source: &str,
        multicast_group: &str,
    ) -> Result<Vec<u8>, JsValue> {
        use std::net::Ipv4Addr;

        let src_addr: Ipv4Addr = multicast_source
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid multicast source: {}", e)))?;

        let dst_addr: Ipv4Addr = multicast_group
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid multicast group: {}", e)))?;

        Ok(self.inner.encode_with_ip(src_addr, dst_addr))
    }
}

/// MLDv2 Report Builder for WASM
#[wasm_bindgen]
pub struct JsMldReport {
    inner: MldV2Report,
}

impl Default for JsMldReport {
    fn default() -> Self {
        Self::new()
    }
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

        self.inner
            .add_record(MldRecord::ssm_join(group_addr, source_addr));
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
    /// @returns DNS query name (e.g., "10.2.0.192.in-addr.arpa" for source 192.0.2.10)
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
    /// Considers every TYPE260 (AMTRELAY) answer whose owner name and class
    /// match the question echoed in the response, and returns the relay from
    /// the most-preferred usable record (RFC 8777 §4.2 precedence: lower wins,
    /// falling through when the best record is unusable). May return an IP
    /// address string (type 1/2) or a DNS hostname (type 3) needing further
    /// resolution.
    ///
    /// Prefer `parseDnsResponseValidated` whenever the caller still holds the
    /// query bytes: this entry point cannot check the transaction ID, so it
    /// cannot distinguish our answer from a forged one over an unauthenticated
    /// transport.
    ///
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns Relay address as string (IP or hostname), or null if no AMTRELAY record found
    #[wasm_bindgen(js_name = parseDnsResponse)]
    pub fn parse_dns_response(data: &[u8]) -> Option<String> {
        DriadResolver::parse_dns_response(data).map(|addr| addr.to_string())
    }

    /// Parse a DNS response, binding it to the query that produced it.
    ///
    /// Same selection as `parseDnsResponse`, plus a transaction-ID and question
    /// match against `query` — the packet returned by `buildDnsQuery`. Pass the
    /// query bytes through so the parser can reject a reply that answers a
    /// different question than the one asked.
    ///
    /// @param query - The DNS query packet that was sent (Uint8Array)
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns Relay address as string (IP or hostname), or null if the response is not a valid answer to `query`
    #[wasm_bindgen(js_name = parseDnsResponseValidated)]
    pub fn parse_dns_response_validated(query: &[u8], data: &[u8]) -> Option<String> {
        DriadResolver::parse_dns_response_validated(query, data).map(|addr| addr.to_string())
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

    /// Parse a DNS A response, binding it to the query that produced it.
    ///
    /// @param query - The DNS A query packet that was sent (Uint8Array)
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns IPv4 address as string, or null if the response is not a valid answer to `query`
    #[wasm_bindgen(js_name = parseDnsAResponseValidated)]
    pub fn parse_dns_a_response_validated(query: &[u8], data: &[u8]) -> Option<String> {
        DriadResolver::parse_dns_a_response_validated(query, data).map(|addr| addr.to_string())
    }

    /// Every usable AMTRELAY answer, in the order a gateway should try them:
    /// lower precedence first, and a random order among equal precedence
    /// (RFC 8777 §3.1.2), so walking the array fails over relay by relay.
    ///
    /// Each element is `{precedence, discoveryOptional, relayType, relay, ttl}`:
    /// `relayType` is the RFC 8777 §4.2.3 type (1 IPv4, 2 IPv6, 3 name), `relay`
    /// an IP string or a name, and `discoveryOptional` the D-bit (§4.2.2; when
    /// false, discovery MUST precede a Request). A type-3 relay stands for each
    /// address its name resolves to (`parseDnsAddressesValidated`), each with
    /// the record's precedence and D-bit and the smaller of the two TTLs
    /// (§4.2.4).
    ///
    /// Prefer `parseDnsResponseCandidatesValidated` whenever the query bytes
    /// are still at hand, for the same reason as `parseDnsResponseValidated`.
    ///
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns Array of candidates, empty when the response is rejected or has no usable record
    #[wasm_bindgen(js_name = parseDnsResponseCandidates)]
    pub fn parse_dns_response_candidates(data: &[u8]) -> js_sys::Array {
        let mut candidates = DriadResolver::parse_dns_response_candidates(data);
        DriadResolver::order_candidates(&mut candidates);
        candidates.iter().map(candidate_to_js).collect()
    }

    /// `parseDnsResponseCandidates`, binding the response to `query` (the
    /// packet `buildDnsQuery` returned): a reply with another transaction ID or
    /// question yields an empty array.
    ///
    /// @param query - The DNS query packet that was sent (Uint8Array)
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns Array of candidates, as for `parseDnsResponseCandidates`
    #[wasm_bindgen(js_name = parseDnsResponseCandidatesValidated)]
    pub fn parse_dns_response_candidates_validated(query: &[u8], data: &[u8]) -> js_sys::Array {
        let mut candidates = DriadResolver::parse_dns_response_candidates_validated(query, data);
        DriadResolver::order_candidates(&mut candidates);
        candidates.iter().map(candidate_to_js).collect()
    }

    /// Every address answer to an A or AAAA `query` (from `buildDnsAQuery` or a
    /// matching AAAA query), bound to that query, in wire order. Each element
    /// is `{address, ttl}`.
    ///
    /// @param query - The DNS A/AAAA query packet that was sent (Uint8Array)
    /// @param data - Raw DNS response bytes (Uint8Array)
    /// @returns Array of addresses, empty when the response is not a valid answer to `query`
    #[wasm_bindgen(js_name = parseDnsAddressesValidated)]
    pub fn parse_dns_addresses_validated(query: &[u8], data: &[u8]) -> js_sys::Array {
        DriadResolver::parse_dns_addresses_validated(query, data)
            .iter()
            .map(address_to_js)
            .collect()
    }
}

/// RFC 8777 §4.2.3 relay type of a decoded relay: 1 IPv4, 2 IPv6, 3 name.
fn relay_type(relay: &DriadRelayAddress) -> u8 {
    match relay {
        DriadRelayAddress::Ip(IpAddr::V4(_)) => 1,
        DriadRelayAddress::Ip(IpAddr::V6(_)) => 2,
        DriadRelayAddress::DnsName(_) => 3,
    }
}

/// Set `key` on a plain object this module just created, which cannot refuse.
fn set(object: &js_sys::Object, key: &str, value: JsValue) {
    js_sys::Reflect::set(object, &JsValue::from_str(key), &value)
        .expect("a fresh plain object accepts any property");
}

fn candidate_to_js(candidate: &DriadCandidate) -> js_sys::Object {
    let object = js_sys::Object::new();
    set(&object, "precedence", candidate.precedence.into());
    set(
        &object,
        "discoveryOptional",
        candidate.discovery_optional.into(),
    );
    set(&object, "relayType", relay_type(&candidate.relay).into());
    set(&object, "relay", candidate.relay.to_string().into());
    set(&object, "ttl", candidate.ttl.into());
    object
}

fn address_to_js(address: &DriadAddress) -> js_sys::Object {
    let object = js_sys::Object::new();
    set(&object, "address", address.addr.to_string().into());
    set(&object, "ttl", address.ttl.into());
    object
}

/// Decode AMT message from bytes
///
/// @param data - Raw message bytes
/// @returns Message type as string ("RelayDiscovery", "RelayAdvertisement", etc.)
#[wasm_bindgen(js_name = decodeAmtMessage)]
pub fn decode_amt_message(data: &[u8]) -> Result<String, JsValue> {
    let msg = AmtMessage::decode(data).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_type_is_the_rfc_8777_type_octet() {
        let v4 = DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let v6 = DriadRelayAddress::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let name = DriadRelayAddress::DnsName("sfo12.bcast.id".to_string());
        assert_eq!(
            [relay_type(&v4), relay_type(&v6), relay_type(&name)],
            [1, 2, 3]
        );
    }
}

/// The JS shape itself, which only a wasm32 build with a JS host can observe.
/// Run with `wasm-pack test --node` or `cargo test --target
/// wasm32-unknown-unknown` under `wasm-bindgen-test-runner`.
#[cfg(all(test, target_arch = "wasm32"))]
mod js_shape_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn get(object: &JsValue, key: &str) -> JsValue {
        js_sys::Reflect::get(object, &JsValue::from_str(key)).unwrap()
    }

    /// A reply to `query` carrying `answers` (type, TTL, RDATA) after the echoed
    /// header and question.
    fn reply(query: &[u8], answers: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = query.to_vec();
        out[2] = 0x81;
        out[3] = 0x80;
        out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (rtype, ttl, rdata) in answers {
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    #[wasm_bindgen_test]
    fn candidates_are_plain_objects_in_walk_order() {
        let query = DriadResolver::build_dns_query("69.25.95.10".parse().unwrap(), 0x1234);
        let mut named = vec![20, 0x03];
        named.extend_from_slice(b"\x05sfo12\x05bcast\x02id\x00");
        let data = reply(
            &query,
            &[(260, 3600, named), (260, 60, vec![10, 0x81, 192, 0, 2, 1])],
        );
        let candidates = JsDriad::parse_dns_response_candidates_validated(&query, &data);
        assert_eq!(candidates.length(), 2);
        let first = candidates.get(0);
        assert_eq!(get(&first, "precedence").as_f64(), Some(10.0));
        assert_eq!(get(&first, "discoveryOptional").as_bool(), Some(true));
        assert_eq!(get(&first, "relayType").as_f64(), Some(1.0));
        assert_eq!(
            get(&first, "relay").as_string().as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(get(&first, "ttl").as_f64(), Some(60.0));
        let second = candidates.get(1);
        assert_eq!(get(&second, "relayType").as_f64(), Some(3.0));
        assert_eq!(
            get(&second, "relay").as_string().as_deref(),
            Some("sfo12.bcast.id")
        );
        assert_eq!(get(&second, "discoveryOptional").as_bool(), Some(false));

        let mut wrong_txid = data.clone();
        wrong_txid[0] ^= 0xFF;
        assert_eq!(
            JsDriad::parse_dns_response_candidates_validated(&query, &wrong_txid).length(),
            0
        );
    }

    #[wasm_bindgen_test]
    fn addresses_are_plain_objects() {
        let query = DriadResolver::build_dns_a_query("sfo12.bcast.id", 0x1234);
        let data = reply(&query, &[(1, 30, vec![192, 0, 2, 7])]);
        let addresses = JsDriad::parse_dns_addresses_validated(&query, &data);
        assert_eq!(addresses.length(), 1);
        let first = addresses.get(0);
        assert_eq!(
            get(&first, "address").as_string().as_deref(),
            Some("192.0.2.7")
        );
        assert_eq!(get(&first, "ttl").as_f64(), Some(30.0));
    }
}
