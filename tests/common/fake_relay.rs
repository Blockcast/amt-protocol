//! Loopback UDP fake AMT relay used by Tier-2 integration tests.
//!
//! Responds with canned Advertisement → Query → synthetic MulticastData.
//! Captures inbound datagram types so tests can assert on them.
//!
//! Membership Queries and Teardowns are built and parsed here straight from
//! RFC 7450's figures, not through this crate's codec, so the relay is an
//! independent check on the gateway's wire format. It authenticates a Teardown
//! the way §5.3.3.5 requires before acting on it. Counting type bytes alone
//! once let a 12-byte Teardown that no relay could parse pass as sent.

use amt_protocol::messages::AmtMessage;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};

/// Gateway Port Number (2 bytes) + Gateway IP Address (16 bytes), RFC 7450
/// §5.1.4.9.
const GATEWAY_ADDRESS_FIELDS_LEN: usize = 18;
/// Where the four IPv4 octets of an IPv4-compatible Gateway IP Address start:
/// after the port and 96 zero bits (§5.1.4.9.2).
const IPV4_COMPATIBLE_OCTETS_AT: usize = 2 + 12;
/// Type, Reserved, Response MAC, Request Nonce, then the Gateway Address
/// fields (§5.1.7, Figure 17).
const TEARDOWN_LEN: usize = 12 + GATEWAY_ADDRESS_FIELDS_LEN;
/// G flag in the second byte of a Membership Query (§5.1.4.5, Figure 14).
const QUERY_G_FLAG: u8 = 0x01;

type GatewayAddressFields = [u8; GATEWAY_ADDRESS_FIELDS_LEN];

#[derive(Debug, Default)]
pub struct CapturedTraffic {
    pub message_types: Vec<u8>,
    /// Tunnel endpoints torn down by a Teardown that parsed as RFC 7450
    /// §5.1.7 and carried the nonce, MAC and Gateway Address fields this relay
    /// issued for that endpoint -- the checks a real relay makes (§5.3.3.5).
    pub authenticated_teardowns: Vec<SocketAddr>,
}

/// Whether the relay supports the optional Teardown procedure, which it
/// advertises by setting the G flag on its Membership Queries (§5.1.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownSupport {
    Supported,
    Unsupported,
}

pub struct FakeRelay {
    pub addr: SocketAddr,
    pub captured: Arc<Mutex<CapturedTraffic>>,
    /// Signalled each time a Teardown is authenticated, after it has been
    /// recorded in `captured` (and so after every datagram received before it).
    pub teardown_authenticated: Arc<Notify>,
    sock: Arc<UdpSocket>,
}

/// §5.1.4.9: the Gateway Address fields for a gateway endpoint, with an IPv4
/// address in the IPv4-compatible form (§5.1.4.9.2).
fn gateway_address_fields(endpoint: SocketAddr) -> GatewayAddressFields {
    let mut fields = [0u8; GATEWAY_ADDRESS_FIELDS_LEN];
    fields[..2].copy_from_slice(&endpoint.port().to_be_bytes());
    match endpoint.ip() {
        IpAddr::V4(v4) => fields[IPV4_COMPATIBLE_OCTETS_AT..].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => fields[2..].copy_from_slice(&v6.octets()),
    }
    fields
}

/// Stand-in for the relay's keyed digest of (gateway endpoint, nonce)
/// (§5.3.5). It differs per endpoint, so a Teardown naming any endpoint but
/// the tunnel's fails authentication here as it would at a real relay.
fn response_mac(gateway: &GatewayAddressFields, nonce: u32) -> [u8; 6] {
    let mut hasher = DefaultHasher::new();
    gateway.hash(&mut hasher);
    nonce.hash(&mut hasher);
    let digest = hasher.finish().to_be_bytes();
    [
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    ]
}

/// §5.1.4, Figure 14. With `gateway` set, the G flag is raised and the
/// Gateway Address fields follow the encapsulated query.
fn membership_query(
    nonce: u32,
    mac: [u8; 6],
    query: &[u8],
    gateway: Option<GatewayAddressFields>,
) -> Vec<u8> {
    let mut wire = vec![0x04, gateway.map_or(0, |_| QUERY_G_FLAG)];
    wire.extend_from_slice(&mac);
    wire.extend_from_slice(&nonce.to_be_bytes());
    wire.extend_from_slice(query);
    if let Some(fields) = gateway {
        wire.extend_from_slice(&fields);
    }
    wire
}

/// §5.1.7, Figure 17: (Request Nonce, Response MAC, Gateway Address fields),
/// or `None` for anything that is not a well-formed Teardown.
fn parse_teardown(wire: &[u8]) -> Option<(u32, [u8; 6], GatewayAddressFields)> {
    if wire.len() != TEARDOWN_LEN || wire[0] != 0x07 {
        return None;
    }
    let mac = wire[2..8].try_into().ok()?;
    let nonce = u32::from_be_bytes(wire[8..12].try_into().ok()?);
    let fields = wire[12..].try_into().ok()?;
    Some((nonce, mac, fields))
}

impl FakeRelay {
    /// Bind a loopback socket on a free port. `family` is "v4" or "v6".
    pub async fn bind(family: &str) -> Self {
        let bind_addr = if family == "v6" {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let sock = UdpSocket::bind(bind_addr).await.expect("bind fake relay");
        let addr = sock.local_addr().unwrap();
        Self {
            addr,
            captured: Arc::new(Mutex::new(CapturedTraffic::default())),
            teardown_authenticated: Arc::new(Notify::new()),
            sock: Arc::new(sock),
        }
    }

    /// Start the fake relay loop. Spawns a tokio task that:
    /// - Responds to RelayDiscovery with a matching RelayAdvertisement (relay = self.addr.ip())
    /// - Responds to Request with a MembershipQuery
    /// - After Update, emits one MulticastData with a synthetic v4+UDP packet
    pub fn spawn(&self, inner_payload: Vec<u8>) {
        self.spawn_advertising(inner_payload, None);
    }

    /// As `spawn`, for a relay that does not support Teardown: its Membership
    /// Queries leave the G flag unset and carry no Gateway Address fields.
    #[allow(dead_code)]
    pub fn spawn_without_teardown_support(&self, inner_payload: Vec<u8>) {
        self.spawn_with(inner_payload, None, TeardownSupport::Unsupported);
    }

    /// As `spawn`, but advertises `advertise` as the relay address instead of
    /// this relay's own. Used to force a gateway-side `send_to` failure: the
    /// gateway redirects all later traffic to the advertised address, so
    /// advertising a broadcast address makes the next send fail EACCES on a
    /// socket without SO_BROADCAST. That is the only way to drive the runtime's
    /// fatal-socket-error path from outside the process.
    pub fn spawn_advertising(&self, inner_payload: Vec<u8>, advertise: Option<IpAddr>) {
        self.spawn_with(inner_payload, advertise, TeardownSupport::Supported);
    }

    fn spawn_with(
        &self,
        inner_payload: Vec<u8>,
        advertise: Option<IpAddr>,
        teardown: TeardownSupport,
    ) {
        let sock = self.sock.clone();
        let captured = self.captured.clone();
        let teardown_authenticated = self.teardown_authenticated.clone();
        let relay_ip = advertise.unwrap_or_else(|| self.addr.ip());
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            // Keyed by the gateway's ephemeral source address, NOT a single
            // shared slot: `--tunnels N` puts N gateways on this one relay
            // socket concurrently, and a shared nonce means gateway B's
            // Request invalidates gateway A's in-flight Update.
            let mut req_nonce: HashMap<SocketAddr, u32> = HashMap::new();
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let bytes = &buf[..n];
                if bytes.is_empty() {
                    continue;
                }
                captured.lock().await.message_types.push(bytes[0]);
                if let Some((nonce, mac, fields)) = parse_teardown(bytes) {
                    // A Teardown is authenticated against the endpoint it
                    // names, not the datagram's source (§5.3.3.5). A relay
                    // that never sent the fields cannot check one at all.
                    let named = req_nonce.iter().find_map(|(endpoint, issued)| {
                        (gateway_address_fields(*endpoint) == fields && *issued == nonce)
                            .then_some(*endpoint)
                    });
                    if let Some(endpoint) = named {
                        if teardown == TeardownSupport::Supported
                            && mac == response_mac(&fields, nonce)
                        {
                            req_nonce.remove(&endpoint);
                            captured.lock().await.authenticated_teardowns.push(endpoint);
                            teardown_authenticated.notify_one();
                        }
                    }
                    continue;
                }
                let msg = match AmtMessage::decode(bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match msg {
                    AmtMessage::RelayDiscovery { nonce } => {
                        let advert = AmtMessage::RelayAdvertisement {
                            nonce,
                            relay_address: relay_ip,
                        };
                        let _ = sock.send_to(&advert.encode(), src).await;
                    }
                    AmtMessage::Request { request_nonce, .. } => {
                        req_nonce.insert(src, request_nonce);
                        let observed = gateway_address_fields(src);
                        let query = membership_query(
                            request_nonce,
                            response_mac(&observed, request_nonce),
                            &[0x11; 12],
                            (teardown == TeardownSupport::Supported).then_some(observed),
                        );
                        let _ = sock.send_to(&query, src).await;
                    }
                    // An Update is authenticated against the datagram's own
                    // source (§5.3.3.4).
                    AmtMessage::MembershipUpdate {
                        request_nonce,
                        response_mac: mac,
                        ..
                    } if req_nonce.get(&src) == Some(&request_nonce)
                        && mac == response_mac(&gateway_address_fields(src), request_nonce) =>
                    {
                        let data = AmtMessage::MulticastData {
                            ip_packet: inner_payload.clone(),
                        };
                        let _ = sock.send_to(&data.encode(), src).await;
                    }
                    _ => {}
                }
            }
        });
    }
}

/// Build a synthetic IPv6+UDP inner packet for fake MulticastData (v6 tests).
#[allow(dead_code)]
pub fn synth_v6_udp(src: [u8; 16], dst: [u8; 16], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x60, 0x00, 0x00, 0x00]; // version=6, traffic class+flow label=0
    let payload_len: u16 = 8 + payload.len() as u16;
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.push(17); // Next Header = UDP
    buf.push(64); // hop limit
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&sp.to_be_bytes());
    buf.extend_from_slice(&dp.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf.extend_from_slice(&udp_len.to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // udp checksum (unused)
    buf.extend_from_slice(payload);
    buf
}

/// Build a synthetic IPv4+UDP inner packet for fake MulticastData.
pub fn synth_v4_udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
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
