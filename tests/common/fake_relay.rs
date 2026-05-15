//! Loopback UDP fake AMT relay used by Tier-2 integration tests.
//!
//! Responds with canned Advertisement → Query → synthetic MulticastData.
//! Captures inbound datagram types so tests can assert on them.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use amt_protocol::messages::AmtMessage;

#[derive(Debug, Default)]
pub struct CapturedTraffic {
    pub message_types: Vec<u8>,
}

pub struct FakeRelay {
    pub addr: SocketAddr,
    pub captured: Arc<Mutex<CapturedTraffic>>,
    sock: Arc<UdpSocket>,
}

impl FakeRelay {
    /// Bind a loopback socket on a free port. `family` is "v4" or "v6".
    pub async fn bind(family: &str) -> Self {
        let bind_addr = if family == "v6" { "[::1]:0" } else { "127.0.0.1:0" };
        let sock = UdpSocket::bind(bind_addr).await.expect("bind fake relay");
        let addr = sock.local_addr().unwrap();
        Self {
            addr,
            captured: Arc::new(Mutex::new(CapturedTraffic::default())),
            sock: Arc::new(sock),
        }
    }

    /// Start the fake relay loop. Spawns a tokio task that:
    /// - Responds to RelayDiscovery with a matching RelayAdvertisement (relay = self.addr.ip())
    /// - Responds to Request with a MembershipQuery
    /// - After Update, emits one MulticastData with a synthetic v4+UDP packet
    pub fn spawn(&self, inner_payload: Vec<u8>) {
        let sock = self.sock.clone();
        let captured = self.captured.clone();
        let relay_ip = self.addr.ip();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            let mut req_nonce: u32 = 0;
            let mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let bytes = &buf[..n];
                if bytes.is_empty() { continue; }
                captured.lock().await.message_types.push(bytes[0]);
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
                        req_nonce = request_nonce;
                        let query = AmtMessage::MembershipQuery {
                            request_nonce,
                            response_mac: mac,
                            query_data: vec![0x11; 12],
                        };
                        let _ = sock.send_to(&query.encode(), src).await;
                    }
                    AmtMessage::MembershipUpdate { request_nonce, response_mac, .. } => {
                        if request_nonce == req_nonce && response_mac == mac {
                            let data = AmtMessage::MulticastData { ip_packet: inner_payload.clone() };
                            let _ = sock.send_to(&data.encode(), src).await;
                        }
                    }
                    AmtMessage::Teardown { .. } => {
                        // Just record — loop continues so we can capture more if needed.
                    }
                    _ => {}
                }
            }
        });
    }
}

/// Build a synthetic IPv6+UDP inner packet for fake MulticastData (v6 tests).
pub fn synth_v6_udp(src: [u8; 16], dst: [u8; 16], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x60, 0x00, 0x00, 0x00];  // version=6, traffic class+flow label=0
    let payload_len: u16 = 8 + payload.len() as u16;
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.push(17);   // Next Header = UDP
    buf.push(64);   // hop limit
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&sp.to_be_bytes());
    buf.extend_from_slice(&dp.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf.extend_from_slice(&udp_len.to_be_bytes());
    buf.extend_from_slice(&[0, 0]);  // udp checksum (unused)
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
