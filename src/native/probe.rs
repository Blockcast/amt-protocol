//! The connection check a gateway runs before committing to a DRIAD relay.
//!
//! RFC 8777 §3.2.3: a connection to a relay is established when the gateway
//! receives "a valid Membership Query message" that does not have the L flag
//! set. The check is the handshake up to that Query: Relay Discovery, Relay
//! Advertisement, Request, Membership Query. It sends no Membership Update, so
//! the relay holds no tunnel state for it (RFC 7450 §5.3.3.5), and a relay that
//! fails it can be passed over for the next candidate.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::net::UdpSocket;
use tokio::time::{timeout_at, Instant};

use crate::messages::AmtMessage;
use crate::subscription::{DISCOVERY_TIMEOUT_MS, MAX_DISCOVERY_RETRIES, REQUEST_TIMEOUT_MS};

/// L flag in the second octet of a Membership Query: the relay is not
/// accepting Membership Updates from new gateways (RFC 7450 §5.1.4.3).
const QUERY_L_FLAG: u8 = 0x02;

/// Largest AMT control message this check reads: a Membership Query carrying a
/// full-size IGMP/MLD query fits one UDP datagram.
const MAX_DATAGRAM: usize = u16::MAX as usize;

/// Run the RFC 8777 §3.2.3 handshake against `relay` (its discovery address).
///
/// Discovery is retried on the gateway's own schedule, so a relay is passed
/// over only when the gateway itself would have given up on it: each attempt
/// waits `DISCOVERY_TIMEOUT_MS`, with `MAX_DISCOVERY_RETRIES` retries. The
/// Request then gets `REQUEST_TIMEOUT_MS`, as in the gateway.
pub async fn handshake(relay: SocketAddr) -> Result<()> {
    let bind = if relay.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    let mut buf = vec![0u8; MAX_DATAGRAM];

    let mut advertised = None;
    for _ in 0..=MAX_DISCOVERY_RETRIES {
        let nonce = random_u32();
        sock.send_to(&AmtMessage::RelayDiscovery { nonce }.encode(), relay)
            .await?;
        let deadline = Instant::now() + Duration::from_millis(DISCOVERY_TIMEOUT_MS);
        advertised = recv_matching(&sock, &mut buf, deadline, |_, msg| match msg {
            AmtMessage::RelayAdvertisement {
                nonce: n,
                relay_address,
            } if n == nonce => Some(relay_address),
            _ => None,
        })
        .await?;
        if advertised.is_some() {
            break;
        }
    }
    let advertised = advertised.ok_or_else(|| anyhow!("no Relay Advertisement from {relay}"))?;

    // RFC 7450 §5.2.3.4.2: the Request goes to the advertised relay address.
    let target = SocketAddr::new(advertised, relay.port());
    let request_nonce = random_u32();
    let request = AmtMessage::Request {
        request_nonce,
        // The relay family selects IGMPv3 or MLDv2, as in the gateway.
        p_flag: matches!(advertised, IpAddr::V6(_)),
    };
    sock.send_to(&request.encode(), target).await?;
    let deadline = Instant::now() + Duration::from_millis(REQUEST_TIMEOUT_MS);
    let limited = recv_matching(&sock, &mut buf, deadline, |raw, msg| match msg {
        AmtMessage::MembershipQuery {
            request_nonce: n, ..
        } if n == request_nonce => Some(raw[1] & QUERY_L_FLAG != 0),
        _ => None,
    })
    .await?
    .ok_or_else(|| anyhow!("no Membership Query from {target}"))?;
    if limited {
        bail!("{target} is not accepting new gateways (Membership Query L flag set)");
    }
    Ok(())
}

/// Read datagrams until `pick` accepts one or `deadline` passes (`None`).
/// Datagrams that do not decode or that `pick` rejects, such as a reply with a
/// stale nonce, are skipped.
async fn recv_matching<T>(
    sock: &UdpSocket,
    buf: &mut [u8],
    deadline: Instant,
    mut pick: impl FnMut(&[u8], AmtMessage) -> Option<T>,
) -> Result<Option<T>> {
    loop {
        let Ok(received) = timeout_at(deadline, sock.recv_from(buf)).await else {
            return Ok(None);
        };
        let (n, _) = received?;
        let raw = &buf[..n];
        if let Ok(msg) = AmtMessage::decode(raw) {
            if let Some(found) = pick(raw, msg) {
                return Ok(Some(found));
            }
        }
    }
}

fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("getrandom for AMT nonce");
    u32::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relay that answers Discovery and a Request, with the L flag on its
    /// Query set as given.
    async fn relay(limited: bool) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, src) = sock.recv_from(&mut buf).await.unwrap();
                let reply = match AmtMessage::decode(&buf[..n]).unwrap() {
                    AmtMessage::RelayDiscovery { nonce } => AmtMessage::RelayAdvertisement {
                        nonce,
                        relay_address: addr.ip(),
                    }
                    .encode(),
                    AmtMessage::Request { request_nonce, .. } => {
                        let mut query = AmtMessage::MembershipQuery {
                            request_nonce,
                            response_mac: [1; 6],
                            query_data: vec![0x11; 12],
                            gateway_address: None,
                        }
                        .encode();
                        if limited {
                            query[1] |= QUERY_L_FLAG;
                        }
                        query
                    }
                    other => panic!("unexpected {other:?}"),
                };
                sock.send_to(&reply, src).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handshake_accepts_a_query_without_the_l_flag() {
        handshake(relay(false).await).await.expect("connected");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handshake_refuses_a_relay_whose_query_sets_the_l_flag() {
        let err = handshake(relay(true).await).await.unwrap_err();
        assert!(err.to_string().contains("L flag"), "{err:#}");
    }
}
