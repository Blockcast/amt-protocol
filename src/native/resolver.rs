//! Native DRIAD resolver: UDP:53 to the system resolver(s), retried over TCP
//! when a reply comes back truncated.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::driad::{DriadAddress, DriadCandidate, DriadRelayAddress, DriadResolver};

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_ATTEMPTS: usize = 3;
/// Largest DNS message: TCP frames each one with a 16-bit length (RFC 1035
/// §4.2.2), and no UDP datagram is larger.
const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

/// Resolve the AMT relay address for `source` via DRIAD over UDP:53: the first
/// of [`resolve_amt_relay_candidates`].
///
/// Reads /etc/resolv.conf, sends an AMTRELAY query to each nameserver until
/// one answers (max 3 total attempts across the nameserver list).
pub async fn resolve_amt_relay(source: IpAddr) -> Result<IpAddr> {
    first_relay(resolve_amt_relay_candidates(source).await?)
}

/// [`resolve_amt_relay`] against the given nameservers, on port 53.
pub async fn resolve_with_nameservers(source: IpAddr, nameservers: &[IpAddr]) -> Result<IpAddr> {
    let via: Vec<SocketAddr> = nameservers
        .iter()
        .map(|ip| SocketAddr::new(*ip, DNS_PORT))
        .collect();
    first_relay(resolve_candidates_via(source, &via).await?)
}

/// Every relay DRIAD offers for `source`, as addresses, in the order a gateway
/// should try them. See [`resolve_candidates_via`].
pub async fn resolve_amt_relay_candidates(source: IpAddr) -> Result<Vec<DriadCandidate>> {
    resolve_candidates_via(source, &system_nameservers()?).await
}

/// Every relay DRIAD offers for `source`, asking `nameservers` in turn (at most
/// three).
///
/// - The query carries an EDNS(0) OPT record, so a resolver can answer with
///   every relay; a reply that still comes back truncated (TC=1) is re-asked
///   over TCP.
/// - Only addresses in `source`'s family are kept: a gateway tunnels one family,
///   and its source, group and relay must all share it.
/// - A type-3 relay is expanded to every address its name resolves to, each
///   inheriting the record's precedence and D-bit (RFC 8777 §4.2.4). A name
///   that does not resolve is skipped, like any unusable record (§4.2).
/// - The result is in [`DriadResolver::order_candidates`] order, with repeated
///   addresses dropped after their first, most preferred, position.
pub async fn resolve_candidates_via(
    source: IpAddr,
    nameservers: &[SocketAddr],
) -> Result<Vec<DriadCandidate>> {
    let query = DriadResolver::build_dns_query_edns(source, rand_id());
    let mut last_err: Option<anyhow::Error> = None;
    for ns in nameservers.iter().take(MAX_ATTEMPTS) {
        let reply = match exchange(*ns, &query).await {
            Ok(reply) => reply,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        // Bind the reply to the query we sent. UDP:53 is unauthenticated, so an
        // off-path attacker who guesses the 5-tuple can race a forged AMTRELAY
        // answer and point relay discovery wherever it likes.
        let records = DriadResolver::parse_dns_response_candidates_validated(&query, &reply);
        if records.is_empty() {
            last_err = Some(anyhow!("DNS reply from {ns} had no valid AMTRELAY answer"));
            continue;
        }
        let mut candidates = Vec::new();
        for record in records {
            match &record.relay {
                DriadRelayAddress::Ip(ip) => {
                    if ip.is_ipv4() == source.is_ipv4() {
                        candidates.push(record);
                    }
                }
                DriadRelayAddress::DnsName(name) => {
                    match resolve_addresses(name, source, nameservers).await {
                        Ok(addresses) => candidates.extend(record.expand(&addresses)),
                        Err(e) => tracing::warn!(
                            target: "amt",
                            relay = %name,
                            error = %e,
                            "AMTRELAY relay name did not resolve; trying the other records"
                        ),
                    }
                }
            }
        }
        if candidates.is_empty() {
            last_err = Some(anyhow!(
                "no AMTRELAY answer from {ns} resolved to a relay in {source}'s address family"
            ));
            continue;
        }
        DriadResolver::order_candidates(&mut candidates);
        let mut seen = Vec::with_capacity(candidates.len());
        candidates.retain(|c| {
            let fresh = !seen.contains(&c.relay);
            if fresh {
                seen.push(c.relay.clone());
            }
            fresh
        });
        return Ok(candidates);
    }
    Err(last_err.unwrap_or_else(|| anyhow!("DRIAD: no usable nameserver answered")))
}

/// The addresses `name` resolves to in `source`'s family, from the first
/// nameserver that answers.
async fn resolve_addresses(
    name: &str,
    source: IpAddr,
    nameservers: &[SocketAddr],
) -> Result<Vec<DriadAddress>> {
    let query = if source.is_ipv4() {
        DriadResolver::build_dns_a_query_edns(name, rand_id())
    } else {
        DriadResolver::build_dns_aaaa_query_edns(name, rand_id())
    };
    let mut last_err: Option<anyhow::Error> = None;
    for ns in nameservers.iter().take(MAX_ATTEMPTS) {
        match exchange(*ns, &query).await {
            Ok(reply) => {
                // Validate transaction ID + question against the exact query
                // bytes BEFORE trusting any answer: a stray, spoofed or stale
                // packet must not be accepted as the relay.
                let addresses = DriadResolver::parse_dns_addresses_validated(&query, &reply);
                if !addresses.is_empty() {
                    return Ok(addresses);
                }
                last_err = Some(anyhow!("{ns} returned no address for {name}"));
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("{name} did not resolve via any nameserver")))
}

/// Send `query` to `ns` over UDP and return the reply. A reply that binds to
/// the query with TC=1 is re-asked over TCP (RFC 7766 §5), whose answer is
/// returned instead.
async fn exchange(ns: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let bind = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    // Connected, so the kernel drops datagrams from any other source.
    sock.connect(ns).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; MAX_DNS_MESSAGE];
    let n = timeout(QUERY_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("DNS query to {ns} timed out"))??;
    buf.truncate(n);
    if !DriadResolver::is_truncated_reply(query, &buf) {
        return Ok(buf);
    }
    tracing::debug!(target: "amt", nameserver = %ns, "truncated DNS reply; retrying over TCP");
    timeout(QUERY_TIMEOUT, exchange_tcp(ns, query))
        .await
        .map_err(|_| anyhow!("DNS query to {ns} over TCP timed out"))?
}

/// One query over TCP, each message framed by a two-octet length (RFC 1035
/// §4.2.2).
async fn exchange_tcp(ns: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(ns).await?;
    let len = u16::try_from(query.len()).context("DNS query longer than a TCP frame")?;
    stream.write_u16(len).await?;
    stream.write_all(query).await?;
    let len = stream.read_u16().await? as usize;
    let mut reply = vec![0u8; len];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// The first relay of an ordered candidate list. Every native candidate is an
/// address: type-3 names are expanded before ordering.
fn first_relay(candidates: Vec<DriadCandidate>) -> Result<IpAddr> {
    candidates
        .into_iter()
        .find_map(|c| match c.relay {
            DriadRelayAddress::Ip(ip) => Some(ip),
            DriadRelayAddress::DnsName(_) => None,
        })
        .ok_or_else(|| anyhow!("DRIAD returned no relay address"))
}

/// The nameservers in /etc/resolv.conf, on port 53.
pub fn system_nameservers() -> Result<Vec<SocketAddr>> {
    let resolv = std::fs::read_to_string("/etc/resolv.conf").context("reading /etc/resolv.conf")?;
    let nameservers = parse_resolv_conf(&resolv);
    if nameservers.is_empty() {
        return Err(anyhow!("no nameserver entries in /etc/resolv.conf"));
    }
    Ok(nameservers
        .into_iter()
        .map(|ip| SocketAddr::new(ip, DNS_PORT))
        .collect())
}

fn rand_id() -> u16 {
    let mut buf = [0u8; 2];
    getrandom::getrandom(&mut buf).expect("getrandom for DNS txn id");
    u16::from_be_bytes(buf)
}

/// Parse the `nameserver` lines of an /etc/resolv.conf-style string.
/// Returns IPs in declaration order; ignores comments + unknown directives.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        let mut parts = trimmed.split_ascii_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(addr) = parts.next() {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    out.push(ip);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn parse_resolv_conf_picks_in_order() {
        let txt = "
# comment
search example.
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2606:4700:4700::1111
";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns.len(), 3);
        assert_eq!(ns[0], "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(ns[1], "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(ns[2], "2606:4700:4700::1111".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_resolv_conf_skips_comments_and_unknown_directives() {
        let txt = "options edns0\noptions rotate\n; another comment\nnameserver 10.0.0.1\n";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_resolv_conf_invalid_ip_silently_skipped() {
        let txt = "nameserver not-an-ip\nnameserver 8.8.4.4\n";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns, vec!["8.8.4.4".parse::<IpAddr>().unwrap()]);
    }

    /// A reply echoing `query`'s header and question (not its OPT record),
    /// then `answers`, each owned by the question name.
    fn reply(query: &[u8], answers: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut end = 12;
        while query[end] != 0 {
            end += 1 + query[end] as usize;
        }
        let mut resp = query[..end + 5].to_vec();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1
        resp[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        resp[8..12].fill(0);
        for (rtype, ttl, rdata) in answers {
            resp.extend_from_slice(&[0xC0, 0x0C]);
            resp.extend_from_slice(&rtype.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(rdata);
        }
        resp
    }

    fn qtype(query: &[u8]) -> u16 {
        let mut end = 12;
        while query[end] != 0 {
            end += 1 + query[end] as usize;
        }
        u16::from_be_bytes([query[end + 1], query[end + 2]])
    }

    #[tokio::test(flavor = "current_thread")]
    async fn amtrelay_ipv4_record_resolves() {
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns = live.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, src) = live.recv_from(&mut buf).await.unwrap();
            let resp = reply(&buf[..n], &[(260, 60, vec![0, 0x01, 192, 0, 2, 96])]);
            live.send_to(&resp, src).await.unwrap();
        });

        let source: IpAddr = "10.0.0.1".parse().unwrap();
        let candidates = resolve_candidates_via(source, &[ns]).await.unwrap();
        assert_eq!(
            first_relay(candidates).unwrap(),
            "192.0.2.96".parse::<IpAddr>().unwrap()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn type3_relay_expands_in_the_source_family_only() {
        // A v4 source: the type-3 name is resolved with an A query only, its two
        // addresses inherit precedence and D-bit, and the v6 literal is dropped.
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns = live.local_addr().unwrap();
        let qtypes = Arc::new(Mutex::new(Vec::new()));
        let seen = qtypes.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let (n, src) = live.recv_from(&mut buf).await.unwrap();
                let query = buf[..n].to_vec();
                seen.lock().unwrap().push(qtype(&query));
                let answers = match qtype(&query) {
                    260 => {
                        let mut named = vec![5, 0x83]; // precedence 5, D=1, type 3
                        named.extend_from_slice(b"\x05relay\x07example\x00");
                        let mut v6 = vec![1, 0x02];
                        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
                        vec![(260, 600, named), (260, 600, v6)]
                    }
                    1 => vec![(1, 30, vec![192, 0, 2, 1]), (1, 900, vec![192, 0, 2, 2])],
                    _ => vec![],
                };
                live.send_to(&reply(&query, &answers), src).await.unwrap();
            }
        });

        let source: IpAddr = "10.0.0.1".parse().unwrap();
        let mut candidates = resolve_candidates_via(source, &[ns]).await.unwrap();
        candidates.sort_by_key(|c| c.relay.to_string());
        let summary: Vec<_> = candidates
            .iter()
            .map(|c| {
                (
                    c.relay.to_string(),
                    c.precedence,
                    c.discovery_optional,
                    c.ttl,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("192.0.2.1".to_string(), 5, true, 30),
                ("192.0.2.2".to_string(), 5, true, 600),
            ]
        );
        assert_eq!(
            *qtypes.lock().unwrap(),
            [260, 1],
            "no AAAA query for a v4 source"
        );
    }
}
