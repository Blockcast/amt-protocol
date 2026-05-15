//! Native DRIAD resolver — UDP:53 to system resolver(s).

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::driad::{DriadRelayAddress, DriadResolver};

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_ATTEMPTS: usize = 3;

/// Resolve the AMT relay address for `source` via DRIAD over UDP:53.
///
/// Reads /etc/resolv.conf, sends an AMTRELAY query to each nameserver until
/// one answers (max 3 total attempts across the nameserver list).
pub async fn resolve_amt_relay(source: IpAddr) -> Result<IpAddr> {
    let resolv =
        std::fs::read_to_string("/etc/resolv.conf").context("reading /etc/resolv.conf")?;
    let nameservers = parse_resolv_conf(&resolv);
    if nameservers.is_empty() {
        return Err(anyhow!("no nameserver entries in /etc/resolv.conf"));
    }
    resolve_with_nameservers(source, &nameservers).await
}

pub async fn resolve_with_nameservers(source: IpAddr, nameservers: &[IpAddr]) -> Result<IpAddr> {
    let query = DriadResolver::build_dns_query(source, rand_id());
    let mut last_err: Option<anyhow::Error> = None;
    let mut attempts = 0;
    for ns in nameservers {
        if attempts >= MAX_ATTEMPTS {
            break;
        }
        attempts += 1;
        match try_one(*ns, &query).await {
            Ok(rdata) => match rdata {
                DriadRelayAddress::Ip(ip) => return Ok(ip),
                DriadRelayAddress::DnsName(name) => {
                    // Follow-up A/AAAA lookup — full impl in Task 4.4.
                    return follow_up_a_or_aaaa(&name, nameservers).await;
                }
            },
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("DRIAD: no usable nameserver answered")))
}

async fn try_one(ns: IpAddr, query: &[u8]) -> Result<DriadRelayAddress> {
    let bind = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.send_to(query, std::net::SocketAddr::new(ns, DNS_PORT))
        .await?;
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("DNS query to {} timed out", ns))??;
    DriadResolver::parse_dns_response(&buf[..n])
        .ok_or_else(|| anyhow!("DNS reply from {} had no AMTRELAY answer", ns))
}

// Stub — full impl in Task 4.4.
async fn follow_up_a_or_aaaa(_name: &str, _nameservers: &[IpAddr]) -> Result<IpAddr> {
    Err(anyhow!("AMTRELAY DnsName follow-up not yet implemented"))
}

fn rand_id() -> u16 {
    let mut buf = [0u8; 2];
    getrandom::getrandom(&mut buf).expect("getrandom for DNS txn id");
    u16::from_be_bytes(buf)
}

#[cfg(test)]
async fn try_one_at_port(ns: IpAddr, port: u16, query: &[u8]) -> Result<DriadRelayAddress> {
    let bind = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.send_to(query, std::net::SocketAddr::new(ns, port))
        .await?;
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("DNS query to {}:{} timed out", ns, port))??;
    DriadResolver::parse_dns_response(&buf[..n])
        .ok_or_else(|| anyhow!("DNS reply from {}:{} had no AMTRELAY answer", ns, port))
}

#[cfg(test)]
pub(crate) async fn resolve_v4_oneshot_for_test(
    source: IpAddr,
    nameserver: IpAddr,
    ns_port: u16,
) -> Result<IpAddr> {
    let query = DriadResolver::build_dns_query(source, rand_id());
    let rdata = try_one_at_port(nameserver, ns_port, &query).await?;
    match rdata {
        DriadRelayAddress::Ip(ip) => Ok(ip),
        DriadRelayAddress::DnsName(_) => Err(anyhow!("DnsName follow-up not in this helper")),
    }
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

    #[tokio::test(flavor = "current_thread")]
    async fn amtrelay_ipv4_record_resolves() {
        // Fake nameserver that echoes back the query as a response with one
        // AMTRELAY answer (type=1, relay=192.0.2.96). Byte layout mirrors
        // the existing `test_parse_dns_response_ipv4_relay` reference fixture
        // in driad.rs: RDLEN = 6 = precedence(1) + D+type(1) + IPv4(4).
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, src) = live.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] = 0x81; // QR=1, RD=1
            resp[3] = 0x80; // RA=1
            resp[6] = 0;
            resp[7] = 1; // ANCOUNT = 1
            resp.extend_from_slice(&[
                0xC0, 0x0C, // NAME: pointer to QNAME
                0x01, 0x04, // TYPE = 260 (AMTRELAY)
                0x00, 0x01, // CLASS = IN
                0x00, 0x00, 0x00, 0x3C, // TTL
                0x00, 0x06, // RDLENGTH = 6
                0,    // precedence
                0x01, // D=0, type=1 (IPv4)
                192, 0, 2, 96, // relay
            ]);
            live.send_to(&resp, src).await.unwrap();
        });

        let source: IpAddr = "10.0.0.1".parse().unwrap();
        let ns: IpAddr = live_addr.ip();
        let port = live_addr.port();
        let relay = resolve_v4_oneshot_for_test(source, ns, port)
            .await
            .unwrap();
        assert_eq!(relay, "192.0.2.96".parse::<IpAddr>().unwrap());
    }
}
