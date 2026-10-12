//! DRIAD candidate lists (RFC 8777).
//!
//! Every acceptable AMTRELAY answer is kept, with its precedence, D-bit and TTL.
//! The list is ordered for failover, and a type-3 relay expands to the addresses
//! its name resolves to.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use amt_protocol::{DriadAddress, DriadCandidate, DriadRelayAddress, DriadResolver};

/// Source 69.25.95.10, so the question is 10.95.25.69.in-addr.arpa.
const SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(69, 25, 95, 10));
const TXID: u16 = 0x1234;
const TYPE_AMTRELAY: u16 = 260;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// RFC 8777 §4.2.2: the D-bit is the top bit of the second RDATA octet.
const D_BIT: u8 = 0x80;
/// RFC 1035 §4.1.1: QR, RD and RA set, RCODE 0.
const RESPONSE_FLAGS: [u8; 2] = [0x81, 0x80];
/// RFC 1035 §4.1.1: header length; a message's question starts here.
const HEADER_LEN: usize = 12;

fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// One answer record whose owner points back at the question name.
fn record(rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut out = vec![0xC0, HEADER_LEN as u8];
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn amtrelay(precedence: u8, d_bit: bool, relay_type: u8, relay: &[u8]) -> Vec<u8> {
    let mut out = vec![precedence, relay_type | if d_bit { D_BIT } else { 0 }];
    out.extend_from_slice(relay);
    out
}

/// A reply to `query`: its header and question echoed, then `answers`. Only
/// the question is echoed, since an EDNS query's OPT record belongs to the
/// query's additional section and would otherwise sit ahead of the answers.
fn reply(query: &[u8], txid: u16, answers: &[Vec<u8>]) -> Vec<u8> {
    let mut question_end = HEADER_LEN;
    while query[question_end] != 0 {
        question_end += 1 + query[question_end] as usize;
    }
    // Root label, then QTYPE and QCLASS.
    question_end += 1 + 4;
    let mut out = query[..question_end].to_vec();
    out[..2].copy_from_slice(&txid.to_be_bytes());
    out[2..4].copy_from_slice(&RESPONSE_FLAGS);
    out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    out[8..12].fill(0); // NSCOUNT, ARCOUNT
    for answer in answers {
        out.extend_from_slice(answer);
    }
    out
}

fn three_record_answers() -> Vec<Vec<u8>> {
    vec![
        record(
            TYPE_AMTRELAY,
            60,
            &amtrelay(20, true, 1, &[198, 51, 100, 7]),
        ),
        record(
            TYPE_AMTRELAY,
            300,
            &amtrelay(10, false, 2, &Ipv6Addr::LOCALHOST.octets()),
        ),
        record(
            TYPE_AMTRELAY,
            3600,
            &amtrelay(10, true, 3, &wire_name("sfo12.bcast.id")),
        ),
    ]
}

fn three_candidates() -> Vec<DriadCandidate> {
    vec![
        DriadCandidate {
            precedence: 20,
            discovery_optional: true,
            relay: DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            ttl: 60,
        },
        DriadCandidate {
            precedence: 10,
            discovery_optional: false,
            relay: DriadRelayAddress::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ttl: 300,
        },
        DriadCandidate {
            precedence: 10,
            discovery_optional: true,
            relay: DriadRelayAddress::DnsName("sfo12.bcast.id".to_string()),
            ttl: 3600,
        },
    ]
}

#[test]
fn three_records_yield_three_candidates_with_precedence_d_bit_and_ttl() {
    let query = DriadResolver::build_dns_query(SOURCE, TXID);
    let response = reply(&query, TXID, &three_record_answers());

    // Wire order, nothing dropped: the higher-precedence record is a failover
    // target, not noise.
    assert_eq!(
        DriadResolver::parse_dns_response_candidates(&response),
        three_candidates()
    );
    assert_eq!(
        DriadResolver::parse_dns_response_candidates_validated(&query, &response),
        three_candidates()
    );
    // The EDNS query asks the same question, so it binds the same reply.
    let edns_query = DriadResolver::build_dns_query_edns(SOURCE, TXID);
    assert_eq!(
        DriadResolver::parse_dns_response_candidates_validated(&edns_query, &response),
        three_candidates()
    );
}

/// xorshift64*, seeded, so the run is reproducible without an RNG dependency.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u32) -> u32 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) % u64::from(n)) as u32
    }
}

fn v4_candidate(precedence: u8, last_octet: u8) -> DriadCandidate {
    DriadCandidate {
        precedence,
        discovery_optional: false,
        relay: DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet))),
        ttl: 300,
    }
}

#[test]
fn seeded_order_reaches_every_tie_permutation_and_never_inverts_precedence() {
    // RFC 8777 §3.1.2 / §4.2.1: lower precedence is tried first, and the order
    // among equal precedence is non-deterministic. Wire order deliberately puts
    // the worst record first and the best last.
    let wire = vec![
        v4_candidate(20, 9),
        v4_candidate(10, 1),
        v4_candidate(10, 2),
        v4_candidate(10, 3),
        v4_candidate(5, 8),
    ];
    let tied: Vec<_> = wire[1..4].to_vec();
    // 3 tied relays have 3! orderings; 64 draws per ordering leaves a fair
    // shuffle a miss chance below 6 * (5/6)^384.
    let permutations_of_three = 6;
    let draws = 64 * permutations_of_three;

    let mut rng = Rng(0x5EED_D41A_0000_0001);
    let mut seen = HashSet::new();
    for _ in 0..draws {
        let mut ordered = wire.clone();
        DriadResolver::order_candidates_with(&mut ordered, |n| rng.below(n));
        assert!(
            ordered
                .windows(2)
                .all(|w| w[0].precedence <= w[1].precedence),
            "precedence inverted: {ordered:?}"
        );
        assert_eq!(ordered[0], wire[4], "the precedence-5 relay must lead");
        assert_eq!(ordered[4], wire[0], "the precedence-20 relay must trail");
        let middle = ordered[1..4].to_vec();
        assert!(
            middle.iter().all(|c| tied.contains(c)),
            "a tie slot holds a non-tied relay: {ordered:?}"
        );
        seen.insert(
            middle
                .iter()
                .map(|c| c.relay.to_string())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(
        seen.len(),
        permutations_of_three,
        "every ordering of the tied relays must be reachable; saw {seen:?}"
    );
}

#[test]
fn type3_relay_expands_to_every_address_answer() {
    // RFC 8777 §4.2.4: the D-bit and precedence of a type-3 record carry over
    // to the A/AAAA records its name resolves to.
    let relay_name = "sfo12.bcast.id";
    let a_query = DriadResolver::build_dns_a_query(relay_name, TXID);
    let a_reply = reply(
        &a_query,
        TXID,
        &[
            record(TYPE_A, 60, &[192, 0, 2, 1]),
            record(TYPE_A, 7200, &[192, 0, 2, 2]),
        ],
    );
    let aaaa_query = DriadResolver::build_dns_aaaa_query(relay_name, TXID);
    let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let aaaa_reply = reply(&aaaa_query, TXID, &[record(TYPE_AAAA, 300, &v6.octets())]);

    let mut addresses = DriadResolver::parse_dns_addresses_validated(&a_query, &a_reply);
    addresses.extend(DriadResolver::parse_dns_addresses_validated(
        &aaaa_query,
        &aaaa_reply,
    ));
    assert_eq!(
        addresses,
        vec![
            DriadAddress {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                ttl: 60
            },
            DriadAddress {
                addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                ttl: 7200
            },
            DriadAddress {
                addr: IpAddr::V6(v6),
                ttl: 300
            },
        ]
    );

    let named = DriadCandidate {
        precedence: 10,
        discovery_optional: true,
        relay: DriadRelayAddress::DnsName(relay_name.to_string()),
        ttl: 3600,
    };
    let expanded = named.expand(&addresses);
    // Each derived binding expires with whichever record expires first.
    let expected_ttls = [60, 3600, 300];
    assert_eq!(expanded.len(), 3);
    for ((candidate, address), ttl) in expanded.iter().zip(&addresses).zip(expected_ttls) {
        assert_eq!(
            candidate,
            &DriadCandidate {
                precedence: 10,
                discovery_optional: true,
                relay: DriadRelayAddress::Ip(address.addr),
                ttl,
            }
        );
    }

    // An address candidate is already resolved: expansion leaves it alone.
    let literal = v4_candidate(10, 1);
    assert_eq!(literal.expand(&addresses), vec![literal.clone()]);
}

#[test]
fn validated_variants_reject_txid_or_question_mismatch() {
    let query = DriadResolver::build_dns_query(SOURCE, TXID);
    let answers = three_record_answers();

    let wrong_txid = reply(&query, TXID ^ 0xFFFF, &answers);
    assert!(
        DriadResolver::parse_dns_response_candidates_validated(&query, &wrong_txid).is_empty(),
        "a reply whose transaction ID differs from the query must be rejected"
    );
    // The query-less parser cannot tell, which is why the native path binds.
    assert_eq!(
        DriadResolver::parse_dns_response_candidates(&wrong_txid),
        three_candidates()
    );

    let other_source: IpAddr = "69.25.95.11".parse().unwrap();
    let other_question = reply(
        &DriadResolver::build_dns_query(other_source, TXID),
        TXID,
        &answers,
    );
    assert!(
        DriadResolver::parse_dns_response_candidates_validated(&query, &other_question).is_empty(),
        "a reply answering another question must be rejected"
    );

    let a_query = DriadResolver::build_dns_a_query("sfo12.bcast.id", TXID);
    let a_reply = reply(&a_query, TXID, &[record(TYPE_A, 60, &[192, 0, 2, 1])]);
    let aaaa_query = DriadResolver::build_dns_aaaa_query("sfo12.bcast.id", TXID);
    assert!(
        DriadResolver::parse_dns_addresses_validated(&aaaa_query, &a_reply).is_empty(),
        "an A reply must not satisfy an AAAA query"
    );
    let a_wrong_txid = reply(
        &a_query,
        TXID ^ 0xFFFF,
        &[record(TYPE_A, 60, &[192, 0, 2, 1])],
    );
    assert!(DriadResolver::parse_dns_addresses_validated(&a_query, &a_wrong_txid).is_empty());
}

#[test]
fn edns_query_advertises_the_ipv6_minimum_mtu_payload() {
    // RFC 6891 §6.1.2: one OPT pseudo-RR in the additional section, its CLASS
    // carrying the requestor's UDP payload size.
    let plain = DriadResolver::build_dns_query(SOURCE, TXID);
    let edns = DriadResolver::build_dns_query_edns(SOURCE, TXID);
    assert_eq!(&edns[..10], &plain[..10]);
    assert_eq!(u16::from_be_bytes([edns[10], edns[11]]), 1, "ARCOUNT");
    assert_eq!(&edns[HEADER_LEN..plain.len()], &plain[HEADER_LEN..]);
    let opt = &edns[plain.len()..];
    let type_opt: u16 = 41;
    // 1280-byte IPv6 minimum MTU (RFC 8200 §5) less the IPv6 and UDP headers.
    let payload: u16 = 1280 - 40 - 8;
    let mut expected = vec![0]; // root owner name
    expected.extend_from_slice(&type_opt.to_be_bytes());
    expected.extend_from_slice(&payload.to_be_bytes());
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ext-RCODE, version, flags, RDLEN
    assert_eq!(opt, expected.as_slice());
    assert_eq!(DriadResolver::EDNS_UDP_PAYLOAD_SIZE, payload);
}

#[cfg(feature = "native")]
#[tokio::test(flavor = "current_thread")]
async fn truncated_udp_reply_is_retried_over_tcp() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    // RFC 1035 §4.1.1: the TC bit is the second-lowest bit of the third octet.
    const TC_BIT: u8 = 0x02;

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(ns).await.unwrap();

    let udp_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (n, src) = udp.recv_from(&mut buf).await.unwrap();
        let query = buf[..n].to_vec();
        // Truncated: the TC bit set and the answer section dropped.
        let mut truncated = reply(&query, u16::from_be_bytes([query[0], query[1]]), &[]);
        truncated[2] |= TC_BIT;
        udp.send_to(&truncated, src).await.unwrap();
        query
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        // RFC 1035 §4.2.2: a two-octet length prefixes each message over TCP.
        let len = stream.read_u16().await.unwrap() as usize;
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await.unwrap();
        let answers = vec![
            record(TYPE_AMTRELAY, 300, &amtrelay(30, false, 1, &[192, 0, 2, 3])),
            record(TYPE_AMTRELAY, 300, &amtrelay(10, true, 1, &[192, 0, 2, 1])),
            record(TYPE_AMTRELAY, 300, &amtrelay(20, false, 1, &[192, 0, 2, 2])),
        ];
        let full = reply(&query, u16::from_be_bytes([query[0], query[1]]), &answers);
        stream.write_u16(full.len() as u16).await.unwrap();
        stream.write_all(&full).await.unwrap();
        query
    });

    let candidates = amt_protocol::native::resolver::resolve_candidates_via(SOURCE, &[ns])
        .await
        .expect("candidates from the TCP retry");
    let relays: Vec<_> = candidates.iter().map(|c| c.relay.to_string()).collect();
    assert_eq!(relays, ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
    assert!(candidates[0].discovery_optional);

    let udp_query = udp_task.await.unwrap();
    let tcp_query = tcp_task.await.unwrap();
    assert_eq!(udp_query, tcp_query, "the TCP retry re-asks the same query");
    assert_eq!(
        udp_query,
        DriadResolver::build_dns_query_edns(
            SOURCE,
            u16::from_be_bytes([udp_query[0], udp_query[1]])
        ),
        "the UDP query carries the EDNS(0) OPT record"
    );
}
