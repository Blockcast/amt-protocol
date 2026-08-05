#![cfg(feature = "hickory-proof")]

use amt_protocol::hickory_proof::{build_query, select_relay, ProofRelay};
use std::net::{IpAddr, Ipv4Addr};

const QNAME: &str = "128.95.25.69.in-addr.arpa";
const TXID: u16 = 0x5a17;

fn response(question: &[u8], answers: &[(&[u8], u16, u16, &[u8])]) -> Vec<u8> {
    let mut wire = question.to_vec();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    for (owner, rr_type, class, rdata) in answers {
        wire.extend_from_slice(owner);
        wire.extend_from_slice(&rr_type.to_be_bytes());
        wire.extend_from_slice(&class.to_be_bytes());
        wire.extend_from_slice(&60u32.to_be_bytes());
        wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        wire.extend_from_slice(rdata);
    }
    wire
}

fn query() -> Vec<u8> {
    build_query(QNAME, TXID).expect("Hickory query")
}

#[test]
fn query_is_golden_for_ipv4_ipv6_and_trailing_dot() {
    let v4 = query();
    assert_eq!(&v4[..4], &[0x5a, 0x17, 0x01, 0x00]);
    assert_eq!(&v4[v4.len() - 4..], &[0x01, 0x04, 0x00, 0x01]);
    assert_eq!(
        build_query(QNAME, TXID),
        build_query(&format!("{QNAME}."), TXID)
    );

    let v6_name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
    let v6 = build_query(v6_name, TXID).expect("IPv6 reverse query");
    assert_eq!(&v6[v6.len() - 4..], &[0x01, 0x04, 0x00, 0x01]);
}

#[test]
fn parses_compressed_ipv4_ipv6_and_type3_answers() {
    let q = query();
    let owner = [0xc0, 0x0c];
    let ipv4 = [10, 1, 192, 0, 2, 10];
    let wire = response(&q, &[(&owner, 260, 1, &ipv4)]);
    assert_eq!(
        select_relay(&wire, TXID, QNAME),
        Some(ProofRelay::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))))
    );

    let mut ipv6 = vec![20, 2];
    ipv6.extend_from_slice(
        &"2001:db8::5"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    let wire = response(&q, &[(&owner, 260, 1, &ipv6)]);
    assert_eq!(
        select_relay(&wire, TXID, QNAME),
        Some(ProofRelay::Ip("2001:db8::5".parse().unwrap()))
    );

    let hostname = [
        30, 3, 5, b's', b'f', b'o', b'1', b'2', 5, b'b', b'c', b'a', b's', b't', 2, b'i', b'd', 0,
    ];
    let wire = response(&q, &[(&owner, 260, 1, &hostname)]);
    assert_eq!(
        select_relay(&wire, TXID, QNAME),
        Some(ProofRelay::DnsName("sfo12.bcast.id".into()))
    );
}

#[test]
fn selects_lowest_precedence_and_skips_malformed_records() {
    let q = query();
    let owner = [0xc0, 0x0c];
    let malformed = [1, 1, 192, 0, 2];
    let lower_priority = [20, 1, 192, 0, 2, 20];
    let preferred = [5, 1, 192, 0, 2, 5];
    let wire = response(
        &q,
        &[
            (&owner, 260, 1, &malformed),
            (&owner, 260, 1, &lower_priority),
            (&owner, 260, 1, &preferred),
        ],
    );
    assert_eq!(
        select_relay(&wire, TXID, QNAME),
        Some(ProofRelay::Ip("192.0.2.5".parse().unwrap()))
    );
}

#[test]
fn rejects_wrong_transaction_question_owner_class_and_malformed_names() {
    let q = query();
    let owner = [0xc0, 0x0c];
    let valid = [5, 1, 192, 0, 2, 5];
    let wire = response(&q, &[(&owner, 260, 1, &valid)]);
    assert_eq!(select_relay(&wire, TXID + 1, QNAME), None);
    assert_eq!(select_relay(&wire, TXID, "wrong.example"), None);

    let wrong_owner = [5, b'w', b'r', b'o', b'n', b'g', 0];
    assert_eq!(
        select_relay(
            &response(&q, &[(&wrong_owner, 260, 1, &valid)]),
            TXID,
            QNAME
        ),
        None
    );
    assert_eq!(
        select_relay(&response(&q, &[(&owner, 260, 3, &valid)]), TXID, QNAME),
        None
    );

    let compressed_type3 = [5, 3, 0xc0, 0x0c];
    assert_eq!(
        select_relay(
            &response(&q, &[(&owner, 260, 1, &compressed_type3)]),
            TXID,
            QNAME
        ),
        None
    );
    let trailing_garbage = [5, 3, 1, b'a', 0, 0];
    assert_eq!(
        select_relay(
            &response(&q, &[(&owner, 260, 1, &trailing_garbage)]),
            TXID,
            QNAME
        ),
        None
    );
}
