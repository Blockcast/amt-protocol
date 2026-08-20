//! Golden DRIAD wire vectors (BLO-28790).
//!
//! Every fixture is a real DNS packet checked in under `tests/fixtures/driad/`,
//! covering the axes named in the AMT-01 rollback plan: IPv4, IPv6, DNS names,
//! compression, multiple TYPE260 answers, precedence, malformed packets,
//! transaction IDs, questions, and answer ownership/class.
//!
//! The fixtures are produced by `vectors()` below and compared byte-for-byte
//! against the files on disk by `fixtures_on_disk_match_generator`. That makes
//! the corpus reproducible and stops a fixture from silently drifting away from
//! the intent recorded in its name. Regenerate with:
//!
//! ```text
//! DRIAD_FIXTURES_WRITE=1 cargo test --test driad_golden
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use amt_protocol::{DriadRelayAddress, DriadResolver};

const AMTRELAY_TYPE: u16 = 260;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const CLASS_CH: u16 = 3;

/// The reverse-DNS question every AMTRELAY fixture asks (source 69.25.95.10).
const QNAME: &str = "10.95.25.69.in-addr.arpa";
const TXID: u16 = 0x1234;

/// Standard response flags: QR=1, RD=1, RA=1, RCODE=0.
const FLAGS_RESPONSE: u16 = 0x8180;

// ---------------------------------------------------------------------------
// Wire builders
// ---------------------------------------------------------------------------

/// Encode a domain name as length-prefixed labels plus the root label.
fn name(n: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in n.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn header(txid: u16, flags: u16, qdcount: u16, ancount: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&txid.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qdcount.to_be_bytes());
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out
}

fn question(qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut out = name(qname);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    out
}

/// How an answer record names its owner.
enum Owner {
    /// Compression pointer to the question's QNAME at offset 12 — what real
    /// resolvers emit, and the compression axis of the corpus.
    PtrToQuestion,
    /// An uncompressed literal name.
    Literal(&'static str),
    /// A pointer that jumps forward, which must be rejected.
    ForwardPtr,
}

fn answer(owner: &Owner, rtype: u16, rclass: u16, rdata: &[u8]) -> Vec<u8> {
    let mut out = match owner {
        Owner::PtrToQuestion => vec![0xC0, 0x0C],
        Owner::Literal(n) => name(n),
        // 0xC0FF points past the end of every fixture here.
        Owner::ForwardPtr => vec![0xC0, 0xFF],
    };
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&rclass.to_be_bytes());
    out.extend_from_slice(&300u32.to_be_bytes()); // TTL
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

/// AMTRELAY RDATA: precedence, D|type, relay field (RFC 8777 §4.2).
fn amtrelay_v4(precedence: u8, ip: [u8; 4]) -> Vec<u8> {
    let mut out = vec![precedence, 0x01];
    out.extend_from_slice(&ip);
    out
}

fn amtrelay_v6(precedence: u8, ip: [u8; 16]) -> Vec<u8> {
    let mut out = vec![precedence, 0x02];
    out.extend_from_slice(&ip);
    out
}

fn amtrelay_name(precedence: u8, n: &str) -> Vec<u8> {
    let mut out = vec![precedence, 0x03];
    out.extend_from_slice(&name(n));
    out
}

/// Relay type 0 — "no relay available". Parseable, but never usable.
fn amtrelay_none(precedence: u8) -> Vec<u8> {
    vec![precedence, 0x00]
}

/// An unassigned relay type: must be skipped, not fatal.
fn amtrelay_unknown(precedence: u8) -> Vec<u8> {
    vec![precedence, 0x7F, 0xDE, 0xAD]
}

const RELAY_V4: [u8; 4] = [192, 0, 2, 1];
const RELAY_V4_ALT: [u8; 4] = [198, 51, 100, 7];
const RELAY_V4_THIRD: [u8; 4] = [203, 0, 113, 9];
const RELAY_V6: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];

/// Compose a full AMTRELAY response over the standard question.
fn response(answers: &[Vec<u8>]) -> Vec<u8> {
    response_with(TXID, FLAGS_RESPONSE, QNAME, AMTRELAY_TYPE, CLASS_IN, answers)
}

fn response_with(
    txid: u16,
    flags: u16,
    qname: &str,
    qtype: u16,
    qclass: u16,
    answers: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = header(txid, flags, 1, answers.len() as u16);
    out.extend_from_slice(&question(qname, qtype, qclass));
    for a in answers {
        out.extend_from_slice(a);
    }
    out
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// (filename, bytes) for every checked-in fixture.
fn vectors() -> Vec<(&'static str, Vec<u8>)> {
    let src_v4: IpAddr = "69.25.95.10".parse().unwrap();
    let src_v6: IpAddr = "2001:db8::1".parse().unwrap();

    let ptr = Owner::PtrToQuestion;

    vec![
        // --- golden queries ---
        ("q_amtrelay_v4_source.bin", DriadResolver::build_dns_query(src_v4, TXID)),
        ("q_amtrelay_v6_source.bin", DriadResolver::build_dns_query(src_v6, TXID)),
        ("q_a_relay_host.bin", DriadResolver::build_dns_a_query("sfo12.bcast.id", TXID)),
        ("q_aaaa_relay_host.bin", DriadResolver::build_dns_aaaa_query("sfo12.bcast.id", TXID)),
        // Trailing dot must frame identically to the relative spelling.
        ("q_aaaa_trailing_dot.bin", DriadResolver::build_dns_aaaa_query("sfo12.bcast.id.", TXID)),
        // --- well-formed responses ---
        ("r_ipv4_relay.bin", response(&[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        ("r_ipv6_relay.bin", response(&[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v6(10, RELAY_V6))])),
        ("r_dnsname_relay.bin", response(&[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_name(10, "sfo12.bcast.id"))])),
        // Owner spelled out in full rather than compressed — same name, so accepted.
        ("r_uncompressed_owner.bin", response(&[answer(&Owner::Literal(QNAME), AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        // --- precedence (RFC 8777 §4.2: lower wins) ---
        // Wire order 30, 10, 20 → the 10 record must win, proving selection is
        // by precedence and not by arrival.
        ("r_multi_precedence.bin", response(&[
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(30, RELAY_V4_THIRD)),
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4)),
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(20, RELAY_V4_ALT)),
        ])),
        // Best precedence is unusable (type 0, then an unassigned type) — the
        // resolver must fall through to the usable record instead of failing.
        ("r_precedence_fallthrough.bin", response(&[
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_none(5)),
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_unknown(7)),
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(50, RELAY_V4_ALT)),
        ])),
        // Ties keep wire order.
        ("r_precedence_tie.bin", response(&[
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4)),
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4_ALT)),
        ])),
        // A non-AMTRELAY record ahead of ours must not shadow it.
        ("r_other_type_first.bin", response(&[
            answer(&ptr, TYPE_A, CLASS_IN, &[10, 0, 0, 1]),
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4)),
        ])),
        // --- responses that must be REJECTED ---
        // Negative control: correct in every respect except the transaction ID.
        ("r_txid_mismatch.bin", response_with(TXID ^ 0xFFFF, FLAGS_RESPONSE, QNAME, AMTRELAY_TYPE, CLASS_IN,
            &[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        // Right TXID, but answers a different question.
        ("r_question_name_mismatch.bin", response_with(TXID, FLAGS_RESPONSE, "11.95.25.69.in-addr.arpa", AMTRELAY_TYPE, CLASS_IN,
            &[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        ("r_question_type_mismatch.bin", response_with(TXID, FLAGS_RESPONSE, QNAME, TYPE_A, CLASS_IN,
            &[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        ("r_question_class_mismatch.bin", response_with(TXID, FLAGS_RESPONSE, QNAME, AMTRELAY_TYPE, CLASS_CH,
            &[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        // Answer owner is a different name than the question asked.
        ("r_answer_owner_mismatch.bin", response(&[answer(&Owner::Literal("relay.attacker.example"), AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        // Answer class is not the question's class.
        ("r_answer_class_mismatch.bin", response(&[answer(&ptr, AMTRELAY_TYPE, CLASS_CH, &amtrelay_v4(10, RELAY_V4))])),
        // A wrong-owner record ahead of the legitimate one must be skipped, and
        // must not cause the good record behind it to be missed.
        ("r_owner_mismatch_then_valid.bin", response(&[
            answer(&Owner::Literal("relay.attacker.example"), AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(1, RELAY_V4_THIRD)),
            answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4)),
        ])),
        ("r_rcode_nxdomain.bin", response_with(TXID, 0x8183, QNAME, AMTRELAY_TYPE, CLASS_IN,
            &[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        // QR=0 — a query, not a response.
        ("r_qr_zero.bin", response_with(TXID, 0x0100, QNAME, AMTRELAY_TYPE, CLASS_IN,
            &[answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        ("r_no_answers.bin", response(&[])),
        // --- malformed ---
        ("r_forward_pointer_owner.bin", response(&[answer(&Owner::ForwardPtr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4))])),
        ("r_truncated_rdata.bin", {
            // RDLENGTH claims 6 bytes of RDATA but only 3 follow.
            let mut out = header(TXID, FLAGS_RESPONSE, 1, 1);
            out.extend_from_slice(&question(QNAME, AMTRELAY_TYPE, CLASS_IN));
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&AMTRELAY_TYPE.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&300u32.to_be_bytes());
            out.extend_from_slice(&6u16.to_be_bytes());
            out.extend_from_slice(&[10, 0x01, 192]);
            out
        }),
        ("r_ancount_overstated.bin", {
            // ANCOUNT says 3, only one record present.
            let mut out = header(TXID, FLAGS_RESPONSE, 1, 3);
            out.extend_from_slice(&question(QNAME, AMTRELAY_TYPE, CLASS_IN));
            out.extend_from_slice(&answer(&ptr, AMTRELAY_TYPE, CLASS_IN, &amtrelay_v4(10, RELAY_V4)));
            out
        }),
        ("r_header_only.bin", header(TXID, FLAGS_RESPONSE, 1, 1)),
        ("r_truncated_mid_name.bin", {
            // A label length that runs off the end of the packet.
            let mut out = header(TXID, FLAGS_RESPONSE, 1, 1);
            out.extend_from_slice(&[0x20, b'a', b'b']);
            out
        }),
        // --- A / AAAA follow-up responses ---
        ("r_a_relay_host.bin", response_with(TXID, FLAGS_RESPONSE, "sfo12.bcast.id", TYPE_A, CLASS_IN,
            &[answer(&ptr, TYPE_A, CLASS_IN, &[69, 25, 95, 128])])),
        ("r_aaaa_relay_host.bin", response_with(TXID, FLAGS_RESPONSE, "sfo12.bcast.id", TYPE_AAAA, CLASS_IN,
            &[answer(&ptr, TYPE_AAAA, CLASS_IN, &RELAY_V6)])),
        ("r_a_txid_mismatch.bin", response_with(TXID ^ 0xFFFF, FLAGS_RESPONSE, "sfo12.bcast.id", TYPE_A, CLASS_IN,
            &[answer(&ptr, TYPE_A, CLASS_IN, &[69, 25, 95, 128])])),
    ]
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/driad")
}

fn load(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading fixture {}: {e}", path.display()))
}

/// The corpus on disk must equal what `vectors()` produces. Without this, a
/// fixture could drift from the behaviour its name claims and every assertion
/// below would still pass.
#[test]
fn fixtures_on_disk_match_generator() {
    let dir = fixture_dir();
    if std::env::var_os("DRIAD_FIXTURES_WRITE").is_some() {
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        for (name, bytes) in vectors() {
            std::fs::write(dir.join(name), &bytes).expect("write fixture");
        }
    }
    for (name, expected) in vectors() {
        assert_eq!(
            load(name),
            expected,
            "fixture {name} on disk differs from generator; \
             regenerate with DRIAD_FIXTURES_WRITE=1"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance: transaction ID and question binding
// ---------------------------------------------------------------------------

#[test]
fn validated_rejects_transaction_id_mismatch() {
    let query = load("q_amtrelay_v4_source.bin");
    let resp = load("r_txid_mismatch.bin");
    assert_eq!(
        DriadResolver::parse_dns_response_validated(&query, &resp),
        None,
        "a reply whose transaction ID does not match the request must be rejected"
    );
}

/// The negative control for BLO-28790: this exact fixture is ACCEPTED by the
/// pre-fix parser, which never compared the transaction ID. `parse_dns_response`
/// still accepts it (it has no query to compare against) — which is precisely
/// why the native UDP path must call the validated entry point.
#[test]
fn unvalidated_entry_point_accepts_what_validated_rejects() {
    let resp = load("r_txid_mismatch.bin");
    assert_eq!(
        DriadResolver::parse_dns_response(&resp),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
        "the query-less entry point cannot check the transaction ID"
    );
    let query = load("q_amtrelay_v4_source.bin");
    assert_eq!(
        DriadResolver::parse_dns_response_validated(&query, &resp),
        None,
        "the query-bound entry point must reject it"
    );
}

#[test]
fn validated_rejects_question_name_mismatch() {
    let query = load("q_amtrelay_v4_source.bin");
    assert_eq!(
        DriadResolver::parse_dns_response_validated(&query, &load("r_question_name_mismatch.bin")),
        None,
        "a reply answering a different QNAME must be rejected"
    );
}

#[test]
fn validated_rejects_question_type_and_class_mismatch() {
    let query = load("q_amtrelay_v4_source.bin");
    assert_eq!(
        DriadResolver::parse_dns_response_validated(&query, &load("r_question_type_mismatch.bin")),
        None,
        "a reply whose QTYPE differs must be rejected"
    );
    assert_eq!(
        DriadResolver::parse_dns_response_validated(&query, &load("r_question_class_mismatch.bin")),
        None,
        "a reply whose QCLASS differs must be rejected"
    );
}

#[test]
fn validated_accepts_the_matching_reply() {
    let query = load("q_amtrelay_v4_source.bin");
    assert_eq!(
        DriadResolver::parse_dns_response_validated(&query, &load("r_ipv4_relay.bin")),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
    );
}

// ---------------------------------------------------------------------------
// Acceptance: answer owner name and class
// ---------------------------------------------------------------------------

#[test]
fn rejects_answer_with_mismatched_owner_name() {
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_answer_owner_mismatch.bin")),
        None,
        "an answer owned by a name we did not ask about must be rejected"
    );
}

#[test]
fn rejects_answer_with_mismatched_class() {
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_answer_class_mismatch.bin")),
        None,
        "an answer in a class we did not ask about must be rejected"
    );
}

#[test]
fn skips_mismatched_owner_and_still_finds_valid_record() {
    // The bogus record carries the better precedence (1 vs 10); rejecting it on
    // owner grounds must not also lose the legitimate record behind it.
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_owner_mismatch_then_valid.bin")),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
    );
}

#[test]
fn accepts_uncompressed_owner_name() {
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_uncompressed_owner.bin")),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
        "an owner spelled out in full is the same name as the compressed form"
    );
}

// ---------------------------------------------------------------------------
// Acceptance: AMTRELAY precedence (RFC 8777 §4.2)
// ---------------------------------------------------------------------------

#[test]
fn honors_precedence_over_wire_order() {
    // Records arrive 30, 10, 20. Lower precedence wins, so 192.0.2.1 (10) must
    // be chosen — the pre-fix parser returned 203.0.113.9, the first record.
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_multi_precedence.bin")),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
    );
}

#[test]
fn falls_through_when_best_precedence_record_is_unusable() {
    // Precedence 5 is relay type 0 ("no relay") and precedence 7 is an
    // unassigned type; the usable record is precedence 50.
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_precedence_fallthrough.bin")),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))),
        "an unusable best-precedence record must not fail the whole lookup"
    );
}

#[test]
fn precedence_tie_keeps_wire_order() {
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_precedence_tie.bin")),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
    );
}

#[test]
fn other_record_types_do_not_shadow_amtrelay() {
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_other_type_first.bin")),
        Some(DriadRelayAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
    );
}

#[test]
fn parses_ipv6_and_dnsname_relays() {
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_ipv6_relay.bin")),
        Some(DriadRelayAddress::Ip("2001:db8::1".parse().unwrap())),
    );
    assert_eq!(
        DriadResolver::parse_dns_response(&load("r_dnsname_relay.bin")),
        Some(DriadRelayAddress::DnsName("sfo12.bcast.id".to_string())),
    );
}

// ---------------------------------------------------------------------------
// Acceptance: trailing-dot query framing
// ---------------------------------------------------------------------------

#[test]
fn trailing_dot_hostname_frames_identically() {
    let with_dot = load("q_aaaa_trailing_dot.bin");
    let without_dot = load("q_aaaa_relay_host.bin");
    assert_eq!(
        with_dot, without_dot,
        "a trailing dot must not add a second root label"
    );
}

#[test]
fn trailing_dot_query_has_exactly_one_root_label() {
    let q = load("q_aaaa_trailing_dot.bin");
    // QNAME starts at 12 and is followed by QTYPE(2) + QCLASS(2).
    let qname = &q[12..q.len() - 4];
    assert_eq!(
        *qname.last().unwrap(),
        0,
        "QNAME must end in the root label"
    );
    assert_ne!(
        qname[qname.len() - 2],
        0,
        "QNAME must not end in two consecutive root labels"
    );
    // A correctly-framed AAAA response over this question must parse, which it
    // cannot if the question section length is miscomputed.
    assert_eq!(
        DriadResolver::parse_dns_aaaa_response_validated(&q, &load("r_aaaa_relay_host.bin")),
        Some("2001:db8::1".parse::<IpAddr>().unwrap()),
    );
}

// ---------------------------------------------------------------------------
// Malformed input must be rejected, never panic
// ---------------------------------------------------------------------------

#[test]
fn malformed_responses_are_rejected() {
    for name in [
        "r_rcode_nxdomain.bin",
        "r_qr_zero.bin",
        "r_no_answers.bin",
        "r_forward_pointer_owner.bin",
        "r_truncated_rdata.bin",
        "r_ancount_overstated.bin",
        "r_header_only.bin",
        "r_truncated_mid_name.bin",
    ] {
        assert_eq!(
            DriadResolver::parse_dns_response(&load(name)),
            None,
            "{name} must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// A / AAAA follow-up
// ---------------------------------------------------------------------------

#[test]
fn a_and_aaaa_follow_up_validate_against_their_query() {
    let a_query = load("q_a_relay_host.bin");
    assert_eq!(
        DriadResolver::parse_dns_a_response_validated(&a_query, &load("r_a_relay_host.bin")),
        Some("69.25.95.128".parse::<IpAddr>().unwrap()),
    );
    assert_eq!(
        DriadResolver::parse_dns_a_response_validated(&a_query, &load("r_a_txid_mismatch.bin")),
        None,
        "an A reply with the wrong transaction ID must be rejected"
    );
    let aaaa_query = load("q_aaaa_relay_host.bin");
    assert_eq!(
        DriadResolver::parse_dns_aaaa_response_validated(&aaaa_query, &load("r_aaaa_relay_host.bin")),
        Some("2001:db8::1".parse::<IpAddr>().unwrap()),
    );
    // An A query must not be satisfied by the AAAA reply, or vice versa.
    assert_eq!(
        DriadResolver::parse_dns_a_response_validated(&a_query, &load("r_aaaa_relay_host.bin")),
        None,
    );
}
