#![no_main]
//! Differential fuzz target: the query-bound parser must be strictly stricter
//! than the query-less one, never differently permissive.
//!
//! `parse_dns_response_validated` adds transaction-ID and question checks on
//! top of the same answer selection `parse_dns_response` performs. The relay
//! choice among equal precedence is random (RFC 8777 §3.1.2), so the property
//! is stated on the deterministic candidate lists, as in
//! `tests/driad_fuzz_corpus.rs`. For any (query, response) pair:
//!
//!   candidates_validated(q, r) ⊆ candidates(r), and
//!   validated(q, r) == Some(x)  ⟹  x is a lowest-precedence record of
//!                                   candidates_validated(q, r)
//!
//! A violation means the query-bound parser accepted a record the query-less
//! one would not offer, which would make the hardened native path and the
//! browser path choose among different relays from identical bytes.

use libfuzzer_sys::fuzz_target;

use amt_protocol::DriadResolver;

fuzz_target!(|data: &[u8]| {
    // Split the input into a synthetic query and a response. Both halves are
    // arbitrary, so the query itself is also exercised as untrusted input.
    let split = data.len() / 2;
    let (query, response) = data.split_at(split);

    let candidates = DriadResolver::parse_dns_response_candidates(response);
    let validated_candidates =
        DriadResolver::parse_dns_response_candidates_validated(query, response);
    assert!(
        validated_candidates.iter().all(|c| candidates.contains(c)),
        "validated candidates exceed the query-less list"
    );
    if let Some(validated) = DriadResolver::parse_dns_response_validated(query, response) {
        let best = validated_candidates.iter().map(|c| c.precedence).min();
        assert!(
            validated_candidates
                .iter()
                .any(|c| Some(c.precedence) == best && c.relay == validated),
            "validated parse selected {validated:?}, outside its lowest-precedence candidates"
        );
    }

    // Real queries built by the crate must also survive being validated against
    // arbitrary response bytes.
    if data.len() >= 6 {
        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        let txid = u16::from_be_bytes([data[4], data[5]]);
        let built = DriadResolver::build_dns_query(src, txid);
        let _ = DriadResolver::parse_dns_response_validated(&built, response);
    }
});
