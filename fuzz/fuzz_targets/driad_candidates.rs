#![no_main]
//! Fuzz the DRIAD candidate list (RFC 8777) against arbitrary response bytes.
//!
//! The candidate list is what a failing-over gateway walks, so it carries the
//! same contract as the single-relay parser plus its own:
//!
//! - total, non-panicking, terminating on any bytes;
//! - it accepts exactly when `parse_dns_response` does, and that relay is one
//!   of its lowest-precedence entries;
//! - every candidate keeps the precedence and D-bit of the record it came from;
//! - the query-bound list is a subset of the query-less one;
//! - ordering is a permutation sorted by precedence, whatever the draw.

use libfuzzer_sys::fuzz_target;

use amt_protocol::DriadResolver;

/// The golden AMTRELAY and A queries the corpus replies answer.
const AMTRELAY_QUERY: &[u8] = include_bytes!("../../tests/fixtures/driad/q_amtrelay_v4_source.bin");
const A_QUERY: &[u8] = include_bytes!("../../tests/fixtures/driad/q_a_relay_host.bin");

fuzz_target!(|data: &[u8]| {
    let candidates = DriadResolver::parse_dns_response_candidates(data);
    let chosen = DriadResolver::parse_dns_response(data);
    assert_eq!(chosen.is_some(), !candidates.is_empty());
    if let Some(relay) = &chosen {
        let best = candidates.iter().map(|c| c.precedence).min();
        assert!(candidates
            .iter()
            .any(|c| Some(c.precedence) == best && &c.relay == relay));
    }

    let validated = DriadResolver::parse_dns_response_candidates_validated(AMTRELAY_QUERY, data);
    assert!(validated.iter().all(|c| candidates.contains(c)));

    // Draw the tie order from the input itself, so libFuzzer explores it.
    let mut draws = data.iter().cycle();
    let mut ordered = candidates.clone();
    DriadResolver::order_candidates_with(&mut ordered, |n| {
        u32::from(draws.next().copied().unwrap_or(0)) % n
    });
    assert!(ordered
        .windows(2)
        .all(|w| w[0].precedence <= w[1].precedence));
    assert!(ordered.len() == candidates.len() && ordered.iter().all(|c| candidates.contains(c)));

    let addresses = DriadResolver::parse_dns_addresses_validated(A_QUERY, data);
    for candidate in &candidates {
        let expanded = candidate.expand(&addresses);
        assert!(expanded.iter().all(|e| e.precedence == candidate.precedence
            && e.discovery_optional == candidate.discovery_optional
            && e.ttl <= candidate.ttl));
    }
    let _ = DriadResolver::is_truncated_reply(AMTRELAY_QUERY, data);
});
