#![no_main]
//! Differential fuzz target: the query-bound parser must be strictly stricter
//! than the query-less one, never differently permissive.
//!
//! `parse_dns_response_validated` adds transaction-ID and question checks on
//! top of the same answer selection `parse_dns_response` performs. So for any
//! (query, response) pair the following must hold:
//!
//!   validated(q, r) == Some(x)  ⟹  parse(r) == Some(x)
//!
//! A violation means the two entry points disagree about which record wins,
//! which would make the hardened native path and the browser path resolve
//! different relays from identical bytes.

use libfuzzer_sys::fuzz_target;

use amt_protocol::DriadResolver;

fuzz_target!(|data: &[u8]| {
    // Split the input into a synthetic query and a response. Both halves are
    // arbitrary, so the query itself is also exercised as untrusted input.
    let split = data.len() / 2;
    let (query, response) = data.split_at(split);

    if let Some(validated) = DriadResolver::parse_dns_response_validated(query, response) {
        let unvalidated = DriadResolver::parse_dns_response(response);
        assert_eq!(
            Some(validated),
            unvalidated,
            "validated parse accepted a record the query-less parse did not select"
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
