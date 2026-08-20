#![no_main]
//! Fuzz `DriadResolver::parse_dns_response` against arbitrary bytes.
//!
//! Bounds handling in the DNS message walker is manual throughout (explicit
//! `offset + 10 > data.len()` style guards, a backward-only compression-pointer
//! rule, a jump cap). That is exactly the shape a fuzzer is for: the parser must
//! return `None` on anything malformed and must never panic, hang, or index out
//! of bounds — the input is an unauthenticated UDP datagram.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The only contract: total, non-panicking, terminating.
    let _ = amt_protocol::DriadResolver::parse_dns_response(data);
    let _ = amt_protocol::DriadResolver::parse_dns_a_response(data);
    let _ = amt_protocol::DriadResolver::parse_dns_aaaa_response(data);
});
