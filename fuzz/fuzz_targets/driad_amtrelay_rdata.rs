#![no_main]
//! Fuzz AMTRELAY RDATA decoding (RFC 8777 §4.2) against arbitrary bytes.
//!
//! RDATA is attacker-chosen: relay type, the length of the relay field, and for
//! type 3 an embedded uncompressed DNS name whose label lengths are also
//! attacker-chosen. Decoding must be total.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let decoded = amt_protocol::fuzz_api::parse_amtrelay_rdata(data);

    // Precedence is the first octet whenever anything decoded at all — the bug
    // this target guards is silently dropping it again (it was `// rdata[0] =
    // precedence (unused for now)` before BLO-28790).
    if let Some((precedence, _)) = decoded {
        assert_eq!(
            precedence, data[0],
            "decoded precedence must be RDATA octet 0"
        );
    }

    let _ = amt_protocol::fuzz_api::parse_dns_wire_name(data);
});
