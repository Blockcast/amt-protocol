//! Bounded, deterministic mutation harness over the DRIAD corpus (BLO-28790).
//!
//! The `fuzz/` crate holds the real coverage-guided libFuzzer targets, but those
//! need a nightly toolchain. This harness runs the same invariants on stable as
//! an ordinary `cargo test`, seeded from the same checked-in corpus, so the
//! parser's totality is gated on every CI run rather than only when the nightly
//! fuzz job runs.
//!
//! It is deterministic by construction (fixed seed, fixed mutation schedule):
//! a failure here reproduces exactly, and the harness cannot go green one run
//! and red the next for reasons unrelated to the code.

use std::path::{Path, PathBuf};

use amt_protocol::DriadResolver;

/// xorshift64*, so the mutation schedule is fixed and reproducible without
/// pulling in an RNG dependency (BLO-28790 forbids new dependencies).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn read_dir_files(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        // Sorted so the seed order — and therefore the whole run — is stable.
        paths.sort();
        for p in paths {
            if p.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    out.push(b);
                }
            }
        }
    }
    out
}

/// Every checked-in packet: golden fixtures plus the fuzz seed corpora.
fn seeds() -> Vec<Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out = read_dir_files(&root.join("tests/fixtures/driad"));
    for target in [
        "driad_parse_response",
        "driad_amtrelay_rdata",
        "driad_query_roundtrip",
    ] {
        out.extend(read_dir_files(&root.join("fuzz/corpus").join(target)));
    }
    assert!(!out.is_empty(), "corpus is empty — fixtures missing?");
    out
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut buf = seed.to_vec();
    match rng.next() % 6 {
        0 => {
            // Flip a bit.
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] ^= 1u8 << (rng.below(8));
            }
        }
        1 => {
            // Overwrite a byte with an arbitrary value.
            if !buf.is_empty() {
                let i = rng.below(buf.len());
                buf[i] = rng.next() as u8;
            }
        }
        2 => {
            // Truncate — exercises every bounds guard in the walker.
            let n = rng.below(buf.len().max(1));
            buf.truncate(n);
        }
        3 => {
            // Extend with arbitrary trailing bytes.
            let n = rng.below(64);
            for _ in 0..n {
                buf.push(rng.next() as u8);
            }
        }
        4 => {
            // Corrupt a header count (QDCOUNT/ANCOUNT) — drives the record loop
            // against a length the packet does not actually contain.
            if buf.len() >= 8 {
                let i = 4 + rng.below(4);
                buf[i] = rng.next() as u8;
            }
        }
        _ => {
            // Splice in a compression pointer, the most dangerous construct.
            if buf.len() >= 2 {
                let i = rng.below(buf.len() - 1);
                buf[i] = 0xC0;
                buf[i + 1] = rng.next() as u8;
            }
        }
    }
    buf
}

/// The parser must be total on arbitrary bytes: no panic, no hang, no
/// out-of-bounds. Every entry point, over every mutated seed.
#[test]
fn parsers_are_total_on_mutated_corpus() {
    let seeds = seeds();
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let query = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/driad/q_amtrelay_v4_source.bin"),
    )
    .expect("golden query fixture");

    let mut executed = 0usize;
    for _ in 0..40_000 {
        let seed = &seeds[rng.below(seeds.len())];
        let input = mutate(&mut rng, seed);

        let unvalidated = DriadResolver::parse_dns_response(&input);
        let _ = DriadResolver::parse_dns_a_response(&input);
        let _ = DriadResolver::parse_dns_aaaa_response(&input);

        // Mutant as response, against a known-good query.
        let validated = DriadResolver::parse_dns_response_validated(&query, &input);

        // The query-bound parser is strictly stricter: it may reject more, but
        // it must never accept a record the query-less parser did not select.
        if let Some(v) = validated {
            assert_eq!(
                Some(v),
                unvalidated,
                "validated accepted a record parse_dns_response did not select; input = {input:02x?}"
            );
        }

        // Mutant as query, against a known-good response — the query side is
        // also attacker-influenced once a type-3 relay name is followed up.
        let _ = DriadResolver::parse_dns_response_validated(&input, seed);

        // Parsing must be a pure function of the bytes.
        assert_eq!(
            unvalidated,
            DriadResolver::parse_dns_response(&input),
            "parse is not deterministic for input = {input:02x?}"
        );

        executed += 1;
    }
    assert_eq!(executed, 40_000, "harness did not run the full schedule");
}

/// AC: a reply whose transaction ID differs from the request must be rejected.
/// Asserted as a property over the whole corpus rather than a single fixture —
/// no mutant, however shaped, may be accepted under a mismatched TXID.
#[test]
fn validated_never_accepts_a_mismatched_transaction_id() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let query = std::fs::read(root.join("tests/fixtures/driad/q_amtrelay_v4_source.bin"))
        .expect("golden query fixture");
    let query_txid = u16::from_be_bytes([query[0], query[1]]);

    let seeds = seeds();
    let mut rng = Rng(0x5EED_1234_ABCD_0002);
    let mut checked = 0usize;

    for _ in 0..20_000 {
        let seed = &seeds[rng.below(seeds.len())];
        let input = mutate(&mut rng, seed);
        if input.len() < 12 {
            continue;
        }
        let input_txid = u16::from_be_bytes([input[0], input[1]]);
        if input_txid == query_txid {
            continue;
        }
        assert_eq!(
            DriadResolver::parse_dns_response_validated(&query, &input),
            None,
            "accepted a response with TXID {input_txid:#06x} for a query with TXID {query_txid:#06x}"
        );
        checked += 1;
    }
    assert!(
        checked > 1_000,
        "only {checked} mismatched-TXID mutants exercised — harness is not covering the case"
    );
}

/// The RDATA decoder must be total, and must never lose the precedence octet.
/// Requires the `fuzzing` feature, which re-exports the private decoders.
#[cfg(feature = "fuzzing")]
#[test]
fn amtrelay_rdata_decoder_is_total_and_keeps_precedence() {
    let seeds = seeds();
    let mut rng = Rng(0x5EED_1234_ABCD_0003);
    for _ in 0..40_000 {
        let seed = &seeds[rng.below(seeds.len())];
        let input = mutate(&mut rng, seed);
        if let Some((precedence, _)) = amt_protocol::fuzz_api::parse_amtrelay_rdata(&input) {
            assert_eq!(
                precedence, input[0],
                "decoded precedence must be RDATA octet 0; input = {input:02x?}"
            );
        }
        let _ = amt_protocol::fuzz_api::parse_dns_wire_name(&input);
    }
}
