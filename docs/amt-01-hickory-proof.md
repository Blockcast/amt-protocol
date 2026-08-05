# AMT-01 Hickory proof

This branch is a proof artifact for the AMT-01 G0 gate. The production
`DriadResolver`, native resolver, and `JsDriad` exports are unchanged. The
candidate is compiled only with the `hickory-proof` feature.

## Behavior matrix

`tests/hickory_driad_proof.rs` exercises `hickory-proto` 0.25.2 against:

- IPv4 and IPv6 reverse-query names, TYPE260, IN class, transaction IDs, and
  trailing-dot normalization;
- compressed answer owners plus IPv4, IPv6, and uncompressed type-3 relay data;
- multiple TYPE260 answers, invalid-record skipping, and lowest-precedence
  selection;
- malformed RDATA and type-3 names, mismatched transaction IDs and questions,
  and wrong answer owners and classes.

Run the proof and the existing native suite:

```bash
cargo test --test hickory_driad_proof --no-default-features \
  --features native,hickory-proof
cargo test --lib --no-default-features --features native,hickory-proof
```

At the pinned baseline `810719fe`, the proof reports 4/4 passing and the
existing suite reports 121/121 passing.

## Dependency and native-build impact

The proof pins `hickory-proto` exactly to 0.25.2 with `default-features = false`
and enables only `std` and `wasm-bindgen`. It explicitly enables
`getrandom` 0.3's `wasm_js` feature, as required by the browser target.

On Rust 1.97.1, clean native release builds measured:

| Build | Normal dependency nodes | Wall time |
|---|---:|---:|
| `native` baseline | 59 | 51.755 s |
| `native,hickory-proof` | 132 | 68.648 s |
| Delta | +73 | +16.893 s (+32.6%) |

The package count is intentionally conservative: it counts unique rendered
normal-dependency tree lines and therefore includes build-visible proc macros.

## WASM measurement command

The candidate exports `hickory_proof_accepts` only when both `wasm` and
`hickory-proof` are enabled, preventing release LTO from eliminating Hickory
from the candidate measurement.

```bash
rm -rf target/amt01-baseline target/amt01-candidate
CARGO_TARGET_DIR=target/amt01-baseline cargo build --lib --release \
  --target wasm32-unknown-unknown --no-default-features --features wasm
CARGO_TARGET_DIR=target/amt01-candidate cargo build --lib --release \
  --target wasm32-unknown-unknown --no-default-features \
  --features wasm,hickory-proof
wc -c target/amt01-{baseline,candidate}/wasm32-unknown-unknown/release/amt_protocol.wasm
gzip -9 -c target/amt01-baseline/wasm32-unknown-unknown/release/amt_protocol.wasm | wc -c
gzip -9 -c target/amt01-candidate/wasm32-unknown-unknown/release/amt_protocol.wasm | wc -c
```

The current proof environment could not install `rust-std` for
`wasm32-unknown-unknown`: `rustup target add wasm32-unknown-unknown` rolled back
with `error opening file for download: cleaning up cached downloads: No such
file or directory`. Raw and gzip WASM deltas therefore remain an explicit G0
blocker until the command above runs in CI or a working Rust target environment.

## Consumer inventory

The existing public boundary remains required:

- Rust: `DriadResolver` is re-exported from `src/lib.rs`; native
  `src/native/resolver.rs` uses query construction and TYPE260/A/AAAA parsing.
- WASM/TypeScript: `JsDriad` retains `buildQuery`, `buildDnsQuery`,
  `parseDnsResponse`, `buildDnsAQuery`, and `parseDnsAResponse`. The IWA loader,
  `DriadDohResolver`, and `AMTGatewayManager` consume those names.
- Native bindings: FFI and JNI use the Rust query-name API. No binding is
  changed by this proof.

No persisted DNS state exists. A later cleared implementation can replace the
private framing atomically behind these APIs without a dual parser.

## G0 disposition

**Blocked.** Native behavior feasibility is proven, but the dependency increase
is substantial and the required release-WASM raw/compressed delta is not yet
measured. This branch does not authorize or implement the production cutover.
