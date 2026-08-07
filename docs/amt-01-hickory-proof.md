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
sha256sum target/amt01-{baseline,candidate}/wasm32-unknown-unknown/release/amt_protocol.wasm
```

## Immutable WASM measurement receipt

The command block above was run at proof parent
`b6b23af046db51dab91dda847d40396fd7c6807c`, against baseline
`0d211700764e30c6c69eecfe3129a08a1597db64`, using:

- `rustc 1.97.1 (8bab26f4f 2026-07-14)`;
- `cargo 1.97.1 (c980f4866 2026-06-30)`;
- `hickory-proto` 0.25.2;
- release profile `opt-level="z"`, `lto=true`, `codegen-units=1`,
  `panic="abort"`, and `strip=true`.

The target was installed from writable copies of `RUSTUP_HOME` and
`CARGO_HOME`; the earlier installation failure came from the runtime user's
lack of write access to `/usr/local/rustup`, not from the proof.

```text
$ CARGO_TARGET_DIR=target/amt01-baseline cargo build --lib --release \
    --target wasm32-unknown-unknown --no-default-features --features wasm
   Compiling amt-protocol v0.1.0
    Finished `release` profile [optimized] target(s) in 41.94s

$ CARGO_TARGET_DIR=target/amt01-candidate cargo build --lib --release \
    --target wasm32-unknown-unknown --no-default-features --features wasm,hickory-proof
   Compiling hickory-proto v0.25.2
   Compiling amt-protocol v0.1.0
    Finished `release` profile [optimized] target(s) in 51.69s

$ wc -c target/amt01-{baseline,candidate}/wasm32-unknown-unknown/release/amt_protocol.wasm
 459689 target/amt01-baseline/wasm32-unknown-unknown/release/amt_protocol.wasm
 800947 target/amt01-candidate/wasm32-unknown-unknown/release/amt_protocol.wasm

$ gzip -9 -c target/amt01-baseline/wasm32-unknown-unknown/release/amt_protocol.wasm | wc -c
115039
$ gzip -9 -c target/amt01-candidate/wasm32-unknown-unknown/release/amt_protocol.wasm | wc -c
227697

$ sha256sum target/amt01-{baseline,candidate}/wasm32-unknown-unknown/release/amt_protocol.wasm
a06ded1c217a3d80a66e178413bc543d3a281afbe7919680761b421da047e966  target/amt01-baseline/wasm32-unknown-unknown/release/amt_protocol.wasm
3d2ad9fc990fb719110a2aabc6c2c3981d2fc553ef6963d11368246d13fbc8dc  target/amt01-candidate/wasm32-unknown-unknown/release/amt_protocol.wasm
```

| Artifact | Baseline | Candidate | Delta |
|---|---:|---:|---:|
| Raw WASM | 459,689 B | 800,947 B | +341,258 B (+74.24%) |
| gzip -9 | 115,039 B | 227,697 B | +112,658 B (+97.93%) |

A direct WASM export-section parse produced:

```text
amt01-baseline:  total_exports=1607  hickory_exports=[]
amt01-candidate: total_exports=1610  hickory_exports=[('__wbindgen_describe_hickory_proof_accepts', 0), ('hickory_proof_accepts', 0)]
```

This verifies the proof export survived release LTO. The measured candidate
nearly doubles the compressed browser payload, so the current Hickory shape
remains blocked rather than authorized for production cutover.

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

**Blocked.** Native and WASM behavior feasibility is proven, but the measured
candidate adds 341,258 raw bytes (+74.24%), 112,658 gzip bytes (+97.93%), 73
normal dependency nodes, and 32.6% clean native build time. This branch does
not authorize or implement the production cutover.
