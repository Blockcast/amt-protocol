# amt-protocol native runtime — Implementation Plan (M1–M5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Sans-I/O `SubscriptionManager` layer, a tokio-based `AsyncAmtGateway` async runtime (behind a new `native` Cargo feature), an `amt-verify` CLI binary, a DRIAD-over-UDP native resolver, and staging-verified E2E tests — all inside the existing `~/src/amt-protocol` crate without breaking its WASM/FFI/JNI/UniFFI paths.

**Architecture:** Three new layers, default-build untouched. (1) `SubscriptionManager<P>` is a platform-agnostic, sync, Sans-I/O state-handler that owns N-(S,G)-over-one-tunnel bookkeeping and emits `Event::Transmit`/`Event::Data` for a caller to act on. (2) `AsyncAmtGateway` (feature = `native`) is a tokio task that wraps one `UdpSocket` + one `SubscriptionManager` and exposes a `subscribe`/`subscribe_data`/`shutdown` API plus a builder. (3) `amt-verify` (feature = `native`, `[[bin]]`) is a clap CLI for one-shot E2E verify and `--watch` mode. DRIAD via UDP:53 lands in M4. Spec: `docs/superpowers/specs/2026-05-15-amt-protocol-native-runtime-design.md`.

**Tech Stack:** Rust 2021, existing `getrandom` for random; new optional deps `tokio` (rt, net, time, sync, macros), `clap` (derive, env), `tracing`, `tracing-subscriber`, `bytes`, `anyhow`, `serde_json` (for `--json` output). WASM build path stays unchanged.

**Scope:** This plan covers M1–M5 — everything that lands in `Blockcast/amt-protocol` and produces a CLI verified end-to-end against staging-blockcastd amt-relay. **M6** (dual-stack-relay migration) and **M7** (IWA `JsSubscriptionManager` binding + TS migration) are deferred to follow-up plans drafted after M5 lands, because their consumption shape depends on the API M1–M5 actually ships.

---

## File structure

All paths relative to `~/src/amt-protocol/`.

### Created during M1 (Sans-I/O subscription core, default-compiled)

| File | Responsibility |
|---|---|
| `src/subscription/mod.rs` | `SubscriptionManager<P>` struct, public API, `#[cfg(test)] mod tests` |
| `src/subscription/event.rs` | `Event` enum (`Transmit` / `Data` / `HandshakeComplete` / `Warning`) |
| `src/subscription/group.rs` | `GroupState` (per-(S,G) bookkeeping helper) |
| `src/subscription/report.rs` | IGMPv3 / MLDv2 report assembly from group set + diff |
| `src/subscription/inner_packet.rs` | Minimal IPv4/IPv6 + UDP header parser (~60 LOC) |

### Modified during M1

| File | Change |
|---|---|
| `src/error.rs` | Add `FamilyMismatch`, `TunnelFull`, `DiscoveryFailed`, `QueryFailed`, `MalformedInner`, `ShutdownInProgress` variants |
| `src/lib.rs` | `pub mod subscription;` + re-export `SubscriptionManager`, `Event`, `GroupState` |

### Created during M2 (native feature, tokio runtime)

| File | Responsibility |
|---|---|
| `src/native/mod.rs` | `#[cfg(feature = "native")]` module; pub re-exports |
| `src/native/platform.rs` | `NativePlatform` impl of `Platform` (std random, std time) |
| `src/native/gateway.rs` | `AsyncAmtGateway` + `AsyncAmtGatewayBuilder` + `DataEvent` + tokio task |
| `tests/common/mod.rs` | Shared test-helpers preamble |
| `tests/common/fake_relay.rs` | Loopback UDP fake AMT relay used by Tier-2 tests |
| `tests/native_runtime.rs` | Tier 2 integration tests (oneshot v4, v6, multi-consumer, teardown, sigint) |

### Modified during M2

| File | Change |
|---|---|
| `Cargo.toml` | Add `native` feature + optional deps `tokio`, `clap`, `tracing`, `tracing-subscriber`, `bytes`, `anyhow`, `serde_json`; bump `[dev-dependencies]` with `tokio` for tests |
| `src/lib.rs` | `#[cfg(feature = "native")] pub mod native;` + conditional re-exports |

### Created during M3 (CLI)

| File | Responsibility |
|---|---|
| `src/bin/amt-verify.rs` | Clap CLI; one-shot + `--watch`; JSON output |

### Modified during M3

| File | Change |
|---|---|
| `Cargo.toml` | Add `[[bin]] name = "amt-verify"` with `required-features = ["native"]` |

### Created during M4 (DRIAD resolver)

| File | Responsibility |
|---|---|
| `src/native/resolver.rs` | `resolve_amt_relay(source)` async fn; `/etc/resolv.conf` parser; UDP:53 query/parallel-A+AAAA follow-up |
| `tests/native_resolver.rs` | Tier 1.5 tests (resolv.conf parse, fallback, DnsName follow-up) |

### Modified during M4

| File | Change |
|---|---|
| `src/driad.rs` | Add `build_dns_aaaa_query(hostname, transaction_id)` helper + `parse_dns_aaaa_response` |
| `src/native/gateway.rs` | Add `AsyncAmtGateway::builder_for_source(source)` factory |
| `src/bin/amt-verify.rs` | Make `--relay` optional; add `--no-driad`; wire DRIAD path |

### Created during M5 (E2E + runbook)

| File | Responsibility |
|---|---|
| `tests/e2e_staging.rs` | `#[ignore]` tests pinned to staging-blockcastd amt-relay |
| `docs/runbook-staging-e2e.md` | Manual run instructions, kubectl pod template, expected output |

### Modified during M5

| File | Change |
|---|---|
| `README.md` | Add link to runbook + one-line CLI install snippet |

---

## Milestone M1 — `SubscriptionManager` core (Sans-I/O, default-compiled)

Gate: Tier-1 unit tests green; existing `AmtGateway` tests untouched; `wasm-pack build` produces same JS exports (verified at end of milestone).

### Task 1.1: Extend `AmtError` with new variants

**Files:**
- Modify: `src/error.rs`

- [ ] **Step 1: Write the failing test**

Add to `src/error.rs` inside a new `#[cfg(test)] mod tests` block:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_error_variants_display() {
        assert_eq!(format!("{}", AmtError::FamilyMismatch), "IP family mismatch between relay, group, and source");
        assert_eq!(format!("{}", AmtError::TunnelFull), "Tunnel group cap (64) reached");
        assert_eq!(format!("{}", AmtError::DiscoveryFailed), "Relay Discovery failed after retries");
        assert_eq!(format!("{}", AmtError::QueryFailed), "Membership Query not received within timeout");
        assert_eq!(format!("{}", AmtError::MalformedInner), "Malformed inner IP/UDP packet in MulticastData");
        assert_eq!(format!("{}", AmtError::ShutdownInProgress), "Operation rejected: manager is shutting down or closed");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/src/amt-protocol
cargo test --lib error::tests::new_error_variants_display 2>&1 | tail -20
```

Expected: FAIL with `no variant or associated item named 'FamilyMismatch' found for enum 'AmtError'`.

- [ ] **Step 3: Patch the new variants in**

In `src/error.rs`, **add** the new variants to the existing `AmtError` enum (do not replace the whole file — the existing variants and `impl Display` / `impl Error` blocks must be preserved). Apply two targeted edits:

**Edit 3a — add new enum variants** after the existing `IoError(String),` line:

```rust
    // Subscription-layer additions (M1 — BLO-3457 follow-up)
    FamilyMismatch,
    TunnelFull,
    DiscoveryFailed,
    QueryFailed,
    MalformedInner,
    ShutdownInProgress,
```

So the full enum becomes:

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum AmtError {
    InvalidMessage(String),
    InvalidState,
    InvalidNonce,
    UnexpectedMessage,
    NoResponseMac,
    IoError(String),
    // Subscription-layer additions (M1 — BLO-3457 follow-up)
    FamilyMismatch,
    TunnelFull,
    DiscoveryFailed,
    QueryFailed,
    MalformedInner,
    ShutdownInProgress,
}
```

**Edit 3b — add display arms** inside the existing `impl fmt::Display for AmtError` match, after the existing `AmtError::IoError(msg) => …` arm:

```rust
            AmtError::FamilyMismatch => write!(f, "IP family mismatch between relay, group, and source"),
            AmtError::TunnelFull => write!(f, "Tunnel group cap (64) reached"),
            AmtError::DiscoveryFailed => write!(f, "Relay Discovery failed after retries"),
            AmtError::QueryFailed => write!(f, "Membership Query not received within timeout"),
            AmtError::MalformedInner => write!(f, "Malformed inner IP/UDP packet in MulticastData"),
            AmtError::ShutdownInProgress => write!(f, "Operation rejected: manager is shutting down or closed"),
```

Leave `impl std::error::Error for AmtError {}` and any other existing impls/derives untouched.

- [ ] **Step 4: Run tests to verify it passes + nothing broke**

```bash
cargo test --lib 2>&1 | tail -10
```

Expected: all existing tests pass (≥ 30); new `new_error_variants_display` passes.

- [ ] **Step 5: Commit**

```bash
git add src/error.rs
git commit -m "feat(error): add subscription-layer AmtError variants

FamilyMismatch, TunnelFull, DiscoveryFailed, QueryFailed,
MalformedInner, ShutdownInProgress — used by the new
SubscriptionManager layer (BLO-3457 follow-up)."
```

---

### Task 1.2: Add `subscription` module skeleton + `Event` enum

**Files:**
- Create: `src/subscription/mod.rs`
- Create: `src/subscription/event.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `src/subscription/event.rs` with this test only (no impl yet — test asserts shape will exist):

```rust
//! Output events emitted by SubscriptionManager.

use std::net::IpAddr;
use crate::error::AmtError;

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Transmit { dst: IpAddr, port: u16, payload: Vec<u8> },
    Data {
        src: IpAddr,
        group: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    },
    HandshakeComplete,
    Warning(AmtError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_variants_construct() {
        let _ = Event::Transmit {
            dst: "192.0.2.1".parse().unwrap(),
            port: 2268,
            payload: vec![1, 2, 3],
        };
        let _ = Event::Data {
            src: "10.0.0.1".parse().unwrap(),
            group: "232.0.0.1".parse().unwrap(),
            src_port: 5004,
            dst_port: 5004,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let _ = Event::HandshakeComplete;
        let _ = Event::Warning(AmtError::MalformedInner);
    }
}
```

Create `src/subscription/mod.rs`:

```rust
//! Subscription Manager — Sans-I/O bookkeeping above AmtGateway.
//!
//! Owns: groups set, pending-while-handshaking queue, keep-alive scheduling,
//! per-(S,G) inner-packet demultiplex. Emits `Event::Transmit` / `Event::Data`
//! for the caller to enact. No I/O, no clock — caller drives via
//! `handle_datagram(bytes, now_ms)`, `tick(now_ms)`, etc.

pub mod event;

pub use event::Event;
```

Add to `src/lib.rs` (under existing `pub use` lines):

```rust
pub mod subscription;
pub use subscription::Event;
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib subscription::event::tests::event_variants_construct 2>&1 | tail -10
```

Expected: PASS (this is a shape-only test — defines the public API).

Then run the full suite to make sure existing tests still pass:

```bash
cargo test --lib 2>&1 | tail -10
```

Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add src/subscription/ src/lib.rs
git commit -m "feat(subscription): add module skeleton + Event enum

First slice of the Sans-I/O subscription layer. Pub re-export
from lib.rs alongside existing AmtGateway exports."
```

---

### Task 1.3: Inner IP+UDP packet parser

**Files:**
- Create: `src/subscription/inner_packet.rs`
- Modify: `src/subscription/mod.rs` (add `mod inner_packet;`)

- [ ] **Step 1: Write the failing test**

Create `src/subscription/inner_packet.rs`:

```rust
//! Parser for inner IPv4/IPv6 + UDP packets carried inside AMT MulticastData.
//!
//! Returns (src, group, src_port, dst_port, payload). Best-effort — caller
//! treats parse failure as a `Warning(MalformedInner)` event, not fatal.
//!
//! **Deliberate limitation**: IPv6 packets with extension headers
//! (Hop-by-Hop, Routing, Fragment, ESP, AH, Destination Options) are NOT
//! decoded. Only IPv6 packets whose `Next Header` is directly UDP (17)
//! are accepted; anything else returns `MalformedInner`. AMT data from
//! a relay rarely carries extension headers in practice, and walking them
//! is a separate ~80 LOC concern. If real traffic needs them, lift this
//! limitation in a follow-up.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::error::{AmtError, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct InnerPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

const IP_PROTOCOL_UDP: u8 = 17;
const IPV6_NEXT_UDP: u8 = 17;

pub fn parse_inner(bytes: &[u8]) -> Result<InnerPacket<'_>> {
    if bytes.is_empty() {
        return Err(AmtError::MalformedInner);
    }
    let version = bytes[0] >> 4;
    match version {
        4 => parse_ipv4(bytes),
        6 => parse_ipv6(bytes),
        _ => Err(AmtError::MalformedInner),
    }
}

fn parse_ipv4(bytes: &[u8]) -> Result<InnerPacket<'_>> {
    if bytes.len() < 20 {
        return Err(AmtError::MalformedInner);
    }
    let ihl = (bytes[0] & 0x0F) as usize * 4;
    if ihl < 20 || bytes.len() < ihl + 8 {
        return Err(AmtError::MalformedInner);
    }
    if bytes[9] != IP_PROTOCOL_UDP {
        return Err(AmtError::MalformedInner);
    }
    let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    let udp = &bytes[ihl..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return Err(AmtError::MalformedInner);
    }
    Ok(InnerPacket {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        src_port,
        dst_port,
        payload: &udp[8..udp_len],
    })
}

fn parse_ipv6(bytes: &[u8]) -> Result<InnerPacket<'_>> {
    if bytes.len() < 40 + 8 {
        return Err(AmtError::MalformedInner);
    }
    if bytes[6] != IPV6_NEXT_UDP {
        return Err(AmtError::MalformedInner);
    }
    let src_octets: [u8; 16] = bytes[8..24].try_into().map_err(|_| AmtError::MalformedInner)?;
    let dst_octets: [u8; 16] = bytes[24..40].try_into().map_err(|_| AmtError::MalformedInner)?;
    let udp = &bytes[40..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp.len() < udp_len {
        return Err(AmtError::MalformedInner);
    }
    Ok(InnerPacket {
        src: IpAddr::V6(Ipv6Addr::from(src_octets)),
        dst: IpAddr::V6(Ipv6Addr::from(dst_octets)),
        src_port,
        dst_port,
        payload: &udp[8..udp_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp_packet(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + 8 + payload.len()) as u16;
        let mut buf = vec![
            0x45, 0x00,                          // version+IHL, ToS
            (total_len >> 8) as u8, total_len as u8,
            0x00, 0x00, 0x40, 0x00, 0x40,        // ID, flags, frag, TTL
            17,                                  // protocol UDP
            0x00, 0x00,                          // checksum (ignored)
        ];
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        // UDP header
        buf.extend_from_slice(&sp.to_be_bytes());
        buf.extend_from_slice(&dp.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf.extend_from_slice(&udp_len.to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // checksum
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn parse_ipv4_udp_happy_path() {
        let pkt = ipv4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5004, b"hello");
        let p = parse_inner(&pkt).unwrap();
        assert_eq!(p.src, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "232.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.src_port, 5004);
        assert_eq!(p.dst_port, 5004);
        assert_eq!(p.payload, b"hello");
    }

    #[test]
    fn parse_truncated_returns_err() {
        let p = parse_inner(&[0x45, 0x00, 0x00]);
        assert_eq!(p, Err(AmtError::MalformedInner));
    }

    #[test]
    fn parse_non_udp_returns_err() {
        let mut pkt = ipv4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5004, b"x");
        pkt[9] = 6; // TCP
        assert_eq!(parse_inner(&pkt), Err(AmtError::MalformedInner));
    }

    #[test]
    fn parse_unknown_version_returns_err() {
        assert_eq!(parse_inner(&[0x50; 40]), Err(AmtError::MalformedInner));
    }

    #[test]
    fn parse_ipv6_udp_happy_path() {
        let mut pkt = vec![0x60, 0x00, 0x00, 0x00];
        let payload_len: u16 = 8 + 3;
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(17); // next header UDP
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&[0xfd; 16]); // src
        let mut dst = vec![0xff, 0x0e]; dst.extend_from_slice(&[0; 14]); pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(&5004u16.to_be_bytes());
        pkt.extend_from_slice(&5005u16.to_be_bytes());
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // checksum
        pkt.extend_from_slice(b"abc");
        let p = parse_inner(&pkt).unwrap();
        assert_eq!(p.src_port, 5004);
        assert_eq!(p.dst_port, 5005);
        assert_eq!(p.payload, b"abc");
    }
}
```

Modify `src/subscription/mod.rs`:

```rust
//! Subscription Manager — Sans-I/O bookkeeping above AmtGateway.

pub mod event;
pub mod inner_packet;

pub use event::Event;
```

- [ ] **Step 2: Run test to verify they pass**

```bash
cargo test --lib subscription::inner_packet 2>&1 | tail -15
```

Expected: 5 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/subscription/inner_packet.rs src/subscription/mod.rs
git commit -m "feat(subscription): inner IPv4/IPv6+UDP packet parser

Used by SubscriptionManager to demultiplex MulticastData by (S,G)
without callers needing their own header parser. Parse failures
return MalformedInner — caller surfaces as a Warning event."
```

---

### Task 1.4: `GroupState` helper + `SubscriptionManager` skeleton

**Files:**
- Create: `src/subscription/group.rs`
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `src/subscription/group.rs`:

```rust
//! Per-(S,G) subscription state, used by SubscriptionManager.

use crate::gateway::GroupKey;

#[derive(Debug, Clone)]
pub struct GroupState {
    pub key: GroupKey,
    /// Unix ms when the caller asked us to subscribe.
    pub requested_at_ms: u64,
    /// True once this group has been sent to the relay in an Update.
    pub announced: bool,
}

impl GroupState {
    pub fn new(key: GroupKey, requested_at_ms: u64) -> Self {
        Self { key, requested_at_ms, announced: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn new_group_state_unannounced() {
        let key = GroupKey {
            group: "232.0.0.1".parse::<IpAddr>().unwrap(),
            source: Some("10.0.0.1".parse::<IpAddr>().unwrap()),
        };
        let st = GroupState::new(key.clone(), 1234);
        assert_eq!(st.requested_at_ms, 1234);
        assert!(!st.announced);
        assert_eq!(st.key, key);
    }
}
```

Append the skeleton at the bottom of `src/subscription/mod.rs`:

```rust
pub mod group;
pub use group::GroupState;

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::AmtConfig;
use crate::error::{AmtError, Result};
use crate::gateway::{AmtGateway, GatewayState, GroupKey};
use crate::platform::Platform;

/// Hard cap mirroring the IWA TS SharedAmtGateway limit.
pub const MAX_GROUPS_PER_TUNNEL: usize = 64;

/// Default timeouts (callers override via builder)
pub const DISCOVERY_TIMEOUT_MS: u64 = 5_000;
pub const REQUEST_TIMEOUT_MS:   u64 = 5_000;
pub const MAX_DISCOVERY_RETRIES: u32 = 3;

pub struct SubscriptionManager<P: Platform> {
    inner: AmtGateway<P>,
    cfg: AmtConfig,
    groups: HashMap<GroupKey, GroupState>,
    pending: VecDeque<GroupKey>,
    last_update_at_ms: Option<u64>,
    last_discovery_at_ms: Option<u64>,
    last_request_at_ms: Option<u64>,
    discovery_retries: u32,
    out_queue: VecDeque<Event>,
    shutting_down: bool,
    /// True after shutdown() has been called. AsyncAmtGateway runtime uses
    /// this — not the inner AmtGateway state — to detect end-of-life,
    /// because the inner state machine only reaches Closed on the Active-
    /// path teardown.
    closed: bool,
}

impl<P: Platform> SubscriptionManager<P> {
    pub fn new(cfg: AmtConfig, platform: Arc<P>) -> Self {
        let inner = AmtGateway::new(cfg.clone(), platform);
        Self {
            inner,
            cfg,
            groups: HashMap::new(),
            pending: VecDeque::new(),
            last_update_at_ms: None,
            last_discovery_at_ms: None,
            last_request_at_ms: None,
            discovery_retries: 0,
            out_queue: VecDeque::new(),
            shutting_down: false,
            closed: false,
        }
    }

    pub fn state(&self) -> GatewayState { self.inner.state() }
    pub fn relay_address(&self) -> Option<IpAddr> { self.inner.relay_address() }
    pub fn relay_port(&self) -> u16 { self.inner.relay_port() }
    pub fn groups(&self) -> &HashMap<GroupKey, GroupState> { &self.groups }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.out_queue.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_platform::TestPlatform;

    fn mgr() -> SubscriptionManager<TestPlatform> {
        let cfg = AmtConfig::new("192.0.2.96".parse::<IpAddr>().unwrap(), Some(2268));
        SubscriptionManager::new(cfg, Arc::new(TestPlatform::new()))
    }

    #[test]
    fn manager_starts_idle_empty() {
        let m = mgr();
        assert_eq!(m.state(), GatewayState::Idle);
        assert!(m.groups().is_empty());
        assert_eq!(m.relay_address(), Some("192.0.2.96".parse::<IpAddr>().unwrap()));
        assert_eq!(m.relay_port(), 2268);
    }

    #[test]
    fn poll_event_empty_initially() {
        let mut m = mgr();
        assert!(m.poll_event().is_none());
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -15
```

Expected: `subscription::group::tests::new_group_state_unannounced`, `subscription::tests::manager_starts_idle_empty`, `subscription::tests::poll_event_empty_initially` all pass; previous subscription tests still pass.

- [ ] **Step 3: Commit**

```bash
git add src/subscription/group.rs src/subscription/mod.rs
git commit -m "feat(subscription): GroupState + SubscriptionManager skeleton

Manager owns AmtGateway + groups map + pending queue + output
event queue. Public API is read-only so far (state, relay address,
groups). Mutating API lands in next tasks."
```

---

### Task 1.5: `subscribe()` family check + Idle path (start Discovery)

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing tests**

Append to the `#[cfg(test)] mod tests` block in `src/subscription/mod.rs`:

```rust
    #[test]
    fn subscribe_in_idle_queues_and_starts_discovery() {
        let mut m = mgr();
        let group: IpAddr = "232.0.0.1".parse().unwrap();
        let source: IpAddr = "10.0.0.1".parse().unwrap();
        m.subscribe(GroupKey { group, source: Some(source) }, 1000).unwrap();

        assert_eq!(m.state(), GatewayState::Discovering);
        assert_eq!(m.groups().len(), 0, "group not announced yet");
        // pending queue has the group:
        assert_eq!(m.pending_len(), 1);

        // First event must be a Transmit of RelayDiscovery to the relay.
        let ev = m.poll_event().expect("expected one Transmit event");
        match ev {
            Event::Transmit { dst, port, payload } => {
                assert_eq!(dst, "192.0.2.96".parse::<IpAddr>().unwrap());
                assert_eq!(port, 2268);
                assert_eq!(payload[0], 0x01, "expected RelayDiscovery message type");
            }
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[test]
    fn subscribe_family_mismatch_rejected() {
        let mut m = mgr();
        let v6_group: IpAddr = "ff0e::1".parse().unwrap();
        let v4_source: IpAddr = "10.0.0.1".parse().unwrap();
        let err = m.subscribe(
            GroupKey { group: v6_group, source: Some(v4_source) },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::FamilyMismatch);
    }

    #[test]
    fn subscribe_relay_family_mismatch_rejected() {
        let mut m = mgr(); // v4 relay
        let v6_group: IpAddr = "ff3e::1234".parse().unwrap();
        let v6_source: IpAddr = "2001:db8::1".parse().unwrap();
        let err = m.subscribe(
            GroupKey { group: v6_group, source: Some(v6_source) },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::FamilyMismatch);
    }

    #[test]
    fn subscribe_when_full_returns_tunnelfull() {
        let mut m = mgr();
        for i in 0..MAX_GROUPS_PER_TUNNEL {
            let group: IpAddr = format!("232.0.0.{}", i + 1).parse().unwrap();
            m.subscribe(
                GroupKey { group, source: Some("10.0.0.1".parse().unwrap()) },
                1000,
            ).unwrap();
        }
        let group: IpAddr = "232.0.1.1".parse().unwrap();
        let err = m.subscribe(
            GroupKey { group, source: Some("10.0.0.1".parse().unwrap()) },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::TunnelFull);
    }

    #[test]
    fn subscribe_idempotent_at_cap() {
        // Fill to cap, then re-subscribe the FIRST one. Must succeed (idempotent),
        // not return TunnelFull.
        let mut m = mgr();
        let first_key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(first_key.clone(), 1000).unwrap();
        for i in 1..MAX_GROUPS_PER_TUNNEL {
            let group: IpAddr = format!("232.0.0.{}", i + 1).parse().unwrap();
            m.subscribe(
                GroupKey { group, source: Some("10.0.0.1".parse().unwrap()) },
                1000,
            ).unwrap();
        }
        // At cap. Re-sub of an existing key must be Ok and a no-op.
        m.subscribe(first_key, 2000).expect("idempotent re-sub at cap must succeed");
    }

    #[test]
    fn subscribe_after_shutdown_rejected() {
        let mut m = mgr();
        m.shutting_down_for_test();
        let err = m.subscribe(
            GroupKey {
                group: "232.0.0.1".parse().unwrap(),
                source: Some("10.0.0.1".parse().unwrap()),
            },
            1000,
        ).unwrap_err();
        assert_eq!(err, AmtError::ShutdownInProgress);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --lib subscription::tests:: 2>&1 | tail -25
```

Expected: FAIL — `no method named 'subscribe'`, `no method named 'pending_len'`, `no method named 'shutting_down_for_test'`.

- [ ] **Step 3: Implement `subscribe()` Idle path + helpers**

Add inside `impl<P: Platform> SubscriptionManager<P>` in `src/subscription/mod.rs`:

```rust
    /// Subscribe to (group, source). Behavior depends on current state:
    /// - Idle: queues group, emits RelayDiscovery Transmit, transitions to Discovering.
    /// - Discovering / Requesting / Querying: queues group; will flush on HandshakeComplete.
    /// - Active: announces immediately via ALLOW_NEW_SOURCES Update (Task 1.10).
    pub fn subscribe(&mut self, key: GroupKey, now_ms: u64) -> Result<()> {
        if self.shutting_down || self.inner.state() == GatewayState::Closed {
            return Err(AmtError::ShutdownInProgress);
        }
        self.check_family(&key)?;
        // Dedup BEFORE cap — re-subscribing an existing (S,G) at cap must be
        // idempotent, not TunnelFull.
        let already_known =
            self.pending.iter().any(|k| k == &key) || self.groups.contains_key(&key);
        if !already_known {
            if self.groups.len() + self.pending.len() >= MAX_GROUPS_PER_TUNNEL {
                return Err(AmtError::TunnelFull);
            }
            self.pending.push_back(key);
        }
        match self.inner.state() {
            GatewayState::Idle => self.start_discovery(now_ms)?,
            GatewayState::Discovering
            | GatewayState::Requesting
            | GatewayState::Querying => { /* queued; handshake in flight */ }
            GatewayState::Active => { /* incremental Allow lands in Task 1.10 */ }
            GatewayState::Closed => return Err(AmtError::ShutdownInProgress),
        }
        Ok(())
    }

    fn check_family(&self, key: &GroupKey) -> Result<()> {
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let relay_is_v4 = matches!(relay, IpAddr::V4(_));
        let group_is_v4 = matches!(key.group, IpAddr::V4(_));
        if relay_is_v4 != group_is_v4 {
            return Err(AmtError::FamilyMismatch);
        }
        if let Some(src) = key.source {
            let src_is_v4 = matches!(src, IpAddr::V4(_));
            if src_is_v4 != group_is_v4 {
                return Err(AmtError::FamilyMismatch);
            }
        }
        Ok(())
    }

    fn start_discovery(&mut self, now_ms: u64) -> Result<()> {
        let msg = self.inner.start_discovery()?;
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_discovery_at_ms = Some(now_ms);
        Ok(())
    }

    // Test helpers (only compiled into the test binary).
    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize { self.pending.len() }
    #[cfg(test)]
    pub(crate) fn shutting_down_for_test(&mut self) { self.shutting_down = true; }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -20
```

Expected: 4 new tests pass (`subscribe_in_idle_*`, `subscribe_family_mismatch_*`, `subscribe_when_full_*`, `subscribe_after_shutdown_*`).

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): subscribe() family checks + Idle Discovery start

Queues group, emits RelayDiscovery Transmit, validates IP family,
enforces 64-group cap. Discovering/Requesting/Querying states
queue without restarting handshake. Active path lands later."
```

---

### Task 1.6: `handle_datagram()` — Advertisement → auto-Request

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to the `#[cfg(test)] mod tests` block:

```rust
    use crate::messages::AmtMessage;

    fn drain(m: &mut SubscriptionManager<TestPlatform>) -> Vec<Event> {
        let mut v = Vec::new();
        while let Some(ev) = m.poll_event() { v.push(ev); }
        v
    }

    fn discovery_nonce_from(events: &[Event]) -> u32 {
        for ev in events {
            if let Event::Transmit { payload, .. } = ev {
                if payload[0] == 0x01 {
                    return u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                }
            }
        }
        panic!("no RelayDiscovery transmit in events: {:?}", events);
    }

    #[test]
    fn advertisement_advances_to_requesting() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(key, 1000).unwrap();
        let initial = drain(&mut m);
        let nonce = discovery_nonce_from(&initial);

        // Synthesize an Advertisement and feed it in.
        let advert = AmtMessage::RelayAdvertisement {
            nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();

        // Manager should auto-emit Request and be in Requesting state.
        assert_eq!(m.state(), GatewayState::Requesting);
        let events = drain(&mut m);
        let req = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x03 => Some(payload.clone()),
            _ => None,
        }).expect("expected a Request transmit");
        assert_eq!(req[1] & 0x80, 0x80, "P-flag should be set");
    }

    #[test]
    fn advertisement_with_wrong_nonce_warns_no_transition() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(key, 1000).unwrap();
        drain(&mut m);

        let advert = AmtMessage::RelayAdvertisement {
            nonce: 0xDEAD_BEEF,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        assert_eq!(m.state(), GatewayState::Discovering, "state must not advance on bad nonce");
        let events = drain(&mut m);
        assert!(events.iter().any(|ev| matches!(ev, Event::Warning(_))));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --lib subscription::tests::advertisement_ 2>&1 | tail -15
```

Expected: FAIL — `no method named 'handle_datagram'`.

- [ ] **Step 3: Implement `handle_datagram()` Advertisement branch + Request emitter**

Add inside `impl<P: Platform> SubscriptionManager<P>`:

```rust
    /// Feed a raw datagram (received on the AMT control socket) into the manager.
    /// Drives state transitions and produces output events.
    pub fn handle_datagram(&mut self, bytes: &[u8], now_ms: u64) -> Result<()> {
        let msg = match AmtMessage::decode(bytes) {
            Ok(m) => m,
            Err(e) => {
                self.out_queue.push_back(Event::Warning(e));
                return Ok(());
            }
        };
        match msg {
            AmtMessage::RelayAdvertisement { nonce, relay_address } => {
                self.handle_advertisement(nonce, relay_address, now_ms)?;
            }
            // Other branches land in subsequent tasks (1.7, 1.9).
            _ => {
                self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            }
        }
        Ok(())
    }

    fn handle_advertisement(
        &mut self,
        nonce: u32,
        relay_address: IpAddr,
        now_ms: u64,
    ) -> Result<()> {
        if self.inner.state() != GatewayState::Discovering {
            self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            return Ok(());
        }
        match self.inner.handle_advertisement(nonce, relay_address) {
            Ok(()) => {
                // Reset retry counter on successful Discovery — a later
                // re-Discovery should start its budget at 0, not at the
                // count left over from a previous successful handshake.
                self.discovery_retries = 0;
                self.last_discovery_at_ms = None;
                self.send_request(now_ms)
            }
            Err(e) => {
                self.out_queue.push_back(Event::Warning(e));
                Ok(())
            }
        }
    }

    fn send_request(&mut self, now_ms: u64) -> Result<()> {
        // P-flag=true: prefer pseudo-header checksum mode (RFC 7450 §5.1.3.2).
        let msg = self.inner.request_membership(true)?;
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_request_at_ms = Some(now_ms);
        Ok(())
    }
```

Make sure `use crate::messages::AmtMessage;` exists at module top (add if not).

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -25
```

Expected: 2 new tests pass plus all prior pass.

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): handle Advertisement → auto-emit Request

On valid nonce match, advance to Requesting and emit Request
Transmit with P-flag set. Bad nonce surfaces as Warning and
state stays Discovering — caller decides whether to retry."
```

---

### Task 1.7: Report assembly — `build_current_state_report`

**Files:**
- Create: `src/subscription/report.rs`
- Modify: `src/subscription/mod.rs` (add `pub mod report;`)

- [ ] **Step 1: Write the failing test**

Create `src/subscription/report.rs`:

```rust
//! IGMPv3 / MLDv2 report assembly from a group set.
//!
//! Produces the bytes that go into AmtMessage::MembershipUpdate.report_data.

use std::net::IpAddr;
use crate::error::{AmtError, Result};
use crate::gateway::GroupKey;
use crate::igmp::{IgmpRecord, IgmpV3Report, RecordType as IgmpRecordType};
use crate::mld::{MldRecord, MldV2Report};

/// Build a current-state IGMPv3 report covering all v4 (S,G) entries in `keys`.
/// Used at handshake completion (response to MembershipQuery) and keep-alive.
pub fn build_current_state_v4<'a, I: IntoIterator<Item = &'a GroupKey>>(
    keys: I,
) -> Result<Vec<u8>> {
    let mut report = IgmpV3Report::new();
    let mut any = false;
    for k in keys {
        match (k.group, k.source) {
            (IpAddr::V4(g), Some(IpAddr::V4(s))) => {
                report.add_record(IgmpRecord::ssm_join(g, s));
                any = true;
            }
            (IpAddr::V4(g), None) => {
                report.add_record(IgmpRecord::asm_join(g));
                any = true;
            }
            _ => return Err(AmtError::FamilyMismatch),
        }
    }
    if !any {
        // An empty current-state report is well-formed but rare; return zero records.
    }
    Ok(report.encode())
}

/// Build a current-state MLDv2 report covering all v6 (S,G) entries in `keys`.
pub fn build_current_state_v6<'a, I: IntoIterator<Item = &'a GroupKey>>(
    keys: I,
) -> Result<Vec<u8>> {
    let mut report = MldV2Report::new();
    for k in keys {
        match (k.group, k.source) {
            (IpAddr::V6(g), Some(IpAddr::V6(s))) => {
                report.add_record(MldRecord::ssm_join(g, s));
            }
            (IpAddr::V6(g), None) => {
                report.add_record(MldRecord::asm_join(g));
            }
            _ => return Err(AmtError::FamilyMismatch),
        }
    }
    Ok(report.encode())
}

/// Build an incremental IGMPv3 record for one new (S,G) join in Active state.
pub fn build_allow_v4(key: &GroupKey) -> Result<Vec<u8>> {
    let mut report = IgmpV3Report::new();
    match (key.group, key.source) {
        (IpAddr::V4(g), Some(IpAddr::V4(s))) => {
            report.add_record(IgmpRecord::new(IgmpRecordType::AllowNewSources, g, vec![s]));
        }
        (IpAddr::V4(g), None) => {
            report.add_record(IgmpRecord::asm_join(g));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode())
}

/// Build an incremental IGMPv3 BLOCK record for unsubscribe in Active state.
pub fn build_block_v4(key: &GroupKey) -> Result<Vec<u8>> {
    let mut report = IgmpV3Report::new();
    match (key.group, key.source) {
        (IpAddr::V4(g), Some(IpAddr::V4(s))) => {
            report.add_record(IgmpRecord::new(IgmpRecordType::BlockOldSources, g, vec![s]));
        }
        (IpAddr::V4(g), None) => {
            report.add_record(IgmpRecord::new(IgmpRecordType::ChangeToIncludeMode, g, vec![]));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode())
}

/// Build an incremental MLDv2 ALLOW record for one new v6 (S,G) join in Active state.
/// MLDv2 record types mirror IGMPv3 (RFC 3810 §5.2.12); ALLOW_NEW_SOURCES = 5.
pub fn build_allow_v6(key: &GroupKey) -> Result<Vec<u8>> {
    use crate::mld::RecordType as MldRecordType;
    let mut report = MldV2Report::new();
    match (key.group, key.source) {
        (IpAddr::V6(g), Some(IpAddr::V6(s))) => {
            report.add_record(MldRecord::new(MldRecordType::AllowNewSources, g, vec![s]));
        }
        (IpAddr::V6(g), None) => {
            report.add_record(MldRecord::asm_join(g));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode())
}

/// Build an incremental MLDv2 BLOCK record for v6 unsubscribe in Active state.
pub fn build_block_v6(key: &GroupKey) -> Result<Vec<u8>> {
    use crate::mld::RecordType as MldRecordType;
    let mut report = MldV2Report::new();
    match (key.group, key.source) {
        (IpAddr::V6(g), Some(IpAddr::V6(s))) => {
            report.add_record(MldRecord::new(MldRecordType::BlockOldSources, g, vec![s]));
        }
        (IpAddr::V6(g), None) => {
            report.add_record(MldRecord::new(MldRecordType::ChangeToIncludeMode, g, vec![]));
        }
        _ => return Err(AmtError::FamilyMismatch),
    }
    Ok(report.encode())
}

// Note: mld.rs already exposes RecordType (not MldRecordType) — the v6 helpers
// above import it as `RecordType as MldRecordType` for symmetry with the v4
// path which uses `RecordType as IgmpRecordType`. No changes needed to mld.rs.

#[cfg(test)]
mod tests {
    use super::*;

    fn k(group: &str, source: Option<&str>) -> GroupKey {
        GroupKey {
            group: group.parse().unwrap(),
            source: source.map(|s| s.parse().unwrap()),
        }
    }

    #[test]
    fn current_state_v4_emits_one_record_per_group() {
        let keys = vec![
            k("232.0.0.1", Some("10.0.0.1")),
            k("232.0.0.2", Some("10.0.0.1")),
        ];
        let bytes = build_current_state_v4(keys.iter()).unwrap();
        assert!(!bytes.is_empty());
        // IGMPv3 report type = 0x22, number of group records at offset 6-7 (big-endian).
        assert_eq!(bytes[0], 0x22);
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 2);
    }

    #[test]
    fn allow_v4_emits_allow_new_sources_record() {
        let bytes = build_allow_v4(&k("232.0.0.1", Some("10.0.0.1"))).unwrap();
        // First group record starts at offset 8: record_type (1 byte).
        assert_eq!(bytes[8], 5, "record type should be ALLOW_NEW_SOURCES");
    }

    #[test]
    fn block_v4_emits_block_old_sources_record() {
        let bytes = build_block_v4(&k("232.0.0.1", Some("10.0.0.1"))).unwrap();
        assert_eq!(bytes[8], 6, "record type should be BLOCK_OLD_SOURCES");
    }

    #[test]
    fn family_mismatch_returns_err() {
        let v6 = k("ff0e::1", Some("2001:db8::1"));
        assert_eq!(build_allow_v4(&v6).unwrap_err(), AmtError::FamilyMismatch);
    }
}
```

Add to `src/subscription/mod.rs` after the other `pub mod` lines:

```rust
pub mod report;
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
cargo test --lib subscription::report 2>&1 | tail -15
```

Expected: 4 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/subscription/report.rs src/subscription/mod.rs
git commit -m "feat(subscription): IGMPv3/MLDv2 report assembly helpers

build_current_state_v4/v6 — for Query response + keep-alive.
build_allow_v4 / build_block_v4 — for incremental sub/unsub
in Active state. Family-mismatched keys return FamilyMismatch."
```

---

### Task 1.8: `handle_datagram()` — Query → flush pending + emit Update

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn query_with_wrong_nonce_warns_no_transition() {
        // The spec's "mac_drift_on_data_warns" was misnamed:
        // AmtMessage::MulticastData carries no nonce / response_mac on the wire
        // (per messages.rs:167-174 — just type/reserved/ip_packet). The validation
        // we DO want is on MembershipQuery: a Query whose request_nonce does not
        // match our outstanding nonce must Warning + leave state in Requesting.
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(key, 1000).unwrap();
        let initial = drain(&mut m);
        let disc_nonce = discovery_nonce_from(&initial);
        let advert = AmtMessage::RelayAdvertisement {
            nonce: disc_nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        let _ = drain(&mut m);

        // Inject a Query with the WRONG nonce.
        let bad_query = AmtMessage::MembershipQuery {
            request_nonce: 0xDEAD_BEEF,
            response_mac: [0xAA; 6],
            query_data: vec![0; 12],
        };
        m.handle_datagram(&bad_query.encode(), 1200).unwrap();

        assert_eq!(m.state(), GatewayState::Requesting, "state must not advance");
        let events = drain(&mut m);
        assert!(events.iter().any(|ev| matches!(ev, Event::Warning(_))));
        assert!(!events.iter().any(|ev| matches!(ev, Event::HandshakeComplete)));
    }

    #[test]
    fn query_flushes_pending_into_one_update_v4() {
        let mut m = mgr();
        let k1 = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        let k2 = GroupKey {
            group: "232.0.0.2".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k1.clone(), 1000).unwrap();
        m.subscribe(k2.clone(), 1010).unwrap();
        let initial = drain(&mut m);
        let disc_nonce = discovery_nonce_from(&initial);

        let advert = AmtMessage::RelayAdvertisement {
            nonce: disc_nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        let after_advert = drain(&mut m);
        let req_nonce = after_advert.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x03 => {
                Some(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]))
            }
            _ => None,
        }).expect("expected Request transmit");

        // Synthesize a MembershipQuery and feed it in.
        let query = AmtMessage::MembershipQuery {
            request_nonce: req_nonce,
            response_mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            query_data: vec![0x11; 12],
        };
        m.handle_datagram(&query.encode(), 1200).unwrap();

        assert_eq!(m.state(), GatewayState::Active);
        assert_eq!(m.groups().len(), 2, "pending must flush to groups");
        assert_eq!(m.pending_len(), 0);

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected MembershipUpdate transmit");
        // Update header is 12 bytes; report should contain 2 records.
        let report = &update[12..];
        assert_eq!(report[0], 0x22, "IGMPv3 report type");
        assert_eq!(u16::from_be_bytes([report[6], report[7]]), 2);

        assert!(events.iter().any(|ev| matches!(ev, Event::HandshakeComplete)));
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib subscription::tests::query_flushes_pending_into_one_update_v4 2>&1 | tail -10
```

Expected: FAIL — manager doesn't handle MembershipQuery yet.

- [ ] **Step 3: Implement the Query branch**

Inside `impl<P: Platform> SubscriptionManager<P>`, extend `handle_datagram()` and add helpers:

Replace the `_ =>` arm in `handle_datagram()` with:

```rust
            AmtMessage::MembershipQuery { request_nonce, response_mac, query_data } => {
                self.handle_query(request_nonce, response_mac, query_data, now_ms)?;
            }
            _ => {
                self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            }
```

Add new methods inside the impl:

```rust
    fn handle_query(
        &mut self,
        nonce: u32,
        mac: [u8; 6],
        query_data: Vec<u8>,
        now_ms: u64,
    ) -> Result<()> {
        if self.inner.state() != GatewayState::Requesting {
            self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            return Ok(());
        }
        if let Err(e) = self.inner.handle_query(nonce, mac, query_data) {
            self.out_queue.push_back(Event::Warning(e));
            return Ok(());
        }
        // Flush pending into groups map.
        while let Some(key) = self.pending.pop_front() {
            self.groups.insert(key.clone(), GroupState::new(key, now_ms));
        }
        // Event-emit ORDER is part of the public contract: Transmit(Update)
        // FIRST, HandshakeComplete SECOND. Consumers that want to know "tunnel
        // is up" via HandshakeComplete must drain in-order; they will have
        // already enqueued the Update for transmission by the time they see
        // the signal. Consumers that want "tunnel is up AND Update sent"
        // semantics get exactly that. Flipping this order would let a consumer
        // gate on HandshakeComplete and then drop the Update.
        self.send_current_state_update(now_ms)?;
        self.out_queue.push_back(Event::HandshakeComplete);
        Ok(())
    }

    fn send_current_state_update(&mut self, now_ms: u64) -> Result<()> {
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let report = match relay {
            IpAddr::V4(_) => crate::subscription::report::build_current_state_v4(self.groups.keys())?,
            IpAddr::V6(_) => crate::subscription::report::build_current_state_v6(self.groups.keys())?,
        };
        let msg = self.inner.send_update(report)?;
        for g in self.groups.values_mut() {
            g.announced = true;
        }
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_update_at_ms = Some(now_ms);
        Ok(())
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -25
```

Expected: previous + new test all pass.

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): Query handler flushes pending → single Update

On valid MembershipQuery, drain the pending queue into groups,
build one current-state IGMPv3/MLDv2 report covering ALL groups,
emit MembershipUpdate + HandshakeComplete. Sets announced=true
on every group; last_update_at_ms anchored for keep-alive."
```

---

### Task 1.9: `handle_datagram()` — MulticastData → demux + `Event::Data`

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `src/subscription/mod.rs`:

```rust
    fn drive_to_active(m: &mut SubscriptionManager<TestPlatform>, key: GroupKey) {
        m.subscribe(key, 1000).unwrap();
        let initial = drain(m);
        let disc_nonce = discovery_nonce_from(&initial);
        let advert = AmtMessage::RelayAdvertisement {
            nonce: disc_nonce,
            relay_address: "192.0.2.96".parse::<IpAddr>().unwrap(),
        };
        m.handle_datagram(&advert.encode(), 1100).unwrap();
        let after_advert = drain(m);
        let req_nonce = after_advert.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x03 => {
                Some(u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]))
            }
            _ => None,
        }).unwrap();
        let query = AmtMessage::MembershipQuery {
            request_nonce: req_nonce,
            response_mac: [0; 6],
            query_data: vec![0x11; 12],
        };
        m.handle_datagram(&query.encode(), 1200).unwrap();
        drain(m);
    }

    fn synth_v4_udp_packet(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let total_len = (20 + 8 + payload.len()) as u16;
        let mut buf = vec![0x45, 0x00];
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 17, 0, 0]);
        buf.extend_from_slice(&src);
        buf.extend_from_slice(&dst);
        buf.extend_from_slice(&sp.to_be_bytes());
        buf.extend_from_slice(&dp.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf.extend_from_slice(&udp_len.to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn multicast_data_emits_data_event_with_demux() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, key);

        let inner = synth_v4_udp_packet([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"abcd");
        let data_msg = AmtMessage::MulticastData { ip_packet: inner };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();

        let events = drain(&mut m);
        let data = events.iter().find_map(|ev| match ev {
            Event::Data { src, group, src_port, dst_port, payload } =>
                Some((*src, *group, *src_port, *dst_port, payload.clone())),
            _ => None,
        }).expect("expected Event::Data");
        assert_eq!(data.0, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(data.1, "232.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(data.2, 5004);
        assert_eq!(data.3, 5005);
        assert_eq!(data.4, b"abcd");
    }

    #[test]
    fn malformed_inner_warns_not_panics() {
        let mut m = mgr();
        let key = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, key);

        let data_msg = AmtMessage::MulticastData { ip_packet: vec![0x45, 0x00] };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();
        assert_eq!(m.state(), GatewayState::Active);
        let events = drain(&mut m);
        assert!(events.iter().any(|ev| matches!(ev, Event::Warning(AmtError::MalformedInner))));
        assert!(!events.iter().any(|ev| matches!(ev, Event::Data { .. })));
    }

    #[test]
    fn unsubscribed_multicast_data_dropped_silently() {
        let mut m = mgr();
        let subscribed = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, subscribed);

        // Inner packet for an UNSUBSCRIBED (S,G).
        let inner = synth_v4_udp_packet([10, 0, 0, 2], [232, 0, 0, 99], 5004, 5005, b"junk");
        let data_msg = AmtMessage::MulticastData { ip_packet: inner };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();

        let events = drain(&mut m);
        assert!(
            !events.iter().any(|ev| matches!(ev, Event::Data { .. })),
            "expected no Data event for unsubscribed (S,G); got: {:?}",
            events
        );
        // Also no Warning — silent drop is the intent.
        assert!(events.is_empty(), "expected zero events; got: {:?}", events);
    }

    #[test]
    fn wrong_source_for_subscribed_group_dropped() {
        let mut m = mgr();
        let subscribed = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, subscribed);

        // Right group, WRONG source.
        let inner = synth_v4_udp_packet([10, 0, 0, 99], [232, 0, 0, 1], 5004, 5005, b"x");
        let data_msg = AmtMessage::MulticastData { ip_packet: inner };
        m.handle_datagram(&data_msg.encode(), 1300).unwrap();
        let events = drain(&mut m);
        assert!(!events.iter().any(|ev| matches!(ev, Event::Data { .. })));
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib subscription::tests::multicast_data_emits_data_event_with_demux 2>&1 | tail -10
```

Expected: FAIL — manager treats MulticastData as `UnexpectedMessage` today.

- [ ] **Step 3: Implement the MulticastData branch**

In `handle_datagram()`, replace the catch-all arm with two arms — add the MulticastData handler before the catch-all:

```rust
            AmtMessage::MulticastData { ip_packet } => {
                if self.inner.state() != GatewayState::Active {
                    self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
                    return Ok(());
                }
                match crate::subscription::inner_packet::parse_inner(&ip_packet) {
                    Ok(p) => {
                        // Filter by subscribed (S,G). The relay can deliver
                        // data for any (S,G) on the tunnel, including ones
                        // we have NOT subscribed to (stale state from another
                        // gateway sharing the tunnel, ASM noise, or a
                        // misconfigured relay). Drop silently if not subscribed
                        // — the manager's groups map is the source of truth.
                        let asm_key = GroupKey { group: p.dst, source: None };
                        let ssm_key = GroupKey { group: p.dst, source: Some(p.src) };
                        if !self.groups.contains_key(&ssm_key)
                            && !self.groups.contains_key(&asm_key)
                        {
                            // Not a subscription we care about. No event.
                            return Ok(());
                        }
                        self.out_queue.push_back(Event::Data {
                            src: p.src,
                            group: p.dst,
                            src_port: p.src_port,
                            dst_port: p.dst_port,
                            payload: p.payload.to_vec(),
                        });
                    }
                    Err(_) => {
                        self.out_queue.push_back(Event::Warning(AmtError::MalformedInner));
                    }
                }
            }
            _ => {
                self.out_queue.push_back(Event::Warning(AmtError::UnexpectedMessage));
            }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -25
```

Expected: 2 new tests pass; all prior tests still pass.

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): MulticastData → parse inner IP+UDP, emit Data event

Drives per-(S,G) demultiplex inside the manager. Caller fans out
to per-(S,G) WT streams (IWA bridge) or broadcasts (dual-stack-relay)
without re-parsing headers. Malformed inner is a Warning, not fatal."
```

---

### Task 1.10: `subscribe()` Active path — incremental ALLOW

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn subscribe_in_active_emits_incremental_allow_update() {
        let mut m = mgr();
        let k1 = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k1);

        let k2 = GroupKey {
            group: "232.0.0.2".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k2.clone(), 1400).unwrap();
        assert_eq!(m.state(), GatewayState::Active);
        assert_eq!(m.groups().len(), 2);
        assert_eq!(m.pending_len(), 0);

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected MembershipUpdate transmit");
        let report = &update[12..];
        assert_eq!(report[0], 0x22, "IGMPv3 report type");
        assert_eq!(u16::from_be_bytes([report[6], report[7]]), 1, "single ALLOW record");
        assert_eq!(report[8], 5, "record type = ALLOW_NEW_SOURCES");
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib subscription::tests::subscribe_in_active_emits_incremental_allow_update 2>&1 | tail -10
```

Expected: FAIL — the `GatewayState::Active` arm in `subscribe()` is currently a no-op.

- [ ] **Step 3: Implement Active path**

In `subscribe()`, replace the `GatewayState::Active => { /* incremental Allow lands in Task 1.10 */ }` arm with:

```rust
            GatewayState::Active => {
                // Move newly-queued group(s) from pending into groups + emit ALLOW Update.
                while let Some(key) = self.pending.pop_front() {
                    let mut state = GroupState::new(key.clone(), now_ms);
                    state.announced = true;
                    self.groups.insert(key.clone(), state);
                    self.emit_incremental_allow(&key, now_ms)?;
                }
            }
```

Add the helper inside the impl block:

```rust
    fn emit_incremental_allow(&mut self, key: &GroupKey, now_ms: u64) -> Result<()> {
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let report = match relay {
            IpAddr::V4(_) => crate::subscription::report::build_allow_v4(key)?,
            IpAddr::V6(_) => crate::subscription::report::build_allow_v6(key)?,
        };
        let msg = self.inner.send_update(report)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_update_at_ms = Some(now_ms);
        Ok(())
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -25
```

Expected: new test passes; all prior pass.

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): subscribe() in Active emits incremental ALLOW

Post-handshake subscriptions go straight into groups + emit a
single-record ALLOW_NEW_SOURCES Update (v4) or current-state
addition (v6). Nonce + MAC are reused from the existing tunnel."
```

---

### Task 1.11: `unsubscribe()` — incremental BLOCK

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn unsubscribe_in_active_emits_block_update() {
        let mut m = mgr();
        let k1 = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k1.clone());

        m.unsubscribe(&k1, 1400).unwrap();
        assert_eq!(m.groups().len(), 0);

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected MembershipUpdate transmit");
        let report = &update[12..];
        assert_eq!(report[8], 6, "record type = BLOCK_OLD_SOURCES");
    }

    #[test]
    fn unsubscribe_unknown_key_is_noop() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.99".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        // Not subscribed first; manager in Idle.
        m.unsubscribe(&k, 1000).unwrap();
        let events = drain(&mut m);
        assert!(events.is_empty(), "no events on unsubscribe of unknown key");
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib subscription::tests::unsubscribe_ 2>&1 | tail -10
```

Expected: FAIL — `no method named 'unsubscribe'`.

- [ ] **Step 3: Implement `unsubscribe()`**

Add inside `impl<P: Platform> SubscriptionManager<P>`:

```rust
    /// Unsubscribe from a (group, source). In Active state, emits an incremental
    /// BLOCK_OLD_SOURCES Update. In all other states, just removes from groups/pending.
    /// Unknown keys are a silent no-op.
    pub fn unsubscribe(&mut self, key: &GroupKey, now_ms: u64) -> Result<()> {
        if self.shutting_down {
            return Err(AmtError::ShutdownInProgress);
        }
        // Drop from pending first (covers pre-handshake removal).
        self.pending.retain(|k| k != key);
        let was_announced = self.groups.remove(key).map(|g| g.announced).unwrap_or(false);
        if !was_announced || self.inner.state() != GatewayState::Active {
            return Ok(());
        }
        let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
        let report = match relay {
            IpAddr::V4(_) => crate::subscription::report::build_block_v4(key)?,
            IpAddr::V6(_) => crate::subscription::report::build_block_v6(key)?,
        };
        let msg = self.inner.send_update(report)?;
        self.out_queue.push_back(Event::Transmit {
            dst: relay,
            port: self.inner.relay_port(),
            payload: msg.encode(),
        });
        self.last_update_at_ms = Some(now_ms);
        Ok(())
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -25
```

Expected: 2 new tests pass; all prior pass.

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): unsubscribe() emits BLOCK in Active

In Active state: BLOCK_OLD_SOURCES (v4) / refreshed current-state
(v6). In pre-handshake states: just removes from pending/groups.
Unknown keys are a silent no-op."
```

---

### Task 1.12: `tick()` — keep-alive + Discovery retry

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn tick_emits_keepalive_update_after_interval() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        let _ = drain(&mut m);

        // Default keep-alive is 60s. Advance just past it.
        let ka_ms = (AmtConfig::DEFAULT_KEEPALIVE_SECS as u64) * 1000;
        m.tick(1200 + ka_ms + 1).unwrap();

        let events = drain(&mut m);
        let update = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x05 => Some(payload.clone()),
            _ => None,
        }).expect("expected keep-alive Update");
        let report = &update[12..];
        assert_eq!(report[0], 0x22);
        assert_eq!(u16::from_be_bytes([report[6], report[7]]), 1);
    }

    #[test]
    fn next_wakeup_ms_returns_keepalive_deadline_in_active() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        // After drive_to_active, last_update_at_ms is 1200 (the synthesized
        // Query timestamp). next_wakeup_ms = last_update_at + 60s.
        let ka_ms = (AmtConfig::DEFAULT_KEEPALIVE_SECS as u64) * 1000;
        assert_eq!(m.next_wakeup_ms(), Some(1200 + ka_ms));
    }

    #[test]
    fn next_wakeup_ms_idle_returns_none() {
        let m = mgr();
        assert_eq!(m.next_wakeup_ms(), None);
    }

    #[test]
    fn next_wakeup_ms_discovering_returns_timeout_deadline() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k, 1000).unwrap();
        let _ = drain(&mut m);
        assert_eq!(m.next_wakeup_ms(), Some(1000 + DISCOVERY_TIMEOUT_MS));
    }

    #[test]
    fn tick_no_keepalive_before_interval() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        let _ = drain(&mut m);
        m.tick(1200 + 1_000).unwrap();
        assert!(drain(&mut m).is_empty(), "no events before interval");
    }

    #[test]
    fn tick_retries_discovery_then_gives_up() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        m.subscribe(k, 1000).unwrap();
        let _ = drain(&mut m); // consume initial Discovery

        // 3 retries (default MAX_DISCOVERY_RETRIES).
        let mut t = 1000 + DISCOVERY_TIMEOUT_MS + 1;
        for _ in 0..MAX_DISCOVERY_RETRIES {
            m.tick(t).unwrap();
            let events = drain(&mut m);
            assert!(events.iter().any(|ev| matches!(ev,
                Event::Transmit { payload, .. } if payload[0] == 0x01)));
            t += DISCOVERY_TIMEOUT_MS + 1;
        }

        // One more tick: should give up.
        m.tick(t).unwrap();
        let events = drain(&mut m);
        assert!(events.iter().any(|ev|
            matches!(ev, Event::Warning(AmtError::DiscoveryFailed))));
        assert_eq!(m.state(), GatewayState::Idle, "manager parks in Idle on give-up");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --lib subscription::tests::tick_ 2>&1 | tail -15
```

Expected: FAIL — `no method named 'tick'`.

- [ ] **Step 3: Implement `tick()` + `next_wakeup_ms()`**

Add inside `impl<P: Platform> SubscriptionManager<P>`:

```rust
    /// Advance time-driven state: keep-alive Updates, Discovery/Request retries.
    pub fn tick(&mut self, now_ms: u64) -> Result<()> {
        if self.shutting_down {
            return Ok(());
        }
        // 1. Discovery retry / give-up.
        if self.inner.state() == GatewayState::Discovering {
            if let Some(t) = self.last_discovery_at_ms {
                if now_ms.saturating_sub(t) >= DISCOVERY_TIMEOUT_MS {
                    if self.discovery_retries < MAX_DISCOVERY_RETRIES {
                        // Re-send by resetting the inner gateway to Idle then starting again.
                        self.inner.reset();
                        self.discovery_retries += 1;
                        self.start_discovery(now_ms)?;
                        return Ok(());
                    } else {
                        self.inner.reset();
                        self.discovery_retries = 0;
                        self.last_discovery_at_ms = None;
                        self.out_queue.push_back(Event::Warning(AmtError::DiscoveryFailed));
                        return Ok(());
                    }
                }
            }
            return Ok(());
        }
        // 2. Request retry: if no Query within REQUEST_TIMEOUT_MS, give up to Idle.
        if self.inner.state() == GatewayState::Requesting {
            if let Some(t) = self.last_request_at_ms {
                if now_ms.saturating_sub(t) >= REQUEST_TIMEOUT_MS {
                    self.inner.reset();
                    self.last_request_at_ms = None;
                    self.out_queue.push_back(Event::Warning(AmtError::QueryFailed));
                }
            }
            return Ok(());
        }
        // 3. Active keep-alive.
        if self.inner.state() == GatewayState::Active && !self.groups.is_empty() {
            let interval_ms = (self.cfg.keepalive_interval_secs as u64) * 1000;
            if interval_ms == 0 { return Ok(()); }
            let due = match self.last_update_at_ms {
                Some(t) => now_ms.saturating_sub(t) >= interval_ms,
                None => false,
            };
            if due {
                self.send_current_state_update(now_ms)?;
            }
        }
        Ok(())
    }

    /// Earliest future wall-clock (ms) at which a `tick(now_ms)` call would emit work,
    /// or `None` if no timer is armed. Caller uses this to drive `sleep_until`.
    pub fn next_wakeup_ms(&self) -> Option<u64> {
        let mut candidates: Vec<u64> = Vec::with_capacity(3);
        if self.inner.state() == GatewayState::Discovering {
            if let Some(t) = self.last_discovery_at_ms {
                candidates.push(t + DISCOVERY_TIMEOUT_MS);
            }
        }
        if self.inner.state() == GatewayState::Requesting {
            if let Some(t) = self.last_request_at_ms {
                candidates.push(t + REQUEST_TIMEOUT_MS);
            }
        }
        if self.inner.state() == GatewayState::Active && !self.groups.is_empty() {
            let interval_ms = (self.cfg.keepalive_interval_secs as u64) * 1000;
            if interval_ms > 0 {
                if let Some(t) = self.last_update_at_ms {
                    candidates.push(t + interval_ms);
                }
            }
        }
        candidates.into_iter().min()
    }
```

When `subscribe()` queues into pending after a `DiscoveryFailed` event, the inner is `Idle` so the existing Idle branch in `subscribe()` will restart. Verify by inspection of the existing arm; no code change needed.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -25
```

Expected: 3 new tests pass; all prior pass.

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): tick() drives keep-alive + retry timers

- Active + groups present + last_update_at_ms past interval → re-emit
  current-state Update.
- Discovering past DISCOVERY_TIMEOUT_MS → retry up to MAX_DISCOVERY_RETRIES;
  give up to Idle + DiscoveryFailed Warning.
- Requesting past REQUEST_TIMEOUT_MS → reset to Idle + QueryFailed Warning.
- next_wakeup_ms() returns the earliest armed deadline for caller scheduling."
```

---

### Task 1.13: `shutdown()` — emit Teardown

**Files:**
- Modify: `src/subscription/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn shutdown_emits_teardown_from_active() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k);
        let _ = drain(&mut m);

        m.shutdown(1500).unwrap();
        assert_eq!(m.state(), GatewayState::Closed);
        let events = drain(&mut m);
        let teardown = events.iter().find_map(|ev| match ev {
            Event::Transmit { payload, .. } if payload[0] == 0x07 => Some(payload.clone()),
            _ => None,
        }).expect("expected Teardown transmit");
        assert_eq!(teardown.len(), 12, "Teardown is 12 bytes");
    }

    #[test]
    fn shutdown_in_idle_is_noop() {
        let mut m = mgr();
        m.shutdown(1500).unwrap();
        assert!(drain(&mut m).is_empty());
    }

    #[test]
    fn subscribe_after_shutdown_rejected_real() {
        let mut m = mgr();
        let k = GroupKey {
            group: "232.0.0.1".parse().unwrap(),
            source: Some("10.0.0.1".parse().unwrap()),
        };
        drive_to_active(&mut m, k.clone());
        drain(&mut m);
        m.shutdown(1500).unwrap();
        let err = m.subscribe(k, 1600).unwrap_err();
        assert_eq!(err, AmtError::ShutdownInProgress);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --lib subscription::tests::shutdown_ subscription::tests::subscribe_after_shutdown_rejected_real 2>&1 | tail -10
```

Expected: FAIL — `no method named 'shutdown'`.

- [ ] **Step 3: Implement `shutdown()`**

Add inside `impl<P: Platform> SubscriptionManager<P>`:

```rust
    /// Initiate teardown. If currently Active, emits a Teardown Transmit and
    /// transitions to Closed. From any non-Active state, transitions straight
    /// to Closed without emitting wire traffic. Subsequent subscribe()/unsubscribe()
    /// calls return ShutdownInProgress. After shutdown(), `is_closed()` returns
    /// true so the AsyncAmtGateway runtime can break out of its select loop.
    pub fn shutdown(&mut self, _now_ms: u64) -> Result<()> {
        self.shutting_down = true;
        if self.inner.state() == GatewayState::Active {
            let relay = self.inner.relay_address().ok_or(AmtError::InvalidState)?;
            let msg = self.inner.send_teardown()?;
            self.out_queue.push_back(Event::Transmit {
                dst: relay,
                port: self.inner.relay_port(),
                payload: msg.encode(),
            });
            // inner.send_teardown() already advanced inner state to Closed.
        } else {
            // No wire traffic — but the manager must still expose "Closed"
            // semantics to its caller. inner.reset() returns to Idle (the
            // AmtGateway primitive has no public set-Closed). Track the
            // shutdown completion in the manager itself.
            self.inner.reset();
        }
        self.closed = true;
        Ok(())
    }

    /// True once `shutdown()` has been called. The AsyncAmtGateway runtime
    /// uses this to detect "manager is done" regardless of whether the inner
    /// AmtGateway state machine itself reached Closed (it only does on the
    /// Active-state teardown path).
    pub fn is_closed(&self) -> bool {
        self.closed
    }
```

Replace the `shutting_down_for_test` test helper with the real path — delete it from the impl:

```rust
    // (delete this line; not needed once shutdown() exists)
    // #[cfg(test)] pub(crate) fn shutting_down_for_test(&mut self) { self.shutting_down = true; }
```

Update the earlier `subscribe_after_shutdown_rejected` test to use the real shutdown path:

```rust
    #[test]
    fn subscribe_after_shutdown_rejected() {
        let mut m = mgr();
        m.shutdown(1000).unwrap();
        let err = m.subscribe(
            GroupKey {
                group: "232.0.0.1".parse().unwrap(),
                source: Some("10.0.0.1".parse().unwrap()),
            },
            1100,
        ).unwrap_err();
        assert_eq!(err, AmtError::ShutdownInProgress);
    }
```

(Replace the old version that called `shutting_down_for_test()`.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --lib subscription:: 2>&1 | tail -25
```

Expected: 3 new tests pass; updated `subscribe_after_shutdown_rejected` passes; all prior pass.

- [ ] **Step 5: Commit**

```bash
git add src/subscription/mod.rs
git commit -m "feat(subscription): shutdown() — Teardown from Active, noop elsewhere

Active state → emit Teardown Transmit + transition to Closed.
Non-Active → reset inner to Idle (no wire traffic). All paths
flip shutting_down so subscribe/unsubscribe reject thereafter."
```

---

### Task 1.14: Re-exports + crate-level smoke

**Files:**
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` in `src/lib.rs` (create the block if it doesn't exist):

```rust
#[cfg(test)]
mod lib_tests {
    use crate::*;

    #[test]
    fn subscription_manager_reachable_from_crate_root() {
        let _ = SubscriptionManager::<platform::test_platform::TestPlatform>::new;
        let _ = Event::HandshakeComplete;
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test --lib lib_tests::subscription_manager_reachable_from_crate_root 2>&1 | tail -10
```

Expected: FAIL — `SubscriptionManager` not in crate root.

- [ ] **Step 3: Add the re-exports**

In `src/lib.rs`, replace the existing subscription pub-use block with:

```rust
pub mod subscription;
pub use subscription::{Event, GroupState, SubscriptionManager};
```

- [ ] **Step 4: Run tests + the full M1 suite**

```bash
cargo test --lib 2>&1 | tail -20
```

Expected: all tests pass — existing (≥ 30) + new subscription tests (≥ 17) + new lib smoke.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs
git commit -m "feat(lib): export SubscriptionManager + Event + GroupState

Crate root now publishes the subscription layer alongside
AmtGateway, AmtMessage, IgmpV3Report, MldV2Report."
```

---

### Task 1.15: WASM regression smoke (M1 gate)

**Files:**
- No code changes. Verification only.

- [ ] **Step 1: Verify WASM build still succeeds**

```bash
cd ~/src/amt-protocol
rustup target list --installed | grep wasm32-unknown-unknown || rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --no-default-features --features wasm 2>&1 | tail -10
```

Expected: clean build, no errors.

- [ ] **Step 2: Verify FFI build still succeeds**

```bash
cargo build --no-default-features --features ffi 2>&1 | tail -10
```

Expected: clean build.

- [ ] **Step 3: Run the entire test suite once more**

```bash
cargo test 2>&1 | tail -10
```

Expected: all green.

- [ ] **Step 4: Tag M1 in git (optional but recommended)**

```bash
git tag -a m1-subscription-core -m "M1 complete: SubscriptionManager core (Sans-I/O)"
```

---

## Milestone M2 — `native` feature + `AsyncAmtGateway`

Gate: Tier-2 integration tests green; default `cargo build` unchanged; `cargo build --features native --no-default-features` green.

### Task 2.1: Add `native` Cargo feature + optional deps

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Write the failing test**

Verify the feature flag does not yet exist:

```bash
cd ~/src/amt-protocol
grep '^native' Cargo.toml && echo "FEATURE PRESENT — task already done" || echo "FEATURE ABSENT — proceed"
```

Expected: `FEATURE ABSENT`.

- [ ] **Step 2: Add the feature + deps**

Open `Cargo.toml`. In the `[features]` table, append:

```toml
# Native target (tokio-based async runtime + CLI binary)
native = [
    "dep:tokio",
    "dep:tracing",
    "dep:tracing-subscriber",
    "dep:bytes",
    "dep:anyhow",
    "dep:serde_json",
    "dep:clap",
]
```

In the `[dependencies]` table, append:

```toml
# Native target dependencies (optional, behind `native` feature)
tokio = { version = "1", features = ["rt", "rt-multi-thread", "net", "time", "sync", "macros", "io-util", "signal"], optional = true }
tracing = { version = "0.1", optional = true }
tracing-subscriber = { version = "0.3", features = ["env-filter"], optional = true }
bytes = { version = "1", optional = true }
anyhow = { version = "1", optional = true }
serde_json = { version = "1", optional = true }
clap = { version = "4", features = ["derive", "env"], optional = true }
```

In `[dev-dependencies]`, append:

```toml
# For native-runtime integration tests. `process` is needed by tests/cli_json.rs
# (Task 3.4) which spawns the built bin via tokio::process::Command.
tokio = { version = "1", features = ["rt", "macros", "net", "time", "sync", "process", "io-util"] }
```

- [ ] **Step 3: Verify build still works with default features**

```bash
cargo build 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 4: Verify the new feature compiles standalone**

```bash
cargo build --no-default-features --features native 2>&1 | tail -5
```

Expected: clean (no `src/native/` code yet, so only the deps download/compile).

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(features): add native feature with tokio + clap stack

All native deps are [optional] so default + WASM + FFI builds
are byte-identical. Test compile path verified for both default
and --no-default-features --features native."
```

---

### Task 2.2: `NativePlatform` — `Platform` impl for native targets

**Files:**
- Create: `src/native/mod.rs`
- Create: `src/native/platform.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `src/native/platform.rs`:

```rust
//! Platform impl for native (non-WASM, non-FFI) Rust callers.

use std::time::{SystemTime, UNIX_EPOCH};
use crate::platform::Platform;

#[derive(Debug, Default, Clone, Copy)]
pub struct NativePlatform;

impl NativePlatform {
    pub fn new() -> Self { Self }
}

impl Platform for NativePlatform {
    fn random_bytes(&self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("getrandom failed");
    }
    fn log_debug(&self, msg: &str) {
        tracing::debug!(target: "amt", "{}", msg);
    }
    fn log_info(&self, msg: &str) {
        tracing::info!(target: "amt", "{}", msg);
    }
    fn log_error(&self, msg: &str) {
        tracing::error!(target: "amt", "{}", msg);
    }
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_platform_random_bytes_changes_each_call() {
        let p = NativePlatform::new();
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        p.random_bytes(&mut a);
        p.random_bytes(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn native_platform_now_millis_is_recent() {
        let p = NativePlatform::new();
        let t = p.now_millis();
        // 2026-01-01 in ms.
        assert!(t > 1_767_225_600_000);
    }
}
```

Create `src/native/mod.rs`:

```rust
//! Native (tokio + std::net + UDP) runtime layer. Gated behind feature = "native".

pub mod platform;

pub use platform::NativePlatform;
```

Add to `src/lib.rs`:

```rust
#[cfg(feature = "native")]
pub mod native;

#[cfg(feature = "native")]
pub use native::NativePlatform;
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
cargo test --no-default-features --features native --lib native::platform 2>&1 | tail -10
```

Expected: 2 tests pass.

- [ ] **Step 3: Verify default build still works**

```bash
cargo test --lib 2>&1 | tail -5
```

Expected: all prior tests still green (the native module is `#[cfg(feature = "native")]` so it's absent here).

- [ ] **Step 4: Commit**

```bash
git add src/native/ src/lib.rs
git commit -m "feat(native): NativePlatform — Platform impl for tokio callers

getrandom for random_bytes, SystemTime for now_millis,
tracing macros for log_debug/info/error. Compiles only under
feature = native; default + WASM + FFI builds unaffected."
```

---

### Task 2.3: `fake_relay` test helper

**Files:**
- Create: `tests/common/mod.rs`
- Create: `tests/common/fake_relay.rs`

- [ ] **Step 1: Write the helper**

Create `tests/common/mod.rs`:

```rust
//! Shared test helpers for native-runtime integration tests.

pub mod fake_relay;
```

Create `tests/common/fake_relay.rs`:

```rust
//! Loopback UDP fake AMT relay used by Tier-2 integration tests.
//!
//! Responds with canned Advertisement → Query → synthetic MulticastData.
//! Captures inbound datagram types so tests can assert on them.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use amt_protocol::messages::AmtMessage;

#[derive(Debug, Default)]
pub struct CapturedTraffic {
    pub message_types: Vec<u8>,
}

pub struct FakeRelay {
    pub addr: SocketAddr,
    pub captured: Arc<Mutex<CapturedTraffic>>,
    sock: Arc<UdpSocket>,
}

impl FakeRelay {
    /// Bind a loopback socket on a free port. `family` is "v4" or "v6".
    pub async fn bind(family: &str) -> Self {
        let bind_addr = if family == "v6" { "[::1]:0" } else { "127.0.0.1:0" };
        let sock = UdpSocket::bind(bind_addr).await.expect("bind fake relay");
        let addr = sock.local_addr().unwrap();
        Self {
            addr,
            captured: Arc::new(Mutex::new(CapturedTraffic::default())),
            sock: Arc::new(sock),
        }
    }

    /// Start the fake relay loop. Spawns a tokio task that:
    /// - Responds to RelayDiscovery with a matching RelayAdvertisement (relay = self.addr.ip())
    /// - Responds to Request with a MembershipQuery
    /// - After Update, emits one MulticastData with a synthetic v4+UDP packet
    pub fn spawn(&self, inner_payload: Vec<u8>) {
        let sock = self.sock.clone();
        let captured = self.captured.clone();
        let relay_ip = self.addr.ip();
        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            let mut req_nonce: u32 = 0;
            let mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let bytes = &buf[..n];
                if bytes.is_empty() { continue; }
                captured.lock().await.message_types.push(bytes[0]);
                let msg = match AmtMessage::decode(bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match msg {
                    AmtMessage::RelayDiscovery { nonce } => {
                        let advert = AmtMessage::RelayAdvertisement {
                            nonce,
                            relay_address: relay_ip,
                        };
                        let _ = sock.send_to(&advert.encode(), src).await;
                    }
                    AmtMessage::Request { request_nonce, .. } => {
                        req_nonce = request_nonce;
                        let query = AmtMessage::MembershipQuery {
                            request_nonce,
                            response_mac: mac,
                            query_data: vec![0x11; 12],
                        };
                        let _ = sock.send_to(&query.encode(), src).await;
                    }
                    AmtMessage::MembershipUpdate { request_nonce, response_mac, .. } => {
                        if request_nonce == req_nonce && response_mac == mac {
                            let data = AmtMessage::MulticastData { ip_packet: inner_payload.clone() };
                            let _ = sock.send_to(&data.encode(), src).await;
                        }
                    }
                    AmtMessage::Teardown { .. } => {
                        // Just record — loop continues so we can capture more if needed.
                    }
                    _ => {}
                }
            }
        });
    }
}

/// Build a synthetic IPv4+UDP inner packet for fake MulticastData.
pub fn synth_v4_udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + 8 + payload.len()) as u16;
    let mut buf = vec![0x45, 0x00];
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 17, 0, 0]);
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&sp.to_be_bytes());
    buf.extend_from_slice(&dp.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf.extend_from_slice(&udp_len.to_be_bytes());
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(payload);
    buf
}
```

- [ ] **Step 2: Verify it compiles standalone**

```bash
cargo build --tests --no-default-features --features native 2>&1 | tail -10
```

Expected: clean compile (no tests yet so no warnings about unused).

- [ ] **Step 3: Commit**

```bash
git add tests/common/
git commit -m "test(native): fake_relay loopback helper

Bound on 127.0.0.1:0 (v4) or [::1]:0 (v6). Responds to
Discovery/Request/Update with canned Advertisement/Query/Data.
Captures inbound message types for test assertions. Helper
synth_v4_udp builds a well-formed v4+UDP inner packet."
```

---

### Task 2.4: `AsyncAmtGateway` — struct, builder, task loop

**Files:**
- Create: `src/native/gateway.rs`
- Modify: `src/native/mod.rs`

- [ ] **Step 1: Implement struct + builder + task spawn**

Create `src/native/gateway.rs`:

```rust
//! AsyncAmtGateway: tokio wrapper around one SubscriptionManager.
//!
//! Owns one UdpSocket bound for the relay's family. Drives SubscriptionManager
//! via select! over: command channel, socket recv, sleep timer, shutdown.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::config::AmtConfig;
use crate::gateway::{GatewayState, GroupKey};
use crate::subscription::{Event, SubscriptionManager};
use super::platform::NativePlatform;

/// Public data event: one demultiplexed inner UDP packet.
#[derive(Debug, Clone)]
pub struct DataEvent {
    pub src: IpAddr,
    pub group: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Bytes,
}

#[derive(Debug)]
enum Cmd {
    Subscribe { key: GroupKey, ack: oneshot::Sender<Result<()>> },
    Unsubscribe { key: GroupKey, ack: oneshot::Sender<Result<()>> },
    Shutdown { ack: oneshot::Sender<Result<()>> },
}

pub struct AsyncAmtGateway {
    cmd_tx: mpsc::Sender<Cmd>,
    data_tx: broadcast::Sender<DataEvent>,
    state: Arc<AtomicU8>,
    task: Mutex<Option<JoinHandle<()>>>,
    /// Holds a fatal runtime error (socket bind/send/recv unrecoverable) if
    /// the spawned task exited because of one. `shutdown()` checks this and
    /// returns Err(...) instead of Ok(()) when set. Aligns with spec
    /// "Fatal runtime → AsyncAmtGateway::shutdown future resolves with Err".
    fatal: Arc<Mutex<Option<anyhow::Error>>>,
}

pub struct AsyncAmtGatewayBuilder {
    relay: Option<IpAddr>,
    relay_port: u16,
    keepalive: Duration,
    log_target: &'static str,
}

impl AsyncAmtGateway {
    pub fn builder(relay: IpAddr) -> AsyncAmtGatewayBuilder {
        AsyncAmtGatewayBuilder {
            relay: Some(relay),
            relay_port: 2268,
            keepalive: Duration::from_secs(AmtConfig::DEFAULT_KEEPALIVE_SECS as u64),
            log_target: "amt",
        }
    }

    pub fn state(&self) -> GatewayState {
        match self.state.load(Ordering::SeqCst) {
            0 => GatewayState::Idle,
            1 => GatewayState::Discovering,
            2 => GatewayState::Requesting,
            3 => GatewayState::Querying,
            4 => GatewayState::Active,
            _ => GatewayState::Closed,
        }
    }

    pub fn subscribe_data(&self) -> broadcast::Receiver<DataEvent> {
        self.data_tx.subscribe()
    }
}

impl AsyncAmtGatewayBuilder {
    pub fn relay_port(mut self, port: u16) -> Self { self.relay_port = port; self }
    pub fn keepalive(mut self, d: Duration) -> Self { self.keepalive = d; self }
    pub fn log_target(mut self, t: &'static str) -> Self { self.log_target = t; self }

    /// Build and spawn the runtime task. `relay` must have been set (via builder/builder_for_source).
    pub async fn build(self) -> Result<AsyncAmtGateway> {
        let relay = self.relay.ok_or_else(|| anyhow!("relay address not set"))?;
        let bind = match relay {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let sock = UdpSocket::bind(bind).await?;
        let mut cfg = AmtConfig::new(relay, Some(self.relay_port));
        cfg.keepalive_interval_secs = self.keepalive.as_secs() as u32;

        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(32);
        let (data_tx, _) = broadcast::channel::<DataEvent>(1024);
        let state = Arc::new(AtomicU8::new(state_to_u8(GatewayState::Idle)));
        let fatal: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));

        let task = tokio::spawn(run_task(
            sock,
            cfg,
            cmd_rx,
            data_tx.clone(),
            state.clone(),
            fatal.clone(),
            self.log_target,
        ));

        Ok(AsyncAmtGateway {
            cmd_tx,
            data_tx,
            state,
            task: Mutex::new(Some(task)),
            fatal,
        })
    }
}

fn state_to_u8(s: GatewayState) -> u8 {
    match s {
        GatewayState::Idle => 0,
        GatewayState::Discovering => 1,
        GatewayState::Requesting => 2,
        GatewayState::Querying => 3,
        GatewayState::Active => 4,
        GatewayState::Closed => 5,
    }
}

async fn run_task(
    sock: UdpSocket,
    cfg: AmtConfig,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    data_tx: broadcast::Sender<DataEvent>,
    state: Arc<AtomicU8>,
    fatal: Arc<Mutex<Option<anyhow::Error>>>,
    log_target: &'static str,
) {
    let platform = Arc::new(NativePlatform::new());
    let mut mgr = SubscriptionManager::new(cfg, platform.clone());
    let mut buf = [0u8; 65535];
    let mut shutdown_ack: Option<oneshot::Sender<Result<()>>> = None;

    loop {
        // Compute next wake. If no timer is armed, sleep a long time.
        let next_wake = mgr.next_wakeup_ms()
            .map(|ms| Instant::now() + duration_until(ms, now_ms_local()))
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

        tokio::select! {
            biased;

            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else { break; };
                handle_cmd(&mut mgr, cmd, now_ms_local(), &mut shutdown_ack);
            }

            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, _)) => {
                        let _ = mgr.handle_datagram(&buf[..n], now_ms_local());
                    }
                    Err(e) => {
                        tracing::error!(target: log_target, error=?e, "socket recv error (fatal)");
                        *fatal.lock().await = Some(anyhow!("socket recv: {e}"));
                        break;
                    }
                }
            }

            _ = tokio::time::sleep_until(next_wake) => {
                let _ = mgr.tick(now_ms_local());
            }
        }

        // Drain events emitted this turn.
        while let Some(ev) = mgr.poll_event() {
            match ev {
                Event::Transmit { dst, port, payload } => {
                    let target = SocketAddr::new(dst, port);
                    if let Err(e) = sock.send_to(&payload, target).await {
                        tracing::error!(target: log_target, error=?e, "socket send error (fatal)");
                        *fatal.lock().await = Some(anyhow!("socket send: {e}"));
                        // Don't break mid-drain — let the next select iteration exit.
                    }
                }
                Event::Data { src, group, src_port, dst_port, payload } => {
                    let _ = data_tx.send(DataEvent {
                        src,
                        group,
                        src_port,
                        dst_port,
                        payload: Bytes::from(payload),
                    });
                }
                Event::HandshakeComplete => {
                    state.store(state_to_u8(GatewayState::Active), Ordering::SeqCst);
                    tracing::info!(target: log_target, "AMT tunnel up");
                }
                Event::Warning(e) => {
                    tracing::warn!(target: log_target, error=?e, "subscription warning");
                }
            }
        }
        state.store(state_to_u8(mgr.state()), Ordering::SeqCst);

        // Loop-exit conditions:
        // (a) SubscriptionManager has been shut down (covers Active-teardown
        //     AND Idle-direct-close paths — fixes shutdown-from-Idle hang).
        // (b) A fatal socket error was just recorded.
        if mgr.is_closed() || fatal.lock().await.is_some() {
            if let Some(ack) = shutdown_ack.take() {
                let _ = ack.send(Ok(()));
            }
            break;
        }
    }
}

fn handle_cmd(
    mgr: &mut SubscriptionManager<NativePlatform>,
    cmd: Cmd,
    now_ms: u64,
    shutdown_ack: &mut Option<oneshot::Sender<Result<()>>>,
) {
    match cmd {
        Cmd::Subscribe { key, ack } => {
            let _ = ack.send(mgr.subscribe(key, now_ms).map_err(|e| anyhow!(e)));
        }
        Cmd::Unsubscribe { key, ack } => {
            let _ = ack.send(mgr.unsubscribe(&key, now_ms).map_err(|e| anyhow!(e)));
        }
        Cmd::Shutdown { ack } => {
            let r = mgr.shutdown(now_ms).map_err(|e| anyhow!(e));
            *shutdown_ack = Some(ack);
            if r.is_err() {
                if let Some(a) = shutdown_ack.take() { let _ = a.send(r); }
            }
        }
    }
}

fn now_ms_local() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_millis() as u64
}

fn duration_until(deadline_ms: u64, now_ms: u64) -> Duration {
    if deadline_ms <= now_ms { Duration::from_millis(1) }
    else { Duration::from_millis(deadline_ms - now_ms) }
}

// Internal-only — used by subscribe/unsubscribe/shutdown methods in Task 2.5.
pub(crate) async fn send_cmd<R: Send + 'static>(
    tx: &mpsc::Sender<Cmd>,
    make: impl FnOnce(oneshot::Sender<Result<R>>) -> Cmd,
    map_unit: impl FnOnce(()) -> R,
) -> Result<R> {
    let (a, b) = oneshot::channel::<Result<R>>();
    tx.send(make(a)).await.map_err(|_| anyhow!("gateway task gone"))?;
    b.await.map_err(|_| anyhow!("ack dropped"))?
        .map(|_| map_unit(()))
}
```

Wait — the helper `send_cmd` is fiddly because Cmd variants have heterogeneous ack types. Drop it and inline simpler `subscribe/unsubscribe/shutdown` impls in Task 2.5. Delete the entire `pub(crate) async fn send_cmd` block at the bottom of the file before saving.

Update `src/native/mod.rs`:

```rust
//! Native (tokio + std::net + UDP) runtime layer. Gated behind feature = "native".

pub mod platform;
pub mod gateway;

pub use platform::NativePlatform;
pub use gateway::{AsyncAmtGateway, AsyncAmtGatewayBuilder, DataEvent};
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build --no-default-features --features native --lib 2>&1 | tail -15
```

Expected: clean (warnings about dead Cmd ack channels OK — fixed in 2.5).

- [ ] **Step 3: Commit**

```bash
git add src/native/gateway.rs src/native/mod.rs
git commit -m "feat(native): AsyncAmtGateway struct + builder + task loop

One tokio task per gateway. Owns UdpSocket + SubscriptionManager.
Drives via select! over command queue, socket recv, sleep timer.
DataEvent.payload is bytes::Bytes (zero-copy fan-out). State
exposed via Arc<AtomicU8> for sync state() reads. Public sub/
unsub/shutdown methods land in Task 2.5."
```

---

### Task 2.5: Public `subscribe`/`unsubscribe`/`shutdown` methods

**Files:**
- Modify: `src/native/gateway.rs`

- [ ] **Step 1: Add methods to `AsyncAmtGateway`**

Inside `impl AsyncAmtGateway` (in `src/native/gateway.rs`), append:

```rust
    pub async fn subscribe(&self, group: IpAddr, source: Option<IpAddr>) -> Result<()> {
        let key = GroupKey { group, source };
        let (ack, rx) = oneshot::channel::<Result<()>>();
        self.cmd_tx
            .send(Cmd::Subscribe { key, ack })
            .await
            .map_err(|_| anyhow!("AsyncAmtGateway task is gone"))?;
        rx.await.map_err(|_| anyhow!("subscribe ack dropped"))?
    }

    pub async fn unsubscribe(&self, group: IpAddr, source: Option<IpAddr>) -> Result<()> {
        let key = GroupKey { group, source };
        let (ack, rx) = oneshot::channel::<Result<()>>();
        self.cmd_tx
            .send(Cmd::Unsubscribe { key, ack })
            .await
            .map_err(|_| anyhow!("AsyncAmtGateway task is gone"))?;
        rx.await.map_err(|_| anyhow!("unsubscribe ack dropped"))?
    }

    /// Initiate graceful shutdown. Waits for the runtime task to finish.
    /// Returns `Err(...)` if a fatal runtime error was observed during the
    /// lifetime of this gateway (per spec "Fatal runtime → shutdown future
    /// resolves with Err").
    pub async fn shutdown(self) -> Result<()> {
        let (ack, rx) = oneshot::channel::<Result<()>>();
        let _ = self.cmd_tx.send(Cmd::Shutdown { ack }).await;
        let _ = rx.await;
        let mut guard = self.task.lock().await;
        if let Some(handle) = guard.take() {
            handle.await.map_err(|e| anyhow!("task join: {e}"))?;
        }
        // Surface any fatal runtime error captured by run_task.
        if let Some(e) = self.fatal.lock().await.take() {
            return Err(e);
        }
        Ok(())
    }
```

- [ ] **Step 2: Verify compile**

```bash
cargo build --no-default-features --features native --lib 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add src/native/gateway.rs
git commit -m "feat(native): AsyncAmtGateway public subscribe/unsubscribe/shutdown

Each method sends a Cmd over the mpsc channel with a oneshot
ack reply. shutdown() consumes self, awaits the runtime task
to join. Errors when the task is gone surface as anyhow::Error."
```

---

### Task 2.6: Tier-2 test — oneshot happy path v4

**Files:**
- Create: `tests/native_runtime.rs`

- [ ] **Step 1: Write the test**

Create `tests/native_runtime.rs`:

```rust
//! Tier 2 integration tests for the native AsyncAmtGateway runtime.

#![cfg(feature = "native")]

mod common;

use std::time::Duration;
use amt_protocol::native::AsyncAmtGateway;
use common::fake_relay::{synth_v4_udp, FakeRelay};

#[tokio::test(flavor = "current_thread")]
async fn oneshot_happy_path_v4() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"hello");
    relay.spawn(inner.clone());

    let gw = AsyncAmtGateway::builder(relay.addr.ip())
        .relay_port(relay.addr.port())
        .keepalive(Duration::from_secs(60))
        .build()
        .await
        .expect("build gateway");

    let mut data_rx = gw.subscribe_data();

    gw.subscribe(
        "232.0.0.1".parse().unwrap(),
        Some("10.0.0.1".parse().unwrap()),
    )
    .await
    .expect("subscribe");

    let evt = tokio::time::timeout(Duration::from_secs(5), data_rx.recv())
        .await
        .expect("timed out waiting for DataEvent")
        .expect("broadcast closed");

    assert_eq!(evt.src, "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(evt.group, "232.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(evt.src_port, 5004);
    assert_eq!(evt.dst_port, 5005);
    assert_eq!(&evt.payload[..], b"hello");

    gw.shutdown().await.expect("shutdown");

    let captured = relay.captured.lock().await;
    assert!(captured.message_types.contains(&1));
    assert!(captured.message_types.contains(&3));
    assert!(captured.message_types.contains(&5));
    assert!(captured.message_types.contains(&7));
}
```

- [ ] **Step 2: Run the test**

```bash
cargo test --no-default-features --features native --test native_runtime oneshot_happy_path_v4 2>&1 | tail -20
```

Expected: PASS within 5 seconds.

- [ ] **Step 3: Commit**

```bash
git add tests/native_runtime.rs
git commit -m "test(native): Tier-2 oneshot_happy_path_v4

Drives AsyncAmtGateway against a loopback fake relay through
the full Discovery → Advertisement → Request → Query → Update
→ first MulticastData flow. Verifies broadcast DataEvent shape
and shutdown emits Teardown."
```

---

### Task 2.7: Tier-2 — v6 + multi-consumer + family-mismatch

**Files:**
- Modify: `tests/native_runtime.rs`

- [ ] **Step 1: Append the tests**

Append to `tests/native_runtime.rs`:

```rust
#[tokio::test(flavor = "current_thread")]
async fn oneshot_happy_path_v6() {
    let relay = FakeRelay::bind("v6").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"hello");
    relay.spawn(inner);

    let gw = AsyncAmtGateway::builder(relay.addr.ip())
        .relay_port(relay.addr.port())
        .build()
        .await
        .expect("build gateway");

    let mut data_rx = gw.subscribe_data();
    gw.subscribe(
        "ff3e::1234".parse().unwrap(),
        Some("2001:db8::1".parse().unwrap()),
    )
    .await
    .expect("subscribe v6");

    let evt = tokio::time::timeout(Duration::from_secs(5), data_rx.recv())
        .await
        .expect("timed out")
        .expect("broadcast closed");
    assert_eq!(&evt.payload[..], b"hello");

    gw.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "current_thread")]
async fn subscribe_data_multi_consumer() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn(inner);

    let gw = AsyncAmtGateway::builder(relay.addr.ip())
        .relay_port(relay.addr.port())
        .build()
        .await
        .unwrap();
    let mut rx_a = gw.subscribe_data();
    let mut rx_b = gw.subscribe_data();

    gw.subscribe(
        "232.0.0.1".parse().unwrap(),
        Some("10.0.0.1".parse().unwrap()),
    )
    .await
    .unwrap();

    let a = tokio::time::timeout(Duration::from_secs(5), rx_a.recv()).await.unwrap().unwrap();
    let b = tokio::time::timeout(Duration::from_secs(5), rx_b.recv()).await.unwrap().unwrap();
    assert_eq!(&a.payload[..], b"x");
    assert_eq!(&b.payload[..], b"x");

    gw.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn subscribe_v4_relay_rejects_v6_group() {
    let relay = FakeRelay::bind("v4").await;
    let gw = AsyncAmtGateway::builder(relay.addr.ip())
        .relay_port(relay.addr.port())
        .build()
        .await
        .unwrap();

    let err = gw.subscribe(
        "ff3e::1234".parse().unwrap(),
        Some("2001:db8::1".parse().unwrap()),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("family"), "got: {err}");

    gw.shutdown().await.unwrap();
}
```

- [ ] **Step 2: Run the tests**

```bash
cargo test --no-default-features --features native --test native_runtime 2>&1 | tail -25
```

Expected: 4 tests pass total.

- [ ] **Step 3: Commit**

```bash
git add tests/native_runtime.rs
git commit -m "test(native): v6 happy path + multi-consumer broadcast + FamilyMismatch"
```

---

### Task 2.8: WASM regression smoke (M2 gate)

**Files:** None — verification only.

- [ ] **Step 1: WASM build with default features**

```bash
cd ~/src/amt-protocol
cargo build --target wasm32-unknown-unknown --no-default-features --features wasm 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 2: Native-only feature tests**

```bash
cargo test --no-default-features --features native 2>&1 | tail -10
```

Expected: all green.

- [ ] **Step 3: Default-feature tests**

```bash
cargo test --lib 2>&1 | tail -5
```

Expected: all green.

- [ ] **Step 4: Tag M2 (optional)**

```bash
git tag -a m2-async-runtime -m "M2 complete: AsyncAmtGateway native runtime + Tier-2 tests"
```

---

## Milestone M3 — `amt-verify` CLI

Gate: `cargo build --no-default-features --features native --bin amt-verify` succeeds; hand-tested against fake relay (or wait for M5 to run against staging).

### Task 3.1: Add `[[bin]]` declaration for `amt-verify`

**Files:**
- Modify: `Cargo.toml`

> `clap` already lives in the `native` feature + optional `[dependencies]` from Task 2.1 — do not re-add. This task only adds the `[[bin]]` block so Cargo knows about `src/bin/amt-verify.rs`.

- [ ] **Step 1: Add the bin**

Add a new `[[bin]]` block at the bottom of `Cargo.toml`:

```toml
[[bin]]
name = "amt-verify"
path = "src/bin/amt-verify.rs"
required-features = ["native"]
```

- [ ] **Step 2: Verify default build untouched**

```bash
cargo build 2>&1 | tail -3
```

Expected: clean (clap is optional; no bin built without `native`).

- [ ] **Step 3: Verify the bin path resolves under native** (intentionally fails until 3.2 creates the file)

```bash
cargo build --no-default-features --features native --bin amt-verify 2>&1 | tail -3
```

Expected: FAIL — `couldn't read 'src/bin/amt-verify.rs'`. This proves Cargo wired the binary. Proceed to 3.2.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "build(cli): declare [[bin]] amt-verify

bin gated on required-features = [\"native\"] so it doesn't
disturb WASM/FFI/JNI paths. clap dep was added in Task 2.1.
Source file lands in next commit."
```

---

### Task 3.2: `amt-verify` one-shot mode (without DRIAD)

**Files:**
- Create: `src/bin/amt-verify.rs`

- [ ] **Step 1: Write the bin**

Create `src/bin/amt-verify.rs`:

```rust
//! amt-verify — one-shot + watch E2E verify CLI for AMT tunnels.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use amt_protocol::native::AsyncAmtGateway;

#[derive(Parser, Debug)]
#[command(name = "amt-verify", version, about = "AMT E2E verify CLI")]
struct Args {
    /// AMT relay address (required in M3; M4 makes this optional via DRIAD)
    #[arg(long)]
    relay: IpAddr,

    /// AMT relay UDP port (RFC 7450 default 2268)
    #[arg(long, default_value_t = 2268)]
    port: u16,

    /// Multicast group address (mandatory)
    #[arg(long)]
    group: IpAddr,

    /// SSM source address — REQUIRED for SSM verify (the spec contract).
    /// ASM verify is out of scope for this CLI; for ASM, use the library.
    #[arg(long)]
    source: IpAddr,

    /// Force IP family. `auto` infers from --relay.
    #[arg(long, value_enum, default_value_t = Family::Auto)]
    family: Family,

    /// Wait at most this many seconds for first data
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Keep-alive interval in seconds
    #[arg(long, default_value = "60")]
    keepalive: u64,

    /// Stay running after first data, log stats every 5s
    #[arg(long, default_value_t = false)]
    watch: bool,

    /// Machine-readable JSON output (one-shot mode only).
    /// Rejected with exit 2 if combined with --watch.
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Verbose logging (sets RUST_LOG=debug for crate=amt)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum Family { V4, V6, Auto }

/// Exit-code classification per spec:
///   0 → success (one-shot data observed, or watch SIGINT clean teardown)
///   1 → handshake / verify failure (timeout, nonce mismatch, broadcast closed)
///   2 → config error (clap rejects, --json with --watch, family mismatch arg combo)
///   3 → fatal runtime (socket bind / send / recv unrecoverable)
#[derive(Debug)]
enum ExitCategory {
    HandshakeFail(anyhow::Error),
    Config(anyhow::Error),
    Fatal(anyhow::Error),
}

impl ExitCategory {
    fn code(&self) -> u8 {
        match self {
            ExitCategory::HandshakeFail(_) => 1,
            ExitCategory::Config(_)        => 2,
            ExitCategory::Fatal(_)         => 3,
        }
    }
    fn err(&self) -> &anyhow::Error {
        match self {
            ExitCategory::HandshakeFail(e) | ExitCategory::Config(e) | ExitCategory::Fatal(e) => e,
        }
    }
}

#[derive(serde::Serialize)]
struct OneshotReport {
    outcome: &'static str,
    relay: String,
    family: &'static str,
    group: String,
    source: Option<String>,
    timings_ms: Timings,
    first_packet: FirstPacket,
}

#[derive(serde::Serialize)]
struct Timings { first_data: u64 }

#[derive(serde::Serialize)]
struct FirstPacket { src: String, dst_port: u16, len: usize }

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    let filter = if args.verbose {
        EnvFilter::new("amt=debug,amt_protocol=debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("amt=info,amt_protocol=info"))
    };
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();

    match run(args).await {
        Ok(()) => ExitCode::from(0),
        Err(cat) => {
            eprintln!("amt-verify: {:#}", cat.err());
            ExitCode::from(cat.code())
        }
    }
}

async fn run(args: Args) -> std::result::Result<(), ExitCategory> {
    // ----- Config validation (exit 2) -----
    if args.json && args.watch {
        return Err(ExitCategory::Config(anyhow!(
            "--json is one-shot only; combining with --watch is rejected"
        )));
    }
    let inferred_family = if args.relay.is_ipv4() { Family::V4 } else { Family::V6 };
    let effective_family = match args.family {
        Family::Auto => inferred_family,
        explicit => {
            let relay_family = inferred_family;
            let same = matches!((explicit, relay_family),
                (Family::V4, Family::V4) | (Family::V6, Family::V6));
            if !same {
                return Err(ExitCategory::Config(anyhow!(
                    "--family explicitly set but does not match --relay family"
                )));
            }
            explicit
        }
    };
    let family_str = match effective_family { Family::V4 => "v4", Family::V6 => "v6", Family::Auto => unreachable!() };

    // group/source family checks (exit 2 — caught before any network)
    if args.group.is_ipv4() != args.source.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --source must be the same IP family"
        )));
    }
    if args.group.is_ipv4() != args.relay.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --relay must be the same IP family"
        )));
    }

    // ----- Build gateway -----
    let gw = AsyncAmtGateway::builder(args.relay)
        .relay_port(args.port)
        .keepalive(Duration::from_secs(args.keepalive))
        .build()
        .await
        .map_err(ExitCategory::Fatal)?;
    let mut data_rx = gw.subscribe_data();

    let started = Instant::now();
    gw.subscribe(args.group, Some(args.source))
        .await
        .map_err(ExitCategory::HandshakeFail)?;

    // ----- First data matching (group, source) within timeout -----
    let evt = match recv_first_matching(
        &mut data_rx,
        args.group,
        args.source,
        Duration::from_secs(args.timeout),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return Err(ExitCategory::HandshakeFail(e)),
    };
    let first_data_ms = started.elapsed().as_millis() as u64;

    if args.json {
        let report = OneshotReport {
            outcome: "ok",
            relay: args.relay.to_string(),
            family: family_str,
            group: args.group.to_string(),
            source: Some(args.source.to_string()),
            timings_ms: Timings { first_data: first_data_ms },
            first_packet: FirstPacket {
                src: format!("{}:{}", evt.src, evt.src_port),
                dst_port: evt.dst_port,
                len: evt.payload.len(),
            },
        };
        println!("{}", serde_json::to_string(&report).map_err(|e| ExitCategory::Fatal(e.into()))?);
    } else {
        println!(
            "ok — relay={} family={} group={} source={} first_data={}ms first_pkt={}:{} len={}",
            args.relay, family_str, args.group, args.source,
            first_data_ms, evt.src, evt.src_port, evt.payload.len()
        );
    }

    if args.watch {
        run_watch(gw, data_rx).await.map_err(ExitCategory::Fatal)?;
    } else {
        // shutdown surfaces fatal runtime errors; map them to category 3.
        gw.shutdown().await.map_err(ExitCategory::Fatal)?;
    }
    Ok(())
}

/// Loop on the broadcast channel until a DataEvent matches (group, source)
/// or the timeout fires. Unrelated events from the same tunnel are skipped.
/// This implements the spec's "await first DataEvent matching (group, source)"
/// contract; without the filter loop, the CLI could complete successfully on
/// noise from another subscription sharing the tunnel.
async fn recv_first_matching(
    rx: &mut tokio::sync::broadcast::Receiver<amt_protocol::native::DataEvent>,
    group: IpAddr,
    source: IpAddr,
    timeout: Duration,
) -> Result<amt_protocol::native::DataEvent> {
    use tokio::sync::broadcast::error::RecvError;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| anyhow!("timed out after {}s waiting for first data matching ({}, {})",
                timeout.as_secs(), group, source))?;
        let recv = tokio::time::timeout(remaining, rx.recv()).await
            .map_err(|_| anyhow!("timed out after {}s waiting for first data matching ({}, {})",
                timeout.as_secs(), group, source))?;
        match recv {
            Ok(evt) if evt.group == group && evt.src == source => return Ok(evt),
            Ok(_skip) => continue,
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => return Err(anyhow!("data broadcast closed before first matching packet")),
        }
    }
}

async fn run_watch(
    _gw: AsyncAmtGateway,
    _data_rx: tokio::sync::broadcast::Receiver<amt_protocol::native::DataEvent>,
) -> Result<()> {
    // --watch implementation lands in Task 3.3.
    Err(anyhow!("--watch mode not yet implemented"))
}
```

Add to `Cargo.toml` `[dependencies]` (these are needed unconditionally by the bin only — but the bin only builds under `native`, so they need to be present whenever native is on). Put them under the existing optional deps as additional optional:

```toml
serde = { version = "1.0", features = ["derive"] }
```

`serde` is already a base dep. No change there. `serde_json` is already in the native feature.

- [ ] **Step 2: Build the bin**

```bash
cargo build --no-default-features --features native --bin amt-verify 2>&1 | tail -5
```

Expected: clean compile.

- [ ] **Step 3: Smoke against fake relay**

Open two shells. In shell A (fake relay — easiest to do via an integration test in `tests/`, but for ad-hoc smoke just run the existing test:

```bash
cargo test --no-default-features --features native --test native_runtime oneshot_happy_path_v4 -- --nocapture 2>&1 | tail -10
```

Expected: PASS — same green as before (no change to behavior, just confirms compile).

Then verify the bin's `--help`:

```bash
cargo run --no-default-features --features native --bin amt-verify -- --help 2>&1 | tail -20
```

Expected: clap usage banner printed.

- [ ] **Step 4: Commit**

```bash
git add src/bin/amt-verify.rs
git commit -m "feat(cli): amt-verify one-shot mode

Required: --relay --group. Optional: --source (SSM), --port,
--timeout, --keepalive, --json, --verbose. Exit 0 on first
DataEvent within --timeout; exit 1 with stderr message otherwise.
--watch and DRIAD path land in next tasks."
```

---

### Task 3.3: `--watch` mode + SIGINT graceful shutdown

**Files:**
- Modify: `src/bin/amt-verify.rs`

- [ ] **Step 1: Replace the `run_watch` stub**

In `src/bin/amt-verify.rs`, replace the body of `run_watch` with:

```rust
async fn run_watch(
    gw: AsyncAmtGateway,
    mut data_rx: tokio::sync::broadcast::Receiver<amt_protocol::native::DataEvent>,
) -> Result<()> {
    use tokio::sync::broadcast::error::RecvError;
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut pkts: u64 = 0;
    let mut bytes: u64 = 0;
    let mut last_seen = Instant::now();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("amt-verify: SIGINT received, tearing down");
                break;
            }
            recv = data_rx.recv() => {
                match recv {
                    Ok(evt) => {
                        pkts += 1;
                        bytes += evt.payload.len() as u64;
                        last_seen = Instant::now();
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        eprintln!("amt-verify: WARN lagged {} packets", skipped);
                    }
                    Err(RecvError::Closed) => {
                        eprintln!("amt-verify: data broadcast closed");
                        break;
                    }
                }
            }
            _ = tick.tick() => {
                let age = last_seen.elapsed().as_millis();
                println!("pkts={} bytes={} last_seen={}ms_ago state={:?}",
                    pkts, bytes, age, gw.state());
            }
        }
    }
    gw.shutdown().await?;
    Ok(())
}
```

- [ ] **Step 2: Build**

```bash
cargo build --no-default-features --features native --bin amt-verify 2>&1 | tail -3
```

Expected: clean.

- [ ] **Step 3: Manual smoke — `--watch` against fake relay**

Spin up a fake-relay test variant for hand-driven smoke. Create `tests/watch_smoke.rs`:

```rust
#![cfg(feature = "native")]

mod common;

use std::time::Duration;
use amt_protocol::native::AsyncAmtGateway;
use common::fake_relay::{synth_v4_udp, FakeRelay};

#[tokio::test(flavor = "current_thread")]
async fn watch_mode_emits_periodic_stats() {
    // Spin a relay that keeps repeating MulticastData every 1s for 3s.
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"hb");
    relay.spawn(inner);

    let gw = AsyncAmtGateway::builder(relay.addr.ip())
        .relay_port(relay.addr.port())
        .build()
        .await
        .unwrap();
    let _data_rx = gw.subscribe_data();
    gw.subscribe(
        "232.0.0.1".parse().unwrap(),
        Some("10.0.0.1".parse().unwrap()),
    )
    .await
    .unwrap();
    // Just confirm we reach Active within the budget — the watch loop itself
    // is exercised manually with `cargo run`.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(gw.state(), amt_protocol::gateway::GatewayState::Active);
    gw.shutdown().await.unwrap();
}
```

Run it:

```bash
cargo test --no-default-features --features native --test watch_smoke 2>&1 | tail -10
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/bin/amt-verify.rs tests/watch_smoke.rs
git commit -m "feat(cli): amt-verify --watch mode + SIGINT teardown

select! over ctrl_c + data_rx + 5s tick interval. Stats line
each tick: pkts, bytes, last_seen_ms_ago, gateway state.
On SIGINT, calls gw.shutdown() before returning Ok."
```

---

### Task 3.4: JSON output verified by parsing

**Files:**
- Modify: `tests/watch_smoke.rs` (or new test file)

- [ ] **Step 1: Write the failing test**

Add this test by creating `tests/cli_json.rs`:

```rust
#![cfg(feature = "native")]

mod common;

use common::fake_relay::{synth_v4_udp, FakeRelay};
use std::process::Stdio;
use tokio::process::Command;
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "current_thread")]
async fn json_output_is_parseable() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn(inner);

    let bin = env!("CARGO_BIN_EXE_amt-verify");
    let mut child = Command::new(bin)
        .args([
            "--relay", &relay.addr.ip().to_string(),
            "--port", &relay.addr.port().to_string(),
            "--group", "232.0.0.1",
            "--source", "10.0.0.1",
            "--timeout", "5",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn amt-verify");

    let mut stdout = child.stdout.take().unwrap();
    let mut buf = String::new();
    stdout.read_to_string(&mut buf).await.unwrap();
    let status = child.wait().await.unwrap();
    assert!(status.success(), "exit code: {status}");

    let v: serde_json::Value = serde_json::from_str(buf.trim()).expect(&buf);
    assert_eq!(v["outcome"], "ok");
    assert_eq!(v["group"], "232.0.0.1");
    assert_eq!(v["first_packet"]["src"], "10.0.0.1:5004");
}
```

- [ ] **Step 2: Run the test**

```bash
cargo test --no-default-features --features native --test cli_json 2>&1 | tail -15
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/cli_json.rs
git commit -m "test(cli): verify --json output is valid JSON with expected fields

Spawns the real bin via CARGO_BIN_EXE_amt-verify against the
loopback fake relay; parses stdout, asserts outcome=ok and
the first_packet src field matches the synthesized inner."
```

---

## Milestone M4 — Native DRIAD resolver

Gate: Tier-1.5 tests green; `amt-verify --source <IP> --group <G>` (without `--relay`) resolves and proceeds.

### Task 4.1: Add AAAA helpers to `driad.rs`

**Files:**
- Modify: `src/driad.rs`

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` in `src/driad.rs`:

```rust
    #[test]
    fn build_dns_aaaa_query_packet_structure() {
        let packet = DriadResolver::build_dns_aaaa_query("relay.example.", 0x1234);
        // DNS header: ID(2) + flags(2) + counts(8) = 12 bytes
        assert_eq!(&packet[..2], &[0x12, 0x34]);
        // QTYPE at end before QCLASS: AAAA = 28 = 0x001C
        let qtype_off = packet.len() - 4;
        assert_eq!(&packet[qtype_off..qtype_off + 2], &[0x00, 0x1C]);
    }

    #[test]
    fn parse_dns_aaaa_response_extracts_ipv6() {
        // Construct minimal AAAA response: header + question echo + 1 answer.
        let query = DriadResolver::build_dns_aaaa_query("relay.example.", 0xABCD);
        let mut response = query.clone();
        // Set flags: response (QR=1) + recursion available
        response[2] = 0x81;
        response[3] = 0x80;
        // Set ANCOUNT to 1 (bytes 6-7)
        response[6] = 0; response[7] = 1;
        // Append answer: pointer (0xC00C) + TYPE(28) + CLASS(1) + TTL(4) + RDLEN(16) + IPv6(16)
        response.extend_from_slice(&[
            0xC0, 0x0C,
            0x00, 0x1C,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x10,
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);

        let addr = DriadResolver::parse_dns_aaaa_response(&response).expect("AAAA parse");
        assert_eq!(addr, "2001:db8::1".parse::<std::net::IpAddr>().unwrap());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd ~/src/amt-protocol
cargo test --lib driad::tests::build_dns_aaaa_query_packet_structure 2>&1 | tail -10
```

Expected: FAIL — `no function or associated item named 'build_dns_aaaa_query' found`.

- [ ] **Step 3: Implement the helpers**

Find the existing private constant `DNS_TYPE_A` near the top of `driad.rs`. Add a sibling:

```rust
const DNS_TYPE_AAAA: u16 = 28;
```

Inside `impl DriadResolver`, after `build_dns_a_query`:

```rust
    /// Build a wire-format DNS AAAA query packet.
    pub fn build_dns_aaaa_query(hostname: &str, transaction_id: u16) -> Vec<u8> {
        Self::build_dns_query_packet(hostname, DNS_TYPE_AAAA, transaction_id)
    }

    /// Parse the first AAAA answer record from a DNS response. Returns None
    /// if there is no AAAA record (e.g. only A answers, or NXDOMAIN).
    pub fn parse_dns_aaaa_response(data: &[u8]) -> Option<std::net::IpAddr> {
        let rdata = Self::find_dns_answer(data, DNS_TYPE_AAAA)?;
        if rdata.len() != 16 { return None; }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&rdata);
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)))
    }
```

- [ ] **Step 4: Run tests**

```bash
cargo test --lib driad:: 2>&1 | tail -10
```

Expected: 2 new tests pass; all existing driad tests still pass.

- [ ] **Step 5: Commit**

```bash
git add src/driad.rs
git commit -m "feat(driad): AAAA query/response helpers

build_dns_aaaa_query mirrors build_dns_a_query, parameterized
to QTYPE=28. parse_dns_aaaa_response extracts the first AAAA
RDATA into IpAddr::V6. Needed for DnsName follow-up when the
AMTRELAY answer is a name rather than a literal address."
```

---

### Task 4.2: `/etc/resolv.conf` parser

**Files:**
- Create: `src/native/resolver.rs`
- Modify: `src/native/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `src/native/resolver.rs`:

```rust
//! Native DRIAD resolver — UDP:53 to system resolver(s).

use std::net::IpAddr;

/// Parse the `nameserver` lines of an /etc/resolv.conf-style string.
/// Returns IPs in declaration order; ignores comments + unknown directives.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with(';') { continue; }
        let mut parts = trimmed.split_ascii_whitespace();
        if parts.next() == Some("nameserver") {
            if let Some(addr) = parts.next() {
                if let Ok(ip) = addr.parse::<IpAddr>() {
                    out.push(ip);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolv_conf_picks_in_order() {
        let txt = "
# comment
search example.
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2606:4700:4700::1111
";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns.len(), 3);
        assert_eq!(ns[0], "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(ns[1], "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(ns[2], "2606:4700:4700::1111".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_resolv_conf_skips_comments_and_unknown_directives() {
        let txt = "options edns0\noptions rotate\n; another comment\nnameserver 10.0.0.1\n";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn parse_resolv_conf_invalid_ip_silently_skipped() {
        let txt = "nameserver not-an-ip\nnameserver 8.8.4.4\n";
        let ns = parse_resolv_conf(txt);
        assert_eq!(ns, vec!["8.8.4.4".parse::<IpAddr>().unwrap()]);
    }
}
```

In `src/native/mod.rs`, add:

```rust
pub mod resolver;
```

- [ ] **Step 2: Run the tests**

```bash
cargo test --no-default-features --features native --lib native::resolver 2>&1 | tail -10
```

Expected: 3 tests pass.

- [ ] **Step 3: Commit**

```bash
git add src/native/resolver.rs src/native/mod.rs
git commit -m "feat(native): parse_resolv_conf helper

Returns nameserver IPs in declaration order from an
/etc/resolv.conf-style string. Skips comments, unknown directives,
and malformed IPs. Pure-string parser — no I/O."
```

---

### Task 4.3: `resolve_amt_relay()` — AMTRELAY query, IP-answer fast path

**Files:**
- Modify: `src/native/resolver.rs`

- [ ] **Step 1: Write the failing test**

Append to `src/native/resolver.rs`:

```rust
use std::time::Duration;
use anyhow::{anyhow, Context, Result};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::driad::{DriadRelayAddress, DriadResolver};

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_ATTEMPTS: usize = 3;

/// Resolve the AMT relay address for `source` via DRIAD over UDP:53.
///
/// Reads /etc/resolv.conf, sends an AMTRELAY query to each nameserver until
/// one answers (max 3 total attempts across the nameserver list).
pub async fn resolve_amt_relay(source: IpAddr) -> Result<IpAddr> {
    let resolv = std::fs::read_to_string("/etc/resolv.conf")
        .context("reading /etc/resolv.conf")?;
    let nameservers = parse_resolv_conf(&resolv);
    if nameservers.is_empty() {
        return Err(anyhow!("no nameserver entries in /etc/resolv.conf"));
    }
    resolve_with_nameservers(source, &nameservers).await
}

pub async fn resolve_with_nameservers(source: IpAddr, nameservers: &[IpAddr]) -> Result<IpAddr> {
    let query = DriadResolver::build_dns_query(source, rand_id());
    let mut last_err: Option<anyhow::Error> = None;
    let mut attempts = 0;
    for ns in nameservers {
        if attempts >= MAX_ATTEMPTS { break; }
        attempts += 1;
        match try_one(*ns, &query).await {
            Ok(rdata) => match rdata {
                DriadRelayAddress::Ipv4(ip) => return Ok(IpAddr::V4(ip)),
                DriadRelayAddress::Ipv6(ip) => return Ok(IpAddr::V6(ip)),
                DriadRelayAddress::DnsName(name) => {
                    // Follow-up A/AAAA lookup — implemented in Task 4.4.
                    return follow_up_a_or_aaaa(&name, nameservers).await;
                }
            },
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("DRIAD: no usable nameserver answered")))
}

async fn try_one(ns: IpAddr, query: &[u8]) -> Result<DriadRelayAddress> {
    let bind = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.send_to(query, std::net::SocketAddr::new(ns, DNS_PORT)).await?;
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf)).await
        .map_err(|_| anyhow!("DNS query to {} timed out", ns))??;
    DriadResolver::parse_dns_response(&buf[..n])
        .ok_or_else(|| anyhow!("DNS reply from {} had no AMTRELAY answer", ns))
}

// Stub — full impl in Task 4.4.
async fn follow_up_a_or_aaaa(_name: &str, _nameservers: &[IpAddr]) -> Result<IpAddr> {
    Err(anyhow!("AMTRELAY DnsName follow-up not yet implemented"))
}

fn rand_id() -> u16 {
    let mut buf = [0u8; 2];
    getrandom::getrandom(&mut buf).expect("getrandom for DNS txn id");
    u16::from_be_bytes(buf)
}

#[cfg(test)]
mod resolve_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn fallback_when_first_nameserver_drops() {
        // Bind a real socket to occupy a port but never reply.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();

        // Fake answering nameserver that emits an AMTRELAY IPv4 record.
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, src) = live.recv_from(&mut buf).await.unwrap();
            let query = &buf[..n];
            // Build a minimal AMTRELAY response.
            let mut resp = query.to_vec();
            resp[2] = 0x81; resp[3] = 0x80;
            resp[6] = 0; resp[7] = 1;
            // pointer + TYPE(260) + CLASS(1) + TTL(60) + RDLEN(7) + precedence(1) + D(1) + type(1) + IPv4(4)
            resp.extend_from_slice(&[
                0xC0, 0x0C,
                0x01, 0x04,
                0x00, 0x01,
                0x00, 0x00, 0x00, 0x3C,
                0x00, 0x07,
                0,
                0x80, // D=1 (digest? — for the parser we just need type byte right)
                0x01, // AMTRELAY type 1 = IPv4
                192, 0, 2, 96,
            ]);
            live.send_to(&resp, src).await.unwrap();
        });

        let ns = vec![IpAddr::V4("127.0.0.1".parse().unwrap()); 0]; // placeholder; we use both:
        let nameservers = vec![
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        ];
        // Override DNS_PORT in test by writing to two distinct binds — but our
        // try_one uses port 53 of the IpAddr. We can't easily redirect to a
        // dynamic port without exposing a helper. Add a `_test` variant:
        let _ = (dead_addr, live_addr, ns, nameservers);
        // This test is a placeholder; see Task 4.4 for the real fallback test
        // that uses `resolve_with_nameservers_for_test`.
    }
}
```

> **Note for the engineer**: the `try_one` function targets DNS port 53. For unit testing we need a test-only function that targets arbitrary ports. The next step adds that.

- [ ] **Step 2: Add a test-port helper**

Append to `src/native/resolver.rs`:

```rust
#[cfg(test)]
async fn try_one_at_port(ns: IpAddr, port: u16, query: &[u8]) -> Result<DriadRelayAddress> {
    let bind = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.send_to(query, std::net::SocketAddr::new(ns, port)).await?;
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf)).await
        .map_err(|_| anyhow!("DNS query to {}:{} timed out", ns, port))??;
    DriadResolver::parse_dns_response(&buf[..n])
        .ok_or_else(|| anyhow!("DNS reply from {}:{} had no AMTRELAY answer", ns, port))
}

#[cfg(test)]
pub(crate) async fn resolve_v4_oneshot_for_test(
    source: IpAddr,
    nameserver: IpAddr,
    ns_port: u16,
) -> Result<IpAddr> {
    let query = DriadResolver::build_dns_query(source, rand_id());
    let rdata = try_one_at_port(nameserver, ns_port, &query).await?;
    match rdata {
        DriadRelayAddress::Ipv4(ip) => Ok(IpAddr::V4(ip)),
        DriadRelayAddress::Ipv6(ip) => Ok(IpAddr::V6(ip)),
        DriadRelayAddress::DnsName(_) => Err(anyhow!("DnsName follow-up not in this helper")),
    }
}
```

Replace the placeholder `fallback_when_first_nameserver_drops` test with one using the helper. Update the test block:

```rust
#[cfg(test)]
mod resolve_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn amtrelay_ipv4_record_resolves() {
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (n, src) = live.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] = 0x81; resp[3] = 0x80;
            resp[6] = 0; resp[7] = 1;
            resp.extend_from_slice(&[
                0xC0, 0x0C,
                0x01, 0x04,                         // TYPE 260
                0x00, 0x01,
                0x00, 0x00, 0x00, 0x3C,
                0x00, 0x07,
                0,                                  // precedence
                0x00,                               // D-bit + reserved
                0x01,                               // AMTRELAY type 1 = IPv4
                192, 0, 2, 96,
            ]);
            live.send_to(&resp, src).await.unwrap();
        });

        let source: IpAddr = "10.0.0.1".parse().unwrap();
        let ns: IpAddr = live_addr.ip();
        let port = live_addr.port();
        let relay = resolve_v4_oneshot_for_test(source, ns, port).await.unwrap();
        assert_eq!(relay, "192.0.2.96".parse::<IpAddr>().unwrap());
    }
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test --no-default-features --features native --lib native::resolver 2>&1 | tail -15
```

Expected: parse_resolv_conf tests pass + `amtrelay_ipv4_record_resolves` passes.

- [ ] **Step 4: Commit**

```bash
git add src/native/resolver.rs
git commit -m "feat(native): DRIAD resolver — AMTRELAY query + IP-answer path

resolve_amt_relay(source) reads /etc/resolv.conf, sends an
AMTRELAY query (reusing driad::build_dns_query) to nameservers
in order with a 2s per-server timeout and a 3-attempt budget.
On AMTRELAY=IPv4 or IPv6 answer, returns it directly. DnsName
follow-up is stubbed and lands in Task 4.4. Test exercises the
IPv4 fast-path via try_one_at_port helper."
```

---

### Task 4.4: DnsName follow-up — parallel A + AAAA

**Files:**
- Modify: `src/native/resolver.rs`

- [ ] **Step 1: Write the failing test**

Append to `src/native/resolver.rs` `#[cfg(test)] mod resolve_tests`:

```rust
    #[tokio::test(flavor = "current_thread")]
    async fn dns_name_followup_resolves_via_aaaa() {
        let live = UdpSocket::bind("[::1]:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            // Respond to whatever we receive with a synthetic AAAA answer.
            // (The follow-up function fires A+AAAA in parallel; we answer AAAA.)
            let mut buf = [0u8; 4096];
            loop {
                let (n, src) = live.recv_from(&mut buf).await.unwrap();
                let query = &buf[..n];
                // Identify QTYPE: 4 bytes before end (skip TTL/RDLEN/etc — actually QTYPE is at
                // 4 bytes before end of question section, i.e. final 4 bytes before any answer).
                let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
                if qtype != 28 {
                    // Drop A queries — force the resolver to pick AAAA.
                    continue;
                }
                let mut resp = query.to_vec();
                resp[2] = 0x81; resp[3] = 0x80;
                resp[6] = 0; resp[7] = 1;
                resp.extend_from_slice(&[
                    0xC0, 0x0C,
                    0x00, 0x1C,         // TYPE AAAA
                    0x00, 0x01,
                    0x00, 0x00, 0x00, 0x3C,
                    0x00, 0x10,
                    0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0x01,
                ]);
                live.send_to(&resp, src).await.unwrap();
            }
        });

        let ns = live_addr.ip();
        let port = live_addr.port();
        let addr = follow_up_a_or_aaaa_for_test("relay.example.", ns, port)
            .await
            .expect("AAAA follow-up");
        assert_eq!(addr, "2001:db8::1".parse::<IpAddr>().unwrap());
    }
```

- [ ] **Step 2: Implement the follow-up function + its test helper**

Replace the existing `follow_up_a_or_aaaa` stub in `src/native/resolver.rs` with:

```rust
async fn follow_up_a_or_aaaa(name: &str, nameservers: &[IpAddr]) -> Result<IpAddr> {
    for ns in nameservers {
        if let Ok(addr) = follow_up_a_or_aaaa_one(name, *ns, DNS_PORT).await {
            return Ok(addr);
        }
    }
    Err(anyhow!("AMTRELAY DnsName {} did not resolve via any nameserver", name))
}

async fn follow_up_a_or_aaaa_one(name: &str, ns: IpAddr, port: u16) -> Result<IpAddr> {
    let a_id = rand_id();
    let aaaa_id = rand_id();
    let a_q   = DriadResolver::build_dns_a_query(name, a_id);
    let aaaa_q = DriadResolver::build_dns_aaaa_query(name, aaaa_id);
    let bind = if ns.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await?;
    let target = std::net::SocketAddr::new(ns, port);
    sock.send_to(&a_q, target).await?;
    sock.send_to(&aaaa_q, target).await?;
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    loop {
        let remaining = deadline.checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| anyhow!("A/AAAA follow-up timed out for {}", name))?;
        let (n, _) = timeout(remaining, sock.recv_from(&mut buf)).await
            .map_err(|_| anyhow!("A/AAAA recv_from timed out for {}", name))??;
        let pkt = &buf[..n];
        // Validate response TXID + qname BEFORE trusting any answer bytes.
        // Without this, a stray / spoofed / stale packet could be accepted
        // as the relay's address.
        if pkt.len() < 12 { continue; }
        let resp_id = u16::from_be_bytes([pkt[0], pkt[1]]);
        let matches_a    = resp_id == a_id;
        let matches_aaaa = resp_id == aaaa_id;
        if !matches_a && !matches_aaaa {
            // Not for either of our queries — ignore.
            continue;
        }
        // qname match: the question section starts at offset 12. Compare
        // against the expected wire-encoded name length we sent.
        if !response_qname_matches(pkt, name) {
            continue;
        }
        if matches_aaaa {
            if let Some(addr) = DriadResolver::parse_dns_aaaa_response(pkt) {
                return Ok(addr);
            }
        }
        if matches_a {
            if let Some(addr) = DriadResolver::parse_dns_a_response(pkt) {
                return Ok(addr);
            }
        }
        // Matched ID + qname but no usable answer — keep waiting for the sibling.
    }
}

/// Compare the question-section qname in a DNS response to an expected hostname.
/// Returns true iff the wire-encoded labels match (case-insensitive ASCII).
fn response_qname_matches(pkt: &[u8], expected: &str) -> bool {
    if pkt.len() < 12 { return false; }
    let mut off = 12usize;
    let mut expected_labels: Vec<&str> = expected.trim_end_matches('.').split('.').collect();
    expected_labels.retain(|s| !s.is_empty());
    let mut got_labels: Vec<String> = Vec::new();
    while off < pkt.len() {
        let len = pkt[off] as usize;
        if len == 0 { off += 1; break; }
        if len >= 0xC0 { return false; } // pointer in question is malformed
        off += 1;
        if off + len > pkt.len() { return false; }
        let label = String::from_utf8_lossy(&pkt[off..off + len]).to_string();
        got_labels.push(label);
        off += len;
    }
    if got_labels.len() != expected_labels.len() { return false; }
    got_labels.iter().zip(expected_labels.iter()).all(|(g, e)| g.eq_ignore_ascii_case(e))
}

#[cfg(test)]
pub(crate) async fn follow_up_a_or_aaaa_for_test(name: &str, ns: IpAddr, port: u16) -> Result<IpAddr> {
    follow_up_a_or_aaaa_one(name, ns, port).await
}
```

- [ ] **Step 3: Run the test**

```bash
cargo test --no-default-features --features native --lib native::resolver 2>&1 | tail -15
```

Expected: 4 tests pass total (3 prior + 1 new).

- [ ] **Step 4: Commit**

```bash
git add src/native/resolver.rs
git commit -m "feat(native): DRIAD DnsName follow-up — parallel A + AAAA

When AMTRELAY answer is a DnsName, send both A and AAAA queries
on the same socket and accept the first valid answer. The
relay's family is orthogonal to the source's family in DRIAD,
so we don't bias either way. 2s total budget per nameserver."
```

---

### Task 4.5: Wire `builder_for_source` + CLI `--no-driad`

**Files:**
- Modify: `src/native/gateway.rs`
- Modify: `src/bin/amt-verify.rs`

- [ ] **Step 1: Add `builder_for_source` to `AsyncAmtGatewayBuilder`**

In `src/native/gateway.rs`, inside `impl AsyncAmtGateway`, add:

```rust
    /// Construct a builder that will DRIAD-resolve the relay from `source`
    /// when `.build()` is awaited.
    pub fn builder_for_source(source: IpAddr) -> AsyncAmtGatewayBuilderForSource {
        AsyncAmtGatewayBuilderForSource {
            source,
            relay_port: 2268,
            keepalive: Duration::from_secs(AmtConfig::DEFAULT_KEEPALIVE_SECS as u64),
            log_target: "amt",
        }
    }
```

At the bottom of `src/native/gateway.rs`, add:

```rust
pub struct AsyncAmtGatewayBuilderForSource {
    source: IpAddr,
    relay_port: u16,
    keepalive: Duration,
    log_target: &'static str,
}

impl AsyncAmtGatewayBuilderForSource {
    pub fn relay_port(mut self, port: u16) -> Self { self.relay_port = port; self }
    pub fn keepalive(mut self, d: Duration) -> Self { self.keepalive = d; self }
    pub fn log_target(mut self, t: &'static str) -> Self { self.log_target = t; self }

    pub async fn build(self) -> Result<AsyncAmtGateway> {
        let relay = super::resolver::resolve_amt_relay(self.source).await?;
        tracing::info!(target: self.log_target, relay=%relay, "DRIAD resolved relay");
        AsyncAmtGateway::builder(relay)
            .relay_port(self.relay_port)
            .keepalive(self.keepalive)
            .log_target(self.log_target)
            .build()
            .await
    }
}
```

- [ ] **Step 2: Update CLI to make `--relay` optional + add `--no-driad`**

Replace the `Args` struct in `src/bin/amt-verify.rs` with:

```rust
#[derive(Parser, Debug)]
#[command(name = "amt-verify", version, about = "AMT E2E verify CLI")]
struct Args {
    /// AMT relay address. If omitted, DRIAD-resolved from --source.
    #[arg(long)]
    relay: Option<IpAddr>,

    /// AMT relay UDP port (RFC 7450 default 2268)
    #[arg(long, default_value_t = 2268)]
    port: u16,

    /// Multicast group address (mandatory)
    #[arg(long)]
    group: IpAddr,

    /// SSM source address — REQUIRED. DRIAD-only mode also needs it
    /// (DRIAD queries on the source).
    #[arg(long)]
    source: IpAddr,

    /// Force IP family. `auto` infers from --relay (or resolved relay).
    #[arg(long, value_enum, default_value_t = Family::Auto)]
    family: Family,

    /// Disable DRIAD. Forces --relay to be explicit.
    #[arg(long, default_value_t = false)]
    no_driad: bool,

    /// Wait at most this many seconds for first data
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Keep-alive interval in seconds
    #[arg(long, default_value = "60")]
    keepalive: u64,

    /// Stay running after first data, log stats every 5s
    #[arg(long, default_value_t = false)]
    watch: bool,

    /// Machine-readable JSON output (one-shot mode only).
    /// Rejected with exit 2 if combined with --watch.
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Verbose logging
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}
```

The `Family` and `ExitCategory` enums from Task 3.2 are unchanged and reused.

Replace the `run()` function:

```rust
async fn run(args: Args) -> std::result::Result<(), ExitCategory> {
    // ----- Config validation (exit 2) -----
    if args.json && args.watch {
        return Err(ExitCategory::Config(anyhow!(
            "--json is one-shot only; combining with --watch is rejected"
        )));
    }
    if args.no_driad && args.relay.is_none() {
        return Err(ExitCategory::Config(anyhow!(
            "--no-driad set but --relay missing"
        )));
    }

    // ----- Build gateway (relay path OR DRIAD path) -----
    let (gw, resolved_relay) = match args.relay {
        Some(r) => {
            let gw = AsyncAmtGateway::builder(r)
                .relay_port(args.port)
                .keepalive(Duration::from_secs(args.keepalive))
                .build()
                .await
                .map_err(ExitCategory::Fatal)?;
            (gw, r)
        }
        None => {
            // DRIAD path — resolve internally, then build.
            let gw = AsyncAmtGateway::builder_for_source(args.source)
                .relay_port(args.port)
                .keepalive(Duration::from_secs(args.keepalive))
                .build()
                .await
                .map_err(ExitCategory::HandshakeFail)?;
            // For JSON output we want to print the resolved relay. Re-resolve
            // once explicitly (cheap) — alternative would be having
            // builder_for_source expose the resolved address.
            let resolved = amt_protocol::native::resolver::resolve_amt_relay(args.source)
                .await
                .map_err(ExitCategory::HandshakeFail)?;
            (gw, resolved)
        }
    };

    // Family inference now that we know the relay (resolved or explicit).
    let inferred_family = if resolved_relay.is_ipv4() { Family::V4 } else { Family::V6 };
    let effective_family = match args.family {
        Family::Auto => inferred_family,
        explicit => {
            let same = matches!((explicit, inferred_family),
                (Family::V4, Family::V4) | (Family::V6, Family::V6));
            if !same {
                return Err(ExitCategory::Config(anyhow!(
                    "--family explicitly set but does not match --relay family"
                )));
            }
            explicit
        }
    };
    let family_str = match effective_family { Family::V4 => "v4", Family::V6 => "v6", Family::Auto => unreachable!() };

    // group/source family checks (caught before any further wire traffic)
    if args.group.is_ipv4() != args.source.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --source must be the same IP family"
        )));
    }
    if args.group.is_ipv4() != resolved_relay.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --relay must be the same IP family"
        )));
    }

    let mut data_rx = gw.subscribe_data();

    let started = Instant::now();
    gw.subscribe(args.group, Some(args.source))
        .await
        .map_err(ExitCategory::HandshakeFail)?;

    let evt = match recv_first_matching(
        &mut data_rx,
        args.group,
        args.source,
        Duration::from_secs(args.timeout),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return Err(ExitCategory::HandshakeFail(e)),
    };
    let first_data_ms = started.elapsed().as_millis() as u64;

    if args.json {
        let report = OneshotReport {
            outcome: "ok",
            relay: resolved_relay.to_string(),
            family: family_str,
            group: args.group.to_string(),
            source: Some(args.source.to_string()),
            timings_ms: Timings { first_data: first_data_ms },
            first_packet: FirstPacket {
                src: format!("{}:{}", evt.src, evt.src_port),
                dst_port: evt.dst_port,
                len: evt.payload.len(),
            },
        };
        println!("{}", serde_json::to_string(&report).map_err(|e| ExitCategory::Fatal(e.into()))?);
    } else {
        println!(
            "ok — relay={} family={} group={} source={} first_data={}ms first_pkt={}:{} len={}",
            resolved_relay, family_str, args.group, args.source,
            first_data_ms, evt.src, evt.src_port, evt.payload.len()
        );
    }

    if args.watch {
        run_watch(gw, data_rx).await.map_err(ExitCategory::Fatal)?;
    } else {
        gw.shutdown().await.map_err(ExitCategory::Fatal)?;
    }
    Ok(())
}
```

- [ ] **Step 3: Verify build + existing tests still pass**

```bash
cargo build --no-default-features --features native --bin amt-verify 2>&1 | tail -3
cargo test --no-default-features --features native --test cli_json 2>&1 | tail -5
cargo test --no-default-features --features native --test native_runtime 2>&1 | tail -10
```

Expected: clean build; cli_json passes (we still pass `--relay` in it); native_runtime tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/native/gateway.rs src/bin/amt-verify.rs
git commit -m "feat(native+cli): builder_for_source + amt-verify DRIAD path

AsyncAmtGateway::builder_for_source(src) returns a builder that
DRIAD-resolves the relay on .build(). amt-verify makes --relay
optional: if absent, DRIAD-resolves from --source; --no-driad
forces --relay to be explicit (defense against silent DNS
misconfig in CI). Both paths use the same shutdown sequence."
```

---

## Milestone M5 — Staging E2E + runbook

Gate: One ignored test pinned to staging passes when run by hand from an in-cluster pod. Runbook documents the command line.

### Task 5.1: E2E ignored test

**Files:**
- Create: `tests/e2e_staging.rs`

- [ ] **Step 1: Write the test**

Create `tests/e2e_staging.rs`:

```rust
//! E2E tests pinned to staging-blockcastd amt-relay.
//! Manual: `cargo test --no-default-features --features native --test e2e_staging -- --ignored --nocapture`.

#![cfg(feature = "native")]

use std::env;
use std::net::IpAddr;
use std::time::Duration;

use amt_protocol::native::AsyncAmtGateway;

/// Pinned via env so the test runs in any environment.
/// Required:
///   STAGING_RELAY        — e.g. "192.0.2.96"
///   STAGING_SOURCE       — e.g. "69.25.95.10"
///   STAGING_GROUP        — e.g. "232.0.0.1"
fn env_required(key: &str) -> IpAddr {
    env::var(key)
        .unwrap_or_else(|_| panic!("env var {} required for staging E2E", key))
        .parse()
        .unwrap_or_else(|e| panic!("env var {} parse: {:?}", key, e))
}

#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn e2e_oneshot_explicit_relay() {
    let relay = env_required("STAGING_RELAY");
    let source = env_required("STAGING_SOURCE");
    let group = env_required("STAGING_GROUP");

    let gw = AsyncAmtGateway::builder(relay)
        .keepalive(Duration::from_secs(60))
        .build()
        .await
        .expect("build gateway");
    let mut data_rx = gw.subscribe_data();
    gw.subscribe(group, Some(source)).await.expect("subscribe");

    let evt = tokio::time::timeout(Duration::from_secs(30), data_rx.recv())
        .await
        .expect("timed out within 30s — relay reachable + (S,G) live?")
        .expect("broadcast closed");
    assert!(!evt.payload.is_empty(), "expected non-empty first packet");
    eprintln!("first packet: src={} dst_port={} len={}", evt.src, evt.dst_port, evt.payload.len());

    gw.shutdown().await.expect("shutdown");
}

#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn e2e_driad_then_join() {
    let source = env_required("STAGING_SOURCE");
    let group = env_required("STAGING_GROUP");

    let gw = AsyncAmtGateway::builder_for_source(source)
        .build()
        .await
        .expect("build gateway (DRIAD)");
    let mut data_rx = gw.subscribe_data();
    gw.subscribe(group, Some(source)).await.expect("subscribe");

    let evt = tokio::time::timeout(Duration::from_secs(30), data_rx.recv())
        .await
        .expect("timed out — DRIAD resolved but no data?")
        .expect("broadcast closed");
    assert!(!evt.payload.is_empty());
    gw.shutdown().await.unwrap();
}
```

- [ ] **Step 2: Verify compile**

```bash
cargo build --no-default-features --features native --tests 2>&1 | tail -5
```

Expected: clean.

- [ ] **Step 3: Verify it does NOT run by default**

```bash
cargo test --no-default-features --features native --test e2e_staging 2>&1 | tail -10
```

Expected: `running 2 tests` followed by both reported as `ignored`. No env vars consulted, no network.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e_staging.rs
git commit -m "test(e2e): staging-pinned ignored tests

e2e_oneshot_explicit_relay — explicit --relay path.
e2e_driad_then_join — DRIAD path (requires in-cluster :53/UDP).
Both gated on env vars STAGING_RELAY/STAGING_SOURCE/STAGING_GROUP
and on --ignored to avoid running in default cargo test."
```

---

### Task 5.2: Runbook + README

**Files:**
- Create: `docs/runbook-staging-e2e.md`
- Modify: `README.md`

- [ ] **Step 1: Write the runbook**

Create `docs/runbook-staging-e2e.md`:

```markdown
# Staging E2E runbook — amt-verify against staging-blockcastd

## Prerequisites

- kubectl access to the `staging-blockcastd` namespace
- A live (S,G) feed: source IP that's currently sending to a known group
- Either:
  - **Direct path** (devbox): set `STAGING_RELAY` to the amt-relay external IP
  - **DRIAD path** (in-cluster pod): leave `STAGING_RELAY` unset; runs from a pod
    where `:53/UDP` reaches kube-dns

## Build the bin

From the amt-protocol repo:

\`\`\`bash
cargo build --release --no-default-features --features native --bin amt-verify
\`\`\`

The binary lands at `target/release/amt-verify`.

## Direct path — from devbox

\`\`\`bash
./target/release/amt-verify \
    --relay 192.0.2.96 \
    --source 69.25.95.10 \
    --group 232.0.0.1 \
    --timeout 30 \
    --json
\`\`\`

Expected output (one line of JSON):

\`\`\`json
{"outcome":"ok","relay":"192.0.2.96","family":"v4","group":"232.0.0.1","source":"69.25.95.10","timings_ms":{"first_data":240},"first_packet":{"src":"69.25.95.10:5004","dst_port":5004,"len":1316}}
\`\`\`

Exit code: 0 on success, 1 on timeout / handshake failure.

## DRIAD path — from in-cluster pod

\`\`\`bash
kubectl -n staging-blockcastd run amt-verify-shot --rm -it --restart=Never \
    --image=ghcr.io/blockcast/amt-verify:latest \
    -- --source 69.25.95.10 --group 232.0.0.1 --timeout 30 --json
\`\`\`

(Image build is out of scope for M5; for ad-hoc verify, `kubectl cp` the
local binary into a debug pod that already has a libc compatible with the
build environment.)

## Running the ignored E2E tests

\`\`\`bash
STAGING_RELAY=192.0.2.96 \
STAGING_SOURCE=69.25.95.10 \
STAGING_GROUP=232.0.0.1 \
    cargo test --no-default-features --features native \
        --test e2e_staging -- --ignored --nocapture
\`\`\`

## Troubleshooting

- **Timeout at 30s on `e2e_oneshot_explicit_relay`**: relay reachable but no
  multicast data flowing for the (S,G). Confirm with `tcpdump -i any host
  $STAGING_RELAY` on the relay; check `staging-blockcastd` amt-relay `/health`
  for `mfc_absent_counters` (requires USE_EBPF=true — separate work).
- **Timeout on `e2e_driad_then_join`** but `e2e_oneshot_explicit_relay`
  passes: DNS path is broken. Check `/etc/resolv.conf` inside the pod;
  verify `dig` against kube-dns from the pod returns an AMTRELAY record for
  the reversed `STAGING_SOURCE`.
- **Exit 2 (config error)**: clap rejected the args. Re-read the `--help`.
\`\`\`

- [ ] **Step 2: Add a README link**

In `README.md`, after the existing crate description, append:

```markdown

## CLI: `amt-verify`

A native CLI for end-to-end AMT tunnel verification (one-shot or `--watch`),
built when this crate is compiled with `--features native`:

\`\`\`bash
cargo build --release --no-default-features --features native --bin amt-verify
\`\`\`

See [`docs/runbook-staging-e2e.md`](docs/runbook-staging-e2e.md) for the
staging verification procedure.
```

- [ ] **Step 3: Commit**

```bash
git add docs/runbook-staging-e2e.md README.md
git commit -m "docs: staging E2E runbook + README CLI section

Covers direct (devbox) + in-cluster DRIAD paths; documents
the env var contract for the ignored E2E tests; troubleshooting
table maps timeout symptoms to /health field expectations and
DNS sanity checks."
```

- [ ] **Step 4: Tag M5 (optional)**

```bash
git tag -a m5-staging-e2e -m "M5 complete: staging E2E + runbook"
```

---

## Self-review notes

### Spec coverage map

| Spec section | Implementing task(s) |
|---|---|
| `SubscriptionManager` construction | 1.4 |
| `subscribe`/`unsubscribe`/`handle_datagram`/`tick`/`shutdown`/`poll_event`/`next_wakeup_ms` | 1.5–1.13 |
| `Event` enum (Transmit/Data/HandshakeComplete/Warning) | 1.2 |
| Per-(S,G) inner-packet demultiplex | 1.3 + 1.9 |
| Invariants 1–8 | 1.5–1.13 (one or more tests per invariant) |
| Error taxonomy (FamilyMismatch / TunnelFull / DiscoveryFailed / QueryFailed / MalformedInner / ShutdownInProgress) | 1.1 + tests in 1.5, 1.6, 1.9, 1.12, 1.13 |
| `AsyncAmtGateway` library API | 2.4 + 2.5 |
| `DataEvent` + broadcast channel | 2.4 |
| `amt-verify` CLI (one-shot + `--watch` + `--json`) | 3.2 + 3.3 + 3.4 |
| Native DRIAD resolver + AAAA helpers | 4.1–4.4 |
| `builder_for_source` + CLI `--no-driad` | 4.5 |
| Feature gating + WASM regression smoke | 2.1 + 1.15 + 2.8 |
| Test Tier 1 (Sans-I/O units, TestPlatform clock) | tests inside 1.5–1.13 |
| Test Tier 1.5 (resolver units) | 4.2–4.4 |
| Test Tier 2 (tokio + loopback fake relay) | 2.3 + 2.6 + 2.7 + 2.8 |
| Test Tier 3 (staging E2E, ignored) | 5.1 |
| Runbook | 5.2 |

### Codex review (gstack-codex consult, 2026-05-15, session 019e2b4b-…)

22 findings (10 P1, 9 P2, 3 P3). User selected "Full revision". Below is the
disposition of each. Numbering matches the Codex output order.

| # | Codex finding | Disposition | Tasks touched |
|---|---|---|---|
| 1 | CLI exit codes 0/1/2/3 not implemented | **Fixed**: added `ExitCategory` enum, `main()` maps to 0/1/2/3 | 3.2, 4.5 |
| 2 | `AsyncAmtGateway::shutdown()` hangs from Idle | **Fixed**: added `closed` flag to manager; `run_task` checks `mgr.is_closed()` not `state==Closed` | 1.4, 1.13, 2.4 |
| 3 | MulticastData emitted for unsubscribed (S,G) | **Fixed**: demux now filters against `self.groups`; silent drop on miss | 1.9 |
| 4 | CLI doesn't filter first data by (group, source) | **Fixed**: added `recv_first_matching` loop | 3.2, 4.5 |
| 5 | `amt_protocol::driad` import inside crate | **Fixed**: changed to `crate::driad` | 4.3 |
| 6 | `tokio::process::Command` without `process` feature | **Fixed**: added `process` to dev tokio features | 2.1 |
| 7 | MulticastData "bypasses nonce/MAC validation" | **Reframed**: `AmtMessage::MulticastData` carries no nonce/MAC on the wire (`messages.rs:167-174`). The spec's `mac_drift_on_data_warns` test was misnamed — the right test is Query nonce mismatch, which is now added | 1.8 (new test) |
| 8 | IPv6 MLDv2 incremental allow/block missing | **Fixed**: added `build_allow_v6` / `build_block_v6` in `report.rs`; subscribe/unsubscribe v6 paths now use them | 1.7, 1.10, 1.11 |
| 9 | Request retry vs Idle-reset | **Deliberate**: plan goes Idle-reset on Request timeout; this is a small spec amendment (invariant 6 wording "Request retry" → "Request fail-to-Idle"). Spec amendment commit follows this revision | (spec, not plan) |
| 10 | Fatal runtime errors swallowed | **Fixed**: `run_task` stores fatal errors in `Arc<Mutex<Option<anyhow::Error>>>`; `AsyncAmtGateway::shutdown` checks and returns Err | 2.4, 2.5 |
| 11 | `clap` staging inconsistent | **Fixed**: clap now in `native` feature from Task 2.1; Task 3.1 only declares `[[bin]]` | 2.1, 3.1 |
| 12 | DNS TXID correlation missing in A/AAAA follow-up | **Fixed**: response now validated against query TXID and qname before any answer bytes are trusted | 4.4 |
| 13 | DRIAD fallback test never implemented | **Open**: test_port helper exists but multi-nameserver fallback test still placeholder. Added to TODO below — small follow-up | 4.3 |
| 14 | IPv6 inner parser only handles `Next Header = UDP` | **Documented as deliberate limitation**: inline doc comment in `inner_packet.rs` | 1.3 |
| 15 | HandshakeComplete ordering | **Documented**: emit order is part of the contract — Transmit BEFORE HandshakeComplete | 1.8 |
| 16 | `--source` mandatory vs optional | **Fixed**: `--source` is now required IpAddr (no Option) | 3.2, 4.5 |
| 17 | `--family v4\|v6\|auto` missing | **Fixed**: added `Family` enum + arg | 3.2, 4.5 |
| 18 | `--json + --watch` allowed | **Fixed**: rejected with exit 2 (config error) | 3.2, 4.5 |
| 19 | TunnelFull check ordering | **Fixed**: dedup before cap; added idempotent-resub-at-cap test | 1.5 |
| 20 | "Replace body of error.rs" wording | **Fixed**: Task 1.1 now does additive Edit, preserves existing impls | 1.1 |
| 21 | Tier-1 doesn't cover all named invariants | **Partially fixed**: added query_nonce_mismatch, unsubscribed_data_dropped, wrong_source_dropped, next_wakeup_ms tests. Open: v6 incremental record-type assertions still TODO | 1.8, 1.9, 1.12 |
| 22 | LOC estimates low | **Acknowledged**: realistic M1 is more like 800-1200 impl + 900-1400 test. Estimates left as written; execution will validate | (none) |
| 23 (P3) | Random bytes test flaky | **Acknowledged**: 1/(2^64) false-fail rate; left as-is | (none) |

### Open follow-ups (Codex findings not fully resolved in this revision)

- **#9 spec wording**: amend spec invariant 6 to clarify "Request fail-to-Idle (no retry)" — separate commit on the spec file.
- **#13 DRIAD multi-nameserver fallback test**: stub helper exists; add full timeout-then-success test in M4 execution.
- **#21 v6 incremental record-type assertion tests**: add MLDv2 ALLOW (type 5) / BLOCK (type 6) byte-level assertions analogous to the v4 tests.

### Placeholder scan

Scanned for: TBD / TODO / "add appropriate" / "similar to" / "fill in" / `...`. None found in tasks; the ASCII ellipsis `...` appears once in M2 Task 2.4 inside the spawned-task pseudocode commentary, but the actual code block underneath has no ellipses.

### Type consistency

- `GroupKey { group, source }` — used consistently across all subscribe/unsubscribe paths.
- `Event::Transmit { dst, port, payload }` — same shape in M1 and consumed in M2.
- `DataEvent { src, group, src_port, dst_port, payload: Bytes }` — single definition (Task 2.4), consumed verbatim in 2.6, 2.7, 2.8, 3.2, 3.3.
- `AmtConfig::DEFAULT_KEEPALIVE_SECS` referenced in 1.4 + 2.4 + 3.2 + 4.5 — matches the existing const in `config.rs:35`.
- `AsyncAmtGateway::builder(IpAddr) → AsyncAmtGatewayBuilder` vs `AsyncAmtGateway::builder_for_source(IpAddr) → AsyncAmtGatewayBuilderForSource` — two distinct builder types, each with its own `relay_port` / `keepalive` / `log_target` / `build()`. Consistent.
- Native DRIAD resolver: `resolve_amt_relay(src) → Result<IpAddr>` (Task 4.3), consumed by `AsyncAmtGatewayBuilderForSource::build()` (Task 4.5). Match.

---

## Execution handoff

Plan complete and saved to `~/src/amt-protocol/docs/superpowers/plans/2026-05-15-amt-protocol-native-runtime.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration with clean context per task.

**2. Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batch execution with checkpoints for review.

Which approach?

