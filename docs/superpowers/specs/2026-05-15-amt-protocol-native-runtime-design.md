# amt-protocol: native async runtime, subscription manager, and verify CLI

**Date:** 2026-05-15
**Status:** Design approved, pending implementation plan
**Owner:** bot2@blockcast.net (Omar Ramadan)
**Tracks:** BLO-3457 follow-up

## Summary

Extend `~/src/amt-protocol` (today: sync, Sans-I/O, WASM-default state-machine library)
with three new layers, all backward-compatible with the existing WASM, FFI, JNI, and
UniFFI feature sets:

1. **`SubscriptionManager`** — a platform-agnostic, sync layer that owns N-(S,G)-over-
   one-tunnel bookkeeping (groups map, pending-while-handshaking queue, keep-alive
   scheduling, per-(S,G) inner-packet demultiplex). Default-compiled, no new deps.
2. **`AsyncAmtGateway`** — a tokio-based async runtime that drives `SubscriptionManager`
   over UDP for native consumers. Lives behind a new `native` Cargo feature.
3. **`amt-verify` CLI** — a `[[bin]]` packaged with the crate (required-features =
   `["native"]`), supporting one-shot E2E verify (Discovery → Request → Update → first
   `MulticastData`) and a long-running `--watch` mode.

A new WASM binding (`JsSubscriptionManager`) exposes the same subscription bookkeeping
to JavaScript, enabling pim-multicast-gateway's IWA package to delegate its TS
subscription manager to the shared Rust core.

`packages/dual-stack-relay` (which already declares amt-protocol as a path dep but
hand-rolls the AMT handshake in `src/upstream/amt_mmt_transport.rs`) migrates to
`AsyncAmtGateway`, dropping ~120 lines of duplicated protocol code.

## Motivation

BLO-3457 merged the eBPF tracker, multi-record IGMPv3/MLDv2 parsing, fail-loud ABI
guards, and observability surfaces (`mfc_absent_counters`, `bpf_parse_failures`) for
the Go-side amt-relay. The gateway side — the thing that *talks to* an AMT relay from
clients — is currently three separate implementations:

| Consumer | Path | Subscription bookkeeping | UDP I/O |
|---|---|---|---|
| IWA (browser) | `pim-multicast-gateway/packages/iwa/src/managers/amt-gateway.ts` | TS, hand-rolled `SharedAmtGateway` | WebTransport bridge in JS |
| Android SDK | `pim-multicast-gateway/packages/blockcast-sdk-android/.../AmtGateway.kt` | Kotlin, hand-rolled | Java UDP socket |
| dual-stack-relay (Rust) | `pim-multicast-gateway/packages/dual-stack-relay/src/upstream/amt_mmt_transport.rs` | None (single-(S,G), inlined handshake) | tokio UdpSocket |

All three reach into the shared `AmtGateway` state machine for protocol correctness but
re-implement everything above it. There is no native CLI today; the BLO-3457 deploy
verify on staging is done by reading `/health` from inside the cluster, which doesn't
exercise the gateway-side path that real consumers walk.

This work consolidates the duplicated bookkeeping into a Rust core, gives native
consumers a real async runtime, and ships a verify CLI that exercises the same code
path as production callers.

## Non-goals

- DRIAD DNS record provisioning (who runs the `Blockcast` DNS, who edits
  `*.in-addr.arpa`). Orthogonal; out of scope.
- `USE_EBPF=true` flip on staging-blockcastd or Playwright tp.orc8r billing
  verification. Those are the next two items in the BLO-3457 follow-up queue and
  proceed independently after this work.
- Multi-relay failover (selecting one of N relays returned in a DRIAD answer).
  Existing `DriadResolver` returns a single address; additive change later if needed.
- IWA's Vue UI changes. M7 (the migration) only rewires the subscription manager's
  backing implementation; the surface IWA's app code sees is preserved.
- The IPFIX/billing surface (Juniper enterprise-IE decoder gap at
  `cmd/amt-astats/ipfix_receiver.go:488`). Separate ticket.

## Architecture

```
amt-protocol crate
│
├── (existing) state machine ────────────────  AmtGateway<P>            sync, no I/O, one (S,G)
│                                                 messages, igmp, mld, driad, platform
│
├── (NEW) subscription layer ────────────────  SubscriptionManager<P>   sync, no I/O
│       crate-default, zero new deps               one tunnel per relay
│                                                  N (S,G) joins via IGMPv3/MLDv2 reports
│                                                  pending-while-handshaking queue
│                                                  keep-alive scheduler advice
│                                                  per-(S,G) data demultiplex
│
├── (NEW, feature = "native") async runtime    AsyncAmtGateway          tokio + UDP I/O
│       deps: tokio, anyhow, tracing,              drives SubscriptionManager
│             clap, bytes                          one instance = one family + one relay
│                                                  v4 + v6 use separate instances
│
├── (NEW, feature = "native") native resolver  resolve_amt_relay(src)   DRIAD over UDP:53
│                                                  reuses driad::build_dns_query
│                                                  follows DnsName → A/AAAA chain
│
├── (NEW, feature = "native") [[bin]]          amt-verify               one-shot + --watch
│       required-features = ["native"]
│
└── (existing, feature = "wasm")               JsAmtGateway + JsIgmpReport + JsMldReport
    (NEW)                                      JsSubscriptionManager    same Sans-I/O surface
                                                                        exposed to JS
```

### Layer responsibility split

| Layer | Owns | Does not own |
|---|---|---|
| `AmtGateway` | Single-(S,G) state machine, nonce + MAC handling, `AmtMessage` encode/decode | I/O, time, subscriptions, keep-alive |
| `SubscriptionManager` | Group set, pending queue, keep-alive schedule, IGMPv3/MLDv2 report assembly, inner-packet demux | I/O, timers, DNS, sockets |
| `AsyncAmtGateway` | UDP sockets, tokio timers, shutdown, broadcast channel for data fan-out | Protocol decisions, group selection |
| `amt-verify` | Arg parsing, exit code semantics, JSON output formatting | Anything above |

The split is exactly the Sans-I/O pattern (think `quinn-proto`, `rustls`): protocol
state owns no I/O; the I/O layer is a thin shim that translates between sockets/timers
and the protocol's input/output events.

## SubscriptionManager API

### Construction

```rust
pub struct SubscriptionManager<P: Platform> {
    inner: AmtGateway<P>,                  // existing state machine, unchanged
    groups: HashMap<GroupKey, GroupState>, // SSM joins, ASM joins
    pending: Vec<GroupKey>,                // queued while state < Querying
    last_update_at: Option<u64>,           // ms; for keep-alive scheduler
    last_known_groups: HashSet<GroupKey>,  // for diff-vs-current Allow/Block
    relay: IpAddr,
    relay_port: u16,
    cfg: AmtConfig,
}

impl<P: Platform> SubscriptionManager<P> {
    pub fn new(cfg: AmtConfig, platform: Arc<P>) -> Self;
}
```

One instance corresponds to one IP family + one relay. v4 and v6 use separate
instances; the manager rejects family mismatches at `subscribe()` time.

### Inputs

```rust
pub fn subscribe(&mut self, key: GroupKey, now_ms: u64) -> Result<()>;
pub fn unsubscribe(&mut self, key: &GroupKey, now_ms: u64) -> Result<()>;
pub fn handle_datagram(&mut self, bytes: &[u8], now_ms: u64) -> Result<()>;
pub fn tick(&mut self, now_ms: u64) -> Result<()>;
pub fn shutdown(&mut self, now_ms: u64) -> Result<()>;
```

### Outputs

```rust
pub enum Event {
    Transmit { dst: IpAddr, port: u16, payload: Vec<u8> },
    Data {
        src: IpAddr, group: IpAddr,
        src_port: u16, dst_port: u16,
        payload: Vec<u8>,
    },
    HandshakeComplete,
    Warning(AmtError),
}

pub fn poll_event(&mut self) -> Option<Event>;
pub fn next_wakeup_ms(&self) -> Option<u64>;
```

### Caller loop shape

```rust
loop {
    tokio::select! {
        Ok((n, _)) = sock.recv_from(&mut buf) => {
            mgr.handle_datagram(&buf[..n], now_ms())?;
        }
        _ = sleep_until(next_wakeup_instant(&mgr)) => {
            mgr.tick(now_ms())?;
        }
        Some(key) = sub_rx.recv() => {
            mgr.subscribe(key, now_ms())?;
        }
    }
    while let Some(ev) = mgr.poll_event() {
        match ev {
            Event::Transmit { dst, port, payload } =>
                sock.send_to(&payload, (dst, port)).await?,
            Event::Data { src, group, payload, .. } =>
                fanout.get(&(src, group)).map(|tx| tx.send(payload)),
            Event::HandshakeComplete => info!("AMT tunnel up"),
            Event::Warning(e) => warn!(?e),
        }
    }
}
```

### Per-(S,G) demultiplex and IWA fan-out

`Event::Data` is emitted **one per inner packet**, with the inner IP+UDP headers
already parsed and stripped. IWA's bridge can route each event to its own WebTransport
stream, giving parallel ordering across (S,G) groups — no head-of-line blocking when
one stream's consumer is slow.

Without this demultiplex in the core, every consumer (IWA, Android, dual-stack-relay)
must re-parse the inner headers. With it, they all share the parser, and IWA's TS
fan-out shrinks to a `Map<(src, group), WTStream>` lookup.

## SubscriptionManager invariants

1. **Pending queue drains exactly once** on `HandshakeComplete`. Groups added via
   `subscribe()` while state was `< Querying` are merged into the first post-handshake
   Update. Subsequent `subscribe()` calls in `Active` emit incremental IGMPv3
   `ALLOW_NEW_SOURCES` (or MLDv2 equivalent) records.

2. **One outstanding handshake at a time per manager.** Calling `subscribe()` while
   `state == Discovering` queues but does not restart Discovery. Re-Discovery is only
   triggered by `tick()` detecting a Discovery-Advertisement timeout
   (`DISCOVERY_TIMEOUT_MS`, default 5000 ms) and only up to `MAX_DISCOVERY_RETRIES`
   (default 3) before emitting `Event::Warning(DiscoveryFailed)` and parking in `Idle`.

3. **Nonce reuse**: `request_nonce` set on the first `Request` is reused for every
   subsequent `MembershipUpdate` and `Teardown` on this tunnel (RFC 7450 §5.2.3.4).
   `response_mac` is captured from the first `MembershipQuery` and reused identically.
   The manager re-Discovers + re-Requests only on explicit reset, `DiscoveryFailed`,
   or when `tick()` sees `QueryFailed` (no Query within `REQUEST_TIMEOUT_MS`,
   default 5000 ms).

4. **Family invariant**: `subscribe(group, source)` rejects with `Err(FamilyMismatch)`
   if `group.family() != relay.family()` or `source.family() != group.family()`. v4
   manager rejects v6 groups; v6 manager rejects v4 groups. No silent coercion.

5. **Group cap**: hard limit `MAX_GROUPS_PER_TUNNEL = 64` (mirrors the IWA TS limit).
   Past cap, `subscribe()` returns `Err(TunnelFull)`. Consumers handle escalation
   (spawn a second tunnel) above the manager.

6. **Keep-alive scheduling**: `next_wakeup_ms()` returns the minimum of armed timers
   among {`last_update_at + cfg.keepalive_interval_secs*1000`,
   `last_discovery_at + DISCOVERY_TIMEOUT_MS`,
   `last_request_at + REQUEST_TIMEOUT_MS`}. On `tick()`, exactly one of
   {keep-alive Update in Active, Discovery retry in Discovering (up to
   `MAX_DISCOVERY_RETRIES`), Request fail-to-Idle in Requesting} fires per call.
   Note: Request does **not** retry — on timeout the manager resets to Idle and
   emits `Event::Warning(QueryFailed)`; the caller decides whether to re-`subscribe()`
   to restart the handshake. This is intentional: Request retransmits without a
   fresh Discovery would reuse a possibly-stale relay binding.

7. **Inner data demux is best-effort, never fatal**: a malformed inner IP/UDP packet
   inside `AmtMessage::MulticastData` produces `Event::Warning(MalformedInner)` and
   the manager continues. No `Event::Data` is emitted for that datagram.

8. **Determinism for tests**: every state transition is driven by `(input event,
   now_ms)`. The only nondeterminism is `generate_nonce()`, which already routes
   through `Platform::random_bytes` — `TestPlatform` already exists for this.

## Error taxonomy

| Class | Examples | Surface |
|---|---|---|
| API misuse | `subscribe()` on a shutdown manager, `FamilyMismatch`, `TunnelFull` | `Err(AmtError::…)` returned from the API call |
| Recoverable protocol | malformed datagram, unexpected message in current state, single bad `MulticastData` | `Event::Warning(_)`, state unchanged |
| Handshake failure | `DiscoveryFailed` after retries, `QueryFailed`, nonce mismatch on Advertisement | `Event::Warning(_)` + auto-transition to `Idle`; caller decides whether to re-`subscribe()` |
| Fatal runtime (native only) | socket bind failure, send_to permanent error, task panic | `AsyncAmtGateway::shutdown` future resolves with `Err`; broadcast channel closes |

CLI exit code mapping:

- API misuse → exit 2 (config error)
- Handshake failure → exit 1 (verify fail)
- Fatal runtime → exit 3 (infrastructure)
- One-shot success → exit 0
- `--watch` mode SIGINT → exit 0 after clean Teardown

## AsyncAmtGateway

### Library API

```rust
// amt-protocol/src/native/gateway.rs (feature = "native")

pub struct AsyncAmtGateway {
    cmd_tx:  mpsc::Sender<Cmd>,
    data_rx: broadcast::Receiver<DataEvent>,
    task:    JoinHandle<()>,
    state:   Arc<AtomicU8>,
}

pub struct AsyncAmtGatewayBuilder {
    relay: Option<IpAddr>,       // None → DRIAD-resolve via source
    source: Option<IpAddr>,
    port: u16,                   // default 2268
    keepalive: Duration,
    discovery_timeout: Duration,
    request_timeout: Duration,
    log_target: &'static str,
}

impl AsyncAmtGateway {
    pub fn builder(relay: IpAddr) -> AsyncAmtGatewayBuilder;
    pub fn builder_for_source(source: IpAddr) -> AsyncAmtGatewayBuilder;  // uses DRIAD

    pub async fn subscribe(&self, group: IpAddr, source: Option<IpAddr>) -> Result<()>;
    pub async fn unsubscribe(&self, group: IpAddr, source: Option<IpAddr>) -> Result<()>;
    pub fn subscribe_data(&self) -> broadcast::Receiver<DataEvent>;
    pub async fn shutdown(self) -> Result<()>;
    pub fn state(&self) -> GatewayState;
}

pub struct DataEvent {
    pub src: IpAddr, pub group: IpAddr,
    pub src_port: u16, pub dst_port: u16,
    pub payload: Bytes,
}
```

### Task structure

One tokio task per gateway. Owns one `UdpSocket` (bound `0.0.0.0:0` for v4 or
`[::]:0` for v6, family inferred from relay address). Owns the `SubscriptionManager`.
Drives select! over: shutdown signal, command queue, socket recv, timer.

```rust
spawn(async move {
    let sock = UdpSocket::bind(bind_addr_for(relay_family)).await?;
    let mut mgr = SubscriptionManager::new(cfg, NativePlatform::new());
    let mut buf = [0u8; 65535];
    let mut next_wake = Instant::now() + Duration::from_secs(60);

    loop {
        select! {
            biased;
            _ = &mut shutdown_rx => {
                mgr.shutdown(now_ms())?;
                drain_transmits(&mut mgr, &sock).await;
                break;
            }
            Some(cmd) = cmd_rx.recv() => apply(&mut mgr, cmd, now_ms())?,
            Ok((n, _)) = sock.recv_from(&mut buf) => {
                mgr.handle_datagram(&buf[..n], now_ms())?;
            }
            _ = tokio::time::sleep_until(next_wake) => {
                mgr.tick(now_ms())?;
            }
        }

        while let Some(ev) = mgr.poll_event() {
            match ev {
                Event::Transmit { dst, port, payload } =>
                    sock.send_to(&payload, (dst, port)).await?,
                Event::Data { .. } => { let _ = data_tx.send(ev.into()); }
                Event::HandshakeComplete => state.store(Active as u8, Ordering::SeqCst),
                Event::Warning(e) => warn!(target: log_target, ?e),
            }
        }
        next_wake = mgr.next_wakeup_ms()
            .map(instant_from_ms)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(60));
    }
});
```

### Channel choices

- **Commands**: `tokio::sync::mpsc<Cmd>`. Single producer per call site, single
  consumer (the task). Bounded at 32 — backpressure on a misbehaving caller.
- **Data**: `tokio::sync::broadcast<DataEvent>`. Multi-consumer: verify CLI, MMT
  decoder, packet capture sink, IWA bridge can all read. Slow consumers see
  `RecvError::Lagged` and resume from latest. Bounded at 1024 events.
- **Shutdown**: `tokio::sync::oneshot`. Single fire.

The Sans-I/O manager already emits pre-demuxed `Event::Data`, so per-(S,G) routing
is constant-time on the consumer side: `match (ev.src, ev.group) { … }`.

## amt-verify CLI

### Arguments

```
amt-verify --group <addr> --source <addr>
           [--relay <addr>] [--port 2268]
           [--family v4|v6|auto]
           [--timeout 30s] [--keepalive 60s]
           [--no-driad]
           [--watch]
           [--json]
           [-v / --verbose]
```

`--source` and `--group` are mandatory. `--relay` is optional; if omitted, the CLI
DRIAD-resolves it from `--source`. `--no-driad` forces `--relay` to be explicit
(defense against silent DNS misconfig in CI).

### One-shot mode (default)

1. Build `AsyncAmtGateway` for the relay (resolved or explicit).
2. `gateway.subscribe(group, source)`.
3. Subscribe to data; await first `DataEvent` matching `(group, source)` with
   `--timeout` cap.
4. Print summary (timings per state transition, first-packet size, first-packet
   source); exit 0.
5. Timeout / handshake error → exit 1 with reason.

### Watch mode (`--watch`)

1. Same handshake.
2. After first packet, stay running.
3. Periodic stats line every 5 s: `pkts=N bytes=M last_seen=Xms_ago state=Active`.
4. SIGINT → `gateway.shutdown()` → graceful Teardown → exit 0.

### JSON output (`--json`, one-shot only)

```json
{
  "outcome": "ok",
  "relay": "192.0.2.96",
  "family": "v4",
  "group": "232.0.0.1",
  "source": "69.25.95.10",
  "timings_ms": {"discovery": 12, "request": 8, "first_data": 240},
  "first_packet": {"src": "69.25.95.10:5004", "dst_port": 5004, "len": 1316}
}
```

## Native DRIAD resolver

```rust
// amt-protocol/src/native/resolver.rs (feature = "native")
pub async fn resolve_amt_relay(source: IpAddr) -> Result<IpAddr>;
```

- Reads `/etc/resolv.conf`, picks nameservers in order.
- Reuses existing `DriadResolver::build_dns_query` (RFC 1035 wire format, already
  in the crate).
- Sends over UDP to each nameserver in turn:53; 2-second per-server timeout;
  total budget of 3 attempts across the nameserver list.
- Feeds reply to existing `DriadResolver::parse_dns_response` (TYPE260 AMTRELAY).
- If the AMTRELAY answer is a `DnsName`, follow up with **both** A and AAAA
  queries in parallel and use the first answer that arrives (the relay's
  family is orthogonal to the source's family in DRIAD; in practice our
  deployment family-matches, but the resolver does not assume that). A small
  `build_dns_aaaa_query` helper is added to `driad.rs` next to the existing
  `build_dns_a_query`.
- Returns the resolved relay `IpAddr`.

The resolver is the only new public surface in `src/native/` outside `AsyncAmtGateway`
itself. It is intentionally minimal — no caching, no fancy load balancing — because
the AMT tunnel that follows is long-lived; one DNS lookup per tunnel start is fine.

## Feature gating

```toml
[features]
default  = ["wasm"]
wasm     = ["dep:wasm-bindgen", ...]
ffi      = []
jni      = ["ffi", "dep:jni"]
uniffi   = ["ffi", "dep:uniffi"]
# NEW
native   = [
    "dep:tokio", "dep:clap", "dep:tracing", "dep:tracing-subscriber",
    "dep:bytes", "dep:anyhow",
]

[[bin]]
name = "amt-verify"
path = "src/bin/amt-verify.rs"
required-features = ["native"]
```

`crate-type = ["cdylib", "staticlib", "rlib"]` is unchanged. The `native` feature
adds tokio, clap, tracing, etc. as **optional** deps. WASM build
(`cargo build --target wasm32-unknown-unknown` with default features) does not see
them. CI must add an explicit WASM-build smoke step on every PR in M1–M5 to catch
feature graph regressions early.

## Consumer migrations

### dual-stack-relay (M6)

`packages/dual-stack-relay/Cargo.toml`:
```toml
amt-protocol = {
    path = "../../../amt-protocol",
    default-features = false,
    features = ["native"]
}
```

`packages/dual-stack-relay/src/upstream/amt_mmt_transport.rs` — replace the
hand-rolled handshake with:

```rust
let gw = AsyncAmtGateway::builder(relay_ip)
    .keepalive(Duration::from_secs(60))
    .build()
    .await?;
gw.subscribe(group_ip, Some(source_ip)).await?;
let mut data_rx = gw.subscribe_data();
// existing MMT pipeline reads from data_rx instead of inner_rx
```

Net delta is ~−80 LOC. The MMT pipeline upstream of the AMT layer is untouched.

### IWA (M7)

New `JsSubscriptionManager` WASM binding exposes the same Sans-I/O API to
JavaScript. IWA's `packages/iwa/src/managers/amt-gateway.ts` rewrites its
`SharedAmtGateway` internals to delegate to `JsSubscriptionManager`:

- Pending queue, groups map, keep-alive timer → all owned by the WASM manager
- The TS layer keeps: the WebTransport-side fan-out map, the per-relay socket
  bridge, and the public API the Vue UI consumes.

The migration drops ~300 lines of TS bookkeeping. The existing `JsAmtGateway`
binding is kept intact; old IWA paths can fall back to it if needed during the
migration. `JsAmtGateway` is only removed after Vue UI is green with the new
binding.

## Test plan

### Tier 1 — `SubscriptionManager` unit tests (sync, `TestPlatform`)

No tokio, no I/O. ~95% of the bug surface lives here.

- `subscribe_before_discovery_queues` — sub then `tick`, assert pending grows, no
  `Transmit`.
- `pending_flush_on_handshake_complete` — full state walk; assert single Update
  carries all queued joins.
- `subscribe_in_active_emits_incremental_allow` — add a 2nd (S,G) post-handshake,
  assert single-record Update.
- `unsubscribe_in_active_emits_block` — `BLOCK_OLD_SOURCES` for SSM,
  `CHANGE_TO_INCLUDE` mode 0 for ASM.
- `family_mismatch_rejected` — v4 manager + v6 group/source.
- `tunnel_full_rejected` — sub 64 then 65th errors `TunnelFull`.
- `discovery_retry_then_give_up` — TestPlatform clock advance, assert 3
  RelayDiscovery transmits then Warning.
- `keepalive_fires_at_interval` — clock advance past interval, assert Update
  emitted with current group set, no group changes.
- `malformed_inner_packet_warns_not_panics` — feed truncated IP header, expect
  Warning + manager still Active.
- `mac_drift_on_data_warns` — Data with wrong nonce / unexpected; manager
  unchanged.
- `nonce_reuse_across_keepalives` — three keep-alives, same nonce + same MAC
  each time.

### Tier 1.5 — resolver unit tests (no real DNS)

- `parse_resolv_conf_picks_first_nameserver` — synthetic file contents.
- `resolver_fallback_on_timeout` — two synthetic nameservers, first drops, second
  answers.
- `amtrelay_dnsname_triggers_aaaa_lookup` — fake nameserver returns DnsName for
  v6 source, expects AAAA follow-up.

### Tier 2 — `AsyncAmtGateway` integration (tokio + loopback)

A `tests/fake_relay.rs` helper that owns a `UdpSocket`, responds with canned
Advertisement / Query / synthetic `MulticastData`. Verifies the runtime wires.

- `oneshot_happy_path_v4` — full handshake against fake relay, first DataEvent.
- `oneshot_happy_path_v6` — same, `[::1]` bound fake relay.
- `subscribe_data_multi_consumer` — two `subscribe_data()` receivers both get
  the same packet.
- `shutdown_emits_teardown` — fake relay records final datagram type =
  Teardown.
- `sigint_in_watch_clean_exit` — spawn the binary, SIGTERM, assert exit 0 +
  Teardown observed.

### Tier 3 — E2E against staging (manual, gated `#[ignore]`)

- `e2e_oneshot_explicit_relay` — `--relay <staging>` `--source <real>`
  `--group <real>`; CLI exit 0 within `--timeout 30s` and first DataEvent has a
  sensible source IP.
- `e2e_driad_then_join` — `--source <real>`, no `--relay`; verifies the full
  prod-shaped flow (DRIAD → handshake → data) which is what BLO-3293/3455
  actually exercises. Must be run from in-cluster pod where `:53/UDP` reaches
  kube-dns.

### Tier 4 — WASM smoke (IWA-facing)

`wasm-pack test --node` for `JsSubscriptionManager`:

- Construct, feed a canned `RelayAdvertisement` bytes via `handle_datagram`,
  drain events, assert one `Transmit` (the Request) came out.
- `wasm-pack build` still produces the same exported JS shape IWA depends on
  (`JsAmtGateway`, `JsIgmpReport`, `JsMldReport`) — additive only.

## Build order

| Milestone | Scope | LOC est. | Gates |
|---|---|---|---|
| **M1** — `SubscriptionManager` core | New sync layer + Sans-I/O API + Tier-1 unit tests. No tokio, no feature gate. Default-compiles. | ~500 LOC + ~600 LOC tests | Tier-1 green; existing `AmtGateway` tests untouched; `wasm-pack build` produces same JS exports |
| **M2** — `native` feature + `AsyncAmtGateway` | New `native` Cargo feature, tokio-based runtime, fake-relay integration tests (Tier 2). No DRIAD yet. No CLI yet. | ~400 LOC + ~400 LOC tests | Tier-2 green; default WASM build unchanged; `cargo build --features native --no-default-features` green |
| **M3** — `amt-verify` CLI | `[[bin]]`, clap args, one-shot + `--watch` modes, JSON output. | ~300 LOC | Hand-test against fake relay; bin only built with `--features native` |
| **M4** — DRIAD native resolver | `src/native/resolver.rs`, builder wires it in, CLI `--source`-only path works. | ~150 LOC + ~150 LOC tests | Tier-1.5 green; CLI verify against staging without `--relay` |
| **M5** — staging E2E + Tier-3 | One `#[ignore]` E2E test pinned to staging-blockcastd amt-relay. Doc runbook. | ~100 LOC | Manual run: exit 0 + first DataEvent observed |
| **M6** — dual-stack-relay migration | Flip `amt_mmt_transport.rs` to `AsyncAmtGateway`; delete ~120 LOC hand-rolled handshake. | net delta ~−80 LOC | pim-multicast-gateway CI green; existing relay smoke tests pass |
| **M7** — `JsSubscriptionManager` WASM binding + IWA migration | New WASM-exposed binding; rewrite IWA `amt-gateway.ts` subscription bookkeeping to delegate to it. WASM smoke tests (Tier 4). | bindings ~200 LOC; IWA delta ~−300 LOC | IWA unit tests pass; manual IWA tunnel-up smoke; bundle size delta noted |

M1–M5 land against `Blockcast/amt-protocol`. M6 against
`Blockcast/pim-multicast-gateway`. M7 spans both repos. Dependency order is
strict: M2 depends on M1, M4 depends on M2, M6/M7 depend on M4.

## Risks and mitigations

1. **WASM build regression**. Adding tokio as optional under `native` should not
   affect WASM, but `wasm-pack` is sensitive to feature-graph wiring. Mitigation:
   add an explicit `cargo build --target wasm32-unknown-unknown --no-default-features
   --features wasm` smoke step on every PR in M1–M5.
2. **iproute2 v6 truncation regression**. Already known
   (`feedback_iproute2_v6_amt_local_truncates_to_v4.md`) as a kernel-side trap
   when registering AMT interfaces. Not in our path — we operate at the AMT
   *gateway* level (UDP control + data), not via `ip link add type amt`.
   Captured here so we don't get distracted during E2E.
3. **DRIAD over plain UDP DNS in restrictive networks**. The staging environment
   may block outbound `:53/UDP` from devbox. Mitigation: M4 documents the
   failure mode and the CLI's `--relay` override; the canonical E2E path is
   from an in-cluster pod where `:53` reaches kube-dns.
4. **Broadcast channel lag for slow consumers**. `tokio::sync::broadcast` drops
   oldest on lag. Verify CLI / IWA bridge are fine. dual-stack-relay's MMT
   decoder needs to keep up; if it doesn't, packets drop silently and FEC
   repairs invisibly. Mitigation: M2 documents the choice; M6 instruments
   channel `len()` and `RecvError::Lagged` frequency in tracing.
5. **WASM `JsSubscriptionManager` ABI break for IWA**. M7 is the only risky
   migration. Mitigation: keep the existing `JsAmtGateway` binding intact and
   add `JsSubscriptionManager` alongside; IWA TS migrates in a single PR with
   both paths still available; old binding is removed only after Vue UI is
   green.
6. **Cargo binary publish surface**. We're a private monorepo with no
   crates.io publish, but `Blockcast/amt-protocol` is now also a binary
   distributor. Whether to build/publish `amt-verify` as a release artifact
   is decided later; not part of this scope.

## Open questions (deferred)

- Multi-relay failover (when DRIAD returns multiple TYPE260 records). Today
  `DriadResolver::parse_dns_response` returns one. Additive change if/when
  required.
- Whether `AsyncAmtGateway` should ever auto-rotate to a new tunnel on
  handshake failure or pin to one relay until the caller asks for a new one.
  Current design: pin. Caller restarts.
- IWA migration cutover: do we ship M7 behind a TS feature flag for staged
  rollout, or hard-cut? Decide during M7.
