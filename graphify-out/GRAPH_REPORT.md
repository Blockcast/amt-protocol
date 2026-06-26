# Graph Report - amt-protocol  (2026-06-26)

## Corpus Check
- 34 files · ~51,018 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 619 nodes · 1595 edges · 22 communities
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 8 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `ce1b686e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]

## God Nodes (most connected - your core abstractions)
1. `mgr()` - 32 edges
2. `AsyncAmtGateway` - 25 edges
3. `drain()` - 25 edges
4. `AmtConfig` - 22 edges
5. `GroupKey` - 22 edges
6. `SubscriptionManager<P>` - 21 edges
7. `TestPlatform` - 20 edges
8. `drive_to_active()` - 19 edges
9. `JsAmtGateway` - 18 edges
10. `AmtGateway<P>` - 17 edges

## Surprising Connections (you probably didn't know these)
- `watch_mode_emits_periodic_stats()` --calls--> `synth_v4_udp()`  [INFERRED]
  tests/watch_smoke.rs → tests/common/fake_relay.rs
- `count()` --references--> `MessageType`  [EXTRACTED]
  tests/cli_json.rs → src/messages.rs
- `json_output_is_parseable()` --calls--> `synth_v4_udp()`  [INFERRED]
  tests/cli_json.rs → tests/common/fake_relay.rs
- `oneshot_happy_path_v4()` --calls--> `synth_v4_udp()`  [INFERRED]
  tests/native_runtime.rs → tests/common/fake_relay.rs
- `subscribe_data_multi_consumer()` --calls--> `synth_v4_udp()`  [INFERRED]
  tests/native_runtime.rs → tests/common/fake_relay.rs

## Import Cycles
- 1-file cycle: `src/platform.rs -> src/platform.rs`

## Communities (22 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.07
Nodes (27): Formatter, I, JsValue, Result, GroupKey, decode_amt_message(), JsAmtGateway, JsDriad (+19 more)

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (51): AtomicU8, Args, ExitCategory, Family, finish_gateway(), FirstPacket, main(), OneshotReport (+43 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (17): AtomicU64, Default, LogCallback, native_platform_now_millis_is_recent(), native_platform_random_bytes_changes_each_call(), NativePlatform, Self, Send (+9 more)

### Community 3 - "Community 3"
Cohesion: 0.12
Nodes (24): Arc, HashMap, P, AmtConfig, test_driad_only(), test_driad_with_fallback(), test_manual_config(), AmtGateway (+16 more)

### Community 4 - "Community 4"
Cohesion: 0.09
Nodes (22): Option, build_dns_aaaa_query_packet_structure(), DriadRelayAddress, DriadResolver, parse_dns_aaaa_response_extracts_ipv6(), test_build_dns_a_query(), test_build_dns_query_packet_structure(), test_build_query_v4_source() (+14 more)

### Community 5 - "Community 5"
Cohesion: 0.17
Nodes (36): Event, advertisement_advances_to_requesting(), advertisement_with_wrong_nonce_warns_no_transition(), discovery_nonce_from(), drain(), drive_to_active(), malformed_inner_warns_not_panics(), manager_starts_idle_empty() (+28 more)

### Community 6 - "Community 6"
Cohesion: 0.09
Nodes (28): CapturedTraffic, FakeRelay, synth_v4_udp(), synth_v6_udp(), Mutex, SocketAddr, MessageType, test_invalid_message_type() (+20 more)

### Community 7 - "Community 7"
Cohesion: 0.13
Nodes (28): AmtGatewayHandle, c_char, Display, From, AmtError, amt_buffer_free(), amt_driad_build_query(), amt_gateway_free() (+20 more)

### Community 8 - "Community 8"
Cohesion: 0.05
Nodes (37): amt-protocol: native async runtime, subscription manager, and verify CLI, amt-verify CLI, Architecture, Arguments, AsyncAmtGateway, Build order, Caller loop shape, Channel choices (+29 more)

### Community 9 - "Community 9"
Cohesion: 0.26
Nodes (27): GatewayHandle, jboolean, jbyteArray, JClass, jint, jlong, JNIEnv, JObjectArray (+19 more)

### Community 10 - "Community 10"
Cohesion: 0.22
Nodes (11): Ipv6Addr, MldRecord, MldV2Report, RecordType, test_asm_record(), test_checksum_calculation(), test_checksum_odd_length(), test_multiple_records() (+3 more)

### Community 11 - "Community 11"
Cohesion: 0.27
Nodes (11): Ipv4Addr, IgmpRecord, IgmpV3Report, RecordType, test_asm_record(), test_checksum_calculation(), test_encode_with_ip_encapsulation(), test_encode_with_ip_size() (+3 more)

### Community 12 - "Community 12"
Cohesion: 0.10
Nodes (18): Billing shutdown matrix, Build the bin, Direct path — from devbox, DRIAD path — from in-cluster pod, Prerequisites, Running the ignored E2E tests, Staging E2E runbook — amt-verify against staging-blockcastd, Troubleshooting (+10 more)

### Community 13 - "Community 13"
Cohesion: 0.12
Nodes (16): Milestone M1 — `SubscriptionManager` core (Sans-I/O, default-compiled), Task 1.10: `subscribe()` Active path — incremental ALLOW, Task 1.11: `unsubscribe()` — incremental BLOCK, Task 1.12: `tick()` — keep-alive + Discovery retry, Task 1.13: `shutdown()` — emit Teardown, Task 1.14: Re-exports + crate-level smoke, Task 1.15: WASM regression smoke (M1 gate), Task 1.1: Extend `AmtError` with new variants (+8 more)

### Community 14 - "Community 14"
Cohesion: 0.30
Nodes (11): InnerPacket, ipv4_udp_packet(), parse_inner(), parse_ipv4(), parse_ipv4_udp_happy_path(), parse_ipv4_udp_zero_payload(), parse_ipv4_with_options_ihl_6(), parse_ipv6() (+3 more)

### Community 15 - "Community 15"
Cohesion: 0.18
Nodes (10): amt-protocol native runtime — Implementation Plan (M1–M5), CLI: `amt-verify`, Milestone M3 — `amt-verify` CLI, Milestone M5 — Staging E2E + runbook, Task 3.1: Add `[[bin]]` declaration for `amt-verify`, Task 3.2: `amt-verify` one-shot mode (without DRIAD), Task 3.3: `--watch` mode + SIGINT graceful shutdown, Task 3.4: JSON output verified by parsing (+2 more)

### Community 16 - "Community 16"
Cohesion: 0.18
Nodes (11): Created during M1 (Sans-I/O subscription core, default-compiled), Created during M2 (native feature, tokio runtime), Created during M3 (CLI), Created during M4 (DRIAD resolver), Created during M5 (E2E + runbook), File structure, Modified during M1, Modified during M2 (+3 more)

### Community 17 - "Community 17"
Cohesion: 0.22
Nodes (9): Milestone M2 — `native` feature + `AsyncAmtGateway`, Task 2.1: Add `native` Cargo feature + optional deps, Task 2.2: `NativePlatform` — `Platform` impl for native targets, Task 2.3: `fake_relay` test helper, Task 2.4: `AsyncAmtGateway` — struct, builder, task loop, Task 2.5: Public `subscribe`/`unsubscribe`/`shutdown` methods, Task 2.6: Tier-2 test — oneshot happy path v4, Task 2.7: Tier-2 — v6 + multi-consumer + family-mismatch (+1 more)

### Community 18 - "Community 18"
Cohesion: 0.33
Nodes (6): Milestone M4 — Native DRIAD resolver, Task 4.1: Add AAAA helpers to `driad.rs`, Task 4.2: `/etc/resolv.conf` parser, Task 4.3: `resolve_amt_relay()` — AMTRELAY query, IP-answer fast path, Task 4.4: DnsName follow-up — parallel A + AAAA, Task 4.5: Wire `builder_for_source` + CLI `--no-driad`

## Knowledge Gaps
- **90 isolated node(s):** `FFI (for CGO/C/C++)`, `Install to system`, `WASM (for web browsers)`, `Android JNI`, `Usage with Go (CGO)` (+85 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AmtConfig` connect `Community 3` to `Community 1`, `Community 2`, `Community 5`, `Community 7`, `Community 9`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **Why does `AmtGateway` connect `Community 3` to `Community 0`, `Community 1`, `Community 4`, `Community 5`, `Community 7`, `Community 9`?**
  _High betweenness centrality (0.031) - this node is a cross-community bridge._
- **Why does `TestPlatform` connect `Community 2` to `Community 3`, `Community 5`?**
  _High betweenness centrality (0.028) - this node is a cross-community bridge._
- **What connects `FFI (for CGO/C/C++)`, `Install to system`, `WASM (for web browsers)` to the rest of the system?**
  _90 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.06664388243335612 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.06306306306306306 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.05701754385964912 - nodes in this community are weakly interconnected._