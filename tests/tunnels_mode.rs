#![cfg(feature = "native")]

//! `--tunnels N` state-occupancy mode (BLO-33457).
//!
//! The failure this suite exists to catch is a FALSE CLEAN STEP: a ramp that
//! reports N tunnels held when fewer than N are actually alive. Every assertion
//! below is about the honesty of the count, not about data delivery — the mode
//! is deliberately run against idle groups where no data exists.

mod common;

use common::fake_relay::{synth_v4_udp, FakeRelay};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

async fn run_amt_verify(args: &[&str]) -> (std::process::ExitStatus, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_amt-verify"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn amt-verify");
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = String::new();
    stdout.read_to_string(&mut buf).await.unwrap();
    let status = child.wait().await.unwrap();
    (status, buf)
}

/// Three concurrent gateways on one relay socket, each held past a keep-alive
/// interval. Asserts the count is real: `alive == requested`, and
/// `keepalives_min >= 1` so no tunnel was counted alive without demonstrably
/// surviving an interval.
#[tokio::test(flavor = "multi_thread")]
async fn tunnels_mode_reports_per_tunnel_survival() {
    let relay = FakeRelay::bind("v4").await;
    relay.spawn(synth_v4_udp(
        [10, 0, 0, 1],
        [232, 0, 0, 1],
        5004,
        5005,
        b"x",
    ));

    let port = relay.addr.port().to_string();
    let (status, out) = run_amt_verify(&[
        "--relay",
        &relay.addr.ip().to_string(),
        "--port",
        &port,
        "--group",
        "232.0.0.1",
        "--source",
        "10.0.0.1",
        "--tunnels",
        "3",
        "--keepalive",
        "1",
        "--hold",
        "3",
        "--stagger-ms",
        "1",
        "--timeout",
        "10",
        "--json",
    ])
    .await;

    assert!(status.success(), "exit code: {status}, stdout: {out}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect(&out);

    assert_eq!(v["outcome"], "ok", "{out}");
    assert_eq!(v["mode"], "tunnels");
    assert_eq!(v["requested"], 3);
    assert_eq!(v["established"], 3);
    assert_eq!(v["alive"], 3);
    // The survival witness. Held 3s across a 1s keep-alive interval, so every
    // tunnel must have emitted at least one Membership Update. A zero here
    // with alive==3 would mean the mode counts established-but-unmaintained
    // tunnels as live state.
    assert!(
        v["keepalives_min"].as_u64().unwrap() >= 1,
        "keepalives_min must be >= 1: {out}"
    );
    assert!(v["establish_ms"]["max"].is_u64(), "{out}");
    assert!(
        v["establish_errors"].as_object().unwrap().is_empty(),
        "{out}"
    );
    assert!(v["not_alive"].as_object().unwrap().is_empty(), "{out}");

    // BLO-33457 acceptance criterion: the control-plane-vs-loaded-state caveat
    // travels WITH the numbers, so a raw per-step artifact cannot be read as a
    // loaded ceiling. It must ALSO name the witness as receiver-side: the
    // relay's amt_relay_active_tunnels is dead on both production relays, so a
    // reader sent there for corroboration reads 0 and calls it a relay defect.
    let caveat = v["caveat"].as_str().expect("caveat field");
    assert!(caveat.contains("CONTROL-PLANE"), "{caveat}");
    assert!(caveat.contains("RECEIVER-SIDE"), "{caveat}");
    assert!(caveat.contains("ATTRIBUTION"), "{caveat}");
    assert!(caveat.contains("DISQUALIFIER"), "{caveat}");

    // The disqualifier must be a FIELD, not only prose in the caveat: the
    // workflow verdict gates on it, and a reader who trusts `alive` is exactly
    // the reader who will not finish the caveat. All 3 gateways bound the host
    // default source, so on a relay keying tunnels by outer address alone they
    // are ONE tunnel entry -- while `alive` says 3, because `alive` is a
    // send-side self-report and every aliased gateway still sends.
    //
    // This asserting `1` rather than `<= requested` is deliberate: if someone
    // gives the gateways distinct sources, this test must FAIL and make them
    // set the field honestly, not pass silently and leave the verdict gate
    // clamped shut on a rig that has outgrown it.
    assert_eq!(v["distinct_outer_sources"], 1, "{out}");
    assert_eq!(v["alive"], 3, "{out}");
}

/// A relay that never answers. The knee case: the report must say `degraded`
/// with a non-zero exit so a `set -e` ramp driver stops, and must still emit
/// parseable JSON carrying the failure reason.
#[tokio::test(flavor = "multi_thread")]
async fn tunnels_mode_reports_degraded_when_relay_is_silent() {
    // Bound but never spawned: the socket exists (so nothing is ICMP-rejected)
    // and answers nothing.
    let relay = FakeRelay::bind("v4").await;

    let port = relay.addr.port().to_string();
    let (status, out) = run_amt_verify(&[
        "--relay",
        &relay.addr.ip().to_string(),
        "--port",
        &port,
        "--group",
        "232.0.0.1",
        "--source",
        "10.0.0.1",
        "--tunnels",
        "2",
        "--keepalive",
        "1",
        "--hold",
        "2",
        "--timeout",
        "2",
        "--json",
    ])
    .await;

    assert_eq!(status.code(), Some(1), "stdout: {out}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect(&out);
    assert_eq!(v["outcome"], "degraded", "{out}");
    assert_eq!(v["established"], 0, "{out}");
    assert_eq!(v["alive"], 0, "{out}");
    assert!(
        !v["establish_errors"].as_object().unwrap().is_empty(),
        "a silent relay must be attributed, not reported as a quiet clean run: {out}"
    );
}

/// `--hold` at or below `--keepalive` makes the survival check unsatisfiable —
/// no tunnel can emit a keep-alive, so every tunnel would fail for a reason
/// that is the operator's arithmetic rather than the relay's behaviour. Reject
/// it up front (exit 2) instead of reporting a ramp-wide false knee.
#[tokio::test(flavor = "multi_thread")]
async fn tunnels_mode_rejects_hold_shorter_than_keepalive() {
    let (status, _out) = run_amt_verify(&[
        "--relay",
        "127.0.0.1",
        "--no-driad",
        "--group",
        "232.0.0.1",
        "--source",
        "10.0.0.1",
        "--tunnels",
        "1",
        "--keepalive",
        "60",
        "--hold",
        "10",
    ])
    .await;
    assert_eq!(status.code(), Some(2));
}

/// `--tunnels` is a state-occupancy mode; `--watch` is a data-observation mode.
#[tokio::test(flavor = "multi_thread")]
async fn tunnels_mode_rejects_watch() {
    let (status, _out) = run_amt_verify(&[
        "--relay",
        "127.0.0.1",
        "--no-driad",
        "--group",
        "232.0.0.1",
        "--source",
        "10.0.0.1",
        "--tunnels",
        "2",
        "--watch",
    ])
    .await;
    assert_eq!(status.code(), Some(2));
}

/// INSTRUMENT VALIDATION, not a relay measurement. Run before any ramp:
/// `cargo test --no-default-features --features native --test tunnels_mode -- --ignored`
///
/// A ramp cannot distinguish "the relay ran out of state" from "the client ran
/// out of sockets/memory/scheduler" unless the client's own ceiling is known to
/// be higher. This establishes 512 concurrent tunnels against a loopback relay,
/// which is well past where a naive implementation falls over. `#[ignore]`d
/// because it is a host-capacity check, not a protocol guard, and its cost does
/// not belong on every PR.
///
/// Measured 2026-09-12 against a black-hole port (socket+task capacity only):
/// N=10000 reached `Discovering` with 0 host-side failures at 98 MB peak RSS,
/// i.e. ~10 KB/tunnel. `AMT_MAX_TUNNELS` (10000) is reachable from one process.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn tunnels_mode_scales_to_512_concurrent() {
    let relay = FakeRelay::bind("v4").await;
    relay.spawn(synth_v4_udp(
        [10, 0, 0, 1],
        [232, 0, 0, 1],
        5004,
        5005,
        b"x",
    ));

    let port = relay.addr.port().to_string();
    let (status, out) = run_amt_verify(&[
        "--relay",
        &relay.addr.ip().to_string(),
        "--port",
        &port,
        "--group",
        "232.0.0.1",
        "--source",
        "10.0.0.1",
        "--tunnels",
        "512",
        "--keepalive",
        "1",
        "--hold",
        "3",
        "--stagger-ms",
        "1",
        "--timeout",
        "20",
        "--json",
    ])
    .await;

    let v: serde_json::Value = serde_json::from_str(out.trim()).expect(&out);
    assert_eq!(
        v["alive"], 512,
        "client-side ceiling below 512 — any ramp knee at or under this N is the \
         INSTRUMENT, not the relay: {out}"
    );
    assert!(status.success(), "{out}");
}
