#![cfg(feature = "native")]

mod common;

use amt_protocol::messages::MessageType;
use common::fake_relay::{synth_v4_udp, FakeRelay};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

#[tokio::test(flavor = "current_thread")]
async fn json_output_is_parseable() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn(inner);

    let bin = env!("CARGO_BIN_EXE_amt-verify");
    let mut child = Command::new(bin)
        .args([
            "--relay",
            &relay.addr.ip().to_string(),
            "--port",
            &relay.addr.port().to_string(),
            "--group",
            "232.0.0.1",
            "--source",
            "10.0.0.1",
            "--timeout",
            "5",
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
    assert_eq!(v["packet_count"], 1);
    assert_eq!(v["byte_count"], 1);
    assert!(v["first_data"].is_u64());
    assert_eq!(v["group"], "232.0.0.1");
    assert_eq!(v["first_packet"]["src"], "10.0.0.1:5004");
}

#[tokio::test(flavor = "current_thread")]
async fn help_exposes_d2_probe_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_amt-verify"))
        .arg("--help")
        .output()
        .await
        .expect("spawn amt-verify --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in [
        "--relay",
        "--port",
        "--source",
        "--group",
        "--no-driad",
        "--family",
        "--timeout",
        "--packet-count",
        "--json",
    ] {
        assert!(stdout.contains(flag), "missing {flag} in:\n{stdout}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn default_shutdown_sends_leave_then_teardown() {
    let relay = run_verify(&[]).await;
    let types = captured_types(&relay).await;

    assert_eq!(count(&types, MessageType::MembershipUpdate), 2, "{types:?}");
    assert_eq!(count(&types, MessageType::Teardown), 1, "{types:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn no_graceful_leave_sends_teardown_without_leave_update() {
    let relay = run_verify(&["--no-graceful-leave"]).await;
    let types = captured_types(&relay).await;

    assert_eq!(count(&types, MessageType::MembershipUpdate), 1, "{types:?}");
    assert_eq!(count(&types, MessageType::Teardown), 1, "{types:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn drop_without_teardown_sends_no_leave_or_teardown() {
    let relay = run_verify(&["--drop-without-teardown"]).await;
    let types = captured_types(&relay).await;

    assert_eq!(count(&types, MessageType::MembershipUpdate), 1, "{types:?}");
    assert_eq!(count(&types, MessageType::Teardown), 0, "{types:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn non_graceful_modes_are_mutually_exclusive() {
    let bin = env!("CARGO_BIN_EXE_amt-verify");
    let output = Command::new(bin)
        .args([
            "--relay",
            "127.0.0.1",
            "--port",
            "2268",
            "--group",
            "232.0.0.1",
            "--source",
            "10.0.0.1",
            "--no-graceful-leave",
            "--drop-without-teardown",
        ])
        .output()
        .await
        .expect("spawn amt-verify");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"), "{stderr}");
}

// BLO-33456. The fake relay emits exactly ONE MulticastData per Membership
// Update, so asking for more than one packet is a deterministic deadline
// expiry with real partial counts already banked. Before the fix the process
// exited 1 having printed nothing, and the workflow's `>report.json` left an
// empty file (sha256 e3b0c442...) -- discarding exactly the datum a saturation
// probe exists to collect.
#[tokio::test(flavor = "current_thread")]
async fn timeout_emits_partial_counts_not_an_empty_report() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"xyz");
    relay.spawn(inner);

    let (stdout, status) = run_json(&relay, "232.0.0.1", &["--packet-count", "3"]).await;

    assert_eq!(status.code(), Some(1), "exit semantics must be unchanged");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect(&stdout);
    assert_eq!(v["outcome"], "timeout");
    // The partial count is the whole point: 1 of the 3 requested.
    assert_eq!(v["packet_count"], 1);
    assert_eq!(v["byte_count"], 3);
    assert!(v["elapsed_ms"].is_u64(), "{v}");
    assert!(v["first_data"].is_u64(), "{v}");
    // The two clocks have different origins on purpose: `first_data` runs from
    // process start and includes the subscribe/handshake join latency, while
    // `elapsed_ms` starts only once the handshake is done so it can serve as a
    // rate denominator. Swapping them back to one clock breaks this.
    assert!(
        v["elapsed_ms"].as_u64() <= v["first_data"].as_u64(),
        "elapsed_ms must exclude the handshake first_data includes: {v}"
    );
    assert_eq!(v["first_packet"]["src"], "10.0.0.1:5004");
    // A clean partial: the shortfall is the deadline, not receiver lag.
    assert_eq!(v["lagged_count"], 0, "{v}");
}

// Deadline expiry with nothing received at all: still a well-formed report,
// with the absent first packet explicitly null rather than a fabricated zero.
#[tokio::test(flavor = "current_thread")]
async fn timeout_before_any_packet_still_emits_a_report() {
    let relay = FakeRelay::bind("v4").await;
    // Data is emitted for (10.0.0.1, 232.0.0.1); subscribing to a different
    // group means every packet is filtered out and nothing ever matches.
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn(inner);

    let (stdout, status) = run_json(&relay, "232.0.0.9", &[]).await;

    assert_eq!(status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect(&stdout);
    assert_eq!(v["outcome"], "timeout");
    assert_eq!(v["packet_count"], 0);
    assert_eq!(v["byte_count"], 0);
    assert!(v["elapsed_ms"].is_null(), "{v}");
    assert!(v["first_packet"].is_null(), "{v}");
}

// The overall-deadline guarantee: N packets share ONE budget, so a run that
// never completes cannot exceed --timeout. Previously each packet got a fresh
// --timeout, so this would have taken ~3x as long.
#[tokio::test(flavor = "current_thread")]
async fn timeout_is_an_overall_deadline_not_per_packet() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn(inner);

    let start = std::time::Instant::now();
    let (_stdout, status) = run_json(&relay, "232.0.0.1", &["--packet-count", "4"]).await;
    let elapsed = start.elapsed();

    assert_eq!(status.code(), Some(1));
    // 4 packets x 2s per-packet would be ~8s. Generous ceiling to stay stable
    // on a loaded CI runner while still failing the per-packet behaviour.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "expected one shared 2s budget, took {elapsed:?}"
    );
}

/// Run amt-verify against `relay` in --json mode subscribed to `group`,
/// returning (stdout, status). `--timeout 2` unless `extra_args` overrides it.
async fn run_json(
    relay: &FakeRelay,
    group: &str,
    extra_args: &[&str],
) -> (String, std::process::ExitStatus) {
    let bin = env!("CARGO_BIN_EXE_amt-verify");
    let mut args = vec![
        "--relay".to_string(),
        relay.addr.ip().to_string(),
        "--port".to_string(),
        relay.addr.port().to_string(),
        "--group".to_string(),
        group.to_string(),
        "--source".to_string(),
        "10.0.0.1".to_string(),
        "--timeout".to_string(),
        "2".to_string(),
        "--json".to_string(),
    ];
    args.extend(extra_args.iter().map(|a| a.to_string()));

    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn amt-verify");
    let mut out = child.stdout.take().unwrap();
    let mut buf = String::new();
    out.read_to_string(&mut buf).await.unwrap();
    let status = child.wait().await.unwrap();
    (buf, status)
}

async fn run_verify(extra_args: &[&str]) -> FakeRelay {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn(inner);

    let bin = env!("CARGO_BIN_EXE_amt-verify");
    let mut args = vec![
        "--relay".to_string(),
        relay.addr.ip().to_string(),
        "--port".to_string(),
        relay.addr.port().to_string(),
        "--group".to_string(),
        "232.0.0.1".to_string(),
        "--source".to_string(),
        "10.0.0.1".to_string(),
        "--timeout".to_string(),
        "5".to_string(),
    ];
    args.extend(extra_args.iter().map(|arg| arg.to_string()));

    let status = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("spawn amt-verify");
    assert!(status.success(), "exit code: {status}");
    relay
}

async fn captured_types(relay: &FakeRelay) -> Vec<u8> {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    relay.captured.lock().await.message_types.clone()
}

fn count(types: &[u8], msg_type: MessageType) -> usize {
    types.iter().filter(|&&t| t == msg_type as u8).count()
}
