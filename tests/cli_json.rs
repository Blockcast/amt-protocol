#![cfg(feature = "native")]

mod common;

use amt_protocol::messages::MessageType;
use amt_protocol::subscription::REQUEST_TIMEOUT_MS;
use common::fake_relay::{synth_v4_udp, FakeRelay, Loss};
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
    // Without --forward the hand-off counts are null, not a fabricated 0.
    assert!(
        v["forwarded"].is_null() && v["forward_errors"].is_null(),
        "{v}"
    );
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
    assert_eq!(authenticated_teardowns(&relay).await, 1, "{types:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn no_graceful_leave_sends_teardown_without_leave_update() {
    let relay = run_verify(&["--no-graceful-leave"]).await;
    let types = captured_types(&relay).await;

    assert_eq!(count(&types, MessageType::MembershipUpdate), 1, "{types:?}");
    assert_eq!(count(&types, MessageType::Teardown), 1, "{types:?}");
    assert_eq!(authenticated_teardowns(&relay).await, 1, "{types:?}");
}

// A relay that leaves the G flag unset does not support Teardown (RFC 7450
// §5.1.4.5) and hands out no Gateway Address fields to build one from. The
// gateway still leaves gracefully and exits 0, but sends no Teardown.
#[tokio::test(flavor = "current_thread")]
async fn relay_without_teardown_support_gets_no_teardown() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn_without_teardown_support(inner);
    verify_against(&relay, &[]).await;
    let types = captured_types(&relay).await;

    assert_eq!(count(&types, MessageType::MembershipUpdate), 2, "{types:?}");
    assert_eq!(count(&types, MessageType::Teardown), 0, "{types:?}");
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

// BLO-46422 (W9 S3a). --forward hands payloads to a decoder on THIS host and
// must never become a sender onto the network. clap refuses each of these with
// exit 2 before a socket is bound or a channel joined; the channel's own group
// typed where the decoder's address belongs is the likeliest slip.
#[tokio::test(flavor = "current_thread")]
async fn forward_refuses_anything_but_loopback() {
    for to in [
        "232.0.0.1:5003",            // v4 SSM group
        "[ff3e::232:201]:5003",      // v6 SSM group, the W9 channel range
        "10.0.0.1:15003",            // routable v4
        "[2602:f74d:1:5::57]:15003", // routable v6
        "0.0.0.0:15003",             // unspecified
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_amt-verify"))
            .args([
                "--relay",
                "127.0.0.1",
                "--group",
                "232.0.0.1",
                "--source",
                "10.0.0.1",
                // Bounds the run if the refusal ever stops firing at parse.
                "--timeout",
                "1",
                "--forward",
                to,
            ])
            .output()
            .await
            .expect("spawn amt-verify");

        assert_eq!(output.status.code(), Some(2), "{to}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("not a loopback address"), "{to}: {stderr}");
    }
}

// What the decoder reads must be the inner UDP payload byte for byte, not the
// AMT or IP framing around it, from either loopback family. Every byte value
// is in the payload, so a re-encode or a truncation would show.
#[tokio::test(flavor = "current_thread")]
async fn forward_sends_each_payload_verbatim() {
    let payload: Vec<u8> = (0..=255).collect();
    for sink in ["127.0.0.1:0", "[::1]:0"] {
        let sink = tokio::net::UdpSocket::bind(sink).await.expect("bind sink");
        let to = sink.local_addr().unwrap().to_string();
        let relay = FakeRelay::bind("v4").await;
        relay.spawn(synth_v4_udp(
            [10, 0, 0, 1],
            [232, 0, 0, 1],
            5004,
            5005,
            &payload,
        ));

        let (stdout, status) = run_json(&relay, "232.0.0.1", &["--forward", &to]).await;

        assert!(status.success(), "{to}: exit {status}: {stdout}");
        let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect(&stdout);
        assert_eq!(v["packet_count"], 1, "{to}: counting is unchanged: {v}");
        assert_eq!(v["forwarded"], 1, "{to}: {v}");
        assert_eq!(v["forward_errors"], 0, "{to}: {v}");
        let mut buf = [0u8; 2048];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), sink.recv_from(&mut buf))
                .await
                .expect("nothing was forwarded")
                .unwrap();
        assert_eq!(&buf[..n], &payload[..], "{to}");
    }
}

// The other place a payload surfaces. Under --watch only the first
// --packet-count packets pass through the one-shot loop; every later one is
// received by run_watch. The fake relay answers each Membership Update with one
// MulticastData, so --keepalive 1 brings a second packet about 1 s in, and a
// second datagram on the sink can only have come from the watch loop.
#[tokio::test(flavor = "current_thread")]
async fn forward_continues_under_watch() {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sink");
    let relay = FakeRelay::bind("v4").await;
    relay.spawn(synth_v4_udp(
        [10, 0, 0, 1],
        [232, 0, 0, 1],
        5004,
        5005,
        b"txfeed",
    ));

    let mut child = Command::new(env!("CARGO_BIN_EXE_amt-verify"))
        .args([
            "--relay",
            &relay.addr.ip().to_string(),
            "--port",
            &relay.addr.port().to_string(),
            "--group",
            "232.0.0.1",
            "--source",
            "10.0.0.1",
            "--keepalive",
            "1",
            "--watch",
            "--forward",
            &sink.local_addr().unwrap().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn amt-verify");

    let mut buf = [0u8; 64];
    for i in 0..2 {
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(10), sink.recv_from(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("datagram {i} was never forwarded"))
                .unwrap();
        assert_eq!(&buf[..n], b"txfeed", "datagram {i}");
    }
    child.kill().await.expect("stop amt-verify");
}

/// A relay that loses the gateway's first Request still delivers within one
/// run. The unanswered Request restarts relay discovery (RFC 7450 §5.2.3.5.3)
/// and the second handshake is answered. Before, the gateway parked in Idle
/// with the subscription never announced, and the run reported zero packets
/// at its deadline -- which the public-vantage probe reads as "relay not
/// forwarding", for one lost datagram.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_request_restarts_discovery_and_still_receives() {
    let relay = FakeRelay::bind("v4").await;
    let inner = synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x");
    relay.spawn_lossy(inner, Loss { requests: 1 });

    let v = run_json_within(&relay, 2 * REQUEST_TIMEOUT_MS).await;

    assert_eq!(v["outcome"], "ok", "{v}");
    assert_eq!(v["packet_count"], 1, "{v}");
    let types = captured_types(&relay).await;
    assert_eq!(count(&types, MessageType::RelayDiscovery), 2, "{types:?}");
    assert_eq!(count(&types, MessageType::Request), 2, "{types:?}");
}

/// Run amt-verify in --json mode against `relay` with a deadline of
/// `deadline_ms` (whole seconds, rounded up), require exit 0, and return the
/// parsed report.
async fn run_json_within(relay: &FakeRelay, deadline_ms: u64) -> serde_json::Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_amt-verify"))
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
            &deadline_ms.div_ceil(1000).to_string(),
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
    assert!(status.success(), "exit code: {status}, report: {buf}");
    serde_json::from_str(buf.trim()).expect(&buf)
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
    verify_against(&relay, extra_args).await;
    relay
}

/// Run amt-verify against an already-spawned `relay` and require exit 0.
async fn verify_against(relay: &FakeRelay, extra_args: &[&str]) {
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
}

async fn captured_types(relay: &FakeRelay) -> Vec<u8> {
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    relay.captured.lock().await.message_types.clone()
}

/// Teardowns the relay parsed and authenticated (RFC 7450 §5.3.3.5), as
/// opposed to datagrams that merely started with the Teardown type byte.
/// Waits for the first. The bound only turns a Teardown that never arrives
/// into a failure instead of a hang; it matches tests/native_runtime.rs.
async fn authenticated_teardowns(relay: &FakeRelay) -> usize {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        relay.teardown_authenticated.notified(),
    )
    .await
    .expect("the relay never authenticated a Teardown");
    relay.captured.lock().await.authenticated_teardowns.len()
}

fn count(types: &[u8], msg_type: MessageType) -> usize {
    types.iter().filter(|&&t| t == msg_type as u8).count()
}
