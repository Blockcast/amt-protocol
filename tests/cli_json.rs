#![cfg(feature = "native")]

mod common;

use amt_protocol::messages::MessageType;
use common::fake_relay::{FakeRelay, synth_v4_udp};
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
    assert_eq!(v["group"], "232.0.0.1");
    assert_eq!(v["first_packet"]["src"], "10.0.0.1:5004");
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
