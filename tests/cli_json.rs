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
