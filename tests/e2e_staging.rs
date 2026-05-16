//! E2E tests pinned to staging-blockcastd amt-relay.
//! Manual: `cargo test --no-default-features --features native --test e2e_staging -- --ignored --nocapture`.

#![cfg(feature = "native")]

use std::env;
use std::net::IpAddr;
use std::time::Duration;

use amt_protocol::native::AsyncAmtGateway;

/// Pinned via env so the test runs in any environment.
/// Required:
///   STAGING_RELAY  — e.g. "192.0.2.96"
///   STAGING_SOURCE — e.g. "69.25.95.10"
///   STAGING_GROUP  — e.g. "232.0.0.1"
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
    eprintln!(
        "first packet: src={} dst_port={} len={}",
        evt.src,
        evt.dst_port,
        evt.payload.len()
    );

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
