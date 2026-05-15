#![cfg(feature = "native")]

mod common;

use std::time::Duration;
use amt_protocol::native::AsyncAmtGateway;
use common::fake_relay::{synth_v4_udp, FakeRelay};

#[tokio::test(flavor = "current_thread")]
async fn watch_mode_emits_periodic_stats() {
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
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(gw.state(), amt_protocol::gateway::GatewayState::Active);
    gw.shutdown().await.unwrap();
}
