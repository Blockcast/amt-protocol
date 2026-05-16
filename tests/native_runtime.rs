//! Tier 2 integration tests for the native AsyncAmtGateway runtime.

#![cfg(feature = "native")]

mod common;

use std::time::Duration;
use amt_protocol::native::AsyncAmtGateway;
use common::fake_relay::{synth_v4_udp, synth_v6_udp, FakeRelay};

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

    // Give the loopback socket a moment to deliver the Teardown to the fake relay task.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let captured = relay.captured.lock().await;
    assert!(captured.message_types.contains(&1));
    assert!(captured.message_types.contains(&3));
    assert!(captured.message_types.contains(&5));
    assert!(captured.message_types.contains(&7));
}

#[tokio::test(flavor = "current_thread")]
async fn oneshot_happy_path_v6() {
    let relay = FakeRelay::bind("v6").await;
    // v6 inner that matches the v6 (S,G) we subscribe to below.
    // src = 2001:db8::1 octets, dst = ff3e::1234 octets.
    let src: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x01];
    let dst: [u8; 16] = [0xff, 0x3e, 0,0,0,0,0,0, 0,0,0,0, 0,0,0x12,0x34];
    let inner = synth_v6_udp(src, dst, 5004, 5005, b"hello");
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
