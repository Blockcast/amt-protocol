//! Tier 2 integration tests for the native AsyncAmtGateway runtime.

#![cfg(feature = "native")]

mod common;

use amt_protocol::native::AsyncAmtGateway;
use common::fake_relay::{synth_v4_udp, synth_v6_udp, FakeRelay};
use std::time::Duration;

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
    await_authenticated_teardown(&relay).await;

    let captured = relay.captured.lock().await;
    assert!(captured.message_types.contains(&1));
    assert!(captured.message_types.contains(&3));
    assert!(captured.message_types.contains(&5));
    assert!(captured.message_types.contains(&7));
    assert_eq!(captured.authenticated_teardowns.len(), 1);
}

/// The relay parsed and authenticated a Teardown (RFC 7450 §5.3.3.5): a
/// datagram that merely starts with the Teardown type byte does not count.
async fn await_authenticated_teardown(relay: &FakeRelay) {
    tokio::time::timeout(
        Duration::from_secs(5),
        relay.teardown_authenticated.notified(),
    )
    .await
    .expect("the relay never authenticated a Teardown");
}

#[tokio::test(flavor = "current_thread")]
async fn oneshot_happy_path_v6() {
    let relay = FakeRelay::bind("v6").await;
    // v6 inner that matches the v6 (S,G) we subscribe to below.
    // src = 2001:db8::1 octets, dst = ff3e::1234 octets.
    let src: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let dst: [u8; 16] = [0xff, 0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34];
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
    // An IPv6 Gateway IP Address travels verbatim (RFC 7450 §5.1.7.7).
    await_authenticated_teardown(&relay).await;
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

    let a = tokio::time::timeout(Duration::from_secs(5), rx_a.recv())
        .await
        .unwrap()
        .unwrap();
    let b = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
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

    let err = gw
        .subscribe(
            "ff3e::1234".parse().unwrap(),
            Some("2001:db8::1".parse().unwrap()),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("family"), "got: {err}");

    gw.shutdown().await.unwrap();
}

/// A fatal socket error must make the gateway report itself DEAD.
///
/// Regression guard for the `--tunnels` liveness verdict (BLO-33457). The
/// runtime published whatever state the SubscriptionManager last reported, and
/// the manager cannot observe socket failures — so a gateway whose task had
/// already died on a send error still read `Active`. That is precisely the
/// shape `amt-verify` counts as a surviving tunnel, so a host-side send failure
/// during a ramp would have inflated the measured ceiling instead of showing up
/// as an instrument failure.
///
/// The relay advertises 255.255.255.255, so the gateway redirects there and its
/// next `send_to` fails EACCES on a socket without SO_BROADCAST. This is the
/// only way to drive the fatal-socket path from outside the process: the
/// destination is fixed for the session, so a send failure reachable *after* a
/// completed handshake cannot be forced without a production fault-injection
/// seam.
#[tokio::test(flavor = "current_thread")]
async fn fatal_send_error_reports_dead_not_active() {
    let relay = FakeRelay::bind("v4").await;
    relay.spawn_advertising(
        synth_v4_udp([10, 0, 0, 1], [232, 0, 0, 1], 5004, 5005, b"x"),
        Some("255.255.255.255".parse().unwrap()),
    );

    let gw = AsyncAmtGateway::builder(relay.addr.ip())
        .relay_port(relay.addr.port())
        .keepalive(Duration::from_secs(1))
        .build()
        .await
        .expect("build gateway");

    gw.subscribe(
        "232.0.0.1".parse().unwrap(),
        Some("10.0.0.1".parse().unwrap()),
    )
    .await
    .expect("subscribe");

    // Let discovery -> advertisement -> redirected (failing) send play out.
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(
        gw.has_fatal().await,
        "a failed send_to must be recorded as a fatal runtime error"
    );
    // Closed specifically, not merely "not Active": the contract is that a
    // gateway whose runtime task has exited reports Closed on EVERY exit path.
    // Before this was published explicitly the runtime left whatever state the
    // manager last reported (here `Idle`/`Requesting`, but `Active` when the
    // failure lands after a completed handshake), which is what let a caller
    // count a dead tunnel as live state.
    assert_eq!(
        gw.state(),
        amt_protocol::GatewayState::Closed,
        "a gateway whose runtime died on a socket error must report Closed"
    );
    assert_eq!(
        gw.keepalives_sent(),
        0,
        "a keep-alive that never left the process must not be counted as one"
    );
}

/// A one-shot DRIAD nameserver: answers the first query it gets with one
/// IPv4 AMTRELAY record per `(precedence, relay)`, echoing the query's header
/// and question (not its OPT record).
async fn spawn_driad_dns(records: Vec<(u8, [u8; 4])>) -> std::net::SocketAddr {
    let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = dns.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (n, src) = dns.recv_from(&mut buf).await.unwrap();
        let query = &buf[..n];
        let mut end = 12;
        while query[end] != 0 {
            end += 1 + query[end] as usize;
        }
        let mut resp = query[..end + 5].to_vec();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1
        resp[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        resp[8..12].fill(0);
        for (precedence, relay) in records {
            resp.extend_from_slice(&[0xC0, 0x0C, 0x01, 0x04, 0x00, 0x01]);
            resp.extend_from_slice(&300u32.to_be_bytes());
            resp.extend_from_slice(&6u16.to_be_bytes());
            resp.extend_from_slice(&[precedence, 0x01]);
            resp.extend_from_slice(&relay);
        }
        dns.send_to(&resp, src).await.unwrap();
    });
    dns_addr
}

/// A reply listing more relays than a gateway will ever try is cut to the most
/// preferred few, so a large RRset cannot turn into an unbounded walk.
#[tokio::test(flavor = "current_thread")]
async fn driad_resolution_keeps_only_the_most_preferred_candidates() {
    use amt_protocol::driad::DriadRelayAddress;
    use amt_protocol::native::resolver::{resolve_candidates_via, MAX_CANDIDATES};

    let offered: Vec<(u8, [u8; 4])> = (1..=10).rev().map(|i| (i * 10, [127, 0, 0, i])).collect();
    let dns_addr = spawn_driad_dns(offered).await;

    let candidates = resolve_candidates_via("10.0.0.1".parse().unwrap(), &[dns_addr])
        .await
        .expect("resolve");
    let kept: Vec<_> = candidates
        .iter()
        .map(|c| (c.precedence, c.relay.clone()))
        .collect();
    let expected: Vec<_> = (1..=MAX_CANDIDATES as u8)
        .map(|i| {
            let relay = DriadRelayAddress::Ip([127, 0, 0, i].into());
            (i * 10, relay)
        })
        .collect();
    assert_eq!(kept, expected);
}

/// A relay that never answers holds the walk for its whole handshake budget;
/// `discovery_timeout` bounds the build instead.
#[tokio::test(flavor = "current_thread")]
async fn driad_build_honours_the_discovery_timeout() {
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dns_addr = spawn_driad_dns(vec![(10, [127, 0, 0, 1])]).await;

    let started = std::time::Instant::now();
    let err = AsyncAmtGateway::builder_for_source("10.0.0.1".parse().unwrap())
        .relay_port(silent.local_addr().unwrap().port())
        .nameservers(vec![dns_addr])
        .discovery_timeout(Duration::from_millis(300))
        .build()
        .await
        .err()
        .expect("a silent relay cannot complete the handshake");
    assert!(err.to_string().contains("within"), "{err:#}");
    // One discovery attempt alone waits DISCOVERY_TIMEOUT_MS.
    assert!(
        started.elapsed() < Duration::from_millis(amt_protocol::subscription::DISCOVERY_TIMEOUT_MS)
    );
}

/// Subscribe on a DRIAD-built gateway and require the relay's data to arrive.
async fn assert_data_flows(gw: AsyncAmtGateway) {
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
    assert_eq!(&evt.payload[..], b"hello");
    gw.shutdown().await.expect("shutdown");
}

/// DRIAD offers two relays. The preferred one cannot complete the handshake
/// (a broadcast address, so its first send fails on a socket without
/// SO_BROADCAST); the build walks on to the working one and reports it, and
/// that tunnel carries data.
#[tokio::test(flavor = "current_thread")]
async fn driad_build_walks_past_a_relay_that_fails_the_handshake() {
    let relay = FakeRelay::bind("v4").await;
    relay.spawn(synth_v4_udp(
        [10, 0, 0, 1],
        [232, 0, 0, 1],
        5004,
        5005,
        b"hello",
    ));
    let dns_addr = spawn_driad_dns(vec![(10, [255, 255, 255, 255]), (20, [127, 0, 0, 1])]).await;

    let gw = AsyncAmtGateway::builder_for_source("10.0.0.1".parse().unwrap())
        .relay_port(relay.addr.port())
        .keepalive(Duration::from_secs(60))
        .nameservers(vec![dns_addr])
        .build()
        .await
        .expect("the build walks to the working relay");
    assert_eq!(gw.relay(), relay.addr.ip());
    assert_data_flows(gw).await;
}

/// The relay keys its tunnel by the gateway's address and answers every
/// Request at the port of the first one, as upstream Linux AMT does. The
/// build's handshake check sends that first Request, so the gateway has to
/// keep the check's socket: a Request from any other port has its Membership
/// Query sent to the first port, and the tunnel never comes up.
#[tokio::test(flavor = "current_thread")]
async fn driad_build_keeps_the_checked_socket_for_an_address_keyed_relay() {
    let relay = FakeRelay::bind("v4").await;
    relay.spawn_keyed_by_gateway_address(synth_v4_udp(
        [10, 0, 0, 1],
        [232, 0, 0, 1],
        5004,
        5005,
        b"hello",
    ));
    let dns_addr = spawn_driad_dns(vec![(10, [127, 0, 0, 1])]).await;

    let gw = AsyncAmtGateway::builder_for_source("10.0.0.1".parse().unwrap())
        .relay_port(relay.addr.port())
        .keepalive(Duration::from_secs(60))
        .nameservers(vec![dns_addr])
        .build()
        .await
        .expect("the relay accepts the handshake");
    assert_eq!(gw.relay(), relay.addr.ip());
    assert_data_flows(gw).await;
}
