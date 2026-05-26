//! amt-verify — one-shot + watch E2E verify CLI for AMT tunnels.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use amt_protocol::native::AsyncAmtGateway;

#[derive(Parser, Debug)]
#[command(name = "amt-verify", version, about = "AMT E2E verify CLI")]
struct Args {
    /// AMT relay address. If omitted, DRIAD-resolved from --source.
    #[arg(long)]
    relay: Option<IpAddr>,

    /// AMT relay UDP port (RFC 7450 default 2268)
    #[arg(long, default_value_t = 2268)]
    port: u16,

    /// Multicast group address (mandatory)
    #[arg(long)]
    group: IpAddr,

    /// SSM source address — REQUIRED. DRIAD-only mode also needs it
    /// (DRIAD queries on the source).
    #[arg(long)]
    source: IpAddr,

    /// Force IP family. `auto` infers from --relay (or resolved relay).
    #[arg(long, value_enum, default_value_t = Family::Auto)]
    family: Family,

    /// Disable DRIAD. Forces --relay to be explicit.
    #[arg(long, default_value_t = false)]
    no_driad: bool,

    /// Wait at most this many seconds for first data
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Keep-alive interval in seconds
    #[arg(long, default_value = "60")]
    keepalive: u64,

    /// Stay running after first data, log stats every 5s
    #[arg(long, default_value_t = false)]
    watch: bool,

    /// On shutdown, skip the Membership Update leave and send only AMT Teardown.
    /// Useful for billing-path negative tests.
    #[arg(long, default_value_t = false)]
    no_graceful_leave: bool,

    /// On shutdown, drop the gateway runtime without Membership Update leave or AMT Teardown.
    /// This simulates hard client loss for relay-side stale-expiry billing tests.
    #[arg(long, default_value_t = false)]
    drop_without_teardown: bool,

    /// Machine-readable JSON output (one-shot mode only).
    /// Rejected with exit 2 if combined with --watch.
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Verbose logging (sets RUST_LOG=debug for crate=amt)
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum Family {
    V4,
    V6,
    Auto,
}

/// Exit-code classification per spec:
///   0 → success (one-shot data observed, or watch SIGINT clean teardown)
///   1 → handshake / verify failure (timeout, nonce mismatch, broadcast closed)
///   2 → config error (clap rejects, --json with --watch, family mismatch arg combo)
///   3 → fatal runtime (socket bind / send / recv unrecoverable)
#[derive(Debug)]
enum ExitCategory {
    HandshakeFail(anyhow::Error),
    Config(anyhow::Error),
    Fatal(anyhow::Error),
}

#[derive(Copy, Clone, Debug)]
enum ShutdownMode {
    GracefulLeave,
    TeardownOnly,
    DropWithoutTeardown,
}

impl ExitCategory {
    fn code(&self) -> u8 {
        match self {
            ExitCategory::HandshakeFail(_) => 1,
            ExitCategory::Config(_) => 2,
            ExitCategory::Fatal(_) => 3,
        }
    }
    fn err(&self) -> &anyhow::Error {
        match self {
            ExitCategory::HandshakeFail(e) | ExitCategory::Config(e) | ExitCategory::Fatal(e) => e,
        }
    }
}

#[derive(serde::Serialize)]
struct OneshotReport {
    outcome: &'static str,
    relay: String,
    family: &'static str,
    group: String,
    source: Option<String>,
    timings_ms: Timings,
    first_packet: FirstPacket,
}

#[derive(serde::Serialize)]
struct Timings {
    first_data: u64,
}

#[derive(serde::Serialize)]
struct FirstPacket {
    src: String,
    dst_port: u16,
    len: usize,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    let filter = if args.verbose {
        EnvFilter::new("amt=debug,amt_protocol=debug")
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("amt=info,amt_protocol=info"))
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    match run(args).await {
        Ok(()) => ExitCode::from(0),
        Err(cat) => {
            eprintln!("amt-verify: {:#}", cat.err());
            ExitCode::from(cat.code())
        }
    }
}

async fn run(args: Args) -> std::result::Result<(), ExitCategory> {
    // ----- Config validation (exit 2) -----
    if args.json && args.watch {
        return Err(ExitCategory::Config(anyhow!(
            "--json is one-shot only; combining with --watch is rejected"
        )));
    }
    if args.no_driad && args.relay.is_none() {
        return Err(ExitCategory::Config(anyhow!(
            "--no-driad set but --relay missing"
        )));
    }
    if args.no_graceful_leave && args.drop_without_teardown {
        return Err(ExitCategory::Config(anyhow!(
            "--no-graceful-leave and --drop-without-teardown are mutually exclusive"
        )));
    }
    let shutdown_mode = if args.drop_without_teardown {
        ShutdownMode::DropWithoutTeardown
    } else if args.no_graceful_leave {
        ShutdownMode::TeardownOnly
    } else {
        ShutdownMode::GracefulLeave
    };

    // ----- Build gateway (explicit relay OR DRIAD path) -----
    let (gw, resolved_relay) = match args.relay {
        Some(r) => {
            let gw = AsyncAmtGateway::builder(r)
                .relay_port(args.port)
                .keepalive(Duration::from_secs(args.keepalive))
                .build()
                .await
                .map_err(ExitCategory::Fatal)?;
            (gw, r)
        }
        None => {
            let gw = AsyncAmtGateway::builder_for_source(args.source)
                .relay_port(args.port)
                .keepalive(Duration::from_secs(args.keepalive))
                .build()
                .await
                .map_err(ExitCategory::HandshakeFail)?;
            // Re-resolve to surface the address in JSON output. Cheap UDP
            // lookup; an alternative is exposing a getter on AsyncAmtGateway.
            let resolved = amt_protocol::native::resolver::resolve_amt_relay(args.source)
                .await
                .map_err(ExitCategory::HandshakeFail)?;
            (gw, resolved)
        }
    };

    // Family inference now that the relay is known (resolved or explicit).
    let inferred_family = if resolved_relay.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    };
    let effective_family = match args.family {
        Family::Auto => inferred_family,
        explicit => {
            let same = matches!(
                (explicit, inferred_family),
                (Family::V4, Family::V4) | (Family::V6, Family::V6)
            );
            if !same {
                return Err(ExitCategory::Config(anyhow!(
                    "--family explicitly set but does not match --relay family"
                )));
            }
            explicit
        }
    };
    let family_str = match effective_family {
        Family::V4 => "v4",
        Family::V6 => "v6",
        Family::Auto => unreachable!(),
    };

    if args.group.is_ipv4() != args.source.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --source must be the same IP family"
        )));
    }
    if args.group.is_ipv4() != resolved_relay.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --relay must be the same IP family"
        )));
    }

    let mut data_rx = gw.subscribe_data();

    let started = Instant::now();
    gw.subscribe(args.group, Some(args.source))
        .await
        .map_err(ExitCategory::HandshakeFail)?;

    let evt = match recv_first_matching(
        &mut data_rx,
        args.group,
        args.source,
        Duration::from_secs(args.timeout),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return Err(ExitCategory::HandshakeFail(e)),
    };
    let first_data_ms = started.elapsed().as_millis() as u64;

    if args.json {
        let report = OneshotReport {
            outcome: "ok",
            relay: resolved_relay.to_string(),
            family: family_str,
            group: args.group.to_string(),
            source: Some(args.source.to_string()),
            timings_ms: Timings {
                first_data: first_data_ms,
            },
            first_packet: FirstPacket {
                src: format!("{}:{}", evt.src, evt.src_port),
                dst_port: evt.dst_port,
                len: evt.payload.len(),
            },
        };
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| ExitCategory::Fatal(e.into()))?
        );
    } else {
        println!(
            "ok — relay={} family={} group={} source={} first_data={}ms first_pkt={}:{} len={}",
            resolved_relay,
            family_str,
            args.group,
            args.source,
            first_data_ms,
            evt.src,
            evt.src_port,
            evt.payload.len()
        );
    }

    if args.watch {
        run_watch(gw, data_rx, args.group, args.source, shutdown_mode)
            .await
            .map_err(ExitCategory::Fatal)?;
    } else {
        finish_gateway(gw, args.group, args.source, shutdown_mode)
            .await
            .map_err(ExitCategory::Fatal)?;
    }
    Ok(())
}

async fn recv_first_matching(
    rx: &mut tokio::sync::broadcast::Receiver<amt_protocol::native::DataEvent>,
    group: IpAddr,
    source: IpAddr,
    timeout: Duration,
) -> Result<amt_protocol::native::DataEvent> {
    use tokio::sync::broadcast::error::RecvError;
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| {
                anyhow!(
                    "timed out after {}s waiting for first data matching ({}, {})",
                    timeout.as_secs(),
                    group,
                    source
                )
            })?;
        let recv = tokio::time::timeout(remaining, rx.recv())
            .await
            .map_err(|_| {
                anyhow!(
                    "timed out after {}s waiting for first data matching ({}, {})",
                    timeout.as_secs(),
                    group,
                    source
                )
            })?;
        match recv {
            Ok(evt) if evt.group == group && evt.src == source => return Ok(evt),
            Ok(_skip) => continue,
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => {
                return Err(anyhow!(
                    "data broadcast closed before first matching packet"
                ));
            }
        }
    }
}

async fn run_watch(
    gw: AsyncAmtGateway,
    mut data_rx: tokio::sync::broadcast::Receiver<amt_protocol::native::DataEvent>,
    group: IpAddr,
    source: IpAddr,
    shutdown_mode: ShutdownMode,
) -> Result<()> {
    use tokio::sync::broadcast::error::RecvError;
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut pkts: u64 = 0;
    let mut bytes: u64 = 0;
    let mut last_seen = Instant::now();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("amt-verify: SIGINT received, tearing down");
                break;
            }
            recv = data_rx.recv() => {
                match recv {
                    Ok(evt) => {
                        pkts += 1;
                        bytes += evt.payload.len() as u64;
                        last_seen = Instant::now();
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        eprintln!("amt-verify: WARN lagged {} packets", skipped);
                    }
                    Err(RecvError::Closed) => {
                        eprintln!("amt-verify: data broadcast closed");
                        break;
                    }
                }
            }
            _ = tick.tick() => {
                let age = last_seen.elapsed().as_millis();
                println!("pkts={} bytes={} last_seen={}ms_ago state={:?}",
                    pkts, bytes, age, gw.state());
            }
        }
    }
    finish_gateway(gw, group, source, shutdown_mode).await?;
    Ok(())
}

async fn finish_gateway(
    gw: AsyncAmtGateway,
    group: IpAddr,
    source: IpAddr,
    mode: ShutdownMode,
) -> Result<()> {
    match mode {
        ShutdownMode::GracefulLeave => {
            if let Err(e) = gw.unsubscribe(group, Some(source)).await {
                tracing::warn!(target: "amt", error=?e, "unsubscribe before shutdown failed");
            } else {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            gw.shutdown().await
        }
        ShutdownMode::TeardownOnly => gw.shutdown().await,
        ShutdownMode::DropWithoutTeardown => {
            drop(gw);
            Ok(())
        }
    }
}
