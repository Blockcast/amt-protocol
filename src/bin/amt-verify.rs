//! amt-verify — one-shot + watch E2E verify CLI for AMT tunnels.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use amt_protocol::native::AsyncAmtGateway;
use amt_protocol::GatewayState;

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

    /// OVERALL deadline for the one-shot data phase, in seconds — not a
    /// first-data timeout and not a per-packet idle timeout. The clock starts
    /// at `subscribe()` and covers all `--packet-count` packets, so a run
    /// cannot exceed it however the stream behaves.
    ///
    /// On expiry the run still emits its report with `outcome: "timeout"` and
    /// the PARTIAL `packet_count` / `byte_count` observed so far; the exit code
    /// is unchanged (1). That partial count is the datum a saturation probe
    /// needs — see BLO-33456.
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Number of matching packets required before one-shot success
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
    packet_count: u64,

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

    /// TUNNEL-STATE mode: hold N concurrent AMT tunnels from this one process,
    /// each with its own UDP socket and gateway state machine, and report
    /// per-tunnel establishment + keep-alive survival.
    ///
    /// This measures the relay's CONTROL-PLANE tunnel-table occupancy, not its
    /// forwarding capacity: run it against an idle or very-low-rate group so
    /// aggregate bitrate is negligible. The witness is tunnel-table occupancy
    /// plus membership survival, NOT data receipt — an idle tunnel may cost a
    /// relay less state than an active one, so a ceiling measured this way is
    /// comparable to a configured control-plane limit (e.g. Junos
    /// `tunnel-limit`, Linux `AMT_MAX_TUNNELS`) and NOT to a loaded ceiling.
    /// See BLO-33457.
    ///
    /// `--watch`, `--packet-count` and the data-receipt wait do not apply.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    tunnels: Option<u32>,

    /// Tunnels mode: seconds to hold the tunnels open after the last one is
    /// established, before reading the survival verdict. Defaults to
    /// `--keepalive + 10`, i.e. long enough for every tunnel to emit at least
    /// one keep-alive Membership Update. A tunnel that has sent none has not
    /// been shown to survive an interval and is not counted alive.
    #[arg(long)]
    hold: Option<u64>,

    /// Tunnels mode: delay between starting successive tunnels, in
    /// milliseconds. Prevents an N-wide simultaneous Discovery burst from
    /// causing loss that would read as a relay-side state knee.
    #[arg(long, default_value_t = 2)]
    stagger_ms: u64,
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
    /// "ok" — `--packet-count` packets observed. "timeout" — the `--timeout`
    /// deadline expired first. "closed" — the tunnel's data broadcast ended
    /// first, which is a TRANSPORT failure and not a deadline observation; do
    /// not feed a "closed" run into a rate or loss calculation. In both failure
    /// cases `packet_count`/`byte_count` are PARTIAL (and may be 0) but are
    /// still real observations, not placeholders.
    outcome: &'static str,
    packet_count: u64,
    byte_count: u64,
    /// Wall time from the completion of `subscribe()` to the last packet
    /// counted, measured in-process. It deliberately EXCLUDES the handshake, as
    /// well as container and process startup, so `packet_count / elapsed_ms` is
    /// a receiver rate that needs no two-run solve for the startup constant.
    /// (`first_data` is the field that still includes join latency.) `null` if
    /// no packet arrived.
    elapsed_ms: Option<u64>,
    /// Packets the receiver's broadcast channel dropped before this process
    /// dequeued them. NOT included in `packet_count`. Non-zero means the
    /// receiver could not keep up, so any shortfall against the source is a
    /// RECEIVER artifact and must not be attributed to relay loss.
    lagged_count: u64,
    /// Time from process start to the first matching packet, INCLUDING the
    /// subscribe/handshake join latency — i.e. "how long until data flowed",
    /// which is the pre-existing meaning of this field. Use `elapsed_ms`, not
    /// this, as a rate denominator. `null` if no packet arrived.
    first_data: Option<u64>,
    relay: String,
    family: &'static str,
    group: String,
    source: Option<String>,
    timings_ms: Timings,
    first_packet: Option<FirstPacket>,
    /// Receiver-intrinsic loss, read off the stream's own sequence numbers.
    /// `null` when no packet arrived. See [`SeqTracker`].
    mmtp: Option<MmtpLoss>,
}

#[derive(serde::Serialize)]
struct Timings {
    first_data: Option<u64>,
}

#[derive(serde::Serialize)]
struct FirstPacket {
    src: String,
    dst_port: u16,
    len: usize,
    /// First 16 bytes, hex. Present so the MMTP header layout that `mmtp` is
    /// parsed against can be checked by hand from the same run that reports a
    /// loss figure, rather than taken on faith.
    head_hex: String,
}

/// Largest per-track sequence jump still read as loss rather than as evidence
/// that the header layout assumed below is wrong. The observed stream runs
/// ~1.3k pkt/s across 8 tracks, so this is minutes of outage on one track.
const MAX_PLAUSIBLE_GAP: u32 = 10_000;

/// Receiver-intrinsic loss accounting, parsed from the MMTP packet header
/// (ISO/IEC 23008-1: `packet_id` at bytes 2..4 and `packet_sequence_number` at
/// bytes 8..12, both big-endian; `version` is the top 2 bits of byte 0 and is 0
/// for this draft). Sequence numbers are per-`packet_id`, so every track is
/// tracked independently.
///
/// This exists because reconciling a receiver count against a source count
/// requires a source-side counter, and the MMTP publisher for this stream
/// exports none — no Prometheus series, no log counter (BLO-33456). A stream
/// that numbers its own packets does not need one, and the resulting figure is
/// immune to the two accountings naming different streams, which is how this
/// reconciliation went wrong twice.
#[derive(Default)]
struct SeqTracker {
    /// Per-track high-water sequence number.
    last: std::collections::HashMap<u16, u32>,
    observed: u64,
    in_sequence: u64,
    gaps: u64,
    reordered: u64,
    implausible: u64,
}

impl SeqTracker {
    fn observe(&mut self, payload: &[u8]) {
        self.observed += 1;
        // Too short to hold a header, or a version this parser does not claim to
        // understand. Either way the layout assumption does not hold here.
        if payload.len() < 12 || payload[0] >> 6 != 0 {
            self.implausible += 1;
            return;
        }
        let pid = u16::from_be_bytes([payload[2], payload[3]]);
        let seq = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let Some(&prev) = self.last.get(&pid) else {
            self.last.insert(pid, seq);
            return;
        };
        let delta = seq.wrapping_sub(prev);
        if delta == 0 || delta > u32::MAX / 2 {
            // Duplicate, or arrived behind the high-water mark. Not loss — and
            // the mark must not move backwards, or the next in-order packet
            // reads as a gap.
            self.reordered += 1;
            return;
        }
        if delta > MAX_PLAUSIBLE_GAP {
            self.implausible += 1;
        } else if delta == 1 {
            self.in_sequence += 1;
        } else {
            self.gaps += u64::from(delta - 1);
        }
        self.last.insert(pid, seq);
    }

    fn finish(self) -> Option<MmtpLoss> {
        if self.observed == 0 {
            return None;
        }
        let denom = self.gaps + self.in_sequence;
        // Withheld rather than approximated: a non-zero `implausible` is the
        // signature of the layout assumption failing, and a ratio computed
        // across it would look precise and be meaningless.
        let loss_ratio =
            (self.implausible == 0 && denom > 0).then(|| self.gaps as f64 / denom as f64);
        Some(MmtpLoss {
            tracks: self.last.len(),
            in_sequence: self.in_sequence,
            gaps: self.gaps,
            reordered: self.reordered,
            implausible: self.implausible,
            loss_ratio,
        })
    }
}

#[derive(serde::Serialize)]
struct MmtpLoss {
    /// Distinct `packet_id` values seen. The catalog this stream publishes
    /// advertises 8: three video renditions plus audio, each with a RaptorQ
    /// repair track.
    tracks: usize,
    /// Adjacent per-track arrivals whose sequence numbers differed by exactly 1.
    in_sequence: u64,
    /// Packets missing between adjacent arrivals, summed over tracks. This is
    /// the loss figure; it needs no source-side counter.
    gaps: u64,
    /// Duplicates, or arrivals behind the per-track high-water mark. Not loss.
    reordered: u64,
    /// Packets too short, carrying a non-zero version, or jumping further than
    /// [`MAX_PLAUSIBLE_GAP`]. **Non-zero invalidates `loss_ratio`**, which is
    /// then `null`: it is what a wrong header-layout assumption looks like, and
    /// failing loudly here is the whole point of the field.
    implausible: u64,
    /// `gaps / (gaps + in_sequence)`. `null` when there is nothing to divide, or
    /// when `implausible` is non-zero.
    loss_ratio: Option<f64>,
}

#[tokio::main]
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

    if let Some(n) = args.tunnels {
        if args.watch {
            return Err(ExitCategory::Config(anyhow!(
                "--tunnels is a state-occupancy mode; combining with --watch is rejected"
            )));
        }
        return run_tunnels(&args, n, shutdown_mode).await;
    }

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
    let family_str = validate_families(&args, resolved_relay)?;

    let mut data_rx = gw.subscribe_data();

    // Two clocks, deliberately. `started` runs from before subscribe() and
    // feeds `first_data`, whose pre-existing meaning is "time from invocation
    // to first data" and so legitimately includes join latency. `data_started`
    // runs from AFTER the handshake and feeds `elapsed_ms`, which exists to be
    // a rate denominator — folding a variable handshake into it is exactly the
    // startup constant the field was added to eliminate (BLO-33456).
    let started = Instant::now();
    gw.subscribe(args.group, Some(args.source))
        .await
        .map_err(ExitCategory::HandshakeFail)?;
    let data_started = Instant::now();

    // One overall deadline for the whole data phase, established before the
    // first recv and shared by every packet. Previously each packet got a fresh
    // `--timeout`, so an N-packet run could run for N x timeout.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout);

    let mut packet_count: u64 = 0;
    let mut byte_count: u64 = 0;
    let mut first_evt = None;
    let mut first_data_ms = None;
    let mut elapsed_ms = None;
    // Held, not returned, until the report has been emitted: the partial counts
    // are the point of the probe and must survive the failure path.
    let mut stopped: Option<RecvStop> = None;
    let mut lagged_count: u64 = 0;
    let mut seq = SeqTracker::default();

    while packet_count < args.packet_count {
        match recv_first_matching(
            &mut data_rx,
            args.group,
            args.source,
            deadline,
            &mut lagged_count,
        )
        .await
        {
            Ok(evt) => {
                packet_count += 1;
                byte_count += evt.payload.len() as u64;
                seq.observe(&evt.payload);
                elapsed_ms = Some(data_started.elapsed().as_millis() as u64);
                if first_evt.is_none() {
                    first_data_ms = Some(started.elapsed().as_millis() as u64);
                    first_evt = Some(evt);
                }
            }
            Err(stop) => {
                stopped = Some(stop);
                break;
            }
        }
    }

    let outcome = stopped.map_or("ok", RecvStop::outcome);

    if args.json {
        let report = OneshotReport {
            outcome,
            packet_count,
            byte_count,
            elapsed_ms,
            lagged_count,
            first_data: first_data_ms,
            relay: resolved_relay.to_string(),
            family: family_str,
            group: args.group.to_string(),
            source: Some(args.source.to_string()),
            timings_ms: Timings {
                first_data: first_data_ms,
            },
            first_packet: first_evt.as_ref().map(|e| FirstPacket {
                src: format!("{}:{}", e.src, e.src_port),
                dst_port: e.dst_port,
                len: e.payload.len(),
                head_hex: e
                    .payload
                    .iter()
                    .take(16)
                    .map(|b| format!("{b:02x}"))
                    .collect(),
            }),
            mmtp: seq.finish(),
        };
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| ExitCategory::Fatal(e.into()))?
        );
    } else {
        let first = first_evt
            .as_ref()
            .map(|e| format!("{}:{} len={}", e.src, e.src_port, e.payload.len()))
            .unwrap_or_else(|| "none".to_string());
        println!(
            "{} — relay={} family={} group={} source={} packets={} bytes={} lagged={} elapsed={}ms first_data={}ms first_pkt={}",
            outcome,
            resolved_relay,
            family_str,
            args.group,
            args.source,
            packet_count,
            byte_count,
            lagged_count,
            elapsed_ms.map_or(-1i64, |v| v as i64),
            first_data_ms.map_or(-1i64, |v| v as i64),
            first,
        );
    }

    // Exit-code semantics unchanged: any early stop is still HandshakeFail
    // (exit 1). The only change is that the report is on stdout first.
    if let Some(stop) = stopped {
        return Err(ExitCategory::HandshakeFail(
            stop.into_err(args.group, args.source),
        ));
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

/// Receive the next packet matching (group, source), bounded by a caller-owned
/// OVERALL `deadline` rather than a per-call duration — so successive calls
/// share one budget instead of each getting a fresh one.
///
/// `lagged` accumulates packets the broadcast channel dropped before this
/// process could dequeue them. They are NOT counted in `packet_count`, so a
/// non-zero value means the reported rate understates what the relay delivered
/// — a receiver-side artifact that must not be read as relay loss.
async fn recv_first_matching(
    rx: &mut tokio::sync::broadcast::Receiver<amt_protocol::native::DataEvent>,
    group: IpAddr,
    source: IpAddr,
    deadline: tokio::time::Instant,
    lagged: &mut u64,
) -> std::result::Result<amt_protocol::native::DataEvent, RecvStop> {
    use tokio::sync::broadcast::error::RecvError;
    loop {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or(RecvStop::Deadline)?;
        let recv = tokio::time::timeout(remaining, rx.recv())
            .await
            .map_err(|_| RecvStop::Deadline)?;
        match recv {
            Ok(evt) if evt.group == group && evt.src == source => return Ok(evt),
            Ok(_skip) => continue,
            Err(RecvError::Lagged(skipped)) => {
                *lagged += skipped;
                continue;
            }
            Err(RecvError::Closed) => return Err(RecvStop::Closed),
        }
    }
}

fn timed_out_err(group: IpAddr, source: IpAddr) -> anyhow::Error {
    anyhow!("--timeout deadline expired waiting for data matching ({group}, {source})")
}

/// Why the data phase stopped early. These are NOT interchangeable: only
/// `Deadline` is a `--timeout` expiry, i.e. a valid observation that the stream
/// was slower than the budget. `Closed` means the tunnel's data broadcast went
/// away, so the partial counts stop for a transport reason and reporting them
/// as `outcome: "timeout"` would fabricate a deadline observation that never
/// happened. Both still emit a report — the counts banked before the stop are
/// real either way (BLO-33456) — but under distinct `outcome` values.
#[derive(Copy, Clone, Debug)]
enum RecvStop {
    Deadline,
    Closed,
}

impl RecvStop {
    fn outcome(self) -> &'static str {
        match self {
            RecvStop::Deadline => "timeout",
            RecvStop::Closed => "closed",
        }
    }

    fn into_err(self, group: IpAddr, source: IpAddr) -> anyhow::Error {
        match self {
            RecvStop::Deadline => timed_out_err(group, source),
            RecvStop::Closed => anyhow!(
                "data broadcast closed before the requested packet count was reached ({group}, {source})"
            ),
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

/// Shared family inference + cross-argument family agreement. Returns the
/// effective family as the string used in JSON output.
fn validate_families(
    args: &Args,
    relay: IpAddr,
) -> std::result::Result<&'static str, ExitCategory> {
    let inferred = if relay.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    };
    let effective = match args.family {
        Family::Auto => inferred,
        explicit => {
            let same = matches!(
                (explicit, inferred),
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
    if args.group.is_ipv4() != args.source.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --source must be the same IP family"
        )));
    }
    if args.group.is_ipv4() != relay.is_ipv4() {
        return Err(ExitCategory::Config(anyhow!(
            "--group and --relay must be the same IP family"
        )));
    }
    Ok(match effective {
        Family::V4 => "v4",
        Family::V6 => "v6",
        Family::Auto => unreachable!(),
    })
}

// ---------------------------------------------------------------------------
// Tunnel-state mode (--tunnels N). See the `tunnels` arg docs for what this
// does and does not measure.
// ---------------------------------------------------------------------------

/// Emitted verbatim into every JSON report so the measurement's scope cannot be
/// separated from the numbers it produced (BLO-33457 acceptance criterion).
const CONTROL_PLANE_CAVEAT: &str = "Idle tunnels: this is the relay's CONTROL-PLANE tunnel-table \
ceiling, not a loaded-state ceiling. An idle tunnel may cost a relay less state than an active \
one. Comparable to a configured control-plane limit (Junos tunnel-limit, Linux AMT_MAX_TUNNELS); \
NOT comparable to a measured loaded ceiling. Client-side counts must be corroborated by relay-side \
amt_relay_active_tunnels at each step.";

/// Per-tunnel result. `establish_ms` is wall-clock from gateway construction to
/// the gateway reporting `Active`.
enum TunnelOutcome {
    Alive {
        establish_ms: u64,
        keepalives: u64,
        rx: u64,
    },
    /// Established, then failed the survival check at the end of the hold.
    NotAlive { reason: &'static str },
    /// Never established.
    Failed { error: String },
}

#[derive(serde::Serialize)]
struct TunnelsReport {
    outcome: &'static str,
    mode: &'static str,
    relay: String,
    family: &'static str,
    group: String,
    source: String,
    requested: u32,
    established: u32,
    alive: u32,
    hold_secs: u64,
    keepalive_secs: u64,
    stagger_ms: u64,
    establish_ms: Option<Spread>,
    /// Lowest per-tunnel keep-alive count among ALIVE tunnels. >= 1 is what
    /// makes "survived one keep-alive interval" a measurement rather than an
    /// assumption; the aggregate hides a single tunnel that sent none.
    keepalives_min: u64,
    /// Relay-originated datagrams summed across tunnels. Zero is expected and
    /// is NOT evidence of death: an AMT relay owes an idle established gateway
    /// no unprompted traffic.
    rx_datagrams_total: u64,
    /// Establishment failures grouped by message. Watch for host-side limits
    /// here ("Too many open files") — those are the INSTRUMENT's ceiling, not
    /// the relay's, and must not be recorded as a state knee.
    establish_errors: BTreeMap<String, u32>,
    /// Post-hold survival failures grouped by reason. As with
    /// `establish_errors`, separate the INSTRUMENT from the relay:
    /// `fatal_runtime_error` is this process's socket dying and must not be
    /// recorded as a state knee, whereas `state_left_active` /
    /// `no_keepalive_sent` are the tunnel genuinely failing to survive.
    not_alive: BTreeMap<String, u32>,
    caveat: &'static str,
}

#[derive(serde::Serialize)]
struct Spread {
    min: u64,
    p50: u64,
    max: u64,
}

fn spread(mut v: Vec<u64>) -> Option<Spread> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(Spread {
        min: v[0],
        p50: v[v.len() / 2],
        max: v[v.len() - 1],
    })
}

#[allow(clippy::too_many_arguments)]
fn summarize(
    outcomes: Vec<TunnelOutcome>,
    requested: u32,
    relay: IpAddr,
    family: &'static str,
    group: IpAddr,
    source: IpAddr,
    hold_secs: u64,
    keepalive_secs: u64,
    stagger_ms: u64,
) -> TunnelsReport {
    let mut alive = 0u32;
    let mut established = 0u32;
    let mut establish_times = Vec::new();
    let mut keepalives_min = u64::MAX;
    let mut rx_total = 0u64;
    let mut establish_errors: BTreeMap<String, u32> = BTreeMap::new();
    let mut not_alive: BTreeMap<String, u32> = BTreeMap::new();

    for o in outcomes {
        match o {
            TunnelOutcome::Alive {
                establish_ms,
                keepalives,
                rx,
            } => {
                alive += 1;
                established += 1;
                establish_times.push(establish_ms);
                keepalives_min = keepalives_min.min(keepalives);
                rx_total += rx;
            }
            TunnelOutcome::NotAlive { reason } => {
                established += 1;
                *not_alive.entry(reason.to_string()).or_insert(0) += 1;
            }
            TunnelOutcome::Failed { error } => {
                *establish_errors.entry(error).or_insert(0) += 1;
            }
        }
    }

    TunnelsReport {
        // A shortfall anywhere is `degraded`, including a tunnel that
        // established and then died: the quantity this mode reports is
        // SURVIVING state, so counting a dead tunnel as a clean step is the
        // exact false-negative the survival check exists to prevent.
        outcome: if alive == requested { "ok" } else { "degraded" },
        mode: "tunnels",
        relay: relay.to_string(),
        family,
        group: group.to_string(),
        source: source.to_string(),
        requested,
        established,
        alive,
        hold_secs,
        keepalive_secs,
        stagger_ms,
        establish_ms: spread(establish_times),
        keepalives_min: if alive == 0 { 0 } else { keepalives_min },
        rx_datagrams_total: rx_total,
        establish_errors,
        not_alive,
        caveat: CONTROL_PLANE_CAVEAT,
    }
}

async fn run_tunnels(
    args: &Args,
    n: u32,
    shutdown_mode: ShutdownMode,
) -> std::result::Result<(), ExitCategory> {
    // Resolve the relay ONCE and reuse it for every gateway. N DRIAD lookups
    // would be N times the load on the resolver for one identical answer, and
    // a resolver-side failure at high N would read as a relay-side state knee.
    let relay = match args.relay {
        Some(r) => r,
        None => amt_protocol::native::resolver::resolve_amt_relay(args.source)
            .await
            .map_err(ExitCategory::HandshakeFail)?,
    };
    let family_str = validate_families(args, relay)?;

    let hold_secs = args.hold.unwrap_or(args.keepalive + 10);
    if hold_secs <= args.keepalive {
        return Err(ExitCategory::Config(anyhow!(
            "--hold ({hold_secs}s) must exceed --keepalive ({}s), otherwise no tunnel can emit a \
             keep-alive and every tunnel fails the survival check",
            args.keepalive
        )));
    }

    let (group, source, port, timeout, keepalive, stagger_ms) = (
        args.group,
        args.source,
        args.port,
        args.timeout,
        Duration::from_secs(args.keepalive),
        args.stagger_ms,
    );

    let mut set = tokio::task::JoinSet::new();
    for i in 0..n {
        set.spawn(async move {
            tokio::time::sleep(Duration::from_millis(stagger_ms * i as u64)).await;
            let t0 = Instant::now();
            let gw = match AsyncAmtGateway::builder(relay)
                .relay_port(port)
                .keepalive(keepalive)
                // This mode never reads data, so the default 1024-slot ring
                // and 64 KiB receive buffer would be ~1.2 GiB of instrument
                // across 8192 gateways — a host-side ceiling masquerading as a
                // relay-side one.
                .data_capacity(2)
                .recv_buf_bytes(4096)
                .build()
                .await
            {
                Ok(g) => g,
                Err(e) => {
                    return TunnelSlot::Failed(format!("{e}"));
                }
            };
            if let Err(e) = gw.subscribe(group, Some(source)).await {
                return TunnelSlot::Failed(format!("subscribe: {e}"));
            }
            // ponytail: poll for Active — the gateway exposes no state-change
            // signal. 250 ms bounds establishment-latency resolution, which is
            // ample for a state-occupancy ramp. Add a watch channel if a
            // latency measurement ever needs finer granularity.
            let deadline = Instant::now() + Duration::from_secs(timeout);
            loop {
                if gw.state() == GatewayState::Active {
                    return TunnelSlot::Up(gw, t0.elapsed().as_millis() as u64);
                }
                if Instant::now() >= deadline {
                    return TunnelSlot::Failed(format!(
                        "timed out after {timeout}s in state {:?}",
                        gw.state()
                    ));
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }

    let mut up: Vec<(AsyncAmtGateway, u64)> = Vec::new();
    let mut outcomes: Vec<TunnelOutcome> = Vec::new();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(TunnelSlot::Up(gw, ms)) => up.push((gw, ms)),
            Ok(TunnelSlot::Failed(error)) => outcomes.push(TunnelOutcome::Failed { error }),
            Err(e) => outcomes.push(TunnelOutcome::Failed {
                error: format!("task join: {e}"),
            }),
        }
    }

    eprintln!(
        "amt-verify: {}/{} tunnels established, holding {}s for keep-alive survival",
        up.len(),
        n,
        hold_secs
    );
    tokio::time::sleep(Duration::from_secs(hold_secs)).await;

    for (gw, establish_ms) in &up {
        let keepalives = gw.keepalives_sent();
        let rx = gw.rx_datagrams();
        outcomes.push(if gw.has_fatal().await {
            // Unrecoverable socket error in this gateway's runtime. Attributed
            // separately from `state_left_active` because it is the INSTRUMENT
            // failing, not the relay evicting state — reading a host-side send
            // failure as a relay knee is how a ramp under-reports the ceiling.
            TunnelOutcome::NotAlive {
                reason: "fatal_runtime_error",
            }
        } else if gw.state() != GatewayState::Active {
            TunnelOutcome::NotAlive {
                reason: "state_left_active",
            }
        } else if keepalives == 0 {
            // Held past one full keep-alive interval and emitted nothing: the
            // tunnel was established but is not demonstrably maintained, so it
            // must not be counted as live state.
            TunnelOutcome::NotAlive {
                reason: "no_keepalive_sent",
            }
        } else {
            TunnelOutcome::Alive {
                establish_ms: *establish_ms,
                keepalives,
                rx,
            }
        });
    }

    let report = summarize(
        outcomes,
        n,
        relay,
        family_str,
        group,
        source,
        hold_secs,
        args.keepalive,
        stagger_ms,
    );
    let degraded = report.outcome == "degraded";

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&report).map_err(|e| ExitCategory::Fatal(e.into()))?
        );
    } else {
        println!(
            "{} — relay={} family={} group={} source={} requested={} established={} alive={} \
             keepalives_min={} rx={} hold={}s\nCAVEAT: {}",
            report.outcome,
            report.relay,
            report.family,
            report.group,
            report.source,
            report.requested,
            report.established,
            report.alive,
            report.keepalives_min,
            report.rx_datagrams_total,
            report.hold_secs,
            CONTROL_PLANE_CAVEAT,
        );
        for (err, count) in &report.establish_errors {
            println!("  establish_error x{count}: {err}");
        }
        for (reason, count) in &report.not_alive {
            println!("  not_alive x{count}: {reason}");
        }
    }

    // Tear down concurrently. Leaving state behind would inflate the next ramp
    // step; confirm relay-side amt_relay_active_tunnels returns to baseline
    // between steps rather than trusting this.
    let mut teardown = tokio::task::JoinSet::new();
    for (gw, _) in up {
        teardown.spawn(async move { finish_gateway(gw, group, source, shutdown_mode).await });
    }
    while let Some(r) = teardown.join_next().await {
        if let Ok(Err(e)) = r {
            tracing::warn!(target: "amt", error=?e, "teardown failed");
        }
    }

    if degraded {
        // Exit non-zero so a `set -e` ramp driver stops at the knee. The JSON
        // report is printed either way and carries the numbers.
        return Err(ExitCategory::HandshakeFail(anyhow!(
            "{}/{} tunnels alive after {}s hold",
            report.alive,
            report.requested,
            report.hold_secs
        )));
    }
    Ok(())
}

/// Intermediate: a gateway must outlive the establish phase to be held, so the
/// spawn tasks hand it back rather than reporting a final outcome.
enum TunnelSlot {
    Up(AsyncAmtGateway, u64),
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use amt_protocol::native::DataEvent;
    use bytes::Bytes;

    fn evt(src: [u8; 4], group: [u8; 4]) -> DataEvent {
        DataEvent {
            src: IpAddr::from(src),
            group: IpAddr::from(group),
            src_port: 5004,
            dst_port: 5005,
            payload: Bytes::from_static(b"x"),
        }
    }

    const SRC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
    const GROUP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(232, 0, 0, 1));

    // BLO-33456 review follow-up. A closed data broadcast and an expired
    // deadline both ended the data phase via the same `anyhow::Error`, so a
    // transport failure was reported as `outcome: "timeout"` — a deadline
    // observation that never happened. These two cases must stay distinct.
    #[tokio::test(flavor = "current_thread")]
    async fn closed_broadcast_is_not_reported_as_a_deadline_expiry() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<DataEvent>(8);
        drop(tx);

        let mut lagged = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let stop = recv_first_matching(&mut rx, GROUP, SRC, deadline, &mut lagged)
            .await
            .expect_err("closed channel must stop the data phase");

        assert!(matches!(stop, RecvStop::Closed), "{stop:?}");
        assert_eq!(stop.outcome(), "closed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_deadline_is_reported_as_a_timeout() {
        // Sender held open, so the only thing that can end the wait is the
        // deadline — the control for the test above.
        let (_tx, mut rx) = tokio::sync::broadcast::channel::<DataEvent>(8);

        let mut lagged = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(50);
        let stop = recv_first_matching(&mut rx, GROUP, SRC, deadline, &mut lagged)
            .await
            .expect_err("expired deadline must stop the data phase");

        assert!(matches!(stop, RecvStop::Deadline), "{stop:?}");
        assert_eq!(stop.outcome(), "timeout");
    }

    // Non-matching traffic must not consume the budget as a match, and lagged
    // packets must be counted but not returned.
    #[tokio::test(flavor = "current_thread")]
    async fn non_matching_packets_are_skipped_and_matching_one_returned() {
        let (tx, mut rx) = tokio::sync::broadcast::channel::<DataEvent>(8);
        tx.send(evt([10, 0, 0, 9], [232, 0, 0, 1])).unwrap(); // wrong source
        tx.send(evt([10, 0, 0, 1], [232, 0, 0, 9])).unwrap(); // wrong group
        tx.send(evt([10, 0, 0, 1], [232, 0, 0, 1])).unwrap(); // match

        let mut lagged = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let got = recv_first_matching(&mut rx, GROUP, SRC, deadline, &mut lagged)
            .await
            .expect("matching packet");

        assert_eq!(got.src, SRC);
        assert_eq!(got.group, GROUP);
        assert_eq!(lagged, 0);
    }

    /// Minimal MMTP packet: version 0, `packet_id` at 2..4, sequence at 8..12.
    fn mmtp(packet_id: u16, seq: u32) -> Vec<u8> {
        let mut p = vec![0u8; 32];
        p[2..4].copy_from_slice(&packet_id.to_be_bytes());
        p[8..12].copy_from_slice(&seq.to_be_bytes());
        p
    }

    fn track(pkts: &[(u16, u32)]) -> MmtpLoss {
        let mut t = SeqTracker::default();
        for &(id, s) in pkts {
            t.observe(&mmtp(id, s));
        }
        t.finish().expect("observed packets yield a report")
    }

    #[test]
    fn contiguous_sequence_is_zero_loss() {
        let got = track(&[(1, 10), (1, 11), (1, 12), (1, 13)]);
        assert_eq!((got.gaps, got.in_sequence, got.implausible), (0, 3, 0));
        assert_eq!(got.loss_ratio, Some(0.0));
    }

    /// The whole point of the field: loss is counted without any source-side
    /// count to compare against.
    #[test]
    fn missing_packets_are_counted_as_gaps() {
        let got = track(&[(1, 10), (1, 14)]);
        assert_eq!(got.gaps, 3);
        assert_eq!(got.loss_ratio, Some(3.0 / 3.0));
    }

    /// Sequence numbers are per-`packet_id`. Interleaving tracks must not read
    /// as loss — with 8 tracks on this stream that would fabricate ~100%.
    #[test]
    fn tracks_are_counted_independently() {
        let got = track(&[(1, 5), (2, 900), (1, 6), (2, 901), (4, 77), (4, 78)]);
        assert_eq!((got.gaps, got.in_sequence, got.tracks), (0, 3, 3));
        assert_eq!(got.loss_ratio, Some(0.0));
    }

    #[test]
    fn reorders_and_duplicates_are_not_loss() {
        // 12 arrives late, then 13 follows 12's predecessor: the high-water mark
        // must not have moved backwards, or 13 reads as a gap.
        let got = track(&[(1, 11), (1, 12), (1, 11), (1, 12), (1, 13)]);
        assert_eq!((got.gaps, got.reordered, got.implausible), (0, 2, 0));
    }

    /// A wrong header-layout assumption must fail loudly, not produce a precise
    /// looking number. Random payloads give huge deltas; `loss_ratio` withholds.
    #[test]
    fn implausible_jumps_withhold_the_ratio() {
        let got = track(&[(1, 1), (1, 1 + MAX_PLAUSIBLE_GAP + 1)]);
        assert_eq!(got.implausible, 1);
        assert_eq!(got.loss_ratio, None);
    }

    #[test]
    fn short_or_wrong_version_payloads_are_implausible() {
        let mut t = SeqTracker::default();
        t.observe(b"tiny");
        let mut wrong_version = mmtp(1, 1);
        wrong_version[0] = 0x40; // version 1
        t.observe(&wrong_version);
        let got = t.finish().expect("observed packets yield a report");
        assert_eq!(got.implausible, 2);
        assert_eq!(got.loss_ratio, None);
    }

    #[test]
    fn no_packets_yields_no_report() {
        assert!(SeqTracker::default().finish().is_none());
    }
}
