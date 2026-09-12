//! AsyncAmtGateway: tokio wrapper around one SubscriptionManager.
//!
//! Owns one UdpSocket bound for the relay's family. Drives SubscriptionManager
//! via select! over: command channel, socket recv, sleep timer, shutdown.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::platform::NativePlatform;
use crate::config::AmtConfig;
use crate::gateway::{GatewayState, GroupKey};
use crate::subscription::{Event, SubscriptionManager};

/// Public data event: one demultiplexed inner UDP packet.
#[derive(Debug, Clone)]
pub struct DataEvent {
    pub src: IpAddr,
    pub group: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Bytes,
}

#[derive(Debug)]
pub(crate) enum Cmd {
    Subscribe {
        key: GroupKey,
        ack: oneshot::Sender<Result<()>>,
    },
    Unsubscribe {
        key: GroupKey,
        ack: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        ack: oneshot::Sender<Result<()>>,
    },
}

pub struct AsyncAmtGateway {
    pub(crate) cmd_tx: mpsc::Sender<Cmd>,
    pub(crate) data_tx: broadcast::Sender<DataEvent>,
    pub(crate) state: Arc<AtomicU8>,
    pub(crate) task: Mutex<Option<JoinHandle<()>>>,
    /// Holds a fatal runtime error (socket bind/send/recv unrecoverable) if
    /// the spawned task exited because of one. `shutdown()` checks this and
    /// returns Err(...) instead of Ok(()) when set.
    pub(crate) fatal: Arc<Mutex<Option<anyhow::Error>>>,
    /// Membership Updates SUCCESSFULLY transmitted after the handshake
    /// completed, i.e. keep-alives. Incremented only once `send_to` has
    /// returned Ok, so a keep-alive that failed to leave the process is not
    /// counted. The initial current-state Update is excluded: the runtime
    /// drains `Transmit` before the `HandshakeComplete` that stores `Active`,
    /// so at that point `state` still reads the pre-handshake value.
    ///
    /// A tunnel is only demonstrably held across a keep-alive interval if this
    /// is >= 1. Note what it does NOT prove: it is client-side emission, not
    /// relay-side acceptance. Relay-side occupancy must come from the relay
    /// (`amt_relay_active_tunnels`) — see BLO-33457.
    pub(crate) keepalives: Arc<AtomicU64>,
    /// Datagrams received from the relay over this tunnel's socket, all types.
    /// Relay-originated, so non-zero is positive evidence the relay is still
    /// talking to us; zero is NOT evidence of death, because an AMT relay owes
    /// an idle established gateway no unprompted traffic.
    pub(crate) rx_datagrams: Arc<AtomicU64>,
}

pub struct AsyncAmtGatewayBuilder {
    relay: Option<IpAddr>,
    relay_port: u16,
    keepalive: Duration,
    log_target: &'static str,
    data_capacity: usize,
    recv_buf_bytes: usize,
}

impl AsyncAmtGateway {
    pub fn builder(relay: IpAddr) -> AsyncAmtGatewayBuilder {
        AsyncAmtGatewayBuilder {
            relay: Some(relay),
            relay_port: 2268,
            keepalive: Duration::from_secs(AmtConfig::DEFAULT_KEEPALIVE_SECS as u64),
            log_target: "amt",
            data_capacity: 1024,
            recv_buf_bytes: 65535,
        }
    }

    /// Construct a builder that will DRIAD-resolve the relay from `source`
    /// when `.build()` is awaited.
    pub fn builder_for_source(source: IpAddr) -> AsyncAmtGatewayBuilderForSource {
        AsyncAmtGatewayBuilderForSource {
            source,
            relay_port: 2268,
            keepalive: Duration::from_secs(AmtConfig::DEFAULT_KEEPALIVE_SECS as u64),
            log_target: "amt",
        }
    }

    pub fn state(&self) -> GatewayState {
        match self.state.load(Ordering::SeqCst) {
            0 => GatewayState::Idle,
            1 => GatewayState::Discovering,
            2 => GatewayState::Requesting,
            3 => GatewayState::Querying,
            4 => GatewayState::Active,
            _ => GatewayState::Closed,
        }
    }

    pub fn subscribe_data(&self) -> broadcast::Receiver<DataEvent> {
        self.data_tx.subscribe()
    }

    /// Keep-alive Membership Updates sent since the handshake completed.
    /// See the field docs for exactly what this does and does not witness.
    pub fn keepalives_sent(&self) -> u64 {
        self.keepalives.load(Ordering::Relaxed)
    }

    /// Datagrams received from the relay on this tunnel's socket.
    pub fn rx_datagrams(&self) -> u64 {
        self.rx_datagrams.load(Ordering::Relaxed)
    }

    /// True once the runtime task has recorded an unrecoverable socket error.
    ///
    /// This is the INSTRUMENT failing, not the relay withdrawing state, and the
    /// distinction matters to anything measuring a ceiling: a host-side send
    /// failure at high tunnel counts must not be recorded as a relay-side knee
    /// (BLO-33457). `state()` alone is not a sufficient liveness test — prefer
    /// checking this first when classifying a tunnel.
    pub async fn has_fatal(&self) -> bool {
        self.fatal.lock().await.is_some()
    }

    pub async fn subscribe(&self, group: IpAddr, source: Option<IpAddr>) -> Result<()> {
        let key = GroupKey { group, source };
        let (ack, rx) = oneshot::channel::<Result<()>>();
        self.cmd_tx
            .send(Cmd::Subscribe { key, ack })
            .await
            .map_err(|_| anyhow!("AsyncAmtGateway task is gone"))?;
        rx.await.map_err(|_| anyhow!("subscribe ack dropped"))?
    }

    pub async fn unsubscribe(&self, group: IpAddr, source: Option<IpAddr>) -> Result<()> {
        let key = GroupKey { group, source };
        let (ack, rx) = oneshot::channel::<Result<()>>();
        self.cmd_tx
            .send(Cmd::Unsubscribe { key, ack })
            .await
            .map_err(|_| anyhow!("AsyncAmtGateway task is gone"))?;
        rx.await.map_err(|_| anyhow!("unsubscribe ack dropped"))?
    }

    /// Initiate graceful shutdown. Waits for the runtime task to finish.
    /// Returns `Err(...)` if a fatal runtime error was observed during the
    /// lifetime of this gateway.
    pub async fn shutdown(self) -> Result<()> {
        let (ack, rx) = oneshot::channel::<Result<()>>();
        let _ = self.cmd_tx.send(Cmd::Shutdown { ack }).await;
        let _ = rx.await;
        let mut guard = self.task.lock().await;
        if let Some(handle) = guard.take() {
            handle.await.map_err(|e| anyhow!("task join: {e}"))?;
        }
        if let Some(e) = self.fatal.lock().await.take() {
            return Err(e);
        }
        Ok(())
    }
}

impl AsyncAmtGatewayBuilder {
    pub fn relay_port(mut self, port: u16) -> Self {
        self.relay_port = port;
        self
    }
    pub fn keepalive(mut self, d: Duration) -> Self {
        self.keepalive = d;
        self
    }
    pub fn log_target(mut self, t: &'static str) -> Self {
        self.log_target = t;
        self
    }
    /// Slots in this gateway's data broadcast ring. Default 1024.
    ///
    /// tokio preallocates the ring, so this is per-gateway resident memory —
    /// at the default it is ~100 KiB, which is invisible for one gateway and
    /// is ~1 GiB across 8192 of them. A caller holding many gateways purely
    /// for tunnel state (BLO-33457) should set this to a small value: the
    /// ceiling it would otherwise measure is this allocation, not the relay.
    pub fn data_capacity(mut self, n: usize) -> Self {
        self.data_capacity = n.max(1);
        self
    }

    /// Per-gateway UDP receive buffer, in bytes. Default 65535 (max UDP
    /// payload). This is one heap allocation per gateway, so it is also
    /// per-tunnel resident memory: ~512 MiB across 8192 gateways at the
    /// default.
    ///
    /// **A datagram longer than this is silently TRUNCATED by `recv_from`,**
    /// which for a data-carrying tunnel means corrupt inner packets rather
    /// than a visible error. Only lower it for control-plane-only use where
    /// no multicast data is expected (BLO-33457 tunnel-state ramp).
    pub fn recv_buf_bytes(mut self, n: usize) -> Self {
        self.recv_buf_bytes = n.max(576);
        self
    }

    /// Build and spawn the runtime task.
    pub async fn build(self) -> Result<AsyncAmtGateway> {
        let relay = self.relay.ok_or_else(|| anyhow!("relay address not set"))?;
        let bind = match relay {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let sock = UdpSocket::bind(bind).await?;
        let mut cfg = AmtConfig::new(relay, Some(self.relay_port));
        cfg.keepalive_interval_secs = self.keepalive.as_secs() as u32;

        let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>(32);
        let (data_tx, _) = broadcast::channel::<DataEvent>(self.data_capacity);
        let state = Arc::new(AtomicU8::new(state_to_u8(GatewayState::Idle)));
        let fatal: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));
        let keepalives = Arc::new(AtomicU64::new(0));
        let rx_datagrams = Arc::new(AtomicU64::new(0));

        let task = tokio::spawn(run_task(
            sock,
            cfg,
            cmd_rx,
            data_tx.clone(),
            state.clone(),
            fatal.clone(),
            keepalives.clone(),
            rx_datagrams.clone(),
            self.recv_buf_bytes,
            self.log_target,
        ));

        Ok(AsyncAmtGateway {
            cmd_tx,
            data_tx,
            state,
            task: Mutex::new(Some(task)),
            fatal,
            keepalives,
            rx_datagrams,
        })
    }
}

fn state_to_u8(s: GatewayState) -> u8 {
    match s {
        GatewayState::Idle => 0,
        GatewayState::Discovering => 1,
        GatewayState::Requesting => 2,
        GatewayState::Querying => 3,
        GatewayState::Active => 4,
        GatewayState::Closed => 5,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_task(
    sock: UdpSocket,
    cfg: AmtConfig,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    data_tx: broadcast::Sender<DataEvent>,
    state: Arc<AtomicU8>,
    fatal: Arc<Mutex<Option<anyhow::Error>>>,
    keepalives: Arc<AtomicU64>,
    rx_datagrams: Arc<AtomicU64>,
    recv_buf_bytes: usize,
    _log_target: &'static str,
) {
    let platform = Arc::new(NativePlatform::new());
    let mut mgr = SubscriptionManager::new(cfg, platform.clone());
    let mut buf = vec![0u8; recv_buf_bytes];
    let mut shutdown_ack: Option<oneshot::Sender<Result<()>>> = None;

    loop {
        // Compute next wake. If no timer is armed, sleep a long time.
        let next_wake = mgr
            .next_wakeup_ms()
            .map(|ms| Instant::now() + duration_until(ms, now_ms_local()))
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

        tokio::select! {
            biased;

            maybe_cmd = cmd_rx.recv() => {
                let Some(cmd) = maybe_cmd else { break; };
                handle_cmd(&mut mgr, cmd, now_ms_local(), &mut shutdown_ack);
            }

            r = sock.recv_from(&mut buf) => {
                match r {
                    Ok((n, _)) => {
                        rx_datagrams.fetch_add(1, Ordering::Relaxed);
                        // A datagram that exactly fills the buffer was almost
                        // certainly truncated by recv_from — the kernel gives us
                        // no way to tell those apart, and the excess is simply
                        // discarded. Silent truncation is the real hazard of the
                        // `recv_buf_bytes` knob (a lowered control-plane buffer
                        // corrupts inner packets rather than erroring), so make
                        // it audible instead of letting it corrupt quietly.
                        if n == buf.len() {
                            tracing::warn!(
                                target: "amt",
                                bytes = n,
                                "datagram filled the receive buffer and was probably \
                                 TRUNCATED; raise recv_buf_bytes if this tunnel carries data"
                            );
                        }
                        let _ = mgr.handle_datagram(&buf[..n], now_ms_local());
                    }
                    Err(e) => {
                        tracing::error!(target: "amt", error=?e, "socket recv error (fatal)");
                        *fatal.lock().await = Some(anyhow!("socket recv: {e}"));
                        break;
                    }
                }
            }

            _ = tokio::time::sleep_until(next_wake) => {
                let _ = mgr.tick(now_ms_local());
            }
        }

        // Drain events emitted this turn.
        while let Some(ev) = mgr.poll_event() {
            match ev {
                Event::Transmit { dst, port, payload } => {
                    // Sampled BEFORE the HandshakeComplete arm below stores
                    // `Active`, so the initial current-state Update is excluded
                    // and this counts keep-alives only. See field docs.
                    let is_keepalive =
                        state.load(Ordering::SeqCst) == state_to_u8(GatewayState::Active);
                    let target = SocketAddr::new(dst, port);
                    if let Err(e) = sock.send_to(&payload, target).await {
                        tracing::error!(target: "amt", error=?e, "socket send error (fatal)");
                        *fatal.lock().await = Some(anyhow!("socket send: {e}"));
                    } else if is_keepalive {
                        // Only after the datagram has actually left the process.
                        // Counting before the send let a FAILED keep-alive leave
                        // `state == Active && keepalives_sent >= 1`, which is the
                        // exact shape a caller reads as a surviving tunnel.
                        keepalives.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Event::Data {
                    src,
                    group,
                    src_port,
                    dst_port,
                    payload,
                } => {
                    let _ = data_tx.send(DataEvent {
                        src,
                        group,
                        src_port,
                        dst_port,
                        payload: Bytes::from(payload),
                    });
                }
                Event::HandshakeComplete => {
                    state.store(state_to_u8(GatewayState::Active), Ordering::SeqCst);
                    tracing::info!(target: "amt", "AMT tunnel up");
                }
                Event::Warning(e) => {
                    tracing::warn!(target: "amt", error=?e, "subscription warning");
                }
            }
        }
        state.store(state_to_u8(mgr.state()), Ordering::SeqCst);

        // Exit when manager is closed (shutdown completed) OR a fatal error.
        if mgr.is_closed() || fatal.lock().await.is_some() {
            if let Some(ack) = shutdown_ack.take() {
                let _ = ack.send(Ok(()));
            }
            break;
        }
    }

    // Every exit above means this task is gone: graceful close, dropped command
    // channel, or a fatal socket error. `mgr` does not observe socket failures,
    // so after a fatal send/recv it still reports `Active` — and the store above
    // would publish that as the final public state, leaving a DEAD tunnel
    // readable as a live one. The recv-error arm also breaks past that store
    // entirely. Publishing Closed here is what makes `state()` honest on every
    // path, so no caller can count a dead gateway as occupancy (BLO-33457).
    state.store(state_to_u8(GatewayState::Closed), Ordering::SeqCst);
}

fn handle_cmd(
    mgr: &mut SubscriptionManager<NativePlatform>,
    cmd: Cmd,
    now_ms: u64,
    shutdown_ack: &mut Option<oneshot::Sender<Result<()>>>,
) {
    match cmd {
        Cmd::Subscribe { key, ack } => {
            let _ = ack.send(mgr.subscribe(key, now_ms).map_err(|e| anyhow!(e)));
        }
        Cmd::Unsubscribe { key, ack } => {
            let _ = ack.send(mgr.unsubscribe(&key, now_ms).map_err(|e| anyhow!(e)));
        }
        Cmd::Shutdown { ack } => {
            let r = mgr.shutdown(now_ms).map_err(|e| anyhow!(e));
            if r.is_err() {
                let _ = ack.send(r);
            } else {
                *shutdown_ack = Some(ack);
            }
        }
    }
}

pub struct AsyncAmtGatewayBuilderForSource {
    source: IpAddr,
    relay_port: u16,
    keepalive: Duration,
    log_target: &'static str,
}

impl AsyncAmtGatewayBuilderForSource {
    pub fn relay_port(mut self, port: u16) -> Self {
        self.relay_port = port;
        self
    }
    pub fn keepalive(mut self, d: Duration) -> Self {
        self.keepalive = d;
        self
    }
    pub fn log_target(mut self, t: &'static str) -> Self {
        self.log_target = t;
        self
    }

    pub async fn build(self) -> Result<AsyncAmtGateway> {
        let relay = super::resolver::resolve_amt_relay(self.source).await?;
        tracing::info!(target: "amt", relay=%relay, "DRIAD resolved relay");
        AsyncAmtGateway::builder(relay)
            .relay_port(self.relay_port)
            .keepalive(self.keepalive)
            .log_target(self.log_target)
            .build()
            .await
    }
}

fn now_ms_local() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_millis() as u64
}

fn duration_until(deadline_ms: u64, now_ms: u64) -> Duration {
    if deadline_ms <= now_ms {
        Duration::from_millis(1)
    } else {
        Duration::from_millis(deadline_ms - now_ms)
    }
}
