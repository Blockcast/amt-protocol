//! AsyncAmtGateway: tokio wrapper around one SubscriptionManager.
//!
//! Owns one UdpSocket bound for the relay's family. Drives SubscriptionManager
//! via select! over: command channel, socket recv, sleep timer, shutdown.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::config::AmtConfig;
use crate::gateway::{GatewayState, GroupKey};
use crate::subscription::{Event, SubscriptionManager};
use super::platform::NativePlatform;

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
    Subscribe { key: GroupKey, ack: oneshot::Sender<Result<()>> },
    Unsubscribe { key: GroupKey, ack: oneshot::Sender<Result<()>> },
    Shutdown { ack: oneshot::Sender<Result<()>> },
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
}

pub struct AsyncAmtGatewayBuilder {
    relay: Option<IpAddr>,
    relay_port: u16,
    keepalive: Duration,
    log_target: &'static str,
}

impl AsyncAmtGateway {
    pub fn builder(relay: IpAddr) -> AsyncAmtGatewayBuilder {
        AsyncAmtGatewayBuilder {
            relay: Some(relay),
            relay_port: 2268,
            keepalive: Duration::from_secs(AmtConfig::DEFAULT_KEEPALIVE_SECS as u64),
            log_target: "amt",
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
    pub fn relay_port(mut self, port: u16) -> Self { self.relay_port = port; self }
    pub fn keepalive(mut self, d: Duration) -> Self { self.keepalive = d; self }
    pub fn log_target(mut self, t: &'static str) -> Self { self.log_target = t; self }

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
        let (data_tx, _) = broadcast::channel::<DataEvent>(1024);
        let state = Arc::new(AtomicU8::new(state_to_u8(GatewayState::Idle)));
        let fatal: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));

        let task = tokio::spawn(run_task(
            sock,
            cfg,
            cmd_rx,
            data_tx.clone(),
            state.clone(),
            fatal.clone(),
            self.log_target,
        ));

        Ok(AsyncAmtGateway {
            cmd_tx,
            data_tx,
            state,
            task: Mutex::new(Some(task)),
            fatal,
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

async fn run_task(
    sock: UdpSocket,
    cfg: AmtConfig,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    data_tx: broadcast::Sender<DataEvent>,
    state: Arc<AtomicU8>,
    fatal: Arc<Mutex<Option<anyhow::Error>>>,
    _log_target: &'static str,
) {
    let platform = Arc::new(NativePlatform::new());
    let mut mgr = SubscriptionManager::new(cfg, platform.clone());
    let mut buf = [0u8; 65535];
    let mut shutdown_ack: Option<oneshot::Sender<Result<()>>> = None;

    loop {
        // Compute next wake. If no timer is armed, sleep a long time.
        let next_wake = mgr.next_wakeup_ms()
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
                    let target = SocketAddr::new(dst, port);
                    if let Err(e) = sock.send_to(&payload, target).await {
                        tracing::error!(target: "amt", error=?e, "socket send error (fatal)");
                        *fatal.lock().await = Some(anyhow!("socket send: {e}"));
                    }
                }
                Event::Data { src, group, src_port, dst_port, payload } => {
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
    SystemTime::now().duration_since(UNIX_EPOCH).expect("time before epoch").as_millis() as u64
}

fn duration_until(deadline_ms: u64, now_ms: u64) -> Duration {
    if deadline_ms <= now_ms { Duration::from_millis(1) }
    else { Duration::from_millis(deadline_ms - now_ms) }
}
