//! Nivyx runtime. Owns the TUN device, the userspace TCP/IP stack, and per-flow handling.
//! All outbound sockets are created through [`connector::Connector`] (protected sockets).

pub mod connector;
pub mod diag;
pub mod dns_flow;
pub mod doh;
pub mod split_io;
pub mod tcp;
pub mod tun;
pub mod udp;

use connector::{Connector, ProtectedConnector, Protector};
use ipstack::{IpStack, IpStackConfig, IpStackStream, TcpConfig};
use nivyx_core::config::Config;
use nivyx_core::dns::DnsCache;
use nivyx_core::quic::NameMap;
use nivyx_core::stats::{self, Stats};
use nivyx_core::strategy::{self, ManualRules};
use std::io;
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use tokio::sync::Notify;

/// Idle timeout for an app-facing TCP session. Long enough for push-notification keepalives.
pub const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(45 * 60);
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const TUN_MTU: u16 = 1500;

/// DNS health as exposed to the UI.
#[derive(Default)]
pub struct DnsHealth {
    pub last_ok: AtomicU64,
    pub consecutive_failures: AtomicU32,
    pub preferred: AtomicU32,
}

pub struct Shared {
    pub cfg: RwLock<Arc<Config>>,
    pub stats: Arc<Stats>,
    pub strategy: Mutex<strategy::Engine>,
    pub rules: RwLock<Arc<ManualRules>>,
    pub dns_cache: Mutex<DnsCache>,
    pub names: Mutex<NameMap>,
    pub connector: Arc<dyn Connector>,
    pub doh: doh::Doh,
    pub tls: Arc<rustls::ClientConfig>,
    pub dns_health: DnsHealth,
    pub ipv6_active: AtomicBool,
    /// False once the packet loop has ended (the watchdog uses this to fail open).
    pub alive: AtomicBool,
    /// Seconds added to the wall clock (tests advance time with this).
    pub clock_offset: AtomicU64,
    pub started: Instant,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Shared {
    pub fn new(
        cfg: Config,
        stats: Arc<Stats>,
        connector: Arc<dyn Connector>,
        tls: Arc<rustls::ClientConfig>,
    ) -> Arc<Shared> {
        let (rules, _) = ManualRules::parse(&cfg.manual_rules);
        let ipv6 = ipv6_wanted(&cfg);
        Arc::new(Shared {
            strategy: Mutex::new(strategy::Engine::new(cfg.strategy.clone())),
            dns_cache: Mutex::new(DnsCache::new(cfg.dns_cache_entries)),
            names: Mutex::new(NameMap::new(4096)),
            doh: doh::Doh::new(connector.clone(), tls.clone()),
            tls,
            connector,
            rules: RwLock::new(Arc::new(rules)),
            cfg: RwLock::new(Arc::new(cfg)),
            stats,
            dns_health: DnsHealth::default(),
            ipv6_active: AtomicBool::new(ipv6),
            alive: AtomicBool::new(true),
            clock_offset: AtomicU64::new(0),
            started: Instant::now(),
        })
    }

    pub fn cfg(&self) -> Arc<Config> {
        self.cfg.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn now(&self) -> u64 {
        unix_now() + self.clock_offset.load(Relaxed)
    }

    pub fn rules(&self) -> Arc<ManualRules> {
        self.rules.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn salt(&self) -> Vec<u8> {
        self.cfg().salt.clone().into_bytes()
    }

    /// Replace the configuration. Strategy parameters, manual rules and cache sizes take effect immediately.
    pub fn set_config(&self, cfg: Config) {
        let (rules, _) = ManualRules::parse(&cfg.manual_rules);
        *self.rules.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(rules);
        self.strategy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_params(cfg.strategy.clone());
        self.ipv6_active.store(ipv6_wanted(&cfg), Relaxed);
        *self.cfg.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(cfg);
    }

    /// The underlying network changed: re-scope learned data, drop DNS state and pooled connections.
    pub fn network_changed(&self, network_id: u64, has_ipv6: bool, system_dns: Vec<IpAddr>) {
        let mut cfg = (*self.cfg()).clone();
        cfg.network_id = network_id;
        cfg.has_ipv6 = has_ipv6;
        cfg.system_dns = system_dns;
        self.set_config(cfg);
        self.dns_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.names.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.doh.reset();
        self.dns_health.consecutive_failures.store(0, Relaxed);
        log::info!("network changed; caches reset");
    }
}

pub fn ipv6_wanted(cfg: &Config) -> bool {
    use nivyx_core::config::Ipv6Mode::*;
    match cfg.ipv6 {
        On => true,
        Off => false,
        Auto => cfg.has_ipv6,
    }
}

/// A running engine instance.
pub struct Engine {
    rt: Option<Runtime>,
    pub shared: Arc<Shared>,
    shutdown: Arc<Notify>,
}

impl Engine {
    /// Start on a real TUN fd. The fd is duplicated; the caller keeps (and must close) its own copy.
    pub fn start(tun_fd: RawFd, cfg: Config, protector: Arc<dyn Protector>) -> io::Result<Engine> {
        let stats = Arc::new(Stats::default());
        let connector: Arc<dyn Connector> =
            Arc::new(ProtectedConnector::new(protector, stats.clone()));
        // The device registers with the reactor, so it must be created inside the runtime context.
        Engine::start_with_factory(
            move || tun::TunDevice::from_dup(tun_fd),
            cfg,
            stats,
            connector,
            doh::tls_config(),
        )
    }

    /// Start on any packet device (the integration harness uses an in-memory one).
    pub fn start_with<D>(
        device: D,
        cfg: Config,
        stats: Arc<Stats>,
        connector: Arc<dyn Connector>,
        tls: Arc<rustls::ClientConfig>,
    ) -> io::Result<Engine>
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Engine::start_with_factory(move || Ok(device), cfg, stats, connector, tls)
    }

    pub fn start_with_factory<D>(
        make_device: impl FnOnce() -> io::Result<D>,
        mut cfg: Config,
        stats: Arc<Stats>,
        connector: Arc<dyn Connector>,
        tls: Arc<rustls::ClientConfig>,
    ) -> io::Result<Engine>
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        cfg.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(2)
            .thread_name("nivyx-rt")
            .enable_all()
            .build()?;
        let device = {
            let _enter = rt.enter();
            make_device()?
        };
        let shared = Shared::new(cfg, stats, connector, tls);
        let shutdown = Arc::new(Notify::new());

        let mut ipcfg = IpStackConfig::default();
        ipcfg
            .mtu_unchecked(TUN_MTU)
            .packet_information(false)
            .udp_timeout(UDP_IDLE_TIMEOUT);
        let mut tcpcfg = TcpConfig::default();
        tcpcfg.timeout = TCP_IDLE_TIMEOUT;
        ipcfg.with_tcp_config(tcpcfg);

        let sh = shared.clone();
        let sd = shutdown.clone();
        rt.spawn(async move {
            let mut stack = IpStack::new(ipcfg, device);
            loop {
                tokio::select! {
                    _ = sd.notified() => break,
                    s = stack.accept() => match s {
                        Ok(stream) => dispatch(&sh, stream),
                        Err(e) => { log::warn!("ip stack stopped: {e}"); break; }
                    }
                }
            }
            sh.alive.store(false, Relaxed);
            log::info!("accept loop ended");
        });
        Ok(Engine {
            rt: Some(rt),
            shared,
            shutdown,
        })
    }

    pub fn stats_json(&self) -> String {
        let s = self.shared.stats.snapshot();
        let sh = &self.shared;
        let now = sh.now();
        let summary = sh
            .strategy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .summary(now);
        let h = &sh.dns_health;
        let doh_ok = h.consecutive_failures.load(Relaxed) < 3;
        serde_json::json!({
            "stats": s,
            "uptime_s": sh.started.elapsed().as_secs(),
            "dns": {
                "healthy": doh_ok,
                "consecutive_failures": h.consecutive_failures.load(Relaxed),
                "last_ok_unix": h.last_ok.load(Relaxed),
                "encrypted": sh.cfg().encrypted_dns,
            },
            "strategy_summary": summary,
            "ipv6_active": sh.ipv6_active.load(Relaxed),
            "alive": sh.alive.load(Relaxed),
        })
        .to_string()
    }

    /// Run `fut` on the engine runtime and wait for it (used for diagnostics from a JNI thread).
    pub fn block_on<F: std::future::Future + Send + 'static>(&self, fut: F) -> Option<F::Output>
    where
        F::Output: Send + 'static,
    {
        let rt = self.rt.as_ref()?;
        let (tx, rx) = std::sync::mpsc::channel();
        rt.spawn(async move {
            let _ = tx.send(fut.await);
        });
        rx.recv_timeout(Duration::from_secs(30)).ok()
    }

    /// What a caller needs to run diagnostics without holding a reference to the engine.
    pub fn diag_context(&self) -> Option<(tokio::runtime::Handle, Arc<Shared>)> {
        self.rt
            .as_ref()
            .map(|rt| (rt.handle().clone(), self.shared.clone()))
    }

    pub fn diagnose(&self, host: &str) -> String {
        match self.diag_context() {
            Some((h, sh)) => diagnose_blocking(&h, sh, host),
            None => r#"{"error":"not running"}"#.to_string(),
        }
    }

    pub fn export_learned(&self) -> String {
        let now = self.shared.now();
        let items = self
            .shared
            .strategy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .export(now, 512);
        serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
    }

    pub fn import_learned(&self, json: &str) -> usize {
        if json.len() > 512 * 1024 {
            return 0;
        }
        match serde_json::from_str(json) {
            Ok(items) => {
                let items: Vec<_> = items;
                let n = items.len();
                let now = self.shared.now();
                self.shared
                    .strategy
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .import(items, now);
                n
            }
            Err(_) => 0,
        }
    }

    pub fn reset_learned(&self) {
        self.shared
            .strategy
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Stop forwarding and release the TUN duplicate. Idempotent.
    pub fn stop(&mut self) {
        self.shutdown.notify_waiters();
        self.shutdown.notify_one();
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn dispatch(sh: &Arc<Shared>, stream: IpStackStream) {
    let cfg = sh.cfg();
    match stream {
        IpStackStream::Tcp(s) => {
            if sh.stats.flows_active.load(Relaxed) as usize >= cfg.max_flows {
                log::debug!("flow limit reached; dropping new TCP flow");
                return;
            }
            let dst = s.peer_addr();
            let sh = sh.clone();
            if dst.port() == 53 {
                tokio::spawn(dns_flow::tcp_dns(sh, s));
            } else {
                tokio::spawn(tcp::handle_tcp(sh, s, dst));
            }
        }
        IpStackStream::Udp(s) => {
            if sh.stats.flows_active.load(Relaxed) as usize >= cfg.max_flows {
                return;
            }
            let dst = s.peer_addr();
            let sh = sh.clone();
            if dst.port() == 53 {
                tokio::spawn(dns_flow::udp_dns(sh, s));
            } else {
                tokio::spawn(udp::handle_udp(sh, s, dst));
            }
        }
        // ICMP and other protocols are not forwarded (no raw sockets on Android without root).
        IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {}
    }
}

/// Run diagnostics on `handle` and wait for the result. Must be called from a non-runtime thread.
pub fn diagnose_blocking(handle: &tokio::runtime::Handle, sh: Arc<Shared>, host: &str) -> String {
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    handle.spawn(async move {
        let _ = tx.send(diag::diagnose(&sh, &host).await.to_string());
    });
    rx.recv_timeout(Duration::from_secs(45))
        .unwrap_or_else(|_| r#"{"error":"diagnostics timed out or engine stopped"}"#.to_string())
}

/// RAII guard that keeps the active-flow counter accurate.
pub struct FlowGuard(Arc<Stats>);

impl FlowGuard {
    pub fn new(stats: &Arc<Stats>) -> FlowGuard {
        stats::inc(&stats.flows_active);
        FlowGuard(stats.clone())
    }
}

impl Drop for FlowGuard {
    fn drop(&mut self) {
        stats::dec(&self.0.flows_active);
    }
}
