#![allow(clippy::zombie_processes)]
//! Real-TUN benchmark. Must run inside a user+net namespace:
//!   unshare -rn target/release/examples/tunbench
//! Three processes: this one hosts ONLY the engine (so its RSS/CPU/threads are the engine's),
//! a child hosts the echo/stream server, another child generates load with kernel TCP sockets.

use nivyx_core::config::Config;
use nivyx_core::stats::Stats;
use nivyx_core::tls::testutil::client_hello;
use nivyx_engine::connector::{BoxFut, Connector};
use nivyx_engine::{tun::TunDevice, Engine};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SERVER: &str = "127.0.0.1:9000";
const TARGET: &str = "203.0.113.5:443";

struct Remap;
impl Connector for Remap {
    fn tcp(&self, _a: SocketAddr, t: Duration) -> BoxFut<tokio::net::TcpStream> {
        Box::pin(async move {
            let s = tokio::time::timeout(t, tokio::net::TcpStream::connect(SERVER))
                .await
                .map_err(|_| std::io::ErrorKind::TimedOut)??;
            s.set_nodelay(true)?;
            Ok(s)
        })
    }
    fn udp(&self, a: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        let s = std::net::UdpSocket::bind("127.0.0.1:0")?;
        s.connect(a)?;
        s.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(s)
    }
}

fn open_tun() -> std::fs::File {
    #[repr(C)]
    struct Ifr {
        name: [u8; 16],
        flags: i16,
        pad: [u8; 22],
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .expect("open /dev/net/tun");
    let mut r = Ifr {
        name: [0; 16],
        flags: 0x0001 | 0x1000,
        pad: [0; 22],
    }; // IFF_TUN | IFF_NO_PI
    r.name[..4].copy_from_slice(b"tun0");
    // SAFETY: valid fd and a correctly sized ifreq-compatible struct.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), 0x400454ca, &mut r) };
    assert!(
        rc >= 0,
        "TUNSETIFF failed: {}",
        std::io::Error::last_os_error()
    );
    f
}

fn sh(cmd: &str) {
    assert!(
        Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .status()
            .unwrap()
            .success(),
        "{cmd}"
    );
}

fn status_kb(pid: u32, key: &str) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0)
}

fn cpu_ticks(pid: u32) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let rest = s.rsplit(')').next().unwrap_or("");
    let f: Vec<&str> = rest.split_whitespace().collect();
    f.get(11).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0)
        + f.get(12).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0)
}

struct Sample {
    rss_mb: f64,
    threads: u64,
    cpu_s: f64,
}
fn sample() -> Sample {
    let pid = std::process::id();
    Sample {
        rss_mb: status_kb(pid, "VmRSS:") as f64 / 1024.0,
        threads: status_kb(pid, "Threads:"),
        cpu_s: cpu_ticks(pid) as f64 / 100.0,
    }
}

fn spawn(mode: &[&str]) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(mode)
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap()
}

fn run_client(args: &[&str]) -> String {
    let mut c = spawn(args);
    let mut out = String::new();
    c.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    c.wait().unwrap();
    out.trim().to_string()
}

// ------------------------------------------------------------------ server / client roles

fn server() {
    let l = TcpListener::bind(SERVER).unwrap();
    for s in l.incoming().flatten() {
        std::thread::spawn(move || {
            let mut s = s;
            s.set_nodelay(true).ok();
            let mut hello = [0u8; 4096];
            let n = s.read(&mut hello).unwrap_or(0);
            if n == 0 {
                return;
            }
            // Mode byte is carried in the SNI's first label: "d..." = stream down, "h..." = hello+echo.
            let down = hello[..n].windows(5).any(|w| w == b"down.");
            if s.write_all(&[0x16, 3, 3, 0, 4, 2, 0, 0, 0]).is_err() {
                return;
            }
            if down {
                let buf = vec![0x5au8; 64 * 1024];
                while s.write_all(&buf).is_ok() {}
            } else {
                let mut b = [0u8; 4096];
                while let Ok(n) = s.read(&mut b) {
                    if n == 0 || s.write_all(&b[..n]).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

fn connect_hello(sni: &str) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(TARGET)?;
    s.set_nodelay(true)?;
    s.write_all(&client_hello(sni))?;
    let mut h = [0u8; 9];
    s.read_exact(&mut h)?;
    Ok(s)
}

fn client(args: &[String]) {
    match args[0].as_str() {
        "down" => {
            let (conns, secs): (usize, u64) = (args[1].parse().unwrap(), args[2].parse().unwrap());
            let hs: Vec<_> = (0..conns)
                .map(|_| {
                    std::thread::spawn(move || {
                        let mut s = connect_hello("down.example.com").unwrap();
                        let end = Instant::now() + Duration::from_secs(secs);
                        let mut total = 0u64;
                        let mut b = vec![0u8; 256 * 1024];
                        while Instant::now() < end {
                            match s.read(&mut b) {
                                Ok(n) if n > 0 => total += n as u64,
                                _ => break,
                            }
                        }
                        total
                    })
                })
                .collect();
            let total: u64 = hs.into_iter().map(|h| h.join().unwrap()).sum();
            println!("{:.1}", total as f64 * 8.0 / secs as f64 / 1e6);
        }
        "short" => {
            let (total, conc): (usize, usize) =
                (args[1].parse().unwrap(), args[2].parse().unwrap());
            let per = total / conc;
            let hs: Vec<_> = (0..conc)
                .map(|i| {
                    std::thread::spawn(move || {
                        let mut lat = Vec::with_capacity(per);
                        let mut fail = 0;
                        for j in 0..per {
                            let t = Instant::now();
                            match connect_hello(&format!("h{i}x{j}.example.com")) {
                                Ok(mut s) => {
                                    lat.push(t.elapsed().as_micros() as u64);
                                    let _ = s.write_all(b"x");
                                    let mut b = [0u8; 1];
                                    let _ = s.read(&mut b);
                                }
                                Err(_) => fail += 1,
                            }
                        }
                        (lat, fail)
                    })
                })
                .collect();
            let mut lat = Vec::new();
            let mut fail = 0;
            for h in hs {
                let (l, f) = h.join().unwrap();
                lat.extend(l);
                fail += f;
            }
            lat.sort_unstable();
            let p = |q: f64| {
                lat.get(((lat.len() as f64) * q) as usize)
                    .copied()
                    .unwrap_or(0)
            };
            println!(
                "ok={} fail={} p50_us={} p99_us={}",
                lat.len(),
                fail,
                p(0.5),
                p(0.99)
            );
        }
        "hold" => {
            let n: usize = args[1].parse().unwrap();
            let conns: Vec<_> = (0..n)
                .filter_map(|i| connect_hello(&format!("h{i}.hold.example.com")).ok())
                .collect();
            println!("{}", conns.len());
            std::io::stdout().flush().unwrap();
            let mut s = String::new();
            let _ = std::io::stdin().read_line(&mut s); // wait until the parent says release
        }
        "pingpong" => {
            let n: usize = args[1].parse().unwrap();
            let target_direct = args.get(2).is_some_and(|a| a == "direct");
            let mut s = if target_direct {
                let mut s = TcpStream::connect(SERVER).unwrap();
                s.set_nodelay(true).unwrap();
                s.write_all(&client_hello("h.example.com")).unwrap();
                let mut h = [0u8; 9];
                s.read_exact(&mut h).unwrap();
                s
            } else {
                connect_hello("h.example.com").unwrap()
            };
            let msg = [7u8; 64];
            let mut b = [0u8; 64];
            let t = Instant::now();
            for _ in 0..n {
                s.write_all(&msg).unwrap();
                s.read_exact(&mut b).unwrap();
            }
            println!("{:.0}", t.elapsed().as_micros() as f64 / n as f64);
        }
        _ => {}
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("--server") {
        return server();
    }
    if args.first().map(|s| s.as_str()) == Some("--client") {
        return client(&args[1..]);
    }

    sh("ip link set lo up");
    let f = open_tun();
    sh("ip addr add 198.18.0.2/24 dev tun0 && ip link set tun0 up && ip route add 203.0.113.0/24 dev tun0");
    let mut srv = spawn(&["--server"]);
    std::thread::sleep(Duration::from_millis(300));

    let raw = f.as_raw_fd();
    let before_engine = sample();
    let stats = Arc::new(Stats::default());
    let mut cfg = Config {
        salt: "bench".into(),
        resolvers: vec![],
        ..Config::default()
    };
    cfg.max_flows = 4096;
    let mut engine = Engine::start_with_factory(
        move || TunDevice::from_dup(raw),
        cfg,
        stats.clone(),
        Arc::new(Remap),
        nivyx_engine::doh::tls_config(),
    )
    .unwrap();
    let me = std::process::id();
    let apk_note = |s: &Sample| format!("rss={:.1}MB threads={}", s.rss_mb, s.threads);
    println!("baseline (pre-engine): {}", apk_note(&before_engine));

    if let Ok(n) = std::env::var("BENCH_SHORT_ONLY") {
        let conc = std::env::var("BENCH_CONC").unwrap_or("10".into());
        let out = run_client(&["--client", "short", &n, &conc]);
        for t in [1, 4, 8, 12] {
            std::thread::sleep(Duration::from_secs(if t == 1 { 1 } else { 4 }));
            println!(
                "t+{t}: flows_active={} rss={:.1}MB",
                stats.snapshot().flows_active,
                sample().rss_mb
            );
        }
        println!("{out}");
        engine.stop();
        let _ = srv.kill();
        return;
    }
    if let Ok(n) = std::env::var("BENCH_DOWN_ONLY") {
        let mbps = run_client(&["--client", "down", &n, "3"]);
        println!("down {mbps}");
        for t in 0..8 {
            println!(
                "t+{}s flows_active={}",
                t * 5,
                stats.snapshot().flows_active
            );
            std::thread::sleep(Duration::from_secs(5));
        }
        engine.stop();
        let _ = srv.kill();
        return;
    }
    // 1. idle
    std::thread::sleep(Duration::from_secs(2));
    let a = sample();
    std::thread::sleep(Duration::from_secs(10));
    let b = sample();
    println!(
        "idle 10s: {} cpu={:.2}s ({:.3}% of one core)",
        apk_note(&b),
        b.cpu_s - a.cpu_s,
        (b.cpu_s - a.cpu_s) / 10.0 * 100.0
    );

    // 2. latency
    let direct = run_client(&["--client", "pingpong", "20000", "direct"]);
    let via = run_client(&["--client", "pingpong", "20000"]);
    println!("pingpong 64B RTT: direct loopback {direct} us, via engine {via} us");

    // 3. throughput
    for conns in [1usize, 4] {
        let a = sample();
        let mbps = run_client(&["--client", "down", &conns.to_string(), "6"]);
        let b = sample();
        println!(
            "download x{conns}: {mbps} Mbit/s, engine cpu {:.0}% of one core, {}",
            (b.cpu_s - a.cpu_s) / 6.0 * 100.0,
            apk_note(&b)
        );
    }

    // 4. many short connections
    let a = sample();
    let t = Instant::now();
    let out = run_client(&["--client", "short", "10000", "50"]);
    let el = t.elapsed().as_secs_f64();
    let b = sample();
    println!(
        "10000 short TLS conns (50 parallel): {out}; {:.0} conn/s; engine cpu {:.2}s; {}",
        10000.0 / el,
        b.cpu_s - a.cpu_s,
        apk_note(&b)
    );
    std::thread::sleep(Duration::from_secs(3));
    let s = stats.snapshot();
    println!(
        "after short burst: flows_active={} total={} rss={:.1}MB threads={}",
        s.flows_active,
        s.connections_total,
        sample().rss_mb,
        sample().threads
    );

    // 5. per-flow memory with N idle open connections
    let base = sample();
    let mut hold = spawn(&["--client", "hold", "1000"]);
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(hold.stdout.as_mut().unwrap()),
        &mut line,
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let held = sample();
    let flows = stats.snapshot().flows_active;
    println!("{} idle open connections (engine flows_active={flows}): rss {:.1}MB -> {:.1}MB = {:.1} KB/flow", line.trim(), base.rss_mb, held.rss_mb, (held.rss_mb - base.rss_mb) * 1024.0 / flows.max(1) as f64);
    drop(hold.stdin.take());
    hold.wait().unwrap();
    std::thread::sleep(Duration::from_secs(5));
    let s = stats.snapshot();
    println!(
        "after release: flows_active={} rss={:.1}MB threads={}",
        s.flows_active,
        sample().rss_mb,
        sample().threads
    );

    let _ = me;
    engine.stop();
    let _ = srv.kill();
}
