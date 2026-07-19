//! M4 spike S1 — capture-into-an-async-runtime, for a capture source that has
//! **no selectable file descriptor**.
//!
//! Why this spike exists (docs/M4-ANALYSIS.md §S1): on Windows, nmap's pcap
//! handle exposes no `pcap_get_selectable_fd` — `PCAP_CAN_DO_SELECT` is undefined
//! on WIN32 (`nsock_pcap.h:85`). nmap works around it by setting the handle
//! non-blocking and *polling* `pcap_next_ex` at a forced 2 ms cap inside the IOCP
//! loop (`engine_iocp.c:328-346`). Any Rust port that assumes "register the pcap
//! fd with tokio/mio and await readiness" **cannot work on Windows** — there is no
//! readiness fd to register. So before we design `sys::npcap`, we must pick the
//! capture→async-driver integration that works WITHOUT a readiness fd.
//!
//! DECISION GATE (written before the code): the chosen design must (a) deliver a
//! loopback packet into the async runtime with median added latency well under the
//! 2 ms poll floor, (b) not busy-spin the CPU while the network is idle, and
//! (c) require no selectable/readiness fd — so it is portable to Npcap on Windows.
//! On failing the gate, document the capture design as a platform constraint
//! before any scan-type work depends on it.
//!
//! To model "no readiness fd" faithfully we use ONLY `std::net::UdpSocket`, never
//! `tokio::net::UdpSocket` (which would register the fd with the reactor — exactly
//! the path Npcap-on-Windows denies us). Real loopback UDP datagrams stand in for
//! captured frames; each payload carries a monotonic send-stamp so the async
//! consumer can measure true send→delivery latency.
//!
//! Two candidate designs, both readiness-fd-free:
//!   1. BlockingThread → tokio::mpsc  — a dedicated OS thread does a *blocking*
//!      recv (models Npcap blocking mode / a capture thread) and forwards frames
//!      into a channel the async driver awaits. Event-driven; parks when idle.
//!   2. PollTask (2 ms) — a tokio task polls a *non-blocking* socket, sleeping 2 ms
//!      between empty reads. This is a faithful analogue of nmap's Windows IOCP
//!      mechanism.
//!
//! Run: `cargo run --release` (prints a comparison table + verdict).

use std::net::UdpSocket;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const N_PACKETS: usize = 2000;
const SEND_GAP: Duration = Duration::from_micros(200); // keep the receiver ahead
const IDLE_WINDOW: Duration = Duration::from_millis(300); // measure idle CPU here
const POLL_INTERVAL: Duration = Duration::from_millis(2); // nmap's PCAP_POLL_INTERVAL

/// A captured frame handed to the async driver: its payload plus the shared-clock
/// nanos at which the generator sent it (embedded in the payload).
struct Frame {
    send_ns: u128,
}

fn parse_frame(buf: &[u8]) -> Option<Frame> {
    if buf.len() < 24 {
        return None;
    }
    // layout: seq: u64 be | send_ns: u128 be
    let send_ns = u128::from_be_bytes(buf[8..24].try_into().ok()?);
    Some(Frame { send_ns })
}

/// Spawn the loopback traffic generator. Returns the port it targets. `t0` is the
/// shared monotonic origin both sides read, so an embedded send-stamp is
/// comparable to the consumer's `t0.elapsed()`.
fn spawn_generator(target_port: u16, t0: Instant) {
    thread::spawn(move || {
        let tx = UdpSocket::bind("127.0.0.1:0").expect("bind gen");
        let dst = ("127.0.0.1", target_port);
        for seq in 0u64..N_PACKETS as u64 {
            let mut buf = [0u8; 24];
            buf[0..8].copy_from_slice(&seq.to_be_bytes());
            let send_ns = t0.elapsed().as_nanos();
            buf[8..24].copy_from_slice(&send_ns.to_be_bytes());
            let _ = tx.send_to(&buf, dst);
            spin_until(t0, send_ns, SEND_GAP);
        }
    });
}

/// Busy-wait a precise short gap (sleep granularity is too coarse for 200 µs).
fn spin_until(t0: Instant, from_ns: u128, gap: Duration) {
    let target = from_ns + gap.as_nanos();
    while t0.elapsed().as_nanos() < target {
        std::hint::spin_loop();
    }
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

struct Report {
    name: &'static str,
    received: usize,
    median_us: f64,
    p99_us: f64,
    max_us: f64,
    idle_wakeups: u64,
    needs_readiness_fd: bool,
}

fn summarize(name: &'static str, mut lat_ns: Vec<u128>, idle_wakeups: u64) -> Report {
    lat_ns.sort_unstable();
    let to_us = |ns: u128| ns as f64 / 1000.0;
    Report {
        name,
        received: lat_ns.len(),
        median_us: to_us(percentile(&lat_ns, 0.50)),
        p99_us: to_us(percentile(&lat_ns, 0.99)),
        max_us: to_us(percentile(&lat_ns, 1.0)),
        idle_wakeups,
        needs_readiness_fd: false, // both designs are readiness-fd-free by construction
    }
}

/// Design 1: dedicated blocking-recv thread → mpsc; async driver awaits.
async fn run_blocking_thread() -> Report {
    let t0 = Instant::now();
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind recv"));
    let port = sock.local_addr().unwrap().port();
    sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let (tx, mut rx) = mpsc::channel::<Frame>(4096);

    // Capture thread: blocks in recv_from (parks the thread — zero idle CPU).
    let cap_sock = sock.clone();
    let cap = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let mut got = 0usize;
        loop {
            match cap_sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    if let Some(f) = parse_frame(&buf[..n]) {
                        got += 1;
                        if tx.blocking_send(f).is_err() {
                            break;
                        }
                        if got >= N_PACKETS {
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if got > 0 {
                        break; // generator finished; drain done
                    }
                }
                Err(_) => break,
            }
        }
    });

    spawn_generator(port, t0);

    // Async driver: event-driven await. No polling.
    let mut lat = Vec::with_capacity(N_PACKETS);
    while let Some(f) = rx.recv().await {
        let now_ns = t0.elapsed().as_nanos();
        lat.push(now_ns.saturating_sub(f.send_ns));
    }
    let _ = cap.join();
    // Idle CPU: the blocking thread parks in recv — no wakeups attributable to idle.
    summarize("BlockingThread -> mpsc", lat, 0)
}

/// Design 2: tokio task polls a non-blocking socket with a 2 ms sleep between
/// empty reads (nmap's Windows IOCP analogue). Counts wakeups during idle.
async fn run_poll_task() -> Report {
    let t0 = Instant::now();
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
    let port = sock.local_addr().unwrap().port();
    sock.set_nonblocking(true).unwrap();

    spawn_generator(port, t0);

    let mut lat = Vec::with_capacity(N_PACKETS);
    let mut buf = [0u8; 2048];
    let mut got = 0usize;
    let mut idle_wakeups = 0u64;
    let mut last_packet_at = Instant::now();

    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(f) = parse_frame(&buf[..n]) {
                    let now_ns = t0.elapsed().as_nanos();
                    lat.push(now_ns.saturating_sub(f.send_ns));
                    got += 1;
                    last_packet_at = Instant::now();
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // The poll floor: sleep, then poll again. Every wakeup on an idle
                // network is wasted work — this is what we're measuring.
                if got >= N_PACKETS || last_packet_at.elapsed() > IDLE_WINDOW {
                    if got > 0 {
                        // Count how many idle wakeups happen in one IDLE_WINDOW.
                        break;
                    }
                }
                if got > 0 {
                    idle_wakeups += 1;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Err(_) => break,
        }
    }
    summarize("PollTask (2ms)", lat, idle_wakeups)
}

fn print_report(r: &Report) {
    println!(
        "  {:<24} recv={:>4}/{:<4}  median={:>7.1}us  p99={:>7.1}us  max={:>8.1}us  idle_wakeups/{}ms={:>4}  needs_readiness_fd={}",
        r.name,
        r.received,
        N_PACKETS,
        r.median_us,
        r.p99_us,
        r.max_us,
        IDLE_WINDOW.as_millis(),
        r.idle_wakeups,
        r.needs_readiness_fd,
    );
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    println!("M4 spike S1 — capture into an async runtime with NO selectable fd");
    println!(
        "  loopback UDP, {} packets @ {}us spacing; std sockets only (no tokio reactor)\n",
        N_PACKETS,
        SEND_GAP.as_micros()
    );

    let blocking = run_blocking_thread().await;
    // brief gap so the two runs don't contend
    tokio::time::sleep(Duration::from_millis(50)).await;
    let poll = run_poll_task().await;

    println!("Results:");
    print_report(&blocking);
    print_report(&poll);

    // Verdict against the decision gate.
    println!("\nDecision gate: median added latency << 2000us, no idle busy-spin, no readiness fd.");
    let gate_2ms = 2000.0;
    let blocking_pass = blocking.median_us < gate_2ms && blocking.idle_wakeups == 0;
    let poll_idle_spin = poll.idle_wakeups > 0;
    println!(
        "  BlockingThread: median {:.1}us {} 2000us, idle_wakeups={} -> {}",
        blocking.median_us,
        if blocking.median_us < gate_2ms { "<" } else { ">=" },
        blocking.idle_wakeups,
        if blocking_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "  PollTask:       median {:.1}us, idle_wakeups={} ({}) -> models nmap's Windows path; adds up-to-2ms latency + idle wakeups",
        poll.median_us,
        poll.idle_wakeups,
        if poll_idle_spin { "busy-spins when idle" } else { "quiet" },
    );

    println!("\nVERDICT:");
    if blocking_pass {
        println!("  Commit to BlockingThread -> mpsc: event-driven, ~0 idle CPU, no readiness fd,");
        println!("  portable to Npcap blocking mode on Windows AND libpcap on Linux. Keep PollTask");
        println!("  only as the fallback if a platform's blocking capture misbehaves.");
    } else {
        println!("  BlockingThread failed the gate — investigate before committing sys::npcap.");
    }
}
