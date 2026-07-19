//! Connect-scan driver — the tokio event loop that turns the pure
//! [`nmap_core::engine`] decisions into real TCP connects. Every *decision*
//! (may I send? which probe? is the host done?) lives in `core` as a pure,
//! Miri-checked state machine; this module only performs the I/O those decisions
//! call for and feeds the outcomes back. Built on tokio's safe task API — **no
//! `unsafe`**.
//!
//! Milestone 2 drives a whole **host group** through a single event loop: each
//! host has its own [`HostScheduler`] (congestion window + adaptive timeout +
//! retransmission), while a shared [`GroupScheduler`] bounds the *total* probes
//! in flight across all hosts and an optional [`RateLimiter`] enforces
//! `--min-rate`/`--max-rate`. One [`JoinSet`] holds every in-flight probe; the
//! loop launches whatever the gates permit, then blocks on the next completion —
//! so it can never spin and, with work outstanding, always has a probe in flight
//! to wake it (the liveness argument the winlsof retrospective asks for).

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use nmap_core::engine::{GroupScheduler, HostScheduler, Probe, RateLimiter, RateVerdict};
use nmap_core::model::{Host, HostState, Port, PortState, Protocol, Reason, ScanResults};
use nmap_core::timing::{TimingParams, TimingTemplate};
use tokio::task::JoinSet;

use crate::net::{tcp_connect, ConnectResult};

/// What to scan and how aggressively — assembled by the CLI from the parsed ports
/// and the timing template.
#[derive(Clone, Debug)]
pub struct ConnectScanConfig {
    /// TCP ports to probe.
    pub ports: Vec<u16>,
    /// Timing template (`-T0..-T5`) driving congestion control and the initial
    /// RTT timeout.
    pub template: TimingTemplate,
    /// Hard ceiling on concurrent connects per host (nmap's `--max-parallelism`;
    /// `0` = the template default). Caps each congestion window.
    pub max_parallelism: usize,
    /// `--min-rate` (probes/sec); `None` = unset.
    pub min_rate: Option<f64>,
    /// `--max-rate` (probes/sec); `None` = unset.
    pub max_rate: Option<f64>,
}

/// Per-host mutable state carried through the group event loop.
struct HostCtx {
    sched: HostScheduler,
    host: Host,
    /// Finalized port outcomes, recorded as each port resolves.
    finals: Vec<(u16, PortState, Reason)>,
}

/// Run an unprivileged TCP connect scan over `targets` (already-resolved IPs) as a
/// single congestion-controlled host group, returning the populated
/// [`ScanResults`] in target order.
pub async fn connect_scan(targets: &[IpAddr], config: &ConnectScanConfig) -> ScanResults {
    let max_par = u32::try_from(config.max_parallelism).unwrap_or(u32::MAX);
    let mut ctxs: Vec<HostCtx> = targets
        .iter()
        .map(|&ip| HostCtx {
            sched: HostScheduler::with_params(
                &config.ports,
                config.template,
                TimingParams::for_template(config.template),
                0,
                max_par,
            ),
            host: Host::new(ip, HostState::Down),
            finals: Vec::new(),
        })
        .collect();

    let mut group = GroupScheduler::new(config.template, 0, max_par);
    let mut rate = RateLimiter::new(config.min_rate, config.max_rate);

    run_group(&mut ctxs, &mut group, &mut rate).await;

    let mut results = ScanResults::new();
    for mut ctx in ctxs {
        for (port, state, reason) in ctx.finals.drain(..) {
            ctx.host
                .ports
                .push(Port::new(port, Protocol::Tcp, state, reason));
        }
        ctx.host.ports.sort_by_key(|p| (p.protocol, p.number));
        results.hosts.push(ctx.host);
    }
    results
}

/// The group event loop: launch every probe the gates permit, then await the next
/// completion, until every host is done.
async fn run_group(ctxs: &mut [HostCtx], group: &mut GroupScheduler, rate: &mut RateLimiter) {
    let start = Instant::now();
    let mut set: JoinSet<(usize, Probe, ConnectResult)> = JoinSet::new();

    loop {
        launch_ready(ctxs, group, rate, start, &mut set);

        if set.is_empty() {
            // Nothing in flight. Either the whole group is finished, or the rate
            // limiter is holding us back.
            if all_done(ctxs) {
                break;
            }
            // With work left but nothing active, the *only* thing that can be
            // holding us is the rate limiter (a host with an unscanned port always
            // clears its own congestion window when its active count is 0, so
            // `launch_ready` would otherwise have dispatched). If it is holding,
            // sleep until it reopens; then loop back to launch.
            //
            // A previous version `break`ed when the verdict here was *not*
            // TooEarly — but that was reachable, and wrong: the rate interval can
            // elapse in the gap between `launch_ready`'s own rate check and this
            // one, so a "not too early" verdict here just means the ready work
            // should be launched on the next iteration, not that the scan is
            // stuck. Retrying (never breaking) classifies every port; it cannot
            // spin, because `launch_ready` dispatches whenever a host can send.
            if let RateVerdict::TooEarly(t) = rate.verdict(now_us(start)) {
                tokio::time::sleep(micros_to_duration(t.saturating_sub(now_us(start)))).await;
            }
            continue;
        }

        if let Some(Ok((idx, probe, res))) = set.join_next().await {
            let ctx = &mut ctxs[idx];
            match res.state {
                PortState::Open | PortState::Closed => {
                    ctx.sched.on_reply(probe, rtt_micros(&res));
                    group.on_reply();
                    ctx.finals.push((probe.port, res.state, res.reason));
                    ctx.host.state = HostState::Up;
                }
                _ => {
                    let before = ctx.sched.resolved();
                    ctx.sched.on_timeout(probe);
                    group.on_timeout();
                    if ctx.sched.resolved() > before {
                        ctx.finals
                            .push((probe.port, PortState::Filtered, res.reason));
                    }
                }
            }
        }
    }
}

/// Launch as many probes as the rate limiter, the group window, and each host's
/// own congestion window currently permit.
fn launch_ready(
    ctxs: &mut [HostCtx],
    group: &mut GroupScheduler,
    rate: &mut RateLimiter,
    start: Instant,
    set: &mut JoinSet<(usize, Probe, ConnectResult)>,
) {
    loop {
        let incomplete = ctxs.iter().filter(|c| !c.sched.is_done()).count();
        let verdict = rate.verdict(now_us(start));
        if matches!(verdict, RateVerdict::TooEarly(_)) {
            return;
        }
        // `--min-rate` behind schedule forces a send past the congestion gate.
        let must_send = matches!(verdict, RateVerdict::MustSend);
        if !must_send && !group.may_admit(incomplete) {
            return;
        }

        // Find a host that can and wants to send. `next_probe` applies the host's
        // own congestion gate, so a host at its window is skipped.
        let mut launched = false;
        for (idx, ctx) in ctxs.iter_mut().enumerate() {
            if ctx.sched.is_done() {
                continue;
            }
            if let Some(probe) = ctx.sched.next_probe() {
                group.on_send();
                rate.record_send(now_us(start));
                let timeout = micros_to_duration(ctx.sched.probe_timeout_us());
                let addr = SocketAddr::new(ctx.host.address, probe.port);
                set.spawn(async move { (idx, probe, tcp_connect(addr, timeout).await) });
                launched = true;
                break;
            }
        }
        if !launched {
            return;
        }
    }
}

fn all_done(ctxs: &[HostCtx]) -> bool {
    ctxs.iter().all(|c| c.sched.is_done())
}

/// Microseconds since the scan started, saturating into `i64` (a scan never runs
/// long enough to approach the `i64::MAX` µs ceiling, ~292,000 years).
fn now_us(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX)
}

/// Convert a µs count into a `Duration`, clamping a non-positive value to zero.
fn micros_to_duration(us: i64) -> Duration {
    Duration::from_micros(u64::try_from(us).unwrap_or(0))
}

/// The round-trip time to report for an `ack`, in µs. `verdict` always attaches an
/// RTT for open/closed; fall back to a small positive value if it somehow didn't
/// (never zero — the estimator treats a tiny sample as 10 ms anyway).
fn rtt_micros(res: &ConnectResult) -> i64 {
    match res.rtt {
        Some(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
        None => 1000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn cfg(ports: Vec<u16>) -> ConnectScanConfig {
        ConnectScanConfig {
            ports,
            template: TimingTemplate::Normal,
            max_parallelism: 0,
            min_rate: None,
            max_rate: None,
        }
    }

    #[test]
    fn micros_to_duration_clamps_negative() {
        assert_eq!(micros_to_duration(-5), Duration::ZERO);
        assert_eq!(micros_to_duration(2000), Duration::from_micros(2000));
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn scans_open_and_closed_ports_on_localhost() {
        // One live listener (open) and one bound-then-freed port (closed).
        let open_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let open_port = open_listener.local_addr().unwrap().port();

        let closed_listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let results = connect_scan(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            &cfg(vec![open_port, closed_port]),
        )
        .await;

        assert_eq!(results.hosts.len(), 1);
        let host = &results.hosts[0];
        assert_eq!(host.state, HostState::Up);

        let open = host.ports.iter().find(|p| p.number == open_port).unwrap();
        assert_eq!(open.state, PortState::Open);
        assert_eq!(open.reason, Reason::ConnAccept);

        let closed = host.ports.iter().find(|p| p.number == closed_port).unwrap();
        assert_eq!(closed.state, PortState::Closed);
        assert_eq!(closed.reason, Reason::ConnRefused);

        let numbers: Vec<u16> = host.ports.iter().map(|p| p.number).collect();
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        assert_eq!(numbers, sorted);
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn scans_multiple_hosts_as_one_group() {
        // A listener on 127.0.0.1 only; scan it plus 127.0.0.2 (also loopback).
        // Both hosts must be scanned and every port classified — exercises the
        // shared group window across hosts.
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let closed = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);

        let targets = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        let results = connect_scan(&targets, &cfg(vec![port, closed_port])).await;

        assert_eq!(results.hosts.len(), 2);
        // Every host classified both ports (2 ports each).
        for h in &results.hosts {
            assert_eq!(h.ports.len(), 2, "host {:?} missing ports", h.address);
        }
        // The listener's port is open on 127.0.0.1.
        let h1 = &results.hosts[0];
        assert_eq!(h1.address, targets[0]);
        assert_eq!(
            h1.ports.iter().find(|p| p.number == port).unwrap().state,
            PortState::Open
        );
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn congestion_window_bounds_a_large_closed_range() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let base = listener.local_addr().unwrap().port();
        drop(listener);

        let ports: Vec<u16> = (base..base.saturating_add(20)).collect();
        let mut c = cfg(ports.clone());
        c.max_parallelism = 4;
        let results = connect_scan(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], &c).await;
        assert_eq!(results.hosts[0].ports.len(), ports.len());
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn group_scan_completes_on_a_multithread_runtime() {
        // Liveness/functional check: the whole group loop must run to completion
        // on a real multi-threaded runtime — no deadlock, no lost task, every port
        // classified (the winlsof-class hang is the risk this guards). Race-freedom
        // itself is structural, not checked here: all scheduler state is mutated by
        // the single driver task and probe tasks capture only Copy/owned data, so
        // `JoinSet::spawn`'s Send bound rejects shared mutable state at compile
        // time. (Full-program TSan of tokio's multi-thread scheduler reports
        // runtime-internal false positives, so it is not used as a gate.)
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let base = listener.local_addr().unwrap().port();
        drop(listener);

        let ports: Vec<u16> = (base..base.saturating_add(16)).collect();
        let targets = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        ];
        let results = connect_scan(&targets, &cfg(ports.clone())).await;
        assert_eq!(results.hosts.len(), 2);
        for h in &results.hosts {
            assert_eq!(h.ports.len(), ports.len());
        }
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn max_rate_paces_without_stalling() {
        // With a max-rate set, a small closed-port scan must still complete and
        // classify every port (the rate-limit sleep path must not hang).
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let base = listener.local_addr().unwrap().port();
        drop(listener);

        let ports: Vec<u16> = (base..base.saturating_add(8)).collect();
        let mut c = cfg(ports.clone());
        c.max_rate = Some(5000.0); // 200 µs spacing
        let results = connect_scan(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], &c).await;
        assert_eq!(results.hosts[0].ports.len(), ports.len());
    }
}
