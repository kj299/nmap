//! Connect-scan driver — the tokio event loop that turns the pure
//! [`nmap_core::engine::HostScheduler`] decisions into real TCP connects. This is
//! the Milestone-2 replacement for the Milestone-1 fixed prime/refill loop: the
//! number of probes in flight is now bounded by the **congestion window**
//! (`ultra_scan`'s AIMD), and each probe's timeout is the scheduler's
//! **adaptive RTT estimate**, not a fixed constant.
//!
//! The split is deliberate and is the safety story: every *decision* (may I send?
//! which probe? is the host done?) lives in `core` as a pure, Miri-checked state
//! machine; this module only performs the I/O the scheduler asks for and feeds
//! the outcomes back. Built on tokio's safe task API — **no `unsafe`**.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use nmap_core::engine::{HostScheduler, Probe};
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
    /// `0` = the template default). Caps the congestion window.
    pub max_parallelism: usize,
}

/// Run an unprivileged TCP connect scan over `targets` (already-resolved IPs),
/// returning the populated [`ScanResults`]. Hosts are scanned in order; within a
/// host the scheduler paces probes by the congestion window.
pub async fn connect_scan(targets: &[IpAddr], config: &ConnectScanConfig) -> ScanResults {
    let max_par = u32::try_from(config.max_parallelism).unwrap_or(u32::MAX);
    let mut results = ScanResults::new();
    for &ip in targets {
        results
            .hosts
            .push(scan_host(ip, &config.ports, config.template, max_par).await);
    }
    results
}

/// Drive one host's ports through the congestion-controlled scheduler.
async fn scan_host(ip: IpAddr, ports: &[u16], template: TimingTemplate, max_par: u32) -> Host {
    let params = TimingParams::for_template(template);
    let mut sched = HostScheduler::with_params(ports, template, params, 0, max_par);

    let mut set: JoinSet<(Probe, ConnectResult)> = JoinSet::new();
    let mut host = Host::new(ip, HostState::Down);
    // Finalized port outcomes, recorded as each port resolves.
    let mut finals: Vec<(u16, PortState, Reason)> = Vec::new();

    loop {
        // Launch every probe the congestion gate currently permits.
        while let Some(probe) = sched.next_probe() {
            let timeout = micros_to_duration(sched.probe_timeout_us());
            let addr = SocketAddr::new(ip, probe.port);
            set.spawn(async move { (probe, tcp_connect(addr, timeout).await) });
        }

        // Nothing in flight: either we're done, or (defensively) there is no more
        // reachable work — break either way.
        let Some(joined) = set.join_next().await else {
            break;
        };

        if let Ok((probe, res)) = joined {
            match res.state {
                // A definite answer resolves the port and grows the window.
                PortState::Open | PortState::Closed => {
                    sched.on_reply(probe, rtt_micros(&res));
                    finals.push((probe.port, res.state, res.reason));
                    host.state = HostState::Up;
                }
                // No answer: the scheduler decides whether to retry or give up.
                // A resolution (retries exhausted) finalizes the port as filtered.
                _ => {
                    let before = sched.resolved();
                    sched.on_timeout(probe);
                    if sched.resolved() > before {
                        finals.push((probe.port, PortState::Filtered, res.reason));
                    }
                }
            }
        }

        if sched.is_done() && set.is_empty() {
            break;
        }
    }

    for (port, state, reason) in finals {
        host.ports
            .push(Port::new(port, Protocol::Tcp, state, reason));
    }
    // Deterministic order regardless of completion order.
    host.ports.sort_by_key(|p| (p.protocol, p.number));
    host
}

/// Convert the scheduler's µs timeout into a `Duration`, clamping a non-positive
/// value to zero (the estimator keeps it in `[min, max]` RTT, so this is just
/// defensive).
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

        let cfg = ConnectScanConfig {
            ports: vec![open_port, closed_port],
            template: TimingTemplate::Normal,
            max_parallelism: 0,
        };
        let results = connect_scan(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], &cfg).await;

        assert_eq!(results.hosts.len(), 1);
        let host = &results.hosts[0];
        assert_eq!(host.state, HostState::Up);

        let open = host.ports.iter().find(|p| p.number == open_port).unwrap();
        assert_eq!(open.state, PortState::Open);
        assert_eq!(open.reason, Reason::ConnAccept);

        let closed = host.ports.iter().find(|p| p.number == closed_port).unwrap();
        assert_eq!(closed.state, PortState::Closed);
        assert_eq!(closed.reason, Reason::ConnRefused);

        // Ports are reported in ascending order.
        let numbers: Vec<u16> = host.ports.iter().map(|p| p.number).collect();
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        assert_eq!(numbers, sorted);
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn congestion_window_bounds_a_large_closed_range() {
        // Scanning many closed ports must still complete and classify every port
        // (exercises the scheduler's prime/refill under drops).
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let base = listener.local_addr().unwrap().port();
        drop(listener);

        let ports: Vec<u16> = (base..base.saturating_add(20)).collect();
        let cfg = ConnectScanConfig {
            ports: ports.clone(),
            template: TimingTemplate::Normal,
            max_parallelism: 4,
        };
        let results = connect_scan(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], &cfg).await;
        assert_eq!(results.hosts[0].ports.len(), ports.len());
    }
}
