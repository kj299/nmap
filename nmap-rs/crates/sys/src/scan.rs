//! Connect-scan driver — the module that turns *targets + ports + timing* into
//! an actual scan by driving [`crate::net::tcp_connect`] concurrently. The Rust
//! analog of `scan_engine_connect.cc`'s job (minus the raw-packet congestion
//! control, which the MVP replaces with a simple bounded-parallelism model).
//!
//! Per host it probes every requested TCP port with at most `max_parallelism`
//! connects in flight, collects the results into the pure [`ScanResults`] model,
//! and derives host liveness from the responses (any open/closed answer ⇒ up).
//! Built on tokio's safe task API — **no `unsafe`**.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use nmap_core::model::{Host, HostState, Port, PortState, Protocol, ScanResults};
use tokio::task::JoinSet;

use crate::net::{tcp_connect, ConnectResult};

/// Concurrency cap used when the timing template asks for "auto" (`0`). Bounds
/// in-flight sockets so a large port range can't exhaust file descriptors; a
/// real congestion-controlled window is a later-milestone refinement.
const DEFAULT_PARALLELISM: usize = 100;

/// What to scan and how aggressively — assembled by the CLI from the parsed
/// ports and the timing template.
#[derive(Clone, Debug)]
pub struct ConnectScanConfig {
    /// TCP ports to probe, in the order to report them.
    pub ports: Vec<u16>,
    /// Per-probe connect timeout.
    pub timeout: Duration,
    /// Max concurrent connects per host; `0` ⇒ [`DEFAULT_PARALLELISM`].
    pub max_parallelism: usize,
}

fn effective_parallelism(max: usize) -> usize {
    if max == 0 {
        DEFAULT_PARALLELISM
    } else {
        max
    }
}

/// Run an unprivileged TCP connect scan over `targets` (already-resolved IPs),
/// returning the populated [`ScanResults`]. Hosts are scanned in order; within a
/// host, ports are probed concurrently and the result ports are sorted.
pub async fn connect_scan(targets: &[IpAddr], config: &ConnectScanConfig) -> ScanResults {
    let parallelism = effective_parallelism(config.max_parallelism);
    let mut results = ScanResults::new();
    for &ip in targets {
        results
            .hosts
            .push(scan_host(ip, &config.ports, config.timeout, parallelism).await);
    }
    results
}

/// Probe every port on one host with at most `parallelism` connects in flight.
async fn scan_host(ip: IpAddr, ports: &[u16], timeout: Duration, parallelism: usize) -> Host {
    let mut set: JoinSet<(u16, ConnectResult)> = JoinSet::new();
    let mut pending = ports.iter().copied();

    // Prime the in-flight window, then refill one probe per completion so no
    // more than `parallelism` connects are ever outstanding.
    for _ in 0..parallelism {
        match pending.next() {
            Some(port) => {
                set.spawn(probe(ip, port, timeout));
            }
            None => break,
        }
    }

    let mut host = Host::new(ip, HostState::Down);
    while let Some(joined) = set.join_next().await {
        if let Ok((port, res)) = joined {
            // Any concrete answer (open or closed) means the host is up.
            if matches!(res.state, PortState::Open | PortState::Closed) {
                host.state = HostState::Up;
            }
            host.ports
                .push(Port::new(port, Protocol::Tcp, res.state, res.reason));
        }
        if let Some(port) = pending.next() {
            set.spawn(probe(ip, port, timeout));
        }
    }

    // Deterministic order regardless of completion order.
    host.ports.sort_by_key(|p| (p.protocol, p.number));
    host
}

/// One port probe, tagged with its port number for reassembly.
async fn probe(ip: IpAddr, port: u16, timeout: Duration) -> (u16, ConnectResult) {
    (port, tcp_connect(SocketAddr::new(ip, port), timeout).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nmap_core::model::Reason;
    use std::net::Ipv4Addr;

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
            timeout: Duration::from_secs(2),
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
    async fn respects_the_parallelism_bound() {
        // Scanning many closed ports with a small window must still complete and
        // classify every port (exercises the prime/refill loop).
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let base = listener.local_addr().unwrap().port();
        drop(listener);

        let ports: Vec<u16> = (base..base.saturating_add(20)).collect();
        let cfg = ConnectScanConfig {
            ports: ports.clone(),
            timeout: Duration::from_secs(2),
            max_parallelism: 4,
        };
        let results = connect_scan(&[IpAddr::V4(Ipv4Addr::LOCALHOST)], &cfg).await;
        assert_eq!(results.hosts[0].ports.len(), ports.len());
    }

    #[test]
    fn parallelism_zero_falls_back_to_default() {
        assert_eq!(effective_parallelism(0), DEFAULT_PARALLELISM);
        assert_eq!(effective_parallelism(8), 8);
    }
}
