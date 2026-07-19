//! Service-detection driver — the tokio loop that turns the pure
//! [`nmap_core::servicescan::Scheduler`] decisions into real probe sends and
//! banner reads. Every *decision* (which probe next, is it finished, what did it
//! match) lives in `core`; this module only performs the connect / send / read
//! those decisions call for, matches the banner with `nmap_core::matcher`, and
//! feeds the outcome back. Built on tokio's safe socket API — **no `unsafe`**.
//!
//! Scope: the **connect** `-sV` path (TCP probes). SSL/STARTTLS tunnels, UDP
//! probes, and the RPC grinder are deferred (`DIVERGENCES.md`
//! `servicescan-connect-only`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nmap_core::matcher::CompiledDb;
use nmap_core::probedb::ProbeDb;
use nmap_core::servicescan::{MatchKind, ProbeRef, Resolution, Scheduler, VersionResult};
use tokio::task::JoinSet;

use crate::net::grab_banner;

/// How to run service detection.
#[derive(Clone, Debug)]
pub struct ServiceScanConfig {
    /// `--version-intensity` (`0..=9`, default 7).
    pub intensity: u8,
    /// Per-connect timeout for each probe.
    pub connect_timeout: Duration,
    /// Cap on banner bytes read per probe (bounds memory on a chatty/hostile port).
    pub max_banner_bytes: usize,
    /// Max concurrent (host, port) probes in flight.
    pub max_parallelism: usize,
}

impl Default for ServiceScanConfig {
    fn default() -> ServiceScanConfig {
        ServiceScanConfig {
            intensity: nmap_core::servicescan::DEFAULT_INTENSITY,
            connect_timeout: Duration::from_secs(5),
            max_banner_bytes: 64 * 1024,
            max_parallelism: 16,
        }
    }
}

/// The detection result for one port.
#[derive(Clone, Debug)]
pub struct PortVersion {
    pub port: u16,
    pub result: VersionResult,
}

/// The detection results for one host, in ascending port order.
#[derive(Clone, Debug)]
pub struct HostVersions {
    pub ip: IpAddr,
    pub ports: Vec<PortVersion>,
}

/// Run `-sV` over the given open TCP ports. `db` is the parsed probe database and
/// `compiled` its matcher (same probe order); both are shared read-only across the
/// concurrent per-port tasks. Returns per-host results in the input host order,
/// each host's ports sorted ascending.
pub async fn service_scan(
    open_ports: &[(IpAddr, Vec<u16>)],
    db: Arc<ProbeDb>,
    compiled: Arc<CompiledDb>,
    config: &ServiceScanConfig,
) -> Vec<HostVersions> {
    let cap = config.max_parallelism.max(1);
    let mut set: JoinSet<(IpAddr, u16, VersionResult)> = JoinSet::new();
    // Flatten to a work queue of (ip, port), preserving order for the output map.
    let mut queue: Vec<(IpAddr, u16)> = Vec::new();
    for (ip, ports) in open_ports {
        for &port in ports {
            queue.push((*ip, port));
        }
    }
    let mut next = 0usize;
    let mut results: Vec<(IpAddr, u16, VersionResult)> = Vec::with_capacity(queue.len());

    // Prime up to `cap` tasks, then keep the pipe full as each completes.
    while next < queue.len() && set.len() < cap {
        spawn_port(&mut set, queue[next], &db, &compiled, config);
        next = next.saturating_add(1);
    }
    while let Some(joined) = set.join_next().await {
        if let Ok(done) = joined {
            results.push(done);
        }
        if next < queue.len() {
            spawn_port(&mut set, queue[next], &db, &compiled, config);
            next = next.saturating_add(1);
        }
    }

    // Reassemble per-host, in the caller's host order.
    let mut out: Vec<HostVersions> = open_ports
        .iter()
        .map(|(ip, _)| HostVersions {
            ip: *ip,
            ports: Vec::new(),
        })
        .collect();
    for (ip, port, result) in results {
        if let Some(h) = out.iter_mut().find(|h| h.ip == ip) {
            h.ports.push(PortVersion { port, result });
        }
    }
    for h in &mut out {
        h.ports.sort_by_key(|p| p.port);
    }
    out
}

/// Spawn one per-port detection task with its own `Arc` clones of the DBs.
fn spawn_port(
    set: &mut JoinSet<(IpAddr, u16, VersionResult)>,
    (ip, port): (IpAddr, u16),
    db: &Arc<ProbeDb>,
    compiled: &Arc<CompiledDb>,
    config: &ServiceScanConfig,
) {
    let db = Arc::clone(db);
    let compiled = Arc::clone(compiled);
    let config = config.clone();
    set.spawn(async move {
        let result = scan_one_port(SocketAddr::new(ip, port), &db, &compiled, &config).await;
        (ip, port, result)
    });
}

/// Drive the pure scheduler over one open TCP port: send each probe it selects,
/// read the banner, match it, feed the result back, and assemble the verdict.
async fn scan_one_port(
    addr: SocketAddr,
    db: &ProbeDb,
    compiled: &CompiledDb,
    config: &ServiceScanConfig,
) -> VersionResult {
    let mut sched = Scheduler::new(addr.port(), config.intensity);
    let mut hard: Option<VersionResult> = None;
    let mut first_probe = true;

    while let Some(probe_ref) = sched.next_probe(db) {
        let (send, wait_ms, tcpwrapped_ms, compiled_probe) = match probe_ref {
            ProbeRef::Null => {
                let np = db.null_probe.as_ref();
                (
                    &[][..],
                    np.map_or(5000, |p| p.totalwaitms),
                    np.map_or(2000, |p| p.tcpwrappedms),
                    compiled.null_probe.as_ref(),
                )
            }
            ProbeRef::Indexed(i) => match db.probes.get(i) {
                Some(p) => (
                    p.probestring.as_slice(),
                    p.totalwaitms,
                    p.tcpwrappedms,
                    compiled.probes.get(i),
                ),
                None => break,
            },
        };

        let banner = grab_banner(
            addr,
            send,
            config.connect_timeout,
            Duration::from_millis(u64::from(wait_ms)),
            config.max_banner_bytes,
        )
        .await;

        // Port was reported open but we can't reconnect now — give up cleanly.
        if !banner.connected {
            break;
        }

        // tcpwrapped: the NULL-probe connection closed with no data quickly.
        if first_probe
            && probe_ref == ProbeRef::Null
            && banner.data.is_empty()
            && banner.closed
            && banner.elapsed < Duration::from_millis(u64::from(tcpwrapped_ms))
        {
            return VersionResult::tcpwrapped();
        }
        first_probe = false;

        // Match the banner against this probe's compiled rules.
        let kind = match compiled_probe.and_then(|cp| cp.test(&banner.data)) {
            Some(outcome) if outcome.is_soft() => MatchKind::Soft {
                service: outcome.service().to_string(),
            },
            Some(outcome) => {
                hard = Some(VersionResult::hard(outcome.rule, &outcome.captures));
                MatchKind::Hard
            }
            None => MatchKind::NoMatch,
        };
        sched.record(kind);
        if sched.is_finished() {
            break;
        }
    }

    match sched.resolution() {
        Resolution::HardMatched => hard.unwrap_or_default(),
        Resolution::SoftMatched => VersionResult::soft(sched.soft_service().unwrap_or_default()),
        Resolution::NoMatch => VersionResult::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    /// Spawn a one-shot loopback server that writes `banner` to the first client
    /// and then closes. Returns the bound port.
    async fn banner_server(banner: &'static [u8]) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(banner).await;
                let _ = sock.shutdown().await;
            }
        });
        port
    }

    fn ssh_db() -> (Arc<ProbeDb>, Arc<CompiledDb>) {
        // NULL probe grabs the banner; the ssh match lives under it.
        let text = "Probe TCP NULL q||\n\
                    match ssh m|^SSH-([\\d.]+)-OpenSSH[_-]([\\w.]+)| p/OpenSSH/ v/$2/ cpe:/a:openbsd:openssh:$2/\n";
        let db = ProbeDb::parse(text);
        let compiled = CompiledDb::compile(&db);
        (Arc::new(db), Arc::new(compiled))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    async fn detects_ssh_from_null_probe_banner() {
        let port = banner_server(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        let (db, compiled) = ssh_db();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let cfg = ServiceScanConfig {
            connect_timeout: Duration::from_secs(2),
            ..ServiceScanConfig::default()
        };

        let out = service_scan(&[(ip, vec![port])], db, compiled, &cfg).await;
        assert_eq!(out.len(), 1);
        let pv = &out[0].ports[0];
        assert_eq!(pv.port, port);
        assert_eq!(pv.result.service.as_deref(), Some("ssh"));
        assert_eq!(pv.result.resolution, Resolution::HardMatched);
        assert_eq!(pv.result.product.as_deref(), Some(&b"OpenSSH"[..]));
        assert_eq!(pv.result.version.as_deref(), Some(&b"9.6"[..]));
        assert_eq!(
            pv.result.cpe.first().map(Vec::as_slice),
            Some(&b"cpe:/a:openbsd:openssh:9.6"[..])
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    async fn no_match_on_silent_port_still_returns() {
        // A server that connects but sends nothing and stays open → no banner,
        // no match; the driver must still return a (default) result, not hang.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept and hold the connection open briefly without writing.
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_millis(50)).await;
                drop(sock);
            }
        });
        let (db, compiled) = ssh_db();
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Short waits so the test is quick; the NULL probe reads nothing.
        let cfg = ServiceScanConfig {
            connect_timeout: Duration::from_secs(1),
            max_parallelism: 4,
            ..ServiceScanConfig::default()
        };
        let out = service_scan(&[(ip, vec![port])], db, compiled, &cfg).await;
        let pv = &out[0].ports[0];
        // Either NoMatch or tcpwrapped depending on timing, but never a hard match.
        assert_ne!(pv.result.resolution, Resolution::HardMatched);
    }
}
