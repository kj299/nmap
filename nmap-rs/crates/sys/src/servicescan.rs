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
use nmap_core::servicefp::{
    should_print_fingerprint, FingerprintHeader, Proto, ServiceFingerprint,
};
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
    /// Version string for the fingerprint header (`NMAP_VERSION` in the C).
    pub version: String,
    /// Platform string for the fingerprint header (`NMAP_PLATFORM` in the C).
    pub platform: String,
    /// Local month (1-12) for the fingerprint header. Supplied by the caller
    /// because `core::servicefp` reads no clock; the C calls `localtime()` inside
    /// the builder, which is what stops its output being reproducible.
    pub header_month: i32,
    /// Local day of month for the fingerprint header.
    pub header_day: i32,
    /// `time(NULL)` for the fingerprint header, rendered `%X`.
    pub header_time: i32,
}

impl Default for ServiceScanConfig {
    fn default() -> ServiceScanConfig {
        ServiceScanConfig {
            intensity: nmap_core::servicescan::DEFAULT_INTENSITY,
            connect_timeout: Duration::from_secs(5),
            max_banner_bytes: 64 * 1024,
            max_parallelism: 16,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            platform: std::env::consts::ARCH.to_owned(),
            // Zeroes, not "now": a default must not silently make the output
            // irreproducible. The CLI fills these in from the real clock.
            header_month: 0,
            header_day: 0,
            header_time: 0,
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

    // Accumulates the transcript of every probe that got data but matched nothing.
    // The C does this at three sites (`service_scan.cc:2583/2595/2605`) -- the
    // read-nomatch, timeout and EOF paths -- all of which reduce here to "this
    // probe produced bytes and did not match", because `grab_banner` has already
    // collapsed the three ways a read can end.
    let mut fp = ServiceFingerprint::new(
        FingerprintHeader {
            port: addr.port(),
            proto: Proto::Tcp,
            version: config.version.clone(),
            platform: config.platform.clone(),
            intensity: i32::from(config.intensity),
            ssl_tunnel: false,
            month: config.header_month,
            day: config.header_day,
            time: config.header_time,
        },
        false,
    );

    while let Some(probe_ref) = sched.next_probe(db) {
        let (send, wait_ms, tcpwrapped_ms, compiled_probe, probe_name) = match probe_ref {
            ProbeRef::Null => {
                let np = db.null_probe.as_ref();
                (
                    &[][..],
                    np.map_or(5000, |p| p.totalwaitms),
                    np.map_or(2000, |p| p.tcpwrappedms),
                    compiled.null_probe.as_ref(),
                    np.map_or("NULL", |p| p.name.as_str()),
                )
            }
            ProbeRef::Indexed(i) => match db.probes.get(i) {
                Some(p) => (
                    p.probestring.as_slice(),
                    p.totalwaitms,
                    p.tcpwrappedms,
                    compiled.probes.get(i),
                    p.name.as_str(),
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
            None => {
                // The C guards this call with `if (readstrlen > 0)` because its
                // `addToServiceFingerprint` does `assert(resplen)` -- passing an
                // empty response aborts the process. `add_response` refuses one
                // instead (ledgered `servicefp-empty-response-is-refused-not-
                // asserted`), so repeating the guard here would be a control that
                // cannot fire: mutation-testing it changed no observable behaviour.
                // One enforcement point, in the callee, where S3b's tests pin it.
                fp.add_response(probe_name, &banner.data);
                MatchKind::NoMatch
            }
        };
        sched.record(kind);
        if sched.is_finished() {
            break;
        }
    }

    let resolution = sched.resolution();
    let mut result = match resolution {
        Resolution::HardMatched => hard.unwrap_or_default(),
        Resolution::SoftMatched => VersionResult::soft(sched.soft_service().unwrap_or_default()),
        Resolution::NoMatch => VersionResult::default(),
    };
    // `shouldWePrintFingerprint` gates on the hard match and the intensity floor;
    // `getServiceFingerprint` returns NULL when no probe ever produced data.
    if should_print_fingerprint(resolution == Resolution::HardMatched, config.intensity) {
        result.fingerprint = fp.finish();
    }
    result
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

    /// A config with a fixed, reproducible fingerprint header.
    fn fp_config(intensity: u8) -> ServiceScanConfig {
        ServiceScanConfig {
            intensity,
            version: "7.94".to_owned(),
            platform: "x86_64-pc-linux-gnu".to_owned(),
            header_month: 8,
            header_day: 31,
            header_time: 0x66D3_A1B2,
            ..ServiceScanConfig::default()
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    async fn an_unmatched_service_that_returned_data_yields_a_fingerprint() {
        // The whole point of the wiring: bytes came back, nothing matched, so the
        // operator gets something they can submit instead of nothing at all.
        let port = banner_server(b"WEIRD-PROTO/1.0 hello\r\n").await;
        let (db, compiled) = ssh_db();
        let out = scan_one_port(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            &db,
            &compiled,
            &fp_config(7),
        )
        .await;

        assert_eq!(out.resolution, Resolution::NoMatch);
        let fp = out
            .fingerprint
            .expect("an unmatched banner must produce one");
        assert!(fp.starts_with("SF-Port"), "{fp}");
        assert!(
            fp.contains(&format!("{port}-TCP")),
            "wrong port in header: {fp}"
        );
        assert!(fp.ends_with(';'), "not terminated: {fp}");
        // The banner is there, escaped: `/` is punctuation and passes through, `\r\n`
        // become escapes.
        assert!(fp.contains("WEIRD"), "{fp}");
        assert!(fp.contains("\\r\\n"), "line ending not escaped: {fp}");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    async fn a_hard_match_produces_no_fingerprint() {
        // nmap already knows what this is.
        let port = banner_server(b"SSH-2.0-OpenSSH_8.9p1\r\n").await;
        let (db, compiled) = ssh_db();
        let out = scan_one_port(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            &db,
            &compiled,
            &fp_config(7),
        )
        .await;
        assert_eq!(out.resolution, Resolution::HardMatched);
        assert_eq!(out.fingerprint, None, "hard match must not be offered");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    async fn below_the_intensity_floor_no_fingerprint_is_produced() {
        // Too few probes for the transcript to describe the service fairly.
        let port = banner_server(b"WEIRD-PROTO/1.0 hello\r\n").await;
        let (db, compiled) = ssh_db();
        let out = scan_one_port(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            &db,
            &compiled,
            &fp_config(6),
        )
        .await;
        assert_eq!(out.resolution, Resolution::NoMatch);
        assert_eq!(out.fingerprint, None, "intensity floor not applied");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    async fn a_silent_port_yields_no_fingerprint() {
        // `getServiceFingerprint` returns NULL when nothing was ever added --
        // silence says nothing about the service, so there is nothing to submit.
        let port = banner_server(b"").await;
        let (db, compiled) = ssh_db();
        let out = scan_one_port(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            &db,
            &compiled,
            &fp_config(9),
        )
        .await;
        assert_eq!(out.fingerprint, None, "silence produced a fingerprint");
    }
}
