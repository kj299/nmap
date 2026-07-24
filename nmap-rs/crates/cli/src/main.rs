//! `nmap-rs` — the CLI binary. Thin by design: parse args, resolve targets and
//! ports, run the connect scan, render. All the real logic lives in `nmap-core`
//! (pure, testable) and `nmap-sys` (the async I/O). Milestone 1 wires the
//! unprivileged connect-scan MVP: `nmap-rs [-sT] [-p SPEC] [-6] [-Pn]
//! [-oN/-oX/-oG FILE|-] [-v|-d] TARGET...`.

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nmap_core::matcher::CompiledDb;
use nmap_core::model::{HostState, PortState, ServiceInfo};
use nmap_core::options::{RunConfig, ScanKind};
use nmap_core::probedb::ProbeDb;
use nmap_core::servicescan::VersionResult;
use nmap_core::{
    parse_args, parse_port_spec, parse_target, render_grepable, render_normal, render_xml,
    ScanMeta, ScanResults, ServiceTable, TargetSpec, TimingParams, TimingTemplate,
};
use nmap_sys::net::resolve_host;
use nmap_sys::{connect_scan, service_scan, ConnectScanConfig, ServiceScanConfig};

/// Default number of top TCP ports scanned when no `-p` is given (nmap's -F is
/// 100; the default is 1000 — we use 1000 when the services table is available).
const DEFAULT_TOP_PORTS: usize = 1000;
/// Safety cap on expanded target count for the MVP (avoids a `/0` materializing
/// billions of hosts); a streaming host iterator is a later refinement.
const MAX_TARGETS: usize = 65_536;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = parse_args(&args);
    nmap_core::log::init(cfg.verbose, cfg.debugging);
    nmap_core::debug!(1, "parsed config: {cfg:?}");

    if cfg.show_version {
        println!("nmap-rs {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if cfg.show_help || (cfg.targets.is_empty() && args.is_empty()) {
        print_usage();
        return ExitCode::SUCCESS;
    }
    for flag in &cfg.unrecognized {
        eprintln!("nmap-rs: warning: ignoring unrecognized option '{flag}' (not yet implemented)");
    }
    if cfg.targets.is_empty() {
        eprintln!("nmap-rs: no targets specified");
        print_usage();
        return ExitCode::FAILURE;
    }

    let services = load_services();
    if services.is_none() {
        nmap_core::verbose!(1, "nmap-services not found; service names limited");
    }

    // Ports to scan (TCP): -p spec, else top-N, else a small default range.
    let ports = match select_ports(&cfg, services.as_ref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nmap-rs: bad -p specification: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    // Resolve every target expression into (ip, optional hostname).
    let targets = resolve_targets(&cfg).await;
    if targets.is_empty() {
        eprintln!("nmap-rs: no scannable targets (all failed to resolve or expand)");
        return ExitCode::FAILURE;
    }

    // Milestone 2: the scan engine derives its per-probe timeout adaptively from
    // observed RTTs and paces probes by the congestion window, so the CLI passes
    // the timing *template* rather than a fixed timeout. (`-T` selection is a
    // later CLI refinement; the default is Normal / -T3.)
    let max_par = TimingParams::default().max_parallelism as usize;
    let template = TimingTemplate::Normal;

    let ips: Vec<IpAddr> = targets.iter().map(|(ip, _)| *ip).collect();
    let started = now_string();
    let clock = Instant::now();
    let mut results = run_scan(&cfg, &ips, &ports, template, max_par).await;
    let elapsed = clock.elapsed().as_secs_f64();

    // Re-attach hostnames (connect_scan works purely by IP) and honor -Pn.
    for (host, (_, name)) in results.hosts.iter_mut().zip(targets.iter()) {
        host.hostname = name.clone();
        if cfg.assume_up && host.state != HostState::Up {
            host.state = HostState::Up;
        }
    }

    // Milestone 3: `-sV` — probe each open TCP port and fill in service/version.
    if cfg.service_version {
        run_service_version(&cfg, &mut results).await;
    }

    let meta = ScanMeta {
        scanner: "nmap-rs",
        version: env!("CARGO_PKG_VERSION"),
        args: &args.join(" "),
        started: &started,
        elapsed_secs: elapsed,
        service_version: cfg.service_version,
    };

    if let Err(e) = emit_outputs(&cfg, &results, &meta, services.as_ref()) {
        eprintln!("nmap-rs: failed to write output: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Dispatch to the requested scan technique. The privileged raw scans fall back to a
/// connect scan when unavailable (no privilege, or a build without `pcap`).
async fn run_scan(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
) -> ScanResults {
    match cfg.scan {
        ScanKind::Connect => connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await,
        ScanKind::Syn => syn_or_fallback(cfg, ips, ports, template, max_par).await,
        ScanKind::Udp => {
            eprintln!(
                "nmap-rs: -sU (UDP scan) is not yet implemented; running a connect scan (-sT)"
            );
            connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
        }
    }
}

/// Assemble a connect-scan config from the run config and resolved ports.
fn connect_cfg(
    cfg: &RunConfig,
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
) -> ConnectScanConfig {
    ConnectScanConfig {
        ports: ports.to_vec(),
        template,
        max_parallelism: max_par,
        min_rate: cfg.min_rate,
        max_rate: cfg.max_rate,
    }
}

/// Run a `-sS` SYN scan, falling back to a connect scan on missing privilege or setup
/// failure (built with `pcap`).
#[cfg(feature = "pcap")]
async fn syn_or_fallback(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
) -> ScanResults {
    match nmap_sys::synscan::syn_scan_targets(ips, ports, template, max_par).await {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "nmap-rs: -sS requires root/CAP_NET_RAW; falling back to a connect scan (-sT)"
            );
            connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
        }
        Err(e) => {
            eprintln!("nmap-rs: -sS setup failed ({e}); falling back to a connect scan (-sT)");
            connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
        }
    }
}

/// Without the `pcap` feature there is no raw-scan backend; `-sS` runs a connect scan.
#[cfg(not(feature = "pcap"))]
async fn syn_or_fallback(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
) -> ScanResults {
    eprintln!(
        "nmap-rs: this build lacks raw-scan support (rebuild with --features pcap); running a connect scan (-sT)"
    );
    connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
}

/// Run `-sV` over every open TCP port and merge the results back into `results`.
/// Degrades gracefully: if the probe DB can't be found or parses to nothing, the
/// scan proceeds without version info (a warning, never a failure).
async fn run_service_version(cfg: &RunConfig, results: &mut ScanResults) {
    let Some(db_text) = load_probe_db_text() else {
        eprintln!(
            "nmap-rs: -sV requested but nmap-service-probes not found; skipping version scan"
        );
        return;
    };
    let db = ProbeDb::parse(&db_text);
    for w in db.warnings.iter().take(3) {
        nmap_core::verbose!(1, "nmap-service-probes line {}: {}", w.line, w.message);
    }
    let db = Arc::new(db);
    let compiled = Arc::new(CompiledDb::compile(&db));

    // Gather open TCP ports per host, in the host order `service_scan` expects.
    let open: Vec<(IpAddr, Vec<u16>)> = results
        .hosts
        .iter()
        .map(|h| {
            let ports = h
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open && p.protocol == nmap_core::Protocol::Tcp)
                .map(|p| p.number)
                .collect();
            (h.address, ports)
        })
        .collect();
    if open.iter().all(|(_, ports)| ports.is_empty()) {
        return; // nothing open to probe
    }

    let sv_cfg = ServiceScanConfig {
        intensity: cfg.version_intensity,
        ..ServiceScanConfig::default()
    };
    let host_versions = service_scan(&open, db, compiled, &sv_cfg).await;

    // Merge each per-port result into the matching port's ServiceInfo.
    for hv in &host_versions {
        let Some(host) = results.hosts.iter_mut().find(|h| h.address == hv.ip) else {
            continue;
        };
        for pv in &hv.ports {
            if let Some(port) = host.ports.iter_mut().find(|p| p.number == pv.port) {
                port.service = merge_version(&port.service, &pv.result);
            }
        }
    }
}

/// Fold a `-sV` [`VersionResult`] into a port's [`ServiceInfo`], converting the
/// byte-faithful version fields to display strings (non-printables escaped as the
/// C's `\xNN`). A hard match sets `method="probed"`, `conf=10`; a soft/tcpwrapped
/// result sets just the name.
fn merge_version(existing: &ServiceInfo, r: &VersionResult) -> ServiceInfo {
    let mut svc = existing.clone();
    if let Some(name) = &r.service {
        svc.name = Some(name.clone()); // the probed name overrides the table guess
    }
    let esc = |b: &Option<Vec<u8>>| b.as_ref().map(|v| printable_escape(v));
    svc.product = esc(&r.product);
    svc.version = esc(&r.version);
    svc.extra_info = esc(&r.info);
    svc.ostype = esc(&r.ostype);
    svc.devicetype = esc(&r.devicetype);
    svc.hostname = esc(&r.hostname);
    svc.cpe = r.cpe.iter().map(|c| printable_escape(c)).collect();
    match r.resolution {
        nmap_core::Resolution::HardMatched => {
            svc.method = Some("probed".into());
            svc.conf = Some(10);
        }
        _ => {
            // Soft match / tcpwrapped: name known, no hard version. nmap still
            // marks the method probed with lower confidence.
            svc.method = Some("probed".into());
            svc.conf = Some(if r.service.is_some() { 8 } else { 3 });
        }
    }
    svc
}

/// nmap's display escaping for a service field: keep printable ASCII (incl. space)
/// verbatim, render everything else as `\xNN`. Bounds the string to a sane length
/// so a hostile banner can't blow up the terminal.
fn printable_escape(bytes: &[u8]) -> String {
    const MAX: usize = 256;
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes.iter().take(MAX) {
        if b == b'\\' {
            out.push_str("\\\\");
        } else if (0x20..=0x7e).contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    if bytes.len() > MAX {
        out.push_str("...");
    }
    out
}

fn print_usage() {
    println!(
        "Usage: nmap-rs [-sT|-sS] [-sV [--version-intensity <0-9>|--version-light|--version-all]]\n              [-p <ports>] [-6] [-Pn] [-oN|-oX|-oG <file|->] [-v|-d] <target...>"
    );
    println!("  TCP connect scan (-sT, default) or raw SYN scan (-sS, needs root +");
    println!(
        "  a --features pcap build; falls back to -sT otherwise), plus -sV version detection."
    );
}

/// Choose the TCP ports to scan.
fn select_ports(
    cfg: &RunConfig,
    services: Option<&ServiceTable>,
) -> Result<Vec<u16>, nmap_core::PortSpecError> {
    if let Some(spec) = &cfg.port_spec {
        return Ok(parse_port_spec(spec, services)?.tcp);
    }
    if let Some(t) = services {
        let top = t.top_ports(nmap_core::Protocol::Tcp, DEFAULT_TOP_PORTS);
        if !top.is_empty() {
            return Ok(top);
        }
    }
    Ok((1u16..=1024).collect())
}

/// Expand and resolve all target expressions into scannable IPs (with the name
/// they came from, for display). Bounded by [`MAX_TARGETS`].
async fn resolve_targets(cfg: &RunConfig) -> Vec<(IpAddr, Option<String>)> {
    let mut out: Vec<(IpAddr, Option<String>)> = Vec::new();
    for expr in &cfg.targets {
        if out.len() >= MAX_TARGETS {
            eprintln!("nmap-rs: target list truncated at {MAX_TARGETS} hosts (MVP cap)");
            break;
        }
        match parse_target(expr, cfg.ipv6) {
            Ok(TargetSpec::Ipv4(ranges)) => {
                for ip in ranges.iter() {
                    if out.len() >= MAX_TARGETS {
                        break;
                    }
                    out.push((IpAddr::V4(ip), None));
                }
            }
            Ok(TargetSpec::Ipv6(ip)) => out.push((IpAddr::V6(ip), None)),
            Ok(TargetSpec::Hostname { name, .. }) => match resolve_host(&name).await {
                Ok(ips) if !ips.is_empty() => {
                    // Scan the first resolved address (nmap's default), tagged
                    // with the name for the report.
                    out.push((ips[0], Some(name)));
                }
                Ok(_) => eprintln!("nmap-rs: failed to resolve \"{name}\": no addresses"),
                Err(e) => eprintln!("nmap-rs: failed to resolve \"{name}\": {e}"),
            },
            Err(e) => eprintln!("nmap-rs: bad target \"{expr}\": {e:?}"),
        }
    }
    out
}

/// Emit the requested output formats. With no `-o` flag, normal output goes to
/// stdout; otherwise each specified format goes to its destination (`-` =
/// stdout, else a file).
fn emit_outputs(
    cfg: &RunConfig,
    results: &nmap_core::ScanResults,
    meta: &ScanMeta,
    services: Option<&ServiceTable>,
) -> std::io::Result<()> {
    let none = cfg.out_normal.is_none() && cfg.out_xml.is_none() && cfg.out_grep.is_none();
    if none {
        print!("{}", render_normal(results, meta, services));
        return Ok(());
    }
    if let Some(dest) = &cfg.out_normal {
        write_to(dest, &render_normal(results, meta, services))?;
    }
    if let Some(dest) = &cfg.out_xml {
        write_to(dest, &render_xml(results, meta, services))?;
    }
    if let Some(dest) = &cfg.out_grep {
        write_to(dest, &render_grepable(results, meta, services))?;
    }
    Ok(())
}

/// Write `content` to `dest` (`-` = stdout, else a file).
fn write_to(dest: &str, content: &str) -> std::io::Result<()> {
    if dest == "-" || dest.is_empty() {
        print!("{content}");
        Ok(())
    } else {
        std::fs::write(dest, content)
    }
}

/// Locate the `nmap-services` data file in a few conventional places. The port
/// never fails if it is absent — it just loses frequency-ranked default ports
/// and service names.
fn load_services() -> Option<ServiceTable> {
    let candidates = [
        std::env::var_os("NMAP_RS_DATADIR").map(|d| {
            let mut p = std::path::PathBuf::from(d);
            p.push("nmap-services");
            p
        }),
        Some("nmap-services".into()),
        Some("../nmap-services".into()),
        Some("../../nmap-services".into()),
        Some("/usr/share/nmap/nmap-services".into()),
    ];
    for cand in candidates.into_iter().flatten() {
        if let Ok(text) = std::fs::read_to_string(&cand) {
            nmap_core::debug!(1, "loaded services from {}", cand.display());
            return Some(ServiceTable::parse(&text));
        }
    }
    None
}

/// Locate and read the `nmap-service-probes` data file (same search convention as
/// [`load_services`]). `None` if absent — `-sV` then degrades to a warning.
fn load_probe_db_text() -> Option<String> {
    let candidates = [
        std::env::var_os("NMAP_RS_DATADIR").map(|d| {
            let mut p = std::path::PathBuf::from(d);
            p.push("nmap-service-probes");
            p
        }),
        Some("nmap-service-probes".into()),
        Some("../nmap-service-probes".into()),
        Some("../../nmap-service-probes".into()),
        Some("../../../nmap-service-probes".into()),
        Some("/usr/share/nmap/nmap-service-probes".into()),
    ];
    for cand in candidates.into_iter().flatten() {
        if let Ok(text) = std::fs::read_to_string(&cand) {
            nmap_core::debug!(1, "loaded service probes from {}", cand.display());
            return Some(text);
        }
    }
    None
}

/// A coarse start-time string for the banner. Deliberately simple (no date
/// dependency); the differential harness normalizes it.
fn now_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch+{secs}s")
}
