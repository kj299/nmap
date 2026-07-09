//! `nmap-rs` — the CLI binary. Thin by design: parse args, resolve targets and
//! ports, run the connect scan, render. All the real logic lives in `nmap-core`
//! (pure, testable) and `nmap-sys` (the async I/O). Milestone 1 wires the
//! unprivileged connect-scan MVP: `nmap-rs [-sT] [-p SPEC] [-6] [-Pn]
//! [-oN/-oX/-oG FILE|-] [-v|-d] TARGET...`.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nmap_core::model::HostState;
use nmap_core::options::RunConfig;
use nmap_core::{
    parse_args, parse_port_spec, parse_target, render_grepable, render_normal, render_xml,
    ScanMeta, ServiceTable, TargetSpec, TimingParams,
};
use nmap_sys::net::resolve_host;
use nmap_sys::{connect_scan, ConnectScanConfig};

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

    let timing = TimingParams::default();
    let scan_cfg = ConnectScanConfig {
        ports,
        // Fixed per-probe timeout for the MVP (adaptive RTT is a refinement).
        timeout: Duration::from_millis(timing.initial_rtt_timeout_ms.max(0) as u64),
        max_parallelism: timing.max_parallelism as usize,
    };

    let ips: Vec<IpAddr> = targets.iter().map(|(ip, _)| *ip).collect();
    let started = now_string();
    let clock = Instant::now();
    let mut results = connect_scan(&ips, &scan_cfg).await;
    let elapsed = clock.elapsed().as_secs_f64();

    // Re-attach hostnames (connect_scan works purely by IP) and honor -Pn.
    for (host, (_, name)) in results.hosts.iter_mut().zip(targets.iter()) {
        host.hostname = name.clone();
        if cfg.assume_up && host.state != HostState::Up {
            host.state = HostState::Up;
        }
    }

    let meta = ScanMeta {
        scanner: "nmap-rs",
        version: env!("CARGO_PKG_VERSION"),
        args: &args.join(" "),
        started: &started,
        elapsed_secs: elapsed,
    };

    if let Err(e) = emit_outputs(&cfg, &results, &meta, services.as_ref()) {
        eprintln!("nmap-rs: failed to write output: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn print_usage() {
    println!(
        "Usage: nmap-rs [-sT] [-p <ports>] [-6] [-Pn] [-oN|-oX|-oG <file|->] [-v|-d] <target...>"
    );
    println!("  Milestone 1 (MVP): unprivileged TCP connect scan. See nmap-rs/PLAN.md.");
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

/// A coarse start-time string for the banner. Deliberately simple (no date
/// dependency); the differential harness normalizes it.
fn now_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch+{secs}s")
}
