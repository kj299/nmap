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

    // Milestone 5: `-O` — OS detection. The probe battery is raw-socket work, so this
    // reports why it cannot run rather than silently producing nothing.
    let os_block = if cfg.os_detection {
        #[cfg(feature = "pcap")]
        {
            run_os_detection(&cfg, &mut results).await
        }
        #[cfg(not(feature = "pcap"))]
        {
            run_os_detection(&cfg, &mut results)
        }
    } else {
        String::new()
    };

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
    // The OS block follows the port table, as nmap orders it.
    if !os_block.is_empty() {
        print!("{os_block}");
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
    use nmap_core::classify::ScanType;
    match cfg.scan {
        ScanKind::Connect => connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await,
        ScanKind::Syn => syn_or_fallback(cfg, ips, ports, template, max_par).await,
        ScanKind::Udp => udp_or_fallback(cfg, ips, ports, template, max_par).await,
        ScanKind::Ack => flag_or_fallback(cfg, ips, ports, template, max_par, ScanType::Ack).await,
        ScanKind::Window => {
            flag_or_fallback(cfg, ips, ports, template, max_par, ScanType::Window).await
        }
        ScanKind::Maimon => {
            flag_or_fallback(cfg, ips, ports, template, max_par, ScanType::Maimon).await
        }
        ScanKind::Fin => flag_or_fallback(cfg, ips, ports, template, max_par, ScanType::Fin).await,
        ScanKind::Null => {
            flag_or_fallback(cfg, ips, ports, template, max_par, ScanType::Null).await
        }
        ScanKind::Xmas => {
            flag_or_fallback(cfg, ips, ports, template, max_par, ScanType::Xmas).await
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

/// Run a `-sU` UDP scan, falling back to a connect scan on missing privilege or setup
/// failure (built with `pcap`). A UDP scan reports UDP ports; the connect fallback can
/// only report TCP, so the fallback is a genuine degradation (noted to the user).
#[cfg(feature = "pcap")]
async fn udp_or_fallback(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
) -> ScanResults {
    match nmap_sys::udpscan::udp_scan_targets(ips, ports, template, max_par, udp_payloads()).await {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "nmap-rs: -sU requires root/CAP_NET_RAW; falling back to a TCP connect scan (-sT)"
            );
            connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
        }
        Err(e) => {
            eprintln!("nmap-rs: -sU setup failed ({e}); falling back to a TCP connect scan (-sT)");
            connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
        }
    }
}

/// Build the UDP probe-payload table from `nmap-service-probes` (nmap derives its
/// payloads from the same file rather than shipping a separate payload DB).
///
/// Degrades gracefully: if the file is missing or unreadable the scan proceeds with bare
/// datagrams — more ports read `open|filtered`, but the scan still runs. C nmap
/// `fatal()`s when it cannot load this file, even for `-sU`; refusing to scan over an
/// absent *optional* data file is a worse outcome than scanning with less detection.
#[cfg(feature = "pcap")]
fn udp_payloads() -> nmap_core::payload::UdpPayloads {
    use nmap_core::payload::{UdpPayloads, MAX_PAYLOADS_PER_PORT};

    let Some(text) = load_probe_db_text() else {
        eprintln!(
            "nmap-rs: nmap-service-probes not found; -sU will send bare datagrams \
             (more ports will read open|filtered)"
        );
        return UdpPayloads::empty();
    };
    let payloads = UdpPayloads::from_probe_db(&ProbeDb::parse(&text));
    for &port in payloads.capped_ports() {
        nmap_core::verbose!(
            1,
            "UDP port {} has more payloads than the {} limit; extras dropped",
            port,
            MAX_PAYLOADS_PER_PORT
        );
    }
    nmap_core::verbose!(
        2,
        "loaded UDP payloads for {} ports",
        payloads.ports_with_payloads()
    );
    payloads
}

/// Without the `pcap` feature there is no raw-scan backend; `-sU` runs a connect scan.
#[cfg(not(feature = "pcap"))]
async fn udp_or_fallback(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
) -> ScanResults {
    eprintln!(
        "nmap-rs: this build lacks raw-scan support (rebuild with --features pcap); running a TCP connect scan (-sT)"
    );
    connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
}

/// Run a stateless TCP flag scan (`-sA`/`-sW`/`-sM`/`-sF`/`-sN`/`-sX`), falling back to
/// a connect scan on missing privilege or setup failure (built with `pcap`).
#[cfg(feature = "pcap")]
async fn flag_or_fallback(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
    scan: nmap_core::classify::ScanType,
) -> ScanResults {
    match nmap_sys::flagscan::flag_scan_targets(scan, ips, ports, template, max_par).await {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "nmap-rs: this scan requires root/CAP_NET_RAW; falling back to a connect scan (-sT)"
            );
            connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
        }
        Err(e) => {
            eprintln!("nmap-rs: raw scan setup failed ({e}); falling back to a connect scan (-sT)");
            connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
        }
    }
}

/// Without the `pcap` feature there is no raw-scan backend; the flag scans run a connect scan.
#[cfg(not(feature = "pcap"))]
async fn flag_or_fallback(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    max_par: usize,
    _scan: nmap_core::classify::ScanType,
) -> ScanResults {
    eprintln!(
        "nmap-rs: this build lacks raw-scan support (rebuild with --features pcap); running a TCP connect scan (-sT)"
    );
    connect_scan(ips, &connect_cfg(cfg, ports, template, max_par)).await
}

/// Run `-sV` over every open TCP port and merge the results back into `results`.
/// Degrades gracefully: if the probe DB can't be found or parses to nothing, the
/// scan proceeds without version info (a warning, never a failure).
/// `-O`: run the fingerprint battery against each up host and report what it found.
///
/// Needs a raw socket and a live capture, so a build without `pcap` or a run without
/// privilege says so plainly rather than printing nothing — silence would leave the user
/// unable to tell an unidentifiable host from a build that cannot look.
#[cfg(feature = "pcap")]
async fn run_os_detection(cfg: &RunConfig, results: &mut ScanResults) -> String {
    use nmap_core::osdb::model::FingerPrintDb;
    use nmap_core::osscan::{
        attribute_distance, render, submission_reason, HostFacts, Report, SubmissionInputs,
    };

    let mut out = String::new();
    let Some(db_text) = load_os_db() else {
        eprintln!("nmap-rs: -O requires nmap-os-db; skipping OS detection");
        return out;
    };
    let db = FingerPrintDb::parse(&db_text);
    if db.prints.is_empty() {
        eprintln!("nmap-rs: nmap-os-db has no usable fingerprints; skipping OS detection");
        return out;
    }

    for host in &mut results.hosts {
        if host.state != HostState::Up {
            continue;
        }
        let v4 = match host.address {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(v6) => {
                // IPv6 OS detection is a different engine end to end: a different probe
                // battery, a different feature vector, and a trained classifier rather
                // than a fingerprint database.
                out.push_str(&run_os_detection6(cfg, &*host, v6).await);
                continue;
            }
        };

        let has_open = host.ports.iter().any(|p| p.state == PortState::Open);
        let has_closed = host.ports.iter().any(|p| p.state == PortState::Closed);
        // nmap's own precondition: without one open and one closed TCP port most of the
        // fingerprint's signal is missing.
        if cfg.osscan_limit && !(has_open && has_closed) {
            eprintln!(
                "nmap-rs: skipping OS detection for {} (--osscan-limit: needs an open and a closed TCP port)",
                host.address
            );
            continue;
        }

        let outcome = nmap_sys::osscan::os_scan_host(
            v4,
            &host.ports,
            &db,
            cfg.max_os_tries.unwrap_or(nmap_sys::osscan::MAX_OS_TRIES),
        )
        .await;
        let (result, selected, _params) = match outcome {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("nmap-rs: -O requires root/CAP_NET_RAW; skipping OS detection");
                return out;
            }
            Err(e) => {
                eprintln!("nmap-rs: -O setup failed for {} ({e})", host.address);
                continue;
            }
        };

        let (Some(observation), Some(matches)) = (result.observation(), result.best_matches())
        else {
            eprintln!("nmap-rs: -O produced no result for {}", host.address);
            continue;
        };

        // A `U1` reply *proves* the port was closed, whether or not we guessed it: the
        // target answered port-unreachable. The C records exactly this in
        // `processTUdpResp` (`if osscan_closedudpport == -1 ... = upi.dport`). A guessed
        // TCP port gets no such confirmation, so it stays unproven.
        let u1_answered = observation
            .fingerprint
            .test(nmap_core::osdb::model::TestId::U1)
            .and_then(|t| t.get("R"))
            == Some("Y");
        let reason = submission_reason(&SubmissionInputs {
            scan_delay_ms: 0,
            timing_level: 3,
            have_open_tcp_port: selected.open_tcp.is_some(),
            have_closed_tcp_port: selected.closed_tcp.is_some() && !selected.closed_tcp_guessed,
            have_closed_udp_port: selected.closed_udp.is_some()
                && (!selected.closed_udp_guessed || u1_answered),
            udp_scan_requested: false,
            distance: observation.distance,
            max_timing_ratio: result.max_timing_ratio,
            incomplete: !result.unsent.is_empty(),
        });

        let facts = HostFacts {
            is_localhost: v4.is_loopback(),
            has_mac_address: false,
        };
        let distance = attribute_distance(facts, observation.distance);

        // The driver now collects these per round; the C keeps them on the target as a
        // side effect of fingerprinting.
        let seq = result.best_seq().cloned().unwrap_or_default();

        // `Uptime guess:` — the C recomputes the elapsed time at print time rather than
        // reusing the derived uptime, and omits the `(since ...)` clause when it cannot
        // format the boot time. Both are reproduced here; formatting needs a clock and a
        // calendar, which is why `core` takes them as data.
        let uptime = result.best_uptime().and_then(|u| {
            if u.lastboot == 0 {
                return None;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_secs()).ok())?;
            Some(nmap_core::osscan::UptimeLine {
                // Clock skew or a clamped boot time can put `lastboot` ahead of now; a
                // negative age would render as a nonsense negative day count.
                seconds: f64::from(
                    i32::try_from(now.saturating_sub(u.lastboot).max(0)).unwrap_or(i32::MAX),
                ),
                since: nmap_core::osscan::format_boot_time(u.lastboot),
            })
        });

        let report = Report {
            matches,
            fingerprint: &observation.fingerprint,
            submission_reason: reason.as_deref(),
            distance,
            seq: &seq,
            uptime,
            open_tcp_port: selected.open_tcp,
            closed_tcp_port: selected.closed_tcp,
            osscan_guess: cfg.osscan_guess,
            reliable: has_open && has_closed,
            verbose: cfg.verbose > 0,
            // `-d` or `-vv`: show the raw observation even when it is unfit to submit.
            // Asking to see it is not the same as being invited to send it in.
            always_show_fingerprint: cfg.debugging > 0 || cfg.verbose > 1,
        };
        let text = render(&report);

        // The same facts, in the shape the XML and grepable renderers need. Built from
        // the *same* values the text just used, so the three outputs cannot disagree.
        host.os = Some(nmap_core::osscan::HostOsReport {
            open_tcp_port: selected.open_tcp,
            closed_tcp_port: selected.closed_tcp,
            closed_udp_port: selected.closed_udp,
            matches: nmap_core::osscan::listed_guesses(matches)
                .into_iter()
                .map(|m| {
                    let record = db.prints.get(m.index);
                    nmap_core::osscan::OsMatchReport {
                        name: m.os_name.clone(),
                        // The C's `(int)(accuracy * 100)` — a C cast, so it TRUNCATES
                        // rather than rounds. Clamped first so a non-finite or
                        // out-of-range accuracy cannot produce an undefined cast.
                        #[allow(
                            clippy::cast_possible_truncation,
                            clippy::cast_sign_loss,
                            reason = "truncation is the C's behaviour and the value is \
                                      clamped to 0..=100 immediately above"
                        )]
                        accuracy_pct: (m.accuracy * 100.0).clamp(0.0, 100.0) as u32,
                        line: record.map_or(0, |r| r.line),
                        classes: record.map(|r| r.classes.clone()).unwrap_or_default(),
                    }
                })
                .collect(),
            // The C writes <osfingerprint> "any time it would be printed to any other
            // output format", so the condition is literally "did the text include it".
            // Asking that directly — rather than sniffing for a header string, which
            // this renderer does not emit and which would have made this silently
            // always-false — keeps the two in step however the text branches change.
            fingerprint: {
                let fp = observation.fingerprint.render_tests();
                (!fp.is_empty() && text.contains(&fp)).then_some(fp)
            },
            uptime: report
                .uptime
                .as_ref()
                .map(|u| nmap_core::osscan::UptimeReport {
                    // The C emits `%.0f`, which ROUNDS — it does not truncate the
                    // way a cast would, so `.round()` comes first. Clamped so a wild
                    // value cannot make the conversion undefined.
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "clamped to i32 range immediately above, so the i64 \
                                  conversion is exact"
                    )]
                    seconds: u
                        .seconds
                        .round()
                        .clamp(f64::from(i32::MIN), f64::from(i32::MAX))
                        as i64,
                    lastboot: u.since.clone(),
                }),
            distance: distance.hops.map(i32::from),
            seq: seq.clone(),
        });

        out.push_str(&text);
    }
    out
}

/// IPv6 OS detection for one host — the `-6 -O` branch.
///
/// Unlike IPv4 this is a classifier, not a database lookup: the battery is scored into a
/// 695-feature vector and run through nmap's trained model, so the output is the model's
/// ranked guesses rather than a fingerprint match.
#[cfg(feature = "pcap")]
async fn run_os_detection6(
    cfg: &RunConfig,
    host: &nmap_core::model::Host,
    v6: std::net::Ipv6Addr,
) -> String {
    use nmap_core::fpmodel::FpModel;

    let mut out = String::new();
    let model = match FpModel::load() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("nmap-rs: -6 -O needs the IPv6 fingerprint model ({e:?}); skipping {v6}");
            return out;
        }
    };

    let outcome = nmap_sys::fpengine::os_scan_host6(v6, &host.ports, &model).await;
    let (observation, results, _params) = match outcome {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("nmap-rs: -6 -O requires root/CAP_NET_RAW; skipping {v6}");
            return out;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
            // No route, or the next hop never answered a neighbor solicitation. Without
            // its MAC no IPv6 probe can be framed — there is no L3 fallback on Linux.
            eprintln!("nmap-rs: -6 -O cannot reach {v6} ({e}); skipping");
            return out;
        }
        Err(e) => {
            eprintln!("nmap-rs: -6 -O setup failed for {v6} ({e})");
            return out;
        }
    };

    if results.matches.is_empty() {
        out.push_str("No OS matches for host (IPv6)\n");
    } else {
        out.push_str("OS guesses (IPv6):\n");
        for m in &results.matches {
            let pct = m.accuracy * 100.0;
            out.push_str(&format!("  {} ({pct:.0}%)\n", m.os_name));
        }
    }
    if cfg.debugging > 0 || cfg.verbose > 1 {
        out.push_str(&format!(
            "IPv6 observation: distance {} ({:?})\n",
            observation.distance, observation.distance_method
        ));
    }
    out
}

/// Without the `pcap` feature there is no capture backend, so `-O` cannot run.
#[cfg(not(feature = "pcap"))]
fn run_os_detection(_cfg: &RunConfig, _results: &mut ScanResults) -> String {
    eprintln!(
        "nmap-rs: -O requires a --features pcap build with raw-socket privilege; skipping OS detection"
    );
    String::new()
}

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
        "Usage: nmap-rs [-sT|-sS|-sU|-sA|-sW|-sM|-sF|-sN|-sX] [-sV [...]]\n              [-p <ports>] [-6] [-Pn] [-oN|-oX|-oG <file|->] [-v|-d] <target...>"
    );
    println!("  Scan types: -sT connect (default) | -sS SYN | -sU UDP | -sA ACK | -sW Window");
    println!("              | -sM Maimon | -sF FIN | -sN Null | -sX Xmas. The raw scans need");
    println!("              root + a --features pcap build; they fall back to -sT otherwise.");
    println!("  Plus -sV service/version detection and -O OS detection");
    println!("       (--osscan-guess to report near matches, --osscan-limit to skip");
    println!("        hosts without both an open and a closed port; -A implies -sV -O).");
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
/// Locate `nmap-os-db`, mirroring [`load_services`]'s search order. `None` if absent —
/// `-O` then degrades to a warning rather than a silent no-op.
#[cfg(feature = "pcap")]
fn load_os_db() -> Option<String> {
    let candidates = [
        std::env::var_os("NMAP_RS_DATADIR").map(|d| {
            let mut p = std::path::PathBuf::from(d);
            p.push("nmap-os-db");
            p
        }),
        Some("nmap-os-db".into()),
        Some("../nmap-os-db".into()),
        Some("../../nmap-os-db".into()),
        Some("/usr/share/nmap/nmap-os-db".into()),
    ];
    for cand in candidates.into_iter().flatten() {
        if let Ok(text) = std::fs::read_to_string(&cand) {
            nmap_core::debug!(1, "loaded os-db from {}", cand.display());
            return Some(text);
        }
    }
    None
}

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
