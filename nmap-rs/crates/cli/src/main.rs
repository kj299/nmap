//! `nmap-rs` — the CLI binary. Thin by design: parse args, resolve targets and
//! ports, run the connect scan, render. All the real logic lives in `nmap-core`
//! (pure, testable) and `nmap-sys` (the async I/O). Milestone 1 wires the
//! unprivileged connect-scan MVP: `nmap-rs [-sT] [-p SPEC] [-6] [-Pn]
//! [-oN/-oX/-oG FILE|-] [-v|-d] TARGET...`.

use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nmap_core::build::PacketOverrides;
use nmap_core::matcher::CompiledDb;
use nmap_core::model::{HostState, PortState, ServiceInfo};
use nmap_core::options::{RunConfig, ScanKind};
use nmap_core::probedb::ProbeDb;
use nmap_core::servicescan::VersionResult;
use nmap_core::{
    exclude_specs, host_specs, parse_args, parse_port_spec, parse_target, render_grepable,
    render_normal, render_xml, Added, ExcludeSet, ScanMeta, ScanResults, ServiceTable, TargetSpec,
    TimingParams, TimingTemplate,
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
    let mut cfg = parse_args(&args);
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
    // Refuse to scan on an option we do not implement.
    //
    // This used to warn and carry on, which is the wrong posture for a scanner
    // and diverged from the C. Two things went wrong at once:
    //
    //  * Most of the unimplemented options CONSTRAIN the scan — `--exclude`,
    //    `--scan-delay`, `-T`, `--max-retries`, `--top-ports`. Ignoring a
    //    constraint means scanning more hosts, or faster, than the operator
    //    asked for. "Warn and continue" turns every one of those into a
    //    silent widening.
    //  * An unimplemented option that takes a VALUE left its value in argv,
    //    where the positional handler collected it as a target. So
    //    `--exclude 10.0.0.5` did not merely fail to exclude 10.0.0.5 — it
    //    added it to the scan. Naming a host to protect it was the thing that
    //    got it scanned.
    //
    // C nmap does not do this: an unrecognised option reaches `case '?'` in
    // `nmap.cc:653`'s getopt loop, which calls `error()` and `exit(-1)` without
    // scanning anything. Failing closed here restores that behaviour and is
    // the safe direction besides.
    // A recognized option with an unusable argument. C `fatal()`s on each of
    // these; the message is C's, because an operator who hits it will be
    // searching for C's wording.
    if !cfg.invalid.is_empty() {
        for msg in &cfg.invalid {
            eprintln!("nmap-rs: {msg}");
        }
        return ExitCode::FAILURE;
    }
    // Fail closed on the two knobs this engine cannot yet honour. Accepting
    // them would be the M7.0 mistake in a new place: `--max-hostgroup 5` that
    // does nothing scans every target at once, which is louder than the
    // operator asked for, and a `--host-timeout` that does nothing runs past a
    // bound they set. Refusing is noisy; silently exceeding an explicit limit
    // is worse. Both are tracked in docs/M7.3-CLI-PARITY.md.
    if cfg.host_timeout_ms.is_some() {
        eprintln!(
            "nmap-rs: --host-timeout is parsed but not yet enforced — this engine has no \
             per-host deadline, so honouring it would be a lie. Refusing rather than \
             running past the bound you set."
        );
        return ExitCode::FAILURE;
    }
    if cfg.min_hostgroup.is_some() || cfg.max_hostgroup.is_some() {
        eprintln!(
            "nmap-rs: --min-hostgroup/--max-hostgroup are parsed but not yet enforced — this \
             engine scans a route's targets as one group, so a hostgroup ceiling would not \
             limit concurrency. Refusing rather than scanning wider than you asked."
        );
        return ExitCode::FAILURE;
    }
    if let Some(msg) = cfg.hostgroup_error() {
        eprintln!("nmap-rs: {msg}");
        return ExitCode::FAILURE;
    }
    for msg in cfg.timing_warnings() {
        eprintln!("{msg}");
    }

    if !cfg.unrecognized.is_empty() {
        for flag in &cfg.unrecognized {
            eprintln!("nmap-rs: unrecognized or unsupported option '{flag}'");
        }
        eprintln!(
            "nmap-rs: refusing to scan — an unimplemented option may widen the scan \
             beyond what you asked for, and its argument would be read as a target."
        );
        eprintln!("See the output of nmap-rs -h for a summary of supported options.");
        return ExitCode::FAILURE;
    }
    // `-iL`: C allows exactly one (`fatal("Only one input filename allowed")`).
    // Refuse rather than pick one — scanning the wrong list is worse than not
    // scanning.
    if cfg.input_file_repeated {
        eprintln!("nmap-rs: only one input filename allowed (-iL given more than once)");
        return ExitCode::FAILURE;
    }
    // Target specs from `-iL`, appended AFTER the positional ones. That order is
    // the C's: `grab_next_host_spec` (libnetutil/netutil.cc:3783) returns argv
    // entries while `optind < argc` and only then reads the input file.
    if let Some(path) = cfg.input_file.clone() {
        match read_host_list(&path) {
            Ok(specs) => cfg.targets.extend(specs),
            Err(e) => {
                eprintln!("nmap-rs: failed to read input file \"{path}\": {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if cfg.targets.is_empty() {
        eprintln!("nmap-rs: no targets specified");
        print_usage();
        return ExitCode::FAILURE;
    }

    // Exclusions from `--exclude` and `--excludefile`, which combine: C loads
    // both into one `exclude_group` (nmap.cc:2070-2074).
    // `-S` once only, matching C's
    // `fatal("You can only use the source option once!")`. Two source addresses
    // is not a preference to resolve — it is an ambiguous command.
    if cfg.spoof_source_repeated {
        eprintln!("nmap-rs: you can only use the source option (-S) once");
        return ExitCode::FAILURE;
    }
    let overrides = match packet_overrides(&cfg) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("nmap-rs: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Raw-only options with a scan that cannot send raw packets. C warns and
    // continues here (nmap.cc:1817) and so do we — these options shape packets
    // rather than constrain scope, so ignoring one does not scan more hosts or
    // faster, and the M7.0 fail-closed rule is not engaged. The message names
    // which options were dropped, which C's does not.
    if cfg.raw_scan_options && cfg.scan == ScanKind::Connect {
        let mut dropped: Vec<&str> = Vec::new();
        if cfg.ttl.is_some() {
            dropped.push("--ttl");
        }
        if cfg.bad_sum {
            dropped.push("--badsum");
        }
        if cfg.spoof_source.is_some() {
            dropped.push("-S");
        }
        eprintln!(
            "nmap-rs: {} {} raw socket access and will not be honored for TCP connect scan",
            dropped.join(", "),
            if dropped.len() == 1 {
                "requires"
            } else {
                "require"
            }
        );
    }

    let excludes = match build_excludes(&cfg).await {
        Ok(set) => set,
        Err(e) => {
            eprintln!("nmap-rs: {e}");
            eprintln!(
                "nmap-rs: refusing to scan — an exclusion that cannot be applied would \
                 scan a host you asked to protect."
            );
            return ExitCode::FAILURE;
        }
    };

    // C: fatal("You cannot use -F (fast scan) or -p (explicit port selection)
    // when not doing a port scan") — nmap.cc:1584. Refusing rather than
    // ignoring matters for the same reason the rest of this CLI refuses: an
    // operator who wrote `-sL -p 80` has asked for two incompatible things, and
    // silently honouring one is a guess about which they meant.
    if cfg.scan == ScanKind::List && (cfg.port_spec.is_some() || cfg.fast_scan) {
        eprintln!(
            "nmap-rs: You cannot use -F (fast scan) or -p (explicit port selection) when not doing a port scan"
        );
        return ExitCode::FAILURE;
    }
    // C: nmap.cc:1587. The message names the way out, so it is reproduced in
    // full -- an operator who wanted "-F but only these ports" is being told
    // which option actually does that.
    if cfg.port_spec.is_some() && cfg.fast_scan {
        eprintln!(
            "nmap-rs: You cannot use -F (fast scan) with -p (explicit port selection) but see --top-ports and --port-ratio to fast scan a range of ports"
        );
        return ExitCode::FAILURE;
    }
    if cfg.exclude_ports_repeated {
        eprintln!(
            "nmap-rs: Only 1 --exclude-ports option allowed, separate multiple ranges with commas."
        );
        return ExitCode::FAILURE;
    }
    // The two checks C defers to `gettoppts` rather than doing at parse time,
    // reproduced at the same point and with the same wording. `--port-ratio 0`
    // passes the parse-time range test (`< 0 || >= 1`) and dies here.
    if let Some(level) = cfg.top_port_level {
        if level <= 0.0 {
            eprintln!(
                "nmap-rs: Argument to gettoppts ({}) should be a positive ratio below 1 or an integer of 1 or higher",
                nmap_core::options::g6(level)
            );
            return ExitCode::FAILURE;
        }
        if level > 65536.0 {
            eprintln!(
                "nmap-rs: Level argument to gettoppts ({}) is too large",
                nmap_core::options::g6(level)
            );
            return ExitCode::FAILURE;
        }
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
    let mut targets = resolve_targets(&cfg).await;
    let mut excluded_all = false;
    if !excludes.is_empty() {
        let before = targets.len();
        targets.retain(|(ip, _)| !excludes.contains(*ip));
        let dropped = before.saturating_sub(targets.len());
        if dropped > 0 {
            nmap_core::verbose!(1, "excluded {dropped} host(s)");
        }
        excluded_all = before > 0 && targets.is_empty();
    }
    if targets.is_empty() {
        // Distinguish "nothing resolved" from "you excluded everything". They
        // need opposite reactions from the operator, and reporting a successful
        // exclusion as a resolution failure would send them looking for a bug
        // that is not there.
        if excluded_all {
            eprintln!("nmap-rs: no targets left to scan — every host matched an exclusion");
        } else {
            eprintln!("nmap-rs: no scannable targets (all failed to resolve or expand)");
        }
        return ExitCode::FAILURE;
    }

    // The scan engine derives its per-probe timeout adaptively from observed
    // RTTs and paces probes by the congestion window, so the CLI passes the
    // timing *template* rather than a fixed timeout. `-T` selects it; the
    // explicit knobs (--scan-delay, --max-rtt-timeout, …) are folded in by
    // `timing_params` in nmap's own order, so they win over -T regardless of
    // where they appeared on the command line.
    let timing = cfg.timing_params();
    let template = cfg.timing_template.unwrap_or(TimingTemplate::Normal);
    let max_par = timing.max_parallelism as usize;

    let ips: Vec<IpAddr> = targets.iter().map(|(ip, _)| *ip).collect();
    let started = now_string();
    let clock = Instant::now();
    let mut results = run_scan(&cfg, &ips, &ports, template, timing, max_par, overrides).await;
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
    params: TimingParams,
    max_par: usize,
    overrides: PacketOverrides,
) -> ScanResults {
    use nmap_core::classify::ScanType;
    match cfg.scan {
        // `-sL` sends nothing at all. C sets listscan + noportscan +
        // PINGTYPE_NONE (nmap.cc:1307), so the targets are expanded, reported
        // and that is the whole scan. Their liveness is `Unknown` rather than
        // `Down` because we never asked — see the renderers, and C's grepable
        // `Status: Unknown`.
        ScanKind::List => ScanResults {
            hosts: ips
                .iter()
                .map(|ip| nmap_core::model::Host::new(*ip, nmap_core::model::HostState::Unknown))
                .collect(),
        },
        ScanKind::Connect => {
            connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
        }
        ScanKind::Syn => {
            syn_or_fallback(cfg, ips, ports, template, params, max_par, overrides).await
        }
        ScanKind::Udp => {
            udp_or_fallback(cfg, ips, ports, template, params, max_par, overrides).await
        }
        ScanKind::Ack => {
            flag_or_fallback(
                cfg,
                ips,
                ports,
                template,
                params,
                max_par,
                ScanType::Ack,
                overrides,
            )
            .await
        }
        ScanKind::Window => {
            flag_or_fallback(
                cfg,
                ips,
                ports,
                template,
                params,
                max_par,
                ScanType::Window,
                overrides,
            )
            .await
        }
        ScanKind::Maimon => {
            flag_or_fallback(
                cfg,
                ips,
                ports,
                template,
                params,
                max_par,
                ScanType::Maimon,
                overrides,
            )
            .await
        }
        ScanKind::Fin => {
            flag_or_fallback(
                cfg,
                ips,
                ports,
                template,
                params,
                max_par,
                ScanType::Fin,
                overrides,
            )
            .await
        }
        ScanKind::Null => {
            flag_or_fallback(
                cfg,
                ips,
                ports,
                template,
                params,
                max_par,
                ScanType::Null,
                overrides,
            )
            .await
        }
        ScanKind::Xmas => {
            flag_or_fallback(
                cfg,
                ips,
                ports,
                template,
                params,
                max_par,
                ScanType::Xmas,
                overrides,
            )
            .await
        }
    }
}

/// Assemble a connect-scan config from the run config and resolved ports.
fn connect_cfg(
    cfg: &RunConfig,
    ports: &[u16],
    template: TimingTemplate,
    params: TimingParams,
    max_par: usize,
) -> ConnectScanConfig {
    ConnectScanConfig {
        ports: ports.to_vec(),
        template,
        // Passed in already resolved (template + the explicit knobs). The
        // engine used to re-derive this from the template alone, which
        // silently dropped --max-rtt-timeout, --max-retries and --scan-delay.
        params,
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
    params: TimingParams,
    max_par: usize,
    overrides: PacketOverrides,
) -> ScanResults {
    match nmap_sys::synscan::syn_scan_targets(ips, ports, template, params, max_par, overrides)
        .await
    {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "nmap-rs: -sS requires root/CAP_NET_RAW; falling back to a connect scan (-sT)"
            );
            connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
        }
        Err(e) => {
            eprintln!("nmap-rs: -sS setup failed ({e}); falling back to a connect scan (-sT)");
            connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
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
    params: TimingParams,
    max_par: usize,
    // Signature parity with the pcap build; nothing here sends packets.
    _overrides: PacketOverrides,
) -> ScanResults {
    eprintln!(
        "nmap-rs: this build lacks raw-scan support (rebuild with --features pcap); running a connect scan (-sT)"
    );
    connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
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
    params: TimingParams,
    max_par: usize,
    overrides: PacketOverrides,
) -> ScanResults {
    match nmap_sys::udpscan::udp_scan_targets(
        ips,
        ports,
        template,
        params,
        max_par,
        udp_payloads(),
        overrides,
    )
    .await
    {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "nmap-rs: -sU requires root/CAP_NET_RAW; falling back to a TCP connect scan (-sT)"
            );
            connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
        }
        Err(e) => {
            eprintln!("nmap-rs: -sU setup failed ({e}); falling back to a TCP connect scan (-sT)");
            connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
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
    params: TimingParams,
    max_par: usize,
    // Signature parity with the pcap build; nothing here sends packets.
    _overrides: PacketOverrides,
) -> ScanResults {
    eprintln!(
        "nmap-rs: this build lacks raw-scan support (rebuild with --features pcap); running a TCP connect scan (-sT)"
    );
    connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
}

/// Run a stateless TCP flag scan (`-sA`/`-sW`/`-sM`/`-sF`/`-sN`/`-sX`), falling back to
/// a connect scan on missing privilege or setup failure (built with `pcap`).
// One argument over the limit since the resolved `TimingParams` joined the
// template. Grouping them into a struct would only move the same fields behind
// a name that no other call site wants.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "pcap")]
async fn flag_or_fallback(
    cfg: &RunConfig,
    ips: &[IpAddr],
    ports: &[u16],
    template: TimingTemplate,
    params: TimingParams,
    max_par: usize,
    scan: nmap_core::classify::ScanType,
    overrides: PacketOverrides,
) -> ScanResults {
    match nmap_sys::flagscan::flag_scan_targets(
        scan, ips, ports, template, params, max_par, overrides,
    )
    .await
    {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "nmap-rs: this scan requires root/CAP_NET_RAW; falling back to a connect scan (-sT)"
            );
            connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
        }
        Err(e) => {
            eprintln!("nmap-rs: raw scan setup failed ({e}); falling back to a connect scan (-sT)");
            connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
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
    params: TimingParams,
    max_par: usize,
    _scan: nmap_core::classify::ScanType,
    // Signature parity with the pcap build; nothing here sends packets.
    _overrides: PacketOverrides,
) -> ScanResults {
    eprintln!(
        "nmap-rs: this build lacks raw-scan support (rebuild with --features pcap); running a TCP connect scan (-sT)"
    );
    connect_scan(ips, &connect_cfg(cfg, ports, template, params, max_par)).await
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

    // Gather open TCP ports per host, in the host order `service_scan` expects,
    // minus the ports `nmap-service-probes` tells us not to probe.
    //
    // The probe file opens with `Exclude T:9100-9107` — the JetDirect printer
    // ports, where a version probe is not a read but a *print job*. C honours it
    // (`service_scan.cc:1447`), and `--allports` is the flag that overrides it.
    //
    // This port parsed the directive from M3 on, unit-tested it
    // (`probedb::is_excluded(9100, Tcp)`), and then called it from nowhere. So
    // `-sV` here behaved exactly like C's `-sV --allports`:
    //
    //     $ nmap    -sV -Pn -n -p 9100 127.0.0.1   ->  9100/tcp open  jetdirect?
    //     $ nmap-rs -sV -Pn -n -p 9100 127.0.0.1   ->  9100/tcp open  tcpwrapped
    //
    // `tcpwrapped` is a *probe result*: proof the probes went out. A test that
    // asserts the parser and never the behaviour is the shape of LESSONS #027,
    // and this is the sharpest instance of it in the port so far.
    let mut skipped_excluded = 0usize;
    let open: Vec<(IpAddr, Vec<u16>)> = results
        .hosts
        .iter()
        .map(|h| {
            let ports = h
                .ports
                .iter()
                .filter(|p| p.state == PortState::Open && p.protocol == nmap_core::Protocol::Tcp)
                .filter(|p| {
                    if cfg.allports || !db.is_excluded(p.number, nmap_core::Protocol::Tcp) {
                        return true;
                    }
                    skipped_excluded = skipped_excluded.saturating_add(1);
                    false
                })
                .map(|p| p.number)
                .collect();
            (h.address, ports)
        })
        .collect();
    if skipped_excluded > 0 {
        // C says the same thing the other way round, when the override is on:
        // "Overriding exclude ports option! Some undesirable ports may be
        // version scanned!" Saying it in the quiet direction too means the
        // operator can tell a port was left alone on purpose.
        nmap_core::verbose!(
            1,
            "{skipped_excluded} port(s) not version-scanned (nmap-service-probes Exclude); --allports overrides"
        );
    }
    if open.iter().all(|(_, ports)| ports.is_empty()) {
        return; // nothing open to probe
    }

    // The C's fingerprint header carries NMAP_VERSION, NMAP_PLATFORM and the local
    // month/day from `localtime()`. `core::servicefp` reads none of that itself --
    // that purity is what lets its differential be byte-exact -- so the boundary
    // supplies it here. UTC rather than local time, matching `-O`'s boot-time line
    // (ledgered `uptime-boot-time-in-utc`): one convention across the port, and no
    // timezone-database dependency for two integers.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (month, day) = nmap_core::osscan::civil_from_epoch(i64::try_from(now_secs).unwrap_or(0))
        .map_or((0, 0), |(_, m, d, ..)| {
            (i32::try_from(m).unwrap_or(0), i32::try_from(d).unwrap_or(0))
        });

    let sv_cfg = ServiceScanConfig {
        intensity: cfg.version_intensity,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        platform: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
        header_month: month,
        header_day: day,
        header_time: i32::try_from(now_secs & 0x7fff_ffff).unwrap_or(0),
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
    // Carried through verbatim: the builder already escaped it, and re-escaping
    // would double every backslash the transcript legitimately contains.
    svc.fingerprint = r.fingerprint.clone();
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

/// Choose the TCP ports to scan — this port's `gettoppts` (`services.cc:390`).
///
/// The shape is C's, and the order of the three steps is what makes it correct:
///
///   1. **Candidates.** `-p` names them explicitly; otherwise every port is a
///      candidate.
///   2. **`--exclude-ports` removes from the candidates FIRST**, before the top-N
///      cut. C is explicit about this — "the specified ports are excluded first
///      and only then are the top N ports taken" — and the order is observable:
///      excluding afterwards would return fewer than N ports, while excluding
///      first backfills with the next most common ones. Getting it backwards
///      silently scans less than asked, which is the quieter failure but still
///      the scanner not doing what it was told.
///   3. **The level.** `>= 1` is a count, `(0, 1)` is a minimum ratio, absent is
///      1000 (or 100 under `-F`).
///
/// With `-p` and no explicit level, the port list is used as given and no
/// top-ports cut happens at all (`services.cc:416`).
fn select_ports(
    cfg: &RunConfig,
    services: Option<&ServiceTable>,
) -> Result<Vec<u16>, nmap_core::PortSpecError> {
    // The candidate set, before any top-N cut.
    let explicit: Option<Vec<u16>> = match &cfg.port_spec {
        Some(spec) => Some(parse_port_spec(spec, services)?.tcp),
        None => None,
    };

    // `--exclude-ports` applies to the candidates, whatever they are.
    let excluded: Option<Vec<u16>> = match &cfg.exclude_ports {
        Some(spec) => Some(parse_port_spec(spec, services)?.tcp),
        None => None,
    };
    let keep = |p: &u16| excluded.as_ref().is_none_or(|ex| !ex.contains(p));

    let Some(table) = services else {
        // No nmap-services: fall back to the historical 1-1024 sweep, which is
        // what C does for an old-style file without ratios (`services.cc:411`).
        let base: Vec<u16> = explicit.unwrap_or_else(|| (1u16..=1024).collect());
        return Ok(base.into_iter().filter(keep).collect());
    };

    // `-p` with no --top-ports/--port-ratio: use the list as given.
    if cfg.top_port_level.is_none() && !cfg.fast_scan {
        if let Some(list) = explicit {
            return Ok(list.into_iter().filter(keep).collect());
        }
    }

    let level = cfg.top_port_level.unwrap_or(if cfg.fast_scan {
        100.0
    } else {
        f64::from(u32::try_from(DEFAULT_TOP_PORTS).unwrap_or(1000))
    });

    // A ratio (0, 1) selects by frequency; 1 or more is a count.
    let ranked: Vec<u16> = if level < 1.0 {
        table.ports_above_ratio(nmap_core::Protocol::Tcp, level)
    } else {
        // Take the whole ranking and cut after filtering, so that an excluded
        // port does not consume one of the N slots -- step 2 above.
        table.top_ports(nmap_core::Protocol::Tcp, usize::MAX)
    };

    let mut out: Vec<u16> = ranked
        .into_iter()
        .filter(|p| explicit.as_ref().is_none_or(|list| list.contains(p)))
        .filter(keep)
        .collect();
    if level >= 1.0 {
        // Bounded above by the 65536 check the CLI already made, and `level`
        // is integral here because `--top-ports` rejects a non-integral value.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let n = usize::try_from(level as u64).unwrap_or(usize::MAX);
        out.truncate(n);
    }
    out.sort_unstable();
    if out.is_empty() && explicit.is_none() && cfg.exclude_ports.is_none() {
        return Ok((1u16..=1024).collect());
    }
    Ok(out)
}

/// Build the IP-layer overrides (`--ttl`, `--badsum`, `-S`) from the parsed
/// options.
///
/// Only `-S` can fail, and it fails rather than falling back: an operator who
/// asked to send from a particular address and silently got the routed one has
/// been told something untrue about their own traffic. C resolves this argument
/// through `resolve()`, so a hostname works there; here it must be an IPv4
/// literal, which is a narrow divergence recorded in `DIVERGENCES.md`.
fn packet_overrides(cfg: &RunConfig) -> Result<PacketOverrides, String> {
    let spoof_src = match &cfg.spoof_source {
        None => None,
        Some(a) => match a.trim().parse::<std::net::Ipv4Addr>() {
            Ok(ip) => Some(ip.octets()),
            Err(_) => {
                return Err(format!(
                    "-S expects an IPv4 address, got \"{a}\" (names are not resolved here)"
                ))
            }
        },
    };
    Ok(PacketOverrides {
        ttl: cfg.ttl,
        bad_sum: cfg.bad_sum,
        spoof_src,
    })
}

/// Read a `-iL` / `--excludefile` list into host specifications.
///
/// `-` means stdin, as in C (`o.inputfd = stdin`). Any read failure is an error
/// the caller must refuse on: C `pfatal`s here, and the safe direction is the
/// same one — a target list we could not read is not an empty list, and an
/// exclusion list we could not read must never become "exclude nothing".
fn read_host_list(path: &str) -> Result<Vec<String>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
    } else {
        bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    }
    match host_specs(&bytes) {
        Ok(specs) => Ok(specs.into_iter().map(str::to_string).collect()),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// Build the exclusion set from `--exclude` and `--excludefile` combined.
///
/// Every failure path refuses, and that is the whole point of this function.
/// An exclusion is the operator saying "not this host"; if we cannot parse it,
/// cannot read it, or cannot resolve it, the only safe answer is to stop. The
/// alternative — carrying on with a partial exclusion set — scans exactly the
/// host the operator took an explicit step to protect, which is the failure
/// M7.0 found and this milestone exists to close.
async fn build_excludes(cfg: &RunConfig) -> Result<ExcludeSet, String> {
    let mut set = ExcludeSet::new();
    let mut pending_names: Vec<String> = Vec::new();

    let add = |set: &mut ExcludeSet, spec: &str, names: &mut Vec<String>| -> Result<(), String> {
        match set.add(spec, cfg.ipv6) {
            Ok(Added::Numeric) => Ok(()),
            Ok(Added::NeedsResolution(n)) => {
                names.push(n);
                Ok(())
            }
            Err(e) => Err(format!("bad exclusion \"{spec}\": {e:?}")),
        }
    };

    if let Some(spec) = &cfg.exclude {
        for one in exclude_specs(spec) {
            add(&mut set, one, &mut pending_names)?;
        }
    }
    if let Some(path) = &cfg.exclude_file {
        let specs = read_host_list(path)
            .map_err(|e| format!("failed to read exclude file \"{path}\": {e}"))?;
        for one in &specs {
            add(&mut set, one, &mut pending_names)?;
        }
    }

    // A named exclusion has to become addresses before it can exclude anything.
    // C resolves these too (`load_exclude_file` runs them through
    // `nmap_mass_dns`). A name we cannot resolve is an error, not a warning.
    for name in pending_names {
        match resolve_host(&name).await {
            Ok(ips) if !ips.is_empty() => {
                for ip in ips {
                    set.add_addr(ip);
                }
            }
            Ok(_) => return Err(format!("excluded name \"{name}\" resolved to no addresses")),
            Err(e) => return Err(format!("could not resolve excluded name \"{name}\": {e}")),
        }
    }
    Ok(set)
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

#[cfg(test)]
mod port_selection_tests {
    //! `select_ports` against C nmap itself.
    //!
    //! The golden files in `tests/differential/m7/topports/` are the exact port
    //! sets the installed `nmap` probes, captured with `--packet-trace` — the
    //! real binary, not a transcription of it.
    //!
    //! **They were generated with `--datadir` pointing at this repository**, and
    //! that is not a detail. `nmap` on this machine reads
    //! `/usr/share/nmap/nmap-services`, which is a *different file* from the
    //! one in the tree: `wsman` (5985/tcp) carries ratio 0.000076 in one and
    //! 0.000380 in the other. Comparing against the installed file produced four
    //! confident "divergences" at N=500 that were nothing but two databases
    //! disagreeing. A differential against a data-driven tool has to pin the
    //! data, not just the binary.
    use super::*;

    fn table() -> ServiceTable {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../nmap-services");
        ServiceTable::parse(&std::fs::read_to_string(path).expect("nmap-services"))
    }

    fn golden(name: &str) -> Vec<u16> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/differential/m7/topports")
            .join(name);
        std::fs::read_to_string(path)
            .expect("golden")
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    fn selected(args: &[&str]) -> Vec<u16> {
        let cfg = parse_args(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>());
        assert!(
            cfg.invalid.is_empty(),
            "{args:?} did not parse: {:?}",
            cfg.invalid
        );
        let t = table();
        let mut v = select_ports(&cfg, Some(&t)).expect("select_ports");
        v.sort_unstable();
        v
    }

    #[test]
    fn top_ports_matches_c_nmap() {
        for n in [1usize, 2, 5, 10, 20, 50, 100, 250, 500, 1000] {
            assert_eq!(
                selected(&["--top-ports", &n.to_string(), "127.0.0.1"]),
                golden(&format!("top-{n}.txt")),
                "--top-ports {n}"
            );
        }
    }

    /// `--port-ratio` selects by open-frequency instead of by count. The
    /// comparison is `>=`, so a port whose ratio exactly equals the level is in.
    #[test]
    fn port_ratio_matches_c_nmap() {
        for r in ["0.1", "0.05", "0.01", "0.005", "0.001"] {
            assert_eq!(
                selected(&["--port-ratio", r, "127.0.0.1"]),
                golden(&format!("ratio-{r}.txt")),
                "--port-ratio {r}"
            );
        }
    }

    /// `-F` is exactly `--top-ports 100` — verified against the reference
    /// rather than assumed from `services.cc:421`.
    #[test]
    fn fast_scan_is_the_top_100() {
        assert_eq!(selected(&["-F", "127.0.0.1"]), golden("fastscan.txt"));
        assert_eq!(
            selected(&["-F", "127.0.0.1"]),
            selected(&["--top-ports", "100", "127.0.0.1"])
        );
    }

    /// THE ordering property. C excludes first and takes the top N second, so
    /// an excluded port does not consume one of the N slots — the list is
    /// backfilled with the next most common ports and still has N entries.
    ///
    /// Cutting first and excluding second would return N-2 here. That is the
    /// quieter failure (it scans less, not more), but it is still the scanner
    /// not doing what it was told, and nothing in the output would say so.
    #[test]
    fn exclude_ports_applies_before_the_top_n_cut() {
        let with = selected(&[
            "--top-ports",
            "20",
            "--exclude-ports",
            "80,443",
            "127.0.0.1",
        ]);
        assert_eq!(with.len(), 20, "the list must be backfilled, not shortened");
        assert!(!with.contains(&80) && !with.contains(&443));

        let plain = selected(&["--top-ports", "20", "127.0.0.1"]);
        let backfilled: Vec<u16> = with
            .iter()
            .copied()
            .filter(|p| !plain.contains(p))
            .collect();
        assert_eq!(
            backfilled.len(),
            2,
            "exactly the two excluded slots should be refilled, got {backfilled:?}"
        );
    }

    /// `-p` narrows the candidates; `--top-ports` then ranks within them.
    #[test]
    fn an_explicit_port_list_bounds_the_top_n() {
        assert_eq!(
            selected(&["-p", "1-200", "--top-ports", "5", "127.0.0.1"]),
            [21, 22, 23, 25, 80]
        );
    }

    /// `-p` with no level is used as given — no top-ports cut at all.
    #[test]
    fn an_explicit_port_list_alone_is_untouched() {
        assert_eq!(
            selected(&["-p", "20-25", "127.0.0.1"]),
            [20, 21, 22, 23, 24, 25]
        );
        assert_eq!(
            selected(&["-p", "20-30", "--exclude-ports", "22-25", "127.0.0.1"]),
            [20, 21, 26, 27, 28, 29, 30]
        );
    }
}
