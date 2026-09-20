//! Output rendering — normal, grepable (`-oG`), and XML (`-oX`) — the Rust
//! analog of `output.cc` / `xml.cc`. Pure functions over [`ScanResults`]: no I/O
//! and no clock reads (time strings are injected by the caller, so rendering is
//! deterministic and unit-testable, and the differential harness can normalize
//! them).
//!
//! Milestone 1 covers the connect-scan surface: the per-host port table, the
//! "Not shown" summary of ignored states, and the corresponding grepable/XML
//! shapes. Latency, OS, traceroute, and script output arrive in later
//! milestones.

use std::fmt::Write as _;

use crate::model::{Host, PortState, Protocol, ScanResults};
use crate::ports::ServiceTable;

/// Per-run metadata the renderers need. Times are pre-formatted strings so the
/// core stays clock-free; the CLI injects real values, tests inject fixed ones.
#[derive(Clone, Copy, Debug)]
pub struct ScanMeta<'a> {
    /// Scanner name, e.g. `"nmap-rs"`.
    pub scanner: &'a str,
    /// Scanner version, e.g. `"0.1.0"`.
    pub version: &'a str,
    /// The full command line, for the XML `args` attribute.
    pub args: &'a str,
    /// Human-readable start time for the banner (normalized in diffs).
    pub started: &'a str,
    /// Elapsed wall-clock seconds for the footer (normalized in diffs).
    pub elapsed_secs: f64,
    /// Whether `-sV` was requested — adds the VERSION column / `<service>` version
    /// attributes to the output, matching nmap.
    pub service_version: bool,
    /// `--open`: force every non-open state into the summary, and drop hosts
    /// with no open ports entirely.
    pub open_only: bool,
    /// `--reason`: add the REASON column and the host-liveness reason.
    pub reason: bool,
    /// `-v` / `-d` levels. They are here because nmap's decision about which
    /// ports to *list* rather than summarize scales with them
    /// (`portlist.cc:811`), so the renderer cannot make that call without them.
    pub verbose: u8,
    pub debugging: u8,
}

/// Assemble the human-readable VERSION column for a port from its `-sV` fields,
/// in nmap's order: `product version (extrainfo)`, with `ostype`/`devicetype`
/// appended when present. Empty string if nothing was determined.
fn version_display(svc: &crate::model::ServiceInfo) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(p) = &svc.product {
        parts.push(p.clone());
    }
    if let Some(v) = &svc.version {
        parts.push(v.clone());
    }
    let mut s = parts.join(" ");
    if let Some(info) = &svc.extra_info {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(&format!("({info})"));
    }
    s
}

/// Is this state summarized ("Not shown" / `<extraports>`) rather than listed?
///
/// A port of C's `PortList::isIgnoredState` (`portlist.cc:785`). **This used to
/// be `matches!(state, Open | OpenFiltered)`** — i.e. this port always behaved
/// as though `--open` had been given, summarizing every closed port however few
/// there were. C lists them until a state exceeds a threshold:
///
/// ```console
/// $ nmap    -sT -Pn -n -p 18080,18081,18443,19999 127.0.0.1
/// 18080/tcp open   unknown
/// 18081/tcp closed unknown          <- listed
/// 18443/tcp open   unknown
/// 19999/tcp closed dnp-sec          <- listed
///
/// $ nmap-rs (before M7.10)
/// Not shown: 2 closed tcp ports (conn-refused)     <- summarized
/// 18080/tcp open  unknown
/// 18443/tcp open  unknown
/// ```
///
/// The differential harness could not see it: `project.py` compares open ports
/// and closed/filtered *counts*, and both spellings carry the same counts. It
/// took implementing the flag that is *supposed* to cause this behaviour to
/// notice that the behaviour was already unconditional.
///
/// The threshold is 25, scaled by verbosity and debugging exactly as C scales
/// it; verified against the reference at 25 (listed) and 26 (summarized).
fn is_ignored_state(host: &Host, state: PortState, meta: &ScanMeta) -> bool {
    // `-d3` and above: nothing is ignored.
    if meta.debugging > 2 {
        return false;
    }
    // Open can never be ignored — which is what makes `--open` mean "only
    // open", rather than "nothing at all".
    if matches!(state, PortState::Open | PortState::Unknown) {
        return false;
    }
    if state == PortState::OpenFiltered && (meta.verbose > 2 || meta.debugging > 2) {
        return false;
    }
    let count = host.ports.iter().filter(|p| p.state == state).count();
    // `--open`: everything that is not at least possibly open is summarized,
    // however few there are.
    if meta.open_only
        && !matches!(state, PortState::OpenFiltered | PortState::Unfiltered)
        && count > 0
    {
        return true;
    }
    let mut max_per_state: usize = 25;
    if meta.verbose > 0 || meta.debugging > 0 {
        let scale = usize::from(meta.verbose)
            .saturating_add(1)
            .saturating_add(20usize.saturating_mul(usize::from(meta.debugging)));
        max_per_state = max_per_state.saturating_mul(scale);
    }
    count > max_per_state
}

/// The ports listed individually for a host, in the order they were discovered.
fn shown_ports<'a>(host: &'a Host, meta: &ScanMeta) -> Vec<&'a crate::model::Port> {
    host.ports
        .iter()
        .filter(|p| !is_ignored_state(host, p.state, meta))
        .collect()
}

/// `--open` drops a host with no open ports from the report entirely
/// (`nmap.cc:2312`). It still counts as up in the footer — the host was found,
/// it just has nothing the operator asked to see.
fn host_is_reportable(host: &Host, meta: &ScanMeta) -> bool {
    !meta.open_only || host.ports.iter().any(|p| p.state == PortState::Open)
}

/// Service name for a port: the port's own info if present, else a lookup in the
/// `nmap-services` table, else the nmap placeholder `"unknown"`.
fn service_name<'a>(
    port: u16,
    proto: Protocol,
    stored: Option<&'a str>,
    services: Option<&'a ServiceTable>,
) -> &'a str {
    stored
        .or_else(|| services.and_then(|t| t.service_name(port, proto)))
        .unwrap_or("unknown")
}

/// The SERVICE column, which under `-sV` marks an *unconfirmed* name with `?`.
///
/// C distinguishes a name that a probe confirmed from one merely looked up in
/// `nmap-services`, and only under `-sV` — because only then was a probe even
/// attempted, so only then does its absence mean anything:
///
/// ```console
/// $ nmap -Pn -n -p 9100 127.0.0.1        # no -sV
/// 9100/tcp open  jetdirect
/// $ nmap -sV -Pn -n -p 9100 127.0.0.1    # -sV, but 9100 is Exclude'd
/// 9100/tcp open  jetdirect?
/// ```
///
/// The `?` is the operator's signal that nothing was verified. Reporting a bare
/// `jetdirect` for a port this scanner deliberately did not probe would claim a
/// confirmation it never made — the same class of overclaim as `-sL` inventing
/// host liveness.
fn service_column<'a>(
    port: u16,
    proto: Protocol,
    svc: &'a crate::model::ServiceInfo,
    services: Option<&'a ServiceTable>,
    service_version: bool,
) -> String {
    let name = service_name(port, proto, svc.name.as_deref(), services);
    if service_version && svc.name.is_none() {
        format!("{name}?")
    } else {
        name.to_string()
    }
}

/// Ignored states (state → count), in nmap's display order, for a host.
fn ignored_states(host: &Host, meta: &ScanMeta) -> Vec<(PortState, usize)> {
    // Order: closed, filtered, then any others we might carry.
    const ORDER: [PortState; 5] = [
        PortState::Closed,
        PortState::Filtered,
        PortState::Unfiltered,
        PortState::ClosedFiltered,
        PortState::Unknown,
    ];
    let mut out = Vec::new();
    for state in ORDER {
        // Only states the ignore rule actually ignores belong here. Listing a
        // state in "Not shown" while also printing its ports would double-count
        // them, and claiming ports are hidden when they are visible is the kind
        // of small lie an operator reasonably relies on.
        if !is_ignored_state(host, state, meta) {
            continue;
        }
        let n = host.ports.iter().filter(|p| p.state == state).count();
        if n > 0 {
            out.push((state, n));
        }
    }
    out
}

/// The reason token nmap prints for an ignored-state summary. Taken from a real port
/// of that state so it is correct across scan types (a connect scan's closed ports
/// carry `conn-refused`, a SYN scan's carry `reset`) rather than a hardcoded guess.
fn ignored_reason(host: &Host, state: PortState) -> &'static str {
    host.ports.iter().find(|p| p.state == state).map_or_else(
        || match state {
            PortState::Closed => "conn-refused",
            _ => "no-response",
        },
        |p| p.reason.as_str(),
    )
}

/// Render the full normal (default, human-readable) report.
pub fn render_normal(
    results: &ScanResults,
    meta: &ScanMeta,
    services: Option<&ServiceTable>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Starting {} {} ( https://nmap.org/nmap-rs ) at {}",
        meta.scanner, meta.version, meta.started
    );

    let mut up = 0usize;
    let mut first = true;
    for host in &results.hosts {
        // The host still counts as up even when `--open` drops it from the
        // report: it WAS found, it just has nothing the operator asked to see.
        // C counts it the same way (`nmap.cc:2312` skips only the printing).
        if host.state == crate::model::HostState::Up {
            up = up.saturating_add(1);
        }
        if !host_is_reportable(host, meta) {
            continue;
        }
        render_host_normal(&mut out, host, services, meta, first);
        first = false;
    }

    let fps = collect_service_fingerprints(results);
    out.push_str(&service_fingerprint_block(&fps));

    let n = results.hosts.len();
    let _ = writeln!(
        out,
        "Nmap done: {} IP address{} ({} host{} up) scanned in {:.2} seconds",
        n,
        if n == 1 { "" } else { "es" },
        up,
        if up == 1 { "" } else { "s" },
        meta.elapsed_secs
    );
    out
}

/// Every unmatched-but-submittable service fingerprint in the scan, in host then
/// port order.
#[must_use]
pub fn collect_service_fingerprints(results: &ScanResults) -> Vec<String> {
    let mut out = Vec::new();
    for host in &results.hosts {
        for port in &host.ports {
            if let Some(fp) = port.service.fingerprint.as_ref() {
                out.push(fp.clone());
            }
        }
    }
    out
}

/// The "N services unrecognized despite returning data" block.
///
/// Ports `output.cc:830-843`. Empty when there is nothing to submit, so callers can
/// append it unconditionally.
///
/// The separator between fingerprints appears **only when there is more than one**,
/// which is the C's behaviour and matters: it tells the operator that each block is
/// a separate submission rather than one long record.
#[must_use]
pub fn service_fingerprint_block(fingerprints: &[String]) -> String {
    if fingerprints.is_empty() {
        return String::new();
    }
    let n = fingerprints.len();
    let plural = if n > 1 { "s" } else { "" };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{n} service{plural} unrecognized despite returning data. \
If you know the service/version, please submit the following fingerprint{plural} at \
https://nmap.org/cgi-bin/submit.cgi?new-service :"
    );
    for fp in fingerprints {
        if n > 1 {
            let _ = writeln!(
                out,
                "==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)=============="
            );
        }
        let _ = writeln!(out, "{fp}");
    }
    out
}

fn render_host_normal(
    out: &mut String,
    host: &Host,
    services: Option<&ServiceTable>,
    meta: &ScanMeta,
    first: bool,
) {
    let service_version = meta.service_version;
    let name = match &host.hostname {
        Some(h) => format!("{h} ({})", host.address),
        None => host.address.to_string(),
    };
    // The blank line SEPARATES host blocks; it does not prefix them, and a host
    // with no block needs none. C emits "Nmap scan report" immediately after the
    // Starting banner, blank-lines only between hosts that have something under
    // them, and — in a list scan — no blank lines at all, because there is no
    // port table for one to belong to:
    //
    //     Nmap scan report for 127.0.0.1
    //     Nmap scan report for 127.0.0.2     <- `-sL`, no separators
    //
    // The old code emitted a leading "\n" unconditionally, which put a stray
    // blank line at the top of every report. Invisible in a normal scan (the
    // differential harness normalizes whitespace) but `-sL`'s entire output is
    // these lines, which is what made it visible.
    if !first && host.state != crate::model::HostState::Unknown {
        out.push('\n');
    }
    let _ = writeln!(out, "Nmap scan report for {name}");

    // A list scan (`-sL`) sends nothing, so it learns nothing about liveness.
    // C prints the report line alone for those hosts — no "Host is up", no port
    // table — and its grepable output calls the state `Unknown` rather than
    // guessing `Down`. Saying "Host seems down" about a host we never probed
    // would be inventing a result.
    if host.state == crate::model::HostState::Unknown {
        return;
    }
    if host.state != crate::model::HostState::Up {
        let _ = writeln!(out, "Host seems down.");
        return;
    }
    // `--reason` says what established liveness: "Host is up, received syn-ack".
    // With `-Pn` C reports `user-set` — the operator asserted it, so the honest
    // answer is "because you said so" rather than a probe result.
    //
    // C also prints a latency here ("Host is up (0.000071s latency)"), which
    // this port does not measure; see DIVERGENCES.md.
    match (meta.reason, host.reason) {
        (true, Some(r)) => {
            let _ = writeln!(out, "Host is up, received {}.", r.as_str());
        }
        _ => {
            let _ = writeln!(out, "Host is up.");
        }
    }

    // "Not shown" summary of ignored states. The protocol label follows the host's
    // ports (a `-sU` scan reports "udp ports"), defaulting to tcp.
    let ignored = ignored_states(host, meta);
    if !ignored.is_empty() {
        let proto = host
            .ports
            .first()
            .map_or(Protocol::Tcp, |p| p.protocol)
            .as_str();
        let parts: Vec<String> = ignored
            .iter()
            .map(|(st, n)| {
                format!(
                    "{} {} {} ports ({})",
                    n,
                    st.as_str(),
                    proto,
                    ignored_reason(host, *st)
                )
            })
            .collect();
        let _ = writeln!(out, "Not shown: {}", parts.join(", "));
    }

    let shown = shown_ports(host, meta);
    if shown.is_empty() {
        return;
    }

    // Column-aligned table (nmap's NmapOutputTable shape). The columns are
    // PORT STATE SERVICE [REASON] [VERSION], in that order — REASON sits
    // *between* SERVICE and VERSION rather than being appended, which is where
    // C puts it:
    //
    //     PORT      STATE  SERVICE REASON       VERSION
    //
    // Built generically rather than as four hand-written branches, because the
    // two optional columns give four combinations and the widths have to be
    // computed over whichever are present.
    let mut headers: Vec<&str> = vec!["PORT", "STATE", "SERVICE"];
    if meta.reason {
        headers.push("REASON");
    }
    if service_version {
        headers.push("VERSION");
    }
    let rows: Vec<Vec<String>> = shown
        .iter()
        .map(|p| {
            let mut row = vec![
                format!("{}/{}", p.number, p.protocol.as_str()),
                p.state.as_str().to_string(),
                service_column(p.number, p.protocol, &p.service, services, service_version),
            ];
            if meta.reason {
                row.push(p.reason.as_str().to_string());
            }
            if service_version {
                row.push(version_display(&p.service));
            }
            row
        })
        .collect();

    // Every column is padded to its widest cell except the last, whose padding
    // would only produce trailing whitespace.
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .filter_map(|r| r.get(i).map(String::len))
                .chain([h.len()])
                .max()
                .unwrap_or(h.len())
        })
        .collect();
    let emit = |cells: &[&str]| -> String {
        let last = cells.len().saturating_sub(1);
        let line: String = cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    (*c).to_string()
                } else {
                    format!("{:w$} ", c, w = widths.get(i).copied().unwrap_or(0))
                }
            })
            .collect();
        line.trim_end().to_string()
    };
    let _ = writeln!(out, "{}", emit(&headers));
    for row in &rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        let _ = writeln!(out, "{}", emit(&cells));
    }
}

/// Render grepable (`-oG`) output.
pub fn render_grepable(
    results: &ScanResults,
    meta: &ScanMeta,
    services: Option<&ServiceTable>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# {} {} scan initiated {}",
        meta.scanner, meta.version, meta.started
    );
    for host in &results.hosts {
        if !host_is_reportable(host, meta) {
            continue;
        }
        let hostname = host.hostname.as_deref().unwrap_or("");
        let status = match host.state {
            crate::model::HostState::Up => "Up",
            crate::model::HostState::Down => "Down",
            // C emits `Status: Unknown` for a list scan.
            crate::model::HostState::Unknown => "Unknown",
        };
        let _ = writeln!(
            out,
            "Host: {} ({})\tStatus: {}",
            host.address, hostname, status
        );

        let shown = shown_ports(host, meta);
        if !shown.is_empty() {
            let entries: Vec<String> = shown
                .iter()
                .map(|p| {
                    // portno/state/proto/owner/service/rpc/version. Without `-sV`
                    // the version field is empty (as nmap does); with `-sV` it
                    // carries the assembled product/version string.
                    let version = if meta.service_version {
                        // Grepable escapes `/` (the field separator) as it would
                        // corrupt the record; nmap uses a comma.
                        version_display(&p.service).replace('/', ",")
                    } else {
                        String::new()
                    };
                    format!(
                        "{}/{}/{}//{}//{}/",
                        p.number,
                        p.state.as_str(),
                        p.protocol.as_str(),
                        service_column(
                            p.number,
                            p.protocol,
                            &p.service,
                            services,
                            meta.service_version
                        ),
                        version,
                    )
                })
                .collect();
            let _ = writeln!(
                out,
                "Host: {} ({})\tPorts: {}{}",
                host.address,
                hostname,
                entries.join(", "),
                host.os.as_ref().map(os_grepable).unwrap_or_default()
            );
        } else if let Some(os) = &host.os {
            // nmap appends the OS fields to the record it is already building, which is
            // the `Ports:` line. With nothing shown there is no such line, so the fields
            // get their own record rather than being dropped.
            let _ = writeln!(
                out,
                "Host: {} ({}){}",
                host.address,
                hostname,
                os_grepable(os)
            );
        }
    }
    let _ = writeln!(
        out,
        "# {} done at {} -- {} IP address scanned",
        meta.scanner,
        meta.started,
        results.hosts.len()
    );
    out
}

/// Escape text for inclusion in XML attribute/character data (defends against
/// injection via hostnames / service names — the class `xml.cc` handles).
/// The XML `<os>` block plus the elements the C emits immediately after it —
/// `<uptime>`, `<distance>`, `<tcpsequence>`, `<ipidsequence>`, `<tcptssequence>`.
///
/// Ports the XML half of `printosscanoutput`. Element order, attribute order and the
/// emit conditions are the C's: `<portused>` only for a port actually used,
/// `<osclass>` nested inside its `<osmatch>`, `<cpe>` children only when the class has
/// them, `lastboot` omitted when the boot time could not be formatted, and the
/// sequence elements gated on the response count (`> 3` for TCP, `> 2` for IP ID) —
/// which is why the plain-text lines and these elements can never disagree.
fn os_xml(os: &crate::osscan::HostOsReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "<os>");

    for (state, proto, port) in [
        ("open", "tcp", os.open_tcp_port),
        ("closed", "tcp", os.closed_tcp_port),
        ("closed", "udp", os.closed_udp_port),
    ] {
        // The C tests `> 0`, so port 0 is "no port used" rather than a used port zero.
        if let Some(p) = port.filter(|p| *p > 0) {
            let _ = writeln!(
                out,
                "<portused state=\"{state}\" proto=\"{proto}\" portid=\"{p}\"/>"
            );
        }
    }

    for m in &os.matches {
        let (name, acc, line) = (xml_escape(&m.name), m.accuracy_pct, m.line);
        if m.classes.is_empty() {
            let _ = writeln!(
                out,
                "<osmatch name=\"{name}\" accuracy=\"{acc}\" line=\"{line}\"/>"
            );
            continue;
        }
        let _ = writeln!(
            out,
            "<osmatch name=\"{name}\" accuracy=\"{acc}\" line=\"{line}\">"
        );
        for c in &m.classes {
            let mut attrs = format!(
                "type=\"{}\" vendor=\"{}\" osfamily=\"{}\"",
                xml_escape(&c.device_type),
                xml_escape(&c.vendor),
                xml_escape(&c.family),
            );
            // `osgen` is optional in the database and omitted, not blank, when absent.
            if let Some(gen) = &c.generation {
                let _ = write!(attrs, " osgen=\"{}\"", xml_escape(gen));
            }
            let _ = write!(attrs, " accuracy=\"{acc}\"");
            if c.cpe.is_empty() {
                let _ = writeln!(out, "<osclass {attrs}/>");
            } else {
                let _ = writeln!(out, "<osclass {attrs}>");
                for cpe in &c.cpe {
                    let _ = writeln!(out, "<cpe>{}</cpe>", xml_escape(cpe));
                }
                let _ = writeln!(out, "</osclass>");
            }
        }
        let _ = writeln!(out, "</osmatch>");
    }

    if let Some(fp) = &os.fingerprint {
        let _ = writeln!(out, "<osfingerprint fingerprint=\"{}\"/>", xml_escape(fp));
    }
    let _ = writeln!(out, "</os>");

    // The C emits <uptime> whenever a boot time exists — unlike the plain-text line,
    // which it gates on -v.
    if let Some(u) = &os.uptime {
        match &u.lastboot {
            Some(t) => {
                let _ = writeln!(
                    out,
                    "<uptime seconds=\"{}\" lastboot=\"{}\"/>",
                    u.seconds,
                    xml_escape(t)
                );
            }
            None => {
                let _ = writeln!(out, "<uptime seconds=\"{}\"/>", u.seconds);
            }
        }
    }
    if let Some(d) = os.distance {
        let _ = writeln!(out, "<distance value=\"{d}\"/>");
    }

    let (seqs, ipids, timestamps) = crate::osscan::seq_value_lists(&os.seq);
    if os.seq.responses > 3 {
        let _ = writeln!(
            out,
            "<tcpsequence index=\"{}\" difficulty=\"{}\" values=\"{}\"/>",
            os.seq.index,
            xml_escape(crate::osscan::difficulty_str(os.seq.index)),
            xml_escape(&seqs)
        );
    }
    if os.seq.responses > 2 {
        let _ = writeln!(
            out,
            "<ipidsequence class=\"{}\" values=\"{}\"/>",
            xml_escape(crate::osscan::ipid_class_str(os.seq.ipid_class)),
            xml_escape(&ipids)
        );
        // The C emits <tcptssequence> inside the same `responses > 2` block.
        let _ = writeln!(
            out,
            "<tcptssequence values=\"{}\"/>",
            xml_escape(&timestamps)
        );
    }
    out
}

/// The grepable OS fields nmap appends to a host's record: `OS:`, `Seq Index:` and
/// `IP ID Seq:` (the C's `LOG_MACHINE` writes in `printosscanoutput`).
///
/// Each is tab-prefixed because it extends an existing record rather than starting one.
/// `OS:` lists every match the C would print, `|`-separated. The two sequence fields
/// carry the same response-count gates as the plain text and the XML.
fn os_grepable(os: &crate::osscan::HostOsReport) -> String {
    let mut out = String::new();
    if !os.matches.is_empty() {
        let names: Vec<&str> = os.matches.iter().map(|m| m.name.as_str()).collect();
        // The field separator is `\t` and records are one per line, so a name carrying
        // either would corrupt the record; nmap does not escape here, and a database
        // name cannot contain them.
        let _ = write!(out, "\tOS: {}", names.join("|"));
    }
    if os.seq.responses > 3 {
        let _ = write!(out, "\tSeq Index: {}", os.seq.index);
    }
    if os.seq.responses > 2 {
        let _ = write!(
            out,
            "\tIP ID Seq: {}",
            crate::osscan::ipid_class_str(os.seq.ipid_class)
        );
    }
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the `<service …/>` element for a port. Without `-sV` (or with no probe
/// result) it is the M1 table guess (`method="table" conf="3"`); with a `-sV`
/// result it carries the probed name plus whatever version fields were determined,
/// and `<cpe>` children.
fn service_xml(table_name: &str, svc: &crate::model::ServiceInfo, service_version: bool) -> String {
    // Prefer the probed name (svc.name) when present; else the table guess.
    let name = svc.name.as_deref().unwrap_or(table_name);
    let mut s = format!("<service name=\"{}\"", xml_escape(name));
    let mut attr = |key: &str, val: &Option<String>| {
        if let Some(v) = val {
            s.push_str(&format!(" {key}=\"{}\"", xml_escape(v)));
        }
    };
    if service_version {
        attr("product", &svc.product);
        attr("version", &svc.version);
        attr("extrainfo", &svc.extra_info);
        attr("ostype", &svc.ostype);
        attr("devicetype", &svc.devicetype);
        attr("hostname", &svc.hostname);
    }
    // Method/confidence are the probed values only under `-sV`; otherwise the
    // service name is just the port-table guess.
    let (method, conf) = if service_version {
        (
            svc.method.as_deref().unwrap_or("table"),
            svc.conf.unwrap_or(3),
        )
    } else {
        ("table", 3)
    };
    s.push_str(&format!(" method=\"{method}\" conf=\"{conf}\""));
    if service_version && !svc.cpe.is_empty() {
        s.push('>');
        for c in &svc.cpe {
            s.push_str(&format!("<cpe>{}</cpe>", xml_escape(c)));
        }
        s.push_str("</service>");
    } else {
        s.push_str("/>");
    }
    s
}

/// Render XML (`-oX`) output following nmap's DTD shape.
pub fn render_xml(
    results: &ScanResults,
    meta: &ScanMeta,
    services: Option<&ServiceTable>,
) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<nmaprun scanner=\"{}\" args=\"{}\" start=\"{}\" version=\"{}\">",
        xml_escape(meta.scanner),
        xml_escape(meta.args),
        xml_escape(meta.started),
        xml_escape(meta.version)
    );

    let mut up = 0usize;
    for host in &results.hosts {
        let is_up = host.state == crate::model::HostState::Up;
        if is_up {
            up = up.saturating_add(1);
        }
        // Counted above, then skipped: `--open` hides the host, it does not
        // un-find it.
        if !host_is_reportable(host, meta) {
            continue;
        }
        let _ = writeln!(out, "<host>");
        let addrtype = if host.address.is_ipv6() {
            "ipv6"
        } else {
            "ipv4"
        };
        let _ = writeln!(
            out,
            "<status state=\"{}\"/>",
            match host.state {
                crate::model::HostState::Up => "up",
                crate::model::HostState::Down => "down",
                crate::model::HostState::Unknown => "unknown",
            }
        );
        let _ = writeln!(
            out,
            "<address addr=\"{}\" addrtype=\"{}\"/>",
            xml_escape(&host.address.to_string()),
            addrtype
        );
        if let Some(h) = &host.hostname {
            let _ = writeln!(
                out,
                "<hostnames><hostname name=\"{}\" type=\"user\"/></hostnames>",
                xml_escape(h)
            );
        }

        let _ = writeln!(out, "<ports>");
        // <extraports> for each ignored state.
        for (st, count) in ignored_states(host, meta) {
            let _ = writeln!(
                out,
                "<extraports state=\"{}\" count=\"{}\"/>",
                st.as_str(),
                count
            );
        }
        for p in shown_ports(host, meta) {
            let svc = service_name(p.number, p.protocol, p.service.name.as_deref(), services);
            let _ = writeln!(
                out,
                "<port protocol=\"{}\" portid=\"{}\"><state state=\"{}\" reason=\"{}\"/>{}</port>",
                p.protocol.as_str(),
                p.number,
                p.state.as_str(),
                p.reason.as_str(),
                service_xml(svc, &p.service, meta.service_version),
            );
        }
        let _ = writeln!(out, "</ports>");
        if let Some(os) = &host.os {
            out.push_str(&os_xml(os));
        }
        let _ = writeln!(out, "</host>");
    }

    let _ = writeln!(
        out,
        "<runstats><finished time=\"{}\" elapsed=\"{:.2}\"/><hosts up=\"{}\" down=\"{}\" total=\"{}\"/></runstats>",
        xml_escape(meta.started),
        meta.elapsed_secs,
        up,
        results.hosts.len().saturating_sub(up),
        results.hosts.len()
    );
    out.push_str("</nmaprun>\n");
    out
}

#[cfg(test)]
mod tests {
    /// A list scan's hosts render as the report line ALONE — no "Host is up",
    /// no "Host seems down", no port table, and no blank lines between them.
    ///
    /// Verified against the reference: `nmap -sL -n 127.0.0.1-3` differs from
    /// this port's `-sL` only in the banner and elapsed time.
    #[test]
    fn a_list_scan_host_renders_as_one_line() {
        let mut results = ScanResults { hosts: Vec::new() };
        for last in 1u8..=3 {
            results.hosts.push(Host::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, last)),
                HostState::Unknown,
            ));
        }
        let out = render_normal(&results, &meta(), None);
        for last in 1..=3 {
            assert!(
                out.contains(&format!("Nmap scan report for 127.0.0.{last}")),
                "missing host {last}:\n{out}"
            );
        }
        // Nothing may be claimed about a host we never probed.
        assert!(!out.contains("Host is up"), "claimed liveness:\n{out}");
        assert!(!out.contains("Host seems down"), "guessed down:\n{out}");
        assert!(!out.contains("PORT"), "rendered a port table:\n{out}");
        // Three report lines, back to back, with no blank between them.
        assert!(
            out.contains(
                "Nmap scan report for 127.0.0.1\nNmap scan report for 127.0.0.2\nNmap scan report for 127.0.0.3"
            ),
            "expected no blank lines between list-scan hosts:\n{out}"
        );
        // And 0 hosts up, because nothing was probed.
        assert!(
            out.contains("(0 hosts up)"),
            "a list scan must report 0 up:\n{out}"
        );
    }

    /// The blank line separates host blocks; it does not prefix them. C emits
    /// "Nmap scan report" immediately after the Starting banner.
    #[test]
    fn the_first_host_has_no_blank_line_before_it() {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HostState::Up);
        host.ports.push(Port::new(
            80,
            Protocol::Tcp,
            PortState::Closed,
            Reason::ConnRefused,
        ));
        let results = ScanResults { hosts: vec![host] };
        let out = render_normal(&results, &meta(), None);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("Starting "), "got: {:?}", lines[0]);
        assert!(
            lines[1].starts_with("Nmap scan report"),
            "expected the report line immediately after the banner, got: {:?}",
            lines[1]
        );
    }

    /// Grepable and XML must say `Unknown`/`unknown`, not collapse to Down.
    /// C's grepable prints `Status: Unknown` for a list scan.
    #[test]
    fn unknown_liveness_is_not_reported_as_down() {
        let results = ScanResults {
            hosts: vec![Host::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                HostState::Unknown,
            )],
        };
        let g = render_grepable(&results, &meta(), None);
        assert!(g.contains("Status: Unknown"), "grepable:\n{g}");
        assert!(!g.contains("Status: Down"), "grepable claimed down:\n{g}");
        let x = render_xml(&results, &meta(), None);
        assert!(x.contains("<status state=\"unknown\"/>"), "xml:\n{x}");
        assert!(!x.contains("state=\"down\""), "xml claimed down:\n{x}");
        // Runstats counts it as DOWN, which looks inconsistent with the
        // per-host `state="unknown"` above — and is exactly what C does:
        //
        //     $ nmap -sL -n -oX - 127.0.0.1-2 | grep hosts
        //     <hosts up="0" down="2" total="2"/>
        //
        // So the inconsistency belongs to the reference, and mirroring it is
        // the correct behaviour. Asserted so nobody "fixes" it into a real
        // divergence later.
        assert!(
            x.contains("<hosts up=\"0\" down=\"1\" total=\"1\"/>"),
            "xml:\n{x}"
        );
    }

    use super::*;
    use crate::model::{Host, HostState, Port, Reason};
    use std::net::{IpAddr, Ipv4Addr};

    fn sample() -> ScanResults {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), HostState::Up);
        host.ports.push(Port::new(
            22,
            Protocol::Tcp,
            PortState::Open,
            Reason::ConnAccept,
        ));
        host.ports.push(Port::new(
            80,
            Protocol::Tcp,
            PortState::Open,
            Reason::ConnAccept,
        ));
        // 998 "closed" ports collapsed to a couple for the test.
        host.ports.push(Port::new(
            81,
            Protocol::Tcp,
            PortState::Closed,
            Reason::ConnRefused,
        ));
        host.ports.push(Port::new(
            443,
            Protocol::Tcp,
            PortState::Closed,
            Reason::ConnRefused,
        ));
        let mut r = ScanResults::new();
        r.hosts.push(host);
        r
    }

    fn meta() -> ScanMeta<'static> {
        ScanMeta {
            scanner: "nmap-rs",
            version: "0.1.0",
            args: "nmap-rs -sT 127.0.0.1",
            started: "TIME",
            elapsed_secs: 1.0,
            service_version: false,
            open_only: false,
            reason: false,
            verbose: 0,
            debugging: 0,
        }
    }

    /// A host whose port 22 carries a full `-sV` result (OpenSSH 9.6).
    fn sample_sv() -> ScanResults {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HostState::Up);
        let mut p = Port::new(22, Protocol::Tcp, PortState::Open, Reason::ConnAccept);
        p.service = crate::model::ServiceInfo {
            name: Some("ssh".into()),
            product: Some("OpenSSH".into()),
            version: Some("9.6".into()),
            extra_info: Some("protocol 2.0".into()),
            cpe: vec!["cpe:/a:openbsd:openssh:9.6".into()],
            method: Some("probed".into()),
            conf: Some(10),
            ..Default::default()
        };
        host.ports.push(p);
        let mut r = ScanResults::new();
        r.hosts.push(host);
        r
    }

    fn meta_sv() -> ScanMeta<'static> {
        ScanMeta {
            service_version: true,
            ..meta()
        }
    }

    #[test]
    fn normal_version_column_under_sv() {
        let out = render_normal(&sample_sv(), &meta_sv(), None);
        assert!(out.contains("SERVICE"));
        assert!(out.contains("VERSION"));
        // The assembled VERSION string: product version (extrainfo).
        assert!(
            out.contains("OpenSSH 9.6 (protocol 2.0)"),
            "missing version column:\n{out}"
        );
    }

    #[test]
    fn xml_service_carries_version_and_cpe_under_sv() {
        let out = render_xml(&sample_sv(), &meta_sv(), None);
        assert!(out.contains("name=\"ssh\""));
        assert!(out.contains("product=\"OpenSSH\""));
        assert!(out.contains("version=\"9.6\""));
        assert!(out.contains("extrainfo=\"protocol 2.0\""));
        assert!(out.contains("method=\"probed\" conf=\"10\""));
        assert!(out.contains("<cpe>cpe:/a:openbsd:openssh:9.6</cpe>"));
    }

    #[test]
    fn grepable_carries_version_under_sv() {
        let out = render_grepable(&sample_sv(), &meta_sv(), None);
        // portno/state/proto//service//version/
        assert!(
            out.contains("22/open/tcp//ssh//OpenSSH 9.6 (protocol 2.0)/"),
            "grep version field missing:\n{out}"
        );
    }

    #[test]
    fn no_version_column_without_sv() {
        // Same data, but -sV not requested → no VERSION column, table method.
        let out = render_normal(&sample_sv(), &meta(), None);
        assert!(!out.contains("VERSION"));
        let xml = render_xml(&sample_sv(), &meta(), None);
        assert!(xml.contains("method=\"table\""));
        assert!(!xml.contains("product="));
    }

    fn services() -> ServiceTable {
        ServiceTable::parse("ssh 22/tcp 0.18\nhttp 80/tcp 0.48\n")
    }

    /// **These assertions were inverted until M7.10.** They required the two
    /// closed ports to be summarized, which is what this port did
    /// unconditionally — i.e. it always behaved as though `--open` had been
    /// given. C lists a state's ports until the state exceeds 25 of them, so
    /// with two closed ports it lists them. Verified against the reference.
    ///
    /// The old assertion is kept, inverted, rather than deleted: the previous
    /// behaviour is exactly what must not come back.
    #[test]
    fn normal_lists_a_small_number_of_closed_ports() {
        let out = render_normal(&sample(), &meta(), Some(&services()));
        assert!(out.contains("Nmap scan report for 127.0.0.1"));
        assert!(out.contains("Host is up."));
        assert!(out.contains("PORT    STATE  SERVICE"), "{out}");
        assert!(out.contains("22/tcp  open   ssh"), "{out}");
        assert!(out.contains("80/tcp  open   http"), "{out}");
        // Two closed ports are below the threshold, so they are LISTED …
        assert!(out.contains("443/tcp closed"), "{out}");
        // … and therefore must not also be claimed as hidden.
        assert!(
            !out.contains("Not shown:"),
            "a listed port must not also be summarized:\n{out}"
        );
        assert!(out.contains("Nmap done: 1 IP address (1 host up) scanned"));
    }

    /// The other side of the same threshold: past 25 ports in a state, C
    /// summarizes. Both sides are asserted because a rule with a boundary needs
    /// both of them — testing only one cannot tell a correct threshold from a
    /// missing one.
    #[test]
    fn normal_summarizes_a_large_number_of_closed_ports() {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HostState::Up);
        for n in 1..=26u16 {
            host.ports.push(Port::new(
                n,
                Protocol::Tcp,
                PortState::Closed,
                Reason::ConnRefused,
            ));
        }
        let results = ScanResults { hosts: vec![host] };
        let out = render_normal(&results, &meta(), None);
        assert!(
            out.contains("Not shown: 26 closed tcp ports (conn-refused)"),
            "{out}"
        );
        assert!(
            !out.contains("1/tcp"),
            "summarized ports must not be listed:\n{out}"
        );
    }

    /// `--open` forces the summary however few ports there are — that is the
    /// flag's whole job, and the behaviour this port used to have by default.
    #[test]
    fn open_only_summarizes_even_a_couple_of_closed_ports() {
        let m = ScanMeta {
            open_only: true,
            ..meta()
        };
        let out = render_normal(&sample(), &m, Some(&services()));
        assert!(
            out.contains("Not shown: 2 closed tcp ports (conn-refused)"),
            "{out}"
        );
        assert!(!out.contains("443/tcp"), "{out}");
        assert!(out.contains("22/tcp open  ssh"), "{out}");
    }

    /// `--open` drops a host with no open ports entirely, while still counting
    /// it as up: it was found, it just has nothing the operator asked to see.
    #[test]
    fn open_only_hides_a_host_with_nothing_open() {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HostState::Up);
        host.ports.push(Port::new(
            80,
            Protocol::Tcp,
            PortState::Closed,
            Reason::ConnRefused,
        ));
        let results = ScanResults { hosts: vec![host] };
        let m = ScanMeta {
            open_only: true,
            ..meta()
        };
        let out = render_normal(&results, &m, None);
        assert!(!out.contains("Nmap scan report"), "{out}");
        assert!(
            out.contains("(1 host up)"),
            "the host is hidden, not un-found:\n{out}"
        );
        // The same suppression applies to the machine-readable formats.
        assert!(!render_xml(&results, &m, None).contains("<address addr="));
        assert!(!render_grepable(&results, &m, None).contains("Host: 127.0.0.1"));
    }

    /// `--reason` adds the REASON column *between* SERVICE and VERSION, and
    /// names what established the host's liveness.
    #[test]
    fn reason_adds_a_column_and_a_host_reason() {
        let mut results = sample();
        results.hosts[0].reason = Some(Reason::UserSet);
        let m = ScanMeta {
            reason: true,
            ..meta()
        };
        let out = render_normal(&results, &m, Some(&services()));
        assert!(out.contains("Host is up, received user-set."), "{out}");
        assert!(out.contains("PORT    STATE  SERVICE REASON"), "{out}");
        assert!(out.contains("22/tcp  open   ssh     syn-ack"), "{out}");
        assert!(out.contains("443/tcp closed"), "{out}");
    }

    /// Without `--reason` the column is absent and the host line is bare, even
    /// when the reason data is present — the flag controls the rendering, not
    /// the collection.
    #[test]
    fn without_reason_the_column_is_absent() {
        let mut results = sample();
        results.hosts[0].reason = Some(Reason::UserSet);
        let out = render_normal(&results, &meta(), Some(&services()));
        assert!(!out.contains("REASON"), "{out}");
        assert!(out.contains("Host is up."), "{out}");
    }

    #[test]
    fn grepable_has_status_and_ports_lines() {
        let out = render_grepable(&sample(), &meta(), Some(&services()));
        assert!(out.contains("Host: 127.0.0.1 ()\tStatus: Up"));
        assert!(out.contains("22/open/tcp//ssh///"));
        assert!(out.contains("80/open/tcp//http///"));
    }

    #[test]
    fn xml_is_well_formed_shape_and_escapes() {
        let out = render_xml(&sample(), &meta(), Some(&services()));
        assert!(out.starts_with("<?xml version=\"1.0\""));
        assert!(out.contains("<address addr=\"127.0.0.1\" addrtype=\"ipv4\"/>"));
        // Two closed ports are below nmap's 25-per-state threshold, so the XML
        // lists them individually and emits no <extraports>. This assertion was
        // the other way round until M7.10; see
        // `normal_lists_a_small_number_of_closed_ports`.
        assert!(!out.contains("<extraports"), "{out}");
        assert!(out.contains("portid=\"443\""), "{out}");
        assert!(out.contains(
            "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"ssh\""
        ));
        assert!(out.contains("<hosts up=\"1\" down=\"0\" total=\"1\"/>"));
        assert!(out.trim_end().ends_with("</nmaprun>"));
    }

    /// The XML carries NO stylesheet reference, and `options::ALREADY_SATISFIED`
    /// depends on that.
    ///
    /// C nmap emits an `<?xml-stylesheet?>` processing instruction by default and
    /// `--no-stylesheet` suppresses it. This port never emits one, which is why
    /// `--no-stylesheet` is accepted as a no-op (M7.3) — the option asks for what
    /// already happens. That carve-out's rule is that every reason must be a
    /// property of the code checkable today, so this is the check: start emitting
    /// a stylesheet and the carve-out's justification is false, and this test says
    /// so rather than leaving the CLI silently accepting an option it no longer
    /// satisfies.
    #[test]
    fn xml_emits_no_stylesheet_reference() {
        let out = render_xml(&sample(), &meta(), Some(&services()));
        assert!(
            !out.contains("xml-stylesheet"),
            "XML gained a stylesheet PI; options::ALREADY_SATISFIED's --no-stylesheet \
             entry is now false and must be removed:\n{out}"
        );
        // The declaration is followed directly by <nmaprun>, with no PI between.
        let after_decl = out
            .split_once("?>\n")
            .expect("an XML declaration")
            .1
            .trim_start();
        assert!(
            after_decl.starts_with("<nmaprun"),
            "expected <nmaprun> straight after the declaration, got: {}",
            &after_decl[..after_decl.len().min(80)]
        );
    }

    #[test]
    fn xml_escaping_defends_against_injection() {
        let mut host = Host::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HostState::Up);
        host.hostname = Some("evil\"><inject>".to_string());
        host.ports.push(Port::new(
            80,
            Protocol::Tcp,
            PortState::Open,
            Reason::ConnAccept,
        ));
        let mut r = ScanResults::new();
        r.hosts.push(host);
        let out = render_xml(&r, &meta(), None);
        assert!(out.contains("evil&quot;&gt;&lt;inject&gt;"));
        assert!(!out.contains("<inject>"));
    }
    // ---- OS detection: the XML <os> block and the grepable fields ----

    fn os_report() -> crate::osscan::HostOsReport {
        use crate::osdb::model::OsClass;
        crate::osscan::HostOsReport {
            open_tcp_port: Some(22),
            closed_tcp_port: Some(1),
            closed_udp_port: Some(42000),
            matches: vec![crate::osscan::OsMatchReport {
                name: "Linux 5.X".to_owned(),
                accuracy_pct: 100,
                line: 4242,
                classes: vec![OsClass {
                    vendor: "Linux".to_owned(),
                    family: "Linux".to_owned(),
                    generation: Some("5.X".to_owned()),
                    device_type: "general purpose".to_owned(),
                    cpe: vec!["cpe:/o:linux:linux_kernel:5".to_owned()],
                }],
            }],
            fingerprint: None,
            uptime: Some(crate::osscan::UptimeReport {
                seconds: 216_000,
                lastboot: Some("Sat Aug 30 17:00:00 2025 UTC".to_owned()),
            }),
            distance: Some(3),
            seq: crate::osscan::SeqReport {
                responses: 6,
                seqs: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                ipids: vec![1, 2, 3, 4, 5, 6],
                timestamps: vec![10, 20, 30, 40, 50, 60],
                index: 260,
                ipid_class: crate::ipid::IpidSequence::Incr,
            },
        }
    }

    fn host_with_os(os: crate::osscan::HostOsReport) -> ScanResults {
        let mut r = sample();
        r.hosts[0].os = Some(os);
        r
    }

    #[test]
    fn xml_os_block_carries_every_element_the_c_emits() {
        let out = render_xml(&host_with_os(os_report()), &meta(), None);
        for want in [
            "<os>",
            "<portused state=\"open\" proto=\"tcp\" portid=\"22\"/>",
            "<portused state=\"closed\" proto=\"tcp\" portid=\"1\"/>",
            "<portused state=\"closed\" proto=\"udp\" portid=\"42000\"/>",
            "<osmatch name=\"Linux 5.X\" accuracy=\"100\" line=\"4242\">",
            "<osclass type=\"general purpose\" vendor=\"Linux\" osfamily=\"Linux\" osgen=\"5.X\" accuracy=\"100\">",
            "<cpe>cpe:/o:linux:linux_kernel:5</cpe>",
            "</osclass>",
            "</osmatch>",
            "</os>",
            "<uptime seconds=\"216000\" lastboot=\"Sat Aug 30 17:00:00 2025 UTC\"/>",
            "<distance value=\"3\"/>",
            "<tcpsequence index=\"260\"",
            "<ipidsequence class=",
            "<tcptssequence values=",
        ] {
            assert!(out.contains(want), "missing {want}\n--- got ---\n{out}");
        }
        // The block sits inside <host>, after the ports.
        let (ports, os, host_end) = (
            out.find("</ports>").unwrap(),
            out.find("<os>").unwrap(),
            out.find("</host>").unwrap(),
        );
        assert!(ports < os && os < host_end, "os block is misplaced");
    }

    #[test]
    fn xml_omits_what_the_c_omits() {
        let mut os = os_report();
        // No port used, no <portused>. The C tests `> 0`, so zero means "none".
        os.open_tcp_port = None;
        os.closed_tcp_port = Some(0);
        // A class with no generation and no CPEs collapses to an empty element.
        os.matches[0].classes[0].generation = None;
        os.matches[0].classes[0].cpe.clear();
        // No boot time formatted: the C drops the attribute, not the element.
        os.uptime = Some(crate::osscan::UptimeReport {
            seconds: 60,
            lastboot: None,
        });
        os.distance = None;

        let out = render_xml(&host_with_os(os), &meta(), None);
        // Scoped to <portused>: `state="open"` also appears in the ports table.
        assert!(
            !out.contains("<portused state=\"open\""),
            "no open port was used"
        );
        assert!(!out.contains("portid=\"0\""), "port 0 means none");
        assert!(
            !out.contains("osgen="),
            "absent generation is omitted, not blank"
        );
        assert!(
            out.contains("accuracy=\"100\"/>"),
            "class collapses when it has no cpe"
        );
        assert!(out.contains("<uptime seconds=\"60\"/>"));
        assert!(!out.contains("<distance"));
    }

    // The C gates <tcpsequence> on responses > 3 and <ipidsequence> on responses > 2,
    // using the response count rather than the array lengths.
    #[test]
    fn xml_sequence_elements_follow_the_response_count() {
        for (responses, tcp, ipid) in [(6, true, true), (3, false, true), (2, false, false)] {
            let mut os = os_report();
            os.seq.responses = responses;
            let out = render_xml(&host_with_os(os), &meta(), None);
            assert_eq!(out.contains("<tcpsequence"), tcp, "responses={responses}");
            assert_eq!(out.contains("<ipidsequence"), ipid, "responses={responses}");
        }
    }

    // The value lists are bounded by the response count, not by the vector length —
    // the C reads only the live entries of its fixed-size arrays.
    #[test]
    fn xml_value_lists_are_bounded_by_the_response_count() {
        let mut os = os_report();
        os.seq.responses = 4;
        let out = render_xml(&host_with_os(os), &meta(), None);
        let line = out
            .lines()
            .find(|l| l.starts_with("<tcpsequence"))
            .expect("a tcpsequence element");
        assert!(line.contains("values=\"AA,BB,CC,DD\""), "got: {line}");
        assert!(
            !line.contains("EE"),
            "entries past `responses` must not print"
        );
    }

    #[test]
    fn grepable_appends_the_os_fields_to_the_ports_record() {
        let out = render_grepable(&host_with_os(os_report()), &meta(), None);
        let line = out
            .lines()
            .find(|l| l.contains("Ports:"))
            .expect("a Ports record");
        assert!(line.contains("\tOS: Linux 5.X"), "got: {line}");
        assert!(line.contains("\tSeq Index: 260"), "got: {line}");
        assert!(line.contains("\tIP ID Seq: "), "got: {line}");
    }

    #[test]
    fn grepable_still_reports_os_when_no_ports_are_shown() {
        let mut r = host_with_os(os_report());
        r.hosts[0].ports.clear();
        let out = render_grepable(&r, &meta(), None);
        assert!(
            out.lines().any(|l| l.contains("OS: Linux 5.X")),
            "the OS fields must not vanish with the ports record\n{out}"
        );
    }

    #[test]
    fn os_names_and_classes_are_xml_escaped() {
        let mut os = os_report();
        os.matches[0].name = "evil\"><inject>".to_owned();
        os.matches[0].classes[0].cpe = vec!["cpe:/o:<evil>".to_owned()];
        let out = render_xml(&host_with_os(os), &meta(), None);
        assert!(out.contains("evil&quot;&gt;&lt;inject&gt;"));
        assert!(!out.contains("<inject>"));
        assert!(out.contains("<cpe>cpe:/o:&lt;evil&gt;</cpe>"));
    }

    #[test]
    fn no_unmatched_fingerprints_renders_nothing_at_all() {
        // Not a header with an empty list: the block is appended unconditionally by
        // render_normal, so an empty one has to be genuinely empty.
        assert_eq!(service_fingerprint_block(&[]), "");
    }

    #[test]
    fn one_fingerprint_gets_no_separator() {
        // The C emits the separator only when there is more than one, and that is
        // load-bearing: it tells the operator each block is its own submission.
        let out = service_fingerprint_block(&["SF-Port22-TCP:V=7.94...;".to_owned()]);
        assert!(out.starts_with("1 service unrecognized despite returning data."));
        assert!(!out.contains("NEXT SERVICE FINGERPRINT"));
        assert!(out.contains("SF-Port22-TCP:V=7.94...;"));
        assert!(out.contains("submit.cgi?new-service"));
    }

    #[test]
    fn several_fingerprints_are_pluralised_and_separated() {
        let fps = vec!["FP-A;".to_owned(), "FP-B;".to_owned(), "FP-C;".to_owned()];
        let out = service_fingerprint_block(&fps);
        assert!(out.starts_with("3 services unrecognized despite returning data."));
        assert!(out.contains("fingerprints at"), "plural not applied: {out}");
        assert_eq!(out.matches("NEXT SERVICE FINGERPRINT").count(), 3);
        for fp in &fps {
            assert!(out.contains(fp.as_str()));
        }
    }

    #[test]
    fn collection_walks_hosts_and_ports_in_order_and_skips_matched_services() {
        use crate::model::{Host, HostState, Port, PortState, Protocol, Reason, ScanResults};
        let mut host = Host::new("10.0.0.1".parse().expect("addr"), HostState::Up);
        for (n, fp) in [(22u16, Some("FP-22;")), (80, None), (443, Some("FP-443;"))] {
            let mut p = Port::new(n, Protocol::Tcp, PortState::Open, Reason::ConnAccept);
            p.service.fingerprint = fp.map(str::to_owned);
            host.ports.push(p);
        }
        let results = ScanResults { hosts: vec![host] };
        assert_eq!(
            collect_service_fingerprints(&results),
            vec!["FP-22;".to_owned(), "FP-443;".to_owned()]
        );
    }
}
