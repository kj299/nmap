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

/// A port is *shown* in the table iff it is open (or open|filtered); every other
/// state is summarized as an ignored state ("Not shown" / `<extraports>`).
fn is_shown(state: PortState) -> bool {
    matches!(state, PortState::Open | PortState::OpenFiltered)
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

/// Ignored states (state → count), in nmap's display order, for a host.
fn ignored_states(host: &Host) -> Vec<(PortState, usize)> {
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
    for host in &results.hosts {
        if host.state == crate::model::HostState::Up {
            up = up.saturating_add(1);
        }
        render_host_normal(&mut out, host, services, meta.service_version);
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
    service_version: bool,
) {
    let name = match &host.hostname {
        Some(h) => format!("{h} ({})", host.address),
        None => host.address.to_string(),
    };
    let _ = writeln!(out, "\nNmap scan report for {name}");

    if host.state != crate::model::HostState::Up {
        let _ = writeln!(out, "Host seems down.");
        return;
    }
    let _ = writeln!(out, "Host is up.");

    // "Not shown" summary of ignored states. The protocol label follows the host's
    // ports (a `-sU` scan reports "udp ports"), defaulting to tcp.
    let ignored = ignored_states(host);
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

    let shown: Vec<_> = host.ports.iter().filter(|p| is_shown(p.state)).collect();
    if shown.is_empty() {
        return;
    }

    // Column-aligned PORT / STATE / SERVICE [/ VERSION] table (nmap's
    // NmapOutputTable shape). The VERSION column appears only under `-sV`.
    let rows: Vec<(String, &str, &str, String)> = shown
        .iter()
        .map(|p| {
            (
                format!("{}/{}", p.number, p.protocol.as_str()),
                p.state.as_str(),
                service_name(p.number, p.protocol, p.service.name.as_deref(), services),
                if service_version {
                    version_display(&p.service)
                } else {
                    String::new()
                },
            )
        })
        .collect();
    let port_w = rows
        .iter()
        .map(|(p, ..)| p.len())
        .chain([4])
        .max()
        .unwrap_or(4);
    let state_w = rows
        .iter()
        .map(|(_, s, ..)| s.len())
        .chain([5])
        .max()
        .unwrap_or(5);
    if service_version {
        let svc_w = rows
            .iter()
            .map(|(_, _, svc, _)| svc.len())
            .chain([7])
            .max()
            .unwrap_or(7);
        let _ = writeln!(
            out,
            "{:port_w$} {:state_w$} {:svc_w$} VERSION",
            "PORT", "STATE", "SERVICE"
        );
        for (p, s, svc, ver) in rows {
            // Trailing space is trimmed so an empty VERSION leaves no dangling ws.
            let line = format!("{p:port_w$} {s:state_w$} {svc:svc_w$} {ver}");
            let _ = writeln!(out, "{}", line.trim_end());
        }
    } else {
        let _ = writeln!(out, "{:port_w$} {:state_w$} SERVICE", "PORT", "STATE");
        for (p, s, svc, _) in rows {
            let _ = writeln!(out, "{p:port_w$} {s:state_w$} {svc}");
        }
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
        let hostname = host.hostname.as_deref().unwrap_or("");
        let status = if host.state == crate::model::HostState::Up {
            "Up"
        } else {
            "Down"
        };
        let _ = writeln!(
            out,
            "Host: {} ({})\tStatus: {}",
            host.address, hostname, status
        );

        let shown: Vec<_> = host.ports.iter().filter(|p| is_shown(p.state)).collect();
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
                        service_name(p.number, p.protocol, p.service.name.as_deref(), services),
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
        let _ = writeln!(out, "<host>");
        let addrtype = if host.address.is_ipv6() {
            "ipv6"
        } else {
            "ipv4"
        };
        let _ = writeln!(
            out,
            "<status state=\"{}\"/>",
            if is_up { "up" } else { "down" }
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
        for (st, count) in ignored_states(host) {
            let _ = writeln!(
                out,
                "<extraports state=\"{}\" count=\"{}\"/>",
                st.as_str(),
                count
            );
        }
        for p in host.ports.iter().filter(|p| is_shown(p.state)) {
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

    #[test]
    fn normal_shows_open_ports_and_not_shown_summary() {
        let out = render_normal(&sample(), &meta(), Some(&services()));
        assert!(out.contains("Nmap scan report for 127.0.0.1"));
        assert!(out.contains("Host is up."));
        assert!(out.contains("Not shown: 2 closed tcp ports (conn-refused)"));
        assert!(out.contains("PORT   STATE SERVICE"));
        assert!(out.contains("22/tcp open  ssh"));
        assert!(out.contains("80/tcp open  http"));
        // Closed ports are summarized, not listed.
        assert!(!out.contains("443/tcp"));
        assert!(out.contains("Nmap done: 1 IP address (1 host up) scanned"));
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
        assert!(out.contains("<extraports state=\"closed\" count=\"2\"/>"));
        assert!(out.contains(
            "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"ssh\""
        ));
        assert!(out.contains("<hosts up=\"1\" down=\"0\" total=\"1\"/>"));
        assert!(out.trim_end().ends_with("</nmaprun>"));
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
