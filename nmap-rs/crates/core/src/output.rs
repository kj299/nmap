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

/// The reason token nmap prints for an ignored-state summary.
fn ignored_reason(state: PortState) -> &'static str {
    match state {
        PortState::Closed => "conn-refused",
        _ => "no-response",
    }
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
        render_host_normal(&mut out, host, services);
    }

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

fn render_host_normal(out: &mut String, host: &Host, services: Option<&ServiceTable>) {
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

    // "Not shown" summary of ignored states.
    let ignored = ignored_states(host);
    if !ignored.is_empty() {
        let parts: Vec<String> = ignored
            .iter()
            .map(|(st, n)| format!("{} {} tcp ports ({})", n, st.as_str(), ignored_reason(*st)))
            .collect();
        let _ = writeln!(out, "Not shown: {}", parts.join(", "));
    }

    let shown: Vec<_> = host.ports.iter().filter(|p| is_shown(p.state)).collect();
    if shown.is_empty() {
        return;
    }

    // Column-aligned PORT / STATE / SERVICE table (nmap's NmapOutputTable shape).
    let rows: Vec<(String, &str, &str)> = shown
        .iter()
        .map(|p| {
            (
                format!("{}/{}", p.number, p.protocol.as_str()),
                p.state.as_str(),
                service_name(p.number, p.protocol, p.service.name.as_deref(), services),
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
        .map(|(_, s, _)| s.len())
        .chain([5])
        .max()
        .unwrap_or(5);
    let _ = writeln!(out, "{:port_w$} {:state_w$} SERVICE", "PORT", "STATE");
    for (p, s, svc) in rows {
        let _ = writeln!(out, "{p:port_w$} {s:state_w$} {svc}");
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
                    // portno/state/proto/owner/service/rpc/version — M1 fills
                    // portno/state/proto//service, the rest empty (as nmap does).
                    format!(
                        "{}/{}/{}//{}///",
                        p.number,
                        p.state.as_str(),
                        p.protocol.as_str(),
                        service_name(p.number, p.protocol, p.service.name.as_deref(), services),
                    )
                })
                .collect();
            let _ = writeln!(
                out,
                "Host: {} ({})\tPorts: {}",
                host.address,
                hostname,
                entries.join(", ")
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
                "<port protocol=\"{}\" portid=\"{}\"><state state=\"{}\" reason=\"{}\"/><service name=\"{}\" method=\"table\" conf=\"3\"/></port>",
                p.protocol.as_str(),
                p.number,
                p.state.as_str(),
                p.reason.as_str(),
                xml_escape(svc)
            );
        }
        let _ = writeln!(out, "</ports>");
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
        }
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
}
