//! Port-spec parsing (`-p`) and the `nmap-services` table — the Rust analog of
//! `scan_lists.cc` (`getpts_aux`) and `services.cc`.
//!
//! Two pieces:
//!   1. [`ServiceTable`] — parses the `nmap-services` data file into a
//!      port/proto → name map plus a frequency ranking (for default "top
//!      ports" and for the service column in output).
//!   2. [`parse_port_spec`] — parses a `-p` expression into per-protocol port
//!      lists: numeric ranges/lists, `T:`/`U:`/`S:` prefixes, open ranges
//!      (`-100`, `1000-`, `-p-`), and exact service names (`http`).
//!
//! Safety properties the fuzz gate proves: both parsers are **total** (any
//! input → `Ok`/typed `Err` or a skipped line, never a panic) and never
//! materialize more than the 65 536-port space. Where the C `fatal()`s on a
//! malformed `nmap-services` line, the port **skips** it (a deliberate,
//! safer-than-C divergence — a bad data file degrades instead of aborting).

use crate::model::Protocol;
use std::collections::HashMap;

// ---- nmap-services table ---------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
struct ServiceEntry {
    port: u16,
    protocol: Protocol,
    name: String,
    /// Open-frequency ratio in [0, 1); 0 when the file had none.
    frequency: f64,
}

/// The parsed `nmap-services` database.
#[derive(Clone, Debug, Default)]
pub struct ServiceTable {
    /// (protocol, port) → service name. First entry per key wins (file order).
    by_port: HashMap<(Protocol, u16), String>,
    /// All kept entries, in file order (top-ports sorts a copy by frequency).
    entries: Vec<ServiceEntry>,
}

impl ServiceTable {
    /// Parse `nmap-services` text. Malformed lines are skipped (never panic,
    /// never abort). Comment (`#`) and blank lines are ignored.
    pub fn parse(text: &str) -> ServiceTable {
        let mut table = ServiceTable::default();
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(entry) = parse_service_line(trimmed) {
                table
                    .by_port
                    .entry((entry.protocol, entry.port))
                    .or_insert_with(|| entry.name.clone());
                table.entries.push(entry);
            }
        }
        table
    }

    /// Service name for a port/protocol, if known.
    pub fn service_name(&self, port: u16, protocol: Protocol) -> Option<&str> {
        self.by_port.get(&(protocol, port)).map(String::as_str)
    }

    /// The `n` highest-frequency ports for `protocol`, most-common first — the
    /// basis of nmap's default "top ports" scan. Ties keep file order (stable).
    pub fn top_ports(&self, protocol: Protocol, n: usize) -> Vec<u16> {
        let mut ranked: Vec<&ServiceEntry> = self
            .entries
            .iter()
            .filter(|e| e.protocol == protocol)
            .collect();
        // Stable sort by descending frequency.
        ranked.sort_by(|a, b| b.frequency.total_cmp(&a.frequency));
        ranked.into_iter().take(n).map(|e| e.port).collect()
    }

    /// Ports for an exact service name whose protocol is in `mask` (used by the
    /// `-p http` form). Empty if the name is unknown for those protocols.
    fn ports_for_name(&self, name: &str, mask: u8) -> Vec<(Protocol, u16)> {
        self.entries
            .iter()
            .filter(|e| e.name == name && (mask & proto_bit(e.protocol)) != 0)
            .map(|e| (e.protocol, e.port))
            .collect()
    }

    /// Number of kept entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parse one non-comment `nmap-services` line: `name port/proto [ratio]`.
/// Returns `None` for any malformed line or an unsupported protocol.
fn parse_service_line(line: &str) -> Option<ServiceEntry> {
    let mut fields = line.split_whitespace();
    let name = fields.next()?;
    let port_proto = fields.next()?;
    let ratio_str = fields.next();

    let (port_s, proto_s) = port_proto.split_once('/')?;
    let port: u16 = port_s.parse().ok()?;
    let protocol = match proto_s.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "sctp" => Protocol::Sctp,
        _ => return None, // ignore ddp/divert/etc.
    };
    let frequency = ratio_str.map_or(0.0, parse_ratio);

    Some(ServiceEntry {
        port,
        protocol,
        name: name.to_string(),
        frequency,
    })
}

/// Parse the ratio field: a decimal (`0.001995`) or a fraction (`n/d`); any
/// invalid or out-of-range value yields 0 (the port never aborts on bad data).
fn parse_ratio(s: &str) -> f64 {
    if let Some((n, d)) = s.split_once('/') {
        match (n.parse::<f64>(), d.parse::<f64>()) {
            (Ok(n), Ok(d)) if d > 0.0 && n >= 0.0 && n <= d => n / d,
            _ => 0.0,
        }
    } else {
        match s.parse::<f64>() {
            Ok(v) if (0.0..1.0).contains(&v) => v,
            _ => 0.0,
        }
    }
}

// ---- port-spec parser ------------------------------------------------------

/// Protocol selector bits (the analog of `SCAN_TCP_PORT` etc.).
const TCP: u8 = 1 << 0;
const UDP: u8 = 1 << 1;
const SCTP: u8 = 1 << 2;

fn proto_bit(p: Protocol) -> u8 {
    match p {
        Protocol::Tcp => TCP,
        Protocol::Udp => UDP,
        Protocol::Sctp => SCTP,
    }
}

/// Parsed port lists per protocol (sorted, de-duplicated) — the analog of
/// `struct scan_lists`. Milestone 1's connect scan reads [`PortList::tcp`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortList {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
    pub sctp: Vec<u16>,
}

/// Why a `-p` expression could not be parsed. Typed, never a `fatal()`/panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortSpecError {
    /// Empty expression.
    Empty,
    /// A port/protocol number outside its valid range.
    OutOfRange { value: i64 },
    /// `start-end` with `end < start`.
    Backwards { start: u16, end: u16 },
    /// A `X:` prefix with an unknown protocol letter.
    UnknownProtoSpecifier(char),
    /// A token that is not a valid range, number, or known service name.
    Malformed(String),
    /// A service name not found in `nmap-services` for the active protocol(s).
    UnknownService(String),
    /// Syntax accepted by nmap but not yet ported (`[...]` top-ports brackets,
    /// `*`/`?` wildcard service masks, `P:` protocol scan). Rejected, never
    /// silently ignored.
    Unsupported(String),
}

/// Parse a `-p` expression into per-protocol [`PortList`]s. `table` enables
/// exact service-name resolution (`-p http`); pass `None` to disable it.
///
/// Faithful to `getpts_aux` for the numeric grammar: comma-separated ranges,
/// `T:`/`U:`/`S:` prefixes that switch the active protocol(s), open-ended
/// ranges (`-100` = `1-100`, `1000-` = `1000-65535`), and single ports. An
/// unprefixed range targets TCP+UDP+SCTP (nmap's default), so the connect scan
/// simply reads `.tcp`.
// Cursor `i` only advances and is bounded by `b.len()`; port ranges are checked
// ≤ 65535 before use, so all the arithmetic here is bounded and can't overflow.
#[allow(clippy::arithmetic_side_effects)]
pub fn parse_port_spec(
    expr: &str,
    table: Option<&ServiceTable>,
) -> Result<PortList, PortSpecError> {
    if expr.trim().is_empty() {
        return Err(PortSpecError::Empty);
    }

    let b = expr.as_bytes();
    let mut list = PortList::default();
    let mut range_type: u8 = TCP | UDP | SCTP;
    let mut i = 0usize;

    while i < b.len() {
        // Leading whitespace.
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Protocol prefix `X:`.
        if b.get(i + 1) == Some(&b':') {
            range_type = match b[i] {
                b'T' => TCP,
                b'U' => UDP,
                b'S' => SCTP,
                b'P' => return Err(PortSpecError::Unsupported("P: (protocol scan)".into())),
                other => return Err(PortSpecError::UnknownProtoSpecifier(char::from(other))),
            };
            i += 2;
            continue;
        }

        // Deferred syntax — rejected explicitly, never silently dropped.
        match b[i] {
            b'[' => {
                return Err(PortSpecError::Unsupported(
                    "[...] top-ports brackets".into(),
                ))
            }
            b'*' | b'?' => {
                return Err(PortSpecError::Unsupported(
                    "*/? wildcard service mask".into(),
                ))
            }
            b']' => return Err(PortSpecError::Malformed("]".into())),
            b',' => {
                i += 1;
                continue;
            }
            _ => {}
        }

        // A service name (starts with a lowercase letter): exact match only.
        if b[i].is_ascii_lowercase() {
            let start = i;
            while i < b.len() && !is_token_end(b[i]) {
                i += 1;
            }
            let name = &expr[start..i];
            let table = table.ok_or_else(|| PortSpecError::UnknownService(name.to_string()))?;
            let matches = table.ports_for_name(name, range_type);
            if matches.is_empty() {
                return Err(PortSpecError::UnknownService(name.to_string()));
            }
            for (proto, port) in matches {
                push_port(&mut list, proto_bit(proto), port);
            }
            continue;
        }

        // Numeric range (possibly open on the left).
        let start: u32 = if b[i] == b'-' {
            1
        } else if b[i].is_ascii_digit() {
            let (v, next) = parse_num(b, i);
            i = next;
            v
        } else {
            return Err(PortSpecError::Malformed(char::from(b[i]).to_string()));
        };
        if start > 65535 {
            return Err(PortSpecError::OutOfRange {
                value: i64::from(start),
            });
        }

        // Range end.
        let end: u32 = if i >= b.len() || b[i] == b',' {
            start
        } else if b[i] == b'-' {
            i += 1;
            if i >= b.len() || b[i] == b',' {
                65535
            } else if b[i].is_ascii_digit() {
                let (v, next) = parse_num(b, i);
                i = next;
                v
            } else {
                return Err(PortSpecError::Malformed(char::from(b[i]).to_string()));
            }
        } else {
            return Err(PortSpecError::Malformed(char::from(b[i]).to_string()));
        };
        if end > 65535 {
            return Err(PortSpecError::OutOfRange {
                value: i64::from(end),
            });
        }

        // Both bounds are ≤ 65535 (checked above), so these conversions can't
        // truncate; iterate over the u16 range with no per-port cast.
        let start = u16::try_from(start).unwrap_or(u16::MAX);
        let end = u16::try_from(end).unwrap_or(u16::MAX);
        if end < start {
            return Err(PortSpecError::Backwards { start, end });
        }
        for port in start..=end {
            push_port(&mut list, range_type, port);
        }
    }

    list.tcp.sort_unstable();
    list.tcp.dedup();
    list.udp.sort_unstable();
    list.udp.dedup();
    list.sctp.sort_unstable();
    list.sctp.dedup();
    Ok(list)
}

/// True at a character that ends a service-name token.
fn is_token_end(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == b',' || byte == b']'
}

/// Parse a decimal run at `pos`, saturating on overflow (caller range-checks).
/// Returns `(value, new_pos)`.
#[allow(clippy::arithmetic_side_effects)] // bounded: pos advances within b.len()
fn parse_num(b: &[u8], pos: usize) -> (u32, usize) {
    let mut i = pos;
    let mut n: u32 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        n = n
            .saturating_mul(10)
            .saturating_add(u32::from(b[i]).saturating_sub(u32::from(b'0')));
        i += 1;
    }
    (n, i)
}

/// Add `port` to each protocol list selected by `mask`.
fn push_port(list: &mut PortList, mask: u8, port: u16) {
    if mask & TCP != 0 {
        list.tcp.push(port);
    }
    if mask & UDP != 0 {
        list.udp.push(port);
    }
    if mask & SCTP != 0 {
        list.sctp.push(port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# comment line
tcpmux\t1/tcp\t0.001995\t# TCP Port Service Multiplexer
echo\t7/tcp\t0.004855
echo\t7/udp\t0.002827
ssh\t22/tcp\t0.182286
http\t80/tcp\t0.484143
http\t80/udp\t0.000078
https\t443/tcp\t0.208762
ddp\t1/ddp\t0.0
malformed line with no slash
domain\t53/udp\t0.213496
";

    fn table() -> ServiceTable {
        ServiceTable::parse(SAMPLE)
    }

    #[test]
    fn services_parse_skips_comments_and_malformed() {
        let t = table();
        // ddp and the malformed line are skipped; 8 real entries remain.
        assert_eq!(t.len(), 8);
        assert_eq!(t.service_name(80, Protocol::Tcp), Some("http"));
        assert_eq!(t.service_name(22, Protocol::Tcp), Some("ssh"));
        assert_eq!(t.service_name(53, Protocol::Udp), Some("domain"));
        assert_eq!(t.service_name(80, Protocol::Udp), Some("http"));
        assert_eq!(t.service_name(9999, Protocol::Tcp), None);
    }

    #[test]
    fn top_ports_ranks_by_frequency() {
        let t = table();
        // TCP by frequency desc: http(.48) https(.21) ssh(.18) echo(.0048) tcpmux(.002)
        assert_eq!(t.top_ports(Protocol::Tcp, 3), vec![80, 443, 22]);
        assert_eq!(t.top_ports(Protocol::Udp, 1), vec![53]); // domain .21 > echo/http
    }

    fn tcp(expr: &str) -> Vec<u16> {
        parse_port_spec(expr, None).unwrap().tcp
    }

    #[test]
    fn single_list_and_range() {
        assert_eq!(tcp("80"), vec![80]);
        assert_eq!(tcp("22,80,443"), vec![22, 80, 443]);
        assert_eq!(tcp("20-25"), vec![20, 21, 22, 23, 24, 25]);
        assert_eq!(tcp("443,22,443,80").len(), 3); // dedup + sort
        assert_eq!(tcp("443,22,80"), vec![22, 80, 443]);
    }

    #[test]
    fn open_ranges_and_all_ports() {
        assert_eq!(tcp("-3"), vec![1, 2, 3]); // 1-3
        assert_eq!(tcp("65533-").len(), 3); // 65533,65534,65535
        let all = tcp("-"); // -p-  → 1..=65535
        assert_eq!(all.len(), 65535);
        assert_eq!(*all.first().unwrap(), 1);
        assert_eq!(*all.last().unwrap(), 65535);
    }

    #[test]
    fn protocol_prefixes_route_to_the_right_list() {
        let p = parse_port_spec("T:80,U:53", None).unwrap();
        assert_eq!(p.tcp, vec![80]);
        assert_eq!(p.udp, vec![53]);
        assert!(p.sctp.is_empty());
        // Unprefixed hits all three (nmap default).
        let p = parse_port_spec("80", None).unwrap();
        assert_eq!(p.tcp, vec![80]);
        assert_eq!(p.udp, vec![80]);
        assert_eq!(p.sctp, vec![80]);
    }

    #[test]
    fn service_names_resolve_against_the_table() {
        let t = table();
        let p = parse_port_spec("http,ssh", Some(&t)).unwrap();
        assert!(p.tcp.contains(&80) && p.tcp.contains(&22));
        // T: prefix limits which protocol a name resolves for.
        let p = parse_port_spec("T:http", Some(&t)).unwrap();
        assert_eq!(p.tcp, vec![80]);
        assert!(p.udp.is_empty());
        assert_eq!(
            parse_port_spec("nosuchservice", Some(&t)),
            Err(PortSpecError::UnknownService("nosuchservice".into()))
        );
    }

    #[test]
    fn errors_are_typed_never_fatal() {
        assert_eq!(parse_port_spec("", None), Err(PortSpecError::Empty));
        assert_eq!(
            parse_port_spec("70000", None),
            Err(PortSpecError::OutOfRange { value: 70000 })
        );
        assert_eq!(
            parse_port_spec("100-50", None),
            Err(PortSpecError::Backwards {
                start: 100,
                end: 50
            })
        );
        assert!(matches!(
            parse_port_spec("[1-10]", None),
            Err(PortSpecError::Unsupported(_))
        ));
        assert!(matches!(
            parse_port_spec("Z:80", None),
            Err(PortSpecError::UnknownProtoSpecifier('Z'))
        ));
    }

    #[test]
    fn never_panics_on_hostile_input() {
        for s in [
            "",
            "-",
            "--",
            ",",
            ",,,",
            "999999999999999",
            "1-",
            "-1",
            "T:",
            ":80",
            "80-",
            "[",
            "]",
            "*",
            "abc-def",
            &"1,".repeat(5000),
            "🦀/tcp",
        ] {
            let _ = parse_port_spec(s, None);
        }
        // services parser must also survive arbitrary bytes.
        for s in ["", "\0\0", "x", "x/", "1/tcp", &"a b c\n".repeat(1000)] {
            let _ = ServiceTable::parse(s);
        }
    }
}
