//! `nmap-service-probes` parser — the Rust analog of the parse half of
//! `service_scan.cc` (`parse_nmap_service_probe_file`, `ServiceProbe::setProbeDetails`,
//! `ServiceProbeMatch::InitMatch`, `next_template`, `cstring_unescape`).
//!
//! This is Milestone 3's first module: it turns the 2.5 MB probe database into a
//! structured [`ProbeDb`]. It does **not** compile or translate any regex — match
//! bodies are stored **raw** (exactly the bytes PCRE2 would receive); translation
//! (`core::pcre_translate`) and matching (`core::matcher`) are the next modules.
//!
//! ## The threat model changed the parser's contract
//!
//! The C `fatal()`s on the first malformed byte — a single bad line aborts the
//! whole scan. `--versiondb <file>` makes this file **untrusted-shaped input**, so
//! the port inverts that: every parse failure is *localized* — the offending line
//! (or probe) is skipped, a [`ProbeWarning`] is recorded, and parsing continues.
//! A hostile or corrupt database degrades to "fewer probes", never a crash and
//! never a panic. This is the same deliberate, safer-than-C divergence M1 made for
//! `nmap-services` (logged in `DIVERGENCES.md`).
//!
//! Safety properties the fuzz gate proves: [`ProbeDb::parse`] is **total** (any
//! `&str` → a `ProbeDb`, never a panic), performs no unchecked indexing, and all
//! integer parsing is range-checked before use.

use crate::model::Protocol;
use crate::ports::{parse_port_spec, PortList};

/// Default `totalwaitms` — `DEFAULT_SERVICEWAITMS` (`service_scan.h:84`).
const DEFAULT_TOTALWAITMS: u32 = 5000;
/// Default `tcpwrappedms` — `DEFAULT_TCPWRAPPEDMS` (`service_scan.h:85`).
const DEFAULT_TCPWRAPPEDMS: u32 = 2000;
/// Default rarity for a probe without a `rarity` directive (`service_scan.cc:1111`).
const DEFAULT_RARITY: u8 = 5;
/// `waitms` bounds enforced by the C parser (`service_scan.cc:1377,1382`).
const WAITMS_MIN: u32 = 100;
const WAITMS_MAX: u32 = 300_000;
/// `MAXFALLBACKS` (`service_scan.h:88`) — cap on comma-separated fallback names.
const MAX_FALLBACKS: usize = 20;

/// The protocol a probe is sent over (`Probe TCP`/`Probe UDP`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

/// One `match`/`softmatch` line: a service name, the **raw** regex body, its
/// flags, and the version-info substitution templates. The regex is *not*
/// compiled here — that is `core::matcher`'s job.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MatchRule {
    /// `softmatch` (narrows the probe set but keeps scanning) vs `match` (final).
    pub soft: bool,
    /// The detected service name (e.g. `http`, `ssh`).
    pub service: String,
    /// Raw regex body between the `m` delimiters — backslash escapes intact,
    /// exactly what `pcre2_compile` receives. Fed to `pcre_translate` later.
    pub pattern: String,
    /// `i` flag — case-insensitive (`PCRE2_CASELESS`).
    pub ignorecase: bool,
    /// `s` flag — `.` matches newline (`PCRE2_DOTALL`).
    pub dotall: bool,
    /// `p/.../` product template.
    pub product: Option<String>,
    /// `v/.../` version template.
    pub version: Option<String>,
    /// `i/.../` extra-info template.
    pub info: Option<String>,
    /// `h/.../` hostname template.
    pub hostname: Option<String>,
    /// `o/.../` OS-type template.
    pub ostype: Option<String>,
    /// `d/.../` device-type template.
    pub devicetype: Option<String>,
    /// `cpe:/.../` templates (a match may carry several), stored verbatim
    /// **including** the `cpe:/` prefix, as the C keeps them.
    pub cpe: Vec<String>,
}

/// A single `Probe` block: how to elicit a banner, and the rules that interpret
/// the reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub protocol: ProbeProtocol,
    /// Probe name (the word after the protocol, e.g. `NULL`, `GetRequest`).
    pub name: String,
    /// The bytes to send, **unescaped** (`cstring_unescape`). May contain NULs
    /// and be empty (the NULL probe sends nothing).
    pub probestring: Vec<u8>,
    /// `no-payload` flag — exclude this probe from UDP payload reuse.
    pub no_payload: bool,
    /// `ports` — plain probable ports.
    pub ports: Vec<u16>,
    /// `sslports` — probable ports behind SSL.
    pub sslports: Vec<u16>,
    /// `rarity` in `1..=9` (default 5); how aggressively the probe is scheduled.
    pub rarity: u8,
    /// `totalwaitms` in `[100, 300000]` (default 5000).
    pub totalwaitms: u32,
    /// `tcpwrappedms` in `[100, 300000]` (default 2000).
    pub tcpwrappedms: u32,
    /// `fallback` names, comma/space-split and **unresolved** — resolving a name
    /// to another probe is deferred to the scheduler (C's `compileFallbacks`).
    pub fallback: Vec<String>,
    /// `match`/`softmatch` rules, in file order.
    pub matches: Vec<MatchRule>,
}

impl Probe {
    fn new(protocol: ProbeProtocol, name: String, probestring: Vec<u8>) -> Probe {
        Probe {
            protocol,
            name,
            probestring,
            no_payload: false,
            ports: Vec::new(),
            sslports: Vec::new(),
            rarity: DEFAULT_RARITY,
            totalwaitms: DEFAULT_TOTALWAITMS,
            tcpwrappedms: DEFAULT_TCPWRAPPEDMS,
            fallback: Vec::new(),
            matches: Vec::new(),
        }
    }

    /// A probe with an empty send-string is the NULL probe (`isNullProbe()` =
    /// `probestringlen == 0`, `service_scan.h:198`).
    pub fn is_null_probe(&self) -> bool {
        self.probestring.is_empty()
    }
}

/// A localized parse problem. The line was skipped; parsing continued. This is
/// the visible form of the "degrade, never `fatal()`" divergence — nothing is
/// dropped *silently*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeWarning {
    /// 1-based line number in the source, matching the C error messages.
    pub line: usize,
    /// Human-readable reason the line/probe was skipped.
    pub message: String,
}

/// The parsed probe database — the analog of `AllProbes`.
#[derive(Clone, Debug, Default)]
pub struct ProbeDb {
    /// The single NULL probe (empty send-string), if present.
    pub null_probe: Option<Probe>,
    /// All non-NULL probes, in file order.
    pub probes: Vec<Probe>,
    /// Ports named by the (at most one) `Exclude` directive.
    pub exclude: PortList,
    /// Whether an `Exclude` directive was seen (mirrors `excluded_seen`).
    pub excluded_seen: bool,
    /// Every skipped line, in order. Empty on a clean file.
    pub warnings: Vec<ProbeWarning>,
}

impl ProbeDb {
    /// Parse `nmap-service-probes` text. Total: any input yields a `ProbeDb`;
    /// malformed lines land in [`ProbeDb::warnings`] instead of aborting.
    pub fn parse(text: &str) -> ProbeDb {
        let mut db = ProbeDb::default();
        let mut current: Option<Probe> = None;

        for (idx, raw) in text.lines().enumerate() {
            let lineno = idx.saturating_add(1);
            // C skips only a bare newline or a `#` comment; we also skip
            // whitespace-only lines (a safe superset — the real file has none).
            let trimmed = raw.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(rest) = raw.strip_prefix("Exclude ") {
                db.handle_exclude(rest, lineno, current.is_some());
                continue;
            }

            if let Some(rest) = raw.strip_prefix("Probe ") {
                // A new Probe closes the one being built.
                if let Some(done) = current.take() {
                    db.finish_probe(done);
                }
                match parse_probe_details(rest) {
                    Ok(probe) => current = Some(probe),
                    Err(msg) => {
                        db.warn(lineno, msg);
                        current = None;
                    }
                }
                continue;
            }

            // Everything else is a directive that belongs to the open probe.
            match current.as_mut() {
                Some(probe) => apply_directive(probe, raw, lineno, &mut db.warnings),
                None => db.warn(
                    lineno,
                    "directive before any Probe (expected \"Probe \" or \"Exclude \")".into(),
                ),
            }
        }

        if let Some(done) = current.take() {
            db.finish_probe(done);
        }
        db
    }

    /// Whether `port`/`proto` is named by the `Exclude` directive
    /// (`AllProbes::isExcluded`).
    pub fn is_excluded(&self, port: u16, proto: Protocol) -> bool {
        if !self.excluded_seen {
            return false;
        }
        let list = match proto {
            Protocol::Tcp => &self.exclude.tcp,
            Protocol::Udp => &self.exclude.udp,
            Protocol::Sctp => &self.exclude.sctp,
        };
        list.contains(&port)
    }

    fn warn(&mut self, line: usize, message: String) {
        self.warnings.push(ProbeWarning { line, message });
    }

    fn finish_probe(&mut self, probe: Probe) {
        if probe.is_null_probe() {
            if self.null_probe.is_some() {
                // C `assert(!AP->nullProbe)` — a second NULL probe would abort.
                // We keep the first and record the duplicate.
                self.warnings.push(ProbeWarning {
                    line: 0,
                    message: format!("duplicate NULL probe '{}' ignored", probe.name),
                });
            } else {
                self.null_probe = Some(probe);
            }
        } else {
            self.probes.push(probe);
        }
    }

    fn handle_exclude(&mut self, rest: &str, lineno: usize, inside_probe: bool) {
        if inside_probe {
            // C fatal: "The Exclude directive must precede all Probes".
            self.warn(lineno, "Exclude directive after a Probe ignored".into());
            return;
        }
        if self.excluded_seen {
            // C fatal: "Only 1 Exclude directive is allowed".
            self.warn(lineno, "duplicate Exclude directive ignored".into());
            return;
        }
        match parse_port_spec(rest.trim(), None) {
            Ok(list) => {
                self.exclude = list;
                self.excluded_seen = true;
            }
            Err(e) => self.warn(lineno, format!("bad Exclude port list: {e:?}")),
        }
    }
}

/// Parse the text after `Probe ` into a [`Probe`] (`setProbeDetails`).
/// `<PROTO> <name> q<delim><string><delim>[ flags]`.
fn parse_probe_details(pd: &str) -> Result<Probe, String> {
    let (protocol, after_proto) = if let Some(r) = pd.strip_prefix("TCP ") {
        (ProbeProtocol::Tcp, r)
    } else if let Some(r) = pd.strip_prefix("UDP ") {
        (ProbeProtocol::Udp, r)
    } else {
        return Err("invalid protocol (expected \"TCP \" or \"UDP \")".into());
    };

    // Probe name: alnum, up to the next space.
    let first = after_proto.chars().next().ok_or("nothing after protocol")?;
    if !first.is_ascii_alphanumeric() {
        return Err("bad probe name".into());
    }
    let sp = after_proto.find(' ').ok_or("nothing after probe name")?;
    let name = after_proto[..sp].to_string();

    // Probe string: must begin `q`, then a delimiter, then the escaped body up
    // to the next occurrence of that delimiter (C uses `strchr` — first match,
    // no escape processing for the delimiter itself).
    let probe_part = &after_proto[sp.saturating_add(1)..];
    let mut pc = probe_part.chars();
    if pc.next() != Some('q') {
        return Err("probe string must begin with 'q'".into());
    }
    let delim = pc.next().ok_or("missing probe-string delimiter")?;
    let body_start = 1usize.saturating_add(delim.len_utf8()); // after "q<delim>"
    let after_q = &probe_part[body_start..];
    let end = after_q
        .find(delim)
        .ok_or("no ending delimiter for probe string")?;
    let escaped = &after_q[..end];
    let probestring = cstring_unescape(escaped).ok_or("bad probe string escaping")?;

    let mut probe = Probe::new(protocol, name, probestring);

    // Optional flags after the closing delimiter (`no-payload`).
    let tail = &after_q[end.saturating_add(delim.len_utf8())..];
    if tail.split_whitespace().any(|w| w == "no-payload") {
        probe.no_payload = true;
    }
    Ok(probe)
}

/// Apply a within-probe directive line to `probe` (`ports`, `sslports`,
/// `rarity`, `fallback`, `totalwaitms`, `tcpwrappedms`, `match`, `softmatch`).
fn apply_directive(probe: &mut Probe, line: &str, lineno: usize, warnings: &mut Vec<ProbeWarning>) {
    let mut warn = |m: String| {
        warnings.push(ProbeWarning {
            line: lineno,
            message: m,
        })
    };

    if let Some(r) = line.strip_prefix("ports ") {
        match parse_probe_ports(r) {
            Ok(mut ports) => probe.ports.append(&mut ports),
            Err(e) => warn(format!("bad ports list: {e}")),
        }
    } else if let Some(r) = line.strip_prefix("sslports ") {
        match parse_probe_ports(r) {
            Ok(mut ports) => probe.sslports.append(&mut ports),
            Err(e) => warn(format!("bad sslports list: {e}")),
        }
    } else if let Some(r) = line.strip_prefix("rarity ") {
        // C `atoi` then range-check `1..=9`; a bad value aborts. We keep the
        // default and warn.
        match r.trim().parse::<u8>() {
            Ok(v) if (1..=9).contains(&v) => probe.rarity = v,
            _ => warn("rarity must be an integer 1..=9".into()),
        }
    } else if let Some(r) = line.strip_prefix("fallback ") {
        // Split on comma/whitespace, drop empties, cap at MAXFALLBACKS.
        probe.fallback = r
            .split([',', ' ', '\t', '\r', '\n'])
            .filter(|s| !s.is_empty())
            .take(MAX_FALLBACKS)
            .map(str::to_string)
            .collect();
    } else if let Some(r) = line.strip_prefix("totalwaitms ") {
        match parse_waitms(r) {
            Some(v) => probe.totalwaitms = v,
            None => warn(format!(
                "bad totalwaitms (must be {WAITMS_MIN}..={WAITMS_MAX})"
            )),
        }
    } else if let Some(r) = line.strip_prefix("tcpwrappedms ") {
        match parse_waitms(r) {
            Some(v) => probe.tcpwrappedms = v,
            None => warn(format!(
                "bad tcpwrappedms (must be {WAITMS_MIN}..={WAITMS_MAX})"
            )),
        }
    } else if line.starts_with("match ") || line.starts_with("softmatch ") {
        match parse_match_rule(line) {
            Ok(rule) => probe.matches.push(rule),
            Err(e) => warn(format!("bad match line: {e}")),
        }
    } else if line.starts_with("Exclude ") {
        warn("Exclude directive after a Probe ignored".into());
    } else {
        warn("unknown directive".into());
    }
}

/// `totalwaitms`/`tcpwrappedms`: C uses `strtol` (leading digits, ignores a
/// trailing tail) then range-checks `[100, 300000]`.
fn parse_waitms(s: &str) -> Option<u32> {
    let v = strtol_prefix(s.trim_start())?;
    let v = u32::try_from(v).ok()?;
    if (WAITMS_MIN..=WAITMS_MAX).contains(&v) {
        Some(v)
    } else {
        None
    }
}

/// `strtol(_, _, 10)` prefix: an optional sign then decimal digits, stopping at
/// the first non-digit. `None` if there are no leading digits.
fn strtol_prefix(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut neg = false;
    if let Some(&c) = b.first() {
        if c == b'+' || c == b'-' {
            neg = c == b'-';
            i = 1;
        }
    }
    let start = i;
    let mut val: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        let d = i64::from(b[i].wrapping_sub(b'0'));
        val = val.saturating_mul(10).saturating_add(d);
        i = i.saturating_add(1);
    }
    if i == start {
        return None;
    }
    Some(if neg { val.saturating_neg() } else { val })
}

/// Parse a probe `ports`/`sslports` list (`setPortVector`): comma-separated
/// single ports and `a-b` ranges, each in `0..=65535`. Returns every port in
/// the ranges (as the C materializes them). Total; typed error string.
fn parse_probe_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            return Err("empty range".into());
        }
        let (start, end) = match tok.split_once('-') {
            Some((a, b)) => {
                let a = parse_port(a.trim())?;
                let b = parse_port(b.trim())?;
                if b < a {
                    return Err(format!("range {a}-{b} is backwards"));
                }
                (a, b)
            }
            None => {
                let p = parse_port(tok)?;
                (p, p)
            }
        };
        for p in start..=end {
            out.push(p);
        }
    }
    Ok(out)
}

fn parse_port(s: &str) -> Result<u16, String> {
    let v: i64 = s.parse().map_err(|_| format!("not a number: {s:?}"))?;
    if !(0..=65535).contains(&v) {
        return Err(format!("port {v} out of range 0..=65535"));
    }
    // `0..=65535` verified above, so the cast cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    Ok(v as u16)
}

/// Parse a full `match`/`softmatch` line (`ServiceProbeMatch::InitMatch`):
/// `match <svc> m<delim><regex><delim><flags> [p/../ v/../ i/../ h/../ o/../ d/../ cpe:/../]`.
fn parse_match_rule(line: &str) -> Result<MatchRule, String> {
    let (soft, rest) = if let Some(r) = line.strip_prefix("softmatch ") {
        (true, r)
    } else if let Some(r) = line.strip_prefix("match ") {
        (false, r)
    } else {
        return Err("must begin with \"match\" or \"softmatch\"".into());
    };

    // Service name up to the first space.
    let sp = rest.find(' ').ok_or("could not find service name")?;
    let service = rest[..sp].to_string();
    let mut cursor = &rest[sp..];

    // First template: the `m/.../` regex.
    let (mode, body, flags, next) = next_template(cursor)?.ok_or("missing match regex")?;
    if mode != "m" {
        return Err("matchtext must begin with 'm'".into());
    }
    let mut rule = MatchRule {
        soft,
        service,
        pattern: body,
        ..MatchRule::default()
    };
    for f in flags.chars() {
        match f {
            'i' => rule.ignorecase = true,
            's' => rule.dotall = true,
            other => return Err(format!("illegal regexp option '{other}'")),
        }
    }
    cursor = next;

    // Remaining templates: p/v/i/h/o/d/cpe.
    while let Some((mode, body, _flags, next)) = next_template(cursor)? {
        match mode.as_str() {
            "p" => rule.product = Some(body),
            "v" => rule.version = Some(body),
            "i" => rule.info = Some(body),
            "h" => rule.hostname = Some(body),
            "o" => rule.ostype = Some(body),
            "d" => rule.devicetype = Some(body),
            "cpe" => rule.cpe.push(body),
            other => return Err(format!("unknown template specifier '{other}'")),
        }
        cursor = next;
    }
    Ok(rule)
}

/// One `next_template` step over `matchtext` (`service_scan.cc:308`).
///
/// Reads up to 3 leading ASCII-alpha mode chars, then a one-char delimiter (for
/// `cpe`, a `:` precedes a mandatory `/` delimiter and the body keeps the
/// `cpe:/` prefix, exactly as the C `mkstr(p, q)` does). The body runs to the
/// next occurrence of the delimiter (C `strchr` — first match). Trailing
/// ASCII-alpha flags must be followed by whitespace or end-of-line.
///
/// Returns `Ok(None)` at end-of-input, `Ok(Some((mode, body, flags, rest)))`
/// otherwise, or `Err` on a malformed template.
type TemplateStep<'a> = (String, String, String, &'a str);
fn next_template(matchtext: &str) -> Result<Option<TemplateStep<'_>>, String> {
    let p = matchtext.trim_start();
    if p.is_empty() {
        return Ok(None);
    }
    let b = p.as_bytes();

    // Mode: up to 3 leading ASCII-alpha bytes.
    let mut i = 0usize;
    while i < 3 && i < b.len() && b[i].is_ascii_alphabetic() {
        i = i.saturating_add(1);
    }
    let mode = &p[..i];

    // Determine the delimiter and where the stored body begins.
    let (delim, body_from, delim_at) = if b.get(i) == Some(&b':') && mode == "cpe" {
        // `cpe:/.../` — delimiter is the '/', body keeps the `cpe:/` prefix (C
        // leaves `p` at the start of "cpe").
        let slash = i.saturating_add(1);
        if b.get(slash) != Some(&b'/') {
            return Err("cpe delimiter is not '/'".into());
        }
        ('/', 0usize, slash)
    } else {
        // Normal template: the CHARACTER after the mode is the delimiter. Read it
        // as a real `char`, not a raw byte — a multi-byte UTF-8 delimiter (which a
        // hostile `--versiondb` can supply) would otherwise be mis-sized by
        // `len_utf8()` and push a later byte index into the middle of a code
        // point, panicking the slice. (Regression: `probedb-multibyte-delim`.)
        match p[i..].chars().next() {
            None => return Err("bare word (no delimiter)".into()),
            Some(dc) if dc.is_whitespace() => return Err("bare word (no delimiter)".into()),
            Some(dc) => (dc, i.saturating_add(dc.len_utf8()), i),
        }
    };

    // Find the closing delimiter (first occurrence after the opening one).
    let search_from = delim_at.saturating_add(delim.len_utf8());
    let rel = p[search_from..]
        .find(delim)
        .ok_or("missing end delimiter")?;
    let close = search_from.saturating_add(rel);
    let body = p[body_from..close].to_string();

    // Flags: ASCII-alpha run after the closing delimiter, then whitespace/EOL.
    let after = close.saturating_add(delim.len_utf8());
    let ab = p.as_bytes();
    let mut j = after;
    while j < ab.len() && j.saturating_sub(after) < 3 && ab[j].is_ascii_alphabetic() {
        j = j.saturating_add(1);
    }
    let flags = &p[after..j];
    // `j` sits on a char boundary (it only advanced over ASCII-alpha). The char
    // after the flags must be whitespace or end-of-line; read it as a real char
    // so a multi-byte follower is judged correctly, not via a lead byte.
    if let Some(c) = p[j..].chars().next() {
        if !c.is_whitespace() {
            return Err("flags too long".into());
        }
    }
    Ok(Some((mode.to_string(), body, flags.to_string(), &p[j..])))
}

/// Port of `cstring_unescape` (`utils.cc:353`): the *strict* escape set the
/// probe strings use. Returns the decoded bytes, or `None` on any unsupported
/// escape (C returns `NULL` → the caller `fatal()`s; we localize to a warning).
///
/// Supported: `\\ \0 \n \r \t \xHH`. Everything else after a `\` is rejected.
fn cstring_unescape(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\\' {
            let n = *b.get(i.saturating_add(1))?;
            match n {
                b'\\' => {
                    out.push(b'\\');
                    i = i.saturating_add(2);
                }
                b'0' => {
                    out.push(0);
                    i = i.saturating_add(2);
                }
                b'n' => {
                    out.push(b'\n');
                    i = i.saturating_add(2);
                }
                b'r' => {
                    out.push(b'\r');
                    i = i.saturating_add(2);
                }
                b't' => {
                    out.push(b'\t');
                    i = i.saturating_add(2);
                }
                b'x' => {
                    let h1 = *b.get(i.saturating_add(2))?;
                    let h2 = *b.get(i.saturating_add(3))?;
                    let hi = hex_val(h1)?;
                    let lo = hex_val(h2)?;
                    out.push(hi.checked_mul(16)?.checked_add(lo)?);
                    i = i.saturating_add(4);
                }
                _ => return None,
            }
        } else {
            out.push(b[i]);
            i = i.saturating_add(1);
        }
    }
    Some(out)
}

/// Single hex digit → value (`hex2char` half). `None` if not `[0-9a-fA-F]`.
fn hex_val(c: u8) -> Option<u8> {
    // Each arm's guard bounds `c`, so the subtractions cannot underflow and the
    // `+10` cannot overflow (max result is 15); `wrapping_*` documents that.
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_probe_is_empty_string() {
        let db = ProbeDb::parse("Probe TCP NULL q||\n");
        assert!(db.null_probe.is_some());
        let np = db.null_probe.unwrap();
        assert_eq!(np.name, "NULL");
        assert!(np.is_null_probe());
        assert_eq!(np.probestring, Vec::<u8>::new());
        assert!(db.probes.is_empty());
        assert!(db.warnings.is_empty());
    }

    #[test]
    fn probe_string_unescaped_to_bytes() {
        let db = ProbeDb::parse("Probe TCP Foo q|GET / HTTP/1.0\\r\\n\\r\\n|\n");
        let p = &db.probes[0];
        assert_eq!(p.name, "Foo");
        assert_eq!(p.protocol, ProbeProtocol::Tcp);
        assert_eq!(p.probestring, b"GET / HTTP/1.0\r\n\r\n");
        assert!(!p.is_null_probe());
    }

    #[test]
    fn hex_and_nul_escapes() {
        let db = ProbeDb::parse("Probe UDP Bar q|\\0\\xff\\x41|\n");
        let p = &db.probes[0];
        assert_eq!(p.protocol, ProbeProtocol::Udp);
        assert_eq!(p.probestring, vec![0x00, 0xff, 0x41]);
    }

    #[test]
    fn no_payload_flag() {
        let db = ProbeDb::parse("Probe UDP Bar q|x| no-payload\n");
        assert!(db.probes[0].no_payload);
    }

    #[test]
    fn directives_populate_probe() {
        let text = "\
Probe TCP GetRequest q|GET|
rarity 7
ports 80,443,8080-8082
sslports 443
totalwaitms 6000
tcpwrappedms 3000
fallback GetRequest,NULL
";
        let db = ProbeDb::parse(text);
        let p = &db.probes[0];
        assert_eq!(p.rarity, 7);
        assert_eq!(p.ports, vec![80, 443, 8080, 8081, 8082]);
        assert_eq!(p.sslports, vec![443]);
        assert_eq!(p.totalwaitms, 6000);
        assert_eq!(p.tcpwrappedms, 3000);
        assert_eq!(p.fallback, vec!["GetRequest", "NULL"]);
        assert!(db.warnings.is_empty());
    }

    #[test]
    fn match_line_full_templates() {
        let line = "match ssh m|^SSH-([\\d.]+)-OpenSSH[_-]([\\w.]+)| p/OpenSSH/ v/$2/ i/protocol $1/ o/Unix/ cpe:/a:openbsd:openssh:$2/";
        let db = ProbeDb::parse(&format!("Probe TCP NULL q||\n{line}\n"));
        // The match attaches to the NULL probe.
        let np = db.null_probe.as_ref().unwrap();
        let m = &np.matches[0];
        assert!(!m.soft);
        assert_eq!(m.service, "ssh");
        assert_eq!(m.pattern, "^SSH-([\\d.]+)-OpenSSH[_-]([\\w.]+)");
        assert_eq!(m.product.as_deref(), Some("OpenSSH"));
        assert_eq!(m.version.as_deref(), Some("$2"));
        assert_eq!(m.info.as_deref(), Some("protocol $1"));
        assert_eq!(m.ostype.as_deref(), Some("Unix"));
        assert_eq!(m.cpe, vec!["cpe:/a:openbsd:openssh:$2"]);
        assert!(db.warnings.is_empty());
    }

    #[test]
    fn match_flags_i_and_s() {
        let db = ProbeDb::parse("Probe TCP NULL q||\nmatch http m|^HTTP|is p/x/\n");
        let m = &db.null_probe.as_ref().unwrap().matches[0];
        assert!(m.ignorecase);
        assert!(m.dotall);
    }

    #[test]
    fn softmatch_flagged() {
        let db = ProbeDb::parse("Probe TCP NULL q||\nsoftmatch ftp m|^220|\n");
        let m = &db.null_probe.as_ref().unwrap().matches[0];
        assert!(m.soft);
        assert_eq!(m.service, "ftp");
    }

    #[test]
    fn cpe_body_keeps_prefix_and_multiple() {
        let line = "match x m|^y| cpe:/a:v:p/ cpe:/o:linux:linux_kernel/a";
        let db = ProbeDb::parse(&format!("Probe TCP NULL q||\n{line}\n"));
        let m = &db.null_probe.as_ref().unwrap().matches[0];
        assert_eq!(m.cpe, vec!["cpe:/a:v:p", "cpe:/o:linux:linux_kernel"]);
    }

    #[test]
    fn exclude_directive_before_probes() {
        let db = ProbeDb::parse("Exclude T:9100-9107\nProbe TCP NULL q||\n");
        assert!(db.excluded_seen);
        assert!(db.is_excluded(9100, Protocol::Tcp));
        assert!(db.is_excluded(9107, Protocol::Tcp));
        assert!(!db.is_excluded(9108, Protocol::Tcp));
        assert!(!db.is_excluded(9100, Protocol::Udp));
    }

    // ---- degrade-not-fatal divergence: these all `fatal()` in C ----

    #[test]
    fn bad_probe_line_skipped_not_fatal() {
        let db = ProbeDb::parse("Probe BOGUS Foo q|x|\nProbe TCP Good q|y|\n");
        assert_eq!(db.probes.len(), 1);
        assert_eq!(db.probes[0].name, "Good");
        assert_eq!(db.warnings.len(), 1);
        assert_eq!(db.warnings[0].line, 1);
    }

    #[test]
    fn bad_escape_skips_probe() {
        // `\q` is not a supported escape → C returns NULL → fatal. We skip.
        let db = ProbeDb::parse("Probe TCP Foo q|bad\\q|\nProbe TCP Ok q|z|\n");
        assert_eq!(db.probes.len(), 1);
        assert_eq!(db.probes[0].name, "Ok");
        assert!(db.warnings.iter().any(|w| w.line == 1));
    }

    #[test]
    fn out_of_range_rarity_keeps_default() {
        let db = ProbeDb::parse("Probe TCP Foo q|x|\nrarity 42\n");
        assert_eq!(db.probes[0].rarity, DEFAULT_RARITY);
        assert!(db.warnings.iter().any(|w| w.message.contains("rarity")));
    }

    #[test]
    fn out_of_range_waitms_keeps_default() {
        let db = ProbeDb::parse("Probe TCP Foo q|x|\ntotalwaitms 99\ntcpwrappedms 999999\n");
        assert_eq!(db.probes[0].totalwaitms, DEFAULT_TOTALWAITMS);
        assert_eq!(db.probes[0].tcpwrappedms, DEFAULT_TCPWRAPPEDMS);
        assert_eq!(db.warnings.len(), 2);
    }

    #[test]
    fn duplicate_exclude_ignored() {
        let db = ProbeDb::parse("Exclude T:1\nExclude T:2\nProbe TCP NULL q||\n");
        assert!(db.is_excluded(1, Protocol::Tcp));
        assert!(!db.is_excluded(2, Protocol::Tcp));
        assert!(db
            .warnings
            .iter()
            .any(|w| w.message.contains("duplicate Exclude")));
    }

    #[test]
    fn exclude_after_probe_ignored() {
        let db = ProbeDb::parse("Probe TCP NULL q||\nExclude T:1\n");
        assert!(!db.excluded_seen);
        assert!(db.warnings.iter().any(|w| w.message.contains("Exclude")));
    }

    #[test]
    fn unknown_directive_skipped() {
        let db = ProbeDb::parse("Probe TCP Foo q|x|\nfrobnicate 1\nrarity 3\n");
        assert_eq!(db.probes[0].rarity, 3);
        assert!(db
            .warnings
            .iter()
            .any(|w| w.message.contains("unknown directive")));
    }

    #[test]
    fn directive_before_probe_skipped() {
        let db = ProbeDb::parse("rarity 3\nProbe TCP Foo q|x|\n");
        assert_eq!(db.probes.len(), 1);
        assert!(db.warnings.iter().any(|w| w.line == 1));
    }

    #[test]
    fn empty_and_comment_lines_ignored() {
        let db = ProbeDb::parse("# comment\n\n# another\nProbe TCP Foo q|x|\n\n");
        assert_eq!(db.probes.len(), 1);
        assert!(db.warnings.is_empty());
    }

    #[test]
    fn totally_empty_input() {
        let db = ProbeDb::parse("");
        assert!(db.null_probe.is_none());
        assert!(db.probes.is_empty());
        assert!(db.warnings.is_empty());
    }

    #[test]
    fn multibyte_delimiter_does_not_panic() {
        // Regression `probedb-multibyte-delim`: a match line whose template
        // delimiter (or the char after flags) is a multi-byte UTF-8 code point
        // used to panic the byte-index slicing in `next_template`. It must now
        // degrade to a skipped line with a warning, never abort.
        for line in [
            "match svc \u{20ac}foo\u{20ac} p/z/\n", // '€' as delimiter
            "match svc m|x|\u{20ac} p/z/\n",        // multi-byte after flags
            "match svc \u{1f600}a\u{1f600}\n",      // 4-byte emoji delimiter
        ] {
            let db = ProbeDb::parse(&format!("Probe TCP X q|y|\n{line}"));
            // Parsed to completion; the bad match line was skipped, not panicked.
            assert!(db.probes.iter().any(|p| p.name == "X"));
        }
    }

    #[test]
    fn ascii_delimiter_still_parses_after_fix() {
        // The multi-byte fix must not regress ordinary ASCII-delimited templates.
        let db =
            ProbeDb::parse("Probe TCP NULL q||\nmatch ssh m|^SSH-([\\d.]+)| p/OpenSSH/ v/$1/\n");
        let m = &db.null_probe.as_ref().unwrap().matches[0];
        assert_eq!(m.service, "ssh");
        assert_eq!(m.pattern, "^SSH-([\\d.]+)");
        assert_eq!(m.product.as_deref(), Some("OpenSSH"));
    }

    #[test]
    fn strtol_prefix_semantics() {
        assert_eq!(strtol_prefix("6000"), Some(6000));
        assert_eq!(strtol_prefix("6000 # comment"), Some(6000));
        assert_eq!(strtol_prefix("-5"), Some(-5));
        assert_eq!(strtol_prefix("abc"), None);
        assert_eq!(strtol_prefix(""), None);
    }
}
