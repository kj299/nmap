//! Run configuration parsed from the command line — the growing Rust analog of
//! nmap's global `NmapOps` (`o`). Pulled forward (before the scan modules) so
//! **verbosity/debugging** is available for troubleshooting from the first
//! module onward.
//!
//! Milestone 1 wires the subset needed now: `-v`/`-d` verbosity, `--version`,
//! `-h`/`--help`, and positional target expressions. The full option surface
//! (scan types, `-p`, `-oN/-oX`, timing, …) fills in as the `cli` module lands.
//!
//! Parsing is pure and total (never panics), so it is unit-testable without a
//! process; the thin `cli` binary calls [`parse_args`] then
//! [`crate::log::init`].

use crate::timing::{TimingParams, TimingTemplate};

/// nmap clamps verbosity/debugging to `box(0, 10, …)`.
const MAX_LEVEL: u8 = 10;

/// Parsed command-line configuration. Grows toward the full `NmapOps` surface.
/// Which scan technique to run. `-sT` connect (unprivileged, the default) or the
/// privileged raw scans `-sS` (SYN) / `-sU` (UDP), which fall back to connect when
/// the process lacks raw-socket capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ScanKind {
    /// `-sT`: unprivileged TCP connect scan.
    #[default]
    Connect,
    /// `-sS`: raw TCP SYN (half-open) scan.
    Syn,
    /// `-sU`: UDP scan.
    Udp,
    /// `-sA`: TCP ACK scan (firewall-rule mapping).
    Ack,
    /// `-sW`: TCP Window scan.
    Window,
    /// `-sM`: TCP Maimon scan.
    Maimon,
    /// `-sF`: TCP FIN scan.
    Fin,
    /// `-sN`: TCP Null scan.
    Null,
    /// `-sX`: TCP Xmas scan.
    Xmas,
    /// `-sL`: list scan — expand the targets, print them, send nothing.
    ///
    /// C sets `listscan`, `noportscan` **and** `PINGTYPE_NONE` (`nmap.cc:1307`),
    /// so it is the one scan type that puts no packet on the wire. That is what
    /// makes it the dry run: an operator can ask "what would you scan?" without
    /// touching anything.
    List,
}

// No `Eq`: `min_rate`/`max_rate` are `f64` (only `PartialEq`). Equality is used
// solely by tests via `assert_eq!`, which needs only `PartialEq`.
#[derive(Clone, Debug, PartialEq)]
pub struct RunConfig {
    /// Scan technique (`-sT`/`-sS`/`-sU`); defaults to connect.
    pub scan: ScanKind,
    /// Verbosity level (nmap `o.verbose`, 0..=10).
    pub verbose: u8,
    /// Debugging level (nmap `o.debugging`, 0..=10).
    pub debugging: u8,
    /// `--version` was requested.
    pub show_version: bool,
    /// `-h` / `--help` was requested.
    pub show_help: bool,
    /// Positional target expressions, in order (parsed by `core::targets`).
    pub targets: Vec<String>,
    /// `-p` port specification (parsed by `core::ports`); `None` ⇒ default ports.
    pub port_spec: Option<String>,
    /// `-6`: treat targets as IPv6.
    pub ipv6: bool,
    /// `-Pn`: skip host discovery (treat every target as up).
    pub assume_up: bool,
    /// `-sV`: probe open ports to determine service/version info.
    pub service_version: bool,
    /// `-O`: attempt OS detection via the fingerprint probe battery.
    pub os_detection: bool,
    /// `--osscan-guess` / `--fuzzy`: report near matches when nothing matches exactly.
    pub osscan_guess: bool,
    /// `--osscan-limit`: only fingerprint hosts with at least one open and one closed
    /// TCP port, where the result stands a chance of being meaningful.
    pub osscan_limit: bool,
    /// `--max-os-tries N`: how many OS-detection rounds to attempt per host before
    /// giving up. `None` leaves the driver's default (nmap's `MAX_OS_TRIES`).
    pub max_os_tries: Option<usize>,
    /// `--version-intensity <0..=9>` (default 7). `--version-light` = 2,
    /// `--version-all` = 9. Only meaningful when [`RunConfig::service_version`].
    pub version_intensity: u8,
    /// `-oN <file>` normal output destination (`"-"` = stdout).
    pub out_normal: Option<String>,
    /// `-oX <file>` XML output destination (`"-"` = stdout).
    pub out_xml: Option<String>,
    /// `-oG <file>` grepable output destination (`"-"` = stdout).
    pub out_grep: Option<String>,
    /// `--min-rate <n>`: floor on probes/sec (`None` ⇒ unset).
    pub min_rate: Option<f64>,
    /// `--max-rate <n>`: ceiling on probes/sec (`None` ⇒ unset).
    pub max_rate: Option<f64>,
    /// `--exclude <spec[,spec...]>`: hosts to leave out, as given. Parsed by
    /// `targets::exclude_specs`; combined with [`RunConfig::exclude_file`]
    /// exactly as C loads both into one `exclude_group`.
    pub exclude: Option<String>,
    /// `--excludefile <file>`: a list file of hosts to leave out.
    pub exclude_file: Option<String>,
    /// `-iL <file>`: read target specs from a file (`-` = stdin). C allows one
    /// only (`fatal("Only one input filename allowed")`), so a second is
    /// recorded as a conflict rather than silently replacing the first.
    pub input_file: Option<String>,
    /// `-iL` given more than once — refused, matching C.
    pub input_file_repeated: bool,
    /// `--ttl N`: IP time-to-live for raw probes. C: `atoi`, then
    /// `fatal` unless 0..=255, so an out-of-range value is a refusal here too.
    pub ttl: Option<u8>,
    /// `--badsum`: send a deliberately wrong L4 checksum.
    pub bad_sum: bool,
    /// `-S <addr>`: claim this source address on raw probes, as given.
    pub spoof_source: Option<String>,
    /// `-S` given more than once — refused, matching C's
    /// `fatal("You can only use the source option once!")`.
    pub spoof_source_repeated: bool,
    /// An option that only affects raw packets was given (`--ttl`, `--badsum`,
    /// `-S`). C tracks the same thing as `delayed_options.raw_scan_options` so it
    /// can tell the operator when the chosen scan cannot honour them.
    pub raw_scan_options: bool,
    /// `--top-ports N` / `--port-ratio X`: nmap keeps both in ONE field,
    /// `o.topportlevel`, so the last of the two on the command line wins and
    /// there is no way to combine them. A value `>= 1` is a count, a value in
    /// `(0, 1)` is a minimum open-frequency ratio. `None` is C's `-1` sentinel,
    /// meaning "no explicit level": the default 1000, or 100 under `-F`.
    pub top_port_level: Option<f64>,
    /// `-F`: fast scan — the top 100 ports. Empirically identical to
    /// `--top-ports 100` (`services.cc:421` sets `level = 100`).
    pub fast_scan: bool,
    /// `--exclude-ports <spec>`: ports to drop from the list, as given.
    pub exclude_ports: Option<String>,
    /// `--exclude-ports` given more than once — refused, matching C's
    /// `fatal("Only 1 --exclude-ports option allowed, …")`.
    pub exclude_ports_repeated: bool,
    /// `--allports`: version-scan every open port, including the ones
    /// `nmap-service-probes` names in its `Exclude` directive.
    ///
    /// C's flag is `override_excludeports`, and it is read only by the service
    /// scanner (`service_scan.cc:1447`, `:2813`) — it has nothing to do with
    /// `--exclude-ports`, which narrows the *port list*. The constraint it
    /// cancels is the probe file's own: `Exclude T:9100-9107`, the JetDirect
    /// printer ports, where sending version probes makes printers print.
    pub allports: bool,
    /// `-T<0-5>` or `-T<name>`: the timing template. `None` ⇒ `-T3` (Normal),
    /// nmap's default.
    pub timing_template: Option<TimingTemplate>,
    /// `--min-rtt-timeout` / `--max-rtt-timeout` / `--initial-rtt-timeout`, in
    /// milliseconds. `None` ⇒ leave whatever the template chose.
    pub min_rtt_timeout_ms: Option<i64>,
    pub max_rtt_timeout_ms: Option<i64>,
    pub initial_rtt_timeout_ms: Option<i64>,
    /// `--scan-delay` / `--max-scan-delay`, in milliseconds.
    pub scan_delay_ms: Option<i64>,
    pub max_scan_delay_ms: Option<i64>,
    /// `--host-timeout`, in milliseconds. `0` is C's explicit "no timeout", and
    /// it overrides a template that set one — which is why this is an
    /// `Option<i64>` and not an `i64` defaulting to 0.
    pub host_timeout_ms: Option<i64>,
    /// `--max-retries`: cap on probe retransmissions.
    pub max_retries: Option<u32>,
    /// `--min-parallelism` / `--max-parallelism` (also spelled `-M`).
    pub min_parallelism: Option<u32>,
    pub max_parallelism: Option<u32>,
    /// `--min-hostgroup` / `--max-hostgroup`.
    pub min_hostgroup: Option<u32>,
    pub max_hostgroup: Option<u32>,
    /// Options we recognize but whose argument is unusable. Distinct from
    /// [`RunConfig::unrecognized`] because the two need different messages: one
    /// is "I do not know this option", the other is "I know it and your value
    /// is wrong". C `fatal()`s on each of these, and so does the CLI.
    pub invalid: Vec<String>,
    /// Non-fatal complaints — C's `error()` calls, which print and continue.
    pub warnings: Vec<String>,
    /// Flags we do not yet recognize — recorded, never silently dropped, so the
    /// CLI can warn instead of misparsing them.
    pub unrecognized: Vec<String>,
}

impl RunConfig {
    /// Resolve `-T` and the explicit timing knobs into one set of parameters.
    ///
    /// The order is nmap's, from the block at `nmap.cc:1472-1500` that runs
    /// *after* the whole argument loop, under the comment "After the arguments
    /// are fully processed we now make any of the timing tweaks the user
    /// might've specified". Two consequences fall out of that, and both are
    /// observable:
    ///
    /// 1. **An explicit knob always beats `-T`, whichever came first on the
    ///    command line.** `-T4 --scan-delay 5` and `--scan-delay 5 -T4` are the
    ///    same scan. Applying them in argv order instead would make the second
    ///    form silently discard the operator's delay.
    /// 2. **The RTT setters run in the order initial, min, max** — and each one
    ///    drags its siblings (see [`TimingParams`]), so reordering them changes
    ///    the result. `--min-rtt-timeout 900 --max-rtt-timeout 100` ends at
    ///    min=100, max=100 because max runs last and pulls min down with it.
    pub fn timing_params(&self) -> TimingParams {
        let mut p =
            TimingParams::for_template(self.timing_template.unwrap_or(TimingTemplate::Normal));

        if let Some(v) = self.max_parallelism {
            p.max_parallelism = v;
        }
        if let Some(v) = self.min_parallelism {
            p.min_parallelism = v;
        }
        if let Some(v) = self.scan_delay_ms {
            p.scan_delay_ms = v;
            // A delay longer than the ceiling would be clamped away, so C
            // raises the ceiling to match rather than quietly ignoring the
            // operator's delay.
            p.max_tcp_scan_delay_ms = p.max_tcp_scan_delay_ms.max(v);
            p.max_udp_scan_delay_ms = p.max_udp_scan_delay_ms.max(v);
            p.max_sctp_scan_delay_ms = p.max_sctp_scan_delay_ms.max(v);
        }
        if let Some(v) = self.max_scan_delay_ms {
            p.max_tcp_scan_delay_ms = v;
            p.max_udp_scan_delay_ms = v;
            p.max_sctp_scan_delay_ms = v;
        }
        // Initial, then min, then max — C's order, which is not interchangeable.
        if let Some(v) = self.initial_rtt_timeout_ms {
            p.set_initial_rtt(v);
        }
        if let Some(v) = self.min_rtt_timeout_ms {
            p.set_min_rtt(v);
        }
        if let Some(v) = self.max_rtt_timeout_ms {
            p.set_max_rtt(v);
        }
        if let Some(v) = self.max_retries {
            p.max_retransmissions = v;
        }
        if let Some(v) = self.host_timeout_ms {
            p.host_timeout_ms = v;
        }
        if let Some(v) = self.min_hostgroup {
            p.min_hostgroup = v;
        }
        if let Some(v) = self.max_hostgroup {
            p.max_hostgroup = v;
        }
        p
    }

    /// Complaints that are not refusals: C's `error()` calls, which print and
    /// carry on. The two that can only be known after the whole command line is
    /// read live here rather than in the parse loop.
    pub fn timing_warnings(&self) -> Vec<String> {
        let mut out = self.warnings.clone();
        // nmap.cc:1483 — the pacing options do not compose, and C says so
        // rather than silently letting one win.
        if self.scan_delay_ms.is_some()
            && (self.max_parallelism.is_some() || self.min_parallelism.is_some())
        {
            out.push(
                "Warning: --min-parallelism and --max-parallelism are ignored with --scan-delay."
                    .to_string(),
            );
        }
        out
    }

    /// `--min-hostgroup` may not exceed `--max-hostgroup`, and the maximum may
    /// not be zero. C enforces both inside the setters, where the check is
    /// against whatever the *other* value happens to be at the time; here the
    /// whole command line is known, so the comparison is against the final
    /// pair.
    pub fn hostgroup_error(&self) -> Option<String> {
        let p = self.timing_params();
        if p.max_hostgroup == 0 {
            return Some("Max host size must be at least 1".to_string());
        }
        if p.min_hostgroup > p.max_hostgroup {
            return Some(format!(
                "Minimum host group size may not be set to greater than maximum size (currently {})",
                p.max_hostgroup
            ));
        }
        None
    }
}

impl Default for RunConfig {
    fn default() -> RunConfig {
        RunConfig {
            scan: ScanKind::Connect,
            verbose: 0,
            debugging: 0,
            show_version: false,
            show_help: false,
            targets: Vec::new(),
            port_spec: None,
            ipv6: false,
            assume_up: false,
            service_version: false,
            os_detection: false,
            osscan_guess: false,
            osscan_limit: false,
            max_os_tries: None,
            // nmap's default `--version-intensity` (`o.version_intensity = 7`).
            version_intensity: crate::servicescan::DEFAULT_INTENSITY,
            out_normal: None,
            out_xml: None,
            out_grep: None,
            min_rate: None,
            max_rate: None,
            ttl: None,
            bad_sum: false,
            spoof_source: None,
            spoof_source_repeated: false,
            raw_scan_options: false,
            exclude: None,
            exclude_file: None,
            input_file: None,
            input_file_repeated: false,
            top_port_level: None,
            fast_scan: false,
            exclude_ports: None,
            exclude_ports_repeated: false,
            allports: false,
            timing_template: None,
            min_rtt_timeout_ms: None,
            max_rtt_timeout_ms: None,
            initial_rtt_timeout_ms: None,
            scan_delay_ms: None,
            max_scan_delay_ms: None,
            host_timeout_ms: None,
            max_retries: None,
            min_parallelism: None,
            max_parallelism: None,
            min_hostgroup: None,
            max_hostgroup: None,
            invalid: Vec::new(),
            warnings: Vec::new(),
            unrecognized: Vec::new(),
        }
    }
}

/// Options accepted as no-ops because this port's *unconditional* behaviour
/// already satisfies them.
///
/// This is deliberately not a list of "flags it seems safe to ignore". The CLI
/// otherwise refuses anything it does not implement, because ignoring an option
/// that constrains a scan makes the scan broader than the operator asked for
/// (see `cli-fails-closed-on-unsupported-options` in `DIVERGENCES.md`). The
/// only sound exception is an option that asks for behaviour the port already
/// has with no way to turn it off — accepting one of those changes nothing, and
/// refusing it would reject a command whose intent is already honoured.
///
/// Each entry carries the reason it qualifies, and the reason has to be a
/// property of the code, checkable today — not an intention. An option whose
/// *opposite* would change behaviour does NOT belong here: `-n` qualifies
/// because no reverse lookup exists to suppress, while `-R` (always resolve)
/// does not, because this port cannot do what it asks.
///
/// Two of these qualify for a second reason worth stating separately: the C
/// itself does nothing with them. `--release-memory` and `--log-errors` are
/// no-ops in `nmap.cc`, kept only so existing scan scripts keep working. So
/// accepting them here is not a concession — it is exact parity, and refusing
/// them would have this port reject a command C nmap accepts and ignores.
const ALREADY_SATISFIED: &[(&str, &str)] = &[
    (
        "-n",
        "never do reverse DNS: this port performs no reverse lookup anywhere. \
         `Host::hostname` is only ever set from the user's own target expression \
         (see the CLI's target resolution), so there is nothing for -n to disable.",
    ),
    (
        "-r",
        "scan ports sequentially, do not randomise: this port never randomises \
         port order. Ports are emitted by `ports::parse_port_spec` in ascending \
         order and sorted by `(protocol, number)` before reporting \
         (`sys::scan` and `sys::group`), which `sys::scan`'s own test asserts. \
         There is no randomisation to turn off.",
    ),
    (
        "--release-memory",
        "release memory before exiting: a no-op in C nmap too — `nmap.cc` \
         handles it with the comment `/* No-op. We always release memory now. */`. \
         Accepting it is parity with the reference, not a concession.",
    ),
    (
        "--no-stylesheet",
        "do not reference an XSL stylesheet from the XML output: this port never \
         emits one. `output::xml` writes the XML declaration and goes straight to \
         `<nmaprun>` (see `output.rs`), with no `<?xml-stylesheet?>` processing \
         instruction anywhere — so there is nothing to suppress. Its opposites, \
         `--stylesheet` and `--webxml`, stay refused: this port cannot emit the \
         reference they ask for.",
    ),
    (
        "--log-errors",
        "log errors to the normal output file: deprecated and always-on in C nmap, \
         whose handler says it is `left in so as to not break anybody's scanning \
         scripts`. This port likewise writes errors unconditionally, so there is \
         nothing to enable.",
    ),
];

/// Parse a `--min-rate`/`--max-rate` value: a positive, finite probes-per-second
/// number. Anything else (empty, non-numeric, `<= 0`, NaN) is rejected as `None`
/// rather than silently treated as a rate.
fn parse_rate(s: &str) -> Option<f64> {
    match s.trim().parse::<f64>() {
        Ok(r) if r.is_finite() && r > 0.0 => Some(r),
        _ => None,
    }
}

/// Increment a level toward the 0..=10 ceiling (nmap's `if (x < 10) x++`).
fn bump(level: u8) -> u8 {
    level.saturating_add(1).min(MAX_LEVEL)
}

/// If `rest` begins with a digit, parse its leading decimal run (atoi-style,
/// trailing junk ignored — matching nmap's `isdigit(optarg[0])` + `atoi`) and
/// clamp to 0..=10. Otherwise `None`.
fn leading_level(rest: &str) -> Option<u8> {
    let bytes = rest.as_bytes();
    let first = *bytes.first()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let mut n: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            break;
        }
        // Widen before subtracting so the op can't underflow a u8.
        n = n
            .saturating_mul(10)
            .saturating_add(u32::from(b).saturating_sub(u32::from(b'0')));
    }
    Some(u8::try_from(n.min(u32::from(MAX_LEVEL))).unwrap_or(MAX_LEVEL))
}

/// Parse a `--version-intensity` value: leading decimal digits, clamped to the
/// nmap-legal `0..=9`. `None` if it does not start with a digit.
fn leading_int_0_9(s: &str) -> Option<u8> {
    let first = *s.as_bytes().first()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let mut n: u32 = 0;
    for &b in s.as_bytes() {
        if !b.is_ascii_digit() {
            break;
        }
        n = n
            .saturating_mul(10)
            .saturating_add(u32::from(b).saturating_sub(u32::from(b'0')));
    }
    Some(u8::try_from(n.min(9)).unwrap_or(9))
}

/// Apply a `-v…` argument (the part after `-v`). `-vN` sets the level; `-v`,
/// `-vv`, `-vvv` increment once per `v` (plus one for the `-v` itself).
fn apply_v(cfg: &mut RunConfig, rest: &str) {
    if let Some(level) = leading_level(rest) {
        cfg.verbose = level;
    } else if rest.bytes().all(|b| b == b'v') {
        cfg.verbose = bump(cfg.verbose);
        for _ in rest.bytes() {
            cfg.verbose = bump(cfg.verbose);
        }
    } else {
        cfg.unrecognized.push(format!("-v{rest}"));
    }
}

/// Apply a `-d…` argument. Like `-v`, but nmap bumps/sets **both** debugging
/// and verbose (`o.debugging = o.verbose = box(0,10,i)`).
fn apply_d(cfg: &mut RunConfig, rest: &str) {
    if let Some(level) = leading_level(rest) {
        cfg.debugging = level;
        cfg.verbose = level;
    } else if rest.bytes().all(|b| b == b'd') {
        cfg.debugging = bump(cfg.debugging);
        cfg.verbose = bump(cfg.verbose);
        for _ in rest.bytes() {
            cfg.debugging = bump(cfg.debugging);
            cfg.verbose = bump(cfg.verbose);
        }
    } else {
        cfg.unrecognized.push(format!("-d{rest}"));
    }
}

/// The value for an option that takes an argument, supporting both the attached
/// (`-p22`, `-oXfile`) and separate (`-p 22`, `-oX file`) forms. Returns the
/// value and how many *extra* argv entries were consumed (0 or 1).
fn opt_value(args: &[String], i: usize, prefix: &str) -> (String, usize) {
    let s = &args[i];
    if s.len() > prefix.len() {
        (s[prefix.len()..].to_string(), 0) // attached
    } else if let Some(next) = args.get(i.saturating_add(1)) {
        (next.clone(), 1) // separate
    } else {
        (String::new(), 0) // missing value — treated as empty
    }
}

/// Does `arg` name the long option `name`, in any spelling `getopt_long_only`
/// accepts? That is one dash or two, with the value attached after `=` or given
/// as the next argument: `--exclude`, `-exclude`, `--exclude=h`, `-exclude=h`.
///
/// Returns the prefix actually used, so [`long_opt_value`] slices the right
/// number of bytes off the attached form.
fn long_flag<'a>(arg: &str, name: &str, buf: &'a mut String) -> Option<&'a str> {
    for dashes in ["--", "-"] {
        buf.clear();
        buf.push_str(dashes);
        buf.push_str(name);
        if arg == buf
            || arg
                .strip_prefix(buf.as_str())
                .is_some_and(|r| r.starts_with('='))
        {
            return Some(buf.as_str());
        }
    }
    None
}

/// Value of a **long** option, which `getopt_long_only` accepts in four forms:
/// `--name value`, `--name=value`, `-name value` and `-name=value`.
///
/// [`opt_value`] slices straight after the prefix, which is right for a short
/// option's attached form (`-oNfile`) but leaves the `=` on `--exclude=host`.
/// Stripping it here and not there matters: `-p=80` is a *short* option in C's
/// getopt string, so its value really is `=80`, and stripping globally would
/// silently change what `-p=80` scans. Only the attached form is touched — in
/// the separate form a leading `=` is part of the operand.
fn long_opt_value(args: &[String], i: usize, prefix: &str) -> (String, usize) {
    let (v, adv) = opt_value(args, i, prefix);
    if adv == 0 {
        (v.strip_prefix('=').unwrap_or(&v).to_string(), adv)
    } else {
        (v, adv)
    }
}

/// C's `%g` with the default precision of 6 significant digits.
///
/// Reproduced because an operator who hits one of the messages that uses it
/// will be searching for C's exact wording, numbers included — the "since April
/// 2010" time guards and the two `gettoppts` refusals both print a `double`
/// this way.
// `exp` comes from log10 of a finite non-zero magnitude, so it is within
// [-308, 308] and `5 - exp` cannot overflow.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
pub fn g6(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    let exp = v.abs().log10().floor() as i32;
    let s = if (-4..6).contains(&exp) {
        let decimals = usize::try_from(5 - exp).unwrap_or(0);
        format!("{v:.decimals$}")
    } else {
        format!("{v:.5e}")
    };
    if s.contains('.') && !s.contains('e') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// How C phrases the "since April 2010" guard for a given option. Each of the
/// four shapes below is a distinct `fatal()` string in `nmap.cc`, differing in
/// the unit it converts to and in the fix it suggests, so one generic message
/// would be wrong for three of them.
#[derive(Clone, Copy)]
enum GuardPhrasing {
    /// `--min/max/initial-rtt-timeout`: "... is N seconds. Use "Nms" for N milliseconds."
    SecondsUseMs,
    /// `--scan-delay`: "... is N minutes. Use "Nms" for N milliseconds."
    MinutesUseMs,
    /// `--max-scan-delay`: "... is N minutes. If this is what you want, use "Ns"."
    MinutesUseS,
    /// `--host-timeout`: "... is N hours. If this is what you want, use "Ns"."
    HoursUseS,
}

impl GuardPhrasing {
    fn message(self, name: &str, raw: &str, ms: i64) -> String {
        #[allow(clippy::cast_precision_loss)]
        let secs = ms as f64 / 1000.0;
        let head = format!(
            "Since April 2010, the default unit for {name} is seconds, so your time of \"{raw}\" is"
        );
        match self {
            GuardPhrasing::SecondsUseMs => format!(
                "{head} {} seconds. Use \"{raw}ms\" for {} milliseconds.",
                g6(secs),
                g6(secs)
            ),
            GuardPhrasing::MinutesUseMs => format!(
                "{head} {:.1} minutes. Use \"{raw}ms\" for {} milliseconds.",
                secs / 60.0,
                g6(secs)
            ),
            GuardPhrasing::MinutesUseS => format!(
                "{head} {:.1} minutes. If this is what you want, use \"{raw}s\".",
                secs / 60.0
            ),
            GuardPhrasing::HoursUseS => format!(
                "{head} {:.1} hours. If this is what you want, use \"{raw}s\".",
                secs / 60.0 / 60.0
            ),
        }
    }
}

/// One `tval2msecs`-backed timing option, with the two checks C wraps around
/// every one of them.
///
/// The order is C's and it is load-bearing: the floor check runs first, so an
/// unparseable value (which `tval2msecs` reports and C represents as `-1`)
/// trips the floor and produces the floor's message, not a separate "cannot
/// parse" one. `--max-rtt-timeout zzz` says "must be at least 5ms" in C, and
/// says it here too.
///
/// The second check is the "since April 2010" footgun guard. A bare number this
/// large is almost certainly an operator who meant milliseconds, so C refuses
/// it — but the *same value with an explicit unit* is honoured, which is the
/// only reason [`crate::timespec::tval_unit`] exists.
fn time_option(
    cfg: &mut RunConfig,
    name: &str,
    raw: &str,
    floor: i64,
    floor_msg: &str,
    guard_ms: i64,
    phrasing: GuardPhrasing,
) -> Option<i64> {
    let ms = crate::timespec::tval2msecs(raw).unwrap_or(-1);
    if ms < floor {
        cfg.invalid.push(floor_msg.to_string());
        return None;
    }
    if ms >= guard_ms && crate::timespec::tval_unit(raw).is_none() {
        cfg.invalid.push(phrasing.message(name, raw, ms));
        return None;
    }
    Some(ms)
}

/// C's `atoi` for a count option: a leading integer, or 0 when there is no
/// leading integer at all. `atoi` does not report failure, so `--max-retries
/// banana` is zero retries in C rather than an error, and the bound checks that
/// follow are the only validation there is.
// The only arithmetic is negating a non-negative `i64` that came from parsing
// digits, which saturates at `i64::MAX` and so cannot overflow on negation.
#[allow(clippy::arithmetic_side_effects)]
fn atoi(raw: &str) -> i64 {
    let t = raw.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, t) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
    let v: i64 = digits
        .parse()
        .unwrap_or(if digits.is_empty() { 0 } else { i64::MAX });
    if neg {
        -v
    } else {
        v
    }
}

/// `-T`: the timing template.
///
/// C accepts a digit `0`-`5` by looking at the **first character only**, so
/// `-T4abc` is Aggressive there, and it has an easter egg: `-T11` prints a
/// message and silently means `-T5` (Insane). That last one is a trap — it
/// turns a typo of `-T1`, the second most cautious template, into the most
/// aggressive one — and reaching it in C also reads past the end of a stack
/// array. This port accepts exactly the digits `0`-`5` and the six names, and
/// refuses everything else. See `DIVERGENCES.md`.
fn parse_timing_template(cfg: &mut RunConfig, raw: &str) {
    let t = TimingTemplate::from_name(raw).or_else(|| {
        let mut chars = raw.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => c
                .to_digit(10)
                .and_then(|d| u8::try_from(d).ok().and_then(TimingTemplate::from_level)),
            _ => None,
        }
    });
    match t {
        Some(t) => cfg.timing_template = Some(t),
        None => cfg.invalid.push(format!(
            "Unknown timing mode (-T argument \"{raw}\").  Use either \"Paranoid\", \"Sneaky\", \"Polite\", \"Normal\", \"Aggressive\", \"Insane\" or a number from 0 (Paranoid) to 5 (Insane)"
        )),
    }
}

/// Parse argv (without the program name) into a [`RunConfig`]. Total and
/// panic-free over any input.
// Index arithmetic is bounded by `args.len()` and only ever advances.
#[allow(clippy::arithmetic_side_effects)]
pub fn parse_args(args: &[String]) -> RunConfig {
    let mut cfg = RunConfig::default();
    let mut keybuf = String::new();
    let mut keybuf2 = String::new();
    let mut i = 0;
    while i < args.len() {
        let s = args[i].as_str();
        let mut consumed_extra = 0;
        match s {
            "--version" => cfg.show_version = true,
            "-h" | "--help" => cfg.show_help = true,
            "--verbose" => cfg.verbose = bump(cfg.verbose),
            "--debug" => {
                cfg.debugging = bump(cfg.debugging);
                cfg.verbose = bump(cfg.verbose);
            }
            "-6" => cfg.ipv6 = true,
            "-Pn" => cfg.assume_up = true,
            // Accepted as a no-op: see ALREADY_SATISFIED.
            _ if ALREADY_SATISFIED.iter().any(|(opt, _)| *opt == s) => {}
            "-sT" => cfg.scan = ScanKind::Connect,
            "-sS" => cfg.scan = ScanKind::Syn,
            "-sU" => cfg.scan = ScanKind::Udp,
            "-sA" => cfg.scan = ScanKind::Ack,
            "-sW" => cfg.scan = ScanKind::Window,
            "-sM" => cfg.scan = ScanKind::Maimon,
            "-sF" => cfg.scan = ScanKind::Fin,
            "-sN" => cfg.scan = ScanKind::Null,
            "-sX" => cfg.scan = ScanKind::Xmas,
            "-sL" => cfg.scan = ScanKind::List,
            // `--allports` takes no argument. It only widens what `-sV`
            // probes; see the field docs for why it is not related to
            // `--exclude-ports` despite the name.
            _ if long_flag(s, "allports", &mut keybuf).is_some() => cfg.allports = true,
            // ---- port selection (M7.8) ----------------------------------
            // `-F`: fast scan. C sets `o.fastscan`, which `gettoppts` turns
            // into `level = 100` when no explicit level was given.
            "-F" => cfg.fast_scan = true,
            // `--top-ports` and `--port-ratio` write the SAME field in C
            // (`o.topportlevel`), so the last one wins. Mirrored exactly: two
            // separate fields would let both apply and silently invent a
            // combination nmap has no way to express.
            _ if long_flag(s, "top-ports", &mut keybuf).is_some() => {
                let key = long_flag(s, "top-ports", &mut keybuf2).unwrap_or("--top-ports");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                // C: `strtod`, then reject anything below 1 or non-integral.
                // The tail is ignored, so `--top-ports 5abc` is five and
                // `--top-ports 0x10` is sixteen -- both confirmed against the
                // reference, both a consequence of using strtod at all.
                let level = crate::timespec::strtod_value(&v);
                if !level.is_finite() || level < 1.0 || level.trunc() != level {
                    cfg.invalid
                        .push("--top-ports should be an integer 1 or greater".to_string());
                } else {
                    cfg.top_port_level = Some(level);
                }
            }
            _ if long_flag(s, "port-ratio", &mut keybuf).is_some() => {
                let key = long_flag(s, "port-ratio", &mut keybuf2).unwrap_or("--port-ratio");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                let level = crate::timespec::strtod_value(&v);
                // C's range test is `< 0 || >= 1`, so zero passes HERE and is
                // caught later by gettoppts ("should be a positive ratio below
                // 1"). Both messages are reproduced, at the same two points.
                // C's test is `< 0 || >= 1`, i.e. the half-open range [0, 1).
                if !level.is_finite() || !(0.0..1.0).contains(&level) {
                    cfg.invalid
                        .push("--port-ratio should be between [0 and 1)".to_string());
                } else {
                    cfg.top_port_level = Some(level);
                }
            }
            _ if long_flag(s, "exclude-ports", &mut keybuf).is_some() => {
                let key = long_flag(s, "exclude-ports", &mut keybuf2).unwrap_or("--exclude-ports");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                if cfg.exclude_ports.is_some() {
                    cfg.exclude_ports_repeated = true;
                } else {
                    cfg.exclude_ports = Some(v);
                }
            }

            // ---- the -T group (M7.7) ------------------------------------
            // `-T` takes a required argument, so `-T4` and `-T 4` both parse;
            // `opt_value` handles the attached and separate spellings alike.
            _ if s == "-T" || s.starts_with("-T") => {
                let (v, adv) = opt_value(args, i, "-T");
                consumed_extra = adv;
                parse_timing_template(&mut cfg, &v);
            }
            // `--max-rtt-timeout` before `--max-retries`? No: they share no
            // prefix. But `--max-scan-delay` and `--max-retries` do not either,
            // so these may be ordered freely — unlike --excludefile/--exclude.
            _ if long_flag(s, "max-rtt-timeout", &mut keybuf).is_some() => {
                let key =
                    long_flag(s, "max-rtt-timeout", &mut keybuf2).unwrap_or("--max-rtt-timeout");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                // C checks `l < 5` BEFORE the unit guard, and warns below 20ms.
                cfg.max_rtt_timeout_ms = time_option(
                    &mut cfg,
                    "--max-rtt-timeout",
                    &v,
                    5,
                    "Bogus --max-rtt-timeout argument specified, must be at least 5ms",
                    50 * 1000,
                    GuardPhrasing::SecondsUseMs,
                );
                if let Some(ms) = cfg.max_rtt_timeout_ms {
                    if ms < 20 {
                        cfg.warnings.push(format!(
                            "WARNING: You specified a round-trip time timeout ({ms} ms) that is EXTRAORDINARILY SMALL.  Accuracy may suffer."
                        ));
                    }
                }
            }
            _ if long_flag(s, "min-rtt-timeout", &mut keybuf).is_some() => {
                let key =
                    long_flag(s, "min-rtt-timeout", &mut keybuf2).unwrap_or("--min-rtt-timeout");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                cfg.min_rtt_timeout_ms = time_option(
                    &mut cfg,
                    "--min-rtt-timeout",
                    &v,
                    0,
                    "Bogus --min-rtt-timeout argument specified",
                    50 * 1000,
                    GuardPhrasing::SecondsUseMs,
                );
            }
            _ if long_flag(s, "initial-rtt-timeout", &mut keybuf).is_some() => {
                let key = long_flag(s, "initial-rtt-timeout", &mut keybuf2)
                    .unwrap_or("--initial-rtt-timeout");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                // C's floor here is `l <= 0`, not `l < 0`: an initial RTT of
                // zero is refused where a minimum of zero is allowed.
                cfg.initial_rtt_timeout_ms = time_option(
                    &mut cfg,
                    "--initial-rtt-timeout",
                    &v,
                    1,
                    "Bogus --initial-rtt-timeout argument specified.  Must be positive",
                    50 * 1000,
                    GuardPhrasing::SecondsUseMs,
                );
            }
            // BEFORE `--scan-delay`: `--max-scan-delay` would otherwise never
            // match, because `long_flag(s, "scan-delay")` does not match it —
            // but the reverse ordering trap is the same shape as
            // --excludefile/--exclude, so keep the specific one first as a rule.
            _ if long_flag(s, "max-scan-delay", &mut keybuf).is_some() => {
                let key =
                    long_flag(s, "max-scan-delay", &mut keybuf2).unwrap_or("--max-scan-delay");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                cfg.max_scan_delay_ms = time_option(
                    &mut cfg,
                    "--max-scan-delay",
                    &v,
                    0,
                    "Bogus --max-scan-delay argument specified.",
                    100 * 1000,
                    GuardPhrasing::MinutesUseS,
                );
            }
            _ if long_flag(s, "scan-delay", &mut keybuf).is_some() => {
                let key = long_flag(s, "scan-delay", &mut keybuf2).unwrap_or("--scan-delay");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                cfg.scan_delay_ms = time_option(
                    &mut cfg,
                    "--scan-delay",
                    &v,
                    0,
                    "Bogus --scan-delay argument specified.",
                    100 * 1000,
                    GuardPhrasing::MinutesUseMs,
                );
            }
            _ if long_flag(s, "host-timeout", &mut keybuf).is_some() => {
                let key = long_flag(s, "host-timeout", &mut keybuf2).unwrap_or("--host-timeout");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                // The guard here is 10000 seconds, not 50 or 100: a host
                // timeout legitimately runs to hours.
                cfg.host_timeout_ms = time_option(
                    &mut cfg,
                    "--host-timeout",
                    &v,
                    0,
                    "Bogus --host-timeout argument specified",
                    10_000 * 1000,
                    GuardPhrasing::HoursUseS,
                );
            }
            _ if long_flag(s, "max-retries", &mut keybuf).is_some() => {
                let key = long_flag(s, "max-retries", &mut keybuf2).unwrap_or("--max-retries");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                let n = atoi(&v);
                if n < 0 {
                    cfg.invalid.push("max-retries must be positive".to_string());
                } else {
                    cfg.max_retries = u32::try_from(n).ok();
                }
            }
            _ if long_flag(s, "min-parallelism", &mut keybuf).is_some() => {
                let key =
                    long_flag(s, "min-parallelism", &mut keybuf2).unwrap_or("--min-parallelism");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                let n = atoi(&v);
                if n < 1 {
                    cfg.invalid
                        .push("Argument to --min-parallelism must be at least 1!".to_string());
                } else {
                    if n > 100 {
                        cfg.warnings.push(
                            "Warning: Your --min-parallelism option is pretty high!  This can hurt reliability.".to_string(),
                        );
                    }
                    cfg.min_parallelism = u32::try_from(n).ok();
                }
            }
            // `-M` is the short spelling of --max-parallelism.
            _ if long_flag(s, "max-parallelism", &mut keybuf).is_some()
                || s == "-M"
                || (s.starts_with("-M") && s.len() > 2) =>
            {
                let (v, adv) = if s.starts_with("-M") {
                    opt_value(args, i, "-M")
                } else {
                    let key = long_flag(s, "max-parallelism", &mut keybuf2)
                        .unwrap_or("--max-parallelism");
                    long_opt_value(args, i, key)
                };
                consumed_extra = adv;
                let n = atoi(&v);
                if n < 1 {
                    cfg.invalid
                        .push("Argument to -M must be at least 1!".to_string());
                } else {
                    if n > 900 {
                        cfg.warnings.push(
                            "Warning: Your max-parallelism (-M) option is extraordinarily high, which can hurt reliability".to_string(),
                        );
                    }
                    cfg.max_parallelism = u32::try_from(n).ok();
                }
            }
            _ if long_flag(s, "max-hostgroup", &mut keybuf).is_some() => {
                let key = long_flag(s, "max-hostgroup", &mut keybuf2).unwrap_or("--max-hostgroup");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                cfg.max_hostgroup = u32::try_from(atoi(&v)).ok();
            }
            _ if long_flag(s, "min-hostgroup", &mut keybuf).is_some() => {
                let key = long_flag(s, "min-hostgroup", &mut keybuf2).unwrap_or("--min-hostgroup");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                let n = atoi(&v);
                if n > 100 {
                    cfg.warnings.push(
                        "Warning: You specified a highly aggressive --min-hostgroup.".to_string(),
                    );
                }
                cfg.min_hostgroup = u32::try_from(n).ok();
            }
            "-sV" => cfg.service_version = true,
            "-O" => cfg.os_detection = true,
            // nmap accepts both spellings for the same behaviour.
            "--osscan-guess" | "--fuzzy" => cfg.osscan_guess = true,
            "--osscan-limit" => cfg.osscan_limit = true,
            _ if s.starts_with("--max-os-tries") => {
                let (v, adv) = opt_value(args, i, "--max-os-tries");
                // Long-option attached form is `--max-os-tries=N`; drop the `=`.
                let v = v.strip_prefix('=').map(str::to_string).unwrap_or(v);
                // nmap rejects a non-positive count rather than scanning zero times.
                match v.trim().parse::<usize>() {
                    Ok(n) if n > 0 => cfg.max_os_tries = Some(n),
                    _ => cfg.unrecognized.push(format!("--max-os-tries {v}")),
                }
                consumed_extra = adv;
            }
            // `-A` turns on the aggressive set; OS detection is the part we implement.
            "-A" => {
                cfg.os_detection = true;
                cfg.service_version = true;
            }
            "--version-light" => {
                cfg.service_version = true;
                cfg.version_intensity = 2; // nmap: light = intensity 2
            }
            "--version-all" => {
                cfg.service_version = true;
                cfg.version_intensity = 9; // nmap: all = intensity 9
            }
            "--version-trace" => {
                // Raises verbosity of the version scan; treat as a debug bump.
                cfg.service_version = true;
                cfg.debugging = bump(cfg.debugging);
            }
            _ if s.starts_with("--version-intensity") => {
                let (v, adv) = opt_value(args, i, "--version-intensity");
                // Long-option attached form is `--version-intensity=N`; drop the `=`.
                let v = v.strip_prefix('=').map(str::to_string).unwrap_or(v);
                if let Some(n) = leading_int_0_9(&v) {
                    cfg.version_intensity = n;
                } else {
                    cfg.unrecognized.push(format!("--version-intensity {v}"));
                }
                consumed_extra = adv;
            }
            // Packet-shaping options (M7.5). These affect only raw probes; the
            // CLI warns when the chosen scan cannot honour them, as C does at
            // nmap.cc:1817. Each sets `raw_scan_options` for exactly that check.
            "--badsum" | "-badsum" => {
                cfg.bad_sum = true;
                cfg.raw_scan_options = true;
            }
            _ if long_flag(s, "ttl", &mut keybuf).is_some() => {
                let key = long_flag(s, "ttl", &mut keybuf2).unwrap_or("--ttl");
                let (v, adv) = long_opt_value(args, i, key);
                consumed_extra = adv;
                cfg.raw_scan_options = true;
                // C: `o.ttl = atoi(optarg)` then fatal unless 0..=255. `atoi`
                // yields 0 for junk, which would silently become a valid TTL of
                // 0 — so parse strictly and record the junk as unrecognized
                // rather than inventing a value the operator did not write.
                // `u8` IS the 0..=255 check C spells with `atoi` + `fatal`:
                // "256", "999" and "-1" all fail to parse and are recorded as
                // unrecognized, which the fail-closed gate turns into a refusal.
                match v.trim().parse::<u8>() {
                    Ok(n) => cfg.ttl = Some(n),
                    Err(_) => cfg.unrecognized.push(format!("--ttl {v}")),
                }
            }
            _ if s == "-S" || s.starts_with("-S") && s.len() > 2 => {
                let (v, adv) = opt_value(args, i, "-S");
                consumed_extra = adv;
                cfg.raw_scan_options = true;
                if cfg.spoof_source.is_some() {
                    cfg.spoof_source_repeated = true;
                } else {
                    cfg.spoof_source = Some(v);
                }
            }
            // Scope options. These take a value, so they MUST consume it: an
            // unimplemented value-taking option used to leave its argument in
            // argv where the positional handler read it as a target, which is
            // how `--exclude H` got H scanned (M7.0). Now they are implemented,
            // and `opt_value` consumes the argument in either spelling.
            _ if long_flag(s, "excludefile", &mut keybuf).is_some() => {
                let key = long_flag(s, "excludefile", &mut keybuf2).unwrap_or("--excludefile");
                let (v, adv) = long_opt_value(args, i, key);
                cfg.exclude_file = Some(v);
                consumed_extra = adv;
            }
            // AFTER excludefile: `--exclude` is a prefix of it, and matching in
            // the other order would read `--excludefile x` as `--exclude` with
            // the attached value "file", silently excluding a host named "file"
            // and leaving the real list unread.
            _ if long_flag(s, "exclude", &mut keybuf).is_some() => {
                let key = long_flag(s, "exclude", &mut keybuf2).unwrap_or("--exclude");
                let (v, adv) = long_opt_value(args, i, key);
                cfg.exclude = Some(v);
                consumed_extra = adv;
            }
            // `-iL` and `--iL` both, as with the output flags: getopt_long_only
            // matches a long option after one dash or two.
            _ if s.starts_with("-iL") || s.starts_with("--iL") => {
                let key = if s.starts_with("--") { "--iL" } else { "-iL" };
                let (v, adv) = long_opt_value(args, i, key);
                if cfg.input_file.is_some() {
                    cfg.input_file_repeated = true;
                } else {
                    cfg.input_file = Some(v);
                }
                consumed_extra = adv;
            }
            // Both spellings, because C nmap accepts both. `getopt_long_only`
            // (nmap.cc:653) matches a long option after a SINGLE dash, and the
            // table carries "oN"/"oX"/"oG" as long options — so `-oN f` and
            // `--oN f` are the same command there. This port matched only the
            // short spelling, so `--oN` was refused while `-oN` worked: a parity
            // gap in a feature that is fully implemented, and one found by
            // running the binary rather than reading it (as M7.0's was).
            _ if s.starts_with("-oN") || s.starts_with("--oN") => {
                let (v, adv) =
                    long_opt_value(args, i, if s.starts_with("--") { "--oN" } else { "-oN" });
                cfg.out_normal = Some(v);
                consumed_extra = adv;
            }
            _ if s.starts_with("-oX") || s.starts_with("--oX") => {
                let (v, adv) =
                    long_opt_value(args, i, if s.starts_with("--") { "--oX" } else { "-oX" });
                cfg.out_xml = Some(v);
                consumed_extra = adv;
            }
            _ if s.starts_with("-oG") || s.starts_with("--oG") => {
                let (v, adv) =
                    long_opt_value(args, i, if s.starts_with("--") { "--oG" } else { "-oG" });
                cfg.out_grep = Some(v);
                consumed_extra = adv;
            }
            _ if s.starts_with("-p") => {
                let (v, adv) = opt_value(args, i, "-p");
                cfg.port_spec = Some(v);
                consumed_extra = adv;
            }
            "--min-rate" => {
                if let Some(next) = args.get(i + 1) {
                    cfg.min_rate = parse_rate(next);
                    consumed_extra = 1;
                }
            }
            _ if s.starts_with("--min-rate=") => {
                cfg.min_rate = parse_rate(&s["--min-rate=".len()..])
            }
            "--max-rate" => {
                if let Some(next) = args.get(i + 1) {
                    cfg.max_rate = parse_rate(next);
                    consumed_extra = 1;
                }
            }
            _ if s.starts_with("--max-rate=") => {
                cfg.max_rate = parse_rate(&s["--max-rate=".len()..])
            }
            _ if s.starts_with("-v") => apply_v(&mut cfg, &s[2..]),
            _ if s.starts_with("-d") => apply_d(&mut cfg, &s[2..]),
            // Any other dash-led token longer than "-" is an option we don't
            // parse yet — record it rather than misread it as a target.
            _ if s.starts_with('-') && s.len() > 1 => cfg.unrecognized.push(s.to_string()),
            // Everything else is a target expression.
            _ => cfg.targets.push(s.to_string()),
        }
        i += 1 + consumed_extra;
    }
    cfg
}

#[cfg(test)]
mod timing_group_tests {
    use super::*;

    fn parse(args: &[&str]) -> RunConfig {
        parse_args(&args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    }

    /// The RTT setters run initial, then min, then max, and each drags its
    /// siblings. Reordering them changes the answer, so the order is pinned.
    ///
    /// `--min-rtt-timeout 900 --max-rtt-timeout 100` ends at min=100 because
    /// max runs last and `set_max_rtt` pulls min down to it. Applying them in
    /// argv order would give min=900, max=900 instead.
    #[test]
    fn the_rtt_setters_run_in_cs_order_not_argv_order() {
        let p =
            parse(&["--min-rtt-timeout", "900ms", "--max-rtt-timeout", "100ms"]).timing_params();
        assert_eq!(p.max_rtt_timeout_ms, 100);
        assert_eq!(
            p.min_rtt_timeout_ms, 100,
            "max ran last and pulled min down"
        );

        // Reversing the command line changes nothing, because argv order is not
        // what decides.
        let q =
            parse(&["--max-rtt-timeout", "100ms", "--min-rtt-timeout", "900ms"]).timing_params();
        assert_eq!(p, q);
    }

    /// An explicit knob beats `-T` from either side of it. C applies the
    /// explicit set after the whole argument loop, so position is irrelevant.
    #[test]
    fn an_explicit_knob_beats_the_template_from_either_side() {
        let before = parse(&["--scan-delay", "7ms", "-T0"]).timing_params();
        let after = parse(&["-T0", "--scan-delay", "7ms"]).timing_params();
        assert_eq!(before, after);
        assert_eq!(before.scan_delay_ms, 7, "-T0's 300000ms must not win");
    }

    /// A later `-T` does beat an earlier one, though: those are both handled in
    /// the loop, so the last one wins.
    #[test]
    fn the_last_template_wins() {
        assert_eq!(
            parse(&["-T0", "-T4"]).timing_template,
            Some(TimingTemplate::Aggressive)
        );
    }

    /// A scan delay longer than the ceiling would be clamped away, so C raises
    /// the ceiling to match rather than quietly ignoring the delay.
    #[test]
    fn a_scan_delay_raises_the_ceiling_it_would_otherwise_exceed() {
        let p = parse(&["--scan-delay", "3000ms"]).timing_params();
        assert_eq!(p.scan_delay_ms, 3000);
        assert!(
            p.max_tcp_scan_delay_ms >= 3000,
            "the 1000ms default ceiling would have clamped the delay away"
        );
    }

    /// `-T4` and `-T5` speed up TCP and SCTP but deliberately leave UDP's
    /// ceiling alone — C's comment is "No call to setMaxUDPScanDelay because of
    /// rate-limiting and unreliability".
    #[test]
    fn aggressive_templates_do_not_speed_up_udp() {
        let p = parse(&["-T4"]).timing_params();
        assert_eq!(p.max_tcp_scan_delay_ms, 10);
        assert_eq!(p.max_sctp_scan_delay_ms, 10);
        assert_eq!(
            p.max_udp_scan_delay_ms, 1000,
            "UDP keeps the default ceiling"
        );
    }

    /// Insane is the only template that sets a host timeout at all.
    #[test]
    fn only_insane_sets_a_host_timeout() {
        assert_eq!(parse(&["-T5"]).timing_params().host_timeout_ms, 900_000);
        for t in ["-T0", "-T1", "-T2", "-T3", "-T4"] {
            assert_eq!(parse(&[t]).timing_params().host_timeout_ms, 0, "{t}");
        }
    }

    /// `--host-timeout 0` is C's explicit "no timeout" and must override a
    /// template that set one — which is why the field is an `Option`, not an
    /// `i64` defaulting to zero.
    #[test]
    fn an_explicit_zero_host_timeout_overrides_the_template() {
        let p = parse(&["-T5", "--host-timeout", "0"]).timing_params();
        assert_eq!(p.host_timeout_ms, 0);
    }

    /// Every option in the group consumes its argument in all four spellings.
    /// One that did not would leave the value in argv for the positional
    /// handler to read as a target — the M7.0 bug.
    #[test]
    fn every_timing_option_consumes_its_argument() {
        for name in [
            "min-rtt-timeout",
            "max-rtt-timeout",
            "initial-rtt-timeout",
            "scan-delay",
            "max-scan-delay",
            "host-timeout",
            "max-retries",
            "min-parallelism",
            "max-parallelism",
            "min-hostgroup",
            "max-hostgroup",
        ] {
            for spelling in [
                vec![format!("--{name}"), "5".to_string()],
                vec![format!("--{name}=5")],
                vec![format!("-{name}"), "5".to_string()],
                vec![format!("-{name}=5")],
            ] {
                let mut argv: Vec<String> = spelling;
                argv.push("127.0.0.1".to_string());
                let cfg = parse_args(&argv);
                assert_eq!(
                    cfg.targets,
                    ["127.0.0.1"],
                    "--{name} ({argv:?}) leaked its argument into the target list"
                );
            }
        }
    }

    /// `-T` takes a required argument, so both spellings must work and neither
    /// may swallow the target.
    #[test]
    fn the_timing_template_parses_attached_and_separate() {
        for argv in [vec!["-T4", "127.0.0.1"], vec!["-T", "4", "127.0.0.1"]] {
            let cfg = parse(&argv);
            assert_eq!(
                cfg.timing_template,
                Some(TimingTemplate::Aggressive),
                "{argv:?}"
            );
            assert_eq!(cfg.targets, ["127.0.0.1"], "{argv:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str]) -> RunConfig {
        parse_args(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn verbose_increments_and_stacks() {
        assert_eq!(cfg(&["-v"]).verbose, 1);
        assert_eq!(cfg(&["-vv"]).verbose, 2);
        assert_eq!(cfg(&["-vvv"]).verbose, 3);
        assert_eq!(cfg(&["-v", "-v"]).verbose, 2);
        assert_eq!(cfg(&["--verbose"]).verbose, 1);
    }

    #[test]
    fn verbose_numeric_sets_and_clamps() {
        assert_eq!(cfg(&["-v3"]).verbose, 3);
        assert_eq!(cfg(&["-v0"]).verbose, 0);
        assert_eq!(cfg(&["-v12"]).verbose, 10); // clamp to 10
        assert_eq!(cfg(&["-v3x"]).verbose, 3); // atoi-style leading digits
    }

    #[test]
    fn debug_bumps_both_debugging_and_verbose() {
        let c = cfg(&["-d"]);
        assert_eq!((c.debugging, c.verbose), (1, 1));
        let c = cfg(&["-dd"]);
        assert_eq!((c.debugging, c.verbose), (2, 2));
        let c = cfg(&["-d3"]);
        assert_eq!((c.debugging, c.verbose), (3, 3));
        let c = cfg(&["--debug"]);
        assert_eq!((c.debugging, c.verbose), (1, 1));
    }

    #[test]
    fn version_help_and_targets() {
        assert!(cfg(&["--version"]).show_version);
        assert!(cfg(&["-h"]).show_help);
        assert!(cfg(&["--help"]).show_help);
        let c = cfg(&["scanme.nmap.org", "10.0.0.0/24"]);
        assert_eq!(c.targets, vec!["scanme.nmap.org", "10.0.0.0/24"]);
    }

    #[test]
    fn version_scan_flags() {
        // Default: no -sV, intensity 7.
        let d = cfg(&["10.0.0.1"]);
        assert!(!d.service_version);
        assert_eq!(d.version_intensity, 7);

        assert!(cfg(&["-sV", "10.0.0.1"]).service_version);
        // OS detection and its modifiers.
        assert!(cfg(&["-O", "10.0.0.1"]).os_detection);
        assert!(!cfg(&["10.0.0.1"]).os_detection);
        assert!(cfg(&["-O", "--osscan-guess", "10.0.0.1"]).osscan_guess);
        assert!(cfg(&["-O", "--fuzzy", "10.0.0.1"]).osscan_guess);
        assert!(cfg(&["-O", "--osscan-limit", "10.0.0.1"]).osscan_limit);
    }

    #[test]
    fn max_os_tries_takes_a_positive_count_in_either_form() {
        assert_eq!(
            cfg(&["-O", "--max-os-tries", "3", "10.0.0.1"]).max_os_tries,
            Some(3)
        );
        assert_eq!(
            cfg(&["-O", "--max-os-tries=7", "10.0.0.1"]).max_os_tries,
            Some(7)
        );
        // Unset leaves the driver's default rather than forcing a value.
        assert_eq!(cfg(&["-O", "10.0.0.1"]).max_os_tries, None);
    }

    #[test]
    fn max_os_tries_rejects_a_count_that_would_scan_nothing() {
        // Zero, negative and non-numeric are recorded as unrecognized rather than
        // silently becoming a default — a scan that never runs is not what was asked.
        for bad in ["0", "-1", "abc", ""] {
            let c = cfg(&["-O", "--max-os-tries", bad, "10.0.0.1"]);
            assert_eq!(c.max_os_tries, None, "{bad}");
            assert!(
                c.unrecognized
                    .iter()
                    .any(|u| u.starts_with("--max-os-tries")),
                "{bad} should be reported"
            );
        }
        // `-A` implies OS detection and version detection together.
        let a = cfg(&["-A", "10.0.0.1"]);
        assert!(a.os_detection && a.service_version);
        // The modifiers do not turn detection on by themselves, matching nmap.
        assert!(!cfg(&["--osscan-guess", "10.0.0.1"]).os_detection);

        let light = cfg(&["--version-light", "10.0.0.1"]);
        assert!(light.service_version);
        assert_eq!(light.version_intensity, 2);

        let all = cfg(&["--version-all", "10.0.0.1"]);
        assert!(all.service_version);
        assert_eq!(all.version_intensity, 9);

        // --version-intensity as a separate arg and inline; clamped to 0..=9.
        assert_eq!(
            cfg(&["-sV", "--version-intensity", "3"]).version_intensity,
            3
        );
        assert_eq!(cfg(&["--version-intensity", "12"]).version_intensity, 9);
        assert_eq!(cfg(&["--version-intensity=0"]).version_intensity, 0);

        // A non-numeric intensity is recorded, not misparsed; intensity stays default.
        let bad = cfg(&["--version-intensity", "hi"]);
        assert_eq!(bad.version_intensity, 7);
        assert!(bad
            .unrecognized
            .iter()
            .any(|u| u.contains("version-intensity")));
    }

    #[test]
    fn flags_and_targets_mix_in_any_order() {
        let c = cfg(&["-v", "10.0.0.1", "-d", "example.com"]);
        assert_eq!(c.verbose, 2); // -v then -d each bump verbose
        assert_eq!(c.debugging, 1);
        assert_eq!(c.targets, vec!["10.0.0.1", "example.com"]);
    }

    #[test]
    fn port_spec_and_output_flags_attached_and_separate() {
        assert_eq!(cfg(&["-p", "22,80"]).port_spec.as_deref(), Some("22,80"));
        assert_eq!(cfg(&["-p22,80"]).port_spec.as_deref(), Some("22,80"));
    }

    #[test]
    fn min_and_max_rate_parse_separate_attached_and_reject_junk() {
        assert_eq!(cfg(&["--min-rate", "100"]).min_rate, Some(100.0));
        assert_eq!(cfg(&["--max-rate=5000"]).max_rate, Some(5000.0));
        assert_eq!(cfg(&["--min-rate", "0"]).min_rate, None); // non-positive rejected
        assert_eq!(cfg(&["--max-rate", "abc"]).max_rate, None); // non-numeric rejected
        assert!(cfg(&["--min-rate"]).unrecognized.is_empty()); // trailing flag: no value, no crash
        assert_eq!(cfg(&["-oX", "out.xml"]).out_xml.as_deref(), Some("out.xml"));
        assert_eq!(cfg(&["-oX-"]).out_xml.as_deref(), Some("-"));
        let c = cfg(&["-oG", "-", "-oN", "n.txt"]);
        assert_eq!(c.out_grep.as_deref(), Some("-"));
        assert_eq!(c.out_normal.as_deref(), Some("n.txt"));
    }

    #[test]
    fn scan_flags_and_targets_together() {
        let c = cfg(&["-sT", "-Pn", "-6", "-p", "1-100", "scanme.nmap.org"]);
        assert!(c.assume_up);
        assert!(c.ipv6);
        assert_eq!(c.port_spec.as_deref(), Some("1-100"));
        assert_eq!(c.targets, vec!["scanme.nmap.org"]);
        assert!(c.unrecognized.is_empty());
    }

    #[test]
    fn scan_technique_selection() {
        assert_eq!(cfg(&["10.0.0.1"]).scan, ScanKind::Connect); // default
        assert_eq!(cfg(&["-sT", "10.0.0.1"]).scan, ScanKind::Connect);
        assert_eq!(cfg(&["-sS", "10.0.0.1"]).scan, ScanKind::Syn);
        assert_eq!(cfg(&["-sU", "10.0.0.1"]).scan, ScanKind::Udp);
        // Last technique flag wins, like nmap's getopt.
        assert_eq!(cfg(&["-sS", "-sT", "10.0.0.1"]).scan, ScanKind::Connect);
        // The stateless TCP flag scans.
        assert_eq!(cfg(&["-sA", "10.0.0.1"]).scan, ScanKind::Ack);
        assert_eq!(cfg(&["-sW", "10.0.0.1"]).scan, ScanKind::Window);
        assert_eq!(cfg(&["-sM", "10.0.0.1"]).scan, ScanKind::Maimon);
        assert_eq!(cfg(&["-sF", "10.0.0.1"]).scan, ScanKind::Fin);
        assert_eq!(cfg(&["-sN", "10.0.0.1"]).scan, ScanKind::Null);
        assert_eq!(cfg(&["-sX", "10.0.0.1"]).scan, ScanKind::Xmas);
    }

    #[test]
    fn unknown_flags_are_recorded_not_treated_as_targets() {
        let c = cfg(&["-Z", "--frobnicate", "10.0.0.1"]);
        assert_eq!(c.unrecognized, vec!["-Z", "--frobnicate"]);
        assert_eq!(c.targets, vec!["10.0.0.1"]);
    }

    /// `-n` is accepted rather than refused, because the port already never
    /// does a reverse lookup. Every case in the M1 differential matrix passes
    /// `-n`, so refusing it took the whole differential red.
    #[test]
    fn an_option_the_port_already_satisfies_is_accepted() {
        let c = cfg(&["-n", "-sT", "127.0.0.1"]);
        assert!(
            c.unrecognized.is_empty(),
            "-n should not be refused: {:?}",
            c.unrecognized
        );
        assert_eq!(c.targets, vec!["127.0.0.1"]);
    }

    /// The carve-out is narrow on purpose. An option whose *opposite* is what
    /// the port does — `-R`, always resolve — asks for behaviour this port
    /// cannot provide, so it must still be refused rather than quietly accepted.
    #[test]
    fn the_no_op_carve_out_does_not_leak_to_its_opposite() {
        assert_eq!(cfg(&["-R", "127.0.0.1"]).unrecognized, vec!["-R"]);
        // Same test, one entry per carve-out: the option that asks for the
        // OPPOSITE of what the port unconditionally does must still be refused,
        // because there the port cannot do what is asked.
        //   -n  (no reverse DNS)        <-> -R                (always resolve)
        //   -r  (sequential ports)      <-> --randomize-hosts (and its --rH alias)
        //   --no-stylesheet             <-> --stylesheet, --webxml
        // `--release-memory` and `--log-errors` have no opposite in C nmap's
        // grammar, so there is nothing to pair them with here.
        for opposite in [
            "-R",
            "--randomize-hosts",
            "--rH",
            "--stylesheet",
            "--webxml",
        ] {
            assert_eq!(
                cfg(&[opposite, "127.0.0.1"]).unrecognized,
                vec![opposite.to_string()],
                "{opposite} asks for behaviour this port does not have and must be refused"
            );
        }
        // And it does not accidentally swallow the constraint options that
        // motivated failing closed in the first place.
        //
        // This list keeps shrinking, which is the point: `--exclude` left in
        // M7.4; `--scan-delay`, `-T2` and `--max-retries` left in M7.7; and
        // `--top-ports`, `--exclude-ports` and `--port-ratio` left in M7.8.
        // Each departure is a flag that graduated from "refused" to
        // "implemented and honoured" — never to "quietly accepted". The
        // property that matters is unchanged: implementing one option must not
        // relax the rest.
        for flag in ["--source-port", "--data-length", "--spoof-mac"] {
            assert_eq!(
                cfg(&[flag, "127.0.0.1"]).unrecognized,
                vec![flag.to_string()],
                "{flag} must still be refused"
            );
        }
        // The graduated ones must now parse rather than land in `unrecognized`.
        // Asserting only the departures would leave the arrival unchecked,
        // which is how LESSONS #027 happened.
        for flag in [
            vec!["--scan-delay", "5ms"],
            vec!["-T2"],
            vec!["--max-retries", "3"],
            vec!["--top-ports", "5"],
            vec!["--exclude-ports", "80"],
            vec!["--port-ratio", "0.5"],
            vec!["-F"],
        ] {
            let mut argv = flag.clone();
            argv.push("127.0.0.1");
            let parsed = cfg(&argv);
            assert!(
                parsed.unrecognized.is_empty() && parsed.invalid.is_empty(),
                "{flag:?} is implemented now and must parse cleanly: {parsed:?}"
            );
        }
    }

    /// The four accepted no-ops are accepted, and each for its own stated reason.
    ///
    /// Pinned individually rather than by iterating the table: a loop over
    /// `ALREADY_SATISFIED` would pass no matter what the table contained, which is
    /// the opposite of what this is for.
    #[test]
    fn each_already_satisfied_option_is_accepted_and_scans() {
        for flag in [
            "-n",
            "-r",
            "--release-memory",
            "--log-errors",
            "--no-stylesheet",
        ] {
            let c = cfg(&[flag, "127.0.0.1"]);
            assert!(
                c.unrecognized.is_empty(),
                "{flag} should be accepted as a no-op, got {:?}",
                c.unrecognized
            );
            assert_eq!(
                c.targets,
                vec!["127.0.0.1"],
                "{flag} must not eat the target"
            );
        }
    }

    /// C nmap's `getopt_long_only` accepts a long option after one dash OR two,
    /// so `-oN f` and `--oN f` are the same command there. Both spellings must
    /// reach the same field here, attached or separate.
    #[test]
    fn output_flags_accept_both_the_short_and_long_spelling() {
        for (short, long) in [("-oN", "--oN"), ("-oX", "--oX"), ("-oG", "--oG")] {
            let sep_s = cfg(&[short, "out.txt", "127.0.0.1"]);
            let sep_l = cfg(&[long, "out.txt", "127.0.0.1"]);
            assert_eq!(sep_s, sep_l, "{short} and {long} must parse identically");
            assert!(sep_l.unrecognized.is_empty(), "{long} must not be refused");
            assert_eq!(
                sep_l.targets,
                vec!["127.0.0.1"],
                "{long} must not eat the target"
            );

            let att_s = cfg(&[&format!("{short}out.txt"), "127.0.0.1"]);
            let att_l = cfg(&[&format!("{long}out.txt"), "127.0.0.1"]);
            assert_eq!(
                att_s, att_l,
                "attached {short}/{long} must parse identically"
            );
        }
    }

    /// The three scope options parse in every spelling getopt_long_only takes,
    /// and — the part that matters — each CONSUMES its argument.
    ///
    /// This is the M7.0 bug's exact shape. An unimplemented value-taking option
    /// left its value in argv, where the positional handler collected it as a
    /// target: `--exclude 127.0.0.2 127.0.0.1` scanned *two* hosts, and naming a
    /// host to protect it was what got it scanned. So every assertion below
    /// checks the target list too, not just that the flag was recognised.
    #[test]
    fn scope_options_parse_in_every_spelling_and_eat_their_argument() {
        let one = |v: Vec<&str>| {
            let owned: Vec<String> = v.iter().map(|s| (*s).to_string()).collect();
            cfg(&owned.iter().map(String::as_str).collect::<Vec<_>>())
        };
        for (args, exclude) in [
            (vec!["--exclude", "10.0.0.2", "127.0.0.1"], "10.0.0.2"),
            (vec!["--exclude=10.0.0.2", "127.0.0.1"], "10.0.0.2"),
            (vec!["-exclude", "10.0.0.2", "127.0.0.1"], "10.0.0.2"),
        ] {
            let c = one(args.clone());
            assert_eq!(c.exclude.as_deref(), Some(exclude), "{args:?}");
            assert!(c.unrecognized.is_empty(), "{args:?} must not be refused");
            assert_eq!(
                c.targets,
                vec!["127.0.0.1"],
                "{args:?} must not scan the excluded host"
            );
        }
        for args in [
            vec!["--excludefile", "ex.txt", "127.0.0.1"],
            vec!["--excludefile=ex.txt", "127.0.0.1"],
        ] {
            let c = one(args.clone());
            assert_eq!(c.exclude_file.as_deref(), Some("ex.txt"), "{args:?}");
            assert_eq!(c.targets, vec!["127.0.0.1"], "{args:?}");
        }
        for args in [
            vec!["-iL", "hosts.txt"],
            vec!["--iL", "hosts.txt"],
            vec!["-iLhosts.txt"],
            vec!["--iL=hosts.txt"],
        ] {
            let c = one(args.clone());
            assert_eq!(c.input_file.as_deref(), Some("hosts.txt"), "{args:?}");
            assert!(
                c.targets.is_empty(),
                "{args:?} must not treat the filename as a target"
            );
        }
    }

    /// `--exclude` is a prefix of `--excludefile`, so the match arms' ORDER is
    /// load-bearing. With `exclude` first, `--excludefile hosts.txt` would read
    /// as `--exclude` with the attached value "file": a host named "file" would
    /// be excluded, the real exclusion list would never be opened, and
    /// "hosts.txt" would fall through to the positional handler and be SCANNED.
    /// Silent, and in the dangerous direction — the M7.0 failure wearing a
    /// different hat.
    #[test]
    fn excludefile_is_not_swallowed_by_the_exclude_prefix() {
        for args in [
            vec!["--excludefile", "hosts.txt", "127.0.0.1"],
            vec!["-excludefile", "hosts.txt", "127.0.0.1"],
            vec!["--excludefile=hosts.txt", "127.0.0.1"],
        ] {
            let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let c = cfg(&owned.iter().map(String::as_str).collect::<Vec<_>>());
            assert_eq!(c.exclude_file.as_deref(), Some("hosts.txt"), "{args:?}");
            assert_eq!(c.exclude, None, "{args:?} is not --exclude");
            assert_eq!(
                c.targets,
                vec!["127.0.0.1"],
                "{args:?} must not scan the list file"
            );
        }
    }

    /// C: `fatal("Only one input filename allowed")`. Recorded rather than
    /// silently overwriting, so the CLI can refuse — quietly dropping the first
    /// list would scan a different set than the operator asked for.
    #[test]
    fn a_second_input_file_is_recorded_as_a_conflict() {
        let c = cfg(&["-iL", "a.txt", "-iL", "b.txt"]);
        assert!(c.input_file_repeated);
        assert_eq!(c.input_file.as_deref(), Some("a.txt"), "the first is kept");
    }

    /// A short option's attached form must NOT lose a leading `=`: `-p` is in
    /// C's short-option string, so `-p=80` really does mean the port spec
    /// `=80` (which then fails to parse) rather than `80`.
    #[test]
    fn stripping_equals_is_confined_to_long_options() {
        assert_eq!(
            cfg(&["-p=80", "127.0.0.1"]).port_spec.as_deref(),
            Some("=80")
        );
        assert_eq!(
            cfg(&["--exclude=10.0.0.2", "127.0.0.1"]).exclude.as_deref(),
            Some("10.0.0.2")
        );
        // Separate form: a leading `=` is part of the operand, not a separator.
        assert_eq!(
            cfg(&["--exclude", "=weird"]).exclude.as_deref(),
            Some("=weird")
        );
    }

    /// The three packet-shaping options, in every spelling, each consuming its
    /// argument and each flagging `raw_scan_options` so the CLI can tell the
    /// operator when the chosen scan cannot honour them.
    #[test]
    fn packet_shaping_options_parse_and_flag_raw() {
        let one = |v: Vec<&str>| {
            let owned: Vec<String> = v.iter().map(|s| (*s).to_string()).collect();
            cfg(&owned.iter().map(String::as_str).collect::<Vec<_>>())
        };
        for args in [
            vec!["--ttl", "7", "-sS", "127.0.0.1"],
            vec!["--ttl=7", "-sS", "127.0.0.1"],
            vec!["-ttl", "7", "-sS", "127.0.0.1"],
        ] {
            let c = one(args.clone());
            assert_eq!(c.ttl, Some(7), "{args:?}");
            assert!(c.raw_scan_options, "{args:?}");
            assert!(c.unrecognized.is_empty(), "{args:?}");
            assert_eq!(
                c.targets,
                vec!["127.0.0.1"],
                "{args:?} must not eat the target"
            );
        }
        for args in [
            vec!["-S", "192.0.2.9", "-sS", "127.0.0.1"],
            vec!["-S192.0.2.9", "-sS", "127.0.0.1"],
        ] {
            let c = one(args.clone());
            assert_eq!(c.spoof_source.as_deref(), Some("192.0.2.9"), "{args:?}");
            assert!(c.raw_scan_options);
            assert_eq!(c.targets, vec!["127.0.0.1"], "{args:?}");
        }
        let c = one(vec!["--badsum", "-sS", "127.0.0.1"]);
        assert!(c.bad_sum && c.raw_scan_options);
        assert_eq!(c.targets, vec!["127.0.0.1"]);
    }

    /// `u8` parsing IS C's `atoi` + `fatal unless 0..=255`. An out-of-range or
    /// junk TTL becomes `unrecognized`, which the fail-closed gate turns into a
    /// refusal — never a silently-invented TTL. `atoi("abc")` is 0 in C, which
    /// would have been a valid TTL, so parsing strictly here is the safer read
    /// of the same rule.
    #[test]
    fn an_out_of_range_or_junk_ttl_is_refused_not_coerced() {
        for bad in ["256", "999", "-1", "abc", "", "7x"] {
            let c = cfg(&["--ttl", bad, "-sS", "127.0.0.1"]);
            assert_eq!(c.ttl, None, "--ttl {bad} must not produce a value");
            assert_eq!(
                c.unrecognized,
                vec![format!("--ttl {bad}")],
                "--ttl {bad} must be refused"
            );
            assert_eq!(
                c.targets,
                vec!["127.0.0.1"],
                "--ttl {bad} must still eat its argument"
            );
        }
        // The boundaries are accepted.
        assert_eq!(cfg(&["--ttl", "0", "-sS", "127.0.0.1"]).ttl, Some(0));
        assert_eq!(cfg(&["--ttl", "255", "-sS", "127.0.0.1"]).ttl, Some(255));
    }

    /// C: `fatal("You can only use the source option once!")`.
    #[test]
    fn a_second_source_address_is_recorded_as_a_conflict() {
        let c = cfg(&["-S", "1.1.1.1", "-S", "2.2.2.2", "-sS", "127.0.0.1"]);
        assert!(c.spoof_source_repeated);
        assert_eq!(
            c.spoof_source.as_deref(),
            Some("1.1.1.1"),
            "the first is kept"
        );
    }

    /// A scan that names none of them must not set the raw flag, or every
    /// ordinary invocation would draw the "will not be honored" warning.
    #[test]
    fn raw_scan_options_is_not_set_by_an_ordinary_scan() {
        for args in [
            &["-sT", "-p", "80", "127.0.0.1"][..],
            &["-sS", "-p", "80", "127.0.0.1"][..],
            &["--exclude", "10.0.0.1", "-sT", "127.0.0.1"][..],
        ] {
            assert!(!cfg(args).raw_scan_options, "{args:?}");
        }
    }

    /// `-S` must not be confused with the lowercase scan-type flags that
    /// surround it in the match.
    #[test]
    fn uppercase_s_does_not_collide_with_scan_types() {
        assert_eq!(cfg(&["-sS", "127.0.0.1"]).scan, ScanKind::Syn);
        assert_eq!(cfg(&["-sS", "127.0.0.1"]).spoof_source, None);
        let c = cfg(&["-S", "192.0.2.9", "-sS", "127.0.0.1"]);
        assert_eq!(c.scan, ScanKind::Syn);
        assert_eq!(c.spoof_source.as_deref(), Some("192.0.2.9"));
    }

    /// Every entry in the table has to carry a stated reason; an entry added
    /// without one is the failure mode this guards against.
    #[test]
    fn every_accepted_no_op_states_why_it_qualifies() {
        for (opt, why) in ALREADY_SATISFIED {
            assert!(opt.starts_with('-'), "{opt} is not an option");
            assert!(
                why.len() > 40,
                "{opt} needs a real justification, got {why:?}"
            );
        }
    }

    #[test]
    fn never_panics_on_hostile_args() {
        for a in [
            "",
            "-",
            "--",
            "-v",
            "-vvvvvvvvvvvvvvvv",
            "-v999999999999999999999",
            "-déjà",
            "-",
        ] {
            let _ = parse_args(&[a.to_string()]);
        }
    }
}
