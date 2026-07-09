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

/// nmap clamps verbosity/debugging to `box(0, 10, …)`.
const MAX_LEVEL: u8 = 10;

/// Parsed command-line configuration. Grows toward the full `NmapOps` surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunConfig {
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
    /// `-oN <file>` normal output destination (`"-"` = stdout).
    pub out_normal: Option<String>,
    /// `-oX <file>` XML output destination (`"-"` = stdout).
    pub out_xml: Option<String>,
    /// `-oG <file>` grepable output destination (`"-"` = stdout).
    pub out_grep: Option<String>,
    /// Flags we do not yet recognize — recorded, never silently dropped, so the
    /// CLI can warn instead of misparsing them.
    pub unrecognized: Vec<String>,
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

/// Parse argv (without the program name) into a [`RunConfig`]. Total and
/// panic-free over any input.
// Index arithmetic is bounded by `args.len()` and only ever advances.
#[allow(clippy::arithmetic_side_effects)]
pub fn parse_args(args: &[String]) -> RunConfig {
    let mut cfg = RunConfig::default();
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
            "-sT" => {} // connect scan — the only scan type in M1 (the default)
            _ if s.starts_with("-oN") => {
                let (v, adv) = opt_value(args, i, "-oN");
                cfg.out_normal = Some(v);
                consumed_extra = adv;
            }
            _ if s.starts_with("-oX") => {
                let (v, adv) = opt_value(args, i, "-oX");
                cfg.out_xml = Some(v);
                consumed_extra = adv;
            }
            _ if s.starts_with("-oG") => {
                let (v, adv) = opt_value(args, i, "-oG");
                cfg.out_grep = Some(v);
                consumed_extra = adv;
            }
            _ if s.starts_with("-p") => {
                let (v, adv) = opt_value(args, i, "-p");
                cfg.port_spec = Some(v);
                consumed_extra = adv;
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
    fn unknown_flags_are_recorded_not_treated_as_targets() {
        let c = cfg(&["-Z", "--frobnicate", "10.0.0.1"]);
        assert_eq!(c.unrecognized, vec!["-Z", "--frobnicate"]);
        assert_eq!(c.targets, vec!["10.0.0.1"]);
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
