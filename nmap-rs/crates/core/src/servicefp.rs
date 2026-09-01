//! The service-fingerprint builder — the port of `service_scan.cc`'s
//! `addServiceChar` / `addServiceString` / `addToServiceFingerprint` /
//! `getServiceFingerprint` (`:1663–1795`).
//!
//! When `-sV` gets data back from a port but no rule matches it, nmap builds a
//! compact escaped transcript of what the service said and prints it for the
//! operator to submit. M3 ported the matcher, the probe database and the version
//! substitution, but **not this**: there was no service-fingerprint builder
//! anywhere in `crates/` until now. The gap surfaced while starting Workstream S3,
//! whose store had a `Service` variant that nothing could produce.
//!
//! Unlike the rest of Workstream S this is a **port**, not an addition, so it has a
//! real C oracle and is gated by a byte-exact differential
//! (`tests/differential/s/`).
//!
//! # The wrap rule is the part that is easy to get wrong
//!
//! [`add_char`](ServiceFingerprint::add_char) wraps on the **cumulative buffer
//! length including the continuations it has already inserted**, not on the column
//! of the current line as a reader would count it:
//!
//! ```text
//! if servicefplen % (wrapat+1) == wrapat { append "\nSF:"; }
//! servicefp[servicefplen++] = c;
//! ```
//!
//! With `wrapat = 74` that is `len % 75 == 74`. Because the four bytes of `"\nSF:"`
//! are themselves counted, the visible line lengths are not constant — reproducing
//! this by writing "wrap at column 74" produces different bytes. The port keeps the
//! C's arithmetic verbatim for that reason.
//!
//! # Why the header is an input rather than something read here
//!
//! The C builds its header from `NMAP_VERSION`, `NMAP_PLATFORM`,
//! `o.version_intensity` and `localtime(time(NULL))`. `core` reads no clock and no
//! globals, so all of that arrives in [`FingerprintHeader`]. That keeps the module
//! pure — Miri can run it, a test can pin it, and the differential can be
//! **byte-exact** rather than "equal after stripping the parts that move".
//!
//! # ASCII classification, deliberately
//!
//! The C uses `isalnum` and `ispunct`, which are locale-dependent in principle. In
//! practice nmap never leaves the `"C"` locale: `main.cc:120` calls
//! `setlocale(LC_CTYPE, NULL)`, which **queries** the locale without setting it, and
//! nothing else calls `setlocale`. So the classification is ASCII-only, and the port
//! uses ASCII predicates to match. Recorded because "the C used the locale
//! functions" would otherwise look like a divergence.

use core::fmt::Write as _;

/// Column argument the C passes (`servicewrap = 74`).
pub const WRAP_AT: usize = 74;

/// The C wraps on `servicefplen % (wrapat + 1)`, so the period is one more than
/// the column argument. A compile-time constant, and non-zero by construction.
const WRAP_PERIOD: usize = WRAP_AT + 1;

/// What is inserted when the wrap point is reached.
const CONTINUATION: &str = "\nSF:";

/// Per-response truncation without `-d` (`MIN(resplen, 900)`).
pub const MAX_RESPONSE_BYTES: usize = 900;

/// Per-response truncation with `-d` (`MIN(resplen, 1300)`).
pub const MAX_RESPONSE_BYTES_DEBUG: usize = 1300;

/// Once the accumulated fingerprint exceeds this, further responses are dropped
/// (`if (servicefplen > 2200) return;`). Note the C's comparison is `>`, not `>=`.
pub const MAX_TOTAL: usize = 2200;

/// The same ceiling with `-d` (`10000`).
pub const MAX_TOTAL_DEBUG: usize = 10000;

/// Transport the port was probed over, for the `SF-PortNNNN-<PROTO>` header.
/// Ports `proto2ascii_uppercase` for the three protocols `-sV` can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
}

impl Proto {
    /// The uppercase name used in the header.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Sctp => "SCTP",
        }
    }
}

/// Everything the C's header line reads from globals and the clock.
///
/// Supplying these rather than reading them is what makes this module pure and the
/// differential byte-exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintHeader {
    /// The probed port.
    pub port: u16,
    /// The transport.
    pub proto: Proto,
    /// `NMAP_VERSION`, e.g. `"7.94"`.
    pub version: String,
    /// `NMAP_PLATFORM`, e.g. `"x86_64-pc-linux-gnu"`.
    pub platform: String,
    /// `o.version_intensity`, 0–9.
    pub intensity: i32,
    /// Whether the probe went over SSL, which adds `%T=SSL`.
    pub ssl_tunnel: bool,
    /// `localtime` month, 1–12. The C writes `0` when `localtime` fails.
    pub month: i32,
    /// `localtime` day of month. The C writes `0` when `localtime` fails.
    pub day: i32,
    /// `time(NULL)` as the C renders it: `%X`, i.e. uppercase hex of the `int`.
    pub time: i32,
}

/// An accumulating service fingerprint.
///
/// Build it with [`new`](Self::new), feed each unmatched probe response to
/// [`add_response`](Self::add_response), then take the result with
/// [`finish`](Self::finish).
#[derive(Debug, Clone)]
pub struct ServiceFingerprint {
    buf: String,
    /// `servicefplen` — a byte count, which is what the wrap arithmetic uses.
    len: usize,
    header: FingerprintHeader,
    max_response: usize,
    max_total: usize,
}

/// ASCII `isalnum` under the `"C"` locale.
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// ASCII `ispunct` under the `"C"` locale: printable, not a space, not alphanumeric.
fn is_punct(b: u8) -> bool {
    b.is_ascii_graphic() && !b.is_ascii_alphanumeric()
}

/// The characters the C backslash-escapes because they are regex metacharacters:
/// `strchr("\\?\"[]().*+$^|", c)`.
fn is_regex_meta(b: u8) -> bool {
    matches!(
        b,
        b'\\' | b'?' | b'"' | b'[' | b']' | b'(' | b')' | b'.' | b'*' | b'+' | b'$' | b'^' | b'|'
    )
}

impl ServiceFingerprint {
    /// A new, empty fingerprint.
    ///
    /// `debug` selects the C's `-d` limits: a 1300-byte per-response truncation and
    /// a 10000-byte total ceiling instead of 900 and 2200.
    #[must_use]
    pub fn new(header: FingerprintHeader, debug: bool) -> Self {
        Self {
            buf: String::new(),
            len: 0,
            header,
            max_response: if debug {
                MAX_RESPONSE_BYTES_DEBUG
            } else {
                MAX_RESPONSE_BYTES
            },
            max_total: if debug { MAX_TOTAL_DEBUG } else { MAX_TOTAL },
        }
    }

    /// Bytes accumulated so far — the C's `servicefplen`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append one byte, inserting the continuation at the wrap point.
    ///
    /// This is `addServiceChar` with its arithmetic kept verbatim; see the module
    /// docs for why the rule is not "wrap at column 74".
    ///
    /// The C `fatal()`s here when fewer than six bytes remain in its buffer
    /// (`service_scan.cc:1666`) — a process abort whose trigger is how much data a
    /// scanned host sent back. A `String` grows, so the abort has no counterpart;
    /// growth is bounded instead by the response and total ceilings.
    fn add_char(&mut self, c: char) {
        // `checked_rem` rather than `%`: the crate denies
        // `clippy::arithmetic_side_effects`, and the lint cannot see that the
        // divisor is a non-zero constant. `WRAP_PERIOD` is a compile-time
        // expression, so this is the C's `servicefplen % (wrapat+1) == wrapat`
        // with no runtime arithmetic added.
        if self.len.checked_rem(WRAP_PERIOD) == Some(WRAP_AT) {
            self.buf.push_str(CONTINUATION);
            self.len = self.len.saturating_add(CONTINUATION.len());
        }
        self.buf.push(c);
        self.len = self.len.saturating_add(1);
    }

    /// Append each byte of a string through [`add_char`](Self::add_char).
    fn add_str(&mut self, s: &str) {
        for c in s.chars() {
            self.add_char(c);
        }
    }

    /// Add one probe's response to the fingerprint.
    ///
    /// Ports `addToServiceFingerprint`. Returns `false` when the response was
    /// dropped because the fingerprint is already at its ceiling — the C's silent
    /// `return`, surfaced so a caller can tell.
    ///
    /// The C `assert(resplen)` and `assert(probeName)`: an empty response or a null
    /// name aborts the process. Here an empty response is simply refused.
    pub fn add_response(&mut self, probe_name: &str, resp: &[u8]) -> bool {
        if resp.is_empty() {
            return false;
        }
        // `if (servicefplen > max) return;` -- strictly greater, as the C has it.
        if self.len > self.max_total {
            return false;
        }

        if self.len == 0 {
            let h = &self.header;
            let ssl = if h.ssl_tunnel { "%T=SSL" } else { "" };
            let mut head = String::new();
            let _ = write!(
                head,
                "SF-Port{}-{}:V={}{}%I={}%D={}/{}%Time={:X}%P={}",
                h.port,
                h.proto.as_str(),
                h.version,
                ssl,
                h.intensity,
                h.month,
                h.day,
                h.time,
                h.platform
            );
            self.add_str(&head);
        }

        // The C reports the response's TOTAL length here even though it truncates
        // the bytes below -- "Note that we give the total length of the response,
        // even though we may truncate".
        let mut rec = String::new();
        let _ = write!(rec, "%r({probe_name},{:X},\"", resp.len());
        self.add_str(&rec);

        let used = resp.len().min(self.max_response);
        for i in 0..used {
            let b = resp[i];
            if is_alnum(b) {
                self.add_char(b as char);
            } else if b == 0 {
                // A NUL followed by an ASCII digit has to be spelled in full, or
                // PCRE reads `\0` plus the digit as a different escape.
                let next_is_digit = i
                    .checked_add(1)
                    .and_then(|n| resp.get(n).filter(|_| n < used))
                    .is_some_and(|n| n.is_ascii_digit());
                if next_is_digit {
                    self.add_str("\\x00");
                } else {
                    self.add_str("\\0");
                }
            } else if is_regex_meta(b) {
                self.add_char('\\');
                self.add_char(b as char);
            } else if is_punct(b) {
                self.add_char(b as char);
            } else if b == b'\r' {
                self.add_str("\\r");
            } else if b == b'\n' {
                self.add_str("\\n");
            } else if b == b'\t' {
                self.add_str("\\t");
            } else {
                self.add_char('\\');
                self.add_char('x');
                let mut hex = String::new();
                let _ = write!(hex, "{b:02x}");
                self.add_str(&hex);
            }
        }

        self.add_char('"');
        self.add_char(')');
        true
    }

    /// The finished fingerprint, or `None` if nothing was added.
    ///
    /// Ports `getServiceFingerprint`: a `;` is appended and, as the C comment says,
    /// "is never wrapped" — it goes on unconditionally without the wrap check.
    #[must_use]
    pub fn finish(&self) -> Option<String> {
        if self.len == 0 {
            return None;
        }
        let mut out = self.buf.clone();
        out.push(';');
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> FingerprintHeader {
        FingerprintHeader {
            port: 22,
            proto: Proto::Tcp,
            version: "7.94".to_owned(),
            platform: "x86_64-pc-linux-gnu".to_owned(),
            intensity: 7,
            ssl_tunnel: false,
            month: 8,
            day: 31,
            time: 0x66D3_A1B2,
        }
    }

    /// Remove the `"\nSF:"` continuations so a test can search for a record that
    /// the wrap may have split.
    ///
    /// This is needed more often than it looks. The wrap counts bytes, not fields,
    /// so it lands wherever it lands -- nmap's own output for a 2000-byte response
    /// reads `%r(NULL\nSF:,7D0,"`, with the continuation between the probe name and
    /// the length. Three tests below were written asserting on contiguous
    /// substrings and failed for exactly that reason; the port was right and the
    /// assertions were naive.
    fn unwrapped(s: &str) -> String {
        s.replace("\nSF:", "")
    }

    fn build(responses: &[(&str, &[u8])], debug: bool) -> Option<String> {
        let mut fp = ServiceFingerprint::new(header(), debug);
        for (p, b) in responses {
            fp.add_response(p, b);
        }
        fp.finish()
    }

    #[test]
    fn nothing_added_yields_no_fingerprint() {
        // getServiceFingerprint returns NULL when servicefplen == 0.
        assert_eq!(build(&[], false), None);
        let fp = ServiceFingerprint::new(header(), false);
        assert!(fp.is_empty());
        assert_eq!(fp.len(), 0);
    }

    #[test]
    fn an_empty_response_is_refused_rather_than_asserted_on() {
        // The C does `assert(resplen)`, aborting the process on a response length
        // the scanned host controls.
        let mut fp = ServiceFingerprint::new(header(), false);
        assert!(!fp.add_response("NULL", &[]));
        assert_eq!(fp.finish(), None);
    }

    #[test]
    fn the_header_appears_once_and_the_terminator_once() {
        let out = build(&[("A", b"aa"), ("B", b"bb"), ("C", b"cc")], false).expect("built");
        assert_eq!(out.matches("SF-Port22-TCP").count(), 1);
        assert_eq!(out.matches(';').count(), 1);
        assert!(out.ends_with(';'));
        assert_eq!(out.matches("%r(").count(), 3);
    }

    #[test]
    fn the_reported_length_is_the_total_not_the_truncated_one() {
        // "Note that we give the total length of the response, even though we may
        // truncate" -- a 2000-byte response reports 0x7D0 while escaping 900 bytes.
        let out = build(&[("A", &vec![b'z'; 2000])], false).expect("built");
        assert!(
            unwrapped(&out).contains("%r(A,7D0,"),
            "reported length wrong: {out}"
        );
    }

    #[test]
    fn the_length_is_uppercase_hex() {
        let out = build(&[("A", &vec![b'a'; 255])], false).expect("built");
        assert!(unwrapped(&out).contains("%r(A,FF,"), "{out}");
    }

    #[test]
    fn every_continuation_line_starts_with_the_marker() {
        let out = build(&[("A", &vec![b'a'; 400])], false).expect("built");
        for (n, line) in out.lines().enumerate() {
            if n > 0 {
                assert!(line.starts_with("SF:"), "line {n}: {line:?}");
            }
        }
        assert!(out.lines().count() > 4, "expected several wraps");
    }

    #[test]
    fn a_nul_before_a_digit_is_spelled_in_full() {
        // Otherwise PCRE reads `\0` plus the digit as a different escape.
        let a = build(&[("A", b"\x005")], false).expect("built");
        assert!(a.contains("\\x00"), "{a}");
        let b = build(&[("A", b"\x00a")], false).expect("built");
        assert!(b.contains("\\0") && !b.contains("\\x00"), "{b}");
    }

    #[test]
    fn a_nul_at_the_truncation_edge_does_not_look_ahead_past_it() {
        // The C tests `srcidx + 1 >= respused`, so a digit beyond the cut does not
        // count -- the byte after the window is not part of the response as far as
        // this decision is concerned.
        let mut resp = vec![b'x'; MAX_RESPONSE_BYTES.saturating_sub(1)];
        resp.push(0);
        resp.extend_from_slice(b"5555");
        let out = build(&[("A", &resp)], false).expect("built");
        assert!(
            out.contains("\\0\")"),
            "should end with the short form: {}",
            &out[out.len().saturating_sub(40)..]
        );
    }

    #[test]
    fn regex_metacharacters_are_backslashed_and_other_punctuation_is_not() {
        let out = build(&[("A", b"a.b!c")], false).expect("built");
        assert!(out.contains("a\\.b!c"), "{out}");
    }

    #[test]
    fn non_printable_bytes_become_lowercase_hex_escapes() {
        let out = build(&[("A", b"\x01\xff")], false).expect("built");
        assert!(out.contains("\\x01\\xff"), "{out}");
    }

    #[test]
    fn ssl_and_protocol_show_in_the_header() {
        let mut h = header();
        h.ssl_tunnel = true;
        h.proto = Proto::Udp;
        h.port = 443;
        let mut fp = ServiceFingerprint::new(h, false);
        fp.add_response("A", b"x");
        let out = fp.finish().expect("built");
        assert!(out.starts_with("SF-Port443-UDP:V=7.94%T=SSL%I=7"), "{out}");
    }

    #[test]
    fn responses_stop_being_added_once_the_total_ceiling_is_passed() {
        let mut fp = ServiceFingerprint::new(header(), false);
        let mut accepted: usize = 0;
        for i in 0..20 {
            if fp.add_response(&format!("P{i}"), &vec![b'y'; 400]) {
                accepted = accepted.saturating_add(1);
            }
        }
        assert!(accepted < 20, "ceiling never applied");
        assert!(fp.len() > MAX_TOTAL, "ceiling applied too early");
    }

    #[test]
    fn debug_raises_both_ceilings() {
        let long = vec![b'z'; 1200];
        let normal = build(&[("A", &long)], false).expect("built");
        let debug = build(&[("A", &long)], true).expect("built");
        // Same reported length, more bytes actually escaped under -d.
        assert!(unwrapped(&normal).contains("%r(A,4B0,"));
        assert!(unwrapped(&debug).contains("%r(A,4B0,"));
        assert!(debug.len() > normal.len(), "debug did not escape more");
    }

    #[test]
    fn finish_is_pure() {
        let mut fp = ServiceFingerprint::new(header(), false);
        fp.add_response("A", b"x");
        assert_eq!(fp.finish(), fp.finish());
    }
}
