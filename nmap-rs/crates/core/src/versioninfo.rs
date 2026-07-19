//! Version-string substitution — the Rust analog of the `getVersionStr` /
//! `dotmplsubst` / `substvar` / `transform_cpe` half of `service_scan.cc`.
//!
//! After [`crate::matcher`] finds the `match`/`softmatch` rule that fires on a
//! banner, its capture groups are substituted into that rule's version templates
//! (`p/…/ v/…/ i/…/ h/…/ o/…/ d/…/ cpe:/…/`) to produce the product, version,
//! extra-info, hostname, OS-type, device-type, and CPE strings shown by `-sV`.
//!
//! A template is literal text plus `$` placeholders:
//!
//! - `$N` — insert capture group N (1–9) verbatim.
//! - `$P(N)` — group N, **printable bytes only** (collapses interleaved NULs,
//!   e.g. UTF-16 `W\0O\0R\0K` → `WORK`).
//! - `$SUBST(N,f,r)` — group N with every byte-substring `f` replaced by `r`.
//! - `$I(N,"<"|">")` — group N (≤ 8 bytes) as a little/big-endian unsigned int.
//!
//! CPE templates additionally run every substitution through [`transform_cpe`]
//! (percent-escape the CPE-reserved set, spaces → `_`, lowercase the rest).
//!
//! ## Safer than the C, by construction
//!
//! The banner bytes are **untrusted network input**, and the templates are
//! **untrusted-shaped** (a custom `--versiondb`). The C assembles each field into
//! a fixed stack buffer (`SERVICE_FIELD_LEN`) with `memcpy`/`Snprintf` and bails
//! the whole field on overflow — the same fixed-buffer family that produced the
//! `strcat`/`sprintf` CWE-120 findings elsewhere in `output.cc`. This port builds
//! into a growing `Vec<u8>`, so **there is no fixed destination and no overflow
//! class** (`versioninfo-no-fixed-buffer` in `DIVERGENCES.md`), and every step is
//! **total** — any template + any captures in, an `Option` out, never a panic,
//! never unbounded work.
//!
//! A template that references an absent/out-of-range group (`$5` when 3 groups
//! captured) drops **that field** (returns `None`), matching the C's whole-field
//! failure — the *service name still stands*, only the decoration is omitted.

use crate::probedb::MatchRule;

/// The substituted `-sV` fields for one match. Byte-faithful: values are raw
/// bytes (a capture may contain non-UTF-8), escaped for display by the output
/// layer, exactly as the C keeps them as `char*`. `None` = the rule had no such
/// template, or substitution failed (absent group).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VersionInfo {
    pub product: Option<Vec<u8>>,
    pub version: Option<Vec<u8>>,
    pub info: Option<Vec<u8>>,
    pub hostname: Option<Vec<u8>>,
    pub ostype: Option<Vec<u8>>,
    pub devicetype: Option<Vec<u8>>,
    /// CPE for an application (`cpe:/a:…`).
    pub cpe_a: Option<Vec<u8>>,
    /// CPE for hardware (`cpe:/h:…`).
    pub cpe_h: Option<Vec<u8>>,
    /// CPE for an OS (`cpe:/o:…`).
    pub cpe_o: Option<Vec<u8>>,
}

/// Build the [`VersionInfo`] for a fired rule from its capture groups.
/// `captures[0]` is the whole match; `captures[1..]` are the numbered groups (a
/// `None` entry is an unset optional group). Mirrors `ServiceProbeMatch::getVersionStr`.
pub fn build(rule: &MatchRule, captures: &[Option<Vec<u8>>]) -> VersionInfo {
    let sub = |tmpl: &Option<String>| {
        tmpl.as_ref()
            .and_then(|t| dotmplsubst(t, captures, false))
            .filter(|v| !v.is_empty())
    };
    let mut vi = VersionInfo {
        product: sub(&rule.product),
        version: sub(&rule.version),
        info: sub(&rule.info),
        hostname: sub(&rule.hostname),
        ostype: sub(&rule.ostype),
        devicetype: sub(&rule.devicetype),
        ..VersionInfo::default()
    };

    // CPE templates: the part letter after `cpe:/` picks the a/h/o field; each is
    // filled with the CPE transform applied to every substitution.
    for tmpl in &rule.cpe {
        let Some(part) = cpe_get_part(tmpl) else {
            continue; // unknown part → ignore (C warns and skips)
        };
        let Some(filled) = dotmplsubst(tmpl, captures, true).filter(|v| !v.is_empty()) else {
            continue;
        };
        match part {
            b'a' => vi.cpe_a = Some(filled),
            b'h' => vi.cpe_h = Some(filled),
            b'o' => vi.cpe_o = Some(filled),
            _ => {}
        }
    }
    vi
}

/// Walk a template, copying literal text and expanding `$` placeholders. When
/// `cpe_transform` is set, every substituted value is passed through
/// [`transform_cpe`]. Trailing whitespace and commas are trimmed (as the C does).
/// Returns `None` if any placeholder fails (absent group / bad command).
fn dotmplsubst(tmpl: &str, captures: &[Option<Vec<u8>>], cpe_transform: bool) -> Option<Vec<u8>> {
    let b = tmpl.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'$' {
            let (value, consumed) = substvar(&b[i..], captures)?;
            let value = if cpe_transform {
                transform_cpe(&value)
            } else {
                value
            };
            out.extend_from_slice(&value);
            i = i.saturating_add(consumed);
        } else {
            out.push(b[i]);
            i = i.saturating_add(1);
        }
    }
    // Trim trailing whitespace and commas.
    while matches!(out.last(), Some(c) if c.is_ascii_whitespace() || *c == b',') {
        out.pop();
    }
    Some(out)
}

/// Expand one `$…` placeholder at the start of `s`. Returns the substituted bytes
/// and the number of bytes consumed from `s`, or `None` on failure. Mirrors
/// `substvar`.
fn substvar(s: &[u8], captures: &[Option<Vec<u8>>]) -> Option<(Vec<u8>, usize)> {
    // s[0] == '$'
    if s.first() != Some(&b'$') {
        return None;
    }
    let after = s.get(1)?;
    if after.is_ascii_digit() {
        // `$N` — plain group insertion.
        let n = usize::from(after.wrapping_sub(b'0'));
        let group = group_bytes(captures, n)?;
        return Some((group.to_vec(), 2));
    }

    // A command like `$P(…)` / `$SUBST(…)` / `$I(…)`.
    // Command name = ASCII letters up to '('.
    let mut j = 1usize;
    while s.get(j).is_some_and(|c| c.is_ascii_alphabetic()) {
        j = j.saturating_add(1);
    }
    if s.get(j) != Some(&b'(') {
        return None;
    }
    let command = &s[1..j];
    // Parse the parenthesized, comma-separated args.
    let (args, after_paren) = parse_args(&s[j.saturating_add(1)..])?;
    let consumed = j.saturating_add(1).saturating_add(after_paren);

    let value = match command {
        b"P" => {
            let [Arg::Int(n)] = args.as_slice() else {
                return None;
            };
            let group = group_bytes(captures, usize::try_from(*n).ok()?)?;
            // Printable bytes only.
            group
                .iter()
                .copied()
                .filter(u8::is_ascii_graphic_or_space)
                .collect()
        }
        b"SUBST" => {
            let [Arg::Int(n), Arg::Str(find), Arg::Str(repl)] = args.as_slice() else {
                return None;
            };
            let group = group_bytes(captures, usize::try_from(*n).ok()?)?;
            subst_bytes(group, find, repl)
        }
        b"I" => {
            let [Arg::Int(n), Arg::Str(endian)] = args.as_slice() else {
                return None;
            };
            if endian.len() != 1 {
                return None;
            }
            let group = group_bytes(captures, usize::try_from(*n).ok()?)?;
            decode_int(group, endian[0])?.to_string().into_bytes()
        }
        _ => return None, // unknown command
    };
    Some((value, consumed))
}

/// Fetch capture group `n` (1..=9) as bytes, or `None` if `n` is out of range or
/// the group is unset. Group 0 (whole match) is not a valid substitution target
/// (C requires `subnum > 0`).
fn group_bytes(captures: &[Option<Vec<u8>>], n: usize) -> Option<&[u8]> {
    if !(1..=9).contains(&n) {
        return None;
    }
    captures.get(n)?.as_deref()
}

/// Byte-substring replace: every non-overlapping occurrence of `find` in `hay` is
/// replaced by `repl`, left to right (mirrors the C `$SUBST` loop). An empty
/// `find` copies `hay` unchanged (the C would advance one byte at a time).
fn subst_bytes(hay: &[u8], find: &[u8], repl: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0usize;
    while i < hay.len() {
        if !find.is_empty() && hay[i..].starts_with(find) {
            out.extend_from_slice(repl);
            i = i.saturating_add(find.len());
        } else {
            out.push(hay[i]);
            i = i.saturating_add(1);
        }
    }
    out
}

/// Interpret up to 8 bytes as an unsigned integer, big-endian (`>`) or
/// little-endian (`<`). `None` if > 8 bytes or the endianness byte is invalid.
fn decode_int(bytes: &[u8], endian: u8) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut val: u64 = 0;
    match endian {
        b'>' => {
            for &byte in bytes {
                // ≤ 8 bytes → the shifts fill at most 64 bits, never overflow.
                val = val.wrapping_shl(8) | u64::from(byte);
            }
        }
        b'<' => {
            for &byte in bytes.iter().rev() {
                val = val.wrapping_shl(8) | u64::from(byte);
            }
        }
        _ => return None,
    }
    Some(val)
}

/// One parsed `$SUBST`/`$I`/`$P` argument.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Arg {
    Int(i64),
    Str(Vec<u8>),
}

/// Parse comma-separated args up to and including the closing `)`. Returns the
/// args and the number of bytes consumed (past the `)`). Mirrors
/// `getsubstcommandargs`: quoted strings (with the strict `cstring_unescape`
/// escape set) or `strtol(base 0)` integers.
fn parse_args(s: &[u8]) -> Option<(Vec<Arg>, usize)> {
    let mut args = Vec::new();
    let mut i = 0usize;
    loop {
        // Skip whitespace.
        while s.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        match s.get(i) {
            None => return None, // unterminated
            Some(&b')') => return Some((args, i.saturating_add(1))),
            Some(&b'"') => {
                // Quoted string: consume to the closing unescaped quote.
                i = i.saturating_add(1);
                let start = i;
                while let Some(&c) = s.get(i) {
                    if c == b'"' {
                        break;
                    }
                    // Skip an escaped byte so `\"` doesn't end the string.
                    if c == b'\\' {
                        i = i.saturating_add(1);
                    }
                    i = i.saturating_add(1);
                }
                if s.get(i) != Some(&b'"') {
                    return None; // unterminated string
                }
                let raw = &s[start..i];
                i = i.saturating_add(1); // past closing quote
                args.push(Arg::Str(cstring_unescape(raw)?));
            }
            Some(_) => {
                // Integer via strtol(base 0): sign, 0x hex / 0 octal / decimal.
                let (val, consumed) = strtol0(&s[i..])?;
                if consumed == 0 {
                    return None;
                }
                i = i.saturating_add(consumed);
                args.push(Arg::Int(val));
            }
        }
        // After an arg: skip whitespace, expect ',' or ')'.
        while s.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        match s.get(i) {
            Some(&b',') => i = i.saturating_add(1),
            Some(&b')') => return Some((args, i.saturating_add(1))),
            _ => return None,
        }
    }
}

/// `strtol(_, _, 0)` prefix: optional sign, then `0x`/`0X` hex, `0` octal, or
/// decimal. Returns the value and bytes consumed (0 if no digits).
fn strtol0(s: &[u8]) -> Option<(i64, usize)> {
    let mut i = 0usize;
    let mut neg = false;
    match s.first() {
        Some(&b'+') => i = 1,
        Some(&b'-') => {
            neg = true;
            i = 1;
        }
        _ => {}
    }
    let (radix, digits_start) = if s.get(i) == Some(&b'0') {
        match s.get(i.saturating_add(1)) {
            Some(&b'x') | Some(&b'X') => (16u32, i.saturating_add(2)),
            _ => (8u32, i), // leading 0 → octal (the '0' itself is a valid digit)
        }
    } else {
        (10u32, i)
    };
    let mut j = digits_start;
    let mut val: i64 = 0;
    while let Some(d) = s.get(j).and_then(|c| (*c as char).to_digit(radix)) {
        val = val
            .saturating_mul(i64::from(radix))
            .saturating_add(i64::from(d));
        j = j.saturating_add(1);
    }
    if j == digits_start {
        // No digits — but a lone "0" (octal path with digits_start==i) is valid.
        if radix == 8 && s.get(i) == Some(&b'0') {
            return Some((0, i.saturating_add(1)));
        }
        return None;
    }
    Some((if neg { val.saturating_neg() } else { val }, j))
}

/// The strict probe-string escape set (`cstring_unescape`, `utils.cc`): `\\ \0 \n
/// \r \t \xHH`. Any other escape → `None`. Ported locally to keep `versioninfo`
/// independent of `probedb`'s private copy.
fn cstring_unescape(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == b'\\' {
            match s.get(i.saturating_add(1))? {
                b'\\' => out.push(b'\\'),
                b'0' => out.push(0),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'x' => {
                    let hi = hex_val(*s.get(i.saturating_add(2))?)?;
                    let lo = hex_val(*s.get(i.saturating_add(3))?)?;
                    out.push(hi.wrapping_mul(16).wrapping_add(lo));
                    i = i.saturating_add(4);
                    continue;
                }
                _ => return None,
            }
            i = i.saturating_add(2);
        } else {
            out.push(s[i]);
            i = i.saturating_add(1);
        }
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Percent-escape a substituted value for insertion into a CPE URL
/// (`transform_cpe`, `service_scan.cc:684`): the CPE-reserved punctuation set →
/// `%XX`, whitespace → `_`, everything else lower-cased.
fn transform_cpe(s: &[u8]) -> Vec<u8> {
    const RESERVED: &[u8] = b":/?#[]@!$&'()*+,;=%<>\"";
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if RESERVED.contains(&c) {
            out.push(b'%');
            out.push(hex_digit(c >> 4));
            out.push(hex_digit(c & 0x0f));
        } else if c.is_ascii_whitespace() {
            out.push(b'_');
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0'.wrapping_add(nibble),
        _ => b'A'.wrapping_add(nibble.wrapping_sub(10)),
    }
}

/// The CPE part letter (`a`/`h`/`o`) right after the `cpe:/` prefix, or `None`.
/// Mirrors `cpe_get_part` (`utils.cc:499`).
fn cpe_get_part(cpe: &str) -> Option<u8> {
    let rest = cpe.strip_prefix("cpe:/")?;
    match rest.bytes().next() {
        Some(p @ (b'a' | b'h' | b'o')) => Some(p),
        _ => None,
    }
}

/// Helper: printable ASCII byte (graphic or a plain space) — the `$P` filter
/// (`isprint`).
trait AsciiPrintable {
    fn is_ascii_graphic_or_space(&self) -> bool;
}
impl AsciiPrintable for u8 {
    fn is_ascii_graphic_or_space(&self) -> bool {
        self.is_ascii_graphic() || *self == b' '
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(groups: &[&[u8]]) -> Vec<Option<Vec<u8>>> {
        groups.iter().map(|g| Some(g.to_vec())).collect()
    }

    fn rule_with(templates: &[(&str, &str)]) -> MatchRule {
        let mut r = MatchRule {
            service: "svc".into(),
            pattern: "^x".into(),
            ..MatchRule::default()
        };
        for (k, v) in templates {
            match *k {
                "p" => r.product = Some((*v).into()),
                "v" => r.version = Some((*v).into()),
                "i" => r.info = Some((*v).into()),
                "h" => r.hostname = Some((*v).into()),
                "o" => r.ostype = Some((*v).into()),
                "d" => r.devicetype = Some((*v).into()),
                "cpe" => r.cpe.push((*v).into()),
                _ => {}
            }
        }
        r
    }

    #[test]
    fn plain_placeholder() {
        // captures[0]=whole, [1]="2.0", [2]="OpenSSH"
        let c = caps(&[b"whole", b"2.0", b"OpenSSH"]);
        assert_eq!(dotmplsubst("$2", &c, false).unwrap(), b"OpenSSH");
        assert_eq!(dotmplsubst("v$1 x", &c, false).unwrap(), b"v2.0 x");
    }

    #[test]
    fn literal_text_only() {
        let c = caps(&[b"m"]);
        assert_eq!(
            dotmplsubst("Apache httpd", &c, false).unwrap(),
            b"Apache httpd"
        );
    }

    #[test]
    fn absent_group_drops_field() {
        let c = caps(&[b"whole", b"1.0"]); // only group 1
        assert_eq!(dotmplsubst("$2", &c, false), None);
        assert_eq!(dotmplsubst("$9", &c, false), None);
    }

    #[test]
    fn trailing_ws_and_commas_trimmed() {
        let c = caps(&[b"whole", b"X"]);
        assert_eq!(dotmplsubst("$1, ,  ", &c, false).unwrap(), b"X");
    }

    #[test]
    fn printable_filter_collapses_nuls() {
        // UTF-16-ish "W\0O\0R\0K" → "WORK".
        let c = caps(&[b"whole", b"W\x00O\x00R\x00K"]);
        assert_eq!(dotmplsubst("$P(1)", &c, false).unwrap(), b"WORK");
    }

    #[test]
    fn subst_replaces_substring() {
        let c = caps(&[b"whole", b"a.b.c"]);
        assert_eq!(
            dotmplsubst(r#"$SUBST(1,".","_")"#, &c, false).unwrap(),
            b"a_b_c"
        );
    }

    #[test]
    fn subst_multichar_find_and_repl() {
        let c = caps(&[b"whole", b"xxABxxABxx"]);
        assert_eq!(
            dotmplsubst(r#"$SUBST(1,"AB","Q")"#, &c, false).unwrap(),
            b"xxQxxQxx"
        );
    }

    #[test]
    fn int_big_and_little_endian() {
        // group 1 = bytes 01 02 (0x0102 BE = 258; LE = 0x0201 = 513)
        let c = caps(&[b"whole", b"\x01\x02"]);
        assert_eq!(dotmplsubst(r#"$I(1,">")"#, &c, false).unwrap(), b"258");
        assert_eq!(dotmplsubst(r#"$I(1,"<")"#, &c, false).unwrap(), b"513");
    }

    #[test]
    fn int_rejects_over_8_bytes() {
        let c = caps(&[b"whole", b"123456789"]); // 9 bytes
        assert_eq!(dotmplsubst(r#"$I(1,">")"#, &c, false), None);
    }

    #[test]
    fn subst_arg_escapes() {
        // find = "\x00" (a NUL), repl = "-"
        let c = caps(&[b"whole", b"a\x00b\x00c"]);
        assert_eq!(
            dotmplsubst(r#"$SUBST(1,"\x00","-")"#, &c, false).unwrap(),
            b"a-b-c"
        );
    }

    #[test]
    fn cpe_transform_escapes_and_lowercases() {
        // A space → '_', '/' → %2F, letters lowercased.
        let c = caps(&[b"whole", b"My App/2"]);
        assert_eq!(
            dotmplsubst("cpe:/a:vendor:$1", &c, true).unwrap(),
            b"cpe:/a:vendor:my_app%2F2".to_vec()
        );
    }

    #[test]
    fn cpe_get_part_reads_letter() {
        assert_eq!(cpe_get_part("cpe:/a:v:p"), Some(b'a'));
        assert_eq!(cpe_get_part("cpe:/o:linux:linux_kernel"), Some(b'o'));
        assert_eq!(cpe_get_part("cpe:/h:x"), Some(b'h'));
        assert_eq!(cpe_get_part("cpe:/x:bad"), None);
        assert_eq!(cpe_get_part("not-cpe"), None);
    }

    #[test]
    fn build_full_versioninfo() {
        let rule = rule_with(&[
            ("p", "OpenSSH"),
            ("v", "$2"),
            ("i", "protocol $1"),
            ("o", "Unix"),
            ("cpe", "cpe:/a:openbsd:openssh:$2"),
        ]);
        // group1="2.0" (protocol), group2="9.6" (version)
        let c = caps(&[b"whole", b"2.0", b"9.6"]);
        let vi = build(&rule, &c);
        assert_eq!(vi.product.as_deref(), Some(&b"OpenSSH"[..]));
        assert_eq!(vi.version.as_deref(), Some(&b"9.6"[..]));
        assert_eq!(vi.info.as_deref(), Some(&b"protocol 2.0"[..]));
        assert_eq!(vi.ostype.as_deref(), Some(&b"Unix"[..]));
        assert_eq!(
            vi.cpe_a.as_deref(),
            Some(&b"cpe:/a:openbsd:openssh:9.6"[..])
        );
        assert!(vi.cpe_h.is_none());
    }

    #[test]
    fn build_drops_field_with_bad_capture_but_keeps_others() {
        // version references $2 which is absent → version dropped, product kept.
        let rule = rule_with(&[("p", "Prod"), ("v", "$2")]);
        let c = caps(&[b"whole", b"1"]); // only group 1
        let vi = build(&rule, &c);
        assert_eq!(vi.product.as_deref(), Some(&b"Prod"[..]));
        assert!(vi.version.is_none());
    }

    #[test]
    fn total_on_adversarial_templates() {
        let c = caps(&[b"whole", b"g1"]);
        for t in [
            "$",
            "$(",
            "$P(",
            "$P()",
            "$SUBST(1)",
            "$I(1)",
            "$Z(1)",
            "$99",
            "$0",
            "$P(1",
            r#"$SUBST(1,"unterminated"#,
            "$I(1,\"\")",
            "cpe:/",
        ] {
            // Never panics; either substitutes or returns None.
            let _ = dotmplsubst(t, &c, false);
            let _ = dotmplsubst(t, &c, true);
        }
    }

    #[test]
    fn strtol0_bases() {
        assert_eq!(strtol0(b"10)").unwrap().0, 10);
        assert_eq!(strtol0(b"0x1f)").unwrap().0, 31);
        assert_eq!(strtol0(b"010)").unwrap().0, 8);
        assert_eq!(strtol0(b"0)").unwrap().0, 0);
        assert_eq!(strtol0(b"-5)").unwrap().0, -5);
    }
}
