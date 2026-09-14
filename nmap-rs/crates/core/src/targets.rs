//! Target-spec parsing & expansion — the Rust analog of nmap's `NetBlock`
//! parsing (`libnetutil/NetBlock.cc` `parse_ipv4_ranges` / `split_netmask` /
//! `apply_ipv4_netmask`) and `TargetGroup` iteration.
//!
//! Handles numeric IPv4 with octet ranges, wildcards, and CIDR
//! (`10.1.0-5.1-254`, `192.168.0.*`, `10.0.0.0/24`), single numeric IPv6, and
//! bare hostnames (resolution itself is `nmap-sys`'s job — this module only
//! *classifies* the spec and, for IPv4, expands it).
//!
//! Two safety properties this module must hold (the fuzz gate proves them):
//!   1. **Never panics** on arbitrary input — every failure is a typed `Err`.
//!   2. **Never materializes** a huge address set — IPv4 expansion is a lazy
//!      iterator (a `/0` is 2³² hosts), matching `NetBlockIPv4Ranges::next`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The set of allowed values (0..=255) for one IPv4 octet — the analog of C's
/// `octet_bitvector`. A plain bool array keeps the netmask bit-mirror algorithm
/// (below) transparent and index-safe in a `#![forbid(unsafe_code)]` crate.
#[derive(Clone, Copy, PartialEq, Eq)]
struct OctetSet {
    bits: [bool; 256],
}

impl OctetSet {
    fn empty() -> Self {
        Self { bits: [false; 256] }
    }

    fn set_range(&mut self, start: usize, end: usize) {
        // Caller guarantees start <= end <= 255.
        for v in start..=end {
            self.bits[v] = true;
        }
    }

    fn is_set(&self, v: usize) -> bool {
        self.bits[v]
    }

    /// Values that are set, ascending — the per-octet iteration order.
    fn values(&self) -> Vec<u8> {
        (0u8..=255).filter(|&v| self.bits[usize::from(v)]).collect()
    }
}

impl std::fmt::Debug for OctetSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OctetSet({} values)", self.values().len())
    }
}

/// A numeric IPv4 spec: four octet value-sets. Its cross product (outer =
/// octet 0, inner = octet 3) is the address list, produced lazily by [`iter`].
///
/// [`iter`]: Ipv4Ranges::iter
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Ranges {
    octets: [OctetSet; 4],
}

impl Ipv4Ranges {
    /// Number of addresses this spec expands to (product of the four set
    /// sizes). `u64` because a `/0` (`0.0.0.0/0`) is 2³² hosts.
    pub fn count(&self) -> u64 {
        self.octets
            .iter()
            .map(|o| o.values().len() as u64)
            .product()
    }

    /// Is `ip` inside this spec?
    ///
    /// Deliberately a per-octet membership test rather than a scan of `iter()`:
    /// a spec may cover 2³² addresses (`0.0.0.0/0`), and the exclusion filter
    /// calls this once per target, so expanding here would turn a legitimate
    /// `--exclude 0.0.0.0/0` into a hang. Constant time, no allocation.
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let o = ip.octets();
        (0..4).all(|i| self.octets[i].is_set(usize::from(o[i])))
    }

    /// A spec matching exactly one address — used when a hostname exclusion has
    /// been resolved to concrete addresses.
    #[must_use]
    pub fn single(ip: Ipv4Addr) -> Self {
        let o = ip.octets();
        let mut octets = [OctetSet::empty(); 4];
        for i in 0..4 {
            octets[i].set_range(usize::from(o[i]), usize::from(o[i]));
        }
        Self { octets }
    }

    /// Lazily yield every address, octet 0 slowest-changing and octet 3
    /// fastest — the order of `NetBlockIPv4Ranges::next`.
    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        let lists = [
            self.octets[0].values(),
            self.octets[1].values(),
            self.octets[2].values(),
            self.octets[3].values(),
        ];
        Ipv4RangesIter::new(lists)
    }

    /// Apply a CIDR netmask (`/bits`) to the parsed octets. Mirrors
    /// `NetBlockIPv4Ranges::apply_netmask` + `apply_ipv4_netmask`: for every
    /// host bit (a 0 in the mask), the set bits are mirrored across the
    /// corresponding power-of-two chunk boundary, filling in all host-bit
    /// combinations. `bits > 32` is treated as `/32` (nmap warns and does the
    /// same); `bits < 0` (no netmask) is `/32` (a no-op).
    // bits is clamped to 0..=32; the shift branch runs only when bits != 0, so the
    // shift amount is 1..=31 (never the UB over-shift of 32). Bounded, no overflow.
    #[allow(clippy::arithmetic_side_effects)]
    fn apply_netmask(&mut self, bits: i64) {
        let bits = if !(0..=32).contains(&bits) { 32 } else { bits };
        let mask: u32 = if bits == 0 {
            0
        } else {
            0xFFFF_FFFFu32 << (32 - bits)
        };
        // Each byte of the mask is 0..=255, so `as usize` here only widens.
        apply_ipv4_netmask_octet(&mut self.octets[0], ((mask >> 24) & 0xFF) as usize);
        apply_ipv4_netmask_octet(&mut self.octets[1], ((mask >> 16) & 0xFF) as usize);
        apply_ipv4_netmask_octet(&mut self.octets[2], ((mask >> 8) & 0xFF) as usize);
        apply_ipv4_netmask_octet(&mut self.octets[3], (mask & 0xFF) as usize);
    }
}

/// One octet's netmask expansion — a direct port of `apply_ipv4_netmask_octet`.
/// `mask` is the single mask byte for this octet (0..=255).
// All arithmetic is over bounded octet indices: chunk_size ∈ {1,2,…,128},
// i,j < 256, and i+j+chunk_size ≤ 256 by the loop invariants — no overflow.
#[allow(clippy::arithmetic_side_effects)]
fn apply_ipv4_netmask_octet(octet: &mut OctetSet, mask: usize) {
    let mut chunk_size: usize = 1;
    while chunk_size < 256 {
        if (mask & chunk_size) != 0 {
            chunk_size <<= 1;
            continue;
        }
        let mut i: usize = 0;
        while i < 256 {
            for j in 0..chunk_size {
                let a = i + j;
                let b = i + j + chunk_size;
                if octet.is_set(a) {
                    octet.bits[b] = true;
                } else if octet.is_set(b) {
                    octet.bits[a] = true;
                }
            }
            i += chunk_size * 2;
        }
        chunk_size <<= 1;
    }
}

/// Lazy 4-level odometer over the per-octet value lists (octet 3 fastest).
struct Ipv4RangesIter {
    lists: [Vec<u8>; 4],
    idx: [usize; 4],
    done: bool,
}

impl Ipv4RangesIter {
    fn new(lists: [Vec<u8>; 4]) -> Self {
        let done = lists.iter().any(|l| l.is_empty());
        Self {
            lists,
            idx: [0; 4],
            done,
        }
    }
}

impl Iterator for Ipv4RangesIter {
    type Item = Ipv4Addr;

    // idx[p] is bounded by lists[p].len() ≤ 256; the +1 increments can't overflow.
    #[allow(clippy::arithmetic_side_effects)]
    fn next(&mut self) -> Option<Ipv4Addr> {
        if self.done {
            return None;
        }
        let addr = Ipv4Addr::new(
            self.lists[0][self.idx[0]],
            self.lists[1][self.idx[1]],
            self.lists[2][self.idx[2]],
            self.lists[3][self.idx[3]],
        );
        // Increment odometer: octet 3 fastest, carry toward octet 0.
        let mut carried = true;
        for p in (0..4).rev() {
            self.idx[p] += 1;
            if self.idx[p] < self.lists[p].len() {
                carried = false;
                break;
            }
            self.idx[p] = 0;
        }
        if carried {
            self.done = true;
        }
        Some(addr)
    }
}

/// A classified target expression, ready for scanning. Hostname resolution and
/// IPv6 range expansion beyond a single address are `nmap-sys`/later-milestone
/// concerns; M1 needs exactly these three shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetSpec {
    /// Numeric IPv4 with optional ranges/wildcards/CIDR — expand via `iter()`.
    /// Boxed because the four 256-entry octet sets are large relative to the
    /// other variants.
    Ipv4(Box<Ipv4Ranges>),
    /// A single numeric IPv6 address (M1 does not expand IPv6 CIDR/ranges).
    Ipv6(Ipv6Addr),
    /// A name to resolve (resolution happens in `nmap-sys`). Any `/mask` is
    /// carried here and applied *after* resolution, matching nmap's
    /// `NetBlockHostname` — never dropped.
    Hostname {
        name: String,
        /// The `/bits` netmask, if the expression had one.
        netmask_bits: Option<u32>,
    },
}

/// Why a target expression could not be parsed. Typed, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetParseError {
    /// Empty expression.
    Empty,
    /// A `/mask` that is not a non-negative integer.
    BadNetmask,
    /// Looks like IPv6 but IPv6 was not requested (nmap: "use the -6 option").
    Ipv6NotEnabled,
    /// An IPv6 address with a non-`/128` netmask. Milestone 1 does not expand
    /// IPv6 ranges; we reject rather than silently scan a single address.
    Ipv6RangeUnsupported,
}

/// Parse one target expression into a [`TargetSpec`]. `want_ipv6` mirrors nmap's
/// `-6` flag: a numeric IPv6 literal is only accepted when it is set.
///
/// `expr` is expected to be a single, already-trimmed token (the CLI / `-iL`
/// reader splits and trims before calling this, exactly as the C tokenizes the
/// host expression before `parse_ipv4_ranges`). Leading/trailing whitespace is
/// therefore treated as part of the token (and makes it a non-numeric name).
///
/// Total over all `&str` inputs: returns `Ok` or a typed `Err`, never panics.
pub fn parse_target(expr: &str, want_ipv6: bool) -> Result<TargetSpec, TargetParseError> {
    if expr.is_empty() {
        return Err(TargetParseError::Empty);
    }

    let (host, bits) = split_netmask(expr)?;

    // 1. Numeric IPv4 with ranges/wildcards?
    if let Some(octets) = parse_ipv4_ranges(host) {
        let mut ranges = Ipv4Ranges { octets };
        // For IPv4, bits > 32 is treated as /32 (nmap warns and does the same);
        // no netmask means /32.
        let applied = match bits {
            Some(b) if b <= 32 => b as i64,
            Some(_) => 32,
            None => -1,
        };
        ranges.apply_netmask(applied);
        return Ok(TargetSpec::Ipv4(Box::new(ranges)));
    }

    // 2. Numeric IPv6 literal?
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        if !want_ipv6 {
            return Err(TargetParseError::Ipv6NotEnabled);
        }
        // A non-/128 mask would denote an IPv6 range, which M1 does not expand.
        // Reject rather than silently scanning just this one address.
        if matches!(bits, Some(b) if b != 128) {
            return Err(TargetParseError::Ipv6RangeUnsupported);
        }
        return Ok(TargetSpec::Ipv6(v6));
    }

    // 3. Otherwise a hostname to resolve later — carry any netmask through so
    // it can be applied post-resolution (nmap's NetBlockHostname behavior).
    Ok(TargetSpec::Hostname {
        name: host.to_string(),
        netmask_bits: bits,
    })
}

/// Split the trailing `/bits` off an expression (on the LAST `/`, like
/// `strrchr`). Returns `(host, Some(bits))`, or `(expr, None)` when there is no
/// slash. `bits` must be a whole non-negative integer that consumes the rest of
/// the string, else [`TargetParseError::BadNetmask`]. Mirrors `split_netmask`.
fn split_netmask(expr: &str) -> Result<(&str, Option<u32>), TargetParseError> {
    match expr.rfind('/') {
        None => Ok((expr, None)),
        Some(pos) => {
            // split_at avoids index arithmetic; slash_tail starts with '/'.
            let (host, slash_tail) = expr.split_at(pos);
            let tail = &slash_tail[1..];
            if tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
                return Err(TargetParseError::BadNetmask);
            }
            // Parse with saturation: an absurdly long run of digits is a bad
            // mask anyway; treat overflow as "too big" (caller clamps >32).
            let bits: u32 = tail.parse().unwrap_or(u32::MAX);
            Ok((host, Some(bits)))
        }
    }
}

/// Parse an IPv4 address with optional ranges and wildcards into four octet
/// sets. Each octet matches `(\*|#?(-#?)?(,#?(-#?)?)*)` where `#` is 0..=255.
/// Returns `None` on any parse error (the C returns -1). A direct, index-safe
/// port of `parse_ipv4_ranges`.
// Cursor `p` only ever advances and is bounded by `b.len()`; `octet_index` ≤ 4.
// All indexing goes through `b.get(..)`, so the arithmetic can't cause OOB.
#[allow(clippy::arithmetic_side_effects)]
fn parse_ipv4_ranges(spec: &str) -> Option<[OctetSet; 4]> {
    let b = spec.as_bytes();
    let mut octets = [OctetSet::empty(); 4];
    let mut p = 0usize;
    let mut octet_index = 0usize;

    while p < b.len() && octet_index < 4 {
        if b[p] == b'*' {
            octets[octet_index].set_range(0, 255);
            p += 1;
        } else {
            loop {
                // Parse the (possibly left-open) range start.
                let (start_opt, tail) = parse_uint(b, p);
                let start = match start_opt {
                    Some(v) => v,
                    None => {
                        if b.get(p) == Some(&b'-') {
                            0
                        } else {
                            return None;
                        }
                    }
                };
                if start > 255 {
                    return None;
                }
                p = tail;

                // Optional range end.
                let end = if b.get(p) == Some(&b'-') {
                    p += 1;
                    let (end_opt, tail2) = parse_uint(b, p);
                    let end = end_opt.unwrap_or(255); // open on the right
                    if end > 255 || end < start {
                        return None;
                    }
                    p = tail2;
                    end
                } else {
                    start
                };

                octets[octet_index].set_range(start, end);

                if b.get(p) != Some(&b',') {
                    break;
                }
                p += 1;
            }
        }
        octet_index += 1;
        if octet_index < 4 {
            if b.get(p) != Some(&b'.') {
                return None;
            }
            p += 1;
        }
    }

    if p != b.len() || octet_index < 4 {
        return None;
    }
    Some(octets)
}

/// Parse a run of ASCII decimal digits at `pos`. Returns `(Some(value),
/// new_pos)` if digits were consumed, else `(None, pos)`. On numeric overflow it
/// saturates (a value `> 255`) so the caller rejects it. Never panics; never
/// indexes out of bounds.
// `i` advances by 1 per digit, bounded by `b.len()`; `acc` uses saturating ops.
#[allow(clippy::arithmetic_side_effects)]
fn parse_uint(b: &[u8], pos: usize) -> (Option<usize>, usize) {
    let mut i = pos;
    let mut acc: usize = 0;
    let mut saw = false;
    while i < b.len() && b[i].is_ascii_digit() {
        saw = true;
        acc = acc
            .saturating_mul(10)
            .saturating_add(usize::from(b[i] - b'0'));
        i += 1;
    }
    if saw {
        (Some(acc), i)
    } else {
        (None, pos)
    }
}

/// Longest host specification accepted from a list file, matching the C's
/// `char host_spec[1024]` in `read_host_from_file` / `grab_next_host_spec`.
/// The C calls `fatal()` when a token reaches this; so do we, via a typed error
/// — silently truncating a spec would scan an address nobody named.
pub const MAX_HOST_SPEC: usize = 1024;

/// Why a `-iL` / `--excludefile` list could not be tokenized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostListError {
    /// A token reached [`MAX_HOST_SPEC`] bytes. C: `fatal("One of the host
    /// specifications from your input file is too long")`.
    SpecTooLong {
        /// Index of the offending token.
        index: usize,
    },
    /// A token was not valid UTF-8. The C reads bytes and lets the address
    /// parser reject it later; we reject here rather than lossily substituting,
    /// because a replacement character would turn a malformed spec into a
    /// *different* spec instead of an error.
    NotUtf8 {
        /// Index of the offending token.
        index: usize,
    },
}

/// Split a `-iL` / `--excludefile` list into host specifications.
///
/// A direct port of `read_host_from_file` (`libnetutil/netutil.cc:3750`), which
/// both flags share in the C. The rules are not the obvious "one per line":
///
///   * separators are space, `\r`, `\n`, `\t` and NUL (`is_host_separator`), so
///     several specs may sit on one line;
///   * `#` begins a comment that runs to the end of the line, and it terminates
///     the current token *without* needing a separator first — `10.0.0.1#hi`
///     yields `10.0.0.1`;
///   * runs of separators and comments are skipped together, so blank and
///     comment-only lines cost nothing.
///
/// Takes bytes rather than `&str` because the C reads bytes and a list file is
/// operator-supplied but not necessarily well-formed; a non-UTF-8 token is a
/// typed error rather than a lossy substitution.
///
/// Total: returns `Ok` or a typed `Err` for any input, and never panics.
pub fn host_specs(text: &[u8]) -> Result<Vec<&str>, HostListError> {
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0usize;
    let is_sep = |c: u8| c == b' ' || c == b'\r' || c == b'\n' || c == b'\t' || c == 0;

    while i < text.len() {
        // Skip separators and whole comments, in any interleaving.
        loop {
            if i < text.len() && text[i] == b'#' {
                while i < text.len() && text[i] != b'\n' {
                    i = i.saturating_add(1);
                }
            } else if i < text.len() && is_sep(text[i]) {
                i = i.saturating_add(1);
            } else {
                break;
            }
        }
        if i >= text.len() {
            break;
        }
        let start = i;
        while i < text.len() && !is_sep(text[i]) && text[i] != b'#' {
            i = i.saturating_add(1);
        }
        let tok = &text[start..i];
        // `>=`, not `>`: the C's check is `n >= sizeof(host_spec)`, because a
        // token of exactly 1024 bytes leaves no room for its NUL.
        if tok.len() >= MAX_HOST_SPEC {
            return Err(HostListError::SpecTooLong { index: out.len() });
        }
        match std::str::from_utf8(tok) {
            Ok(s) => out.push(s),
            Err(_) => return Err(HostListError::NotUtf8 { index: out.len() }),
        }
    }
    Ok(out)
}

/// Split an `--exclude` argument into host specifications.
///
/// C: `load_exclude_string` (`targets.cc:206`) splits on `,` and nothing else —
/// no whitespace trimming, no comments. A spec the address parser then rejects
/// is `fatal`, not a warning, and this port keeps that: see `ExcludeSet::add`.
pub fn exclude_specs(s: &str) -> impl Iterator<Item = &str> {
    s.split(',')
}

/// What [`ExcludeSet::add`] did with a spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Added {
    /// A numeric spec, now in the set.
    Numeric,
    /// A name the caller must resolve and feed back via [`ExcludeSet::add_addr`].
    ///
    /// Returned rather than stored so the name cannot be silently dropped. An
    /// exclusion that quietly fails to apply scans the host it was meant to
    /// protect — the M7.0 failure exactly — so the caller is forced to either
    /// resolve it or refuse to scan.
    NeedsResolution(String),
}

/// Addresses to leave out of a scan: `--exclude` and `--excludefile` combined.
///
/// The C keeps one `addrset` fed by both flags (`nmap.cc:2070-2074` loads the
/// file *and* the string into the same `exclude_group`), and tests membership
/// per **expanded address** (`targets.cc:466`), not per spec. This does the same.
///
/// Matching never expands a spec: `--exclude 0.0.0.0/0` is 2³² addresses and is
/// answered in constant time by testing each octet against its own value set.
#[derive(Clone, Debug, Default)]
pub struct ExcludeSet {
    v4: Vec<Ipv4Ranges>,
    v6: Vec<Ipv6Addr>,
}

impl ExcludeSet {
    /// An empty set — excludes nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when nothing has been added, so no filtering need happen.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Add one specification. A parse failure is an `Err` the caller must act on
    /// — the C's `load_exclude_string` calls `fatal()` here, and refusing is the
    /// only safe direction: an `--exclude` argument that does not parse must
    /// never degrade into "scan it anyway".
    pub fn add(&mut self, spec: &str, want_ipv6: bool) -> Result<Added, TargetParseError> {
        match parse_target(spec, want_ipv6)? {
            TargetSpec::Ipv4(ranges) => {
                self.v4.push(*ranges);
                Ok(Added::Numeric)
            }
            TargetSpec::Ipv6(ip) => {
                self.v6.push(ip);
                Ok(Added::Numeric)
            }
            TargetSpec::Hostname { name, .. } => Ok(Added::NeedsResolution(name)),
        }
    }

    /// Add a single already-resolved address.
    pub fn add_addr(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => self.v4.push(Ipv4Ranges::single(v4)),
            IpAddr::V6(v6) => self.v6.push(v6),
        }
    }

    /// Is this address excluded?
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4.iter().any(|r| r.contains(v4)),
            IpAddr::V6(v6) => self.v6.contains(&v6),
        }
    }
}

#[cfg(test)]
mod tests {
    // ---- -iL / --excludefile tokenizer -------------------------------------
    //
    // Every expectation below was produced by running nmap's OWN
    // `read_host_from_file` (lifted verbatim from libnetutil/netutil.cc:3750
    // into a standalone oracle), not by reading the C and describing it. A
    // further 4,000 random inputs over the interesting alphabet (separators,
    // '#', and address characters) diffed clean against that oracle.

    fn toks(s: &[u8]) -> Vec<&str> {
        host_specs(s).expect("tokenizes")
    }

    #[test]
    fn a_list_may_put_several_specs_on_one_line() {
        // All five separators: space, tab, CR, LF, NUL.
        assert_eq!(
            toks(b"10.0.0.1 10.0.0.2\t10.0.0.3\r\n10.0.0.4\x0010.0.0.5"),
            ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
        );
    }

    #[test]
    fn comments_run_to_end_of_line_and_need_no_separator() {
        assert_eq!(
            toks(b"# whole line\n10.0.0.1 # trailing\n#\n10.0.0.2\n"),
            ["10.0.0.1", "10.0.0.2"]
        );
        // '#' ends the token it touches, with no space in between.
        assert_eq!(toks(b"10.0.0.1#nospace\n"), ["10.0.0.1"]);
        // And the FIRST '#' swallows the rest of the line, so `b` and `c` here
        // are never specs at all — a second '#' does not reopen anything.
        assert_eq!(toks(b"a#b#c\n"), ["a"]);
        // A comment that never reaches a newline still terminates cleanly.
        assert!(toks(b"#unterminated").is_empty());
    }

    #[test]
    fn blank_and_comment_only_input_yields_nothing() {
        for s in [&b""[..], b"\n\n   \n\t\n", b"# a\n# b\n", b"\x00\x00"] {
            assert!(toks(s).is_empty(), "expected no specs from {s:?}");
        }
    }

    #[test]
    fn a_final_spec_without_a_trailing_newline_is_still_read() {
        assert_eq!(toks(b"10.0.0.1"), ["10.0.0.1"]);
    }

    /// The C's bound is `n >= sizeof(host_spec)`, so 1023 bytes is the longest
    /// spec that fits — 1024 has no room for its NUL and is `fatal` there.
    /// Truncating instead would scan an address nobody wrote down.
    #[test]
    fn an_over_long_spec_is_refused_not_truncated() {
        let ok = vec![b'a'; MAX_HOST_SPEC - 1];
        assert_eq!(toks(&ok).len(), 1);
        let too_long = vec![b'a'; MAX_HOST_SPEC];
        assert_eq!(
            host_specs(&too_long),
            Err(HostListError::SpecTooLong { index: 0 })
        );
    }

    #[test]
    fn a_non_utf8_spec_is_an_error_not_a_lossy_substitution() {
        assert_eq!(
            host_specs(b"10.0.0.1 \xff\xfe"),
            Err(HostListError::NotUtf8 { index: 1 })
        );
    }

    #[test]
    fn the_tokenizer_never_panics() {
        let mut rng: u64 = 0x5eed;
        for _ in 0..3000 {
            let n = {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                (rng >> 33) as usize % 64
            };
            let buf: Vec<u8> = (0..n)
                .map(|_| {
                    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                    b" \t\r\n\0#a1./-*:,"[(rng >> 33) as usize % 14]
                })
                .collect();
            let _ = host_specs(&buf);
        }
    }

    // ---- --exclude ----------------------------------------------------------

    #[test]
    fn exclude_splits_on_commas_only_and_does_not_trim() {
        // C's load_exclude_string splits on ',' and hands the piece straight to
        // the address parser — no trimming, so " 10.0.0.2" stays malformed and
        // is rejected rather than silently becoming a valid host.
        assert_eq!(
            exclude_specs("10.0.0.1, 10.0.0.2,10.0.0.3").collect::<Vec<_>>(),
            ["10.0.0.1", " 10.0.0.2", "10.0.0.3"]
        );
    }

    #[test]
    fn an_unparseable_exclude_is_an_error_never_ignored() {
        let mut set = ExcludeSet::new();
        // A netmask that is not a number at all has nowhere to go but an error.
        assert_eq!(
            set.add("10.0.0.0/x", false),
            Err(TargetParseError::BadNetmask)
        );
        // The critical property: the failure did not quietly leave the set
        // empty-but-happy. Nothing was added, and the caller has an Err to act on.
        assert!(set.is_empty());
    }

    /// An out-of-range netmask is NOT an error — it is one host, matching C.
    ///
    /// `NetBlock::parse_expr` (`libnetutil/NetBlock.cc:266`) checks
    /// `bits > 32`, emits "Illegal netmask in ... Assuming /32 (one host)" and
    /// carries on. Worth pinning explicitly because the instinct is to reject:
    /// rejecting would make `--exclude 10.0.0.0/33` refuse the scan where C
    /// runs it, and for an *exclusion* the C behaviour is also the safe one —
    /// one host is still excluded rather than none.
    ///
    /// The port does not yet print C's warning here; the spec is accepted
    /// silently. That is a missing diagnostic, not a behavioural divergence.
    #[test]
    fn an_out_of_range_netmask_is_one_host_as_in_c() {
        for spec in ["10.0.0.0/33", "10.0.0.0/999"] {
            let mut set = ExcludeSet::new();
            assert_eq!(set.add(spec, false), Ok(Added::Numeric), "{spec}");
            assert!(set.contains("10.0.0.0".parse().unwrap()), "{spec}");
            assert!(
                !set.contains("10.0.0.1".parse().unwrap()),
                "{spec} must be ONE host"
            );
        }
    }

    #[test]
    fn a_hostname_exclusion_is_handed_back_not_dropped() {
        let mut set = ExcludeSet::new();
        match set.add("scanme.nmap.org", false) {
            Ok(Added::NeedsResolution(n)) => assert_eq!(n, "scanme.nmap.org"),
            other => panic!("expected NeedsResolution, got {other:?}"),
        }
        // It is NOT in the set yet — the caller must resolve it or refuse.
        assert!(set.is_empty());
    }

    // ---- exclusion matching -------------------------------------------------

    #[test]
    fn exclusion_matches_cidr_ranges_and_wildcards() {
        let mut set = ExcludeSet::new();
        set.add("10.0.0.0/24", false).expect("cidr");
        set.add("192.168.1.10-20", false).expect("range");
        set.add("172.16.*.1", false).expect("wildcard");
        for ip in ["10.0.0.1", "10.0.0.255", "192.168.1.15", "172.16.99.1"] {
            assert!(set.contains(ip.parse().unwrap()), "{ip} should be excluded");
        }
        for ip in ["10.0.1.1", "192.168.1.21", "172.16.99.2"] {
            assert!(
                !set.contains(ip.parse().unwrap()),
                "{ip} should NOT be excluded"
            );
        }
    }

    /// `--exclude 0.0.0.0/0` is 2³² addresses. Matching must answer without
    /// expanding, or a legitimate "exclude everything" hangs the scanner.
    #[test]
    fn excluding_everything_is_constant_time() {
        let mut set = ExcludeSet::new();
        set.add("0.0.0.0/0", false).expect("v4 default route");
        assert!(set.contains("1.2.3.4".parse().unwrap()));
        assert!(set.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn v4_and_v6_exclusions_do_not_bleed_into_each_other() {
        let mut set = ExcludeSet::new();
        set.add("10.0.0.1", false).expect("v4");
        set.add("::1", true).expect("v6");
        assert!(set.contains("10.0.0.1".parse().unwrap()));
        assert!(set.contains("::1".parse().unwrap()));
        assert!(!set.contains("::2".parse().unwrap()));
        assert!(!set.contains("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn a_resolved_address_can_be_added_directly() {
        let mut set = ExcludeSet::new();
        set.add_addr("10.1.2.3".parse().unwrap());
        assert!(set.contains("10.1.2.3".parse().unwrap()));
        assert!(!set.contains("10.1.2.4".parse().unwrap()));
    }

    use super::*;

    fn v4(spec: &str) -> Vec<Ipv4Addr> {
        match parse_target(spec, false).unwrap() {
            TargetSpec::Ipv4(r) => r.iter().collect(),
            other => panic!("expected Ipv4, got {other:?}"),
        }
    }

    #[test]
    fn single_address() {
        assert_eq!(v4("192.168.1.1"), vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn octet_range_and_order() {
        // octet 3 fastest, octet 2 slower — nmap's order.
        assert_eq!(
            v4("192.168.1-2.1-2"),
            vec![
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(192, 168, 2, 1),
                Ipv4Addr::new(192, 168, 2, 2),
            ]
        );
    }

    #[test]
    fn wildcard_is_full_octet() {
        let hosts = v4("10.0.0.*");
        assert_eq!(hosts.len(), 256);
        assert_eq!(hosts[0], Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(hosts[255], Ipv4Addr::new(10, 0, 0, 255));
    }

    #[test]
    fn open_ranges() {
        assert_eq!(v4("10.0.0.-3").len(), 4); // 0..=3
        assert_eq!(v4("10.0.0.253-").len(), 3); // 253..=255
        assert_eq!(
            v4("10.0.0.1,3,5"),
            vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 3),
                Ipv4Addr::new(10, 0, 0, 5),
            ]
        );
    }

    #[test]
    fn cidr_24_and_count() {
        match parse_target("10.0.0.0/24", false).unwrap() {
            TargetSpec::Ipv4(r) => {
                assert_eq!(r.count(), 256);
                let hosts: Vec<_> = r.iter().collect();
                assert_eq!(hosts.first(), Some(&Ipv4Addr::new(10, 0, 0, 0)));
                assert_eq!(hosts.last(), Some(&Ipv4Addr::new(10, 0, 0, 255)));
            }
            other => panic!("expected Ipv4, got {other:?}"),
        }
    }

    #[test]
    fn cidr_30_is_four_hosts() {
        let r = match parse_target("192.168.1.4/30", false).unwrap() {
            TargetSpec::Ipv4(r) => r,
            _ => unreachable!(),
        };
        assert_eq!(r.count(), 4);
        assert_eq!(
            r.iter().collect::<Vec<_>>(),
            vec![
                Ipv4Addr::new(192, 168, 1, 4),
                Ipv4Addr::new(192, 168, 1, 5),
                Ipv4Addr::new(192, 168, 1, 6),
                Ipv4Addr::new(192, 168, 1, 7),
            ]
        );
    }

    #[test]
    fn cidr_zero_is_huge_but_lazy() {
        // Must NOT allocate 2^32 addresses — count is math, iter is lazy.
        let r = match parse_target("0.0.0.0/0", false).unwrap() {
            TargetSpec::Ipv4(r) => r,
            _ => unreachable!(),
        };
        assert_eq!(r.count(), 1u64 << 32);
        // Take only the first few from the lazy iterator.
        let first: Vec<_> = r.iter().take(3).collect();
        assert_eq!(
            first,
            vec![
                Ipv4Addr::new(0, 0, 0, 0),
                Ipv4Addr::new(0, 0, 0, 1),
                Ipv4Addr::new(0, 0, 0, 2),
            ]
        );
    }

    #[test]
    fn hostname_and_ipv6() {
        assert_eq!(
            parse_target("scanme.nmap.org", false),
            Ok(TargetSpec::Hostname {
                name: "scanme.nmap.org".to_string(),
                netmask_bits: None,
            })
        );
        assert_eq!(
            parse_target("::1", false),
            Err(TargetParseError::Ipv6NotEnabled)
        );
        assert!(matches!(parse_target("::1", true), Ok(TargetSpec::Ipv6(_))));
    }

    #[test]
    fn netmask_on_hostname_is_carried_not_dropped() {
        // Regression: a /mask on a hostname must survive for post-resolution
        // application, not silently collapse to a single host.
        assert_eq!(
            parse_target("example.com/24", false),
            Ok(TargetSpec::Hostname {
                name: "example.com".to_string(),
                netmask_bits: Some(24),
            })
        );
    }

    #[test]
    fn ipv6_range_is_rejected_not_silently_single() {
        // Regression: "2001:db8::/64" must not silently become a single host.
        assert_eq!(
            parse_target("2001:db8::/64", true),
            Err(TargetParseError::Ipv6RangeUnsupported)
        );
        // A bare address or explicit /128 is still a single host.
        assert!(matches!(
            parse_target("2001:db8::1/128", true),
            Ok(TargetSpec::Ipv6(_))
        ));
    }

    #[test]
    fn rejects_bad_specs() {
        for bad in [
            "10.0.0.256",
            "10.0.0",
            "10.0.0.0.0",
            "10.0.0.5-3",
            "10.0.0./",
            "1.2.3.4/x",
        ] {
            let r = parse_target(bad, false);
            assert!(
                r.is_err() || matches!(r, Ok(TargetSpec::Hostname { .. })),
                "{bad:?} should not parse as a valid IPv4 range: {r:?}"
            );
        }
        // "10.0.0.256" specifically is not a valid range and not a hostname-ish
        // accept path we want — it must be an error, not an Ipv4.
        assert!(!matches!(
            parse_target("10.0.0.256", false),
            Ok(TargetSpec::Ipv4(_))
        ));
    }

    #[test]
    fn never_panics_on_hostile_input() {
        for s in [
            "",
            "/",
            "//",
            "-",
            ".",
            "*.*.*.*",
            "999999999999999999999",
            "\0\0",
            &"1-".repeat(5000),
            "1.2.3.4/999999999999",
            "é.ü.ö.à",
        ] {
            let _ = parse_target(s, false);
            let _ = parse_target(s, true);
        }
    }
}
