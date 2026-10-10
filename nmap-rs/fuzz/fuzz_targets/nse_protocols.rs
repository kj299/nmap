// cargo-fuzz target for `nmap_core::protocols::ProtocolTable`, the
// `nmap-protocols` parser behind `nmapdb.getprotbynum` and `getprotbyname`.
//
// `nmap-protocols` is read from the data-file search path (`--datadir`,
// `$NMAPDIR`, `~/.nmap`), so whoever can place a file there chooses every byte.
// In 7.94 a line `ff 255` writes one past the end of `protocol_table`, and
// `%hu` misreads `65542` as 6 (`protocols-hu-wrap-rejected`). The properties:
//
//   * parsing is TOTAL, over bytes, and every warning names a real line;
//   * every name the table knows is one `%127s` reads whole — 1 to 127 bytes,
//     no C whitespace, no NUL — and looks up to its number;
//   * the two tables agree: a number's name looks up to that number, and every
//     number a name has has a name;
//   * FIRST WINS, on both tables: the file followed by itself gives the same
//     tables, and a line put in front of it is what its name and its number
//     look up to;
//   * THE MODEL: an independent reading of each line — the name, then the
//     number field as a token ending at whitespace or `#`, which must be an
//     optional sign and decimal digits, 0 to 255, `-0` allowed — gives exactly
//     the parser's two tables, and exactly its warnings: every line the model
//     reads is in the tables (or lost to first-wins), every line it rejects is
//     warned of, and nothing else is. A parser that wraps `x 65542` to 6,
//     reads `8abc` as 8, or keeps only the first entry fails here (M6.6
//     review, security D4).
//
// Input layout: the whole input is the file; its first bytes also make the
// line put in front.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::protocols::ProtocolTable;

fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn tables(t: &ProtocolTable) -> (Vec<(Vec<u8>, u8)>, Vec<Option<Vec<u8>>>) {
    let names = t.names().map(|(n, v)| (n.to_vec(), v)).collect();
    let numbers = (0..=255u8)
        .map(|n| t.by_number(n).map(<[u8]>::to_vec))
        .collect();
    (names, numbers)
}

/// The model's reading of one line.
enum Line<'a> {
    Blank,
    Entry(&'a [u8], u8),
    Bad,
}

/// The number field as a token: everything up to whitespace, `#` or the end.
fn model_number(token: &[u8]) -> Option<u8> {
    let (negative, digits) = match token.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, token),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let significant = &digits[digits.iter().take_while(|&&d| d == b'0').count()..];
    if significant.len() > 3 {
        return None;
    }
    let value = significant
        .iter()
        .fold(0u32, |v, &d| v * 10 + u32::from(d - b'0'));
    if negative && value != 0 {
        return None;
    }
    u8::try_from(value).ok()
}

fn model_line(raw: &[u8]) -> Line<'_> {
    let line = raw.split(|&b| b == 0).next().unwrap_or_default();
    // Words, by whitespace: the name, and the text after it.
    let skip = |s: &[u8]| s.iter().take_while(|&&b| is_c_space(b)).count();
    let line = &line[skip(line)..];
    if line.is_empty() || line[0] == b'#' {
        return Line::Blank;
    }
    let name_len = line.iter().take_while(|&&b| !is_c_space(b)).count();
    let (name, rest) = line.split_at(name_len);
    if name.len() > 127 {
        return Line::Bad;
    }
    let rest = &rest[skip(rest)..];
    // The number field: up to the next whitespace or `#`.
    let end = rest
        .iter()
        .position(|&b| is_c_space(b) || b == b'#')
        .unwrap_or(rest.len());
    match model_number(&rest[..end]) {
        Some(n) => Line::Entry(name, n),
        None => Line::Bad,
    }
}

fuzz_target!(|data: &[u8]| {
    let t = ProtocolTable::parse(data);

    // The model's tables and warnings.
    let mut by_name: std::collections::BTreeMap<Vec<u8>, u8> = Default::default();
    let mut by_number: Vec<Option<Vec<u8>>> = vec![None; 256];
    let mut bad = Vec::new();
    for (i, raw) in data.split(|&b| b == b'\n').enumerate() {
        match model_line(raw) {
            Line::Blank => {}
            Line::Bad => bad.push(i + 1),
            Line::Entry(name, n) => {
                if !by_name.contains_key(name) {
                    by_name.insert(name.to_vec(), n);
                    let slot = &mut by_number[usize::from(n)];
                    if slot.is_none() {
                        *slot = Some(name.to_vec());
                    }
                }
            }
        }
    }
    assert_eq!(
        tables(&t),
        (by_name.into_iter().collect::<Vec<_>>(), by_number),
        "the tables are not the model's"
    );
    assert_eq!(t.warning_count, bad.len(), "warned lines");
    assert_eq!(
        t.warnings.iter().map(|w| w.line).collect::<Vec<_>>(),
        bad.iter()
            .copied()
            .take(t.warnings.len())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        t.warnings.len(),
        bad.len().min(nmap_core::protocols::KEPT_WARNINGS)
    );

    let lines = data.iter().filter(|&&b| b == b'\n').count() + 1;
    for w in &t.warnings {
        assert!(w.line >= 1 && w.line <= lines, "warning line out of range");
    }
    assert_eq!(t.is_empty(), t.len() == 0);

    for (name, number) in t.names() {
        assert!(!name.is_empty() && name.len() <= 127, "{name:?}");
        assert!(name.iter().all(|&b| b != 0 && !is_c_space(b)), "{name:?}");
        assert!(name[0] != b'#', "a comment read as a name: {name:?}");
        assert_eq!(t.by_name(name), Some(number));
        assert!(
            t.by_number(number).is_some(),
            "{number} has a name but no entry"
        );
    }
    for n in 0..=255u8 {
        if let Some(name) = t.by_number(n) {
            assert_eq!(t.by_name(name), Some(n), "by_number({n}) = {name:?}");
        }
    }

    // First wins: reading the file again after itself changes nothing.
    let mut twice = data.to_vec();
    twice.push(b'\n');
    twice.extend_from_slice(data);
    assert_eq!(tables(&ProtocolTable::parse(&twice)), tables(&t));

    // A line in front wins both lookups.
    let name: Vec<u8> = data
        .iter()
        .copied()
        .filter(|&b| b.is_ascii_alphanumeric())
        .take(8)
        .collect();
    if !name.is_empty() {
        let number = data[0];
        let mut front = name.clone();
        front.extend_from_slice(format!(" {number}\n").as_bytes());
        front.extend_from_slice(data);
        let f = ProtocolTable::parse(&front);
        assert_eq!(f.by_name(&name), Some(number));
        assert_eq!(f.by_number(number), Some(&name[..]));
    }
});
