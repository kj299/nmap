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
//     look up to.
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

fuzz_target!(|data: &[u8]| {
    let t = ProtocolTable::parse(data);

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
