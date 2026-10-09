// cargo-fuzz target for `nmap_core::nse::nmapdb::parse_mac`, the argument
// parser of `nmapdb.mac2corp` (`nse_db.cc:19-41`).
//
// Its argument is script-controlled: `datafiles.parse_mac_prefixes()`'s table
// passes whatever key a script indexes it with. The C walks the string with
// two indices and a colon skip; this checks the port against a reference
// model written another way, from the grammar the C's loop accepts (matched
// against the C on 300,000 fuzzed inputs in M6.6 Phase 0, `model_mac.py`):
//
//   * a string of exactly 6 bytes is the address itself, raw;
//   * anything else is `(:?XX){6}` with nothing after it, XX two ASCII hex
//     digits — equivalently, with every `:` removed, 12 hex digits, where no
//     `:` follows another or ends the string, and each stands where an even
//     number of hex digits precede it.
//
// A byte of 128 or more is never a hex digit (the C hands `isxdigit` a
// negative `char`). Also checked: the parser is TOTAL, and an address written
// out as hex, in either case, with a colon before any pair, parses back to
// itself.
//
// Input layout: the whole input is the argument; its first 6 bytes, and the
// 7th and 8th as colon and case masks, also drive the round trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::nmapdb::parse_mac;

/// The grammar, stated without the C's loop.
fn model(s: &[u8]) -> Option<[u8; 6]> {
    if s.len() == 6 {
        return Some(s.try_into().expect("6 bytes"));
    }
    let mut digits = Vec::new();
    let mut prev_colon = false;
    for &b in s {
        if b == b':' {
            if prev_colon || digits.len() % 2 == 1 {
                return None;
            }
            prev_colon = true;
        } else if b.is_ascii_hexdigit() {
            digits.push(char::from(b).to_digit(16)? as u8);
            prev_colon = false;
        } else {
            return None;
        }
    }
    if prev_colon || digits.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for (o, pair) in out.iter_mut().zip(digits.chunks(2)) {
        *o = (pair[0] << 4) | pair[1];
    }
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(parse_mac(data), model(data), "{data:?}");

    // The round trip.
    if data.len() >= 8 {
        let mac: [u8; 6] = data[..6].try_into().expect("6 bytes");
        let (colons, upper) = (data[6], data[7]);
        let mut text = Vec::new();
        for (i, b) in mac.iter().enumerate() {
            if colons & (1 << i) != 0 {
                text.push(b':');
            }
            let pair = if upper & (1 << i) != 0 {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            };
            text.extend_from_slice(pair.as_bytes());
        }
        assert_eq!(parse_mac(&text), Some(mac), "{text:?}");
    }
});
