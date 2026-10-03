// cargo-fuzz target for the byte-level parts of the stdlib tail:
// `nmap_core::nse::stdlib::strrep::rep` and `nmap_core::nse::stdlib::base::chunk_id`.
//
// `string.rep` is the one string function whose output size its arguments
// alone choose, and `chunk_id` is how `load` names a script-supplied chunk in
// an error message, cutting the name to a fixed buffer. The properties
// checked:
//
//   * `rep` is TOTAL and EXACT: any string, count and separator give either
//     the C's refusal -- exactly when `l + lsep > MAXSIZE / n` -- or the bytes
//     a naive concatenation gives; never a panic, an overflow trap or a
//     multi-gigabyte allocation (a count the C would accept with a large
//     result is checked on the bound alone, not built);
//   * `chunk_id` agrees byte for byte with a transliteration of
//     `luaO_chunkid` that writes into a 60-byte buffer the way the C does,
//     `memcpy` lengths and terminating NULs included, and never yields more
//     than `LUA_IDSIZE - 1` bytes.
//
// Input layout: byte 0 selects the count's shape, bytes 1..9 its value, byte
// 9 splits the rest into the string and the separator; the whole input is
// also a chunk name.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::stdlib::base::chunk_id;
use nmap_core::nse::stdlib::strrep::rep;

const MAXSIZE: usize = i32::MAX as usize;
/// Results larger than this are checked on the bound alone.
const BUILD_LIMIT: usize = 1 << 16;

fn count(sel: u8, raw: i64) -> i64 {
    let small = |m: u64| (raw.unsigned_abs() % m) as i64;
    match sel % 6 {
        0 => raw % 64, // small, either sign
        1 => raw,      // anything
        2 => i64::from(i32::MAX) + raw % 4,
        3 => (MAXSIZE as i64) / (1 + small(8)) + raw % 2,
        4 => i64::MAX - small(4),
        _ => -small(4),
    }
}

/// `luaO_chunkid` (lobject.c), over a 60-byte buffer, then read as a C string.
fn reference_chunk_id(name: &[u8]) -> Vec<u8> {
    const IDSIZE: usize = 60;
    // `luaL_loadbufferx` receives the name as a C string.
    let src: Vec<u8> = name.iter().copied().take_while(|&b| b != 0).collect();
    let srclen = src.len();
    let mut source = src.clone();
    source.push(0); // the C string's terminator, which the copies may include
    let mut out = [0u8; IDSIZE];
    let mut o = 0;
    let addstr = |out: &mut [u8; IDSIZE], o: &mut usize, s: &[u8]| {
        out[*o..*o + s.len()].copy_from_slice(s);
        *o += s.len();
    };
    let mut bufflen = IDSIZE;
    if source[0] == b'=' {
        if srclen <= bufflen {
            addstr(&mut out, &mut o, &source[1..1 + srclen]);
        } else {
            addstr(&mut out, &mut o, &source[1..bufflen]);
            out[o] = 0;
        }
    } else if source[0] == b'@' {
        if srclen <= bufflen {
            addstr(&mut out, &mut o, &source[1..1 + srclen]);
        } else {
            addstr(&mut out, &mut o, b"...");
            bufflen -= 3;
            let from = 1 + srclen - bufflen;
            addstr(&mut out, &mut o, &source[from..from + bufflen]);
        }
    } else {
        let nl = src.iter().position(|&b| b == b'\n');
        addstr(&mut out, &mut o, b"[string \"");
        bufflen -= 9 + 3 + 2 + 1;
        let mut len = srclen;
        if len < bufflen && nl.is_none() {
            addstr(&mut out, &mut o, &source[..len]);
        } else {
            if let Some(nl) = nl {
                len = nl;
            }
            if len > bufflen {
                len = bufflen;
            }
            addstr(&mut out, &mut o, &source[..len]);
            addstr(&mut out, &mut o, b"...");
        }
        addstr(&mut out, &mut o, b"\"]\0");
    }
    out.iter().copied().take_while(|&b| b != 0).collect()
}

fuzz_target!(|data: &[u8]| {
    let got = chunk_id(data);
    assert!(got.len() < 60);
    assert_eq!(got, reference_chunk_id(data), "chunk_id({data:?})");

    if data.len() < 10 {
        return;
    }
    let raw = i64::from_le_bytes(data[1..9].try_into().unwrap());
    let n = count(data[0], raw);
    let rest = &data[10..];
    let split = usize::from(data[9]).min(rest.len());
    let (s, sep) = rest.split_at(split);

    let refused = n > 0 && {
        let n = n as usize;
        s.len() + sep.len() > MAXSIZE / n
    };
    let size = if n <= 0 || refused {
        0
    } else {
        let n = n as usize;
        s.len() * n + sep.len() * (n - 1)
    };
    if !refused && size > BUILD_LIMIT && !(s.is_empty() && sep.is_empty()) {
        return; // accepted, and too large to build here
    }
    match rep(s, n, sep) {
        Err(e) => {
            assert!(refused, "refused a call the C accepts: {}", e.0);
            assert_eq!(e.0, "resulting string too large");
        }
        Ok(out) => {
            assert!(!refused, "accepted a call the C refuses");
            assert_eq!(out.len(), size);
            let mut want = Vec::new();
            for i in 0..n.max(0).min(BUILD_LIMIT as i64 + 1) {
                if i > 0 {
                    want.extend_from_slice(sep);
                }
                want.extend_from_slice(s);
                if want.len() > size {
                    break;
                }
            }
            if size > 0 {
                assert_eq!(out, want);
            }
        }
    }
});
