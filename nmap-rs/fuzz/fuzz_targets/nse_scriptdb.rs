// cargo-fuzz target for `nmap_core::nse::script::parse_script_db`.
//
// `script.db` decides which scripts nmap runs. nmap reads it by *executing* it as
// Lua (`nse_main.lua:1310`); this port parses it. The whole value of that change
// rests on the parser being total, so that is what is enforced here:
//
//   * parsing is TOTAL for any input -- no panic, no unwrap, no overflow;
//   * every declared bound holds on whatever comes back;
//   * an accepted database re-serialises to something that parses again to the
//     same value, so nothing is lost or invented in the round trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::script::{parse_script_db, MAX_CATEGORIES, MAX_ENTRIES, MAX_STRING_LEN};

/// Re-emit a parsed index in the exact form `--script-updatedb` writes.
///
/// The escaping matters more than it looks. A short decimal escape is ambiguous:
/// `\\0` followed by the digit `4` reads back as `\\04`, a different byte, so
/// re-serialising a NUL that way silently changes the filename. The fuzzer found
/// that within a thousand executions. Every escaped byte is therefore written as
/// exactly three digits.
fn escape_into(out: &mut Vec<u8>, bytes: &[u8]) {
    for &b in bytes {
        match b {
            b'"' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            0x00..=0x1f | 0x7f => {
                out.push(b'\\');
                out.push(b'0' + (b / 100));
                out.push(b'0' + ((b / 10) % 10));
                out.push(b'0' + (b % 10));
            }
            _ => out.push(b),
        }
    }
}

fn reserialise(db: &nmap_core::nse::script::ScriptDb) -> Vec<u8> {
    let mut out = Vec::new();
    for e in db.entries() {
        out.extend_from_slice(b"Entry { filename = \"");
        escape_into(&mut out, e.filename());
        out.extend_from_slice(b"\", categories = {");
        for c in e.categories() {
            out.extend_from_slice(b" \"");
            escape_into(&mut out, c);
            out.extend_from_slice(b"\",");
        }
        out.extend_from_slice(b" } }\n");
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(db) = parse_script_db(data) else {
        return;
    };

    assert!(db.entries().len() <= MAX_ENTRIES, "entry cap exceeded");
    for e in db.entries() {
        assert!(e.filename().len() <= MAX_STRING_LEN, "filename cap exceeded");
        assert!(e.categories().len() <= MAX_CATEGORIES, "category cap exceeded");
        for c in e.categories() {
            assert!(c.len() <= MAX_STRING_LEN, "category cap exceeded");
        }
    }

    // Anything this parser accepts must survive being written back out and read
    // again unchanged: that is what makes `--script-updatedb` idempotent.
    let again = reserialise(&db);
    let round = parse_script_db(&again).expect("re-serialised index must parse");
    assert!(round == db, "round trip changed the index");
});
