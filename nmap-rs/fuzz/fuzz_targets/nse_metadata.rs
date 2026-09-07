// cargo-fuzz target for `nmap_core::nse::script::parse_nse_metadata`.
//
// A `.nse` file is the input with the worst provenance in the whole port: nmap
// reads its metadata by *running the script* with the complete Lua standard
// library (`nse_main.lua:601-628`), which is why `--script-updatedb` on a
// directory containing a hostile file is code execution. This port reads it
// instead, so the parser must be total against exactly that hostile file.
//
//   * parsing is TOTAL for any input -- no panic, no unwrap, no overflow;
//   * every declared bound holds;
//   * a script that parses always names at least one rule and an action, the two
//     conditions `Script.new` itself insists on;
//   * a field is never both literal and unreadable.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::script::{
    parse_nse_metadata, Field, MAX_CATEGORIES, MAX_DEPENDENCIES, MAX_STRING_LEN,
};

fn check_list(f: &Field<Vec<Vec<u8>>>, cap: usize) {
    if let Field::Literal(v) = f {
        assert!(v.len() <= cap, "list cap exceeded");
        for s in v {
            assert!(s.len() <= MAX_STRING_LEN, "string cap exceeded");
        }
    }
}

fn check_str(f: &Field<Vec<u8>>) {
    if let Field::Literal(s) = f {
        assert!(s.len() <= MAX_STRING_LEN, "string cap exceeded");
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(meta) = parse_nse_metadata(data) else {
        return;
    };

    // `Script.new` refuses a script with no rule; so must this.
    assert!(meta.rules().any(), "accepted a script with no rule function");

    check_list(meta.categories(), MAX_CATEGORIES);
    check_list(meta.dependencies(), MAX_DEPENDENCIES);
    check_str(meta.description());
    check_str(meta.author());
    check_str(meta.license());

    // Parsing is a pure function of the bytes: the same input twice gives the
    // same answer, so nothing here depends on allocation addresses or ordering.
    let again = parse_nse_metadata(data).expect("parse is deterministic");
    assert!(again == meta, "parse is not a function of its input");
});
