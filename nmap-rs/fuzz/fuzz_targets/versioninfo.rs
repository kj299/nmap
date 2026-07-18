// cargo-fuzz target for `nmap_core::versioninfo` — the `-sV` version-string
// substitution. Generated from porting-kit/harnesses/fuzz/gen_fuzz_target.sh,
// then specialized.
//
// The contract this enforces: substituting attacker-influenced captures into
// attacker-influenced templates must be **total and bounded** — never a panic,
// abort, UB, or unbounded work. Both inputs are untrusted: the capture bytes come
// straight off the wire (the banner), and the templates come from a possibly
// hostile `--versiondb`. This is the C's fixed-buffer `getVersionStr`/`substvar`
// path, which the port replaces with growing `Vec<u8>` (no overflow class). A
// crash here is a release blocker (PLAYBOOK Phase 4, gate 3).
//
// Strategy: carve the fuzz input into a template string (first line) and up to a
// few capture groups (the remaining lines), then run both a plain field build
// and a CPE build.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::probedb::MatchRule;
use nmap_core::versioninfo::build;

fuzz_target!(|data: &[u8]| {
    // First line → template text (must be UTF-8, as templates are). Remaining
    // lines → capture groups (raw bytes; group 0 is the whole match).
    let mut lines = data.split(|&b| b == b'\n');
    let Some(tmpl_bytes) = lines.next() else {
        return;
    };
    let Ok(tmpl) = std::str::from_utf8(tmpl_bytes) else {
        return;
    };

    let mut captures: Vec<Option<Vec<u8>>> = vec![Some(b"whole".to_vec())];
    for (i, grp) in lines.enumerate() {
        if i >= 9 {
            break; // groups 1..=9 only
        }
        captures.push(Some(grp.to_vec()));
    }

    // Exercise every field, plain and CPE-transformed, via a rule that routes the
    // same template through each slot.
    let rule = MatchRule {
        service: "fuzz".into(),
        pattern: "^x".into(),
        product: Some(tmpl.to_string()),
        version: Some(tmpl.to_string()),
        info: Some(tmpl.to_string()),
        hostname: Some(tmpl.to_string()),
        ostype: Some(tmpl.to_string()),
        devicetype: Some(tmpl.to_string()),
        cpe: vec![format!("cpe:/a:{tmpl}"), format!("cpe:/o:{tmpl}")],
        ..MatchRule::default()
    };
    let _ = build(&rule, &captures);
});
