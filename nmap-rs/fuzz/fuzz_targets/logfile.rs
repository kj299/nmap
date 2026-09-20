// cargo-fuzz target for the output-filename expander —
// `nmap_core::logfile::{expand, validate}`.
//
// The corpus differential (crates/core/tests/logfile_differential.rs) compares
// 3204 vectors against the C oracle, which proves agreement on inputs someone
// chose. This proves the invariants hold on inputs nobody chose.
//
// What makes this worth a target at all, given the input is argv: the output is
// a PATH that the scanner then writes to. A name the operator did not intend is
// a file written somewhere they did not intend, and the expansion is the only
// thing standing between the two.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::logfile::{all_formats, expand, validate};

fuzz_target!(|data: &[u8]| {
    let Ok(spec) = std::str::from_utf8(data) else {
        return;
    };

    // Total and deterministic, at a normal instant and at the edges of what the
    // civil-date conversion accepts.
    for epoch in [0_i64, 1_789_000_000, 32_503_680_000, -1, i64::MAX, i64::MIN] {
        let out = expand(spec, epoch);
        assert_eq!(out, expand(spec, epoch), "expand is not deterministic");

        // A '%' can only survive as the literal produced by "%%", so the output
        // can never contain more '%' than the input. If it could, an escape was
        // passed through unexpanded -- which is the M7.9 bug: a filename with a
        // live '%' in it is one file overwritten nightly instead of a series.
        assert!(
            out.matches('%').count() <= spec.matches('%').count(),
            "expand({spec:?}) produced more '%' than it consumed: {out:?}"
        );

        // Expansion never invents a path separator. One that appeared from
        // nowhere would write the scan into a different directory.
        if !spec.contains('/') {
            assert!(
                !out.contains('/'),
                "expand({spec:?}) invented a '/': {out:?}"
            );
        }
    }

    // Validation is total, and agrees with itself.
    for opt in ["oN", "oX", "oG", "oA", "o"] {
        let a = validate(spec, opt);
        assert_eq!(a, validate(spec, opt), "validate is not deterministic");
        // THE invariant: anything accepted must not begin with '-'. A file whose
        // name starts with a dash is read as a flag by the next shell command
        // that touches it, which is the whole reason C refuses these.
        if a.is_ok() {
            assert!(
                !spec.starts_with('-') || (spec == "-" && opt != "oA"),
                "validate({spec:?}, {opt}) accepted a leading dash"
            );
        }
    }

    // The three -oA names differ from each other and keep the base as a prefix,
    // so one format can never clobber another's file.
    let (n, g, x) = all_formats(spec);
    assert!(n != g && g != x && n != x, "two -oA formats share a filename");
    for name in [&n, &g, &x] {
        assert!(name.starts_with(spec), "{name:?} lost its base {spec:?}");
    }
});
