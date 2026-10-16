// cargo-fuzz target for `nmap_core::nse::scriptargs` and the byte sanitiser of
// `nmap_core::nse::nmaplib`.
//
// `--script-args` and `--script-args-file` are operator input that becomes
// `nmap.registry.args`, a nested table every script can read. The properties
// checked:
//
//   * `registry_args` is TOTAL: any file contents and command line give a
//     table or a refusal, never a panic, an overflow trap or unbounded
//     recursion (a nesting bomb is refused at `MAX_DEPTH`);
//   * the grammar ROUND-TRIPS: any table it produces, written back out with
//     every string quoted (`\` and `"` escaped), parses to the same table.
//     A parsed table is never empty -- `{}` is `{""}` -- so writing one back
//     out never needs a form the grammar lacks;
//   * `sanitize` (`cstringSanityCheck`) keeps at most the length asked for, of
//     the bytes before the first NUL, every one printable;
//   * `fspolicy::output_dir_values` designates exactly the string values of
//     the top-level arguments `OUTPUT_DIR_ARGS` names, in order, and nothing
//     nested or array-indexed; and a policy over those directories lets a
//     script make a directory exactly where it may write, beneath one of them.
//
// Input layout: byte 0 splits the rest into the file and the command line
// (0 means no file); byte 1 is the sanitiser's length.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::{Path, PathBuf};

use nmap_core::nse::fspolicy::{output_dir_values, FsPolicy, OUTPUT_DIR_ARGS};
use nmap_core::nse::nmaplib::sanitize;
use nmap_core::nse::scriptargs::{parse, registry_args, ArgTable, ArgValue, ArgsError};

fn quote(s: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    for &b in s {
        if b == b'\\' || b == b'"' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out.push(b'"');
}

fn write_table(t: &ArgTable, out: &mut Vec<u8>) {
    let mut first = true;
    let mut sep = |out: &mut Vec<u8>| {
        if !first {
            out.push(b',');
        }
        first = false;
    };
    for v in &t.array {
        sep(out);
        write_value(v, out);
    }
    for (k, v) in &t.fields {
        sep(out);
        quote(k, out);
        out.push(b'=');
        write_value(v, out);
    }
}

fn write_value(v: &ArgValue, out: &mut Vec<u8>) {
    match v {
        ArgValue::Str(s) => quote(s, out),
        ArgValue::Table(t) => {
            out.push(b'{');
            write_table(t, out);
            out.push(b'}');
        }
    }
}

fn never_empty(t: &ArgTable) -> bool {
    (!t.array.is_empty() || !t.fields.is_empty())
        && t.array.iter().chain(t.fields.iter().map(|(_, v)| v)).all(|v| match v {
            ArgValue::Str(_) => true,
            ArgValue::Table(t) => never_empty(t),
        })
}

fn check_output_dirs(t: &ArgTable) {
    let want: Vec<Vec<u8>> = t
        .fields
        .iter()
        .filter(|(k, _)| OUTPUT_DIR_ARGS.iter().any(|a| a.as_bytes() == k.as_slice()))
        .filter_map(|(_, v)| match v {
            ArgValue::Str(s) => Some(s.clone()),
            ArgValue::Table(_) => None,
        })
        .collect();
    let got = output_dir_values(t);
    assert_eq!(got, want, "output_dir_values");
    // Each designated value that reads as an absolute path, as a root.
    let roots: Vec<PathBuf> = got
        .iter()
        .filter_map(|v| std::str::from_utf8(v).ok())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .collect();
    let policy = FsPolicy {
        write_roots: roots.clone(),
        ..FsPolicy::default()
    };
    for r in &roots {
        let beneath = r.join("x");
        assert!(policy.allows_mkdir(&beneath) && policy.allows(&beneath, true));
    }
    // Any path at all: a directory may be made only where a file may be
    // written, and never by a relative path.
    for v in t.fields.iter().filter_map(|(_, v)| match v {
        ArgValue::Str(s) => std::str::from_utf8(s).ok(),
        ArgValue::Table(_) => None,
    }) {
        let p = Path::new(v);
        if policy.allows_mkdir(p) {
            assert!(p.is_absolute() && policy.allows(p, true), "{v:?}");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = usize::from(data[0]);
    let rest = &data[2..];
    let (file, cli) = if split == 0 {
        (None, rest)
    } else {
        let at = split.min(rest.len());
        (Some(&rest[..at]), &rest[at..])
    };
    match registry_args(file, cli) {
        Ok(t) => {
            if t.array.is_empty() && t.fields.is_empty() {
                return; // nothing was given
            }
            assert!(never_empty(&t), "the grammar produced an empty table");
            let mut text = Vec::new();
            write_table(&t, &mut text);
            assert_eq!(parse(&text), Ok(t.clone()), "re-parsing {text:?}");
            check_output_dirs(&t);
        }
        Err(ArgsError::NoMatch | ArgsError::TooDeep) => {}
    }

    let len = usize::from(data[1]);
    let clean = sanitize(rest, len);
    assert!(clean.len() <= len);
    assert!(clean.iter().all(|b| (0x20..=0x7e).contains(b) || *b == b'.'));
    assert!(!clean.contains(&0));
});
