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
//     the bytes before the first NUL, every one printable.
//
// Input layout: byte 0 splits the rest into the file and the command line
// (0 means no file); byte 1 is the sanitiser's length.
#![no_main]

use libfuzzer_sys::fuzz_target;
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
        }
        Err(ArgsError::NoMatch | ArgsError::TooDeep) => {}
    }

    let len = usize::from(data[1]);
    let clean = sanitize(rest, len);
    assert!(clean.len() <= len);
    assert!(clean.iter().all(|b| (0x20..=0x7e).contains(b) || *b == b'.'));
    assert!(!clean.contains(&0));
});
