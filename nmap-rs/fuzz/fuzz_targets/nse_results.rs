// cargo-fuzz target for `nmap_core::nse::results` and `nmap_core::nse::choose`.
//
// A script's output is mostly what a remote host sent it, and nmap prints it
// to the terminal and into XML through `formatScriptOutput`,
// `escape_for_screen`, `protect_xml` and `xml.cc`'s `escape`. The port
// reimplements those over bytes; this target checks them against
// transliterations of the C, written the way the C runs (NUL-terminated
// strings, `strchr`), and checks what the output may contain:
//
//   * `normal()` agrees with `formatScriptOutput`; and, for a script id of
//     printable characters (the id is a file name the operator chose, which
//     the C prints as it is), every line starts `| ` or `|_` and holds no
//     byte a terminal would act on (nothing below 0x20 but tab and newline,
//     nothing above 0x7E), whatever the script returned;
//   * `xml()` agrees with `ScriptResult::write_xml` for a string result, and,
//     for a printable id, contains nothing but printable ASCII: an attribute
//     value can hold no `<`, `&` or `"` of its own, and no control byte;
//   * `choose` is total over arbitrary `--script` rules against a fixed
//     index, and never chooses a script twice.
//
// Input layout: byte 0 splits the rest into a script id and its output; the
// whole input is also split on commas into rules.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::choose::{choose, Found, RuleOptions, ScriptLocator};
use nmap_core::nse::results::ScriptOutput;
use nmap_core::nse::script::parse_script_db;

/// `escape_for_screen` / `protect_xml`, as output.cc writes them.
fn reference_escape(s: &[u8], keep_cr: bool) -> Vec<u8> {
    let mut r = Vec::new();
    for &c in s {
        if c == b'\t' || c == b'\n' || (keep_cr && c == b'\r') || (0x20..=0x7e).contains(&c) {
            r.push(c);
        } else {
            r.extend_from_slice(format!("\\x{c:02X}").as_bytes());
        }
    }
    r
}

/// `xml.cc`'s `escape`, over a C string, signed `char` and all.
fn reference_xml_escape(s: &[u8]) -> Vec<u8> {
    let s: Vec<u8> = s.iter().copied().take_while(|&b| b != 0).collect();
    let mut r = Vec::new();
    for (i, &b) in s.iter().enumerate() {
        let c = b as i8;
        match b {
            b'<' => r.extend_from_slice(b"&lt;"),
            b'>' => r.extend_from_slice(b"&gt;"),
            b'&' => r.extend_from_slice(b"&amp;"),
            b'"' => r.extend_from_slice(b"&quot;"),
            b'\'' => r.extend_from_slice(b"&apos;"),
            b'-' if i > 0 && s[i - 1] == b'-' => r.extend_from_slice(b"&#45;"),
            _ if c < 0x20 || b > 0x7f => r.extend_from_slice(format!("&#x{b:x};").as_bytes()),
            _ => r.push(b),
        }
    }
    r
}

/// `formatScriptOutput`.
fn reference_format(id: &[u8], output: &[u8]) -> Option<Vec<u8>> {
    let c_output = reference_escape(output, false);
    if c_output.is_empty() {
        return None;
    }
    let mut lines: Vec<&[u8]> = Vec::new();
    let mut p = 0;
    while p < c_output.len() {
        match c_output[p..].iter().position(|&b| b == b'\n') {
            None => {
                lines.push(&c_output[p..]);
                break;
            }
            Some(q) => {
                lines.push(&c_output[p..p + q]);
                p += q + 1;
            }
        }
    }
    if lines.is_empty() {
        lines.push(b"");
    }
    let id: Vec<u8> = id.iter().copied().take_while(|&b| b != 0).collect();
    let mut result = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        result.extend_from_slice(if i < lines.len() - 1 { b"| " } else { b"|_" });
        if i == 0 {
            result.extend_from_slice(&id);
            result.extend_from_slice(b": ");
        }
        result.extend_from_slice(line);
        if i < lines.len() - 1 {
            result.push(b'\n');
        }
    }
    Some(result)
}

struct Fixed;

impl ScriptLocator for Fixed {
    fn fetch_script(&self, name: &[u8]) -> Option<Found> {
        let mut p = b"/d/scripts/".to_vec();
        p.extend_from_slice(name);
        match name.last() {
            Some(b'/') => Some(Found::Directory(p)),
            _ if name.ends_with(b".nse") && name.len() < 12 => Some(Found::File(p)),
            _ if name == b"dir" => Some(Found::BareDirectory(p)),
            _ => None,
        }
    }
    fn list_dir(&self, _: &[u8]) -> Vec<Vec<u8>> {
        vec![b"b.nse".to_vec(), b"a.nse".to_vec(), b"x".to_vec()]
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = usize::from(data[0]).min(data.len() - 1);
    let (id, output) = data[1..].split_at(split);
    let r = ScriptOutput {
        id: id.to_vec(),
        output: Some(output.to_vec()),
        table_xml: None,
    };
    let normal = r.normal();
    assert_eq!(normal, reference_format(id, output));
    // The id is printed as it is: it is the script's file name, which the
    // operator chose. Only what the script returned is escaped.
    let printable_id = id.iter().all(|&b| (0x20..=0x7e).contains(&b));
    if let Some(n) = normal.as_ref().filter(|_| printable_id) {
        for line in n.split(|&b| b == b'\n') {
            assert!(line.starts_with(b"| ") || line.starts_with(b"|_"));
        }
        assert!(n
            .iter()
            .all(|&b| b == b'\t' || b == b'\n' || (0x20..=0x7e).contains(&b)));
    }
    let mut want = b"<script id=\"".to_vec();
    want.extend_from_slice(&reference_xml_escape(id));
    want.extend_from_slice(b"\" output=\"");
    want.extend_from_slice(&reference_xml_escape(&reference_escape(output, true)));
    want.extend_from_slice(b"\"/>");
    let xml = r.xml();
    assert_eq!(xml, want);
    if printable_id {
        assert!(xml.iter().all(|&b| (0x20..=0x7e).contains(&b)));
    }

    let db = parse_script_db(
        b"Entry { filename = \"a.nse\", categories = { \"default\", \"safe\", } }\n\
          Entry { filename = \"b-c.nse\", categories = { \"intrusive\", } }\n",
    )
    .expect("fixed index");
    let rules: Vec<Vec<u8>> = data[1..]
        .split(|&b| b == b',')
        .map(<[u8]>::to_vec)
        .take(16)
        .collect();
    let chosen = choose(
        &rules,
        RuleOptions {
            default: data[0] & 1 == 1,
            version: data[0] & 2 == 2,
        },
        &db,
        &Fixed,
    );
    for (i, s) in chosen.scripts.iter().enumerate() {
        assert!(
            !chosen.scripts[..i].iter().any(|t| t.path == s.path),
            "chosen twice"
        );
    }
});
