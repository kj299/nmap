//! Script results as nmap prints them: `formatScriptOutput` and
//! `printscriptresults` (`output.cc`), `ScriptResult::write_xml`
//! (`nse_main.cc`), and the escaping `xml.cc` and `output.cc` apply.
//!
//! Pure functions over bytes. What a result *says* is produced by the engine
//! ([`super::engine`]): its text — the script's string, or its table run
//! through `nse_main.lua`'s `format_table` — and the XML its table writes
//! through `format_xml`. This module turns those into the lines and elements
//! of normal and XML output.

/// One script's result, as `ScriptResult` holds it once rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptOutput {
    /// The script's id (`ScriptResult::get_id`).
    pub id: Vec<u8>,
    /// `get_output_str()`: the string output, or the table's formatting;
    /// `None` when the result has neither (a table whose formatting failed).
    pub output: Option<Vec<u8>>,
    /// What `format_xml` wrote for the structured output, when there is one.
    pub table_xml: Option<Vec<u8>>,
}

impl ScriptOutput {
    /// `formatScriptOutput`: the result's lines for normal output, each
    /// prefixed `| ` and the last `|_`, the first naming the script; `None`
    /// when the text is empty, which normal output skips.
    pub fn normal(&self) -> Option<Vec<u8>> {
        let text = escape_for_screen(self.output.as_deref().unwrap_or(&[]));
        if text.is_empty() {
            return None;
        }
        // `strchr` splitting: a final newline ends the last line rather than
        // starting an empty one.
        let mut lines: Vec<&[u8]> = Vec::new();
        let mut rest = text.as_slice();
        while !rest.is_empty() {
            match rest.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    lines.push(&rest[..i]);
                    rest = &rest[i.saturating_add(1)..];
                }
                None => {
                    lines.push(rest);
                    break;
                }
            }
        }
        let last = lines.len().saturating_sub(1);
        let mut out = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            out.extend_from_slice(if i < last { b"| " } else { b"|_" });
            if i == 0 {
                out.extend_from_slice(c_str(&self.id));
                out.extend_from_slice(b": ");
            }
            out.extend_from_slice(line);
            if i < last {
                out.push(b'\n');
            }
        }
        Some(out)
    }

    /// `ScriptResult::write_xml`: the `<script>` element, its `output`
    /// attribute the text with control characters spelt out, and its children
    /// the structured output, if any.
    pub fn xml(&self) -> Vec<u8> {
        let mut out = b"<script".to_vec();
        attribute(&mut out, b"id", c_str(&self.id));
        // An empty text is a bug in the script the C reports (and still
        // writes the empty attribute): `error("Bug in %s: no string output.")`.
        let text = protect_xml(self.output.as_deref().unwrap_or(&[]));
        attribute(&mut out, b"output", &text);
        match &self.table_xml {
            Some(inner) => {
                out.push(b'>');
                out.extend_from_slice(inner);
                out.extend_from_slice(b"</script>");
            }
            None => out.extend_from_slice(b"/>"),
        }
        out
    }
}

/// The phase a block of pre- or post-scan results belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptPhase {
    PreScan,
    PostScan,
}

/// `printscriptresults`: the normal-output block of pre- or post-scan
/// results, or nothing when there are none.
pub fn phase_normal(phase: ScriptPhase, results: &[ScriptOutput]) -> Vec<u8> {
    if results.is_empty() {
        return Vec::new();
    }
    let mut out = match phase {
        ScriptPhase::PreScan => b"Pre-scan script results:\n".to_vec(),
        ScriptPhase::PostScan => b"Post-scan script results:\n".to_vec(),
    };
    lines_of(&mut out, results);
    out
}

/// `printscriptresults`: the `<prescript>` or `<postscript>` element, or
/// nothing when there are no results.
pub fn phase_xml(phase: ScriptPhase, results: &[ScriptOutput]) -> Vec<u8> {
    let tag: &[u8] = match phase {
        ScriptPhase::PreScan => b"prescript",
        ScriptPhase::PostScan => b"postscript",
    };
    container_xml(tag, results)
}

/// `printhostscriptresults`: the host's block of normal output.
pub fn host_normal(results: &[ScriptOutput]) -> Vec<u8> {
    if results.is_empty() {
        return Vec::new();
    }
    let mut out = b"\nHost script results:\n".to_vec();
    lines_of(&mut out, results);
    out
}

/// `printhostscriptresults`: the `<hostscript>` element.
pub fn host_xml(results: &[ScriptOutput]) -> Vec<u8> {
    container_xml(b"hostscript", results)
}

fn lines_of(out: &mut Vec<u8>, results: &[ScriptOutput]) {
    for r in results {
        if let Some(text) = r.normal() {
            out.extend_from_slice(&text);
            out.push(b'\n');
        }
    }
}

fn container_xml(tag: &[u8], results: &[ScriptOutput]) -> Vec<u8> {
    if results.is_empty() {
        return Vec::new();
    }
    let mut out = vec![b'<'];
    out.extend_from_slice(tag);
    out.push(b'>');
    for r in results {
        out.extend_from_slice(&r.xml());
    }
    out.extend_from_slice(b"</");
    out.extend_from_slice(tag);
    out.push(b'>');
    out
}

/// The bytes before the first NUL: what C's string functions see.
fn c_str(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    &s[..end]
}

/// `"\\x%02X"`.
fn hex_escape(out: &mut Vec<u8>, c: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.extend_from_slice(b"\\x");
    out.push(HEX[usize::from(c >> 4)]);
    out.push(HEX[usize::from(c & 0xF)]);
}

/// `escape_for_screen` (`output.cc`): printable ASCII, tab and newline kept;
/// every other byte, `\r` and NUL included, as `\xHH`.
pub fn escape_for_screen(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if c == b'\t' || c == b'\n' || (0x20..=0x7E).contains(&c) {
            out.push(c);
        } else {
            hex_escape(&mut out, c);
        }
    }
    out
}

/// `protect_xml` (`output.cc`): as [`escape_for_screen`], but `\r` kept too.
pub fn protect_xml(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &c in s {
        if c == b'\t' || c == b'\r' || c == b'\n' || (0x20..=0x7E).contains(&c) {
            out.push(c);
        } else {
            hex_escape(&mut out, c);
        }
    }
    out
}

/// `escape` (`xml.cc`), over the C string `s` is: `<>&"'` as entities, the
/// second of two hyphens as `&#45;`, and control characters and bytes past
/// ASCII as `&#xHH;` (lowercase, unpadded).
pub fn xml_escape(s: &[u8]) -> Vec<u8> {
    let s = c_str(s);
    let mut out = Vec::with_capacity(s.len());
    for (i, &c) in s.iter().enumerate() {
        match c {
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'&' => out.extend_from_slice(b"&amp;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\'' => out.extend_from_slice(b"&apos;"),
            b'-' if i > 0 && s[i.saturating_sub(1)] == b'-' => out.extend_from_slice(b"&#45;"),
            c if !(0x20..=0x7F).contains(&c) => {
                out.extend_from_slice(format!("&#x{c:x};").as_bytes());
            }
            c => out.push(c),
        }
    }
    out
}

/// `xml_attribute`: ` name="escaped"`.
pub fn attribute(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(b' ');
    out.extend_from_slice(name);
    out.extend_from_slice(b"=\"");
    out.extend_from_slice(&xml_escape(value));
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, output: &[u8]) -> ScriptOutput {
        ScriptOutput {
            id: id.as_bytes().to_vec(),
            output: Some(output.to_vec()),
            table_xml: None,
        }
    }

    #[test]
    fn one_line_and_many() {
        assert_eq!(result("a", b"hi").normal().unwrap(), b"|_a: hi");
        assert_eq!(
            result("a", b"x\ny\nz").normal().unwrap(),
            b"| a: x\n| y\n|_z"
        );
        // A trailing newline ends the last line; a leading one is an empty
        // first line.
        assert_eq!(result("a", b"x\n").normal().unwrap(), b"|_a: x");
        assert_eq!(result("a", b"\nx").normal().unwrap(), b"| a: \n|_x");
        assert_eq!(result("a", b"").normal(), None);
    }

    #[test]
    fn control_characters_are_spelt_out() {
        assert_eq!(
            result("a", b"\r\0\xff\t").normal().unwrap(),
            b"|_a: \\x0D\\x00\\xFF\t"
        );
        assert_eq!(protect_xml(b"\r\0"), b"\r\\x00");
        assert_eq!(
            xml_escape(b"a<&\"'>--x\r\x7f\x80"),
            b"a&lt;&amp;&quot;&apos;&gt;-&#45;x&#xd;\x7f&#x80;"
        );
    }

    #[test]
    fn xml_elements() {
        assert_eq!(
            result("a", b"x\"y").xml(),
            b"<script id=\"a\" output=\"x&quot;y\"/>"
        );
        let mut r = result("a", b"t");
        r.table_xml = Some(b"<elem>1</elem>\n".to_vec());
        assert_eq!(
            r.xml(),
            b"<script id=\"a\" output=\"t\"><elem>1</elem>\n</script>"
        );
        assert_eq!(
            phase_normal(ScriptPhase::PreScan, &[result("a", b"x")]),
            b"Pre-scan script results:\n|_a: x\n"
        );
        assert!(phase_xml(ScriptPhase::PostScan, &[]).is_empty());
    }
}
