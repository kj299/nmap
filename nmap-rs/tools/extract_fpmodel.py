#!/usr/bin/env python3
"""Extract nmap's compiled-in IPv6 fingerprint model from FPModel.cc into a binary blob.

The C compiles a 2.8 MB generated source file containing four f64 tables plus the class
names. Re-emitting those as Rust source would be an enormous, slow-to-compile file, so
this converts them once into a compact little-endian f64 blob that `core::fpmodel`
embeds with `include_bytes!`. The values themselves are copied verbatim — the text in
FPModel.cc has ~8 significant digits and parses to exactly the same f64 the C compiler
produces.

Layout (all little-endian):
    magic  "NMFP6\0\0\1"                     8 bytes
    n_class u32, n_feature u32               8 bytes
    scale   [n_feature][2] f64               (a, b) pairs
    mean    [n_class][n_feature] f64
    var     [n_class][n_feature] f64
    w       [n_feature][n_class] f64         liblinear's row-major layout
    labels  u32 count, then length-prefixed UTF-8 names
"""
import re
import struct
import sys

MAGIC = b"NMFP6\0\0\1"


def block(text, decl):
    """The brace-delimited body following `decl`."""
    i = text.index(decl)
    start = text.index("{", i + len(decl))
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start : j + 1]
    raise ValueError(f"unterminated block for {decl}")


NUM = re.compile(r"[-+]?\d+\.?\d*(?:[eE][-+]?\d+)?")


def numbers(body):
    # Strip comments first: they contain digits (OS names like "Linux 2.6.38").
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    return [float(m.group()) for m in NUM.finditer(body)]


def rows(body, width):
    """Split a `{{...},{...}}` body into rows of `width` numbers."""
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    out = []
    for m in re.finditer(r"\{([^{}]*)\}", body):
        vals = [float(x.group()) for x in NUM.finditer(m.group(1))]
        if vals:
            if len(vals) != width:
                raise ValueError(f"row has {len(vals)} values, expected {width}")
            out.append(vals)
    return out


def main(src, out):
    text = open(src, encoding="utf-8", errors="replace").read()

    # nr_class / nr_feature from the model struct itself, not hardcoded.
    m = re.search(r"struct model FPModel\s*=\s*\{\s*\{0\}\s*,\s*(\d+)\s*,\s*(\d+)", text)
    n_class, n_feature = int(m.group(1)), int(m.group(2))

    scale = rows(block(text, "double FPscale[][2]"), 2)
    mean = rows(block(text, "double FPmean[][695]"), n_feature)
    var = rows(block(text, "double FPvariance[][695]"), n_feature)
    w = numbers(block(text, "static double _w[]"))

    assert len(scale) == n_feature, f"scale {len(scale)} != {n_feature}"
    assert len(mean) == n_class, f"mean {len(mean)} != {n_class}"
    assert len(var) == n_class, f"var {len(var)} != {n_class}"
    assert len(w) == n_feature * n_class, f"w {len(w)} != {n_feature * n_class}"

    # Class names, in label order, from load_fp_matches(). Each block sets `match.line`
    # to its own label, so pair them rather than trusting source order.
    entries = re.findall(
        r'match\.line\s*=\s*(\d+);.*?match\.OS_name\s*=\s*\(char \*\)\s*"((?:[^"\\]|\\.)*)"',
        text,
        flags=re.S,
    )
    by_label = {int(line): name for line, name in entries}
    assert len(by_label) == n_class, f"names {len(by_label)} != {n_class}"
    names = [by_label[i] for i in range(n_class)]

    buf = bytearray(MAGIC)
    buf += struct.pack("<II", n_class, n_feature)
    for r in scale:
        buf += struct.pack("<2d", *r)
    for table in (mean, var):
        for r in table:
            buf += struct.pack(f"<{n_feature}d", *r)
    buf += struct.pack(f"<{len(w)}d", *w)
    buf += struct.pack("<I", len(names))
    for nm in names:
        b = nm.encode("utf-8")
        buf += struct.pack("<H", len(b)) + b

    open(out, "wb").write(buf)
    print(f"{n_class} classes x {n_feature} features -> {out} ({len(buf):,} bytes)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
