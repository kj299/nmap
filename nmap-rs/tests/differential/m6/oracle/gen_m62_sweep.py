"""Generate the M6.2 whole-corpus golden: every rule against all 611 scripts.

The edge-case corpus in `gen_m62_cases.py` pins the grammar's corners with
inputs chosen by hand. This is the other half of the gate, and the broader one:
it takes the script index nmap actually ships and evaluates a set of realistic
`--script` rules against every entry in it, with nmap's own LPeg deciding the
answer. 611 entries times the rules below is tens of thousands of independent
(rule, script) verdicts, none of them chosen to be interesting.

The golden records, per rule, how many scripts matched, how many were selected
by name, and a digest of the matching names in index order. A digest keeps the
file small; the two counts keep a failure diagnosable without it.
"""

import hashlib
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_m62_cases as g  # noqa: E402

#: Rules a person would plausibly type. Every shipped category, the pseudo
#: category, the operator forms, and globs over the real naming conventions.
RULES = [
    # every category in the shipped index
    "safe", "discovery", "intrusive", "default", "vuln", "brute", "version",
    "broadcast", "exploit", "auth", "external", "dos", "malware", "fuzzer",
    "info",
    # the pseudo-category and the literals
    "all", "true", "false",
    # negation
    "not safe", "not intrusive", "not broadcast",
    # the documented idiom, and the grouping trap next to it
    "default and safe", "safe and not intrusive", "default or safe",
    "safe and not intrusive or vuln",           # = safe and (not intrusive or vuln)
    "(safe and not intrusive) or vuln",         # the conventional reading
    "not (intrusive or dos)",
    "safe and discovery and not broadcast",
    # globs over real naming conventions
    "http-*", "ssl-*", "smb-*", "*-brute", "*-info", "broadcast-*",
    "http-vuln-*", "*", "ftp-anon", "http-title",
    # a glob and a category together, which decides `by_name`
    "http-* or safe", "safe and not http-*", "http-* and safe",
    # case
    "SAFE", "Http-*",
    # things that select nothing
    "nosuchcategory", "zzz-*",
]

DRIVER = "m62_sweep.lua"


def build_driver(root):
    """The sweep driver: the same verbatim grammar, run over the real index."""
    body, digest = g.build_driver(root)
    # Reuse everything up to the stdin loop, then drive it differently.
    head = body.split("-- stdin: one case per line.")[0]
    return head + '''
-- stdin: rule_hex<TAB>filename_hex<TAB>cat_hex,cat_hex,...
-- stdout: one line per input, "1"/"0" for matched, then by_name.
for line in io.lines() do
  local rule_hex, file_hex, cats_hex = line:match("^(%x*)\\t(%x*)\\t(.*)$")
  local cats = {}
  for c in cats_hex:gmatch("[^,]+") do cats[#cats+1] = unhex(c) end
  io.write(evaluate(unhex(rule_hex), unhex(file_hex), cats), "\\n")
end
''', digest


def read_index(root):
    """Parse the shipped script.db the crude way — this is oracle input, and it
    must not depend on the Rust parser it is here to check."""
    text = open(f"{root}/scripts/script.db", encoding="utf-8").read()
    entries = []
    for m in re.finditer(
        r'Entry\s*\{\s*filename\s*=\s*"([^"]*)"\s*,\s*categories\s*=\s*\{(.*?)\}\s*\}',
        text,
        re.S,
    ):
        cats = re.findall(r'"([^"]*)"', m.group(2))
        entries.append((m.group(1), cats))
    return entries


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", "..", "..", "..", ".."))
    # An explicit output directory lets regen_m62.sh generate into a scratch
    # dir and diff, so --check never touches the committed files.
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(os.path.join(here, ".."))
    lua = os.path.join(here, "lua")

    driver, digest = build_driver(root)
    driver_path = os.path.join(here, DRIVER)
    with open(driver_path, "w", encoding="utf-8") as fh:
        fh.write(driver)

    entries = read_index(root)
    if len(entries) < 500:
        raise SystemExit(f"only parsed {len(entries)} entries from script.db — refusing")

    stdin = []
    for rule in RULES:
        for filename, cats in entries:
            stdin.append(
                "{}\t{}\t{}".format(
                    rule.encode("latin-1").hex(),
                    filename.encode("latin-1").hex(),
                    ",".join(c.encode("latin-1").hex() for c in cats),
                )
            )
    proc = subprocess.run(
        [lua, driver_path], input="\n".join(stdin) + "\n", capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise SystemExit(f"oracle failed: {proc.stderr.strip()[:400]}")
    out = proc.stdout.rstrip("\n").split("\n")
    if len(out) != len(stdin):
        raise SystemExit(f"oracle returned {len(out)} rows for {len(stdin)} pairs")

    rows = []
    i = 0
    for rule in RULES:
        matched, by_name, names = 0, 0, []
        for filename, _cats in entries:
            verdict = out[i]
            i += 1
            if not verdict.startswith("ACCEPT:"):
                raise SystemExit(f"rule {rule!r} did not parse against {filename}: {verdict}")
            _, m, n = verdict.split(":")
            if m == "true":
                matched += 1
                names.append(filename)
            if n == "true":
                by_name += 1
        h = hashlib.sha256("\n".join(names).encode()).hexdigest()
        rows.append("{}\t{}\t{}\t{}".format(rule.encode("latin-1").hex(), matched, by_name, h))

    header = (
        "# rule_hex\tmatched\tby_name\tsha256(matching filenames, index order)\n"
        "# Generated by oracle/gen_m62_sweep.py. Do not edit by hand.\n"
        f"# {len(RULES)} rules x {len(entries)} shipped scripts = "
        f"{len(RULES) * len(entries)} verdicts from nmap's own LPeg.\n"
        f"# Provenance digest over the extracted grammar blocks: {digest}\n"
    )
    with open(os.path.join(out_dir, "m62_sweep_golden.txt"), "w", encoding="utf-8") as fh:
        fh.write(header + "\n".join(rows) + "\n")
    print(f"M6.2 sweep: {len(RULES)} rules x {len(entries)} scripts = "
          f"{len(RULES) * len(entries)} verdicts")


if __name__ == "__main__":
    main()
