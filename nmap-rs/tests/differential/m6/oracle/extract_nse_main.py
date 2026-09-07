"""Lift the M6.1-relevant logic OUT of `nse_main.lua`, verbatim.

The kit's rule is that an oracle must COPY the reference, not restate it. So
none of the loading logic below is written here — it is sliced out of the
shipped `nse_main.lua` by anchor line, byte for byte, and pasted into the
generated oracle driver. If upstream edits any of these blocks the anchors stop
matching and generation fails loudly, which is the point: a silently-diverged
oracle is worse than none.
"""

import hashlib

NSE_MAIN = "nse_main.lua"


class ExtractError(RuntimeError):
    pass


def _lines(root):
    with open(f"{root}/{NSE_MAIN}", encoding="utf-8") as fh:
        return fh.read().split("\n")


def _slice(lines, start, end_pred, name):
    """Return the verbatim block beginning at the sole line equal to `start`."""
    hits = [i for i, l in enumerate(lines) if l == start]
    if len(hits) != 1:
        raise ExtractError(f"{name}: expected 1 anchor match, found {len(hits)}")
    i = hits[0]
    out = [lines[i]]
    if end_pred(lines[i]):        # single-line block
        return lines[i], i + 1, i + 1
    for j in range(i + 1, len(lines)):
        out.append(lines[j])
        if end_pred(lines[j]):
            return "\n".join(out), i + 1, j + 1
    raise ExtractError(f"{name}: unterminated block from line {i + 1}")


#: name -> (start anchor, predicate that recognises the block's last line)
BLOCKS = {
    "script_rules": (
        "local NSE_SCRIPT_RULES = {",
        lambda l: l == "};",
    ),
    "loadscript": (
        "local function loadscript (filename)",
        lambda l: l == "end",
    ),
    "required_fields": (
        "  local required_fields = {",
        lambda l: l == "  };",
    ),
    "env": (
        "    -- Give the closure its own environment, with global access",
        lambda l: l == "    local status, e = resume(co); -- Get the globals it loads in env",
    ),
    "validate": (
        "    -- Check that all the required fields were set",
        lambda l: "has non-string entries in the 'dependencies' array\");" in l,
    ),
    "db_category_assert": (
        "      assert(type(category) == \"string\", \"bad entry in script database\");",
        lambda l: True,
    ),
    "db_entry_head": (
        "    local categories = rawget(script_entry, \"categories\");",
        lambda l: "script database appears corrupt" in l,
    ),
}


def extract(root):
    """Return {name: (text, first_line, last_line)} plus a digest of the whole."""
    lines = _lines(root)
    out = {}
    for name, (start, end_pred) in BLOCKS.items():
        out[name] = _slice(lines, start, end_pred, name)
    return out


def provenance(blocks):
    """A stable digest over every extracted block, for the generated header."""
    h = hashlib.sha256()
    for name in sorted(blocks):
        text, first, last = blocks[name]
        h.update(f"{name}:{first}-{last}\n".encode())
        h.update(text.encode())
        h.update(b"\0")
    return h.hexdigest()
