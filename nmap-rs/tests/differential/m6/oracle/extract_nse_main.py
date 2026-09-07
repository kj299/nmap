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
LPEG_UTILITY = "nselib/lpeg-utility.lua"


class ExtractError(RuntimeError):
    pass


def _lines(root, source=NSE_MAIN):
    with open(f"{root}/{source}", encoding="utf-8") as fh:
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
    # ---- M6.2: the `--script` selection grammar ------------------------------
    # `K` builds the caseless keyword pattern, including the follow-set that
    # keeps "not" from splitting "nota".
    "keyword": (
        "local memo_K = {}",
        lambda l: l == "end",
    ),
    # The rule normaliser: the "+" forced prefix and the whitespace strip.
    "rule_normalise": (
        "  for i, rule in ipairs(rules) do",
        lambda l: l == "  end",
    ),
    # The grammar itself — ordered choice, right-recursive operators.
    "grammar": (
        "  local pre_T = locale {",
        lambda l: l == "  }",
    ),
    # Glob compilation: which characters are escaped, and that only `*` is not.
    "globs": (
        "  local globs = {}",
        lambda l: l == "    })",
    ),
    # Per-entry wiring: basename extraction, the `selected_by_name` side
    # effect, the pseudo-category "all", and the path character class.
    "entry_match": (
        "    local escaped_basename = match(filename, \"([^/\\\\]-)%.nse$\") or match(filename, \"([^/\\\\]-)$\");",
        lambda l: l == "    local T = P(pre_T)",
    ),
}

#: blocks that live in `nselib/lpeg-utility.lua` rather than `nse_main.lua`
LPEG_UTILITY_BLOCKS = {
    # `caseless` is what makes every keyword case-insensitive while leaving
    # path globs case-SENSITIVE — an asymmetry the port has to reproduce.
    "caselessp": (
        "local caselessP = lpeg.Cf((lpeg.P(1) / function (a) return lpeg.S(lower(a)..upper(a)) end)^1, function (a, b) return a * b end)",
        lambda l: True,
    ),
    "caseless": (
        "function caseless (literal)",
        lambda l: l == "end",
    ),
}


def extract(root):
    """Return {name: (text, first_line, last_line)} plus a digest of the whole."""
    out = {}
    lines = _lines(root)
    for name, (start, end_pred) in BLOCKS.items():
        out[name] = _slice(lines, start, end_pred, name)
    util = _lines(root, LPEG_UTILITY)
    for name, (start, end_pred) in LPEG_UTILITY_BLOCKS.items():
        out[name] = _slice(util, start, end_pred, name)
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
