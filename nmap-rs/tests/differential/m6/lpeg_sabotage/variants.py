"""The sabotaged lpeg.c variants of the M6.6 sequencing review: S00 (the
unpatched baseline) and the 16 sabotages S01-S16.

Each edit is (anchor, replacement), applied to a COPY of the tree's lpeg.c.
An anchor must occur exactly once, and a sabotage must change the file, or the
build stops: a variant that silently built unpatched would look "uncaught".
"""

VARIANTS = {
    "S00_baseline": [],
    "S01_C_wholematch_last": [
        ("      lua_insert(L, -k);  /* make whole match be first result */\n", "")],
    "S02_Ct_reverse_multi": [
        ("        lua_rawseti(L, -(i + 1), n + i);",
         "        lua_rawseti(L, -(i + 1), n + (k - i + 1));")],
    "S03_Cf_args_swapped": [
        ("    n = pushcapture(cs);  /* get next capture's values */\n    lua_call(L, n + 1, 1);",
         "    n = pushcapture(cs);  /* get next capture's values */\n    lua_rotate(L, -(n + 1), n);\n    lua_call(L, n + 1, 1);")],
    "S04_no_backtrack_limit": [
        ("  if (n >= max)  /* already at maximum size? */\n    luaL_error(L, \"too many pending calls/choices\");\n", ""),
        ("  if (newn > max) newn = max;\n", "")],
    "S05_backtrack_limit_plus1": [
        ("  if (newn > max) newn = max;\n", "  if (newn > max) newn = max + 1;\n")],
    "S06_Cmt_allows_backward": [
        ("    if (res < curr || res > limit)\n", "    if (res > limit)\n")],
    "S07_Cmt_accepts_float": [
        ("    res = lua_tointeger(L, fr) - 1;  /* new position */",
         "    res = (lua_Integer)lua_tonumber(L, fr) - 1;  /* new position */")],
    "S08_dyncap_kept_on_backtrack": [
        ("          ndyncap -= removedyncap(L, capture, stack->caplevel, captop);", "          (void)0;")],
    "S09_query_rawget": [
        ("  lua_gettable(cs->L, updatecache(cs, idx));  /* query cap. value at table */",
         "  lua_rawget(cs->L, updatecache(cs, idx));  /* query cap. value at table */")],
    "S10_MAXSTRCAPS_9": [("#define MAXSTRCAPS\t10", "#define MAXSTRCAPS\t9")],
    "S11_codechoice_off": [
        ("  if (headfail(p1) ||\n      (!e1 && (getfirst(p2, fl, &cs2), cs_disjoint(&cs1, &cs2)))) {", "  if (0) {")],
    "S12_INITBACK_32": [("#define INITBACK\t100", "#define INITBACK\t32")],
    "S13_init_past_end_crop": [
        ("    else return len;  /* crop at the end */",
         "    else return len > 0 ? len - 1 : 0;  /* crop at the end */")],
    "S14_Cb_ignores_name": [
        ("      if (lua_equal(L, -2, -1)) {  /* right group? */", "      if (1) {  /* right group? */")],
    "S15_named_group_last_value": [
        ("  if (n > 1)\n    lua_pop(cs->L, n - 1);  /* pop extra values */",
         "  if (n > 1) {\n    lua_replace(cs->L, -n);\n    if (n > 2) lua_pop(cs->L, n - 2);\n  }")],
    "S16_correctkeys_shifts_Carg": [
        ("      if (tree->key > 0 && tree->cap != Carg && tree->cap != Cnum)",
         "      if (tree->key > 0 && tree->cap != Cnum)")],
}

LABELS = {
    "S00_baseline": "unpatched",
    "S01_C_wholematch_last": "`C` pushes the whole match last",
    "S02_Ct_reverse_multi": "`Ct` multi-value order reversed",
    "S03_Cf_args_swapped": "`Cf` arguments swapped",
    "S04_no_backtrack_limit": "backtrack limit removed",
    "S05_backtrack_limit_plus1": "backtrack limit + 1",
    "S06_Cmt_allows_backward": "`Cmt` accepts backward positions",
    "S07_Cmt_accepts_float": "`Cmt` accepts 3.5",
    "S08_dyncap_kept_on_backtrack": "dynamic captures kept on backtrack",
    "S09_query_rawget": "`/table` through `rawget`",
    "S10_MAXSTRCAPS_9": "`MAXSTRCAPS` 9",
    "S11_codechoice_off": "`codechoice` off",
    "S12_INITBACK_32": "`INITBACK` 32",
    "S13_init_past_end_crop": "`init` past the end cropped to len-1",
    "S14_Cb_ignores_name": "`Cb` ignores the group name",
    "S15_named_group_last_value": "a named group keeps its last value",
    "S16_correctkeys_shifts_Carg": "`correctkeys` shifts `Carg`",
}

BASELINE = "S00_baseline"

# The plan singles these out: each must be caught by a fixed row of family X,
# not only by random rows (checked on a full run).
REQUIRED_X = ("S05", "S07", "S08", "S09", "S10", "S14")


def select(args):
    """Full variant names for `args` (full names or S-number prefixes); all if empty."""
    if not args:
        return sorted(VARIANTS)
    out = []
    for a in args:
        hits = [n for n in VARIANTS if n == a or n.split("_", 1)[0] == a]
        if len(hits) != 1:
            raise SystemExit("unknown variant %r (one of: %s)" % (a, " ".join(sorted(VARIANTS))))
        if hits[0] not in out:
            out.append(hits[0])
    return sorted(out)


def patched(src, name):
    """The tree's lpeg.c text with variant `name` applied."""
    s = src
    for a, b in VARIANTS[name]:
        c = s.count(a)
        if c != 1:
            raise SystemExit("%s: anchor occurs %d times (expected 1): %r" % (name, c, a[:60]))
        s = s.replace(a, b)
    if name != BASELINE and s == src:
        raise SystemExit("%s: the edit changed nothing" % name)
    return s
