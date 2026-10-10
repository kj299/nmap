//! LPeg construction at its limits, through the VM with the test-only
//! registration: pre-emption of the exponential analyses (D3), depth past
//! the C's crash depths (E2), sizes past the C's `int` (E4), and the
//! storage `setmaxstack` keeps.
//!
//! The answers here are pinned rather than compared with the oracle: either
//! they take seconds there (the 2^26 verifier), or the C crashes on them
//! (sizes past `int`, nesting past its stack), which no golden may record.
#![cfg(not(miri))] // seconds of VM time

mod lpeg_eval;

use lpeg_eval::{new_lua, run, start, step_to_end, Outcome};

fn returned(v: &[&str]) -> Outcome {
    Outcome::Returned(v.iter().map(|s| s.to_string()).collect())
}

/// `Rᵢ ← Rᵢ₊₁ + Rᵢ₊₁`: every analysis that follows calls takes 2^k steps
/// over it (`docs/M6.6-ANALYSIS.md` §1.1; the C's build takes 1.5 s at k = 26).
const CHAIN: &str = "local function chain(k, last) \
       local g = { 'R1' } \
       for i = 1, k do g['R' .. i] = lpeg.V('R' .. (i + 1)) + lpeg.V('R' .. (i + 1)) end \
       g['R' .. (k + 1)] = last or lpeg.P'a' \
       return g end ";

/// Fuel per slice, as the NSE engine's slices are a few thousand
/// instructions: the analyses must stop at slice boundaries and resume.
const SLICE: i32 = 100_000;

/// Run `src` in `lua` in slices of [`SLICE`] fuel: the outcome and how many
/// slices it took. More than one means it returned `Pending` and was resumed.
fn sliced(lua: &mut piccolo::Lua, src: &str) -> (Outcome, u64) {
    let ex = start(lua, src);
    step_to_end(lua, &ex, SLICE, 10_000_000)
}

/// The verifier over the k = 26 chain, then `lpeg.B` (`fixedlenx`) and
/// `p^1` (`nullable`, `checkaux`) over its pattern: each answers as the C
/// does — a pattern — after returning to the host between slices, many
/// times over, rather than holding the VM for the whole walk.
#[test]
fn exponential_analyses_are_pre_empted_and_finish() {
    let mut lua = new_lua();
    let t = std::time::Instant::now();
    let (out, build) = sliced(
        &mut lua,
        &format!("{CHAIN} G = lpeg.P(chain(26)) return lpeg.type(G)"),
    );
    let build_time = t.elapsed();
    assert_eq!(out, returned(&["pattern"]));
    let t = std::time::Instant::now();
    let (out, behind) = sliced(&mut lua, "return lpeg.type(lpeg.B(G))");
    let behind_time = t.elapsed();
    assert_eq!(out, returned(&["pattern"]));
    let t = std::time::Instant::now();
    let (out, star) = sliced(&mut lua, "return lpeg.type(G^1), lpeg.type(G^-1)");
    let star_time = t.elapsed();
    assert_eq!(out, returned(&["pattern", "pattern"]));
    eprintln!(
        "k = 26: build {build} slices in {build_time:?}, B {behind} slices in {behind_time:?}, \
         ^1 {star} slices in {star_time:?}"
    );
    // 2^26 paths, each several steps, in slices of 10^5: hundreds of slices.
    for (what, n) in [("build", build), ("B", behind), ("^n", star)] {
        assert!(
            n > 500,
            "{what} took {n} slices: it did not yield to the host"
        );
    }
}

/// The same work, run as one call, is the same answer: a slice boundary is
/// invisible to the result. With an empty last rule the chain is nullable,
/// so `^1` is refused — after an answer reached early (`checkaux` stops at
/// the first nullable alternative) — and `B` measures 0.
#[test]
fn pre_emption_does_not_change_answers() {
    let mut lua = new_lua();
    let (out, _) = sliced(
        &mut lua,
        &format!(
            "{CHAIN} local p = lpeg.P(chain(18, lpeg.P'')) \
             local ok, e = pcall(function() return p ^ 1 end) \
             local okb, eb = pcall(lpeg.B, p) \
             local q = lpeg.P(chain(18, lpeg.P'xy')) \
             return ok, e, okb, eb, lpeg.type(lpeg.B(q)), rawequal(p + 'z', p)"
        ),
    );
    assert_eq!(
        out,
        returned(&[
            "false",
            "chunk:1: loop body may accept empty string",
            "false",
            "bad argument #1 to 'lpeg.B' (pattern may not have fixed length)",
            "pattern",
            "true",
        ])
    );
}

/// A left recursion through 17 rules, each of two alternatives, found by
/// the verifier as the C finds it — naming the rule the C names, measured on
/// the tree's oracle — in slices.
#[test]
fn deep_left_recursion_is_found_in_slices() {
    let mut lua = new_lua();
    let (out, slices) = sliced(
        &mut lua,
        &format!("{CHAIN} local g = chain(16) g.R17 = lpeg.V'R1' * 'x' return pcall(lpeg.P, g)"),
    );
    assert_eq!(
        out,
        returned(&["false", "rule 'R14' may be left recursive"]),
        "{slices}"
    );
}

/// C's crash depths (§1.3), times ten. The C recurses on its stack in
/// `finalfix`, `checkloops` and `fixedlenx` along a pattern's first
/// siblings; `P"a"^-n` is n choices deep along them, built in one step.
const DEEP: u32 = 458_980;

#[test]
fn deep_patterns_are_walked_without_recursion() {
    let cases: [(&str, &[&str]); 5] = [
        // `finalfix` and the verifier, inside a grammar.
        (
            "local p = lpeg.P'a'^-458980 return lpeg.type(lpeg.P{ p })",
            &["pattern"],
        ),
        // `checkloops` finds the empty loop after the chain.
        (
            "return pcall(lpeg.P, { 'S', S = lpeg.P'a'^-458980 * lpeg.V'E'^0, E = lpeg.P'' })",
            &["false", "empty loop in rule 'S'"],
        ),
        // `fixedlenx`.
        (
            "return pcall(lpeg.B, lpeg.P'a'^-458980)",
            &[
                "false",
                "bad argument #1 to 'lpeg.B' (pattern may not have fixed length)",
            ],
        ),
        // `finalfix` outside a grammar, through `ptree`.
        (
            "return pcall(lpeg.ptree, lpeg.P'a'^-458980, true)",
            &["false", "function only implemented in debug mode"],
        ),
        // An open call after the chain, outside any grammar.
        (
            "return pcall(lpeg.ptree, lpeg.P'a'^-458980 * lpeg.V'x', true)",
            &["false", "rule 'x' used outside a grammar"],
        ),
    ];
    for (src, want) in cases {
        assert!(src.contains(&DEEP.to_string()), "{src}");
        assert_eq!(run(src), returned(want), "{src}");
    }
}

/// Sizes the C computes in an overflowing `int` — and then writes past its
/// allocation — are `not enough memory` here (`lpeg-tree-size-int-overflow`,
/// `lpeg-pattern-string-size-overflow`); so is any tree the memory budget
/// refuses. Each is a catchable error, not an abort.
#[test]
fn oversized_trees_are_not_enough_memory() {
    for src in [
        // 2^31 + 1 narrows to -2147483647: the C's 2 * n overflows.
        "return pcall(lpeg.P, 2^31 + 1)",
        "return pcall(lpeg.P, -(2^31))",
        "return pcall(lpeg.P, 2^31 - 1)",
        // (n + 1) * (size + 1) and n * (size + 3) - 1.
        "return pcall(function() return lpeg.P'a' ^ (2^31) end)",
        "return pcall(function() return lpeg.P'a' ^ (2^31 - 1) end)",
        "return pcall(function() return lpeg.P'ab' ^ -(2^30) end)",
        "return pcall(function() return lpeg.P'' ^ (2^31 - 1) end)",
    ] {
        assert_eq!(run(src), returned(&["false", "not enough memory"]), "{src}");
    }
    // Under a memory budget: a string pattern of 10^7 bytes is 2 * 10^7
    // nodes, and a repetition of a million copies of it more.
    let mut lua = new_lua();
    lua.set_memory_limit(64 << 20);
    let (out, _) = sliced(
        &mut lua,
        "local s = string.rep('a', 10^7) local ok, e = pcall(lpeg.P, s) \
         local ok2, e2 = pcall(function() return lpeg.P'abcd' ^ 10^7 end) \
         return ok, e, ok2, e2, lpeg.type(lpeg.P'still' * 'works')",
    );
    assert_eq!(
        out,
        returned(&[
            "false",
            "not enough memory",
            "false",
            "not enough memory",
            "pattern"
        ])
    );
}

/// `setmaxstack` stores its argument as given, in the state's registry
/// (`lpeg-maxstack`): a string stays a string, nothing is nil, and every
/// coroutine of the state sees the one value — the C's registry is per
/// `lua_State`, and nmap runs every script in one. It is read only when a
/// match grows its stack (step c); here what is stored is pinned.
#[test]
fn setmaxstack_stores_its_argument_as_given() {
    let mut lua = new_lua();
    let stored = |lua: &mut piccolo::Lua, src: &str| {
        let (out, _) = sliced(lua, src);
        assert!(matches!(out, Outcome::Returned(_)), "{src}: {out:?}");
        lua.enter(|ctx| {
            let v = nmap_core::nse::lpeg::max_stack_value(ctx);
            format!("{}:{}", v.type_name(), v.display())
        })
    };
    assert_eq!(
        stored(&mut lua, "return 0"),
        "number:100.0",
        "MAXBACK, a float"
    );
    assert_eq!(stored(&mut lua, "lpeg.setmaxstack('1000')"), "string:1000");
    assert_eq!(
        stored(&mut lua, "lpeg.setmaxstack(2^32 + 1000)"),
        "number:4294968296.0"
    );
    assert_eq!(stored(&mut lua, "lpeg.setmaxstack()"), "nil:nil");
    assert_eq!(
        stored(
            &mut lua,
            "coroutine.wrap(function() lpeg.setmaxstack(7) end)() return 1"
        ),
        "number:7"
    );
    // A refused argument leaves the stored value alone.
    assert_eq!(
        stored(&mut lua, "return pcall(lpeg.setmaxstack, 1000.5)"),
        "number:7"
    );
    assert_eq!(
        run("return pcall(lpeg.setmaxstack, 1000.5)"),
        returned(&[
            "false",
            "bad argument #1 to 'lpeg.setmaxstack' (number has no integer representation)"
        ])
    );
}

/// `tostring` and the stdlib's type errors name a value by its metatable's
/// `__name` (E7); patterns are `lpeg-pattern`.
#[test]
fn name_is_honoured_by_tostring_and_type_errors() {
    assert_eq!(
        run("return (tostring(lpeg.P(1)):gsub('0x%x+', 'ADDR')), \
                    (tostring(setmetatable({}, { __name = 'My.Type' })):gsub('0x%x+', 'ADDR')), \
                    (tostring(setmetatable({}, { __name = 5 })):gsub('0x%x+', 'ADDR')), \
                    select(2, pcall(string.rep, lpeg.P(1), 1))"),
        returned(&[
            "lpeg-pattern: ADDR",
            "My.Type: ADDR",
            "table: ADDR",
            "bad argument #1 to 'rep' (string expected, got lpeg-pattern)",
        ])
    );
}
