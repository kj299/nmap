//! LPeg construction at its limits, through the VM with the test-only
//! registration: pre-emption of the exponential analyses and of building a
//! grammar (D3), depth past the C's crash depths (E2), sizes past the C's
//! `int` and memory held between slices (E4), the storage `setmaxstack`
//! keeps, `__name` (E7), left calls through `B`, and callbacks that yield.
//!
//! The answers here are pinned rather than compared with the oracle: either
//! they take seconds there (the 2^26 verifier), or the C crashes on them
//! (sizes past `int`, nesting past its stack), which no golden may record,
//! or they are where the port differs on purpose (a yield), or they measure
//! the port itself (slices, fuel, memory). Where the C answers too, its
//! answer was measured on the tree's oracle and is the one pinned.
#![cfg(not(miri))] // seconds of VM time

mod lpeg_eval;

use lpeg_eval::{new_lua, run, start, step_to_end, step_traced, Outcome};
use nmap_core::nse::lpeg::take_most_work_per_fuel;

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
/// the tree's oracle — in slices, and within a bound on them: the verifier
/// follows at most `MAXRULES` rules along any path, so a verifier that lost
/// that bound runs on, and fails here by assertion rather than by a timeout.
#[test]
fn deep_left_recursion_is_found_in_slices() {
    let mut lua = new_lua();
    let ex = start(
        &mut lua,
        &format!("{CHAIN} local g = chain(16) g.R17 = lpeg.V'R1' * 'x' return pcall(lpeg.P, g)"),
    );
    // 14 slices of 10^4 fuel, measured; a few times that is the bound.
    let (out, slices) = step_to_end(&mut lua, &ex, 10_000, 100);
    assert_eq!(
        out,
        returned(&["false", "rule 'R14' may be left recursive"]),
        "{slices}"
    );
    for src in [
        "return pcall(lpeg.P, { 'S', S = lpeg.V'S' * 'a' })",
        "return pcall(lpeg.P, { 'A', A = lpeg.V'B' + 'a', B = lpeg.V'A' * 'b' })",
    ] {
        let mut lua = new_lua();
        let ex = start(&mut lua, src);
        let (out, slices) = step_to_end(&mut lua, &ex, 10_000, 3);
        assert!(
            matches!(&out, Outcome::Returned(v) if v.len() == 2 && v[1].ends_with("may be left recursive")),
            "{src}: {out:?} after {slices} slices"
        );
    }
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

/// Sizes the C computes in an `int` (`lpeg-tree-size-int-overflow`), as
/// the tree's oracle answers each (measured): where the `int` wraps to -3 or
/// below, `luaM_toobig`'s "memory allocation error: block too big", with no
/// position even from Lua code; where it wraps to -2, -1 or a size short of
/// the tree, the C allocates that and writes past it (it crashes), which is
/// `not enough memory` here — unless the C's own check comes between the
/// allocation and the writes, which is reproduced. Any tree the memory
/// budget refuses is `not enough memory` too. Each is a catchable error,
/// not an abort.
#[test]
fn sizes_past_the_cs_int_are_its_errors() {
    let big = "memory allocation error: block too big";
    let nem = "not enough memory";
    for (src, want) in [
        ("return pcall(lpeg.P, 2^30 + 1)", big),
        ("return pcall(function() return lpeg.P(2^31 - 1) end)", big),
        ("return pcall(lpeg.P, -(2^30))", big),
        ("return pcall(lpeg.P, 1500000000)", big),
        ("return pcall(lpeg.P, -1500000000)", big),
        (
            "return pcall(function() return lpeg.P'a' ^ (2^30) end)",
            big,
        ),
        // Before the check for an empty loop.
        ("return pcall(function() return lpeg.P'' ^ (2^30) end)", big),
        (
            "return pcall(function() return (#lpeg.P'a') ^ (2^31 - 1) end)",
            big,
        ),
        (
            "return pcall(function() return lpeg.P'a' ^ -(2^31 - 1) end)",
            big,
        ),
        // 2^31 + 1 narrows to -2147483647: 2 * n wraps to -2.
        ("return pcall(lpeg.P, 2^31 + 1)", nem),
        ("return pcall(lpeg.P, -(2^31))", nem),
        (
            "return pcall(function() return lpeg.P'a' ^ (2^31) end)",
            nem,
        ),
        (
            "return pcall(function() return lpeg.P'ab' ^ (2^31 - 1) end)",
            nem,
        ),
        (
            "return pcall(function() return lpeg.P'ab' ^ -(2^30) end)",
            nem,
        ),
        // Wrapped to 0: the C's allocation holds the pattern's header, and
        // its check for an empty loop comes before it writes the tree.
        (
            "return pcall(function() return lpeg.P'' ^ (2^31 - 1) end)",
            "chunk:1: loop body may accept empty string",
        ),
    ] {
        assert_eq!(run(src), returned(&["false", want]), "{src}");
    }
    // A grammar's size: 300 rules of the one pattern of 2^23 - 1 nodes wrap
    // the C's `int` negative; 520 wrap it past 2^32 to a positive size, which
    // the C allocates and then refuses for the count of rules.
    let mut lua = new_lua();
    let (out, _) = sliced(
        &mut lua,
        "local p = lpeg.P(2^22) local function g(n) local t = { 'r1' } \
         for i = 1, n do t['r' .. i] = p end return t end \
         return select(2, pcall(lpeg.P, g(300))), select(2, pcall(lpeg.P, g(520)))",
    );
    assert_eq!(
        out,
        returned(&[
            big,
            "bad argument #1 to 'lpeg.P' (grammar has too many rules)"
        ])
    );
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

/// Building a grammar copies each rule's tree into the grammar's and
/// appends each rule's constant table to the grammar's — work as large as
/// the rules, which the C does in one call — a slice of fuel at a time
/// (D3): the call returns to the VM many times, no slice runs past its fuel
/// by more than a fixed amount, and no slice does more work than its fuel
/// buys (`take_most_work_per_fuel`), however large the rules. Here 200
/// rules share one table of 200,001 entries (`/` appends to the table its
/// operand shares), 200 rules are each a 16,383-node tree, and 3 rules are
/// each a 524,287-node tree, more than one slice may copy.
#[test]
fn grammar_construction_is_pre_empted() {
    let mut lua = new_lua();
    let (out, _) = sliced(
        &mut lua,
        "base = lpeg.Cc(1) for i = 1, 200000 do local _ = base / 'x' end \
         big = lpeg.P'a' for i = 1, 13 do big = big * big end \
         kt, tr = { 'r1' }, { 'r1' } \
         for r = 1, 200 do kt['r' .. r] = base tr['r' .. r] = big end \
         for i = 1, 6 do big = big * big end \
         wide = { 'r1', r1 = big, r2 = big, r3 = big } \
         return lpeg.type(big)",
    );
    assert_eq!(out, returned(&["pattern"]));
    for (what, src, min) in [
        ("a shared table", "return lpeg.type(lpeg.P(kt))", 15),
        ("200 trees", "return lpeg.type(lpeg.P(tr))", 40),
        ("3 large trees", "return lpeg.type(lpeg.P(wide))", 40),
    ] {
        let _ = take_most_work_per_fuel();
        let ex = start(&mut lua, src);
        let t = step_traced(&mut lua, &ex, 10_000, 1_000_000);
        let work = take_most_work_per_fuel();
        assert!(t.done, "{what}: {t:?}");
        assert!(t.slices >= min, "{what}: one call, {t:?}: not pre-empted");
        assert!(
            (1..=16).contains(&work),
            "{what}: a slice did {work}/16 of the work its fuel buys"
        );
        assert!(
            t.deepest >= -4_096,
            "{what}: {t:?}: a slice ran far past its fuel"
        );
    }
}

/// What a call holds between slices counts against the memory budget (E4):
/// a grammar's tree is counted from the slice that allocates it, while its
/// rules are still being copied into it, not only once the pattern exists.
#[test]
fn a_grammar_being_built_is_counted_while_it_is_built() {
    let mut lua = new_lua();
    let (out, _) = sliced(
        &mut lua,
        "big = lpeg.P'a' for i = 1, 13 do big = big * big end \
         tr = { 'r1' } for r = 1, 200 do tr['r' .. r] = big end return 1",
    );
    assert_eq!(out, returned(&["1"]));
    let before = lua.total_memory();
    let ex = start(&mut lua, "return lpeg.type(lpeg.P(tr))");
    let t = step_traced(&mut lua, &ex, 10_000, 1_000_000);
    assert!(t.done && t.slices > 2, "{t:?}");
    let tree = 200 * (16_383 + 1) * std::mem::size_of::<nmap_core::nse::lpeg::tree::Node>();
    assert!(
        t.pending_peak >= before + tree * 9 / 10,
        "{t:?}: {before} before, a tree of {tree} bytes being built"
    );
}

/// The verifier does not follow a left call under a predicate in `B`'s
/// body, as the C's does not (`lpeg-getfirst-unbounded-recursion`): the C
/// builds such grammars and matches with them in some uses, and step c's
/// compiler refuses them where the C's recursed. Over the review's 334
/// shapes — predicates on `V"A"` under `B`, in seven contexts; two-rule
/// cycles; sub-grammars under predicates — every analysis construction runs
/// (`+`'s nofail, `^n`'s nullable, `B`'s fixed length, `ptree`'s scan, and the
/// verifier and empty-loop check of a grammar holding the pattern) finishes
/// within a bound on slices: none of them loops on a cycle through `B`.
/// What is refused is the left recursion past a sub-grammar in a nullable
/// context (the hidden pass), and what the C refuses too.
#[test]
fn left_calls_through_behind_build_and_every_analysis_finishes() {
    let src = r##"
        local P, V, B, C = lpeg.P, lpeg.V, lpeg.B, lpeg.C
        local function preds(R)
          return { "#" .. R, "-" .. R, "#(" .. R .. ' * "b")', "-(" .. R .. ' * "b")',
                   "#(" .. R .. ' + "b")', '#(P"b" + ' .. R .. ")", "-(-" .. R .. ")" }
        end
        local function bodies(p)
          return { "B(" .. p .. ' * "a")', "B(" .. p .. ' * P"ab")', "B(" .. p .. " * " .. p .. ' * "a")',
                   "B(B(" .. p .. ' * "a") * "c")' }
        end
        local WRAP = { "{X}", 'P"x" + {X}', '{X} + "x"', 'P"x" * {X}', '{X} * "x"', '#P"x" * {X}',
                       '-P"x" * {X}', '({X})^-1 * "y"', "C({X})", '{X} * V"Z"' }
        local gs = {}
        for _, p in ipairs(preds('V"A"')) do
          for _, b in ipairs(bodies(p)) do
            for _, w in ipairs(WRAP) do
              local body = w:gsub("{X}", function() return b end)
              local extra = body:find('V"Z"', 1, true) and ', Z = P"z"' or ""
              gs[#gs + 1] = '{ "A", A = ' .. body .. extra .. " }"
            end
          end
        end
        for _, p in ipairs(preds('V"A"')) do
          for _, w in ipairs { 'V"C"', 'P"x" + V"C"', 'V"C" + "x"', 'V"C" * "x"' } do
            gs[#gs + 1] = '{ "A", A = ' .. w .. ", C = B(" .. p .. ' * "c") }'
          end
        end
        for _, p in ipairs(preds('V"A"')) do
          gs[#gs + 1] = '{ "A", A = B(P"a" * ' .. p .. ") }"
          gs[#gs + 1] = '{ "A", A = P"x" + B(P"a" * ' .. p .. ") }"
        end
        for _, c in ipairs { '-P{P"x"}', '#P{P"x"}', 'P{P"x"}^0', '(#P"a" + P{P"x"})', '-(-P{P"x"})',
                             'P{P"x"}^-1' } do
          gs[#gs + 1] = '{ "A", A = ' .. c .. ' * V"A" + "y" }'
          gs[#gs + 1] = '{ "A", A = P"q" + ' .. c .. ' * V"A" }'
        end
        local built, why = 0, {}
        for _, g in ipairs(gs) do
          local t = assert(load("local P, V, B, C = ... return " .. g))(P, V, B, C)
          local ok, p = pcall(P, t)
          if ok then
            built = built + 1
            pcall(function() return p + "x" end)
            pcall(function() return p ^ 1 end)
            pcall(B, p)
            pcall(lpeg.ptree, p, true)
            pcall(P, { "S", S = p * V"S" + "z" })
            pcall(P, { "S", S = -p * V"S" + "z" })
          else
            why[p] = (why[p] or 0) + 1
          end
        end
        local w = {}
        for k, n in pairs(why) do w[#w + 1] = k .. " x" .. n end
        table.sort(w)
        return #gs, built, table.concat(w, "; ")
    "##;
    let mut lua = new_lua();
    let ex = start(&mut lua, src);
    let t = step_traced(&mut lua, &ex, 100_000, 2_000);
    assert!(t.done, "an analysis did not finish: {t:?}");
    let (out, _) = step_to_end(&mut lua, &ex, 100_000, 1);
    // The 12 refused are the six sub-grammar contexts, twice: on the tree's
    // oracle 10 of them crash or hang at the first match that reaches the
    // cycle, and 2 (`P{P"x"}^-1`) are refused there too.
    assert_eq!(
        out,
        returned(&["334", "322", "rule 'A' may be left recursive x12"])
    );
}

/// `coroutine.yield` from the Lua a constructor calls — a grammar table's
/// `__index` (for its initial rule), `locale(t)`'s `__newindex` — yields
/// the coroutine, and the call goes on where it was when it is resumed. The
/// C raises "attempt to yield across a C-call boundary" there
/// (`lpeg-callback-may-yield`).
#[test]
fn a_constructors_callbacks_may_yield() {
    assert_eq!(
        run("local g = setmetatable({ 'S', T = lpeg.P'b' }, { __index = function(t, k) \
               return coroutine.yield(k) end }) \
             local co = coroutine.wrap(function() return pcall(lpeg.P, g) end) \
             local k = co() \
             local ok, p = co(lpeg.P'a' * lpeg.V'T') \
             local seen = {} \
             local t = setmetatable({}, { __newindex = function(t, k, v) \
               seen[#seen + 1] = k rawset(t, k, v) if k == 'digit' then coroutine.yield(#seen) end end }) \
             local lo = coroutine.wrap(function() return lpeg.locale(t) end) \
             local n = lo() \
             local r = lo() \
             return k, tostring(ok), lpeg.type(p), n, tostring(rawequal(r, t)), #seen, lpeg.type(t.xdigit)"),
        returned(&["S", "true", "pattern", "4", "true", "11", "pattern"])
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

/// `__name` as the C prints it, with `%s` (measured on the tree's oracle,
/// whose function names differ only as `stdlib-bad-argument-naming` says):
/// up to its first NUL, byte for byte; and `luaL_typeerror` reads it from
/// any value's metatable, so a `__name` in the string metatable names every
/// string in a type error.
#[test]
fn name_is_read_as_the_c_reads_it() {
    assert_eq!(
        run(
            "local function hex(s) return (s:gsub('0x%x+', 'ADDR'):gsub('[^ -~]', function(c) \
               return string.format('<%02x>', c:byte()) end)) end \
             local odd = setmetatable({}, { __name = '\\255x\\0y' }) \
             local r = { hex(tostring(odd)), hex(select(2, pcall(string.rep, odd, 1))), \
                         hex(select(2, pcall(lpeg.Carg, odd))) } \
             getmetatable('').__name = 'Str' \
             r[#r + 1] = select(2, pcall(string.rep, 'x', 'y')) \
             r[#r + 1] = select(2, pcall(lpeg.Cmt, lpeg.P'a', 'x')) \
             r[#r + 1] = select(2, pcall(lpeg.locale, 'x')) \
             r[#r + 1] = tostring('plain') \
             getmetatable('').__name = nil \
             return table.unpack(r)"
        ),
        returned(&[
            "<ff>x: ADDR",
            "bad argument #1 to 'rep' (string expected, got <ff>x)",
            "bad argument #1 to 'lpeg.Carg' (number expected, got <ff>x)",
            "bad argument #2 to 'rep' (number expected, got Str)",
            "bad argument #2 to 'lpeg.Cmt' (function expected, got Str)",
            "bad argument #1 to 'lpeg.locale' (table expected, got Str)",
            "plain",
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
