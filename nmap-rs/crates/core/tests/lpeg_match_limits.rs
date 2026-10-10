//! `lpeg.match` at its limits, through the VM with the test-only
//! registration: the backtrack ceilings of D2, depth past the C's crash
//! depths (E2), the Lua-stack ceiling on captures, pre-emption of
//! compilation, matching and capture evaluation (D3), memory (E4), the
//! three behaviours `hascaptures` gives 0.12 by not following calls, the C's
//! crashes the port fixes, and left calls through `lpeg.B`.
//!
//! Where the C answers, its answer was measured on the tree's oracle (or, for
//! the left calls through `B`, on a build of it with the defects the port
//! fixes fixed: `m66c_behind_golden.txt`) and is the one pinned. Where it
//! crashes, the pin is a correct LPeg's answer.
#![cfg(not(miri))] // seconds of VM time

mod lpeg_eval;

use std::path::Path;

use lpeg_eval::{new_lua, run, start, step_only, step_to_end, step_traced, Outcome};
use piccolo::{Fuel, Value, Variadic};

fn returned(v: &[&str]) -> Outcome {
    Outcome::Returned(v.iter().map(|s| s.to_string()).collect())
}

/// Run `src` on a thread whose stack is 1 MiB, far less than recursion to
/// these depths would need: a walker that recursed would abort the process.
fn run_small_stack(src: &'static str) -> Outcome {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || run(src))
        .expect("a thread")
        .join()
        .expect("no panic")
}

/// D2: the C's backtrack ceilings, exactly, through `lpeg.match`. The stack
/// starts at 100 entries (`INITBACK`, the floor) and grows, when full, by
/// doubling up to the value `setmaxstack` stored, as an `int` (the C reads
/// it at each growth; no Lua but a callback the match calls runs in between,
/// so a match reads it when it starts and after each such call).
#[test]
fn the_backtrack_ceilings_are_the_cs() {
    let nested = "local S = lpeg.P{'S', S = 'a' * lpeg.V'S' * 'b' + ''} \
                  local function at(n) local ok, r = pcall(lpeg.match, S, ('a'):rep(n) .. ('b'):rep(n)) \
                  return ok and tostring(r) or r end ";
    // Two entries a level, a choice and a call: 49 levels, 98 entries,
    // with the giveup entry and the first call 100.
    assert_eq!(
        run(&format!(
            "{nested} return at(49), at(50), select(2, pcall(lpeg.match, S, ('a'):rep(50)))"
        )),
        returned(&[
            "99",
            "too many pending calls/choices",
            "too many pending calls/choices"
        ])
    );
    // Disjoint alternatives are coded with a test: one entry a level.
    assert_eq!(
        run("local S = lpeg.P{'S', S = '(' * lpeg.V'S' * ')' + 'x'} \
             local function at(n) local ok, r = pcall(lpeg.match, S, ('('):rep(n) .. 'x' .. (')'):rep(n)) \
             return ok and tostring(r) or r end return at(98), at(99)"),
        returned(&["198", "too many pending calls/choices"])
    );
    // The same at a raised ceiling: grown from 100 to exactly 150 entries,
    // so 148 levels pass and 149 fail (one entry more fails the 149th).
    assert_eq!(
        run("local S = lpeg.P{'S', S = '(' * lpeg.V'S' * ')' + 'x'} lpeg.setmaxstack(150) \
             local function at(n) local ok, r = pcall(lpeg.match, S, ('('):rep(n) .. 'x' .. (')'):rep(n)) \
             return ok and tostring(r) or r end return at(148), at(149)"),
        returned(&["298", "too many pending calls/choices"])
    );
    // A call followed by a return is a jump: no entry at all.
    assert_eq!(
        run("return lpeg.match(lpeg.P{'S', S = 'a' * lpeg.V'S' + ''}, ('a'):rep(100000))"),
        returned(&["100001"])
    );
    // `setmaxstack`: its value narrowed to an `int`, a string converted at
    // each growth, anything under the floor the floor.
    for (set, ok, fails) in [
        ("1000", 499, 500),
        ("2^32 + 1000", 499, 500),
        ("'1000'", 499, 500),
        ("'0x3e8'", 499, 500),
        ("1000.0", 499, 500),
        ("150", 74, 75),
        ("2^31", 49, 50),
        ("", 49, 50),
        ("5", 49, 50),
        ("nil", 49, 50),
    ] {
        let got = run(&format!(
            "{nested} lpeg.setmaxstack({set}) return at({ok}), at({fails})"
        ));
        assert_eq!(
            got,
            returned(&[&(2 * ok + 1).to_string(), "too many pending calls/choices"]),
            "setmaxstack({set})"
        );
    }
}

/// A match pre-empted part-way keeps the ceiling it had: another script's
/// `setmaxstack` between its slices does not reach it. In the C no Lua runs
/// inside a match but the callbacks the match calls, and a `__gc` finalizer
/// a collection during the stack's growth may run, which the port never runs
/// (`gc_metamethods_never_run`). So a match reads the ceiling when it
/// starts and again after each call it makes returns
/// (`a_setmaxstack_in_a_callback_reaches_its_own_match`), and not after a
/// plain pause for fuel.
#[test]
fn setmaxstack_does_not_reach_a_running_match() {
    let mut lua = new_lua();
    let ex = start(
        &mut lua,
        "S = lpeg.P{'S', S = 'a' * lpeg.V'S' * 'b' + ''} lpeg.match(S, '') \
         lpeg.setmaxstack(5000) return 1",
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 10).0,
        returned(&["1"])
    );
    // Compiled already, so the slice goes to the machine: a few hundred
    // levels of the 2,000 (4,001 entries), the stack grown from 100 to 800
    // and to grow four times more.
    let ex = start(
        &mut lua,
        "return lpeg.match(S, ('a'):rep(2000) .. ('b'):rep(2000))",
    );
    let t = step_traced(&mut lua, &ex, 200, 1);
    assert!(!t.done, "the match finished in one slice: {t:?}");
    let other = start(&mut lua, "lpeg.setmaxstack(100) return 1");
    assert_eq!(
        step_to_end(&mut lua, &other, 1_000_000, 10).0,
        returned(&["1"])
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, 200, 100_000).0,
        returned(&["4001"])
    );
    // The next match reads the new value.
    let ex = start(
        &mut lua,
        "return pcall(lpeg.match, S, ('a'):rep(2000) .. ('b'):rep(2000))",
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 10).0,
        returned(&["false", "too many pending calls/choices"])
    );
}

/// A `setmaxstack` a callback calls reaches the match the callback runs in,
/// as the C's `doublestack` reads the stored maximum at every growth (the
/// brief's X10): `S <- 'a' S 'b' / ''` on a^200 b^200 fails with the
/// default, and matches (401) after a match-time capture raises the
/// ceiling first.
#[test]
fn a_setmaxstack_in_a_callback_reaches_its_own_match() {
    assert_eq!(
        run(
            "local g = lpeg.P{ 'S', S = lpeg.P'a' * lpeg.V'S' * 'b' + '' } \
             local p = lpeg.Cmt(lpeg.P(true), function() lpeg.setmaxstack(1000) return true end) * g \
             local s = ('a'):rep(200) .. ('b'):rep(200) \
             lpeg.setmaxstack(100) local ok1, r1 = pcall(lpeg.match, g, s) \
             lpeg.setmaxstack(100) local ok2, r2 = pcall(lpeg.match, p, s) \
             lpeg.setmaxstack(100) return ok1, r1, ok2, r2"
        ),
        returned(&["false", "too many pending calls/choices", "true", "401"])
    );
}

/// The VM never runs a `__gc` metamethod, a table's or a userdata's
/// (`vm-gc-metamethods-never-run`): objects with one, collected in full
/// collections, are never finalized. So no Lua runs inside a match but the
/// callbacks it calls, where in the C a collection that a growth of the
/// match's stacks triggers runs pending finalizers too: the review's repro (`t5.lua`: 300
/// matches of `S <- C'a' S 'b' / ''` 100 deep under `setmaxstack(150)`, each
/// after 50 objects whose `__gc` raises the ceiling to 1,000 when it runs
/// during a match) gives the tree's oracle 210 finalizer calls mid-match and
/// 22 matches past the ceiling; here none of either, with a full collection
/// after every slice.
#[test]
fn gc_metamethods_never_run() {
    let mut lua = new_lua();
    lua.enter(|ctx| {
        // A userdata with a `__gc`, which no script can make.
        let mt = piccolo::Table::new(&ctx);
        let f = piccolo::Closure::load(ctx, Some("=gc"), &b"calls = calls + 1"[..]).unwrap();
        mt.set_field(ctx, "__gc", f);
        for _ in 0..100 {
            let u = piccolo::UserData::new_static(&ctx, 0u8);
            u.set_metatable(&ctx, Some(mt));
        }
    });
    let ex = start(
        &mut lua,
        "calls = 0 \
         for i = 1, 1000 do setmetatable({}, {__gc = function() calls = calls + 1 end}) end",
    );
    assert_eq!(step_to_end(&mut lua, &ex, 1_000, 10_000).0, returned(&[]));
    lua.gc_collect();
    lua.gc_collect();
    let ex = start(
        &mut lua,
        "collectgarbage() local L = lpeg \
         local S = L.P{'S', S = L.C'a' * L.V'S' * L.P'b' + L.P''} \
         local subj = string.rep('a', 100) .. string.rep('b', 100) \
         local inmatch, mid, wins = false, 0, 0 \
         for trial = 1, 300 do \
           for i = 1, 50 do setmetatable({}, {__gc = function() \
             if inmatch then mid = mid + 1 L.setmaxstack(1000) end end}) end \
           for i = 1, trial * 3 do local _ = {} end \
           L.setmaxstack(150) inmatch = true \
           local ok, r = pcall(L.match, S, subj) inmatch = false \
           if ok and r then wins = wins + 1 end \
         end \
         L.setmaxstack(100) \
         return calls, mid, wins",
    );
    let mut slices = 0u64;
    loop {
        let mut fuel = Fuel::with(997);
        let done = lua
            .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
            .expect("steps");
        lua.gc_collect();
        slices += 1;
        if done {
            break;
        }
        assert!(slices < 10_000_000, "runs on");
    }
    let out = lua.enter(|ctx| {
        let vs: Variadic<Vec<Value>> = ctx.fetch(&ex).take_result(ctx).unwrap().unwrap();
        vs.0.iter()
            .map(|v| v.display().to_string())
            .collect::<Vec<_>>()
    });
    assert_eq!(out, ["0", "0", "0"]);
}

/// Deep patterns built, compiled, matched and evaluated with no recursion,
/// on a thread with a 1 MiB stack: `P'a'^-200000`, past the 45,898 levels of
/// `-`, `#` and `^-1` where the C's recursive code generator crashes it, and
/// `Ct` 2,000 deep. (Built from Lua each level copies the tree, as in the C,
/// so `Ct` and `P{}` past the C's 6,159 and 7,699 levels, at ten times
/// them, are the module's own tests, built directly.)
#[test]
fn deep_patterns_match_without_recursion() {
    assert_eq!(
        run_small_stack("return lpeg.match(lpeg.P'a'^-200000, ('a'):rep(3))"),
        returned(&["4"])
    );
    assert_eq!(
        run_small_stack(
            "local p = lpeg.C(lpeg.P'a'^-200000) * -lpeg.P'b' * #(lpeg.P'a'^-200000) \
             return lpeg.match(p, ('a'):rep(5))"
        ),
        returned(&["aaaaa"])
    );
    assert_eq!(
        run_small_stack(
            "local p = lpeg.P'a' for i = 1, 2000 do p = lpeg.Ct(p) end \
             local t = lpeg.match(p, 'a') local d = 0 \
             while type(t) == 'table' do d = d + 1 t = t[1] end return d"
        ),
        returned(&["2000"])
    );
}

/// `hascaptures` does not follow a rule call (`numsiblings[TCall]` is 0),
/// so code generation treats a call as capturing nothing, and 0.12 gives:
/// a full capture placed after the call; an and-predicate that keeps the
/// called rule's captures; values out of order (`docs/M6.6-ANALYSIS.md` §5).
#[test]
fn hascaptures_does_not_follow_calls() {
    assert_eq!(
        run(
            "local t = { lpeg.match(lpeg.P{'A', A = lpeg.Ct(lpeg.V'B'), B = lpeg.C'x'}, 'x') } \
             return t[1], #t[2], select('#', table.unpack(t))"
        ),
        returned(&["x", "0", "2"])
    );
    assert_eq!(
        run(
            "return lpeg.match(lpeg.P{'A', A = #lpeg.V'B' * 1, B = lpeg.C'x'}, 'x'), \
                    lpeg.match(#lpeg.C'x' * 1, 'x')"
        ),
        returned(&["x", "2"])
    );
    assert_eq!(
        run(
            "return lpeg.match(lpeg.P{'A', A = lpeg.C(lpeg.V'B') * lpeg.V'B', B = lpeg.Cc(1)}, '')"
        ),
        returned(&["1", "", "1"])
    );
}

/// The Lua-stack ceiling on captures: `luaL_checkstack(L, 4, ...)` at each
/// capture evaluated, "stack overflow (too many captures)" past it. Where
/// it falls is the embedding's (the frames below the call, which piccolo
/// lays out otherwise than the C: `stack-limit-counts-slots-differently`);
/// relative to `table.unpack`'s ceiling in the same frame it is the C's,
/// -5. Values that pass LPeg's check, handed to a function whose frame
/// cannot hold them, are Lua's own bare "stack overflow".
#[test]
fn the_capture_ceiling_is_the_cs() {
    let src = "local p = lpeg.C(1) ^ 0 \
               local function maxok(lo, hi, test) \
                 while hi - lo > 1 do local mid = (lo + hi) // 2 \
                   if test(mid) then lo = mid else hi = mid end end return lo end \
               local caps = maxok(900000, 1000001, function(n) return (pcall(lpeg.match, p, ('a'):rep(n))) end) \
               local unp = maxok(900000, 1000001, function(n) return (pcall(table.unpack, {}, 1, n)) end) \
               local ok, e = pcall(lpeg.match, p, ('a'):rep(caps + 50)) \
               local big = load('return function(...) ' .. ('local x '):rep(200) .. ' return select(\"#\", ...) end')() \
               local ok2, e2 = pcall(function() return big(lpeg.match(p, ('a'):rep(caps - 2))) end) \
               return caps - unp, ok, e, ok2, e2";
    assert_eq!(
        run(src),
        returned(&[
            "-5",
            "false",
            "stack overflow (too many captures)",
            "false",
            "chunk:1: stack overflow"
        ])
    );
    // A table holds its values off the stack: no ceiling.
    assert_eq!(
        run("local t = lpeg.match(lpeg.Ct(lpeg.C(1)^0), ('a'):rep(1200000)) return #t"),
        returned(&["1200000"])
    );
}

/// `Cc(nil)` adds no constant, and the C's `Cconst` reads entry 0 of a
/// constant table the pattern may not have (`lpeg-cc-nil-without-ktable`,
/// a crash): here it is nil.
#[test]
fn cc_nil_reads_no_constant_table() {
    assert_eq!(
        run(
            "return select('#', lpeg.match(lpeg.Cc(nil), '')), lpeg.match(lpeg.Cc(nil), ''), \
                    lpeg.match(lpeg.Cc(nil) * lpeg.Cc(1), '')"
        ),
        returned(&["1", "nil", "nil", "1"])
    );
    assert_eq!(
        run(
            "return #lpeg.match(lpeg.Ct(lpeg.Cc(nil) * lpeg.Cc(nil)), ''), \
                    lpeg.match(lpeg.Cs(lpeg.Cc(nil) / 0 * 'x'), 'x')"
        ),
        returned(&["0", "x"])
    );
}

/// The C's peephole goes on from the slot before a jump it turned into a
/// commit, loses its alignment, and follows labels out of the code
/// (`lpeg-codegen-jump-out-of-code`: H06 and H07 crash 7.94 in some
/// harnesses). The answer of the C with that fixed: 1, both.
#[test]
fn the_peephole_stays_aligned() {
    assert_eq!(
        run("return lpeg.match(lpeg.P{lpeg.P''}^-1, 'x'), \
                    lpeg.match(-(lpeg.S'' * 'a') + 'c', 'x')"),
        returned(&["1", "1"])
    );
}

/// The compiled program is kept on the pattern only once it is whole (the
/// C keeps it from the start of compiling: `lpeg-partial-program-not-cached`),
/// and an error in `finalfix` caches nothing, so it is raised at every
/// match.
#[test]
fn a_failed_compile_caches_nothing() {
    // A compile the memory budget refuses part-way: the C would keep the
    // partial program and run it at the next match; here the next match
    // compiles again, and answers.
    let mut lua = new_lua();
    let ex = start(&mut lua, "p = lpeg.P'a'^-200000 collectgarbage() return 1");
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 1_000).0,
        returned(&["1"])
    );
    lua.set_memory_limit(lua.total_memory() + (2 << 20));
    let ex = start(&mut lua, "return pcall(lpeg.match, p, 'aaa')");
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 1_000).0,
        returned(&["false", "not enough memory"])
    );
    lua.set_memory_limit(usize::MAX);
    let ex = start(&mut lua, "return lpeg.match(p, 'aaa')");
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 1_000).0,
        returned(&["4"])
    );
    // An error before any code: nothing to keep, in the C too.
    assert_eq!(
        run("local p = lpeg.V'a' * 1 \
             return select(2, pcall(lpeg.match, p, 'x')), select(2, pcall(lpeg.match, p, 'x'))"),
        returned(&[
            "rule 'a' used outside a grammar",
            "rule 'a' used outside a grammar"
        ])
    );
}

/// Every stage of a match returns to the VM between slices of fuel (D3):
/// compiling a large pattern, matching an exponential grammar, evaluating
/// nested back-references. Each finishes with the answer one slice gives,
/// after many slices, no slice running past its fuel by more than a fixed
/// amount. And compiling a grammar whose analyses the C repeats
/// exponentially (`Rᵢ ← Rᵢ₋₁'x' / Rᵢ₋₁'y'`, 13 s at n = 24) takes steps
/// linear in it.
#[test]
fn every_stage_of_a_match_is_pre_empted() {
    let cases = [
        // Compile: 800,000 nodes, copied, fixed and coded a slice at a time.
        ("p = lpeg.P'a'^-200000", "return lpeg.match(p, 'b')", "1"),
        // Match: `S <- 'a' S 'b' / 'a' S 'c' / ''` on a^16 d is 2^16 attempts.
        (
            "p = lpeg.P{'S', S = 'a' * lpeg.V'S' * 'b' + 'a' * lpeg.V'S' * 'c' + ''} lpeg.match(p, '')",
            "return lpeg.match(p, ('a'):rep(16) .. 'd')",
            "1",
        ),
        // Capture evaluation: each `Cb` evaluates the group before it again,
        // 2^12 values from 13 groups, no Lua call involved.
        (
            "local g = lpeg.Cg(lpeg.C(1), 'a') \
             for i = 1, 12 do g = g * lpeg.Cg(lpeg.Cb'a' * lpeg.Cb'a', 'a') end \
             p = lpeg.Ct(g * lpeg.Cb'a') lpeg.match(p, 'y')",
            "return #lpeg.match(p, 'x')",
            "4096",
        ),
        // Step d: 2^13 such values evaluated inside a match-time capture
        // when it closes, then made its function's arguments. (The
        // callbacks take the first: a Lua function that walks 8,192 varargs
        // runs 15,000 units past its slice on its own, `f(table.unpack(t))`
        // as much, which is the VM's granularity, not LPeg's.)
        (
            "local g = lpeg.Cg(lpeg.C(1), 'a') \
             for i = 1, 13 do g = g * lpeg.Cg(lpeg.Cb'a' * lpeg.Cb'a', 'a') end \
             p = lpeg.Cmt(g * lpeg.Cb'a', function(s, i, a) return true, a end) \
             lpeg.match(p, 'y')",
            "return lpeg.match(p, 'x')",
            "x",
        ),
        // And made a `/function`'s arguments after the match.
        (
            "local g = lpeg.Cg(lpeg.C(1), 'a') \
             for i = 1, 13 do g = g * lpeg.Cg(lpeg.Cb'a' * lpeg.Cb'a', 'a') end \
             p = (g * lpeg.Cb'a') / function(a) return a .. '!' end lpeg.match(p, 'y')",
            "return lpeg.match(p, 'x')",
            "x!",
        ),
    ];
    for (setup, src, want) in cases {
        let mut lua = new_lua();
        let ex = start(&mut lua, setup);
        assert_eq!(
            step_to_end(&mut lua, &ex, 1_000_000, 10_000).0,
            returned(&[])
        );
        let ex = start(&mut lua, src);
        let t = step_traced(&mut lua, &ex, 10_000, 1_000_000);
        assert!(t.done && t.slices > 20, "{src}: {t:?}");
        assert!(
            t.deepest > -2_000,
            "{src}: a slice ran {} past its fuel",
            -t.deepest
        );
        let (out, _) = step_to_end(&mut lua, &ex, 10_000, 1);
        assert_eq!(out, returned(&[want]), "{src}");
    }
    // The chain the C's compile takes 13 s over at n = 24 (0.16 s at
    // n = 18): its build (the verifier, 2^n) is step b's; its compile, a few
    // thousand steps.
    let mut lua = new_lua();
    let ex = start(
        &mut lua,
        "local g = { 'R18', R0 = lpeg.P'z' } \
         for i = 1, 18 do g['R' .. i] = lpeg.V('R' .. (i - 1)) * 'x' + lpeg.V('R' .. (i - 1)) * 'y' end \
         p = lpeg.P(g) return 1",
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 100_000).0,
        returned(&["1"])
    );
    let ex = start(&mut lua, "return lpeg.match(p, 'z' .. ('x'):rep(18))");
    let t = step_traced(&mut lua, &ex, 1_000, 1_000);
    assert!(t.done && t.slices < 100, "compiling the chain: {t:?}");
}

/// The review's repros of work that took fuel out of proportion to it, at a
/// reduced scale: (setup, the match, its answer).
const BYTE_WORK: &[(&str, &str, &str)] = &[
    // `/string` whose every `%1` is a non-simple capture: its frame reads
    // the 40,000-byte format again at each, which a copy made quadratic.
    (
        "fmt = ('%1'):rep(20000)",
        "return #lpeg.match(lpeg.Cc'z' / fmt, '')",
        "20000",
    ),
    // 64 back-references to a group holding the whole 64 KiB subject: each
    // value a Lua string made of 64 KiB (hashed, compared, kept).
    (
        "s = ('a'):rep(65536) local refs = lpeg.Cb'x' for i = 1, 6 do refs = refs * refs end \
         p = lpeg.Cg(lpeg.C(lpeg.P(1)^0), 'x') * refs",
        "return select('#', lpeg.match(p, s))",
        "64",
    ),
    // The same values into a table.
    (
        "s = ('a'):rep(65536) local refs = lpeg.Cb'x' for i = 1, 6 do refs = refs * refs end \
         p = lpeg.Ct(lpeg.Cg(lpeg.C(lpeg.P(1)^0), 'x') * refs)",
        "return #lpeg.match(p, s)",
        "64",
    ),
    // A substitution whose every replacement is a 64 KiB constant.
    (
        "big = ('b'):rep(65536) p = lpeg.Cs((lpeg.P(1) * lpeg.Cc(big))^0) s = ('a'):rep(64)",
        "return #lpeg.match(p, s)",
        "4194368",
    ),
    // A `/string` slot of 1 MiB of subject, twice; a substitution of a
    // string another made.
    (
        "s = ('a'):rep(1 << 20)",
        "return #lpeg.match(lpeg.P(1)^0 / '%0%0', s), \
                #lpeg.match(lpeg.Cs(lpeg.Cs(lpeg.P(1)^0) / 1), s)",
        "2097152",
    ),
    // 16 back-references to a substitution of the whole 256 KiB subject
    // (the memory finding's shape): each copies the subject again.
    (
        "s = ('a'):rep(262144) local refs = lpeg.Cb'x' for i = 1, 4 do refs = refs * refs end \
         p = lpeg.Cg(lpeg.Cs(lpeg.P(1)^0), 'x') * refs",
        "return select('#', lpeg.match(p, s))",
        "16",
    ),
    // `C` nested 3,000 deep at match time: each level's whole match moved
    // below its nested values, 4.5 million values moved in all.
    (
        "lpeg.setmaxstack(100000) p = lpeg.P{'S', S = lpeg.C('a' * lpeg.V'S' + '')} \
         s = ('a'):rep(3000)",
        "return select('#', lpeg.match(p, s))",
        "3001",
    ),
    // A table of 200,000 positions.
    (
        "s = ('a'):rep(200000) p = lpeg.Ct((lpeg.Cp() * 1)^0)",
        "return #lpeg.match(p, s)",
        "200000",
    ),
    // The compiler's memo tables for a tree of 400,000 nodes.
    ("p = lpeg.P'a'^-100000", "return lpeg.match(p, 'b')", "1"),
    // Step d. A fold over 20,000 values, each the result of a call: 40,000
    // calls, each through the VM.
    (
        "p = lpeg.Cf(lpeg.Cc(0) * (lpeg.C(1) / function(c) return 1 end)^0, \
           function(a, b) return a + b end) s = ('a'):rep(20000)",
        "return lpeg.match(p, s)",
        "20000",
    ),
    // A `/table` indexed by a 1 MiB key, made a Lua string for its
    // `__index`.
    (
        "s = ('a'):rep(1 << 20) \
         p = lpeg.C(lpeg.P(1)^0) / setmetatable({}, { __index = function(_, k) return #k end })",
        "return lpeg.match(p, s)",
        "1048576",
    ),
    // A match-time capture returning 100,000 values, kept as captures and
    // read back.
    (
        "T = {} for i = 1, 100000 do T[i] = i end \
         p = lpeg.Cmt(1, function() return true, table.unpack(T) end)",
        "return select('#', lpeg.match(p, 'a'))",
        "100000",
    ),
    // 50,000 dynamic captures in a table capture, each read from the window.
    (
        "p = lpeg.Ct(lpeg.Cmt(1, function(s, i) return true, i end)^0) s = ('a'):rep(50000)",
        "return #lpeg.match(p, s)",
        "50000",
    ),
    // Dynamic captures 2,000 deep: each level's match-time capture gets its
    // inner ones' values and returns them all and one more, 2 million in all
    // (the innermost gets the whole match, `"a"`: 2,001 values, the C's).
    (
        "lpeg.setmaxstack(100000) \
         p = lpeg.P{'S', S = lpeg.Cmt('a' * lpeg.V'S', function(s, i, ...) return true, i, ... end) + ''} \
         s = ('a'):rep(2000)",
        "return select('#', lpeg.match(p, s))",
        "2001",
    ),
    // A table capture of 100,000 entries made a Lua table for a call, and a
    // call of 100,000 arguments.
    (
        "s = ('a'):rep(100000) \
         p = lpeg.Ct(lpeg.C(1)^0) / function(t) return #t end \
         q = lpeg.C(1)^0 / function(...) return select('#', ...) end",
        "return lpeg.match(p, s) + lpeg.match(q, s)",
        "200000",
    ),
];

/// D3, counted: no slice of a match does more than a few times the work its
/// fuel pays for. The work is counted where it is done, apart from the fuel
/// charged for it (`lpeg::take_work`): an instruction, a frame of capture
/// evaluation, a compiler step or a jump followed is `BYTES_PER_FUEL`
/// bytes, and every byte copied into a buffer or a Lua string, hashed,
/// compared, moved or filled is one. A step pays for itself and a unit for
/// each `BYTES_PER_FUEL` bytes, so a slice that pays for what it does stays
/// within twice its fuel's worth; work done without paying shows as more.
/// Each case runs in the engine's slices (4,096 units; a match takes at
/// least 1,024 a slice).
#[test]
fn no_slice_does_more_work_than_its_fuel_pays_for() {
    use nmap_core::nse::lpeg::{take_work, BYTES_PER_FUEL};
    const SLICE: i32 = 4096;
    let per = u64::try_from(BYTES_PER_FUEL).unwrap();
    for &(setup, src, want) in BYTE_WORK {
        let mut lua = new_lua();
        let ex = start(&mut lua, setup);
        assert_eq!(
            step_to_end(&mut lua, &ex, 1_000_000, 10_000).0,
            returned(&[]),
            "{setup}"
        );
        let ex = start(&mut lua, src);
        let _ = take_work();
        let (mut slices, mut worst, mut total) = (0u64, 0f64, 0u64);
        loop {
            let mut fuel = Fuel::with(SLICE);
            let done = lua
                .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
                .expect("steps");
            let used = u64::try_from(i64::from(SLICE) - i64::from(fuel.remaining()))
                .unwrap_or(0)
                .max(1);
            let work = take_work();
            total += work;
            worst = worst.max(work as f64 / (used * per) as f64);
            assert!(
                work <= 4 * per * used + 8 * per,
                "{src}: slice {slices} did {work} bytes' work on {used} units of fuel"
            );
            slices += 1;
            if done {
                break;
            }
            assert!(slices < 1_000_000, "{src}: runs on");
        }
        assert!(slices > 2, "{src}: not pre-empted ({slices} slices)");
        assert!(total > 0, "{src}: no work counted");
        let out = lua.enter(|ctx| {
            let vs: Variadic<Vec<Value>> = ctx.fetch(&ex).take_result(ctx).unwrap().unwrap();
            match vs.0.first() {
                Some(v) => v.display().to_string(),
                None => String::new(),
            }
        });
        assert_eq!(out, want, "{src}");
        eprintln!("{src}: {slices} slices, at most {worst:.2} of the fuel's worth");
    }
}

/// E4 within a slice: what a match grows is accounted to the heap as it
/// grows, and a growth that takes the heap past the memory budget ends the
/// slice, so the collection the VM runs before Lua goes on sees it. The
/// review's 256 back-references to a substitution of an 8 MiB subject, at a
/// 64 MiB budget, peaked at 344 MB inside one slice before "not enough
/// memory"; here 64 back-references to a substitution of 1 MiB under a
/// budget 8 MiB above what the state holds, in slices with fuel enough to
/// finish in one: the heap, as the budget counts it, never passes the budget
/// by more than one growth (a 1 MiB buffer, room made at once for its text).
#[test]
fn a_match_passes_the_memory_budget_by_at_most_one_growth() {
    use nmap_core::nse::lpeg::take_peak_accounted;
    let mut lua = new_lua();
    let ex = start(
        &mut lua,
        "s = ('a'):rep(1 << 20) local refs = lpeg.Cb'x' for i = 1, 6 do refs = refs * refs end \
         p = lpeg.Cg(lpeg.Cs(lpeg.P(1)^0), 'x') * refs lpeg.match(p, 'a') collectgarbage()",
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 1_000).0,
        returned(&[])
    );
    let limit = lua.total_memory() + (8 << 20);
    lua.set_memory_limit(limit);
    let _ = take_peak_accounted();
    let ex = start(
        &mut lua,
        "return pcall(function() return select('#', lpeg.match(p, s)) end)",
    );
    let mut peak = 0usize;
    let mut slices = 0u64;
    loop {
        let mut fuel = Fuel::with(i32::MAX);
        let done = lua
            .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
            .expect("steps");
        peak = peak.max(lua.total_memory());
        slices += 1;
        if done {
            break;
        }
        assert!(slices < 1_000, "runs on");
    }
    let accounted = take_peak_accounted();
    let peak = peak.max(accounted);
    let out = lua.enter(|ctx| {
        let vs: Variadic<Vec<Value>> = ctx.fetch(&ex).take_result(ctx).unwrap().unwrap();
        vs.0.iter()
            .map(|v| v.display().to_string())
            .collect::<Vec<_>>()
    });
    assert_eq!(out, ["false", "not enough memory"]);
    assert!(
        accounted > limit - (8 << 20) + (1 << 20),
        "the growths were not accounted as they happened: {accounted}"
    );
    assert!(
        peak <= limit + (1 << 20) + (64 << 10),
        "the heap passed the budget ({limit}) by {} bytes",
        peak.saturating_sub(limit)
    );
}

/// E4 within a slice for the captures that call Lua (step d): the values a
/// call takes, made Lua values in a list that grows through the budget; a
/// table capture made a Lua table for a call; the values match-time
/// captures keep, on the match's stack, and their entries in the capture
/// list. Each case, under a budget 8 MiB above what the state holds, fails
/// with "not enough memory", and the heap, as the budget counts it, passes
/// the budget by at most its largest single growth: (setup, the match, that
/// growth's bound).
#[test]
fn calls_pass_the_memory_budget_by_at_most_one_growth() {
    use nmap_core::nse::lpeg::take_peak_accounted;
    let cases: [(&str, &str, usize); 3] = [
        // 400,000 values to a call: the capture list (24 bytes an entry,
        // doubling to 2^19), the cursor's values (as many), the arguments
        // (16 bytes each), each growth asking the budget first, which refuses
        // the one that would not fit (4 KB past it, measured: the strings
        // around it).
        (
            "s = ('a'):rep(400000) p = lpeg.C(1)^0 / function(...) return select('#', ...) end \
             lpeg.match(p, 'a') collectgarbage()",
            "return pcall(lpeg.match, p, s)",
            64 << 10,
        ),
        // A table of 400,000 entries made a Lua table for a call (4 KB).
        (
            "s = ('a'):rep(400000) p = lpeg.Ct(lpeg.C(1)^0) / function(t) return #t end \
             lpeg.match(p, 'a') collectgarbage()",
            "return pcall(lpeg.match, p, s)",
            64 << 10,
        ),
        // Match-time captures keeping 1,000 values each: the window — the
        // match's stack, 16 bytes a value, doubling as Lua's stack does —
        // and the capture list grow (3.9 MB past the budget, measured: the
        // stack's doubling from 2^18 values).
        (
            "T = {} for i = 1, 1000 do T[i] = i end s = ('a'):rep(900) \
             p = lpeg.Cmt(1, function() return true, table.unpack(T) end)^0 \
             lpeg.match(p, 'a') collectgarbage()",
            "return pcall(lpeg.match, p, s)",
            (1 << 18) * 24,
        ),
    ];
    for (setup, src, bound) in cases {
        let mut lua = new_lua();
        let ex = start(&mut lua, setup);
        assert_eq!(
            step_to_end(&mut lua, &ex, 1_000_000, 1_000).0,
            returned(&[]),
            "{setup}"
        );
        let limit = lua.total_memory() + (8 << 20);
        lua.set_memory_limit(limit);
        let _ = take_peak_accounted();
        let ex = start(&mut lua, src);
        let mut peak = 0usize;
        let mut slices = 0u64;
        loop {
            let mut fuel = Fuel::with(i32::MAX);
            let done = lua
                .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
                .expect("steps");
            peak = peak.max(lua.total_memory());
            slices += 1;
            if done {
                break;
            }
            assert!(slices < 100_000, "{setup}: runs on");
        }
        let peak = peak.max(take_peak_accounted());
        let out = lua.enter(|ctx| {
            let vs: Variadic<Vec<Value>> = ctx.fetch(&ex).take_result(ctx).unwrap().unwrap();
            vs.0.iter()
                .map(|v| v.display().to_string())
                .collect::<Vec<_>>()
        });
        eprintln!(
            "{setup}: {out:?}, past the budget by {}",
            peak.saturating_sub(limit)
        );
        assert_eq!(out, ["false", "not enough memory"], "{setup}");
        assert!(
            peak <= limit + bound,
            "{setup}: the heap passed the budget ({limit}) by {} bytes",
            peak.saturating_sub(limit)
        );
    }
}

/// What capture evaluation holds for a table capture is given back as the
/// table fills (F5): a table of 200,000 positions, 40 bytes each in the
/// cursor, filled in the engine's slices. In the last slice before the match
/// ends, the cursor holds a small part of them, where it held them all to
/// the end before.
#[test]
fn a_table_capture_gives_back_what_it_filled() {
    let mut lua = new_lua();
    let ex = start(
        &mut lua,
        "s = ('a'):rep(200000) p = lpeg.Ct((lpeg.Cp() * 1)^0) lpeg.match(p, '') collectgarbage()",
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 1_000).0,
        returned(&[])
    );
    let ex = start(&mut lua, "t = lpeg.match(p, s) return #t");
    let mut held = Vec::new();
    loop {
        let mut fuel = Fuel::with(4096);
        let done = lua
            .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
            .expect("steps");
        held.push(lua.total_memory());
        if done {
            break;
        }
    }
    let out = lua.enter(|ctx| {
        let vs: Variadic<Vec<Value>> = ctx.fetch(&ex).take_result(ctx).unwrap().unwrap();
        vs.0[0].display().to_string()
    });
    assert_eq!(out, "200000");
    // The table is whole and the cursor gone at the end; one slice before,
    // the cursor's list is all but given back.
    let (last, before) = (held[held.len() - 1], held[held.len() - 2]);
    assert!(
        before.saturating_sub(last) < 200_000 * 40 / 4,
        "the slice before the end held {} bytes more than the end",
        before.saturating_sub(last)
    );
}

/// Two script threads in one state share a pattern no match has compiled
/// yet, and run alternately in slices of 64 and 5 units with a full
/// collection after every slice, while one of them calls the pattern's
/// `__gc` and `setmaxstack` between its matches: each compiles it, one keeps
/// its program, and every result is what the threads give run one after the
/// other in one slice each (E3).
#[test]
fn concurrent_compiles_of_a_shared_pattern_agree() {
    const SETUP: &str = "local P, C, Ct, Cg, Cb, Cc, Cp, Cs, V = lpeg.P, lpeg.C, lpeg.Ct, lpeg.Cg, \
        lpeg.Cb, lpeg.Cc, lpeg.Cp, lpeg.Cs, lpeg.V \
        G = P{ 'list', \
          list = Ct((V'item' * (',' * V'item')^0)^-1), \
          item = Cg(C(lpeg.R'az'^1), 'k') * '=' \
                 * (Cs((P'\\\\' / '' * 1 + (1 - lpeg.S',;'))^0) / '<%0>') * Cb'k' * Cp() * Cc(true), \
        } \
        local subj = {} \
        for i = 1, 300 do subj[#subj + 1] = 'key' .. string.char(97 + i % 26) .. '=val\\\\,ue' .. i end \
        SUBJ = table.concat(subj, ',') \
        function digest(t) \
          local acc = {} \
          for i = 1, #t do acc[#acc + 1] = tostring(t[i]) end \
          return #t .. ':' .. #table.concat(acc, '|') .. ':' .. tostring(acc[1]) .. ':' .. tostring(acc[#acc]) \
        end";
    // `A` matches three times: its first match compiles alongside `B`'s,
    // and the other two run while `B` calls `__gc` and `setmaxstack`.
    const A: &str = "local out = {} \
                     for i = 1, 3 do out[i] = digest(lpeg.match(G, SUBJ)) end \
                     return table.unpack(out)";
    const B: &str = "local out = { digest(lpeg.match(G, SUBJ)) } \
                     local gc = getmetatable(G).__gc \
                     for i = 1, 3000 do gc(G) lpeg.setmaxstack(i % 7 == 0 and 5 or 1000 + i) end \
                     out[#out + 1] = digest(lpeg.match(G, SUBJ)) \
                     lpeg.setmaxstack(100) \
                     return table.concat(out, ' ')";
    let outcome = |lua: &mut piccolo::Lua, ex: &piccolo::StashedExecutor| {
        lua.enter(
            |ctx| match ctx.fetch(ex).take_result::<Variadic<Vec<Value>>>(ctx) {
                Ok(Ok(vs)) => vs.0.iter().map(|v| v.display().to_string()).collect(),
                Ok(Err(e)) => vec![format!("raised: {e:#}")],
                Err(e) => vec![format!("not done: {e}")],
            },
        )
    };
    // One after the other, each in one slice.
    let mut lua = new_lua();
    let setup = start(&mut lua, SETUP);
    assert!(step_only(&mut lua, &setup, i32::MAX, 1).0);
    let a = start(&mut lua, A);
    assert!(step_only(&mut lua, &a, i32::MAX, 1).0);
    let b = start(&mut lua, B);
    assert!(step_only(&mut lua, &b, i32::MAX, 1).0);
    let want = (outcome(&mut lua, &a), outcome(&mut lua, &b));
    // 300 items of four values each; the name each `Cg` gives is the table's.
    assert!(want.0[0].starts_with("1200:"), "{want:?}");
    // Side by side.
    for slice in [64, 5] {
        let mut lua = new_lua();
        let setup = start(&mut lua, SETUP);
        assert!(step_only(&mut lua, &setup, i32::MAX, 1).0);
        let exs = [start(&mut lua, A), start(&mut lua, B)];
        let mut done = [false, false];
        let mut slices = 0u64;
        while !(done[0] && done[1]) {
            for (i, ex) in exs.iter().enumerate() {
                if done[i] {
                    continue;
                }
                let mut fuel = Fuel::with(slice);
                done[i] = lua
                    .enter(|ctx| ctx.fetch(ex).step(ctx, &mut fuel))
                    .expect("steps");
                lua.gc_collect();
                slices += 1;
            }
            assert!(slices < 10_000_000, "runs on");
        }
        assert!(slices > 100, "{slices} slices");
        let got = (outcome(&mut lua, &exs[0]), outcome(&mut lua, &exs[1]));
        assert_eq!(got, want, "slices of {slice}");
    }
}

/// For manual runs (`cargo test --release --test lpeg_match_limits -- --ignored
/// --nocapture lpeg_slice_times`): the time slices of the engine's size take
/// on the machine's instructions and on byte work, and how long the longest
/// is. `BYTES_PER_FUEL` is chosen so a slice of byte work takes no longer
/// than one of instructions. Wall-clock: never asserted.
#[test]
#[ignore = "wall-clock; for manual runs in a release build"]
fn lpeg_slice_times() {
    use std::time::{Duration, Instant};
    let instructions: &[(&str, &str)] = &[
        (
            "p = lpeg.P{'S', S = 'a' * lpeg.V'S' * 'b' + 'a' * lpeg.V'S' * 'c' + ''} \
             s = ('a'):rep(20) .. 'd' lpeg.match(p, '')",
            "return lpeg.match(p, s)",
        ),
        (
            "p = (lpeg.P'a' * 'b' + 1)^0 s = ('ac'):rep(1 << 21) lpeg.match(p, '')",
            "return lpeg.match(p, s)",
        ),
        (
            "local g = lpeg.Cg(lpeg.C(1), 'a') \
             for i = 1, 18 do g = g * lpeg.Cg(lpeg.Cb'a' * lpeg.Cb'a', 'a') end \
             p = g * lpeg.Cb'a' lpeg.match(p, 'y')",
            "return select('#', lpeg.match(p, 'x'))",
        ),
    ];
    let bytes: &[(&str, &str)] = &[
        // 64 values of 2 MiB, each hashed and compared with the string of
        // its text the subject already is.
        (
            "s = ('a'):rep(2 << 20) local refs = lpeg.Cb'x' for i = 1, 6 do refs = refs * refs end \
             p = lpeg.Cg(lpeg.C(lpeg.P(1)^0), 'x') * refs",
            "return select('#', lpeg.match(p, s:sub(1, -2) .. 'b'))",
        ),
        // 200 copies of a 1 MiB constant into a growing buffer, then a
        // 200 MiB string made of it (at once: its slice is the longest).
        (
            "big = ('b'):rep(1 << 20) p = lpeg.Cs((lpeg.P(1) * lpeg.Cc(big))^0) s = ('a'):rep(200)",
            "return #lpeg.match(p, s)",
        ),
        // The same copies, the buffer dropped (`/2` keeps the `Cc`).
        (
            "big = ('b'):rep(1 << 20) p = (lpeg.Cs((lpeg.P(1) * lpeg.Cc(big))^0) * lpeg.Cc(1)) / 2 \
             s = ('a'):rep(200)",
            "return lpeg.match(p, s)",
        ),
        // A format of a million `%1`, each a capture evaluated again.
        (
            "fmt = ('%1'):rep(1000000) p = lpeg.Cc'z' / fmt",
            "return #lpeg.match(p, '')",
        ),
        // 8 MiB of subject into a buffer twice, and the 16 MiB string.
        (
            "s = ('a'):rep(1 << 23)",
            "return #lpeg.match(lpeg.P(1)^0 / '%0%0', s)",
        ),
        // `C` nested 20,000 deep: 200 million values moved.
        (
            "lpeg.setmaxstack(1000000) p = lpeg.P{'S', S = lpeg.C('a' * lpeg.V'S' + '')} \
             s = ('a'):rep(20000)",
            "return select('#', lpeg.match(p, s))",
        ),
        // A table of 4 million positions. Its longest slice is the Lua
        // table's array growing, as in plain Lua (the next case).
        (
            "s = ('a'):rep(1 << 22) p = lpeg.Ct((lpeg.Cp() * 1)^0)",
            "return #lpeg.match(p, s)",
        ),
        ("n = 1 << 22", "local t = {} for i = 1, n do t[i] = i end return #t"),
        // A compile of 4 million nodes, the memo tables among them.
        ("p = lpeg.P'a'^-1000000", "return lpeg.match(p, 'b')"),
    ];
    for (kind, cases) in [("instructions", instructions), ("bytes", bytes)] {
        for &(setup, src) in cases {
            for slice in [4096, 100_000] {
                let mut lua = new_lua();
                let ex = start(&mut lua, setup);
                assert!(step_only(&mut lua, &ex, i32::MAX, 1_000).0, "{setup}");
                let ex = start(&mut lua, src);
                let _ = nmap_core::nse::lpeg::take_work();
                let (mut slices, mut fuel_used, mut longest) = (0u64, 0i64, Duration::ZERO);
                let t0 = Instant::now();
                loop {
                    let mut fuel = Fuel::with(slice);
                    let t = Instant::now();
                    let done = lua
                        .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
                        .expect("steps");
                    longest = longest.max(t.elapsed());
                    fuel_used += i64::from(slice) - i64::from(fuel.remaining());
                    slices += 1;
                    if done {
                        break;
                    }
                }
                let total = t0.elapsed();
                let work = nmap_core::nse::lpeg::take_work();
                println!(
                    "{kind:>12} slice {slice:>6}: {slices:>7} slices, {total:>10.3?}, longest {longest:>10.3?}, \
                     {:.2} ns a unit, {:.3} ns a byte of work: {}",
                    total.as_nanos() as f64 / fuel_used.max(1) as f64,
                    total.as_nanos() as f64 / work.max(1) as f64,
                    src
                );
            }
        }
    }
}

/// What a match holds counts against the memory budget (E4): a capture
/// list, a backtrack stack or a capture's string the budget refuses is
/// "not enough memory", and the state goes on.
#[test]
fn a_match_is_held_to_the_memory_budget() {
    let mut lua = new_lua();
    lua.set_memory_limit(32 << 20);
    let ex = start(
        &mut lua,
        "local s = ('a'):rep(3000000) \
         local ok, e = pcall(lpeg.match, lpeg.C(1)^0, s) \
         lpeg.setmaxstack(2^30) \
         local deep = lpeg.P{'S', S = 'a' * lpeg.V'S' * 'b' + ''} \
         local ok2, e2 = pcall(lpeg.match, deep, s) \
         lpeg.setmaxstack(100) \
         local ok3, e3 = pcall(lpeg.match, lpeg.Cs((lpeg.P(1) / ('x'):rep(100))^0), s:sub(1, 500000)) \
         local ok4, e4 = pcall(lpeg.match, lpeg.C(1)^0 * 'x', s) \
         return ok, e, ok2, e2, ok3, e3, ok4, e4, lpeg.match(lpeg.C'a', 'a')",
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, 1_000_000, 100_000).0,
        returned(&[
            "false",
            "not enough memory",
            "false",
            "not enough memory",
            "false",
            "not enough memory",
            "false",
            "not enough memory",
            "a"
        ])
    );
    // Within one slice, with no slice boundary at which the VM sees what a
    // match holds: the capture list asks the budget as it grows. One the
    // match then drops (no `'x'`: the C, with no budget, gives nil) is
    // refused all the same, where a list grown without asking would not be.
    let mut lua = new_lua();
    lua.set_memory_limit(32 << 20);
    let ex = start(
        &mut lua,
        "local s = ('a'):rep(3000000) return pcall(lpeg.match, lpeg.C(1)^0 * 'x', s)",
    );
    assert_eq!(
        step_to_end(&mut lua, &ex, i32::MAX, 10).0,
        returned(&["false", "not enough memory"])
    );
}

/// Left calls through `lpeg.B`, which the verifier does not follow
/// (`lpeg-getfirst-unbounded-recursion`): 334 grammars in six uses each,
/// against the C (with its peephole and `Cc(nil)` defects fixed:
/// `m66c_behind_golden.txt`). Where the C answers, the port answers the
/// same; where the C's `getfirst` recursed until it crashed, the port's
/// first match raises "rule '...' may be left recursive" — and nowhere
/// else. The C descends into a call the same whatever the follow set, so
/// re-entering a rule on the walk is exactly where its recursion does not
/// end.
#[test]
fn left_calls_through_behind_compile_where_the_c_does() {
    let m6 = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6");
    let cases = std::fs::read_to_string(m6.join("oracle/m66c_behind.lua")).expect("the cases");
    let golden = std::fs::read_to_string(m6.join("m66c_behind_golden.txt")).expect("the golden");
    let golden: Vec<(usize, String)> = golden
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let (i, o) = l.split_once('\t').expect("i<TAB>outcome");
            (i.parse().expect("a case number"), o.to_string())
        })
        .collect();
    let mut lua = new_lua();
    let src = format!("local m = (function() {cases} end)() run_case = m.run return m.count");
    let ex = start(&mut lua, &src);
    let Outcome::Returned(count) = step_to_end(&mut lua, &ex, 1_000_000, 1_000).0 else {
        panic!("the cases did not load");
    };
    assert_eq!(count[0].parse::<usize>().ok(), Some(golden.len()));
    // Each case on its own budget: where the C runs on, so does the port —
    // a slice at a time, until the budget is spent.
    let got: Vec<String> = (1..=golden.len())
        .map(|i| {
            let ex = start(&mut lua, &format!("return run_case({i})"));
            match step_to_end(&mut lua, &ex, 100_000, 100).0 {
                Outcome::Returned(v) => v[0].clone(),
                Outcome::Unfinished => "HANG".to_string(),
                Outcome::Raised(e) => format!("raised:{e}"),
            }
        })
        .collect();
    let (mut crashes, mut answers, mut refused, mut hangs, mut bad) = (0, 0, 0, 0, Vec::new());
    let mask = |s: &str| {
        regex::Regex::new(r"rule '[^']*' may be left recursive")
            .unwrap()
            .replace_all(s, "rule '?' may be left recursive")
            .into_owned()
    };
    for (i, want) in &golden {
        let port = got[i - 1].as_str();
        let ok = if mask(port) == "build:rule '?' may be left recursive"
            && !want.starts_with("build:")
        {
            // A cycle past a sub-grammar in a nullable context, which the
            // C's verifier misses and the port's refuses at construction
            // (step b's hidden pass): the C crashes or runs on.
            refused += 1;
            want == "CRASH" || want == "HANG"
        } else if want == "HANG" {
            // A left recursion through `B` coded as a tail call, which
            // loops at one position in the C as here.
            hangs += 1;
            port == "HANG"
        } else if want == "CRASH" {
            crashes += 1;
            port.split('|')
                .all(|r| mask(r) == "err:rule '?' may be left recursive")
        } else {
            answers += 1;
            mask(port) == mask(want)
        };
        if !ok {
            bad.push(format!("  case {i}: C {want}, port {port}"));
        }
    }
    assert!(
        bad.is_empty(),
        "{} cases differ:\n{}",
        bad.len(),
        bad.join("\n")
    );
    eprintln!(
        "{crashes} crashes, {hangs} hangs and {answers} answers of the C's; {refused} refused at construction"
    );
    assert!(
        crashes > 500 && answers > 500,
        "{crashes} crashes, {answers} answers"
    );
}
