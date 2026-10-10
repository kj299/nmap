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

use lpeg_eval::{new_lua, run, start, step_to_end, step_traced, Outcome};

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
/// it at each growth; no Lua runs in between, so a match reads it once).
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

/// A match pre-empted part-way keeps the ceiling it started with: another
/// script's `setmaxstack` between its slices does not reach it, as in the C,
/// where no Lua runs inside a match that calls none.
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
