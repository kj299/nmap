//! M6.6 step d's gates for the captures that call Lua, through the VM with
//! the test-only registration: the JSON nesting ceilings (D2, end to end
//! through `json.lua`), the six ways LPeg calls Lua — a match-time
//! capture's function, `/function`, `Cf`, a `/table`'s `__index`, a grammar
//! table's `__index` and `locale(t)`'s `__newindex` — each one C level, each
//! passing a callback's error object on unchanged, each allowed to yield
//! (`lpeg-callback-may-yield`), and a match that collections, `__gc` calls,
//! recompiles and another thread's matches of the same pattern, mid-match,
//! leave as it was (E3).
#![cfg(not(miri))] // the VM over 200-deep re-entry and full collections

mod lpeg_eval;

use lpeg_eval::{new_lua, new_lua_with_nselib, start, step_only, step_to_end, Outcome};
use piccolo::{Fuel, Lua, StashedExecutor, Value, Variadic};

fn returned(v: &[&str]) -> Outcome {
    Outcome::Returned(v.iter().map(|s| (*s).to_string()).collect())
}

/// Run `src` in `lua` to its end, in slices of a million.
fn run_in(lua: &mut Lua, src: &str) -> Outcome {
    let ex = start(lua, src);
    step_to_end(lua, &ex, 1_000_000, 100_000).0
}

/// D2 through `json.lua`: its grammar's ceilings on nesting are the C's —
/// `too many pending calls/choices` first at 34 for `[`...`]`, at 32 for
/// `[`...`1]` and for objects (M6.6-ANALYSIS §1.3). A match-time capture
/// decodes each `\u` escape on the way.
#[test]
fn the_json_nesting_ceilings_are_the_cs() {
    let mut lua = new_lua_with_nselib();
    let first_fail = |lua: &mut Lua, open: &str, mid: &str, close: &str| -> String {
        let src = format!(
            "for d = 1, 100 do \
               local ok, r = json.parse(('{open}'):rep(d) .. '{mid}' .. ('{close}'):rep(d)) \
               if not ok then return d, r end \
             end"
        );
        match run_in(lua, &src) {
            Outcome::Returned(v) => v.join(" "),
            o => format!("{o:?}"),
        }
    };
    assert_eq!(
        first_fail(&mut lua, "[", "", "]"),
        "34 too many pending calls/choices"
    );
    assert_eq!(
        first_fail(&mut lua, "[", "1", "]"),
        "32 too many pending calls/choices"
    );
    assert_eq!(
        first_fail(&mut lua, r#"{"a":"#, "1", "}"),
        "32 too many pending calls/choices"
    );
    assert_eq!(
        first_fail(&mut lua, r#"{"\\u0041":"#, r#""\\u00e9""#, "}"),
        "32 too many pending calls/choices"
    );
}

/// Each way LPeg calls Lua is one C level (`lua_call`, `lua_gettable`,
/// `lua_setfield` from C): recursion through each stops at `LUAI_MAXCCALLS`
/// one level less deep than recursion through `gsub`, whose callback is one
/// C call too, as in the C (the tree's oracle, the same chunks: 196 against
/// 197). The absolute depths are the embedding's.
#[test]
fn each_way_into_lua_takes_one_c_level() {
    let mut lua = new_lua();
    let depth = |lua: &mut Lua, body: &str| -> (u32, String) {
        let src = format!("local d = 0 {body}");
        match run_in(lua, &src) {
            Outcome::Returned(v) => (v[0].parse().expect("a depth"), v[1].clone()),
            o => panic!("{body}: {o:?}"),
        }
    };
    let (gsub, e) = depth(
        &mut lua,
        "local function f(s) d = d + 1 return (string.gsub(s, '.', f)) end \
         local ok, e = pcall(f, 'a') return d, e",
    );
    assert_eq!(e, "C stack overflow");
    let paths = [
        (
            "Cmt",
            "local p p = lpeg.Cmt(lpeg.P(true), function(s, i) d = d + 1 return lpeg.match(p, s) end) \
             local ok, e = pcall(lpeg.match, p, 'a') return d, e",
        ),
        (
            "/function",
            "local p p = lpeg.P(1) / function(c) d = d + 1 return lpeg.match(p, c) end \
             local ok, e = pcall(lpeg.match, p, 'a') return d, e",
        ),
        (
            "Cf",
            "local f f = function(a, b) d = d + 1 return lpeg.match(lpeg.Cf(lpeg.Cc(1) * lpeg.Cc(2), f), '') end \
             local ok, e = pcall(lpeg.match, lpeg.Cf(lpeg.Cc(1) * lpeg.Cc(2), f), '') return d, e",
        ),
        (
            "/table",
            "local t = setmetatable({}, {}) \
             getmetatable(t).__index = function(_, k) d = d + 1 return lpeg.match(lpeg.C(1) / t, k) end \
             local ok, e = pcall(lpeg.match, lpeg.C(1) / t, 'a') return d, e",
        ),
        (
            "grammar __index",
            "local mk mk = function() return setmetatable({ 'S' }, \
               { __index = function() d = d + 1 return lpeg.P(mk()) end }) end \
             local ok, e = pcall(lpeg.P, mk()) return d, e",
        ),
        (
            "locale __newindex",
            "local mk mk = function() return setmetatable({}, \
               { __newindex = function() d = d + 1 lpeg.locale(mk()) end }) end \
             local ok, e = pcall(lpeg.locale, mk()) return d, e",
        ),
    ];
    for (name, body) in paths {
        let (d, e) = depth(&mut lua, body);
        assert!(e.ends_with("C stack overflow"), "{name}: {e}");
        assert_eq!(d + 1, gsub, "{name}: {d} levels deep, gsub {gsub}");
    }
}

/// An error a callback raises reaches the caller of `match` (or of the
/// constructor) as the object raised — a table keeps its identity, nil stays
/// nil, a string the position its `error` gave it — on each of the six
/// paths; and the pattern goes on working.
#[test]
fn each_way_into_lua_passes_its_error_on_unchanged() {
    let mut lua = new_lua();
    let paths = [
        "lpeg.match(lpeg.Cmt(1, function() error(E) end), 'a')",
        "lpeg.match(lpeg.P(1) / function() error(E) end, 'a')",
        "lpeg.match(lpeg.Cf(lpeg.Cc(1) * lpeg.Cc(2), function() error(E) end), '')",
        "lpeg.match(lpeg.C(1) / setmetatable({}, { __index = function() error(E) end }), 'a')",
        "lpeg.P(setmetatable({ 'S' }, { __index = function() error(E) end }))",
        "lpeg.locale(setmetatable({}, { __newindex = function() error(E) end }))",
    ];
    for call in paths {
        let src = format!(
            "local out = {{}} \
             E = {{}} local ok, e = pcall(function() return {call} end) \
             out[1] = tostring(ok) out[2] = tostring(rawequal(e, E)) \
             E = nil local ok, e = pcall(function() return {call} end) \
             out[3] = tostring(e) \
             E = 'plain' local ok, e = pcall(function() return {call} end) \
             out[4] = e \
             return table.concat(out, ' ')"
        );
        assert_eq!(
            run_in(&mut lua, &src),
            returned(&["false true nil chunk:1: plain"]),
            "{call}"
        );
    }
    // The pattern goes on working after an error (E08).
    assert_eq!(
        run_in(
            &mut lua,
            "local p = lpeg.Cmt(1, function(s) if s == 'e' then error('E', 0) end return true end) * lpeg.C(1) \
             local ok, e = pcall(p.match, p, 'e') return e, p:match('ab')"
        ),
        returned(&["E", "b"])
    );
}

/// A callback may yield (`lpeg-callback-may-yield`; the C refuses, "attempt
/// to yield across a C-call boundary"): the coroutine yields what the
/// callback yields, other code runs — a match of the same pattern, a full
/// collection, the pattern's `__gc` — and when the coroutine is resumed the
/// callback returns what it was resumed with and the match goes on from
/// where it was, with the answer it would have had.
#[test]
fn each_way_into_lua_may_yield() {
    let mut lua = new_lua();
    let paths = [
        // A match-time capture: its values and position come back.
        (
            "lpeg.Cmt(lpeg.C'a' * lpeg.Cmt(1, function() return true, 'in' end), \
               function(s, i, a, b) return i, coroutine.yield(a .. b) end) * lpeg.C(1)",
            "'abc'",
            "ain",
            "R c",
        ),
        // `/function`, inside a table capture.
        (
            "lpeg.Ct(lpeg.C(1) * (lpeg.C(1) / function(c) return coroutine.yield(c) end) * lpeg.C(1))",
            "'xyz'",
            "y",
            "x R z",
        ),
        // `Cf`, part-way through its fold.
        (
            "lpeg.Cf(lpeg.Cc(1) * lpeg.Cc(2) * lpeg.Cc(3), function(a, b) \
               if b == 2 then return coroutine.yield(a + b) end return a .. '+' .. b end)",
            "''",
            "3",
            "R+3",
        ),
        // A `/table`'s `__index`.
        (
            "lpeg.C(1) / setmetatable({}, { __index = function(_, k) return coroutine.yield(k) end }) * lpeg.Cp()",
            "'k'",
            "k",
            "R 2",
        ),
    ];
    for (pat, subject, yielded, answer) in paths {
        let src = format!(
            "local p = {pat} \
             local co = coroutine.wrap(function() \
               local r = table.pack(lpeg.match(p, {subject})) \
               for i = 1, r.n do if type(r[i]) == 'table' then r[i] = table.concat(r[i], ' ') end end \
               return table.concat(r, ' ', 1, r.n) \
             end) \
             local y = co() \
             collectgarbage() getmetatable(p).__gc(p) collectgarbage() \
             local other = coroutine.wrap(function() return pcall(lpeg.match, p, {subject}) end) \
             local _ = other() \
             return tostring(y), co('R')"
        );
        assert_eq!(
            run_in(&mut lua, &src),
            returned(&[yielded, answer]),
            "{pat}"
        );
    }
    // The constructors' two (step b's): a grammar's `__index`, `locale(t)`'s
    // `__newindex`.
    assert_eq!(
        run_in(
            &mut lua,
            "local co = coroutine.wrap(function() \
               local p = lpeg.P(setmetatable({ 'S' }, { __index = function(_, k) return coroutine.yield(k) end })) \
               return p:match('a') end) \
             local k = co() \
             local loc = coroutine.wrap(function() \
               return lpeg.locale(setmetatable({}, { __newindex = function(t, k, v) \
                 rawset(t, k, v) if k == 'digit' then coroutine.yield(k) end end })) end) \
             local d = loc() \
             return k, co(lpeg.P'a'), d, lpeg.type(loc().xdigit)"
        ),
        returned(&["S", "2", "digit", "pattern"])
    );
}

/// What a full collection, a pattern's `__gc` and another thread's matches of
/// the same pattern do to a match that is running (E3): nothing. Two script
/// threads share a pattern whose match-time captures return fresh tables —
/// held only by the match's window until it ends — and whose callbacks call
/// the pattern's `__gc` and `collectgarbage()`; each also matches a pattern
/// nothing but the running match holds, and the C's use-after-free repro
/// (`lpeg-code-freed-during-match`: a callback calls `__gc` on the pattern
/// running it, `nil` from the tree's oracle where the answer is `"ccc"`). Run
/// alternately in slices of 37 and 5 units, with a full collection after
/// every slice, each gives what it gives run alone in one slice. The VM
/// never runs a `__gc` metamethod by itself (`vm-gc-metamethods-never-run`),
/// so the test calls the pattern's.
#[test]
fn a_collection_mid_match_changes_nothing() {
    const SETUP: &str = "local L = lpeg \
        function build(tag) \
          local p \
          local item = L.Cmt(L.C(L.R'az'), function(s, i, c) \
              collectgarbage() getmetatable(p).__gc(p) \
              return i, { tag = tag .. c, n = i } \
            end) \
          local word = L.Cf(L.Cc(0) * (item / function(t) collectgarbage() return t.n, t.tag end)^1, \
              function(a, n, tag) return a + n end) \
          local q = setmetatable({}, { __index = function(_, k) collectgarbage() return k .. '!' end }) \
          local keep = L.Cmt(L.P',', function(s, i) return i, { i } end) \
          p = L.Ct((L.Cg(word, 'sum') + keep + (L.C(1) / q))^0) \
          return p \
        end \
        SHARED = build('s') \
        function digest(t) \
          local acc = { tostring(t.sum) } \
          for i = 1, #t do local v = t[i] acc[#acc + 1] = type(v) == 'table' and ('<' .. v[1] .. '>') or v end \
          return table.concat(acc, '|') \
        end";
    const THREAD: &str = "local out = {} \
        for i = 1, 3 do \
          out[#out + 1] = digest(lpeg.match(SHARED, 'ab cd,ef g' .. i)) \
          out[#out + 1] = digest(lpeg.match(build('x' .. i), 'gh,ij k')) \
        end \
        local hits, p = 0 \
        p = lpeg.Cmt(lpeg.P'a', function() \
            hits = hits + 1 getmetatable(p).__gc(p) collectgarbage() \
            local junk = {} for k = 1, 200 do junk[k] = ('x'):rep(64) .. k end \
            return true \
          end) * lpeg.P'b' * lpeg.C(lpeg.P'c'^0) \
        out[#out + 1] = tostring(lpeg.match(p, 'abccc')) .. ':' .. hits \
        return table.concat(out, ' ')";
    let outcome = |lua: &mut Lua, ex: &StashedExecutor| -> String {
        lua.enter(
            |ctx| match ctx.fetch(ex).take_result::<Variadic<Vec<Value>>>(ctx) {
                Ok(Ok(vs)) => vs.0.iter().map(|v| v.display().to_string()).collect(),
                Ok(Err(e)) => format!("raised: {e:#}"),
                Err(e) => format!("not done: {e}"),
            },
        )
    };
    // Alone, one slice each.
    let mut lua = new_lua();
    let setup = start(&mut lua, SETUP);
    assert!(step_only(&mut lua, &setup, i32::MAX, 1).0);
    let a = start(&mut lua, THREAD);
    assert!(step_only(&mut lua, &a, i32::MAX, 1).0);
    let want = outcome(&mut lua, &a);
    assert_eq!(
        want, "11| !|<7>| !|1! 8|<4>| ! 11| !|<7>| !|2! 8|<4>| ! 11| !|<7>| !|3! 8|<4>| ! ccc:1",
        "the C's answers (its `__gc` calls left out: they free the code it runs)"
    );
    // Side by side, collected after every slice.
    for slice in [37, 5] {
        let mut lua = new_lua();
        let setup = start(&mut lua, SETUP);
        assert!(step_only(&mut lua, &setup, i32::MAX, 1).0);
        let exs = [start(&mut lua, THREAD), start(&mut lua, THREAD)];
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
        assert!(slices > 200, "{slices} slices");
        for ex in &exs {
            assert_eq!(outcome(&mut lua, ex), want, "slices of {slice}");
        }
    }
}
