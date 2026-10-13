//! M6.6 step e: the adversarial-slowness regression gate (`docs/M6.6-ANALYSIS.md`
//! §9, D3 condition 4; §11, step e).
//!
//! Step 0b's adversarial search (`tests/differential/m6/lpeg_search/`) hunts,
//! for each of the 11 LPeg patterns that read network data, the subject that
//! makes the tree's own `lpeg.c` take the most steps per byte, steps counted
//! by an instrumented copy of it: one per VM instruction, one per byte a span
//! instruction examines (since step e: before, a span counted once however
//! many bytes it scanned, so a span rescanned from many positions looked
//! linear), one per capture-evaluation step. Its 600-second run per pattern
//! found every pattern linear, and the subject with the most steps per byte is
//! committed beside its table, `lpeg_search/adversarial/` (`K.txt`): the
//! pattern's adversarial maximum, and its ceiling K, 1.25 times that.
//!
//! This builds the same 11 patterns in the port — `lpeg_search/matchers.lua`
//! itself, unmodified, which takes json, `re` and lpeg-utility from `nselib/`
//! and slices the grammars that live in scripts out of the real files — and
//! runs each on its committed subject, counting steps in the same units with
//! the port's own counters (`lpeg::take_steps`: the matching machine's
//! instructions and the bytes its spans test, and capture evaluation's
//! frames). Each pattern's steps per byte must stay at or under its K. A
//! change that makes a corpus pattern super-linear on its adversarial input,
//! or that lets the counter go blind again, fails here deterministically.
//!
//! What this does not measure: the Lua around a pattern (ntp-info's
//! `accumulate_output` is quadratic in its pairs, `docs/M6.6-ANALYSIS.md` §6),
//! the compile (once per pattern), or subjects above 64 KiB.
#![cfg(not(miri))] // reads nselib/, scripts/ and the subjects from disk

mod lpeg_eval;
mod nse_host;

use std::path::PathBuf;
use std::rc::Rc;

use nmap_core::nse::lpeg::take_steps;
use nmap_core::nse::package::load_package;
use nmap_core::nse::stdlib::iolib::load_io;
use nmap_core::nse::stdlib::utf8lib::load_utf8;
use piccolo::{Closure, Executor, Function, Lua, Value};

fn search_dir() -> PathBuf {
    nse_host::repo_root()
        .join("nmap-rs/tests/differential/m6/lpeg_search")
        .canonicalize()
        .expect("lpeg_search/")
}

/// `K.txt`'s rows: id, subject size, the C's machine and capture steps on
/// it, its steps per byte, and K.
type Ceiling = (String, usize, u64, u64, f64, f64);

/// [`Ceiling`]s, from `K.txt`.
fn ceilings() -> Vec<Ceiling> {
    let text = std::fs::read_to_string(search_dir().join("adversarial/K.txt")).expect("K.txt");
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 6, "a malformed K.txt row: {l}");
            (
                f[0].to_string(),
                f[1].parse().expect("size"),
                f[2].parse().expect("c_vm"),
                f[3].parse().expect("c_cap"),
                f[4].parse().expect("c_spb"),
                f[5].parse().expect("K"),
            )
        })
        .collect()
}

/// `lpeg_search`'s 11 patterns, built by `matchers.lua` in a state with
/// `lpeg`, `io` over the real files, `utf8`, and `require` finding `nselib/`
/// (its own stubs stand in for `stdnse`, `unicode`, `unittest` and
/// `tableaux`, as under the instrumented C). `loadfile`, which the port's
/// sandbox leaves out (`require-searches-only-nselib`), is a shim over `io`
/// and `load`, and `package.path`, which `stubs.lua` prepends to and the
/// port's `require` never reads, starts empty. The table of matchers is the
/// global `GATE`.
fn matchers() -> Lua {
    let mut lua = lpeg_eval::new_lua();
    let repo = nse_host::repo_root()
        .canonicalize()
        .expect("the repository");
    let here = search_dir();
    let src = format!(
        "package.path = package.path or '' \
         loadfile = function(path) \
           local f, e = io.open(path, 'rb') \
           if not f then return nil, e end \
           local s = f:read('a') f:close() \
           return load(s, '@' .. path) \
         end \
         local M = assert(loadfile({here:?} .. '/matchers.lua'))({repo:?}, {here:?}) \
         GATE = M \
         return 1",
        here = here.to_string_lossy(),
        repo = repo.to_string_lossy()
    );
    let ex = lua
        .try_enter(|ctx| {
            load_io(ctx, Rc::new(nse_host::ReadOnlyFs));
            load_utf8(ctx);
            let loaded = load_package(ctx, Rc::new(nse_host::Dir(repo.clone())));
            let lpeg = ctx.get_global::<Value>("lpeg").expect("lpeg");
            loaded.set_field(ctx, "lpeg", lpeg);
            let c = Closure::load(ctx, Some("=gate"), src.as_bytes())?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        })
        .expect("the gate's chunk compiles");
    let (out, _) = lpeg_eval::step_to_end(&mut lua, &ex, 1_000_000, 100_000);
    assert_eq!(
        out,
        lpeg_eval::Outcome::Returned(vec!["1".into()]),
        "matchers.lua"
    );
    lua
}

/// The steps one call of pattern `id`'s matcher takes on `subject`, through
/// `pcall` as the search measures it.
fn steps(lua: &mut Lua, id: &str, subject: &[u8]) -> (u64, u64) {
    let ex = lua.enter(|ctx| {
        let gate: piccolo::Table = ctx.get_global("GATE").expect("GATE");
        let Value::Table(m) = gate.get_value(ctx, Value::String(ctx.intern(id.as_bytes()))) else {
            panic!("{id}: no matcher");
        };
        let f: Function = m.get(ctx, "match").expect("its match");
        let pcall: Function = ctx.get_global("pcall").expect("pcall");
        ctx.stash(Executor::start(
            ctx,
            pcall,
            (f, Value::String(ctx.intern(subject))),
        ))
    });
    let _ = take_steps();
    let (done, _) = lpeg_eval::step_only(lua, &ex, 100_000, 10_000_000);
    assert!(done, "{id}: runs on");
    take_steps()
}

#[test]
fn each_network_facing_pattern_stays_under_its_ceiling_on_its_adversarial_input() {
    let rows = ceilings();
    assert_eq!(rows.len(), 11, "K.txt has {} patterns", rows.len());
    let mut lua = matchers();
    let mut over = Vec::new();
    for (id, size, c_vm, c_cap, c_spb, k) in &rows {
        let subject = std::fs::read(search_dir().join(format!("adversarial/{id}.bin")))
            .unwrap_or_else(|e| panic!("{id}.bin: {e}"));
        assert_eq!(subject.len(), *size, "{id}.bin is not K.txt's");
        assert!(*size >= 1024, "{id}: a subject under SELMIN");
        let (vm, cap) = steps(&mut lua, id, &subject);
        let spb = (vm + cap) as f64 / subject.len() as f64;
        eprintln!(
            "{id:>14}: port {spb:7.3} steps/byte (vm {vm}, cap {cap}), C {c_spb:7.3}, K {k:7.3}"
        );
        if spb > *k {
            over.push(format!("  {id}: {spb:.3} steps/byte, over K = {k}"));
        }
        // The port counts what the C counts, so K is in the port's units:
        // the compiler and the machine are the C's instruction for
        // instruction (D2), and capture evaluation calls `pushcapture` where
        // the C does. Measured equal on every subject, but for the one step
        // the C's machine takes on `IGiveup` when a match fails, which the
        // port's ends without dispatching. A count that moved would be a
        // fidelity change, or a counter gone blind, not a faster pattern.
        assert!(
            vm.abs_diff(*c_vm) <= 1 && cap == *c_cap,
            "{id}: the port counts ({vm}, {cap}) where the C counts ({c_vm}, {c_cap})"
        );
    }
    assert!(
        over.is_empty(),
        "patterns past their ceiling:\n{}",
        over.join("\n")
    );
}

/// The counter is not blind to spans: `anywhere(P'a'^0 * 'b')` on a run of
/// `a`s rescans the run from every position, quadratic in time — and, since
/// each byte a span tests is a step, in steps. Counted once a span, it was
/// a flat 6 steps a byte (`lpeg_search/README.md`, before step e).
#[test]
fn the_counter_sees_every_byte_a_span_tests() {
    let mut lua = lpeg_eval::new_lua();
    let ex = lpeg_eval::start(
        &mut lua,
        "local P = lpeg.P \
         GATE = { span = { match = function(s) \
           return lpeg.match(P{ P'a'^0 * 'b' + 1 * lpeg.V(1) }, s) end } } \
         return 1",
    );
    assert_eq!(
        lpeg_eval::step_to_end(&mut lua, &ex, 1_000_000, 1_000).0,
        lpeg_eval::Outcome::Returned(vec!["1".into()])
    );
    let (small, _) = steps(&mut lua, "span", &[b'a'; 1000]);
    let (large, _) = steps(&mut lua, "span", &[b'a'; 4000]);
    assert!(
        large > small * 12,
        "4,000 bytes took {large} steps, 1,000 took {small}: spans are not counted"
    );
}
