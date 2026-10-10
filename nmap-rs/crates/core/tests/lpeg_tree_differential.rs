//! Differential: LPeg pattern construction against the tree's own LPeg.
//!
//! `core::nse::lpeg` (step b) builds patterns: every constructor and
//! operator, the grammar builder and its verifier, `type`, `version`,
//! `setmaxstack`, `locale`, the `ptree`/`pcode` stubs and the metatable. The
//! corpus `tests/differential/m6/m66b_tree_cases.txt` is what the tree's
//! standalone Lua with `lpeg.c` (`oracle/build_lua_oracle.sh`) answers for
//! each case; `regen_m66b_trees.sh` makes it.
//!
//! Both sides run the same Lua, `oracle/m66b_tree_core.lua`, which builds
//! each case's environment and renders its results, so they differ only
//! where LPeg does. Nothing is matched: a case sees a result's type, its
//! identity, the metatable, and every error message, compared byte for
//! byte, position prefix and function name included. No exemption list; the
//! one masked class is the rule name four grammar errors take from the
//! grammar table's traversal order ("hashorder"), which the core masks on
//! both sides except in rows noted `[exact]`.
//!
//! **Ad-hoc cases.** `LPEG_TREE_CASES=FILE` runs a cases file of the same
//! format (`id<TAB>hex(chunk)<TAB>note`) in place of the corpus, and
//! `LPEG_TREE_GOLDEN=FILE` compares it with that golden (the oracle's
//! output for it: `./oracle/lua oracle/m66b_tree_driver.lua
//! oracle/m66b_tree_core.lua FILE`). With no golden, the port's answers are
//! written to `LPEG_TREE_OUT` (default `lpeg_tree_port.txt`) in the
//! golden's format, for `diff`, and the test passes. The family floors apply
//! only to the corpus.
#![cfg(not(miri))] // reads the corpus from disk

mod lpeg_eval;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use piccolo::{Closure, Executor, Function, Value, Variadic};

fn corpus(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

/// The non-comment rows of a cases or golden file, split on tabs.
fn rows(path: &Path) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.splitn(3, '\t').map(str::to_string).collect())
        .collect()
}

/// The fewest rows of each family the corpus may have: the generator is
/// shared by nothing but this gate, and a weakened generator regenerated in
/// place would otherwise pass on what is left.
const MIN_ROWS: [(&str, usize); 14] = [
    ("A", 100),
    ("B", 1_300),
    ("C", 180),
    ("D", 115),
    ("E", 40),
    ("F", 400),
    ("G", 120),
    ("H", 19),
    ("I", 12),
    ("J", 12),
    ("L", 35),
    ("M", 50),
    ("Q", 3_000),
    ("Z", 85),
];

#[test]
fn constructions_match_the_trees_own_lpeg() {
    let adhoc = std::env::var_os("LPEG_TREE_CASES").map(PathBuf::from);
    let cases = rows(
        &adhoc
            .clone()
            .unwrap_or_else(|| corpus("m66b_tree_cases.txt")),
    );
    let golden_file = match (&adhoc, std::env::var_os("LPEG_TREE_GOLDEN")) {
        (_, Some(g)) => Some(PathBuf::from(g)),
        (None, None) => Some(corpus("m66b_tree_golden.txt")),
        (Some(_), None) => None,
    };
    let golden: Option<HashMap<String, (String, String)>> = golden_file.map(|g| {
        rows(&g)
            .into_iter()
            .map(|r| (r[0].clone(), (r[1].clone(), r[2].clone())))
            .collect()
    });
    if let Some(golden) = &golden {
        assert_eq!(
            cases.len(),
            golden.len(),
            "cases and golden differ in length"
        );
    }
    // The hashorder mask leaves `initial rule 'X' is not a pattern` alone:
    // that name is the grammar's first field, not one the table's order
    // picks, and rows not noted `[exact]` show it.
    if let (None, Some(golden)) = (&adhoc, &golden) {
        let shown = golden
            .values()
            .any(|(_, p)| String::from_utf8_lossy(&unhex(p)).contains("initial rule 'S' is not"));
        assert!(shown, "the mask hides the initial rule's name");
    }
    for (family, min) in MIN_ROWS {
        if adhoc.is_some() {
            break;
        }
        let n = cases
            .iter()
            .filter(|r| r[0].split('.').next() == Some(family))
            .count();
        assert!(
            n >= min,
            "family {family} has {n} rows, fewer than {min}: regenerate"
        );
    }

    let core = std::fs::read(corpus("oracle/m66b_tree_core.lua")).expect("the core");
    let mut lua = lpeg_eval::new_lua();
    let ex = lua
        .try_enter(|ctx| {
            let c = Closure::load(ctx, Some("@m66b_tree_core.lua"), &core[..])?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        })
        .expect("the core compiles");
    assert!(
        lpeg_eval::step_only(&mut lua, &ex, 1_000_000, 1_000).0,
        "the core loads"
    );
    lua.enter(|ctx| {
        let t: piccolo::Table = ctx
            .fetch(&ex)
            .take_result(ctx)
            .expect("finished")
            .expect("no error");
        ctx.set_global("run_one", t.get_value(ctx, "run_one"));
    });

    let mut mismatches = Vec::new();
    let mut port_out = String::new();
    for row in &cases {
        let (id, chunk, note) = (
            &row[0],
            unhex(&row[1]),
            row.get(2).cloned().unwrap_or_default(),
        );
        let ex = lua.enter(|ctx| {
            let f: Function = ctx.get_global("run_one").expect("run_one");
            let args = (
                Value::String(ctx.intern(&chunk)),
                Value::String(ctx.intern(note.as_bytes())),
            );
            ctx.stash(Executor::start(ctx, f, args))
        });
        let (done, _) = lpeg_eval::step_only(&mut lua, &ex, 1_000_000, 100_000);
        let (status, payload) = if !done {
            ("UNFINISHED".to_string(), String::new())
        } else {
            lua.enter(
                |ctx| match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
                    Ok(Ok(vs)) => {
                        let s = |i: usize| match vs.0.get(i) {
                            Some(Value::String(s)) => s.as_bytes().to_vec(),
                            Some(v) => v.display().to_string().into_bytes(),
                            None => Vec::new(),
                        };
                        (String::from_utf8_lossy(&s(0)).into_owned(), hex(&s(1)))
                    }
                    Ok(Err(e)) => ("RAISED".to_string(), hex(e.to_string().as_bytes())),
                    Err(e) => ("NO-RESULT".to_string(), hex(e.to_string().as_bytes())),
                },
            )
        };
        let Some(golden) = &golden else {
            port_out.push_str(&format!("{id}\t{status}\t{payload}\n"));
            continue;
        };
        let want = golden
            .get(id)
            .unwrap_or_else(|| panic!("{id}: in cases but not in golden"));
        if (status.as_str(), payload.as_str()) != (want.0.as_str(), want.1.as_str()) {
            mismatches.push(format!(
                "  {id} ({note}):\n      lua  = {} {}\n      port = {status} {}",
                want.0,
                String::from_utf8_lossy(&unhex(&want.1)),
                String::from_utf8_lossy(&unhex(&payload)),
            ));
        }
    }
    if golden.is_none() {
        let out = std::env::var_os("LPEG_TREE_OUT")
            .map_or_else(|| PathBuf::from("lpeg_tree_port.txt"), PathBuf::from);
        std::fs::write(&out, port_out).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
        eprintln!(
            "{} cases: the port's answers are in {}",
            cases.len(),
            out.display()
        );
        return;
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} constructions diverge from the tree's LPeg:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches
            .iter()
            .take(60)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
