// Standalone scorer: run the committed M6.0 semantics corpus through a piccolo
// build and emit exactly the format oracle/m60_driver.lua emits, so the two can
// be diffed directly.
//
// NOT wired into the workspace, and regen_m60.sh does not run it: piccolo is
// not a dependency of nmap-rs yet — deciding whether and how it becomes one is
// what this corpus was built to inform. Keep it here so the measurements in
// docs/M6-ANALYSIS.md stay reproducible. To run it:
//
//   cargo new --bin score && cd score
//   # add ONE of these to [dependencies]:
//   #   piccolo = "0.3.3"                       (the published crate)
//   #   piccolo = { path = "/path/to/fork" }    (a fork of master)
//   # and to [profile.release]: overflow-checks = true
//   #   — this matches nmap-rs's own release profile, and it MATTERS: with
//   #     overflow checks off, the panics below become silent wrong answers
//   #     instead, which is not an improvement.
//   cp .../m60_score.rs src/main.rs
//   cargo run --release -- ../m60_semantics_cases.txt > got.txt
//   diff got.txt ../m60_semantics_golden.txt
//
// Measured 2026-09: piccolo 0.3.3 diverges on 26 of 55 cases with 5 panics;
// piccolo master (ce709eb) diverges on 16 with 2.
// Run the committed M6.0 semantics corpus through piccolo and emit exactly the
// format nmap's own Lua emits, so the two can be diffed directly.
use piccolo::{Closure, Executor, Lua, Value};

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

fn render(v: Value) -> String {
    match v {
        Value::Integer(i) => format!("integer:{i}"),
        Value::Number(n) if n.is_nan() => "float:nan".to_string(),
        Value::Number(n) if n.is_infinite() => {
            format!("float:{}", if n > 0.0 { "inf" } else { "-inf" })
        }
        // Lua prints floats with %.14g and always keeps a decimal marker.
        Value::Number(n) => {
            let s = format!("{:.14}", n);
            let s = s.trim_end_matches('0').to_string();
            format!("float:{}", if s.ends_with('.') { format!("{s}0") } else { s })
        }
        Value::String(s) => format!("string:{}", hex(s.as_bytes())),
        Value::Nil => "nil:nil".to_string(),
        Value::Boolean(b) => format!("boolean:{b}"),
        Value::Table(_) => "table:<table>".to_string(),
        Value::Function(_) => "function:<function>".to_string(),
        Value::UserData(_) => "userdata:<userdata>".to_string(),
        Value::Thread(_) => "thread:<thread>".to_string(),
    }
}

fn eval(src: &[u8]) -> String {
    // `catch_unwind` is the whole point of the harness: a host-language panic
    // is NOT a Lua error. It escapes pcall, so a script cannot defend against
    // it, and in the scanner it takes the process down. Catching it here lets
    // the corpus record it as a distinct verdict rather than losing the run.
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut lua = Lua::core();
        let ex = match lua.try_enter(|ctx| {
            let c = Closure::load(ctx, None, src)?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        }) {
            Ok(e) => e,
            Err(e) => return format!("loaderror\t{e}"),
        };
        lua.finish(&ex);
        lua.enter(|ctx| {
            let e = ctx.fetch(&ex);
            match e.take_result::<Value>(ctx) {
                Ok(Ok(v)) => format!("ok\t{}", render(v)),
                Ok(Err(err)) => format!("error\t{err}"),
                Err(err) => format!("error\t{err}"),
            }
        })
    }));
    r.unwrap_or_else(|_| {
        "PANIC\thost-language panic: escapes pcall, aborts the process".to_string()
    })
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let path = std::env::args().nth(1).expect("usage: score CASES.txt");
    let text = std::fs::read_to_string(path).expect("read cases");
    println!("# name\toracle_status\toracle_value");
    println!("# piccolo's verdict, rendered exactly as oracle/m60_driver.lua renders Lua's.");
    println!("# (three header lines to match the golden's four minus this note)");
    println!("#");
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split('\t');
        let name = f.next().unwrap_or("");
        let chunk_hex = f.next().unwrap_or("");
        let chunk: Vec<u8> = (0..chunk_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&chunk_hex[i..i + 2], 16).unwrap_or(0))
            .collect();
        println!("{name}\t{}", eval(&chunk));
    }
}
