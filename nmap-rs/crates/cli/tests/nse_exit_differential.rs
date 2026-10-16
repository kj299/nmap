//! M6.6's exit criterion (`docs/M6.6-ANALYSIS.md` §12) and its two
//! denial-of-service scenarios (§11, step e), through the `nmap-rs` binary.
//!
//! **Exit scenarios, against nmap 7.94.** `oracle/gen_m66_exit.py` recorded,
//! on this repository's own data directory, what nmap selects and loads for
//! `-sC`, `--script default`, `--script version`, `-A` and `--script safe`
//! (`-d2`'s `selected`, `Loaded` and `Failed to load` lines, 127 / 127 / 48 /
//! 158 / 352 selected; `safe` runs its scripts in a loopback-only network
//! namespace, `unshare -rn`), with the loaded and quiet lists nmap gives
//! without the C modules the port lacks; and the results of one executed script per
//! module: address-info for `nmapdb`, riak-http-info and bitcoinrpc-info for
//! `lpeg` (through `json.lua`, with `\uXXXX` escapes and the JSON nesting
//! ceiling, 29 / 30 and 28 / 29, D2 end to end), and http-affiliate-id for
//! `re`; and, for the categories that still stop at start-up (`vuln`,
//! `intrusive`, `exploit` and `all`, on `openssl`,
//! `nse-categories-abort-on-unported-modules`), the script and `file:line`
//! nmap stops on without those modules. [`the_exit_scenarios_run_as_under_nmap`]
//! runs the same script in `--check` mode against this crate's binary: one
//! parser for both, 18 scenarios. Its two
//! tolerances are ledger entries (LESSONS #031): `nse-sc-openssl-quiet-drops`
//! (the `openssl` scripts dropped quietly: six of `default`, 18 of `safe`) and
//! `nse-sv-version-scripts-pending` (the port's `-A` selects `default` only).
//! `M66_EXIT_GOLDEN` names a golden to use instead of the committed one; CI's
//! differential job regenerates it live.
//!
//! **Denial of service, the port alone** (nmap 7.94 hangs in every one: the
//! C cannot be interrupted, and `--script-timeout` never fires; measured
//! under a hard timeout, `lpeg-stall-limit-ends-finite-work`). LPeg work
//! exponential in a pattern, built by a script
//! (`tests/differential/m6/nse_lpeg_dos/`), at `--script-timeout 2`:
//! - at load: start-up fails at the stall limit, rc 1, with nothing to keep;
//! - in a prerule action, one row per stage — build, compile, match,
//!   capture — after another script stored a result: the phase ends with
//!   `Script Engine Scan Aborted` at the limit, in that stage (the last
//!   `m66dos:` marker the fixture logged), the result is kept, and the scan
//!   goes on.
//!
//! A stage that burned no fuel would run inside one slice of VM work, where
//! the watchdog cannot see it: its row hangs until [`run_bounded`] kills it
//! and fails the test.
#![cfg(all(unix, not(miri)))] // runs a Python harness, listeners and the binary

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn m6() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6")
}

#[test]
fn the_exit_scenarios_run_as_under_nmap() {
    let golden = std::env::var_os("M66_EXIT_GOLDEN")
        .map_or_else(|| m6().join("m66_exit_golden.txt"), PathBuf::from);
    let out = Command::new("python3")
        .arg("-B")
        .arg(m6().join("oracle/gen_m66_exit.py"))
        .arg("--check")
        .arg(&golden)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_nmap-rs"))
        .output()
        .expect("python3 runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("0 of 18 scenarios differ"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The harness's own limit on one run: a stage that does not burn fuel
/// hangs into it, and the test fails here, not by hanging.
const HARNESS_TIMEOUT: Duration = Duration::from_secs(60);

/// The most a run at `--script-timeout 2` may take, start-up and the scan
/// included, in a debug build on a loaded host (measured: 2.2 s).
const MARGIN: Duration = Duration::from_secs(20);

/// Run `nmap-rs --datadir REPO ARGS`, killed at [`HARNESS_TIMEOUT`].
fn run_bounded(args: &[&str]) -> (Output, Duration) {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .arg("--datadir")
        .arg(repo())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("nmap-rs runs");
    while child.try_wait().expect("wait").is_none() {
        if started.elapsed() > HARNESS_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("nmap-rs {args:?} ran past the harness's {HARNESS_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    (child.wait_with_output().expect("output"), started.elapsed())
}

fn fixture(name: &str) -> String {
    m6().join("nse_lpeg_dos")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

const STALL: &str =
    "no script thread yielded for 2 seconds (the stall limit; see --script-timeout)";

/// The exponential grammar built at a script's top level (K = 36): start-up
/// fails at the stall limit with nmap's own `QUITTING!`, and no script is
/// loaded. 7.94 hangs after `selected by file path` (measured, rc 124 under
/// `timeout 60`).
#[test]
fn an_exponential_grammar_built_at_load_fails_start_up_at_the_stall_limit() {
    let script = fixture("m66-expo-load.nse");
    let (out, elapsed) = run_bounded(&[
        "-d2",
        "-Pn",
        "-n",
        "-sT",
        "-p",
        "1",
        "--script-timeout",
        "2",
        "--script",
        &script,
        "--script-args",
        "m66dos.k=36",
        "127.0.0.1",
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(
        stderr.ends_with(&format!(
            "NSE: failed to initialize the script engine:\nloading scripts: {STALL}\n\nQUITTING!\n"
        )),
        "{stderr}"
    );
    assert!(
        stdout.contains("NSE: Script m66-expo-load.nse was selected by file path."),
        "{stdout}"
    );
    assert!(!stdout.contains("NSE: Loaded '"), "{stdout}");
    assert!(elapsed < MARGIN, "{elapsed:?}");
}

/// One row: `m66-quick` then `m66-expo-run` at `m66dos.stage=STAGE`. The
/// phase ends at the limit, in STAGE: the last marker the fixture logged
/// (each piece of work starts after a yield, so in a window of its own) is
/// STAGE's, and it never logs `done`. m66-quick's result is kept, in normal
/// output and XML, and the scan reports the host.
fn dos_row(stage: &str) {
    let dir = std::env::temp_dir().join(format!("m66-dos-{stage}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let (normal, xml) = (dir.join("out.nmap"), dir.join("out.xml"));
    let scripts = format!(
        "{},{}",
        fixture("m66-quick.nse"),
        fixture("m66-expo-run.nse")
    );
    let stage_arg = format!("m66dos.stage={stage}");
    let (out, elapsed) = run_bounded(&[
        "-d",
        "-Pn",
        "-n",
        "-sT",
        "-p",
        "1",
        "--script-timeout",
        "2",
        "--script",
        &scripts,
        "--script-args",
        &stage_arg,
        "127.0.0.1",
        "-oN",
        &normal.to_string_lossy(),
        "-oX",
        &xml.to_string_lossy(),
    ]);
    let read =
        |p: &Path| String::from_utf8_lossy(&std::fs::read(p).unwrap_or_default()).into_owned();
    let (normal, xml) = (read(&normal), read(&xml));
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stage}: {stdout}\n{stderr}");
    assert!(
        stderr.contains("NSE: Script Engine Scan Aborted.")
            && stderr.contains(&format!(
                "An error was thrown by the engine: script scan: {STALL}"
            )),
        "{stage}: {stderr}"
    );
    let markers: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("NSE: [m66-expo-run] m66dos: "))
        .collect();
    assert_eq!(
        markers.last().copied(),
        Some(stage),
        "{stage}: cut elsewhere: {markers:?}\n{stdout}"
    );
    // The pre-scan results: m66-quick's alone, kept.
    let pre: Vec<&str> = normal
        .lines()
        .skip_while(|l| *l != "Pre-scan script results:")
        .skip(1)
        .take_while(|l| l.starts_with('|'))
        .collect();
    assert_eq!(
        pre,
        ["|_m66-quick: stored before the stall"],
        "{stage}: {normal}"
    );
    let prescript = xml
        .split_once("<prescript>")
        .and_then(|(_, rest)| rest.split_once("</prescript>"))
        .map(|(inner, _)| inner.trim());
    assert_eq!(
        prescript,
        Some("<script id=\"m66-quick\" output=\"stored before the stall\"/>"),
        "{stage}: {xml}"
    );
    assert!(
        !xml.contains("<script id=\"m66-expo-run\""),
        "{stage}: {xml}"
    );
    // And the scan went on.
    assert!(normal.contains("1/tcp closed"), "{stage}: {normal}");
    assert!(elapsed < MARGIN, "{stage}: {elapsed:?}");
}

/// Build: the choice chain `Rᵢ ← Rᵢ₊₁ / Rᵢ₊₁` (n = 36), 2^35 paths in the
/// verifier, in C and here.
#[test]
fn an_exponential_build_in_an_action_ends_its_phase_at_the_stall_limit() {
    dos_row("build");
}

/// Compile: a pattern of 6 million nodes, which the port compiles in linear
/// time (about 8 s in a debug build; C's analyses of the chain that follows
/// it, `Rᵢ ← Rᵢ₋₁'x' / Rᵢ₋₁'y'`, are exponential, the port's linear, E10).
#[test]
fn a_long_compile_in_an_action_ends_its_phase_at_the_stall_limit() {
    dos_row("compile");
}

/// Match: `S <- 'a' S 'b' / 'a' S 'c' / ''` on `a³⁴d`, 2^34 attempts.
#[test]
fn an_exponential_match_in_an_action_ends_its_phase_at_the_stall_limit() {
    dos_row("match");
}

/// Capture evaluation: back-references nested 32 deep, 2^32 values, no Lua
/// call.
#[test]
fn an_exponential_capture_in_an_action_ends_its_phase_at_the_stall_limit() {
    dos_row("capture");
}
