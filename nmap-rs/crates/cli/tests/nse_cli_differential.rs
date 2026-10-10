//! M6.4e gate: NSE through the command line, against nmap 7.94.
//!
//! `oracle/gen_m64_cli.py` ran nmap with `--script` over fixture scripts and
//! shipped ones, against loopback services, and recorded every script result
//! it printed (normal output and XML) or the error the engine failed to start
//! with. This test runs the same script in `--check` mode against this
//! crate's `nmap-rs` binary: the same data directory, services, command
//! lines and parsing, so the two programs are compared by one parser. Every
//! scenario must match. `M64_CLI_GOLDEN` names a golden to use instead of the
//! committed one; CI's differential job regenerates it live.
#![cfg(all(unix, not(miri)))] // runs a Python harness, services and the binary

use std::path::PathBuf;
use std::process::Command;

#[test]
fn script_scans_print_as_under_nmap() {
    let m6 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6");
    let golden = std::env::var_os("M64_CLI_GOLDEN")
        .map_or_else(|| m6.join("m64_cli_golden.txt"), PathBuf::from);
    let out = Command::new("python3")
        .arg(m6.join("oracle/gen_m64_cli.py"))
        .arg("--check")
        .arg(&golden)
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_nmap-rs"))
        .output()
        .expect("python3 runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("0 of 15 scenarios differ"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A data directory with `nselib/` and `nmap-services` from this repository
/// and `scripts` holding `files` (name, contents), plus their `script.db`.
fn datadir(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let d = std::env::temp_dir().join(format!("m64e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("scripts")).expect("scripts dir");
    for name in ["nselib", "nmap-services"] {
        std::os::unix::fs::symlink(repo.join(name), d.join(name)).expect("symlink");
    }
    let mut db = String::new();
    for (name, body) in files {
        std::fs::write(d.join("scripts").join(name), body).expect("script");
        db.push_str(&format!(
            "Entry {{ filename = \"{name}\", categories = {{ \"safe\", }} }}\n"
        ));
    }
    std::fs::write(d.join("scripts/script.db"), db).expect("script.db");
    d
}

/// The stall limit (`nse-stall-limit`): a script that never yields ends its
/// phase once the scheduler has made no pass for `--script-timeout`, with
/// nmap's abort message, and the scan still reports. nmap would hang.
#[test]
fn a_script_that_never_yields_ends_its_phase_at_the_stall_limit() {
    let d = datadir(
        "stall",
        &[(
            "spin.nse",
            "categories = {'safe'}\nprerule = function() return true end\n\
             action = function() local x = 0 while true do x = x + 1 end end\n",
        )],
    );
    let started = std::time::Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .args(["--datadir"])
        .arg(&d)
        .args([
            "-sT",
            "-Pn",
            "-p",
            "1",
            "--script",
            "spin",
            "--script-timeout",
            "2",
        ])
        .arg("127.0.0.1")
        .output()
        .expect("nmap-rs runs");
    let elapsed = started.elapsed();
    let _ = std::fs::remove_dir_all(&d);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NSE: Script Engine Scan Aborted.")
            && stderr.contains("no script thread yielded for 2 seconds"),
        "{stderr}"
    );
    assert!(out.status.success(), "{stderr}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Nmap scan report for 127.0.0.1"),
        "the scan must still report"
    );
    assert!(elapsed < std::time::Duration::from_secs(30), "{elapsed:?}");
}

/// Run `nmap-rs --datadir D -sT -Pn -n -p 1 ARGS 127.0.0.1`, killing it if
/// it runs past a minute: a load the stall limit fails to stop must fail
/// the test, not hang it.
fn run_bounded(d: &std::path::Path, args: &[&str]) -> (std::process::Output, std::time::Duration) {
    use std::process::Stdio;
    let started = std::time::Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .arg("--datadir")
        .arg(d)
        .args(["-sT", "-Pn", "-n", "-p", "1"])
        .args(args)
        .arg("127.0.0.1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("nmap-rs runs");
    while child.try_wait().expect("wait").is_none() {
        if started.elapsed() > std::time::Duration::from_secs(60) {
            let _ = child.kill();
            panic!("nmap-rs {args:?} ran for more than a minute");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    (child.wait_with_output().expect("output"), started.elapsed())
}

/// Loading is held to the stall limit one script at a time: each script's
/// start counts as a pass. Five scripts whose top-level code computes for
/// 0.3 s when loaded load under `--script-timeout 1`, as 7.94 loads them.
/// Before this, the whole load was timed, so `-sC --script-timeout 1`
/// failed to start (about a second for the 124 `default` scripts in a debug
/// build). Each thread runs a script's top-level code again; the scripts
/// compute only the first time, because the scheduler's first resume of
/// five such threads is timed as one pass (`nse-stall-limit-times-a-pass`).
#[test]
fn the_stall_limit_bounds_each_script_load_not_the_whole_load() {
    let slow = "if not nmap.registry[SCRIPT_NAME] then\n\
                  nmap.registry[SCRIPT_NAME] = true\n\
                  local t = os.clock() while os.clock() - t < 0.3 do end\n\
                end\n\
                categories = {'safe'}\nprerule = function() return true end\n\
                action = function() return 'loaded' end\n";
    let names = [
        "slow1.nse",
        "slow2.nse",
        "slow3.nse",
        "slow4.nse",
        "slow5.nse",
    ];
    let files: Vec<(&str, &str)> = names.iter().map(|n| (*n, slow)).collect();
    let d = datadir("loadslice", &files);
    let (out, _) = run_bounded(
        &d,
        &[
            "--script",
            "slow1,slow2,slow3,slow4,slow5",
            "--script-timeout",
            "1",
        ],
    );
    let _ = std::fs::remove_dir_all(&d);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(!stderr.contains("stall limit"), "{stderr}");
    for n in names {
        let id = n.trim_end_matches(".nse");
        assert!(stdout.contains(&format!("{id}: loaded")), "{id}: {stdout}");
    }
}

/// And a script whose top-level code never finishes is still stopped at
/// the limit: the engine fails to start, with the stall message, in bounded
/// time. 7.94 hangs.
#[test]
fn a_script_that_spins_at_load_is_stopped_at_the_stall_limit() {
    let d = datadir(
        "loadspin",
        &[(
            "spinload.nse",
            "local x = 0 while true do x = x + 1 end\n\
             categories = {'safe'}\nprerule = function() return true end\n\
             action = function() return 'unreachable' end\n",
        )],
    );
    let (out, elapsed) = run_bounded(&d, &["--script", "spinload", "--script-timeout", "1"]);
    let _ = std::fs::remove_dir_all(&d);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("NSE: failed to initialize the script engine:\nloading scripts: no script thread yielded for 1 seconds (the stall limit; see --script-timeout)"),
        "{stderr}"
    );
    assert!(elapsed < std::time::Duration::from_secs(30), "{elapsed:?}");
}

/// Data files and scripts are never taken from the working directory
/// (`datadir-no-working-directory`): a `scripts/` there is passed over, with
/// nmap's warning, and its script cannot be selected by name.
#[test]
fn the_working_directory_is_not_a_data_directory() {
    let d = datadir(
        "nocwd",
        &[("real.nse", "categories = {'safe'}\nprerule = function() return true end\naction = function() return 'real' end\n")],
    );
    let cwd = std::env::temp_dir().join(format!("m64e-cwd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cwd);
    std::fs::create_dir_all(cwd.join("scripts")).expect("cwd scripts");
    std::fs::write(
        cwd.join("scripts/evil.nse"),
        "categories = {'safe'}\nprerule = function() return true end\naction = function() return 'evil' end\n",
    )
    .expect("evil script");
    std::fs::write(
        cwd.join("scripts/script.db"),
        "Entry { filename = \"evil.nse\", categories = { \"safe\", } }\n",
    )
    .expect("evil db");
    let run = |script: &str| {
        Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
            .current_dir(&cwd)
            .env_remove("NMAPDIR")
            .env_remove("NMAP_RS_DATADIR")
            .arg("--datadir")
            .arg(&d)
            .args(["-sT", "-Pn", "-p", "1", "--script", script, "127.0.0.1"])
            .output()
            .expect("nmap-rs runs")
    };
    let real = run("real");
    let evil = run("evil");
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&cwd);
    let real_out = String::from_utf8_lossy(&real.stdout);
    let real_err = String::from_utf8_lossy(&real.stderr);
    assert!(real_out.contains("|_real: real"), "{real_out}\n{real_err}");
    assert!(
        real_err.contains("Warning: File ./scripts/script.db exists, but Nmap is using"),
        "{real_err}"
    );
    let evil_err = String::from_utf8_lossy(&evil.stderr);
    assert!(
        evil_err.contains("'evil' did not match a category, filename, or directory"),
        "{evil_err}"
    );
    assert!(!String::from_utf8_lossy(&evil.stdout).contains("evil"));
}
