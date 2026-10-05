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
        .args(["-sT", "-Pn", "-p", "1", "--script", "spin", "--script-timeout", "2"])
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
