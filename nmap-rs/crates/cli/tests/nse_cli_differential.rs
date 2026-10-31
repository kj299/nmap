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
        out.status.success() && stdout.contains("0 of 24 scenarios differ"),
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

/// The stall limit bounds one script's work, not a batch of them: each
/// script's load and each time the scheduler resumes a script thread count
/// as progress. Five scripts whose top-level code computes for 0.3 s run
/// under `--script-timeout 1`, as 7.94 runs them (1.6 s), though that code
/// runs once at load and again in each thread's first resume, all in one
/// pass of the scheduler. Before, the whole load was timed, so
/// `-sC --script-timeout 1` failed to start, and then the whole pass was
/// (`nse-stall-limit-times-a-pass`), so these five aborted the pre-scan.
#[test]
fn the_stall_limit_bounds_each_script_load_not_the_whole_load() {
    let slow = "local t = os.clock() while os.clock() - t < 0.3 do end\n\
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

/// A script cannot hold the limit off with coroutines of its own: their
/// resumes are not the scheduler's, so a thread that ping-pongs between
/// two of them forever, never yielding to the scheduler, ends its phase at
/// the limit. 7.94 hangs.
#[test]
fn a_scripts_own_coroutines_do_not_count_as_progress() {
    let d = datadir(
        "pingpong",
        &[(
            "pingpong.nse",
            "categories = {'safe'}\nprerule = function() return true end\n\
             action = function()\n\
               local co = coroutine.wrap(function() while true do coroutine.yield() end end)\n\
               while true do co() end\n\
             end\n",
        )],
    );
    let (out, elapsed) = run_bounded(&d, &["--script", "pingpong", "--script-timeout", "1"]);
    let _ = std::fs::remove_dir_all(&d);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NSE: Script Engine Scan Aborted.")
            && stderr.contains("no script thread yielded for 1 seconds"),
        "{stderr}"
    );
    assert!(out.status.success(), "{stderr}");
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

/// The port alone (`nse-output-dirs-documented-args`, the lfs review's S4):
/// only the arguments the shipped scripts document as an output directory
/// designate one. A directory named by any other argument — `url=`, which
/// http scripts read as a path on the target, `dir=` and `save=`, short keys
/// other scripts read otherwise, a nested or array value — stays closed to
/// writes and to `lfs.mkdir`; the documented key opens it.
#[test]
fn only_documented_arguments_open_a_directory_to_scripts() {
    let script = "categories = {'safe'}\n\
        local lfs = require 'lfs'\n\
        local stdnse = require 'stdnse'\n\
        prerule = function() return true end\n\
        action = function()\n\
          local d = stdnse.get_script_args('target')\n\
          local f, err = io.open(d .. '/x', 'w')\n\
          if f then f:close() end\n\
          local ok, merr = lfs.mkdir(d .. '/sub')\n\
          return (f and 'open' or err:gsub('^.*: ', '')) .. ' / ' .. tostring(ok or merr)\n\
        end\n";
    let d = datadir("designate", &[("w-probe.nse", script)]);
    let out = std::env::temp_dir().join(format!("m64e-designate-out-{}", std::process::id()));
    let run = |args: &str| {
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).expect("out dir");
        let o = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
            .arg("--datadir")
            .arg(&d)
            .args(["-sT", "-Pn", "-n", "-p", "1", "--script", "w-probe"])
            .arg("--script-args")
            .arg(args.replace("OUT", &out.to_string_lossy()))
            .arg("127.0.0.1")
            .output()
            .expect("nmap-rs runs");
        let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
        let made: Vec<String> = std::fs::read_dir(&out)
            .expect("out dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        (stdout, made)
    };
    for args in [
        "target=OUT,url=OUT",
        "target=OUT,dir=OUT",
        "target=OUT,save=OUT",
        "target=OUT,x.destination=OUT",
        "target=OUT,nested={destination=OUT}",
        "target=OUT,{OUT}",
        "target=OUT,path=OUT",
    ] {
        let (stdout, made) = run(args);
        assert!(
            stdout.contains("|_w-probe: Permission denied / Permission denied"),
            "{args}: {stdout}"
        );
        assert!(made.is_empty(), "{args}: made {made:?}");
    }
    let (stdout, made) = run("target=OUT,destination=OUT");
    assert!(stdout.contains("|_w-probe: open / true"), "{stdout}");
    let mut made = made;
    made.sort();
    assert_eq!(made, ["sub", "x"]);
    let _ = std::fs::remove_dir_all(&out);
    let _ = std::fs::remove_dir_all(&d);
}

/// The port alone (D2, `nse-file-args-documented`): a value opens a file
/// only from an argument a shipped script uses as a local file, as that
/// script uses it. A path on the target (`http-phpmyadmin-dir-traversal.file`,
/// `file`) opens nothing here; `userdb` reads and does not write; `outfile`
/// writes. And nothing writable overlaps a data directory: such a
/// designation is refused, with a warning.
#[test]
fn only_local_file_arguments_open_their_files() {
    let script = "categories = {'safe'}\n\
        local stdnse = require 'stdnse'\n\
        prerule = function() return true end\n\
        action = function()\n\
          local p = stdnse.get_script_args('target')\n\
          local r = io.open(p, 'r')\n\
          local got = r and r:read('a') or 'no read'\n\
          if r then r:close() end\n\
          local w, err = io.open(p, 'a')\n\
          if w then w:write('!') w:close() end\n\
          return got .. ' / ' .. (w and 'wrote' or err:gsub('^.*: ', ''))\n\
        end\n";
    let d = datadir("files", &[("f-probe.nse", script)]);
    let secret = std::env::temp_dir().join(format!("m64e-files-secret-{}", std::process::id()));
    let home = std::env::temp_dir().join(format!("m64e-files-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("home");
    let run = |args: &str| {
        std::fs::write(&secret, "secret").expect("secret");
        let o = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
            .env("HOME", &home)
            .env_remove("NMAPDIR")
            .arg("--datadir")
            .arg(&d)
            .args(["-sT", "-Pn", "-n", "-p", "1", "--script", "f-probe"])
            .arg("--script-args")
            .arg(args.replace("SECRET", &secret.to_string_lossy()))
            .arg("127.0.0.1")
            .output()
            .expect("nmap-rs runs");
        (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
            std::fs::read_to_string(&secret).expect("secret"),
        )
    };
    for args in [
        "target=SECRET,http-phpmyadmin-dir-traversal.file=SECRET",
        "target=SECRET,file=SECRET",
        "target=SECRET,url=SECRET",
        "target=SECRET,nested={userdb=SECRET}",
    ] {
        let (out, _, after) = run(args);
        assert!(
            out.contains("|_f-probe: no read / Permission denied"),
            "{args}: {out}"
        );
        assert_eq!(after, "secret", "{args}: written");
    }
    // Read arguments, by a library's key, a script's full key (jdwp-inject
    // reads its `filename` locally: the review's M1) and the short key.
    for args in [
        "target=SECRET,userdb=SECRET",
        "target=SECRET,jdwp-inject.filename=SECRET",
        "target=SECRET,filename=SECRET",
    ] {
        let (out, _, after) = run(args);
        assert!(
            out.contains("|_f-probe: secret / Permission denied"),
            "{args}: {out}"
        );
        assert_eq!(after, "secret", "{args}");
    }
    // A device, as nmap reads `userdb=/dev/null` (the review's L1).
    let (out, _, _) = run("target=/dev/null,userdb=/dev/null");
    assert!(
        out.contains("/ Permission denied") && !out.contains("no read"),
        "{out}"
    );
    let (out, _, after) = run("target=SECRET,outfile=SECRET");
    assert!(out.contains("|_f-probe: secret / wrote"), "{out}");
    assert_eq!(after, "secret!");
    // An output directory inside the data directory, whose `nselib` is a
    // link to the tree's: refused, said once, naming the link.
    let (_, err, _) = run(&format!(
        "target=SECRET,destination={}",
        d.join("nselib").display()
    ));
    let want = format!("which {} leads to.", d.join("nselib").display());
    assert!(
        err.contains("NSE: Warning: scripts may not write to") && err.contains(&want),
        "{err}"
    );
    assert_eq!(err.matches("NSE: Warning").count(), 1, "{err}");
    // `~/.nmap` does not exist, but a later run would load it: neither the
    // home holding it nor a way to it is writable (the review's H2).
    for dest in [home.clone(), home.join(".nmap/nselib")] {
        let (_, err, _) = run(&format!("target=SECRET,destination={}", dest.display()));
        let want = format!(
            "overlaps the data directory {}",
            home.join(".nmap").display()
        );
        assert!(err.contains(&want), "{dest:?}: {err}");
    }
    assert!(!home.join(".nmap").exists());
    // A script chosen by path, outside the data directories, is what this
    // run loads: not writable, though named in a write argument (M2).
    let own = home.join("own.nse");
    std::fs::write(&own, script).expect("own script");
    let o = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .env("HOME", &home)
        .env_remove("NMAPDIR")
        .arg("--datadir")
        .arg(&d)
        .args(["-sT", "-Pn", "-n", "-p", "1", "--script"])
        .arg(&own)
        .arg("--script-args")
        .arg(format!("target={0},outfile={0}", own.display()))
        .arg("127.0.0.1")
        .output()
        .expect("nmap-rs runs");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("which this run loads"), "{err}");
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("/ Permission denied"),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(std::fs::read_to_string(&own).expect("own"), script);
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_file(&secret);
    let _ = std::fs::remove_dir_all(&d);
}
