//! M6.6 step a, end to end: `nmapdb` through the command line, reading this
//! repository's data files from `--datadir`, as a scan reads them.
//!
//! The unit tests and `nmapdb_differential` give the engine a data-file
//! reader of their own; this is the only gate on the CLI's
//! (`read_data_bytes`). A reader that finds nothing, or the wrong file,
//! fails here (M6.6 review, sabotage S21). The answers are 7.94's, run as
//! `nmap --datadir REPO -sn -n --script nmapdb-prerule.nse 127.0.0.1`.
#![cfg(all(unix, not(miri)))] // runs the binary

use std::path::PathBuf;
use std::process::Command;

const PRERULE: &str = r#"
categories = {"safe"}
prerule = function() return true end
action = function()
  return ("mac=%s prot6=%s udp=%s svc=%s unknown=%s"):format(
    tostring(nmapdb.mac2corp("080027000000")),
    tostring(nmapdb.getprotbynum(6)),
    tostring(nmapdb.getprotbyname("udp")),
    tostring(nmapdb.getservbyport(22, "tcp")),
    tostring(nmapdb.getservbyport(4, "tcp")))
end
"#;

fn run(datadir: &std::path::Path, tag: &str) -> (String, String) {
    let dir = std::env::temp_dir().join(format!("nmapdb-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let script = dir.join("nmapdb-prerule.nse");
    std::fs::write(&script, PRERULE).expect("script");
    let out = Command::new(env!("CARGO_BIN_EXE_nmap-rs"))
        .arg("--datadir")
        .arg(datadir)
        .args(["-sT", "-Pn", "-n", "-p", "1", "--script"])
        .arg(&script)
        .arg("127.0.0.1")
        .env_remove("NMAPDIR")
        .env_remove("NMAP_RS_DATADIR")
        .output()
        .expect("nmap-rs runs");
    let _ = std::fs::remove_dir_all(&dir);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn nmapdb_answers_from_the_data_directory() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let (stdout, stderr) = run(&repo, "repo");
    assert!(
        stdout.contains(
            "|_nmapdb-prerule: mac=Oracle VirtualBox virtual NIC prot6=tcp udp=17 svc=ssh unknown=nil"
        ),
        "{stdout}\n{stderr}"
    );
    assert!(!stderr.contains("Cannot find"), "{stderr}");
    assert!(!stderr.contains("Unable to"), "{stderr}");
}

/// The repository's files and none other: with `nmap-mac-prefixes` and
/// `nmap-protocols` replaced by a directory of copies holding marker
/// entries, the markers are what the scripts see. 7.94 gives the same over
/// the same directory.
#[test]
fn nmapdb_reads_the_files_the_search_finds() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let d = std::env::temp_dir().join(format!("nmapdb-cli-data-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("data dir");
    for name in ["nselib", "nse_main.lua", "nmap-services", "scripts"] {
        std::os::unix::fs::symlink(repo.join(name), d.join(name)).expect("symlink");
    }
    std::fs::write(d.join("nmap-mac-prefixes"), "080027 Marker Vendor\n").expect("macs");
    // `tcp 6` stays: 7.94 resolves `nmap-services`' protocol column through
    // this file, and without it names no tcp port (`services-protocols-hardcoded`).
    std::fs::write(d.join("nmap-protocols"), "marker 6\ntcp 6\nudp 99\n").expect("protocols");
    let (stdout, stderr) = run(&d, "marker");
    // A directory where a data file should be is "not found", as in 7.94.
    std::fs::remove_file(d.join("nmap-mac-prefixes")).expect("rm");
    std::fs::create_dir(d.join("nmap-mac-prefixes")).expect("mkdir");
    let (dir_stdout, dir_stderr) = run(&d, "dir");
    let _ = std::fs::remove_dir_all(&d);
    assert!(
        stdout.contains("mac=Marker Vendor prot6=marker udp=99 svc=ssh unknown=nil"),
        "{stdout}\n{stderr}"
    );
    assert!(
        dir_stdout.contains("mac=nil prot6=marker udp=99 svc=ssh unknown=nil"),
        "{dir_stdout}\n{dir_stderr}"
    );
    assert!(
        dir_stderr.contains(
            "Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed"
        ),
        "{dir_stderr}"
    );
}
