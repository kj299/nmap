//! Which files an NSE script may open (Decision 2, `docs/M6-ANALYSIS.md`).
//!
//! nmap gives every script the whole file system, with the privileges nmap
//! runs under — usually root. Measured across the 744 shipped Lua files, what
//! scripts open is: data files nmap ships (found with `nmap.fetchfile`), files
//! the operator names in `--script-args` (`userdb=`, `passdb=`, output files),
//! and nothing else. So that is what is allowed:
//!
//! - **reading** a file beneath one of nmap's data directories, or a file the
//!   operator named;
//! - **writing** a file the operator named, or one beneath a directory the
//!   operator designated for script output.
//!
//! A directory is designated for output by the operator naming it in one of
//! the arguments the shipped scripts document as an output directory
//! ([`OUTPUT_DIR_ARGS`], `docs/LFS-ANALYSIS.md` D1), and only there: a value
//! elsewhere that happens to name a directory (`url=/`) designates nothing.
//! Directories are created ([`FsPolicy::allows_mkdir`], `lfs.mkdir`) beneath
//! a designated directory and nowhere else.
//!
//! Every path is compared after canonicalisation — the host resolves `..`,
//! `.` and symbolic links before asking, and names the file it would open —
//! so neither `../../etc/shadow` nor a link planted in a data directory gets
//! out. A refusal looks to the script like the system refusing:
//! `nil, "NAME: Permission denied", 13`.

use std::path::{Path, PathBuf};

/// The directories and files a run allows, each canonical.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsPolicy {
    /// nmap's data directories (`--datadir`, `NMAPDIR`, `~/.nmap`, the
    /// install directory): readable, with everything beneath them.
    pub read_roots: Vec<PathBuf>,
    /// Directories the operator designated for script output: readable and
    /// writable, with everything beneath them.
    pub write_roots: Vec<PathBuf>,
    /// Files the operator named in `--script-args`: readable and writable.
    pub named: Vec<PathBuf>,
    /// Files the host makes readable and nothing more: the operator's
    /// `~/.ssh/config` and `~/.ssh/known_hosts`, which `ssh1.lua` reads
    /// through `os.getenv("HOME")` (`os-getenv-home-only`).
    pub read_named: Vec<PathBuf>,
}

impl FsPolicy {
    /// Whether a script may create the directory at `canonical`: only
    /// beneath a designated output directory (a named *file* is a file).
    pub fn allows_mkdir(&self, canonical: &Path) -> bool {
        canonical.is_absolute() && self.write_roots.iter().any(|r| canonical.starts_with(r))
    }

    /// Whether a script may open the file at `canonical` — for writing too
    /// when `write` is set.
    pub fn allows(&self, canonical: &Path, write: bool) -> bool {
        if !canonical.is_absolute() {
            return false;
        }
        let beneath = |roots: &[PathBuf]| roots.iter().any(|r| canonical.starts_with(r));
        if self.named.iter().any(|n| n == canonical) || beneath(&self.write_roots) {
            return true;
        }
        !write && (beneath(&self.read_roots) || self.read_named.iter().any(|n| n == canonical))
    }
}

/// The script arguments that designate an output directory: those the
/// shipped scripts document as the directory they save into, by their full
/// key, and by the short key `stdnse.get_script_args` also accepts
/// (`stdnse.lua:616-628`) only where no other shipped script reads that short
/// key. `dir` is not one: `http-phpmyadmin-dir-traversal.dir` and
/// `http-vlcstreamer-ls.dir` are paths on the target, so `dir=/` would
/// otherwise make this host's root writable. Nor is `save`, which
/// `stuxnet-detect` reads as a file-name template, nor `path`, which 34
/// script keys end in, most of them URL paths on the target.
pub const OUTPUT_DIR_ARGS: [&str; 12] = [
    "http-fetch.destination", // http-fetch.nse:200
    "destination",
    "http-config-backup.save",  // http-config-backup.nse:183
    "ms-sql-dump-hashes.dir",   // ms-sql-dump-hashes.nse:98
    "snmp-ios-config.tftproot", // snmp-ios-config.nse:55
    "tftproot",
    "cics-enum.path",                    // cics-enum.nse:378
    "lu-enum.path",                      // lu-enum.nse:178
    "vtam-enum.path",                    // vtam-enum.nse:249
    "domino-enum-users.path",            // domino-enum-users.nse:74
    "http-domino-enum-passwords.idpath", // http-domino-enum-passwords.nse:217
    "idpath",
];

/// The values of the top-level arguments in [`OUTPUT_DIR_ARGS`] that are
/// strings: the directories the operator designated for output, if they are
/// directories, which is for the host to find out.
pub fn output_dir_values(args: &super::scriptargs::ArgTable) -> Vec<Vec<u8>> {
    use super::scriptargs::ArgValue;
    args.fields
        .iter()
        .filter(|(k, _)| OUTPUT_DIR_ARGS.iter().any(|a| a.as_bytes() == k.as_slice()))
        .filter_map(|(_, v)| match v {
            ArgValue::Str(s) => Some(s.clone()),
            ArgValue::Table(_) => None,
        })
        .collect()
}

/// The string values of the script arguments, at any depth: the paths an
/// operator may have named. Which of them are files is for the host to find
/// out; a value that names no file names nothing a script can open.
pub fn named_values(args: &super::scriptargs::ArgTable) -> Vec<Vec<u8>> {
    use super::scriptargs::ArgValue;
    fn walk(t: &super::scriptargs::ArgTable, out: &mut Vec<Vec<u8>>) {
        let values = t.array.iter().chain(t.fields.iter().map(|(_, v)| v));
        for v in values {
            match v {
                ArgValue::Str(s) => out.push(s.clone()),
                ArgValue::Table(t) => walk(t, out),
            }
        }
    }
    let mut out = Vec::new();
    walk(args, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FsPolicy {
        FsPolicy {
            read_roots: vec![PathBuf::from("/usr/share/nmap")],
            write_roots: vec![PathBuf::from("/home/op/loot")],
            named: vec![PathBuf::from("/home/op/users.txt")],
            read_named: vec![PathBuf::from("/home/op/.ssh/known_hosts")],
        }
    }

    #[test]
    fn read_named_files_are_readable_not_writable() {
        let p = policy();
        assert!(p.allows(Path::new("/home/op/.ssh/known_hosts"), false));
        assert!(!p.allows(Path::new("/home/op/.ssh/known_hosts"), true));
        assert!(!p.allows(Path::new("/home/op/.ssh/known_hosts/x"), false));
    }

    #[test]
    fn data_files_are_readable_not_writable() {
        let p = policy();
        assert!(p.allows(
            Path::new("/usr/share/nmap/nselib/data/passwords.lst"),
            false
        ));
        assert!(!p.allows(Path::new("/usr/share/nmap/nselib/data/passwords.lst"), true));
    }

    #[test]
    fn named_files_and_output_dirs_are_both() {
        let p = policy();
        assert!(p.allows(Path::new("/home/op/users.txt"), false));
        assert!(p.allows(Path::new("/home/op/users.txt"), true));
        assert!(p.allows(Path::new("/home/op/loot/http/index.html"), true));
    }

    #[test]
    fn everything_else_is_refused() {
        let p = policy();
        for path in [
            "/etc/shadow",
            "/home/op/.ssh/id_rsa",
            "/usr/share/nmapx/f",
            "/home/op/lootx",
        ] {
            assert!(!p.allows(Path::new(path), false), "{path}");
            assert!(!p.allows(Path::new(path), true), "{path}");
        }
        // A named file names that file, not its directory.
        assert!(!p.allows(Path::new("/home/op/users.txt/x"), false));
        // Relative paths are never canonical.
        assert!(!p.allows(Path::new("nselib/data/x"), false));
    }

    #[test]
    fn directories_are_made_beneath_output_dirs_only() {
        let p = policy();
        assert!(p.allows_mkdir(Path::new("/home/op/loot/10.0.0.1")));
        assert!(p.allows_mkdir(Path::new("/home/op/loot/a/b")));
        // Not beside it, not in a data directory, not where a file is named.
        for path in [
            "/home/op/lootx",
            "/home/op/new",
            "/usr/share/nmap/scripts/x",
            "/home/op/users.txt",
            "/home/op/.ssh/known_hosts",
            "loot/x",
        ] {
            assert!(!p.allows_mkdir(Path::new(path)), "{path}");
        }
    }

    #[test]
    fn only_documented_output_arguments_designate_directories() {
        use crate::nse::scriptargs::registry_args;
        let args = registry_args(
            None,
            b"http-fetch.destination=/a,destination=/b,tftproot=/c,ms-sql-dump-hashes.dir=/d,\
              http-config-backup.save=/e,snmp-ios-config.tftproot=/f,dir=/,save=/g,url=/,\
              x.destination=/h,{/i},nested={destination=/j},http-fetch.destination2=/k,\
              cics-enum.path=/l,lu-enum.path=/m,vtam-enum.path=/n,domino-enum-users.path=/o,\
              http-domino-enum-passwords.idpath=/p,idpath=/q,path=/,\
              http-domino-enum-passwords.path=/r",
        )
        .expect("parses");
        assert_eq!(
            output_dir_values(&args),
            ["/a", "/b", "/c", "/d", "/e", "/f", "/l", "/m", "/n", "/o", "/p", "/q"]
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect::<Vec<_>>()
        );
        // A table value designates nothing.
        let args = registry_args(None, b"destination={/a,/b}").expect("parses");
        assert!(output_dir_values(&args).is_empty());
    }

    #[test]
    fn prefixes_are_components_not_bytes() {
        let p = policy();
        assert!(!p.allows(Path::new("/usr/share/nmap-evil/x"), false));
        assert!(!p.allows(Path::new("/home/op/loot2/x"), true));
    }
}
