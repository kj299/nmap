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
    fn prefixes_are_components_not_bytes() {
        let p = policy();
        assert!(!p.allows(Path::new("/usr/share/nmap-evil/x"), false));
        assert!(!p.allows(Path::new("/home/op/loot2/x"), true));
    }
}
