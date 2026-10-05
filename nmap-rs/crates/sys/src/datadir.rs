//! Where nmap's data files are found: `nmap_fetchfile` (`nmap.cc:2677`).
//!
//! A file is looked for in each of these, in order, and the first readable
//! copy wins:
//!
//! 1. `--datadir`;
//! 2. `$NMAPDIR`, then `$NMAP_RS_DATADIR` (this port's older name for it);
//! 3. the user's directory: `~/.nmap` (`%APPDATA%\nmap` on Windows);
//! 4. the executable's directory, then `../share/nmap` beside it (not on
//!    Windows);
//! 5. the compiled-in data directory, [`NMAPDATADIR`] (not on Windows).
//!
//! The working directory is not among them. nmap leaves it out "for security
//! and consistency reasons", and says so when a `./` copy is passed over. For
//! NSE it matters more than for data files: `nselib/` and `scripts/` are code
//! the scan runs. This port's CLI used to look in `.`, `..` and `../..`
//! (`datadir-no-working-directory`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// nmap's compiled-in `NMAPDATADIR`, as distributions build it.
#[cfg(not(windows))]
pub const NMAPDATADIR: &str = "/usr/share/nmap";

/// The directories data files are looked for in, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataDirs {
    dirs: Vec<PathBuf>,
}

/// `file_is_readable`: 1 for a file, 2 for a directory, 0 for neither or for
/// one that cannot be opened.
fn readable(p: &Path) -> bool {
    match std::fs::metadata(p) {
        Ok(m) if m.is_dir() => std::fs::read_dir(p).is_ok(),
        Ok(_) => std::fs::File::open(p).is_ok(),
        Err(_) => false,
    }
}

static WARNED: AtomicBool = AtomicBool::new(false);

impl DataDirs {
    /// The search for this process: `datadir` from the command line, then
    /// the environment, the user's directory and the executable's.
    pub fn from_env(datadir: Option<&Path>) -> DataDirs {
        let mut dirs: Vec<PathBuf> = Vec::new();
        dirs.extend(datadir.map(Path::to_path_buf));
        for var in ["NMAPDIR", "NMAP_RS_DATADIR"] {
            dirs.extend(std::env::var_os(var).map(PathBuf::from));
        }
        dirs.extend(user_dir());
        if let Some(exe) = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(Path::to_path_buf))
        {
            #[cfg(not(windows))]
            let share = exe.join("../share/nmap");
            dirs.push(exe);
            #[cfg(not(windows))]
            dirs.push(share);
        }
        #[cfg(not(windows))]
        dirs.push(PathBuf::from(NMAPDATADIR));
        DataDirs { dirs }
    }

    /// A search over exactly `dirs`, in order.
    pub fn new(dirs: Vec<PathBuf>) -> DataDirs {
        DataDirs { dirs }
    }

    /// The directories, in search order, whether or not they exist.
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// The directories that exist, in search order: what NSE scripts may
    /// read beneath (Decision 2).
    pub fn existing(&self) -> Vec<PathBuf> {
        self.dirs.iter().filter(|d| d.is_dir()).cloned().collect()
    }

    /// `nmap_fetchfile(file)`: the first readable `dir/file`. Like nmap, warns
    /// once when a `./file` exists that is not the one used.
    pub fn fetch(&self, file: &str) -> Option<PathBuf> {
        let found = self
            .dirs
            .iter()
            .map(|d| d.join(file))
            .find(|p| readable(p))?;
        let dot = Path::new(".").join(file);
        if readable(&dot) && !same_file(&dot, &found) && !WARNED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "Warning: File {} exists, but Nmap is using {} for security and consistency \
                 reasons.  set NMAPDIR=. to give priority to files in your local directory \
                 (may affect the other data files too).",
                dot.display(),
                found.display()
            );
        }
        Some(found)
    }

    /// `nse_fetchfile_absolute`: an absolute name as given, otherwise
    /// [`DataDirs::fetch`].
    pub fn fetch_absolute(&self, file: &str) -> Option<PathBuf> {
        let p = Path::new(file);
        if p.is_absolute() {
            return readable(p).then(|| p.to_path_buf());
        }
        self.fetch(file)
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// The user's data directory: `~/.nmap`, or `%APPDATA%\nmap` on Windows.
/// nmap reads the home directory from the password database; `home_dir`
/// reads `$HOME` first (`datadir-home-from-environment`).
fn user_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("nmap"))
    }
    #[cfg(not(windows))]
    {
        home().map(|h| h.join(".nmap"))
    }
}

/// The user's home directory, which `os.getenv("HOME")` reports to scripts.
pub fn home() -> Option<PathBuf> {
    std::env::home_dir().filter(|h| !h.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_readable_copy_wins_in_order() {
        let tmp = std::env::temp_dir().join(format!("nmap-rs-datadir-{}", std::process::id()));
        let (a, b) = (tmp.join("a"), tmp.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(b.join("scripts")).unwrap();
        std::fs::write(b.join("nmap-services"), "b").unwrap();
        std::fs::write(b.join("scripts/x.nse"), "b").unwrap();
        let dd = DataDirs::new(vec![a.clone(), b.clone()]);
        assert_eq!(dd.fetch("nmap-services"), Some(b.join("nmap-services")));
        std::fs::write(a.join("nmap-services"), "a").unwrap();
        assert_eq!(dd.fetch("nmap-services"), Some(a.join("nmap-services")));
        assert_eq!(dd.fetch("scripts/x.nse"), Some(b.join("scripts/x.nse")));
        assert_eq!(dd.fetch("missing"), None);
        // A directory counts, as file_is_readable's 2 does.
        assert_eq!(dd.fetch("scripts"), Some(b.join("scripts")));
        let abs = b.join("nmap-services");
        assert_eq!(dd.fetch_absolute(abs.to_str().unwrap()), Some(abs.clone()));
        assert_eq!(dd.existing(), vec![a, b]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn the_working_directory_is_never_searched() {
        let dd = DataDirs::from_env(None);
        let cwd = std::env::current_dir().unwrap();
        assert!(
            dd.dirs()
                .iter()
                .all(|d| d.as_os_str() != "." && d.as_os_str() != ".." && *d != cwd),
            "{:?}",
            dd.dirs()
        );
    }
}
