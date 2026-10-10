//! Where nmap's data files are found: `nmap_fetchfile_sub` (`nmap.cc:2677`).
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

/// `file_is_readable` (`nbase_misc.c:706-731`): `stat`, then `access(R_OK)`;
/// 1 for a file, 2 for a directory, 0 for neither. The search stops at either
/// (`nmap_fetchfile` returns 2 for a directory, and the data-file loaders
/// then treat it as not found, since they test for 1).
///
/// `access` is not in `std`, and this crate keeps its FFI behind `raw-ffi`, so
/// its answer is had without it, and without ever opening anything that could
/// block: a directory is readable if it can be listed, a regular file if it
/// can be opened (neither blocks), and any other kind of file — a FIFO, a
/// socket, a device — counts as readable without being opened, as `access`
/// says of it to root. The loader that then opens it reports what it finds
/// (`read_data_file`). Where this can differ from C: a non-root user and a
/// FIFO, socket or device without read permission, which C passes over and
/// this stops at (`datadir-readable-without-access`).
fn readable(p: &Path) -> bool {
    match std::fs::metadata(p) {
        Ok(m) if m.is_dir() => std::fs::read_dir(p).is_ok(),
        Ok(m) if m.is_file() => std::fs::File::open(p).is_ok(),
        Ok(_) => true,
        Err(_) => false,
    }
}

/// The most of a data file [`read_data_file`] reads: far beyond any shipped
/// file (`nmap-mac-prefixes` is under 1 MiB), and a bound on what a file
/// planted in the search path can cost (`datafile-size-cap`).
pub const DATA_FILE_MAX: u64 = 64 * 1024 * 1024;

/// What [`read_data_file`] found.
#[derive(Debug)]
pub enum DataRead {
    /// A regular file, read whole.
    Bytes(Vec<u8>),
    /// A directory: to the loaders, as to C's, not found.
    Directory,
    /// Neither a regular file nor a directory: a FIFO, a socket that opened,
    /// a device. Refused, where C would read it (`datafile-special-file-refused`).
    NotRegular,
    /// Larger than the cap (`datafile-size-cap`).
    TooLarge,
    /// It could not be opened or read: the system's reason.
    Io(std::io::Error),
}

/// Read a data file `nmap_fetchfile` found, as `fopen` and `fgets` would,
/// but safely: opened non-blocking (a FIFO cannot stall the scan), only a
/// regular file read, and at most `max` bytes of it.
pub fn read_data_file(path: &Path, max: u64) -> DataRead {
    use std::io::Read;
    if std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
        return DataRead::Directory;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(f) => f,
        Err(e) => return DataRead::Io(e),
    };
    // The kind of what was opened, not of what the name named a moment ago.
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return DataRead::Io(e),
    };
    if meta.is_dir() {
        return DataRead::Directory;
    }
    if !meta.is_file() {
        return DataRead::NotRegular;
    }
    if meta.len() > max {
        return DataRead::TooLarge;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    // One byte past the cap tells a file that grew from one that fits.
    match file.take(max.saturating_add(1)).read_to_end(&mut bytes) {
        Ok(_) if !u64::try_from(bytes.len()).is_ok_and(|n| n <= max) => DataRead::TooLarge,
        Ok(_) => DataRead::Bytes(bytes),
        Err(e) => DataRead::Io(e),
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

#[cfg(all(test, not(miri)))] // real directories and the working directory; Miri has no filesystem
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

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nmap-rs-datadir-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// `file_is_readable` stops the search at a directory (its 2), and the
    /// loader then calls it not found; at a FIFO, without opening it.
    #[test]
    fn the_search_stops_at_a_directory_and_at_a_fifo() {
        let tmp = scratch("stop");
        let (a, b) = (tmp.join("a"), tmp.join("b"));
        std::fs::create_dir_all(a.join("nmap-protocols")).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("nmap-protocols"), "tcp 6\n").unwrap();
        let dd = DataDirs::new(vec![a.clone(), b.clone()]);
        let found = dd.fetch("nmap-protocols").unwrap();
        assert_eq!(found, a.join("nmap-protocols"));
        assert!(matches!(
            read_data_file(&found, DATA_FILE_MAX),
            DataRead::Directory
        ));
        #[cfg(unix)]
        {
            let fifo = a.join("nmap-mac-prefixes");
            let ok = std::process::Command::new("mkfifo").arg(&fifo).status();
            if ok.is_ok_and(|s| s.success()) {
                std::fs::write(b.join("nmap-mac-prefixes"), "000000 X\n").unwrap();
                // Neither the search nor the read blocks on the FIFO.
                assert_eq!(dd.fetch("nmap-mac-prefixes"), Some(fifo.clone()));
                assert!(matches!(
                    read_data_file(&fifo, DATA_FILE_MAX),
                    DataRead::NotRegular
                ));
            }
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_data_file_is_read_up_to_the_cap() {
        let tmp = scratch("cap");
        let f = tmp.join("nmap-protocols");
        std::fs::write(&f, b"tcp 6\nudp 17\n").unwrap();
        match read_data_file(&f, DATA_FILE_MAX) {
            DataRead::Bytes(b) => assert_eq!(b, b"tcp 6\nudp 17\n"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(read_data_file(&f, 13), DataRead::Bytes(_)));
        assert!(matches!(read_data_file(&f, 12), DataRead::TooLarge));
        match read_data_file(&tmp.join("missing"), DATA_FILE_MAX) {
            DataRead::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("{other:?}"),
        }
        #[cfg(unix)]
        assert!(matches!(
            read_data_file(Path::new("/dev/zero"), DATA_FILE_MAX),
            DataRead::NotRegular
        ));
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
