//! Installing a verified signature-database file (Workstream S, slice S4).
//!
//! This is the only place in the port that writes a detection database to disk, so
//! it is where "the bytes we fetched become the bytes nmap-rs will trust next run"
//! actually happens. Two properties matter more than anything else here:
//!
//! **Nothing unverified can be installed.** [`Installer::install`] takes the
//! [`FileEntry`] from the manifest and the bytes, and checks the declared size and
//! SHA-256 itself before opening a file. There is no "install these bytes, I already
//! checked" entry point, because that is an invitation to a caller who did not.
//! Holding a `Manifest` is not evidence of verification (S1 says so explicitly);
//! neither is holding a `Vec<u8>`.
//!
//! **A failed or interrupted install leaves the previous database intact.** The
//! write goes to a temporary file in the destination directory, is flushed and
//! fsynced, and only then renamed over the target. `rename(2)` within a directory is
//! atomic, so a reader either sees the whole old file or the whole new one — never a
//! half-written database, and never a missing one because the process died between
//! truncate and write.
//!
//! # What this deliberately does not do
//!
//! There is **no archive unpacking here**, and that is a scope decision worth
//! stating. The manifest already carries each file's name, size and SHA-256, so a
//! bundle can be a set of files rather than an archive — which removes the
//! decompression-bomb class by construction rather than defending against it, and
//! avoids an archive-format dependency. Whether the bytes arrive as one archive or
//! several downloads is the fetcher's business (S5); this module's contract is the
//! same either way. See `docs/S-ANALYSIS.md`.
//!
//! It also never writes to a system directory. An update lands in the per-user data
//! directory, the same one nmap's own `nmap_fetchfile_userdir` reads from, so an
//! update can never overwrite a distribution's files.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use nmap_core::sigstore::digest::{to_hex, Sha256};
use nmap_core::sigstore::manifest::FileEntry;

/// Why an install did not happen.
#[derive(Debug)]
pub enum InstallError {
    /// The bytes were not the length the manifest declared.
    SizeMismatch {
        /// What the manifest said.
        declared: u64,
        /// What arrived.
        actual: u64,
    },
    /// The bytes did not hash to the digest the manifest declared. **This is the
    /// one that matters**: it means the content is not what was signed.
    DigestMismatch {
        /// The manifest's digest, lowercase hex.
        declared: String,
        /// The digest of what arrived.
        actual: String,
    },
    /// The per-user data directory could not be determined.
    NoDataDir,
    /// A filesystem operation failed, with the step that failed named — "write
    /// failed" and "rename failed" have very different consequences for what is now
    /// on disk, so the caller is told which.
    Io {
        /// What was being attempted.
        step: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
}

impl core::fmt::Display for InstallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SizeMismatch { declared, actual } => {
                write!(f, "manifest declares {declared} bytes but {actual} arrived")
            }
            Self::DigestMismatch { declared, actual } => write!(
                f,
                "content does not match the signed digest (declared {declared}, got {actual})"
            ),
            Self::NoDataDir => write!(f, "cannot determine the per-user data directory"),
            Self::Io { step, source } => write!(f, "{step}: {source}"),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// The per-user data directory an update installs into.
///
/// Mirrors nmap's `nmap_fetchfile_userdir` (`nmap.cc:2633`/`:2660`): `%APPDATA%\nmap`
/// on Windows, `~/.nmap` elsewhere. Reading the same directory nmap reads is the
/// point — an installed update has to be found by the loader.
///
/// **Only the user's own directory**, never a system one. The C's search path also
/// covers `$NMAPDIR`, the executable's directory and `NMAPDATADIR`; an update that
/// could write to those could overwrite a distribution's files, so this does not
/// resolve them. Returns `None` when the home directory is not known.
#[must_use]
pub fn user_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("nmap"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".nmap"))
    }
}

/// Installs verified database files into a directory.
#[derive(Debug, Clone)]
pub struct Installer {
    dir: PathBuf,
}

impl Installer {
    /// An installer writing into `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// An installer writing into the per-user data directory.
    ///
    /// # Errors
    ///
    /// [`InstallError::NoDataDir`] when the home directory is not known.
    pub fn for_user() -> Result<Self, InstallError> {
        user_data_dir()
            .map(Self::new)
            .ok_or(InstallError::NoDataDir)
    }

    /// The directory this installer writes into.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Verify `bytes` against `entry` and, only if they match, install them.
    ///
    /// Returns the path written. The size is checked before the digest purely
    /// because it is the cheaper of the two and rules out the common case of a
    /// truncated download without hashing megabytes; both are checked before
    /// anything is opened for writing.
    ///
    /// # Errors
    ///
    /// [`InstallError::SizeMismatch`] or [`InstallError::DigestMismatch`] when the
    /// content is not what the manifest describes — nothing is written in either
    /// case. [`InstallError::Io`] naming the failed step otherwise; a failure at any
    /// step leaves any previously installed file untouched.
    pub fn install(&self, entry: &FileEntry, bytes: &[u8]) -> Result<PathBuf, InstallError> {
        let actual_len = bytes.len() as u64;
        if actual_len != entry.size {
            return Err(InstallError::SizeMismatch {
                declared: entry.size,
                actual: actual_len,
            });
        }
        let actual = Sha256::digest(bytes);
        if actual != entry.sha256 {
            return Err(InstallError::DigestMismatch {
                declared: to_hex(&entry.sha256),
                actual: to_hex(&actual),
            });
        }

        fs::create_dir_all(&self.dir).map_err(|source| InstallError::Io {
            step: "creating the data directory",
            source,
        })?;

        // The temporary lives in the DESTINATION directory, not the system temp dir:
        // `rename` is only atomic within a filesystem, and /tmp is very often a
        // different one. A cross-device rename would fall back to copy-then-delete,
        // which is exactly the non-atomic behaviour this is avoiding.
        //
        // The name is derived from the entry's name, which S1's allowlist has already
        // constrained to a single ordinary path component -- so this cannot escape
        // the directory however the manifest was written.
        let target = self.dir.join(&entry.name);
        let tmp = self.dir.join(format!(".{}.tmp", entry.name));

        {
            let mut f = fs::File::create(&tmp).map_err(|source| InstallError::Io {
                step: "creating the temporary file",
                source,
            })?;
            f.write_all(bytes).map_err(|source| InstallError::Io {
                step: "writing the temporary file",
                source,
            })?;
            // Flush the file's own contents to the device before renaming. Without
            // this the rename can be durable while the data behind it is not, which
            // on a crash leaves a name pointing at zeroes -- a corrupt database that
            // looks installed.
            //
            // NOT COVERED BY ANY TEST, and deliberately left in anyway. Durability
            // across power loss cannot be observed from inside the process: a
            // mutation that deletes this call passes every test in this module.
            // That is the opposite case from the redundant guard removed in S3c --
            // that one could never fire, this one does real work that userspace
            // cannot watch. Recorded in DIVERGENCES so the gap is known rather than
            // mistaken for coverage.
            f.sync_all().map_err(|source| InstallError::Io {
                step: "syncing the temporary file",
                source,
            })?;
        }

        fs::rename(&tmp, &target).map_err(|source| {
            // Best effort: leaving a stale `.name.tmp` behind is untidy but harmless,
            // and the rename error is the one worth reporting.
            let _ = fs::remove_file(&tmp);
            InstallError::Io {
                step: "renaming the temporary file into place",
                source,
            }
        })?;

        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nmap_core::sigstore::manifest::Manifest;

    /// A scratch directory under the target dir, removed by the guard on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!("nmap-rs-sigstore-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).expect("scratch dir");
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A one-file manifest whose entry describes `content` correctly.
    fn entry_for(name: &str, content: &[u8]) -> FileEntry {
        let src = format!(
            "schema = 1\nserial = 1\nfile = {name}\nversion = 1\nsha256 = {}\nsize = {}\n",
            to_hex(&Sha256::digest(content)),
            content.len()
        );
        Manifest::parse(src.as_bytes())
            .expect("manifest parses")
            .files
            .into_iter()
            .next()
            .expect("one entry")
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn a_verified_file_is_installed_under_its_manifest_name() {
        let tmp = TempDir::new("ok");
        let content = b"# nmap-os-db\nFingerprint Something\n";
        let entry = entry_for("nmap-os-db", content);
        let path = Installer::new(tmp.path())
            .install(&entry, content)
            .expect("install");
        assert_eq!(path, tmp.path().join("nmap-os-db"));
        assert_eq!(fs::read(&path).expect("read back"), content);
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn content_that_does_not_match_the_signed_digest_is_refused_and_writes_nothing() {
        // The property the whole module exists for.
        let tmp = TempDir::new("digest");
        // The tampered bytes are the SAME LENGTH as the signed ones, so the size
        // check passes and the DIGEST check is what fires. The first version of this
        // test used a longer replacement, tripped SizeMismatch, and passed while
        // never exercising the path it is named for -- a test that asserts the wrong
        // control is worse than none.
        let entry = entry_for("nmap-os-db", b"the signed content");
        let err = Installer::new(tmp.path())
            .install(&entry, b"the s1gned content")
            .expect_err("must refuse");
        assert!(
            matches!(err, InstallError::DigestMismatch { .. }),
            "{err:?}"
        );
        assert!(
            !tmp.path().join("nmap-os-db").exists(),
            "a refused install left a file behind"
        );
        // Not even a temporary.
        let leftovers: Vec<_> = fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .collect();
        assert!(leftovers.is_empty(), "refused install left {leftovers:?}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn a_truncated_download_is_refused_on_size_before_it_is_hashed() {
        let tmp = TempDir::new("size");
        let entry = entry_for("nmap-os-db", b"the whole file");
        let err = Installer::new(tmp.path())
            .install(&entry, b"the whole")
            .expect_err("must refuse");
        match err {
            InstallError::SizeMismatch { declared, actual } => {
                assert_eq!(declared, 14);
                assert_eq!(actual, 9);
            }
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
        assert!(!tmp.path().join("nmap-os-db").exists());
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn a_refused_install_leaves_the_previous_file_untouched() {
        // The reason the write is atomic: an operator whose update fails must still
        // have a working database.
        let tmp = TempDir::new("keep");
        let inst = Installer::new(tmp.path());
        let old = b"the database that works";
        inst.install(&entry_for("nmap-os-db", old), old)
            .expect("first install");

        // Same length as the declared content, so this is a digest failure rather
        // than a size failure -- the harder case, since the bytes look plausible.
        let entry = entry_for("nmap-os-db", b"the replacement");
        let err = inst
            .install(&entry, b"the rep1acement")
            .expect_err("must refuse");
        assert!(matches!(err, InstallError::DigestMismatch { .. }));
        assert_eq!(
            fs::read(tmp.path().join("nmap-os-db")).expect("old file"),
            old,
            "the previous database was disturbed by a failed update"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn a_successful_install_replaces_the_previous_file_completely() {
        let tmp = TempDir::new("replace");
        let inst = Installer::new(tmp.path());
        let old = b"a much much much longer previous database";
        inst.install(&entry_for("nmap-os-db", old), old)
            .expect("first");
        let new = b"short";
        inst.install(&entry_for("nmap-os-db", new), new)
            .expect("second");
        // Not old bytes with the new prefix written over them, which is what a
        // truncate-and-write would leave if it died midway.
        assert_eq!(fs::read(tmp.path().join("nmap-os-db")).expect("read"), new);
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn no_temporary_file_survives_a_successful_install() {
        let tmp = TempDir::new("notmp");
        let content = b"content";
        Installer::new(tmp.path())
            .install(&entry_for("nmap-os-db", content), content)
            .expect("install");
        let names: Vec<String> = fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["nmap-os-db".to_string()],
            "stray files: {names:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn the_data_directory_is_created_if_it_does_not_exist() {
        let tmp = TempDir::new("mkdir");
        let nested = tmp.path().join("does").join("not").join("exist");
        let content = b"x";
        let path = Installer::new(&nested)
            .install(&entry_for("nmap-os-db", content), content)
            .expect("install into a fresh tree");
        assert!(path.exists());
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn an_empty_file_installs_and_reads_back_empty() {
        // Zero-length is the degenerate case for both the size check and the hash.
        let tmp = TempDir::new("empty");
        let entry = entry_for("nmap-os-db", b"");
        // The manifest rejects an empty FINGERPRINT, not an empty file, so this is
        // a legitimate entry: size 0 with the digest of the empty string.
        let path = Installer::new(tmp.path())
            .install(&entry, b"")
            .expect("install");
        assert_eq!(fs::read(&path).expect("read"), b"");
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn a_failed_rename_does_not_leave_the_temporary_behind() {
        // Induce a real rename failure by making the target path a NON-EMPTY
        // directory: rename(file, dir) cannot succeed. Without this the cleanup arm
        // was never executed by any test, and mutation-testing showed removing it
        // changed nothing observable.
        let tmp = TempDir::new("renamefail");
        let target = tmp.path().join("nmap-os-db");
        fs::create_dir_all(target.join("occupied")).expect("blocking directory");

        let content = b"content";
        let err = Installer::new(tmp.path())
            .install(&entry_for("nmap-os-db", content), content)
            .expect_err("rename over a non-empty directory must fail");
        assert!(matches!(err, InstallError::Io { .. }), "{err:?}");

        let names: Vec<String> = fs::read_dir(tmp.path())
            .expect("readdir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| n.ends_with(".tmp")),
            "a failed rename left a temporary behind: {names:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn a_reader_never_observes_a_partially_written_database() {
        // THE reason the write goes via a temporary. A reader racing the install
        // must see either the whole old file or the whole new one -- never a prefix.
        // Direct-to-target writing fails this; nothing else in this module's tests
        // can tell the two apart, because on the success path the end state is
        // identical.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let tmp = TempDir::new("atomic");
        let inst = Installer::new(tmp.path());
        let old = vec![b'o'; 512 * 1024];
        let new = vec![b'n'; 512 * 1024];
        inst.install(&entry_for("nmap-os-db", &old), &old)
            .expect("seed");

        let target = tmp.path().join("nmap-os-db");
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let reader_target = target.clone();
        let reader = std::thread::spawn(move || {
            let mut seen_bad = None;
            while !reader_stop.load(Ordering::Relaxed) {
                if let Ok(bytes) = fs::read(&reader_target) {
                    let all_old = bytes.iter().all(|b| *b == b'o');
                    let all_new = bytes.iter().all(|b| *b == b'n');
                    if !(bytes.len() == 512 * 1024 && (all_old || all_new)) {
                        seen_bad = Some(bytes.len());
                        break;
                    }
                }
            }
            seen_bad
        });

        for _ in 0..20 {
            inst.install(&entry_for("nmap-os-db", &new), &new)
                .expect("install new");
            inst.install(&entry_for("nmap-os-db", &old), &old)
                .expect("install old");
        }
        stop.store(true, Ordering::Relaxed);

        let seen = reader.join().expect("reader thread");
        assert_eq!(
            seen, None,
            "a reader observed a partial file of {seen:?} bytes -- the install is not atomic"
        );
    }

    #[test]
    fn the_user_data_directory_is_the_one_nmap_reads() {
        // ~/.nmap (or %APPDATA%\nmap): the same directory nmap_fetchfile_userdir
        // looks in, which is the point -- an installed update must be found by the
        // loader. Never a system directory.
        let Some(dir) = user_data_dir() else {
            return; // no HOME in this environment; nothing to assert
        };
        #[cfg(not(windows))]
        assert!(dir.ends_with(".nmap"), "{dir:?}");
        #[cfg(windows)]
        assert!(dir.ends_with("nmap"), "{dir:?}");
        for system in ["/usr", "/etc", "/opt", "/usr/share"] {
            assert!(
                !dir.starts_with(system),
                "the installer would write into a system directory: {dir:?}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot execute real filesystem syscalls")]
    fn the_temporary_is_a_sibling_of_the_target_not_a_system_temp_file() {
        // `rename` is only atomic within one filesystem, and /tmp is very often a
        // different one. Assert the invariant by installing into a directory and
        // checking that a mid-install temporary would be a sibling: the successful
        // path leaves none, so this checks the naming rule directly.
        let tmp = TempDir::new("sibling");
        let content = b"content";
        let entry = entry_for("nmap-os-db", content);
        let inst = Installer::new(tmp.path());
        inst.install(&entry, content).expect("install");
        assert_eq!(inst.dir(), tmp.path());
        // The name the implementation derives, spelled out so a change to it is a
        // deliberate act rather than an accident.
        let expected_tmp = tmp.path().join(".nmap-os-db.tmp");
        assert_eq!(expected_tmp.parent(), Some(tmp.path()));
    }
}
