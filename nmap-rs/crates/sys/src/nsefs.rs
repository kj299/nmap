//! The files NSE scripts open: [`ScriptFs`] over the real file system,
//! behind [`FsPolicy`] (Decision 2, `docs/M6-ANALYSIS.md`).
//!
//! A path is resolved as `fopen` would resolve it — relative to the working
//! directory — then canonicalised: a file that exists to itself, one that
//! does not yet to its canonical directory and its name. The policy decides on
//! that, and the canonical path is what is opened, so a symbolic link cannot
//! lead a check one way and an open another. (A script cannot make a link:
//! nothing a script is given creates one.)

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use nmap_core::nse::fspolicy::FsPolicy;
use nmap_core::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, ScriptFs, Whence};

/// The real file system, behind a policy.
pub struct PolicyFs {
    policy: FsPolicy,
}

impl PolicyFs {
    /// `data_dirs` readable, `output_dirs` readable and writable, and each of
    /// `named` that is a file — or could be one, in an existing directory —
    /// readable and writable. Directories that do not exist are dropped.
    pub fn new(data_dirs: &[PathBuf], output_dirs: &[PathBuf], named: &[Vec<u8>]) -> PolicyFs {
        let dirs = |ds: &[PathBuf]| -> Vec<PathBuf> {
            ds.iter().filter_map(|d| d.canonicalize().ok()).collect()
        };
        let named = named
            .iter()
            .filter_map(|n| path_of(n))
            .filter_map(|p| canonical_target(&p))
            .filter(|p| !p.is_dir())
            .collect();
        PolicyFs {
            policy: FsPolicy {
                read_roots: dirs(data_dirs),
                write_roots: dirs(output_dirs),
                named,
                read_named: Vec::new(),
            },
        }
    }

    /// Also readable, and only readable: each of `files` that exists. An
    /// absent one is dropped, so a file created later is not let in.
    pub fn with_read_files(mut self, files: &[PathBuf]) -> PolicyFs {
        self.policy.read_named.extend(
            files
                .iter()
                .filter_map(|f| f.canonicalize().ok())
                .filter(|f| f.is_file()),
        );
        self
    }

    pub fn policy(&self) -> &FsPolicy {
        &self.policy
    }
}

/// `path` as the OS reads it: bytes up to the first NUL (`fopen` reads a C
/// string), as a path.
fn path_of(bytes: &[u8]) -> Option<PathBuf> {
    let bytes = bytes.split(|&b| b == 0).next().unwrap_or(&[]);
    if bytes.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes).ok().map(PathBuf::from)
    }
}

/// The canonical path a file at `path` is, or would be once created: the
/// file itself when it exists, else its canonical directory joined with its
/// name. `None` when the directory does not exist either.
fn canonical_target(path: &Path) -> Option<PathBuf> {
    if let Ok(c) = path.canonicalize() {
        return Some(c);
    }
    let name = path.file_name()?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Some(parent.canonicalize().ok()?.join(name))
}

fn fs_error(e: &std::io::Error) -> FsError {
    let errno = i64::from(e.raw_os_error().unwrap_or(0));
    // `strerror`'s text, without the " (os error N)" Rust appends.
    let text = e.to_string();
    let message = match text.rfind(" (os error ") {
        Some(i) => text[..i].to_string(),
        None => text,
    };
    FsError { message, errno }
}

impl ScriptFs for PolicyFs {
    fn open(&self, path: &[u8], mode: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
        let path = path_of(path).ok_or(FsError {
            message: "No such file or directory".into(),
            errno: 2,
        })?;
        let Some(target) = canonical_target(&path) else {
            // Nothing there to open, and no directory to create it in: what
            // `fopen` reports, whether or not the script may look.
            return Err(FsError {
                message: "No such file or directory".into(),
                errno: 2,
            });
        };
        if !self.policy.allows(&target, mode.writes()) {
            return Err(FsError::denied());
        }
        let mut o = OpenOptions::new();
        match mode.base {
            b'r' => o.read(true).write(mode.update),
            b'w' => o.write(true).create(true).truncate(true).read(mode.update),
            _ => o.append(true).create(true).read(mode.update),
        };
        let file = o.open(&target).map_err(|e| fs_error(&e))?;
        Ok(Box::new(DiskFile(file)))
    }

    fn stdout(&self) -> Box<dyn ScriptFile> {
        Box::new(Stdout)
    }
}

struct DiskFile(File);

impl ScriptFile for DiskFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FsError> {
        self.0.read(buf).map_err(|e| fs_error(&e))
    }
    fn write(&mut self, data: &[u8]) -> Result<(), FsError> {
        self.0.write_all(data).map_err(|e| fs_error(&e))
    }
    fn seek(&mut self, whence: Whence, offset: i64) -> Result<u64, FsError> {
        let pos = match whence {
            Whence::Set => match u64::try_from(offset) {
                Ok(o) => SeekFrom::Start(o),
                Err(_) => {
                    return Err(FsError {
                        message: "Invalid argument".into(),
                        errno: 22,
                    })
                }
            },
            Whence::Cur => SeekFrom::Current(offset),
            Whence::End => SeekFrom::End(offset),
        };
        self.0.seek(pos).map_err(|e| fs_error(&e))
    }
    fn flush(&mut self) -> Result<(), FsError> {
        self.0.flush().map_err(|e| fs_error(&e))
    }
}

/// The process's standard output, which `io.write` and `print` write to.
struct Stdout;

impl ScriptFile for Stdout {
    fn read(&mut self, _: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError {
            message: "Bad file descriptor".into(),
            errno: 9,
        })
    }
    fn write(&mut self, data: &[u8]) -> Result<(), FsError> {
        std::io::stdout().write_all(data).map_err(|e| fs_error(&e))
    }
    fn seek(&mut self, _: Whence, _: i64) -> Result<u64, FsError> {
        Err(FsError {
            message: "Illegal seek".into(),
            errno: 29,
        })
    }
    fn flush(&mut self) -> Result<(), FsError> {
        std::io::stdout().flush().map_err(|e| fs_error(&e))
    }
}

#[cfg(all(test, not(miri)))] // real files and directories; Miri has no filesystem
mod tests {
    use super::*;

    /// A fresh directory under the system's temporary directory.
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nsefs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("temp dir");
        d
    }

    fn read_mode() -> OpenMode {
        OpenMode::parse(b"r").expect("valid")
    }

    fn write_mode() -> OpenMode {
        OpenMode::parse(b"w").expect("valid")
    }

    fn bytes(p: &Path) -> Vec<u8> {
        p.to_string_lossy().into_owned().into_bytes()
    }

    #[test]
    fn data_dirs_are_read_only() {
        let root = scratch("data");
        let data = root.join("nmap");
        std::fs::create_dir_all(data.join("nselib/data")).expect("mkdir");
        let file = data.join("nselib/data/list.txt");
        std::fs::write(&file, b"x").expect("write");
        let fs = PolicyFs::new(std::slice::from_ref(&data), &[], &[]);
        assert!(fs.open(&bytes(&file), read_mode()).is_ok());
        assert_eq!(
            fs.open(&bytes(&file), write_mode()).err(),
            Some(FsError::denied())
        );
        // Out of the data directory by `..`, and by a symbolic link.
        let secret = root.join("secret.txt");
        std::fs::write(&secret, b"s").expect("write");
        let dotdot = data.join("nselib/../../secret.txt");
        assert_eq!(
            fs.open(&bytes(&dotdot), read_mode()).err(),
            Some(FsError::denied())
        );
        #[cfg(unix)]
        {
            let link = data.join("nselib/data/link");
            std::os::unix::fs::symlink(&secret, &link).expect("symlink");
            assert_eq!(
                fs.open(&bytes(&link), read_mode()).err(),
                Some(FsError::denied())
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn named_files_and_output_dirs_are_writable() {
        let root = scratch("out");
        let out = root.join("loot");
        std::fs::create_dir_all(&out).expect("mkdir");
        let named = root.join("users.txt");
        let fs = PolicyFs::new(&[], std::slice::from_ref(&out), &[bytes(&named)]);
        // The named file does not exist yet; it may be created and read back.
        let mut f = fs.open(&bytes(&named), write_mode()).expect("named file");
        f.write(b"root\n").expect("write");
        drop(f);
        let mut f = fs.open(&bytes(&named), read_mode()).expect("read back");
        let mut buf = [0u8; 16];
        assert_eq!(f.read(&mut buf).expect("read"), 5);
        assert!(fs.open(&bytes(&out.join("a/b")), write_mode()).is_err());
        assert!(fs
            .open(&bytes(&out.join("page.html")), write_mode())
            .is_ok());
        // Its neighbour is not named.
        assert_eq!(
            fs.open(&bytes(&root.join("other.txt")), write_mode()).err(),
            Some(FsError::denied())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_files_fail_as_fopen_does() {
        let root = scratch("missing");
        let fs = PolicyFs::new(std::slice::from_ref(&root), &[], &[]);
        let e = fs
            .open(&bytes(&root.join("nope")), read_mode())
            .err()
            .expect("fails");
        assert_eq!(
            (e.message.as_str(), e.errno),
            ("No such file or directory", 2)
        );
        let e = fs
            .open(b"/nonexistent-dir-for-nsefs/x", write_mode())
            .err()
            .expect("fails");
        assert_eq!(e.errno, 2);
        let _ = std::fs::remove_dir_all(&root);
    }
}
