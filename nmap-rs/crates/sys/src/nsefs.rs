//! The files NSE scripts open: [`ScriptFs`] over the real file system,
//! behind [`FsPolicy`] (Decision 2, `docs/M6-ANALYSIS.md`).
//!
//! A path is resolved as `fopen` would resolve it — relative to the working
//! directory — then canonicalised: a file that exists to itself, one that
//! does not yet to its canonical directory and its name ([`resolve`]). The
//! policy decides on that, and the canonical path is what is opened, so a
//! symbolic link cannot lead a check one way and an open another. A name that
//! is a symbolic link leading nowhere is not written through: `fopen` would
//! create the link's target, wherever it is (`nse-write-through-dangling-link`).
//! And the final name is opened without following a link (`O_NOFOLLOW`), so
//! one swapped in after the check is refused too. (A script cannot make a
//! link: nothing a script is given creates one.)

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use nmap_core::nse::fspolicy::FsPolicy;
use nmap_core::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, ScriptFs, Whence};

/// The real file system, behind a policy.
pub struct PolicyFs {
    policy: FsPolicy,
}

impl PolicyFs {
    /// `data_dirs` readable, `output_dirs` readable and writable, with
    /// directories creatable beneath them, and each of `named` that is a
    /// file — or could be one, in an existing directory — readable and
    /// writable. A data or output directory that does not exist, or is not a
    /// directory, is dropped.
    pub fn new(data_dirs: &[PathBuf], output_dirs: &[PathBuf], named: &[Vec<u8>]) -> PolicyFs {
        let dirs = |ds: &[PathBuf]| -> Vec<PathBuf> {
            ds.iter()
                .filter_map(|d| d.canonicalize().ok())
                .filter(|d| d.is_dir())
                .collect()
        };
        let named = named
            .iter()
            .filter_map(|n| match resolve(n) {
                Ok(Target::Exists(p)) => Some(p),
                Ok(Target::New {
                    path,
                    dangling: false,
                    trailing: false,
                }) => Some(path),
                _ => None,
            })
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

/// The directories the operator designated for script output: the values
/// of the arguments `fspolicy::OUTPUT_DIR_ARGS` names, as paths.
pub fn output_dirs(values: &[Vec<u8>]) -> Vec<PathBuf> {
    values.iter().filter_map(|v| path_of(v)).collect()
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

/// What a path names, for the policy.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// It exists: its canonical path.
    Exists(PathBuf),
    /// It does not, and its directory does: that directory, canonical, and
    /// the name. `dangling` when something is there all the same, a symbolic
    /// link that leads nowhere; `trailing` when the path ended in a
    /// separator.
    New {
        path: PathBuf,
        dangling: bool,
        trailing: bool,
    },
}

impl Target {
    /// The path the policy decides on.
    fn path(&self) -> &std::path::Path {
        match self {
            Target::Exists(p) | Target::New { path: p, .. } => p,
        }
    }
}

/// The path's last component, trailing separators aside.
fn last_component(bytes: &[u8]) -> &[u8] {
    let sep = |b: &u8| *b == b'/' || (cfg!(windows) && *b == b'\\');
    let mut trimmed = bytes;
    while let Some((last, rest)) = trimmed.split_last() {
        if !sep(last) {
            break;
        }
        trimmed = rest;
    }
    trimmed.rsplit(sep).next().unwrap_or(trimmed)
}

/// Whether `bytes`, as a C string, ends in a separator.
fn ends_in_separator(bytes: &[u8]) -> bool {
    let raw = bytes.split(|&b| b == 0).next().unwrap_or(&[]);
    !raw.is_empty() && !raw.ends_with(last_component(raw))
}

fn os_error(errno: i32) -> FsError {
    fs_error(&std::io::Error::from_raw_os_error(errno))
}

fn no_such_file() -> FsError {
    FsError {
        message: "No such file or directory".into(),
        errno: 2,
    }
}

/// `bytes` resolved as `open(2)` and `mkdir(2)` resolve a path, or the error
/// they give before touching the last name:
/// - empty, as a C string: `ENOENT`;
/// - `PATH_MAX` bytes or more: `ENAMETOOLONG`, before any lookup;
/// - a path that exists: its canonical form;
/// - one that does not, whose last component is a name (not `.` or `..`):
///   its directory's canonical form and the name, or the directory's own
///   error;
/// - otherwise the lookup's error: `ENOTDIR`, `ELOOP`, `ENAMETOOLONG`,
///   `ENOENT` (`x/.` with `x` missing).
fn resolve(bytes: &[u8]) -> Result<Target, FsError> {
    let raw = bytes.split(|&b| b == 0).next().unwrap_or(&[]);
    let path = path_of(raw).ok_or_else(no_such_file)?;
    #[cfg(unix)]
    if raw.len() >= usize::try_from(libc::PATH_MAX).unwrap_or(usize::MAX) {
        return Err(os_error(libc::ENAMETOOLONG));
    }
    let err = match path.canonicalize() {
        Ok(c) => return Ok(Target::Exists(c)),
        Err(e) => e,
    };
    let last = last_component(raw);
    if err.kind() != std::io::ErrorKind::NotFound
        || last.is_empty()
        || last == b"."
        || last == b".."
    {
        return Err(fs_error(&err));
    }
    let name = path.file_name().ok_or_else(no_such_file)?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let path = parent.canonicalize().map_err(|e| fs_error(&e))?.join(name);
    let dangling = std::fs::symlink_metadata(&path).is_ok();
    let trailing = ends_in_separator(raw);
    Ok(Target::New {
        path,
        dangling,
        trailing,
    })
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
    /// `fopen(path, mode)` on the canonical path, if the policy allows it.
    /// What does not resolve fails as `fopen` fails, whether or not the
    /// script may look ([`resolve`]). Beyond `fopen`: a name that is a
    /// symbolic link leading nowhere is refused for writing (`EACCES`), and
    /// is missing for reading, where `fopen` would create or miss the link's
    /// target; and the final name is opened with `O_NOFOLLOW`.
    fn open(&self, path: &[u8], mode: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
        let writes = mode.writes();
        // `open(path, O_CREAT)` with a trailing separator is `EISDIR`,
        // before any lookup, whatever is there.
        if mode.base != b'r' && ends_in_separator(path) {
            return Err(os_error(21)); // EISDIR
        }
        let resolved = resolve(path)?;
        if !self.policy.allows(resolved.path(), writes) {
            return Err(FsError::denied());
        }
        let target = match resolved {
            Target::Exists(p) => p,
            // Without `O_CREAT` (above), there is nothing there.
            Target::New { trailing: true, .. } => return Err(no_such_file()),
            Target::New { dangling: true, .. } if writes => return Err(FsError::denied()),
            Target::New { dangling: true, .. } => return Err(no_such_file()),
            Target::New { path, .. } => path,
        };
        let mut o = OpenOptions::new();
        match mode.base {
            b'r' => o.read(true).write(mode.update),
            b'w' => o.write(true).create(true).truncate(true).read(mode.update),
            _ => o.append(true).create(true).read(mode.update),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.custom_flags(libc::O_NOFOLLOW);
        }
        let file = o.open(&target).map_err(|e| {
            // A link swapped in at the final name since the check.
            #[cfg(unix)]
            if e.raw_os_error() == Some(libc::ELOOP) {
                return if writes {
                    FsError::denied()
                } else {
                    no_such_file()
                };
            }
            fs_error(&e)
        })?;
        Ok(Box::new(DiskFile(file)))
    }

    fn stdout(&self) -> Box<dyn ScriptFile> {
        Box::new(Stdout)
    }

    /// `mkdir(path, 0775)` (`nse_fs.cc:121`), on the canonical path, if it
    /// is beneath a designated output directory. What does not resolve
    /// fails as `mkdir` fails, whether or not the script may look
    /// ([`resolve`]: a missing parent is `ENOENT`, `f/x` on a file
    /// `ENOTDIR`, a loop `ELOOP`); a path that exists, a directory, a file
    /// or a link leading nowhere (`mkdir` does not follow it), is `EEXIST`
    /// where the script may write, and `EACCES` elsewhere.
    fn mkdir(&self, path: &[u8]) -> Result<(), FsError> {
        let resolved = resolve(path)?;
        let target = resolved.path();
        if !self.policy.allows_mkdir(target) {
            return Err(FsError::denied());
        }
        #[cfg(unix)]
        let b = {
            use std::os::unix::fs::DirBuilderExt;
            let mut b = std::fs::DirBuilder::new();
            b.mode(0o775);
            b
        };
        #[cfg(not(unix))]
        let b = std::fs::DirBuilder::new();
        b.create(target).map_err(|e| fs_error(&e))
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
    use std::path::Path;

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
    fn directories_are_made_beneath_output_dirs_only() {
        let root = scratch("mkdir");
        let out = root.join("loot");
        let data = root.join("data");
        std::fs::create_dir_all(&out).expect("mkdir");
        std::fs::create_dir_all(&data).expect("mkdir");
        let named = root.join("named.txt");
        let fs = PolicyFs::new(
            std::slice::from_ref(&data),
            std::slice::from_ref(&out),
            &[bytes(&named)],
        );
        // Beneath the output directory, with a trailing separator as
        // http-fetch writes it, and C's mode before the umask.
        assert_eq!(fs.mkdir(&bytes(&out.join("10.0.0.1/"))), Ok(()));
        assert!(out.join("10.0.0.1").is_dir());
        #[cfg(unix)]
        {
            // 0775 under the process's umask, which a directory made 0777
            // shows. (Under a umask with 002 set, 0775 and 0777 agree.)
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let mode = |p: &Path| std::fs::metadata(p).expect("made").permissions().mode() & 0o777;
            std::fs::DirBuilder::new()
                .mode(0o777)
                .create(root.join("umask"))
                .expect("mkdir");
            let allowed = mode(&root.join("umask"));
            assert_eq!(mode(&out.join("10.0.0.1")), 0o775 & allowed);
        }
        let e = fs.mkdir(&bytes(&out.join("10.0.0.1"))).expect_err("exists");
        assert_eq!((e.message.as_str(), e.errno), ("File exists", 17));
        let e = fs.mkdir(&bytes(&out.join("a/b"))).expect_err("no parent");
        assert_eq!(
            (e.message.as_str(), e.errno),
            ("No such file or directory", 2)
        );
        std::fs::write(out.join("f"), b"x").expect("write");
        let e = fs.mkdir(&bytes(&out.join("f/g"))).expect_err("not a dir");
        assert_eq!((e.message.as_str(), e.errno), ("Not a directory", 20));
        // Nowhere else: beside it, in a data directory, where a file is named,
        // or out by `..`.
        for p in [
            root.join("beside"),
            data.join("x"),
            named.clone(),
            out.join("10.0.0.1/../../escaped"),
        ] {
            assert_eq!(
                fs.mkdir(&bytes(&p)),
                Err(FsError::denied()),
                "{}",
                p.display()
            );
            assert!(!p.exists(), "{} was made", p.display());
        }
        // An existing path outside: refused, not reported as existing.
        assert_eq!(fs.mkdir(&bytes(&data)), Err(FsError::denied()));
        assert_eq!(
            fs.mkdir(b"").map_err(|e| e.errno),
            Err(2),
            "mkdir(\"\") is ENOENT"
        );
        // Out by a symbolic link planted beneath the output directory.
        #[cfg(unix)]
        {
            let elsewhere = root.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).expect("mkdir");
            std::os::unix::fs::symlink(&elsewhere, out.join("link")).expect("symlink");
            assert_eq!(
                fs.mkdir(&bytes(&out.join("link/x"))),
                Err(FsError::denied())
            );
            assert!(!elsewhere.join("x").exists());
            // A dangling link is not followed: it exists.
            std::os::unix::fs::symlink(root.join("nowhere"), out.join("dangling"))
                .expect("symlink");
            let e = fs.mkdir(&bytes(&out.join("dangling"))).expect_err("exists");
            assert_eq!(e.errno, 17);
            assert!(!root.join("nowhere").exists());
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The review's B1: a name beneath a writable root that is a link
    /// leading nowhere. `fopen` would create the link's target, wherever it
    /// is; here a write is refused, a read finds nothing, and `mkdir` does
    /// not follow it.
    #[cfg(unix)]
    #[test]
    fn a_dangling_link_is_not_written_through() {
        let root = scratch("dangling");
        let out = root.join("loot");
        let victim = root.join("victim");
        std::fs::create_dir_all(&out).expect("mkdir");
        std::fs::create_dir_all(&victim).expect("mkdir");
        let link = out.join("index.html");
        std::os::unix::fs::symlink(victim.join("authorized_keys"), &link).expect("symlink");
        // A named file that is a dangling link, too.
        let named = root.join("named.txt");
        std::os::unix::fs::symlink(victim.join("named-target"), &named).expect("symlink");
        let fs = PolicyFs::new(&[], std::slice::from_ref(&out), &[bytes(&named)]);
        for mode in [&b"w"[..], b"a", b"w+", b"a+", b"r+"] {
            let mode = OpenMode::parse(mode).expect("valid");
            for p in [&link, &named] {
                assert_eq!(
                    fs.open(&bytes(p), mode).err(),
                    Some(FsError::denied()),
                    "{} {:?}",
                    p.display(),
                    mode
                );
            }
        }
        let e = fs
            .open(&bytes(&link), read_mode())
            .err()
            .expect("nothing to read");
        assert_eq!(e.errno, 2);
        let e = fs.mkdir(&bytes(&link)).expect_err("exists");
        assert_eq!(e.errno, 17);
        assert_eq!(
            std::fs::read_dir(&victim).expect("dir").count(),
            0,
            "written through"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The review's S7: what `open(2)` and `mkdir(2)` do with a trailing
    /// `.` or separator, a file in the middle of a path, a loop and a path
    /// too long, which canonicalising alone would have changed.
    #[cfg(unix)]
    #[test]
    fn paths_resolve_as_the_system_calls_resolve_them() {
        let root = scratch("resolve");
        let out = root.join("loot");
        std::fs::create_dir_all(out.join("a")).expect("mkdir");
        std::fs::write(out.join("f"), b"keep").expect("write");
        std::os::unix::fs::symlink(out.join("loop"), out.join("loop")).expect("symlink");
        let fs = PolicyFs::new(&[], std::slice::from_ref(&out), &[]);
        let errno = |r: Result<(), FsError>| r.err().map(|e| e.errno);
        let open_errno = |p: &str, m: &[u8]| {
            fs.open(&bytes(&out.join(p)), OpenMode::parse(m).expect("valid"))
                .err()
                .map(|e| e.errno)
        };
        let mk = |p: &str| errno(fs.mkdir(&bytes(&out.join(p))));
        assert_eq!(mk("nx/."), Some(2), "mkdir nx/. with nx missing");
        assert!(!out.join("nx").exists());
        assert_eq!(mk("f/."), Some(20), "mkdir f/. on a file");
        assert_eq!(mk("a/."), Some(17), "mkdir a/. on a directory");
        assert_eq!(mk("f/x"), Some(20), "mkdir beneath a file");
        assert_eq!(mk("loop/x"), Some(40), "mkdir through a loop");
        assert_eq!(open_errno("q/.", b"w"), Some(2));
        assert!(!out.join("q").exists(), "q/. created q");
        assert_eq!(open_errno("f/.", b"w"), Some(20));
        assert_eq!(open_errno("f/", b"w"), Some(21), "fopen file/ w");
        assert_eq!(open_errno("f/", b"r"), Some(20), "fopen file/ r");
        assert_eq!(open_errno("f/", b"r+"), Some(20), "fopen file/ r+");
        assert_eq!(
            std::fs::read(out.join("f")).expect("read"),
            b"keep",
            "f truncated"
        );
        assert_eq!(open_errno("new/", b"w"), Some(21), "fopen new/ w");
        assert_eq!(open_errno("new/", b"r"), Some(2), "fopen new/ r");
        assert_eq!(open_errno("new/", b"a"), Some(21), "fopen new/ a");
        assert!(!out.join("new").exists());
        assert_eq!(open_errno("a/", b"w"), Some(21), "fopen dir/ w");
        assert_eq!(open_errno("loop/x", b"w"), Some(40));
        // PATH_MAX bytes or more, though they canonicalise short.
        let long = format!("{}/{}z", out.display(), "../loot/".repeat(600));
        assert!(long.len() >= 4096);
        assert_eq!(errno(fs.mkdir(long.as_bytes())), Some(36));
        assert!(!out.join("z").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn output_dirs_must_exist_and_be_directories() {
        let root = scratch("outdirs");
        let file = root.join("file");
        std::fs::write(&file, b"x").expect("write");
        let fs = PolicyFs::new(&[], &[root.join("absent"), file.clone()], &[]);
        assert!(fs.policy().write_roots.is_empty());
        assert_eq!(
            output_dirs(&[b"/a\0b".to_vec(), Vec::new()]),
            vec![PathBuf::from("/a")]
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
