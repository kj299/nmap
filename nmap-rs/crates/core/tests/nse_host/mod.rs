//! A host for NSE states in tests and examples: libraries and files from a
//! data directory on disk, read-only, and the system clock.
#![allow(dead_code)] // each user takes a different subset

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nmap_core::nse::nmaplib::{Interface, NmapEnv, NmapLib, Phase};
use nmap_core::nse::package::LibrarySource;
use nmap_core::nse::runtime::{new_state, NseState, StateConfig};
use nmap_core::nse::scriptargs::ArgTable;
use nmap_core::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, ScriptFs, Whence};
use nmap_core::nse::stdlib::oslib::OsEnv;

/// The repository root: nmap's own data directory, with `nselib/`.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// `nselib/` from a data directory.
pub struct Dir(pub PathBuf);

impl LibrarySource for Dir {
    fn find(&self, file: &[u8]) -> Option<Vec<u8>> {
        let p = self.0.join(std::str::from_utf8(file).ok()?);
        p.is_file()
            .then(|| p.to_string_lossy().into_owned().into_bytes())
    }
    fn read(&self, path: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
        std::fs::read(Path::new(
            std::str::from_utf8(path).map_err(|_| Vec::new())?,
        ))
        .map_err(|e| e.to_string().into_bytes())
    }
}

/// Any file, for reading only; standard output discarded.
pub struct ReadOnlyFs;

struct Disk(std::fs::File);

fn fs_err(e: std::io::Error) -> FsError {
    let text = e.to_string();
    let message = match text.rfind(" (os error ") {
        Some(i) => text[..i].to_string(),
        None => text,
    };
    FsError {
        message,
        errno: i64::from(e.raw_os_error().unwrap_or(0)),
    }
}

impl ScriptFile for Disk {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FsError> {
        self.0.read(buf).map_err(fs_err)
    }
    fn write(&mut self, _: &[u8]) -> Result<(), FsError> {
        Err(FsError::denied())
    }
    fn seek(&mut self, whence: Whence, offset: i64) -> Result<u64, FsError> {
        let pos = match whence {
            Whence::Set => SeekFrom::Start(u64::try_from(offset).unwrap_or(0)),
            Whence::Cur => SeekFrom::Current(offset),
            Whence::End => SeekFrom::End(offset),
        };
        self.0.seek(pos).map_err(fs_err)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        Ok(())
    }
}

struct Discard;

impl ScriptFile for Discard {
    fn read(&mut self, _: &mut [u8]) -> Result<usize, FsError> {
        Ok(0)
    }
    fn write(&mut self, _: &[u8]) -> Result<(), FsError> {
        Ok(())
    }
    fn seek(&mut self, _: Whence, _: i64) -> Result<u64, FsError> {
        Ok(0)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        Ok(())
    }
}

impl ScriptFs for ReadOnlyFs {
    fn open(&self, path: &[u8], mode: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
        if mode.writes() {
            return Err(FsError::denied());
        }
        let path = std::str::from_utf8(path).map_err(|_| FsError::denied())?;
        std::fs::File::open(path)
            .map(|f| Box::new(Disk(f)) as Box<dyn ScriptFile>)
            .map_err(fs_err)
    }
    fn stdout(&self) -> Box<dyn ScriptFile> {
        Box::new(Discard)
    }
}

/// The run's options: defaults, and data files from `dir`.
pub fn env(dir: PathBuf) -> NmapEnv {
    NmapEnv {
        verbose: 0,
        debugging: 0,
        timing_level: 3,
        version_intensity: 7,
        ttl: -1,
        data_length: -1,
        have_ssl: false,
        privileged: false,
        ipv6: false,
        interface: None,
        dns_servers: vec![],
        excluded_ports: None,
        services: None,
        phase: Phase::PreScan,
        interfaces: Ok(Vec::<Interface>::new()),
        fetchfile: Box::new(move |f| {
            let p = dir.join(std::str::from_utf8(f).ok()?);
            p.exists()
                .then(|| p.to_string_lossy().into_owned().into_bytes())
        }),
        clock: Box::new(|| (0, 0)),
        random: Box::new(|_| false),
        log: Box::new(|_, _| {}),
    }
}

/// The system clock, for `os`.
pub fn os_env() -> OsEnv {
    OsEnv {
        now: Box::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        }),
        cpu_seconds: Box::new(|| 0.0),
    }
}

/// A fresh NSE state over `dir`.
pub fn state(dir: &Path) -> Result<NseState, String> {
    new_state(&StateConfig {
        lib: NmapLib::new(env(dir.to_path_buf())),
        args: ArgTable::default(),
        source: Rc::new(Dir(dir.to_path_buf())),
        fs: Rc::new(ReadOnlyFs),
        os: Rc::new(os_env()),
        memory_limit: Some(256 << 20),
        engine: Default::default(),
    })
}

/// `require(lib)`, or `unittest.run_tests({lib})` when `unittest`, in a fresh
/// state over `dir`: the outcome as the oracle probes print it — `ok` or
/// `error`, `pass` or `fail` — and any detail.
pub fn probe(dir: &Path, lib: &str, unittest: bool) -> (String, Option<String>) {
    use nmap_core::nse::runtime::{run_chunk, ChunkOutcome};
    let mut st = match state(dir) {
        Ok(st) => st,
        Err(e) => return ("error".into(), Some(format!("PRELUDE: {e}"))),
    };
    let src = if unittest {
        format!(
            "local u = require 'unittest'\n\
             local fails = u.run_tests({{{lib:?}}})\n\
             local f = fails[{lib:?}]\n\
             if f == nil then return 'pass' end\n\
             return 'fail', tostring(f)"
        )
    } else {
        format!("require({lib:?}) return 'ok'")
    };
    match run_chunk(&mut st.lua, "=probe", src.as_bytes(), 2_000_000_000) {
        ChunkOutcome::Returned(v) => {
            let mut v = v.into_iter();
            let status = v.next().unwrap_or_default();
            (status, v.next())
        }
        ChunkOutcome::Raised(e) => ("error".into(), Some(e)),
        ChunkOutcome::OutOfFuel => ("error".into(), Some("OUT OF FUEL".into())),
    }
}
