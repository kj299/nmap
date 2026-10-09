//! A host for NSE states in tests and examples: libraries and files from a
//! data directory on disk, read-only, and the system clock.
#![allow(dead_code)] // each user takes a different subset

pub mod scenarios;

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Mutex, OnceLock};

use nmap_core::nse::nmapdb::DataFile;
use nmap_core::nse::nmaplib::{Interface, NmapEnv, NmapLib, Phase};
use nmap_core::nse::package::LibrarySource;
use nmap_core::nse::runtime::{new_state, NseState, StateConfig};
use nmap_core::nse::scriptargs::ArgTable;
use nmap_core::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, ScriptFs, Whence};
use nmap_core::nse::stdlib::oslib::OsEnv;
use nmap_core::ports::ServiceTable;

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

/// `dir`'s `nmap-services`, parsed once per directory for the whole test
/// binary: hundreds of states are built from the same one.
fn services(dir: &Path) -> Option<ServiceTable> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Option<ServiceTable>>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache
        .entry(dir.to_path_buf())
        .or_insert_with(|| {
            std::fs::read_to_string(dir.join("nmap-services"))
                .ok()
                .map(|t| ServiceTable::parse(&t))
        })
        .clone()
}

/// A data file from `dir`, as the command line reads one: found, and read
/// as bytes.
pub fn read_data_file(dir: &Path, name: &str) -> DataFile {
    let p = dir.join(name);
    if !p.is_file() {
        return DataFile::NotFound;
    }
    let path = p.to_string_lossy().into_owned().into_bytes();
    match std::fs::read(&p) {
        Ok(bytes) => DataFile::Read { path, bytes },
        Err(e) => {
            // `strerror(errno)` and `errno`, as `gh_perror` prints them.
            let e = fs_err(e);
            DataFile::Unreadable {
                path,
                error: format!("{} ({})", e.message, e.errno).into_bytes(),
            }
        }
    }
}

/// The run's options: defaults, and data files from `dir` — the services
/// table the scan would hold, and `nmapdb`'s files on demand.
pub fn env(dir: PathBuf) -> NmapEnv {
    let services = services(&dir);
    let data = dir.clone();
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
        services,
        phase: Phase::PreScan,
        interfaces: Ok(Vec::<Interface>::new()),
        fetchfile: Box::new(move |f| {
            let p = dir.join(std::str::from_utf8(f).ok()?);
            p.exists()
                .then(|| p.to_string_lossy().into_owned().into_bytes())
        }),
        read_data_file: Box::new(move |name| read_data_file(&data, name)),
        clock: Box::new(|| {
            let d = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            (
                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                i64::from(d.subsec_micros()),
            )
        }),
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
        home: None,
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
        net: std::rc::Rc::new(std::cell::RefCell::new(nmap_core::nse::net::NoNet)),
    })
}

/// `require(lib)`, or `unittest.run_tests({lib})` when `unittest`, in a fresh
/// state over `dir`: the outcome as the oracle probes print it — `ok` or
/// `error`, `pass` or `fail` — and any detail.
pub fn probe(dir: &Path, lib: &str, unittest: bool) -> (String, Option<String>) {
    let (status, detail, _) = probe_modules(dir, lib, unittest);
    (status, detail)
}

/// [`probe`], and the modules no searcher found while it ran, in the order
/// `require` asked for them: a last searcher, which finds nothing, records
/// each name that reaches it. The last of them is the module a load that
/// failed for want of one failed on, whether its `require` was hard (the
/// detail names it) or `stdnse.silent_require` (the detail is a table).
pub fn probe_modules(
    dir: &Path,
    lib: &str,
    unittest: bool,
) -> (String, Option<String>, Vec<String>) {
    use nmap_core::nse::runtime::{run_chunk, ChunkOutcome};
    let mut st = match state(dir) {
        Ok(st) => st,
        Err(e) => return ("error".into(), Some(format!("PRELUDE: {e}")), Vec::new()),
    };
    // A searcher that returns nothing adds nothing to `require`'s message.
    let record = "local nf = {}\n\
                  rawset(_G, 'NMAP_RS_NOT_FOUND', nf)\n\
                  local s = package.searchers\n\
                  s[#s + 1] = function(name) nf[#nf + 1] = name end\n";
    let src = if unittest {
        format!(
            "{record}\
             local u = require 'unittest'\n\
             local fails = u.run_tests({{{lib:?}}})\n\
             local f = fails[{lib:?}]\n\
             if f == nil then return 'pass' end\n\
             return 'fail', tostring(f)"
        )
    } else {
        format!("{record}require({lib:?}) return 'ok'")
    };
    let (status, detail) = match run_chunk(&mut st.lua, "=probe", src.as_bytes(), 2_000_000_000) {
        ChunkOutcome::Returned(v) => {
            let mut v = v.into_iter();
            let status = v.next().unwrap_or_default();
            (status, v.next())
        }
        ChunkOutcome::Raised(e) => ("error".into(), Some(e)),
        ChunkOutcome::OutOfFuel => ("error".into(), Some("OUT OF FUEL".into())),
    };
    let not_found = match run_chunk(
        &mut st.lua,
        "=not_found",
        b"return table.concat(rawget(_G, 'NMAP_RS_NOT_FOUND'), ',')",
        1_000_000,
    ) {
        ChunkOutcome::Returned(v) => v
            .first()
            .map(|s| {
                s.split(',')
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        other => panic!("reading the modules not found: {other:?}"),
    };
    (status, detail, not_found)
}
