//! An in-memory file system for the `io` corpus: the fixture files, readable
//! at `fixtures/io/NAME` as the oracle reads them from `tests/differential/m6/`,
//! and a scratch directory, `/tmp/m64io/`, where a case may create files. A
//! path anywhere else does not exist, as `/nonexistent-dir/` does not for the
//! oracle. Errors are the `strerror` texts and `errno` values glibc gives.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

use nmap_core::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, ScriptFs, Whence};

const SCRATCH: &[u8] = b"/tmp/m64io/";

type Data = Rc<RefCell<Vec<u8>>>;

#[derive(Default)]
pub struct MemFs {
    files: RefCell<HashMap<Vec<u8>, Data>>,
}

fn err(message: &str, errno: i64) -> FsError {
    FsError {
        message: message.into(),
        errno,
    }
}

impl MemFs {
    /// The fixture files, from `dir`, at `fixtures/io/NAME`.
    pub fn with_fixtures(dir: &Path) -> MemFs {
        let fs = MemFs::default();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Ok(data) = std::fs::read(e.path()) {
                    let key = format!("fixtures/io/{name}").into_bytes();
                    fs.files
                        .borrow_mut()
                        .insert(key, Rc::new(RefCell::new(data)));
                }
            }
        }
        fs
    }
}

impl ScriptFs for MemFs {
    fn open(&self, path: &[u8], mode: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
        let existing = self.files.borrow().get(path).cloned();
        let data = match (existing, mode.base) {
            (Some(d), b'w') => {
                d.borrow_mut().clear();
                d
            }
            (Some(d), _) => d,
            (None, b'r') => return Err(err("No such file or directory", 2)),
            (None, _) if path.starts_with(SCRATCH) => {
                let d: Data = Rc::new(RefCell::new(Vec::new()));
                self.files.borrow_mut().insert(path.to_vec(), d.clone());
                d
            }
            (None, _) => return Err(err("No such file or directory", 2)),
        };
        Ok(Box::new(MemFile {
            data,
            pos: 0,
            read: mode.base == b'r' || mode.update,
            write: mode.writes(),
            append: mode.base == b'a',
        }))
    }

    fn stdout(&self) -> Box<dyn ScriptFile> {
        Box::new(MemFile {
            data: Rc::new(RefCell::new(Vec::new())),
            pos: 0,
            read: false,
            write: true,
            append: true,
        })
    }
}

struct MemFile {
    data: Data,
    pos: usize,
    read: bool,
    write: bool,
    append: bool,
}

impl ScriptFile for MemFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, FsError> {
        if !self.read {
            return Err(err("Bad file descriptor", 9));
        }
        let data = self.data.borrow();
        let rest = data.get(self.pos..).unwrap_or(&[]);
        let n = buf.len().min(rest.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.pos = self.pos.saturating_add(n);
        Ok(n)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        if !self.write {
            return Err(err("Bad file descriptor", 9));
        }
        let mut data = self.data.borrow_mut();
        if self.append {
            self.pos = data.len();
        }
        let end = self.pos.saturating_add(bytes.len());
        if data.len() < end {
            data.resize(end, 0);
        }
        data[self.pos..end].copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn seek(&mut self, whence: Whence, offset: i64) -> Result<u64, FsError> {
        let base = match whence {
            Whence::Set => 0,
            Whence::Cur => i64::try_from(self.pos).unwrap_or(i64::MAX),
            Whence::End => i64::try_from(self.data.borrow().len()).unwrap_or(i64::MAX),
        };
        let to = base.checked_add(offset).filter(|&p| p >= 0);
        match to {
            Some(p) => {
                self.pos = usize::try_from(p).unwrap_or(usize::MAX);
                Ok(p.unsigned_abs())
            }
            None => Err(err("Invalid argument", 22)),
        }
    }

    fn flush(&mut self) -> Result<(), FsError> {
        Ok(())
    }
}
