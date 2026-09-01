//! The signature-bundle manifest: what a bundle contains, at what version, with
//! what hash — and the downgrade comparison that decides whether an update is
//! allowed to proceed.
//!
//! # Why this is parsed differently from the other database files
//!
//! [`crate::macvendor`], [`crate::osdb::parse`] and [`crate::probedb`] all follow
//! nmap's posture: collect warnings, skip the bad line, keep going. That is right
//! for a 116,000-line database shipped with the tool, where one malformed
//! fingerprint should not cost you the other 6,107.
//!
//! A manifest is the opposite kind of document. It is **signed**, it is small, and
//! it is the thing that decides whether other bytes are trustworthy. A defect in it
//! is never a line to skip: either the whole document is exactly what the signer
//! produced, or it is rejected. So this parser is **fail-closed** — one error type,
//! no warning list, no partial results.
//!
//! # Format
//!
//! Line-based `key = value`, deliberately with no serialization dependency: `core`
//! carries two crates today and the trusted surface of the code that gates
//! signature verification is the last place to grow it. Comments start with `#`.
//! Blank lines are ignored. A `file` key opens a record; the keys after it attach
//! to that record until the next `file` or end of input.
//!
//! ```text
//! # nmap-rs signature bundle
//! schema = 1
//! serial = 41
//! released = 2026-08-31
//! source = https://example.invalid/nmap-rs/signatures
//!
//! file = nmap-os-db
//! version = 41
//! sha256 = 3b1f...64 lowercase hex...
//! size = 5368132
//! ```
//!
//! # Why the version is a serial and not a date
//!
//! The downgrade check needs a **total order that cannot be argued with**. Dates
//! invite timezone and format questions, semver invites precedence rules, and both
//! invite a parser. A `u64` serial that the publisher increments has exactly one
//! ordering, needs no parsing beyond `u64`, and makes "is this a downgrade?" a
//! comparison rather than a policy. `released` is carried alongside as
//! display-only text and is **never** consulted for ordering.
//!
//! Per-file `version` is likewise informational — it lets a report say "os-db
//! unchanged since serial 38" — and the downgrade decision is made on the bundle
//! serial alone. One rule, one comparison, no ambiguity about which field wins.
//!
//! # Why forward compatibility is a schema number and not lenient parsing
//!
//! Unknown keys are an **error**, not something to ignore. In a signed document an
//! unrecognised field may be the signer expressing an intent we would be silently
//! discarding — exactly the shape of a downgrade-by-omission attack. Forward
//! compatibility is instead handled honestly by [`SCHEMA_VERSION`]: a manifest
//! declaring a schema we do not implement is rejected with
//! [`ManifestError::SchemaTooNew`], which tells the operator to update the tool
//! rather than leaving them to guess why a field had no effect.
//!
//! # Path traversal dies here
//!
//! [`FileEntry::name`] is validated at parse time against a strict allowlist, so no
//! downstream consumer can ever be handed `../../etc/passwd`, an absolute path, or
//! a name with a separator or control character in it. Doing this in the parser
//! rather than in the installer means the guarantee holds for *every* consumer,
//! including ones not written yet, instead of resting on each of them remembering.

/// Manifest schema this build implements. A manifest declaring a higher number is
/// rejected outright (see [`ManifestError::SchemaTooNew`]).
pub const SCHEMA_VERSION: u32 = 1;

/// Largest manifest accepted, in bytes. A manifest describes a handful of files;
/// anything approaching this is malformed or hostile. Bounds memory before any
/// allocation proportional to input.
pub const MAX_MANIFEST_LEN: usize = 64 * 1024;

/// Longest single line accepted. Comfortably above a 64-hex-digit hash line.
pub const MAX_LINE_LEN: usize = 1024;

/// Most file records accepted in one bundle.
pub const MAX_FILES: usize = 64;

/// Longest accepted [`FileEntry::name`].
pub const MAX_NAME_LEN: usize = 64;

/// Largest accepted [`FileEntry::size`], 1 GiB. The three real databases total
/// under 10 MB; this is a decompression-bomb ceiling the installer can enforce
/// *before* writing a byte, not a prediction of legitimate growth.
pub const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

/// Everything that can be wrong with a manifest. Each variant carries the 1-based
/// line it was found on where a line is meaningful, so an operator gets a pointer
/// rather than "invalid manifest".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Input exceeded [`MAX_MANIFEST_LEN`].
    TooLarge {
        /// Length of the input that was rejected.
        len: usize,
    },
    /// A line exceeded [`MAX_LINE_LEN`].
    LineTooLong {
        /// 1-based line number.
        line: usize,
        /// Length of the offending line.
        len: usize,
    },
    /// A byte outside printable ASCII (plus tab) appeared. A manifest is an ASCII
    /// document; rejecting the rest avoids every encoding question downstream.
    NonAscii {
        /// 1-based line number.
        line: usize,
        /// The offending byte.
        byte: u8,
    },
    /// A non-comment, non-blank line had no `=`.
    MalformedLine {
        /// 1-based line number.
        line: usize,
    },
    /// A key appeared that this schema does not define.
    UnknownKey {
        /// 1-based line number.
        line: usize,
        /// The key as written.
        key: String,
    },
    /// A key that may appear at most once appeared twice. In a signed document,
    /// last-wins is an ambiguity an attacker chooses the value of.
    DuplicateKey {
        /// 1-based line number of the second occurrence.
        line: usize,
        /// The key as written.
        key: String,
    },
    /// A per-file key appeared before any `file` key opened a record.
    KeyOutsideFileRecord {
        /// 1-based line number.
        line: usize,
        /// The key as written.
        key: String,
    },
    /// A value did not parse as the integer its key requires.
    BadInteger {
        /// 1-based line number.
        line: usize,
        /// The key as written.
        key: String,
    },
    /// `sha256` was not exactly 64 lowercase hex digits. Case is fixed rather than
    /// normalised so that a manifest has exactly one byte representation.
    BadDigest {
        /// 1-based line number.
        line: usize,
    },
    /// A file name failed the allowlist: empty, too long, a leading dot, or a byte
    /// outside `[A-Za-z0-9._-]` (which is what excludes `/`, `\` and `..`).
    BadName {
        /// 1-based line number.
        line: usize,
        /// The name as written, with non-printable bytes escaped.
        name: String,
    },
    /// Two file records shared a name.
    DuplicateFile {
        /// 1-based line number of the second occurrence.
        line: usize,
        /// The repeated name.
        name: String,
    },
    /// `size` exceeded [`MAX_FILE_SIZE`].
    FileTooLarge {
        /// 1-based line number.
        line: usize,
        /// The declared size.
        size: u64,
    },
    /// More than [`MAX_FILES`] file records.
    TooManyFiles {
        /// 1-based line number of the record that went over.
        line: usize,
    },
    /// A file record was missing one of `version`, `sha256` or `size`.
    IncompleteFile {
        /// The record's name.
        name: String,
        /// Which key was missing.
        missing: &'static str,
    },
    /// A required top-level key was absent.
    MissingKey {
        /// Which key was missing.
        key: &'static str,
    },
    /// The manifest declared no files. A bundle that installs nothing is a
    /// no-op at best and a content-stripping attack at worst.
    NoFiles,
    /// The manifest's `schema` is newer than [`SCHEMA_VERSION`].
    SchemaTooNew {
        /// The schema the manifest declared.
        found: u32,
        /// The newest schema this build implements.
        supported: u32,
    },
}

impl core::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { len } => {
                write!(f, "manifest is {len} bytes, over the {MAX_MANIFEST_LEN} limit")
            }
            Self::LineTooLong { line, len } => {
                write!(f, "line {line}: {len} bytes, over the {MAX_LINE_LEN} limit")
            }
            Self::NonAscii { line, byte } => {
                write!(f, "line {line}: non-ASCII byte {byte:#04x}")
            }
            Self::MalformedLine { line } => write!(f, "line {line}: expected `key = value`"),
            Self::UnknownKey { line, key } => write!(f, "line {line}: unknown key `{key}`"),
            Self::DuplicateKey { line, key } => write!(f, "line {line}: duplicate key `{key}`"),
            Self::KeyOutsideFileRecord { line, key } => {
                write!(f, "line {line}: `{key}` appeared before any `file` key")
            }
            Self::BadInteger { line, key } => {
                write!(f, "line {line}: `{key}` is not a valid integer")
            }
            Self::BadDigest { line } => {
                write!(f, "line {line}: `sha256` must be 64 lowercase hex digits")
            }
            Self::BadName { line, name } => write!(f, "line {line}: unacceptable name `{name}`"),
            Self::DuplicateFile { line, name } => {
                write!(f, "line {line}: `{name}` already appears in this manifest")
            }
            Self::FileTooLarge { line, size } => {
                write!(f, "line {line}: size {size} is over the {MAX_FILE_SIZE} limit")
            }
            Self::TooManyFiles { line } => {
                write!(f, "line {line}: more than {MAX_FILES} files")
            }
            Self::IncompleteFile { name, missing } => {
                write!(f, "file `{name}` is missing `{missing}`")
            }
            Self::MissingKey { key } => write!(f, "manifest is missing `{key}`"),
            Self::NoFiles => write!(f, "manifest declares no files"),
            Self::SchemaTooNew { found, supported } => write!(
                f,
                "manifest schema {found} is newer than this build supports ({supported}); update nmap-rs"
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

/// One database in a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// The database's file name. Guaranteed by [`Manifest::parse`] to be non-empty,
    /// at most [`MAX_NAME_LEN`] bytes, free of path separators and `..`, and not
    /// starting with `.` — so it is safe to join onto a directory.
    pub name: String,
    /// Informational per-file serial. **Not** used for the downgrade decision; see
    /// the module docs.
    pub version: u64,
    /// SHA-256 of the file's bytes.
    pub sha256: [u8; 32],
    /// Declared length in bytes. The installer enforces this *before* writing, so a
    /// bundle cannot expand into more disk than it admits to.
    pub size: u64,
}

/// A parsed, structurally valid manifest.
///
/// "Structurally valid" is all this type asserts. It says nothing about whether the
/// bytes it came from carried a good signature — that is S2's job, and it runs
/// **before** this parser, over the raw bytes. Holding a `Manifest` is never
/// evidence that anything was verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Schema the manifest declared; always `<= SCHEMA_VERSION`.
    pub schema: u32,
    /// The bundle serial. This, and only this, orders bundles.
    pub serial: u64,
    /// Display-only release label. Never consulted for ordering.
    pub released: Option<String>,
    /// Where the publisher says the bundle came from. Informational: the fetcher is
    /// configured out of band, so a manifest cannot redirect it.
    pub source: Option<String>,
    /// The databases in the bundle, in declaration order.
    pub files: Vec<FileEntry>,
}

/// How a candidate bundle's serial relates to the installed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionVerdict {
    /// Candidate is newer. A normal update.
    Newer,
    /// Same serial. Nothing to do.
    Same,
    /// Candidate is **older** than what is installed. A correctly signed bundle can
    /// still be a stale one replayed at you, so this is refused unless the operator
    /// passes an explicit override.
    Older,
}

/// Bytes that may appear in a file name.
fn name_byte_ok(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'
}

/// Render a byte string for an error message without letting control characters
/// reach a terminal.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// Decode exactly 64 lowercase hex digits into 32 bytes.
fn parse_digest(value: &[u8]) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in value.chunks_exact(2).enumerate() {
        let hi = lower_hex_value(pair[0])?;
        let lo = lower_hex_value(pair[1])?;
        // `hi` is 0..=15, so `hi << 4` is 0..=240 and the sum is 0..=255: no
        // overflow, but written with checked ops so the lint holds without a
        // local allow.
        out[i] = hi.checked_mul(16)?.checked_add(lo)?;
    }
    Some(out)
}

/// Value of one lowercase hex digit. Uppercase is deliberately rejected so a
/// manifest has exactly one byte representation.
fn lower_hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// Parse a `u64` from ASCII digits, rejecting anything else (no sign, no
/// whitespace, no underscores, no leading `+`).
fn parse_u64(value: &[u8]) -> Option<u64> {
    if value.is_empty() || value.len() > 20 {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in value {
        let d = (b as char).to_digit(10)?;
        acc = acc.checked_mul(10)?.checked_add(u64::from(d))?;
    }
    Some(acc)
}

/// A file record under construction.
struct PartialFile {
    name: String,
    version: Option<u64>,
    sha256: Option<[u8; 32]>,
    size: Option<u64>,
}

impl PartialFile {
    fn finish(self) -> Result<FileEntry, ManifestError> {
        let missing = |k: &'static str| ManifestError::IncompleteFile {
            name: self.name.clone(),
            missing: k,
        };
        Ok(FileEntry {
            version: self.version.ok_or_else(|| missing("version"))?,
            sha256: self.sha256.ok_or_else(|| missing("sha256"))?,
            size: self.size.ok_or_else(|| missing("size"))?,
            name: self.name,
        })
    }
}

impl Manifest {
    /// Parse a manifest from its raw bytes.
    ///
    /// Input is taken as `&[u8]`, not `&str`, on purpose: this is untrusted input,
    /// and a parser that walks a `&str` by character re-introduces the
    /// mid-codepoint panic class that fuzzing caught in `core::probedb` (kit
    /// LESSONS #12). Bytes are validated as printable ASCII before any of them
    /// become a `String`.
    ///
    /// # Errors
    ///
    /// Returns the first [`ManifestError`] found. There is no partial success and
    /// no warning list: see the module docs for why this parser is fail-closed
    /// where its siblings are lenient.
    pub fn parse(input: &[u8]) -> Result<Self, ManifestError> {
        if input.len() > MAX_MANIFEST_LEN {
            return Err(ManifestError::TooLarge { len: input.len() });
        }

        let mut schema: Option<u32> = None;
        let mut serial: Option<u64> = None;
        let mut released: Option<String> = None;
        let mut source: Option<String> = None;
        let mut files: Vec<PartialFile> = Vec::new();

        for (idx, raw) in input.split(|&b| b == b'\n').enumerate() {
            // 1-based, and saturating so a pathological input cannot wrap the
            // counter into a misleading line number.
            let line = idx.saturating_add(1);

            // Tolerate CRLF: a manifest may well be produced on Windows.
            let raw = match raw.split_last() {
                Some((b'\r', rest)) => rest,
                _ => raw,
            };

            if raw.len() > MAX_LINE_LEN {
                return Err(ManifestError::LineTooLong {
                    line,
                    len: raw.len(),
                });
            }
            if let Some(&byte) = raw
                .iter()
                .find(|&&b| b != b'\t' && !(0x20..0x7f).contains(&b))
            {
                return Err(ManifestError::NonAscii { line, byte });
            }

            let trimmed = trim(raw);
            if trimmed.is_empty() || trimmed.first() == Some(&b'#') {
                continue;
            }

            let eq = trimmed
                .iter()
                .position(|&b| b == b'=')
                .ok_or(ManifestError::MalformedLine { line })?;
            // Both halves are in-bounds slices of `trimmed`, so neither index can
            // panic: `eq < trimmed.len()`.
            let key = trim(&trimmed[..eq]);
            let value = trim(&trimmed[eq.saturating_add(1)..]);
            let key_str = escape(key);

            match key {
                b"schema" => {
                    if schema.is_some() {
                        return Err(ManifestError::DuplicateKey { line, key: key_str });
                    }
                    let n = parse_u64(value)
                        .and_then(|v| u32::try_from(v).ok())
                        .ok_or(ManifestError::BadInteger { line, key: key_str })?;
                    if n > SCHEMA_VERSION {
                        return Err(ManifestError::SchemaTooNew {
                            found: n,
                            supported: SCHEMA_VERSION,
                        });
                    }
                    schema = Some(n);
                }
                b"serial" => {
                    if serial.is_some() {
                        return Err(ManifestError::DuplicateKey { line, key: key_str });
                    }
                    serial = Some(
                        parse_u64(value).ok_or(ManifestError::BadInteger { line, key: key_str })?,
                    );
                }
                b"released" => {
                    if released.is_some() {
                        return Err(ManifestError::DuplicateKey { line, key: key_str });
                    }
                    released = Some(escape(value));
                }
                b"source" => {
                    if source.is_some() {
                        return Err(ManifestError::DuplicateKey { line, key: key_str });
                    }
                    source = Some(escape(value));
                }
                b"file" => {
                    if files.len() >= MAX_FILES {
                        return Err(ManifestError::TooManyFiles { line });
                    }
                    let name = validate_name(value, line)?;
                    if files.iter().any(|f| f.name == name) {
                        return Err(ManifestError::DuplicateFile { line, name });
                    }
                    files.push(PartialFile {
                        name,
                        version: None,
                        sha256: None,
                        size: None,
                    });
                }
                b"version" | b"sha256" | b"size" => {
                    let current = files
                        .last_mut()
                        .ok_or(ManifestError::KeyOutsideFileRecord {
                            line,
                            key: key_str.clone(),
                        })?;
                    match key {
                        b"version" => {
                            if current.version.is_some() {
                                return Err(ManifestError::DuplicateKey { line, key: key_str });
                            }
                            current.version = Some(
                                parse_u64(value)
                                    .ok_or(ManifestError::BadInteger { line, key: key_str })?,
                            );
                        }
                        b"sha256" => {
                            if current.sha256.is_some() {
                                return Err(ManifestError::DuplicateKey { line, key: key_str });
                            }
                            current.sha256 =
                                Some(parse_digest(value).ok_or(ManifestError::BadDigest { line })?);
                        }
                        _ => {
                            if current.size.is_some() {
                                return Err(ManifestError::DuplicateKey { line, key: key_str });
                            }
                            let size = parse_u64(value)
                                .ok_or(ManifestError::BadInteger { line, key: key_str })?;
                            if size > MAX_FILE_SIZE {
                                return Err(ManifestError::FileTooLarge { line, size });
                            }
                            current.size = Some(size);
                        }
                    }
                }
                _ => return Err(ManifestError::UnknownKey { line, key: key_str }),
            }
        }

        let schema = schema.ok_or(ManifestError::MissingKey { key: "schema" })?;
        let serial = serial.ok_or(ManifestError::MissingKey { key: "serial" })?;
        if files.is_empty() {
            return Err(ManifestError::NoFiles);
        }

        let mut entries = Vec::with_capacity(files.len());
        for f in files {
            entries.push(f.finish()?);
        }

        Ok(Self {
            schema,
            serial,
            released,
            source,
            files: entries,
        })
    }

    /// Look up one database by name.
    #[must_use]
    pub fn file(&self, name: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.name == name)
    }

    /// Compare this manifest's serial against the installed one.
    ///
    /// [`VersionVerdict::Older`] means a valid signature is carrying stale content —
    /// a replay, whether malicious or an operator pointing at an old mirror. The
    /// caller refuses it unless explicitly overridden.
    #[must_use]
    pub fn compare_to_installed(&self, installed_serial: u64) -> VersionVerdict {
        match self.serial.cmp(&installed_serial) {
            core::cmp::Ordering::Greater => VersionVerdict::Newer,
            core::cmp::Ordering::Equal => VersionVerdict::Same,
            core::cmp::Ordering::Less => VersionVerdict::Older,
        }
    }
}

/// Trim ASCII spaces and tabs from both ends.
fn trim(mut s: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = s.split_first() {
        if first == b' ' || first == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = s.split_last() {
        if last == b' ' || last == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

/// Windows device names. Opening one of these does not touch the filesystem: a
/// write to `NUL` is silently discarded and a write to `COM1` can block on a serial
/// port. They are reserved with or without an extension and regardless of case, so
/// the check is on the stem, uppercased.
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Enforce the file-name allowlist.
///
/// This is where path traversal is killed, and it is deliberately stricter than
/// "not a traversal", because the name is later joined onto a directory on two
/// operating systems with different ideas about what a name means.
///
/// - `/` and `\` are outside the allowed byte set, so no separator can appear.
/// - A dot at **either** end is rejected. Leading rules out `.`, `..`, `./x` and
///   `.hidden`. Trailing matters for a reason that is easy to miss: the Win32 path
///   layer silently strips trailing dots, so `db`, `db.` and `db..` all name the
///   same file there. The manifest's duplicate-name check compares the declared
///   strings, so without this a bundle could pass that check and still have two
///   records resolve to one file on Windows — the second quietly overwriting the
///   first. (Trailing spaces are stripped by Win32 too; they are already excluded
///   by the byte allowlist.)
/// - `..` anywhere is rejected. `a..b` is a harmless name on both platforms, but no
///   real database is spelled that way, and forbidding the sequence outright makes
///   the traversal guarantee something a reader can check at a glance instead of
///   reconstructing from the interaction of two other rules.
/// - Windows reserved device names are rejected, since "open the installed file"
///   would otherwise be able to reach a device instead of the filesystem.
///
/// A name that survives this is a single ordinary path component, on either
/// platform, by construction rather than by the caller remembering to check.
fn validate_name(value: &[u8], line: usize) -> Result<String, ManifestError> {
    let bad = || ManifestError::BadName {
        line,
        name: escape(value),
    };
    if value.is_empty() || value.len() > MAX_NAME_LEN {
        return Err(bad());
    }
    if value.first() == Some(&b'.') || value.last() == Some(&b'.') {
        return Err(bad());
    }
    if value.windows(2).any(|w| w == b"..") {
        return Err(bad());
    }
    if !value.iter().copied().all(name_byte_ok) {
        return Err(bad());
    }
    let name = escape(value);
    let stem = name.split('.').next().unwrap_or(&name).to_ascii_uppercase();
    if WINDOWS_RESERVED.contains(&stem.as_str()) {
        return Err(bad());
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "3b1f2c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c";
    const D2: &str = "0011223344556677889900aabbccddeeff00112233445566778899aabbccddee";

    fn good() -> String {
        format!(
            "# nmap-rs signature bundle\n\
             schema = 1\n\
             serial = 41\n\
             released = 2026-08-31\n\
             source = https://example.invalid/sig\n\
             \n\
             file = nmap-os-db\n\
             version = 41\n\
             sha256 = {D1}\n\
             size = 5368132\n\
             \n\
             file = nmap-mac-prefixes\n\
             version = 38\n\
             sha256 = {D2}\n\
             size = 1375622\n"
        )
    }

    #[test]
    fn a_well_formed_manifest_parses_to_exactly_the_declared_content() {
        let m = Manifest::parse(good().as_bytes()).expect("should parse");
        assert_eq!(m.schema, 1);
        assert_eq!(m.serial, 41);
        assert_eq!(m.released.as_deref(), Some("2026-08-31"));
        assert_eq!(m.source.as_deref(), Some("https://example.invalid/sig"));
        assert_eq!(m.files.len(), 2);

        let os = m.file("nmap-os-db").expect("os-db present");
        assert_eq!(os.version, 41);
        assert_eq!(os.size, 5_368_132);
        assert_eq!(os.sha256[0], 0x3b);
        assert_eq!(os.sha256[31], 0x2c);

        // Declaration order is preserved: a consumer installing in order gets the
        // publisher's order, not a hash-map shuffle.
        assert_eq!(m.files[0].name, "nmap-os-db");
        assert_eq!(m.files[1].name, "nmap-mac-prefixes");
        assert!(m.file("nmap-service-probes").is_none());
    }

    #[test]
    fn crlf_line_endings_parse_identically_to_lf() {
        let lf = Manifest::parse(good().as_bytes()).expect("lf");
        let crlf = Manifest::parse(good().replace('\n', "\r\n").as_bytes()).expect("crlf");
        assert_eq!(lf, crlf);
    }

    #[test]
    fn comments_blank_lines_and_surrounding_space_are_ignored() {
        let src = format!(
            "\n   \n# leading comment\n  schema   =  1  \n\t# indented comment\nserial=7\n\
             file =  db-one \nversion = 7\nsha256 ={D1}\nsize= 10\n\n"
        );
        let m = Manifest::parse(src.as_bytes()).expect("should parse");
        assert_eq!(m.serial, 7);
        assert_eq!(m.files[0].name, "db-one");
        assert_eq!(m.files[0].size, 10);
    }

    #[test]
    fn a_manifest_with_no_trailing_newline_still_parses() {
        let src = good();
        let m = Manifest::parse(src.trim_end().as_bytes()).expect("should parse");
        assert_eq!(m.files.len(), 2);
    }

    // --- forward compatibility -------------------------------------------------

    #[test]
    fn a_newer_schema_is_refused_with_a_pointer_to_the_fix() {
        let src = good().replace("schema = 1", "schema = 2");
        assert_eq!(
            Manifest::parse(src.as_bytes()),
            Err(ManifestError::SchemaTooNew {
                found: 2,
                supported: SCHEMA_VERSION
            })
        );
    }

    #[test]
    fn an_unknown_key_is_an_error_not_something_to_ignore() {
        // The attack this closes: a signer expresses intent in a field an older
        // build silently drops. Fail closed instead.
        let src = good().replace("serial = 41", "serial = 41\nrevoked = nmap-os-db");
        match Manifest::parse(src.as_bytes()) {
            Err(ManifestError::UnknownKey { key, .. }) => assert_eq!(key, "revoked"),
            other => panic!("expected UnknownKey, got {other:?}"),
        }
    }

    // --- required structure ----------------------------------------------------

    #[test]
    fn schema_and_serial_are_both_required() {
        let no_schema = good().replace("schema = 1\n", "");
        assert_eq!(
            Manifest::parse(no_schema.as_bytes()),
            Err(ManifestError::MissingKey { key: "schema" })
        );
        let no_serial = good().replace("serial = 41\n", "");
        assert_eq!(
            Manifest::parse(no_serial.as_bytes()),
            Err(ManifestError::MissingKey { key: "serial" })
        );
    }

    #[test]
    fn a_manifest_declaring_no_files_is_refused() {
        // A bundle that installs nothing is a content-stripping attack at worst
        // and a no-op at best; neither is worth accepting.
        assert_eq!(
            Manifest::parse(b"schema = 1\nserial = 1\n"),
            Err(ManifestError::NoFiles)
        );
    }

    #[test]
    fn an_incomplete_file_record_names_the_missing_key() {
        for (drop, missing) in [
            ("version = 41\n", "version"),
            (&format!("sha256 = {D1}\n"), "sha256"),
            ("size = 5368132\n", "size"),
        ] {
            let src = good().replacen(drop, "", 1);
            assert_eq!(
                Manifest::parse(src.as_bytes()),
                Err(ManifestError::IncompleteFile {
                    name: "nmap-os-db".to_string(),
                    missing
                }),
                "dropping {drop:?}"
            );
        }
    }

    #[test]
    fn a_per_file_key_before_any_file_record_is_refused() {
        let src = format!("schema = 1\nserial = 1\nsha256 = {D1}\nfile = a\n");
        match Manifest::parse(src.as_bytes()) {
            Err(ManifestError::KeyOutsideFileRecord { key, line }) => {
                assert_eq!(key, "sha256");
                assert_eq!(line, 3);
            }
            other => panic!("expected KeyOutsideFileRecord, got {other:?}"),
        }
    }

    // --- ambiguity is an attack surface ---------------------------------------

    #[test]
    fn a_duplicated_key_is_refused_rather_than_resolved_last_wins() {
        // Last-wins would let whoever controls the tail of a document choose the
        // value, which in a signed file is exactly the wrong default.
        let src = good().replace("serial = 41", "serial = 41\nserial = 99");
        match Manifest::parse(src.as_bytes()) {
            Err(ManifestError::DuplicateKey { key, .. }) => assert_eq!(key, "serial"),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    #[test]
    fn a_duplicated_per_file_key_is_refused() {
        let src = good().replace("version = 41", "version = 41\nversion = 42");
        match Manifest::parse(src.as_bytes()) {
            Err(ManifestError::DuplicateKey { key, .. }) => assert_eq!(key, "version"),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    #[test]
    fn two_records_for_the_same_file_are_refused() {
        // Otherwise a second record could shadow the first's hash.
        let src = good().replace("file = nmap-mac-prefixes", "file = nmap-os-db");
        match Manifest::parse(src.as_bytes()) {
            Err(ManifestError::DuplicateFile { name, .. }) => assert_eq!(name, "nmap-os-db"),
            other => panic!("expected DuplicateFile, got {other:?}"),
        }
    }

    // --- path traversal --------------------------------------------------------

    #[test]
    fn no_name_containing_a_path_can_survive_parsing() {
        // This is the control that means no downstream consumer -- including ones
        // not written yet -- can be handed a traversing name.
        for hostile in [
            "../../etc/passwd",
            "..",
            ".",
            "./x",
            "/etc/passwd",
            "a/b",
            "a\\b",
            "..\\..\\windows\\system32",
            ".hidden",
            "",
            "a b",
            "a:b",
            "a;rm -rf /",
            "~root",
            "%APPDATA%",
        ] {
            let src = format!(
                "schema = 1\nserial = 1\nfile = {hostile}\nversion = 1\nsha256 = {D1}\nsize = 1\n"
            );
            let got = Manifest::parse(src.as_bytes());
            assert!(
                matches!(got, Err(ManifestError::BadName { .. })),
                "name {hostile:?} was not rejected: {got:?}"
            );
        }
    }

    #[test]
    fn a_name_with_a_trailing_dot_is_refused_because_win32_strips_it() {
        // Found by fuzzing, which flagged `nmap-os-..` -- not a traversal as a single
        // component, but the Win32 path layer strips trailing dots, so `db`, `db.` and
        // `db..` all name the SAME file there. The duplicate-name check compares the
        // declared strings, so without this rule a bundle could pass that check and
        // still have its second record silently overwrite the first on Windows.
        for hostile in ["nmap-os-..", "db.", "db..", "a.b.", "x..y"] {
            let src = format!(
                "schema = 1\nserial = 1\nfile = {hostile}\nversion = 1\nsha256 = {D1}\nsize = 1\n"
            );
            let got = Manifest::parse(src.as_bytes());
            assert!(
                matches!(got, Err(ManifestError::BadName { .. })),
                "name {hostile:?} was not rejected: {got:?}"
            );
        }
        // An interior single dot is still a perfectly good name.
        let src =
            format!("schema = 1\nserial = 1\nfile = a.b\nversion = 1\nsha256 = {D1}\nsize = 1\n");
        assert_eq!(
            Manifest::parse(src.as_bytes()).expect("parses").files[0].name,
            "a.b"
        );
    }

    #[test]
    fn windows_reserved_device_names_are_refused() {
        // Writing to `NUL` is silently discarded; opening `COM1` can block on a serial
        // port. Neither is a filesystem operation, so neither should be reachable from
        // a name in a bundle. Reserved with or without an extension, any case.
        for hostile in [
            "NUL", "nul", "CON", "con.txt", "AUX", "com1", "LPT9", "Com3.db",
        ] {
            let src = format!(
                "schema = 1\nserial = 1\nfile = {hostile}\nversion = 1\nsha256 = {D1}\nsize = 1\n"
            );
            let got = Manifest::parse(src.as_bytes());
            assert!(
                matches!(got, Err(ManifestError::BadName { .. })),
                "reserved name {hostile:?} was not rejected: {got:?}"
            );
        }
        // Names that merely start with a reserved stem are fine.
        for ok in ["console", "nulls", "com10", "lpt0"] {
            let src = format!(
                "schema = 1\nserial = 1\nfile = {ok}\nversion = 1\nsha256 = {D1}\nsize = 1\n"
            );
            assert!(
                Manifest::parse(src.as_bytes()).is_ok(),
                "{ok:?} should be accepted"
            );
        }
    }

    #[test]
    fn an_over_long_name_is_refused() {
        let long = "a".repeat(MAX_NAME_LEN.saturating_add(1));
        let src = format!(
            "schema = 1\nserial = 1\nfile = {long}\nversion = 1\nsha256 = {D1}\nsize = 1\n"
        );
        assert!(matches!(
            Manifest::parse(src.as_bytes()),
            Err(ManifestError::BadName { .. })
        ));
        // ...and exactly at the limit is fine, so the bound is off-by-one-proof.
        let at = "a".repeat(MAX_NAME_LEN);
        let src =
            format!("schema = 1\nserial = 1\nfile = {at}\nversion = 1\nsha256 = {D1}\nsize = 1\n");
        assert!(Manifest::parse(src.as_bytes()).is_ok());
    }

    // --- digests ---------------------------------------------------------------

    #[test]
    fn a_digest_must_be_exactly_64_lowercase_hex_digits() {
        for bad in [
            "",
            "3b1f",
            &D1[..63],
            &format!("{D1}0"),
            &D1.to_uppercase(),
            &format!("{}g", &D1[..63]),
            &D1.replace('3', " "),
        ] {
            let src = format!(
                "schema = 1\nserial = 1\nfile = a\nversion = 1\nsha256 = {bad}\nsize = 1\n"
            );
            let got = Manifest::parse(src.as_bytes());
            assert!(
                matches!(got, Err(ManifestError::BadDigest { .. })),
                "digest {bad:?} was not rejected: {got:?}"
            );
        }
    }

    #[test]
    fn digest_bytes_decode_in_order() {
        let src = format!(
            "schema = 1\nserial = 1\nfile = a\nversion = 1\nsha256 = {}\nsize = 1\n",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        );
        let m = Manifest::parse(src.as_bytes()).expect("parses");
        assert_eq!(m.files[0].sha256[0], 0x00);
        assert_eq!(m.files[0].sha256[1], 0x11);
        assert_eq!(m.files[0].sha256[15], 0xff);
        assert_eq!(m.files[0].sha256[31], 0xff);
    }

    // --- integers --------------------------------------------------------------

    #[test]
    fn integer_fields_reject_everything_that_is_not_plain_digits() {
        for bad in [
            "",
            "-1",
            "+1",
            " ",
            "1_000",
            "0x10",
            "1.0",
            "99999999999999999999999",
        ] {
            let src = format!("schema = 1\nserial = {bad}\nfile = a\n");
            let got = Manifest::parse(src.as_bytes());
            assert!(
                matches!(
                    got,
                    Err(ManifestError::BadInteger { .. })
                        | Err(ManifestError::MalformedLine { .. })
                ),
                "serial {bad:?} was not rejected: {got:?}"
            );
        }
    }

    #[test]
    fn a_u64_serial_at_the_maximum_still_parses() {
        let src = format!(
            "schema = 1\nserial = {}\nfile = a\nversion = 1\nsha256 = {D1}\nsize = 1\n",
            u64::MAX
        );
        assert_eq!(
            Manifest::parse(src.as_bytes()).expect("parses").serial,
            u64::MAX
        );
    }

    // --- resource bounds -------------------------------------------------------

    #[test]
    fn a_file_larger_than_the_cap_is_refused_before_anything_is_written() {
        let src = format!(
            "schema = 1\nserial = 1\nfile = a\nversion = 1\nsha256 = {D1}\nsize = {}\n",
            MAX_FILE_SIZE.saturating_add(1)
        );
        assert!(matches!(
            Manifest::parse(src.as_bytes()),
            Err(ManifestError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn more_than_the_file_cap_is_refused() {
        let mut src = String::from("schema = 1\nserial = 1\n");
        for i in 0..=MAX_FILES {
            src.push_str(&format!(
                "file = db{i}\nversion = 1\nsha256 = {D1}\nsize = 1\n"
            ));
        }
        assert!(matches!(
            Manifest::parse(src.as_bytes()),
            Err(ManifestError::TooManyFiles { .. })
        ));
    }

    #[test]
    fn an_over_long_manifest_is_refused_before_it_is_walked() {
        let src = vec![b'#'; MAX_MANIFEST_LEN.saturating_add(1)];
        assert_eq!(
            Manifest::parse(&src),
            Err(ManifestError::TooLarge {
                len: MAX_MANIFEST_LEN.saturating_add(1)
            })
        );
    }

    #[test]
    fn an_over_long_line_is_refused() {
        let src = format!("# {}\nschema = 1\n", "x".repeat(MAX_LINE_LEN));
        assert!(matches!(
            Manifest::parse(src.as_bytes()),
            Err(ManifestError::LineTooLong { .. })
        ));
    }

    // --- encoding --------------------------------------------------------------

    #[test]
    fn a_non_ascii_byte_anywhere_is_refused() {
        // Taking the input as bytes and rejecting non-ASCII up front is what keeps
        // every later step free of encoding questions (kit LESSONS #12).
        for byte in [0x00u8, 0x0b, 0x1b, 0x7f, 0x80, 0xc3, 0xff] {
            let mut src = b"schema = 1\nserial = 1\n".to_vec();
            src.push(byte);
            src.push(b'\n');
            let got = Manifest::parse(&src);
            assert!(
                matches!(got, Err(ManifestError::NonAscii { byte: b, .. }) if b == byte),
                "byte {byte:#04x} was not rejected: {got:?}"
            );
        }
    }

    #[test]
    fn a_line_without_an_equals_sign_is_refused() {
        assert_eq!(
            Manifest::parse(b"schema = 1\nnonsense\n"),
            Err(ManifestError::MalformedLine { line: 2 })
        );
    }

    #[test]
    fn error_text_escapes_control_bytes_rather_than_emitting_them() {
        // An error message reaches a terminal; a name is attacker-influenced.
        let err = ManifestError::BadName {
            line: 1,
            name: escape(b"a\x1b[31mb"),
        };
        let shown = err.to_string();
        assert!(!shown.contains('\x1b'), "escape sequence leaked: {shown:?}");
        assert!(shown.contains("\\x1b"));
    }

    // --- the downgrade decision ------------------------------------------------

    #[test]
    fn the_downgrade_comparison_is_a_total_order_on_the_serial() {
        let m = |serial: u64| Manifest {
            schema: 1,
            serial,
            released: None,
            source: None,
            files: vec![FileEntry {
                name: "a".into(),
                version: 1,
                sha256: [0; 32],
                size: 1,
            }],
        };
        assert_eq!(m(42).compare_to_installed(41), VersionVerdict::Newer);
        assert_eq!(m(41).compare_to_installed(41), VersionVerdict::Same);
        assert_eq!(m(40).compare_to_installed(41), VersionVerdict::Older);
        // The boundaries, where an off-by-one would silently permit a rollback.
        assert_eq!(m(0).compare_to_installed(0), VersionVerdict::Same);
        assert_eq!(m(0).compare_to_installed(1), VersionVerdict::Older);
        assert_eq!(m(u64::MAX).compare_to_installed(0), VersionVerdict::Newer);
        assert_eq!(
            m(u64::MAX.saturating_sub(1)).compare_to_installed(u64::MAX),
            VersionVerdict::Older
        );
    }

    #[test]
    fn a_valid_signature_over_an_old_serial_still_reads_as_a_downgrade() {
        // The whole point: signature validity and freshness are separate questions.
        let old = Manifest::parse(good().replace("serial = 41", "serial = 3").as_bytes())
            .expect("parses");
        assert_eq!(old.compare_to_installed(41), VersionVerdict::Older);
    }

    #[test]
    fn the_per_file_version_does_not_affect_the_downgrade_decision() {
        // Per-file versions are informational; only the bundle serial orders.
        let src = good().replace("version = 41", "version = 9999");
        let m = Manifest::parse(src.as_bytes()).expect("parses");
        assert_eq!(m.file("nmap-os-db").expect("present").version, 9999);
        assert_eq!(m.compare_to_installed(41), VersionVerdict::Same);
    }

    // --- robustness ------------------------------------------------------------

    /// Stride for the two exhaustive sweeps below.
    ///
    /// Miri interprets every operation, so sweeping ~2,700 parses costs it roughly
    /// fourteen minutes — which lands on the Miri job, already the critical path of
    /// CI. Under Miri these sweeps are asking "is this path free of UB?", and a
    /// sample answers that as well as an exhaustive walk; the question they answer
    /// exhaustively, "does any offset panic?", is answered by the normal test run
    /// (stride 1) and by the `sigstore_manifest` fuzz target at millions of runs.
    /// A prime stride so the sampled offsets do not align with the document's own
    /// line structure.
    #[cfg(miri)]
    const SWEEP_STRIDE: usize = 37;
    #[cfg(not(miri))]
    const SWEEP_STRIDE: usize = 1;

    #[test]
    fn parsing_never_panics_on_truncations_of_a_valid_manifest() {
        // Every prefix of a good document, which is what a cut-off download looks
        // like. Fuzzing covers the general case; this pins the specific one.
        let src = good();
        let bytes = src.as_bytes();
        for n in (0..=bytes.len()).step_by(SWEEP_STRIDE) {
            let _ = Manifest::parse(&bytes[..n]);
        }
        // The boundaries always run, whatever the stride: empty input and the
        // complete document are the two prefixes most worth pinning.
        assert!(Manifest::parse(b"").is_err());
        assert!(Manifest::parse(bytes).is_ok());
    }

    #[test]
    fn parsing_never_panics_on_single_byte_corruptions() {
        let src = good().into_bytes();
        for i in (0..src.len()).step_by(SWEEP_STRIDE) {
            for byte in [0u8, b'=', b'#', b'\n', b'\r', b'\t', b' ', 0xff] {
                let mut m = src.clone();
                m[i] = byte;
                let _ = Manifest::parse(&m);
            }
        }
    }
}
