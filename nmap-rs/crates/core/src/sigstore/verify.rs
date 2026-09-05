//! Ed25519 verification of a signature bundle's manifest, in the minisign
//! container format.
//!
//! This is the trust anchor of the whole update path. Everything downstream —
//! [`super::manifest::Manifest`]'s downgrade check, [`super::digest::Sha256`]'s
//! per-file hashes, the installer in `sys::sigstore` — is only as good as the
//! signature checked here. So this module holds no policy, touches no
//! filesystem, reads no clock, and takes its trusted keys as an argument.
//!
//! # Why minisign's container and not a new one
//!
//! The bytes on the wire are an ordinary [minisign] `.minisig` file. That buys
//! three things a bespoke format would not: a publisher can sign with a tool they
//! already audit rather than one this project ships, an operator can cross-check a
//! bundle with a second implementation, and the format has been reviewed by people
//! who are not us. It is four lines of ASCII, which is also about as small as a
//! parser in the trusted path can be.
//!
//! ```text
//! untrusted comment: signature from nmap-rs signing key
//! RUQAAAAAAAAAAO/eG...                     <- "Ed" | key id[8] | signature[64]
//! trusted comment: nmap-rs-sig:1<TAB>serial:41
//! Uk9nZ2xl...                              <- global signature[64]
//! ```
//!
//! [minisign]: https://jedisct1.github.io/minisign/
//!
//! # What each signature actually covers
//!
//! Line 2 signs the manifest bytes. Line 4 — minisign's *global signature* — signs
//! `signature[64] || trusted_comment`, and nothing else: not the prefix, not the
//! newline, not the algorithm bytes, not the key id. Both are checked, and both
//! must succeed **under the same key**.
//!
//! Line 1 is signed by nothing, in any mode, ever. It is therefore parsed only far
//! enough to confirm the prefix and then discarded — never stored, never returned,
//! never logged. An attacker-chosen string arriving at an operator's terminal next
//! to the word "verified" is a phishing primitive, not a comment.
//!
//! # What the key id is not
//!
//! The 8-byte key id is unauthenticated: no signature covers it, so an attacker
//! rewrites it for free. Here it only *orders* verification attempts; it never
//! removes a key from consideration and never short-circuits. Stock minisign exits
//! on a key-id mismatch before trying anything, which with a multi-key ring would
//! hand an attacker a choice of which key you are allowed to attempt. A matching
//! key id is evidence of nothing, and no code path here may treat it otherwise.
//!
//! # Redundancy, stated honestly
//!
//! The trusted comment repeats the manifest's `serial`, and this module
//! cross-checks the two. That check cannot catch an attacker: the manifest is
//! inside the signed bytes, so a forged serial fails the signature first. What it
//! catches is a **publisher-tooling bug** that signs an envelope disagreeing with
//! the manifest it accompanies, and it fails closed when it does. The claim is
//! deliberately no larger than that.
//!
//! What the global signature *does* buy is the extension point: because the
//! trusted comment is signed as a unit, a future `nmap-rs-sig:2` carrying a
//! transparency-log inclusion proof cannot be stripped back to a v1 envelope. That
//! is why line 4 is required rather than optional — an implementation that treats
//! lines 3 and 4 as optional silently degrades to OpenBSD `signify` semantics,
//! which have neither.
//!
//! # Verification is the only way to get a parsed manifest
//!
//! [`super::manifest::Manifest`]'s own documentation warns that holding one is
//! never evidence that anything was verified. [`VerifiedManifest`] turns that
//! warning into a type: it has exactly one constructor, [`verify_manifest`], and
//! the update path accepts nothing else. Parsing happens *after* both signatures
//! pass, so a malformed manifest is never parsed on an attacker's say-so.
//!
//! # Nothing here is secret
//!
//! Every byte this module handles is public: a public key, a public signature, a
//! public manifest. There is deliberately no constant-time comparison and no
//! `subtle`-style masking. Dressing public data as secret would obscure where the
//! real secrets are — and in this crate there are none.

use ed25519_dalek::{Signature, VerifyingKey};

use super::manifest::{escape, parse_u64, Manifest, ManifestError, MAX_LINE_LEN, MAX_MANIFEST_LEN};

/// Largest `.minisig` accepted, in bytes. A real one is 321 bytes; this is a
/// ceiling checked before anything else, not a prediction.
pub const MAX_SIG_LEN: usize = 4 * 1024;

/// Longest trusted comment accepted. Stock minisign allows 8192; the envelope
/// grammar below has no legitimate use for more than a few dozen bytes.
pub const MAX_TRUSTED_COMMENT_LEN: usize = 256;

/// Most keys a [`KeyRing`] may hold. Enough for a rotation window plus slack.
pub const MAX_TRUSTED_KEYS: usize = 4;

/// Envelope grammar version this build implements, carried in the trusted comment
/// as `nmap-rs-sig:<n>`. Deliberately independent of the manifest's
/// [`super::manifest::SCHEMA_VERSION`]: one versions the signed *content*, this
/// one versions the signed *envelope*.
pub const ENVELOPE_VERSION: u32 = 1;

/// Bytes in an Ed25519 public key.
const PUBLIC_KEY_LEN: usize = 32;

/// Bytes in an Ed25519 signature.
const SIGNATURE_LEN: usize = 64;

/// Bytes in a minisign key id.
const KEY_ID_LEN: usize = 8;

/// Decoded length of a minisign public-key blob: `alg[2] || key_id[8] || key[32]`.
const PUBKEY_BLOB_LEN: usize = 42;

/// Decoded length of a minisign signature blob: `alg[2] || key_id[8] || sig[64]`.
const SIG_BLOB_LEN: usize = 74;

/// Base64 length of a public-key line. Exact, not a maximum.
const PK_LINE_LEN: usize = 56;

/// Base64 length of the signature line. Exact, not a maximum.
const SIG_LINE_LEN: usize = 100;

/// Base64 length of the global-signature line. Exact, not a maximum.
const GLOBAL_SIG_LINE_LEN: usize = 88;

/// Prefix required on line 1 of a `.minisig`.
const UNTRUSTED_PREFIX: &[u8] = b"untrusted comment: ";

/// Prefix required on line 3 of a `.minisig`.
const TRUSTED_PREFIX: &[u8] = b"trusted comment: ";

/// Algorithm bytes for pure Ed25519 — the only mode accepted.
const ALG_PURE: [u8; 2] = *b"Ed";

/// Algorithm bytes for minisign's prehashed mode, named in errors so an operator
/// handed one is told exactly which mode was refused rather than left guessing.
const ALG_PREHASHED: [u8; 2] = *b"ED";

/// Scratch buffer for the global signature's message, `sig[64] || comment`.
const GLOBAL_MSG_MAX: usize = SIGNATURE_LEN + MAX_TRUSTED_COMMENT_LEN;

/// The Curve25519 field prime `2^255 - 19`, little-endian, for the canonical
/// public-key encoding check.
const FIELD_PRIME_LE: [u8; PUBLIC_KEY_LEN] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Everything that can be wrong with a signature, a key, or the envelope.
///
/// Flat, one variant per distinguishable condition, with no warning list and no
/// partial success — the same fail-closed shape as
/// [`super::manifest::ManifestError`], for the same reason: this document decides
/// whether other bytes are trustworthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Signature file exceeded [`MAX_SIG_LEN`].
    TooLarge {
        /// Length of the input that was rejected.
        len: usize,
    },
    /// A `.minisig` is exactly four lines. This was not.
    LineCount {
        /// Number of lines found.
        found: usize,
    },
    /// A line exceeded [`MAX_LINE_LEN`].
    LineTooLong {
        /// 1-based line number.
        line: usize,
        /// Length of the offending line.
        len: usize,
    },
    /// A byte outside printable ASCII (plus tab) appeared.
    NonAscii {
        /// 1-based line number.
        line: usize,
        /// The offending byte.
        byte: u8,
    },
    /// A carriage return appeared somewhere other than immediately before a
    /// newline.
    BadEol {
        /// 1-based line number.
        line: usize,
    },
    /// Line 1 did not begin `untrusted comment: `.
    MissingUntrustedPrefix,
    /// Line 3 did not begin `trusted comment: `.
    MissingTrustedPrefix,
    /// Line 2 was not exactly [`SIG_LINE_LEN`] base64 characters.
    BadSigLine {
        /// Length found.
        len: usize,
    },
    /// Line 4 was not exactly [`GLOBAL_SIG_LINE_LEN`] base64 characters.
    BadGlobalSigLine {
        /// Length found.
        len: usize,
    },
    /// A base64 line was not canonically encoded.
    BadBase64 {
        /// 1-based line number.
        line: usize,
    },
    /// The two algorithm bytes were not `Ed`.
    UnsupportedAlgorithm {
        /// The bytes found.
        found: [u8; 2],
    },
    /// The trusted comment exceeded [`MAX_TRUSTED_COMMENT_LEN`].
    TrustedCommentTooLong {
        /// Length found.
        len: usize,
    },
    /// No trusted key verified **both** signatures.
    ///
    /// Deliberately one variant covering wrong key, bad message signature and bad
    /// global signature alike. Splitting them would let a caller write
    /// `if e == BadGlobalSig { warn and continue }`, which is precisely the mistake
    /// the global signature exists to prevent.
    BadSignature,
    /// A public key line was not exactly [`PK_LINE_LEN`] base64 characters.
    BadKeyLine {
        /// Length found.
        len: usize,
    },
    /// A public key line was not canonically base64-encoded.
    BadKeyBase64,
    /// A public key blob did not carry the `Ed` algorithm bytes.
    BadKeyAlgorithm {
        /// The bytes found.
        found: [u8; 2],
    },
    /// A public key's 32 bytes are not a canonical field element (`y >= p`).
    ///
    /// `ed25519-dalek` accepts these; they are rejected here so a key has exactly
    /// one byte representation.
    NonCanonicalKey,
    /// A public key's 32 bytes do not decode to a curve point.
    BadKeyEncoding,
    /// A public key is a small-order point, which admits signatures valid for
    /// almost any message.
    WeakKey,
    /// A [`KeyRing`] was built with no keys.
    EmptyKeyRing,
    /// A [`KeyRing`] was built with more than [`MAX_TRUSTED_KEYS`] keys.
    TooManyKeys {
        /// Number of keys offered.
        found: usize,
    },
    /// The trusted comment's first field was not `nmap-rs-sig:<n>`.
    MissingEnvelopeVersion,
    /// The envelope declares a grammar this build does not implement.
    EnvelopeTooNew {
        /// Version found.
        found: u32,
        /// Version this build implements.
        supported: u32,
    },
    /// An envelope field this build does not know. In a signed document an
    /// unrecognised field may be the signer expressing an intent that would
    /// otherwise be silently discarded.
    UnknownEnvelopeField {
        /// The offending key.
        key: String,
    },
    /// An envelope field appeared twice.
    DuplicateEnvelopeField {
        /// The offending key.
        key: String,
    },
    /// The envelope's fields were missing, out of order, or not `key:value`.
    MalformedEnvelope,
    /// An envelope field's value was not a valid integer.
    BadEnvelopeInteger {
        /// The offending key.
        key: &'static str,
    },
    /// The envelope's `serial` disagreed with the manifest's.
    SerialMismatch {
        /// Serial the envelope declared.
        envelope: u64,
        /// Serial the manifest declared.
        manifest: u64,
    },
    /// The signature was good but the manifest inside it did not parse.
    Manifest(ManifestError),
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { len } => {
                write!(f, "signature is {len} bytes, over the {MAX_SIG_LEN} limit")
            }
            Self::LineCount { found } => {
                write!(f, "expected exactly 4 lines, found {found}")
            }
            Self::LineTooLong { line, len } => {
                write!(f, "line {line}: {len} bytes, over the {MAX_LINE_LEN} limit")
            }
            Self::NonAscii { line, byte } => write!(f, "line {line}: non-ASCII byte {byte:#04x}"),
            Self::BadEol { line } => write!(f, "line {line}: stray carriage return"),
            Self::MissingUntrustedPrefix => {
                write!(f, "line 1: expected `untrusted comment: `")
            }
            Self::MissingTrustedPrefix => write!(f, "line 3: expected `trusted comment: `"),
            Self::BadSigLine { len } => {
                write!(f, "line 2: {len} base64 characters, expected {SIG_LINE_LEN}")
            }
            Self::BadGlobalSigLine { len } => write!(
                f,
                "line 4: {len} base64 characters, expected {GLOBAL_SIG_LINE_LEN}"
            ),
            Self::BadBase64 { line } => write!(f, "line {line}: not canonical base64"),
            Self::UnsupportedAlgorithm { found } => {
                let name = escape(found);
                if *found == ALG_PREHASHED {
                    write!(
                        f,
                        "line 2: prehashed signatures (`{name}`) are not accepted; sign the manifest directly"
                    )
                } else {
                    write!(f, "line 2: unknown signature algorithm `{name}`")
                }
            }
            Self::TrustedCommentTooLong { len } => write!(
                f,
                "line 3: trusted comment is {len} bytes, over the {MAX_TRUSTED_COMMENT_LEN} limit"
            ),
            Self::BadSignature => write!(f, "no trusted key verified this signature"),
            Self::BadKeyLine { len } => {
                write!(f, "public key: {len} base64 characters, expected {PK_LINE_LEN}")
            }
            Self::BadKeyBase64 => write!(f, "public key: not canonical base64"),
            Self::BadKeyAlgorithm { found } => {
                write!(f, "public key: unknown algorithm `{}`", escape(found))
            }
            Self::NonCanonicalKey => write!(f, "public key: not a canonical field element"),
            Self::BadKeyEncoding => write!(f, "public key: not a valid curve point"),
            Self::WeakKey => write!(f, "public key: small-order point"),
            Self::EmptyKeyRing => write!(f, "no trusted signing keys"),
            Self::TooManyKeys { found } => {
                write!(f, "{found} trusted keys, over the {MAX_TRUSTED_KEYS} limit")
            }
            Self::MissingEnvelopeVersion => {
                write!(f, "line 3: expected `nmap-rs-sig:<version>` first")
            }
            Self::EnvelopeTooNew { found, supported } => write!(
                f,
                "line 3: signature envelope {found} is newer than this build supports ({supported}); update nmap-rs"
            ),
            Self::UnknownEnvelopeField { key } => {
                write!(f, "line 3: unknown envelope field `{key}`")
            }
            Self::DuplicateEnvelopeField { key } => {
                write!(f, "line 3: duplicate envelope field `{key}`")
            }
            Self::MalformedEnvelope => write!(f, "line 3: malformed signature envelope"),
            Self::BadEnvelopeInteger { key } => {
                write!(f, "line 3: `{key}` is not a valid integer")
            }
            Self::SerialMismatch { envelope, manifest } => write!(
                f,
                "signature envelope declares serial {envelope} but the manifest declares {manifest}"
            ),
            Self::Manifest(e) => write!(f, "signed manifest is invalid: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Manifest(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ManifestError> for VerifyError {
    fn from(e: ManifestError) -> Self {
        Self::Manifest(e)
    }
}

/// One key the operator trusts to sign bundles.
///
/// Constructed from the base64 line of a minisign `.pub` file — the same 56
/// characters a publisher would paste into a release note. `core` never reads that
/// file; the caller supplies the line.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    key_id: [u8; KEY_ID_LEN],
    key: VerifyingKey,
}

impl TrustedKey {
    /// Parse the base64 line of a minisign public key.
    ///
    /// Rejects, in addition to what `ed25519-dalek` rejects: a non-canonical field
    /// element (`y >= p`, which `VerifyingKey::from_bytes` accepts and which a
    /// `to_bytes()` round-trip does *not* detect, because the original bytes are
    /// stored verbatim), and a small-order point.
    pub fn from_minisign_b64(line: &[u8]) -> Result<Self, VerifyError> {
        if line.len() != PK_LINE_LEN {
            return Err(VerifyError::BadKeyLine { len: line.len() });
        }
        let blob: [u8; PUBKEY_BLOB_LEN] = decode_exact(line).ok_or(VerifyError::BadKeyBase64)?;
        let (alg, rest) = split_array2(&blob);
        if alg != ALG_PURE {
            return Err(VerifyError::BadKeyAlgorithm { found: alg });
        }
        let mut key_id = [0u8; KEY_ID_LEN];
        let mut key_bytes = [0u8; PUBLIC_KEY_LEN];
        let (id_part, key_part) = rest.split_at(KEY_ID_LEN);
        key_id.copy_from_slice(id_part);
        key_bytes.copy_from_slice(key_part);

        if !is_canonical_field_element(&key_bytes) {
            return Err(VerifyError::NonCanonicalKey);
        }
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| VerifyError::BadKeyEncoding)?;
        if key.is_weak() {
            return Err(VerifyError::WeakKey);
        }
        Ok(Self { key_id, key })
    }

    /// The key id this key advertises. Useful for reporting which key signed a
    /// bundle; never for deciding whether to trust one.
    #[must_use]
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        self.key_id
    }
}

/// The set of keys trusted for this run.
///
/// Verification succeeds if **any single key** verifies **both** signatures: an OR
/// across keys, an AND within one. That is what makes key rotation possible — ship
/// a release trusting `{old, new}`, then start signing with `new` — without ever
/// letting a bundle be assembled from two different signers' work.
#[derive(Debug, Clone)]
pub struct KeyRing {
    keys: Vec<TrustedKey>,
}

impl KeyRing {
    /// Build a ring. At least one key, at most [`MAX_TRUSTED_KEYS`].
    pub fn new(keys: Vec<TrustedKey>) -> Result<Self, VerifyError> {
        if keys.is_empty() {
            return Err(VerifyError::EmptyKeyRing);
        }
        if keys.len() > MAX_TRUSTED_KEYS {
            return Err(VerifyError::TooManyKeys { found: keys.len() });
        }
        Ok(Self { keys })
    }

    /// Parse a ring from minisign public-key base64 lines.
    pub fn from_minisign_b64_lines<I, L>(lines: I) -> Result<Self, VerifyError>
    where
        I: IntoIterator<Item = L>,
        L: AsRef<[u8]>,
    {
        let keys = lines
            .into_iter()
            .map(|l| TrustedKey::from_minisign_b64(l.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(keys)
    }

    /// Number of keys in the ring.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the ring is empty. It never is — [`KeyRing::new`] refuses — but
    /// clippy asks for this next to `len`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The signed envelope: what the trusted comment says about this signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedEnvelope {
    /// Envelope grammar version, `<= ENVELOPE_VERSION`.
    pub version: u32,
    /// Bundle serial, cross-checked against the manifest's.
    pub serial: u64,
}

/// A manifest whose signature has been verified.
///
/// The only constructor is [`verify_manifest`]. Downstream code takes this rather
/// than a bare [`Manifest`], so "did anyone check the signature?" is answered by
/// the type rather than by a comment or a convention.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    manifest: Manifest,
    envelope: SignedEnvelope,
    signing_key_id: [u8; KEY_ID_LEN],
}

impl VerifiedManifest {
    /// The manifest, now that it is known to be authentic.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Consume this and return the manifest.
    #[must_use]
    pub fn into_manifest(self) -> Manifest {
        self.manifest
    }

    /// What the signed envelope declared.
    #[must_use]
    pub fn envelope(&self) -> SignedEnvelope {
        self.envelope
    }

    /// The key id of the key that actually verified both signatures. Reportable —
    /// an operator watching a rotation can see it change.
    #[must_use]
    pub fn signing_key_id(&self) -> [u8; KEY_ID_LEN] {
        self.signing_key_id
    }
}

/// The pieces of a `.minisig` after structural parsing and before any curve
/// arithmetic.
struct ParsedSignature<'a> {
    key_id: [u8; KEY_ID_LEN],
    signature: [u8; SIGNATURE_LEN],
    trusted_comment: &'a [u8],
    global_signature: [u8; SIGNATURE_LEN],
}

/// Verify a manifest against a `.minisig` and a ring of trusted keys.
///
/// Every structural check completes before any curve arithmetic runs, and the
/// manifest is parsed only after both signatures pass.
///
/// # Errors
///
/// Returns [`VerifyError`] if the signature file is malformed, if no trusted key
/// verifies both signatures, if the envelope is unrecognised, or if the — now
/// authentic — manifest does not parse.
pub fn verify_manifest(
    ring: &KeyRing,
    manifest_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<VerifiedManifest, VerifyError> {
    // Bound the manifest BEFORE any curve arithmetic. `Manifest::parse` enforces
    // this same limit, but it runs after verification by design, so without this
    // an attacker could hand over an arbitrarily large "manifest" with a
    // well-formed-but-wrong signature and make us hash all of it — once per key in
    // the ring — before the size was ever consulted. Measured before this check
    // existed: 256 MiB cost 572 ms against a one-key ring and 2.29 s against four.
    // The same error `Manifest::parse` would raise, just raised earlier.
    if manifest_bytes.len() > MAX_MANIFEST_LEN {
        return Err(VerifyError::Manifest(ManifestError::TooLarge {
            len: manifest_bytes.len(),
        }));
    }

    let parsed = parse_signature(sig_bytes)?;

    // The global signature's message is `signature[64] || trusted_comment`, and
    // nothing else — not the prefix, not the EOL, not the algorithm bytes, not the
    // key id. `parse_signature` has already capped the comment at
    // MAX_TRUSTED_COMMENT_LEN and GLOBAL_MSG_MAX is sized from that cap, so neither
    // step below can actually fail; they are written fallibly rather than by
    // indexing so this module stays panic-free by construction instead of by
    // argument.
    let comment_len = parsed.trusted_comment.len();
    let too_long = || VerifyError::TrustedCommentTooLong { len: comment_len };
    let global_len = SIGNATURE_LEN
        .checked_add(comment_len)
        .ok_or_else(too_long)?;
    let mut buf = [0u8; GLOBAL_MSG_MAX];
    let global_msg = buf.get_mut(..global_len).ok_or_else(too_long)?;
    // `global_len` is `SIGNATURE_LEN + comment_len`, so the split point is always
    // in range.
    let (sig_part, comment_part) = global_msg.split_at_mut(SIGNATURE_LEN);
    sig_part.copy_from_slice(&parsed.signature);
    comment_part.copy_from_slice(parsed.trusted_comment);
    let global_msg: &[u8] = global_msg;

    // Both signatures, same key. The key id orders the attempts and nothing more:
    // every key is tried either way, so a rewritten id cannot exclude one.
    let message_sig = Signature::from_bytes(&parsed.signature);
    let global_sig = Signature::from_bytes(&parsed.global_signature);

    let ordered = ring
        .keys
        .iter()
        .filter(|k| k.key_id == parsed.key_id)
        .chain(ring.keys.iter().filter(|k| k.key_id != parsed.key_id));

    let mut signing_key_id = None;
    for candidate in ordered {
        // `verify_strict`, never `Verifier::verify`: only the strict path rejects
        // small-order public keys and small-order R.
        if candidate
            .key
            .verify_strict(manifest_bytes, &message_sig)
            .is_ok()
            && candidate.key.verify_strict(global_msg, &global_sig).is_ok()
        {
            signing_key_id = Some(candidate.key_id);
            break;
        }
    }
    let signing_key_id = signing_key_id.ok_or(VerifyError::BadSignature)?;

    // Authentic from here down.
    let envelope = parse_envelope(parsed.trusted_comment)?;
    let manifest = Manifest::parse(manifest_bytes)?;
    if envelope.serial != manifest.serial {
        return Err(VerifyError::SerialMismatch {
            envelope: envelope.serial,
            manifest: manifest.serial,
        });
    }

    Ok(VerifiedManifest {
        manifest,
        envelope,
        signing_key_id,
    })
}

/// Structural parse of a `.minisig`. No cryptography happens here.
fn parse_signature(sig_bytes: &[u8]) -> Result<ParsedSignature<'_>, VerifyError> {
    if sig_bytes.len() > MAX_SIG_LEN {
        return Err(VerifyError::TooLarge {
            len: sig_bytes.len(),
        });
    }

    let raw: Vec<&[u8]> = sig_bytes.split(|&b| b == b'\n').collect();
    // Four lines, optionally followed by one terminating newline (which `split`
    // renders as a trailing empty element). Anything else — a truncated file
    // missing line 3 or 4, or bytes appended after line 4 — is refused. Stock
    // minisign reads exactly four lines and ignores whatever follows, so a mirror
    // can append invisibly; here it cannot.
    let trailing_newline = raw.last().is_some_and(|l| l.is_empty());
    let found = if trailing_newline {
        raw.len().saturating_sub(1)
    } else {
        raw.len()
    };
    if found != 4 {
        return Err(VerifyError::LineCount { found });
    }
    let lines: &[&[u8]] = raw.get(..4).ok_or(VerifyError::LineCount { found })?;

    let mut clean: [&[u8]; 4] = [&[]; 4];
    for (idx, raw_line) in lines.iter().enumerate() {
        // 1-based for the operator. `idx` is 0..=3, so this cannot saturate; it is
        // written this way rather than `+ 1` to keep the arithmetic lint on, and
        // without inventing an error variant for a branch that cannot be taken.
        let no = idx.saturating_add(1);
        let line = match raw_line.split_last() {
            Some((&b'\r', head)) => head,
            _ => raw_line,
        };
        if line.len() > MAX_LINE_LEN {
            return Err(VerifyError::LineTooLong {
                line: no,
                len: line.len(),
            });
        }
        for &byte in line {
            if byte == b'\r' {
                return Err(VerifyError::BadEol { line: no });
            }
            if byte != b'\t' && !(0x20..0x7f).contains(&byte) {
                return Err(VerifyError::NonAscii { line: no, byte });
            }
        }
        clean[idx] = line;
    }

    if !clean[0].starts_with(UNTRUSTED_PREFIX) {
        return Err(VerifyError::MissingUntrustedPrefix);
    }
    // The rest of line 1 is deliberately dropped here and never travels further.

    if clean[1].len() != SIG_LINE_LEN {
        return Err(VerifyError::BadSigLine {
            len: clean[1].len(),
        });
    }
    let blob: [u8; SIG_BLOB_LEN] =
        decode_exact(clean[1]).ok_or(VerifyError::BadBase64 { line: 2 })?;
    let (alg, rest) = split_array2(&blob);
    if alg != ALG_PURE {
        return Err(VerifyError::UnsupportedAlgorithm { found: alg });
    }
    let mut key_id = [0u8; KEY_ID_LEN];
    let mut signature = [0u8; SIGNATURE_LEN];
    let (id_part, sig_part) = rest.split_at(KEY_ID_LEN);
    key_id.copy_from_slice(id_part);
    signature.copy_from_slice(sig_part);

    let trusted_comment = clean[2]
        .strip_prefix(TRUSTED_PREFIX)
        .ok_or(VerifyError::MissingTrustedPrefix)?;
    // Taken verbatim: `trim` in minisign strips one LF and one CR and nothing
    // else, so trailing spaces are part of the signed bytes.
    if trusted_comment.len() > MAX_TRUSTED_COMMENT_LEN {
        return Err(VerifyError::TrustedCommentTooLong {
            len: trusted_comment.len(),
        });
    }

    if clean[3].len() != GLOBAL_SIG_LINE_LEN {
        return Err(VerifyError::BadGlobalSigLine {
            len: clean[3].len(),
        });
    }
    let global_signature: [u8; SIGNATURE_LEN] =
        decode_exact(clean[3]).ok_or(VerifyError::BadBase64 { line: 4 })?;

    Ok(ParsedSignature {
        key_id,
        signature,
        trusted_comment,
        global_signature,
    })
}

/// Parse the trusted comment's `key:value` grammar. Runs only after both
/// signatures have passed, so this is parsing authentic bytes.
fn parse_envelope(comment: &[u8]) -> Result<SignedEnvelope, VerifyError> {
    let mut fields = comment.split(|&b| b == b'\t');

    let first = fields.next().ok_or(VerifyError::MissingEnvelopeVersion)?;
    let (key, value) = split_field(first).ok_or(VerifyError::MissingEnvelopeVersion)?;
    if key != b"nmap-rs-sig" {
        return Err(VerifyError::MissingEnvelopeVersion);
    }
    let version = parse_u64(value)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(VerifyError::BadEnvelopeInteger { key: "nmap-rs-sig" })?;
    if version > ENVELOPE_VERSION {
        return Err(VerifyError::EnvelopeTooNew {
            found: version,
            supported: ENVELOPE_VERSION,
        });
    }

    let mut serial = None;
    for field in fields {
        let (key, value) = split_field(field).ok_or(VerifyError::MalformedEnvelope)?;
        match key {
            b"serial" => {
                if serial.is_some() {
                    return Err(VerifyError::DuplicateEnvelopeField {
                        key: "serial".to_owned(),
                    });
                }
                serial = Some(
                    parse_u64(value).ok_or(VerifyError::BadEnvelopeInteger { key: "serial" })?,
                );
            }
            b"nmap-rs-sig" => {
                return Err(VerifyError::DuplicateEnvelopeField {
                    key: "nmap-rs-sig".to_owned(),
                })
            }
            other => return Err(VerifyError::UnknownEnvelopeField { key: escape(other) }),
        }
    }

    let serial = serial.ok_or(VerifyError::MalformedEnvelope)?;
    Ok(SignedEnvelope { version, serial })
}

/// Split one envelope field at its first `:`.
fn split_field(field: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = field.iter().position(|&b| b == b':')?;
    let (key, rest) = field.split_at(at);
    let value = rest.get(1..)?;
    Some((key, value))
}

/// Split a blob's leading two algorithm bytes from the rest.
fn split_array2(blob: &[u8]) -> ([u8; 2], &[u8]) {
    let (head, rest) = blob.split_at(2);
    let mut alg = [0u8; 2];
    alg.copy_from_slice(head);
    (alg, rest)
}

/// Whether a 32-byte little-endian Ed25519 public key encodes `y < p`.
///
/// The high bit is the point's sign and is not part of `y`, so it is masked off
/// before the comparison.
fn is_canonical_field_element(bytes: &[u8; PUBLIC_KEY_LEN]) -> bool {
    let mut y = *bytes;
    if let Some(top) = y.last_mut() {
        *top &= 0x7f;
    }
    for (a, b) in y.iter().rev().zip(FIELD_PRIME_LE.iter().rev()) {
        if a != b {
            return a < b;
        }
    }
    // Exactly `p`, which is not `< p`.
    false
}

/// Value of one standard-alphabet base64 character.
///
/// URL-safe `-` and `_` are rejected: two alphabets would mean two spellings of
/// one signature. `=` is rejected here too and handled only as padding.
fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(c.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(c.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode exactly `N` bytes of canonically encoded base64.
///
/// Canonical means: standard alphabet only, padding mandatory, length exactly the
/// one `N` implies, no whitespace anywhere, and **the unused trailing bits of the
/// final character must be zero**. Stock minisign's decoder masks none of those
/// bits, so it accepts 4 distinct spellings of any signature line and 16 of any
/// global-signature line. Rejecting them gives a signature exactly one byte
/// representation — the same argument `manifest.rs` makes for lowercase-only hex,
/// and what makes hashing or mirror-comparing a `.minisig` meaningful.
fn decode_exact<const N: usize>(line: &[u8]) -> Option<[u8; N]> {
    let full = N.checked_div(3)?;
    let rem = N.checked_rem(3)?;
    let quads = if rem == 0 { full } else { full.checked_add(1)? };
    if line.len() != quads.checked_mul(4)? {
        return None;
    }

    let mut out = [0u8; N];
    let mut sink = out.iter_mut();
    for (index, quad) in line.chunks_exact(4).enumerate() {
        let tail = rem != 0 && index == full;
        let a = b64_value(quad[0])?;
        let b = b64_value(quad[1])?;
        let (c, d, emit) = if tail && rem == 1 {
            // `xx==`: the second character carries 4 unused low bits.
            if quad[2] != b'=' || quad[3] != b'=' || b & 0x0f != 0 {
                return None;
            }
            (0, 0, 1)
        } else if tail && rem == 2 {
            // `xxx=`: the third character carries 2 unused low bits.
            let c = b64_value(quad[2])?;
            if quad[3] != b'=' || c & 0x03 != 0 {
                return None;
            }
            (c, 0, 2)
        } else {
            (b64_value(quad[2])?, b64_value(quad[3])?, 3)
        };

        let packed = u32::from(a)
            .wrapping_shl(18)
            .checked_add(u32::from(b).wrapping_shl(12))?
            .checked_add(u32::from(c).wrapping_shl(6))?
            .checked_add(u32::from(d))?;
        let bytes = packed.to_be_bytes();
        for byte in bytes.iter().skip(1).take(emit) {
            *sink.next()? = *byte;
        }
    }
    if sink.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real signatures, produced by the OpenSSL CLI and emitted by
    /// `tests/differential/s/oracle/gen_minisign_cases.py` alongside the
    /// differential corpus. Brought in with `include!` rather than read at run
    /// time because these tests also run under Miri, where there is no
    /// filesystem — and because sharing one generator with the corpus is what
    /// stops the two from drifting apart.
    mod fixtures {
        include!("../../../../tests/differential/s/minisign_fixtures.rs");
    }
    use fixtures as fx;

    fn ring() -> KeyRing {
        KeyRing::from_minisign_b64_lines([fx::PUB_A]).expect("test key ring")
    }

    // ---------------------------------------------------------------------
    // End-to-end. Each Ed25519 verification costs ~1.8 s under Miri, and a
    // well-formed file needs two, so only a handful run there. Everything that
    // can be proved against a private helper instead is tested that way below,
    // where it costs nothing.
    // ---------------------------------------------------------------------

    #[test]
    fn a_well_formed_signature_verifies_and_reports_its_key() {
        let verified = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_BASIC).expect("verifies");
        assert_eq!(verified.manifest().serial, 41);
        assert_eq!(verified.envelope().version, ENVELOPE_VERSION);
        assert_eq!(verified.envelope().serial, 41);
        assert_eq!(
            verified.signing_key_id(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(verified.manifest().files.len(), 1);
    }

    #[test]
    fn a_tampered_manifest_is_refused() {
        let err =
            verify_manifest(&ring(), fx::MANIFEST_TAMPERED, fx::SIG_BASIC).expect_err("tampered");
        assert_eq!(err, VerifyError::BadSignature);
    }

    #[test]
    fn a_broken_global_signature_is_refused_though_the_manifest_signature_is_good() {
        // The whole point of the global signature: this file's manifest signature
        // is perfect, and it is still rejected.
        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_TAMPERED_GLOBAL)
            .expect_err("global signature broken");
        assert_eq!(err, VerifyError::BadSignature);
    }

    #[test]
    #[cfg_attr(miri, ignore = "two Ed25519 verifications; covered natively")]
    fn a_trusted_comment_rewritten_after_signing_is_refused() {
        // An attacker takes a genuine bundle and edits the serial in the envelope.
        // Nothing is forged; the global signature is what catches it.
        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_REWRITTEN_COMMENT)
            .expect_err("rewritten comment");
        assert_eq!(err, VerifyError::BadSignature);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Ed25519 verification; covered natively")]
    fn a_signature_from_a_key_outside_the_ring_is_refused() {
        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_WRONG_KEY).expect_err("wrong key");
        assert_eq!(err, VerifyError::BadSignature);
    }

    // Not miri-ignored: `verify_strict` checks `R.is_small_order()` before it
    // recomputes R, so this short-circuits ahead of the message hash and is cheap.
    #[test]
    fn a_second_valid_signature_over_the_same_manifest_is_refused() {
        // R = the identity point. Only the key holder can build this, so it is not
        // a forgery — it is a *second*, different, equally valid signature over the
        // same bytes. OpenSSL, python-cryptography and `ed25519-dalek`'s permissive
        // `verify` all accept it; `verify_strict` is the only thing that refuses.
        // This is the case that pays for choosing the strict path, and it is why no
        // caller may assume (key, manifest) yields a unique signature.
        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_SMALL_ORDER_R)
            .expect_err("small-order R");
        assert_eq!(err, VerifyError::BadSignature);
    }

    // Not miri-ignored: the scalar range check runs before any point arithmetic.
    #[test]
    fn a_non_canonical_scalar_is_refused() {
        // s + L verifies under a cofactored implementation that skips the range
        // check. `verify_strict` refuses it, which is what closes the malleability
        // class.
        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_S_PLUS_L).expect_err("s + L");
        assert_eq!(err, VerifyError::BadSignature);
    }

    #[test]
    #[cfg_attr(miri, ignore = "two Ed25519 verifications; covered natively")]
    fn a_mismatched_key_id_does_not_prevent_verification() {
        // Stock minisign exits on a key-id mismatch before trying anything. The id
        // is unauthenticated, so here it only orders attempts.
        let verified = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_KEY_ID_MISMATCH)
            .expect("key id is not a gate");
        // The file claims an all-zero key id. What is reported is the id of the
        // *trusted* key that actually verified, never the one the file supplied —
        // so nothing an attacker writes into the file can reach a report.
        assert_eq!(
            verified.signing_key_id(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "two Ed25519 verifications; covered natively")]
    fn crlf_line_endings_verify_identically() {
        let verified =
            verify_manifest(&ring(), fx::MANIFEST, fx::SIG_CRLF).expect("CRLF is accepted");
        assert_eq!(verified.envelope().serial, 41);
    }

    #[test]
    #[cfg_attr(miri, ignore = "two Ed25519 verifications; covered natively")]
    fn a_multi_file_manifest_verifies() {
        let verified =
            verify_manifest(&ring(), fx::MANIFEST_TWO_FILES, fx::SIG_TWO_FILES).expect("verifies");
        assert_eq!(verified.manifest().files.len(), 2);
    }

    #[test]
    #[cfg_attr(miri, ignore = "two Ed25519 verifications; covered natively")]
    fn a_ring_verifies_when_any_key_matches() {
        let two = KeyRing::from_minisign_b64_lines([fx::PUB_A, fx::PUB_A]).expect("ring");
        assert_eq!(two.len(), 2);
        assert!(verify_manifest(&two, fx::MANIFEST, fx::SIG_BASIC).is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore = "two Ed25519 verifications; covered natively")]
    fn envelope_faults_are_reported_only_after_the_signatures_pass() {
        // These three files are correctly signed. They are refused on their
        // envelope, which is the only way an envelope error can be reached.
        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_SERIAL_MISMATCH)
            .expect_err("serial mismatch");
        assert_eq!(
            err,
            VerifyError::SerialMismatch {
                envelope: 99,
                manifest: 41
            }
        );

        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_ENVELOPE_TOO_NEW)
            .expect_err("envelope too new");
        assert_eq!(
            err,
            VerifyError::EnvelopeTooNew {
                found: 2,
                supported: ENVELOPE_VERSION
            }
        );

        let err = verify_manifest(&ring(), fx::MANIFEST, fx::SIG_UNKNOWN_FIELD)
            .expect_err("unknown field");
        assert_eq!(
            err,
            VerifyError::UnknownEnvelopeField {
                key: "log".to_owned()
            }
        );
    }

    // ---------------------------------------------------------------------
    // Structural refusals. None of these reach curve arithmetic, so they cost
    // nothing under Miri — which is exactly where the fail-closed coverage
    // should be concentrated.
    // ---------------------------------------------------------------------

    #[test]
    fn structural_faults_are_refused_before_any_curve_arithmetic() {
        let cases: &[(&[u8], VerifyError)] = &[
            (
                fx::SIG_PREHASHED,
                VerifyError::UnsupportedAlgorithm { found: *b"ED" },
            ),
            (
                fx::SIG_NON_CANONICAL_B64,
                VerifyError::BadBase64 { line: 2 },
            ),
            (fx::SIG_APPENDED_JUNK, VerifyError::LineCount { found: 5 }),
            (fx::SIG_MISSING_GLOBAL, VerifyError::LineCount { found: 3 }),
            (b"", VerifyError::LineCount { found: 0 }),
        ];
        for (sig, want) in cases {
            let err = verify_manifest(&ring(), fx::MANIFEST, sig).expect_err("refused");
            assert_eq!(
                &err,
                want,
                "for {}",
                escape(sig).chars().take(40).collect::<String>()
            );
        }
    }

    #[test]
    fn an_oversized_signature_file_is_refused_before_it_is_split() {
        let big = vec![b'A'; MAX_SIG_LEN.saturating_add(1)];
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &big).expect_err("too large"),
            VerifyError::TooLarge {
                len: MAX_SIG_LEN.saturating_add(1)
            }
        );
    }

    #[test]
    fn the_line_prefixes_are_exact() {
        // Edit one line at a time: "trusted comment: " is a substring of
        // "untrusted comment: ", so a whole-file replace would hit the wrong line.
        let rewrite = |index: usize, replacement: &str| {
            let mut lines: Vec<Vec<u8>> = fx::SIG_BASIC
                .split(|&b| b == b'\n')
                .map(<[u8]>::to_vec)
                .collect();
            lines[index] = replacement.as_bytes().to_vec();
            lines.join(&b'\n')
        };
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &rewrite(0, "untrusted comment:x"))
                .expect_err("prefix"),
            VerifyError::MissingUntrustedPrefix
        );
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &rewrite(2, "Trusted comment: x"))
                .expect_err("prefix"),
            VerifyError::MissingTrustedPrefix
        );
    }

    #[test]
    fn an_over_long_line_is_refused_even_though_the_file_fits() {
        // Only line 1 can be long — the other three have exact lengths — and its
        // content is discarded. It is still capped, at `manifest.rs`'s own
        // MAX_LINE_LEN, so the same rule holds across both signed documents.
        let mut lines: Vec<Vec<u8>> = fx::SIG_BASIC
            .split(|&b| b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        let mut long = UNTRUSTED_PREFIX.to_vec();
        long.resize(MAX_LINE_LEN.saturating_add(1), b'x');
        lines[0] = long;
        let sig = lines.join(&b'\n');
        assert!(
            sig.len() <= MAX_SIG_LEN,
            "the whole-file cap must not be what fires"
        );
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &sig).expect_err("long line"),
            VerifyError::LineTooLong {
                line: 1,
                len: MAX_LINE_LEN.saturating_add(1)
            }
        );
    }

    #[test]
    fn a_wrong_length_signature_line_names_the_length_rather_than_the_encoding() {
        // Both the explicit length check and the decoder would refuse this. The
        // explicit one runs first so the operator is told the line is the wrong
        // length, not that base64 is malformed — a different and much more useful
        // sentence. Pinned because otherwise the two are indistinguishable.
        let mut lines: Vec<Vec<u8>> = fx::SIG_BASIC
            .split(|&b| b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        lines[1].truncate(SIG_LINE_LEN.saturating_sub(4));
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &lines.join(&b'\n')).expect_err("short line"),
            VerifyError::BadSigLine {
                len: SIG_LINE_LEN.saturating_sub(4)
            }
        );
        lines = fx::SIG_BASIC
            .split(|&b| b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        lines[3].truncate(GLOBAL_SIG_LINE_LEN.saturating_sub(4));
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &lines.join(&b'\n')).expect_err("short line"),
            VerifyError::BadGlobalSigLine {
                len: GLOBAL_SIG_LINE_LEN.saturating_sub(4)
            }
        );
    }

    #[test]
    fn the_trusted_comment_cap_is_checked_before_the_global_signature_line() {
        // Two bounds could refuse an oversized comment: this explicit cap, and the
        // fixed buffer the global signature's message is assembled in. They report
        // the same error, so the only thing that distinguishes them is ORDER — the
        // cap runs while parsing line 3, before line 4 is looked at. Pinning that
        // keeps the declared limit the thing doing the work, rather than an
        // implementation detail of a buffer size.
        let mut lines: Vec<Vec<u8>> = fx::SIG_BASIC
            .split(|&b| b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        let mut comment = TRUSTED_PREFIX.to_vec();
        comment.resize(
            TRUSTED_PREFIX
                .len()
                .saturating_add(MAX_TRUSTED_COMMENT_LEN.saturating_add(1)),
            b'x',
        );
        lines[2] = comment;
        lines[3] = b"not base64 at all".to_vec();
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &lines.join(&b'\n')).expect_err("long comment"),
            VerifyError::TrustedCommentTooLong {
                len: MAX_TRUSTED_COMMENT_LEN.saturating_add(1)
            }
        );
    }

    #[test]
    fn a_stray_carriage_return_is_refused() {
        let mut sig = fx::SIG_BASIC.to_vec();
        sig.splice(5..5, *b"\r");
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &sig).expect_err("stray CR"),
            VerifyError::BadEol { line: 1 }
        );
    }

    #[test]
    fn a_non_ascii_byte_anywhere_is_refused() {
        let mut sig = fx::SIG_BASIC.to_vec();
        sig.splice(5..5, [0xc3]);
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, &sig).expect_err("non-ascii"),
            VerifyError::NonAscii {
                line: 1,
                byte: 0xc3
            }
        );
    }

    // ---------------------------------------------------------------------
    // Public keys.
    // ---------------------------------------------------------------------

    #[test]
    fn a_small_order_public_key_is_refused() {
        assert_eq!(
            TrustedKey::from_minisign_b64(fx::PUB_SMALL_ORDER.as_bytes()).expect_err("weak"),
            VerifyError::WeakKey
        );
    }

    #[test]
    fn a_non_canonical_public_key_is_refused() {
        // `ed25519-dalek` accepts `y >= p`, and a `to_bytes()` round-trip does not
        // detect it because the original bytes are stored verbatim. So the check
        // has to happen on the raw bytes, here.
        assert_eq!(
            TrustedKey::from_minisign_b64(fx::PUB_NON_CANONICAL.as_bytes())
                .expect_err("non-canonical"),
            VerifyError::NonCanonicalKey
        );
    }

    #[test]
    fn a_non_canonical_key_that_is_not_small_order_is_still_refused() {
        // y = 2^255-1 aliases to y = 18, a FULL-ORDER point. Unlike y = p it is not
        // weak, so `verify_strict` would happily use it — this is the vector that
        // fails if `is_canonical_field_element` is ever deleted as redundant with
        // the small-order check. It is not redundant.
        assert_eq!(
            TrustedKey::from_minisign_b64(fx::PUB_NON_CANONICAL_FULL_ORDER.as_bytes())
                .expect_err("non-canonical"),
            VerifyError::NonCanonicalKey
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "two Ed25519 verifications; covered natively")]
    fn an_envelope_transplanted_from_another_bundle_is_refused() {
        // Both halves are genuine: bundle A's message signature, bundle B's trusted
        // comment and global signature. The global signature is over
        // `sig || comment`, so it binds one comment to one specific signature value
        // and the pair cannot be recombined.
        assert_eq!(
            verify_manifest(&ring(), fx::MANIFEST, fx::SIG_TRANSPLANT).expect_err("transplant"),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn a_public_key_that_is_not_a_curve_point_is_refused() {
        assert_eq!(
            TrustedKey::from_minisign_b64(fx::PUB_UNDECOMPRESSABLE.as_bytes())
                .expect_err("not a point"),
            VerifyError::BadKeyEncoding
        );
    }

    #[test]
    fn key_lines_are_length_checked_and_algorithm_checked() {
        assert_eq!(
            TrustedKey::from_minisign_b64(b"RWQ").expect_err("short"),
            VerifyError::BadKeyLine { len: 3 }
        );
        // "ED" in the algorithm slot of a *public key* is not a thing minisign
        // emits; refuse it rather than guess.
        let mut blob = [0u8; PUBKEY_BLOB_LEN];
        blob[0] = b'E';
        blob[1] = b'D';
        let line = base64_for_test(&blob);
        assert_eq!(
            TrustedKey::from_minisign_b64(line.as_bytes()).expect_err("alg"),
            VerifyError::BadKeyAlgorithm { found: *b"ED" }
        );
    }

    #[test]
    fn a_key_ring_must_hold_between_one_and_max_keys() {
        assert_eq!(
            KeyRing::new(Vec::new()).expect_err("empty"),
            VerifyError::EmptyKeyRing
        );
        let one = TrustedKey::from_minisign_b64(fx::PUB_A.as_bytes()).expect("key");
        let too_many = vec![one; MAX_TRUSTED_KEYS.saturating_add(1)];
        assert_eq!(
            KeyRing::new(too_many).expect_err("too many"),
            VerifyError::TooManyKeys {
                found: MAX_TRUSTED_KEYS.saturating_add(1)
            }
        );
    }

    // ---------------------------------------------------------------------
    // Canonical base64. Stock minisign's decoder masks none of the unused
    // trailing bits, so it accepts 4 spellings of any signature line and 16 of
    // any global-signature line. Exactly one spelling is accepted here.
    // ---------------------------------------------------------------------

    /// A small loop index as `u32`. Written out rather than cast so the crate's
    /// `cast_possible_truncation` lint stays on everywhere, tests included.
    fn idx32(i: usize) -> u32 {
        u32::try_from(i).expect("base64 group index is 0..=3")
    }

    /// Standard-alphabet base64, for building test inputs only.
    fn base64_for_test(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let mut packed = 0u32;
            for (i, &b) in chunk.iter().enumerate() {
                packed |=
                    u32::from(b).wrapping_shl(16u32.wrapping_sub(8u32.wrapping_mul(idx32(i))));
            }
            let take = chunk.len().saturating_add(1);
            for i in 0..4 {
                if i < take {
                    let shift = 18u32.wrapping_sub(6u32.wrapping_mul(idx32(i)));
                    let idx = usize::try_from(packed.wrapping_shr(shift) & 0x3f).expect("6 bits");
                    out.push(char::from(ALPHABET[idx]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn canonical_base64_round_trips_every_tail_shape() {
        for len in [1usize, 2, 3, 32, 42, 63, 64, 74] {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i & 0xff).expect("byte"))
                .collect();
            let text = base64_for_test(&data);
            match len {
                32 => assert_eq!(
                    decode_exact::<32>(text.as_bytes()),
                    Some(<[u8; 32]>::try_from(data.as_slice()).expect("32"))
                ),
                42 => assert_eq!(
                    decode_exact::<42>(text.as_bytes()),
                    Some(<[u8; 42]>::try_from(data.as_slice()).expect("42"))
                ),
                64 => assert_eq!(
                    decode_exact::<64>(text.as_bytes()),
                    Some(<[u8; 64]>::try_from(data.as_slice()).expect("64"))
                ),
                74 => assert_eq!(
                    decode_exact::<74>(text.as_bytes()),
                    Some(<[u8; 74]>::try_from(data.as_slice()).expect("74"))
                ),
                _ => {}
            }
        }
    }

    #[test]
    fn base64_with_non_zero_trailing_bits_is_refused() {
        // 64 bytes encodes as 86 data characters plus "=="; the 86th carries four
        // unused bits. 74 bytes encodes as 99 plus "="; the 99th carries two.
        let sixty_four = base64_for_test(&[0u8; 64]);
        assert!(decode_exact::<64>(sixty_four.as_bytes()).is_some());
        for alt in ['B', 'C', 'D', 'E', 'F', 'G', 'H'] {
            let mut bad = sixty_four.clone();
            bad.replace_range(85..86, &alt.to_string());
            assert_eq!(
                decode_exact::<64>(bad.as_bytes()),
                None,
                "alternate spelling `{alt}` must be refused"
            );
        }
        let seventy_four = base64_for_test(&[0u8; 74]);
        assert!(decode_exact::<74>(seventy_four.as_bytes()).is_some());
        for alt in ['B', 'C', 'D'] {
            let mut bad = seventy_four.clone();
            bad.replace_range(98..99, &alt.to_string());
            assert_eq!(decode_exact::<74>(bad.as_bytes()), None);
        }
    }

    #[test]
    fn base64_alphabet_padding_and_length_are_all_exact() {
        let good = base64_for_test(&[0u8; 42]);
        assert!(decode_exact::<42>(good.as_bytes()).is_some());
        // URL-safe alphabet: two spellings of one key.
        let urlsafe = base64_for_test(&[0xfb, 0xff, 0xbe])
            .replace('+', "-")
            .replace('/', "_");
        assert_eq!(decode_exact::<3>(urlsafe.as_bytes()), None);
        // Padding is mandatory, and length is compared to a compile-time constant.
        assert_eq!(
            decode_exact::<64>(good.trim_end_matches('=').as_bytes()),
            None
        );
        assert_eq!(decode_exact::<42>(&good.as_bytes()[..55]), None);
        // No whitespace skipping.
        let mut spaced = good.clone();
        spaced.replace_range(4..5, " ");
        assert_eq!(decode_exact::<42>(spaced.as_bytes()), None);
        // `=` may only be padding.
        let mut early = good.clone();
        early.replace_range(4..5, "=");
        assert_eq!(decode_exact::<42>(early.as_bytes()), None);
    }

    // ---------------------------------------------------------------------
    // The envelope grammar, tested directly. Reaching these end to end costs two
    // Ed25519 verifications; the grammar itself costs nothing.
    // ---------------------------------------------------------------------

    #[test]
    fn the_envelope_grammar_is_ordered_complete_and_closed() {
        assert_eq!(
            parse_envelope(b"nmap-rs-sig:1\tserial:41").expect("valid"),
            SignedEnvelope {
                version: 1,
                serial: 41
            }
        );
        let cases: &[(&[u8], VerifyError)] = &[
            (b"", VerifyError::MissingEnvelopeVersion),
            (b"serial:41", VerifyError::MissingEnvelopeVersion),
            (
                b"serial:41\tnmap-rs-sig:1",
                VerifyError::MissingEnvelopeVersion,
            ),
            (b"nmap-rs-sig", VerifyError::MissingEnvelopeVersion),
            (
                b"nmap-rs-sig:x\tserial:41",
                VerifyError::BadEnvelopeInteger { key: "nmap-rs-sig" },
            ),
            (
                b"nmap-rs-sig:2\tserial:41",
                VerifyError::EnvelopeTooNew {
                    found: 2,
                    supported: ENVELOPE_VERSION,
                },
            ),
            (b"nmap-rs-sig:1", VerifyError::MalformedEnvelope),
            (b"nmap-rs-sig:1\tserial", VerifyError::MalformedEnvelope),
            (
                b"nmap-rs-sig:1\tserial:41\tserial:41",
                VerifyError::DuplicateEnvelopeField {
                    key: "serial".to_owned(),
                },
            ),
            (
                b"nmap-rs-sig:1\tserial:41\tnmap-rs-sig:1",
                VerifyError::DuplicateEnvelopeField {
                    key: "nmap-rs-sig".to_owned(),
                },
            ),
            (
                b"nmap-rs-sig:1\tserial:41\tlog:x",
                VerifyError::UnknownEnvelopeField {
                    key: "log".to_owned(),
                },
            ),
            (
                b"nmap-rs-sig:1\tserial:+41",
                VerifyError::BadEnvelopeInteger { key: "serial" },
            ),
            (
                b"nmap-rs-sig:1\tserial: 41",
                VerifyError::BadEnvelopeInteger { key: "serial" },
            ),
        ];
        for (input, want) in cases {
            assert_eq!(
                &parse_envelope(input).expect_err("refused"),
                want,
                "for `{}`",
                escape(input)
            );
        }
    }

    #[test]
    fn an_envelope_version_beyond_u32_is_an_integer_error_not_a_panic() {
        assert_eq!(
            parse_envelope(b"nmap-rs-sig:99999999999\tserial:1").expect_err("too big"),
            VerifyError::BadEnvelopeInteger { key: "nmap-rs-sig" }
        );
    }

    // ---------------------------------------------------------------------
    // Field-element canonicality, tested directly against the boundary.
    // ---------------------------------------------------------------------

    #[test]
    fn field_elements_are_canonical_below_p_and_not_at_or_above_it() {
        let mut zero = [0u8; PUBLIC_KEY_LEN];
        assert!(is_canonical_field_element(&zero));
        // p - 1 is canonical.
        let mut p_minus_one = FIELD_PRIME_LE;
        p_minus_one[0] = 0xec;
        assert!(is_canonical_field_element(&p_minus_one));
        // p itself is not.
        assert!(!is_canonical_field_element(&FIELD_PRIME_LE));
        // p + 1 is not.
        let mut p_plus_one = FIELD_PRIME_LE;
        p_plus_one[0] = 0xee;
        assert!(!is_canonical_field_element(&p_plus_one));
        // The high bit is the sign, not part of y, so setting it changes nothing.
        zero[31] = 0x80;
        assert!(is_canonical_field_element(&zero));
        let mut signed_prime = FIELD_PRIME_LE;
        signed_prime[31] |= 0x80;
        assert!(!is_canonical_field_element(&signed_prime));
    }

    // ---------------------------------------------------------------------
    // Errors and hygiene.
    // ---------------------------------------------------------------------

    #[test]
    fn the_untrusted_comment_never_escapes_the_parser() {
        // Line 1 is signed by nothing. Whatever it says must not reach a caller.
        let hostile = b"untrusted comment: VERIFIED BY NMAP -- SAFE TO INSTALL";
        let mut sig = fx::SIG_BASIC.to_vec();
        let first_lf = sig.iter().position(|&b| b == b'\n').expect("line 1");
        sig.splice(..first_lf, hostile.iter().copied());
        // Whether it verifies or not, nothing in the returned value or the error
        // text may carry that string.
        let rendered = match verify_manifest(&ring(), fx::MANIFEST, &sig) {
            Ok(v) => format!("{:?}", v),
            Err(e) => format!("{e}|{e:?}"),
        };
        assert!(
            !rendered.contains("SAFE TO INSTALL"),
            "line 1 leaked into output: {rendered}"
        );
    }

    #[test]
    fn every_error_renders_without_panicking_and_stays_printable() {
        let errors = [
            VerifyError::TooLarge { len: 9 },
            VerifyError::LineCount { found: 3 },
            VerifyError::LineTooLong { line: 2, len: 9 },
            VerifyError::NonAscii { line: 1, byte: 0 },
            VerifyError::BadEol { line: 1 },
            VerifyError::MissingUntrustedPrefix,
            VerifyError::MissingTrustedPrefix,
            VerifyError::BadSigLine { len: 1 },
            VerifyError::BadGlobalSigLine { len: 1 },
            VerifyError::BadBase64 { line: 4 },
            VerifyError::UnsupportedAlgorithm { found: *b"ED" },
            VerifyError::UnsupportedAlgorithm {
                found: [0x00, 0xff],
            },
            VerifyError::TrustedCommentTooLong { len: 999 },
            VerifyError::BadSignature,
            VerifyError::BadKeyLine { len: 3 },
            VerifyError::BadKeyBase64,
            VerifyError::BadKeyAlgorithm { found: *b"xx" },
            VerifyError::NonCanonicalKey,
            VerifyError::BadKeyEncoding,
            VerifyError::WeakKey,
            VerifyError::EmptyKeyRing,
            VerifyError::TooManyKeys { found: 9 },
            VerifyError::MissingEnvelopeVersion,
            VerifyError::EnvelopeTooNew {
                found: 2,
                supported: 1,
            },
            VerifyError::UnknownEnvelopeField {
                key: "log".to_owned(),
            },
            VerifyError::DuplicateEnvelopeField {
                key: "serial".to_owned(),
            },
            VerifyError::MalformedEnvelope,
            VerifyError::BadEnvelopeInteger { key: "serial" },
            VerifyError::SerialMismatch {
                envelope: 1,
                manifest: 2,
            },
            VerifyError::Manifest(ManifestError::NoFiles),
        ];
        for e in errors {
            let text = format!("{e}");
            assert!(!text.is_empty());
            assert!(
                text.bytes().all(|b| b == b' ' || (0x20..0x7f).contains(&b)),
                "unprintable byte in `{text}`"
            );
        }
    }

    #[test]
    fn an_oversized_manifest_is_refused_on_its_length_before_any_curve_arithmetic() {
        // Not `BadSignature`. If this ever reports a signature failure it means the
        // size check moved below the verification loop, and an attacker can make us
        // hash an arbitrarily large body — once per key in the ring — before the
        // limit is consulted. The error variant IS the ordering guarantee.
        let oversized = vec![b'#'; MAX_MANIFEST_LEN.saturating_add(1)];
        assert_eq!(
            verify_manifest(&ring(), &oversized, fx::SIG_BASIC).expect_err("refused"),
            VerifyError::Manifest(ManifestError::TooLarge {
                len: MAX_MANIFEST_LEN.saturating_add(1)
            })
        );
        // A manifest exactly at the ceiling still reaches verification, so the
        // bound is `>` and not `>=`.
        let at_ceiling = vec![b'#'; MAX_MANIFEST_LEN];
        assert_eq!(
            verify_manifest(&ring(), &at_ceiling, fx::SIG_BASIC).expect_err("refused"),
            VerifyError::BadSignature
        );
    }
}
