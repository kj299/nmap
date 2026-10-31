# Provenance — `rustls` (vendored)

Everything in `rustls/src/`, `test-ca/` and `fuzz/corpus/message/` is
third-party: rustls's, at the revision below, plus the patch series in
`patches/`. This file records whose, which revision, what we changed and how
to re-derive it. The rule is the port's: **no silent drift.**

| | |
|---|---|
| upstream | <https://github.com/rustls/rustls> |
| tag | `v/0.23.46` |
| commit | `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb` (2026-10-13) |
| crates.io | `rustls` 0.23.46, sha256 `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`; its `src/` is the tag's `rustls/src/` less `src/testdata/` (checked file for file) |
| license | Apache-2.0 **or** ISC **or** MIT, at your option (`rustls/LICENSE-*`) |
| local changes | the patches in `patches/`, listed below |
| vendored besides `src/` | upstream's `.rustfmt.toml`; nine `test-ca/` files and `fuzz/corpus/message/` (502 files), the data the unit tests read, at the paths they read them from |
| omitted | upstream's integration tests (`rustls/tests/`), benches, examples, `build.rs`, and every other crate of upstream's workspace |

The layout mirrors upstream's repository, `rustls/` beside `test-ca/` and
`fuzz/`, so the tests' relative paths (`include_bytes!("../../../test-ca/...")`,
`../fuzz/corpus/message`) hold without a patch.

## Why it is vendored

M6.7 (docs/M6.7-ANALYSIS.md, D1 (b)): nmap 7.94 reaches servers that rustls
cannot, and the provider interface cannot carry them. That covers TLS 1.2 RSA
key exchange, CBC record protection, a server's own DH group, DSA
certificates, OpenSSL's handshake limits, and 7.94's ClientHello. Upstream
declines these by design, so the port carries them as a patch series, as it
carries piccolo's. Step b vendors the tree with no change in behaviour; steps
c to f add the patches.

## `rustls/Cargo.toml` is ours

Upstream's manifest names `workspace = true` dependencies against upstream's
root and the C providers. Ours differs as follows:

- **No `ring`, `aws-lc-rs`, `brotli`, `zlib-rs` or `hashbrown`.** The C ban
  (`deny.toml`) and the port's first-party provider (`sys::tls`) rule them
  out. Their features are not declared, so CI's `--all-features` cannot reach
  code that names those crates. A `check-cfg` entry keeps `unexpected_cfgs`
  quiet about the `cfg(feature = ...)` that still mention them.
- **No build script.** Upstream's only sets `cfg(read_buf)` on nightly when
  the `read_buf` feature is on, which is not declared here.
- **Dev-dependencies:** only `env_logger`, `log` and `macro_rules_attribute`,
  the ones the library's own unit tests use. Doctests are off, because the
  doc examples name a provider crate.
- **Versions** are upstream's workspace requirements, resolved by this
  workspace's lockfile.

## The patch series

One file per intent, applied in name order to `rustls/src/`.

| patch | what it does |
|---|---|
| `0001-allow-std-io-errorkind-import.patch` | `#![allow(clippy::std_instead_of_core)]` in `stream.rs`: clippy 1.97 asks for `core::io::ErrorKind`, which does not exist at this workspace's MSRV (1.88) |
| `0002-rsa-key-exchange.patch` | TLS 1.2 RSA key exchange, client side (M6.7 step c). `KeyExchangeAlgorithm::RSA`, and `CryptoProvider::rsa_key_transport`, an optional `RsaKeyTransport` hook that encrypts the premaster to the leaf (`fips()` is false when it is set; the builder takes it as a key exchange for its suite-has-a-group check). The client expects no ServerKeyExchange and so verifies no signature, draws the premaster (0x0303 and 46 random bytes, RFC 5246 §7.4.7.1), sends it encrypted in a u16-length ClientKeyExchange, and derives the master secret from it with the suite's PRF and EMS as usual (`ConnectionSecrets::from_premaster`). Exhaustive matches elsewhere gain an arm; the server never selects an RSA suite, its filter asking for ECDHE or DHE. 8 files, +191 −48 |

## Re-deriving this tree

```sh
git clone https://github.com/rustls/rustls /tmp/rustls
cd /tmp/rustls && git checkout f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb
V=/path/to/nmap-rs/crates/vendor/rustls
for p in "$V"/patches/*.patch; do git apply --include='rustls/src/*' "$p"; done
diff -ru rustls/src "$V/rustls/src"                       # expect no output
diff -ru fuzz/corpus/message "$V/fuzz/corpus/message"     # expect no output
```

`check_vendor.sh` does exactly that, also comparing the licence texts,
`.rustfmt.toml` and each vendored `test-ca` file, and checking that every
`test-ca` file a test names is vendored. CI runs it, so the tree cannot drift
from `upstream tag + patches` without the build going red.

## Upstream is active — plan for it

Unlike piccolo, rustls releases often. A new release is taken by
re-vendoring at its tag and re-applying the series. Each patch that no longer
applies is re-derived by hand against the new code, and the TLS fixture gate
and the unit tests are re-run. The series is kept small and named for that
reason. A security release upstream is a reason to do this promptly: the
port no longer gets rustls fixes through `cargo update`.

## What the gates see

| gate | sees this crate? | because |
|---|---|---|
| `cargo deny` | yes | it resolves the whole graph |
| `audit_unsafe.py` | yes | it is under `crates/`; rustls is `#![forbid(unsafe_code)]`, so the count is 0 |
| clippy (`-D warnings`, `--all-features`) | yes | a workspace member; `0001` is what it needed |
| `cargo fmt --check` | yes | under upstream's `.rustfmt.toml`, which the tree already follows |
| unit tests | yes | `cargo test --all` runs its 148 |
| Miri | **no, deliberately** | `--exclude rustls` in the Miri job: the crate is `#![forbid(unsafe_code)]`, its 148 tests run past 25 minutes under Miri (measured), and several read the clock or the filesystem, which isolation refuses. The unsafe in its dependencies (`subtle`, `zeroize`, `once_cell`) runs under Miri through `nmap-sys`'s TLS tests |
| progress tracker | skipped, reported | `PROVENANCE.md` marks a vendored tree |
