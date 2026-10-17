# M6.5 step 0 — the D3 spike: a TLS client nmap's rules can live with

Scratch, detached from the workspace (`[workspace]` of its own): a rustls
0.23 `CryptoProvider` written over RustCrypto primitives of the generation
the tree already locks, with the signature verification, key-type and
certificate-entry rules OpenSSL applies even under `SSL_VERIFY_NONE`
(`docs/M6.5-ANALYSIS.md` §1.3), and a fixture run that measures it against
nmap 7.94 on loopback. Its findings decided D3 and are written up in
`docs/M6.5-ANALYSIS.md` §14. Nothing here ships: step f1 ports what this
proved into `sys::tls`.

## What is here

- `src/` — the provider (`aead`, `hash`, `hmac`, `kx`, `rand`, `provider`),
  first-party RSA verification (`rsa`), a DER walker for the subject public
  key (`spki`), the verification dispatcher (`verify`) and the verifier that
  applies nmap's rules (`client`). `sign` and `src/bin/badserver.rs` are a
  TLS 1.3 fixture server that can corrupt its CertificateVerify;
  `src/bin/tlsprobe.rs` is the client under test.
- `fixtures/run.py` — the 61 fixtures: `openssl s_server` 3.0.13 with each
  suite, group and signature scheme forced, dual certificates, STARTTLS (a
  small SMTP front over Python's `ssl`, since OpenSSL 3's `s_server` has no
  `-starttls`), weak and odd certificates, oversized chains, SNI shapes, the
  legacy set, a fake TLS 1.2 server that mutates one thing per mode
  (`fakesrv.py`: bad signature, trailing byte, undecodable certificate, no
  `renegotiation_info`, a substituted key type), the corrupt-CertificateVerify
  server, a silent server and a closed port. For each, nmap 7.94 connects
  through `s0probe.nse` and then `tlsprobe` connects; `results/` holds the
  last run.
- `fixtures/certs/` — the certificates: the Phase 0 set plus P-384, P-521,
  X25519-keyed, DH-keyed and unknown-OID certificates and two chains, 70,606
  and 104,267 bytes of DER (rustls's handshake limit is 65,535; OpenSSL's
  certificate-list limit 102,400).

## Reproduce

```
export CARGO_TARGET_DIR=/somewhere/outside/the/tree
cargo build --release
python3 fixtures/run.py OUTDIR            # needs /usr/bin/nmap 7.94 and openssl 3.0.13
cargo +1.88 check --all-targets           # MSRV
cargo deny --config ../../deny.toml check # plus the C ban of §6, see the write-up
cargo tree -i cc -e all --target all      # prints nothing
```

The measurements in §14 (lines, crates, `unsafe`, duplicates, the workspace
copy at MSRV) were taken as described there, with the commands given.
