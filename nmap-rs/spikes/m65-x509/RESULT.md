# E5 spike — can `x509-cert` or `x509-parser` be nmap-rs's certificate reader?

Question (docs/M6.5-ANALYSIS.md §4 "BER leniency and re-encoding", §10 E5): nmap parses peer
certificates with OpenSSL `d2i_X509` and computes `pem`/`digest` over OpenSSL's re-encoding
(`i2d_X509`). A crate can be the reader only if it agrees with `d2i_X509` on every accept/reject
verdict and, for accepted inputs, produces the same re-encoded bytes.

**Answer: neither crate does, in any configuration.** Counts over 3,020 inputs (2,876 corpus rows +
144 BER rows added here):

| reader | verdict agrees | C-accept / R-reject | C-reject / R-accept | panics | re-encoding == `i2d_X509` (rows both accept) |
|---|---:|---:|---:|---:|---:|
| x509-cert 0.3.0 `Certificate::from_der` (strict DER) | 2836/3020 | 143 | 41 | 0 | 2492/2505 |
| x509-cert 0.3.0 `Certificate::decode(&mut SliceReader)` (DER, trailing bytes allowed) | 2852/3020 | 127 | 41 | 0 | 2508/2521 |
| x509-cert 0.3.0 `decode` with `EncodingRules::Ber` (der feature `ber`) | 2875/3020 | 104 | 41 | 0 | 2517/2544 |
| x509-parser 0.18.1 `X509Certificate::from_der` | 2849/3020 | 72 | 99 | 0 | n/a (no encoder) |

The disagreements are not corner cases of one family: they cover length encoding, indefinite
lengths, constructed strings, BIT STRING padding, BOOLEAN/INTEGER canonicality, time syntax,
version/serial ranges, OID arcs, DirectoryString content validation, and (for x509-cert) five
re-encoding normalisations OpenSSL does not perform. Section 10 lists what a first-party reader
must do, each item tied to the families that prove it.

## 1. Environment

- OpenSSL 3.0.13 30 Jan 2024 (system libcrypto, `/usr/include/openssl`), gcc; oracle built with
  `gcc -O2 -Wall -o oracle oracle.c -lcrypto`.
- cargo 1.94.1 (build), rustc 1.88.0 for the MSRV check (`cargo +1.88 check`).
- x509-cert 0.3.0 (der 0.8.2, spki 0.8.1, const-oid 0.10.2); x509-parser 0.18.1 (asn1-rs 0.7.2,
  der-parser 10.0.0, nom 7.1.3). Both latest on crates.io (`cargo info`, 2026-10-17).
- /usr/bin/python3.12 (`-I`) for the generator and comparison scripts.
- OpenSSL sources for citations fetched at tag openssl-3.0.13 into `ossl/` (tasn_dec.c, tasn_enc.c,
  asn1_lib.c, a_int.c, a_bitstr.c, a_mbstr.c, a_strex.c, x_name.c, x_pubkey.c).
- Build dir `target/` (252 MB) deleted after the runs, as asked. `src/run_all.sh` reproduces everything.

## 2. Inputs

- Corpus `../../m65/certs.tsv`: 2,876 rows, families attr 1092, ext 1092, flip 400, trunc 143,
  strtype 66, lib 18, utc 17, gen 12, sigalg 7, version 6, serial 5, long-cn 4, rsa-e 3, and one each
  of unknown-oids, trailing, time-wrongtag, spki-unknown-alg, spki-rsa-garbage,
  spki-ec-explicit-junk, multi-rdn, dup-cn, empty-name, many-rdns, empty.
- BER family `ber.tsv` (144 rows, `src/mkber.py`): every kind is built from three bases —
  `x02315` (lib rsa2048, 1228 B), `x02321` (lib ec-secp256r1, 838 B) and a hand-built 193-byte v1
  ed25519 certificate (`mini-ed25519-v1`, body < 256 B so the `0x82 00 xx` case exists; SPKI and
  signature bits borrowed from `x02319`; `d2i_X509` does not verify signatures). Family = first word
  of column 2; `-lenN` means the length is written with N octets after the `0x8N` initial octet,
  always one or more octets longer than minimal:
  - (a) `ber-outer-len{2,3,4,5,8,9}` non-minimal outer SEQUENCE length (`30 83 00 04 c8 …`, up to 9
    length octets with leading zeros); (b) `ber-outer-indef` (`30 80 … 00 00`);
  - (c) `ber-sig-unused{1,7}-{clear,set}` (unused-bits byte 1 or 7, padding bits zero / set),
    `ber-sig-unused0-lowset` (control: unused 0, low bit set — plain DER), `ber-sig-unused8`,
    `ber-sig-unused1-empty` (`03 01 01`), `ber-sig-empty` (`03 00`);
  - (d) `ber-trailing-{1,1ff,2,100,cert}` (1 byte `00`, 1 byte `ff`, `30 00`, 100×`A`, another whole
    certificate);
  - (e) `ber-tbs-len{1,3,4}` non-minimal tbsCertificate length (`len1` = `0x81 xx`, xx < 0x80, on the
    mini base);
  - (f) `ber-tbs-indef`, `ber-subject-indef`, `ber-ext-indef` ([3] wrapper), `ber-extseq-indef`,
    `ber-version-indef` ([0] wrapper), `ber-alg-indef` (outer AlgorithmIdentifier, i.e. outside the
    tbs), `ber-all-indef` (outer + tbs + subject + alg);
  - (g) `ber-name-value-len1` (CN value `0c 81 xx`), `ber-name-rdn-len1` (RDN SET `31 81 xx`),
    `ber-name-len2` (Name `30 82 00 xx`); plus `ber-rdn-unsorted` / `ber-rdn-sorted` (two-AVA RDN
    out of / in DER order);
  - (h) `ber-serial-nonmin` (`02 02 00 01`), `ber-serial-neg1` (`02 01 ff`), `ber-serial-neg-nonmin`
    (`ff ff`), `ber-serial-neg-nonmin80` (`ff 80`), `ber-serial-neg-big` (`80 00×19`),
    `ber-serial-empty` (`02 00`), `ber-serial-00-80` (control), `ber-version-nonmin` (`a0 04 02 02 00 02`);
  - extras OpenSSL is known to tolerate: `ber-bool-true-01` (critical `01 01 01`),
    `ber-bool-false-explicit` (explicit DEFAULT FALSE critical), `ber-alg-len2` (non-minimal length
    outside the tbs), `ber-sig-constructed` / `-indef` (signature as constructed BIT STRING `23 …`
    with two `03` segments), `ber-ext-octet-constructed` / `-indef` (first extnValue as constructed
    OCTET STRING `24 …`), `ber-oid-nonmin-arc` (attribute type OID with a redundant `0x80` prefix on
    its last arc), `ber-base` (unchanged base, control).

## 3. How nmap calls `d2i_X509`

`/home/user/nmap/nse_ssl_cert.cc:526-545`:

```c
int l_parse_ssl_certificate(lua_State *L)
{
  X509 *cert;
  size_t l;
  const char *der;

  der = luaL_checklstring(L, 1, &l);
  if (der == NULL) {
    lua_pushnil(L);
    return 1;
  }

  cert = d2i_X509(NULL, (const unsigned char **) &der, l);
  if (cert == NULL) {
    lua_pushnil(L);
    return 1;
  }
  return parse_ssl_cert(L, cert);
}
```

`der` is advanced by `d2i_X509` and never compared with `der + l`: trailing bytes are tolerated and
silently ignored (the oracle confirms `d2i_X509` consumes exactly the outer element: `x02875`
consumed 997 of 999; `ber-trailing-cert` consumed 1228 of 2066). The other path,
`l_get_ssl_certificate` (`:546-558`), takes the `X509*` from `SSL_get_peer_certificate`, so the
reader also has to match what OpenSSL's TLS stack accepted. `pem` is `PEM_write_bio_X509`
(`:421-437`) and `digest` is `X509_digest` (`:126-147`); both go through `i2d_X509`.

## 4. The C oracle (`c/oracle.c` → `c_oracle.tsv`)

Per row: `ERR_clear_error(); x = d2i_X509(NULL, &p, len)`; on reject the first and last queued error
(`ERR_get_error` → `ERR_reason_error_string` / `ERR_error_string_n`); on accept `consumed = p - start`,
`i2d_X509` length and SHA-256, whether `i2d == input`, `EVP_PKEY_base_id`/`EVP_PKEY_bits` of
`X509_get0_pubkey` (or `nokey`), `X509_get_version`, `X509_get_signature_nid` (short names), any error
left queued after an accept (none, ever), and the `i2d` bytes when they differ from the input
(≤ 4000 B).

C verdicts: 2,648 accept (corpus 2,527, BER 121), 372 reject (corpus 349, BER 23). Corpus rejects by
reason: trunc 142 `too long` + 1 `too small`; flip 169 (`wrong tag` 56, `too long` 40,
`header too long` 31, `invalid object encoding` 16, `invalid utf8string` 10, `sequence length
mismatch` 8, `mstring not universal` 3, `explicit length mismatch` 2, `invalid bit string bits left`
2, `mstring wrong tag` 1); strtype 34 (`mstring wrong tag` 24, `universalstring is wrong length` 3,
`illegal characters` 3, `bmpstring is wrong length` 2, `invalid utf8string` 2); serial 1
(`x02299`, `illegal padding`: the generator wrote −2^159 as 21 octets `ff 80 00…`, non-minimal);
time-wrongtag 1 (`mstring wrong tag`); empty 1 (`too small`). Everything else in the corpus is
accepted, including every utc/gen row (`''`, `'Z'`, `2x0101000000Z`, month 13, hour 24, second 60,
fractional seconds, lowercase `z`), version 3 and 255 (`X509_get_version` = 3 / 255), a 26-octet
serial, OIDs `2.999.1` and `1.3.6.1.4.1.99999.1.2.3`, unknown signature OID (`sig_alg` = UNDEF), and
the three spki-* rows (accepted with `nokey`).

BER rows: C rejects only `ber-sig-unused8` (`invalid bit string bits left`), `ber-sig-empty`
(`string too short`), `ber-serial-{nonmin,neg-nonmin,neg-nonmin80}` and `ber-version-nonmin`
(`illegal padding`), `ber-serial-empty` (`illegal zero content`), `ber-oid-nonmin-arc`
(`invalid object encoding`). It accepts everything else, including 9-octet lengths with leading
zeros, every indefinite-length variant, constructed BIT STRING / OCTET STRING, `03 01 01`, BOOLEAN
`01`, unsorted RDN SETs, and all trailing variants (consumed = outer element length).

`i2d_X509 == input` for every accepted corpus row except `x02875` (trailing). For BER rows it differs
exactly on: all `ber-outer-len*`, `ber-outer-indef`, `ber-alg-indef`, `ber-alg-len2`, `ber-all-indef`
(outer header and outer AlgorithmIdentifier re-emitted minimal/definite), `ber-sig-unused{1,7}-set`
(last byte masked, e.g. `…67` → `…66`), `ber-sig-unused1-empty` (`03 01 01` → `03 01 00`),
`ber-sig-constructed(-indef)` (segments concatenated into one primitive BIT STRING), all
`ber-trailing-*` (dropped). It is byte-identical to the input for every variant inside the
tbsCertificate (`ber-tbs-len*`, `ber-tbs-indef`, `ber-subject-indef`, `ber-ext-indef`,
`ber-extseq-indef`, `ber-version-indef`, `ber-name-*`, `ber-rdn-unsorted`, `ber-bool-*`,
`ber-ext-octet-constructed(-indef)`): `ossl_asn1_enc_save` (tasn_dec.c:470) caches the tbs bytes
from the tag through the EOC, and `ossl_asn1_enc_restore` (tasn_enc.c:155) replays them.

## 5. Agreement tables

Per family, per crate, per variant; classes are C-verdict/Rust-verdict. "re-enc == i2d" compares
SHA-256 of x509-cert's `Encode::to_der` with the oracle's `i2d_X509` SHA-256; "consumed == C"
compares bytes consumed (x509-cert `Reader::position`, x509-parser rest length). Full tables with
the per-class error strings are in `out/compare.md`; the row-level join is `out/joined.tsv`. The
tolerant-DER variant differs from strict on exactly the 16 trailing rows (`ber-trailing-*` ×15 and
`x02875`) and nowhere else, so its per-family table is omitted here (it is in `out/compare.md`).

### x509-cert strict (from_der)

| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| flip | 400 | 202 | 29 | 9 | 160 | 0 | 362/400 | 202/202 | 202/202 |
| strtype | 66 | 31 | 1 | 29 | 5 | 0 | 36/66 | 31/31 | 31/31 |
| utc | 17 | 4 | 13 | 0 | 0 | 0 | 4/17 | 4/4 | 4/4 |
| gen | 12 | 3 | 9 | 0 | 0 | 0 | 3/12 | 2/3 | 3/3 |
| version | 6 | 4 | 2 | 0 | 0 | 0 | 4/6 | 3/4 | 4/4 |
| serial | 5 | 3 | 1 | 0 | 1 | 0 | 4/5 | 3/3 | 3/3 |
| unknown-oids | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| trailing | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-alg-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-alg-len2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-all-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-bool-false-explicit | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | 0/2 | 2/2 |
| ber-bool-true-01 | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-ext-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-ext-octet-constructed | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-ext-octet-constructed-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-extseq-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-name-len2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-name-rdn-len1 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-name-value-len1 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-oid-nonmin-arc | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len2 | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-outer-len3 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len4 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len5 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len8 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len9 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-rdn-unsorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-constructed | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-constructed-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-unused1-empty | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-unused1-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused7-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-subject-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-len1 | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-tbs-len3 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-len4 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-trailing-1 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-trailing-100 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-trailing-1ff | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-trailing-2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-trailing-cert | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-version-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| **all** | 3020 | 2505 | 143 | 41 | 331 | 0 | 2836/3020 | 2492/2505 | 2505/2505 |

Families with full agreement (verdicts, re-encoding, consumed) omitted from the table: attr (1092), ext (1092), trunc (143), lib (18), sigalg (7), long-cn (4), rsa-e (3), time-wrongtag (1), spki-unknown-alg (1), spki-rsa-garbage (1), spki-ec-explicit-junk (1), multi-rdn (1), dup-cn (1), empty-name (1), many-rdns (1), empty (1), ber-base (3), ber-rdn-sorted (3), ber-serial-00-80 (3), ber-serial-empty (3), ber-serial-neg-big (3), ber-serial-neg-nonmin (3), ber-serial-neg-nonmin80 (3), ber-serial-neg1 (3), ber-serial-nonmin (3), ber-sig-empty (3), ber-sig-unused0-lowset (3), ber-sig-unused1-clear (3), ber-sig-unused7-clear (3), ber-sig-unused8 (3), ber-version-nonmin (2).

### x509-cert tolerant BER (EncodingRules::Ber)

| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| flip | 400 | 202 | 29 | 9 | 160 | 0 | 362/400 | 202/202 | 202/202 |
| strtype | 66 | 31 | 1 | 29 | 5 | 0 | 36/66 | 31/31 | 31/31 |
| utc | 17 | 4 | 13 | 0 | 0 | 0 | 4/17 | 4/4 | 4/4 |
| gen | 12 | 3 | 9 | 0 | 0 | 0 | 3/12 | 2/3 | 3/3 |
| version | 6 | 4 | 2 | 0 | 0 | 0 | 4/6 | 3/4 | 4/4 |
| serial | 5 | 3 | 1 | 0 | 1 | 0 | 4/5 | 3/3 | 3/3 |
| unknown-oids | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-alg-len2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-all-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-bool-false-explicit | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | 0/2 | 2/2 |
| ber-bool-true-01 | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-ext-indef | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | 0/2 | 2/2 |
| ber-ext-octet-constructed | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-ext-octet-constructed-indef | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | 0/2 | 2/2 |
| ber-extseq-indef | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | 0/2 | 2/2 |
| ber-name-len2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-name-rdn-len1 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-name-value-len1 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-oid-nonmin-arc | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len2 | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-outer-len3 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len4 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len5 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len8 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len9 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-constructed | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-constructed-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-unused1-empty | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-unused1-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused7-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-subject-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-tbs-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-tbs-len1 | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-tbs-len3 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-len4 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-version-indef | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | 0/2 | 2/2 |
| **all** | 3020 | 2544 | 104 | 41 | 331 | 0 | 2875/3020 | 2517/2544 | 2544/2544 |

Families with full agreement (verdicts, re-encoding, consumed) omitted from the table: attr (1092), ext (1092), trunc (143), lib (18), sigalg (7), long-cn (4), rsa-e (3), trailing (1), time-wrongtag (1), spki-unknown-alg (1), spki-rsa-garbage (1), spki-ec-explicit-junk (1), multi-rdn (1), dup-cn (1), empty-name (1), many-rdns (1), empty (1), ber-alg-indef (3), ber-base (3), ber-outer-indef (3), ber-rdn-sorted (3), ber-rdn-unsorted (3), ber-serial-00-80 (3), ber-serial-empty (3), ber-serial-neg-big (3), ber-serial-neg-nonmin (3), ber-serial-neg-nonmin80 (3), ber-serial-neg1 (3), ber-serial-nonmin (3), ber-sig-empty (3), ber-sig-unused0-lowset (3), ber-sig-unused1-clear (3), ber-sig-unused7-clear (3), ber-sig-unused8 (3), ber-trailing-1 (3), ber-trailing-100 (3), ber-trailing-1ff (3), ber-trailing-2 (3), ber-trailing-cert (3), ber-version-nonmin (2).

### x509-parser 0.18.1 (from_der)

| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| flip | 400 | 214 | 17 | 49 | 120 | 0 | 334/400 | n/a | 214/214 |
| strtype | 66 | 32 | 0 | 34 | 0 | 0 | 32/66 | n/a | 32/32 |
| utc | 17 | 7 | 10 | 0 | 0 | 0 | 7/17 | n/a | 7/7 |
| gen | 12 | 7 | 5 | 0 | 0 | 0 | 7/12 | n/a | 7/7 |
| serial | 5 | 4 | 0 | 1 | 0 | 0 | 4/5 | n/a | 4/4 |
| ber-alg-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-all-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-ext-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-ext-octet-constructed | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-ext-octet-constructed-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-extseq-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-oid-nonmin-arc | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-outer-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-serial-empty | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-serial-neg-nonmin | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-serial-neg-nonmin80 | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-serial-nonmin | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-constructed | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-constructed-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-unused1-empty | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-unused1-set | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-unused7-set | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-subject-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-tbs-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-version-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| **all** | 3020 | 2576 | 72 | 99 | 273 | 0 | 2849/3020 | n/a | 2576/2576 |

Families with full agreement (verdicts, re-encoding, consumed) omitted from the table: attr (1092), ext (1092), trunc (143), lib (18), sigalg (7), version (6), long-cn (4), rsa-e (3), unknown-oids (1), trailing (1), time-wrongtag (1), spki-unknown-alg (1), spki-rsa-garbage (1), spki-ec-explicit-junk (1), multi-rdn (1), dup-cn (1), empty-name (1), many-rdns (1), empty (1), ber-alg-len2 (3), ber-base (3), ber-bool-false-explicit (2), ber-bool-true-01 (2), ber-name-len2 (3), ber-name-rdn-len1 (3), ber-name-value-len1 (3), ber-outer-len2 (1), ber-outer-len3 (3), ber-outer-len4 (3), ber-outer-len5 (3), ber-outer-len8 (3), ber-outer-len9 (3), ber-rdn-sorted (3), ber-rdn-unsorted (3), ber-serial-00-80 (3), ber-serial-neg-big (3), ber-serial-neg1 (3), ber-sig-empty (3), ber-sig-unused0-lowset (3), ber-sig-unused1-clear (3), ber-sig-unused7-clear (3), ber-sig-unused8 (3), ber-tbs-len1 (1), ber-tbs-len3 (3), ber-tbs-len4 (3), ber-trailing-1 (3), ber-trailing-100 (3), ber-trailing-1ff (3), ber-trailing-2 (3), ber-trailing-cert (3), ber-version-nonmin (2).


## 6. Re-encoding agreement (x509-cert `Encode::to_der` vs `i2d_X509`, rows both accept)

| variant | agree | differ | differing families (rows) |
|---|---:|---:|---|
| strict / tolerant DER | 2492/2505, 2508/2521 | 13 | ber-sig-unused1-set 3, ber-sig-unused7-set 3, ber-rdn-unsorted 3, ber-bool-false-explicit 2, gen 1 (`x02285`), version 1 (`x02291`) |
| tolerant BER | 2517/2544 | 27 | the six above minus ber-rdn-unsorted (under BER rules der keeps SET order), plus every indefinite-length element inside the tbs: ber-tbs-indef 3, ber-subject-indef 3, ber-all-indef 3, ber-ext-indef 2, ber-extseq-indef 2, ber-version-indef 2, ber-ext-octet-constructed-indef 2 |

Where x509-cert accepts trailing bytes (tolerant variants), consumed length and re-encoding match
OpenSSL on all 16 trailing rows. `ber-outer-indef` and `ber-alg-indef` match under BER rules because
both sides re-emit those (non-cached) headers minimally. Byte-level examples are in
`out/inspect_examples.txt`:

- `b00009` ber-sig-unused1-set: OpenSSL `i2d` ends `…66`, input and x509-cert end `…67`
  (a_bitstr.c:123 `s[len - 1] &= (0xff << i)` masks on decode; der's `BitString` keeps the bits).
- `b00033` ber-rdn-unsorted: x509-cert emits the RDN sorted (`30 16 …` before `30 27 …`); OpenSSL
  emits the input order (der set_of.rs:258-260 sorts at decode under DER rules; no ordering check).
- `b00043` ber-bool-false-explicit: x509-cert drops `01 01 00` (3 bytes shorter); OpenSSL keeps it.
- `x02291` version 0: x509-cert drops the explicit `a0 03 02 01 00` (DEFAULT v1); OpenSSL keeps it.
- `x02285` gen 20200229000000Z: x509-cert rewrites both GeneralizedTimes as UTCTime (4 bytes
  shorter; x509-cert time.rs:72-78 `rfc5280_adjust_utc_time`, applied at decode for years ≤ 2049);
  OpenSSL keeps them.
- `b00023` ber-tbs-indef (BER rules): x509-cert emits `30 82 03 b0 …`; OpenSSL replays the cached
  `30 80 … 00 00`.

## 7. Disagreement classes, examples and reasons

### 7.1 x509-cert — C accepts, crate rejects (143 strict / 127 tolerant-DER / 104 BER rows)

| class | rows (BER mode) | example ids | crate error | reason |
|---|---:|---|---|---|
| non-minimal definite length, anywhere (outer, tbs, Name, RDN, value, outer AlgorithmIdentifier) | 35 | b00002, b00090 (`30 82 00 be`), b00110 (`30 81 72`), b00030, b00031, b00032, b00028 | `incorrect length for SEQUENCE/SET/UTF8String` (`ErrorKind::Overlength`) | der length.rs:291-335 requires the minimal form and ≤ 4 length octets unconditionally, BER rules included. OpenSSL asn1_lib.c:116-152 skips leading zero octets and accepts up to `sizeof(long)` = 8 significant octets (`ber-outer-len9` accepted). |
| indefinite length (DER rules only) | 0 in BER mode; 21 in strict/tolerant-DER | b00007, b00023, b00024, b00025, b00134 | `indefinite length disallowed/malformed` | `ErrorKind::IndefiniteLength` unless `EncodingRules::Ber` (feature `ber`). Under BER rules all 21 are accepted, but the re-encoding of the 15 inside the tbs differs (§6). |
| trailing bytes (strict only) | 0 tolerant; 16 strict | b00016, b00020, x02875 | `trailing data at end of DER message` | `from_der` calls `Reader::finish` (reader.rs:115-126). `Certificate::decode` on a `SliceReader` tolerates them and consumed matches OpenSSL. |
| constructed BIT STRING signature | 6 | b00130, b00131, b00136, b00142 | `unknown/unsupported ASN.1 DER tag: 0x23` | der has no constructed-string support for `BitString`. OpenSSL `asn1_collect` concatenates the segments' content octets and parses the result as one primitive: `03 L1 00 A ‖ 03 L2 00 B` becomes a BIT STRING with unused = 0 and value `A 00 B` (`i2d` is one byte longer than the base certificate: the extra `00`). |
| constructed OCTET STRING extnValue | 2 definite (all modes), 2 indefinite (DER modes only) | b00132, b00133, b00138, b00139 | `unknown/unsupported tag 0x24`; BER mode: `OCTET STRING not canonically encoded` | der's BER mode reassembles only *indefinite-length* constructed strings (bytes.rs:164). OpenSSL accepts both (nesting ≤ ASN1_MAX_STRING_NEST = 5) and keeps the tbs verbatim. |
| BIT STRING unused = 1 with no content | 3 | b00014, b00058, b00103 | `malformed ASN.1 DER value for BIT STRING` | bit_string.rs:270 rejects `unused != 0 && bytes.is_empty()`. OpenSSL accepts (a_bitstr.c:105-123: `03 01 01`) and re-encodes as `03 01 00`. |
| BOOLEAN octet other than 00/FF | 2 + 5 flips | b00042, b00086, x02647, x02683 | `ASN.1 BOOLEAN not canonically encoded as DER` | boolean.rs:20-28. OpenSSL takes any octet as the value. |
| time syntax/range | utc 13, gen 9, flip 18 | x02262 (`500101000000Z`), x02265 (no seconds), x02266 (`+0100`), x02268 (month 13), x02274 (`2x…`), x02275 (`''`), x02278 (gen 1950), x02279 (gen 0001), x02281 (`.5Z`), x02287 (`z`), x02502 | `malformed ASN.1 DER value for UTCTime/GeneralizedTime`, `date/time error` | der decodes only `YYMMDDHHMMSSZ` / `YYYYMMDDHHMMSSZ` with a valid calendar date, years 1970-9999 (datetime.rs:19,63; UTCTime ≤ 2049, utc_time.rs:40). OpenSSL `d2i` treats both time types as plain strings (tasn_dec.c:904-905) and validates nothing: `''`, `Z`, `2x0101000000Z`, hour 24, second 60 are all accepted. |
| version > v3 | 2 | x02294 (3), x02295 (255) | `malformed ASN.1 DER value for INTEGER` | `Version` enum = 0..2 (certificate.rs:91-103). `X509_get_version` returns 3 / 255. |
| serial > 20 octets | 1 | x02300 (26 octets) | `malformed ASN.1 DER value for INTEGER` | `SerialNumber::MAX_LEN` = 20 (serial_number.rs:39,55). OpenSSL has no limit. |
| OID arcs const-oid cannot hold | 1 + 6 flips | x02253 (`2.999.1` at bytes 111-116), x02641, x02820, x02738, x02863 | `malformed OID` | const-oid 0.10 arc/length constraints; OpenSSL stores any sub-identifier sequence. |
| UniversalString attribute value | 1 (+5 both-reject for different reasons) | x02215 (empty UniversalString) | `unknown/unsupported ASN.1 DER tag: 0x1c` | der has no UniversalString tag, so even `Any` cannot hold it. OpenSSL accepts tag 0x1c in DirectoryString. |

### 7.2 x509-cert — C rejects, crate accepts (41 rows, identical in all three modes)

| class | rows | example ids | C reason | reason |
|---|---:|---|---|---|
| DirectoryString tag not in OpenSSL's set | 24 strtype | x02227 (VisibleString 0x1a) | `mstring wrong tag` | X509_NAME_ENTRY values decode as ASN1_PRINTABLE, an MSTRING limited to B_ASN1_PRINTABLE (asn1.h:595; tasn_dec.c:253). Corpus evidence: tags 0c,12,13,14,16,1c,1e accepted; 02,04,05,1a rejected. x509-cert's `AttributeValue` is `Any`. (`strtype` rows with tags 02/04/05 are both-reject only because the *content* fails der's INTEGER/NULL checks, not the tag.) |
| string content validation | 5 strtype + 7 flip | x02189 (`0c 02 ff fe`), x02210 (BMPString odd length), x02214 (BMP surrogates), x02481 | `invalid utf8string`, `bmpstring is wrong length`, `illegal characters`, `universalstring is wrong length` | OpenSSL canonicalises every Name at d2i time (x_name.c:192 → :347 `asn1_string_canon` → a_strex.c:605 `ASN1_STRING_to_UTF8` → a_mbstr.c:66/74/85/113), which validates UTF-8, BMP/Universal lengths and code points. Neither crate validates attribute-value content. |
| non-universal class tag where a string is expected | 2 flip | x02685 (`dc …`), x02839 | `mstring not universal` | tasn_dec.c:244. `Any` accepts any class. |
| OID sub-identifier with redundant 0x80 prefix | 3 | b00135, b00141, b00144 (`06 04 55 04 80 0a`) | `invalid object encoding` | c2i_ASN1_OBJECT rejects a leading 0x80 octet in a sub-identifier; const-oid decodes it. |

### 7.3 x509-parser — C accepts, crate rejects (72 rows)

| class | rows | example ids | crate error | reason |
|---|---:|---|---|---|
| any indefinite length | 21 | b00007, b00023, b00024, b00026, b00027, b00134; b00025 | `DerConstraintFailed(IndefiniteLength)`; `InvalidIssuerUID` for ber-ext-indef | der-parser der/multi.rs:522-529 (`parse_der_container`) rejects `Length::Indefinite`; the `a3 80` wrapper is mis-read as issuerUniqueID. |
| constructed strings | 6 + 4 | b00130, b00136, b00142; b00132, b00133 | `InvalidSignatureValue`; `NomError(Eof)` | asn1-rs `BitString::from_der` / extension parsing are primitive-only. |
| signature BIT STRING with nonzero padding bits, or unused=1 and empty | 9 | b00009, b00011, b00014 | `InvalidSignatureValue` | asn1-rs DER constraint: padding bits must be zero (x509.rs:574-576). `-clear` variants are accepted. |
| time semantics | utc 10, gen 5, flip 17 | x02267 (no `Z`), x02268 (month 13), x02275, x02276, x02282 (`.123456Z`), x02283, x02286 (Feb 29 2021), x02287, x02288 | `InvalidDate` | x509-parser validates calendar fields and some syntax; but it accepts `2001010000Z` (no seconds), `+0100`, `500101000000Z`, gen 1950 / 0001, `.5Z` — a third, different notion of validity. |

### 7.4 x509-parser — C rejects, crate accepts (99 rows)

| class | rows | example ids | C reason | reason |
|---|---:|---|---|---|
| non-minimal or empty INTEGER | 13 | b00035 (`02 02 00 01`), b00037, b00038, b00040 (`02 00`), x02299 | `illegal padding`, `illegal zero content` | asn1-rs `Integer` imposes no canonical-form check; OpenSSL a_int.c:159-194 rejects both. |
| DirectoryString tag/content validation | 34 strtype + 9 flip | x02227, x02189, x02210, x02214, x02481, x02685 | as 7.2 | `AttributeValue` is `Any`; no content validation. |
| structural damage inside a Name or after the last field of a SEQUENCE | 14 + 10 + 8 + 5 + 3 flips | x02539 (OID last octet with continuation bit), x02504 (attribute type tag 06→03), x02505 (inner length > remaining), x02536 (length octet 0xff), x02665 (signature length −4 ⇒ 4 unparsed bytes inside the outer SEQUENCE) | `invalid object encoding`, `wrong tag`, `too long`, `header too long`, `sequence length mismatch` | Two leniencies compound: `X509Name::from_der` is `many0(complete(RDN::from_der))` (x509.rs:474) — the RDN list silently stops at the first RDN that fails to parse — and `parse_der_container` discards whatever the field parser leaves unconsumed in any SEQUENCE (der/multi.rs:531 `let (_rest, v) = f(data, hdr)?;`). A corrupted RDN therefore truncates the subject instead of failing, and stray bytes inside the outer SEQUENCE are ignored. x509-cert agrees with OpenSSL on all of these. |
| OID with 0x80-prefixed arc | 3 | b00135 | `invalid object encoding` | asn1-rs stores raw OID bytes. |

No panics were observed in any reader on any input (both harnesses run every decode under
`catch_unwind`, including the 200 kB `long-cn` row and the 300-RDN `many-rdns` row).

## 8. Nesting limits

- OpenSSL 3.0.13: `ASN1_MAX_CONSTRUCTED_NEST` = 30 (`ossl/tasn_dec.c:26`), enforced in
  `asn1_item_embed_d2i` at `:195` (`if (++depth > ASN1_MAX_CONSTRUCTED_NEST) → ASN1_R_NESTED_TOO_DEEP`).
  Constructed *strings* have their own limit `ASN1_MAX_STRING_NEST` = 5 (`:1030-1037`, checked at
  `:1079`). With the X.509 template the 30-level counter is bounded by the schema (the depth is a
  recursion counter per `ASN1_item_ex_d2i` call; X509_NAME restarts it through its own
  `ASN1_item_ex_d2i`), so only the string limit is reachable from `d2i_X509` input. Not measured here.
- der 0.8.2: `Position::MAX_DEPTH` = 64 nested productions (`src/reader/position.rs:20`), enforced in
  `split_nested` (`:76-79`, `ErrorKind::NestingDepth`). Nothing in x509-cert raises it.
- asn1-rs 0.7.2 (x509-parser): `MAX_RECURSION` = 50 (`src/ber/parser.rs:9`).

## 9. Crate facts

| | x509-cert 0.3.0 | x509-parser 0.18.1 |
|---|---|---|
| license | Apache-2.0 OR MIT | MIT OR Apache-2.0 |
| declared rust-version / edition | 1.85 / 2024 | 1.67.1 / 2018 |
| effective MSRV of the tree | 1.85 (every RustCrypto crate declares 1.85) | **1.88**: time 0.3.55, time-core 0.1.9, time-macros 0.2.32 declare 1.88.0, deranged 0.5.9 declares 1.85.0 |
| `cargo +1.88 check` | passes | passes |
| `cargo tree -e normal --prefix none \| sort -u` (excluding the harness) | **13 crates**: base64ct 1.8.3, const-oid 0.10.2, der 0.8.2, der_derive 0.8.0, flagset 0.4.7, pem-rfc7468 1.0.0, proc-macro2 1.0.107, quote 1.0.47, spki 0.8.1, syn 2.0.119, unicode-ident 1.0.27, x509-cert 0.3.0, zeroize 1.9.1 | **30 crates**: asn1-rs 0.7.2, asn1-rs-derive 0.6.0, asn1-rs-impl 0.2.0, data-encoding 2.11.1, der-parser 10.0.0, deranged 0.5.9, displaydoc 0.2.7, lazy_static 1.5.1, memchr 2.8.3, minimal-lexical 0.2.1, nom 7.1.3, num-bigint 0.4.8, num-conv 0.2.2, num-integer 0.1.47, num-traits 0.2.19, oid-registry 0.8.1, powerfmt 0.2.1, proc-macro2 1.0.107, quote 1.0.47, rusticata-macros 4.1.0, syn 2.0.119 **and** syn 3.0.9, synstructure 0.13.2, thiserror 2.0.21, thiserror-impl 2.0.21, time 0.3.55, time-core 0.1.9, time-macros 0.2.32, unicode-ident 1.0.27, x509-parser 0.18.1 |
| Cargo.lock entries (audit_src.py) | 16 (adds tls_codec, tls_codec_derive, zeroize_derive: feature-gated, not built) | 33 (adds autocfg, serde_core, serde_derive) |
| licenses other than MIT/Apache dual | flagset Apache-2.0; unicode-ident (MIT OR Apache-2.0) AND Unicode-3.0 | memchr Unlicense OR MIT; nom, data-encoding, synstructure MIT; unicode-ident … AND Unicode-3.0 |
| `unsafe` tokens (audit_src.py, non-test .rs over the lock) | **108**: syn 71, zeroize 17 (+1 `asm!`), proc-macro2 6, base64ct 4, der 4, flagset 2, unicode-ident 2, const-oid 1, pem-rfc7468 1; x509-cert, spki, der_derive `forbid`; der, const-oid, pem-rfc7468 `deny` | **920** (+3 `asm!`): memchr 333, time 272, syn3 81, syn2 71, deranged 71, minimal-lexical 42 (+2 asm!), num-bigint 8 (+1 asm!), time-macros 7, nom 6, data-encoding 6, proc-macro2 6, powerfmt 5, synstructure 4, lazy_static 2, unicode-ident 2, serde_core 2, num-traits 1, thiserror-impl 1; x509-parser, asn1-rs, der-parser, oid-registry `forbid` |
| C/asm sources, build scripts | none / proc-macro2, quote | none / proc-macro2, quote, num-traits, oid-registry, serde_core, thiserror |

The full per-crate tables are `out/audit_x509cert.txt`, `out/audit_x509parser.txt`; trees in
`out/tree_*.txt`. The x509-cert harness enables der's `ber` feature only for the BER variant; the
feature adds no crates.

## 10. Conclusion for E5

**Neither crate can be the reader.** x509-cert, even in its most lenient reachable configuration
(`EncodingRules::Ber` on a `SliceReader`, trailing bytes allowed), rejects 104 inputs `d2i_X509`
accepts, accepts 41 it rejects, and re-encodes 27 of 2,544 commonly-accepted inputs differently;
its BER mode also changes a semantic (SET sorting off) without closing the length/BOOLEAN/time gaps.
x509-parser disagrees on 171 verdicts, truncates a damaged Name instead of failing (which would also
mis-report subjects), and has no encoder at all. So the reader is first-party, as §10 E5 anticipated.
What it must reproduce, each with the families that prove it:

1. **Lengths** (asn1_lib.c:116-152): short form; long form with any number of leading zero octets and
   ≤ 8 significant octets, value ≤ LONG_MAX; `0x80` = indefinite, allowed only on constructed
   elements, terminated by `00 00`. — ber-outer-len2..9, ber-tbs-len1/3/4, ber-name-value-len1,
   ber-name-rdn-len1, ber-name-len2, ber-alg-len2; ber-outer-indef, ber-tbs-indef, ber-subject-indef,
   ber-ext-indef, ber-extseq-indef, ber-version-indef, ber-alg-indef, ber-all-indef. Reject truncation
   and inner lengths exceeding the enclosing element, and content left over inside a SEQUENCE or
   explicit tag — trunc, flip (`too long`, `header too long`, `sequence length mismatch`,
   `explicit length mismatch`, `wrong tag`).
2. **Trailing bytes**: stop at the end of the outer element and ignore the rest; nmap never checks the
   advanced pointer. — ber-trailing-1/1ff/2/100/cert, trailing.
3. **Re-encoding (`i2d_X509`)**: outer SEQUENCE header re-emitted with a minimal definite length;
   tbsCertificate replayed byte-for-byte as received, from its tag through its EOC if indefinite
   (ossl_asn1_enc_save, tasn_dec.c:470; restore, tasn_enc.c:155); signatureAlgorithm re-encoded
   minimal/definite; signature BIT STRING re-emitted with the received unused-bits byte and the last
   octet masked by `0xff << unused`, and `03 01 00` when the content is empty; trailing bytes dropped.
   — every ber-* row's `i2d_eq_input` column; §4 and §6.
4. **BIT STRING**: unused-bits byte ≤ 7 (else reject, `invalid bit string bits left`), at least one
   content octet (else `string too short`), unused ≠ 0 with zero data octets accepted, padding bits
   masked on decode. — ber-sig-unused{1,7}-{clear,set}, ber-sig-unused8, ber-sig-unused1-empty,
   ber-sig-empty, flip (`invalid bit string bits left`).
5. **Constructed strings** (BER): accepted for OCTET STRING and BIT STRING (not INTEGER, BOOLEAN,
   OID, NULL, ENUMERATED), definite or indefinite, nested ≤ 5; contents of the segments are
   concatenated and the result parsed as one primitive, so for a BIT STRING the second segment's
   unused-bits octet becomes a data octet. — ber-sig-constructed, ber-sig-constructed-indef,
   ber-ext-octet-constructed, ber-ext-octet-constructed-indef.
6. **INTEGER** (a_int.c:154-199): reject empty content (`illegal zero content`) and non-minimal
   padding (`00` then < 0x80, `ff` then ≥ 0x80: `illegal padding`); accept negative values and any
   length; version may be any integer (3, 255 → `X509_get_version` 3, 255). — ber-serial-*,
   ber-version-nonmin, serial, version.
7. **BOOLEAN**: any single content octet is accepted; explicitly encoded DEFAULT values (critical
   FALSE, version v1) are accepted and, being inside the tbs, preserved. — ber-bool-true-01,
   ber-bool-false-explicit, version 0, flip x02647/x02683.
8. **Time**: UTCTime (tag 17) and GeneralizedTime (tag 18) contents are not validated at parse time
   at all (empty, `Z`, non-digits, month 13, hour 24, second 60, fractions, offsets, lowercase z all
   accepted); any other tag is rejected (`mstring wrong tag`). What nmap then does with an unparsable
   time (`asn1_time_to_obj`, `nse_ssl_cert.cc`) is downstream of this spike. — utc, gen, flip,
   time-wrongtag.
9. **Name attribute values**: tag must be in B_ASN1_PRINTABLE (NumericString 12, PrintableString 13,
   T61 14, IA5 16, UTF8 0c, UniversalString 1c, BMPString 1e accepted; INTEGER 02, OCTET STRING 04,
   NULL 05, VisibleString 1a rejected with `mstring wrong tag`; non-universal class rejected with
   `mstring not universal`); then the Name canonicalisation validates content: UTF8String must be
   valid UTF-8, BMPString even length, UniversalString length ≡ 0 mod 4, code points legal
   (`illegal characters`). Empty names, duplicate CNs, 300-RDN names, multi-AVA RDNs in any order,
   64/1000/65535/200000-byte values are accepted. — strtype, flip, empty-name, dup-cn, many-rdns,
   multi-rdn, long-cn, ber-rdn-unsorted.
10. **OID**: reject a sub-identifier beginning with `0x80` and a final octet with the continuation bit
    set (`invalid object encoding`); otherwise any arcs and lengths, including `2.999.1` and
    `1.3.6.1.4.1.99999.1.2.3`; unknown signature OIDs give `UNDEF`, unknown SPKI algorithms and
    undecodable keys give "no key" rather than a reject. — ber-oid-nonmin-arc, flip, unknown-oids,
    sigalg 1.2.3.4, spki-unknown-alg, spki-rsa-garbage, spki-ec-explicit-junk.
11. **Nesting**: a 30-level constructed limit (unreachable through the X.509 schema) and a 5-level
    constructed-string limit. — not exercised by the corpus (§11).

If a crate is still wanted for the *typed* view after a first-party BER reader has produced
OpenSSL's re-encoding, x509-cert fed with that re-encoding would still reject the time, version,
serial, OID, UniversalString and BOOLEAN cases above (they survive re-encoding), so it cannot be a
second stage either without a lenient first-party model of those fields.

## 11. Not measured, and why

- Nesting limits (§8) are read from source, not exercised: the corpus has no input deep enough, and
  reaching OpenSSL's 30-level limit through `d2i_X509` is not possible with the X.509 template.
- `d2i_X509` was run on bytes only; the `l_get_ssl_certificate` path (`SSL_get_peer_certificate`)
  adds OpenSSL's TLS-layer handling of the certificate message, which this spike does not cover.
- OpenSSL's C/asm sources were read only at the cited lines; the behavioural claims in §10 rest on
  the oracle's measurements, the citations locate the code.
- x509-cert's `Certificate` was only decoded and re-encoded; field-level values (names, times, keys)
  were not compared with OpenSSL's accessors beyond version/signature-nid/pubkey in the oracle.
- The `ber` feature of der 0.8.2 was measured only through `EncodingRules::Ber` on a `SliceReader`;
  no other tolerant configuration exists in x509-cert 0.3.0 / der 0.8.2 (length minimality,
  BOOLEAN and INTEGER canonicality are unconditional in the source).

## 12. Files (all under this directory) and reproduction

- `ber.tsv` — the 144 added rows; `src/mkber.py` — their generator (run with `python3.12 -I`).
- `c/oracle.c` → `c_oracle.tsv` — the `d2i_X509` oracle and its output (3,020 rows).
- `rs_x509cert/` → `x509cert.tsv` — x509-cert harness (strict, tolerant-DER, tolerant-BER columns,
  re-encoding as hex or `=input`); `rs_x509parser/` → `x509parser.tsv`.
- `src/compare.py` → `out/compare.md` (all four per-family tables with per-class error strings),
  `out/joined.tsv` (one row per input with every verdict and re-encoding flag).
- `src/inspect.py` → `out/inspect_examples.txt` (byte-level view of the examples cited above).
- `out/tree_*.txt`, `out/audit_*.txt` — crate facts. `ossl/` — the OpenSSL 3.0.13 files cited.
- `src/run_all.sh` — the full sequence of commands (sets `CARGO_TARGET_DIR`, deletes it at the end).
