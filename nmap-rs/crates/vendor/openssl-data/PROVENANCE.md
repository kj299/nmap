# Provenance — OpenSSL data tables (vendored)

`core::nse::openssl::objects` names an object as OpenSSL 3.0.13 does: the long
name a certificate subject key gets (`OBJ_nid2ln`), the dotted text of an OID
OpenSSL has no name for, and the NID an OID's DER maps to (`OBJ_obj2nid`).
`core::nse::openssl::ec` knows OpenSSL's 82 built-in curves: their numbers,
which decide whether a certificate's EC key is a valid point and which curve
explicit parameters are, and their names (`OSSL_EC_curve_nid2name`).
`core::nse::openssl::err` prints OpenSSL's error codes as `ERR_error_string`
does, for the libraries the certificate code raises from. The three tables
are OpenSSL's data, so they are generated from OpenSSL's own source
rather than written by hand (D11, `docs/M6.5-ANALYSIS.md` §9 and §14.4).

| | |
|---|---|
| upstream | <https://github.com/openssl/openssl>, release `openssl-3.0.13` |
| tarball | `openssl-3.0.13.tar.gz`, sha256 `88525753f79d3bec27d2fa7c66aa0b92b3aa9498dafd93d7cfa4b3780cdae313` |
| files | `crypto/objects/objects.txt`, `crypto/objects/obj_mac.num`, `crypto/ec/ec_curve.c`, `crypto/evp/ec_support.c`, `crypto/err/openssl.txt`, `crypto/err/err.c`, `LICENSE.txt`, unchanged |
| license | Apache-2.0 (`LICENSE.txt`, `NOTICE`) |
| generated | `crates/core/src/nse/openssl/objects_table.rs`, `curves_table.rs` and `errors_table.rs`, by `gen.py` (rustfmt skips them: `#[rustfmt::skip]` on their `mod` lines) |
| local changes | none |

The sha256 of each file as committed:

```
097d3e0e0d50873c2e8320366ef6d4efde70eeee193a8bdbc80348cb25761b9c  objects.txt
41e850a05c349fb489e1ef08916e9a9e75ede234c25298f85bf89ae7c85032d2  obj_mac.num
4220c6c7a508cf023e94612fc5622d41e5f931c7572e49001e8f2b07a0f69c20  ec_curve.c
a02d33c2a012fff1f356440685af5ca80071c39f5af83575a2a812e01c3a6233  ec_support.c
9eac6fc37488d397e677a71ee2f91641f6d7248778e9e8f72d064bb757cbe105  openssl.txt
c8804a5e699b97a83e99066495d79105546bb4e7ae9538955c8d68e6e1b92c0d  err.c
7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a  LICENSE.txt
```

## Why 3.0.13

It is the libcrypto nmap 7.94 runs on in the oracle (the golden's header,
`tests/differential/m6/m65_golden.txt`). OpenSSL adds objects between
releases; a newer table would name OIDs 7.94 prints as dotted numbers.

## How the table is checked

`gen.py` is `objects.pl` and `obj_dat.pl` in Python. Three checks, the first
in CI:

- `gen.py --check`: `objects_table.rs` is what `gen.py` writes from these
  files.
- `gen.py --check-obj-dat OBJ_DAT_H`: every NID's short name, long name and DER
  equal `crypto/objects/obj_dat.h`, the table OpenSSL generated from the same
  files with its own Perl. All 1,248 do.
- `gen.py --check-libcrypto`: the installed `libcrypto.so.3`, refused unless
  it is 3.0.13, answers `OBJ_nid2sn`, `OBJ_nid2ln`, `OBJ_obj2txt` and
  `OBJ_obj2nid` as the table does, for every NID and every OID, and builds
  the same curves: `EC_get_builtin_curves`' list in the same order, and for
  each its field type, prime or polynomial, coefficients, generator, order,
  cofactor, seed and `OSSL_EC_curve_nid2name`, and prints every error code
  of the table as `ERR_error_string_n` does. All do.

Two quirks the Perl has and the table keeps: an `!Alias` that `obj_mac.num`
numbers (`ccitt` 404, `joint_iso_ccitt` 393) is named `"NULL"` twice, and a
DER two NIDs share (`1.3`, `org` 379 and `identified-organization` 676)
maps to the lower, as `OBJ_obj2nid`'s search finds it.

## Re-deriving

```
tar -xzf openssl-3.0.13.tar.gz
cp openssl-3.0.13/crypto/objects/{objects.txt,obj_mac.num} openssl-3.0.13/crypto/ec/ec_curve.c \
   openssl-3.0.13/crypto/evp/ec_support.c openssl-3.0.13/crypto/err/{openssl.txt,err.c} \
   openssl-3.0.13/LICENSE.txt .
python3 -I -B gen.py
python3 -I -B gen.py --check-obj-dat openssl-3.0.13/crypto/objects/obj_dat.h
python3 -I -B gen.py --check-libcrypto
```
