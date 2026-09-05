#!/usr/bin/env python3
"""Generate the S2 minisign/Ed25519 corpus and its golden verdicts.

The oracle here is deliberately *not* this project's code. Every signature in the
corpus is produced by the OpenSSL CLI and then re-checked by it, so what
`core::sigstore::verify` consumes was made by an unrelated implementation. The
golden file records both the oracle's verdict and the verdict this port is
expected to reach, so a row where the two differ is a *visible, reviewed*
divergence rather than a silent one.

Only the Python standard library is used: an Ed25519 private key is just a raw
32-byte seed wrapped in a fixed PKCS#8 DER prefix, which OpenSSL reads directly.
That keeps the harness runnable anywhere OpenSSL 3 exists, with no pip install.

Everything is derived from fixed seeds: no clock, no RNG, no network. Running this
twice produces byte-identical output, which is what lets CI re-derive the corpus
and diff it.
"""

import base64
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
TMP = Path(tempfile.mkdtemp(prefix="s2-minisign-"))

UNTRUSTED = b"untrusted comment: "
TRUSTED = b"trusted comment: "
ALG_PURE = b"Ed"
ALG_PREHASHED = b"ED"

# Curve25519 group order L and field prime p.
L = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19

# A raw Ed25519 seed becomes a PKCS#8 private key by prefixing these bytes, and a
# raw public key becomes a SubjectPublicKeyInfo by prefixing those. Both prefixes
# are fixed by RFC 8410, which is what lets this file drive OpenSSL with no
# key-generation step and therefore no randomness.
PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

# Fixed seeds -> deterministic keys. These are RFC 8032 section 7.1 TEST 1 and
# TEST 2 secret keys, which is what makes the self-check below meaningful.
SEED_A = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
SEED_B = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
KEY_ID_A = bytes.fromhex("1122334455667788")
KEY_ID_B = bytes.fromhex("99aabbccddeeff00")


def _run(args, **kw):
    return subprocess.run(args, capture_output=True, **kw)


def _key_file(seed):
    path = TMP / f"sk-{seed.hex()[:16]}.der"
    if not path.exists():
        path.write_bytes(PKCS8_PREFIX + seed)
    return path


def pk_raw(seed):
    """Derive the 32-byte public key with OpenSSL rather than computing it here."""
    out = _run(["openssl", "pkey", "-in", str(_key_file(seed)), "-inform", "DER",
                "-pubout", "-outform", "DER"])
    if out.returncode != 0:
        raise SystemExit(f"openssl pkey failed: {out.stderr.decode()}")
    return out.stdout[-32:]


def sign(seed, message):
    """Raw Ed25519 signature, produced by OpenSSL."""
    msg = TMP / "msg.bin"
    msg.write_bytes(message)
    out = _run(["openssl", "pkeyutl", "-sign", "-inkey", str(_key_file(seed)),
                "-keyform", "DER", "-rawin", "-in", str(msg)])
    if out.returncode != 0:
        raise SystemExit(f"openssl sign failed: {out.stderr.decode()}")
    return out.stdout


def openssl_verdict(pub, message, signature):
    """Second opinion: does OpenSSL accept this raw Ed25519 signature?"""
    if len(signature) != 64 or len(pub) != 32 or not message:
        return "OPENSSL_NA"
    (TMP / "pub.der").write_bytes(SPKI_PREFIX + pub)
    (TMP / "vmsg.bin").write_bytes(message)
    (TMP / "vsig.bin").write_bytes(signature)
    rc = _run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(TMP / "pub.der"),
               "-keyform", "DER", "-rawin", "-in", str(TMP / "vmsg.bin"),
               "-sigfile", str(TMP / "vsig.bin")]).returncode
    return "OPENSSL_OK" if rc == 0 else "OPENSSL_FAIL"


def self_check():
    """Refuse to emit a corpus unless the toolchain reproduces published vectors.

    RFC 8032 section 7.1 TEST 2 pins both the public key and the signature for a
    known seed and a one-byte message. If OpenSSL here disagrees with the RFC, the
    oracle is broken and nothing it produces is worth diffing against.
    """
    want_pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    want_sig = ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    got_pk = pk_raw(SEED_B).hex()
    got_sig = sign(SEED_B, bytes([0x72])).hex()
    if got_pk != want_pk or got_sig != want_sig:
        raise SystemExit(
            "RFC 8032 self-check FAILED; refusing to emit a corpus\n"
            f"  public key: got {got_pk}\n              want {want_pk}\n"
            f"  signature:  got {got_sig}\n              want {want_sig}"
        )


def b64(data):
    return base64.standard_b64encode(data).decode("ascii")


def pub_line(seed, key_id):
    return b64(ALG_PURE + key_id + pk_raw(seed))


def manifest(serial=41, extra=""):
    return (
        "# nmap-rs signature bundle\n"
        "schema = 1\n"
        f"serial = {serial}\n"
        "released = 2026-08-31\n"
        "\n"
        "file = nmap-os-db\n"
        "version = 41\n"
        "sha256 = " + hashlib.sha256(b"os-db").hexdigest() + "\n"
        "size = 5368132\n"
        + extra
    ).encode("ascii")


def build(
    seed=SEED_A,
    key_id=KEY_ID_A,
    msg=None,
    comment=b"nmap-rs-sig:1\tserial:41",
    untrusted=b"signature from the nmap-rs test key",
    alg=ALG_PURE,
    prehash=False,
    sig_override=None,
    global_override=None,
    comment_after_sign=None,
    trailing_newline=True,
):
    """Assemble a .minisig. Every knob exists to build one specific bad case."""
    if msg is None:
        msg = manifest()
    signed_msg = hashlib.blake2b(msg, digest_size=64).digest() if prehash else msg
    sig = sig_override if sig_override is not None else sign(seed, signed_msg)
    gcomment = comment if comment_after_sign is None else comment_after_sign
    gsig = global_override if global_override is not None else sign(seed, sig + comment)
    body = b"\n".join(
        [
            UNTRUSTED + untrusted,
            b64(alg + key_id + sig).encode("ascii"),
            TRUSTED + gcomment,
            b64(gsig).encode("ascii"),
        ]
    )
    return msg, body + (b"\n" if trailing_newline else b"")


def small_order_r_signature(seed, message):
    """A genuine signature whose R is the identity point.

    Only the key holder can build this, so it is not a forgery — it is a
    *signature-uniqueness* break: a second, different, equally-valid signature over
    the same message. OpenSSL, python-cryptography and ed25519-dalek's non-strict
    `verify` all ACCEPT it; only `verify_strict` refuses. It is in the corpus
    because it is the one case that demonstrates what `verify_strict` actually buys
    over the permissive path, on a signature that is otherwise entirely legitimate.

    With R = identity the equation [s]B = R + [h]A reduces to [s]B = [h]A, which
    holds exactly when s = h*a mod L.
    """
    expanded = hashlib.sha512(seed).digest()
    scalar = bytearray(expanded[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    a = int.from_bytes(scalar, "little")
    A = pk_raw(seed)
    R = bytes([1]) + bytes(31)
    h = int.from_bytes(hashlib.sha512(R + A + message).digest(), "little") % L
    return R + ((h * a) % L).to_bytes(32, "little")


def flip(data, index):
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def denorm_b64(line):
    """Re-spell a base64 line non-canonically by setting an unused trailing bit.

    Only the padded final quad has spare bits, so this changes the spelling
    without changing the bytes it decodes to.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    text = line.decode("ascii")
    pad = text.count("=")
    assert pad in (1, 2), "line has no spare bits to flip"
    at = len(text) - pad - 1
    spare = 2 if pad == 1 else 4
    value = alphabet.index(text[at])
    for candidate in range(64):
        if candidate != value and candidate & ~(spare - 1) == value & ~(spare - 1):
            return (text[:at] + alphabet[candidate] + text[at + 1:]).encode("ascii")
    raise AssertionError("no alternate spelling found")


CASES = []


def case(name, pub, msg, sig_file, expected, note):
    """Record one case plus the oracle's independent opinion of its crypto."""
    raw_pub = base64.standard_b64decode(pub)[10:]
    lines = sig_file.split(b"\n")
    verdict = "OPENSSL_NA"
    if len(lines) > 1 and len(lines[1]) == 100:
        try:
            blob = base64.standard_b64decode(lines[1])
            if len(blob) == 74:
                signed = (
                    hashlib.blake2b(msg, digest_size=64).digest()
                    if blob[:2] == ALG_PREHASHED
                    else msg
                )
                verdict = openssl_verdict(raw_pub, signed, blob[10:])
        except Exception:
            verdict = "OPENSSL_NA"
    CASES.append((name, pub, msg, sig_file, verdict, expected, note))


def decompressable(y):
    """Whether an Ed25519 y coordinate yields a point on the curve."""
    d = (-121665 * pow(121666, P - 2, P)) % P
    u = (y * y - 1) % P
    v = (d * y * y + 1) % P
    x2 = (u * pow(v, P - 2, P)) % P
    return x2 == 0 or pow(x2, (P - 1) // 2, P) == 1


def first_undecompressable():
    y = 2
    while decompressable(y):
        y += 1
    return y.to_bytes(32, "little")


self_check()

PUB_A = pub_line(SEED_A, KEY_ID_A)
PUB_B = pub_line(SEED_B, KEY_ID_B)

# ---------------------------------------------------------------- accepted ----
m, s = build()
case("basic", PUB_A, m, s, "ACCEPT", "well-formed pure-Ed25519 signature")

m, s = build(trailing_newline=False)
case("no_trailing_newline", PUB_A, m, s, "ACCEPT", "final LF is optional")

m, s = build(untrusted=b"")
case("empty_untrusted_comment", PUB_A, m, s, "ACCEPT", "line 1 content is ignored")

m, s = build(untrusted=b"x" * 400)
case("long_untrusted_comment", PUB_A, m, s, "ACCEPT", "line 1 may be long, still ignored")

m, s = build(msg=manifest(extra="\nfile = nmap-service-probes\nversion = 41\nsha256 = "
                               + hashlib.sha256(b"probes").hexdigest() + "\nsize = 2400000\n"))
case("two_file_manifest", PUB_A, m, s, "ACCEPT", "manifest with two file records")

m, s = build(key_id=bytes(8))
case("key_id_mismatch", PUB_A, m, s, "ACCEPT",
     "DIVERGENCE: stock minisign exits on a key-id mismatch; the id only orders attempts here")

m, s = build()
case("crlf_line_endings", PUB_A, m, s.replace(b"\n", b"\r\n"), "ACCEPT",
     "one trailing CR per line is stripped")

# ------------------------------------------------- rejected: cryptographic ----
m, s = build()
case("tampered_manifest", PUB_A, flip(m, 30), s, "REJECT", "one bit flipped in the signed manifest")

m, s = build()
lines = s.split(b"\n")
blob = bytearray(base64.standard_b64decode(lines[1]))
blob[40] ^= 0x01
lines[1] = b64(bytes(blob)).encode("ascii")
case("tampered_signature", PUB_A, m, b"\n".join(lines), "REJECT", "one bit flipped in signature[64]")

m, s = build()
lines = s.split(b"\n")
g = bytearray(base64.standard_b64decode(lines[3]))
g[10] ^= 0x01
lines[3] = b64(bytes(g)).encode("ascii")
case("tampered_global_signature", PUB_A, m, b"\n".join(lines), "REJECT",
     "global signature broken; the message signature is still perfect")

m, s = build(comment_after_sign=b"nmap-rs-sig:1\tserial:99")
case("rewritten_trusted_comment", PUB_A, m, s, "REJECT",
     "serial rewritten after signing: exactly what the global signature exists to stop")

# Bundle A's message signature, wearing bundle B's trusted comment AND B's global
# signature. Both halves are genuine; they just never belonged together. The global
# signature is computed over sig||comment, so it binds one comment to one specific
# signature value and this transplant cannot verify.
_m_a, _s_a = build(comment=b"nmap-rs-sig:1\tserial:41")
_m_b, _s_b = build(msg=manifest(serial=42), comment=b"nmap-rs-sig:1\tserial:42")
_la, _lb = _s_a.split(b"\n"), _s_b.split(b"\n")
case("transplanted_envelope", PUB_A, _m_a,
     b"\n".join([_la[0], _la[1], _lb[2], _lb[3], b""]), "REJECT",
     "a genuine message signature paired with another bundle's genuine trusted "
     "comment and global signature")

m, s = build(seed=SEED_B, key_id=KEY_ID_A)
case("wrong_key", PUB_A, m, s, "REJECT", "signed by a key that is not in the ring")

m, s = build()
lines = s.split(b"\n")
blob = base64.standard_b64decode(lines[1])
sig = blob[10:]
s_val = int.from_bytes(sig[32:], "little")
malleable = sig[:32] + (s_val + L).to_bytes(32, "little")
lines[1] = b64(blob[:10] + malleable).encode("ascii")
case("s_plus_group_order", PUB_A, m, b"\n".join(lines), "REJECT",
     "non-canonical scalar s+L: signature malleability")

m, s = build()
lines = s.split(b"\n")
blob = bytearray(base64.standard_b64decode(lines[1]))
blob[73] |= 0xE0
lines[1] = b64(bytes(blob)).encode("ascii")
case("s_high_bits_set", PUB_A, m, b"\n".join(lines), "REJECT", "s far above the group order")

_msg = manifest()
m, s = build(sig_override=small_order_r_signature(SEED_A, _msg))
case("small_order_r", PUB_A, m, s, "REJECT",
     "DIVERGENCE: a genuine signature with R = identity; every implementation but "
     "verify_strict accepts it")

m, s = build()
case("small_order_key", b64(ALG_PURE + KEY_ID_A + bytes([1]) + bytes(31)), m, s, "REJECT",
     "identity public key: admits signatures for almost any message")

m, s = build()
case("non_canonical_key_y_eq_p", b64(ALG_PURE + KEY_ID_A + P.to_bytes(32, "little")), m, s,
     "REJECT",
     "DIVERGENCE: ed25519-dalek accepts y >= p and a to_bytes() round-trip does not detect it")

m, s = build()
case("non_canonical_key_y_eq_p_plus_18",
     b64(ALG_PURE + KEY_ID_A + (P + 18).to_bytes(32, "little")), m, s, "REJECT",
     "DIVERGENCE: y = 2^255-1 aliases to y = 18, a FULL-ORDER point. Unlike y = p it "
     "is not small-order, so verify_strict does not reject it — this is the vector "
     "that fails if the explicit y < p check is ever removed as redundant")

m, s = build()
case("undecompressable_key", b64(ALG_PURE + KEY_ID_A + first_undecompressable()), m, s,
     "REJECT", "public key bytes are not a curve point")

# ---------------------------------------------------- rejected: structural ----
m, s = build(alg=ALG_PREHASHED, prehash=True)
case("prehashed_mode", PUB_A, m, s, "REJECT",
     "DIVERGENCE: minisign's BLAKE2b prehash is a genuine signature but is refused")

m, s = build()
lines = s.split(b"\n")
lines[1] = denorm_b64(lines[1])
case("non_canonical_b64_signature", PUB_A, m, b"\n".join(lines), "REJECT",
     "DIVERGENCE: same 74 bytes, different spelling; stock minisign accepts 4 of these")

m, s = build()
lines = s.split(b"\n")
lines[3] = denorm_b64(lines[3])
case("non_canonical_b64_global", PUB_A, m, b"\n".join(lines), "REJECT",
     "DIVERGENCE: same 64 bytes, different spelling; stock minisign accepts 16 of these")

m, s = build()
case("appended_junk", PUB_A, m, s + b"and one more thing\n", "REJECT",
     "DIVERGENCE: stock minisign reads four lines and ignores whatever follows")

m, s = build()
case("missing_global_signature", PUB_A, m, b"\n".join(s.split(b"\n")[:3]) + b"\n", "REJECT",
     "three lines: signify semantics, with the trusted comment unauthenticated")

m, s = build()
case("stray_carriage_return", PUB_A, m, s.replace(b"comment: ", b"comment:\r "), "REJECT",
     "CR anywhere but immediately before the LF")

m, s = build(comment=b"nmap-rs-sig:1\tserial:41\tlog:example")
case("unknown_envelope_field", PUB_A, m, s, "REJECT",
     "an unrecognised signed field may be intent we would be discarding")

m, s = build(comment=b"nmap-rs-sig:2\tserial:41")
case("envelope_too_new", PUB_A, m, s, "REJECT", "a newer envelope grammar than this build knows")

m, s = build(comment=b"nmap-rs-sig:1\tserial:99")
case("serial_mismatch", PUB_A, m, s, "REJECT", "envelope and manifest disagree on the serial")

m, s = build(comment=b"serial:41\tnmap-rs-sig:1")
case("envelope_version_not_first", PUB_A, m, s, "REJECT", "the version field is ordered first")

m, s = build(comment=b"nmap-rs-sig:1\tserial:41\tserial:41")
case("duplicate_envelope_field", PUB_A, m, s, "REJECT", "a field appearing twice")

m, s = build(comment=b"nmap-rs-sig:1")
case("envelope_missing_serial", PUB_A, m, s, "REJECT", "serial is required in v1")

m, s = build()
lines = s.split(b"\n")
lines[1] = lines[1].replace(b"+", b"-").replace(b"/", b"_")
case("url_safe_b64", PUB_A, m, b"\n".join(lines), "REJECT",
     "URL-safe alphabet: two spellings of one signature")

m, s = build()
lines = s.split(b"\n")
lines[1] = lines[1].rstrip(b"=")
case("unpadded_b64", PUB_A, m, b"\n".join(lines), "REJECT", "padding is mandatory")

m, s = build()
lines = s.split(b"\n")
lines[1] = lines[1][:-4]
case("short_signature_line", PUB_A, m, b"\n".join(lines), "REJECT", "line 2 is exactly 100 characters")

m, s = build()
case("bad_untrusted_prefix", PUB_A, m, s.replace(UNTRUSTED, b"untrusted-comment: ", 1), "REJECT",
     "line 1 prefix is exact")

m, s = build()
case("bad_trusted_prefix", PUB_A, m, s.replace(TRUSTED, b"trusted-comment: ", 1), "REJECT",
     "line 3 prefix is exact")

m, s = build(comment=b"nmap-rs-sig:1\tserial:41\xc3\xa9")
case("non_ascii_trusted_comment", PUB_A, m, s, "REJECT",
     "DIVERGENCE: stock minisign permits UTF-8; homoglyphs beside the word `verified` are a spoof")

m, s = build(comment=b"nmap-rs-sig:1\tserial:" + b"0" * 300 + b"41")
case("oversized_trusted_comment", PUB_A, m, s, "REJECT", "over the 256-byte cap")

m, s = build()
case("empty_input", PUB_A, m, b"", "REJECT", "no lines at all")

m, s = build()
case("giant_input", PUB_A, m, b"untrusted comment: " + b"A" * 8192, "REJECT", "over MAX_SIG_LEN")

# -------------------------------------------------------------------- emit ----
cases_path = OUT / "minisign_cases.txt"
golden_path = OUT / "minisign_golden.txt"
with cases_path.open("w") as cf, golden_path.open("w") as gf:
    cf.write("# name\tpubkey_b64\tmanifest_hex\tminisig_hex\tnote\n")
    cf.write("# Generated by oracle/gen_minisign_cases.py. Do not edit by hand.\n")
    gf.write("# name\toracle\texpected\n")
    gf.write("# `oracle` is the OpenSSL CLI's independent verdict on the raw Ed25519\n")
    gf.write("# signature. A row with OPENSSL_OK / REJECT is a deliberate divergence:\n")
    gf.write("# the signature is genuine and this port refuses it anyway, on purpose.\n")
    for name, pub, msg, sig_file, oracle, expected, note in CASES:
        cf.write(f"{name}\t{pub}\t{msg.hex()}\t{sig_file.hex()}\t{note}\n")
        gf.write(f"{name}\t{oracle}\t{expected}\n")


# --------------------------------------------------------------- fixtures ----
# A handful of cases are also emitted as Rust consts so the unit tests inside
# `core::sigstore::verify` can use real signatures. Those tests run under Miri,
# where the filesystem is unavailable, so they must arrive through `include!`
# at compile time rather than be read at run time. Emitting them from the same
# generator that builds the corpus is what stops the two from drifting apart.
FIXTURES = [
    ("BASIC", "basic"),
    ("TAMPERED_GLOBAL", "tampered_global_signature"),
    ("REWRITTEN_COMMENT", "rewritten_trusted_comment"),
    ("WRONG_KEY", "wrong_key"),
    ("S_PLUS_L", "s_plus_group_order"),
    ("PREHASHED", "prehashed_mode"),
    ("NON_CANONICAL_B64", "non_canonical_b64_signature"),
    ("APPENDED_JUNK", "appended_junk"),
    ("SERIAL_MISMATCH", "serial_mismatch"),
    ("ENVELOPE_TOO_NEW", "envelope_too_new"),
    ("UNKNOWN_FIELD", "unknown_envelope_field"),
    ("CRLF", "crlf_line_endings"),
    ("KEY_ID_MISMATCH", "key_id_mismatch"),
    ("MISSING_GLOBAL", "missing_global_signature"),
    ("SMALL_ORDER_R", "small_order_r"),
    ("TRANSPLANT", "transplanted_envelope"),
]
FIXTURE_KEYS = [
    ("PUB_A", "basic"),
    ("PUB_SMALL_ORDER", "small_order_key"),
    ("PUB_NON_CANONICAL", "non_canonical_key_y_eq_p"),
    ("PUB_NON_CANONICAL_FULL_ORDER", "non_canonical_key_y_eq_p_plus_18"),
    ("PUB_UNDECOMPRESSABLE", "undecompressable_key"),
]


def rust_bytes(data):
    """A Rust byte-string literal that is safe to paste into source."""
    out = []
    for byte in data:
        char = chr(byte)
        if char in ('"', "\\"):
            out.append("\\" + char)
        elif 0x20 <= byte < 0x7F:
            out.append(char)
        else:
            out.append(f"\\x{byte:02x}")
    return 'b"' + "".join(out) + '"'


by_name = {c[0]: c for c in CASES}
fixtures = OUT / "minisign_fixtures.rs"
with fixtures.open("w") as fx:
    fx.write("// @generated by tests/differential/s/oracle/gen_minisign_cases.py\n")
    fx.write("// Regenerate with tests/differential/s/regen_minisign.sh; CI re-derives\n")
    fx.write("// this file and fails if it differs, so it cannot drift from the corpus.\n")
    fx.write("//\n")
    fx.write("// Every signature here was produced by the OpenSSL CLI, not by this crate.\n")
    fx.write("\n")
    for const, name in FIXTURE_KEYS:
        fx.write(f'pub const {const}: &str = "{by_name[name][1]}";\n')
    fx.write("\n")
    fx.write(f"pub const MANIFEST: &[u8] = {rust_bytes(by_name['basic'][2])};\n")
    fx.write(f"pub const MANIFEST_TAMPERED: &[u8] = {rust_bytes(by_name['tampered_manifest'][2])};\n")
    fx.write(f"pub const MANIFEST_TWO_FILES: &[u8] = {rust_bytes(by_name['two_file_manifest'][2])};\n")
    fx.write(f"pub const SIG_TWO_FILES: &[u8] = {rust_bytes(by_name['two_file_manifest'][3])};\n")
    fx.write("\n")
    for const, name in FIXTURES:
        fx.write(f"pub const SIG_{const}: &[u8] = {rust_bytes(by_name[name][3])};\n")
print(f"fixtures -> {fixtures.name}")

import shutil
shutil.rmtree(TMP, ignore_errors=True)
print(f"{len(CASES)} cases -> {cases_path.name}, {golden_path.name}")
