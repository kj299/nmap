#!/usr/bin/env python3
"""OpenSSL's object and curve tables, for `core::nse::openssl::objects` and
`core::nse::openssl::ec` (D11).

    python3 -I -B gen.py                 write ../../core/src/nse/openssl/objects_table.rs
                                         and curves_table.rs
    python3 -I -B gen.py --check         FAIL unless those files are what this writes
    python3 -I -B gen.py --check-obj-dat OBJ_DAT_H
                                         FAIL unless every NID's short name, long
                                         name and DER equal OpenSSL's own generated
                                         crypto/objects/obj_dat.h
    python3 -I -B gen.py --check-libcrypto
                                         FAIL unless the installed libcrypto.so.3
                                         answers OBJ_nid2sn, OBJ_nid2ln,
                                         OBJ_obj2txt(no_name=1) and OBJ_obj2nid as
                                         the object table does, and lists the same
                                         built-in curves with the same parameters
                                         and names as the curve table

The inputs are OpenSSL 3.0.13's `crypto/objects/objects.txt`, `obj_mac.num`,
`crypto/ec/ec_curve.c` and `crypto/evp/ec_support.c`, committed next to this
script under their own licence (Apache-2.0: LICENSE.txt, NOTICE). The curves
are `ec_curve.c`'s non-FIPS `curve_list` (each curve once: its `#if` branches
differ only in the implementation method) and their data blocks; the names
are `ec_support.c`'s `curve_list`, `OSSL_EC_curve_nid2name`'s table. This is the two Perl generators OpenSSL builds its table with, in
Python: `objects.pl` (names, NIDs, OIDs; aliases, `!module`, `!Cname`, NIDs
from obj_mac.num and then numbered on) and `obj_dat.pl` (a missing short name
is the long name and the reverse; an OID with fewer than two arcs has no DER;
the first two arcs are one octet, 40*a+b).
"""
import ctypes
import ctypes.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "core", "src", "nse", "openssl", "objects_table.rs")
OUT_CURVES = os.path.join(HERE, "..", "..", "core", "src", "nse", "openssl", "curves_table.rs")


def objects():
    """{nid: (sn, ln, arcs or None)} as objects.pl then obj_dat.pl make it."""
    return objects_and_cnames()[0]


def objects_and_cnames():
    """objects(), and {C name: nid} (`NID_<C name>`)."""
    nid = {}
    nidn = {}
    max_nid = 0
    with open(os.path.join(HERE, "obj_mac.num"), encoding="ascii") as f:
        for line in f:
            line = re.sub(r"#.*$", "", line.rstrip("\r\n"))
            if not line.strip():
                continue
            cname, num = ("X" + line).split()
            cname, num = cname[1:], int(num)
            assert num not in nidn and cname not in nid, line
            nid[cname] = num
            nidn[num] = cname
            max_nid = max(max_nid, num)

    obj = {}  # Cname -> list of arcs (ints), or [] for none
    comma = {}  # Cname -> whether objects.pl's OBJ_ text has a comma (obj_dat.pl's DER test)
    sn, ln = {}, {}
    defined = {"undef"}  # obj_mac.h's hand-written head defines NID_undef
    module = ""
    cname = ""
    with open(os.path.join(HERE, "objects.txt"), encoding="ascii") as f:
        for line in f:
            line = line.rstrip("\r\n")
            m = re.match(r"^!module\s+(.*)$", line)
            if m:
                module = (m.group(1) + "-").replace(".", "_").replace("-", "_")
            if re.match(r"^!global$", line):
                module = ""
            m = re.match(r"^!Cname\s+(.*)$", line)
            if m:
                cname = m.group(1)
            m = re.match(r"^!Alias\s+(.+?)\s+(.*)$", line)
            if m:
                c = (module + m.group(1)).replace("-", "_")
                obj[c], comma[c] = process_oid(m.group(2), obj)
                defined.add(c)
                line = ""
                cname = ""
            line = re.sub(r"!.*$", "", line)
            line = re.sub(r"#.*$", "", line)
            if not line.strip():
                continue
            parts = line.split(":")
            parts += [""] * (3 - len(parts))
            myoid, mysn, myln = (p.strip() for p in parts[:3])
            arcs, has_comma = process_oid(myoid, obj) if myoid else ([], False)
            if cname == "" and re.match(r"^[_A-Za-z][\w.-]*$", myln):
                cname = myln.replace(".", "_").replace("-", "_")
            if cname == "":
                cname = mysn.replace("-", "_")
            if cname == "":
                cname = myln.replace("-", "_").replace(".", "_").replace(" ", "_")
            cname = module + cname.replace(".", "_").replace("-", "_")
            sn[cname], ln[cname], obj[cname], comma[cname] = mysn, myln, arcs, has_comma
            defined.add(cname)
            if cname not in nid:
                max_nid += 1
                nid[cname] = max_nid
                nidn[max_nid] = cname
            cname = ""

    table = {}
    for n in range(max(nidn) + 1):
        c = nidn.get(n)
        if c is None or c not in defined:
            continue
        s, l = sn.get(c) or None, ln.get(c) or None
        if c == "undef":  # obj_mac.h's hand-written head: SN_undef, LN_undef
            s, l = "UNDEF", "undefined"
        # obj_dat.pl: a missing name is the other one, and with neither (an
        # !Alias that obj_mac.num numbers: ccitt, joint_iso_ccitt) both are
        # the text "NULL".
        s, l = s or l or "NULL", l or s or "NULL"
        table[n] = (s, l, obj[c] if comma.get(c) else None)
    return table, {c: nid[c] for c in defined if c in nid}


def curves():
    """[(nid, char2, seed, p, a, b, x, y, order, cofactor)] in curve_list order,
    and [(name, nid)] from ec_support.c."""
    _, cnames = objects_and_cnames()
    src = open(os.path.join(HERE, "ec_curve.c"), encoding="ascii").read()
    data = {}
    for m in re.finditer(r"\}\s*(_EC_\w+)\s*=\s*\{\s*\{\s*NID_(\w+),\s*(\d+),\s*(\d+),\s*(\w+)\s*\},\s*\{(.*?)\}\s*\};", src, re.S):
        name, field, seed_len, plen, cof, body = m.groups()
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
        b = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body))
        seed_len, plen = int(seed_len), int(plen)
        assert len(b) == seed_len + 6 * plen, name
        parts = [b[seed_len + i * plen: seed_len + (i + 1) * plen] for i in range(6)]
        data[name] = (field == "X9_62_characteristic_two_field", b[:seed_len], parts, int(cof, 0))
    first_list = src.index("static const ec_list_element curve_list")
    fips_else = src.index("#else", src.rindex("#ifdef FIPS_MODULE", 0, first_list))
    section = src[fips_else:src.index("#endif /* FIPS_MODULE */", fips_else)]
    out, seen = [], set()
    for nidname, dname in re.findall(r"\{NID_(\w+),\s*&(_EC_\w+)\.h", section):
        n = cnames[nidname]
        if n in seen:
            continue
        seen.add(n)
        char2, seed, (p, a, b, x, y, order), cof = data[dname]
        out.append((n, char2, seed, p, a, b, x, y, order, cof))
    sup = open(os.path.join(HERE, "ec_support.c"), encoding="ascii").read()
    body = sup[sup.index("curve_list[] = {"):]
    body = body[:body.index("};")]
    names = [(nm, cnames[c]) for nm, c in re.findall(r'\{"([^"]+)",\s*NID_(\w+)\s*\}', body)]
    return out, names


def render_curves(cs, names):
    def hx(b):
        return "&[" + ", ".join("0x%02x" % x for x in b) + "]"
    rows = []
    for n, char2, seed, p, a, b, x, y, order, cof in cs:
        rows.append("    Curve { nid: %d, char2: %s, seed: %s,\n        p: %s,\n        a: %s,\n        b: %s,\n        x: %s,\n        y: %s,\n        order: %s,\n        cofactor: %d },"
                    % (n, "true" if char2 else "false", hx(seed), hx(p), hx(a), hx(b), hx(x), hx(y), hx(order), cof))
    nm = "\n".join("    (%s, %d)," % (rust_str(a), b) for a, b in names)
    return (
        "// Generated by crates/vendor/openssl-data/gen.py from OpenSSL 3.0.13's\n"
        "// crypto/ec/ec_curve.c and crypto/evp/ec_support.c (Apache-2.0:\n"
        "// crates/vendor/openssl-data/NOTICE). Do not edit; `gen.py --check` refuses a\n"
        "// hand edit.\n\n"
        "use super::ec::Curve;\n\n"
        "/// The built-in curves (`ec_curve.c`'s `curve_list`), in its order: the\n"
        "/// field (a prime `p`, or for a binary field the reduction polynomial's\n"
        "/// bits), the coefficients, the generator, its order and the cofactor, all\n"
        "/// big-endian as `ec_curve.c` holds them.\n"
        "pub(super) static CURVES: [Curve; %d] = [\n%s\n];\n\n"
        "/// `OSSL_EC_curve_nid2name`'s table (`ec_support.c`), in its order: the\n"
        "/// first name listed for a NID is the one it returns.\n"
        "pub(super) static CURVE_NAMES: [(&str, u16); %d] = [\n%s\n];\n"
        % (len(cs), "\n".join(rows), len(names), nm)
    )


def process_oid(text, obj):
    """The arcs, and whether objects.pl's text for them has a comma: obj_dat.pl
    gives an object DER only then, so an alias of a bare `OBJ_x` has none."""
    a = text.split()
    pref = None
    if not re.match(r"^[0-9]+$", a[0]):
        key = a[0].replace("-", "_")
        assert key in obj, "undefined identifier " + a[0]
        pref = obj[key]
        a = a[1:]
    local = [int(x) for x in a]
    has_comma = len(local) >= 2 or (pref is not None and len(local) >= 1)
    return (pref or []) + local, has_comma


def der(arcs):
    out = bytearray([arcs[0] * 40 + arcs[1]])
    for v in arcs[2:]:
        r = [v & 0x7F]
        v >>= 7
        while v:
            r.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(r))
    return bytes(out)


def lookup(table):
    """{DER: NID}, as OBJ_obj2nid answers. Two NIDs share a DER (1.3: org and
    identified-organization); OpenSSL's sorted obj_objs lists the lower first
    and its bsearch finds it, which --check-libcrypto confirms."""
    out = {}
    for n in sorted(table):
        if table[n][2]:
            out.setdefault(der(table[n][2]), n)
    return out


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(table):
    n = max(table) + 1
    rows = []
    for i in range(n):
        if i not in table:
            rows.append("    Object { sn: \"\", ln: \"\", der: &[] },")
            continue
        s, l, arcs = table[i]
        d = ", ".join("0x%02x" % b for b in der(arcs)) if arcs else ""
        rows.append("    Object { sn: %s, ln: %s, der: &[%s] }," % (rust_str(s or ""), rust_str(l or ""), d))
    by_der = sorted(lookup(table).values(), key=lambda i: der(table[i][2]))
    return (
        "// Generated by crates/vendor/openssl-data/gen.py from OpenSSL 3.0.13's\n"
        "// objects.txt and obj_mac.num (Apache-2.0: crates/vendor/openssl-data/NOTICE).\n"
        "// Do not edit; `gen.py --check` refuses a hand edit.\n\n"
        "use super::objects::Object;\n\n"
        "/// Every NID's short name, long name and DER content octets, indexed by NID\n"
        "/// (`nid_objs`, crypto/objects/obj_dat.h). A NID OpenSSL leaves unassigned\n"
        "/// has empty names.\n"
        "pub(super) static OBJECTS: [Object; %d] = [\n%s\n];\n\n"
        "/// The NIDs that have an OID, sorted by its DER content octets.\n"
        "pub(super) static BY_DER: [u16; %d] = [\n%s\n];\n"
        % (n, "\n".join(rows), len(by_der), wrap(by_der))
    )


def wrap(nums):
    out, line = [], "   "
    for x in nums:
        piece = " %d," % x
        if len(line) + len(piece) > 99:
            out.append(line)
            line = "   "
        line += piece
    out.append(line)
    return "\n".join(out)


def check_obj_dat(path, table):
    src = open(path, encoding="ascii").read()
    so = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-F]{2})",
               src[src.index("static const unsigned char so["):src.index("#define NUM_NID")]))
    body = src[src.index("nid_objs[NUM_NID]"):]
    body = body[:body.index("};")]
    entries = re.findall(r'\{\s*(NULL|"((?:[^"\\]|\\.)*)"),\s*(NULL|"((?:[^"\\]|\\.)*)"),\s*NID_\w+(?:,\s*(\d+),\s*&so\[(\d+)\])?\s*\}', body)
    bad = 0
    for n, (snr, s, lnr, l, ln_, off) in enumerate(entries):
        want = (None if snr == "NULL" else s, None if lnr == "NULL" else l,
                so[int(off):int(off) + int(ln_)] if ln_ else None)
        got = table.get(n)
        got = (got[0], got[1], der(got[2]) if got[2] else None) if got else (None, None, None)
        if want != got:
            bad += 1
            if bad <= 10:
                print("obj_dat.h NID %d: %r, table %r" % (n, want, got), file=sys.stderr)
    if len(entries) != max(table) + 1:
        bad += 1
        print("obj_dat.h has %d NIDs, the table %d" % (len(entries), max(table) + 1), file=sys.stderr)
    return bad, len(entries)


def check_libcrypto(table):
    lib = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so.3")
    lib.OpenSSL_version.restype = ctypes.c_char_p
    lib.OBJ_nid2sn.restype = ctypes.c_char_p
    lib.OBJ_nid2ln.restype = ctypes.c_char_p
    lib.OBJ_nid2obj.restype = ctypes.c_void_p
    lib.OBJ_obj2txt.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    version = lib.OpenSSL_version(0).decode()
    if not version.startswith("OpenSSL 3.0.13 "):
        print("libcrypto is %s, not 3.0.13" % version, file=sys.stderr)
        return 1, 0
    lib.OBJ_txt2obj.restype = ctypes.c_void_p
    lib.OBJ_txt2obj.argtypes = [ctypes.c_char_p, ctypes.c_int]
    lib.OBJ_obj2nid.argtypes = [ctypes.c_void_p]
    lib.ASN1_OBJECT_free.argtypes = [ctypes.c_void_p]
    bad = 0
    for d, n in lookup(table).items():
        o = lib.OBJ_txt2obj(".".join(map(str, table[n][2])).encode(), 1)
        got = lib.OBJ_obj2nid(o)
        lib.ASN1_OBJECT_free(o)
        if got != n:
            bad += 1
            print("libcrypto OBJ_obj2nid(%s) = %d, table %d" % (d.hex(), got, n), file=sys.stderr)
    buf = ctypes.create_string_buffer(512)
    for n in range(max(table) + 1):
        s, l, arcs = table.get(n, (None, None, None))
        got_sn, got_ln = lib.OBJ_nid2sn(n), lib.OBJ_nid2ln(n)
        got_sn = got_sn.decode() if got_sn is not None else None
        got_ln = got_ln.decode() if got_ln is not None else None
        o = lib.OBJ_nid2obj(n)
        dotted = None
        if o and arcs:
            k = lib.OBJ_obj2txt(buf, 512, o, 1)
            dotted = buf.value.decode() if k > 0 else ""
        want = (s, l, ".".join(map(str, arcs)) if arcs else None)
        if (got_sn, got_ln, dotted) != want:
            bad += 1
            if bad <= 10:
                print("libcrypto NID %d: %r, table %r" % (n, (got_sn, got_ln, dotted), want), file=sys.stderr)
    return bad, max(table) + 1


def check_curves_libcrypto(cs, names):
    """Each built-in curve as libcrypto builds it: the same list in the same
    order (EC_get_builtin_curves), and per curve the field type, p (or the
    polynomial), a, b, generator, order, cofactor and seed, and the name
    OSSL_EC_curve_nid2name gives."""
    lib = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so.3")
    vp = ctypes.c_void_p
    for f, res, args in [
        ("EC_get_builtin_curves", ctypes.c_size_t, [vp, ctypes.c_size_t]),
        ("EC_GROUP_new_by_curve_name", vp, [ctypes.c_int]),
        ("EC_GROUP_get_curve", ctypes.c_int, [vp, vp, vp, vp, vp]),
        ("EC_GROUP_get0_generator", vp, [vp]),
        ("EC_POINT_get_affine_coordinates", ctypes.c_int, [vp, vp, vp, vp, vp]),
        ("EC_GROUP_get0_order", vp, [vp]),
        ("EC_GROUP_get0_cofactor", vp, [vp]),
        ("EC_GROUP_get0_seed", ctypes.POINTER(ctypes.c_ubyte), [vp]),
        ("EC_GROUP_get_seed_len", ctypes.c_size_t, [vp]),
        ("EC_GROUP_get_field_type", ctypes.c_int, [vp]),
        ("EC_GROUP_free", None, [vp]),
        ("BN_new", vp, []),
        ("BN_free", None, [vp]),
        ("BN_bn2hex", ctypes.c_char_p, [vp]),
        ("OSSL_EC_curve_nid2name", ctypes.c_char_p, [ctypes.c_int]),
    ]:
        fn = getattr(lib, f)
        fn.restype, fn.argtypes = res, args

    class Item(ctypes.Structure):
        _fields_ = [("nid", ctypes.c_int), ("comment", ctypes.c_char_p)]

    n = lib.EC_get_builtin_curves(None, 0)
    items = (Item * n)()
    lib.EC_get_builtin_curves(items, n)
    bad = 0
    if [i.nid for i in items] != [c[0] for c in cs]:
        bad += 1
        print("libcrypto lists %d curves, the table %d, or in another order" % (n, len(cs)), file=sys.stderr)

    def hexof(bn):
        return int(lib.BN_bn2hex(bn).decode() or "0", 16)

    for nid, char2, seed, p, a, b, x, y, order, cof in cs:
        g = lib.EC_GROUP_new_by_curve_name(nid)
        bns = [lib.BN_new() for _ in range(5)]
        lib.EC_GROUP_get_curve(g, bns[0], bns[1], bns[2], None)
        lib.EC_POINT_get_affine_coordinates(g, lib.EC_GROUP_get0_generator(g), bns[3], bns[4], None)
        got = [hexof(v) for v in bns] + [hexof(lib.EC_GROUP_get0_order(g)), hexof(lib.EC_GROUP_get0_cofactor(g))]
        want = [int.from_bytes(v, "big") for v in (p, a, b, x, y, order)] + [cof]
        sl = lib.EC_GROUP_get_seed_len(g)
        gseed = bytes(lib.EC_GROUP_get0_seed(g)[:sl]) if sl else b""
        ftype = lib.EC_GROUP_get_field_type(g)
        if got != want or gseed != seed or ftype != (407 if char2 else 406):
            bad += 1
            print("libcrypto curve %d differs from the table" % nid, file=sys.stderr)
        for v in bns:
            lib.BN_free(v)
        lib.EC_GROUP_free(g)
    for nid in sorted({n for _, n in names}):
        want = next(nm for nm, k in names if k == nid)
        got = lib.OSSL_EC_curve_nid2name(nid)
        if got is None or got.decode() != want:
            bad += 1
            print("libcrypto names curve %d %r, the table %r" % (nid, got, want), file=sys.stderr)
    return bad


def main(argv):
    table = objects()
    text = render(table)
    cs, names = curves()
    ctext = render_curves(cs, names)
    if argv[1:2] == ["--check"]:
        if open(OUT, encoding="utf-8").read() != text:
            sys.exit("FAIL: objects_table.rs is not what gen.py writes; run gen.py")
        if open(OUT_CURVES, encoding="utf-8").read() != ctext:
            sys.exit("FAIL: curves_table.rs is not what gen.py writes; run gen.py")
        print("openssl data: objects_table.rs (%d NIDs) and curves_table.rs (%d curves) current"
              % (max(table) + 1, len(cs)))
    elif argv[1:2] == ["--check-obj-dat"]:
        bad, n = check_obj_dat(argv[2], table)
        if bad:
            sys.exit("FAIL: %d NIDs differ from obj_dat.h" % bad)
        print("openssl objects: all %d NIDs equal obj_dat.h" % n)
    elif argv[1:2] == ["--check-libcrypto"]:
        bad, n = check_libcrypto(table)
        if bad:
            sys.exit("FAIL: %d NIDs differ from libcrypto" % bad)
        print("openssl objects: all %d NIDs equal libcrypto 3.0.13" % n)
        bad = check_curves_libcrypto(cs, names)
        if bad:
            sys.exit("FAIL: %d curve facts differ from libcrypto" % bad)
        print("openssl curves: all %d curves and %d names equal libcrypto 3.0.13" % (len(cs), len(names)))
    elif len(argv) == 1:
        with open(OUT, "w", encoding="utf-8") as f:
            f.write(text)
        with open(OUT_CURVES, "w", encoding="utf-8") as f:
            f.write(ctext)
        print("wrote %s (%d NIDs) and %s (%d curves)"
              % (os.path.relpath(OUT), max(table) + 1, os.path.relpath(OUT_CURVES), len(cs)))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
