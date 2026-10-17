#!/usr/bin/env python3
"""mkber.py - BER-leniency family for E5 (M6.5 x509 spike).
Usage: python3 -I mkber.py <certs.tsv> <ber.tsv>
Bases: x02315 (lib rsa2048), x02321 (lib ec-secp256r1), plus a hand-built 193-byte v1 ed25519
certificate ("mini", body < 256 so the 0x82 00 xx case exists).  Output rows: ID<TAB>family note<TAB>hex,
family = 'ber-<kind>', note = '<kind> <base>'."""
import sys
src, dst = sys.argv[1], sys.argv[2]
rows = {}
with open(src) as f:
    for line in f:
        line = line.rstrip('\n')
        if not line:
            continue
        i, note, h = line.split('\t')
        rows[i] = (note, bytes.fromhex(h))

def tlv(b, i=0):
    tag = b[i]; l = b[i + 1]; j = i + 2
    assert l != 0x80, "definite lengths only"
    if l & 0x80:
        n = l & 0x7f; L = int.from_bytes(b[j:j + n], 'big'); j += n
    else:
        L = l
    return tag, j, L, j + L

def children(content):
    out = []; i = 0
    while i < len(content):
        t, j, L, e = tlv(content, i); out.append(content[i:e]); i = e
    assert i == len(content)
    return out

def content_of(t):
    _, j, L, e = tlv(t); return t[j:e]

def enc_len(n, nbytes=None):
    if nbytes is None:
        if n < 0x80:
            return bytes([n])
        s = n.to_bytes((n.bit_length() + 7) // 8, 'big'); return bytes([0x80 | len(s)]) + s
    return bytes([0x80 | nbytes]) + n.to_bytes(nbytes, 'big')

def wrap(tag, content, nbytes=None, indef=False):
    if indef:
        return bytes([tag, 0x80]) + content + b'\x00\x00'
    return bytes([tag]) + enc_len(len(content), nbytes) + content

def variants(der, other):
    V = []
    def add(kind, b):
        V.append((kind, b))
    tbs, alg, sig = children(content_of(der))
    assert tbs[0] == 0x30 and alg[0] == 0x30 and sig[0] == 0x03
    tbsc = content_of(tbs)
    parts = children(tbsc)
    idx = {}; k = 0
    if parts[0][0] == 0xa0:
        idx['version'] = 0; k = 1
    for n, name in enumerate(('serial', 'sigalg', 'issuer', 'validity', 'subject', 'spki')):
        idx[name] = k + n
    for n, p in enumerate(parts):
        if p[0] == 0xa3:
            idx['ext'] = n
    def cert(tbs_=None, alg_=None, sig_=None, nbytes=None, indef=False):
        return wrap(0x30, (tbs if tbs_ is None else tbs_) + (alg if alg_ is None else alg_) + (sig if sig_ is None else sig_), nbytes, indef)
    def tbs_with(nbytes=None, indef=False, **repl):
        ps = list(parts)
        for name, val in repl.items():
            ps[idx[name]] = val
        return wrap(0x30, b''.join(ps), nbytes, indef)
    assert cert() == der and tbs_with() == tbs
    minimal_outer = enc_len(len(tbs + alg + sig))
    # (a) outer SEQUENCE, non-minimal definite length (one more octet than minimal, then 3,4,5,8,9 octets)
    for nb in sorted({len(minimal_outer), 3, 4, 5, 8, 9}):
        add('outer-len%d' % nb, cert(nbytes=nb))
    # (b) outer SEQUENCE, indefinite length
    add('outer-indef', cert(indef=True))
    # (c) signatureValue BIT STRING unused-bits byte
    sc = content_of(sig); assert sc[0] == 0; sb = sc[1:]
    def mksig(unused, op=None):
        b = bytearray(sb)
        if op:
            b[-1] = op(b[-1])
        return wrap(0x03, bytes([unused]) + bytes(b))
    add('sig-unused1-clear', cert(sig_=mksig(1, lambda x: x & 0xFE)))    # unused=1, padding bit 0 (DER-valid)
    add('sig-unused1-set', cert(sig_=mksig(1, lambda x: x | 0x01)))      # unused=1, padding bit 1 (BER only)
    add('sig-unused7-clear', cert(sig_=mksig(7, lambda x: x & 0x80)))
    add('sig-unused7-set', cert(sig_=mksig(7, lambda x: x | 0x7F)))
    add('sig-unused0-lowset', cert(sig_=mksig(0, lambda x: x | 0x01)))   # control: unused=0, low bit set is plain DER
    add('sig-unused8', cert(sig_=mksig(8)))                               # invalid in BER and DER
    add('sig-unused1-empty', cert(sig_=wrap(0x03, b'\x01')))              # unused=1 with no content octets
    add('sig-empty', cert(sig_=wrap(0x03, b'')))                          # no unused-bits octet at all
    # (d) trailing bytes
    add('trailing-1', der + b'\x00')
    add('trailing-1ff', der + b'\xff')
    add('trailing-2', der + b'\x30\x00')
    add('trailing-100', der + b'A' * 100)
    add('trailing-cert', der + other)
    # (e) tbsCertificate SEQUENCE, non-minimal length
    for nb in sorted({len(enc_len(len(tbsc))), 3, 4}):
        add('tbs-len%d' % nb, cert(tbs_=tbs_with(nbytes=nb)))
    # (f) inner elements with indefinite length
    add('tbs-indef', cert(tbs_=tbs_with(indef=True)))
    subj = parts[idx['subject']]; subjc = content_of(subj)
    add('subject-indef', cert(tbs_=tbs_with(subject=wrap(0x30, subjc, indef=True))))
    if 'ext' in idx:
        ext = parts[idx['ext']]; extc = content_of(ext); extseq = children(extc); assert len(extseq) == 1
        add('ext-indef', cert(tbs_=tbs_with(ext=wrap(0xa3, extc, indef=True))))
        add('extseq-indef', cert(tbs_=tbs_with(ext=wrap(0xa3, wrap(0x30, content_of(extseq[0]), indef=True)))))
    add('alg-indef', cert(alg_=wrap(0x30, content_of(alg), indef=True)))      # outside the cached tbs
    add('alg-len2', cert(alg_=wrap(0x30, content_of(alg), nbytes=2)))         # outside the cached tbs
    add('all-indef', cert(tbs_=tbs_with(indef=True, subject=wrap(0x30, subjc, indef=True)),
                          alg_=wrap(0x30, content_of(alg), indef=True), indef=True))
    # (g) non-minimal length inside the subject Name (last AVA of last RDN)
    rdns = children(subjc); last = rdns[-1]; avas = children(content_of(last)); ava = avas[-1]
    oid, val = children(content_of(ava))
    def name_with(val_nb=None, rdn_nb=None, name_nb=None, rdn_content=None):
        val2 = wrap(val[0], content_of(val), nbytes=val_nb)
        ava2 = wrap(0x30, oid + val2)
        rdn2 = wrap(0x31, b''.join(avas[:-1]) + ava2 if rdn_content is None else rdn_content, nbytes=rdn_nb)
        return wrap(0x30, b''.join(rdns[:-1]) + rdn2, nbytes=name_nb)
    assert name_with() == subj
    add('name-value-len1', cert(tbs_=tbs_with(subject=name_with(val_nb=1))))
    add('name-rdn-len1', cert(tbs_=tbs_with(subject=name_with(rdn_nb=1))))
    add('name-len2', cert(tbs_=tbs_with(subject=name_with(name_nb=2))))
    # RDN SET OF ordering (DER sorts members by encoding; BER does not care)
    ava_o = wrap(0x30, b'\x06\x03\x55\x04\x0a' + wrap(0x0c, b'O' * (len(ava) + 8)))
    assert ava_o > ava and len(ava_o) < 0x80
    add('rdn-unsorted', cert(tbs_=tbs_with(subject=name_with(rdn_content=ava_o + ava))))
    add('rdn-sorted', cert(tbs_=tbs_with(subject=name_with(rdn_content=ava + ava_o))))   # control, DER-valid
    # (h) serial INTEGER
    add('serial-nonmin', cert(tbs_=tbs_with(serial=wrap(0x02, b'\x00\x01'))))
    add('serial-neg1', cert(tbs_=tbs_with(serial=wrap(0x02, b'\xff'))))
    add('serial-neg-nonmin', cert(tbs_=tbs_with(serial=wrap(0x02, b'\xff\xff'))))
    add('serial-neg-nonmin80', cert(tbs_=tbs_with(serial=wrap(0x02, b'\xff\x80'))))
    add('serial-neg-big', cert(tbs_=tbs_with(serial=wrap(0x02, b'\x80' + b'\x00' * 19))))
    add('serial-empty', cert(tbs_=tbs_with(serial=wrap(0x02, b''))))
    add('serial-00-80', cert(tbs_=tbs_with(serial=wrap(0x02, b'\x00\x80'))))           # control, minimal positive
    # BOOLEAN leniency inside extensions
    if 'ext' in idx:
        exts = children(content_of(extseq[0]))
        for n, e in enumerate(exts):
            ec = children(content_of(e))
            if len(ec) == 3 and ec[1] == b'\x01\x01\xff':
                exts2 = list(exts); exts2[n] = wrap(0x30, ec[0] + b'\x01\x01\x01' + ec[2])
                add('bool-true-01', cert(tbs_=tbs_with(ext=wrap(0xa3, wrap(0x30, b''.join(exts2))))))
                break
        for n, e in enumerate(exts):
            ec = children(content_of(e))
            if len(ec) == 2:
                exts2 = list(exts); exts2[n] = wrap(0x30, ec[0] + b'\x01\x01\x00' + ec[1])
                add('bool-false-explicit', cert(tbs_=tbs_with(ext=wrap(0xa3, wrap(0x30, b''.join(exts2))))))
                break
    # version INTEGER non-minimal inside [0]
    if 'version' in idx:
        add('version-nonmin', cert(tbs_=tbs_with(version=wrap(0xa0, wrap(0x02, b'\x00\x02')))))
    return V

rsa = rows['x02315'][1]; ec = rows['x02321'][1]; ed = rows['x02319'][1]
assert rows['x02315'][0] == 'lib rsa2048' and rows['x02321'][0] == 'lib ec-secp256r1' and rows['x02319'][0] == 'lib ed25519'
# hand-built mini v1 ed25519 certificate: SPKI and signature bits borrowed from x02319 (d2i does not verify)
edparts = children(content_of(children(content_of(ed))[0]))
ed_spki = [p for p in edparts if p[0] == 0x30 and p[2:4] == b'\x30\x05'][0]
assert ed_spki[:9] == bytes.fromhex('302a300506032b6570')
ed_sig = children(content_of(ed))[2]
name = wrap(0x30, wrap(0x31, wrap(0x30, b'\x06\x03\x55\x04\x03' + wrap(0x0c, b'a'))))
validity = wrap(0x30, wrap(0x17, b'200101000000Z') + wrap(0x17, b'300101000000Z'))
sigalg = wrap(0x30, b'\x06\x03\x2b\x65\x70')
mini_tbs = wrap(0x30, wrap(0x02, b'\x01') + sigalg + name + validity + name + ed_spki)
mini = wrap(0x30, mini_tbs + sigalg + ed_sig)
assert len(mini) < 256 and mini[1] == 0x81

n = 0
with open(dst, 'w') as out:
    for base, der, other in (('rsa2048', rsa, ec), ('ec-secp256r1', ec, rsa), ('mini-ed25519-v1', mini, ec)):
        n += 1
        out.write('b%05d\tber-base %s\t%s\n' % (n, base, der.hex()))
        for kind, b in variants(der, other):
            n += 1
            out.write('b%05d\tber-%s %s\t%s\n' % (n, kind, base, b.hex()))

# second pass (ids continue): constructed strings, indefinite [0], non-minimal OID arc
def variants2(der):
    V = []
    def add(kind, b):
        V.append((kind, b))
    tbs, alg, sig = children(content_of(der)); tbsc = content_of(tbs); parts = children(tbsc)
    idx = {}; k = 0
    if parts[0][0] == 0xa0:
        idx['version'] = 0; k = 1
    for n, name in enumerate(('serial', 'sigalg', 'issuer', 'validity', 'subject', 'spki')):
        idx[name] = k + n
    for n, p in enumerate(parts):
        if p[0] == 0xa3:
            idx['ext'] = n
    def cert(tbs_=None, alg_=None, sig_=None):
        return wrap(0x30, (tbs if tbs_ is None else tbs_) + (alg if alg_ is None else alg_) + (sig if sig_ is None else sig_))
    def tbs_with(**repl):
        ps = list(parts)
        for name, val in repl.items():
            ps[idx[name]] = val
        return wrap(0x30, b''.join(ps))
    sc = content_of(sig)
    # constructed BIT STRING signature (X.690 8.6.4: segments are BIT STRINGs; first byte of the value = unused bits of the whole)
    half = len(sc) // 2
    seg1 = wrap(0x03, sc[:half]); seg2 = wrap(0x03, b'\x00' + sc[half:])
    add('sig-constructed', cert(sig_=wrap(0x23, seg1 + seg2)))
    add('sig-constructed-indef', cert(sig_=wrap(0x23, seg1 + seg2, indef=True)))
    if 'ext' in idx:
        ext = parts[idx['ext']]; extseq = children(content_of(ext))[0]; exts = children(content_of(extseq))
        e0 = exts[0]; ec = children(content_of(e0)); val = ec[-1]; assert val[0] == 0x04
        vc = content_of(val); h = len(vc) // 2
        segs = wrap(0x04, vc[:h]) + wrap(0x04, vc[h:])
        for kind, newval in (('ext-octet-constructed', wrap(0x24, segs)), ('ext-octet-constructed-indef', wrap(0x24, segs, indef=True))):
            exts2 = list(exts); exts2[0] = wrap(0x30, b''.join(ec[:-1]) + newval)
            add(kind, cert(tbs_=tbs_with(ext=wrap(0xa3, wrap(0x30, b''.join(exts2))))))
    if 'version' in idx:
        add('version-indef', cert(tbs_=tbs_with(version=wrap(0xa0, content_of(parts[0]), indef=True))))
    # last AVA's attribute type OID with a redundant 0x80 sub-identifier prefix on its last arc (X.690 8.19.2 forbids)
    subj = parts[idx['subject']]; rdns = children(content_of(subj)); last = rdns[-1]; avas = children(content_of(last)); ava = avas[-1]
    oid, val = children(content_of(ava)); oc = content_of(oid); assert oc[-1] < 0x80 and oc[-2] < 0x80, oc.hex()
    ava2 = wrap(0x30, wrap(0x06, oc[:-1] + b'\x80' + oc[-1:]) + val)   # e.g. 2.5.4.10 as 55 04 80 0a
    rdn2 = wrap(0x31, b''.join(avas[:-1]) + ava2)
    add('oid-nonmin-arc', cert(tbs_=tbs_with(subject=wrap(0x30, b''.join(rdns[:-1]) + rdn2))))
    return V
with open(dst, 'a') as out:
    for base, der in (('rsa2048', rsa), ('ec-secp256r1', ec), ('mini-ed25519-v1', mini)):
        for kind, b in variants2(der):
            n += 1
            out.write('b%05d\tber-%s %s\t%s\n' % (n, kind, base, b.hex()))
print('rows', n)
