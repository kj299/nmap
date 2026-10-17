#!/usr/bin/env python3
"""inspect.py - byte-level look at disagreement examples.  Usage: inspect.py <scratch> <certs.tsv> <ber.tsv> id...
For 'flip' rows: diff against the flip base (x02331) and name the enclosing element of each flipped byte.
For any row: print the serial TLV, and (if x509-cert accepted) the first difference between input and its re-encoding."""
import sys
S, corpus, ber = sys.argv[1:4]; ids = sys.argv[4:]
rows = {}
for p in (corpus, ber):
    for line in open(p):
        i, note, hx = line.rstrip('\n').split('\t'); rows[i] = (note, bytes.fromhex(hx))
A = {}
with open(S + '/x509cert.tsv') as f:
    hdr = f.readline().rstrip('\n').split('\t')
    for line in f:
        d = dict(zip(hdr, line.rstrip('\n').split('\t'))); A[d['id']] = d
C = {}
with open(S + '/c_oracle.tsv') as f:
    hdr = f.readline().rstrip('\n').split('\t')
    for line in f:
        d = dict(zip(hdr, line.rstrip('\n').split('\t'))); C[d['id']] = d
TBS_FIELDS = ['serial', 'sigalg', 'issuer', 'validity', 'subject', 'spki']
def elements(b, start, end, path, out, depth=0):
    i = start
    n = 0
    while i < end:
        if i + 2 > end: out.append((i, end, 'TRUNC', path + '/?')); break
        tag = b[i]; l = b[i + 1]; j = i + 2
        if l == 0x80: out.append((i, end, 'INDEF', path + '/%02x' % tag)); break
        if l & 0x80:
            k = l & 0x7f
            if j + k > end: out.append((i, end, 'BADLEN', path + '/%02x' % tag)); break
            L = int.from_bytes(b[j:j + k], 'big'); j += k
        else: L = l
        e = j + L
        name = '%02x[%d]' % (tag, n)
        if path == '' : name = 'Certificate'
        elif path == '/Certificate': name = ['tbs', 'sigalg', 'signature'][n] if n < 3 else name
        elif path == '/Certificate/tbs':
            name = 'version' if tag == 0xa0 else ('extensions' if tag == 0xa3 else (TBS_FIELDS[n - 1] if n - 1 < len(TBS_FIELDS) and b[start] == 0xa0 else (TBS_FIELDS[n] if n < len(TBS_FIELDS) else name)))
        p2 = path + '/' + name
        out.append((i, j, 'HDR', p2)); out.append((j, min(e, end), 'VAL', p2))
        if tag & 0x20 and e <= end and depth < 12:
            elements(b, j, e, p2, out, depth + 1)
        i = e; n += 1
def locate(b, off):
    out = []; elements(b, 0, len(b), '', out)
    best = None
    for s, e, kind, path in out:
        if s <= off < e and (best is None or (e - s) <= (best[1] - best[0])): best = (s, e, kind, path)
    return best
def show(i):
    note, b = rows[i]; c = C[i]; a = A[i]
    print('=== %s  %s  len=%d  C=%s %s  x509-cert strict=%s %s' % (i, note, len(b), c['verdict'], c['reason_first'] if c['verdict'] == 'reject' else '', a['strict_verdict'], a['strict_err'][:100] if a['strict_verdict'] != 'accept' else ''))
    if note == 'flip':
        base = rows['x02331'][1]; assert len(base) == len(b)
        for off in [k for k in range(len(b)) if b[k] != base[k]]:
            loc = locate(base, off)
            print('   flipped byte @%d: %02x -> %02x  in %s %s (elem %d..%d)' % (off, base[off], b[off], loc[2], loc[3], loc[0], loc[1]))
    # serial TLV
    try:
        out = []; elements(b, 0, len(b), '', out)
        for s, e, kind, path in out:
            if kind == 'HDR' and path.endswith('/tbs/serial'):
                v = [x for x in out if x[3] == path and x[2] == 'VAL'][0]
                print('   serial TLV: %s' % b[s:v[1]].hex())
            if kind == 'HDR' and '/subject/' in path and path.count('/') == 5:
                v = [x for x in out if x[3] == path and x[2] == 'VAL'][0]
                print('   subject RDN: %s' % b[s:v[1]].hex()[:120])
    except Exception as ex:
        print('   (walk failed: %s)' % ex)
    for pre in ('strict_', 'ber_'):
        r = a[pre + 'reenc']
        if r not in ('-', '=input'):
            rb = bytes.fromhex(r)
            k = next((k for k in range(min(len(b), len(rb))) if b[k] != rb[k]), min(len(b), len(rb)))
            loc = locate(b, k) if k < len(b) else None
            print('   %s re-enc differs: len %d vs %d, first diff @%d in %s\n      input: %s\n      reenc: %s' % (pre, len(b), len(rb), k, loc[3] if loc else '?', b[max(0, k - 8):k + 16].hex(), rb[max(0, k - 8):k + 16].hex()))
    if c['verdict'] == 'accept' and c['i2d_eq_input'] == '0' and c['i2d_hex_if_diff'] != '-':
        ob = bytes.fromhex(c['i2d_hex_if_diff'])
        k = next((k for k in range(min(len(b), len(ob))) if b[k] != ob[k]), min(len(b), len(ob)))
        print('   C i2d differs: len %d vs %d, first diff @%d\n      input: %s\n      i2d  : %s' % (len(b), len(ob), k, b[max(0, k - 8):k + 16].hex(), ob[max(0, k - 8):k + 16].hex()))
for i in ids: show(i)
