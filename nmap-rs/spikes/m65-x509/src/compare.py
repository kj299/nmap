#!/usr/bin/env python3
"""compare.py - join c_oracle.tsv with x509cert.tsv and x509parser.tsv; per-family agreement tables,
re-encoding agreement, and disagreement classes with examples.  Usage: compare.py <scratch> <certs.tsv> <ber.tsv>"""
import sys, hashlib, collections
S, corpus, ber = sys.argv[1:4]
def load(path):
    with open(path) as f:
        hdr = f.readline().rstrip('\n').split('\t'); rows = collections.OrderedDict()
        for line in f:
            d = dict(zip(hdr, line.rstrip('\n').split('\t'))); rows[d['id']] = d
    return rows
C = load(S + '/c_oracle.tsv'); A = load(S + '/x509cert.tsv'); B = load(S + '/x509parser.tsv')
inputs = {}
for p in (corpus, ber):
    with open(p) as f:
        for line in f:
            i, note, hx = line.rstrip('\n').split('\t'); inputs[i] = bytes.fromhex(hx)
assert set(C) == set(A) == set(B) == set(inputs), (len(C), len(A), len(B), len(inputs))
CORPUS_FAMS = ['attr', 'ext', 'flip', 'trunc', 'strtype', 'lib', 'utc', 'gen', 'sigalg', 'version', 'serial', 'long-cn', 'rsa-e',
               'unknown-oids', 'trailing', 'time-wrongtag', 'spki-unknown-alg', 'spki-rsa-garbage', 'spki-ec-explicit-junk',
               'multi-rdn', 'dup-cn', 'empty-name', 'many-rdns', 'empty']
fams = [f for f in CORPUS_FAMS] + sorted({r['family'] for r in C.values() if r['family'].startswith('ber-')})
assert set(fams) == {r['family'] for r in C.values()}, set(fams) ^ {r['family'] for r in C.values()}
VARIANTS = [('x509-cert strict (from_der)', A, 'strict_'), ('x509-cert tolerant DER (decode on SliceReader)', A, 'tol_'),
            ('x509-cert tolerant BER (EncodingRules::Ber)', A, 'ber_'), ('x509-parser 0.18.1 (from_der)', B, '')]
def sha_reenc(row, pre, i):
    v = row[pre + 'reenc'] if pre else None
    if v is None or v == '-': return None
    data = inputs[i] if v == '=input' else bytes.fromhex(v)
    return hashlib.sha256(data).hexdigest()
out = []
P = out.append
joined = open(S + '/out/joined.tsv', 'w')
joined.write('id\tfamily\tC\tC_reason\tC_consumed\tC_i2d_eq_input\tstrict\ttol\ttol_consumed\tber\tber_consumed\tparser\tparser_consumed\treenc_strict_eq_C\treenc_tol_eq_C\treenc_ber_eq_C\n')
for i, c in C.items():
    a = A[i]; b = B[i]
    def req(pre):
        if c['verdict'] != 'accept' or a[pre + 'verdict'] != 'accept': return '-'
        return '1' if sha_reenc(a, pre, i) == c['i2d_sha256'] else '0'
    joined.write('\t'.join([i, c['family'], c['verdict'], c['reason_first'], c['consumed'], c['i2d_eq_input'], a['strict_verdict'], a['tol_verdict'], a['tol_consumed'],
                            a['ber_verdict'], a['ber_consumed'], b['verdict'], b['consumed'], req('strict_'), req('tol_'), req('ber_')]) + '\n')
joined.close()
TOT = collections.OrderedDict()
for vname, R, pre in VARIANTS:
    P('\n## Variant: %s\n' % vname)
    P('| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |')
    P('|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    tot = collections.Counter(); dis = collections.defaultdict(list)
    for fam in fams:
        cnt = collections.Counter(); re_ok = re_bad = re_na = 0; cons_ok = cons_bad = 0
        for i, c in C.items():
            if c['family'] != fam: continue
            r = R[i]; cv = c['verdict']; rv = r[pre + 'verdict']
            if rv == 'panic': key = 'panic'
            else: key = ('A' if cv == 'accept' else 'R') + ('A' if rv == 'accept' else 'R')
            cnt[key] += 1
            if key != 'AA' and key != 'RR':
                dis[(fam, key)].append((i, c['reason_first'] if cv == 'reject' else '-', r[pre + 'err'] if rv != 'accept' else '-', c['note']))
            if key == 'AA':
                if pre == '' : re_na += 1
                else:
                    if sha_reenc(r, pre, i) == c['i2d_sha256']: re_ok += 1
                    else: re_bad += 1; dis[(fam, 'REENC')].append((i, c['i2d_eq_input'], r[pre + 'reenc'] == '=input', c['note']))
                if r[pre + 'consumed'] == c['consumed']: cons_ok += 1
                else: cons_bad += 1; dis[(fam, 'CONSUMED')].append((i, c['consumed'], r[pre + 'consumed'], c['note']))
        n = sum(cnt.values())
        if n == 0: continue
        agree = cnt['AA'] + cnt['RR']
        P('| %s | %d | %d | %d | %d | %d | %d | %d/%d | %s | %d/%d |' % (fam, n, cnt['AA'], cnt['AR'], cnt['RA'], cnt['RR'], cnt['panic'], agree, n,
            ('%d/%d' % (re_ok, re_ok + re_bad)) if pre else 'n/a', cons_ok, cons_ok + cons_bad))
        tot.update(cnt); tot['re_ok'] += re_ok; tot['re_bad'] += re_bad; tot['cons_ok'] += cons_ok; tot['cons_bad'] += cons_bad
    n = tot['AA'] + tot['AR'] + tot['RA'] + tot['RR'] + tot['panic']
    P('| **all** | %d | %d | %d | %d | %d | %d | %d/%d | %s | %d/%d |' % (n, tot['AA'], tot['AR'], tot['RA'], tot['RR'], tot['panic'], tot['AA'] + tot['RR'], n,
        ('%d/%d' % (tot['re_ok'], tot['re_ok'] + tot['re_bad'])) if pre else 'n/a', tot['cons_ok'], tot['cons_ok'] + tot['cons_bad']))
    TOT[vname] = tot
    P('\n### Disagreements (%s)\n' % vname)
    for (fam, key), lst in sorted(dis.items()):
        if key in ('REENC', 'CONSUMED'):
            P('- %s / %s: %d rows, e.g. %s' % (fam, key, len(lst), '; '.join('%s (C i2d==input:%s, R reenc==input:%s; %s)' % (i, x, y, note) for i, x, y, note in lst[:3])))
            continue
        combos = collections.Counter((cr, rr[:110]) for i, cr, rr, note in lst)
        P('- %s / %s: %d rows' % (fam, {'AR': 'C-accept/R-reject', 'RA': 'C-reject/R-accept', 'panic': 'R-panic'}[key], len(lst)))
        for (cr, rr), k in combos.most_common(6):
            ex = [i for i, c2, r2, note in lst if c2 == cr and r2[:110] == rr][:4]
            notes = [note for i, c2, r2, note in lst if c2 == cr and r2[:110] == rr][:2]
            P('    - %d x  C: `%s`  R: `%s`  e.g. %s  (notes: %s)' % (k, cr, rr, ', '.join(ex), ' | '.join(notes)))
P('\n## Totals\n')
P('| variant | verdict agree | C-acc/R-rej | C-rej/R-acc | panics | re-enc agree (both-accept) | consumed agree (both-accept) |')
P('|---|---:|---:|---:|---:|---:|---:|')
for vname, tot in TOT.items():
    n = tot['AA'] + tot['AR'] + tot['RA'] + tot['RR'] + tot['panic']
    P('| %s | %d/%d | %d | %d | %d | %s | %d/%d |' % (vname, tot['AA'] + tot['RR'], n, tot['AR'], tot['RA'], tot['panic'],
        ('%d/%d' % (tot['re_ok'], tot['re_ok'] + tot['re_bad'])) if tot['re_ok'] + tot['re_bad'] else 'n/a', tot['cons_ok'], tot['cons_ok'] + tot['cons_bad']))
open(S + '/out/compare.md', 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
