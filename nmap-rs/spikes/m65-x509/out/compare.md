
## Variant: x509-cert strict (from_der)

| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| attr | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | 1092/1092 | 1092/1092 |
| ext | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | 1092/1092 | 1092/1092 |
| flip | 400 | 202 | 29 | 9 | 160 | 0 | 362/400 | 202/202 | 202/202 |
| trunc | 143 | 0 | 0 | 0 | 143 | 0 | 143/143 | 0/0 | 0/0 |
| strtype | 66 | 31 | 1 | 29 | 5 | 0 | 36/66 | 31/31 | 31/31 |
| lib | 18 | 18 | 0 | 0 | 0 | 0 | 18/18 | 18/18 | 18/18 |
| utc | 17 | 4 | 13 | 0 | 0 | 0 | 4/17 | 4/4 | 4/4 |
| gen | 12 | 3 | 9 | 0 | 0 | 0 | 3/12 | 2/3 | 3/3 |
| sigalg | 7 | 7 | 0 | 0 | 0 | 0 | 7/7 | 7/7 | 7/7 |
| version | 6 | 4 | 2 | 0 | 0 | 0 | 4/6 | 3/4 | 4/4 |
| serial | 5 | 3 | 1 | 0 | 1 | 0 | 4/5 | 3/3 | 3/3 |
| long-cn | 4 | 4 | 0 | 0 | 0 | 0 | 4/4 | 4/4 | 4/4 |
| rsa-e | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| unknown-oids | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| trailing | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| time-wrongtag | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | 0/0 | 0/0 |
| spki-unknown-alg | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| spki-rsa-garbage | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| spki-ec-explicit-junk | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| multi-rdn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| dup-cn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| empty-name | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| many-rdns | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| empty | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | 0/0 | 0/0 |
| ber-alg-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-alg-len2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-all-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-base | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
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
| ber-rdn-sorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-rdn-unsorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-serial-00-80 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-empty | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg-big | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-neg-nonmin | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg-nonmin80 | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-nonmin | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-sig-constructed | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-constructed-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-empty | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-sig-unused0-lowset | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused1-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused1-empty | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-unused1-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused7-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused7-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused8 | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
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
| ber-version-nonmin | 2 | 0 | 0 | 0 | 2 | 0 | 2/2 | 0/0 | 0/0 |
| **all** | 3020 | 2505 | 143 | 41 | 331 | 0 | 2836/3020 | 2492/2505 | 2505/2505 |

### Disagreements (x509-cert strict (from_der))

- ber-alg-indef / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 954`  e.g. b00027  (notes: ber-alg-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 753`  e.g. b00071  (notes: ber-alg-indef ec-secp256r1)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 121`  e.g. b00115  (notes: ber-alg-indef mini-ed25519-v1)
- ber-alg-len2 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 956`  e.g. b00028  (notes: ber-alg-len2 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 755`  e.g. b00072  (notes: ber-alg-len2 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 123`  e.g. b00116  (notes: ber-alg-len2 mini-ed25519-v1)
- ber-all-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 2`  e.g. b00029, b00073, b00117  (notes: ber-all-indef rsa2048 | ber-all-indef ec-secp256r1)
- ber-bool-false-explicit / REENC: 2 rows, e.g. b00043 (C i2d==input:1, R reenc==input:False; ber-bool-false-explicit rsa2048); b00087 (C i2d==input:1, R reenc==input:False; ber-bool-false-explicit ec-secp256r1)
- ber-bool-true-01 / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 475`  e.g. b00042  (notes: ber-bool-true-01 rsa2048)
    - 1 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 274`  e.g. b00086  (notes: ber-bool-true-01 ec-secp256r1)
- ber-ext-indef / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 458`  e.g. b00025  (notes: ber-ext-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 257`  e.g. b00069  (notes: ber-ext-indef ec-secp256r1)
- ber-ext-octet-constructed / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 476`  e.g. b00132  (notes: ber-ext-octet-constructed rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 275`  e.g. b00138  (notes: ber-ext-octet-constructed ec-secp256r1)
- ber-ext-octet-constructed-indef / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 476`  e.g. b00133  (notes: ber-ext-octet-constructed-indef rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 275`  e.g. b00139  (notes: ber-ext-octet-constructed-indef ec-secp256r1)
- ber-extseq-indef / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 462`  e.g. b00026  (notes: ber-extseq-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 261`  e.g. b00070  (notes: ber-extseq-indef ec-secp256r1)
- ber-name-len2 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 107`  e.g. b00032  (notes: ber-name-len2 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 104`  e.g. b00076  (notes: ber-name-len2 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 65`  e.g. b00120  (notes: ber-name-len2 mini-ed25519-v1)
- ber-name-rdn-len1 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 139`  e.g. b00031  (notes: ber-name-rdn-len1 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 141`  e.g. b00075  (notes: ber-name-rdn-len1 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 66`  e.g. b00119  (notes: ber-name-rdn-len1 mini-ed25519-v1)
- ber-name-value-len1 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 148`  e.g. b00030  (notes: ber-name-value-len1 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 150`  e.g. b00074  (notes: ber-name-value-len1 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 75`  e.g. b00118  (notes: ber-name-value-len1 mini-ed25519-v1)
- ber-oid-nonmin-arc / C-reject/R-accept: 3 rows
    - 3 x  C: `invalid object encoding`  R: `-`  e.g. b00135, b00141, b00144  (notes: ber-oid-nonmin-arc rsa2048 | ber-oid-nonmin-arc ec-secp256r1)
- ber-outer-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 2`  e.g. b00007, b00051, b00096  (notes: ber-outer-indef rsa2048 | ber-outer-indef ec-secp256r1)
- ber-outer-len2 / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 4`  e.g. b00090  (notes: ber-outer-len2 mini-ed25519-v1)
- ber-outer-len3 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 5`  e.g. b00002, b00046, b00091  (notes: ber-outer-len3 rsa2048 | ber-outer-len3 ec-secp256r1)
- ber-outer-len4 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 6`  e.g. b00003, b00047, b00092  (notes: ber-outer-len4 rsa2048 | ber-outer-len4 ec-secp256r1)
- ber-outer-len5 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00004, b00048, b00093  (notes: ber-outer-len5 rsa2048 | ber-outer-len5 ec-secp256r1)
- ber-outer-len8 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00005, b00049, b00094  (notes: ber-outer-len8 rsa2048 | ber-outer-len8 ec-secp256r1)
- ber-outer-len9 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00006, b00050, b00095  (notes: ber-outer-len9 rsa2048 | ber-outer-len9 ec-secp256r1)
- ber-rdn-unsorted / REENC: 3 rows, e.g. b00033 (C i2d==input:1, R reenc==input:False; ber-rdn-unsorted rsa2048); b00077 (C i2d==input:1, R reenc==input:False; ber-rdn-unsorted ec-secp256r1); b00121 (C i2d==input:1, R reenc==input:False; ber-rdn-unsorted mini-ed25519-v1)
- ber-sig-constructed / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 968`  e.g. b00130  (notes: ber-sig-constructed rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 764`  e.g. b00136  (notes: ber-sig-constructed ec-secp256r1)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 127`  e.g. b00142  (notes: ber-sig-constructed mini-ed25519-v1)
- ber-sig-constructed-indef / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 968`  e.g. b00131  (notes: ber-sig-constructed-indef rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 764`  e.g. b00137  (notes: ber-sig-constructed-indef ec-secp256r1)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 127`  e.g. b00143  (notes: ber-sig-constructed-indef mini-ed25519-v1)
- ber-sig-unused1-empty / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `malformed ASN.1 DER value for BIT STRING`  e.g. b00014, b00058, b00103  (notes: ber-sig-unused1-empty rsa2048 | ber-sig-unused1-empty ec-secp256r1)
- ber-sig-unused1-set / REENC: 3 rows, e.g. b00009 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set rsa2048); b00053 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set ec-secp256r1); b00098 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set mini-ed25519-v1)
- ber-sig-unused7-set / REENC: 3 rows, e.g. b00011 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set rsa2048); b00055 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set ec-secp256r1); b00100 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set mini-ed25519-v1)
- ber-subject-indef / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 105`  e.g. b00024  (notes: ber-subject-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 102`  e.g. b00068  (notes: ber-subject-indef ec-secp256r1)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 63`  e.g. b00114  (notes: ber-subject-indef mini-ed25519-v1)
- ber-tbs-indef / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 6`  e.g. b00023, b00067  (notes: ber-tbs-indef rsa2048 | ber-tbs-indef ec-secp256r1)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 5`  e.g. b00113  (notes: ber-tbs-indef mini-ed25519-v1)
- ber-tbs-len1 / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 6`  e.g. b00110  (notes: ber-tbs-len1 mini-ed25519-v1)
- ber-tbs-len3 / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 9`  e.g. b00021, b00065  (notes: ber-tbs-len3 rsa2048 | ber-tbs-len3 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 8`  e.g. b00111  (notes: ber-tbs-len3 mini-ed25519-v1)
- ber-tbs-len4 / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 10`  e.g. b00022, b00066  (notes: ber-tbs-len4 rsa2048 | ber-tbs-len4 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 9`  e.g. b00112  (notes: ber-tbs-len4 mini-ed25519-v1)
- ber-trailing-1 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 1228 bytes, 1 bytes remaining at DER byte 1228`  e.g. b00016  (notes: ber-trailing-1 rsa2048)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 838 bytes, 1 bytes remaining at DER byte 838`  e.g. b00060  (notes: ber-trailing-1 ec-secp256r1)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 193 bytes, 1 bytes remaining at DER byte 193`  e.g. b00105  (notes: ber-trailing-1 mini-ed25519-v1)
- ber-trailing-100 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 1228 bytes, 100 bytes remaining at DER byte 1228`  e.g. b00019  (notes: ber-trailing-100 rsa2048)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 838 bytes, 100 bytes remaining at DER byte 838`  e.g. b00063  (notes: ber-trailing-100 ec-secp256r1)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 193 bytes, 100 bytes remaining at DER byte 193`  e.g. b00108  (notes: ber-trailing-100 mini-ed25519-v1)
- ber-trailing-1ff / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 1228 bytes, 1 bytes remaining at DER byte 1228`  e.g. b00017  (notes: ber-trailing-1ff rsa2048)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 838 bytes, 1 bytes remaining at DER byte 838`  e.g. b00061  (notes: ber-trailing-1ff ec-secp256r1)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 193 bytes, 1 bytes remaining at DER byte 193`  e.g. b00106  (notes: ber-trailing-1ff mini-ed25519-v1)
- ber-trailing-2 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 1228 bytes, 2 bytes remaining at DER byte 1228`  e.g. b00018  (notes: ber-trailing-2 rsa2048)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 838 bytes, 2 bytes remaining at DER byte 838`  e.g. b00062  (notes: ber-trailing-2 ec-secp256r1)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 193 bytes, 2 bytes remaining at DER byte 193`  e.g. b00107  (notes: ber-trailing-2 mini-ed25519-v1)
- ber-trailing-cert / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 1228 bytes, 838 bytes remaining at DER byte 1228`  e.g. b00020  (notes: ber-trailing-cert rsa2048)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 838 bytes, 1228 bytes remaining at DER byte 838`  e.g. b00064  (notes: ber-trailing-cert ec-secp256r1)
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 193 bytes, 838 bytes remaining at DER byte 193`  e.g. b00109  (notes: ber-trailing-cert mini-ed25519-v1)
- ber-version-indef / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 10`  e.g. b00134, b00140  (notes: ber-version-indef rsa2048 | ber-version-indef ec-secp256r1)
- flip / C-accept/R-reject: 29 rows
    - 12 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 100`  e.g. x02502, x02534, x02550, x02569  (notes: flip | flip)
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime`  e.g. x02526, x02538, x02673, x02726  (notes: flip | flip)
    - 2 x  C: `-`  R: `malformed OID at DER byte 676`  e.g. x02641, x02820  (notes: flip | flip)
    - 2 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 770`  e.g. x02647, x02683  (notes: flip | flip)
    - 2 x  C: `-`  R: `malformed OID at DER byte 58`  e.g. x02738, x02863  (notes: flip | flip)
    - 1 x  C: `-`  R: `date/time error at DER byte 100`  e.g. x02509  (notes: flip)
- flip / C-reject/R-accept: 9 rows
    - 7 x  C: `invalid utf8string`  R: `-`  e.g. x02481, x02583, x02681, x02724  (notes: flip | flip)
    - 2 x  C: `mstring not universal`  R: `-`  e.g. x02685, x02839  (notes: flip | flip)
- gen / C-accept/R-reject: 9 rows
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 51`  e.g. x02281, x02282, x02283, x02284  (notes: gen 20200101000000.5Z | gen 20200101000000.123456Z)
    - 4 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 66`  e.g. x02278, x02279, x02286, x02287  (notes: gen 19500101000000Z | gen 00010101000000Z)
- gen / REENC: 1 rows, e.g. x02285 (C i2d==input:1, R reenc==input:False; gen 20200229000000Z)
- serial / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `malformed ASN.1 DER value for INTEGER`  e.g. x02300  (notes: serial 1606938044258990275541962092341162602522202993782792835301376)
- strtype / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x1c at DER byte 91`  e.g. x02215  (notes: strtype 1c)
- strtype / C-reject/R-accept: 29 rows
    - 24 x  C: `mstring wrong tag`  R: `-`  e.g. x02227, x02228, x02229, x02230  (notes: strtype 1a | strtype 1a)
    - 2 x  C: `invalid utf8string`  R: `-`  e.g. x02189, x02190  (notes: strtype 0c | strtype 0c)
    - 2 x  C: `bmpstring is wrong length`  R: `-`  e.g. x02210, x02212  (notes: strtype 1e | strtype 1e)
    - 1 x  C: `illegal characters`  R: `-`  e.g. x02214  (notes: strtype 1e)
- trailing / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `trailing data at end of DER message: decoded 997 bytes, 2 bytes remaining at DER byte 997`  e.g. x02875  (notes: trailing)
- unknown-oids / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `malformed OID at DER byte 116`  e.g. x02253  (notes: unknown-oids)
- utc / C-accept/R-reject: 13 rows
    - 7 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime at DER byte 64`  e.g. x02262, x02268, x02269, x02270  (notes: utc 500101000000Z | utc 201301000000Z)
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime at DER byte 51`  e.g. x02265, x02266, x02267, x02275  (notes: utc 2001010000Z | utc 200101000000+0100)
    - 1 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime`  e.g. x02274  (notes: utc 2x0101000000Z)
- version / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `malformed ASN.1 DER value for INTEGER`  e.g. x02294, x02295  (notes: version 3 | version 255)
- version / REENC: 1 rows, e.g. x02291 (C i2d==input:1, R reenc==input:False; version 0)

## Variant: x509-cert tolerant DER (decode on SliceReader)

| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| attr | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | 1092/1092 | 1092/1092 |
| ext | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | 1092/1092 | 1092/1092 |
| flip | 400 | 202 | 29 | 9 | 160 | 0 | 362/400 | 202/202 | 202/202 |
| trunc | 143 | 0 | 0 | 0 | 143 | 0 | 143/143 | 0/0 | 0/0 |
| strtype | 66 | 31 | 1 | 29 | 5 | 0 | 36/66 | 31/31 | 31/31 |
| lib | 18 | 18 | 0 | 0 | 0 | 0 | 18/18 | 18/18 | 18/18 |
| utc | 17 | 4 | 13 | 0 | 0 | 0 | 4/17 | 4/4 | 4/4 |
| gen | 12 | 3 | 9 | 0 | 0 | 0 | 3/12 | 2/3 | 3/3 |
| sigalg | 7 | 7 | 0 | 0 | 0 | 0 | 7/7 | 7/7 | 7/7 |
| version | 6 | 4 | 2 | 0 | 0 | 0 | 4/6 | 3/4 | 4/4 |
| serial | 5 | 3 | 1 | 0 | 1 | 0 | 4/5 | 3/3 | 3/3 |
| long-cn | 4 | 4 | 0 | 0 | 0 | 0 | 4/4 | 4/4 | 4/4 |
| rsa-e | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| unknown-oids | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| trailing | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| time-wrongtag | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | 0/0 | 0/0 |
| spki-unknown-alg | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| spki-rsa-garbage | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| spki-ec-explicit-junk | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| multi-rdn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| dup-cn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| empty-name | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| many-rdns | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| empty | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | 0/0 | 0/0 |
| ber-alg-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-alg-len2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-all-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-base | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
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
| ber-rdn-sorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-rdn-unsorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-serial-00-80 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-empty | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg-big | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-neg-nonmin | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg-nonmin80 | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-nonmin | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-sig-constructed | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-constructed-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-empty | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-sig-unused0-lowset | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused1-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused1-empty | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-unused1-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused7-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused7-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused8 | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-subject-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-len1 | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-tbs-len3 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-len4 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-trailing-1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-100 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-1ff | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-2 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-cert | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-version-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | 0/0 | 0/0 |
| ber-version-nonmin | 2 | 0 | 0 | 0 | 2 | 0 | 2/2 | 0/0 | 0/0 |
| **all** | 3020 | 2521 | 127 | 41 | 331 | 0 | 2852/3020 | 2508/2521 | 2521/2521 |

### Disagreements (x509-cert tolerant DER (decode on SliceReader))

- ber-alg-indef / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 954`  e.g. b00027  (notes: ber-alg-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 753`  e.g. b00071  (notes: ber-alg-indef ec-secp256r1)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 121`  e.g. b00115  (notes: ber-alg-indef mini-ed25519-v1)
- ber-alg-len2 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 956`  e.g. b00028  (notes: ber-alg-len2 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 755`  e.g. b00072  (notes: ber-alg-len2 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 123`  e.g. b00116  (notes: ber-alg-len2 mini-ed25519-v1)
- ber-all-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 2`  e.g. b00029, b00073, b00117  (notes: ber-all-indef rsa2048 | ber-all-indef ec-secp256r1)
- ber-bool-false-explicit / REENC: 2 rows, e.g. b00043 (C i2d==input:1, R reenc==input:False; ber-bool-false-explicit rsa2048); b00087 (C i2d==input:1, R reenc==input:False; ber-bool-false-explicit ec-secp256r1)
- ber-bool-true-01 / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 475`  e.g. b00042  (notes: ber-bool-true-01 rsa2048)
    - 1 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 274`  e.g. b00086  (notes: ber-bool-true-01 ec-secp256r1)
- ber-ext-indef / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 458`  e.g. b00025  (notes: ber-ext-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 257`  e.g. b00069  (notes: ber-ext-indef ec-secp256r1)
- ber-ext-octet-constructed / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 476`  e.g. b00132  (notes: ber-ext-octet-constructed rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 275`  e.g. b00138  (notes: ber-ext-octet-constructed ec-secp256r1)
- ber-ext-octet-constructed-indef / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 476`  e.g. b00133  (notes: ber-ext-octet-constructed-indef rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x24 at DER byte 275`  e.g. b00139  (notes: ber-ext-octet-constructed-indef ec-secp256r1)
- ber-extseq-indef / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 462`  e.g. b00026  (notes: ber-extseq-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 261`  e.g. b00070  (notes: ber-extseq-indef ec-secp256r1)
- ber-name-len2 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 107`  e.g. b00032  (notes: ber-name-len2 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 104`  e.g. b00076  (notes: ber-name-len2 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 65`  e.g. b00120  (notes: ber-name-len2 mini-ed25519-v1)
- ber-name-rdn-len1 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 139`  e.g. b00031  (notes: ber-name-rdn-len1 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 141`  e.g. b00075  (notes: ber-name-rdn-len1 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 66`  e.g. b00119  (notes: ber-name-rdn-len1 mini-ed25519-v1)
- ber-name-value-len1 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 148`  e.g. b00030  (notes: ber-name-value-len1 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 150`  e.g. b00074  (notes: ber-name-value-len1 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 75`  e.g. b00118  (notes: ber-name-value-len1 mini-ed25519-v1)
- ber-oid-nonmin-arc / C-reject/R-accept: 3 rows
    - 3 x  C: `invalid object encoding`  R: `-`  e.g. b00135, b00141, b00144  (notes: ber-oid-nonmin-arc rsa2048 | ber-oid-nonmin-arc ec-secp256r1)
- ber-outer-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 2`  e.g. b00007, b00051, b00096  (notes: ber-outer-indef rsa2048 | ber-outer-indef ec-secp256r1)
- ber-outer-len2 / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 4`  e.g. b00090  (notes: ber-outer-len2 mini-ed25519-v1)
- ber-outer-len3 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 5`  e.g. b00002, b00046, b00091  (notes: ber-outer-len3 rsa2048 | ber-outer-len3 ec-secp256r1)
- ber-outer-len4 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 6`  e.g. b00003, b00047, b00092  (notes: ber-outer-len4 rsa2048 | ber-outer-len4 ec-secp256r1)
- ber-outer-len5 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00004, b00048, b00093  (notes: ber-outer-len5 rsa2048 | ber-outer-len5 ec-secp256r1)
- ber-outer-len8 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00005, b00049, b00094  (notes: ber-outer-len8 rsa2048 | ber-outer-len8 ec-secp256r1)
- ber-outer-len9 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00006, b00050, b00095  (notes: ber-outer-len9 rsa2048 | ber-outer-len9 ec-secp256r1)
- ber-rdn-unsorted / REENC: 3 rows, e.g. b00033 (C i2d==input:1, R reenc==input:False; ber-rdn-unsorted rsa2048); b00077 (C i2d==input:1, R reenc==input:False; ber-rdn-unsorted ec-secp256r1); b00121 (C i2d==input:1, R reenc==input:False; ber-rdn-unsorted mini-ed25519-v1)
- ber-sig-constructed / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 968`  e.g. b00130  (notes: ber-sig-constructed rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 764`  e.g. b00136  (notes: ber-sig-constructed ec-secp256r1)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 127`  e.g. b00142  (notes: ber-sig-constructed mini-ed25519-v1)
- ber-sig-constructed-indef / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 968`  e.g. b00131  (notes: ber-sig-constructed-indef rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 764`  e.g. b00137  (notes: ber-sig-constructed-indef ec-secp256r1)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 127`  e.g. b00143  (notes: ber-sig-constructed-indef mini-ed25519-v1)
- ber-sig-unused1-empty / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `malformed ASN.1 DER value for BIT STRING`  e.g. b00014, b00058, b00103  (notes: ber-sig-unused1-empty rsa2048 | ber-sig-unused1-empty ec-secp256r1)
- ber-sig-unused1-set / REENC: 3 rows, e.g. b00009 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set rsa2048); b00053 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set ec-secp256r1); b00098 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set mini-ed25519-v1)
- ber-sig-unused7-set / REENC: 3 rows, e.g. b00011 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set rsa2048); b00055 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set ec-secp256r1); b00100 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set mini-ed25519-v1)
- ber-subject-indef / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 105`  e.g. b00024  (notes: ber-subject-indef rsa2048)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 102`  e.g. b00068  (notes: ber-subject-indef ec-secp256r1)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 63`  e.g. b00114  (notes: ber-subject-indef mini-ed25519-v1)
- ber-tbs-indef / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 6`  e.g. b00023, b00067  (notes: ber-tbs-indef rsa2048 | ber-tbs-indef ec-secp256r1)
    - 1 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 5`  e.g. b00113  (notes: ber-tbs-indef mini-ed25519-v1)
- ber-tbs-len1 / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 6`  e.g. b00110  (notes: ber-tbs-len1 mini-ed25519-v1)
- ber-tbs-len3 / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 9`  e.g. b00021, b00065  (notes: ber-tbs-len3 rsa2048 | ber-tbs-len3 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 8`  e.g. b00111  (notes: ber-tbs-len3 mini-ed25519-v1)
- ber-tbs-len4 / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 10`  e.g. b00022, b00066  (notes: ber-tbs-len4 rsa2048 | ber-tbs-len4 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 9`  e.g. b00112  (notes: ber-tbs-len4 mini-ed25519-v1)
- ber-version-indef / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `indefinite length disallowed/malformed at DER byte 10`  e.g. b00134, b00140  (notes: ber-version-indef rsa2048 | ber-version-indef ec-secp256r1)
- flip / C-accept/R-reject: 29 rows
    - 12 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 100`  e.g. x02502, x02534, x02550, x02569  (notes: flip | flip)
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime`  e.g. x02526, x02538, x02673, x02726  (notes: flip | flip)
    - 2 x  C: `-`  R: `malformed OID at DER byte 676`  e.g. x02641, x02820  (notes: flip | flip)
    - 2 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 770`  e.g. x02647, x02683  (notes: flip | flip)
    - 2 x  C: `-`  R: `malformed OID at DER byte 58`  e.g. x02738, x02863  (notes: flip | flip)
    - 1 x  C: `-`  R: `date/time error at DER byte 100`  e.g. x02509  (notes: flip)
- flip / C-reject/R-accept: 9 rows
    - 7 x  C: `invalid utf8string`  R: `-`  e.g. x02481, x02583, x02681, x02724  (notes: flip | flip)
    - 2 x  C: `mstring not universal`  R: `-`  e.g. x02685, x02839  (notes: flip | flip)
- gen / C-accept/R-reject: 9 rows
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 51`  e.g. x02281, x02282, x02283, x02284  (notes: gen 20200101000000.5Z | gen 20200101000000.123456Z)
    - 4 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 66`  e.g. x02278, x02279, x02286, x02287  (notes: gen 19500101000000Z | gen 00010101000000Z)
- gen / REENC: 1 rows, e.g. x02285 (C i2d==input:1, R reenc==input:False; gen 20200229000000Z)
- serial / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `malformed ASN.1 DER value for INTEGER`  e.g. x02300  (notes: serial 1606938044258990275541962092341162602522202993782792835301376)
- strtype / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x1c at DER byte 91`  e.g. x02215  (notes: strtype 1c)
- strtype / C-reject/R-accept: 29 rows
    - 24 x  C: `mstring wrong tag`  R: `-`  e.g. x02227, x02228, x02229, x02230  (notes: strtype 1a | strtype 1a)
    - 2 x  C: `invalid utf8string`  R: `-`  e.g. x02189, x02190  (notes: strtype 0c | strtype 0c)
    - 2 x  C: `bmpstring is wrong length`  R: `-`  e.g. x02210, x02212  (notes: strtype 1e | strtype 1e)
    - 1 x  C: `illegal characters`  R: `-`  e.g. x02214  (notes: strtype 1e)
- unknown-oids / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `malformed OID at DER byte 116`  e.g. x02253  (notes: unknown-oids)
- utc / C-accept/R-reject: 13 rows
    - 7 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime at DER byte 64`  e.g. x02262, x02268, x02269, x02270  (notes: utc 500101000000Z | utc 201301000000Z)
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime at DER byte 51`  e.g. x02265, x02266, x02267, x02275  (notes: utc 2001010000Z | utc 200101000000+0100)
    - 1 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime`  e.g. x02274  (notes: utc 2x0101000000Z)
- version / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `malformed ASN.1 DER value for INTEGER`  e.g. x02294, x02295  (notes: version 3 | version 255)
- version / REENC: 1 rows, e.g. x02291 (C i2d==input:1, R reenc==input:False; version 0)

## Variant: x509-cert tolerant BER (EncodingRules::Ber)

| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| attr | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | 1092/1092 | 1092/1092 |
| ext | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | 1092/1092 | 1092/1092 |
| flip | 400 | 202 | 29 | 9 | 160 | 0 | 362/400 | 202/202 | 202/202 |
| trunc | 143 | 0 | 0 | 0 | 143 | 0 | 143/143 | 0/0 | 0/0 |
| strtype | 66 | 31 | 1 | 29 | 5 | 0 | 36/66 | 31/31 | 31/31 |
| lib | 18 | 18 | 0 | 0 | 0 | 0 | 18/18 | 18/18 | 18/18 |
| utc | 17 | 4 | 13 | 0 | 0 | 0 | 4/17 | 4/4 | 4/4 |
| gen | 12 | 3 | 9 | 0 | 0 | 0 | 3/12 | 2/3 | 3/3 |
| sigalg | 7 | 7 | 0 | 0 | 0 | 0 | 7/7 | 7/7 | 7/7 |
| version | 6 | 4 | 2 | 0 | 0 | 0 | 4/6 | 3/4 | 4/4 |
| serial | 5 | 3 | 1 | 0 | 1 | 0 | 4/5 | 3/3 | 3/3 |
| long-cn | 4 | 4 | 0 | 0 | 0 | 0 | 4/4 | 4/4 | 4/4 |
| rsa-e | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| unknown-oids | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| trailing | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| time-wrongtag | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | 0/0 | 0/0 |
| spki-unknown-alg | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| spki-rsa-garbage | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| spki-ec-explicit-junk | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| multi-rdn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| dup-cn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| empty-name | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| many-rdns | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | 1/1 | 1/1 |
| empty | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | 0/0 | 0/0 |
| ber-alg-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-alg-len2 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-all-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-base | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
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
| ber-outer-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-outer-len2 | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-outer-len3 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len4 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len5 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len8 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-outer-len9 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-rdn-sorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-rdn-unsorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-00-80 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-empty | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg-big | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-neg-nonmin | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg-nonmin80 | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-serial-neg1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-serial-nonmin | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-sig-constructed | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-constructed-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-empty | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-sig-unused0-lowset | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused1-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused1-empty | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-sig-unused1-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused7-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-sig-unused7-set | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-sig-unused8 | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | 0/0 | 0/0 |
| ber-subject-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-tbs-indef | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 0/3 | 3/3 |
| ber-tbs-len1 | 1 | 0 | 1 | 0 | 0 | 0 | 0/1 | 0/0 | 0/0 |
| ber-tbs-len3 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-tbs-len4 | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | 0/0 | 0/0 |
| ber-trailing-1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-100 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-1ff | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-2 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-trailing-cert | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | 3/3 | 3/3 |
| ber-version-indef | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | 0/2 | 2/2 |
| ber-version-nonmin | 2 | 0 | 0 | 0 | 2 | 0 | 2/2 | 0/0 | 0/0 |
| **all** | 3020 | 2544 | 104 | 41 | 331 | 0 | 2875/3020 | 2517/2544 | 2544/2544 |

### Disagreements (x509-cert tolerant BER (EncodingRules::Ber))

- ber-alg-len2 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 956`  e.g. b00028  (notes: ber-alg-len2 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 755`  e.g. b00072  (notes: ber-alg-len2 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 123`  e.g. b00116  (notes: ber-alg-len2 mini-ed25519-v1)
- ber-all-indef / REENC: 3 rows, e.g. b00029 (C i2d==input:0, R reenc==input:False; ber-all-indef rsa2048); b00073 (C i2d==input:0, R reenc==input:False; ber-all-indef ec-secp256r1); b00117 (C i2d==input:0, R reenc==input:False; ber-all-indef mini-ed25519-v1)
- ber-bool-false-explicit / REENC: 2 rows, e.g. b00043 (C i2d==input:1, R reenc==input:False; ber-bool-false-explicit rsa2048); b00087 (C i2d==input:1, R reenc==input:False; ber-bool-false-explicit ec-secp256r1)
- ber-bool-true-01 / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 475`  e.g. b00042  (notes: ber-bool-true-01 rsa2048)
    - 1 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 274`  e.g. b00086  (notes: ber-bool-true-01 ec-secp256r1)
- ber-ext-indef / REENC: 2 rows, e.g. b00025 (C i2d==input:1, R reenc==input:False; ber-ext-indef rsa2048); b00069 (C i2d==input:1, R reenc==input:False; ber-ext-indef ec-secp256r1)
- ber-ext-octet-constructed / C-accept/R-reject: 2 rows
    - 1 x  C: `-`  R: `ASN.1 OCTET STRING not canonically encoded as DER at DER byte 477`  e.g. b00132  (notes: ber-ext-octet-constructed rsa2048)
    - 1 x  C: `-`  R: `ASN.1 OCTET STRING not canonically encoded as DER at DER byte 276`  e.g. b00138  (notes: ber-ext-octet-constructed ec-secp256r1)
- ber-ext-octet-constructed-indef / REENC: 2 rows, e.g. b00133 (C i2d==input:1, R reenc==input:False; ber-ext-octet-constructed-indef rsa2048); b00139 (C i2d==input:1, R reenc==input:False; ber-ext-octet-constructed-indef ec-secp256r1)
- ber-extseq-indef / REENC: 2 rows, e.g. b00026 (C i2d==input:1, R reenc==input:False; ber-extseq-indef rsa2048); b00070 (C i2d==input:1, R reenc==input:False; ber-extseq-indef ec-secp256r1)
- ber-name-len2 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 107`  e.g. b00032  (notes: ber-name-len2 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 104`  e.g. b00076  (notes: ber-name-len2 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 65`  e.g. b00120  (notes: ber-name-len2 mini-ed25519-v1)
- ber-name-rdn-len1 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 139`  e.g. b00031  (notes: ber-name-rdn-len1 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 141`  e.g. b00075  (notes: ber-name-rdn-len1 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SET at DER byte 66`  e.g. b00119  (notes: ber-name-rdn-len1 mini-ed25519-v1)
- ber-name-value-len1 / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 148`  e.g. b00030  (notes: ber-name-value-len1 rsa2048)
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 150`  e.g. b00074  (notes: ber-name-value-len1 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for UTF8String at DER byte 75`  e.g. b00118  (notes: ber-name-value-len1 mini-ed25519-v1)
- ber-oid-nonmin-arc / C-reject/R-accept: 3 rows
    - 3 x  C: `invalid object encoding`  R: `-`  e.g. b00135, b00141, b00144  (notes: ber-oid-nonmin-arc rsa2048 | ber-oid-nonmin-arc ec-secp256r1)
- ber-outer-len2 / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 4`  e.g. b00090  (notes: ber-outer-len2 mini-ed25519-v1)
- ber-outer-len3 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 5`  e.g. b00002, b00046, b00091  (notes: ber-outer-len3 rsa2048 | ber-outer-len3 ec-secp256r1)
- ber-outer-len4 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 6`  e.g. b00003, b00047, b00092  (notes: ber-outer-len4 rsa2048 | ber-outer-len4 ec-secp256r1)
- ber-outer-len5 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00004, b00048, b00093  (notes: ber-outer-len5 rsa2048 | ber-outer-len5 ec-secp256r1)
- ber-outer-len8 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00005, b00049, b00094  (notes: ber-outer-len8 rsa2048 | ber-outer-len8 ec-secp256r1)
- ber-outer-len9 / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 2`  e.g. b00006, b00050, b00095  (notes: ber-outer-len9 rsa2048 | ber-outer-len9 ec-secp256r1)
- ber-sig-constructed / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 968`  e.g. b00130  (notes: ber-sig-constructed rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 764`  e.g. b00136  (notes: ber-sig-constructed ec-secp256r1)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 127`  e.g. b00142  (notes: ber-sig-constructed mini-ed25519-v1)
- ber-sig-constructed-indef / C-accept/R-reject: 3 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 968`  e.g. b00131  (notes: ber-sig-constructed-indef rsa2048)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 764`  e.g. b00137  (notes: ber-sig-constructed-indef ec-secp256r1)
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x23 at DER byte 127`  e.g. b00143  (notes: ber-sig-constructed-indef mini-ed25519-v1)
- ber-sig-unused1-empty / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `malformed ASN.1 DER value for BIT STRING`  e.g. b00014, b00058, b00103  (notes: ber-sig-unused1-empty rsa2048 | ber-sig-unused1-empty ec-secp256r1)
- ber-sig-unused1-set / REENC: 3 rows, e.g. b00009 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set rsa2048); b00053 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set ec-secp256r1); b00098 (C i2d==input:0, R reenc==input:True; ber-sig-unused1-set mini-ed25519-v1)
- ber-sig-unused7-set / REENC: 3 rows, e.g. b00011 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set rsa2048); b00055 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set ec-secp256r1); b00100 (C i2d==input:0, R reenc==input:True; ber-sig-unused7-set mini-ed25519-v1)
- ber-subject-indef / REENC: 3 rows, e.g. b00024 (C i2d==input:1, R reenc==input:False; ber-subject-indef rsa2048); b00068 (C i2d==input:1, R reenc==input:False; ber-subject-indef ec-secp256r1); b00114 (C i2d==input:1, R reenc==input:False; ber-subject-indef mini-ed25519-v1)
- ber-tbs-indef / REENC: 3 rows, e.g. b00023 (C i2d==input:1, R reenc==input:False; ber-tbs-indef rsa2048); b00067 (C i2d==input:1, R reenc==input:False; ber-tbs-indef ec-secp256r1); b00113 (C i2d==input:1, R reenc==input:False; ber-tbs-indef mini-ed25519-v1)
- ber-tbs-len1 / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 6`  e.g. b00110  (notes: ber-tbs-len1 mini-ed25519-v1)
- ber-tbs-len3 / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 9`  e.g. b00021, b00065  (notes: ber-tbs-len3 rsa2048 | ber-tbs-len3 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 8`  e.g. b00111  (notes: ber-tbs-len3 mini-ed25519-v1)
- ber-tbs-len4 / C-accept/R-reject: 3 rows
    - 2 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 10`  e.g. b00022, b00066  (notes: ber-tbs-len4 rsa2048 | ber-tbs-len4 ec-secp256r1)
    - 1 x  C: `-`  R: `incorrect length for SEQUENCE at DER byte 9`  e.g. b00112  (notes: ber-tbs-len4 mini-ed25519-v1)
- ber-version-indef / REENC: 2 rows, e.g. b00134 (C i2d==input:1, R reenc==input:False; ber-version-indef rsa2048); b00140 (C i2d==input:1, R reenc==input:False; ber-version-indef ec-secp256r1)
- flip / C-accept/R-reject: 29 rows
    - 12 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 100`  e.g. x02502, x02534, x02550, x02569  (notes: flip | flip)
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime`  e.g. x02526, x02538, x02673, x02726  (notes: flip | flip)
    - 2 x  C: `-`  R: `malformed OID at DER byte 676`  e.g. x02641, x02820  (notes: flip | flip)
    - 2 x  C: `-`  R: `ASN.1 BOOLEAN not canonically encoded as DER at DER byte 770`  e.g. x02647, x02683  (notes: flip | flip)
    - 2 x  C: `-`  R: `malformed OID at DER byte 58`  e.g. x02738, x02863  (notes: flip | flip)
    - 1 x  C: `-`  R: `date/time error at DER byte 100`  e.g. x02509  (notes: flip)
- flip / C-reject/R-accept: 9 rows
    - 7 x  C: `invalid utf8string`  R: `-`  e.g. x02481, x02583, x02681, x02724  (notes: flip | flip)
    - 2 x  C: `mstring not universal`  R: `-`  e.g. x02685, x02839  (notes: flip | flip)
- gen / C-accept/R-reject: 9 rows
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 51`  e.g. x02281, x02282, x02283, x02284  (notes: gen 20200101000000.5Z | gen 20200101000000.123456Z)
    - 4 x  C: `-`  R: `malformed ASN.1 DER value for GeneralizedTime at DER byte 66`  e.g. x02278, x02279, x02286, x02287  (notes: gen 19500101000000Z | gen 00010101000000Z)
- gen / REENC: 1 rows, e.g. x02285 (C i2d==input:1, R reenc==input:False; gen 20200229000000Z)
- serial / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `malformed ASN.1 DER value for INTEGER`  e.g. x02300  (notes: serial 1606938044258990275541962092341162602522202993782792835301376)
- strtype / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `unknown/unsupported ASN.1 DER tag: 0x1c at DER byte 91`  e.g. x02215  (notes: strtype 1c)
- strtype / C-reject/R-accept: 29 rows
    - 24 x  C: `mstring wrong tag`  R: `-`  e.g. x02227, x02228, x02229, x02230  (notes: strtype 1a | strtype 1a)
    - 2 x  C: `invalid utf8string`  R: `-`  e.g. x02189, x02190  (notes: strtype 0c | strtype 0c)
    - 2 x  C: `bmpstring is wrong length`  R: `-`  e.g. x02210, x02212  (notes: strtype 1e | strtype 1e)
    - 1 x  C: `illegal characters`  R: `-`  e.g. x02214  (notes: strtype 1e)
- unknown-oids / C-accept/R-reject: 1 rows
    - 1 x  C: `-`  R: `malformed OID at DER byte 116`  e.g. x02253  (notes: unknown-oids)
- utc / C-accept/R-reject: 13 rows
    - 7 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime at DER byte 64`  e.g. x02262, x02268, x02269, x02270  (notes: utc 500101000000Z | utc 201301000000Z)
    - 5 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime at DER byte 51`  e.g. x02265, x02266, x02267, x02275  (notes: utc 2001010000Z | utc 200101000000+0100)
    - 1 x  C: `-`  R: `malformed ASN.1 DER value for UTCTime`  e.g. x02274  (notes: utc 2x0101000000Z)
- version / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `malformed ASN.1 DER value for INTEGER`  e.g. x02294, x02295  (notes: version 3 | version 255)
- version / REENC: 1 rows, e.g. x02291 (C i2d==input:1, R reenc==input:False; version 0)

## Variant: x509-parser 0.18.1 (from_der)

| family | n | C-acc/R-acc | C-acc/R-rej | C-rej/R-acc | C-rej/R-rej | R-panic | verdict agree | both-accept: re-enc == i2d | both-accept: consumed == C |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| attr | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | n/a | 1092/1092 |
| ext | 1092 | 1092 | 0 | 0 | 0 | 0 | 1092/1092 | n/a | 1092/1092 |
| flip | 400 | 214 | 17 | 49 | 120 | 0 | 334/400 | n/a | 214/214 |
| trunc | 143 | 0 | 0 | 0 | 143 | 0 | 143/143 | n/a | 0/0 |
| strtype | 66 | 32 | 0 | 34 | 0 | 0 | 32/66 | n/a | 32/32 |
| lib | 18 | 18 | 0 | 0 | 0 | 0 | 18/18 | n/a | 18/18 |
| utc | 17 | 7 | 10 | 0 | 0 | 0 | 7/17 | n/a | 7/7 |
| gen | 12 | 7 | 5 | 0 | 0 | 0 | 7/12 | n/a | 7/7 |
| sigalg | 7 | 7 | 0 | 0 | 0 | 0 | 7/7 | n/a | 7/7 |
| version | 6 | 6 | 0 | 0 | 0 | 0 | 6/6 | n/a | 6/6 |
| serial | 5 | 4 | 0 | 1 | 0 | 0 | 4/5 | n/a | 4/4 |
| long-cn | 4 | 4 | 0 | 0 | 0 | 0 | 4/4 | n/a | 4/4 |
| rsa-e | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| unknown-oids | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| trailing | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| time-wrongtag | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | n/a | 0/0 |
| spki-unknown-alg | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| spki-rsa-garbage | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| spki-ec-explicit-junk | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| multi-rdn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| dup-cn | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| empty-name | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| many-rdns | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| empty | 1 | 0 | 0 | 0 | 1 | 0 | 1/1 | n/a | 0/0 |
| ber-alg-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-alg-len2 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-all-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-base | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-bool-false-explicit | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | n/a | 2/2 |
| ber-bool-true-01 | 2 | 2 | 0 | 0 | 0 | 0 | 2/2 | n/a | 2/2 |
| ber-ext-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-ext-octet-constructed | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-ext-octet-constructed-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-extseq-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-name-len2 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-name-rdn-len1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-name-value-len1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-oid-nonmin-arc | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-outer-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-outer-len2 | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| ber-outer-len3 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-outer-len4 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-outer-len5 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-outer-len8 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-outer-len9 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-rdn-sorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-rdn-unsorted | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-serial-00-80 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-serial-empty | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-serial-neg-big | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-serial-neg-nonmin | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-serial-neg-nonmin80 | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-serial-neg1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-serial-nonmin | 3 | 0 | 0 | 3 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-constructed | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-constructed-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-empty | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | n/a | 0/0 |
| ber-sig-unused0-lowset | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-sig-unused1-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-sig-unused1-empty | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-unused1-set | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-unused7-clear | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-sig-unused7-set | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-sig-unused8 | 3 | 0 | 0 | 0 | 3 | 0 | 3/3 | n/a | 0/0 |
| ber-subject-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-tbs-indef | 3 | 0 | 3 | 0 | 0 | 0 | 0/3 | n/a | 0/0 |
| ber-tbs-len1 | 1 | 1 | 0 | 0 | 0 | 0 | 1/1 | n/a | 1/1 |
| ber-tbs-len3 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-tbs-len4 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-trailing-1 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-trailing-100 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-trailing-1ff | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-trailing-2 | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-trailing-cert | 3 | 3 | 0 | 0 | 0 | 0 | 3/3 | n/a | 3/3 |
| ber-version-indef | 2 | 0 | 2 | 0 | 0 | 0 | 0/2 | n/a | 0/0 |
| ber-version-nonmin | 2 | 0 | 0 | 0 | 2 | 0 | 2/2 | n/a | 0/0 |
| **all** | 3020 | 2576 | 72 | 99 | 273 | 0 | 2849/3020 | n/a | 2576/2576 |

### Disagreements (x509-parser 0.18.1 (from_der))

- ber-alg-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(Der(DerConstraintFailed(IndefiniteLength)))`  e.g. b00027, b00071, b00115  (notes: ber-alg-indef rsa2048 | ber-alg-indef ec-secp256r1)
- ber-all-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(Der(DerConstraintFailed(IndefiniteLength)))`  e.g. b00029, b00073, b00117  (notes: ber-all-indef rsa2048 | ber-all-indef ec-secp256r1)
- ber-ext-indef / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `Error(InvalidIssuerUID)`  e.g. b00025, b00069  (notes: ber-ext-indef rsa2048 | ber-ext-indef ec-secp256r1)
- ber-ext-octet-constructed / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `Error(NomError(Eof))`  e.g. b00132, b00138  (notes: ber-ext-octet-constructed rsa2048 | ber-ext-octet-constructed ec-secp256r1)
- ber-ext-octet-constructed-indef / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `Error(NomError(Eof))`  e.g. b00133, b00139  (notes: ber-ext-octet-constructed-indef rsa2048 | ber-ext-octet-constructed-indef ec-secp256r1)
- ber-extseq-indef / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `Error(Der(DerConstraintFailed(IndefiniteLength)))`  e.g. b00026, b00070  (notes: ber-extseq-indef rsa2048 | ber-extseq-indef ec-secp256r1)
- ber-oid-nonmin-arc / C-reject/R-accept: 3 rows
    - 3 x  C: `invalid object encoding`  R: `-`  e.g. b00135, b00141, b00144  (notes: ber-oid-nonmin-arc rsa2048 | ber-oid-nonmin-arc ec-secp256r1)
- ber-outer-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(Der(DerConstraintFailed(IndefiniteLength)))`  e.g. b00007, b00051, b00096  (notes: ber-outer-indef rsa2048 | ber-outer-indef ec-secp256r1)
- ber-serial-empty / C-reject/R-accept: 3 rows
    - 3 x  C: `illegal zero content`  R: `-`  e.g. b00040, b00084, b00128  (notes: ber-serial-empty rsa2048 | ber-serial-empty ec-secp256r1)
- ber-serial-neg-nonmin / C-reject/R-accept: 3 rows
    - 3 x  C: `illegal padding`  R: `-`  e.g. b00037, b00081, b00125  (notes: ber-serial-neg-nonmin rsa2048 | ber-serial-neg-nonmin ec-secp256r1)
- ber-serial-neg-nonmin80 / C-reject/R-accept: 3 rows
    - 3 x  C: `illegal padding`  R: `-`  e.g. b00038, b00082, b00126  (notes: ber-serial-neg-nonmin80 rsa2048 | ber-serial-neg-nonmin80 ec-secp256r1)
- ber-serial-nonmin / C-reject/R-accept: 3 rows
    - 3 x  C: `illegal padding`  R: `-`  e.g. b00035, b00079, b00123  (notes: ber-serial-nonmin rsa2048 | ber-serial-nonmin ec-secp256r1)
- ber-sig-constructed / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(InvalidSignatureValue)`  e.g. b00130, b00136, b00142  (notes: ber-sig-constructed rsa2048 | ber-sig-constructed ec-secp256r1)
- ber-sig-constructed-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(InvalidSignatureValue)`  e.g. b00131, b00137, b00143  (notes: ber-sig-constructed-indef rsa2048 | ber-sig-constructed-indef ec-secp256r1)
- ber-sig-unused1-empty / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(InvalidSignatureValue)`  e.g. b00014, b00058, b00103  (notes: ber-sig-unused1-empty rsa2048 | ber-sig-unused1-empty ec-secp256r1)
- ber-sig-unused1-set / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(InvalidSignatureValue)`  e.g. b00009, b00053, b00098  (notes: ber-sig-unused1-set rsa2048 | ber-sig-unused1-set ec-secp256r1)
- ber-sig-unused7-set / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(InvalidSignatureValue)`  e.g. b00011, b00055, b00100  (notes: ber-sig-unused7-set rsa2048 | ber-sig-unused7-set ec-secp256r1)
- ber-subject-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(Der(DerConstraintFailed(IndefiniteLength)))`  e.g. b00024, b00068, b00114  (notes: ber-subject-indef rsa2048 | ber-subject-indef ec-secp256r1)
- ber-tbs-indef / C-accept/R-reject: 3 rows
    - 3 x  C: `-`  R: `Error(Der(DerConstraintFailed(IndefiniteLength)))`  e.g. b00023, b00067, b00113  (notes: ber-tbs-indef rsa2048 | ber-tbs-indef ec-secp256r1)
- ber-version-indef / C-accept/R-reject: 2 rows
    - 2 x  C: `-`  R: `Error(Der(DerConstraintFailed(IndefiniteLength)))`  e.g. b00134, b00140  (notes: ber-version-indef rsa2048 | ber-version-indef ec-secp256r1)
- flip / C-accept/R-reject: 17 rows
    - 17 x  C: `-`  R: `Error(InvalidDate)`  e.g. x02502, x02509, x02526, x02534  (notes: flip | flip)
- flip / C-reject/R-accept: 49 rows
    - 14 x  C: `invalid object encoding`  R: `-`  e.g. x02539, x02541, x02559, x02576  (notes: flip | flip)
    - 10 x  C: `wrong tag`  R: `-`  e.g. x02504, x02519, x02618, x02708  (notes: flip | flip)
    - 8 x  C: `too long`  R: `-`  e.g. x02505, x02586, x02602, x02658  (notes: flip | flip)
    - 7 x  C: `invalid utf8string`  R: `-`  e.g. x02481, x02583, x02681, x02724  (notes: flip | flip)
    - 5 x  C: `header too long`  R: `-`  e.g. x02536, x02688, x02695, x02728  (notes: flip | flip)
    - 3 x  C: `sequence length mismatch`  R: `-`  e.g. x02665, x02832, x02847  (notes: flip | flip)
- gen / C-accept/R-reject: 5 rows
    - 5 x  C: `-`  R: `Error(InvalidDate)`  e.g. x02282, x02283, x02286, x02287  (notes: gen 20200101000000.123456Z | gen 20200101000000+0000)
- serial / C-reject/R-accept: 1 rows
    - 1 x  C: `illegal padding`  R: `-`  e.g. x02299  (notes: serial -730750818665451459101842416358141509827966271488)
- strtype / C-reject/R-accept: 34 rows
    - 24 x  C: `mstring wrong tag`  R: `-`  e.g. x02227, x02228, x02229, x02230  (notes: strtype 1a | strtype 1a)
    - 3 x  C: `illegal characters`  R: `-`  e.g. x02214, x02217, x02220  (notes: strtype 1e | strtype 1c)
    - 3 x  C: `universalstring is wrong length`  R: `-`  e.g. x02216, x02218, x02219  (notes: strtype 1c | strtype 1c)
    - 2 x  C: `invalid utf8string`  R: `-`  e.g. x02189, x02190  (notes: strtype 0c | strtype 0c)
    - 2 x  C: `bmpstring is wrong length`  R: `-`  e.g. x02210, x02212  (notes: strtype 1e | strtype 1e)
- utc / C-accept/R-reject: 10 rows
    - 10 x  C: `-`  R: `Error(InvalidDate)`  e.g. x02267, x02268, x02269, x02270  (notes: utc 200101000000 | utc 201301000000Z)

## Totals

| variant | verdict agree | C-acc/R-rej | C-rej/R-acc | panics | re-enc agree (both-accept) | consumed agree (both-accept) |
|---|---:|---:|---:|---:|---:|---:|
| x509-cert strict (from_der) | 2836/3020 | 143 | 41 | 0 | 2492/2505 | 2505/2505 |
| x509-cert tolerant DER (decode on SliceReader) | 2852/3020 | 127 | 41 | 0 | 2508/2521 | 2521/2521 |
| x509-cert tolerant BER (EncodingRules::Ber) | 2875/3020 | 104 | 41 | 0 | 2517/2544 | 2544/2544 |
| x509-parser 0.18.1 (from_der) | 2849/3020 | 72 | 99 | 0 | n/a | 2576/2576 |
