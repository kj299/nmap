/* oracle.c - d2i_X509 verdict oracle for E5.  Build: gcc -O2 -o oracle oracle.c -lcrypto
 * Input: TSV files (ID<TAB>note<TAB>hex).  Output: TSV on stdout, one row per input row. */
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hv(int c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return 0; }
static void hex(const unsigned char *b, size_t n, char *out) { static const char *d = "0123456789abcdef"; for (size_t i = 0; i < n; i++) { out[2*i] = d[b[i] >> 4]; out[2*i+1] = d[b[i] & 15]; } out[2*n] = 0; }

int main(int argc, char **argv)
{
    printf("id\tfamily\tnote\tlen\tverdict\treason_first\terr_first\terr_last\tconsumed\tremaining\ti2d_len\ti2d_sha256\ti2d_eq_input\tpkey\tbits\tversion\tsig_alg\terr_after_accept\ti2d_hex_if_diff\n");
    for (int a = 1; a < argc; a++) {
        FILE *f = fopen(argv[a], "r");
        if (!f) { perror(argv[a]); return 1; }
        char *line = NULL; size_t cap = 0; ssize_t n;
        while ((n = getline(&line, &cap, f)) > 0) {
            if (line[n-1] == '\n') line[--n] = 0;
            if (n == 0) continue;
            char *id = line; char *t1 = strchr(line, '\t'); if (!t1) continue; *t1 = 0;
            char *note = t1 + 1; char *t2 = strchr(note, '\t'); if (!t2) continue; *t2 = 0;
            char *hx = t2 + 1; size_t len = strlen(hx) / 2;
            unsigned char *buf = malloc(len + 1);
            for (size_t i = 0; i < len; i++) buf[i] = (unsigned char)((hv(hx[2*i]) << 4) | hv(hx[2*i+1]));
            char fam[64]; { size_t k = 0; while (note[k] && note[k] != ' ' && k < 63) { fam[k] = note[k]; k++; } fam[k] = 0; }
            ERR_clear_error();
            const unsigned char *p = buf;
            X509 *x = d2i_X509(NULL, &p, (long)len);
            if (!x) {
                unsigned long e = ERR_get_error(); char eb[256], lb[256];
                const char *rs = e ? ERR_reason_error_string(e) : "(no error queued)";
                ERR_error_string_n(e, eb, sizeof eb);
                unsigned long last = e, t; while ((t = ERR_get_error()) != 0) last = t;
                ERR_error_string_n(last, lb, sizeof lb);
                printf("%s\t%s\t%s\t%zu\treject\t%s\t%s\t%s\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\t-\n", id, fam, note, len, rs ? rs : "?", eb, lb);
            } else {
                unsigned long e2 = ERR_peek_error(); char e2b[256] = "-"; if (e2) ERR_error_string_n(e2, e2b, sizeof e2b);
                size_t consumed = (size_t)(p - buf);
                unsigned char *o = NULL; int ol = i2d_X509(x, &o);
                char sha[65] = "-"; int eq = 0; char *ohex = NULL;
                if (ol > 0) {
                    unsigned char d[32]; SHA256(o, (size_t)ol, d); hex(d, 32, sha);
                    eq = ((size_t)ol == len && memcmp(o, buf, len) == 0);
                    if (!eq && ol <= 4000) { ohex = malloc(2 * (size_t)ol + 1); hex(o, (size_t)ol, ohex); }
                }
                EVP_PKEY *pk = X509_get0_pubkey(x); const char *pks = "nokey"; int bits = -1;
                if (pk) { int bid = EVP_PKEY_base_id(pk); pks = OBJ_nid2sn(bid); if (!pks) pks = "?"; bits = EVP_PKEY_bits(pk); }
                long ver = X509_get_version(x); int snid = X509_get_signature_nid(x); const char *ss = OBJ_nid2sn(snid);
                printf("%s\t%s\t%s\t%zu\taccept\t-\t-\t-\t%zu\t%zu\t%d\t%s\t%d\t%s\t%d\t%ld\t%s\t%s\t%s\n",
                       id, fam, note, len, consumed, len - consumed, ol, sha, eq, pks, bits, ver, ss ? ss : "?", e2b, ohex ? ohex : "-");
                OPENSSL_free(o); free(ohex); X509_free(x);
            }
            free(buf);
        }
        free(line); fclose(f);
    }
    return 0;
}
