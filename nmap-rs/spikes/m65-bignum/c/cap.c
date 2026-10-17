/* Probe OpenSSL 3.0.13 BN_bin2bn cap at the documented boundary.
 * bn_expand_internal fails when words > INT_MAX/(4*BN_BITS2).
 * With 64-bit words: 8388607 words = 536870848 bits = 67108856 bytes OK,
 * 67108857 bytes needs 8388608 words -> should fail BN_R_BIGNUM_TOO_LONG.
 * nmap's l_bignum_bin2bn ignores the return value, so a failure leaves
 * the freshly-BN_new()'d bignum at its zero value.
 */
#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void probe(size_t len){
    unsigned char *buf = calloc(1, len);      /* zero-filled */
    if(!buf){ printf("len=%zu: calloc failed\n", len); return; }
    buf[0]=0xff; /* a nonzero high byte so a success would be nonzero */
    ERR_clear_error();
    BIGNUM *num = BN_new();                    /* mirrors nmap: BN_new then bin2bn */
    BIGNUM *ret = BN_bin2bn(buf, (int)len, num);
    unsigned long e = ERR_get_error();
    char ebuf[256]; ebuf[0]=0;
    if(e) ERR_error_string_n(e, ebuf, sizeof ebuf);
    int bits = BN_num_bits(num);
    printf("len=%zu  bin2bn_ret=%s  bits_in_num=%d  is_zero=%s  err=%s\n",
           len,
           ret? "non-NULL":"NULL",
           bits,
           BN_is_zero(num)?"yes":"no",
           e? ebuf : "(none)");
    BN_free(num);
    free(buf);
}

int main(void){
    /* note: (int)len requires len <= INT_MAX; 67108857 < INT_MAX so cast is fine */
    probe((size_t)67108856);  /* expected OK */
    probe((size_t)67108857);  /* expected BN_R_BIGNUM_TOO_LONG -> zero bignum */
    return 0;
}
