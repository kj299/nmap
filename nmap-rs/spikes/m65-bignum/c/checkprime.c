/* Generate an N-bit prime, then time BN_check_prime on it (the is_prime
 * worst case: trial division survives, then the full MR rounds run).
 * Usage: checkprime <bits> [reps]
 */
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec*1000.0 + ts.tv_nsec/1e6;
}

int main(int argc,char**argv){
    int bits = argc>1?atoi(argv[1]):8192;
    int reps = argc>2?atoi(argv[2]):3;
    BN_CTX*ctx=BN_CTX_new();
    BIGNUM*p=BN_new();
    double gs=now_ms();
    if(!BN_generate_prime_ex(p,bits,0,NULL,NULL,NULL)){
        fprintf(stderr,"prime gen failed\n"); return 1;
    }
    double gen_ms=now_ms()-gs;
    printf("generated %d-bit prime in %.1f ms (num_bits=%d)\n",bits,gen_ms,BN_num_bits(p));
    for(int r=0;r<reps;r++){
        double s=now_ms();
        int ip=BN_check_prime(p,ctx,NULL);
        double ms=now_ms()-s;
        printf("BN_check_prime(%d-bit prime) rep%d = %.3f ms (result=%d)\n",bits,r,ms,ip);
    }
    BN_free(p); BN_CTX_free(ctx);
    return 0;
}
