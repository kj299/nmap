/* nmap bignum measurement spike - C side (OpenSSL 3.0.13)
 * Usage: bench <op> <bits> [reps]
 * ops: modexp_full modexp_dh modexp_e17 trialdiv bn2dec dec2bn
 * Prints: op bits rep_ms... median_ms  (median last, ms)
 * Random operands from BN_rand (no fixed seed; values are random).
 */
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>

static double now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
    return ts.tv_sec*1000.0 + ts.tv_nsec/1e6;
}
static int cmp_d(const void*a,const void*b){
    double x=*(const double*)a,y=*(const double*)b;
    return (x>y)-(x<y);
}

/* trial-division primes count, mirrors calc_trial_divisions in bn_prime.c */
static int calc_trial_divisions(int bits){
    if(bits<=512) return 64;
    else if(bits<=1024) return 128;
    else if(bits<=2048) return 384;
    else if(bits<=4096) return 1024;
    return 2048; /* NUMPRIMES for the small-primes table */
}

int main(int argc,char**argv){
    if(argc<3){fprintf(stderr,"usage: %s op bits [reps]\n",argv[0]);return 2;}
    const char*op=argv[1];
    int bits=atoi(argv[2]);
    int reps=argc>3?atoi(argv[3]):3;
    if(reps<1) reps=1;
    double *t=malloc(sizeof(double)*reps);
    BN_CTX*ctx=BN_CTX_new();

    for(int r=0;r<reps;r++){
        double ms=0;
        if(!strcmp(op,"modexp_full")){
            BIGNUM*a=BN_new(),*e=BN_new(),*m=BN_new(),*res=BN_new();
            BN_rand(a,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ANY);
            BN_rand(e,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ANY);
            BN_rand(m,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD);
            double s=now_ms();
            BN_mod_exp(res,a,e,m,ctx);
            ms=now_ms()-s;
            BN_free(a);BN_free(e);BN_free(m);BN_free(res);
        } else if(!strcmp(op,"modexp_dh")){
            /* 2048-bit exponent, N-bit modulus and base */
            BIGNUM*a=BN_new(),*e=BN_new(),*m=BN_new(),*res=BN_new();
            BN_rand(a,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ANY);
            BN_rand(e,2048,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ANY);
            BN_rand(m,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD);
            double s=now_ms();
            BN_mod_exp(res,a,e,m,ctx);
            ms=now_ms()-s;
            BN_free(a);BN_free(e);BN_free(m);BN_free(res);
        } else if(!strcmp(op,"modexp_e17")){
            BIGNUM*a=BN_new(),*e=BN_new(),*m=BN_new(),*res=BN_new();
            BN_rand(a,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ANY);
            BN_set_word(e,65537);
            BN_rand(m,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD);
            double s=now_ms();
            BN_mod_exp(res,a,e,m,ctx);
            ms=now_ms()-s;
            BN_free(a);BN_free(e);BN_free(m);BN_free(res);
        } else if(!strcmp(op,"trialdiv")){
            /* BN_mod_word over K small odd divisors; mirrors trial-division loop cost */
            int K=calc_trial_divisions(bits);
            BIGNUM*w=BN_new();
            BN_rand(w,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD);
            volatile BN_ULONG acc=0;
            double s=now_ms();
            for(int i=1;i<K;i++){
                acc ^= BN_mod_word(w,(BN_ULONG)(2*i+1));
            }
            ms=now_ms()-s;
            BN_free(w);
        } else if(!strcmp(op,"bn2dec")){
            BIGNUM*a=BN_new();
            BN_rand(a,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ANY);
            double s=now_ms();
            char*d=BN_bn2dec(a);
            ms=now_ms()-s;
            OPENSSL_free(d);
            BN_free(a);
        } else if(!strcmp(op,"dec2bn")){
            BIGNUM*a=BN_new();
            BN_rand(a,bits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ANY);
            char*d=BN_bn2dec(a);         /* build a decimal string of this size */
            BIGNUM*out=NULL;
            double s=now_ms();
            BN_dec2bn(&out,d);
            ms=now_ms()-s;
            OPENSSL_free(d); BN_free(out); BN_free(a);
        } else {
            fprintf(stderr,"unknown op %s\n",op); return 2;
        }
        t[r]=ms;
    }
    BN_CTX_free(ctx);
    qsort(t,reps,sizeof(double),cmp_d);
    double med = t[reps/2];
    printf("%s %d", op, bits);
    for(int r=0;r<reps;r++) printf(" %.3f", t[r]);
    printf(" median %.3f", med);
    { struct rusage ru; getrusage(RUSAGE_SELF,&ru); printf(" maxrss_kb %ld\n", ru.ru_maxrss); }
    free(t);
    return 0;
}
