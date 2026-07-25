// C oracle for core::osprobe::seq — the numeric core of makeTSeqFP.
//
// gcd_n_uint, the ISN rate/stddev block and the TS bucketing below are copied
// VERBATIM from osscan2.cc, so this exercises nmap's own arithmetic rather than a
// restatement of it. The surrounding HostOsScan plumbing is replaced by a stdin
// driver, because the original is a method on a class that pulls in most of nmap.
//
// The IP-ID classification (TI/CI/II) is deliberately NOT covered here: it lives in
// core::ipid, which already has its own C-oracle differential from M4.
//
// Input: one case per line
//     <scan_delay_ms> <n> <isn>:<usec>:<ts> [...]
// Output: one line per case
//     SP=<hex|-> GCD=<hex|-> ISR=<hex|-> TS=<hex|-|0|U>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>

typedef unsigned int u32;

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MOD_DIFF(a,b) ((u32) (MIN((u32)(a) - (u32 ) (b), (u32 )(b) - (u32) (a))))

#define NUM_SEQ_SAMPLES 6

/* --- verbatim from osscan2.cc --- */
static unsigned int gcd_n_uint(int nvals, unsigned int *val) {
  unsigned int a, b, c;

  if (!nvals)
    return 1;
  a = *val;
  for (nvals--; nvals; nvals--) {
    b = *++val;
    if (a < b) {
      c = a;
      a = b;
      b = c;
    }
    while (b) {
      c = a % b;
      a = b;
      b = c;
    }
  }
  return a;
}
/* --- end verbatim --- */

int main(void) {
  char line[8192];
  while (fgets(line, sizeof(line), stdin)) {
    long scan_delay = 0;
    int n = 0;
    char *p = line;
    scan_delay = strtol(p, &p, 10);
    n = (int) strtol(p, &p, 10);
    if (n < 0) n = 0;
    if (n > NUM_SEQ_SAMPLES) n = NUM_SEQ_SAMPLES;

    u32 seqs[NUM_SEQ_SAMPLES];
    unsigned long long times[NUM_SEQ_SAMPLES];
    u32 tstamps[NUM_SEQ_SAMPLES];
    for (int i = 0; i < n; i++) {
      seqs[i]    = (u32) strtoul(p, &p, 10); if (*p == ':') p++;
      times[i]   = strtoull(p, &p, 10);      if (*p == ':') p++;
      tstamps[i] = (u32) strtoul(p, &p, 10);
    }

    u32 seq_diffs[NUM_SEQ_SAMPLES];
    u32 ts_diffs[NUM_SEQ_SAMPLES];
    float seq_rates[NUM_SEQ_SAMPLES];
    unsigned long time_usec_diffs[NUM_SEQ_SAMPLES];
    double seq_avg_rate = 0, seq_rate = 0, seq_stddev = 0;
    u32 seq_gcd = 1;
    int responses = n;
    long index = -1;
    int have_isn = 0;

    for (int j = 1; j < n; j++) {
      seq_diffs[j - 1] = MOD_DIFF(seqs[j], seqs[j - 1]);
      ts_diffs[j - 1] = MOD_DIFF(tstamps[j], tstamps[j - 1]);
      time_usec_diffs[j - 1] = (unsigned long) (times[j] - times[j - 1]);
      if (!time_usec_diffs[j - 1]) time_usec_diffs[j - 1]++;
      seq_rates[j - 1] = seq_diffs[j - 1] * 1000000.0 / time_usec_diffs[j - 1];
      seq_avg_rate += seq_rates[j - 1];
    }

    /* --- verbatim from osscan2.cc (makeTSeqFP) --- */
    if (responses >= 4 && scan_delay <= 1000) {
      have_isn = 1;
      seq_avg_rate /= responses - 1;
      seq_rate = seq_avg_rate;
      seq_gcd = gcd_n_uint(responses - 1, seq_diffs);

      if (!seq_gcd) {
        seq_rate = 0;
        seq_stddev = 0;
        index = 0;
      } else {
        seq_rate = log(seq_rate) / log(2.0);
        seq_rate = (unsigned int) (seq_rate * 8 + 0.5);

        int div_gcd = 1;
        if (seq_gcd > 9)
          div_gcd = seq_gcd;

        for (int i = 0; i < responses - 1; i++) {
          double rtmp = seq_rates[i] / div_gcd - seq_avg_rate / div_gcd;
          seq_stddev += rtmp * rtmp;
        }
        seq_stddev /= responses - 2;
        seq_stddev = sqrt(seq_stddev);

        if (seq_stddev <= 1)
          index = 0;
        else {
          seq_stddev = log(seq_stddev) / log(2.0);
          index = (int) (seq_stddev * 8 + 0.5);
        }
      }
    }
    /* --- end verbatim --- */

    /* TS: only the TS_SEQ_UNKNOWN path, which is what the frequency analysis covers. */
    double avg_ts_hz = 0.0;
    int ts_known = 0;
    int tsnewval = 0;
    if (responses >= 2) {
      for (int i = 0; i < responses - 1; i++) {
        double dhz = (double) ts_diffs[i] / (time_usec_diffs[i] / 1000000.0);
        avg_ts_hz += dhz / (responses - 1);
      }
      if (avg_ts_hz > 0) {
        ts_known = 1;
        /* --- verbatim --- */
        if (avg_ts_hz <= 5.66) {
          tsnewval = 1;
        } else if (avg_ts_hz > 70 && avg_ts_hz <= 150) {
          tsnewval = 7;
        } else if (avg_ts_hz > 150 && avg_ts_hz <= 350) {
          tsnewval = 8;
        } else {
          tsnewval = (unsigned int)(0.5 + log(avg_ts_hz) / log(2.0));
        }
        /* --- end verbatim --- */
      }
    }

    if (have_isn)
      printf("SP=%lX GCD=%X ISR=%X", index, seq_gcd, (unsigned int) seq_rate);
    else
      printf("SP=- GCD=- ISR=-");
    if (ts_known)
      printf(" TS=%X\n", tsnewval);
    else
      printf(" TS=-\n");
  }
  return 0;
}
