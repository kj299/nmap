// M4 IP-ID sequence-classification oracle — the C side of core::ipid.
//
// A near-verbatim copy of get_diffs / identify_sequence / get_ipid_sequence_16 /
// get_ipid_sequence_32 from osscan2.cc (they are self-contained u32 arithmetic with
// no nmap globals). Reads one case per stdin line and prints one class token per line:
//   <bits 16|32> <islocalhost 0|1> <numSamples> <ipid0> <ipid1> ...
// Output: unknown incr broken_incr rpi rd constant zero incr_by_2

#include <cstdio>
#include <cstdint>
#include <cstring>

typedef uint32_t u32;

#define IPID_SEQ_UNKNOWN 0
#define IPID_SEQ_INCR 1
#define IPID_SEQ_BROKEN_INCR 2
#define IPID_SEQ_RPI 3
#define IPID_SEQ_RD 4
#define IPID_SEQ_CONSTANT 5
#define IPID_SEQ_ZERO 6
#define IPID_SEQ_INCR_BY_2 7

// --- verbatim from osscan2.cc ---------------------------------------------------
int identify_sequence(int numSamples, u32 *ipid_diffs, int islocalhost) {
  int i, j, k, l;
  if (islocalhost) {
    int allgto = 1;
    for (i = 0; i < numSamples - 1; i++) {
      if (ipid_diffs[i] < 2) { allgto = 0; break; }
    }
    if (allgto) {
      for (i = 0; i < numSamples - 1; i++) {
        if (ipid_diffs[i] % 256 == 0) ipid_diffs[i] -= 256;
        else ipid_diffs[i]--;
      }
    }
  }
  j = 1;
  for (i = 0; i < numSamples - 1; i++) {
    if (ipid_diffs[i] != 0) { j = 0; break; }
  }
  if (j) return IPID_SEQ_CONSTANT;
  for (i = 0; i < numSamples - 1; i++) {
    if (ipid_diffs[i] > 1000 &&
        (ipid_diffs[i] % 256 != 0 ||
        (ipid_diffs[i] % 256 == 0 && ipid_diffs[i] >= 25600))) {
      return IPID_SEQ_RPI;
    }
  }
  j = 1; k = 1; l = 1;
  for (i = 0; i < numSamples - 1; i++) {
    if (k && (ipid_diffs[i] > 5120 || ipid_diffs[i] % 256 != 0)) k = 0;
    if (l && ipid_diffs[i] % 2 != 0) l = 0;
    if (j && ipid_diffs[i] > 9) j = 0;
  }
  if (k == 1) return IPID_SEQ_BROKEN_INCR;
  if (l == 1) return IPID_SEQ_INCR_BY_2;
  if (j == 1) return IPID_SEQ_INCR;
  return IPID_SEQ_UNKNOWN;
}

int get_diffs(u32 *ipid_diffs, int numSamples, const u32 *ipids, int islocalhost) {
  int i;
  bool allipideqz = true;
  if (numSamples < 2) return IPID_SEQ_UNKNOWN;
  for (i = 1; i < numSamples; i++) {
    if (ipids[i - 1] != 0 || ipids[i] != 0) allipideqz = false;
    ipid_diffs[i - 1] = ipids[i] - ipids[i - 1];
    if (numSamples > 2 && ipid_diffs[i - 1] > 20000) return IPID_SEQ_RD;
  }
  if (allipideqz) return IPID_SEQ_ZERO;
  else return -1;
}

int get_ipid_sequence_32(int numSamples, const u32 *ipids, int islocalhost) {
  u32 ipid_diffs[32];
  int ipid_seq = get_diffs(ipid_diffs, numSamples, ipids, islocalhost);
  if (ipid_seq < 0) return identify_sequence(numSamples, ipid_diffs, islocalhost);
  else return ipid_seq;
}

int get_ipid_sequence_16(int numSamples, const u32 *ipids, int islocalhost) {
  int i;
  u32 ipid_diffs[32];
  int ipid_seq = get_diffs(ipid_diffs, numSamples, ipids, islocalhost);
  for (i = 0; i < numSamples; i++) ipid_diffs[i] = ipid_diffs[i] & 0xffff;
  if (ipid_seq < 0) return identify_sequence(numSamples, ipid_diffs, islocalhost);
  else return ipid_seq;
}
// --- end verbatim ----------------------------------------------------------------

static const char *tok(int c) {
  switch (c) {
  case IPID_SEQ_INCR: return "incr";
  case IPID_SEQ_BROKEN_INCR: return "broken_incr";
  case IPID_SEQ_RPI: return "rpi";
  case IPID_SEQ_RD: return "rd";
  case IPID_SEQ_CONSTANT: return "constant";
  case IPID_SEQ_ZERO: return "zero";
  case IPID_SEQ_INCR_BY_2: return "incr_by_2";
  default: return "unknown";
  }
}

int main(void) {
  char line[4096];
  while (fgets(line, sizeof(line), stdin)) {
    int bits = 0, islocal = 0, n = 0;
    char *p = line;
    int consumed = 0;
    if (sscanf(p, "%d %d %d%n", &bits, &islocal, &n, &consumed) < 3) continue;
    p += consumed;
    if (n < 0 || n > 31) { printf("unknown\n"); continue; }
    u32 ipids[32];
    bool ok = true;
    for (int i = 0; i < n; i++) {
      unsigned v; int c2 = 0;
      if (sscanf(p, "%u%n", &v, &c2) < 1) { ok = false; break; }
      ipids[i] = v; p += c2;
    }
    if (!ok) { printf("unknown\n"); continue; }
    int r = (bits == 16) ? get_ipid_sequence_16(n, ipids, islocal)
                         : get_ipid_sequence_32(n, ipids, islocal);
    printf("%s\n", tok(r));
  }
  return 0;
}
