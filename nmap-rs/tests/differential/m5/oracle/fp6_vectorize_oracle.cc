// C oracle for nmap-rs's core::fp6::vectorize — the IPv6 feature-vector builder.
//
// vectorize() and its helpers are `static` in FPEngine.cc, so they are pasted here
// VERBATIM (the block between the two "BEGIN/END verbatim" markers) and driven by
// nmap's REAL libnetutil PacketParser + TCP/IPv6/ICMPv6 header classes. The Rust port
// reads the same packet bytes and must produce a bit-identical 695-element vector.
//
// Only *containers* the pasted code needs are stubbed, never its logic:
//   * FPPacket   — a 4-method holder (setPacket/getPacket/setTime/getTime); the real
//                  class does exactly this for these methods, and vectorize always
//                  passes a non-NULL senttime, so the stub is faithful for the used path.
//   * FPResponse / FPR6 — plain holders for the fields vectorize reads
//                  (probe_id/buf/len/senttime, and fp_responses/distance/method).
//   * struct model FPModel — only its nr_feature is read; 695 is nmap's real count
//                  (51 + 1 + 637 + 6). feature_node is liblinear's real definition.
//   * o / log_write / LOG_PLAIN — satisfy the o.debugging>2 debug block, which is inert
//                  here (debugging == 0) but must still compile, so the paste stays whole.
//
// Protocol (stdin), one case per block, values printed as %a so the diff is exact:
//   case
//   distance <int>
//   method <0..4>            (dist_calc_method order: NONE,LOCALHOST,DIRECT,ICMP,TRACEROUTE)
//   resp <PROBE_ID> <sent_sec> <sent_usec> <hex-packet>
//   ... (any number of resp lines)
//   end
// Output per case:  v <695 hex-f64, space separated>

#include "IPv6Header.h"
#include "ICMPv6Header.h"
#include "PacketParser.h"
#include "TCPHeader.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <string>
#include <vector>
#include <map>

// ---- Minimal stand-ins for the containers the pasted code names -----------------
#ifndef NELEMS
#define NELEMS(a) (sizeof(a) / sizeof((a)[0]))
#endif
#ifndef TIMEVAL_FSEC_SUBTRACT
#define TIMEVAL_FSEC_SUBTRACT(a, b) \
  ((a).tv_sec - (b).tv_sec + (((a).tv_usec - (b).tv_usec) / 1000000.0))
#endif

enum dist_calc_method {
  DIST_METHOD_NONE,
  DIST_METHOD_LOCALHOST,
  DIST_METHOD_DIRECT,
  DIST_METHOD_ICMP,
  DIST_METHOD_TRACEROUTE
};

#define NUM_FP_PROBES_IPv6 18   // 13 TCP + 4 ICMPv6 + 1 UDP (FPEngine.h)

struct feature_node { int index; double value; };   // liblinear's real definition
struct model { int nr_feature; };
struct model FPModel = { 695 };
static int get_nr_feature(const struct model *m) { return m->nr_feature; }

// A holder matching FPPacket's setPacket/getPacket/setTime/getTime behaviour exactly.
class FPPacket {
  PacketElement *pkt;
  struct timeval pkt_time;
 public:
  FPPacket() : pkt(NULL) { pkt_time.tv_sec = 0; pkt_time.tv_usec = 0; }
  void setPacket(PacketElement *p) { pkt = p; }
  void setTime(const struct timeval *tv) { pkt_time = *tv; }
  const PacketElement *getPacket() const { return pkt; }
  struct timeval getTime() const { return pkt_time; }
};

struct FPResponse {
  const char *probe_id;
  u8 *buf;
  size_t len;
  struct timeval senttime;
};

struct FPR6 {   // the fields vectorize reads off FingerPrintResultsIPv6
  FPResponse *fp_responses[NUM_FP_PROBES_IPv6];
  int distance;
  enum dist_calc_method distance_calculation_method;
};

// Inert stubs for the o.debugging>2 debug block (never taken; must compile).
static struct { int debugging; } o = { 0 };
#define LOG_PLAIN 0
static void log_write(int, const char *, ...) {}

// ============================ BEGIN verbatim from FPEngine.cc =====================
// find_ipv6, find_tcp, find_icmpv6, vectorize_plen/tc/hlim/isr/icmpv6_type/code,
// tcpopt_vectorize_ctx, MODEL_NUM_OPTS, tcpopt_vectorize, vectorize — pasted unchanged
// except vectorize's parameter type (FingerPrintResultsIPv6 -> the field-identical FPR6
// stand-in above). The bodies are untouched.

static const IPv6Header *find_ipv6(const PacketElement *pe) {
  while (pe != NULL && pe->protocol_id() != HEADER_TYPE_IPv6)
    pe = pe->getNextElement();

  return (IPv6Header *) pe;
}

static const TCPHeader *find_tcp(const PacketElement *pe) {
  while (pe != NULL && pe->protocol_id() != HEADER_TYPE_TCP)
    pe = pe->getNextElement();

  return (TCPHeader *) pe;
}

static const ICMPv6Header *find_icmpv6(const PacketElement *pe) {
  while (pe != NULL && pe->protocol_id() != HEADER_TYPE_ICMPv6)
    pe = pe->getNextElement();

  return (ICMPv6Header *) pe;
}

static double vectorize_plen(const PacketElement *pe) {
  const IPv6Header *ipv6;

  ipv6 = find_ipv6(pe);
  if (ipv6 == NULL)
    return -1;
  else
    return ipv6->getPayloadLength();
}

static double vectorize_tc(const PacketElement *pe) {
  const IPv6Header *ipv6;

  ipv6 = find_ipv6(pe);
  if (ipv6 == NULL)
    return -1;
  else
    return ipv6->getTrafficClass();
}

static int vectorize_hlim(const PacketElement *pe, int target_distance, enum dist_calc_method method) {
  const IPv6Header *ipv6;
  int hlim;
  int er_lim;

  ipv6 = find_ipv6(pe);
  if (ipv6 == NULL)
    return -1;
  hlim = ipv6->getHopLimit();

  if (method != DIST_METHOD_NONE) {
      if (method == DIST_METHOD_TRACEROUTE || method == DIST_METHOD_ICMP) {
        if (target_distance > 0)
          hlim += target_distance - 1;
      }
      er_lim = 5;
  } else
    er_lim = 20;

  if (32 - er_lim <= hlim && hlim <= 32+ 5 )
    hlim = 32;
  else if (64 - er_lim <= hlim && hlim <= 64+ 5 )
    hlim = 64;
  else if (128 - er_lim <= hlim && hlim <= 128+ 5 )
    hlim = 128;
  else if (255 - er_lim <= hlim && hlim <= 255+ 5 )
    hlim = 255;
  else
    hlim = -1;

  return hlim;
}

static double vectorize_isr(std::map<std::string, FPPacket>& resps) {
  const char * const SEQ_PROBE_NAMES[] = {"S1", "S2", "S3", "S4", "S5", "S6"};
  u32 seqs[NELEMS(SEQ_PROBE_NAMES)];
  struct timeval times[NELEMS(SEQ_PROBE_NAMES)];
  unsigned int i, j;
  double sum, t;

  j = 0;
  for (i = 0; i < NELEMS(SEQ_PROBE_NAMES); i++) {
    const char *probe_name;
    const FPPacket *fp;
    const TCPHeader *tcp;
    std::map<std::string, FPPacket>::const_iterator it;

    probe_name = SEQ_PROBE_NAMES[i];
    it = resps.find(probe_name);
    if (it == resps.end())
      continue;

    fp = &it->second;
    tcp = find_tcp(fp->getPacket());
    if (tcp == NULL)
      continue;

    seqs[j] = tcp->getSeq();
    times[j] = fp->getTime();
    j++;
  }

  if (j < 2)
    return -1;

  sum = 0.0;
  for (i = 0; i < j - 1; i++)
    sum += seqs[i + 1] - seqs[i];
  t = TIMEVAL_FSEC_SUBTRACT(times[j - 1], times[0]);

  return sum / t;
}

static int vectorize_icmpv6_type(const PacketElement *pe) {
  const ICMPv6Header *icmpv6;

  icmpv6 = find_icmpv6(pe);
  if (icmpv6 == NULL)
    return -1;

  return icmpv6->getType();
}

static int vectorize_icmpv6_code(const PacketElement *pe) {
  const ICMPv6Header *icmpv6;

  icmpv6 = find_icmpv6(pe);
  if (icmpv6 == NULL)
    return -1;

  return icmpv6->getCode();
}

struct tcpopt_vectorize_ctx {
  feature_node *features;
  const unsigned int base;
  unsigned int optnum;
  int mss;
  int sackok;
  int wscale;
  tcpopt_vectorize_ctx(feature_node *f, unsigned int i)
    : features(f), base(i), optnum(0), mss(-1), sackok(-1), wscale(-1) {}
};

static const u8 MODEL_NUM_OPTS = 16;
static bool tcpopt_vectorize(u8 op, u8 oplen, const u8 *data, void *ctx) {
  tcpopt_vectorize_ctx *c = static_cast<tcpopt_vectorize_ctx *>(ctx);
  c->features[c->base + c->optnum].value = op;
  c->features[c->base + c->optnum + MODEL_NUM_OPTS].value = oplen;
  if (op == TCPOPT_MSS && oplen == 4 && c->mss == -1)
    c->mss = (data[2] << 8) + data[3];
  else if (op == TCPOPT_SACKOK && oplen == 2 && c->sackok == -1)
    c->sackok = 1;
  else if (op == TCPOPT_WSCALE && oplen == 3 && c->wscale == -1)
    c->wscale = data[2];
  if (c->optnum++ < MODEL_NUM_OPTS)
    return true;
  return false;
}

static struct feature_node *vectorize(const FPR6 *FPR) {
  const char * const IPV6_PROBE_NAMES[] = {"S1", "S2", "S3", "S4", "S5", "S6", "IE1", "IE2", "NS", "U1", "TECN", "T2", "T3", "T4", "T5", "T6", "T7"};
  const char * const TCP_PROBE_NAMES[] = {"S1", "S2", "S3", "S4", "S5", "S6", "TECN", "T2", "T3", "T4", "T5", "T6", "T7"};
  const char * const ICMPV6_PROBE_NAMES[] = {"IE1", "IE2", "NS"};

  unsigned int nr_feature, i, idx;
  struct feature_node *features;
  std::map<std::string, FPPacket> resps;

  for (i = 0; i < NUM_FP_PROBES_IPv6; i++) {
    PacketElement *pe;

    if (FPR->fp_responses[i] == NULL)
      continue;
    pe = PacketParser::split(FPR->fp_responses[i]->buf, FPR->fp_responses[i]->len);
    assert(pe != NULL);
    resps[FPR->fp_responses[i]->probe_id].setPacket(pe);
    resps[FPR->fp_responses[i]->probe_id].setTime(&FPR->fp_responses[i]->senttime);
  }

  nr_feature = get_nr_feature(&FPModel);
  features = new feature_node[nr_feature + 1];
  for (i = 0; i < nr_feature; i++) {
    features[i].index = i + 1;
    features[i].value = -1;
  }
  features[i].index = -1;

  idx = 0;
  for (i = 0; i < NELEMS(IPV6_PROBE_NAMES); i++) {
    const char *probe_name;

    probe_name = IPV6_PROBE_NAMES[i];
    features[idx++].value = vectorize_plen(resps[probe_name].getPacket());
    features[idx++].value = vectorize_tc(resps[probe_name].getPacket());
    features[idx++].value = vectorize_hlim(resps[probe_name].getPacket(), FPR->distance, FPR->distance_calculation_method);
  }
  /* TCP features */
  features[idx++].value = vectorize_isr(resps);
  for (i = 0; i < NELEMS(TCP_PROBE_NAMES); i++) {
    const char *probe_name;
    const TCPHeader *tcp;
    u16 flags;
    u16 mask;

    probe_name = TCP_PROBE_NAMES[i];

    tcp = find_tcp(resps[probe_name].getPacket());
    if (tcp == NULL) {
      /* 49 TCP features. */
      idx += 49;
      continue;
    }
    features[idx++].value = tcp->getWindow();
    flags = tcp->getFlags16();
    for (mask = 0x001; mask <= 0x800; mask <<= 1)
      features[idx++].value = (flags & mask) != 0;

    TCPOptions opts;
    tcpopt_vectorize_ctx ctx(features, idx);
    if (opts.fromTCPHeader(*tcp)) {
      opts.foreachOpt(tcpopt_vectorize, &ctx);
    }
    idx += MODEL_NUM_OPTS * 2;

    features[idx++].value = ctx.mss;
    features[idx++].value = ctx.sackok;
    features[idx++].value = ctx.wscale;
    features[idx++].value = (ctx.mss > 0) ? (float)tcp->getWindow() / ctx.mss : -1;
  }
  /* ICMPv6 features */
  for (i = 0; i < NELEMS(ICMPV6_PROBE_NAMES); i++) {
    const char *probe_name;

    probe_name = ICMPV6_PROBE_NAMES[i];
    features[idx++].value = vectorize_icmpv6_type(resps[probe_name].getPacket());
    features[idx++].value = vectorize_icmpv6_code(resps[probe_name].getPacket());
  }

  assert(idx == nr_feature);

  if (o.debugging > 2) {
    log_write(LOG_PLAIN, "v = {");
    for (i = 0; i < nr_feature; i++)
      log_write(LOG_PLAIN, "%.16g, ", features[i].value);
    log_write(LOG_PLAIN, "};\n");
  }

  return features;
}
// ============================ END verbatim from FPEngine.cc =======================

// Map a probe id to its slot in fp_responses[]. Order is irrelevant to vectorize (it
// keys by probe_id string), so any stable assignment works; this uses input order.
static std::vector<unsigned char> unhex(const std::string &s) {
  std::vector<unsigned char> out;
  int hi = -1;
  for (char ch : s) {
    int v;
    if (ch >= '0' && ch <= '9') v = ch - '0';
    else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
    else continue;
    if (hi < 0) hi = v;
    else { out.push_back((unsigned char)((hi << 4) | v)); hi = -1; }
  }
  return out;
}

int main() {
  std::string line;
  auto getline_str = [](std::string &out) -> bool {
    out.clear();
    int c;
    bool any = false;
    while ((c = getchar()) != EOF) {
      any = true;
      if (c == '\n') return true;
      out.push_back((char) c);
    }
    return any;
  };

  FPR6 fpr;
  // Per-case backing storage, all reserved so no reallocation invalidates a pointer
  // handed to FPResponse (buf) or fp_responses (which point into these vectors).
  std::vector<std::vector<unsigned char>> buffers;
  std::vector<std::string> ids;
  std::vector<FPResponse> responses;
  int nresp = 0;
  bool in_case = false;

  auto reset_case = [&]() {
    memset(&fpr, 0, sizeof(fpr));
    fpr.distance = -1;
    fpr.distance_calculation_method = DIST_METHOD_NONE;
    buffers.clear();
    buffers.reserve(NUM_FP_PROBES_IPv6);
    ids.clear();
    ids.reserve(NUM_FP_PROBES_IPv6);
    responses.clear();
    responses.reserve(NUM_FP_PROBES_IPv6);
    nresp = 0;
  };

  auto emit_case = [&]() {
    // Wire every pointer now that all backing vectors are fully populated and stable.
    for (int k = 0; k < nresp; k++) {
      responses[k].probe_id = ids[k].c_str();
      responses[k].buf = buffers[k].data();
      responses[k].len = buffers[k].size();
      fpr.fp_responses[k] = &responses[k];
    }
    feature_node *f = vectorize(&fpr);
    printf("v");
    for (int i = 0; i < 695; i++) {
      uint64_t bits;
      memcpy(&bits, &f[i].value, sizeof(bits));   // exact bit pattern, NaN/inf included
      printf(" %016llx", (unsigned long long) bits);
    }
    printf("\n");
    delete[] f;
  };

  while (getline_str(line)) {
    if (line.empty()) continue;
    if (line == "case") { reset_case(); in_case = true; continue; }
    if (line == "end") { if (in_case) emit_case(); in_case = false; continue; }
    if (!in_case) continue;

    if (line.rfind("distance ", 0) == 0) {
      fpr.distance = atoi(line.c_str() + 9);
    } else if (line.rfind("method ", 0) == 0) {
      fpr.distance_calculation_method = (enum dist_calc_method) atoi(line.c_str() + 7);
    } else if (line.rfind("resp ", 0) == 0) {
      // resp <ID> <sec> <usec> <hex>
      char id[16];
      long sec, usec;
      int consumed = 0;
      if (sscanf(line.c_str(), "resp %15s %ld %ld %n", id, &sec, &usec, &consumed) >= 3
          && nresp < NUM_FP_PROBES_IPv6) {
        buffers.push_back(unhex(line.c_str() + consumed));
        ids.push_back(std::string(id));
        FPResponse r;
        memset(&r, 0, sizeof(r));
        r.senttime.tv_sec = sec;
        r.senttime.tv_usec = usec;
        responses.push_back(r);
        nresp++;
      }
    }
  }
  return 0;
}
