// IPv6 scan-probe oracle — the C side of the IPv6 builders in core::build and the
// probe builders in core::{synscan,udpscan,flagscan} (IPv6 scans step c).
//
// The builders are nmap's own, extracted unchanged into scanprobe6_c.inc by
// build_scanprobe6_oracle.sh (the list is there). This file supplies what they
// reference and the oracle does not otherwise have (o.badsum, safe_malloc, fatal,
// and the random hooks no case reaches), and transcribes, with line references, how
// sendIPScanProbe (scan_engine_raw.cc:1166) chooses their arguments for an IPv6
// target. One case per stdin line, one packet in hex per stdout line:
//
//   tcp <src> <dst> <tc> <flow> <hlim> <sport> <dport> <seq> <ack> <res> <flags>
//       <win> <urp> <opts|-> <data|-> <badsum 0|1>        build_tcp_raw_ipv6
//   udp <src> <dst> <tc> <flow> <hlim> <sport> <dport> <data|-> <badsum 0|1>
//                                                            build_udp_raw_ipv6
//   probe <scan> <src> <dst> <ttl> <base> <dport> <tryno> <seqmask> <data|-> <badsum>
//       sendIPScanProbe's TCP/UDP IPv6 arm; <tryno> is tryno_t's opaque byte,
//       <ttl> is o.ttl (-1 when --ttl is not given)
//
// Addresses are 32 hex digits; numbers are decimal; byte strings hex.

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <stdint.h>
#include <netinet/in.h>
#include <dnet/os.h>
#include <dnet/ip.h>
#include <dnet/ip6.h>
#include <dnet/tcp.h>
#include <dnet/udp.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

// What the extracted code references.
static struct { bool badsum; } o;
static void *safe_malloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) abort(); return p; }
static void fatal(const char *fmt, ...) { fprintf(stderr, "fatal: %s\n", fmt); exit(2); }
// Reached only for a SYN with sequence 0 (build_tcp) and a hop limit of -1
// (build_ipv6_raw); no case has either, so reaching one is an error.
static void get_random_bytes(void *, int) { fprintf(stderr, "random sequence reached\n"); exit(3); }
static unsigned int get_random_uint() { fprintf(stderr, "random hop limit reached\n"); exit(3); }
// scan_engine.h's tryno_t and the one UltraScanInfo field seq32_encode reads.
union _tryno_u { struct { u8 isPing : 1; u8 seqnum : 7; } fields; u8 opaque; };
typedef union _tryno_u tryno_t;
struct UltraScanInfo { u32 seqmask; };

#include "scanprobe6_c.inc"

#define TCP_SYN_PROBE_OPTIONS "\x02\x04\x05\xb4"                 // nmap.h:163
#define TCP_SYN_PROBE_OPTIONS_LEN (sizeof(TCP_SYN_PROBE_OPTIONS)-1) // nmap.h:164

static std::vector<u8> unhex(const std::string &s) {
  std::vector<u8> out;
  if (s == "-") return out;
  for (size_t i = 0; i + 1 < s.size(); i += 2)
    out.push_back((u8)strtoul(s.substr(i, 2).c_str(), NULL, 16));
  return out;
}

static struct in6_addr addr(const std::string &s) {
  struct in6_addr a;
  std::vector<u8> b = unhex(s);
  if (b.size() != 16) { fprintf(stderr, "bad address %s\n", s.c_str()); exit(2); }
  memcpy(&a, b.data(), 16);
  return a;
}

static void emit(const u8 *p, u32 len) {
  for (u32 i = 0; i < len; i++) printf("%02x", p[i]);
  printf("\n");
}

// The flags each scan type sends (scan_engine.cc:1292), or -1 for UDP.
static int scan_flags(const std::string &scan) {
  if (scan == "syn") return TH_SYN;
  if (scan == "ack" || scan == "window") return TH_ACK;
  if (scan == "xmas") return TH_FIN | TH_URG | TH_PUSH;
  if (scan == "null") return 0;
  if (scan == "fin") return TH_FIN;
  if (scan == "maimon") return TH_FIN | TH_ACK;
  if (scan == "udp") return -1;
  fprintf(stderr, "bad scan %s\n", scan.c_str());
  exit(2);
}

int main() {
  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream in(line);
    std::string kind;
    in >> kind;
    u32 len = 0;
    u8 *pkt = NULL;
    if (kind == "tcp") {
      std::string src, dst, opts, data;
      unsigned tc, flow, hlim, sport, dport, res, flags, win, urp, bad;
      unsigned long seq, ack;
      in >> src >> dst >> tc >> flow >> hlim >> sport >> dport >> seq >> ack >> res >> flags
         >> win >> urp >> opts >> data >> bad;
      struct in6_addr s = addr(src), d = addr(dst);
      std::vector<u8> ob = unhex(opts), db = unhex(data);
      o.badsum = bad;
      pkt = build_tcp_raw_ipv6(&s, &d, tc, flow, hlim, sport, dport, seq, ack, res, flags,
                               win, urp, ob.data(), ob.size(), (const char *)db.data(),
                               db.size(), &len);
    } else if (kind == "udp") {
      std::string src, dst, data;
      unsigned tc, flow, hlim, sport, dport, bad;
      in >> src >> dst >> tc >> flow >> hlim >> sport >> dport >> data >> bad;
      struct in6_addr s = addr(src), d = addr(dst);
      std::vector<u8> db = unhex(data);
      o.badsum = bad;
      pkt = build_udp_raw_ipv6(&s, &d, tc, flow, hlim, sport, dport, (const char *)db.data(),
                               db.size(), &len);
    } else if (kind == "probe") {
      std::string scan, src, dst, data;
      int ttl;
      unsigned base, dport, tryno, bad;
      unsigned long seqmask;
      in >> scan >> src >> dst >> ttl >> base >> dport >> tryno >> seqmask >> data >> bad;
      struct in6_addr s = addr(src), d = addr(dst);
      std::vector<u8> db = unhex(data);
      UltraScanInfo usi = { (u32)seqmask };
      tryno_t t;
      t.opaque = (u8)tryno;
      o.badsum = bad;
      u16 sport = sport_encode(base, t);                       // (:1194)
      int flags = scan_flags(scan);
      if (flags >= 0) {                                         // PS_TCP (:1199)
        u32 seq = 0, ack = 0;
        if (flags & TH_ACK)                                     // (:1205)
          ack = seq32_encode(&usi, t);
        else
          seq = seq32_encode(&usi, t);
        const u8 *tcpops = NULL;
        u16 tcpopslen = 0;
        if (flags & TH_SYN) {                                   // (:1210)
          tcpops = (const u8 *)TCP_SYN_PROBE_OPTIONS;
          tcpopslen = TCP_SYN_PROBE_OPTIONS_LEN;
        }
        // (:1233) traffic class 0, flow label 0, o.ttl into the u8 hop limit,
        // reserved 0, window 0 (1024 by build_tcp), urgent 0, o.extra_payload.
        pkt = build_tcp_raw_ipv6(&s, &d, 0, 0, ttl, sport, dport, seq, ack, 0, flags, 0, 0,
                                 tcpops, tcpopslen, (const char *)db.data(), db.size(), &len);
      } else {                                                  // PS_UDP (:1278)
        pkt = build_udp_raw_ipv6(&s, &d, 0, 0, ttl, sport, dport, (const char *)db.data(),
                                 db.size(), &len);
      }
    } else {
      continue;
    }
    emit(pkt, len);
    free(pkt);
  }
  return 0;
}
