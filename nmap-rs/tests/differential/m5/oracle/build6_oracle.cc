// M5 IPv6 probe-battery oracle — the C side.
//
// Emits the exact wire bytes nmap's own `FPHost6::build_probe_list()` produces for the
// 17 IPv6 OS-detection probes, so `core::build6` can be gated on **byte identity** with
// nmap rather than on "nmap can parse what we emit".
//
// ---------------------------------------------------------------------------
// WHAT WAS COPIED, AND WHAT WAS CHANGED
//
// `build_probe_list()` is an `FPHost6` method whose inputs come from member state that
// is seeded by randomness, by `NmapOps o`, and by the network controller. Its BODY is
// pasted here verbatim — every header allocation, every setter, in the original order,
// including the `TCP_DESCS` table copied byte for byte from FPEngine.cc. The only
// changes, each of which is a substitution of an *input*, never of logic:
//
//   * member reads become fields of `struct Params` supplied on stdin:
//       this->target_host->SourceSockAddr()/TargetSockAddr()  -> p.src / p.dst
//       this->open_port_tcp / closed_port_tcp / closed_port_udp
//       this->tcp_port_base / udp_port_base / tcpSeqBase / icmp_seq_counter
//       this->target_host->directlyConnected()                -> p.directly_connected
//   * `get_hoplimit()` (which reads `o.ttl` or a random value) -> p.hoplimit, and the
//     NS probe keeps its hard-coded 255 exactly as the C does.
//   * `get_random_u32()` for each TCP probe's ACK -> p.tcp_ack[i], so the battery is
//     reproducible. The C passes a fresh random per probe EXCEPT for TECN, which
//     passes a literal 0; that asymmetry is preserved.
//   * the `this->fp_probes[...]` bookkeeping (host pointer, setProbeID, setEthernet,
//     total_probes/timed_probes counters) is replaced by `emit(id, ip6)`, which dumps
//     the chain's bytes. No Ethernet header is added: the comparison is at the IP
//     layer, which is what `l2_frames()` gates in the C.
//
// Nothing else is retyped. In particular `make_tcp` and `get_hoplimit`'s NS/255 rule
// are reproduced as-is, and the probe ORDER (S1-S6, IE1, IE2, NS, U1, TECN, T2-T7) is
// the C's, including that `i` is left at 6 by the timed loop so TCP_DESCS[6] is TECN.
//
// Build: see build_build6_oracle.sh.
// ---------------------------------------------------------------------------

#include "DestOptsHeader.h"
#include "HopByHopHeader.h"
#include "ICMPv6Header.h"
#include "IPv6Header.h"
#include "RawData.h"
#include "RoutingHeader.h"
#include "TCPHeader.h"
#include "UDPHeader.h"
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define OPEN 1
#define CLSD 0

/* Copied from FPEngine.h. */
static const unsigned int OSDETECT_FLOW_LABEL = 0x12345;
#define NUM_FP_PROBES_IPv6_TCP    13
#define NUM_FP_TIMEDPROBES_IPv6 6

/* Copied verbatim from FPEngine.cc. */
struct tcp_desc {
  const char *id;
  u16 win;
  u8 flags;
  u16 dstport;
  u16 urgptr;
  const char *opts;
  unsigned int optslen;
};

/* The inputs build_probe_list() would have read from member state. */
struct Params {
  struct in6_addr src, dst;
  int open_port_tcp, closed_port_tcp, closed_port_udp;
  u16 tcp_port_base, udp_port_base;
  u32 tcpSeqBase;
  u32 tcp_ack[NUM_FP_PROBES_IPv6_TCP];
  u8 hoplimit;
  u16 icmp_seq_counter;
  int directly_connected;
};

static void emit(const char *id, PacketElement *ip6) {
  u8 buf[4096];
  int len = ip6->dumpToBinaryBuffer(buf, sizeof(buf));
  printf("probe %s ", id);
  for (int i = 0; i < len; i++)
    printf("%02x", buf[i]);
  printf("\n");
}

/* Copied verbatim from FPEngine.cc, with get_hoplimit() -> hoplimit parameter. */
static IPv6Header *make_tcp(const struct in6_addr *src, const struct in6_addr *dst,
  u32 fl, u16 win, u32 seq, u32 ack, u8 flags, u16 srcport, u16 dstport,
  u16 urgptr, const char *opts, unsigned int optslen, u8 hoplimit) {
  IPv6Header *ip6;
  TCPHeader *tcp;

  /* Allocate an instance of the protocol headers */
  ip6 = new IPv6Header();
  tcp = new TCPHeader();

  ip6->setSourceAddress(*src);
  ip6->setDestinationAddress(*dst);

  ip6->setFlowLabel(fl);
  ip6->setHopLimit(hoplimit);
  ip6->setNextHeader("TCP");
  ip6->setNextElement(tcp);

  tcp->setWindow(win);
  tcp->setSeq(seq);
  tcp->setAck(ack);
  tcp->setFlags(flags);
  tcp->setSourcePort(srcport);
  tcp->setDestinationPort(dstport);
  tcp->setUrgPointer(urgptr);
  tcp->setOptions((u8 *) opts, optslen);

  ip6->setPayloadLength(tcp->getLen());
  tcp->setSum();

  return ip6;
}

static void build_probe_list(const Params &p) {
  /* TCP Options:
   *  S1-S6: six sequencing probes.
   *  TECN:  ECN probe.
   *  T2-T7: other non-sequencing probes. */
  const struct tcp_desc TCP_DESCS[] = {
    { "S1",     1, 0x02, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x05\xb4\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "S2",    63, 0x02, OPEN,     0,
      "\x02\x04\x05\x78\x03\x03\x00\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x00", 20 },
    { "S3",     4, 0x02, OPEN,     0,
      "\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x01\x01\x03\x03\x05\x01\x02\x04\x02\x80", 20 },
    { "S4",     4, 0x02, OPEN,     0,
      "\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00", 16 },
    { "S5",    16, 0x02, OPEN,     0,
      "\x02\x04\x02\x18\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00", 20 },
    { "S6",   512, 0x02, OPEN,     0,
      "\x02\x04\x01\x09\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00", 16 },
    { "TECN",   3, 0xc2, OPEN, 63477,
      "\x03\x03\x0A\x01\x02\x04\x05\xb4\x04\x02\x01\x01", 12 },
    { "T2",   128, 0x00, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T3",   256, 0x2b, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T4",  1024, 0x10, OPEN,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T5", 31337, 0x02, CLSD,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T6", 32768, 0x10, CLSD,     0,
      "\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
    { "T7", 65535, 0x29, CLSD,     0,
      "\x03\x03\x0f\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02", 20 },
  };

  IPv6Header *ip6;
  ICMPv6Header *icmp6;
  UDPHeader *udp;
  DestOptsHeader *dstopts;
  RoutingHeader *routing;
  HopByHopHeader *hopbyhop1, *hopbyhop2;
  RawData *payload;
  int i;
  char payloadbuf[300];
  u16 icmp_seq_counter = p.icmp_seq_counter;

  /* Set timed TCP probes */
  for (i = 0; i < NUM_FP_PROBES_IPv6_TCP && i < NUM_FP_TIMEDPROBES_IPv6; i++) {
    if (TCP_DESCS[i].dstport == OPEN && p.open_port_tcp < 0)
      continue;
    if (TCP_DESCS[i].dstport == CLSD && p.closed_port_tcp < 0)
      continue;

    ip6 = make_tcp(&p.src, &p.dst,
      OSDETECT_FLOW_LABEL, TCP_DESCS[i].win, p.tcpSeqBase + i, p.tcp_ack[i],
      TCP_DESCS[i].flags, p.tcp_port_base + i,
      TCP_DESCS[i].dstport == OPEN ? p.open_port_tcp : p.closed_port_tcp,
      TCP_DESCS[i].urgptr, TCP_DESCS[i].opts, TCP_DESCS[i].optslen, p.hoplimit);
    emit(TCP_DESCS[i].id, ip6);
  }

  /* Set ICMPv6 probes */

  memset(payloadbuf, 0, 120);

  /* ICMP Probe #1: Echo Request with hop-by-hop options */
  ip6 = new IPv6Header();
  icmp6 = new ICMPv6Header();
  hopbyhop1 = new HopByHopHeader();
  payload = new RawData();
  ip6->setSourceAddress(p.src);
  ip6->setDestinationAddress(p.dst);
  ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
  ip6->setHopLimit(p.hoplimit);
  ip6->setNextHeader((u8) HEADER_TYPE_IPv6_HOPOPT);
  ip6->setNextElement(hopbyhop1);
  hopbyhop1->setNextHeader(HEADER_TYPE_ICMPv6);
  hopbyhop1->setNextElement(icmp6);
  icmp6->setNextElement(payload);
  payload->store((u8 *) payloadbuf, 120);
  icmp6->setType(ICMPv6_ECHO);
  icmp6->setCode(9); // But is supposed to be 0.
  icmp6->setIdentifier(0xabcd);
  icmp6->setSequence(icmp_seq_counter++);
  icmp6->setTargetAddress(p.dst); // Should still contain target's addr
  ip6->setPayloadLength();
  icmp6->setSum();
  emit("IE1", ip6);

  /* ICMP Probe #2: Echo Request with badly ordered extension headers */
  ip6 = new IPv6Header();
  hopbyhop1 = new HopByHopHeader();
  dstopts = new DestOptsHeader();
  routing = new RoutingHeader();
  hopbyhop2 = new HopByHopHeader();
  icmp6 = new ICMPv6Header();
  ip6->setSourceAddress(p.src);
  ip6->setDestinationAddress(p.dst);
  ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
  ip6->setHopLimit(p.hoplimit);
  ip6->setNextHeader((u8) HEADER_TYPE_IPv6_HOPOPT);
  ip6->setNextElement(hopbyhop1);
  hopbyhop1->setNextHeader(HEADER_TYPE_IPv6_OPTS);
  hopbyhop1->setNextElement(dstopts);
  dstopts->setNextHeader(HEADER_TYPE_IPv6_ROUTE);
  dstopts->setNextElement(routing);
  routing->setNextHeader(HEADER_TYPE_IPv6_HOPOPT);
  routing->setNextElement(hopbyhop2);
  hopbyhop2->setNextHeader(HEADER_TYPE_ICMPv6);
  hopbyhop2->setNextElement(icmp6);
  icmp6->setType(ICMPv6_ECHO);
  icmp6->setCode(0);
  icmp6->setIdentifier(0xabcd);
  icmp6->setSequence(icmp_seq_counter++);
  icmp6->setTargetAddress(p.dst); // Should still contain target's addr
  ip6->setPayloadLength();
  icmp6->setSum();
  emit("IE2", ip6);

  /* ICMP Probe #3: Neighbor Solicitation. (only sent to on-link targets) */
  if (p.directly_connected) {
    ip6 = new IPv6Header();
    icmp6 = new ICMPv6Header();
    ip6->setSourceAddress(p.src);
    ip6->setDestinationAddress(p.dst);
    ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
    /* RFC 2461 section 7.1.1 */
    ip6->setHopLimit(255);
    ip6->setNextHeader("ICMPv6");
    ip6->setNextElement(icmp6);
    icmp6->setType(ICMPv6_NGHBRSOLICIT);
    icmp6->setCode(0);
    icmp6->setTargetAddress(p.dst);
    icmp6->setSum();
    ip6->setPayloadLength();
    emit("NS", ip6);
  }

  /* Set UDP probes */

  memset(payloadbuf, 0x43, 300);

  ip6 = new IPv6Header();
  udp = new UDPHeader();
  payload = new RawData();
  ip6->setSourceAddress(p.src);
  ip6->setDestinationAddress(p.dst);
  ip6->setFlowLabel(OSDETECT_FLOW_LABEL);
  ip6->setHopLimit(p.hoplimit);
  ip6->setNextHeader("UDP");
  ip6->setNextElement(udp);
  udp->setSourcePort(p.udp_port_base);
  udp->setDestinationPort(p.closed_port_udp);
  payload->store((u8 *) payloadbuf, 300);
  udp->setNextElement(payload);
  udp->setTotalLength();
  udp->setSum();
  ip6->setPayloadLength(udp->getLen());
  emit("U1", ip6);

  /* Set TECN probe */
  if ((TCP_DESCS[i].dstport == OPEN && p.open_port_tcp >= 0)
      || (TCP_DESCS[i].dstport == CLSD && p.closed_port_tcp >= 0)) {
    ip6 = make_tcp(&p.src, &p.dst,
      OSDETECT_FLOW_LABEL, TCP_DESCS[i].win, p.tcpSeqBase + i, 0,
      TCP_DESCS[i].flags, p.tcp_port_base + i,
      TCP_DESCS[i].dstport == OPEN ? p.open_port_tcp : p.closed_port_tcp,
      TCP_DESCS[i].urgptr, TCP_DESCS[i].opts, TCP_DESCS[i].optslen, p.hoplimit);
    emit(TCP_DESCS[i].id, ip6);
  }
  i++;

  /* Set untimed TCP probes */
  for (; i < NUM_FP_PROBES_IPv6_TCP; i++) {
    if (TCP_DESCS[i].dstport == OPEN && p.open_port_tcp < 0)
      continue;
    if (TCP_DESCS[i].dstport == CLSD && p.closed_port_tcp < 0)
      continue;

    ip6 = make_tcp(&p.src, &p.dst,
      OSDETECT_FLOW_LABEL, TCP_DESCS[i].win, p.tcpSeqBase + i, p.tcp_ack[i],
      TCP_DESCS[i].flags, p.tcp_port_base + i,
      TCP_DESCS[i].dstport == OPEN ? p.open_port_tcp : p.closed_port_tcp,
      TCP_DESCS[i].urgptr, TCP_DESCS[i].opts, TCP_DESCS[i].optslen, p.hoplimit);
    emit(TCP_DESCS[i].id, ip6);
  }
}

/* One case per input line:
 *   <src> <dst> <open_tcp> <closed_tcp> <closed_udp> <tcp_base> <udp_base>
 *   <seqbase> <hoplimit> <icmp_seq> <directly_connected> <ack0..ack12>
 * Addresses are in presentation form; ports are decimal and may be -1. */
int main(void) {
  char line[2048];
  int caseno = 0;
  while (fgets(line, sizeof(line), stdin) != NULL) {
    if (line[0] == '#' || line[0] == '\n')
      continue;
    Params p;
    char srcs[64], dsts[64];
    unsigned long seqbase, hoplimit, icmpseq;
    int tcpbase, udpbase;
    int n = sscanf(line, "%63s %63s %d %d %d %d %d %lu %lu %lu %d",
      srcs, dsts, &p.open_port_tcp, &p.closed_port_tcp, &p.closed_port_udp,
      &tcpbase, &udpbase, &seqbase, &hoplimit, &icmpseq, &p.directly_connected);
    assert(n == 11);
    /* The 13 ACKs follow, after the 11 leading fields. */
    const char *q = line;
    for (int f = 0; f < 11; f++) { while (*q && *q != ' ') q++; while (*q == ' ') q++; }
    for (int a = 0; a < NUM_FP_PROBES_IPv6_TCP; a++) {
      unsigned long v = strtoul(q, (char **) &q, 10);
      p.tcp_ack[a] = (u32) v;
      while (*q == ' ') q++;
    }
    assert(inet_pton(AF_INET6, srcs, &p.src) == 1);
    assert(inet_pton(AF_INET6, dsts, &p.dst) == 1);
    p.tcp_port_base = (u16) tcpbase;
    p.udp_port_base = (u16) udpbase;
    p.tcpSeqBase = (u32) seqbase;
    p.hoplimit = (u8) hoplimit;
    p.icmp_seq_counter = (u16) icmpseq;

    printf("case %d\n", ++caseno);
    build_probe_list(p);
  }
  return 0;
}
