// M4 function-level differential oracle — the C side.
//
// Links nmap's real libnetutil IPv4Header and emits the canonical projection
// (tests/differential/m4/README.md) for a hex packet read on stdin. The Rust side
// (`nmap-core` test binary / --project-packet) emits the same projection; the
// harness diffs them over the corpus. This is the "semantic equivalence, not
// it-builds" oracle the kit's Phase 2 requires for a library-shaped port.
//
// Build: see build.sh (needs -DHAVE_CONFIG_H + nbase configured + the pcap.h stub).

#include "ARPHeader.h"
#include "EthernetHeader.h"
#include "ICMPv4Header.h"
#include "IPv4Header.h"
#include "IPv6Header.h"
#include "PacketParser.h"
#include "TCPHeader.h"
#include "UDPHeader.h"
#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Decode a hex string (optional whitespace) into bytes.
static std::vector<unsigned char> unhex(const std::string &s) {
  std::vector<unsigned char> out;
  int hi = -1;
  for (char ch : s) {
    int v;
    if (ch >= '0' && ch <= '9') v = ch - '0';
    else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
    else continue; // skip whitespace/newlines
    if (hi < 0) hi = v;
    else { out.push_back((unsigned char)((hi << 4) | v)); hi = -1; }
  }
  return out;
}

// Project a TCP header (used when argv[1]=="tcp").
static int project_tcp(const std::vector<unsigned char> &pkt) {
  TCPHeader tcp;
  if (tcp.storeRecvData(pkt.data(), pkt.size()) != 0) {
    printf("result err:truncated\n");
    return 0;
  }
  int vlen = tcp.validate();
  if (vlen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  printf("hdr 0 tcp len=%d\n", vlen);
  printf("  tcp sport=%u dport=%u flags=0x%02x off=%u win=%u seq=%u ack=%u\n",
         tcp.getSourcePort(), tcp.getDestinationPort(), tcp.getFlags(),
         tcp.getOffset(), tcp.getWindow(), tcp.getSeq(), tcp.getAck());
  printf("result ok\n");
  return 0;
}

// Project a UDP header (used when argv[1]=="udp").
static int project_udp(const std::vector<unsigned char> &pkt) {
  UDPHeader udp;
  if (udp.storeRecvData(pkt.data(), pkt.size()) != 0) {
    printf("result err:truncated\n");
    return 0;
  }
  int vlen = udp.validate();
  if (vlen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  printf("hdr 0 udp len=%d\n", vlen);
  printf("  udp sport=%u dport=%u ulen=%u\n", udp.getSourcePort(),
         udp.getDestinationPort(), udp.getTotalLength());
  printf("result ok\n");
  return 0;
}

// Project an ICMPv4 header (used when argv[1]=="icmp").
static int project_icmp(const std::vector<unsigned char> &pkt) {
  ICMPv4Header icmp;
  if (icmp.storeRecvData(pkt.data(), pkt.size()) != 0) {
    printf("result err:truncated\n");
    return 0;
  }
  int vlen = icmp.validate();
  if (vlen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  printf("hdr 0 icmp len=%d\n", vlen);
  printf("  icmp type=%u code=%u\n", icmp.getType(), icmp.getCode());
  printf("result ok\n");
  return 0;
}

// Project an Ethernet header (used when argv[1]=="eth").
static int project_eth(const std::vector<unsigned char> &pkt) {
  EthernetHeader eth;
  if (eth.storeRecvData(pkt.data(), pkt.size()) != 0) {
    printf("result err:truncated\n");
    return 0;
  }
  int vlen = eth.validate();
  if (vlen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  const u8 *d = eth.getDstMAC();
  const u8 *s = eth.getSrcMAC();
  printf("hdr 0 eth len=%d\n", vlen);
  printf("  eth dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x "
         "type=0x%04x\n",
         d[0], d[1], d[2], d[3], d[4], d[5], s[0], s[1], s[2], s[3], s[4], s[5],
         eth.getEtherType());
  printf("result ok\n");
  return 0;
}

// Project an ARP header (used when argv[1]=="arp").
static int project_arp(const std::vector<unsigned char> &pkt) {
  ARPHeader arp;
  if (arp.storeRecvData(pkt.data(), pkt.size()) != 0) {
    printf("result err:truncated\n");
    return 0;
  }
  int vlen = arp.validate();
  if (vlen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  const u8 *sha = arp.getSenderMAC();
  const u8 *tha = arp.getTargetMAC();
  u32 sip = arp.getSenderIP();
  u32 tip = arp.getTargetIP();
  const u8 *sb = (const u8 *)&sip;
  const u8 *tb = (const u8 *)&tip;
  printf("hdr 0 arp len=%d\n", vlen);
  printf("  arp hrd=%u pro=0x%04x hln=%u pln=%u op=%u "
         "sha=%02x:%02x:%02x:%02x:%02x:%02x sip=%u.%u.%u.%u "
         "tha=%02x:%02x:%02x:%02x:%02x:%02x tip=%u.%u.%u.%u\n",
         arp.getHardwareType(), arp.getProtocolType(), arp.getHwAddrLen(),
         arp.getProtoAddrLen(), arp.getOpCode(), sha[0], sha[1], sha[2], sha[3],
         sha[4], sha[5], sb[0], sb[1], sb[2], sb[3], tha[0], tha[1], tha[2],
         tha[3], tha[4], tha[5], tb[0], tb[1], tb[2], tb[3]);
  printf("result ok\n");
  return 0;
}

// Project an IPv6 base header (used when argv[1]=="ip6").
static int project_ip6(const std::vector<unsigned char> &pkt) {
  IPv6Header ip6;
  if (ip6.storeRecvData(pkt.data(), pkt.size()) != 0) {
    printf("result err:truncated\n");
    return 0;
  }
  int vlen = ip6.validate();
  if (vlen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  const u8 *s = ip6.getSourceAddress();
  const u8 *d = ip6.getDestinationAddress();
  printf("hdr 0 ip6 len=%d\n", vlen);
  printf("  ip6 ver=%u tc=%u flow=%u plen=%u nh=%u hlim=%u src=", ip6.getVersion(),
         ip6.getTrafficClass(), ip6.getFlowLabel(), ip6.getPayloadLength(),
         ip6.getNextHeader(), ip6.getHopLimit());
  for (int i = 0; i < 16; i++) printf("%02x", s[i]);
  printf(" dst=");
  for (int i = 0; i < 16; i++) printf("%02x", d[i]);
  printf("\nresult ok\n");
  return 0;
}

// Map a libnetutil HEADER_TYPE_* to the canonical short token the Rust side emits.
static const char *hdr_token(u32 t) {
  switch (t) {
  case HEADER_TYPE_ETHERNET: return "eth";
  case HEADER_TYPE_ARP:      return "arp";
  case HEADER_TYPE_IPv4:     return "ip4";
  case HEADER_TYPE_IPv6:     return "ip6";
  case HEADER_TYPE_TCP:      return "tcp";
  case HEADER_TYPE_UDP:      return "udp";
  case HEADER_TYPE_ICMPv4:   return "icmp";
  case HEADER_TYPE_RAW_DATA: return "raw";
  default:                   return "other";
  }
}

// Project the full multi-header walk (used when argv[1]=="pkt_eth" / "pkt_ip").
// Links nmap's REAL PacketParser::parse_packet state machine.
static int project_packet(const std::vector<unsigned char> &pkt, bool eth_included) {
  pkt_type_t *hs = PacketParser::parse_packet(pkt.data(), pkt.size(), eth_included);
  // The array is terminated by a sentinel entry with length==0.
  int n = 0;
  for (int i = 0; hs[i].length != 0; i++) n++;
  printf("pkt nhdrs=%d\n", n);
  unsigned long off = 0;
  for (int i = 0; i < n; i++) {
    printf("hdr %d %s off=%lu len=%lu\n", i, hdr_token(hs[i].type), off,
           (unsigned long)hs[i].length);
    off += hs[i].length;
  }
  printf("result ok\n");
  return 0;
}

// Project a whole OS-detection probe packet: the IPv4 header plus the full detail of
// its transport layer, using nmap's REAL header classes. Used when argv[1]=="osprobe".
//
// Richer than the generic per-layer projections because the OS probes are defined
// precisely by the fields those omit — TOS, DF, IP ID, TTL, the TCP option bytes, the
// urgent pointer and the reserved bits are the whole point of the battery.
static int project_osprobe(const std::vector<unsigned char> &pkt) {
  IPv4Header ip;
  if (ip.storeRecvData(pkt.data(), pkt.size()) != 0) {
    printf("result err:truncated\n");
    return 0;
  }
  int iplen = ip.validate();
  if (iplen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  const u8 *s = ip.getSourceAddress();
  const u8 *d = ip.getDestinationAddress();
  printf("ip4 src=%u.%u.%u.%u dst=%u.%u.%u.%u ihl=%u tos=%u totlen=%u id=%u df=%d "
         "ttl=%u proto=%u\n",
         s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3],
         ip.getHeaderLength(), ip.getTOS(), ip.getTotalLength(),
         ip.getIdentification(), ip.getDF() ? 1 : 0, ip.getTTL(), ip.getNextProto());

  const unsigned char *l4 = pkt.data() + iplen;
  size_t l4len = pkt.size() - (size_t)iplen;

  if (ip.getNextProto() == 6) {
    TCPHeader tcp;
    if (tcp.storeRecvData(l4, l4len) != 0 || tcp.validate() <= 0) {
      printf("result err:tcp\n");
      return 0;
    }
    size_t optslen = 0;
    const u8 *opts = tcp.getOptions(&optslen);
    printf("tcp sport=%u dport=%u seq=%u ack=%u off=%u reserved=%u flags=0x%02x "
           "win=%u urp=%u optlen=%u\n",
           tcp.getSourcePort(), tcp.getDestinationPort(), tcp.getSeq(), tcp.getAck(),
           tcp.getOffset(), tcp.getReserved(), tcp.getFlags(), tcp.getWindow(),
           tcp.getUrgPointer(), (unsigned)optslen);
    printf("tcpopts ");
    for (size_t i = 0; i < optslen && opts != NULL; i++) printf("%02x", opts[i]);
    printf("\n");
  } else if (ip.getNextProto() == 17) {
    UDPHeader udp;
    if (udp.storeRecvData(l4, l4len) != 0 || udp.validate() <= 0) {
      printf("result err:udp\n");
      return 0;
    }
    printf("udp sport=%u dport=%u ulen=%u\n", udp.getSourcePort(),
           udp.getDestinationPort(), udp.getTotalLength());
    // The U1 payload is a fixed pattern; report its length and whether it holds.
    size_t dlen = l4len > 8 ? l4len - 8 : 0;
    int uniform = 1;
    for (size_t i = 8; i < l4len; i++) if (l4[i] != l4[8]) uniform = 0;
    printf("udpdata len=%u byte=%02x uniform=%d\n", (unsigned)dlen,
           dlen ? l4[8] : 0, uniform);
  } else if (ip.getNextProto() == 1) {
    ICMPv4Header icmp;
    if (icmp.storeRecvData(l4, l4len) != 0 || icmp.validate() <= 0) {
      printf("result err:icmp\n");
      return 0;
    }
    printf("icmp type=%u code=%u id=%u seq=%u\n", icmp.getType(), icmp.getCode(),
           icmp.getIdentifier(), icmp.getSequence());
    size_t dlen = l4len > 8 ? l4len - 8 : 0;
    int allzero = 1;
    for (size_t i = 8; i < l4len; i++) if (l4[i] != 0) allzero = 0;
    printf("icmpdata len=%u allzero=%d\n", (unsigned)dlen, allzero);
  } else {
    printf("result err:proto\n");
    return 0;
  }
  printf("result ok\n");
  return 0;
}

// ---------------------------------------------------------------------------
// Project nmap's TCP-option summary (used when argv[1]=="tcpopt").
//
// `tcpopt_string_ctx` and `tcpopt_tostring` below are copied VERBATIM from
// osscan2.cc so the oracle exercises nmap's own encoder, driven by nmap's own
// TCPOptions walk from libnetutil/TCPHeader.cc. Only `get_tcpopt_string`'s
// wrapper is re-expressed here, because the original is a HostOsScan method.
// ---------------------------------------------------------------------------
struct tcpopt_string_ctx {
  char *p;
  char *end;
  bool valid;
  tcpopt_string_ctx() : p(NULL), end(NULL), valid(true) {}
  bool check_length(int len) const {
    return (end - p) >= len;
  }
  void put(char c) {
    assert(end > p);
    *p++ = c;
  }
  void put_hex(unsigned int u) {
    int w = sprintf(p, "%X", u);
    p += w;
  }
};

static bool tcpopt_tostring(u8 op, u8 oplen, const u8 *data, void *ctx)
{
  tcpopt_string_ctx *args = static_cast<tcpopt_string_ctx *>(ctx);

  if (!args->check_length(1))
    return false;

  const u8 *q = data + 2;

  switch (op) {
    case 0: /* End of List */
      args->put('L');
      break;
    case 1: /* No Op */
      args->put('N');
      break;
    case 2: /* MSS */
      if (oplen < 4) {
        args->valid = false;
        break; /* MSS has 4 bytes */
      }
      args->put('M');
      if (!args->check_length(4))
        return false;
      args->put_hex((q[0] << 8) + q[1]);
      break;
    case 3:/* Window Scale */
      if (oplen < 3) {
        args->valid = false;
        break; /* Window Scale option has 3 bytes */
      }
      args->put('W');
      if (!args->check_length(2))
        return false;
      args->put_hex(q[0]);
      break;
    case 4:/* SACK permitted */
      if (oplen < 2) {
        args->valid = false;
        break; /* SACK permitted option has 2 bytes */
      }
      args->put('S');
      break;
    case 8: /* Timestamp */
      if (oplen < 10) {
        args->valid = false;
        break; /* Timestamp option has 10 bytes */
      }
      args->put('T');
      if (!args->check_length(2))
        return false;
      args->put((q[0] || q[1] || q[2] || q[3]) ? '1' : '0');
      args->put((q[4] || q[5] || q[6] || q[7]) ? '1' : '0');
      break;
    default:
      break;
  }
  return args->valid;
}

static int project_tcpopt(const std::vector<unsigned char> &pkt) {
  char result[512];
  memset(result, 0, sizeof(result));

  TCPOptions opts;
  if (!opts.fromTCPPacket(pkt.data(), (int)pkt.size())) {
    printf("result err:-1\n");
    return 0;
  }
  tcpopt_string_ctx ctx;
  ctx.p = result;
  ctx.end = result + sizeof(result) - 1;

  if (!opts.foreachOpt(tcpopt_tostring, &ctx) || !ctx.valid) {
    printf("result err:-1\n");
    return 0;
  }
  printf("tcpopt len=%d str=%s\n", (int)(ctx.p - result), result);
  printf("result ok\n");
  return 0;
}

int main(int argc, char **argv) {
  const char *layer = (argc > 1) ? argv[1] : "ip4";
  std::string in;
  { int c; while ((c = getchar()) != EOF) in.push_back((char)c); }
  std::vector<unsigned char> pkt = unhex(in);

  if (strcmp(layer, "tcpopt") == 0) {
    return project_tcpopt(pkt);
  }
  if (strcmp(layer, "osprobe") == 0) {
    return project_osprobe(pkt);
  }
  if (strcmp(layer, "pkt_eth") == 0) {
    return project_packet(pkt, true);
  }
  if (strcmp(layer, "pkt_ip") == 0) {
    return project_packet(pkt, false);
  }
  if (strcmp(layer, "eth") == 0) {
    return project_eth(pkt);
  }
  if (strcmp(layer, "ip6") == 0) {
    return project_ip6(pkt);
  }
  if (strcmp(layer, "arp") == 0) {
    return project_arp(pkt);
  }
  if (strcmp(layer, "tcp") == 0) {
    return project_tcp(pkt);
  }
  if (strcmp(layer, "udp") == 0) {
    return project_udp(pkt);
  }
  if (strcmp(layer, "icmp") == 0) {
    return project_icmp(pkt);
  }

  IPv4Header ip;
  // storeRecvData mirrors nmap's receive path: it refuses < IP_HEADER_LEN.
  if (ip.storeRecvData(pkt.data(), pkt.size()) != 0 /* OP_SUCCESS==0? see below */) {
    // storeRecvData returns OP_SUCCESS/OP_FAILURE; nmap defines OP_SUCCESS=0,
    // OP_FAILURE=-1. A failure here means "too short".
    printf("result err:truncated\n");
    return 0;
  }
  int vlen = ip.validate();
  if (vlen <= 0) {
    printf("result err:invalid\n");
    return 0;
  }
  // Accepted: project the load-bearing fields.
  const u8 *src = ip.getSourceAddress();
  const u8 *dst = ip.getDestinationAddress();
  printf("hdr 0 ip4 len=%d\n", vlen);
  printf("  ip4 src=%u.%u.%u.%u dst=%u.%u.%u.%u proto=%u ihl=%u totlen=%u\n",
         src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3],
         ip.getNextProto(), ip.getHeaderLength(), ip.getTotalLength());
  printf("result ok\n");
  return 0;
}
