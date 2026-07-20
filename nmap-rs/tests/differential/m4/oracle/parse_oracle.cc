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

int main(int argc, char **argv) {
  const char *layer = (argc > 1) ? argv[1] : "ip4";
  std::string in;
  { int c; while ((c = getchar()) != EOF) in.push_back((char)c); }
  std::vector<unsigned char> pkt = unhex(in);

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
