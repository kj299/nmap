// M4 function-level differential oracle — the C side.
//
// Links nmap's real libnetutil IPv4Header and emits the canonical projection
// (tests/differential/m4/README.md) for a hex packet read on stdin. The Rust side
// (`nmap-core` test binary / --project-packet) emits the same projection; the
// harness diffs them over the corpus. This is the "semantic equivalence, not
// it-builds" oracle the kit's Phase 2 requires for a library-shaped port.
//
// Build: see build.sh (needs -DHAVE_CONFIG_H + nbase configured + the pcap.h stub).

#include "ICMPv4Header.h"
#include "IPv4Header.h"
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

int main(int argc, char **argv) {
  const char *layer = (argc > 1) ? argv[1] : "ip4";
  std::string in;
  { int c; while ((c = getchar()) != EOF) in.push_back((char)c); }
  std::vector<unsigned char> pkt = unhex(in);

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
