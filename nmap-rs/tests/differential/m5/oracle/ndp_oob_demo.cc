// Demonstration: nmap's Neighbor Advertisement reply path reads past the captured
// packet. Not a CI gate — an ASAN witness for the divergence ledger.
//
// `accept_ns()` admits any capture holding offset + IP6_HDR_LEN + ICMPV6_HDR_LEN
// bytes. `read_ns_reply_pcap()` then reads the 16-byte target address at
// offset + 48 .. offset + 64 with NO length check — the bounds test that is present
// guards only the option fields, and the `memcpy` of the target sits outside it.
// A capture anywhere in [offset+44, offset+64) therefore reads up to 20 bytes past
// the data libpcap captured, and those bytes become the `senderIP` that `doND()`
// compares against the address it solicited.
//
// Both functions below are pasted VERBATIM from libnetutil/netutil.cc; only the pcap
// plumbing is replaced by a heap buffer sized exactly to the capture, so ASAN can see
// the overread that a pcap ring buffer would silently absorb.
//
//   ./build_ndp_oracle.sh --demo && ./ndp_oob_demo
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include "dnet.h"

typedef unsigned char u8;
#define DLT_EN10MB 1
struct pkthdr { unsigned int caplen; };

/* --- verbatim accept_ns(), pcap types replaced --- */
static bool accept_ns(const unsigned char *p, const struct pkthdr *head,
  int datalink, size_t offset)
{
  struct icmpv6_hdr *icmp6_header;

  if (head->caplen < offset + IP6_HDR_LEN + ICMPV6_HDR_LEN)
    return false;

  icmp6_header = (struct icmpv6_hdr *)(p + offset + IP6_HDR_LEN);
  return icmp6_header->icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT &&
    icmp6_header->icmpv6_code == 0;
}

int main(void) {
  const size_t offset = ETH_HDR_LEN;
  /* The shortest capture accept_ns() admits: IPv6 header + ICMPv6 header. A real
     advertisement is longer, but nothing downstream re-checks that. */
  const size_t caplen = offset + IP6_HDR_LEN + ICMPV6_HDR_LEN;

  u8 *p = (u8 *)malloc(caplen);          /* exactly what was captured */
  memset(p, 0, caplen);
  p[12] = 0x86; p[13] = 0xdd;            /* IPv6 ethertype */
  p[offset + 6] = IP_PROTO_ICMPV6;
  p[offset + IP6_HDR_LEN + 0] = ICMPV6_NEIGHBOR_ADVERTISEMENT;
  p[offset + IP6_HDR_LEN + 1] = 0;       /* code 0 */

  struct pkthdr h; h.caplen = (unsigned int)caplen;
  printf("caplen = %zu; accept_ns says %s\n", caplen,
         accept_ns(p, &h, DLT_EN10MB, offset) ? "ACCEPT" : "reject");

  struct sockaddr_in6 senderIP;
  struct icmpv6_msg_nd *na;
  bool has_mac;
  u8 sendermac[6];
  struct pkthdr *head = &h;

  /* --- verbatim read_ns_reply_pcap() body --- */
  na = (struct icmpv6_msg_nd *)(p + offset + IP6_HDR_LEN + ICMPV6_HDR_LEN);
  if (head->caplen >= ((unsigned char *)na - p) + sizeof(struct icmpv6_msg_nd) &&
    na->icmpv6_option_type == 2 &&
    na->icmpv6_option_length == 1) {
    has_mac = true;
    memcpy(sendermac, &na->icmpv6_mac, 6);
  }
  else {
    has_mac = false;
  }
  senderIP.sin6_family = AF_INET6;
  printf("about to read 16 bytes at capture offset %zu (capture is %zu bytes)\n",
         (size_t)((u8 *)&na->icmpv6_target - p), caplen);
  fflush(stdout);
  memcpy(&senderIP.sin6_addr.s6_addr, &na->icmpv6_target, 16);   /* <-- overread */
  /* --- end verbatim --- */

  printf("read completed; has_mac=%d (doND never checks this)\n", (int)has_mac);
  free(p);
  return 0;
}
