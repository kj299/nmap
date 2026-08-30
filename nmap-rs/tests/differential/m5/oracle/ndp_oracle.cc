// M5 NDP oracle — the C side of IPv6 neighbor discovery.
//
// Emits (a) the exact wire bytes nmap's `doND()` puts on the link when it solicits a
// next hop's MAC, and (b) the accept/parse verdict its reply path reaches for a given
// captured frame — so `core::ndp` can be gated on byte identity and on decision
// identity with nmap rather than on "it looks right".
//
// ---------------------------------------------------------------------------
// WHAT WAS COPIED, AND WHAT WAS CHANGED
//
// The address construction and frame packing below are the lines of
// `netutil.cc:doND()` **verbatim**, in their original order, operating on the real
// libdnet packing macros (`eth_pack_hdr`, `ip6_pack_hdr`, `icmpv6_pack_hdr_ns_mac`)
// included from <dnet/*.h>. Those macros are where the byte layout actually lives, so
// they are used, not retyped. `ip6_checksum` is copied verbatim from
// libdnet-stripped/src/ip6.c and `ip_cksum_add` from libdnet-stripped/src/ip-util.c
// (`ip_cksum_carry` is a macro in dnet/ip.h and is used directly).
//
// The only changes are substitutions of *inputs* and of I/O, never of logic:
//   * `dev`, the pcap handle, the retransmit loop and the `eth_send` call are dropped;
//     this oracle emits the frame that loop would have transmitted, unchanged.
//   * `srcmac` / `srcip` / `targetip` come from stdin instead of from the caller.
//
// For the reply side, `accept_ns()` and the body of `read_ns_reply_pcap()` are pasted
// verbatim, with the `read_reply_pcap()` call replaced by the case's own buffer and
// `head->caplen` by the case's length. Everything they decide is decided here.
//
// !! SCOPE OF THE REPLY CORPUS !!
// `read_ns_reply_pcap` reads `na->icmpv6_target` (16 bytes at offset+48)
// UNCONDITIONALLY, while `accept_ns` only guarantees offset+44 bytes are captured. For
// any capture shorter than offset+64 the C therefore reads past the captured data and
// its result is undefined — there is no golden to record, because there is no defined
// behavior to record. The generator emits only captures at or beyond that bound, where
// the C is well-defined; the Rust's handling of shorter frames (it rejects them) is
// pinned by unit tests and by the fuzz target instead, and ledgered as a divergence.
//
// Build: see build_ndp_oracle.sh.
// ---------------------------------------------------------------------------

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>

#include "dnet.h"

typedef unsigned char u8;

// accept_ns() takes the datalink but never reads it; this keeps the pasted
// signature intact without pulling in pcap just for the constant.
#define DLT_EN10MB 1

// ---- copied VERBATIM from libdnet-stripped/src/ip-util.c ----
int
ip_cksum_add(const void *buf, size_t len, int cksum)
{
	uint16_t *sp = (uint16_t *)buf;
	int n, sn;
	
	sn = len / 2;
	n = (sn + 15) / 16;
	
	/* XXX - unroll loop using Duff's device. */
	switch (sn % 16) {
	case 0:	do {
		cksum += *sp++;
	case 15:
		cksum += *sp++;
	case 14:
		cksum += *sp++;
	case 13:
		cksum += *sp++;
	case 12:
		cksum += *sp++;
	case 11:
		cksum += *sp++;
	case 10:
		cksum += *sp++;
	case 9:
		cksum += *sp++;
	case 8:
		cksum += *sp++;
	case 7:
		cksum += *sp++;
	case 6:
		cksum += *sp++;
	case 5:
		cksum += *sp++;
	case 4:
		cksum += *sp++;
	case 3:
		cksum += *sp++;
	case 2:
		cksum += *sp++;
	case 1:
		cksum += *sp++;
		} while (--n > 0);
	}
	if (len & 1)
		cksum += htons(*(u_char *)sp << 8);

	return (cksum);
}

// ---- copied VERBATIM from libdnet-stripped/src/ip6.c ----
#define IP6_IS_EXT(n)	\
	((n) == IP_PROTO_HOPOPTS || (n) == IP_PROTO_DSTOPTS || \
	 (n) == IP_PROTO_ROUTING || (n) == IP_PROTO_FRAGMENT)

void
ip6_checksum(void *buf, size_t len)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	struct ip6_ext_hdr *ext;
	u_char *p, nxt;
	int i, sum;
	
	nxt = ip6->ip6_nxt;
	
	for (i = IP6_HDR_LEN; IP6_IS_EXT(nxt); i += (ext->ext_len + 1) << 3) {
		if (i >= (int)len) return;
		ext = (struct ip6_ext_hdr *)((u_char *)buf + i);
		nxt = ext->ext_nxt;
	}
	p = (u_char *)buf + i;
	len -= i;
	
	if (nxt == IP_PROTO_TCP) {
		struct tcp_hdr *tcp = (struct tcp_hdr *)p;
		
		if (len >= TCP_HDR_LEN) {
			tcp->th_sum = 0;
			sum = ip_cksum_add(tcp, len, 0) + htons(nxt + len);
			sum = ip_cksum_add(&ip6->ip6_src, 32, sum);
			tcp->th_sum = ip_cksum_carry(sum);
		}
	} else if (nxt == IP_PROTO_UDP) {
		struct udp_hdr *udp = (struct udp_hdr *)p;

		if (len >= UDP_HDR_LEN) {
			udp->uh_sum = 0;
			sum = ip_cksum_add(udp, len, 0) + htons(nxt + len);
			sum = ip_cksum_add(&ip6->ip6_src, 32, sum);
			if ((udp->uh_sum = ip_cksum_carry(sum)) == 0)
				udp->uh_sum = 0xffff;
		}
	} else if (nxt == IP_PROTO_ICMPV6) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)p;

		if (len >= ICMP_HDR_LEN) {
			icmp->icmp_cksum = 0;
			sum = ip_cksum_add(icmp, len, 0) + htons(nxt + len);
			sum = ip_cksum_add(&ip6->ip6_src, 32, sum);
			icmp->icmp_cksum = ip_cksum_carry(sum);
		}		
	} else if (nxt == IP_PROTO_ICMP || nxt == IP_PROTO_IGMP) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)p;
		
		if (len >= ICMP_HDR_LEN) {
			icmp->icmp_cksum = 0;
			sum = ip_cksum_add(icmp, len, 0);
			icmp->icmp_cksum = ip_cksum_carry(sum);
		}
	}
}

// ---------------------------------------------------------------------------
// The solicitation frame, exactly as doND() builds it.
// ---------------------------------------------------------------------------
static void emit_ns(const u8 *srcmac, const struct sockaddr_in6 *src_sin6,
                    const struct sockaddr_in6 *target_sin6) {
  u8 frame[ETH_HDR_LEN + IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8];
  struct sockaddr_in6 ns_dst_ip6;

  /* --- begin verbatim doND() --- */
  unsigned char ns_dst_mac[6] = {0x33, 0x33, 0xff};
  ns_dst_mac[3] = target_sin6->sin6_addr.s6_addr[13];
  ns_dst_mac[4] = target_sin6->sin6_addr.s6_addr[14];
  ns_dst_mac[5] = target_sin6->sin6_addr.s6_addr[15];

  ns_dst_ip6 = *target_sin6;
  unsigned char multicast_prefix[13] = {0};
  multicast_prefix[0] = 0xff;
  multicast_prefix[1] = 0x02;
  multicast_prefix[11] = 0x1;
  multicast_prefix[12] = 0xff;
  memcpy(ns_dst_ip6.sin6_addr.s6_addr, multicast_prefix, sizeof(multicast_prefix));

  eth_pack_hdr(frame, *ns_dst_mac, *srcmac, ETH_TYPE_IPV6);
  ip6_pack_hdr(frame + ETH_HDR_LEN, 0, 0, 32, 0x3a, 255, *src_sin6->sin6_addr.s6_addr, *ns_dst_ip6.sin6_addr.s6_addr);
  icmpv6_pack_hdr_ns_mac(frame + ETH_HDR_LEN + IP6_HDR_LEN, target_sin6->sin6_addr.s6_addr, *srcmac);
  ip6_checksum(frame + ETH_HDR_LEN, IP6_HDR_LEN + ICMPV6_HDR_LEN + 4 + 16 + 8);
  /* --- end verbatim doND() --- */

  printf("ns ");
  for (size_t i = 0; i < sizeof(frame); i++) printf("%02x", frame[i]);
  printf("\n");
}

// ---------------------------------------------------------------------------
// The reply verdict, exactly as accept_ns() + read_ns_reply_pcap() reach it.
// ---------------------------------------------------------------------------
struct pkthdr { unsigned int caplen; };

/* --- begin verbatim accept_ns() (pcap types replaced by the case buffer) --- */
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
/* --- end verbatim accept_ns() --- */

static void emit_na(const u8 *p, size_t caplen, size_t offset) {
  struct pkthdr h; h.caplen = (unsigned int)caplen;
  u8 sendermac[6];
  u8 senderip[16];
  bool has_mac;
  struct icmpv6_msg_nd *na;

  if (!accept_ns(p, &h, DLT_EN10MB, offset)) {
    printf("na nomatch\n");
    return;
  }

  /* --- begin verbatim read_ns_reply_pcap() body --- */
  struct pkthdr *head = &h;
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
  memcpy(&senderip, &na->icmpv6_target, 16);
  /* --- end verbatim read_ns_reply_pcap() body --- */

  printf("na match target=");
  for (int i = 0; i < 16; i++) printf("%02x", senderip[i]);
  if (has_mac) {
    printf(" mac=");
    for (int i = 0; i < 6; i++) printf("%02x", sendermac[i]);
  } else {
    printf(" mac=none");
  }
  printf("\n");
}

// ---------------------------------------------------------------------------
static int unhex(const char *s, u8 *out, size_t max) {
  if (strcmp(s, "-") == 0) return 0;   /* the empty capture */
  size_t n = strlen(s);
  if (n % 2 || n / 2 > max) return -1;
  for (size_t i = 0; i < n / 2; i++) {
    unsigned v;
    if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
    out[i] = (u8)v;
  }
  return (int)(n / 2);
}

int main(void) {
  char line[8192];
  while (fgets(line, sizeof(line), stdin)) {
    char *nl = strchr(line, '\n'); if (nl) *nl = 0;
    if (line[0] == 0 || line[0] == '#') continue;
    char kind[16], a[4096], b[4096], c[4096];
    int nf = sscanf(line, "%15s %4095s %4095s %4095s", kind, a, b, c);
    if (nf >= 4 && strcmp(kind, "ns") == 0) {
      u8 mac[6], src[16], tgt[16];
      if (unhex(a, mac, 6) != 6 || unhex(b, src, 16) != 16 || unhex(c, tgt, 16) != 16) {
        fprintf(stderr, "bad ns case: %s\n", line); return 1;
      }
      struct sockaddr_in6 s6, t6;
      memset(&s6, 0, sizeof(s6)); memset(&t6, 0, sizeof(t6));
      s6.sin6_family = AF_INET6; t6.sin6_family = AF_INET6;
      memcpy(s6.sin6_addr.s6_addr, src, 16);
      memcpy(t6.sin6_addr.s6_addr, tgt, 16);
      emit_ns(mac, &s6, &t6);
    } else if (nf >= 3 && strcmp(kind, "na") == 0) {
      size_t offset = (size_t)strtoul(a, NULL, 10);
      static u8 buf[4096];
      int n = unhex(b, buf, sizeof(buf));
      if (n < 0) { fprintf(stderr, "bad na case: %s\n", line); return 1; }
      emit_na(buf, (size_t)n, offset);
    } else {
      fprintf(stderr, "unrecognised case: %s\n", line); return 1;
    }
  }
  return 0;
}
