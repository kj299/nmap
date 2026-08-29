// Real checksum implementations for the build6 oracle.
//
// WHY THIS FILE EXISTS. The M4 `stubs.cc` inert-stubs `ipv6_pseudoheader_cksum`,
// `ipv4_pseudoheader_cksum` and `in_cksum` to RETURN ZERO, so the parse-only oracles
// can link libnetutil without dragging in netutil.cc, libpcap and libdnet. That is
// harmless for a parser — nothing on a parse path computes a checksum — but it is
// fatal for a *builder* oracle: every `setSum()` would silently produce 0, and the
// golden would then assert that nmap emits zero checksums. That is a paraphrase of
// the C, not the C, and gating against it would prove nothing. (Exactly the failure
// mode ledgered in BACKLOG.md after #70.)
//
// So the build6 oracle links THIS file instead of the checksum half of stubs.cc.
// `ipv6_pseudoheader_cksum` and `ipv4_pseudoheader_cksum` below are copied VERBATIM
// from libnetutil/netutil.cc; `ip_cksum_add` is copied VERBATIM from
// libdnet-stripped/src/ip-util.c (Duff's-device loop and all) and `ip_cksum_carry`
// from libdnet-stripped/include/dnet/ip.h. Diff them against those files to check.
// Copying rather than linking avoids pulling libpcap/libdnet into the oracle build;
// nothing here is rewritten, reordered or "cleaned up".

#include "nbase.h"
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#ifndef IP_PROTO_UDP
#define IP_PROTO_UDP 17
#endif

/* --- VERBATIM from libdnet-stripped/src/ip-util.c ------------------------- */
extern "C" int ip_cksum_add(const void *buf, size_t len, int cksum)
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

/* --- VERBATIM from libdnet-stripped/include/dnet/ip.h --------------------- */
#define	 ip_cksum_carry(x) \
	    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

/* --- VERBATIM from libnetutil/netutil.cc ---------------------------------- */
u16 ipv6_pseudoheader_cksum(const struct in6_addr *src,
  const struct in6_addr *dst, u8 nxt, u32 len, const void *hstart) {
  struct {
    struct in6_addr src;
    struct in6_addr dst;
    u32 length;
    u8 z0, z1, z2;
    u8 nxt;
  } hdr;
  int sum;

  hdr.src = *src;
  hdr.dst = *dst;
  hdr.z0 = hdr.z1 = hdr.z2 = 0;
  hdr.length = htonl(len);
  hdr.nxt = nxt;

  sum = ip_cksum_add(&hdr, sizeof(hdr), 0);
  sum = ip_cksum_add(hstart, len, sum);
  sum = ip_cksum_carry(sum);
  /* RFC 2460: "Unlike IPv4, when UDP packets are originated by an IPv6 node,
     the UDP checksum is not optional.  That is, whenever originating a UDP
     packet, an IPv6 node must compute a UDP checksum over the packet and the
     pseudo-header, and, if that computation yields a result of zero, it must be
     changed to hex FFFF for placement in the UDP header." */
  if (nxt == IP_PROTO_UDP && sum == 0)
    sum = 0xFFFF;

  return sum;
}

/* --- VERBATIM from libnetutil/netutil.cc ---------------------------------- */
unsigned short ipv4_pseudoheader_cksum(const struct in_addr *src,
  const struct in_addr *dst, u8 proto, u16 len, const void *hstart) {
  struct pseudo {
    struct in_addr src;
    struct in_addr dst;
    u8 zero;
    u8 proto;
    u16 length;
  } hdr;
  int sum;

  hdr.src = *src;
  hdr.dst = *dst;
  hdr.zero = 0;
  hdr.proto = proto;
  hdr.length = htons(len);

  /* Get the ones'-complement sum of the pseudo-header. */
  sum = ip_cksum_add(&hdr, sizeof(hdr), 0);
  /* Add it to the sum of the packet. */
  sum = ip_cksum_add(hstart, len, sum);

  /* Fold in the carry, take the complement, and return. */
  sum = ip_cksum_carry(sum);
  /* RFC 768 */
  if (proto == IP_PROTO_UDP && sum == 0)
    sum = 0xFFFF;

  return sum;
}

/* --- VERBATIM from libnetutil/netutil.cc ---------------------------------- */
unsigned short in_cksum(const u16 *ptr,int nbytes) {
  int sum;

   sum = ip_cksum_add(ptr, nbytes, 0);

  return ip_cksum_carry(sum);

  return 0;
}
