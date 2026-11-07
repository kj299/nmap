// M4 receive-validation oracle — the C side of the core::recv_validate differential.
//
// `validatepkt()` and `validateTCPhdr()` are `static` in tcpip.cc and cannot be
// linked, so this is a faithful byte-level transcription of them, with each block
// annotated by its tcpip.cc source line for review. The debug-only `error()` calls
// (guarded by o.debugging) are omitted — they do not affect the accept/reject
// result.
//
// The IPv6 path's extension-header walk is not transcribed: build_validate_oracle.sh
// copies nmap's own `ipv6_is_extension_header`, `ipv6_is_upperlayer`,
// `ipv6_get_data_primitive` and both `ipv6_get_data` overloads out of
// libnetutil/netutil.cc into validate_ipv6_walk.inc (gitignored), and they are
// compiled here unchanged against libdnet's own headers. So the walk the IPv6 scan
// milestone fixes (docs/IPV6-SCAN-ANALYSIS.md D3, Q4) is the C's, byte for byte.
//
//   validate_oracle          one hex packet on stdin
//   validate_oracle lines    one hex packet per stdin line, one projection per line
//
// The canonical projection:
//   accept caplen=<n> proto=<p> doff=<n>
//   reject
//
// Build: see build_validate_oracle.sh (no libnetutil link needed).

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <stdint.h>
#include <dnet/os.h>
#include <dnet/ip.h>
#include <dnet/ip6.h>

typedef uint8_t u8;
typedef uint16_t u16;

// netutil.cc's walk, extracted verbatim at build time.
#include "validate_ipv6_walk.inc"

static std::vector<u8> unhex(const std::string &s) {
  std::vector<u8> out;
  int hi = -1;
  for (char ch : s) {
    int v;
    if (ch >= '0' && ch <= '9') v = ch - '0';
    else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
    else continue;
    if (hi < 0) hi = v;
    else { out.push_back((u8)((hi << 4) | v)); hi = -1; }
  }
  return out;
}

#define IP_OFFMASK 0x1fff

// Transcription of validateTCPhdr() (tcpip.cc:1183). `tcpc`/`len` are the TCP header
// + options + payload.
static bool validateTCPhdr(const u8 *tcpc, unsigned len) {
  if (len < 20) return false;                       // len < sizeof(tcp) (1185)
  unsigned hdrlen, optlen;
  hdrlen = (tcpc[12] >> 4) * 4;                      // tcp.th_off * 4 (1190)
  if (hdrlen > len || hdrlen < 20) return false;    // (1193)
  tcpc += 20;                                        // to the options (1197)
  optlen = hdrlen - 20;                              // (1198)

#define OPTLEN_IS(expected) do { \
  if ((expected) == 0 || optlen < (unsigned)(expected) || hdrlen != (unsigned)(expected)) \
    return false; \
  optlen -= (expected); \
  tcpc += (expected); \
} while(0)

  while (optlen > 1) {                               // (1208)
    hdrlen = *(tcpc + 1);                            // option length byte (1209)
    switch (*tcpc) {                                 // option kind (1210)
    case 0: return true;                             // EOL (1211)
    case 1: optlen--; tcpc++; break;                 // NOP (1214)
    case 2: OPTLEN_IS(4); break;                     // MSS (1219)
    case 3: OPTLEN_IS(3); break;                     // WScale (1222)
    case 4: OPTLEN_IS(2); break;                     // SACK OK (1225)
    case 5:                                          // SACK (1228)
      if (!(hdrlen - 2) || ((hdrlen - 2) % 8)) return false;
      OPTLEN_IS(hdrlen);
      break;
    case 8: OPTLEN_IS(10); break;                    // Timestamp (1233)
    case 14: OPTLEN_IS(3); break;                    // Alt checksum (1236)
    default: OPTLEN_IS(hdrlen); break;               // (1242)
    }
  }
  if (optlen == 1) return (*tcpc == 0 || *tcpc == 1); // (1248)
  return true;                                        // optlen == 0
}

// Transcription of validatepkt() (tcpip.cc:1274). Returns the accept/reject
// decision and, on accept, the capped length via *out_caplen.
static bool validatepkt(const u8 *ipc, unsigned len, unsigned *out_caplen,
                        u8 *out_proto, unsigned *out_doff) {
  if (len < 20) return false;                        // len < sizeof(ip) (1276)
  u8 ver = ipc[0] >> 4;
  unsigned datalen, iplen;
  u8 hdr;
  const u8 *data;
  if (ver == 4) {                                    // (1283)
    // ipv4_get_data: IHL bounds + L4 data length (netutil.cc:789).
    unsigned header_len = (ipc[0] & 0x0f) * 4;
    if (len < 20) return false;
    if (header_len < 20) return false;
    if (header_len > len) return false;
    datalen = len - header_len;
    data = ipc + header_len;

    iplen = (ipc[2] << 8) | ipc[3];                  // ntohs(ip_len) (1294)
    unsigned fragoff = 8 * (((ipc[6] << 8) | ipc[7]) & IP_OFFMASK); // (1296)
    if (fragoff) return false;                       // (1297)
    if (len > iplen) len = iplen;                    // cap (1306)
    hdr = ipc[9];                                    // ip_p (1309)
  } else if (ver == 6) {                             // (1310)
    if (len < sizeof(struct ip6_hdr)) return false;  // (1312)
    datalen = len;                                   // (1316)
    data = ipv6_get_data(ipc, &datalen, &hdr);       // netutil.cc's own (1317)
    if (data == NULL) return false;                  // (1318)
    iplen = (ipc[4] << 8) | ipc[5];                  // ntohs(ip6_plen) (1324)
    if (datalen > iplen) len -= datalen - iplen;     // (1325-1326)
  } else {
    return false;                                    // bad version (1327-1330)
  }

  switch (hdr) {                                     // (1333)
  case 6: // TCP
    if (datalen < 20) return false;                  // (1335)
    if (!validateTCPhdr(data, datalen)) return false; // (1340)
    break;
  case 17: // UDP
    if (datalen < 8) return false;                   // (1347)
    break;
  default: break;
  }
  *out_caplen = len;
  *out_proto = hdr;
  *out_doff = (unsigned)(data - ipc);
  return true;
}

static void project(const std::vector<u8> &pkt) {
  unsigned caplen = 0, doff = 0;
  u8 proto = 0;
  if (validatepkt(pkt.data(), (unsigned)pkt.size(), &caplen, &proto, &doff)) {
    printf("accept caplen=%u proto=%u doff=%u\n", caplen, proto, doff);
  } else {
    printf("reject\n");
  }
}

int main(int argc, char **argv) {
  if (argc > 1 && std::string(argv[1]) == "lines") {
    std::string line;
    while (std::getline(std::cin, line)) project(unhex(line));
    return 0;
  }
  std::string in;
  { int c; while ((c = getchar()) != EOF) in.push_back((char)c); }
  project(unhex(in));
  return 0;
}
