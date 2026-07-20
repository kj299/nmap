// M4 receive-validation oracle — the C side of the core::recv_validate differential.
//
// `validatepkt()` and `validateTCPhdr()` are `static` in tcpip.cc and cannot be
// linked, so this is a faithful byte-level transcription of their IPv4 path, with
// each block annotated by its tcpip.cc source line for review. The debug-only
// `error()` calls (guarded by o.debugging) are omitted — they do not affect the
// accept/reject result. Reads a hex packet on stdin; prints the canonical projection:
//   accept caplen=<n> proto=<p> doff=<n>
//   reject
//
// Build: see build_validate_oracle.sh (no libnetutil link needed — self-contained).

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

typedef unsigned char u8;
typedef unsigned short u16;

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

// Transcription of validatepkt() (tcpip.cc:1274), IPv4 path only. Returns the
// accept/reject decision and, on accept, the capped length via *out_caplen.
static bool validatepkt(const u8 *ipc, unsigned len, unsigned *out_caplen,
                        u8 *out_proto, unsigned *out_doff) {
  if (len < 20) return false;                        // len < sizeof(ip) (1276)
  u8 ver = ipc[0] >> 4;
  unsigned datalen, iplen;
  u8 hdr;
  if (ver == 4) {                                    // (1283)
    // ipv4_get_data: IHL bounds + L4 data length (netutil.cc:789).
    unsigned header_len = (ipc[0] & 0x0f) * 4;
    if (len < 20) return false;
    if (header_len < 20) return false;
    if (header_len > len) return false;
    datalen = len - header_len;
    const u8 *data = ipc + header_len;

    iplen = (ipc[2] << 8) | ipc[3];                  // ntohs(ip_len) (1294)
    unsigned fragoff = 8 * (((ipc[6] << 8) | ipc[7]) & IP_OFFMASK); // (1296)
    if (fragoff) return false;                       // (1297)
    if (len > iplen) len = iplen;                    // cap (1306)
    hdr = ipc[9];                                    // ip_p (1309)

    switch (hdr) {                                   // (1333)
    case 6: // TCP
      if (datalen < 20) return false;               // (1335)
      if (!validateTCPhdr(data, datalen)) return false; // (1340)
      break;
    case 17: // UDP
      if (datalen < 8) return false;                // (1347)
      break;
    default: break;
    }
    *out_caplen = len;
    *out_proto = hdr;
    *out_doff = header_len;
    return true;
  } else {
    // IPv6 (ver==6) and bogus versions: this oracle only covers the IPv4 path the
    // port implements; the Rust side rejects them, so they are not in the corpus.
    return false;
  }
}

int main(void) {
  std::string in;
  { int c; while ((c = getchar()) != EOF) in.push_back((char)c); }
  std::vector<u8> pkt = unhex(in);
  unsigned caplen = 0, doff = 0;
  u8 proto = 0;
  if (validatepkt(pkt.data(), (unsigned)pkt.size(), &caplen, &proto, &doff)) {
    printf("accept caplen=%u proto=%u doff=%u\n", caplen, proto, doff);
  } else {
    printf("reject\n");
  }
  return 0;
}
