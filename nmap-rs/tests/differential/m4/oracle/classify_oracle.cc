// M4 scan-response classification oracle — the C side of core::classify.
//
// A faithful transcription of the port-state decision branches in
// scan_engine_raw.cc (ultra_scan response handling) and set_default_port_state
// (scan_engine.cc), annotated with source lines. Reads one case per stdin line and
// prints one state token per line, so the Rust side can compare an exhaustive matrix.
//
// Case grammar (whitespace-separated):
//   default <scan> <defeat_icmp_ratelimit 0|1>
//   tcp     <scan> <flags u8> <window u16>
//   icmp    <scan> <type u8> <code u8> <from_target 0|1>
//   sctp    <scan> <chunk u8>
// Scans: syn connect ack window maimon fin null xmas udp ipproto sctpinit sctpcookie
// Output: open closed filtered unfiltered openfiltered closedfiltered unknown none

#include <cstdio>
#include <cstring>
#include <string>

enum Scan { SYN, CONNECT, ACK, WINDOW, MAIMON, FIN, NULLS, XMAS, UDP, IPPROT, SCTPINIT, SCTPCOOKIE, BADSCAN };
enum State { OPEN, CLOSED, FILTERED, UNFILTERED, OPENFILTERED, CLOSEDFILTERED, UNKNOWN, NONE };

#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10
#define SCTP_INIT_ACK 0x02
#define SCTP_ABORT 0x06

static Scan parse_scan(const std::string &s) {
  if (s == "syn") return SYN;
  if (s == "connect") return CONNECT;
  if (s == "ack") return ACK;
  if (s == "window") return WINDOW;
  if (s == "maimon") return MAIMON;
  if (s == "fin") return FIN;
  if (s == "null") return NULLS;
  if (s == "xmas") return XMAS;
  if (s == "udp") return UDP;
  if (s == "ipproto") return IPPROT;
  if (s == "sctpinit") return SCTPINIT;
  if (s == "sctpcookie") return SCTPCOOKIE;
  return BADSCAN;
}

static const char *state_str(State s) {
  switch (s) {
  case OPEN: return "open";
  case CLOSED: return "closed";
  case FILTERED: return "filtered";
  case UNFILTERED: return "unfiltered";
  case OPENFILTERED: return "openfiltered";
  case CLOSEDFILTERED: return "closedfiltered";
  case UNKNOWN: return "unknown";
  default: return "none";
  }
}

// set_default_port_state (scan_engine.cc:803)
static State default_state(Scan scan, int defeat) {
  switch (scan) {
  case SYN: case ACK: case WINDOW: case CONNECT: return FILTERED;
  case SCTPINIT: return FILTERED;
  case NULLS: case FIN: case MAIMON: case XMAS: return OPENFILTERED;
  case UDP: return defeat ? CLOSEDFILTERED : OPENFILTERED;
  case IPPROT: return OPENFILTERED;
  case SCTPCOOKIE: return OPENFILTERED;
  default: return UNKNOWN;
  }
}

// TCP response branch (scan_engine_raw.cc:1717)
static State classify_tcp(Scan scan, unsigned flags, unsigned window) {
  if (scan == SYN && (flags & (TH_SYN | TH_ACK)) == (unsigned)(TH_SYN | TH_ACK))
    return OPEN;
  if (flags & TH_RST) {
    if (scan == WINDOW) return window ? OPEN : CLOSED;
    else if (scan == ACK) return UNFILTERED;
    else return CLOSED;
  }
  if (scan == SYN && (flags & TH_SYN)) return OPEN;
  return NONE;
}

// ICMPv4 response branch (scan_engine_raw.cc:1888 / :1927)
static State classify_icmp(Scan scan, unsigned type, unsigned code, int from_target) {
  if (type == 3) {
    switch (code) {
    case 0: case 1: return FILTERED;
    case 2:
      return (scan == IPPROT && from_target) ? CLOSED : FILTERED;
    case 3:
      if (from_target && scan == UDP) return CLOSED;
      else if (from_target && scan == IPPROT) return OPEN;
      else return FILTERED;
    case 9: case 10: case 13: return FILTERED;
    default: return NONE;
    }
  } else if (type == 11) {
    return FILTERED;
  }
  return NONE;
}

// SCTP response branch (scan_engine_raw.cc:1779)
static State classify_sctp(Scan scan, unsigned chunk) {
  if (scan == SCTPINIT) {
    if (chunk == SCTP_INIT_ACK) return OPEN;
    if (chunk == SCTP_ABORT) return CLOSED;
    return NONE;
  } else if (scan == SCTPCOOKIE) {
    if (chunk == SCTP_ABORT) return CLOSED;
    return NONE;
  }
  return NONE;
}

int main(void) {
  char line[256];
  while (fgets(line, sizeof(line), stdin)) {
    char kind[32], scanstr[32];
    unsigned a = 0, b = 0, c = 0;
    int n = sscanf(line, "%31s %31s %u %u %u", kind, scanstr, &a, &b, &c);
    if (n < 2) continue;
    Scan scan = parse_scan(scanstr);
    State st = NONE;
    if (strcmp(kind, "default") == 0) st = default_state(scan, (int)a);
    else if (strcmp(kind, "tcp") == 0) st = classify_tcp(scan, a, b);
    else if (strcmp(kind, "icmp") == 0) st = classify_icmp(scan, a, b, (int)c);
    else if (strcmp(kind, "sctp") == 0) st = classify_sctp(scan, a);
    printf("%s\n", state_str(st));
  }
  return 0;
}
