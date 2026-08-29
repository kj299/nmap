// M5 IPv6 response-matching oracle — the C side.
//
// Links nmap's real PacketParser::is_response (and the whole libnetutil packet parser it
// walks) and prints its verdict for each (sent, received) packet pair on stdin. The Rust
// core::fp6_match::is_response must return the same bool for every pair.
//
// is_response is called with a `sent` packet this scanner built and a `rcvd` packet from
// the wire; it returns whether rcvd is a response to sent. Nothing here is retyped — the
// oracle only unhexes the two packets, calls PacketParser::split on each (as
// FPHost6::callback does for the received packet, and as the probe was parsed from its
// own buffer), and hands both to the real is_response.
//
// Build: see build_fp6match_oracle.sh.

#include "PacketParser.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static std::vector<unsigned char> unhex(const std::string &s) {
  std::vector<unsigned char> out;
  int hi = -1;
  for (char ch : s) {
    int v;
    if (ch >= '0' && ch <= '9') v = ch - '0';
    else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
    else continue;
    if (hi < 0) hi = v;
    else { out.push_back((unsigned char)((hi << 4) | v)); hi = -1; }
  }
  return out;
}

// One case per line: "<sent hex> <rcvd hex>". Both parsed at the network layer
// (eth_included = false), exactly as core::fp6_match does.
int main(void) {
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  int caseno = 0;
  while ((n = getline(&line, &cap, stdin)) != -1) {
    if (line[0] == '#' || line[0] == '\n')
      continue;
    // Split on the single space between the two hex blobs.
    std::string s(line);
    size_t sp = s.find(' ');
    if (sp == std::string::npos)
      continue;
    std::vector<unsigned char> sent = unhex(s.substr(0, sp));
    std::vector<unsigned char> rcvd = unhex(s.substr(sp + 1));

    PacketElement *sent_pe = PacketParser::split(sent.data(), sent.size(), false);
    PacketElement *rcvd_pe = PacketParser::split(rcvd.data(), rcvd.size(), false);

    bool verdict = false;
    if (sent_pe != NULL && rcvd_pe != NULL)
      verdict = PacketParser::is_response(sent_pe, rcvd_pe);

    printf("case %d %s\n", ++caseno, verdict ? "match" : "nomatch");

    if (sent_pe) PacketParser::freePacketChain(sent_pe);
    if (rcvd_pe) PacketParser::freePacketChain(rcvd_pe);
  }
  free(line);
  return 0;
}
