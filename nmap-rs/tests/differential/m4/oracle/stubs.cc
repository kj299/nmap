// Stub definitions for libnetutil symbols referenced only by IPv4Header methods
// the parse oracle never calls (print(), randomizing setters, checksum, option
// formatting). Including the real headers makes every signature and linkage
// (extern "C" vs C++) match exactly; the bodies are inert because the oracle's code
// path is storeRecvData -> validate -> field getters, none of which reach these.
//
// This is the minimal-link approach: it avoids dragging netutil.cc + libpcap +
// libdnet into the oracle just to resolve dead references.

#include "nbase.h"
#include "netutil.h"
#include <cstdlib>

extern "C" void *safe_zalloc(size_t size) {
  return calloc(1, size ? size : 1);
}

int Snprintf(char *s, size_t n, const char *fmt, ...) {
  (void)fmt;
  if (n) s[0] = '\0';
  return 0;
}

u16 get_random_u16(void) { return 0; }
u8 get_random_u8(void) { return 0; }

void netutil_fatal(const char *fmt, ...) {
  (void)fmt;
  abort();
}

char *format_ip_options(const u8 *ipopt, int ipoptlen) {
  (void)ipopt;
  (void)ipoptlen;
  return NULL;
}

int parse_ip_options(const char *txt, u8 *data, int datalen, int *firsthopoff,
                     int *lasthopoff, char *errstr, size_t errstrlen) {
  (void)txt;
  (void)data;
  (void)datalen;
  (void)firsthopoff;
  (void)lasthopoff;
  (void)errstr;
  (void)errstrlen;
  return -1;
}

void ip_checksum(void *buf, size_t len) {
  (void)buf;
  (void)len;
}
