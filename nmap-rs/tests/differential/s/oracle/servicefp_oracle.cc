// Oracle for core::servicefp — nmap's REAL service-fingerprint builder.
//
// The four functions below are PASTED VERBATIM from service_scan.cc:1663-1795
// (addServiceChar, addServiceString, addToServiceFingerprint,
// getServiceFingerprint), with exactly three mechanical changes, each marked
// `// ORACLE:` at the site:
//
//   1. `ServiceNFO::` method qualifiers dropped; the four buffer fields and the
//      header inputs become file-scope variables, because linking the real
//      ServiceNFO would drag in the whole service-scan engine, nsock and OpenSSL
//      for four self-contained string functions.
//   2. The header's globals (NMAP_VERSION, NMAP_PLATFORM, o.version_intensity)
//      and its localtime() call become inputs read from the test case, so the
//      comparison is byte-exact instead of "equal after stripping what moves".
//      The FORMAT STRING and argument order are untouched.
//   3. o.debugging becomes a per-case flag.
//
// Nothing else is retyped. This matters: #70 shipped a real fidelity bug because
// an oracle "verbatim" comment sat above a function that had been quietly retyped
// without nmap's `if (val < 0) continue;` guard, so the differential compared a
// port against a paraphrase and proved only self-consistency.
//
// Reads cases from stdin, writes results to stdout. See gen_servicefp_cases.py.

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

// ORACLE: the ServiceNFO fields the four functions touch.
static char *servicefp = NULL;
static int servicefplen = 0;
static int servicefpalloc = 0;

// ORACLE: the header inputs, supplied per case instead of read from globals/clock.
static unsigned short g_portno;
static const char *g_proto;      // proto2ascii_uppercase(proto)
static const char *g_version;    // NMAP_VERSION
static const char *g_platform;   // NMAP_PLATFORM
static int g_intensity;          // o.version_intensity
static int g_ssl;                // tunnel == SERVICE_TUNNEL_SSL
static int g_mon;                // ltime.tm_mon + 1
static int g_mday;               // ltime.tm_mday
static int g_time;               // (int) timep
static int g_debugging;          // o.debugging

static void *safe_realloc(void *p, size_t n) {
  void *r = realloc(p, n);
  if (!r) { fprintf(stderr, "oom\n"); exit(1); }
  return r;
}
static void fatal(const char *fmt, ...) { fprintf(stderr, "%s\n", fmt); exit(1); }
#define Snprintf snprintf

static void reset_fp(void) {
  if (servicefp) free(servicefp);
  servicefp = NULL;
  servicefplen = servicefpalloc = 0;
}

// ---------------------------------------------------------------------------
// VERBATIM from service_scan.cc:1663 (ServiceNFO:: qualifier dropped)
  // Adds a character to servicefp.  Takes care of word wrapping if
  // necessary at the given (wrapat) column.  Chars will only be
  // written if there is enough space.  Otherwise it exits.
void addServiceChar(const char c, int wrapat) {

  if (servicefpalloc - servicefplen < 6)
    fatal("%s - out of space for servicefp");

  if (servicefplen % (wrapat+1) == wrapat) {
    // we need to start a new line
    memcpy(servicefp + servicefplen, "\nSF:", 4);
    servicefplen += 4;
  }

  servicefp[servicefplen++] = c;
}

// Like addServiceChar, but for a whole zero-terminated string
void addServiceString(const char *s, int wrapat) {
  while(*s)
    addServiceChar(*s++, wrapat);
}

// If a service responds to a given probeName, this function adds the
// response to the fingerprint for that service.  The fingerprint can
// be printed when nothing matches the service.  You can obtain the
// fingerprint (if any) via getServiceFingerprint();
void addToServiceFingerprint(const char *probeName, const u8 *resp,
                                         int resplen) {
  int spaceleft = servicefpalloc - servicefplen;
  int servicewrap=74; // Wrap after 74 chars / line
  int respused = MIN(resplen, (g_debugging)? 1300 : 900); // ORACLE: o.debugging
  // every char could require \xHH escape, plus there is the matter of
  // "\nSF:" for each line, plus "%r(probename,probelen,"") Oh, and
  // the SF-PortXXXX-TCP stuff, etc
  int spaceneeded = respused * 5 + strlen(probeName) + 128;
  int srcidx;
  char buf[128];

  assert(resplen);
  assert(probeName);

  if (servicefplen > (g_debugging? 10000 : 2200))   // ORACLE: o.debugging
    return; // it is large enough.

  if (spaceneeded >= spaceleft) {
    spaceneeded = MAX(spaceneeded, 512); // No point in tiny allocations
    spaceneeded += servicefpalloc;

    servicefp = (char *) safe_realloc(servicefp, spaceneeded);
    servicefpalloc = spaceneeded;
  }
  spaceleft = servicefpalloc - servicefplen;

  if (servicefplen == 0) {
    // ORACLE: NMAP_VERSION / NMAP_PLATFORM / o.version_intensity / localtime()
    // replaced by the per-case inputs. Format string and argument order verbatim.
    Snprintf(buf, sizeof(buf), "SF-Port%hu-%s:V=%s%s%%I=%d%%D=%d/%d%%Time=%X%%P=%s",
        g_portno, g_proto, g_version,
        (g_ssl)? "%T=SSL" : "", g_intensity,
        g_mon, g_mday, g_time, g_platform);
    addServiceString(buf, servicewrap);
  }

  // Note that we give the total length of the response, even though we
  // may truncate
  Snprintf(buf, sizeof(buf), "%%r(%s,%X,\"", probeName, resplen);
  addServiceString(buf, servicewrap);

  // Now for the probe response itself ...
  for(srcidx=0; srcidx < respused; srcidx++) {
    // A run of this can take up to 8 chars: "\n  \x20"
    assert(servicefpalloc - servicefplen > 8);

    if (isalnum((int)resp[srcidx]))
      addServiceChar((char) resp[srcidx], servicewrap);
    else if (resp[srcidx] == '\0') {
      /* We need to be careful with this, because if it is followed by
         an ASCII number, PCRE will treat it differently. */
      if (srcidx + 1 >= respused || !isdigit((int) resp[srcidx + 1]))
        addServiceString("\\0", servicewrap);
      else addServiceString("\\x00", servicewrap);
    } else if (strchr("\\?\"[]().*+$^|", resp[srcidx])) {
      addServiceChar('\\', servicewrap);
      addServiceChar(resp[srcidx], servicewrap);
    } else if (ispunct((int)resp[srcidx])) {
      addServiceChar((char) resp[srcidx], servicewrap);
    } else if (resp[srcidx] == '\r') {
      addServiceString("\\r", servicewrap);
    } else if (resp[srcidx] == '\n') {
      addServiceString("\\n", servicewrap);
    } else if (resp[srcidx] == '\t') {
      addServiceString("\\t", servicewrap);
    } else {
      addServiceChar('\\', servicewrap);
      addServiceChar('x', servicewrap);
      Snprintf(buf, sizeof(buf), "%02x", resp[srcidx]);
      addServiceChar(*buf, servicewrap);
      addServiceChar(*(buf+1), servicewrap);
    }
  }

  addServiceChar('"', servicewrap);
  addServiceChar(')', servicewrap);
  assert(servicefpalloc - servicefplen > 1);
  servicefp[servicefplen] = '\0';
}

const char *getServiceFingerprint(int *flen) {

  if (servicefplen == 0) {
    if (flen) *flen = 0;
    return NULL;
  }

  // Ensure we have enough space for the terminating semi-colon and \0
  if (servicefplen + 2 > servicefpalloc) {
    servicefpalloc = servicefplen + 20;
    servicefp = (char *) safe_realloc(servicefp, servicefpalloc);
  }

  if (flen) *flen = servicefplen + 1;
  // We terminate with a semi-colon, which is never wrapped.
  servicefp[servicefplen] = ';';
  servicefp[servicefplen + 1] = '\0';
  return servicefp;
}
// END VERBATIM
// ---------------------------------------------------------------------------

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Decode a hex string into buf; returns length, or -1.
static int unhex(const char *s, u8 *out, int cap) {
  int n = 0;
  while (s[0] && s[1]) {
    int hi = hexval(s[0]), lo = hexval(s[1]);
    if (hi < 0 || lo < 0) return -1;
    if (n >= cap) return -1;
    out[n++] = (u8)((hi << 4) | lo);
    s += 2;
  }
  return s[0] ? -1 : n;
}

static void emit_escaped(const char *s) {
  for (; *s; s++) {
    if (*s == '\n') fputs("\\n", stdout);
    else if (*s == '\\') fputs("\\\\", stdout);
    else fputc(*s, stdout);
  }
}

int main(void) {
  static char line[1 << 16];
  static u8 resp[1 << 15];
  char probe[256];

  // Case format, one per line:
  //   CASE <id> <port> <proto> <version> <platform> <intensity> <ssl> <mon> <mday> <time> <debug>
  //   RESP <probeName> <hexbytes>
  //   FINISH
  static char version[64], platform[128], proto[16];
  char id[64];

  while (fgets(line, sizeof(line), stdin)) {
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;
    if (strncmp(line, "CASE ", 5) == 0) {
      reset_fp();
      if (sscanf(line + 5, "%63s %hu %15s %63s %127s %d %d %d %d %d %d",
                 id, &g_portno, proto, version, platform,
                 &g_intensity, &g_ssl, &g_mon, &g_mday, &g_time, &g_debugging) != 11) {
        fprintf(stderr, "bad CASE line: %s\n", line);
        return 1;
      }
      g_proto = proto; g_version = version; g_platform = platform;
    } else if (strncmp(line, "RESP ", 5) == 0) {
      char *sp = strchr(line + 5, ' ');
      if (!sp) { fprintf(stderr, "bad RESP line\n"); return 1; }
      *sp = 0;
      snprintf(probe, sizeof(probe), "%s", line + 5);
      int n = unhex(sp + 1, resp, (int)sizeof(resp));
      if (n < 0) { fprintf(stderr, "bad hex\n"); return 1; }
      // The C asserts resplen; the generator never emits an empty response.
      if (n > 0) addToServiceFingerprint(probe, resp, n);
    } else if (strcmp(line, "FINISH") == 0) {
      int flen = 0;
      const char *fp = getServiceFingerprint(&flen);
      printf("%s ", id);
      if (!fp) printf("NONE\n");
      else { emit_escaped(fp); printf("\n"); }
      fflush(stdout);
    }
  }
  return 0;
}
