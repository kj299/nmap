/* What nse_openssl.cc and nse_ssl_cert.cc take from the rest of nmap, for
 * the standalone M6.5 oracle (build_openssl_oracle.sh). Nothing here changes
 * what the module computes:
 *   - `o.debugging` and `o.verbose` gate two log lines when a provider fails
 *     to load (nse_openssl.cc:642, 649); both are 0, as in a plain nmap run;
 *   - `log_write` writes those lines to stderr;
 *   - `get_random_bytes` is nbase's non-cryptographic generator in nmap
 *     (nbase/nbase_rnd.c); here RAND_bytes. rand_pseudo_bytes' output is
 *     random either way, and the corpora compare only its length;
 *   - `MIN`, as nbase.h defines it;
 *   - `oracle_nsock_ssl_env`: what nmap does to OpenSSL's global state before
 *     the `openssl` library opens. nse_main.cc:563-572 opens `nmap` first,
 *     whose `luaopen_nsock` calls `nsock_pool_ssl_init` (nse_nsock.cc:1227),
 *     which loads the legacy and default providers (nsock_ssl.c:159-178) and
 *     creates an SSL_CTX (nsock_ssl.c:143). SSL_CTX_new runs
 *     OPENSSL_init_ssl, which registers every cipher and digest name, so
 *     `supported_ciphers` and `supported_digests` (OBJ_NAME_do_all_sorted)
 *     list them; without it they return empty tables (measured);
 *   - `nse_nsock_get_ssl` returns NULL: get_ssl_certificate needs a live
 *     nsock socket, and the TLS fixtures (m65_tls/) cover it against nmap. */
#ifndef OPENSSL_ORACLE_SHIM_H
#define OPENSSL_ORACLE_SHIM_H

#include <stdarg.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#ifndef HAVE_OPENSSL
#define HAVE_OPENSSL 1
#endif

/* nbase.h */
#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

#define SCRIPT_ENGINE "NSE"
#define LOG_STDOUT 1

static struct {
  int debugging;
  int verbose;
} o = {0, 0};

static inline void log_write(int, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

static inline int get_random_bytes(void *buf, int numbytes) {
  return RAND_bytes((unsigned char *) buf, numbytes) == 1 ? 0 : -1;
}

static inline void oracle_nsock_ssl_env(void) {
  static SSL_CTX *ctx;
  if (ctx) return;
  OSSL_PROVIDER_load(NULL, "legacy");
  OSSL_PROVIDER_load(NULL, "default");
  ctx = SSL_CTX_new(SSLv23_client_method());
  ERR_clear_error();
}

struct lua_State;
static inline SSL *nse_nsock_get_ssl(struct lua_State *) { return NULL; }

#endif
