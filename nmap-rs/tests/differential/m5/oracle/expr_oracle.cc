// M5 expr_match oracle — the C side of core::osdb::expr.
//
// A verbatim transcription of expr_match() from osscan.cc (plus strchr_p() from
// nbase/nbase_str.c, its only dependency). Both are self-contained: pure pointer
// walking over two byte strings with no nmap globals, no allocation, no I/O.
//
// expr_match is how nmap decides whether an *observed* fingerprint attribute value
// matches a *reference* expression out of nmap-os-db. The expression language it
// implements is small but gnarly:
//   * alternation      "A|B|C"
//   * hex ranges       "1-5"      (inclusive, leading zeros normalized)
//   * comparisons      ">400" "<A"
//   * nested groups    "M[>500]ST11W[1-5]"   (only when do_nested)
// The C author's own comment on the pointer soup is `/* OHHHH YEEEAAAAAHHHH!#!@#$!% */`,
// which is why this module gets a real C oracle rather than hand-written expectations.
//
// Protocol: one case per stdin line, tab-separated:
//     <do_nested 0|1> \t <val> \t <expr>
// Prints one token per line:
//     "1"      match
//     "0"      no match
//     "ABORT"  the C died on this input (its `assert(q1)` on an unterminated '[')
//
// Each case runs in a forked child so an abort is *recorded* rather than ending the
// run. That matters: "the C aborts here" is a real, citable behavior of the original,
// and the Rust differential asserts our port returns a value instead (see
// DIVERGENCES.md `osdb-expr-unterminated-nest-no-abort`). Modelling when the assert
// fires would mean re-deriving the very pointer logic under test, so we observe it.
//
// `val` and `expr` are taken literally, so they must not contain a tab or newline;
// the generator only emits printable ASCII without those.
//
// Build: g++ -O2 -Wall expr_oracle.cc -o expr_oracle   (do NOT define NDEBUG: the
// assert is exactly what we want to observe).

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <cctype>
#include <string>

// --- verbatim from nbase/nbase_str.c --------------------------------------------
const char *strchr_p(const char *str, const char *end, char c) {
  const char *q=str;
  assert(str && end >= str);
  for (; q < end; q++) {
    if (*q == c)
      return q;
  }
  return NULL;
}

// --- verbatim from osscan.cc ----------------------------------------------------
bool expr_match(const char *val, size_t vlen, const char *expr, size_t explen, bool do_nested) {
  const char *p, *q, *q1;  /* OHHHH YEEEAAAAAHHHH!#!@#$!% */
  if (vlen == 0)
    vlen = strlen(val);
  if (explen == 0)
    explen = strlen(expr);

  // If both are empty, match; else if either is empty, no match.
  if (explen == 0) {
    return vlen == 0;
  }

  p = expr;
  const char * const p_end = p + explen;

  do {
    const char *nest = NULL; // where the [] nested expr starts
    const char *subval = val; // portion of val after previous nest and before the next one
    size_t sublen; // length of subval not subject to nested matching
    q = strchr_p(p, p_end, '|');
    nest = strchr_p(p, q ? q : p_end, '[');

    if (vlen == 0) {
      // value is empty, so can only match an empty expression
      if (q == p || p == p_end ) {
        // expression is also empty, match
        return true;
      }
      else if (!nest) {
        // simple expression before '|', no match.
        goto next_expr;
      }
      // other short-circuit may be possible here, but drop to nesting logic
      // below to avoid confusion/bugs
    }

    // if we're already in a nested expr, we skip this and just match as usual.
    if (do_nested && nest) {
      // As long as we keep finding nested portions, e.g. M[>500]ST11W[1-5]
      while (nest) {
        q1 = strchr_p(nest, p_end, ']');
        assert(q1);
        if (q && q < q1) {
          // "AB[C|D]E|XYZ"
          q = strchr_p(q1, p_end, '|');
        }
        // "AB[C-D]E" or  or "AB[C-D]E|F"
        sublen = nest - p;
        if (strncmp(p, subval, sublen) != 0) {
          goto next_expr;
        }
        nest++;
        subval += sublen;
        size_t nlen = 0;
        while (isxdigit(subval[nlen])) {
          nlen++;
        }
        p = q1 + 1;
        if (nlen > 0 && expr_match(subval, nlen, nest, q1 - nest, false)) {
          subval += nlen;
          nest = strchr_p(p, q ? q : p_end, '[');
        }
        else {
          goto next_expr;
        }
      }
      // No more nested portions. string match the rest:
      sublen = vlen - (subval - val);
      if ((explen - (p - expr)) == sublen && !strncmp(subval, p, sublen)) {
        return true;
      }
      else {
        goto next_expr;
      }
    }
    // Now sublen is the length of the relevant portion of expr
    sublen = q ? q - p : explen - (p - expr);
    if (isxdigit(*subval)) {
      while (*subval == '0' && vlen > 1) {
        subval++;
        vlen--;
      }
      if (*p == '>') {
        do {
          p++;
          sublen--;
        } while (*p == '0' && sublen > 1);
        if ((vlen > sublen)
            || (vlen == sublen && strncmp(subval, p, vlen) > 0)) {
          return true;
        }
        goto next_expr;
      }
      else if (*p == '<') {
        do {
          p++;
          sublen--;
        } while (*p == '0' && sublen > 1);
        if ((vlen < sublen)
            || (vlen == sublen && strncmp(subval, p, vlen) < 0)) {
          return true;
        }
        goto next_expr;
      }
      else if (isxdigit(*p)) {
        while (sublen > 1 && *p == '0') {
          p++;
          sublen--;
        }
        q1 = strchr_p(p, q ? q : p_end, '-');
        if (q1 != NULL) {
          if (q1 == p) {
            p--;
            sublen++;
          }
          size_t sublen1 = q1 - p;
          if ((vlen > sublen1)
              || (vlen == sublen1 && strncmp(subval, p, vlen) >= 0)) {
            p = q1 + 1;
            sublen -= (sublen1 + 1);
            while (sublen > 1 && *p == '0') {
              p++;
              sublen--;
            }
            if ((vlen < sublen)
                || (vlen == sublen && strncmp(subval, p, vlen) <= 0)) {
              return true;
            }
          }
          goto next_expr;
        }
      }
      else {
        // subval isxdigit, but expr doesn't start with xdigit or < or >
        goto next_expr;
      }
    }
    if (vlen == sublen && !strncmp(p, subval, vlen)) {
      return true;
    }
    next_expr:
    if (q)
      p = q + 1;
  } while (q);

  return false;
}

// --- driver ---------------------------------------------------------------------
#include <unistd.h>
#include <sys/wait.h>

/* Run one case in a child so an abort() is observable rather than fatal.
   Returns 0/1 for the boolean result, or -1 if the child died. */
static int run_case(const char *val, const char *expr, bool do_nested) {
  int fds[2];
  if (pipe(fds) != 0) return -1;
  pid_t pid = fork();
  if (pid < 0) { close(fds[0]); close(fds[1]); return -1; }
  if (pid == 0) {
    close(fds[0]);
    // Silence the assert message; the exit status is what we read.
    if (!freopen("/dev/null", "w", stderr)) { /* best effort */ }
    // Pass explicit lengths so an empty string stays empty (the C treats a 0
    // length as "call strlen", which for "" is 0 anyway — same thing).
    unsigned char r = expr_match(val, strlen(val), expr, strlen(expr), do_nested) ? 1 : 0;
    ssize_t unused = write(fds[1], &r, 1);
    (void)unused;
    close(fds[1]);
    _exit(0);
  }
  close(fds[1]);
  unsigned char r = 0;
  ssize_t got = read(fds[0], &r, 1);
  close(fds[0]);
  int status = 0;
  waitpid(pid, &status, 0);
  if (got != 1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return -1;
  return r ? 1 : 0;
}

int main(void) {
  char buf[8192];
  while (fgets(buf, sizeof(buf), stdin)) {
    size_t n = strlen(buf);
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';
    // split on two tabs
    char *t1 = strchr(buf, '\t');
    if (!t1) { printf("ERR\n"); continue; }
    *t1 = '\0';
    char *t2 = strchr(t1 + 1, '\t');
    if (!t2) { printf("ERR\n"); continue; }
    *t2 = '\0';
    bool do_nested = (atoi(buf) != 0);
    int r = run_case(t1 + 1, t2 + 1, do_nested);
    if (r < 0) printf("ABORT\n");
    else printf("%d\n", r);
    fflush(stdout);
  }
  return 0;
}
