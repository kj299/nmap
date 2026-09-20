/* Differential oracle for nmap's output-filename expander.
 *
 * WHAT THIS IS: a verbatim transcription of `logfilename()` from
 * `output.cc`, lifted rather than described. Every `-oN` / `-oX` / `-oG` /
 * `-oA` argument passes through it, so a wrong answer here silently writes the
 * operator's scan to the wrong file — or to the same file every day, when they
 * asked for a dated series.
 *
 * LINE MAP (nmap 7.94SVN, output.cc): logfilename, lines 853-899.
 * The body below is byte-for-byte that function. Only the comments, the fixed
 * `tm`, and the main() harness are new.
 *
 * WHY LIFT RATHER THAN DESCRIBE: the escape rules are not the obvious ones.
 * An UNRECOGNISED conversion drops the '%' and keeps the letter, so "%Z"
 * expands to "Z" and "%%" to "%"; a trailing '%' is dropped entirely; and the
 * recognised set is exactly eleven letters, several of which (D = %m%d%y,
 * T = %H%M%S, R = %H%M) are nmap's own compressed spellings rather than the
 * C-library ones. Reimplementing "handle strftime escapes" from memory gets at
 * least three of those wrong.
 *
 * DETERMINISM: the caller passes local time. This harness pins a fixed UTC
 * `tm` so the golden is reproducible on any machine in any timezone; the Rust
 * side is given the same instant. (The port itself renders UTC rather than
 * local time — its standing convention, ledgered as `logfile-name-in-utc`.)
 *
 * PROTOCOL: stdin is a sequence of NUL-separated records. For each, one line:
 *     <expanded name, hex>
 * Hex because a filename may contain a tab or a newline, and this oracle
 * exists to be fed arbitrary bytes.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_STRFTIME_EXPANSION 10

static void *safe_malloc(size_t n) {
  void *p = malloc(n ? n : 1);
  if (!p) {
    abort();
  }
  return p;
}

static void *safe_realloc(void *q, size_t n) {
  void *p = realloc(q, n ? n : 1);
  if (!p) {
    abort();
  }
  return p;
}

/* ---- BEGIN verbatim from output.cc ---- */

char *logfilename(const char *str, struct tm *tm) {
  char *ret, *end, *p;
  // Max expansion: "%F" => "YYYY-mm-dd"
  int retlen = strlen(str) * (MAX_STRFTIME_EXPANSION - 2) + 1;
  size_t written = 0;

  ret = (char *) safe_malloc(retlen);
  end = ret + retlen;

  for (p = ret; *str; str++) {
    if (*str == '%') {
      str++;
      written = 0;

      if (!*str)
        break;

#define FTIME_CASE(_fmt, _fmt_str) case _fmt: \
        written = strftime(p, end - p, _fmt_str, tm); \
        break;

      switch (*str) {
        FTIME_CASE('H', "%H");
        FTIME_CASE('M', "%M");
        FTIME_CASE('S', "%S");
        FTIME_CASE('T', "%H%M%S");
        FTIME_CASE('R', "%H%M");
        FTIME_CASE('m', "%m");
        FTIME_CASE('d', "%d");
        FTIME_CASE('y', "%y");
        FTIME_CASE('Y', "%Y");
        FTIME_CASE('D', "%m%d%y");
        FTIME_CASE('F', "%Y-%m-%d");
      default:
        *p++ = *str;
        continue;
      }

      assert(end - p > 1);
      p += written;
    } else {
      *p++ = *str;
    }
  }

  *p = 0;

  return (char *) safe_realloc(ret, strlen(ret) + 1);
}

/* ---- END verbatim ---- */

int main(int argc, char **argv) {
  /* A fixed instant, so the golden does not depend on when it was made.
     Overridable so the Rust side and this oracle can agree on any instant. */
  time_t when = (argc > 1) ? (time_t) strtoll(argv[1], NULL, 10) : 1789000000;
  struct tm tmv;
  gmtime_r(&when, &tmv);

  static char buf[1 << 20];
  size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
  buf[n] = '\0';

  size_t i = 0;
  while (i < n) {
    const char *rec = buf + i;
    size_t len = strlen(rec);
    char *out = logfilename(rec, &tmv);
    for (const unsigned char *u = (const unsigned char *) out; *u; u++)
      printf("%02x", *u);
    putchar('\n');
    free(out);
    i += len + 1;
  }
  return 0;
}
