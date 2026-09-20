/* Differential oracle for nmap's time-specification parser.
 *
 * WHAT THIS IS: a verbatim transcription of three functions from
 * `nbase/nbase_misc.c`, lifted rather than described. They are the shared
 * parser behind SIX of the options M7.7 implements — --min-rtt-timeout,
 * --max-rtt-timeout, --initial-rtt-timeout, --scan-delay, --max-scan-delay
 * and --host-timeout — so getting them wrong gets six options wrong at once.
 *
 * LINE MAP (nmap 7.94SVN, nbase/nbase_misc.c):
 *   tval2secs   lines 305-322
 *   tval2msecs  lines 325-335
 *   tval_unit   lines 339-351
 * The bodies below are byte-for-byte those functions. Only the comments and
 * the main() harness are new.
 *
 * WHY LIFT RATHER THAN DESCRIBE: the semantics are strtod's, and strtod
 * accepts far more than "a number" — hex floats ("0x10" is 16), exponents
 * ("1e3ms"), a leading sign, leading whitespace, and the literals "inf" and
 * "nan". A hand-written reimplementation of "parse a number with an optional
 * unit" would reject most of those and be wrong in a way no amount of
 * plausible-looking test data would reveal. The kit's rule exists for cases
 * exactly like this one.
 *
 * PROTOCOL: stdin is a sequence of NUL-separated records (a C string cannot
 * contain a NUL, so this loses no reachable input). For each record, one
 * output line:
 *     <tval2secs as its 64-bit IEEE pattern, hex>\t<tval2msecs as %ld>\t<tval_unit, hex>
 * The double is compared as raw bits rather than as text: %.17g is a lossy,
 * fiddly rendering to reproduce exactly on the Rust side, and reproducing a
 * PRINTING function is not what this oracle is for.
 * The unit is hex-encoded (and "-" when NULL) because it is a suffix of the
 * record and so can contain a tab or a newline -- "5\n" has the unit "\n" --
 * which would otherwise break the line-and-column framing. The whole point of
 * this oracle is to be fed arbitrary bytes, so the framing has to survive them.
 * %.17g round-trips an IEEE double exactly, so the Rust side can compare the
 * parsed value rather than a rounded rendering of it.
 */
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- BEGIN verbatim from nbase/nbase_misc.c ---- */

/* Convert a time specification into a count of seconds. A time specification is
 * a non-negative real number, possibly followed by a units suffix. The suffixes
 * are "ms" for milliseconds, "s" for seconds, "m" for minutes, or "h" for
 * hours. Seconds is the default with no suffix. -1 is returned if the string
 * can't be parsed. */
double tval2secs(const char *tspec) {
  double d;
  char *tail;

  errno = 0;
  d = strtod(tspec, &tail);
  if (*tspec == '\0' || errno != 0)
    return -1;
  if (strcasecmp(tail, "ms") == 0)
    return d / 1000.0;
  else if (*tail == '\0' || strcasecmp(tail, "s") == 0)
    return d;
  else if (strcasecmp(tail, "m") == 0)
    return d * 60.0;
  else if (strcasecmp(tail, "h") == 0)
    return d * 60.0 * 60.0;
  else
    return -1;
}

long tval2msecs(const char *tspec) {
  double s, ms;

  s = tval2secs(tspec);
  if (s == -1)
    return -1;
  ms = s * 1000.0;
  if (ms > LONG_MAX || ms < LONG_MIN)
    return -1;

  return (long) ms;
}

/* Returns the unit portion of a time specification (such as "ms", "s", "m", or
   "h"). Returns NULL if there was a parsing error or no unit is present. */
const char *tval_unit(const char *tspec) {
  double d;
  char *tail;

  errno = 0;
  d = strtod(tspec, &tail);
  /* Avoid GCC 4.6 error "variable 'd' set but not used
     [-Wunused-but-set-variable]". */
  (void) d;
  if (*tspec == '\0' || errno != 0 || *tail == '\0')
    return NULL;

  return tail;
}

/* ---- END verbatim ---- */

int main(void) {
  static char buf[1 << 20];
  size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
  buf[n] = '\0';

  /* Records are the NUL-terminated runs before each separator; the trailing
     separator terminates the last record and does not start a new one. */
  size_t i = 0;
  while (i < n) {
    const char *rec = buf + i;
    size_t len = strlen(rec);
    const char *unit = tval_unit(rec);
    double secs = tval2secs(rec);
    uint64_t bits;
    memcpy(&bits, &secs, sizeof bits);
    printf("%016llx\t%ld\t", (unsigned long long) bits, tval2msecs(rec));
    if (unit == NULL) {
      putchar('-');
    } else {
      for (const unsigned char *u = (const unsigned char *) unit; *u; u++)
        printf("%02x", *u);
    }
    putchar('\n');
    i += len + 1;
  }
  return 0;
}
