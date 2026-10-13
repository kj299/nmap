# ORACLE-CHECKS: is the reference sound, and can the corpus tell?

PLAYBOOK Phase 2 links here. A differential gate is only as strong as three
things. The reference must be defined behaviour. The corpus must reach what the
port exposes. The comparison must not forgive more than the ledger says. Each
section below is one check, with the M6.6 evidence behind it.

## 1. Defaults are inputs (LESSONS #047)

Most matrices pass every option explicitly, so they never test what happens
when an option is left out. Two nmap defects survived for milestones this way.
The terminal report went silent whenever `-o` wrote a file, a defect present
since M1. `-sU` scanned the TCP port list, a defect present since M4. Every
matrix passed `-p` and `-oX -`.

- **Each option gets a row where it is omitted.** Its default value then becomes
  part of the corpus.
- **Add the combinations users actually run**: a report to the terminal and to a
  file at once, a scan type with no port list, and so on.
- `harnesses/differential/input-matrix.example.toml` shows both shapes.

## 2. Reach census: what does the corpus actually call? (LESSONS #043)

Count the corpus rows that reach each function the port exposes: every
script-visible global, every API entry point, every option. **Zero rows means
unverified**, whatever the ported or vendored code claims.

A dependency's own compatibility list is not an oracle. nmap vendored the
`piccolo` Lua VM, whose `COMPATIBILITY.md` marked the base library
"implemented", and credited that at Phase 0. "Implemented" meant *present*.
Step d's review then found these defects:

- `pcall` raises on a non-callable;
- `pairs` and `ipairs` return 2 values;
- `#t` picks border 4 where C gives 8;
- `rawlen` and `rawset` are unchecked;
- `__metatable` is ignored;
- `collectgarbage` raises.

The corpora had **0 rows** for `rawlen(`, `rawset(`, `pairs(`, `ipairs(`,
`collectgarbage` and `{...}`. The fix was a first-party base library, 2,473
lines. So:

- Run the census at Phase 2, and again whenever a dependency's surface becomes
  reachable. A grep of the corpus for each name is enough to start with.
- Vet reused code for fidelity as well as safety (PLAYBOOK Phase 0, the
  safe-crate classification).
- A tolerance class that covers a dependency's divergence triggers an audit of
  that dependency's sibling functions. M6.6's `vmbase` class absorbed
  base-library differences from step b to step d.

## 3. Every C-generated golden is UB-screened (LESSONS #049)

Build the oracle a second time:

```
cc -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
   -DLUA_USE_APICHECK ...        # the embedded runtime's own API checks too
```

Run every generator's inputs through this build. Any report means that row's
golden records undefined behaviour. Either drop the row, or generate it from a
defined variant (`-fwrapv`, or a patched copy that is named in the generator)
and pin the port's answer as a semantic choice in the ledger. **UB that looks
deterministic is still UB.** nmap's tree golden held 14 rows whose C answers came
from signed `int` overflow (`lpeg.c:2374, 2377, 2643, 2655, 2977`). The ledger
justified them as "the C's arithmetic modulo 2^32", which made what `gcc -O1`
happened to do into the spec. CI regenerated them from that build on every run.

- **The screen's record carries a digest of everything that decides its
  verdict.** That is the corpus, the C sources (the library, the runtime, the
  glue), the screen script and the flags. The generator refuses a mismatch,
  and CI checks the record. nmap's screen digested the corpus only, so a change
  to `lpeg.c` or to the flags would not have forced a re-screen. Its second
  C-generated corpus had no screen at all. Nothing ran the screen. The only
  wiring was a digest check that a corpus edit tripped.
- **Build in the embedded library's own checking mode too** (LESSONS #051).
  ASan reported nothing on 40 to 299 nested captures. `LUA_USE_APICHECK`
  caught the Lua stack overflow they cause. ASan sees the C heap. The
  runtime's checks see the runtime's own invariants.
- **Store goldens greppable, or decode them before any sweep.** The tree golden
  was hex-encoded, so a text grep for `block too big` found nothing. The 14 rows
  turned up only when someone read the generator.

## 4. Sabotage the C to measure the corpus (LESSONS #044)

Build variants of the C oracle, each with one deliberate change to one
behaviour the port must reproduce. Then run the corpus against each variant.
A variant the corpus does not catch marks a behaviour the corpus cannot tell
apart. In M6.6, 16 sabotaged builds of `lpeg.c` measured the corpus at step 0b.
One of them kept dynamic captures on backtrack, and it passed all 60,806 rows.
At HEAD the harness runs 17 variants over 62,599 rows and catches every one.
Port sabotage measures the gates (`REVIEW-GATE.md`). C sabotage measures the
corpus. A milestone needs both.

## 5. A tolerance is an exemption: scope it and pin it (LESSONS #048)

A normalisation that makes a ledgered difference compare equal is not noise
removal. It is an exemption, and an unscoped exemption covers every row. nmap's
LPeg corpus gate tried its `position`, `argname` and `method` classes on every
differing row, and `report()` printed class members without asserting them.
The classes reached 5,906 of 62,599 rows. A port sabotaged to report argument
#2 for argument #1 passed on all 5,906. The control, `"value"` changed to
`"valuf"`, failed on 2 rows. So the gate was sound outside the class spans and
blind inside them.

- Tag each tolerance with the case IDs it was ledgered for. It must refuse to
  fire on any other case.
- Pin its membership exactly. A listed case that no longer needs the tolerance
  fails.
- `harnesses/differential/normalize.py` (`scoped_rule`, `[[tolerance]]` files)
  and `diff_run.py --tolerances` implement both. `diff_run.py` reports the
  second as `STALE-TOLERANCE`.
- Name the ledger entry in the tolerance. When the entry closes, the tolerance
  goes with it (LESSONS #031).

## 6. At the retrospective

1. Decode the goldens.
2. Re-run the UB screen with current flags and sources.
3. Re-run the reach census against the port's current surface.
4. Re-scan the C with any new scanner rules, and sweep the corpora for inputs
   that reach each hit (LESSONS #033).
