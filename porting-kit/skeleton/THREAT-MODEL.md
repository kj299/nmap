# Threat model — <project>

Fill this in at Phase 0, before writing Rust. It scopes what "secure" means here
and tells the port loop which modules touch untrusted input (fuzz those first)
and which cross a privilege boundary (audit those hardest).

## 1. Assets — what are we protecting?
- e.g. the integrity of the host we run on; the confidentiality of data we read;
  our own process from being subverted by hostile input.

## 2. Trust boundaries — where does untrusted data / lower trust cross in?
List each entry point and mark it. These are the fuzz + validation priorities.
The **bound** column is availability: how time and peak memory may grow with the
input (n = its size), checked at n/2n/4n against C by
`harnesses/scaling/scale_check.py` (PLAYBOOK Phase 4 step 4b; LESSONS #040).
| Entry point | Source | Trust | Ported module | Bound (time / memory) |
|---|---|---|---|---|
| CLI args / stdin | user / pipe | untrusted | `cli`, `core::parser` | e.g. O(n) / O(n) |
| files parsed | filesystem (may be a FIFO or `/dev/zero`) | semi-trusted | | |
| network / IPC | remote | untrusted | | |
| environment / config | operator | trusted-ish | | |

### 2a. What the standard requires of a receiver (LESSONS #056)
For each message the tool *receives and acts on*, list the checks its standard
makes mandatory for a receiver, and whether the C makes them. The flaw scanner
cannot see a check that is absent. nmap acts on a Neighbor Advertisement without
the hop-limit-255 check RFC 4861 §7.1.2 requires; the port found that only in a
review, after it had begun framing every probe to the address such a message names.
| Message | Standard's receiver MUSTs | C checks them? | Port |
|---|---|---|---|
| e.g. ND Neighbor Advertisement | hop limit 255; valid checksum; length | no | enforce, ledger |

### 2b. Claims this environment cannot measure (LESSONS #056)
A claim about the C's run-time behaviour that was read, not run. Trace each from
the option's *default* value, not from the branch that looks like the main path.
| Claim | Read from (`rev:path:line`, incl. where the default is set) | Why unmeasured here | Step that will measure it |
|---|---|---|---|

## 3. Privilege transitions
Where does the tool gain/drop privilege, elevate, or act on another security
principal's behalf? Each is an audit hotspot; keep privilege JUST-IN-TIME and
scoped (the retrospective's `PrivilegeGuard` RAII pattern).

## 4. Attacker capabilities we defend against
- Supplies arbitrary bytes on any untrusted boundary (→ no panic/UB: fuzz gate).
- Supplies pathological sizes (→ no integer overflow / OOM: overflow-checks on).
- Supplies inputs shaped to maximise work: deep nesting, long runs, repeated
  formats, a path that never reaches EOF (→ the bound column; "it can yield" is
  not "it is bounded").
- Races the filesystem/IPC (→ no TOCTOU: prefer open-then-check over check-then-open).

## 5. Explicit non-goals
- e.g. we do not defend against a malicious operator who already has our
  privileges; side-channel resistance is out of scope. State them so reviewers
  don't assume coverage that isn't there.

## 6. C-defect inventory (from `scan_c_flaws.py`)
Link the Phase-0 scan output. Each confirmed flaw becomes a DIVERGENCES.md entry
when the port closes it.
