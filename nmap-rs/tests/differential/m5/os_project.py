#!/usr/bin/env python3
"""Canonical projection of an nmap `-O` fingerprint, for the M5 differential.

Both C nmap and nmap-rs are asked to fingerprint the same loopback host. What must
agree is the *observed fingerprint* — the thirteen tests and their attributes — because
that is the entire input to OS matching. Everything else in the output is decoration.

Three classes of field are stripped, and each for a stated reason rather than to make the
diff pass:

  * The `SCAN(...)` line: scanner version, date, timestamp, and the ports/interface this
    particular run happened to choose. None of it describes the target's stack.
  * `SEQ`'s `SP`, `GCD` and `ISR`: these summarise the *randomness* of the target's ISN
    generator, sampled over six probes. Two runs against the same host legitimately differ
    here — that is the property being measured. `TI`/`CI`/`II`/`TS` are kept, because those
    classify the counter's behaviour and are stable.
  * `T`/`TG`: the reconstructed initial TTL depends on the measured hop count, which on
    loopback is 0 for both but is not guaranteed identical off-loopback.

Everything else — OPS, WIN, ECN, T1-T7, U1, IE, and SEQ's classification attributes —
must match exactly. Those are the fields that carry the identifying signal.
"""
import re
import sys

# Attributes whose value is a sample of randomness rather than a property of the stack.
VOLATILE = {
    "SEQ": {"SP", "GCD", "ISR"},
}
# `SEQ`'s IP-ID classification attributes. Their *values* are properties of the target's
# counters and must agree. Their *presence* is not comparable between the two tools: each
# needs at least two usable IP-ID samples, and C nmap discards the sample from any probe it
# retransmitted ("Retransmitted ipid is useless", osscan2.cc) — so under packet loss it
# emits fewer of these than a run that lost nothing. This port re-sends the whole battery
# per round instead of retransmitting individual probes, so its samples always come from
# first transmissions. Comparing presence would therefore diff the two tools' luck rather
# than their fidelity. Compared when both sides have them; skipped when only one does.
PRESENCE_OPTIONAL = {("SEQ", "TI"), ("SEQ", "CI"), ("SEQ", "II")}

# `U1`'s *response* is run-dependent on loopback. The probe is a UDP datagram to a closed
# port; the response is an ICMP port-unreachable, and whether it is elicited and captured
# inside the scan window is a race that C nmap and nmap-rs — which run seconds apart — can
# lose independently. The same commit has produced a run where both tools saw the response
# and a run where only one did. So when the two sides disagree on whether `U1` got a
# response at all (`R=Y` vs `R=N`), that is sampling luck, not a fidelity divergence, and
# the test is skipped. When BOTH saw a response its attributes are still compared in full,
# and a `U1` test missing entirely from one side is still caught (a broken battery, not a
# race). Same spirit as PRESENCE_OPTIONAL.
RESPONSE_OPTIONAL_TESTS = {"U1"}

# `SEQ`'s `TS` is a *measured frequency*: the timestamp counter's rate, derived from how
# much it advanced across six probes spread over half a second. The two tools run
# seconds apart, so their measurement windows differ and the value can land one bucket
# either side — the same reason `ISR` is stripped. Its non-numeric forms are different in
# kind: `U` means the option was absent and `0` means the counter was zero, and both are
# stable properties of the stack rather than samples, so they are kept and compared.
STABLE_TS = {"U", "0"}
# Attributes stripped from every test.
VOLATILE_ANY = {"T", "TG"}
# Tests to compare. SCAN is metadata about the run, not the target.
SKIP_TESTS = {"SCAN"}

TEST_RE = re.compile(r"([A-Z0-9]+)\(([^)]*)\)")


def extract(text):
    """Pull the fingerprint text out of either tool's output.

    C nmap wraps it in `OS:`-prefixed continuation lines; nmap-rs prints the tests one
    per line. Both reduce to the same `NAME(A=v%B=v)` soup.
    """
    joined = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("OS:"):
            joined.append(line[3:])
        elif TEST_RE.fullmatch(line):
            joined.append(line)
    return "".join(joined)


def project(text):
    """Canonical `TEST(ATTR=VAL%...)` lines, sorted, with volatile fields removed.

    Under `-d` both tools print a fingerprint *per retry round*, so the same test name
    appears several times. Only the last occurrence is the reported fingerprint — the
    earlier ones are incomplete rounds. Keeping them all would merge several rounds into
    one soup and diff two things that are not comparable.
    """
    latest = {}
    for name, body in TEST_RE.findall(extract(text)):
        if name in SKIP_TESTS:
            continue
        latest[name] = body

    out = []
    for name, body in latest.items():
        drop = VOLATILE.get(name, set()) | VOLATILE_ANY
        attrs = []
        for pair in body.split("%"):
            if not pair:
                continue
            key, _, value = pair.partition("=")
            if key in drop:
                continue
            if name == "SEQ" and key == "TS" and value not in STABLE_TS:
                continue
            attrs.append(pair)
        out.append(f"{name}({'%'.join(attrs)})")
    return "\n".join(sorted(out))


def self_test():
    c = (
        "OS:SCAN(V=7.94%D=8/23%OT=22%CT=1%CU=38291%TM=6A8A)SEQ(SP=101%GCD=1%ISR=109%TI=Z\n"
        "OS:%CI=Z%II=I%TS=21)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)\n"
    )
    rs = "SEQ(SP=F7%GCD=2%ISR=FF%TI=Z%CI=Z%II=I%TS=21)\nT1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)\n"
    a, b = project(c), project(rs)
    assert a == b, f"self-test failed:\n{a}\n---\n{b}"
    # A real disagreement must still be caught.
    bad = rs.replace("F=AS", "F=A")
    assert project(bad) != a, "self-test failed: a real divergence was masked"
    # And a volatile-only difference must not be.
    assert "SP=" not in a and "SCAN" not in a and "T=40" not in a
    # Multi-round `-d` output: only the final round counts, and no test appears twice.
    multi = "OPS(O1=%O2=%O3=%O4=%O5=%O6=)\nOPS(O1=MFF%O2=MFF%O3=MFF%O4=MFF%O5=MFF%O6=MFF)\n"
    proj = project(multi)
    assert proj.count("OPS(") == 1, f"rounds were merged: {proj}"
    assert "O1=MFF" in proj, f"kept the wrong round: {proj}"
    # A numeric TS is a measurement and is dropped; U/0 are classifications and are kept.
    assert "TS=" not in project("SEQ(TI=Z%TS=21)")
    assert "TS=U" in project("SEQ(TI=Z%TS=U)")
    assert "TS=0" in project("SEQ(TI=Z%TS=0)")
    # Stripping TS must not blind the gate to the attributes that carry the signal.
    assert project("SEQ(TI=Z%TS=21)") != project("SEQ(TI=I%TS=21)")

    # An IP-ID attribute only one side sampled is sampling luck, not a divergence...
    assert compare("SEQ(TI=Z%CI=Z)", "SEQ(TI=Z%CI=Z%II=I)") == []
    # ...but a value both sides have and disagree on IS one.
    assert compare("SEQ(TI=Z%II=I)", "SEQ(TI=Z%II=RD)") != []
    assert compare("SEQ(TI=Z)", "SEQ(TI=I)") != []
    # And a non-optional attribute missing from one side is still caught.
    assert compare("T1(R=Y%DF=Y)", "T1(R=Y)") != []
    assert compare("T1(R=Y)", "T1(R=Y)") == []
    # A whole missing test is caught.
    assert compare("T1(R=Y)\nU1(R=Y)", "T1(R=Y)") != []
    # A U1 response seen by only one side (the loopback ICMP-unreachable race) is skipped...
    assert compare("U1(R=Y%DF=N%IPL=164%UN=0%RIPL=G)", "U1(R=N)") == []
    assert compare("U1(R=N)", "U1(R=Y%DF=N%IPL=164)") == []
    # ...both no response agree...
    assert compare("U1(R=N)", "U1(R=N)") == []
    # ...but when BOTH responded, the content is still compared, and a real divergence caught.
    assert compare("U1(R=Y%DF=N)", "U1(R=Y%DF=Y)") != []
    assert compare("U1(R=Y%DF=N%IPL=164)", "U1(R=Y%DF=N%IPL=164)") == []
    # The response-race tolerance is U1-only: a T-test response mismatch is still a divergence.
    assert compare("T4(R=Y%DF=Y)", "T4(R=N)") != []
    print("os_project.py self-test OK")


def parse(text):
    """`{test: {attr: value}}` after stripping the volatile fields."""
    out = {}
    for line in project(text).splitlines():
        name, _, rest = line.partition("(")
        attrs = {}
        for pair in rest.rstrip(")").split("%"):
            if pair:
                k, _, v = pair.partition("=")
                attrs[k] = v
        out[name] = attrs
    return out


def compare(c_text, rs_text):
    """Differences that represent a fidelity divergence. Empty list means agreement."""
    c, rs = parse(c_text), parse(rs_text)
    problems = []

    for name in sorted(set(c) | set(rs)):
        if name not in c:
            problems.append(f"{name}: only nmap-rs emitted this test")
            continue
        if name not in rs:
            problems.append(f"{name}: only C nmap emitted this test")
            continue
        # A U1 response seen by only one side is a loopback race, not a divergence.
        if name in RESPONSE_OPTIONAL_TESTS and c[name].get("R") != rs[name].get("R"):
            continue
        for attr in sorted(set(c[name]) | set(rs[name])):
            in_c, in_rs = attr in c[name], attr in rs[name]
            if in_c and in_rs:
                if c[name][attr] != rs[name][attr]:
                    problems.append(
                        f"{name}.{attr}: C nmap={c[name][attr]!r} nmap-rs={rs[name][attr]!r}"
                    )
            elif (name, attr) in PRESENCE_OPTIONAL:
                continue  # sampling luck, not fidelity — see PRESENCE_OPTIONAL
            else:
                who = "C nmap" if in_c else "nmap-rs"
                problems.append(f"{name}.{attr}: only {who} emitted this attribute")
    return problems


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    elif len(sys.argv) == 3:
        issues = compare(open(sys.argv[1]).read(), open(sys.argv[2]).read())
        for i in issues:
            print(i)
        sys.exit(1 if issues else 0)
    else:
        result = project(sys.stdin.read())
        # No trailing newline when empty: an empty projection must be detectably empty,
        # not a one-byte file that a `test -s` check would call non-empty.
        sys.stdout.write(result + "\n" if result else "")
