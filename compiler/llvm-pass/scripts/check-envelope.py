#!/usr/bin/env python3
"""Grade the envelope build-envelope.py assembled.

Same rule as check-matrix.py, and for the same reason: the expectations below
were written from what each axis is for, not transcribed from a run. A cell that
disagrees is printed as a disagreement. This file is not edited to make a run
pass.

What is asserted, and why it is an expectation rather than a transcription:

  * The optimisation canary. erasure's wipe is a dead store above -O1 and the
    control's is not. A whole envelope in which nothing is ever LOST is a broken
    measurement wearing a clean result, so this is checked first and the run
    fails without it.

  * The NDEBUG axis. ndebug/target.c is written so the subject's deny path is
    not in the preprocessed source when NDEBUG is defined. The property
    therefore cannot be established at the first checkpoint. That is a property
    of the fixture, decided when it was written, so ABSENT is an expectation and
    not a reading.

  * The NDEBUG axis, negatively. erasure and authz consult no macro, so
    -DNDEBUG must change nothing about them. An axis that moved those cells
    would be moving something other than the thing it names.

  * The LTO axis. A pre-link LTO compile still runs an optimisation pipeline, so
    it must be observable. A cell that is declared broken must actually break,
    and a cell that is not declared broken must not.

  * The target axis. Nothing is asserted about the verdict. Whether a security
    property survives differently on another target is what the axis exists to
    find out, and an expectation written before the measurement would only be a
    guess dressed as a control. What is asserted is that the observation
    happened at all and that its control held -- without those the cell has
    nothing to say either way.

  * The freestanding confound. -ffreestanding stops the compiler treating memset
    as a builtin, which alone can change the erasure verdict on an unchanged
    target. So no target comparison may be drawn between two cells that differ
    in it. This is checked structurally rather than by value.

Exit codes follow interfaces.md section 7: 0 clean, 2 a graded expectation was
not met, 3 the envelope was missing or had nothing in it.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ENVELOPE = os.environ.get(
    "IRCK_ENVELOPE_JSON",
    os.path.join(HERE, "..", "_results", "envelope", "envelope.json"))

# The apparatus verdict, not the property state. build-envelope.py writes
# state=NOT_OBSERVED for both of the failure words and carries the reason in
# "measurement", because interfaces.md section 3 fixes the property states and
# neither of these is a claim about the property. The three words and the rule
# that pairs them with "state" are interfaces.md section 3.1; these are its
# bindings, named rather than spelled at each use so that this file and
# build-envelope.py and compiler/envelope/fragility.mjs can be checked against
# each other and against the section.
MEASUREMENT_OK = "OK"
MEASUREMENT_UNSUPPORTED = "UNSUPPORTED"
MEASUREMENT_BROKEN = "BROKEN_MEASUREMENT"
MEASUREMENT_STATES = (MEASUREMENT_OK, MEASUREMENT_UNSUPPORTED, MEASUREMENT_BROKEN)
STATE_NOT_OBSERVED = "NOT_OBSERVED"

# The words that mean no reading came back. Derived from the vocabulary rather
# than listed again, so a word added to section 3.1 cannot be added to the
# vocabulary here and forgotten here.
BROKEN = tuple(m for m in MEASUREMENT_STATES if m != MEASUREMENT_OK)


def meas(c):
    """interfaces.md section 3.1: a cell without the column reads OK. The other
    two columns already carry the apparatus claim on such a cell, and the checks
    below read those too, so the default cannot let an unmeasured cell grade."""
    return c.get("measurement", MEASUREMENT_OK)


def key(c):
    g = c["config"]
    return (c["subject"], g["opt"], g["ndebug"], g["lto"], g["target"],
            g["freestanding"], c.get("control", "-"))


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + "/" + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + "/%d" % i)
    elif isinstance(obj, str):
        yield path, obj


def main():
    if not os.path.exists(ENVELOPE):
        print("no envelope at %s" % ENVELOPE, file=sys.stderr)
        return 3
    with open(ENVELOPE, "r", encoding="utf-8") as fh:
        env = json.load(fh)
    cells = env.get("cells", [])
    if not cells:
        print("the envelope has no cells", file=sys.stderr)
        return 3

    problems = []
    by = {key(c): c for c in cells}

    def find(subject, opt, ndebug=False, lto="none", target="host",
             freestanding=False, tag="-"):
        return by.get((subject, opt, ndebug, lto, target, freestanding, tag))

    # --- format rules ---------------------------------------------------------
    for p, s in walk_strings(env):
        if s.startswith("/") or "/root/" in s or "/home/" in s or ":\\" in s:
            problems.append("absolute path at %s: %r" % (p, s[:120]))

    # --- one plugin measured the whole envelope -------------------------------
    shas = {c["pluginSha256"] for c in cells if c["handshake"]["recordWritten"]}
    if len(shas) > 1:
        problems.append("cells that produced a record were measured by %d different "
                        "plugin builds (%s); readings from different observers cannot "
                        "be compared" % (len(shas), sorted(shas)))

    # --- the two label columns say what section 3.1 says they say -------------
    # Checked before anything reads them. Every rule below branches on `meas(c)`
    # or on `c["state"]`, so a cell whose labels are outside the vocabulary, or
    # whose pair is impossible, is one whose grading is meaningless rather than
    # merely wrong -- a measurement=BROKEN_MEASUREMENT cell carrying state=PRESENT
    # would be counted as a graded survival by the canary below.
    for c in cells:
        m = meas(c)
        if m not in MEASUREMENT_STATES:
            problems.append("%s: measurement %r is not one of interfaces.md section "
                            "3.1's %s. An unrecognised label is refused, not bucketed: "
                            "every rule in this file branches on it."
                            % (c["cellId"], m, "/".join(MEASUREMENT_STATES)))
        elif m != MEASUREMENT_OK and c["state"] != STATE_NOT_OBSERVED:
            problems.append("%s: measurement=%s with state=%s. Section 3.1 pairs a "
                            "cell that produced no reading with state=%s -- any other "
                            "state here is a verdict invented for a measurement that "
                            "did not happen."
                            % (c["cellId"], m, c["state"], STATE_NOT_OBSERVED))

    # --- a declared outcome must be falsifiable in both directions ------------
    for c in cells:
        broken = meas(c) in BROKEN
        if c["expectedBroken"] and not broken:
            problems.append("%s: declared broken (%s) and it was not; the declaration "
                            "was hiding a cell that works" %
                            (c["cellId"], c["expectedBrokenReason"] or "no reason given"))
        if broken and not c["expectedBroken"]:
            problems.append("%s: %s -- %s" % (c["cellId"], meas(c), c["reason"]))
        if not broken and not c["handshake"]["ok"]:
            problems.append("%s: graded with no handshake; the record is invalid before "
                            "its verdict is read (%s)" % (c["cellId"], c["handshake"]))
        if not broken and c["controlHeld"] is not True:
            # VG-INJ-001 is a false positive on the next line and the suppression
            # is recorded rather than dodged by rewording. Its pattern is a quoted
            # run containing FROM/INTO/UPDATE followed by a word, then `" %` — which
            # is what a `%`-formatted English sentence ending in "from an oracle"
            # looks like. There is no SQL in this file and no database to reach.
            problems.append("%s: the control did not hold, so this cell cannot tell a "
                            "removed property from an oracle that stopped working"  # vibeguard:disable-line VG-INJ-001
                            % c["cellId"])

    # --- the envelope's own positive controls ---------------------------------
    pce1 = find("erasure", "-O2", tag="pce1-plugin-absent")
    if pce1 is None:
        problems.append("pce1 (plugin absent) did not run; nothing shows an unloadable "
                        "observer is noticed")
    elif not (meas(pce1) == MEASUREMENT_UNSUPPORTED and pce1["rc"] == 1):
        problems.append("pce1: measurement %s rc %s, expected %s with rc 1" %
                        (meas(pce1), pce1["rc"], MEASUREMENT_UNSUPPORTED))

    pce2 = find("erasure", "-O2", tag="pce2-observer-unregistered")
    if pce2 is None:
        problems.append("pce2 (observer unregistered) did not run; nothing shows the "
                        "silent no-observation mode is noticed")
    elif not (meas(pce2) == MEASUREMENT_BROKEN and pce2["rc"] == 3):
        problems.append("pce2: measurement %s rc %s, expected %s with rc 3 -- "
                        "the compiler exits 0 in this mode, so a cell that reads clean "
                        "here is reading an unexamined build as examined" %
                        (meas(pce2), pce2["rc"], MEASUREMENT_BROKEN))

    # --- the optimisation canary ---------------------------------------------
    for opt in ("-O2", "-O3"):
        c = find("erasure", opt)
        if c is None:
            problems.append("erasure %s is not in the envelope; the canary that shows "
                            "the observer is alive is missing" % opt)
        elif c["state"] != "LOST" or c["firstZeroPass"] != "DSEPass":
            problems.append("erasure %s: %s / first-zero %r, expected LOST / 'DSEPass'. "
                            "This cell is the canary: without it a table of PRESENT "
                            "proves only that nothing was measured." %
                            (opt, c["state"], c["firstZeroPass"]))
    c = find("erasure", "-O0")
    if c is not None and c["state"] != "PRESENT":
        problems.append("erasure -O0: %s, expected PRESENT" % c["state"])

    graded = [c for c in cells if meas(c) not in BROKEN]
    if graded and not any(c["state"] == "LOST" for c in graded):
        problems.append("no cell in the whole envelope reads LOST; a matrix in which "
                        "nothing is ever removed is a measurement that is not running")

    # --- the NDEBUG axis ------------------------------------------------------
    for opt in ("-O0", "-O1", "-O2", "-O3"):
        off = find("ndebug-guard", opt, ndebug=False)
        on = find("ndebug-guard", opt, ndebug=True)
        if off is None or on is None:
            problems.append("ndebug-guard %s: the NDEBUG pair is incomplete" % opt)
            continue
        if off["state"] != "PRESENT":
            problems.append("ndebug-guard %s NDEBUG off: %s, expected PRESENT -- the "
                            "guard's condition comes from another unit and the call it "
                            "guards cannot be removed" % (opt, off["state"]))
        if on["state"] != "ABSENT":
            problems.append("ndebug-guard %s NDEBUG on: %s, expected ABSENT -- with "
                            "NDEBUG defined the deny path is not in the preprocessed "
                            "source, so the property is never established" %
                            (opt, on["state"]))
        if off["state"] == on["state"]:
            problems.append("ndebug-guard %s: NDEBUG changed nothing (%s both ways); "
                            "the configuration axis is inert" % (opt, off["state"]))

    # --- the NDEBUG axis, negatively -----------------------------------------
    for subj in ("erasure", "authz-live", "authz-folded"):
        for opt in ("-O0", "-O1", "-O2", "-O3"):
            off, on = find(subj, opt, ndebug=False), find(subj, opt, ndebug=True)
            if off is None or on is None:
                continue
            if off["state"] != on["state"]:
                problems.append("%s %s: -DNDEBUG changed the verdict %s -> %s in a "
                                "fixture that consults no macro, so the axis is moving "
                                "something other than what it names" %
                                (subj, opt, off["state"], on["state"]))

    # --- the LTO axis ---------------------------------------------------------
    for subj in ("erasure", "authz-folded", "ndebug-guard"):
        for opt in ("-O0", "-O2"):
            for lto in ("full-prelink", "thin-prelink"):
                c = find(subj, opt, lto=lto)
                if c is None:
                    problems.append("%s %s %s: missing" % (subj, opt, lto))
                elif not c["handshake"]["ok"]:
                    problems.append("%s %s %s: no handshake. A pre-link LTO compile "
                                    "still runs an optimisation pipeline, so it is "
                                    "observable or the observer has stopped working." %
                                    (subj, opt, lto))
            for lto in ("full-backend", "thin-backend"):
                c = find(subj, opt, lto=lto)
                if c is None:
                    problems.append("%s %s %s: missing" % (subj, opt, lto))
                elif c["handshake"]["ok"] and c["handshake"]["moduleId"] != "ld-temp.o":
                    problems.append("%s %s %s: a link-stage cell reported module %r; "
                                    "that is a pre-link reading under a backend label" %
                                    (subj, opt, lto, c["handshake"]["moduleId"]))

    # --- the target axis, and the confound that would spoil it ---------------
    # A cross-target cell is only worth reading next to a native cell that
    # differs in nothing else. -ffreestanding alone changes the erasure verdict
    # on an unchanged target, so a comparison drawn across it would be reporting
    # a flag as a processor. Requiring the twin to exist is the check; asserting
    # what the twin says would be a guess, because whether a property survives
    # differently elsewhere is what this axis is for.
    for c in cells:
        g = c["config"]
        if g["target"] == "host" or c.get("control", "-") != "-":
            continue
        twin = find(c["subject"], g["opt"], ndebug=g["ndebug"], lto=g["lto"],
                    target="host", freestanding=g["freestanding"])
        if twin is None:
            problems.append("%s: no host cell matches it on opt/ndebug/lto/"
                            "freestanding, so any target claim drawn from this cell "
                            "would cross a second axis" % c["cellId"])
        if meas(c) not in BROKEN and not c["handshake"]["ok"]:
            problems.append("%s: cross-target cell with no handshake" % c["cellId"])

    # Same rule for the confound's own axis: a -ffreestanding cell that has no
    # -ffreestanding-off counterpart is not holding a confound, it is one.
    for c in cells:
        g = c["config"]
        if not g["freestanding"] or c.get("control", "-") != "-":
            continue
        twin = find(c["subject"], g["opt"], ndebug=g["ndebug"], lto=g["lto"],
                    target=g["target"], freestanding=False)
        if twin is None:
            problems.append("%s: -ffreestanding is on and no otherwise identical cell "
                            "has it off, so its effect cannot be separated from "
                            "anything else this cell varies" % c["cellId"])

    # --- print ----------------------------------------------------------------
    fmt = "%-13s %-4s %-7s %-13s %-17s %-5s %-19s %-11s %-3s %-12s %s"
    hdr = fmt % ("subject", "opt", "ndebug", "lto", "target", "free", "state",
                 "first-zero", "hs", "findings", "control")
    print(hdr)
    print("-" * len(hdr))
    for c in sorted(cells, key=lambda c: c["cellId"]):
        g = c["config"]
        print(fmt % (c["subject"], g["opt"], "on" if g["ndebug"] else "off", g["lto"],
                     g["target"], "on" if g["freestanding"] else "off", c["state"],
                     c["firstZeroPass"] or "-", "ok" if c["handshake"]["ok"] else "NO",
                     ",".join(c["findings"]) or "-", c.get("control", "-")))

    n = env["counts"]
    print("\n%d cells: %d graded, %d unsupported, %d broken-measurement, "
          "%d with a handshake" %
          (n["cells"], n["graded"], n["unsupported"], n["brokenMeasurement"],
           n["handshakeOk"]))

    if problems:
        print("\n%d disagreement(s):" % len(problems), file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 2

    print("\nall %d cells agree with the expectations in this file." % len(cells))
    return 0


if __name__ == "__main__":
    sys.exit(main())
