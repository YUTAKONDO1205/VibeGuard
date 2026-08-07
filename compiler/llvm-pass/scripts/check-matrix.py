#!/usr/bin/env python3
"""Grade the records run-matrix.sh produced.

The expectations below were written from what the fixtures are for, not
transcribed from a run. A cell that disagrees is printed as a disagreement --
this file is not edited to make a run pass.

Three things are checked for every record regardless of the cell:

  * the record re-digests to the value it carries, under the canonicalisation in
    compiler/schema/interfaces.md section 5, recomputed here independently of
    the C++ that wrote it;
  * no absolute path appears anywhere in it;
  * the control unit's effect count never reached zero -- except in the cells
    whose whole purpose is that it does.

Exit codes follow interfaces.md section 7: 0 clean, 2 a graded expectation was
not met, 3 a record was missing or unreadable.
"""

import hashlib
import json
import os
import sys

LAB = os.environ.get("IRCK_LAB", os.path.expanduser("~/vg-lab/llvm-pass"))
RECORDS = os.path.join(LAB, "records")

# cell -> checks. Keys:
#   state          verdict.state
#   control        control.held
#   completes      verdict.completesTheCheck
#   firstZeroPass  firstZeroTransition.pass
#   reasonHas      substring of verdict.reason
#   findings       exact list of finding ids
#   also           list of (jsonpath-ish tuple, predicate, description)
EXPECT = {
    # Secure erasure. The wipe is a dead store above -O1; the control's is not.
    "erasure-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    # -O1 keeps the call in IR. The prototype workspace attributes the -O1 loss
    # to the backend, which is downstream of every checkpoint this component
    # has, so PRESENT here is a statement about scope, not a disagreement.
    "erasure-O1": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "erasure-O2": dict(state="LOST", control=True, completes=True,
                       firstZeroPass="DSEPass", findings=["VG-PROP-001"]),
    "erasure-O3": dict(state="LOST", control=True, completes=True,
                       firstZeroPass="DSEPass", findings=["VG-PROP-001"]),

    # Identical source, one -D apart, identical 1 -> 0 count trajectory.
    "promotion-escape-off-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "promotion-escape-off-O2": dict(state="NOT_APPLICABLE", control=True, completes=False,
                                    reasonHas="memory-object-promoted", findings=[]),
    "promotion-escape-on-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "promotion-escape-on-O2": dict(state="LOST", control=True, completes=True,
                                   firstZeroPass="DSEPass", findings=["VG-PROP-001"]),

    # The subject is promoted while an unrelated object of the same size
    # survives. NOT_APPLICABLE is the true answer; a size-matching
    # discriminator says LOST, which is a finding about a program that has no
    # buffer to clear.
    "promotion-decoy-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "promotion-decoy-O2": dict(state="NOT_APPLICABLE", control=True,
                               reasonHas="memory-object-promoted", findings=[]),

    # The unit itself disappears.
    "inlined-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "inlined-O2": dict(state="NOT_APPLICABLE", control=True, completes=False,
                       reasonHas="unit-absent", findings=[]),

    # Same inlining, removable wipe. The effect does not survive the body, so
    # the honest verdict is LOST -- not the NOT_APPLICABLE that unit presence
    # alone would give it. If this cell ever reads NOT_APPLICABLE again, the
    # discrimination has collapsed back into "did the function survive".
    "inlined-removable-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "inlined-removable-O2": dict(state="LOST", control=True,
                                 reasonHas="unit-absent-effect-gone",
                                 findings=["VG-PROP-001"]),

    # A deleted call leaves its declaration behind.
    "residue-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "residue-O2": dict(state="LOST", control=True, completes=True,
                       firstZeroPass="DSEPass", findings=["VG-PROP-001"]),

    # Fail-closed branch.
    "authz-live-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "authz-live-O2": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "authz-folded-O0": dict(state="PRESENT", control=True, completes=True, findings=[]),
    "authz-folded-O2": dict(state="LOST", control=True, completes=True, findings=["VG-PROP-001"]),

    # Forbidden callee. Opposite polarity: PRESENT is the finding, and the
    # control is a unit where the forbidden call is certainly still there, which
    # is what shows the extractor can still see one at this optimisation level.
    "notappear-O0": dict(state="PRESENT", control=True, completes=True, findings=["VG-PROP-002"]),
    "notappear-O2": dict(state="LOST", control=True, completes=True, findings=[]),

    # --- positive controls --------------------------------------------------
    "pc1-no-discriminator-O2": dict(state="LOST", control=True, completes=True,
                                    firstZeroPass="SROAPass", findings=["VG-PROP-001"]),
    "pc2-broken-control-O2": dict(control=False, completes=False, findings=["VG-PROP-003"]),
    "pc3-missing-subject-O2": dict(state="NOT_OBSERVED", completes=False),
    "pc4-wrong-symbol-O2": dict(state="ABSENT", control=False, completes=False,
                                findings=["VG-PROP-003"]),
}

# Cells whose point is that the control does not hold.
CONTROL_MAY_FAIL = {"pc2-broken-control-O2", "pc3-missing-subject-O2", "pc4-wrong-symbol-O2"}


def canonical(obj):
    """interfaces.md section 5, reimplemented here so the digest is checked by
    something other than the code that produced it."""
    if isinstance(obj, float):
        raise ValueError("a record carried a non-integer number")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def recompute_digest(record):
    stripped = {k: v for k, v in record.items() if k not in ("context", "evidenceDigest")}
    return hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + "/" + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + "/%d" % i)
    elif isinstance(obj, str):
        yield path, obj


def walk_numbers(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from walk_numbers(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_numbers(v)
    elif isinstance(obj, bool):
        return
    elif isinstance(obj, (int, float)):
        yield obj


def main():
    problems = []
    missing = []
    rows = []

    for cell, exp in EXPECT.items():
        path = os.path.join(RECORDS, cell + ".json")
        if not os.path.exists(path):
            missing.append(cell)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)

        def bad(msg):
            problems.append("%s: %s" % (cell, msg))

        # --- format rules, every record -------------------------------------
        got = recompute_digest(rec)
        if got != rec.get("evidenceDigest"):
            bad("evidenceDigest %s but recomputed %s" % (rec.get("evidenceDigest"), got))
        for n in walk_numbers(rec):
            if isinstance(n, float):
                bad("non-integer number %r in the record" % n)
        for p, s in walk_strings(rec):
            if s.startswith("/") or "/mnt/" in s or "/root/" in s or ":\\" in s:
                bad("absolute path at %s: %r" % (p, s))

        state = rec["verdict"]["state"]
        held = rec["control"]["held"]
        completes = rec["verdict"]["completesTheCheck"]
        fz = rec["firstZeroTransition"]["pass"]
        fids = [f["id"] for f in rec["findings"]]

        if cell not in CONTROL_MAY_FAIL and not held:
            bad("the control did not hold: min effect %d" % rec["control"]["minEffectObserved"])

        if "state" in exp and state != exp["state"]:
            bad("state %s, expected %s" % (state, exp["state"]))
        if "control" in exp and held != exp["control"]:
            bad("control.held %s, expected %s" % (held, exp["control"]))
        if "completes" in exp and completes != exp["completes"]:
            bad("completesTheCheck %s, expected %s" % (completes, exp["completes"]))
        if "firstZeroPass" in exp and fz != exp["firstZeroPass"]:
            bad("firstZeroTransition.pass %r, expected %r" % (fz, exp["firstZeroPass"]))
        if "reasonHas" in exp and exp["reasonHas"] not in rec["verdict"]["reason"]:
            bad("reason %r does not mention %r" % (rec["verdict"]["reason"], exp["reasonHas"]))
        if "findings" in exp and sorted(fids) != sorted(exp["findings"]):
            bad("findings %s, expected %s" % (fids, exp["findings"]))

        rows.append((cell, state, held, completes, fz or "-", ",".join(fids) or "-"))

    # --- cross-cell claims that no single record can make --------------------
    def load(c):
        with open(os.path.join(RECORDS, c + ".json"), encoding="utf-8") as fh:
            return json.load(fh)

    def have(*cs):
        return all(os.path.exists(os.path.join(RECORDS, c + ".json")) for c in cs)

    if have("promotion-escape-off-O2", "promotion-escape-on-O2"):
        off, on = load("promotion-escape-off-O2"), load("promotion-escape-on-O2")
        for r, n in ((off, "escape-off"), (on, "escape-on")):
            if (r["subject"]["preOptIr"]["effect"], r["subject"]["postOptIr"]["effect"]) != (1, 0):
                problems.append("promotion %s: effect trajectory %d -> %d, expected 1 -> 0; the "
                                "two cells no longer share a trajectory, so their differing "
                                "verdicts no longer prove anything" %
                                (n, r["subject"]["preOptIr"]["effect"],
                                 r["subject"]["postOptIr"]["effect"]))
        if off["verdict"]["state"] == on["verdict"]["state"]:
            problems.append("promotion: escape-off and escape-on reached the same verdict %s; "
                            "the discriminator is not looking at the escape" %
                            off["verdict"]["state"])
        if off["subject"]["preOptIr"]["allocasEscapingToOpaqueCall"] != 0:
            problems.append("promotion escape-off: the buffer was recorded as escaping")
        if on["subject"]["preOptIr"]["allocasEscapingToOpaqueCall"] != 1:
            problems.append("promotion escape-on: the buffer was not recorded as escaping")

    if have("promotion-escape-off-O2", "pc1-no-discriminator-O2"):
        a, b = load("promotion-escape-off-O2"), load("pc1-no-discriminator-O2")
        if not (a["verdict"]["state"] == "NOT_APPLICABLE" and b["verdict"]["state"] == "LOST"):
            problems.append("pc1: turning the memory-object discriminator off did not change the "
                            "verdict (%s -> %s); the discriminator is inert" %
                            (a["verdict"]["state"], b["verdict"]["state"]))

    if have("inlined-O2"):
        r = load("inlined-O2")
        if r["subject"]["postOptIr"]["effect"] != 0:
            problems.append("inlined-O2: the subject's unit count is not zero")
        if r["naiveOracle"]["moduleWideCallSitesPostOpt"] < 1:
            problems.append("inlined-O2: the module-wide count is zero too, so this cell no longer "
                            "shows the difference between counting in a unit and counting in a "
                            "module")

    if have("residue-O2"):
        # Why the oracle resolves callees. The two oracles are read from the same
        # run, so a difference between them cannot be blamed on the run.
        r = load("residue-O2")
        od = r["oracleDivergence"]
        res = od["declaredButUncalledWhenTheCallLeftTheUnit"]
        if not any(s.startswith("llvm.memset") for s in res):
            problems.append("residue-O2: when the call left the unit, no memset declaration was "
                            "left uncalled (%s), so this cell no longer demonstrates why a name "
                            "lookup is not an oracle" % res)
        if not od["naiveSaidPresentWhenTheCallLeftTheUnit"]:
            problems.append("residue-O2: the name lookup did not say present at the moment the "
                            "call left the unit")
        if r["subject"]["postOptIr"]["effectCallSites"] != 0:
            problems.append("residue-O2: the call-site oracle did not say zero")
        cs = od["callSiteOracle"]["pass"]
        nl = od["nameLookupOracle"]["sweptByPass"]
        if nl is None:
            problems.append("residue-O2: the leftover declaration was never swept inside the "
                            "observed pipeline, so the two oracles cannot be compared here")
        elif cs == nl:
            problems.append("residue-O2: both oracles named %s, so this cell does not show them "
                            "disagreeing" % cs)
        elif od["observationsBetween"] is None or od["observationsBetween"] <= 0:
            problems.append("residue-O2: the name lookup did not lag the call-site oracle "
                            "(observationsBetween=%r)" % od["observationsBetween"])

    # --- the digest check must itself be able to fail ------------------------
    if have("erasure-O2"):
        r = load("erasure-O2")
        r["subjectUnit"] = r["subjectUnit"] + "x"
        if recompute_digest(r) == r["evidenceDigest"]:
            problems.append("the digest did not change when the record was altered; the digest "
                            "check is inert")

    print("%-28s %-15s %-6s %-9s %-14s %s" %
          ("cell", "state", "ctl", "completes", "first-zero", "findings"))
    for row in rows:
        print("%-28s %-15s %-6s %-9s %-14s %s" % row)

    if missing:
        print("\nno record for: %s" % ", ".join(missing), file=sys.stderr)
    if problems:
        print("\n%d disagreement(s):" % len(problems), file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)

    if missing:
        return 3
    if problems:
        return 2
    print("\nall %d cells agree with the expectations in this file." % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
