#!/usr/bin/env python3
"""Grade the records run-dual-channel.sh produced.

The expectations below were written from what each fixture is for, before the
records existed. A cell that disagrees is printed as a disagreement -- this file
is not edited to make a run pass.

What is graded, beyond the per-cell table:

  * the dual-channel vocabulary is disjoint from the six states of
    interfaces.md section 3. The whole reason the metadata channel needed its
    own words is that "the annotation went" must not be spelled `LOST`, and a
    grep is not a guarantee once the code can emit strings;
  * `verdict.state` is still the structural channel's answer. The metadata
    channel is a second reading, not a second vote, so a cell where the
    annotation went and the effect did not must still read `PRESENT`;
  * the two channels really do disagree somewhere. If every cell reads
    BOTH_CHANNELS_SURVIVED, the pair is inert and proves nothing -- so the run
    fails when no cell shows a channel going without the other;
  * every record re-digests to the value it carries, recomputed here
    independently of the C++ that wrote it, and the digest check is then shown
    to be able to fail.

Exit codes follow interfaces.md section 7: 0 clean, 2 a graded expectation was
not met, 3 a record was missing or unreadable.
"""

import hashlib
import json
import os
import sys

LAB = os.environ.get("IRCK_DUAL_LAB", os.path.expanduser("~/vg-lab/llvm-pass-dual"))
RECORDS = os.path.join(LAB, "records")

# The six states of interfaces.md section 3. The dual-channel vocabulary must
# not intersect this set.
STRUCTURAL_WORDS = {
    "PRESENT", "ABSENT", "LOST", "REINTRODUCED", "NOT_APPLICABLE", "NOT_OBSERVED",
}

DUAL_WORDS = {
    "CHANNELS_NOT_OBSERVED",
    "ANNOTATION_NOT_DECLARED",
    "EFFECT_NOT_ESTABLISHED",
    "BOTH_CHANNELS_SURVIVED",
    "ANNOTATION_ERASED_EFFECT_SURVIVED",
    "ANNOTATION_SURVIVED_EFFECT_ERASED",
    "BOTH_CHANNELS_ERASED",
    "SUBJECT_UNIT_ABSENT_AT_POST",
}

# Keys:
#   unit        dualChannel.unitScope.state
#   verdict     verdict.state -- checked to prove the metadata channel did not
#               reach into the structural one
#   metaCtl     dualChannel.metadata.control.held
#   carrier     dualChannel.metadata.module.preOptIr.carrierPresent
#   metaTraj    (metadataPreOpt, metadataPostOpt) at unit scope
#   effTraj     (structuralPreOpt, structuralPostOpt) at unit scope
EXPECT = {
    # -- subject A: the annotation is deleted with the block it lives in, the
    #    wipe on the live path is not. The headline case.
    "dual-red-O0": dict(unit="BOTH_CHANNELS_SURVIVED", verdict="PRESENT",
                        metaCtl=True, carrier=True),
    "dual-red-O1": dict(unit="ANNOTATION_ERASED_EFFECT_SURVIVED", verdict="PRESENT",
                        metaCtl=True, carrier=True, metaTraj=(1, 0)),
    "dual-red-O2": dict(unit="ANNOTATION_ERASED_EFFECT_SURVIVED", verdict="PRESENT",
                        metaCtl=True, carrier=True, metaTraj=(1, 0)),
    "dual-red-O3": dict(unit="ANNOTATION_ERASED_EFFECT_SURVIVED", verdict="PRESENT",
                        metaCtl=True, carrier=True, metaTraj=(1, 0)),

    # -- subject B: neither channel loses anything. Without this cell the run
    #    could not tell "the optimiser removed the annotation" from "the reader
    #    never finds an annotation".
    "dual-both-survive-O0": dict(unit="BOTH_CHANNELS_SURVIVED", verdict="PRESENT",
                                 metaCtl=True, carrier=True),
    "dual-both-survive-O2": dict(unit="BOTH_CHANNELS_SURVIVED", verdict="PRESENT",
                                 metaCtl=True, carrier=True),

    # -- subject C: the declaration outlives the processing it declared.
    "dual-metadata-lies-O0": dict(unit="BOTH_CHANNELS_SURVIVED", verdict="PRESENT",
                                  metaCtl=True, carrier=True),
    "dual-metadata-lies-O2": dict(unit="ANNOTATION_SURVIVED_EFFECT_ERASED",
                                  verdict="LOST", metaCtl=True, carrier=True,
                                  effTraj=(1, 0)),

    # -- subject D: both go.
    "dual-both-erased-O0": dict(unit="BOTH_CHANNELS_SURVIVED", verdict="PRESENT",
                                metaCtl=True, carrier=True),
    "dual-both-erased-O2": dict(unit="BOTH_CHANNELS_ERASED", verdict="LOST",
                                metaCtl=True, carrier=True),

    # -- the metadata channel pointed at a vocabulary nothing carries. It must
    #    report that it measured nothing, never that something was erased. This
    #    is the metadata channel's pc4: a reader pointed at the wrong string
    #    reads every unit as undeclared, and the state has to say so.
    "dual-wrong-prefix-O2": dict(unit="ANNOTATION_NOT_DECLARED", verdict="PRESENT",
                                 metaCtl=False, carrier=True, metaTraj=(0, 0)),

    # -- the same program with the annotations taken out of the source. The
    #    carrier is absent from the module entirely, which is a different fact
    #    from "the prefix did not match" and is recorded separately.
    "dual-no-annotation-O2": dict(unit="ANNOTATION_NOT_DECLARED", verdict="PRESENT",
                                  metaCtl=False, carrier=False, metaTraj=(0, 0)),
}

# Cells whose point is that the metadata control does not hold.
META_CONTROL_MAY_FAIL = {"dual-wrong-prefix-O2", "dual-no-annotation-O2"}


def canonical(obj):
    """interfaces.md section 5, reimplemented here so the digest is checked by
    something other than the code that produced it."""
    if isinstance(obj, float):
        raise ValueError("a record carried a non-integer number")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def recompute_digest(record):
    stripped = {k: v for k, v in record.items()
                if k not in ("context", "evidenceDigest")}
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


def main():
    problems = []
    missing = []
    rows = []
    seen_states = set()

    for cell, exp in EXPECT.items():
        path = os.path.join(RECORDS, cell + ".json")
        if not os.path.exists(path):
            missing.append(cell)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)

        def bad(msg):
            problems.append("%s: %s" % (cell, msg))

        if "dualChannel" not in rec:
            bad("the record carries no dualChannel block; the metadata channel "
                "did not run")
            continue

        got = recompute_digest(rec)
        if got != rec.get("evidenceDigest"):
            bad("evidenceDigest %s but recomputed %s" % (rec.get("evidenceDigest"), got))
        for p, s in walk_strings(rec):
            if s.startswith("/") or "/mnt/" in s or "/root/" in s or ":\\" in s:
                bad("absolute path at %s: %r" % (p, s))

        dc = rec["dualChannel"]
        unit = dc["unitScope"]
        mod = dc["moduleScope"]
        meta = dc["metadata"]
        state = rec["verdict"]["state"]

        seen_states.add(unit["state"])

        for scope_name, scope in (("unitScope", unit), ("moduleScope", mod)):
            if scope["state"] not in DUAL_WORDS:
                bad("%s.state %r is not in the dual-channel vocabulary"
                    % (scope_name, scope["state"]))
            if scope["state"] in STRUCTURAL_WORDS:
                bad("%s.state %r is one of the six structural words; the two "
                    "vocabularies have collided" % (scope_name, scope["state"]))

        if "unit" in exp and unit["state"] != exp["unit"]:
            bad("unitScope.state %s, expected %s" % (unit["state"], exp["unit"]))
        if "verdict" in exp and state != exp["verdict"]:
            bad("verdict.state %s, expected %s -- the structural verdict must be "
                "unchanged by the metadata channel" % (state, exp["verdict"]))
        if "metaCtl" in exp and meta["control"]["held"] != exp["metaCtl"]:
            bad("metadata.control.held %s, expected %s"
                % (meta["control"]["held"], exp["metaCtl"]))
        if "carrier" in exp and meta["module"]["preOptIr"]["carrierPresent"] != exp["carrier"]:
            bad("metadata.module.preOptIr.carrierPresent %s, expected %s"
                % (meta["module"]["preOptIr"]["carrierPresent"], exp["carrier"]))
        if "metaTraj" in exp:
            got_traj = (unit["metadataPreOpt"], unit["metadataPostOpt"])
            if got_traj != exp["metaTraj"]:
                bad("metadata trajectory %s, expected %s" % (got_traj, exp["metaTraj"]))
        if "effTraj" in exp:
            got_traj = (unit["structuralPreOpt"], unit["structuralPostOpt"])
            if got_traj != exp["effTraj"]:
                bad("structural trajectory %s, expected %s" % (got_traj, exp["effTraj"]))

        if cell not in META_CONTROL_MAY_FAIL and not meta["control"]["held"]:
            bad("the metadata channel's control did not hold, so this cell "
                "cannot tell an erased annotation from a reader that stopped "
                "finding annotations")

        # The claim the headline state makes, checked against the numbers in the
        # same record rather than taken from the state name.
        if unit["state"] == "ANNOTATION_ERASED_EFFECT_SURVIVED":
            if not (unit["metadataPreOpt"] > 0 and unit["metadataPostOpt"] == 0):
                bad("state says the annotation was erased but the metadata "
                    "trajectory is %d -> %d"
                    % (unit["metadataPreOpt"], unit["metadataPostOpt"]))
            if unit["structuralPostOpt"] <= 0:
                bad("state says the effect survived but the structural count is %d"
                    % unit["structuralPostOpt"])
            if state == "LOST":
                bad("verdict.state is LOST for a cell where the effect survived; "
                    "the metadata channel's absence has been read as a lost "
                    "property")

        rows.append((cell, unit["state"], mod["state"], state,
                     "%d->%d" % (unit["metadataPreOpt"], unit["metadataPostOpt"]),
                     "%d->%d" % (unit["structuralPreOpt"], unit["structuralPostOpt"]),
                     str(meta["control"]["held"])))

    # --- cross-cell claims that no single record can make --------------------
    def load(c):
        with open(os.path.join(RECORDS, c + ".json"), encoding="utf-8") as fh:
            return json.load(fh)

    def have(*cs):
        return all(os.path.exists(os.path.join(RECORDS, c + ".json")) for c in cs)

    # A pair of channels that never disagree is one channel with extra steps.
    disagreements = {"ANNOTATION_ERASED_EFFECT_SURVIVED",
                     "ANNOTATION_SURVIVED_EFFECT_ERASED"}
    if rows and not (seen_states & disagreements):
        problems.append("no cell showed the two channels disagreeing; the pair is "
                        "inert and this run demonstrates nothing that one channel "
                        "would not have shown")

    # The same source at -O0 and at -O2. If the -O0 cell does not show the
    # annotation present, the -O2 cell is not showing it being removed.
    if have("dual-red-O0", "dual-red-O2"):
        a, b = load("dual-red-O0"), load("dual-red-O2")
        if a["dualChannel"]["unitScope"]["metadataPostOpt"] < 1:
            problems.append("dual-red-O0: the annotation is already absent at -O0, so "
                            "the -O2 cell is not showing the optimiser removing it")
        if a["dualChannel"]["unitScope"]["state"] == b["dualChannel"]["unitScope"]["state"]:
            problems.append("dual-red: -O0 and -O2 reached the same dual state %s; the "
                            "cell no longer shows a change"
                            % a["dualChannel"]["unitScope"]["state"])

    # The wrong-prefix cell is the same compilation as dual-red-O2. If it read
    # the same, the prefix is not being consulted and the metadata channel is
    # not configurable -- which would make the "wrong vocabulary" control inert.
    if have("dual-red-O2", "dual-wrong-prefix-O2"):
        a, b = load("dual-red-O2"), load("dual-wrong-prefix-O2")
        if a["dualChannel"]["unitScope"]["metadataPreOpt"] == \
           b["dualChannel"]["unitScope"]["metadataPreOpt"]:
            problems.append("dual-wrong-prefix-O2: pointing the metadata channel at a "
                            "vocabulary nothing carries did not change what it counted; "
                            "the prefix is inert")
        if a["verdict"]["state"] != b["verdict"]["state"]:
            problems.append("dual-wrong-prefix-O2: changing only the annotation prefix "
                            "changed verdict.state from %s to %s; the metadata channel "
                            "is reaching into the structural verdict"
                            % (a["verdict"]["state"], b["verdict"]["state"]))

    # Same again for the annotation-free source: the structural channel must not
    # notice that the annotations are gone.
    if have("dual-red-O2", "dual-no-annotation-O2"):
        a, b = load("dual-red-O2"), load("dual-no-annotation-O2")
        if a["verdict"]["state"] != b["verdict"]["state"]:
            problems.append("dual-no-annotation-O2: removing the annotations from the "
                            "source changed verdict.state from %s to %s; the structural "
                            "channel is reading the metadata"
                            % (a["verdict"]["state"], b["verdict"]["state"]))

    # --- the digest check must itself be able to fail ------------------------
    if have("dual-red-O2"):
        r = load("dual-red-O2")
        r["dualChannel"]["unitScope"]["state"] = "BOTH_CHANNELS_SURVIVED"
        if recompute_digest(r) == r["evidenceDigest"]:
            problems.append("the digest did not change when the dual-channel state was "
                            "altered; the dual-channel block is outside the digest and "
                            "can be edited without trace")

    hdr = ("cell", "unit scope", "module scope", "verdict", "meta", "struct", "metaCtl")
    print("%-24s %-34s %-24s %-9s %-7s %-7s %s" % hdr)
    for row in rows:
        print("%-24s %-34s %-24s %-9s %-7s %-7s %s" % row)

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
