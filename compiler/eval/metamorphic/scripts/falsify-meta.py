#!/usr/bin/env python3
"""Corrupt a metamorphic report in eight named ways and check that check-meta.py
REFUSES each one, with the exit code interfaces.md section 7 assigns to it.

    python3 compiler/eval/metamorphic/scripts/falsify-meta.py [report.json]

WHY THIS FILE EXISTS

A grader that has never been shown to fail has not been shown to work, and it is
the first thing an adversarial reviewer attacks. Every run of check-meta.py in this
lane so far has exited 0, which is precisely what a grader with its predicates
inverted, its loop never entered, or its return value discarded would also do. So
each corruption below takes a document the grader has just accepted and changes ONE
thing, and the expected exit code is written here from the contract rather than
from a run.

The corruptions are chosen to hit the four things this lane could most plausibly
get wrong while still looking green:

  * an R1 relation that moved -- the invariance half of the lane, which is what
    makes every R2 reading attributable to the mutation rather than to the run
  * a digest that no longer recomputes -- the precondition, which if skipped means
    every invariant below it is being graded on bytes nobody can trust
  * interfaces.md section 3.1's pairing rule -- a state word on a side whose
    instrument did not work, which is a verdict invented for a measurement that did
    not happen
  * a lane-level declared absence deleted -- "we cannot measure this" silently
    becoming "there was never a fourth shape"

and four more that guard the distinctions this lane's vocabulary rests on: an
unreadable cross-vendor comparison relabelled as a split, the last readable
comparison of a shape removed so that nothing in the run witnesses the oracle
working, an R2c cell put on the survival axis, and a float in a document whose
digest is defined over integers.

Each corruption REDIGESTS unless the point of it is the digest, because a
corruption that also breaks the digest would be caught by the precondition and
would prove nothing about the invariant it was aiming at. That is the whole trick
of a falsification harness and it is the easiest part to get wrong.

WHAT THIS IS NOT

Not a control for the measurement, and it grades no compiler. It is a control for
the GRADER. A corruption this harness reports as ACCEPTED is a finding about
check-meta.py and must be fixed there, never by removing the corruption.

Exit codes: 0 every corruption was refused with the expected code. 2 the grader
ACCEPTED a corrupted document, or refused it with the wrong code -- a finding about
the grader. 3 the harness could not run, which is never reported as a pass.
"""

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-meta.py")
LAB = os.environ.get("VG_META_LAB", os.path.expanduser("~/vg-lab/metamorphic"))
REPORTS = os.environ.get("VG_META_OUT", os.path.join(LAB, "_results"))
WORK = os.environ.get("VG_META_FALSIFY", os.path.join(LAB, "_falsify"))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def redigest(doc):
    stripped = {k: v for k, v in doc.items()
                if k not in ("context", "evidenceDigest")}
    doc["evidenceDigest"] = hashlib.sha256(
        canonical(stripped).encode("utf-8")).hexdigest()
    return doc


def first_cell(doc, pred):
    for c in doc["cells"]:
        if pred(c):
            return c
    return None


# --- the corruptions --------------------------------------------------------
#
# Each returns (doc, why-it-does-not-apply). A corruption that cannot be applied to
# this document is SKIPPED and is not counted as a refusal, because a corruption
# nobody applied is not evidence that the grader would have caught it.

def c_r1_state_flipped(doc):
    """An R1 cell whose verdict moved. The transition string is moved with it, so
    the ONLY thing wrong is the invariance -- otherwise the document's own
    arithmetic check would fire and the run would 'pass' for the wrong reason."""
    cell = first_cell(doc, lambda c: c["declaredDirection"] == "INVARIANT"
                      and c["transitionReadable"] and c["graded"])
    if cell is None:
        return None, "no graded readable INVARIANT cell in this document"
    cell["mutant"]["state"] = "LOST"
    cell["transition"] = "%s->LOST" % cell["base"]["state"]
    return redigest(doc), None


def c_digest_staled(doc):
    """A state changed and the digest left alone. The grader must refuse before it
    grades anything: a document that does not hash to the value it carries cannot
    be trusted, and grading it would be 'we did not look' reported as a finding."""
    cell = first_cell(doc, lambda c: c["transitionReadable"])
    if cell is None:
        return None, "no readable cell in this document"
    cell["mutant"]["state"] = "ABSENT"
    return doc, None   # deliberately NOT redigested


def c_pairing_rule_broken(doc):
    """A side whose measurement is not OK carrying a state word, a held control and
    completesTheCheck true. interfaces.md section 3.1 forbids all three, and this
    is the corruption a real BROKEN_MEASUREMENT would look like if the assembler
    forgot the rule."""
    cell = first_cell(doc, lambda c: c["base"]["measurement"] == "OK")
    if cell is None:
        return None, "no cell with an OK base in this document"
    cell["base"]["measurement"] = "BROKEN_MEASUREMENT"
    cell["base"]["brokenReason"] = "introduced by falsify-meta.py"
    # The document is otherwise made self-consistent, so that the pairing rule is
    # the only thing left to catch.
    cell["transitionReadable"] = False
    cell["transition"] = None
    return redigest(doc), None


def c_dominance_lane_deleted(doc):
    """The declared absence removed. A document over three shapes reads as a
    document about an instrument that has three shapes, and the fourth stops being
    something nothing can measure and becomes something nobody mentioned."""
    before = len(doc["lanes"])
    doc["lanes"] = [l for l in doc["lanes"] if l.get("laneId") != "dominance"]
    if len(doc["lanes"]) == before:
        return None, "this document has no dominance lane to delete"
    return redigest(doc), None


def c_unreadable_folded_into_split(doc):
    """An unreadable comparison relabelled as a split, with the tally moved to
    match so that nothing but the word itself is inconsistent. This is the exact
    fold frontier-match.mjs refuses: 'the two differ' and 'I could not look' send a
    reader to two different places and only one of them is a finding."""
    cross = doc.get("crossVendor") or {}
    rows = [r for r in cross.get("comparisons") or []
            if r.get("agreement") == "vendor-unreadable"]
    if not rows:
        return None, "no vendor-unreadable comparison in this document"
    rows[0]["agreement"] = "vendors-split"
    rows[0]["unreadableSide"] = None
    cross["tally"]["vendor-unreadable"] -= 1
    cross["tally"]["vendors-split"] += 1
    return redigest(doc), None


def c_r2c_put_on_survival_axis(doc):
    """An R2c cell marked as graded on the survival axis. Its edge ends on
    NOT_APPLICABLE, which is off the axis, and putting it on would report a lost
    referent as a lost property -- in the direction that looks like a result."""
    cell = first_cell(doc, lambda c: c["declaredDirection"].endswith("NOT_APPLICABLE"))
    if cell is None:
        return None, "no R2c cell in this document"
    cell["survivalAxisGraded"] = True
    return redigest(doc), None


def c_witness_removed(doc):
    """The last readable comparison of a shape that already has an unreadable one,
    made unreadable too. The document is left self-consistent -- the agreement word
    and the tally are moved with it -- so the only thing wrong is that nothing in
    the run now shows the oracle can read that shape at all, and 'I could not look'
    has become indistinguishable from 'this oracle cannot read this shape'. That is
    the shape of failure negative-controls/README.md refuses to accept as a result,
    and it is exit 3 rather than exit 2 because it is an absence."""
    cross = doc.get("crossVendor") or {}
    rows = cross.get("comparisons") or []
    shape_of = {c["operatorId"]: c.get("shape") for c in doc["cells"]}
    unreadable_shapes = {shape_of.get(r.get("operatorId"))
                         for r in rows if r.get("agreement") == "vendor-unreadable"}
    victim = None
    for r in rows:
        if (r.get("agreement") != "vendor-unreadable"
                and shape_of.get(r.get("operatorId")) in unreadable_shapes):
            victim = r
            break
    if victim is None:
        return None, "no readable comparison shares a shape with an unreadable one"
    for v in victim["vendors"]:
        v["mutant"]["state"] = "NOT_OBSERVED"
        v["mutant"]["readable"] = False
        v["readable"] = False
        v["transition"] = None
    cross["tally"][victim["agreement"]] -= 1
    cross["tally"]["vendor-unreadable"] += 1
    victim["agreement"] = "vendor-unreadable"
    victim["unreadableSide"] = "both"
    return redigest(doc), None


def c_float_introduced(doc):
    """A non-integer number. interfaces.md section 5 rule 4 says the canonicaliser
    fails rather than rounding, so the digest cannot even be checked and the whole
    document is refused. Written with the old digest because there is no way to
    compute a new one for a document the canonicaliser will not serialise -- which
    is the point."""
    cell = first_cell(doc, lambda c: isinstance(c["base"].get("effectPre"), int))
    if cell is None:
        return None, "no cell with an integer effectPre in this document"
    cell["base"]["effectPre"] = 1.5
    return doc, None


CORRUPTIONS = (
    ("r1-state-flipped", c_r1_state_flipped, 2,
     "an R1 relation that moved is a finding: the reading is coming from something "
     "other than the property"),
    ("digest-staled", c_digest_staled, 3,
     "a document that does not hash to the value it carries is refused before any "
     "invariant is graded"),
    ("pairing-rule-broken", c_pairing_rule_broken, 2,
     "a state word, a held control and completesTheCheck on a side whose "
     "measurement is not OK (interfaces.md section 3.1)"),
    ("dominance-lane-deleted", c_dominance_lane_deleted, 2,
     "a lane-level declared absence deleted from the document"),
    ("unreadable-folded-into-split", c_unreadable_folded_into_split, 2,
     "'I could not look' relabelled as 'the two differ'"),
    ("r2c-put-on-survival-axis", c_r2c_put_on_survival_axis, 2,
     "an off-axis class graded as a movement down the survival axis"),
    ("witness-removed", c_witness_removed, 3,
     "the last readable comparison of a shape that already has an unreadable one, "
     "so nothing left in the run shows the oracle can read that shape at all"),
    ("float-introduced", c_float_introduced, 3,
     "a non-integer number makes the document uncanonicalisable, so its digest "
     "cannot be checked at all"),
)


def run_checker(path):
    proc = subprocess.run([sys.executable, CHECKER, path],
                          capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main(argv):
    if any(a.startswith("-") for a in argv):
        print("usage: falsify-meta.py [report.json]", file=sys.stderr)
        return 3

    if argv:
        reports = list(argv)
    else:
        if not os.path.isdir(REPORTS):
            print("no report directory at %s; build-meta-report.py has not been run"
                  % REPORTS.replace(os.path.expanduser("~"), "~"), file=sys.stderr)
            return 3
        reports = [os.path.join(REPORTS, n) for n in sorted(os.listdir(REPORTS))
                   if n.endswith(".json")]
    if not reports:
        print("no reports to corrupt", file=sys.stderr)
        return 3

    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)

    # The uncorrupted document is graded first. Without this line the whole harness
    # could be reporting refusals that have nothing to do with the corruptions.
    baseline_failures = []
    for report in reports:
        rc, _out = run_checker(report)
        if rc != 0:
            baseline_failures.append("%s exits %d before any corruption"
                                     % (os.path.basename(report), rc))
    if baseline_failures:
        print("the baseline is not clean, so nothing below would mean anything:",
              file=sys.stderr)
        for b in baseline_failures:
            print("  " + b, file=sys.stderr)
        return 3

    wrong = []
    applied = 0
    skipped = 0
    print("%-30s %-14s %-8s %-8s %s"
          % ("corruption", "document", "expect", "got", "verdict"))
    print("-" * 96)
    for report in reports:
        with open(report, "r", encoding="utf-8") as fh:
            original = json.load(fh)
        for cname, fn, expect, _why in CORRUPTIONS:
            doc, why_not = fn(copy.deepcopy(original))
            if doc is None:
                print("%-30s %-14s %-8s %-8s SKIPPED (%s)"
                      % (cname, os.path.basename(report), expect, "-", why_not))
                skipped += 1
                continue
            out_path = os.path.join(WORK, "%s.%s.json"
                                    % (os.path.basename(report)[:-5], cname))
            with open(out_path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
                fh.write("\n")
            rc, _out = run_checker(out_path)
            applied += 1
            ok = rc == expect
            if not ok:
                wrong.append("%s on %s: expected exit %d and the grader exited %d%s"
                             % (cname, os.path.basename(report), expect, rc,
                                " -- IT ACCEPTED THE CORRUPTED DOCUMENT"
                                if rc == 0 else ""))
            print("%-30s %-14s %-8d %-8d %s"
                  % (cname, os.path.basename(report), expect, rc,
                     "refused" if ok else "WRONG"))

    print("\n%d corruption(s) applied, %d skipped as not applicable to the "
          "document." % (applied, skipped))
    if applied == 0:
        print("no corruption was applied, so the grader was not exercised at all",
              file=sys.stderr)
        return 3
    if wrong:
        print("\n%d corruption(s) the grader did not refuse correctly:" % len(wrong),
              file=sys.stderr)
        for w in wrong:
            print("  " + w, file=sys.stderr)
        print("  A corruption the grader accepts is a finding about check-meta.py. "
              "Fix it there, never by removing the corruption.", file=sys.stderr)
        return 2
    print("check-meta.py refused every applicable corruption with the exit code "
          "interfaces.md section 7 assigns to it.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
