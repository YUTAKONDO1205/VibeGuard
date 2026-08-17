#!/usr/bin/env python3
"""Corrupt assembled calibration reports and assert that check-battery.py refuses each.

    python3 falsify-battery.py [--keep]

A grader that has never been shown to FAIL has not been shown to work. This
directory demonstrated its refusals once, by hand, in a session whose output has
scrolled away -- which is exactly the asymmetry the metamorphic lane next door does
not have, because it ships scripts/falsify-meta.py. This is the missing half.

WHAT IT IS NOT

Not a measurement, and it compiles nothing. It reads the reports already in
$VG_CAL_LAB/_results/calibration, writes corrupted copies into a scratch directory,
and runs the real grader on them. If there are no reports it exits 3 rather than
reporting success over an empty set: a falsifier with nothing to falsify is the same
empty-scan failure every check in this tree is written against.

EVERY CORRUPTION RE-DIGESTS unless the digest IS the point. Otherwise each one would
be caught by the digest precondition and nothing below it would ever be exercised --
the test would pass while testing one thing ten times.

WHAT EACH CORRUPTION IS FOR, AND WHY ITS CODE IS ITS CODE

Exit 2 is a positive finding about the instrument or the document; exit 3 is a check
that could not be completed. The pairing that matters is which side each corruption
lands on, because a grader that reported them all the same way would be telling a
reader "something is wrong" and nothing more:

  reference-state-flipped        2  a reference cell misread its known true value
  pairing-rule-broken           2  a state word on a cell whose measurement is not OK
  control-held-null-when-fell   2  a fallen control described as one nobody ran
  role-laundered                2  a reference cell relabelled a probe, which is how
                                   its state would stop being graded at all
  lane-claims-measured          2  the dominance lane claiming it measured something
  digest-staled                 3  the document cannot be trusted, so nothing in it is
  dominance-lane-deleted        3  a declared absence removed from the document
  cell-dropped                  3  an expectation with no cell to hold it against
  toolchain-removed             3  section 5's block missing: readings unattributable
  frame-declaration-broken      3  the witness disagrees with what expected.json
                                   declares, in either direction
  configuration-missing         3  half a battery swept and reported as a whole one

EXIT CODES (interfaces.md section 7)
  0  every corruption was refused with the code it is contracted to produce
  2  a corruption was NOT refused, or was refused with the wrong code. That is a
     finding about the grader, not about the corruption.
  3  there was nothing to corrupt, or the scratch directory could not be made.
"""

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(HERE, "check-battery.py")
LAB = os.environ.get("VG_CAL_LAB", os.path.join(os.path.expanduser("~"), "vg-lab", "calibration"))
RESULTS = os.path.join(LAB, "_results", "calibration")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def redigest(doc):
    """Recompute the digest so that the corruption below it is what gets caught."""
    stripped = {k: v for k, v in doc.items() if k not in ("context", "evidenceDigest")}
    doc["evidenceDigest"] = hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()
    return doc


def first_reference_cell(doc, want_measurement="OK"):
    for c in doc["cells"]:
        if c.get("role") == "reference" and c.get("measurement") == want_measurement:
            return c
    return None


def first_broken_cell(doc):
    for c in doc["cells"]:
        if c.get("measurement") != "OK":
            return c
    return None


# --- the corruptions -------------------------------------------------------
# Each returns (mutated-doc, note) or (None, why-not-applicable). "Not applicable"
# is reported and never silently counted as a pass.

def c_state_flipped(doc):
    cell = first_reference_cell(doc)
    if cell is None:
        return None, "no reference cell with a reading in this document"
    other = "PRESENT" if cell["state"] != "PRESENT" else "LOST"
    cell["state"] = other
    return redigest(doc), "%s: state -> %s" % (cell["fixtureId"], other)


def c_pairing_rule(doc):
    cell = first_broken_cell(doc)
    if cell is None:
        return None, "no cell whose measurement is not OK in this document"
    cell["state"] = "LOST"
    return redigest(doc), "%s: a state word on a %s cell" % (cell["fixtureId"], cell["measurement"])


def c_control_held_null(doc):
    cell = first_broken_cell(doc)
    if cell is None:
        return None, "no cell whose measurement is not OK in this document"
    if cell.get("rawRecordControlHeld") is not False:
        return None, "%s's control did not fall, so null is the true answer there" % cell["fixtureId"]
    cell["controlHeld"] = None
    return redigest(doc), "%s: a fallen control reported as one nobody ran" % cell["fixtureId"]


def c_role_laundered(doc):
    cell = first_reference_cell(doc)
    if cell is None:
        return None, "no reference cell with a reading in this document"
    cell["role"] = "instrument-limit-probe"
    return redigest(doc), "%s: reference -> instrument-limit-probe" % cell["fixtureId"]


def c_lane_claims_measured(doc):
    for lane in doc["lanes"]:
        if lane.get("laneStatus") == "no-probe":
            lane["laneStatus"] = "measured"
            return redigest(doc), "%s lane claims it measured something" % lane["shape"]
    return None, "no no-probe lane in this document"


def c_digest_staled(doc):
    doc["evidenceDigest"] = "0" * 64      # deliberately NOT re-digested
    return doc, "digest replaced with zeroes"


def c_lane_deleted(doc):
    before = len(doc["lanes"])
    doc["lanes"] = [l for l in doc["lanes"] if l.get("laneStatus") != "no-probe"]
    if len(doc["lanes"]) == before:
        return None, "no no-probe lane to delete"
    return redigest(doc), "the declared-absence lane removed"


def c_cell_dropped(doc):
    cell = first_reference_cell(doc)
    if cell is None:
        return None, "no reference cell to drop"
    doc["cells"] = [c for c in doc["cells"] if c["fixtureId"] != cell["fixtureId"]]
    return redigest(doc), "%s removed from the document" % cell["fixtureId"]


def c_toolchain_removed(doc):
    if "toolchain" not in doc:
        return None, "this document carries no toolchain block to remove"
    doc.pop("toolchain")
    return redigest(doc), "section 5's toolchain block removed"


def c_frame_declaration(doc):
    for c in doc["cells"]:
        frame = ((c.get("witness") or {}).get("structural") or {}).get("frameRulesOutObject")
        if isinstance(frame, dict) and frame.get("verdict"):
            was = frame["verdict"]
            frame["verdict"] = "present-in-frame" if was != "present-in-frame" else "ruled-out"
            return redigest(doc), "%s: frame witness %s -> %s" % (c["fixtureId"], was, frame["verdict"])
    return None, "no cell in this document carries a frame verdict"


CORRUPTIONS = [
    ("reference-state-flipped", 2, c_state_flipped),
    ("pairing-rule-broken", 2, c_pairing_rule),
    ("control-held-null-when-fell", 2, c_control_held_null),
    ("role-laundered", 2, c_role_laundered),
    ("lane-claims-measured", 2, c_lane_claims_measured),
    ("digest-staled", 3, c_digest_staled),
    ("dominance-lane-deleted", 3, c_lane_deleted),
    ("cell-dropped", 3, c_cell_dropped),
    ("toolchain-removed", 3, c_toolchain_removed),
    ("frame-declaration-broken", 3, c_frame_declaration),
]


def run_checker(*args, lab=None):
    env = dict(os.environ)
    if lab:
        env["VG_CAL_LAB"] = lab
    proc = subprocess.run([sys.executable, CHECKER, *args],
                          capture_output=True, text=True, env=env)
    return proc.returncode


def main(argv):
    keep = "--keep" in argv
    if not os.path.isdir(RESULTS):
        print("falsify-battery.py: no assembled reports at %s -- run the battery first"
              % RESULTS.replace(os.path.expanduser("~"), "~"), file=sys.stderr)
        return 3
    names = sorted(n for n in os.listdir(RESULTS) if n.endswith(".json"))
    if not names:
        print("falsify-battery.py: %s holds no reports. A falsifier with nothing to falsify "
              "reports success over an empty set, which is the failure every check here is "
              "written against." % RESULTS.replace(os.path.expanduser("~"), "~"), file=sys.stderr)
        return 3

    baseline = run_checker(*[os.path.join(RESULTS, n) for n in names])
    print("baseline (uncorrupted, %d document(s)): exit %d" % (len(names), baseline))
    if baseline != 0:
        print("falsify-battery.py: the uncorrupted reports do not grade clean, so nothing below "
              "would distinguish a refused corruption from an already-failing set.", file=sys.stderr)
        return 3

    scratch = tempfile.mkdtemp(prefix="falsify-battery-")
    rows, wrong, skipped = [], [], []
    try:
        for name in names:
            with open(os.path.join(RESULTS, name), "r", encoding="utf-8") as fh:
                original = json.load(fh)
            for label, want, fn in CORRUPTIONS:
                doc, note = fn(copy.deepcopy(original))
                if doc is None:
                    skipped.append("%-28s %-10s SKIPPED (%s)" % (label, name, note))
                    continue
                d = os.path.join(scratch, "%s-%s" % (label, name))
                os.makedirs(d, exist_ok=True)
                target = os.path.join(d, name)
                with open(target, "w", encoding="utf-8", newline="\n") as fh:
                    json.dump(doc, fh, indent=2, sort_keys=True, ensure_ascii=False)
                got = run_checker(target)
                ok = got == want
                rows.append("%-28s %-10s want %d got %d  %s  %s"
                            % (label, name, want, got, "refused" if ok else "NOT REFUSED", note))
                if not ok:
                    wrong.append("%s on %s: contracted exit %d, got %d (%s)"
                                 % (label, name, want, got, note))

        # The one corruption that cannot be done to a single document, because it is
        # about the SET: a sweep that finds only some of the configurations the
        # standard declares. Run against a lab whose results directory holds one.
        if len(names) > 1:
            lab = os.path.join(scratch, "half-lab")
            half = os.path.join(lab, "_results", "calibration")
            os.makedirs(half, exist_ok=True)
            shutil.copy(os.path.join(RESULTS, names[0]), os.path.join(half, names[0]))
            got = run_checker(lab=lab)
            ok = got == 3
            rows.append("%-28s %-10s want 3 got %d  %s  only %s swept"
                        % ("configuration-missing", "(set)", got,
                           "refused" if ok else "NOT REFUSED", names[0]))
            if not ok:
                wrong.append("configuration-missing: contracted exit 3, got %d" % got)
        else:
            skipped.append("%-28s %-10s SKIPPED (only one configuration is assembled)"
                           % ("configuration-missing", "(set)"))
    finally:
        if keep:
            print("\nscratch kept at %s" % scratch)
        else:
            shutil.rmtree(scratch, ignore_errors=True)

    print()
    for r in rows:
        print("  " + r)
    for s in skipped:
        print("  " + s)
    print("\n%d corruption(s) applied, %d skipped as not applicable to the document."
          % (len(rows), len(skipped)))

    if wrong:
        print("\n%d corruption(s) the grader did not refuse as contracted:" % len(wrong),
              file=sys.stderr)
        for w in wrong:
            print("  " + w, file=sys.stderr)
        return 2
    if not rows:
        print("no corruption was applicable to any document", file=sys.stderr)
        return 3
    print("check-battery.py refused every applicable corruption with the exit code "
          "interfaces.md section 7 assigns to it.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
