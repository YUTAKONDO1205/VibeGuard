#!/usr/bin/env python3
"""The survival-axis fence in check-meta.py, in both directions.

    python3 compiler/eval/metamorphic/test/test_check_meta_survival_axis.py

WHY THIS FILE EXISTS

A `-O0` run of this lane is a real run and its document is a real document: every
R1 invariance holds, every R2a source deletion lands on ABSENT, every R2c lands on
NOT_APPLICABLE, and only the three R2b cells -- the only class that asks the
instrument to tell PRESENT from LOST -- read `not-expressed`, because at -O0
nothing is folded. Before the fence, a sweep of a results directory holding only
that document exited 0, and that 0 is exactly what a sweep would report for an
extractor that had been made incapable of ever reporting a loss. The lane's own
README runs O0 and O2; nothing made it.

The fence has to be conditional or it would be wrong, so both halves are asserted
here and the pair is the claim:

  * the same document, NAMED on the command line, is still accepted -- grading one
    on purpose is legitimate, it is what the -O0-only demonstrations do, and it is
    what scripts/falsify-meta.py does on every one of its corruptions
  * the same document, SWEPT as the whole set, is refused at 3

Nothing here compiles anything or reads a lab. It synthesises documents from the
tracked catalogue into the system temp directory and removes them.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
CHECKER = os.path.join(SCRIPTS, "check-meta.py")
CATALOGUE = os.path.join(HERE, "..", "catalogue.json")


def load_checker():
    """check-meta.py as a module. Its filename is not an identifier, so it cannot
    be imported by name, and copying its helpers into this file would test a copy."""
    spec = importlib.util.spec_from_file_location("check_meta", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CM = load_checker()
CAT = json.load(open(CATALOGUE, encoding="utf-8"))


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def side(state, **extra):
    """One measured side. measurement OK throughout: this file is about the
    survival axis and not about the pairing rule, which has its own corruption in
    falsify-meta.py."""
    out = {
        "measurement": "OK",
        "state": state,
        "controlHeld": True,
        "completesTheCheck": True,
        "brokenReason": None,
    }
    out.update(extra)
    return out


#: What each declared edge looks like when the cell MOVED along it. The R2b row is
#: the one the fence is about; every other row is here so that the synthesised
#: document is otherwise a document the grader accepts, which is the only way the
#: fence can be shown to be the thing that fired.
MOVED = {
    "INVARIANT": None,                       # filled per shape below
    "PRESENT->ABSENT": ("PRESENT", "ABSENT"),
    "PRESENT->LOST": ("PRESENT", "LOST"),
    "PRESENT->NOT_APPLICABLE": ("PRESENT", "NOT_APPLICABLE"),
    "ABSENT->PRESENT": ("ABSENT", "PRESENT"),
}


def states_for(op, express_survival_axis):
    """(base, mutant) for one operator.

    `express_survival_axis=False` puts every R2b mutant back where its base is,
    which is `not-expressed` -- the legitimate -O0 reading, and the whole point.
    """
    declared = op["declaredDirection"]
    if declared == "INVARIANT":
        # An invariance over a base that never established the property is
        # `vacuous-invariance` and exit 3, so the base has to be at a reading the
        # relation can be about. The forbidden polarity accepts either.
        base = "ABSENT" if op["shape"] == "forbidden" else "PRESENT"
        return base, base
    pair = MOVED[declared]
    if op["class"] == "R2b" and not express_survival_axis:
        return pair[0], pair[0]
    return pair


def build_doc(run_id, opt, express_survival_axis):
    """A document the grader accepts, assembled from the tracked catalogue.

    Deliberately NOT a copy of a real report: a fixture copied out of a lab would
    pin whatever that lab happened to hold, and this file would then stop testing
    the rule the day the specimens changed.
    """
    measured = [op for op in CAT["operators"] if op.get("measured") is not False]
    cells = []
    for op in measured:
        base_state, mutant_state = states_for(op, express_survival_axis)
        extra_base, extra_mutant = {}, {}
        at_cp = None
        if op.get("gradeOn") == "count-at-pre-opt-ir":
            # The one operator graded on a COUNT at one checkpoint. The counts are
            # the object it is graded against, so they are written rather than left
            # for the grader to find missing.
            extra_base = {"effectPre": 0 if base_state == "ABSENT" else 1}
            extra_mutant = {"effectPre": 0 if mutant_state == "ABSENT" else 1}
            at_cp = "%s->%s" % ("ABSENT" if extra_base["effectPre"] == 0 else "PRESENT",
                                "ABSENT" if extra_mutant["effectPre"] == 0 else "PRESENT")
        cells.append({
            "operatorId": op["operatorId"],
            "class": op["class"],
            "shape": op["shape"],
            "declaredDirection": op["declaredDirection"],
            "graded": bool(op.get("graded")),
            "whyUngraded": op.get("whyUngraded"),
            "notMonotonic": op.get("notMonotonicWhen") is not None,
            "notMonotonicWhen": op.get("notMonotonicWhen"),
            "survivalAxisGraded": op["class"] == "R2b",
            "base": side(base_state, **extra_base),
            "mutant": side(mutant_state, **extra_mutant),
            "transition": "%s->%s" % (base_state, mutant_state),
            "transitionReadable": True,
            "transitionAtDeclaredCheckpoint": at_cp,
        })

    by_shape = {}
    for c in cells:
        by_shape[c["shape"]] = by_shape.get(c["shape"], 0) + 1
    lanes = [{
        "laneId": lane["laneId"],
        "shape": lane["shape"],
        "status": lane["status"],
        "statusReason": lane["statusReason"],
        "propertyId": lane["propertyId"],
        "cellsEmitted": by_shape.get(lane["shape"], 0),
    } for lane in CAT["lanes"]]

    doc = {
        "schemaVersion": CM.SCHEMA,
        "failureDirection": "a synthesised document, for the survival-axis fence only",
        "catalogue": {"schemaVersion": CAT["schemaVersion"], "sha256": sha256_file(CATALOGUE)},
        "generator": {"version": 1, "sha256": "0" * 64},
        "run": {"id": run_id, "opt": opt, "extraArgs": []},
        "toolchain": {"cc": "clang-18", "clang": "18.1.3", "pluginSha256": "1" * 64},
        "cells": cells,
        "lanes": lanes,
        # UNSUPPORTED with a reason and no comparisons: a declared absence, which
        # the grader accepts, rather than an OK channel with an empty table, which
        # it refuses.
        "crossVendor": {
            "status": "UNSUPPORTED",
            "statusReason": "this document is synthesised by a unit test and took no assembly reading",
            "comparisons": [],
            "tally": {"vendors-agree": 0, "vendors-split": 0, "vendor-unreadable": 0},
        },
    }
    doc["evidenceDigest"] = CM.digest_of(doc)
    return doc


def write_doc(directory, name, doc):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    return path


def run_named(path):
    proc = subprocess.run([sys.executable, CHECKER, path], capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def run_swept(out_dir):
    env = dict(os.environ)
    env["VG_META_OUT"] = out_dir
    proc = subprocess.run([sys.executable, CHECKER], capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout + proc.stderr


class SurvivalAxisHelpers(unittest.TestCase):
    """The two pure helpers, over the tracked catalogue."""

    def test_the_catalogue_declares_graded_R2b_operators_at_all(self):
        # Without this the fence below is a rule about an empty set and every
        # assertion in this file would hold for the wrong reason.
        declared = CM.graded_r2b_operators(CAT)
        self.assertGreaterEqual(len(declared), 3, declared)
        self.assertIn("W-R2B-DEADZERO", declared)
        self.assertNotIn("D-R2-HOIST", declared,
                         "D-R2-HOIST is declared ungraded; a fence that demanded it "
                         "move would demand a measurement the lane says it cannot take")

    def test_movers_counts_only_R2b_cells_that_passed(self):
        grades = {
            "W-R2B-DEADZERO": (CM.PASS, ""),
            "W-R2B-ZEROLEN": (CM.NOT_EXPRESSED, ""),
            "W-R2A-DELETE": (CM.PASS, ""),       # moved, but off the survival axis
            "W-R1-RENAME": (CM.PASS, ""),        # an invariance that held
            "W-R2C-UNPIN": (CM.PASS, ""),        # a referent removal, off the axis
        }
        self.assertEqual(CM.survival_axis_movers(grades, CAT), ["W-R2B-DEADZERO"])

    def test_an_R2b_cell_that_did_not_move_is_not_a_mover(self):
        grades = {op: (CM.NOT_EXPRESSED, "") for op in CM.graded_r2b_operators(CAT)}
        grades["W-R2A-DELETE"] = (CM.PASS, "")
        self.assertEqual(CM.survival_axis_movers(grades, CAT), [],
                         "an R2a source deletion is not a substitute for a loss: it is "
                         "what an extractor that can no longer report one still passes")


class SurvivalAxisFence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="check-meta-axis-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_a_sweep_in_which_the_axis_was_expressed_is_clean(self):
        """The control for everything below. If this document did not grade clean,
        a refusal in the next test would prove nothing about the fence."""
        out = os.path.join(self.tmp, "expressed")
        write_doc(out, "O2.json", build_doc("O2", "-O2", True))
        rc, output = run_swept(out)
        self.assertEqual(rc, 0, output)
        self.assertIn("survival axis: 3 of 3", output)

    def test_a_sweep_of_only_a_not_expressed_document_is_refused_at_3(self):
        out = os.path.join(self.tmp, "flat")
        write_doc(out, "O0.json", build_doc("O0", "-O0", False))
        rc, output = run_swept(out)
        self.assertEqual(rc, 3, output)
        self.assertIn("no cell on the survival axis moved", output)
        self.assertIn("W-R2B-DEADZERO", output)
        self.assertNotIn("disagreement", output.lower().replace("0 disagreement", ""))

    def test_the_same_document_named_on_the_command_line_is_still_accepted(self):
        """The fence is conditional, and this is the half that says so. A fence that
        fired here would refuse a legitimate act and would make falsify-meta.py's
        own baseline unclean, at which point none of its refusals mean anything."""
        out = os.path.join(self.tmp, "named")
        path = write_doc(out, "O0.json", build_doc("O0", "-O0", False))
        rc, output = run_named(path)
        self.assertEqual(rc, 0, output)
        self.assertIn("survival axis: 0 of 3", output)

    def test_one_document_in_the_sweep_expressing_the_axis_carries_the_set(self):
        """`not-expressed` at -O0 beside `pass` at -O2 is the expected shape of this
        lane, and the fence must not have broken it."""
        out = os.path.join(self.tmp, "both")
        write_doc(out, "O0.json", build_doc("O0", "-O0", False))
        write_doc(out, "O2.json", build_doc("O2", "-O2", True))
        rc, output = run_swept(out)
        self.assertEqual(rc, 0, output)
        self.assertIn("2 document(s) graded", output)

    def test_the_fence_reports_an_absence_and_not_a_falsification(self):
        """3, never 2. Nothing in a flat document was falsified -- the run simply
        never asked the question -- and reporting an absence as a finding would be
        the mirror of reporting a finding as an absence."""
        out = os.path.join(self.tmp, "code")
        write_doc(out, "O0.json", build_doc("O0", "-O0", False))
        rc, output = run_swept(out)
        self.assertEqual(rc, 3)
        self.assertIn("could not be graded", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
