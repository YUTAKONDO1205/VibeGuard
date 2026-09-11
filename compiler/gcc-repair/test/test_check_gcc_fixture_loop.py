#!/usr/bin/env python3
"""Unit tests for the grading logic of scripts/check-gcc-fixture-loop.py that
does not need a lab: the expectation tables, the stderr comparison and the
per-cell record comparison.

    python3 compiler/gcc-repair/test/test_check_gcc_fixture_loop.py

The checker's behaviour on a real lab, and on deliberately corrupted copies of
one, is measured in README.md ("The checker was shown to fail").
"""

import copy
import importlib.util
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
sys.path.insert(0, SCRIPTS)

_spec = importlib.util.spec_from_file_location("check_loop", os.path.join(SCRIPTS, "check-gcc-fixture-loop.py"))
chk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chk)

from test_wpin_gcc_record import good_record, reseal  # noqa: E402


class Tables(unittest.TestCase):
    def test_every_loop_cell_has_an_expectation(self):
        self.assertEqual(sorted(chk.ORDER), sorted(chk.EXPECT))
        self.assertEqual(len(chk.ORDER), 5 * len(chk.LEVELS))
        for cell, exp in chk.EXPECT.items():
            self.assertIn(exp["opt"], chk.OPT_LEVELS, cell)

    def test_the_pin_must_show_at_every_level(self):
        for o in chk.LEVELS:
            self.assertEqual(chk.EXPECT["pin" + o]["subject"], "PRESENT")
            # The red controls read exactly like the stock build.
            self.assertEqual(chk.EXPECT["dry" + o]["subject"], chk.EXPECT["base" + o]["subject"])
            self.assertEqual(chk.EXPECT["wrongname" + o]["subject"], chk.EXPECT["base" + o]["subject"])
            for k in ("dry", "wrongname", "nothing"):
                self.assertIs(chk.EXPECT[k + o]["sameAsBase"], True)

    def test_shape_and_stale_tables_are_complete(self):
        self.assertEqual(sorted(chk.SHAPE_ORDER), sorted(chk.SHAPES))
        self.assertEqual(sorted(chk.STALE_ORDER), sorted(chk.STALE))
        self.assertEqual(sorted(chk.ALONE_ORDER), sorted(chk.ALONE))
        for name, exp in chk.SHAPES.items():
            followed = sum(1 for v in exp["sites"] if v)
            partial = [l for l in exp["lines"] if l.startswith("WipePinGcc: partial:")]
            if followed:
                self.assertEqual(len(partial), 1, name)
                self.assertIn(f"; {followed} followed by", partial[0], name)

    def test_opt_levels_are_the_measured_pairs(self):
        self.assertEqual(chk.OPT_LEVELS, {"-O0": (0, 0), "-O1": (1, 0), "-O2": (2, 0),
                                          "-O3": (3, 0), "-Os": (2, 1)})


class Lines(unittest.TestCase):
    def test_every_expected_line_and_nothing_else(self):
        want = [chk.nothing_line("t.c")]
        self.assertEqual(chk.lines_problems(want, want), [])
        self.assertEqual(len(chk.lines_problems([], want)), 1)
        extra = chk.lines_problems(want + ["WipePinGcc: something else"], want)
        self.assertEqual(len(extra), 1)
        self.assertIn("unexpected", extra[0])

    def test_the_line_formats_are_the_plugins(self):
        # Copied from a measured stderr (README.md, the shapes).
        self.assertEqual(
            chk.partial_line(2, 1, "initwipe.c"),
            "WipePinGcc: partial: pinned 2 site(s) in initwipe.c; 1 followed by a later use of the same "
            "buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=0 memsetChk=0 "
            "nonZeroFill=0 atomicMemset=0 inlineWrapperMemset=0")
        self.assertEqual(chk.dry_line(1),
                         "WipePinGcc: dry run: 1 zero-fill memset site(s) would be pinned; none was changed")

    def test_only_plugin_lines_are_compared(self):
        self.assertEqual(chk.plugin_lines(["cc1: note", "WipePinGcc: x", ""]), ["WipePinGcc: x"])


class RecordProblems(unittest.TestCase):
    def test_the_pin_cell_record(self):
        self.assertEqual(chk.record_problems(good_record(), chk.EXPECT["pin-O2"], "target.c"), [])

    def test_a_record_for_another_level(self):
        bad = chk.record_problems(good_record(), chk.EXPECT["pin-Os"], "target.c")
        self.assertTrue(any("optLevel" in b for b in bad), bad)

    def test_an_initialiser_like_site_where_the_wipe_should_be(self):
        rec = good_record()
        rec["pinned"][0]["followedByUse"] = True
        bad = chk.record_problems(reseal(rec), chk.EXPECT["pin-O2"], "target.c")
        self.assertTrue(any("followedByUse per site" in b for b in bad), bad)

    def test_a_record_that_does_not_validate_stops_there(self):
        rec = copy.deepcopy(good_record())
        rec["pinnedCount"] = 7
        bad = chk.record_problems(rec, chk.EXPECT["pin-O2"], "target.c")
        self.assertTrue(bad and all(b.startswith("record: ") for b in bad), bad)


if __name__ == "__main__":
    unittest.main()
