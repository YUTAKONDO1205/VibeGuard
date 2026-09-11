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

    def test_the_barrier_shapes_are_graded_from_the_listings(self):
        # A barrier that is not a pin: the plugin must pin, and the store must
        # be back in the listing where the stock listing lost it.
        for name in ("clobonly", "otherbar"):
            exp = chk.SHAPES[name]
            self.assertEqual(exp["volatile"], [False], name)
            self.assertEqual(exp["pinned"], 1, name)
            self.assertEqual(exp["pinShRc"], 0, name)
            self.assertEqual(exp["store"], ("PRESENT", "ABSENT"), name)
        # The source's own pin: left alone, and the store is there either way.
        self.assertEqual(chk.SHAPES["srcbarrier"]["volatile"], [True])
        self.assertEqual(chk.SHAPES["srcbarrier"]["store"], ("PRESENT", "PRESENT"))

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


# `objdump -d --no-show-raw-insn` of `handle` in the stock -flto -shared links,
# copied from a measured run (README.md, the lto cells).
PINNED_LINK = """
0000000000001160 <handle>:
    1160:\tendbr64
    1164:\tpush   %rbx
    1165:\tsub    $0x30,%rsp
    1169:\tmov    %fs:0x28,%rax
    1172:\tmov    %rax,0x28(%rsp)
    1177:\txor    %eax,%eax
    1179:\tmov    %rsp,%rbx
    117c:\tmov    %rbx,%rdi
    117f:\tcall   1090 <derive@plt>
    1184:\tmov    $0x20,%esi
    1189:\tmov    %rbx,%rdi
    118c:\tcall   1080 <use@plt>
    1191:\tpxor   %xmm0,%xmm0
    1195:\tmovaps %xmm0,(%rsp)
    1199:\tmovaps %xmm0,0x10(%rsp)
    119e:\tmov    0x28(%rsp),%rax
    11a3:\tsub    %fs:0x28,%rax
    11ac:\tjne    11b6 <handle+0x56>
    11ae:\tadd    $0x30,%rsp
    11b2:\txor    %eax,%eax
    11b4:\tpop    %rbx
    11b5:\tret
    11b6:\tcall   1070 <__stack_chk_fail@plt>

0000000000001200 <other>:
    1200:\tmovq   $0x0,(%rsp)
"""
UNPINNED_LINK = PINNED_LINK.replace(
    "    1191:\tpxor   %xmm0,%xmm0\n    1195:\tmovaps %xmm0,(%rsp)\n    1199:\tmovaps %xmm0,0x10(%rsp)\n", "")


class ObjdumpZeroStores(unittest.TestCase):
    def test_the_pinned_link_holds_the_whole_fill(self):
        z = chk.objdump_zero_stores(PINNED_LINK, "handle")
        self.assertEqual((z["stores"], z["bytes"], z["calls"]), (2, 32, 0))

    def test_the_unpinned_link_holds_none_and_the_next_function_is_not_read(self):
        z = chk.objdump_zero_stores(UNPINNED_LINK, "handle")
        self.assertEqual((z["stores"], z["bytes"], z["calls"]), (0, 0, 0))
        self.assertEqual(chk.objdump_zero_stores(PINNED_LINK, "other")["bytes"], 8)

    def test_a_register_reloaded_after_the_xor_is_not_zero(self):
        text = PINNED_LINK.replace("    1195:\tmovaps %xmm0,(%rsp)\n",
                                   "    1193:\tmovdqa (%rax),%xmm0\n    1195:\tmovaps %xmm0,(%rsp)\n")
        z = chk.objdump_zero_stores(text, "handle")
        self.assertEqual(z["stores"], 0)

    def test_only_stores_to_memory_count_and_a_missing_function_is_none(self):
        # `xor %eax,%eax` zeroes a register, not memory.
        self.assertEqual(chk.objdump_zero_stores(PINNED_LINK, "handle")["lines"],
                         ["movaps %xmm0,(%rsp)", "movaps %xmm0,0x10(%rsp)"])
        self.assertIsNone(chk.objdump_zero_stores(PINNED_LINK, "nosuch"))


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
