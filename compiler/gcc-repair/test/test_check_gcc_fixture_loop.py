#!/usr/bin/env python3
"""Unit tests for the grading logic of scripts/check-gcc-fixture-loop.py that
does not need a lab: the expectation tables, the stderr comparison and the
per-cell record comparison; and for scripts/objdump_fill.py, the reader of
linked code that this checker and ../../llvm-repair/scripts/check-fixture-loop.py
both import, with the two checkers' xtu tables held to the same design. The
LLVM checker's reading of how its xtu cells were built (the LTO form from each
object's summary block; the linker, and which link it was, from the
executable) is tested here too, because this is the file CI runs.

    python3 compiler/gcc-repair/test/test_check_gcc_fixture_loop.py

The checker's behaviour on a real lab, and on deliberately corrupted copies of
one, is measured in README.md ("The checker was shown to fail").
"""

import copy
import importlib.util
import os
import shutil
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
sys.path.insert(0, SCRIPTS)

_spec = importlib.util.spec_from_file_location("check_loop", os.path.join(SCRIPTS, "check-gcc-fixture-loop.py"))
chk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chk)

_lspec = importlib.util.spec_from_file_location(
    "check_llvm_loop", os.path.join(HERE, "..", "..", "llvm-repair", "scripts", "check-fixture-loop.py"))
llvm_chk = importlib.util.module_from_spec(_lspec)
_lspec.loader.exec_module(llvm_chk)

import objdump_fill as of  # noqa: E402
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

    def test_every_switch_value_the_plugin_must_refuse_has_a_cell(self):
        for cell, var in (("badbarrier-O2", "WPIN_BARRIER_CALLS='2'"), ("badzerocopy-O2", "WPIN_ZERO_COPY='2'"),
                          ("badbuffer-O2", "WPIN_BUFFER_BARRIER='2'")):
            exp = chk.ALONE[cell]
            self.assertEqual((exp["pinShRc"], exp["record"]), (3, False), cell)
            self.assertEqual(exp["lines"], [f"WipePinGcc: refusing to install: {var} is neither 0 nor 1"])
        # WPIN_BUFFER_BARRIER=1 is implemented: no alone cell expects it refused.
        self.assertNotIn("bufferon-O2", chk.ALONE)
        self.assertFalse(any("not implemented" in l for exp in chk.ALONE.values() for l in exp["lines"]))


class SwitchTables(unittest.TestCase):
    def test_every_shape_has_one_switch_and_one_counter(self):
        self.assertEqual(sorted(chk.SWITCH_ORDER), sorted(chk.SWITCH))
        for shape, exp in chk.SWITCH.items():
            self.assertIn(exp["switch"], ("barrierCalls", "zeroCopy"), shape)
            self.assertIn(exp["counter"], chk.UNHANDLED_ORDER, shape)
            self.assertEqual(exp["stock"], "ABSENT", shape)  # each cell can show a repair
            self.assertEqual(exp["site"]["function"], "handle", shape)
            self.assertEqual("zeroSymbol" in exp, exp["switch"] == "zeroCopy", shape)

    def test_the_off_cell_counts_and_changes_nothing(self):
        for shape in chk.SWITCH_ORDER:
            w = chk.switch_cell_expectation(shape, "off")
            self.assertEqual(w["expect"], chk.SWITCHES_OFF)
            self.assertEqual(w["blockValue"]["sites"], [], shape)
            self.assertEqual(w["unhandled"][chk.SWITCH[shape]["counter"]], 1, shape)
            self.assertEqual((w["pinShRc"], w["repairCount"], w["sameAsStock"], w["wipe"]), (4, 0, True, "ABSENT"))
            self.assertEqual(len(w["lines"]), 1)
            self.assertTrue(w["lines"][0].startswith("WipePinGcc: nothing to pin"), shape)

    def test_the_on_cell_repairs_once_and_the_dry_cell_does_not(self):
        for shape in chk.SWITCH_ORDER:
            blk = chk.SWITCH[shape]["switch"]
            done, would = chk.wpr.BLOCK_COUNTS[blk]
            on = chk.switch_cell_expectation(shape, "on")
            dry = chk.switch_cell_expectation(shape, "dry")
            self.assertIs(on["expect"][blk], True)
            self.assertEqual((on["blockValue"][done], on["blockValue"][would]), (1, 1), shape)
            self.assertEqual((dry["blockValue"][done], dry["blockValue"][would]), (0, 1), shape)
            self.assertEqual(sum(on["unhandled"].values()), 0, shape)
            self.assertEqual((on["pinShRc"], on["repairCount"], on["sameAsStock"], on["wipe"], on["lines"]),
                             (0, 1, False, "PRESENT", []))
            self.assertEqual((dry["pinShRc"], dry["repairCount"], dry["sameAsStock"], dry["wipe"], dry["dryRun"]),
                             (4, 0, True, "ABSENT", True))
            self.assertEqual(len(dry["lines"]), 1)

    def test_the_expected_records_are_ones_the_reader_accepts(self):
        # Build each cell's record from its expectation and hold the reader to it.
        for shape in chk.SWITCH_ORDER:
            for mode in chk.SWITCH_MODES:
                w = chk.switch_cell_expectation(shape, mode)
                rec = good_record(module=chk.SWITCH[shape]["module"], requested=["handle"],
                                  resolution=[{"name": "handle", "resolution": "resolved", "exact": True,
                                               "linkage": "external"}],
                                  pinned=[], pinnedCount=0, wouldPinCount=0, dryRun=w["dryRun"],
                                  seen={"zeroFillMemsetInScope": 0, "zeroFillMemsetInModule": 0},
                                  unhandled=w["unhandled"], **{w["block"]: w["blockValue"]})
                self.assertEqual(chk.wpr.validate(rec, w["expect"]), [], f"{shape}-{mode}")
                self.assertEqual(chk.wpr.repair_count(rec), w["repairCount"], f"{shape}-{mode}")

    def test_the_previous_group_covers_every_plugin_compile_with_the_switches_off(self):
        ids = chk.previous_ids()
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 4 * len(chk.LEVELS) + len(chk.SHAPE_ORDER) + len(chk.SWITCH_ORDER) + 1)
        self.assertEqual(ids[-1], "buffer-loopbar-off")
        for o in chk.LEVELS:
            for k in ("pin", "dry", "wrongname", "nothing"):
                self.assertIn(k + o, ids)
        self.assertNotIn("base-O2", ids)
        self.assertTrue(all(not i.endswith(("-on", "-dry")) for i in ids if i.startswith("switch-")))


class PreviousGroup(unittest.TestCase):
    """grade_previous on a synthetic lab: every pair the same bytes, the staged
    plugins the ones named in given.kv. Nothing is compiled."""

    def lab(self, plugin_sha, previous_sha):
        root = tempfile.mkdtemp(prefix="gcc-prev-")
        self.addCleanup(shutil.rmtree, root, True)
        d = os.path.join(root, "previous")
        os.makedirs(os.path.join(d, "this"))
        os.makedirs(os.path.join(d, "prev"))
        with open(os.path.join(d, "given.kv"), "w", encoding="utf-8") as f:
            f.write(f"pluginSha256={plugin_sha}\npreviousSha256={previous_sha}\nccVersion=13.3.0\n")
        ids = chk.previous_ids()
        with open(os.path.join(d, "cells.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(ids) + "\n")
        for cid in ids:
            with open(os.path.join(d, cid + ".kv"), "w", encoding="utf-8") as f:
                f.write(f"thisRc=0\nprevRc=0\nthisStagedSha256={plugin_sha}\nprevStagedSha256={previous_sha}\n")
            for which in ("this", "prev"):
                with open(os.path.join(d, which, cid + ".s"), "w", encoding="utf-8") as f:
                    f.write(f"\t.file\t\"{cid}\"\n")
        return root

    def test_two_plugins_with_the_same_listings_pass(self):
        rows, problems, incomplete, given = chk.grade_previous(self.lab("a" * 64, "b" * 64))
        self.assertTrue(given)
        self.assertEqual((problems, incomplete), ([], []))
        self.assertEqual(len(rows), len(chk.previous_ids()))

    def test_the_same_plugin_given_twice_is_a_problem(self):
        # Every pair is the same bytes and every staged sha256 matches its name,
        # so only the comparison of the two names can catch it.
        rows, problems, incomplete, given = chk.grade_previous(self.lab("c" * 64, "c" * 64))
        self.assertTrue(given)
        self.assertEqual(incomplete, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("the previous plugin is this plugin", problems[0])
        self.assertIn("c" * 64, problems[0])


class BufferTables(unittest.TestCase):
    def test_every_buffer_shape_has_an_expectation(self):
        self.assertEqual(sorted(chk.BUFFER_ORDER), sorted(chk.BUFFER))
        self.assertEqual(chk.BUFFER["loopbar"]["modes"], ("off", "on", "dry"))
        self.assertEqual(chk.BUFFER_SITE, {"function": "handle", "buffer": "key", "bytes": 32,
                                           "reason": "loop-store", "anchor": "clobber"})

    def test_off_counts_nothing_on_places_one_dry_places_none(self):
        off = chk.buffer_cell_expectation("loopbar", "off")
        on = chk.buffer_cell_expectation("loopbar", "on")
        dry = chk.buffer_cell_expectation("loopbar", "dry")
        self.assertEqual(off["blockValue"], {"enabled": False, "count": 0, "sites": []})
        self.assertEqual((off["pinShRc"], off["sameAsStock"], off["wipe"]), (4, True, "ABSENT"))
        self.assertEqual(off["lines"], [chk.nothing_line("loop.c")])
        self.assertEqual(on["blockValue"], {"enabled": True, "count": 1, "sites": [chk.BUFFER_SITE]})
        self.assertEqual((on["pinShRc"], on["repairCount"], on["sameAsStock"], on["wipe"], on["lines"],
                          on["controlSame"]), (0, 1, False, "PRESENT", [], True))
        self.assertEqual(dry["blockValue"], {"enabled": True, "count": 0, "sites": [chk.BUFFER_SITE]})
        self.assertEqual((dry["pinShRc"], dry["sameAsStock"], dry["wipe"], dry["dryRun"]), (4, True, "ABSENT", True))
        self.assertEqual(dry["lines"], [chk.dry_buffer_line(1)])
        self.assertEqual(chk.dry_buffer_line(1),
                         "WipePinGcc: dry run: 1 buffer barrier(s) would be placed; none was changed")

    def test_the_initialiser_gets_no_barrier_on_gcc(self):
        w = chk.buffer_cell_expectation("initbar", "on")
        self.assertEqual(w["blockValue"], {"enabled": True, "count": 0, "sites": []})
        self.assertEqual((w["pinShRc"], w["repairCount"], w["sameAsStock"], w["wipe"]), (4, 0, True, None))
        self.assertEqual(w["lines"], [chk.nothing_line("init.c")])

    def test_a_buffer_wiped_in_every_iteration_gets_its_barrier_and_no_initialiser_line(self):
        # The next iteration's uses come after the buffer's clobber: another
        # lifetime, so the wipe is a wipe and nothing is printed.
        w = chk.buffer_cell_expectation("inloop", "on")
        self.assertEqual(chk.BUFFER["inloop"]["modes"], ("on",))
        self.assertEqual(w["blockValue"], {"enabled": True, "count": 1, "sites": [chk.BUFFER_SITE]})
        self.assertEqual((w["pinShRc"], w["repairCount"], w["sameAsStock"], w["wipe"], w["controlSame"]),
                         (0, 1, False, "PRESENT", True))
        self.assertEqual(w["lines"], [])

    def test_an_initialiser_only_buffer_gets_no_barrier_and_one_line(self):
        w = chk.buffer_cell_expectation("initzero", "on")
        self.assertEqual(w["blockValue"], {"enabled": True, "count": 0, "sites": []})
        self.assertEqual((w["pinShRc"], w["repairCount"], w["sameAsStock"], w["wipe"], w["controlSame"]),
                         (4, 0, True, None, False))
        self.assertEqual(w["lines"], [chk.not_barriered_line(1), chk.nothing_line("initzero.c")])
        # The line the plugin prints, word for word (WipePin's wording, with
        # this plugin's prefix).
        self.assertEqual(chk.not_barriered_line(1),
                         "WipePinGcc: buffer barrier: 1 buffer(s) not barriered: every zero fill is followed "
                         "by a later use (read as an initialiser; a wipe that later code still touches, even "
                         "code the optimiser removes, is counted here too)")
        # The line the earlier rule printed for a barrier it did place is not
        # expected anywhere any more.
        for shape in chk.BUFFER_ORDER:
            for mode in chk.BUFFER[shape]["modes"]:
                for line in chk.buffer_cell_expectation(shape, mode)["lines"]:
                    self.assertNotIn("barrier site(s) are on buffers", line, f"{shape}-{mode}")

    def test_the_expected_records_are_ones_the_reader_accepts(self):
        for shape in chk.BUFFER_ORDER:
            for mode in chk.BUFFER[shape]["modes"]:
                w = chk.buffer_cell_expectation(shape, mode)
                rec = good_record(module=chk.BUFFER[shape]["module"], requested=["handle"],
                                  resolution=[{"name": "handle", "resolution": "resolved", "exact": True,
                                               "linkage": "external"}],
                                  pinned=[], pinnedCount=0, wouldPinCount=0, dryRun=w["dryRun"],
                                  seen={"zeroFillMemsetInScope": 0, "zeroFillMemsetInModule": 0},
                                  bufferBarriers=w["blockValue"])
                self.assertEqual(chk.wpr.validate(rec, w["expect"]), [], f"{shape}-{mode}")
                self.assertEqual(chk.wpr.repair_count(rec), w["repairCount"], f"{shape}-{mode}")

    def test_labels_are_renumbered_in_order_of_appearance(self):
        a = ["\tjne\t.L7", ".L7:", "\tjmp\t.L9", ".L9:"]
        b = ["\tjne\t.L3", ".L3:", "\tjmp\t.L4", ".L4:"]
        self.assertEqual(chk.canonical_labels(a), chk.canonical_labels(b))
        self.assertNotEqual(chk.canonical_labels(a), chk.canonical_labels(["\tjne\t.L3", ".L4:", "\tjmp\t.L4", ".L3:"]))
        # .LFB/.LFE and .LC are not plain numbered labels and stay as they are.
        self.assertEqual(chk.canonical_labels([".LFB0:", "\tleaq\t.LC0(%rip), %rdi"]), [".LFB0:", "\tleaq\t.LC0(%rip), %rdi"])


# The handle of switch/zcopyhdr-on.s, copied from a measured run (README.md,
# the switch cells; the .cfi lines cut): the copy from vg_zeros the barrier
# keeps. `other` is made up, to show the reading stops at the .size.
ZCOPY_ON = """\
handle:
.LFB14:
\t.cfi_startproc
\tendbr64
\tpushq\t%rbx
\tsubq\t$48, %rsp
\tmovq\t%rsp, %rbx
\tmovq\t%rbx, %rdi
\tcall\tderive@PLT
\tmovl\t$32, %esi
\tmovq\t%rbx, %rdi
\tcall\tuse@PLT
\tmovdqa\tvg_zeros(%rip), %xmm0
\tmovdqa\t16+vg_zeros(%rip), %xmm1
\tmovaps\t%xmm0, (%rsp)
\tmovaps\t%xmm1, 16(%rsp)
\taddq\t$48, %rsp
\tpopq\t%rbx
\tret
\t.cfi_endproc
.LFE14:
\t.size\thandle, .-handle
other:
\tmovdqa\tvg_zeros(%rip), %xmm0
\tmovaps\t%xmm0, (%rdi)
\t.size\tother, .-other
"""
ZCOPY_STOCK = ZCOPY_ON.replace("\tmovdqa\tvg_zeros(%rip), %xmm0\n\tmovdqa\t16+vg_zeros(%rip), %xmm1\n"
                               "\tmovaps\t%xmm0, (%rsp)\n\tmovaps\t%xmm1, 16(%rsp)\n", "", 1)


class ZcopyReading(unittest.TestCase):
    def test_the_kept_copy_is_two_loads_and_two_stores(self):
        self.assertEqual(chk.zcopy_reading(ZCOPY_ON, "handle", "vg_zeros"), {"loads": 2, "stores": 2, "calls": 0})

    def test_the_stock_listing_has_none_and_the_next_function_is_not_read(self):
        self.assertEqual(chk.zcopy_reading(ZCOPY_STOCK, "handle", "vg_zeros"), {"loads": 0, "stores": 0, "calls": 0})
        self.assertEqual(chk.zcopy_reading(ZCOPY_STOCK, "other", "vg_zeros")["stores"], 1)
        self.assertIsNone(chk.zcopy_reading(ZCOPY_ON, "nosuch", "vg_zeros"))

    def test_a_store_of_a_register_not_loaded_from_the_constant_is_not_a_copy(self):
        text = ZCOPY_ON.replace("\tmovaps\t%xmm1, 16(%rsp)\n", "\tmovaps\t%xmm2, 16(%rsp)\n")
        self.assertEqual(chk.zcopy_reading(text, "handle", "vg_zeros")["stores"], 1)
        # Another symbol's load does not count.
        self.assertEqual(chk.zcopy_reading(ZCOPY_ON, "handle", "zeros2"), {"loads": 0, "stores": 0, "calls": 0})

    def test_a_memcpy_call_counts_only_with_the_constants_address(self):
        call = "\tleaq\tvg_zeros(%rip), %rsi\n\tmovq\t%rbx, %rdi\n\tmovl\t$32, %edx\n\tcall\tmemcpy@PLT\n"
        text = ZCOPY_STOCK.replace("\tcall\tuse@PLT\n", "\tcall\tuse@PLT\n" + call, 1)
        self.assertEqual(chk.zcopy_reading(text, "handle", "vg_zeros")["calls"], 1)
        text = text.replace("leaq\tvg_zeros(%rip)", "leaq\tother(%rip)")
        self.assertEqual(chk.zcopy_reading(text, "handle", "vg_zeros")["calls"], 0)

    def test_either_reading_makes_the_wipe_present(self):
        absent = {"subject": {"verdict": "ABSENT", "via": "oracle"}}
        present = {"subject": {"verdict": "PRESENT", "via": "oracle"}}
        self.assertEqual(chk.wipe_reading(absent, ZCOPY_ON, "vg_zeros")[:2], ("PRESENT", "zcopy"))
        self.assertEqual(chk.wipe_reading(absent, ZCOPY_STOCK, "vg_zeros")[0], "ABSENT")
        self.assertEqual(chk.wipe_reading(present, ZCOPY_STOCK, "vg_zeros")[:2], ("PRESENT", "oracle"))
        # A barrier-call cell is the oracle's reading alone.
        self.assertEqual(chk.wipe_reading(absent, ZCOPY_ON, None), ("ABSENT", "oracle", None))


class Lines(unittest.TestCase):
    def test_every_expected_line_and_nothing_else(self):
        want = [chk.nothing_line("t.c")]
        self.assertEqual(chk.lines_problems(want, want), [])
        self.assertEqual(len(chk.lines_problems([], want)), 1)
        extra = chk.lines_problems(want + ["WipePinGcc: something else"], want)
        self.assertEqual(len(extra), 1)
        self.assertIn("unexpected", extra[0])

    def test_the_line_formats_are_the_plugins(self):
        # Copied from measured stderr (README.md, the shapes and the switch
        # cells): the wipe-pin-v3 plugin lists all nine unhandled counters.
        self.assertEqual(
            chk.partial_line(2, 1, "initwipe.c"),
            "WipePinGcc: partial: pinned 2 site(s) in initwipe.c; 1 followed by a later use of the same "
            "buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=0 memsetChk=0 "
            "nonZeroFill=0 atomicMemset=0 inlineWrapperMemset=0 bzeroCall=0 inlineWrapperBzero=0 "
            "zeroGlobalCopy=0 zeroGlobalCopyCall=0")
        self.assertEqual(chk.dry_line(1),
                         "WipePinGcc: dry run: 1 zero-fill memset site(s) would be pinned; none was changed")
        self.assertEqual(chk.dry_zero_copy_line(1),
                         "WipePinGcc: dry run: 1 copy(ies) from an all-zero constant would get a barrier; "
                         "none was changed")
        self.assertEqual(
            chk.nothing_line("chkvar.c", chk.unhandled_text(memsetChk=1)),
            "WipePinGcc: nothing to pin in scope in chkvar.c (zero-fill memset in scope: 0; unhandled in scope: "
            "libcallMemset=0 memsetChk=1 nonZeroFill=0 atomicMemset=0 inlineWrapperMemset=0 bzeroCall=0 "
            "inlineWrapperBzero=0 zeroGlobalCopy=0 zeroGlobalCopyCall=0)")

    def test_the_unhandled_list_is_the_records(self):
        self.assertEqual(set(chk.UNHANDLED_ORDER), chk.wpr.UNHANDLED_KEYS)
        self.assertEqual(len(chk.UNHANDLED_ORDER), 9)

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


# `objdump -d --no-show-raw-insn` of the xtu executables, copied from measured
# runs (README.md, the xtu cells): the pinned -flto link's handle, and the
# non-LTO link's handle and secure_wipe.
XTU_PINNED_HANDLE = """
0000000000001170 <handle>:
    1170:\tpush   %rbx
    1171:\tsub    $0x30,%rsp
    1175:\tmov    %fs:0x28,%rax
    117e:\tmov    %rax,0x28(%rsp)
    1183:\txor    %eax,%eax
    1185:\tmov    %rsp,%rbx
    1188:\tmov    %rbx,%rdi
    118b:\tcall   1230 <derive>
    1190:\tmov    $0x20,%esi
    1195:\tmov    %rbx,%rdi
    1198:\tcall   1250 <use>
    119d:\tpxor   %xmm0,%xmm0
    11a1:\tmovaps %xmm0,(%rsp)
    11a5:\tmovaps %xmm0,0x10(%rsp)
    11aa:\tmov    0x28(%rsp),%rax
    11af:\tsub    %fs:0x28,%rax
    11b8:\tjne    11c0 <handle+0x50>
    11ba:\tadd    $0x30,%rsp
    11be:\tpop    %rbx
    11bf:\tret
    11c0:\tcall   1050 <__stack_chk_fail@plt>

"""
XTU_STOCK_HANDLE = XTU_PINNED_HANDLE.replace(
    "    119d:\tpxor   %xmm0,%xmm0\n    11a1:\tmovaps %xmm0,(%rsp)\n    11a5:\tmovaps %xmm0,0x10(%rsp)\n", "")
XTU_NOLTO = """
0000000000001190 <handle>:
    1190:\tendbr64
    11af:\tcall   1260 <derive>
    11bc:\tcall   1280 <use>
    11c1:\tmov    $0x20,%esi
    11c6:\tmov    %rbx,%rdi
    11c9:\tcall   1250 <secure_wipe>
    11e3:\tret

0000000000001250 <secure_wipe>:
    1250:\tendbr64
    1254:\tmov    %rsi,%rdx
    1257:\txor    %esi,%esi
    1259:\tjmp    1070 <memset@plt>
    125e:\txchg   %ax,%ax

"""
# The first xtu fixture's pinned -flto link (secure_wipe with two callers):
# the helper kept out of line as an IPA-CP clone, the 32-byte fill in it.
XTU_CLONE = """
0000000000001170 <secure_wipe.constprop.0>:
    1170:\tpxor   %xmm0,%xmm0
    1174:\tmovups %xmm0,(%rdi)
    1177:\tmovups %xmm0,0x10(%rdi)
    117b:\tret

0000000000001180 <handle>:
    119b:\tcall   1220 <derive>
    11a8:\tcall   1240 <use>
    11ad:\tmov    %rbx,%rdi
    11b0:\tcall   1170 <secure_wipe.constprop.0>
    11ca:\tret

"""


class ObjdumpBranches(unittest.TestCase):
    def test_calls_and_tail_calls_with_plt_taken_off(self):
        self.assertEqual(of.objdump_branches(XTU_NOLTO, "secure_wipe"), [("jmp    1070 <memset@plt>", "memset")])
        self.assertEqual([t for _, t in of.objdump_branches(XTU_NOLTO, "handle")],
                         ["derive", "use", "secure_wipe"])

    def test_a_jump_inside_the_function_is_not_a_branch_to_one(self):
        text = XTU_PINNED_HANDLE.replace("jne    11c0 <handle+0x50>", "jmp    11c0 <handle+0x50>")
        self.assertIn("jmp    11c0 <handle+0x50>", text)
        targets = [t for _, t in of.objdump_branches(text, "handle")]
        self.assertEqual(targets, ["derive", "use", "__stack_chk_fail"])
        self.assertIsNone(of.objdump_branches(XTU_PINNED_HANDLE, "nosuch"))

    def test_renamed_copies_of_a_function(self):
        for t in ("secure_wipe", "secure_wipe.constprop.0", "secure_wipe.isra.0", "secure_wipe.lto_priv.0",
                  "secure_wipe.llvm.4242"):
            self.assertTrue(of.copy_of(t, "secure_wipe"), t)
        for t in ("secure_wipe2", "secure_wiper", "not_secure_wipe", "secure_wipe."):
            self.assertFalse(of.copy_of(t, "secure_wipe"), t)


class WipeReading(unittest.TestCase):
    def test_inlined_and_kept(self):
        r = of.wipe_reading(XTU_PINNED_HANDLE, "handle", "secure_wipe", 32)
        self.assertEqual((r["verdict"], r["inlined"], r["where"], r["bytes"]), ("PRESENT", True, "handle", 32))

    def test_inlined_and_gone(self):
        r = of.wipe_reading(XTU_STOCK_HANDLE, "handle", "secure_wipe", 32)
        self.assertEqual((r["verdict"], r["inlined"], r["where"], r["bytes"]), ("ABSENT", True, "handle", 0))

    def test_kept_out_of_line_and_read_in_the_helper(self):
        r = of.wipe_reading(XTU_NOLTO, "handle", "secure_wipe", 32)
        self.assertEqual((r["verdict"], r["inlined"], r["where"], r["memsetCalls"]),
                         ("PRESENT", False, "secure_wipe", 1))
        self.assertEqual(r["helperCalls"], ["call   1250 <secure_wipe>"])

    def test_a_renamed_clone_is_not_inlined(self):
        r = of.wipe_reading(XTU_CLONE, "handle", "secure_wipe", 32)
        self.assertEqual((r["verdict"], r["inlined"], r["where"], r["bytes"]),
                         ("PRESENT", False, "secure_wipe.constprop.0", 32))

    def test_half_a_fill_is_partial(self):
        text = XTU_PINNED_HANDLE.replace("    11a5:\tmovaps %xmm0,0x10(%rsp)\n", "")
        self.assertEqual(of.wipe_reading(text, "handle", "secure_wipe", 32)["verdict"], "PARTIAL")

    def test_nothing_to_read(self):
        self.assertEqual(of.wipe_reading(XTU_PINNED_HANDLE, "nosuch", "secure_wipe", 32)["verdict"], "NOT_OBSERVED")
        # The call is there, and what it calls is not in the output.
        text = XTU_NOLTO.split("0000000000001250 <secure_wipe>:")[0]
        r = of.wipe_reading(text, "handle", "secure_wipe", 32)
        self.assertEqual((r["verdict"], r["inlined"]), ("NOT_OBSERVED", False))

    def test_a_fill_of_its_own(self):
        r = of.wipe_reading(XTU_PINNED_HANDLE, "handle", None, 32)
        self.assertEqual((r["verdict"], r["inlined"], r["where"]), ("PRESENT", None, "handle"))
        self.assertEqual(of.describe(r), "PRESENT in handle (2 store(s)/32B)")


class ReadingProblems(unittest.TestCase):
    def read(self, text):
        return (of.wipe_reading(text, "handle", "secure_wipe", 32), of.wipe_reading(XTU_PINNED_HANDLE, "handle", None, 32))

    def test_every_measured_cell_reads_as_its_expectation(self):
        for text, exp in ((XTU_NOLTO, chk.XTU["xtu-nolto"]), (XTU_STOCK_HANDLE, chk.XTU["xtu-lto-stock"]),
                          (XTU_PINNED_HANDLE, chk.XTU["xtu-lto-pin"]), (XTU_STOCK_HANDLE, chk.XTU["xtu-lto-dry"])):
            s, c = self.read(text)
            self.assertEqual(of.reading_problems(s, c, exp["inlined"], exp["subject"], "handle", "secure_wipe"), [])

    def test_a_helper_left_out_of_line_says_so_rather_than_passing(self):
        s, c = self.read(XTU_CLONE)
        bad = of.reading_problems(s, c, True, "PRESENT", "handle", "secure_wipe")
        self.assertEqual(len(bad), 1, bad)
        self.assertIn("was not inlined into handle", bad[0])

    def test_the_stock_link_where_the_pin_should_be(self):
        s, c = self.read(XTU_STOCK_HANDLE)
        bad = of.reading_problems(s, c, True, "PRESENT", "handle", "secure_wipe")
        self.assertEqual(bad, ["subject ABSENT in handle (0 store(s)/0B), expected PRESENT"])

    def test_an_inlined_helper_where_it_must_be_opaque(self):
        s, c = self.read(XTU_STOCK_HANDLE)
        bad = of.reading_problems(s, c, False, "PRESENT", "handle", "secure_wipe")
        self.assertTrue(any("was inlined into handle" in b for b in bad), bad)

    def test_a_blind_control(self):
        s = of.wipe_reading(XTU_PINNED_HANDLE, "handle", "secure_wipe", 32)
        c = of.wipe_reading(XTU_STOCK_HANDLE, "handle", None, 32)
        bad = of.reading_problems(s, c, True, "PRESENT", "handle", "secure_wipe")
        self.assertEqual(len(bad), 1, bad)
        self.assertIn("the reading is blind", bad[0])


class ObjectKind(unittest.TestCase):
    def test_the_four_kinds_and_a_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            files = {"bitcode": b"BC\xc0\xde\x35\x14\x00\x00", "gcc-lto": b"\x7fELF\x02\x01\x01\x00.gnu.lto_.opts\x00",
                     "elf": b"\x7fELF\x02\x01\x01\x00.text\x00", "other": b"!<arch>\n"}
            for kind, data in files.items():
                p = os.path.join(d, kind + ".o")
                with open(p, "wb") as f:
                    f.write(data)
                self.assertEqual(of.object_kind(p), kind)
            self.assertIsNone(of.object_kind(os.path.join(d, "nosuch.o")))


class XtuTables(unittest.TestCase):
    def test_every_xtu_cell_has_an_expectation(self):
        for m in (chk, llvm_chk):
            self.assertEqual(sorted(m.XTU_ORDER), sorted(m.XTU), m.__name__)
            self.assertEqual(m.XTU_ORDER[0], "xtu-nolto", m.__name__)
            self.assertEqual(m.XTU_FILL_BYTES, 32, m.__name__)
        self.assertEqual(len(chk.XTU_ORDER), 4)
        self.assertEqual(len(llvm_chk.XTU_ORDER), 7)

    def test_both_loops_expect_the_same_thing_of_each_mode(self):
        for m in (chk, llvm_chk):
            for cell, exp in m.XTU.items():
                lto = exp["form"] != "none"
                # Without LTO the helper stays out of line; every LTO link inlines it.
                self.assertIs(exp["inlined"], lto, cell)
                want = {"stock": "ABSENT" if lto else "PRESENT", "pin": "PRESENT", "dry": "ABSENT"}[exp["mode"]]
                self.assertEqual(exp["subject"], want, cell)
                self.assertIs(exp["sameAsStock"], {"stock": None, "pin": False, "dry": True}[exp["mode"]], cell)
                if exp["mode"] != "stock":
                    self.assertEqual((exp["pinnedCount"], exp["wouldPinCount"], exp["dryRun"]),
                                     (0, 1, True) if exp["mode"] == "dry" else (1, 1, False), cell)
                    self.assertEqual(len(exp["lines"]), 1 if exp["mode"] == "dry" else 0, cell)
                    if lto:
                        self.assertIn(f"xtu-{exp['form']}-stock", m.XTU, cell)

    def test_the_site_is_the_helpers_parameter_in_both_records(self):
        # The same site on both vendors; only GCC has a line without -g.
        self.assertEqual({k: v for k, v in chk.XTU_SITE.items() if k != "line"},
                         {k: v for k, v in llvm_chk.XTU_SITE.items() if k != "line"})
        self.assertEqual((chk.XTU_SITE["line"], llvm_chk.XTU_SITE["line"]), (3, None))
        self.assertEqual(chk.XTU_SITE["destKind"], "argument")
        self.assertIsNone(chk.XTU_SITE["followedByUse"])
        self.assertEqual(chk.XTU_RESOLUTION, llvm_chk.XTU_RESOLUTION)


def xtu_record(**over):
    """A WipePinGcc record shaped like the one xtu-lto-pin measured."""
    rec = dict(module="wipe.c", requested=["secure_wipe"],
               resolution=[{"name": "secure_wipe", "resolution": "resolved", "exact": True, "linkage": "external"}],
               pinned=[dict(chk.XTU_SITE)], seen={"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 1})
    rec.update(over)
    return good_record(**rec)


class XtuRecord(unittest.TestCase):
    def test_the_pin_and_dry_records(self):
        self.assertEqual(chk.xtu_record_problems(xtu_record(), chk.XTU["xtu-lto-pin"]), [])
        dry = xtu_record(dryRun=True, pinnedCount=0)
        self.assertEqual(chk.xtu_record_problems(dry, chk.XTU["xtu-lto-dry"]), [])
        bad = chk.xtu_record_problems(dry, chk.XTU["xtu-lto-pin"])
        self.assertTrue(any("dryRun" in b for b in bad) and any("pinnedCount" in b for b in bad), bad)

    def test_a_site_that_is_not_the_helpers_parameter(self):
        site = dict(chk.XTU_SITE, destKind="alloca", followedByUse=False, lengthBytes=32)
        bad = chk.xtu_record_problems(xtu_record(pinned=[site]), chk.XTU["xtu-lto-pin"])
        self.assertEqual(len(bad), 1, bad)
        self.assertTrue(bad[0].startswith("record pinned = "), bad)

    def test_another_unit(self):
        bad = chk.xtu_record_problems(xtu_record(module="use.c"), chk.XTU["xtu-lto-pin"])
        self.assertEqual(bad, ["record module = 'use.c', expected 'wipe.c'"])


# `llvm-bcanalyzer-18 -dump` of wipe.o from the WipePin loop's xtu cells, cut to
# the lines that open and close a block and the summary block in full, copied
# from measured runs (../../llvm-repair/README.md, the xtu cells): a -flto=thin
# object and a -flto object. The thin one without its summary block stands for
# a plain -O2 -emit-llvm -c compile of the same source, whose dump has none.
THIN_DUMP = """<IDENTIFICATION_BLOCK_ID NumWords=5 BlockCodeSize=5>
</IDENTIFICATION_BLOCK_ID>
<MODULE_BLOCK NumWords=548 BlockCodeSize=3>
  <TYPE_BLOCK_ID NumWords=14 BlockCodeSize=4>
  </TYPE_BLOCK_ID>
  <UnknownBlock26 NumWords=6 BlockCodeSize=2>
  </UnknownBlock26>
  <FUNCTION_BLOCK NumWords=8 BlockCodeSize=4>
    <CONSTANTS_BLOCK NumWords=2 BlockCodeSize=4>
    </CONSTANTS_BLOCK>
  </FUNCTION_BLOCK>
  <GLOBALVAL_SUMMARY_BLOCK NumWords=18 BlockCodeSize=4>
    <VERSION op0=9/>
    <FLAGS op0=0/>
    <PERMODULE_PROFILE abbrevid=4 op0=0 op1=64 op2=2 op3=68 op4=0 op5=0 op6=0/> record string = ''
  </GLOBALVAL_SUMMARY_BLOCK>
  <VALUE_SYMTAB NumWords=3 BlockCodeSize=4>
  </VALUE_SYMTAB>
</MODULE_BLOCK>
<SYMTAB_BLOCK NumWords=37 BlockCodeSize=3>
</SYMTAB_BLOCK>
<STRTAB_BLOCK NumWords=27 BlockCodeSize=3>
</STRTAB_BLOCK>
"""
FULL_DUMP = (THIN_DUMP.replace("NumWords=548", "NumWords=546")
             .replace("GLOBALVAL_SUMMARY_BLOCK", "FULL_LTO_GLOBALVAL_SUMMARY_BLOCK")
             .replace("<FLAGS op0=0/>", "<FLAGS op0=8/>").replace("op1=64 op2=2", "op1=80 op2=2"))
NO_SUMMARY_DUMP = THIN_DUMP.split("  <GLOBALVAL_SUMMARY_BLOCK")[0] + THIN_DUMP.split("</GLOBALVAL_SUMMARY_BLOCK>\n")[1]

# The .comment of the xtu executables (readelf -p .comment): linked by lld, and
# by GNU ld when the runner's -fuse-ld=lld is taken out.
LLD_COMMENT = (b"\0GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0\0Ubuntu clang version 18.1.3 (1ubuntu1)\0"
               b"Linker: Ubuntu LLD 18.1.3\0")
GNU_LD_COMMENT = b"GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0\0Ubuntu clang version 18.1.3 (1ubuntu1)\0"
LLD_STRINGS = ["GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0", "Ubuntu clang version 18.1.3 (1ubuntu1)",
               "Linker: Ubuntu LLD 18.1.3"]


def elf64(sections):
    """A 64-bit little-endian ELF file whose section header table holds a null
    section, .shstrtab and `sections` ({name: bytes}), and nothing else."""
    order = [".shstrtab"] + list(sections)
    names, name_at = b"\0", {}
    for n in order:
        name_at[n] = len(names)
        names += n.encode() + b"\0"
    blobs = {".shstrtab": names, **sections}
    data, at = bytearray(64), {}
    for n in order:
        at[n] = len(data)
        data += blobs[n]
    data += bytes(-len(data) % 8)
    shoff = len(data)
    data += bytes(64)
    for n in order:
        # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize
        data += struct.pack("<IIQQQQIIQQ", name_at[n], 1, 0, 0, at[n], len(blobs[n]), 0, 0, 1, 0)
    struct.pack_into("<4sBBBB8x", data, 0, b"\x7fELF", 2, 1, 1, 0)
    # e_type .. e_shstrndx; e_shoff at 0x28, e_shentsize/e_shnum/e_shstrndx at 0x3a
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(order) + 1, 1)
    return bytes(data)


class LlvmXtuBuild(unittest.TestCase):
    """How the WipePin loop's xtu cells were built, read by its checker from the
    objects and the executable rather than from the runner's form=."""

    def test_the_summary_block_is_the_form(self):
        self.assertEqual(llvm_chk.summary_forms(THIN_DUMP), ["thin"])
        self.assertEqual(llvm_chk.summary_forms(FULL_DUMP), ["full"])
        self.assertEqual(llvm_chk.summary_forms(NO_SUMMARY_DUMP), [])
        self.assertIn("<FUNCTION_BLOCK", NO_SUMMARY_DUMP)

    def test_only_a_line_that_opens_a_block_counts(self):
        text = ("  </GLOBALVAL_SUMMARY_BLOCK>\n"
                "  <FLAGS op0=0/> record string = '<GLOBALVAL_SUMMARY_BLOCK NumWords=1 BlockCodeSize=4>'\n")
        self.assertEqual(llvm_chk.summary_forms(text), [])

    def test_a_reader_that_cannot_run_says_so_without_a_path(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError) as cm:
                llvm_chk.lto_form(os.path.join(d, "wipe.o"), bcanalyzer=os.path.join(d, "no-such-bcanalyzer"))
        self.assertEqual(str(cm.exception), "no-such-bcanalyzer could not run: FileNotFoundError")

    def test_the_comment_section(self):
        with tempfile.TemporaryDirectory() as d:
            def write(name, data):
                p = os.path.join(d, name)
                with open(p, "wb") as f:
                    f.write(data)
                return p
            lld = llvm_chk.elf_comment(write("lld", elf64({".text": b"\xc3", ".comment": LLD_COMMENT})))
            self.assertEqual(lld, LLD_STRINGS)
            self.assertEqual(llvm_chk.linkers(lld), ["Ubuntu LLD 18.1.3"])
            gnu = llvm_chk.elf_comment(write("ld", elf64({".comment": GNU_LD_COMMENT})))
            self.assertEqual(gnu, LLD_STRINGS[:2])
            self.assertEqual(llvm_chk.linkers(gnu), [])
            self.assertEqual(llvm_chk.elf_comment(write("nocomment", elf64({".text": b"\xc3"}))), [])
            self.assertIsNone(llvm_chk.elf_comment(write("bitcode", b"BC\xc0\xde\x35\x14\x00\x00")))
            self.assertIsNone(llvm_chk.elf_comment(write("cut", elf64({".comment": LLD_COMMENT})[:80])))
            self.assertIsNone(llvm_chk.elf_comment(os.path.join(d, "nosuch")))

    @staticmethod
    def build(cell, forms=None, io="elf", comment=LLD_STRINGS, helper=None):
        """xtu_build_problems for `cell`, with everything not given as that
        cell was measured."""
        exp = llvm_chk.XTU[cell]
        lto = exp["form"] != "none"
        k = "bitcode" if lto else "elf"
        kinds = {"main": k, "use": k, "wipe": k, "io": io}
        if forms is None:
            forms = {u: exp["form"] for u in llvm_chk.XTU_LTO_UNITS} if lto else {}
        if helper is None:
            helper = llvm_chk.XTU_HELPER_DEFINED[exp["form"]]
        return llvm_chk.xtu_build_problems(exp, kinds, forms, comment, helper)

    def test_every_cell_built_as_it_is_named(self):
        for cell in llvm_chk.XTU:
            self.assertEqual(self.build(cell), [], cell)

    def test_thin_cells_built_as_full_lto(self):
        # The review's finding: thin compiled and linked as plain -flto.
        forms = {u: "full" for u in llvm_chk.XTU_LTO_UNITS}
        for m in ("stock", "pin", "dry"):
            self.assertEqual(self.build(f"xtu-thin-{m}", forms=forms, helper=False),
                             ["main.o, use.o, wipe.o: a full module summary, expected a thin module summary: "
                              "the cell was not built as the LTO form it is named for",
                              "the executable does not define secure_wipe, which a ThinLTO link of these units "
                              "keeps (measured): not the output of the link this cell is named for"])

    def test_one_object_of_the_other_form_or_with_none(self):
        bad = self.build("xtu-full-stock", forms={"main": "full", "use": "full", "wipe": "thin"})
        self.assertEqual(len(bad), 1, bad)
        self.assertTrue(bad[0].startswith("wipe.o: a thin module summary, expected a full module summary"), bad)
        bad = self.build("xtu-full-stock", forms={"main": "full", "use": "no summary", "wipe": "full"})
        self.assertTrue(len(bad) == 1 and bad[0].startswith("use.o: no module summary, expected"), bad)

    def test_objects_of_the_wrong_kind(self):
        bad = llvm_chk.xtu_build_problems(llvm_chk.XTU["xtu-nolto"],
                                          {"main": "bitcode", "use": "bitcode", "wipe": "bitcode", "io": "elf"},
                                          {u: "full" for u in llvm_chk.XTU_LTO_UNITS}, LLD_STRINGS, True)
        self.assertEqual(bad, [f"{u}.o is bitcode, expected elf" for u in llvm_chk.XTU_LTO_UNITS])
        bad = self.build("xtu-thin-pin", io="bitcode")
        self.assertEqual(len(bad), 1, bad)
        self.assertTrue(bad[0].startswith("io.o is bitcode, expected elf"), bad)

    def test_an_executable_that_lld_did_not_link(self):
        bad = self.build("xtu-full-pin", comment=LLD_STRINGS[:2])
        self.assertEqual(len(bad), 1, bad)
        self.assertTrue(bad[0].startswith("the executable's .comment names no linker"), bad)
        bad = self.build("xtu-full-pin", comment=LLD_STRINGS[:2] + ["Linker: other 1.0"])
        self.assertEqual(bad, ["the executable's .comment names the linker ['other 1.0'], expected lld"])

    def test_the_executable_of_the_other_link(self):
        # The measured executables: a ThinLTO link keeps secure_wipe, called
        # from nowhere; a full-LTO link leaves none.
        self.assertIsNotNone(of.objdump_body(LLVM_THIN_STOCK, "secure_wipe"))
        self.assertEqual(of.objdump_branches(LLVM_THIN_STOCK, "handle"),
                         [("call   17c0 <derive>", "derive"), ("call   17e0 <use>", "use")])
        self.assertIsNone(of.objdump_body(LLVM_FULL_STOCK, "secure_wipe"))
        # A full cell holding the thin link's executable, and the other way round.
        bad = self.build("xtu-full-stock", helper=True)
        self.assertEqual(bad, ["the executable defines secure_wipe, which a full-LTO link of these units drops "
                               "(measured): not the output of the link this cell is named for"])
        self.assertEqual(len(self.build("xtu-thin-dry", helper=False)), 1)
        self.assertEqual(self.build("xtu-nolto", helper=True), [])


# `objdump -d --no-show-raw-insn` of the WipePin loop's xtu-thin-stock and
# xtu-full-stock executables, copied from a measured run (the int3 padding after
# each ret cut): handle, and the helper the thin link keeps.
LLVM_THIN_STOCK = """
0000000000001870 <handle>:
    1870:\tpush   %rbx
    1871:\tsub    $0x20,%rsp
    1875:\tmov    %rsp,%rbx
    1878:\tmov    %rbx,%rdi
    187b:\tcall   17c0 <derive>
    1880:\tmov    $0x20,%esi
    1885:\tmov    %rbx,%rdi
    1888:\tcall   17e0 <use>
    188d:\tadd    $0x20,%rsp
    1891:\tpop    %rbx
    1892:\tret

00000000000018d0 <secure_wipe>:
    18d0:\tmov    %rsi,%rdx
    18d3:\txor    %esi,%esi
    18d5:\tjmp    1930 <memset@plt>

"""
LLVM_FULL_STOCK = """
0000000000001810 <handle>:
    1810:\tpush   %rbx
    1811:\tsub    $0x20,%rsp
    1815:\tmov    %rsp,%rbx
    1818:\tmov    %rbx,%rdi
    181b:\tcall   1760 <derive>
    1820:\tmov    $0x20,%esi
    1825:\tmov    %rbx,%rdi
    1828:\tcall   1780 <use>
    182d:\tadd    $0x20,%rsp
    1831:\tpop    %rbx
    1832:\tret

"""


if __name__ == "__main__":
    unittest.main()
