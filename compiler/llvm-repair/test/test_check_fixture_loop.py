#!/usr/bin/env python3
"""Unit tests for the wipe-pin-v3 grading logic of
scripts/check-fixture-loop.py that does not need a lab: the record checks
(record_problems and the block, host and compile checks it is built from),
the v3 expectation tables and the runner lines that run them, and the grading
of every kind of v3 cell (the four-arm cells, the initialiser, the pin.sh-alone
cells, the refusals, the handshake), of one loop cell and of one shape cell, on
small synthetic labs written into a temporary directory.

    python3 compiler/llvm-repair/test/test_check_fixture_loop.py

The four-arm cells read their executables through objdump. Here no compiler or
objdump runs: each executable is a file of synthetic `objdump -d` text, read by
a stand-in for objdump_fill.disassemble, and objdump_fill's reading of that
text is its own. Each check is shown failing on an input that, as far as
possible, no other check refuses, so that a check weakened on its own fails a
test here rather than only on a broken lab.

Every record here is synthetic, built in this file and sealed with the
checker's own digest_of; no fixture source, record or executable is kept in
this tree. The checker's behaviour on a real lab, and on deliberately broken
copies of one, is measured in README.md ("The checker was shown to fail").
The xtu helpers the GCC loop shares are tested in
../../gcc-repair/test/test_check_gcc_fixture_loop.py.
"""

import copy
import importlib.util
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")

_spec = importlib.util.spec_from_file_location("check_fixture_loop", os.path.join(SCRIPTS, "check-fixture-loop.py"))
chk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chk)

RUNNER = os.path.join(SCRIPTS, "run-fixture-loop.sh")


def seal(rec):
    rec["evidenceDigest"] = chk.digest_of(rec)
    return rec


def toolchain(version="18.1.3"):
    pkgs = [{"name": "llvm", "version": version}]
    return {"clang": version, "packages": pkgs,
            "digest": chk.sha256_text(chk.canonical({"clang": version, "packages": pkgs}))}


def good_record(module="memset.c", **blocks):
    """A wipe-pin-v3 record with the three switches off, as WipePin writes one
    for a compile of `handle` that pinned nothing. Keyword arguments replace
    whole top-level values before the record is sealed."""
    rec = {
        "schemaVersion": "wipe-pin-v3",
        "component": "WipePin",
        "module": module,
        "toolchain": toolchain(),
        "optLevel": {"speedup": 2, "size": 0},
        "scope": "functions",
        "requested": ["handle"],
        "resolution": [{"name": "handle", "resolution": "resolved", "exact": True, "linkage": "external"}],
        "dryRun": False,
        "pinned": [],
        "pinnedCount": 0,
        "wouldPinCount": 0,
        "seen": {"zeroFillMemsetInScope": 0, "zeroFillMemsetInModule": 0},
        "unhandled": {k: 0 for k in chk.UNHANDLED_KEYS},
        "barrierCalls": {"enabled": False, "sites": [], "barrierCount": 0, "wouldBarrierCount": 0},
        "zeroCopy": {"enabled": False, "sites": [], "repairedCount": 0, "wouldRepairCount": 0},
        "bufferBarriers": {"enabled": False, "count": 0, "sites": []},
        "host": {"ident": "Ubuntu clang version 18.1.3", "identMajor": 18, "builtMajor": 18, "checked": True,
                 "intrinsicsCompared": 3},
        "evidenceDigest": "",
        "context": {"timeSource": "wall-clock", "sourceDateEpoch": None, "generatedAt": 0},
    }
    rec.update(copy.deepcopy(blocks))
    return seal(rec)


def buffer_site(anchor="lifetime-end", bytes_=32, reason="loop-store", buffer=None, function="handle"):
    return {"function": function, "buffer": buffer, "bytes": bytes_, "reason": reason, "anchor": anchor}


def edited(rec, fn, reseal=True):
    out = copy.deepcopy(rec)
    fn(out)
    return seal(out) if reseal else out


class RecordProblems(unittest.TestCase):
    def test_a_good_record_has_none(self):
        self.assertEqual(chk.record_problems(good_record()), [])
        self.assertEqual(chk.v3_problems(good_record()), [])

    def test_not_an_object(self):
        self.assertTrue(chk.record_problems(["wipe-pin-v3"]))

    def test_an_unknown_or_missing_top_level_key(self):
        self.assertTrue(any("S1" in p for p in chk.record_problems(edited(good_record(),
                                                                         lambda r: r.update(extra=1)))))
        self.assertTrue(any("S1" in p for p in chk.record_problems(edited(good_record(),
                                                                         lambda r: r.pop("host")))))

    def test_a_v2_record_is_refused(self):
        rec = edited(good_record(), lambda r: r.update(schemaVersion="wipe-pin-v2"))
        self.assertTrue(any("schemaVersion" in p for p in chk.record_problems(rec)))

    def test_another_component(self):
        rec = edited(good_record(), lambda r: r.update(component="WipePinGcc"))
        self.assertTrue(any("component" in p for p in chk.record_problems(rec)))

    def test_the_toolchain_digest_is_re_derived(self):
        rec = edited(good_record(), lambda r: r["toolchain"].update(digest="0" * 64))
        self.assertTrue(any("toolchain.digest" in p for p in chk.record_problems(rec)))

    def test_an_unresealed_edit_fails_the_evidence_digest(self):
        rec = edited(good_record(), lambda r: r.update(pinnedCount=1), reseal=False)
        self.assertIn("evidenceDigest does not re-derive", chk.record_problems(rec))
        # the context is outside the digest
        rec = edited(good_record(), lambda r: r.update(context={"generatedAt": 1}), reseal=False)
        self.assertEqual(chk.record_problems(rec), [])

    def test_unhandled_must_be_the_nine_counters_as_counts(self):
        rec = edited(good_record(), lambda r: r["unhandled"].pop("bzeroCall"))
        self.assertTrue(any("S2" in p for p in chk.record_problems(rec)))
        for bad in (-1, True, 1.5, None):
            rec = edited(good_record(), lambda r: r["unhandled"].update(memsetChk=bad))
            self.assertTrue(any("memsetChk" in p for p in chk.record_problems(rec)), bad)

    def test_an_absolute_path_outside_the_context(self):
        rec = edited(good_record(), lambda r: r.update(module="/" + "tmp/x.c"))
        self.assertTrue(any("absolute path" in p for p in chk.record_problems(rec)))
        rec = edited(good_record(), lambda r: r["context"].update(where="/" + "tmp"), reseal=False)
        self.assertEqual(chk.record_problems(rec), [])

    def test_followed_by_use_is_null_exactly_when_the_destination_is_not_an_alloca(self):
        site = {"function": "handle", "index": 0, "lengthBytes": 32, "destKind": "alloca", "alreadyVolatile": False,
                "followedByUse": None, "line": None}
        self.assertTrue(chk.record_problems(good_record(pinned=[site], pinnedCount=1, wouldPinCount=1)))
        site.update(destKind="argument", followedByUse=False)
        self.assertTrue(chk.record_problems(good_record(pinned=[site], pinnedCount=1, wouldPinCount=1)))
        site.update(followedByUse=None)
        self.assertEqual(chk.record_problems(good_record(pinned=[site], pinnedCount=1, wouldPinCount=1)), [])

    def test_a_resolved_name_needs_exact_and_linkage(self):
        rec = edited(good_record(), lambda r: r["resolution"][0].update(exact=None))
        self.assertTrue(chk.record_problems(rec))
        rec = edited(good_record(), lambda r: r["resolution"][0].update(resolution="not-in-module"))
        self.assertTrue(chk.record_problems(rec))

    def test_toolchain_packages_is_a_list_of_name_and_version(self):
        # the digest is re-derived from these packages, so only the shape is wrong
        for pkgs in ([{"name": "llvm"}], [{"name": "llvm", "version": "18.1.3", "arch": "amd64"}], ["llvm"], "llvm"):
            tc = {"clang": "18.1.3", "packages": pkgs,
                  "digest": chk.sha256_text(chk.canonical({"clang": "18.1.3", "packages": pkgs}))}
            probs = chk.record_problems(good_record(toolchain=tc))
            self.assertTrue(any("toolchain.packages" in p for p in probs), (pkgs, probs))

    def test_followed_by_use_is_true_false_or_null(self):
        site = {"function": "handle", "index": 0, "lengthBytes": 32, "destKind": "alloca", "alreadyVolatile": False,
                "followedByUse": "yes", "line": None}
        no_key = {k: v for k, v in site.items() if k != "followedByUse"}
        no_key["destKind"] = "argument"
        # 1, 0 and 1.0 compare equal to True/False under `in`; they are not booleans
        numeric = [dict(site, followedByUse=v) for v in (1, 0, 1.0)]
        for s in [site, no_key] + numeric:
            probs = chk.record_problems(good_record(pinned=[s], pinnedCount=1, wouldPinCount=1))
            self.assertTrue(any("true/false/null" in p for p in probs), (s, probs))


class CallAndCopyBlocks(unittest.TestCase):
    def barrier(self, **kw):
        b = {"enabled": True, "sites": [{"function": "handle", "callee": "memset.inline", "lengthBytes": 32,
                                         "line": None}], "barrierCount": 1, "wouldBarrierCount": 1}
        b.update(kw)
        return b

    def test_a_repaired_call_passes(self):
        self.assertEqual(chk.record_problems(good_record(barrierCalls=self.barrier())), [])

    def test_off_with_sites_or_counts_is_C1(self):
        rec = good_record(barrierCalls=self.barrier(enabled=False))
        self.assertTrue(any("C1" in p for p in chk.record_problems(rec)))

    def test_the_would_count_is_the_number_of_sites(self):
        rec = good_record(barrierCalls=self.barrier(wouldBarrierCount=2, barrierCount=2))
        self.assertTrue(any("C2/C3" in p for p in chk.record_problems(rec)))

    def test_a_dry_run_repairs_nothing(self):
        rec = good_record(dryRun=True, barrierCalls=self.barrier())
        self.assertTrue(any("C2/C3" in p for p in chk.record_problems(rec)))
        rec = good_record(dryRun=True, barrierCalls=self.barrier(barrierCount=0))
        self.assertEqual(chk.record_problems(rec), [])

    def test_the_callee_value_set(self):
        for callee in ("memcpy", "explicit_bzero", ""):
            b = self.barrier()
            b["sites"][0]["callee"] = callee
            self.assertTrue(any("C7" in p for p in chk.record_problems(good_record(barrierCalls=b))), callee)

    def test_a_site_in_a_function_not_requested_is_C5(self):
        b = self.barrier()
        b["sites"][0]["function"] = "wipe_kept"
        self.assertTrue(any("C5" in p for p in chk.record_problems(good_record(barrierCalls=b))))

    def test_the_zero_copy_form_and_callee_pair(self):
        site = {"function": "handle", "form": "intrinsic", "callee": "llvm.memcpy", "source": "vg_zeros",
                "destKind": "alloca", "lengthBytes": 32, "line": None}
        z = {"enabled": True, "sites": [site], "repairedCount": 1, "wouldRepairCount": 1}
        self.assertEqual(chk.record_problems(good_record(zeroCopy=z)), [])
        for form, callee in (("intrinsic", "memcpy"), ("intrinsic", "llvm.memcpy.inline"), ("call", "llvm.memcpy"),
                             ("inline", "llvm.memcpy")):
            bad = copy.deepcopy(z)
            bad["sites"][0].update(form=form, callee=callee)
            self.assertTrue(chk.record_problems(good_record(zeroCopy=bad)), (form, callee))

    def zero(self, **kw):
        site = {"function": "handle", "form": "intrinsic", "callee": "llvm.memcpy", "source": "vg_zeros",
                "destKind": "alloca", "lengthBytes": 32, "line": None}
        site.update(kw)
        return {"enabled": True, "sites": [site], "repairedCount": 1, "wouldRepairCount": 1}

    def test_a_barrier_sites_length_is_a_count_or_null(self):
        for n in (-1, "32", 32.0, True):
            b = self.barrier()
            b["sites"][0]["lengthBytes"] = n
            probs = chk.record_problems(good_record(barrierCalls=b))
            self.assertTrue(any("barrierCalls site lengthBytes" in p for p in probs), (n, probs))

    def test_the_zero_copy_site_value_sets(self):
        # a form outside the two is given a callee that the form would pair with,
        # so that the form check is the one that refuses it
        for kw, field in ((dict(form="inline", callee="memcpy"), "form"), (dict(form="", callee="memcpy"), "form"),
                          (dict(destKind="stack"), "destKind"), (dict(destKind=None), "destKind"),
                          (dict(source=None), "source"), (dict(source=7), "source"),
                          (dict(lengthBytes=-1), "lengthBytes"), (dict(line="12"), "line")):
            probs = chk.record_problems(good_record(zeroCopy=self.zero(**kw)))
            self.assertTrue(any(f"zeroCopy site {field} is" in p for p in probs), (kw, probs))

    def test_each_call_block_has_exactly_its_four_keys(self):
        for name, blk in (("barrierCalls", self.barrier()), ("zeroCopy", self.zero()),
                          ("barrierCalls", good_record()["barrierCalls"]), ("zeroCopy", good_record()["zeroCopy"])):
            for bad in (dict(blk, note="x"), {k: v for k, v in blk.items() if k != "enabled"}):
                probs = chk.record_problems(good_record(**{name: bad}))
                self.assertTrue(any(f"{name} keys are not" in p for p in probs), (name, bad, probs))

    def test_enabled_is_a_boolean(self):
        # 0 and 1 compare equal to False and True, so no other check refuses these
        for name, blk in (("barrierCalls", {"enabled": 0, "sites": [], "barrierCount": 0, "wouldBarrierCount": 0}),
                          ("barrierCalls", self.barrier(enabled=1)),
                          ("zeroCopy", {"enabled": 0, "sites": [], "repairedCount": 0, "wouldRepairCount": 0}),
                          ("zeroCopy", dict(self.zero(), enabled="true")),
                          ("bufferBarriers", {"enabled": 0, "count": 0, "sites": []})):
            probs = chk.record_problems(good_record(**{name: blk}))
            self.assertTrue(any(f"{name}.enabled is not a boolean" in p for p in probs), (blk, probs))

    def test_the_counts_are_integers_not_booleans_or_floats(self):
        for name, blk, key in (("barrierCalls", self.barrier(barrierCount=1.0), "barrierCount"),
                               ("barrierCalls", self.barrier(wouldBarrierCount=True), "wouldBarrierCount"),
                               ("zeroCopy", dict(self.zero(), repairedCount=True), "repairedCount"),
                               ("zeroCopy", {"enabled": False, "sites": [], "repairedCount": 0,
                                             "wouldRepairCount": False}, "wouldRepairCount"),
                               ("bufferBarriers", {"enabled": True, "count": 1.0, "sites": [buffer_site()]}, "count")):
            probs = chk.record_problems(good_record(**{name: blk}))
            self.assertTrue(any(f"{name}.{key} is not an integer" in p for p in probs), (blk, probs))


class BufferBlock(unittest.TestCase):
    def on(self, *sites, count=None):
        return {"enabled": True, "count": len(sites) if count is None else count, "sites": list(sites)}

    def test_placed_barriers_pass(self):
        for blk in (self.on(), self.on(buffer_site()), self.on(buffer_site("ret", None), buffer_site("ret", None))):
            self.assertEqual(chk.record_problems(good_record(bufferBarriers=blk)), [], blk)

    def test_off_must_be_exactly_the_empty_block(self):
        for blk in ({"enabled": False, "count": 1, "sites": []},
                    {"enabled": False, "count": 0, "sites": [buffer_site()]}):
            self.assertTrue(any("C1" in p for p in chk.record_problems(good_record(bufferBarriers=blk))), blk)

    def test_count_is_the_sites_placed_or_zero_in_a_dry_run(self):
        self.assertTrue(any("C4" in p for p in chk.record_problems(
            good_record(bufferBarriers=self.on(buffer_site(), count=2)))))
        self.assertTrue(any("C4" in p for p in chk.record_problems(
            good_record(dryRun=True, bufferBarriers=self.on(buffer_site())))))
        self.assertEqual(chk.record_problems(good_record(dryRun=True, bufferBarriers=self.on(buffer_site(),
                                                                                             count=0))), [])

    def test_site_keys_and_value_sets(self):
        for site in (dict(buffer_site(), extra=1), buffer_site(anchor="stackrestore"), buffer_site(reason="loop"),
                     buffer_site(bytes_=-1), buffer_site(buffer=""), buffer_site(function="")):
            self.assertTrue(chk.record_problems(good_record(bufferBarriers=self.on(site))), site)

    def test_a_site_outside_the_requested_functions_is_C5(self):
        rec = good_record(bufferBarriers=self.on(buffer_site(function="wipe_kept")))
        self.assertTrue(any("C5" in p for p in chk.record_problems(rec)))
        # module scope requests nothing by name
        rec = good_record(scope="module", requested=[], resolution=[],
                          bufferBarriers=self.on(buffer_site(function="wipe_kept")))
        self.assertEqual(chk.record_problems(rec), [])

    def test_the_block_has_exactly_its_three_keys(self):
        for blk in (dict(self.on(buffer_site()), note="x"), dict(chk.BUFFER_BARRIERS_OFF, note="x"),
                    {"enabled": True, "sites": []}):
            probs = chk.record_problems(good_record(bufferBarriers=blk))
            self.assertTrue(any("bufferBarriers keys are not" in p for p in probs), (blk, probs))


class Host(unittest.TestCase):
    def host(self, **kw):
        h = dict(good_record()["host"])
        h.update(kw)
        return good_record(host=h)

    def test_no_ident_is_checked_false(self):
        self.assertEqual(chk.record_problems(self.host(ident=None, identMajor=None, checked=False)), [])

    def test_checked_true_with_no_major_is_C6(self):
        self.assertTrue(any("C6" in p for p in chk.record_problems(self.host(ident=None, identMajor=None))))

    def test_a_major_other_than_the_build_must_have_been_a_refusal(self):
        rec = self.host(ident="Ubuntu clang version 19.1.1", identMajor=19)
        self.assertTrue(any("refusal" in p for p in chk.record_problems(rec)))

    def test_the_major_re_derives_from_the_ident(self):
        rec = self.host(ident="Ubuntu clang version 17.0.6", identMajor=18)
        self.assertTrue(any("re-derive" in p for p in chk.record_problems(rec)))

    def test_the_ident_is_stripped(self):
        rec = self.host(ident="Ubuntu clang version 18.1.3 (1ubuntu1)")
        self.assertTrue(any("stripped" in p for p in chk.record_problems(rec)))
        rec = self.host(ident=" Ubuntu clang version 18.1.3")
        self.assertTrue(any("stripped" in p for p in chk.record_problems(rec)))

    def test_intrinsics_compared_is_never_null_from_this_build(self):
        self.assertTrue(chk.record_problems(self.host(intrinsicsCompared=None)))
        self.assertEqual(chk.record_problems(self.host(intrinsicsCompared=0)), [])

    def test_built_major_is_the_toolchain_major(self):
        rec = good_record(toolchain=toolchain("19.1.1"))
        self.assertTrue(any("toolchain.clang" in p for p in chk.record_problems(rec)))

    def test_strip_ident_and_ident_major(self):
        self.assertEqual(chk.strip_ident("Ubuntu clang version 18.1.3 (1ubuntu1)"), "Ubuntu clang version 18.1.3")
        self.assertEqual(chk.strip_ident("clang version 18.1.3 (git x (nested) y) tail )"),
                         "clang version 18.1.3 tail")
        self.assertEqual(chk.ident_major("Debian clang version 18.1.8"), 18)
        self.assertEqual(chk.ident_major("clang version git clang version 19.0.0"), 19)
        self.assertIsNone(chk.ident_major("Intel(R) oneAPI DPC++/C++ Compiler"))
        self.assertIsNone(chk.ident_major(None))

    def test_the_block_has_exactly_its_five_keys(self):
        h = good_record()["host"]
        for bad in (dict(h, note="x"), {k: v for k, v in h.items() if k != "checked"}):
            probs = chk.record_problems(good_record(host=bad))
            self.assertTrue(any("host keys are not" in p for p in probs), (bad, probs))

    def test_the_value_types(self):
        # each refused by its type check alone: 18.0 == 18 and 1 == True in the
        # comparisons that follow it
        for kw, head in ((dict(ident=5, identMajor=None, checked=False), "host.ident 5 is not"),
                         (dict(identMajor=18.0), "host.identMajor 18.0 is not"),
                         (dict(builtMajor=18.0), "host.builtMajor 18.0 is not"),
                         (dict(checked=1), "host.checked 1 is not"),
                         (dict(intrinsicsCompared=True), "host.intrinsicsCompared True is not")):
            probs = chk.record_problems(self.host(**kw))
            self.assertTrue(any(p.startswith(head) for p in probs), (kw, probs))

    def test_a_major_is_at_least_one(self):
        rec = good_record(toolchain=toolchain("0.1.0"),
                          host={"ident": "clang version 0.1.0", "identMajor": 0, "builtMajor": 0, "checked": True,
                                "intrinsicsCompared": 3})
        probs = chk.record_problems(rec)
        self.assertIn("host.identMajor 0 is not an integer >= 1 or null", probs)
        self.assertIn("host.builtMajor 0 is not an integer >= 1", probs)


class CompileProblems(unittest.TestCase):
    def test_each_enabled_flag_must_match_what_the_cell_set(self):
        rec = good_record(bufferBarriers={"enabled": True, "count": 0, "sites": []})
        self.assertEqual(chk.compile_problems(rec, buffer=True), [])
        self.assertTrue(any("W1" in p for p in chk.compile_problems(rec)))
        self.assertTrue(any("W1" in p for p in chk.compile_problems(good_record(), zero=True)))

    def test_checked_must_be_what_the_cell_expects(self):
        rec = good_record(host={"ident": None, "identMajor": None, "builtMajor": 18, "checked": False,
                                "intrinsicsCompared": 0})
        self.assertEqual(chk.compile_problems(rec, checked=False), [])
        self.assertTrue(chk.compile_problems(rec))


class TextHelpers(unittest.TestCase):
    def test_musttail_must_be_directly_followed_by_its_ret(self):
        ok = ["define i32 @handle(i32 %0) {", '  call void asm sideeffect "", "r,~{memory}"(ptr %2)',
              "  %5 = musttail call i32 @next(i32 %0)", "  ret i32 %5", "}"]
        self.assertTrue(chk.musttail_followed_by_ret(ok))
        broken = ok[:2] + [ok[2], ok[1], ok[3], ok[4]]
        self.assertFalse(chk.musttail_followed_by_ret(broken))
        self.assertFalse(chk.musttail_followed_by_ret(["define void @handle() {", "  ret void", "}"]))

    def test_ir_function_takes_one_definition(self):
        lines = ["declare void @use(ptr)", "define void @other() {", "  ret void", "}",
                 "define void @handle(i64 %0) {", "  ret void", "}"]
        self.assertEqual(chk.ir_function(lines, "handle"), lines[4:])
        self.assertIsNone(chk.ir_function(lines, "missing"))

    def test_clang_asm_function(self):
        text = "\t.text\nhandle:\n\t#APP\n\t#NO_APP\n\tretq\n.Lfunc_end0:\nother:\n\tretq\n.Lfunc_end1:\n"
        self.assertEqual(chk.clang_asm_function(text, "handle"), ["\t#APP", "\t#NO_APP", "\tretq"])
        self.assertIsNone(chk.clang_asm_function(text, "missing"))

    def test_table_declarations_follow_the_plugin_table(self):
        ll = ["declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)",
              "declare void @llvm.memset.inline.p0.i64(ptr, i8, i64, i1)",
              "declare void @llvm.lifetime.start.p0(i64, ptr)",
              "declare i64 @llvm.objectsize.i64.p0(ptr, i1, i1, i1)",
              "declare void @llvm.memmove.p0.p0.i64(ptr, ptr, i64, i1)"]
        self.assertEqual(chk.table_declarations(ll), 3)

    def test_module_ident(self):
        ll = ["!llvm.ident = !{!3}", '!3 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}']
        self.assertEqual(chk.module_ident(ll), "Ubuntu clang version 18.1.3 (1ubuntu1)")
        self.assertIsNone(chk.module_ident(['!3 = !{!"x"}']))

    def test_the_intrinsic_table_is_the_plugins(self):
        with open(os.path.join(HERE, "..", "src", "WipePin.cpp"), encoding="utf-8") as f:
            src = f.read()
        table = re.search(r"IntrinsicTable\[\] = \{(.*?)\};", src, re.S)
        self.assertIsNotNone(table)
        bases = tuple(re.findall(r'\{"([a-z.]+)", Intrinsic::', table.group(1)))
        self.assertEqual(bases, chk.INTRINSIC_BASES)


class V3Tables(unittest.TestCase):
    def runner_text(self):
        with open(RUNNER, encoding="utf-8") as f:
            return f.read()

    def test_every_v3_case_and_single_cell_is_run(self):
        text = self.runner_text()
        self.assertEqual(re.findall(r"^v3case (\S+)", text, re.M), chk.V3_ORDER)
        self.assertEqual(re.findall(r"^v3single (\S+)", text, re.M), chk.V3_SINGLE_ORDER)
        self.assertEqual(re.findall(r"^v3refuse (\S+)", text, re.M), chk.V3_REFUSE_ORDER)
        self.assertEqual(re.findall(r"^v3ident (\S+)", text, re.M), chk.V3_IDENT_ORDER)

    def test_the_initialiser_gets_no_barrier(self):
        self.assertEqual(chk.V3_INIT_BLOCK, {"enabled": True, "count": 0, "sites": []})
        self.assertIn("(read as an initialiser; a wipe that later code still touches", chk.V3_INITIALISER_LINE)
        self.assertEqual(chk.V3_SINGLE["v3-buffer-initloop"]["block"]["sites"], [])

    def test_single_cells_are_coherent(self):
        for cell, exp in chk.V3_SINGLE.items():
            placed = exp["block"]["count"] + (1 if exp["zeroSite"] else 0)
            # pin.sh 4 exactly when nothing is repaired, and then stderr says why
            self.assertEqual(exp["pinsh"] == "4", placed == 0, cell)
            if exp["pinsh"] == "4":
                self.assertTrue(any(l.startswith("nothing:") for l in exp["lines"]), cell)
                self.assertTrue(exp["sameStock"], cell)
            self.assertEqual(exp["block"]["count"], len(exp["block"]["sites"]), cell)
        for cell in ("v3-vla-branch-O0", "v3-vla-branch-O2"):
            self.assertIn(chk.V3_NO_PLACE_LINE, chk.V3_SINGLE[cell]["lines"])
        for cell in ("v3-musttail-O0", "v3-vla-musttail-O2", "v3-musttail-O2", "v3-musttail-Os"):
            self.assertTrue(chk.V3_SINGLE[cell]["musttail"])
            self.assertEqual([s["anchor"] for s in chk.V3_SINGLE[cell]["block"]["sites"]], ["ret"])
        # Where the .ll is optimised IR, the barriers left in it are the ones the
        # record counts: a place in a dead block would be deleted.
        for cell in ("v3-musttail-O2", "v3-musttail-Os", "v3-musttail-exits-O2", "v3-loop-ptrcmp-O2"):
            exp = chk.V3_SINGLE[cell]
            self.assertEqual(exp["irBarriers"], exp["block"]["count"], cell)
            self.assertFalse(exp["sameStock"], cell)
        self.assertEqual([s["anchor"] for s in chk.V3_SINGLE["v3-musttail-exits-O2"]["block"]["sites"]],
                         ["ret", "lifetime-end"])
        self.assertEqual(chk.V3_SINGLE["v3-loop-ptrcmp-O2"]["lines"], [])
        self.assertEqual(chk.V3_SINGLE["v3-buffer-inloop"]["lines"], [])

    def test_the_expected_records_are_ones_the_checks_accept(self):
        for cell, exp in chk.V3_SINGLE.items():
            buffer_on = exp["setting"] == "WPIN_BUFFER_BARRIER=1"
            blocks = {"module": exp["source"], "bufferBarriers": exp["block"]}
            if exp["zeroSite"]:
                blocks["zeroCopy"] = {"enabled": True, "sites": [exp["zeroSite"]], "repairedCount": 1,
                                      "wouldRepairCount": 1}
            rec = good_record(**blocks)
            self.assertEqual(chk.v3_problems(rec, zero=bool(exp["zeroSite"]), buffer=buffer_on), [], cell)

    def test_the_runner_runs_each_cell_as_its_table_defines_it(self):
        text = self.runner_text()

        def lines(pattern):
            return {m.group(1): m.groups()[1:] for m in re.finditer(pattern, text, re.M)}

        cases = lines(r"^v3case (\S+)[ \t]+(\S+)[ \t]+(\S+)[ \t]*(.*)$")
        self.assertEqual(sorted(cases), sorted(chk.V3))
        for cell, (src, switch, cflags) in cases.items():
            exp = chk.V3[cell]
            self.assertEqual((src, switch, " ".join(cflags.split())), (exp["source"], exp["switch"], exp["cflags"]),
                             cell)
        singles = lines(r"^v3single (\S+)[ \t]+(\S+)[ \t]+(.*?)[ \t]+--[ \t]+(.*)$")
        self.assertEqual(sorted(singles), sorted(chk.V3_SINGLE))
        for cell, (src, setting, cflags) in singles.items():
            exp = chk.V3_SINGLE[cell]
            self.assertEqual((src, " ".join(setting.split()), " ".join(cflags.split())),
                             (exp["source"], exp["setting"], exp["cflags"]), cell)
        refused = lines(r"^v3refuse (\S+)[ \t]+(\S+)[ \t]*$")
        self.assertEqual({c: v[0] for c, v in refused.items()}, {c: v[0] for c, v in chk.V3_REFUSE.items()})
        idents = lines(r"^v3ident (\S+)[ \t]+(\S+)[ \t]*$")
        self.assertEqual({c: v[0] for c, v in idents.items()}, chk.V3_IDENT)

    def test_each_single_cells_sites_are_what_the_cell_is_for(self):
        # (anchor, bytes) per site, from the protocol written above V3_SINGLE,
        # not from the table itself
        want = {"v3-vla-branch-O0": [], "v3-vla-branch-O2": [],
                "v3-musttail-O0": [("ret", 32)], "v3-vla-musttail-O2": [("ret", None)],
                "v3-musttail-O2": [("ret", 32)], "v3-musttail-Os": [("ret", 32)],
                "v3-musttail-exits-O2": [("ret", 32), ("lifetime-end", 32)],
                "v3-loop-ptrcmp-O2": [("lifetime-end", 32)], "v3-exit-O2": [],
                "v3-buffer-initloop": [], "v3-buffer-inloop": [("lifetime-end", 32)], "v3-zcopy-inline": []}
        got = {c: [(s["anchor"], s["bytes"]) for s in e["block"]["sites"]] for c, e in chk.V3_SINGLE.items()}
        self.assertEqual(got, want)
        for cell, exp in chk.V3_SINGLE.items():
            for s in exp["block"]["sites"]:
                self.assertEqual((s["function"], s["buffer"], s["reason"]), ("handle", None, "loop-store"), cell)


class V3Lab(unittest.TestCase):
    """A synthetic lab in a temporary directory, graded with grade_v3. Only
    the files of the cells a test writes are there: the other cells are
    reported incomplete, and a test asserts the problems of its own cell."""

    def setUp(self):
        self.lab = tempfile.mkdtemp(prefix="wpin-test-")
        os.makedirs(os.path.join(self.lab, "v3"))

    def tearDown(self):
        shutil.rmtree(self.lab, ignore_errors=True)

    def reset(self):
        """Empty the lab, for the next case of a test that tries several."""
        shutil.rmtree(os.path.join(self.lab, "v3"))
        os.makedirs(os.path.join(self.lab, "v3"))

    def write(self, name, text):
        with open(os.path.join(self.lab, "v3", name), "w", encoding="utf-8") as f:
            f.write(text)

    def write_kv(self, name, kv):
        self.write(name, "".join(f"{k}={v}\n" for k, v in kv.items()))

    def problems_of(self, cell, require_baseline=False):
        rows, problems, incomplete = chk.grade_v3(self.lab, require_baseline)
        self.assertFalse([i for i in incomplete if i.startswith(cell + ":")], incomplete)
        self.assertIn(cell, [r[0] for r in rows])
        return [p for p in problems if p.startswith(cell + ":")]

    def incomplete_of(self, cell):
        rows, problems, incomplete = chk.grade_v3(self.lab)
        self.assertNotIn(cell, [r[0] for r in rows])
        return [i for i in incomplete if i.startswith(cell + ":")]

    def assertProblem(self, probs, *parts):
        """Some problem holds every one of `parts`."""
        self.assertTrue(any(all(x in p for x in parts) for p in probs), (parts, probs))


class V3SingleGrading(V3Lab):
    """grade_v3 on a lab that holds only the files of the cell under test: the
    other cells are reported incomplete, and the cell's own problems are what
    is asserted."""

    LL_OK = ["define i32 @handle(i32 noundef %0) #0 {",
             '  call void asm sideeffect "", "r,~{memory}"(ptr %2)',
             "  %5 = musttail call i32 @next(i32 noundef %0)",
             "  ret i32 %5",
             "}"]
    S_BARRIER = "\t.text\nhandle:\n\tpushq\t%rbx\n\t#APP\n\t#NO_APP\n\tpopq\t%rbx\n\tretq\n.Lfunc_end0:\n"
    S_STOCK = "\t.text\nhandle:\n\tpushq\t%rbx\n\tpopq\t%rbx\n\tretq\n.Lfunc_end0:\n"

    def musttail_cell(self, rec=None, ll_rec=None, kv=None, lines="", ll=None, s=None, stock=None):
        cell = "v3-musttail-O0"
        good = good_record(module="musttail.c", bufferBarriers=chk.V3_SINGLE[cell]["block"])
        kvs = {"cellId": cell, "source": "musttail.c", "setting": "WPIN_BUFFER_BARRIER=1", "cflags": "-O0",
               "stockRc": "0", "pinShRc": "0", "llPinShRc": "0", "verifyRc": "0", "opt": "opt-18"}
        kvs.update(kv or {})
        self.write(cell + ".kv", "".join(f"{k}={v}\n" for k, v in kvs.items()))
        for sfx, r in (("", rec or good), ("-ll", ll_rec or rec or good)):
            self.write(f"{cell}{sfx}.json", chk.canonical(r) + "\n")
            self.write(f"{cell}{sfx}.manifest.kv", "rc=0\nstatus=0\nrepairCount=1\nrecordError=\n")
            self.write(f"{cell}{sfx}.stderr.txt", lines)
        self.write(cell + ".s", self.S_BARRIER if s is None else s)
        self.write(cell + "-stock.s", self.S_STOCK if stock is None else stock)
        self.write(cell + ".ll", "\n".join(self.LL_OK if ll is None else ll) + "\n")
        return cell

    BARRIER_LL = '  call void asm sideeffect "", "r,~{memory}"(ptr %2)'
    STORE_S = "\tmovq\t$0, (%rsp)\n"

    @staticmethod
    def listing(apps, extra=""):
        """handle in a clang -S listing, with `apps` barriers (#APP) and `extra`."""
        return ("\t.text\nhandle:\n\tpushq\t%rbx\n" + "\t#APP\n\t#NO_APP\n" * apps + extra
                + "\tpopq\t%rbx\n\tretq\n.Lfunc_end0:\n")

    def handle_ll(self, barriers, musttail, other_barriers=0):
        """Textual IR: @other with `other_barriers` barrier calls, then @handle
        with `barriers`, ending in a musttail call and its ret, or a ret."""
        tail = ["  %5 = musttail call i32 @next(i32 noundef %0)", "  ret i32 %5"] if musttail else ["  ret i32 0"]
        return (["define i32 @other(i32 noundef %0) #0 {", "  %2 = alloca [32 x i8], align 16"]
                + [self.BARRIER_LL] * other_barriers + ["  ret i32 0", "}",
                                                        "define i32 @handle(i32 noundef %0) #0 {",
                                                        "  %2 = alloca [32 x i8], align 16"]
                + [self.BARRIER_LL] * barriers + tail + ["}"])

    def single_cell(self, cell, rec=None, ll_rec=None, kv=None, man=None, lines=None, ll=None, s=None, stock=None):
        """Any v3single cell, written as its row of V3_SINGLE says it is
        measured; each argument replaces one part (`man` and `kv` key by key)."""
        exp = chk.V3_SINGLE[cell]
        blocks = {"module": exp["source"], "bufferBarriers": exp["block"]}
        if exp["zeroSite"]:
            blocks["zeroCopy"] = {"enabled": True, "sites": [exp["zeroSite"]], "repairedCount": 1,
                                  "wouldRepairCount": 1}
        good = good_record(**blocks)
        kvs = {"cellId": cell, "source": exp["source"], "setting": exp["setting"], "cflags": exp["cflags"],
               "stockRc": "0", "pinShRc": exp["pinsh"], "llPinShRc": exp["pinsh"], "verifyRc": "0", "opt": "opt-18"}
        kvs.update(kv or {})
        self.write_kv(cell + ".kv", kvs)
        # pin.sh counts every repair: each barrier placed and the zero copy
        mans = {"rc": "0", "status": exp["pinsh"],
                "repairCount": str(exp["block"]["count"] + (1 if exp["zeroSite"] else 0)), "recordError": ""}
        mans.update(man or {})
        measured_lines = [chk.nothing_to_pin_line(l.split(":", 1)[1], {}) if l.startswith("nothing:") else l
                          for l in exp["lines"]]
        for sfx, r in (("", rec or good), ("-ll", ll_rec or rec or good)):
            self.write(f"{cell}{sfx}.json", chk.canonical(r) + "\n")
            self.write_kv(f"{cell}{sfx}.manifest.kv", mans)
            self.write(f"{cell}{sfx}.stderr.txt",
                       "".join(l + "\n" for l in (measured_lines if lines is None else lines)))
        apps = exp["block"]["count"] if exp["apps"] is None else exp["apps"]
        measured = self.listing(apps, "" if exp["sameStock"] else self.STORE_S)
        self.write(cell + ".s", measured if s is None else s)
        self.write(cell + "-stock.s", (measured if exp["sameStock"] else self.listing(0)) if stock is None else stock)
        n = exp["block"]["count"] if exp["irBarriers"] is None else exp["irBarriers"]
        self.write(cell + ".ll", "\n".join(self.handle_ll(n, exp["musttail"]) if ll is None else ll) + "\n")
        return cell

    def test_the_cell_as_measured_passes(self):
        self.assertEqual(self.problems_of(self.musttail_cell()), [])

    def test_a_barrier_on_the_path_without_the_wipe_is_a_problem(self):
        # v3-exit-O2 as the build before 2026-11-10 afternoon compiled it: the
        # wipe only before exit(), a barrier at the other path's lifetime end,
        # record 1, pin.sh 0, and no no-place line
        blk = {"enabled": True, "count": 1, "sites": [buffer_site()]}
        rec = good_record(module="exit.c", bufferBarriers=blk)
        probs = self.problems_of(self.single_cell(
            "v3-exit-O2", rec=rec, kv={"pinShRc": "0", "llPinShRc": "0"}, lines=[],
            man={"status": "0", "repairCount": "1"}, s=self.listing(1, self.STORE_S), stock=self.listing(0),
            ll=self.handle_ll(1, False)))
        self.assertProblem(probs, "bufferBarriers")
        self.assertProblem(probs, "pinShRc=0, expected 4")
        self.assertProblem(probs, "WipePin lines")

    def test_the_verifier_failing_is_a_problem(self):
        self.assertTrue(self.problems_of(self.musttail_cell(kv={"verifyRc": "1"})))

    def test_a_barrier_between_the_musttail_call_and_its_ret(self):
        ll = [self.LL_OK[0], self.LL_OK[2], self.LL_OK[1], self.LL_OK[3], self.LL_OK[4]]
        probs = self.problems_of(self.musttail_cell(ll=ll))
        self.assertTrue(any("musttail" in p for p in probs), probs)

    def test_a_dead_return_counted(self):
        blk = {"enabled": True, "count": 2,
               "sites": [buffer_site("ret"), buffer_site("ret")]}
        probs = self.problems_of(self.musttail_cell(rec=good_record(module="musttail.c", bufferBarriers=blk)))
        self.assertTrue(any("bufferBarriers" in p for p in probs), probs)

    def test_two_barrier_calls_in_the_ir(self):
        ll = self.LL_OK[:2] + [self.LL_OK[1]] + self.LL_OK[2:]
        probs = self.problems_of(self.musttail_cell(ll=ll))
        self.assertTrue(any("barrier call" in p for p in probs), probs)

    def test_an_extra_stderr_line(self):
        probs = self.problems_of(self.musttail_cell(lines="WipePin: buffer barrier: 1 buffer(s) not barriered: x\n"))
        self.assertTrue(any("WipePin lines" in p for p in probs), probs)

    def test_the_two_compiles_must_write_the_same_record(self):
        other = good_record(module="musttail.c", bufferBarriers=chk.V3_SINGLE["v3-musttail-O0"]["block"],
                            optLevel={"speedup": 0, "size": 0})
        probs = self.problems_of(self.musttail_cell(ll_rec=other))
        self.assertTrue(any("different records" in p for p in probs), probs)

    def test_an_output_equal_to_stock_where_a_barrier_was_placed(self):
        probs = self.problems_of(self.musttail_cell(s=self.S_STOCK))
        self.assertTrue(any("byte-identical" in p for p in probs), probs)
        self.assertTrue(any("#APP" in p for p in probs), probs)

    def test_pin_sh_refusing(self):
        probs = self.problems_of(self.musttail_cell(kv={"llPinShRc": "3"}))
        self.assertTrue(any("llPinShRc" in p for p in probs), probs)

    def init_cell(self, block=None, s=None, lines=None, kv=None, man=None, followed=True):
        cell = chk.V3_INIT
        pinned = [{"function": "handle", "index": 0, "lengthBytes": 32, "destKind": "alloca",
                   "alreadyVolatile": False, "followedByUse": followed, "line": None}]
        rec = good_record(module="init.c", pinned=pinned, pinnedCount=1, wouldPinCount=1,
                          seen={"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 1},
                          bufferBarriers=block or chk.V3_INIT_BLOCK)
        kvs = {"cellId": "v3-buffer-init", "source": "init.c", "setting": "WPIN_BUFFER_BARRIER=1", "stockRc": "0",
               "pinShRc": "0"}
        kvs.update(kv or {})
        self.write_kv(cell + ".kv", kvs)
        mans = {"rc": "0", "status": "0", "repairCount": "1", "pinnedCount": "1", "bufferBarrierCount": "0",
                "followedByUseCount": "1", "recordError": ""}
        mans.update(man or {})
        self.write_kv(cell + ".manifest.kv", mans)
        want = chk.V3_INIT_LINES + [chk.partial_line(1, 1, "init.c")]
        self.write(cell + ".stderr.txt", "\n".join(want if lines is None else lines) + "\n")
        self.write(cell + ".json", chk.canonical(rec) + "\n")
        self.write(cell + ".s", self.S_STOCK if s is None else s)
        self.write(cell + "-stock.s", self.S_STOCK)
        return cell

    def test_the_initialiser_cell_as_measured_passes(self):
        self.assertEqual(self.problems_of(self.init_cell()), [])

    def test_a_barrier_on_the_initialiser_is_a_problem(self):
        blk = {"enabled": True, "count": 1, "sites": [buffer_site(reason="memset")]}
        self.assertTrue(self.problems_of(self.init_cell(block=blk)))
        self.assertTrue(self.problems_of(self.init_cell(s=self.S_BARRIER)))

    def test_the_old_initialiser_line_is_a_problem(self):
        old = ["WipePin: buffer barrier: 1 of 1 barrier site(s) are on buffers whose every zero fill is followed "
               "by a later use (initialiser-like, not a wipe)", chk.partial_line(1, 1, "init.c")]
        self.assertTrue(self.problems_of(self.init_cell(lines=old)))

    def test_the_initialiser_line_dropped(self):
        probs = self.problems_of(self.init_cell(lines=[chk.partial_line(1, 1, "init.c")]))
        self.assertProblem(probs, "WipePin lines")

    def test_the_initialisers_manifest(self):
        for man in ({"bufferBarrierCount": "1"}, {"followedByUseCount": "0"}, {"recordError": "unreadable"},
                    {"rc": "1"}, {"status": "4"}, {"repairCount": "0"}, {"pinnedCount": "0"}):
            self.reset()
            self.assertProblem(self.problems_of(self.init_cell(man=man)), f"pin.sh manifest {next(iter(man))}=")

    def test_the_initialisers_fill_is_followed_by_a_use(self):
        self.assertProblem(self.problems_of(self.init_cell(followed=False)), "record followedByUse per site")

    def test_the_initialisers_runner_and_exit_statuses(self):
        for kv, part in (({"pinShRc": "4"}, "pin.sh exited 4, expected 0"), ({"stockRc": "1"}, "stockRc=1"),
                         ({"source": "loop.c"}, "runner ran"), ({"setting": "WPIN_BUFFER_BARRIER=0"}, "runner ran")):
            self.reset()
            self.assertProblem(self.problems_of(self.init_cell(kv=kv)), part)

    # -- every v3single cell, through single_cell

    def test_every_single_cell_as_measured_passes(self):
        for cell in chk.V3_SINGLE_ORDER:
            self.single_cell(cell)
        rows, problems, incomplete = chk.grade_v3(self.lab)
        for cell in chk.V3_SINGLE_ORDER:
            self.assertIn(cell, [r[0] for r in rows])
            self.assertFalse([i for i in incomplete if i.startswith(cell + ":")], incomplete)
            self.assertEqual([p for p in problems if p.startswith(cell + ":")], [], cell)

    def test_the_runner_must_have_run_the_cell_as_defined(self):
        self.assertProblem(self.problems_of(self.musttail_cell(kv={"cflags": "-O2"})), "runner ran")
        for kv in ({"cflags": "-O2"}, {"source": "vla.c"}, {"setting": "WPIN_BUFFER_BARRIER=0"}):
            self.reset()
            self.assertProblem(self.problems_of(self.single_cell("v3-musttail-Os", kv=kv)), "runner ran")

    def test_the_stock_compile_must_have_succeeded(self):
        self.assertProblem(self.problems_of(self.single_cell("v3-musttail-O2", kv={"stockRc": "1"})), "stockRc=1")

    def test_pin_sh_status_of_each_compile(self):
        for k in ("pinShRc", "llPinShRc"):
            self.reset()
            self.assertProblem(self.problems_of(self.single_cell("v3-musttail-O2", kv={k: "3"})), f"{k}=3, expected 0")
        self.reset()
        self.assertProblem(self.problems_of(self.musttail_cell(kv={"pinShRc": "3"})), "pinShRc=3, expected 0")
        self.reset()
        self.assertProblem(self.problems_of(self.single_cell("v3-vla-branch-O2", kv={"pinShRc": "0"})),
                           "pinShRc=0, expected 4")

    def test_the_record_is_of_the_cells_module_and_counts_nothing_unhandled(self):
        exp = chk.V3_SINGLE["v3-loop-ptrcmp-O2"]
        un = {k: 0 for k in chk.UNHANDLED_KEYS}
        un["bzeroCall"] = 1
        for over, part in (({"module": "loop.c"}, "s record module"), ({"unhandled": un}, "s record unhandled"),
                           ({"requested": ["wipe_kept"], "resolution": [
                               {"name": "wipe_kept", "resolution": "resolved", "exact": True,
                                "linkage": "external"}]}, "s record requested")):
            self.reset()
            rec = good_record(**dict({"module": exp["source"], "bufferBarriers": exp["block"]}, **over))
            self.assertProblem(self.problems_of(self.single_cell("v3-loop-ptrcmp-O2", rec=rec)), part)

    def test_the_zero_copy_cell_records_its_one_copy(self):
        exp = chk.V3_SINGLE["v3-zcopy-inline"]
        for site in (dict(exp["zeroSite"], lengthBytes=16), dict(exp["zeroSite"], destKind="argument")):
            self.reset()
            rec = good_record(module=exp["source"], bufferBarriers=exp["block"],
                              zeroCopy={"enabled": True, "sites": [site], "repairedCount": 1, "wouldRepairCount": 1})
            self.assertProblem(self.problems_of(self.single_cell("v3-zcopy-inline", rec=rec)), "record zeroCopy")

    def test_the_pin_sh_manifest_of_each_compile(self):
        for man in ({"rc": "1"}, {"status": "4"}, {"repairCount": "0"}, {"recordError": "unreadable"}):
            self.reset()
            self.assertProblem(self.problems_of(self.single_cell("v3-musttail-O2", man=man)),
                               f"s: pin.sh manifest {next(iter(man))}=")
        self.reset()
        self.assertProblem(self.problems_of(self.single_cell("v3-zcopy-inline", man={"repairCount": "0"})),
                           "repairCount='0', expected '1'")

    def test_two_barriers_are_two_repairs(self):
        # measured: pin.sh reports repairCount=2 for this cell
        self.assertEqual(self.problems_of(self.single_cell("v3-musttail-exits-O2", man={"repairCount": "2"})), [])
        self.reset()
        self.assertProblem(self.problems_of(self.single_cell("v3-musttail-exits-O2", man={"repairCount": "1"})),
                           "repairCount='1', expected '2'")

    def test_a_memset_call_in_the_freestanding_build(self):
        call = "\tcallq\tmemset@PLT\n"
        probs = self.problems_of(self.single_cell("v3-zcopy-inline", s=self.listing(0, self.STORE_S + call)))
        self.assertProblem(probs, "the plugin's -S calls memset")
        self.reset()
        probs = self.problems_of(self.single_cell("v3-zcopy-inline", stock=self.listing(0, call)))
        self.assertProblem(probs, "stock's -S calls memset")

    def test_the_number_of_barriers_in_the_listing(self):
        probs = self.problems_of(self.single_cell("v3-zcopy-inline", s=self.listing(1, self.STORE_S)))
        self.assertProblem(probs, "1 barrier(s) (#APP), expected 0")
        self.reset()
        both = self.listing(1)
        probs = self.problems_of(self.single_cell("v3-vla-branch-O2", s=both, stock=both))
        self.assertProblem(probs, "1 barrier(s) (#APP), expected 0")
        self.reset()
        probs = self.problems_of(self.single_cell("v3-musttail-O2", s=self.listing(0, self.STORE_S)))
        self.assertProblem(probs, "0 barrier(s) (#APP), expected at least 1")

    # -- the cells whose .ll is optimised IR (irBarriers on -O2 / -Os)

    OPTIMISED = {"v3-musttail-O2": (1, True), "v3-musttail-Os": (1, True), "v3-musttail-exits-O2": (2, True),
                 "v3-loop-ptrcmp-O2": (1, False)}

    def test_a_counted_barrier_the_optimiser_deleted(self):
        # the record counts a barrier the optimised IR no longer has
        for cell, (n, musttail) in self.OPTIMISED.items():
            self.reset()
            probs = self.problems_of(self.single_cell(cell, ll=self.handle_ll(n - 1, musttail)))
            self.assertProblem(probs, f"handle's .ll has {n - 1} barrier call(s), expected {n}")

    def test_a_barrier_more_than_the_record_counts(self):
        for cell, (n, musttail) in self.OPTIMISED.items():
            self.reset()
            probs = self.problems_of(self.single_cell(cell, ll=self.handle_ll(n + 1, musttail)))
            self.assertProblem(probs, f"handle's .ll has {n + 1} barrier call(s), expected {n}")

    def test_only_handles_barrier_calls_are_counted(self):
        probs = self.problems_of(self.single_cell("v3-loop-ptrcmp-O2", ll=self.handle_ll(0, False, other_barriers=1)))
        self.assertProblem(probs, "handle's .ll has 0 barrier call(s), expected 1")
        self.reset()
        probs = self.problems_of(self.single_cell("v3-loop-ptrcmp-O2", ll=self.handle_ll(0, False)[:4]))
        self.assertProblem(probs, "handle is missing from the .ll")

    def test_the_dead_block_placement(self):
        # musttail.c at -O2 before the fix: the barrier before a lifetime end in a
        # block no path reaches, deleted with that block, still counted, pin.sh 0
        # and the -S byte-identical to stock's
        for cell in ("v3-musttail-O2", "v3-musttail-Os"):
            self.reset()
            rec = good_record(module="musttail.c",
                              bufferBarriers={"enabled": True, "count": 1, "sites": [buffer_site("lifetime-end")]})
            same = self.listing(0)
            probs = self.problems_of(self.single_cell(cell, rec=rec, ll=self.handle_ll(0, True), s=same, stock=same))
            for part in ("s record bufferBarriers", "handle's .ll has 0 barrier call(s), expected 1",
                         "0 barrier(s) (#APP)", "byte-identical to stock's"):
                self.assertProblem(probs, part)

    def test_the_musttail_call_keeps_its_ret_in_the_optimised_ir(self):
        for cell, (n, musttail) in self.OPTIMISED.items():
            if not musttail:
                continue
            self.reset()
            ll = (["define i32 @handle(i32 noundef %0) #0 {", "  %2 = alloca [32 x i8], align 16"]
                  + [self.BARRIER_LL] * (n - 1) + ["  %5 = musttail call i32 @next(i32 noundef %0)", self.BARRIER_LL,
                                                   "  ret i32 %5", "}"])
            self.assertProblem(self.problems_of(self.single_cell(cell, ll=ll)),
                               "musttail call is not directly followed by its ret")

    def test_both_exits_of_the_musttail_cell_keep_their_barrier(self):
        cell = "v3-musttail-exits-O2"
        hoisted = {"enabled": True, "count": 1, "sites": [buffer_site("ret")]}
        swapped = {"enabled": True, "count": 2, "sites": [buffer_site("lifetime-end"), buffer_site("ret")]}
        for blk in (hoisted, swapped):
            self.reset()
            probs = self.problems_of(self.single_cell(cell, rec=good_record(module="mtexit.c", bufferBarriers=blk)))
            self.assertProblem(probs, "s record bufferBarriers")
        self.reset()
        ll = ["define i32 @handle(i32 noundef %0) #0 {", "  %2 = alloca [32 x i8], align 16", self.BARRIER_LL,
              "  %5 = musttail call i32 @next(i32 noundef %0)", self.BARRIER_LL, "  ret i32 %5", "}"]
        self.assertProblem(self.problems_of(self.single_cell(cell, ll=ll)),
                           "musttail call is not directly followed by its ret")
        self.reset()
        self.assertProblem(self.problems_of(self.single_cell(cell, ll=self.handle_ll(2, False))),
                           "musttail call is not directly followed by its ret")

    def test_the_pointer_compared_loop_is_a_wipe(self):
        cell = "v3-loop-ptrcmp-O2"
        self.assertProblem(self.problems_of(self.single_cell(cell, lines=[chk.V3_INITIALISER_LINE])),
                           "s: WipePin lines")
        # read as an initialiser: no barrier, nothing to pin, the -S stock's
        self.reset()
        rec = good_record(module="ptrcmp.c", bufferBarriers={"enabled": True, "count": 0, "sites": []})
        same = self.listing(0)
        probs = self.problems_of(self.single_cell(
            cell, rec=rec, kv={"pinShRc": "4", "llPinShRc": "4"}, man={"status": "4", "repairCount": "0"},
            lines=[chk.V3_INITIALISER_LINE, chk.nothing_to_pin_line("ptrcmp.c", {})], ll=self.handle_ll(0, False),
            s=same, stock=same))
        for part in ("pinShRc=4, expected 0", "s record bufferBarriers", "s: WipePin lines",
                     "handle's .ll has 0 barrier call(s), expected 1", "byte-identical to stock's"):
            self.assertProblem(probs, part)


class V3FourArmGrading(V3Lab):
    """The four-arm v3 cells (stock, off, ext, dry), written with --baseline.
    Each executable is a file of synthetic `objdump -d` text, read by a
    stand-in for objdump_fill.disassemble; objdump_fill reads the text itself."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(chk.objdump_fill, "disassemble", self.read_disassembly)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def read_disassembly(path, *args, **kwargs):
        with open(path, encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def disassembly(subject=True, control=True):
        """`objdump -d --no-show-raw-insn` text: handle, then wipe_kept, each with
        its 32 bytes zeroed (a zeroed register stored twice) or with no store."""
        def function(name, addr, zeroed):
            ins = (["pxor   %xmm0,%xmm0", "movaps %xmm0,(%rsp)", "movaps %xmm0,0x10(%rsp)"] if zeroed
                   else ["xor    %eax,%eax"]) + ["ret"]
            return [f"{addr:016x} <{name}>:"] + [f"    {addr + 4 * i:x}:\t{x}" for i, x in enumerate(ins)] + [""]
        return "\n".join(["", "prog:     file format elf64-x86-64", "", "", "Disassembly of section .text:", ""]
                         + function("handle", 0x1150, subject) + function("wipe_kept", 0x1180, control))

    @staticmethod
    def listing(barrier=False, control_extra=""):
        return ("\t.text\nhandle:\n\tpushq\t%rbx\n" + ("\t#APP\n\t#NO_APP\n" if barrier else "")
                + "\tpopq\t%rbx\n\tretq\n.Lfunc_end0:\nwipe_kept:\n\tpushq\t%rbx\n" + control_extra
                + "\tpopq\t%rbx\n\tretq\n.Lfunc_end1:\n")

    def arm_record(self, cell, arm):
        exp = chk.V3[cell]
        blocks = {"module": exp["source"]}
        if arm == "off":
            if exp["counter"]:
                blocks["unhandled"] = dict({k: 0 for k in chk.UNHANDLED_KEYS}, **{exp["counter"]: 1})
        else:
            blk = {"enabled": True, "sites": [exp["site"]], exp["done"]: 0 if arm == "dry" else 1}
            if exp["would"]:
                blk[exp["would"]] = 1
            blocks[exp["block"]] = blk
            blocks["dryRun"] = arm == "dry"
        return good_record(**blocks)

    def four_arm_cell(self, cell, kv=None, recs=None, lines=None, mans=None, s=None, progs=None, baseline=True):
        """A cell of V3 as measured. `recs`, `lines`, `mans` replace an arm's
        record, WipePin lines or manifest keys; `s` and `progs` an arm's -S
        listing or disassembly (stock and orig too; None removes the file)."""
        exp = chk.V3[cell]
        want_rc = {"off": "4", "ext": "0", "dry": "4"}
        kvs = {"cellId": cell, "source": exp["source"], "switch": exp["switch"], "cflags": exp["cflags"],
               "baseline": "present" if baseline else "", "ioRc": "0", "mainRc": "0", "stockRc": "0",
               "origRc": "0" if baseline else "not-run"}
        for a in chk.V3_ARMS:
            kvs[a + "PinShRc"] = want_rc[a]
        for a in chk.V3_LINKED:
            kvs[a + "AsmRc"] = kvs[a + "LinkRc"] = "0"
        kvs.update(kv or {})
        self.write_kv(cell + ".kv", kvs)
        counts = {exp["counter"]: 1} if exp["counter"] else {}
        want_lines = {"off": [chk.nothing_to_pin_line(exp["source"], counts)], "ext": [], "dry": [exp["dryLine"]]}
        for a in chk.V3_ARMS:
            rec = (recs or {}).get(a) or self.arm_record(cell, a)
            self.write(f"{cell}-{a}.json", chk.canonical(rec) + "\n")
            man = {"rc": "0", "status": want_rc[a], "repairCount": "1" if a == "ext" else "0", "pinnedCount": "0",
                   "hostChecked": "true", "recordError": ""}
            man.update((mans or {}).get(a) or {})
            self.write_kv(f"{cell}-{a}.manifest.kv", man)
            self.write(f"{cell}-{a}.stderr.txt", "".join(l + "\n" for l in (lines or {}).get(a, want_lines[a])))
        listings = {a: self.listing(barrier=a == "ext") for a in chk.V3_LINKED}
        if baseline:
            listings["orig"] = listings["off"]
        listings.update(s or {})
        texts = {a: self.disassembly(subject=a == "ext" or exp["stock"] == "PRESENT") for a in chk.V3_LINKED}
        texts.update(progs or {})
        for sfx, files in ((".s", listings), (".prog", texts)):
            for a, text in files.items():
                if text is not None:
                    self.write(f"{cell}-{a}{sfx}", text)
        return cell

    def test_the_synthetic_disassembly_reads_as_meant(self):
        for subject in (True, False):
            r = chk.objdump_fill.wipe_reading(self.disassembly(subject=subject), "handle", None, 32)
            self.assertEqual(r["verdict"], "PRESENT" if subject else "ABSENT")

    def test_every_four_arm_cell_as_measured_passes(self):
        for cell in chk.V3_ORDER:
            self.four_arm_cell(cell)
        rows, problems, incomplete = chk.grade_v3(self.lab, require_baseline=True)
        for cell in chk.V3_ORDER:
            self.assertIn(cell, [r[0] for r in rows])
            self.assertEqual([p for p in problems if p.startswith(cell + ":")], [], cell)
        self.assertFalse([i for i in incomplete if i.split(":")[0] in chk.V3_ORDER], incomplete)

    def test_what_each_arms_listing_shares_with_stock(self):
        changed = self.listing() + "# changed\n"
        for cell, arm, part in (("v3-fort2", "dry", "dry: the -S output differs from stock's"),
                                ("v3-loop", "dry", "dry: the -S output differs from stock's"),
                                ("v3-zcopy", "off", "off: the -S output differs from stock's"),
                                ("v3-fort2", "ext", "ext: the -S output is byte-identical to stock's"),
                                ("v3-loop", "ext", "ext: the -S output is byte-identical to stock's")):
            self.reset()
            listing = self.listing() if part.endswith("byte-identical to stock's") else changed
            self.assertProblem(self.problems_of(self.four_arm_cell(cell, s={arm: listing})), part)

    def test_the_switches_off_listing_against_the_v2_build(self):
        changed = self.listing() + "# changed\n"
        self.assertProblem(self.problems_of(self.four_arm_cell("v3-fort2", s={"orig": changed})),
                           "off: the -S output differs from the v2 build's")
        self.reset()
        self.assertProblem(self.problems_of(self.four_arm_cell("v3-fort2", s={"orig": None})),
                           "no -S output from the v2 build")
        self.reset()
        self.assertProblem(self.problems_of(self.four_arm_cell("v3-fort2", kv={"origRc": "1"})),
                           "the v2 build's compile exited 1")
        self.reset()
        self.assertProblem(self.problems_of(self.four_arm_cell("v3-fort2", baseline=False), require_baseline=True),
                           "no --baseline on the runner")
        self.reset()
        self.assertEqual(self.problems_of(self.four_arm_cell("v3-fort2", baseline=False)), [])

    def test_the_exit_statuses(self):
        for kv, part in (({"extPinShRc": "4"}, "ext: pin.sh exited 4, expected 0"),
                         ({"offPinShRc": "0"}, "off: pin.sh exited 0, expected 4"),
                         ({"dryPinShRc": "0"}, "dry: pin.sh exited 0, expected 4"),
                         ({"extLinkRc": "1"}, "a step failed: extLinkRc=1"),
                         ({"switch": "WPIN_ZERO_COPY"}, "runner ran")):
            self.reset()
            self.assertProblem(self.problems_of(self.four_arm_cell("v3-chk", kv=kv)), part)

    def test_the_wipepin_lines_of_each_arm(self):
        for cell, lines, part in (("v3-fort2", {"ext": ["WipePin: partial: pinned 0 site(s) in memset.c"]},
                                   "ext: WipePin lines"),
                                  ("v3-fort2", {"off": []}, "off: WipePin lines"),
                                  ("v3-fort2", {"off": [chk.nothing_to_pin_line("memset.c", {})]}, "off: WipePin lines"),
                                  ("v3-zcopy", {"dry": [chk.V3_BARRIER_DRY]}, "dry: WipePin lines")):
            self.reset()
            self.assertProblem(self.problems_of(self.four_arm_cell(cell, lines=lines)), part)

    def test_the_pin_sh_manifest_of_each_arm(self):
        for arm, man in (("ext", {"repairCount": "0"}), ("off", {"status": "0"}), ("dry", {"hostChecked": "false"}),
                         ("ext", {"recordError": "unreadable"})):
            self.reset()
            self.assertProblem(self.problems_of(self.four_arm_cell("v3-fort2", mans={arm: man})),
                               f"{arm}: pin.sh manifest {next(iter(man))}=")

    def test_what_each_executable_reads(self):
        absent = self.disassembly(subject=False)
        for cell, progs, part in (("v3-fort2", {"ext": absent}, "ext: subject ABSENT"),
                                  ("v3-libcall", {"ext": absent}, "ext: subject ABSENT"),
                                  ("v3-libcall", {"stock": absent}, "stock: subject ABSENT"),
                                  ("v3-fort2", {"dry": self.disassembly()}, "dry: subject PRESENT"),
                                  ("v3-libcall", {"ext": self.disassembly(control=False)},
                                   "ext: control ABSENT in wipe_kept")):
            self.reset()
            self.assertProblem(self.problems_of(self.four_arm_cell(cell, progs=progs)), part)

    def test_the_records_of_the_three_arms(self):
        cases = [
            ("v3-fort2", "ext", lambda r: r["barrierCalls"].update(barrierCount=0),
             "ext record: barrierCalls.barrierCount 0, expected 1 (C2/C3)"),
            ("v3-fort2", "ext", lambda r: r.update(extra=1), "ext record: top-level keys"),
            ("v3-fort2", "ext", lambda r: r["unhandled"].pop("zeroGlobalCopyCall"), "ext record: unhandled keys"),
            ("v3-fort2", "off", lambda r: r["barrierCalls"].update(enabled=True),
             "off record: barrierCalls.enabled is True"),
            ("v3-fort2", "off", lambda r: r["unhandled"].update(inlineWrapperMemset=0), "off record unhandled"),
            ("v3-fort2", "dry", lambda r: r["barrierCalls"].update(barrierCount=1),
             "dry record: barrierCalls.barrierCount 1, expected 0"),
            ("v3-fort2", "ext", lambda r: r["bufferBarriers"].update(enabled=True),
             "ext record: bufferBarriers.enabled is True"),
            ("v3-fort2", "ext", lambda r: r["barrierCalls"]["sites"][0].update(callee="memcpy"),
             "ext record: barrierCalls site callee"),
            ("v3-fort2", "ext", lambda r: r.update(optLevel={"speedup": 0, "size": 0}), "ext record optLevel"),
            ("v3-zcopy", "ext", lambda r: r["zeroCopy"]["sites"][0].update(callee="memcpy"),
             "ext record: zeroCopy site callee"),
            ("v3-loop", "ext", lambda r: r["bufferBarriers"]["sites"][0].update(anchor="clobber"),
             "ext record: bufferBarriers site anchor"),
            ("v3-loop", "ext", lambda r: r["bufferBarriers"].update(count=0),
             "ext record: bufferBarriers.count 0, expected 1 (C4)"),
            ("v3-loop", "ext", lambda r: r["bufferBarriers"]["sites"][0].update(buffer="key"),
             "ext record bufferBarriers.sites"),
            ("v3-loop", "off", lambda r: r["bufferBarriers"].update(enabled=True),
             "off record: bufferBarriers.enabled is True"),
        ]
        for cell, arm, edit, part in cases:
            self.reset()
            rec = edited(self.arm_record(cell, arm), edit)
            self.assertProblem(self.problems_of(self.four_arm_cell(cell, recs={arm: rec})), part)
        self.reset()
        rec = edited(self.arm_record("v3-fort2", "ext"), lambda r: r["barrierCalls"].update(barrierCount=2),
                     reseal=False)
        self.assertProblem(self.problems_of(self.four_arm_cell("v3-fort2", recs={"ext": rec})),
                           "ext record: evidenceDigest does not re-derive")

    def test_the_barrier_must_not_change_the_control(self):
        changed = self.listing(barrier=True, control_extra="\tnop\n")
        self.assertProblem(self.problems_of(self.four_arm_cell("v3-loop", s={"ext": changed})),
                           "control wipe_kept's -S text differs from stock's")
        self.reset()
        self.assertProblem(self.problems_of(self.four_arm_cell("v3-loop", s={"ext": "\t.text\nhandle:\n\t#APP\n"})),
                           "wipe_kept is missing")
        # compared without -g only, where no module-wide numbering can move it
        self.reset()
        self.assertEqual(self.problems_of(self.four_arm_cell("v3-loop-g", s={"ext": changed})), [])

    def test_a_missing_file_leaves_the_cell_ungraded(self):
        for cell, name in (("v3-fort2", "v3-fort2-ext.json"), ("v3-fort2", "v3-fort2.kv"),
                           ("v3-zcopy", "v3-zcopy-ext.prog"), ("v3-loop", "v3-loop-dry.s"),
                           ("v3-loop", "v3-loop-ext.json")):
            self.reset()
            self.four_arm_cell(cell)
            os.remove(os.path.join(self.lab, "v3", name))
            self.assertTrue(self.incomplete_of(cell), name)


class V3RefuseGrading(V3Lab):
    """pin.sh with a switch value the plugin refuses: exit 3, no record, clang
    rc 0, exactly the refusal line."""

    def refuse_cell(self, cell, kv=None, man=None, lines=None, console=None):
        setting, line = chk.V3_REFUSE[cell]
        kvs = {"cellId": cell, "setting": setting, "pinShRc": "3"}
        kvs.update(kv or {})
        self.write_kv(cell + ".kv", kvs)
        mans = {"rc": "0", "record": ""}
        mans.update(man or {})
        self.write_kv(cell + ".manifest.kv", mans)
        self.write(cell + ".stderr.txt", "".join(l + "\n" for l in ([line] if lines is None else lines)))
        self.write(cell + ".console.txt", "pin.sh: no WipePin record was written\n" if console is None else console)
        return cell

    def test_each_refusal_as_measured_passes(self):
        for cell in chk.V3_REFUSE_ORDER:
            self.assertEqual(self.problems_of(self.refuse_cell(cell)), [], cell)

    def test_pin_sh_exits_3_and_leaves_the_compiles_status_alone(self):
        for kv, man, part in (({"pinShRc": "0"}, None, "pin.sh exited 0, expected 3"),
                              ({"pinShRc": "4"}, None, "pin.sh exited 4, expected 3"),
                              (None, {"rc": "1"}, "clang rc 1, expected 0")):
            for cell in chk.V3_REFUSE_ORDER:
                self.reset()
                self.assertProblem(self.problems_of(self.refuse_cell(cell, kv=kv, man=man)), part)

    def test_no_record_after_a_refusal(self):
        cell = self.refuse_cell("v3-refuse-barrier2")
        self.write(cell + ".json", chk.canonical(good_record()) + "\n")
        self.assertProblem(self.problems_of(cell), "a record exists")
        self.reset()
        cell = self.refuse_cell("v3-refuse-buffer2", man={"record": "v3-refuse-buffer2.json"})
        self.assertProblem(self.problems_of(cell), "a record exists")
        self.reset()
        self.assertProblem(self.problems_of(self.refuse_cell("v3-refuse-buffer2", console="")), "pin.sh did not say")

    def test_exactly_the_refusal_line(self):
        cell = "v3-refuse-zerocopy-true"
        line = chk.V3_REFUSE[cell][1]
        for lines in ([line.replace("'true'", "'TRUE'")], [line, line], [], [line, "WipePin: nothing to pin"]):
            self.reset()
            self.assertProblem(self.problems_of(self.refuse_cell(cell, lines=lines)), "WipePin lines")

    def test_the_runner_set_the_refused_value(self):
        cell = self.refuse_cell("v3-refuse-buffer2", kv={"setting": "WPIN_BUFFER_BARRIER=1"})
        self.assertProblem(self.problems_of(cell), "runner set")


class V3IdentGrading(V3Lab):
    """The handshake on the trailing shape's front-end IR, compiled back with
    -x ir: as written, with llvm.ident naming the next major, and without it.
    The expected lines are written out here, not built with the checker's."""

    IDENT = "Ubuntu clang version 18.1.3 (1ubuntu1)"
    DECLS = ["declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #1",
             "declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture) #2",
             "declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture) #2",
             "declare void @use(ptr noundef) #3"]
    INPUT_IDENT = {"v3-ident-same": IDENT, "v3-ident-other": "clang version 19.1.1", "v3-ident-none": None}
    LINES = {"v3-ident-same": [],
             "v3-ident-other": ['WipePin: refusing to install: the module was produced by clang 19 (llvm.ident '
                                '"clang version 19.1.1") and this plugin was built against LLVM 18'],
             "v3-ident-none": ["WipePin: the module's llvm.ident names no clang version (absent); the host compiler "
                               "was not checked against LLVM 18"]}
    STOCK_S = "\t.text\nhandle:\n\tretq\n.Lfunc_end0:\n"
    PINNED_S = "\t.text\nhandle:\n\tmovq\t$0, (%rsp)\n\tretq\n.Lfunc_end0:\n"

    def input_ll(self, ident):
        lines = ["; ModuleID = 'trailing.c'", "define dso_local void @handle() #0 {", "  ret void", "}"] + self.DECLS
        return lines + (["!llvm.ident = !{!3}", f'!3 = !{{!"{ident}"}}'] if ident is not None else [])

    def ident_record(self, cell, **host):
        none = cell == "v3-ident-none"
        h = {"ident": None if none else "Ubuntu clang version 18.1.3", "identMajor": None if none else 18,
             "builtMajor": 18, "checked": not none, "intrinsicsCompared": 3}
        h.update(host)
        site = {"function": "handle", "index": 0, "lengthBytes": 32, "destKind": "alloca", "alreadyVolatile": False,
                "followedByUse": False, "line": None}
        return good_record(module=chk.V3_IDENT[cell], pinned=[site], pinnedCount=1, wouldPinCount=1,
                           seen={"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 1}, host=h)

    def ident_cell(self, cell, kv=None, man=None, lines=None, rec=None, ll=None, s=None, console=None):
        ll_name = chk.V3_IDENT[cell]
        other, none = cell == "v3-ident-other", cell == "v3-ident-none"
        kvs = {"cellId": cell, "input": ll_name, "frontEndRc": "0", "stockRc": "0",
               "pinShRc": "3" if other else "0", "ccMajor": "18"}
        kvs.update(kv or {})
        self.write_kv(cell + ".kv", kvs)
        mans = ({"rc": "0", "record": ""} if other else
                {"rc": "0", "status": "0", "record": cell + ".json", "hostChecked": "false" if none else "true"})
        mans.update(man or {})
        self.write_kv(cell + ".manifest.kv", mans)
        self.write(ll_name, "\n".join(self.input_ll(self.INPUT_IDENT[cell]) if ll is None else ll) + "\n")
        self.write(cell + ".stderr.txt", "".join(l + "\n" for l in (self.LINES[cell] if lines is None else lines)))
        self.write(cell + ".console.txt",
                   ("pin.sh: no WipePin record was written\n" if other else "") if console is None else console)
        self.write(cell + "-stock.s", self.STOCK_S)
        self.write(cell + ".s", (self.STOCK_S if other else self.PINNED_S) if s is None else s)
        if not other:
            self.write(cell + ".json", chk.canonical(rec or self.ident_record(cell)) + "\n")
        return cell

    def test_the_three_handshake_cells_as_measured_pass(self):
        for cell in chk.V3_IDENT_ORDER:
            self.ident_cell(cell)
        for cell in chk.V3_IDENT_ORDER:
            self.assertEqual(self.problems_of(cell), [], cell)

    def test_the_host_block_is_re_derived_from_the_input(self):
        for host, part in ((dict(intrinsicsCompared=4), "record host ="), (dict(intrinsicsCompared=2), "record host ="),
                           (dict(ident="Ubuntu clang version 18.1.8"), "record host ="),
                           (dict(builtMajor=17), "record host ="),
                           (dict(identMajor=19), "is not builtMajor 18"),
                           (dict(ident=self.IDENT), "is not stripped"),
                           (dict(intrinsicsCompared=None), "intrinsicsCompared None")):
            self.reset()
            rec = self.ident_record("v3-ident-same", **host)
            self.assertProblem(self.problems_of(self.ident_cell("v3-ident-same", rec=rec)), part)

    def test_the_pin_through_ir_input(self):
        for kv, part in (({"pinShRc": "4"}, "pin.sh exited 4, expected 0"), ({"ccMajor": ""}, "ccMajor"),
                         ({"input": "ident-none.ll"}, "runner compiled"), ({"stockRc": "1"}, "stockRc=1"),
                         ({"frontEndRc": "1"}, "frontEndRc=1")):
            self.reset()
            self.assertProblem(self.problems_of(self.ident_cell("v3-ident-same", kv=kv)), part)
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-same", s=self.STOCK_S)),
                           "byte-identical to stock's: the pin changed nothing")
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-same", lines=["WipePin: partial: x"])),
                           "WipePin lines")
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-same", man={"hostChecked": "false"})),
                           "hostChecked")

    def test_a_module_without_an_ident_is_not_checked(self):
        rec = self.ident_record("v3-ident-none", checked=True)
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-none", rec=rec)),
                           "host.checked True with identMajor None (C6)")
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-none", lines=[])), "WipePin lines [], expected")
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-none", man={"hostChecked": "true"})),
                           "hostChecked")
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-none", ll=self.input_ll(self.IDENT))),
                           "still has an llvm.ident")

    def test_a_refused_module_is_left_as_stock_left_it(self):
        s = "\t.text\nhandle:\n\tnop\n\tretq\n.Lfunc_end0:\n"
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-other", s=s)),
                           "differs from stock's: the IR was changed")

    def test_no_record_after_the_version_refusal(self):
        cell = self.ident_cell("v3-ident-other")
        self.write(cell + ".json", chk.canonical(self.ident_record("v3-ident-same")) + "\n")
        self.assertProblem(self.problems_of(cell), "a record exists after a refusal")
        self.reset()
        cell = self.ident_cell("v3-ident-other", man={"record": "v3-ident-other.json"})
        self.assertProblem(self.problems_of(cell), "a record exists after a refusal")
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-other", console="")), "pin.sh did not say")

    def test_exactly_the_version_refusal_line(self):
        line = self.LINES["v3-ident-other"][0]
        for lines in ([line.replace("built against", "built for")], [], [line, line]):
            self.reset()
            self.assertProblem(self.problems_of(self.ident_cell("v3-ident-other", lines=lines)), "WipePin lines")
        for kv, man, part in (({"pinShRc": "0"}, None, "pin.sh exited 0, expected 3"),
                              (None, {"rc": "1"}, "clang rc 1, expected 0")):
            self.reset()
            self.assertProblem(self.problems_of(self.ident_cell("v3-ident-other", kv=kv, man=man)), part)
        self.reset()
        self.assertProblem(self.problems_of(self.ident_cell("v3-ident-other", ll=self.input_ll(self.IDENT))),
                           "the input's llvm.ident is")

    def test_a_missing_listing_leaves_the_cell_ungraded(self):
        cell = self.ident_cell("v3-ident-other")
        os.remove(os.path.join(self.lab, "v3", cell + ".s"))
        self.assertTrue(self.incomplete_of(cell))


class LoopAndShapeCells(unittest.TestCase):
    """One loop cell (grade) and one shape cell (grade_shapes): their records
    are wipe-pin-v3 records of compiles that set no v3 switch."""

    SYMBOLS = ["memset", "llvm.memset"]

    def setUp(self):
        self.lab = tempfile.mkdtemp(prefix="wpin-test-")

    def tearDown(self):
        shutil.rmtree(self.lab, ignore_errors=True)

    def write(self, rel, text):
        path = os.path.join(self.lab, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def pin_record(self, **blocks):
        site = {"function": "handle_request", "index": 0, "lengthBytes": 32, "destKind": "alloca",
                "alreadyVolatile": False, "followedByUse": False, "line": None}
        rec = {"module": "target.c", "requested": ["handle_request"],
               "resolution": [{"name": "handle_request", "resolution": "resolved", "exact": True,
                               "linkage": "external"}],
               "pinned": [site], "pinnedCount": 1, "wouldPinCount": 1,
               "seen": {"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 1}}
        rec.update(blocks)
        return good_record(**rec)

    def loop_cell(self, rec=None):
        cell = "pin-O2"
        rec = rec or self.pin_record()
        obs = {"verdict": {"state": "PRESENT"}, "firstZeroTransition": {"pass": None}, "control": {"held": True},
               "subject": {"preOptIr": {"effect": 1}, "postOptIr": {"effect": 1}},
               "oracle": {"symbols": self.SYMBOLS}, "toolchain": toolchain()}
        self.write(f"records/{cell}.json", chk.canonical(obs) + "\n")
        self.write(f"snapshots/{cell}/post-opt-ir.ll", "define void @handle_request() {\n"
                   "  call void @llvm.memset.p0.i64(ptr %1, i8 0, i64 32, i1 true)\n  ret void\n}\n")
        self.write(f"stderr/{cell}.txt", "")
        self.write(f"cells/{cell}.kv", "pinShRc=0\n")
        self.write(f"wipepin/{cell}.json", chk.canonical(rec) + "\n")
        self.write(f"pinsh/{cell}.manifest.kv", "rc=0\nstatus=0\npinnedCount=1\nfollowedByUseCount=0\nunresolved=\n")
        self.write(f"pinsh/{cell}.json", chk.canonical(rec) + "\n")
        return cell

    def shape_record(self, **blocks):
        site = {"function": "handle", "index": 0, "lengthBytes": 32, "destKind": "alloca", "alreadyVolatile": False,
                "followedByUse": False, "line": 9}
        rec = {"module": "trailing.c", "pinned": [site], "pinnedCount": 1, "wouldPinCount": 1,
               "seen": {"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 1}}
        rec.update(blocks)
        return good_record(**rec)

    def shape_cell(self, rec=None):
        rec = rec or self.shape_record()
        self.write("shapes/trailing.kv", "opt=-O2\npinShRc=0\n")
        self.write("shapes/trailing.manifest.kv", "status=0\nfollowedByUseCount=0\nunresolved=\nexactAll=true\n")
        self.write("shapes/trailing.stderr.txt", "")
        self.write("shapes/trailing.json", chk.canonical(rec) + "\n")
        return "trailing"

    def problems_of(self, graded, cell):
        rows, problems, incomplete = graded
        self.assertFalse([i for i in incomplete if i.startswith(cell + ":")], incomplete)
        self.assertIn(cell, [r[0] for r in rows])
        return [p for p in problems if p.startswith(cell + ":")]

    def loop_problems(self, cell):
        return self.problems_of(chk.grade(self.lab, self.SYMBOLS), cell)

    def shape_problems(self, cell):
        return self.problems_of(chk.grade_shapes(self.lab), cell)

    def test_the_loop_cell_as_measured_passes(self):
        self.assertEqual(self.loop_problems(self.loop_cell()), [])

    def test_a_loop_record_with_a_v3_switch_on(self):
        for block, on in (("barrierCalls", {"enabled": True, "sites": [], "barrierCount": 0, "wouldBarrierCount": 0}),
                          ("bufferBarriers", {"enabled": True, "count": 0, "sites": []})):
            probs = self.loop_problems(self.loop_cell(self.pin_record(**{block: on})))
            self.assertTrue(any(f"{block}.enabled is True" in p and "W1" in p for p in probs), probs)

    def test_the_shape_cell_as_measured_passes(self):
        self.assertEqual(self.shape_problems(self.shape_cell()), [])

    def test_a_shape_record_of_another_schema_or_with_a_switch_on(self):
        probs = self.shape_problems(self.shape_cell(self.shape_record(schemaVersion="wipe-pin-v2")))
        self.assertTrue(any("schemaVersion 'wipe-pin-v2'" in p for p in probs), probs)
        on = {"enabled": True, "count": 0, "sites": []}
        probs = self.shape_problems(self.shape_cell(self.shape_record(bufferBarriers=on)))
        self.assertTrue(any("bufferBarriers.enabled is True" in p and "W1" in p for p in probs), probs)


if __name__ == "__main__":
    unittest.main()
