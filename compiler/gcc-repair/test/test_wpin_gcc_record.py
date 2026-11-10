#!/usr/bin/env python3
"""Unit tests for scripts/wpin_gcc_record.py, the strict wipe-pin-v3 reader.

    python3 compiler/gcc-repair/test/test_wpin_gcc_record.py

(run as a file: the directory name has a hyphen, so it is not importable as a
package, and `python3 -m unittest` cannot address it by module name).

The canonical serialiser is calibrated against the shared vectors in
compiler/evidence/testdata/digest-vectors.json -- the same calibration the C++
writer in ../src/Canon.cpp is held to by canon-vectors -- and the reader is
shown to refuse each way a record can be wrong, the rules v3 adds
(compiler/schema/wipe-pin.md section 14.9) one at a time.
"""

import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import wpin_gcc_record as wpr  # noqa: E402

VECTORS = os.path.join(HERE, "..", "..", "evidence", "testdata", "digest-vectors.json")

U0 = {k: 0 for k in ("libcallMemset", "memsetChk", "nonZeroFill", "atomicMemset", "inlineWrapperMemset",
                     "bzeroCall", "inlineWrapperBzero", "zeroGlobalCopy", "zeroGlobalCopyCall")}
OFF = {"barrierCalls": False, "zeroCopy": False, "bufferBarriers": False}


def good_record(**over):
    """A record shaped the way WipePinGcc writes one with every switch off,
    sealed here."""
    pkgs = [{"name": "gcc", "version": "13.3.0"}]
    rec = {
        "schemaVersion": "wipe-pin-v3", "component": "WipePinGcc", "module": "target.c",
        "toolchain": {"gcc": "13.3.0", "packages": pkgs,
                      "digest": wpr.sha256_text(wpr.canonical_raw({"gcc": "13.3.0", "packages": pkgs}))},
        "optLevel": {"speedup": 2, "size": 0}, "scope": "functions",
        "requested": ["handle_request"],
        "resolution": [{"name": "handle_request", "resolution": "resolved", "exact": True, "linkage": "external"}],
        "dryRun": False,
        "pinned": [{"function": "handle_request", "index": 0, "lengthBytes": 32, "destKind": "alloca",
                    "alreadyVolatile": False, "followedByUse": False, "line": 22}],
        "pinnedCount": 1, "wouldPinCount": 1,
        "seen": {"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 3},
        "unhandled": dict(U0),
        "barrierCalls": {"enabled": False, "sites": [], "barrierCount": 0, "wouldBarrierCount": 0},
        "zeroCopy": {"enabled": False, "sites": [], "repairedCount": 0, "wouldRepairCount": 0},
        "bufferBarriers": {"enabled": False, "count": 0, "sites": []},
        "host": {"ident": "13.3.0", "identMajor": 13, "builtMajor": 13, "checked": True,
                 "intrinsicsCompared": None},
        "context": {"generatedAt": 1789136746, "timeSource": "wall-clock", "sourceDateEpoch": None},
    }
    rec.update(copy.deepcopy(over))
    return reseal(rec)


def reseal(rec):
    rec = copy.deepcopy(rec)
    rec.pop("evidenceDigest", None)
    rec["evidenceDigest"] = wpr.evidence_digest(rec)
    return rec


def with_barrier(rec=None, dry=False, **site):
    """`rec` with WPIN_BARRIER_CALLS=1 and one bzero site, resealed."""
    rec = copy.deepcopy(rec or good_record())
    s = {"function": "handle_request", "callee": "bzero", "lengthBytes": 32, "line": 23}
    s.update(site)
    rec["barrierCalls"] = {"enabled": True, "sites": [s], "barrierCount": 0 if dry else 1, "wouldBarrierCount": 1}
    if dry:
        rec["dryRun"] = True
        rec["pinnedCount"] = 0
    return reseal(rec)


def with_zero_copy(rec=None, dry=False, **site):
    """`rec` with WPIN_ZERO_COPY=1 and one aggregate-copy site, resealed."""
    rec = copy.deepcopy(rec or good_record())
    s = {"function": "handle_request", "form": "aggregate", "callee": None, "source": "vg_zeros",
         "destKind": "alloca", "lengthBytes": 32, "line": 24}
    s.update(site)
    rec["zeroCopy"] = {"enabled": True, "sites": [s], "repairedCount": 0 if dry else 1, "wouldRepairCount": 1}
    if dry:
        rec["dryRun"] = True
        rec["pinnedCount"] = 0
    return reseal(rec)


# compiler/schema/wipe-pin.md section 14.11, the WipePinGcc example, verbatim:
# constructed there, not captured from a compile, and sealed with canon.mjs.
SCHEMA_EXAMPLE = (
    '{"schemaVersion":"wipe-pin-v3","component":"WipePinGcc","module":"session.c","toolchain":{"gcc":"13.3.0",'
    '"packages":[{"name":"gcc","version":"13.3.0"}],"digest":"59918b2e94592419773ed8982734ac2d9ed571a328feec4d8430d158995291e0"},'
    '"optLevel":{"speedup":2,"size":0},"scope":"module","requested":[],"resolution":[],"dryRun":true,'
    '"pinned":[{"function":"close_session","index":0,"lengthBytes":32,"destKind":"alloca","alreadyVolatile":false,'
    '"followedByUse":false,"line":55}],"pinnedCount":0,"wouldPinCount":1,"seen":{"zeroFillMemsetInScope":1,'
    '"zeroFillMemsetInModule":1},"unhandled":{"libcallMemset":1,"memsetChk":0,"nonZeroFill":0,"atomicMemset":0,'
    '"inlineWrapperMemset":0,"bzeroCall":0,"inlineWrapperBzero":0,"zeroGlobalCopy":0,"zeroGlobalCopyCall":0},'
    '"barrierCalls":{"enabled":true,"sites":[{"function":"close_session","callee":"bzero","lengthBytes":16,"line":56}],'
    '"barrierCount":0,"wouldBarrierCount":1},"zeroCopy":{"enabled":true,"sites":[{"function":"close_session",'
    '"form":"aggregate","callee":null,"source":"zero_block","destKind":"alloca","lengthBytes":64,"line":58}],'
    '"repairedCount":0,"wouldRepairCount":1},"bufferBarriers":{"enabled":false,"count":0,"sites":[]},'
    '"host":{"ident":"13.3.0","identMajor":13,"builtMajor":13,"checked":true,"intrinsicsCompared":null},'
    '"evidenceDigest":"3904af95abe913d30dc707fa10a9e7f51737f6d56bc95a21c15b2f4fe145c77e",'
    '"context":{"timeSource":"SOURCE_DATE_EPOCH","sourceDateEpoch":1762300800,"generatedAt":1762300800}}')


class CanonicalCalibration(unittest.TestCase):
    def test_every_vector_and_every_refusal(self):
        with open(VECTORS, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertGreater(len(doc["vectors"]), 0)
        self.assertGreater(len(doc["mustFail"]), 0)
        for v in doc["vectors"]:
            with self.subTest(vector=v["name"]):
                self.assertEqual(wpr.canonical(v["input"]), v["canonicalText"])
                self.assertEqual(wpr.evidence_digest(v["input"]), v["digest"])
        for v in doc["mustFail"]:
            with self.subTest(mustFail=v["name"]):
                with self.assertRaises(wpr.CanonError):
                    wpr.canonical(v["input"])

    def test_utf16_key_order(self):
        # Expected text and digest from compiler/evidence/canon.mjs: U+1F600 is
        # a surrogate pair and sorts before U+FF01 in UTF-16 code units.
        rec = {"\uff01": 1, "\U0001f600": 2, "z": 3, "\u00e9": 4}
        self.assertEqual(wpr.canonical(rec), '{"z":3,"\u00e9":4,"\U0001f600":2,"\uff01":1}')
        self.assertEqual(wpr.evidence_digest(rec),
                         "61de167b353bccbdf6aa0a3245e30f7bea2fe594dc749bbc6c16ff4c76fcaea1")

    def test_toolchain_digest_for_13_3_0(self):
        # The value canon.mjs derives, and the one every record measured here carries.
        pkgs = [{"name": "gcc", "version": "13.3.0"}]
        self.assertEqual(wpr.sha256_text(wpr.canonical_raw({"gcc": "13.3.0", "packages": pkgs})),
                         "59918b2e94592419773ed8982734ac2d9ed571a328feec4d8430d158995291e0")

    def test_the_schema_example_re_derives_and_is_accepted(self):
        # Its digest was computed with canon.mjs (wipe-pin.md 14.11); this
        # serialiser shares no code with it.
        rec = json.loads(SCHEMA_EXAMPLE)
        self.assertEqual(wpr.evidence_digest(rec), rec["evidenceDigest"])
        self.assertEqual(wpr.validate(rec, {"barrierCalls": True, "zeroCopy": True, "bufferBarriers": False}), [])


class Validate(unittest.TestCase):
    def test_a_good_record_is_accepted(self):
        self.assertEqual(wpr.validate(good_record()), [])
        self.assertEqual(wpr.validate(good_record(), OFF), [])

    def test_context_is_outside_the_digest(self):
        rec = good_record()
        rec["context"]["generatedAt"] = 0
        self.assertEqual(wpr.validate(rec), [])

    def assertRefused(self, rec, needle, expect=None):
        problems = wpr.validate(rec, expect)
        self.assertTrue(any(needle in p for p in problems), f"{needle!r} not in {problems}")

    def test_an_edit_after_the_compile_is_refused(self):
        rec = good_record()
        rec["pinned"][0]["followedByUse"] = True
        self.assertRefused(rec, "digest-mismatch")
        rec = with_zero_copy()
        rec["zeroCopy"]["sites"][0]["source"] = "other"
        self.assertRefused(rec, "digest-mismatch")

    def test_v1_and_v2_records_are_refused(self):
        self.assertRefused(good_record(schemaVersion="wipe-pin-v1"), "unknown-schemaVersion")
        self.assertRefused(good_record(schemaVersion="wipe-pin-v2"), "unknown-schemaVersion")
        # A v2 record as the v2 writer wrote it: the 16 keys and 5 counters.
        v2 = good_record(schemaVersion="wipe-pin-v2")
        for k in ("barrierCalls", "zeroCopy", "bufferBarriers", "host"):
            del v2[k]
        for k in ("bzeroCall", "inlineWrapperBzero", "zeroGlobalCopy", "zeroGlobalCopyCall"):
            del v2["unhandled"][k]
        problems = wpr.validate(reseal(v2))
        for needle in ("unknown-schemaVersion", "missing-field: host", "missing-field: unhandled.bzeroCall"):
            self.assertTrue(any(needle in p for p in problems), (needle, problems))

    def test_the_llvm_component_is_refused(self):
        self.assertRefused(good_record(component="WipePin"), "wrong-component")

    def test_a_clang_toolchain_is_refused(self):
        rec = good_record()
        rec["toolchain"] = {"clang": "18.1.3", "packages": [{"name": "llvm", "version": "18.1.3"}],
                            "digest": "x"}
        self.assertRefused(reseal(rec), "missing-field: toolchain.gcc")

    def test_a_toolchain_digest_that_does_not_re_derive_is_refused(self):
        rec = good_record()
        rec["toolchain"]["digest"] = "0" * 64
        self.assertRefused(reseal(rec), "toolchain.digest")

    def test_packages_must_name_gcc_at_the_same_version(self):
        rec = good_record()
        rec["toolchain"]["packages"] = [{"name": "gcc", "version": "13.2.0"}]
        self.assertRefused(reseal(rec), "toolchain.packages")

    def test_followed_by_use_null_exactly_off_the_stack(self):
        rec = good_record()
        rec["pinned"][0]["followedByUse"] = None
        self.assertRefused(reseal(rec), "null exactly when")
        rec = good_record()
        rec["pinned"][0]["destKind"] = "argument"
        self.assertRefused(reseal(rec), "null exactly when")
        rec["pinned"][0]["followedByUse"] = None
        self.assertEqual(wpr.validate(reseal(rec)), [])

    def test_followed_by_use_is_a_boolean_not_a_number(self):
        # 1 and 0 compare equal to True and False; they are not booleans (a float
        # cannot be sealed at all: canonical JSON has no non-integer numbers)
        for v in (1, 0, "true"):
            rec = good_record()
            rec["pinned"][0]["followedByUse"] = v
            self.assertRefused(reseal(rec), "bad-type: pinned[0].followedByUse")

    def test_dest_kind_words_are_the_observers(self):
        rec = good_record()
        rec["pinned"][0]["destKind"] = "stack"
        self.assertRefused(reseal(rec), "bad-destKind")

    def test_linkage_words_and_exactness(self):
        rec = good_record()
        rec["resolution"][0]["linkage"] = "linkonce_odr"
        self.assertRefused(reseal(rec), "inconsistent: resolution[0].exact")
        rec["resolution"][0]["exact"] = False
        self.assertEqual(wpr.validate(reseal(rec)), [])
        rec["resolution"][0]["linkage"] = "weak_odr"  # LLVM has it; the GCC mapping cannot produce it
        self.assertRefused(reseal(rec), "bad-linkage")

    def test_unresolved_names_carry_null_exact_and_linkage(self):
        rec = good_record(pinned=[], pinnedCount=0, wouldPinCount=0,
                          seen={"zeroFillMemsetInScope": 0, "zeroFillMemsetInModule": 3})
        rec["resolution"][0].update(resolution="not-in-module", exact=None, linkage=None)
        self.assertEqual(wpr.validate(reseal(rec)), [])
        rec["resolution"][0]["linkage"] = "external"
        self.assertRefused(reseal(rec), "non-null exact or linkage")

    def test_counts_must_agree_with_the_list(self):
        self.assertRefused(good_record(pinnedCount=0), "pinnedCount differs")
        self.assertRefused(good_record(seen={"zeroFillMemsetInScope": 2, "zeroFillMemsetInModule": 3}),
                           "number of listed sites")
        self.assertRefused(good_record(seen={"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 0}),
                           "exceeds")

    def test_a_dry_run_pins_nothing(self):
        self.assertEqual(wpr.validate(good_record(dryRun=True, pinnedCount=0)), [])
        self.assertRefused(good_record(dryRun=True), "dry run with pinnedCount")

    def test_already_pinned_sites_are_in_neither_count(self):
        rec = good_record(pinnedCount=0, wouldPinCount=0)
        rec["pinned"][0]["alreadyVolatile"] = True
        self.assertEqual(wpr.validate(reseal(rec)), [])

    def test_shapes_gcc_does_not_have_stay_zero(self):
        for k in ("atomicMemset", "inlineWrapperMemset", "inlineWrapperBzero"):
            rec = good_record()
            rec["unhandled"][k] = 1
            self.assertRefused(reseal(rec), "GCC has no such shape")
        # The other six may count.
        rec = good_record()
        for k in ("libcallMemset", "memsetChk", "nonZeroFill", "bzeroCall", "zeroGlobalCopy", "zeroGlobalCopyCall"):
            rec["unhandled"][k] = 2
        self.assertEqual(wpr.validate(reseal(rec)), [])

    def test_the_module_is_a_basename(self):
        self.assertRefused(good_record(module="/home/someone/target.c"), "module-not-a-basename")
        self.assertRefused(good_record(module="C:\\x\\target.c"), "module-not-a-basename")

    def test_requested_and_resolution_agree(self):
        rec = good_record(requested=["handle_request", "other"])
        self.assertRefused(rec, "exactly the requested functions")
        rec = good_record(scope="module")
        self.assertRefused(rec, "module scope with requested")

    def test_unknown_and_missing_fields(self):
        rec = good_record()
        rec["extra"] = 1
        self.assertRefused(reseal(rec), "unknown-field: extra")
        rec = good_record()
        del rec["pinned"][0]["line"]
        self.assertRefused(reseal(rec), "missing-field: pinned[0].line")

    def test_booleans_are_not_counts(self):
        self.assertRefused(good_record(pinnedCount=True), "not-a-count: pinnedCount")

    def test_not_an_object(self):
        self.assertEqual(wpr.validate([]), ["not-an-object"])


class V3Structure(unittest.TestCase):
    """S1-S6 of compiler/schema/wipe-pin.md section 14.9."""

    def assertRefused(self, rec, needle, expect=None):
        problems = wpr.validate(rec, expect)
        self.assertTrue(any(needle in p for p in problems), f"{needle!r} not in {problems}")

    def test_s1_every_block_on_every_record(self):
        for k in ("barrierCalls", "zeroCopy", "bufferBarriers", "host"):
            rec = good_record()
            del rec[k]
            self.assertRefused(reseal(rec), f"missing-field: {k}")
        rec = good_record()
        rec["config"] = {}
        self.assertRefused(reseal(rec), "unknown-field: config")

    def test_s2_nine_counters(self):
        rec = good_record()
        del rec["unhandled"]["zeroGlobalCopyCall"]
        self.assertRefused(reseal(rec), "missing-field: unhandled.zeroGlobalCopyCall")
        rec = good_record()
        rec["unhandled"]["zeroCopyLeft"] = 0
        self.assertRefused(reseal(rec), "unknown-field: unhandled.zeroCopyLeft")
        rec = good_record()
        rec["unhandled"]["bzeroCall"] = -1
        self.assertRefused(reseal(rec), "not-a-count: unhandled.bzeroCall")

    def test_s3_s4_the_shapes_the_patches_wrote_are_refused(self):
        # The GCC patches wrote bare counts, and only when the switch was on.
        rec = good_record()
        rec["barrierCalls"] = {"barrierCount": 0}
        self.assertRefused(reseal(rec), "missing-field: barrierCalls.enabled")
        rec = good_record()
        rec["zeroCopy"] = {"repairedCount": 0, "wouldRepairCount": 1}
        self.assertRefused(reseal(rec), "missing-field: zeroCopy.enabled")

    def test_s3_site_keys_and_types(self):
        rec = with_barrier()
        rec["barrierCalls"]["sites"][0]["callee"] = ""
        self.assertRefused(reseal(rec), "bad-type: barrierCalls.sites[0].callee")
        rec = with_barrier()
        del rec["barrierCalls"]["sites"][0]["line"]
        self.assertRefused(reseal(rec), "missing-field: barrierCalls.sites[0].line")
        rec = with_barrier(lengthBytes=None, line=None)
        self.assertEqual(wpr.validate(rec), [])
        rec = with_barrier()
        rec["barrierCalls"]["enabled"] = 1
        self.assertRefused(reseal(rec), "bad-type: barrierCalls.enabled")

    def test_s4_site_keys_and_types(self):
        rec = with_zero_copy(destKind="heap")
        self.assertRefused(rec, "bad-destKind: zeroCopy.sites[0].destKind")
        rec = with_zero_copy(source=None)
        self.assertRefused(rec, "bad-type: zeroCopy.sites[0].source")
        self.assertEqual(wpr.validate(with_zero_copy(source="")), [])
        rec = with_zero_copy()
        rec["zeroCopy"]["sites"][0]["extra"] = 1
        self.assertRefused(reseal(rec), "unknown-field: zeroCopy.sites[0].extra")

    def test_s5_buffer_sites(self):
        site = {"function": "handle_request", "buffer": "key", "bytes": 32, "reason": "wipe", "anchor": "clobber"}
        rec = good_record(bufferBarriers={"enabled": True, "count": 1, "sites": [site]})
        self.assertRefused(rec, "bad-reason")
        site = dict(site, reason="memset", anchor="end")
        rec = good_record(bufferBarriers={"enabled": True, "count": 1, "sites": [site]})
        self.assertRefused(rec, "bad-anchor")

    def test_s6_host(self):
        rec = good_record()
        rec["host"]["mismatch"] = False
        self.assertRefused(reseal(rec), "unknown-field: host.mismatch")
        rec = good_record()
        rec["host"]["identMajor"] = 0
        self.assertRefused(reseal(rec), "bad-type: host.identMajor")
        rec = good_record()
        rec["host"]["builtMajor"] = None
        self.assertRefused(reseal(rec), "bad-type: host.builtMajor")


class V3Consistency(unittest.TestCase):
    """C1-C7 and W1 of compiler/schema/wipe-pin.md section 14.9."""

    def assertRefused(self, rec, needle, expect=None):
        problems = wpr.validate(rec, expect)
        self.assertTrue(any(needle in p for p in problems), f"{needle!r} not in {problems}")

    def test_switched_records_are_accepted(self):
        self.assertEqual(wpr.validate(with_barrier(), {"barrierCalls": True}), [])
        self.assertEqual(wpr.validate(with_barrier(dry=True)), [])
        self.assertEqual(wpr.validate(with_zero_copy(), {"zeroCopy": True}), [])
        self.assertEqual(wpr.validate(with_zero_copy(dry=True)), [])
        both = with_zero_copy(with_barrier())
        self.assertEqual(wpr.validate(both, {"barrierCalls": True, "zeroCopy": True, "bufferBarriers": False}), [])

    def test_c1_a_switch_that_is_off_lists_and_counts_nothing(self):
        rec = with_barrier()
        rec["barrierCalls"]["enabled"] = False
        self.assertRefused(reseal(rec), "inconsistent: barrierCalls.enabled is false but sites lists 1")
        rec = good_record()
        rec["zeroCopy"]["wouldRepairCount"] = 1
        self.assertRefused(reseal(rec), "inconsistent: zeroCopy.enabled is false but zeroCopy.wouldRepairCount")
        rec = good_record()
        rec["bufferBarriers"]["count"] = 1
        self.assertRefused(reseal(rec), "inconsistent: bufferBarriers.enabled is false")

    def test_c2_a_barrier_that_was_not_placed(self):
        rec = with_barrier()
        rec["barrierCalls"]["barrierCount"] = 0
        self.assertRefused(reseal(rec), "outside a dry run barrierCalls.barrierCount 0 differs")
        rec = with_barrier(dry=True)
        rec["barrierCalls"]["barrierCount"] = 1
        self.assertRefused(reseal(rec), "inconsistent: dry run with barrierCalls.barrierCount")
        rec = with_barrier()
        rec["barrierCalls"]["wouldBarrierCount"] = 2
        self.assertRefused(reseal(rec), "inconsistent: barrierCalls.wouldBarrierCount 2, sites lists 1")

    def test_c3_the_same_for_zero_copy(self):
        rec = with_zero_copy()
        rec["zeroCopy"]["repairedCount"] = 0
        self.assertRefused(reseal(rec), "outside a dry run zeroCopy.repairedCount 0 differs")
        rec = with_zero_copy(dry=True)
        rec["zeroCopy"]["wouldRepairCount"] = 2
        self.assertRefused(reseal(rec), "inconsistent: zeroCopy.wouldRepairCount 2, sites lists 1")

    def test_c4_buffer_count_is_the_list_outside_a_dry_run(self):
        site = {"function": "handle_request", "buffer": None, "bytes": 32, "reason": "memset", "anchor": "clobber"}
        rec = good_record(bufferBarriers={"enabled": True, "count": 0, "sites": [site]})
        self.assertRefused(rec, "inconsistent: outside a dry run bufferBarriers.count 0")
        self.assertEqual(wpr.validate(good_record(bufferBarriers={"enabled": True, "count": 1, "sites": [site]})), [])
        rec = good_record(dryRun=True, pinnedCount=0, bufferBarriers={"enabled": True, "count": 1, "sites": [site]})
        self.assertRefused(rec, "inconsistent: dry run with bufferBarriers.count")

    def test_c5_sites_in_requested_functions_only(self):
        self.assertRefused(with_barrier(function="helper"), "barrierCalls site in helper, which was not requested")
        self.assertRefused(with_zero_copy(function="helper"), "zeroCopy site in helper, which was not requested")
        # In module scope any function may have one.
        rec = good_record(scope="module", requested=[], resolution=[])
        rec["pinned"][0]["function"] = "helper"
        self.assertEqual(wpr.validate(with_barrier(rec, function="other")), [])

    def test_c6_host(self):
        rec = good_record()
        rec["host"].update(identMajor=None)
        self.assertRefused(reseal(rec), "inconsistent: host.checked True with identMajor None")
        rec = good_record()
        rec["host"].update(ident="14.2.0", identMajor=14)
        self.assertRefused(reseal(rec), "differs from builtMajor")
        rec = good_record()
        rec["host"].update(ident="12.4.0")
        self.assertRefused(reseal(rec), "does not re-derive from host.ident")
        rec = good_record()
        rec["host"].update(ident="13.3.0 (Ubuntu)")
        self.assertRefused(reseal(rec), "parenthesised")
        rec = good_record()
        rec["host"].update(ident="14.2.0", identMajor=14, builtMajor=14)
        self.assertRefused(reseal(rec), "is not the major of toolchain.gcc")

    def test_c7_the_gcc_column(self):
        self.assertRefused(with_zero_copy(form="intrinsic", callee="llvm.memcpy"), "bad-form")
        self.assertRefused(with_zero_copy(callee="memcpy"), "inconsistent: zeroCopy.sites[0] form aggregate")
        self.assertRefused(with_zero_copy(form="call", callee=None), "inconsistent: zeroCopy.sites[0] form call")
        self.assertEqual(wpr.validate(with_zero_copy(form="builtin", callee="memcpy")), [])
        self.assertEqual(wpr.validate(with_zero_copy(form="call", callee="__builtin___memcpy_chk")), [])
        site = {"function": "handle_request", "buffer": "key", "bytes": 32, "reason": "memset",
                "anchor": "lifetime-end"}
        self.assertRefused(good_record(bufferBarriers={"enabled": True, "count": 1, "sites": [site]}),
                           "bad-anchor: bufferBarriers.sites[0].anchor lifetime-end on WipePinGcc")
        rec = good_record()
        rec["host"].update(ident=None, identMajor=None, checked=False)
        self.assertRefused(reseal(rec), "WipePinGcc host must be checked")
        rec = good_record()
        rec["host"]["intrinsicsCompared"] = 0
        self.assertRefused(reseal(rec), "intrinsicsCompared must be null")
        # GCC's barrierCalls callee is the DECL_NAME, not one of LLVM's family.
        self.assertEqual(wpr.validate(with_barrier(callee="__builtin___memset_chk")), [])

    def test_w1_what_the_caller_set(self):
        self.assertRefused(with_barrier(), "wrong-compile: barrierCalls.enabled True", OFF)
        self.assertRefused(good_record(), "wrong-compile: zeroCopy.enabled False", {"zeroCopy": True})
        self.assertEqual(wpr.validate(with_barrier(), {"zeroCopy": False}), [])
        with self.assertRaises(ValueError):
            wpr.validate(good_record(), {"bufferBarrier": False})

    def test_repair_count_is_the_four_counts(self):
        self.assertEqual(wpr.repair_count(good_record()), 1)
        rec = good_record(pinned=[], pinnedCount=0, wouldPinCount=0,
                          seen={"zeroFillMemsetInScope": 0, "zeroFillMemsetInModule": 0})
        self.assertEqual(wpr.repair_count(rec), 0)
        self.assertEqual(wpr.repair_count(with_barrier(rec)), 1)
        self.assertEqual(wpr.repair_count(with_zero_copy(with_barrier(rec))), 2)
        self.assertEqual(wpr.repair_count(with_barrier(rec, dry=True)), 0)


class Cli(unittest.TestCase):
    def run_main(self, text, *opts):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = wpr.main(["wpin_gcc_record.py", *opts, p])
            return rc, buf.getvalue().splitlines()

    def test_summary_lines_for_pin_gcc_sh(self):
        rec = good_record()
        rc, lines = self.run_main(json.dumps(rec))
        self.assertEqual(rc, 0)
        self.assertEqual(lines, ["pinnedCount=1", "wouldPinCount=1", "followedByUseCount=0",
                                 "unresolved=", "exactAll=true", "barrierCount=0", "wouldBarrierCount=0",
                                 "zeroCopyRepairedCount=0", "wouldZeroCopyCount=0", "bufferBarrierCount=0",
                                 "repairCount=1"])

    def test_a_barrier_alone_is_a_repair(self):
        rec = with_barrier(good_record(pinned=[], pinnedCount=0, wouldPinCount=0,
                                       seen={"zeroFillMemsetInScope": 0, "zeroFillMemsetInModule": 0}))
        rc, lines = self.run_main(json.dumps(rec), "--expect", "barrierCalls=1,zeroCopy=0,bufferBarriers=0")
        self.assertIn("barrierCount=1", lines)
        self.assertEqual(lines[0], "pinnedCount=0")
        self.assertEqual(lines[-1], "repairCount=1")

    def test_expect_is_compared(self):
        rc, lines = self.run_main(json.dumps(with_barrier()), "--expect", "barrierCalls=0")
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("error=wrong-compile: barrierCalls.enabled True"), lines)
        rc, lines = self.run_main(json.dumps(good_record()), "--expect", "barrierCalls=2")
        self.assertEqual(rc, 0)
        self.assertTrue(lines[0].startswith("error=usage: --expect"), lines)

    def test_an_unusable_record_is_one_error_line(self):
        rc, lines = self.run_main("{not json")
        self.assertEqual((rc, lines), (0, ["error=not-json"]))
        rc, lines = self.run_main(json.dumps(good_record(component="WipePin")))
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("error=wrong-component"))

    def test_a_missing_file(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            wpr.main(["wpin_gcc_record.py", os.path.join(HERE, "no-such-record.json")])
        self.assertTrue(buf.getvalue().startswith("error=unreadable"))

    def test_parse_expect(self):
        self.assertEqual(wpr.parse_expect("barrierCalls=1, zeroCopy=0"), {"barrierCalls": True, "zeroCopy": False})
        self.assertEqual(wpr.parse_expect(""), {})
        for bad in ("barrierCalls", "barrierCalls=yes", "bufferBarrier=0"):
            with self.assertRaises(ValueError):
                wpr.parse_expect(bad)


if __name__ == "__main__":
    unittest.main()
