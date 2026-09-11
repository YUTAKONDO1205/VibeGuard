#!/usr/bin/env python3
"""Unit tests for scripts/wpin_gcc_record.py, the strict wipe-pin-v2 reader.

    python3 compiler/gcc-repair/test/test_wpin_gcc_record.py

(run as a file: the directory name has a hyphen, so it is not importable as a
package, and `python3 -m unittest` cannot address it by module name).

The canonical serialiser is calibrated against the shared vectors in
compiler/evidence/testdata/digest-vectors.json -- the same calibration the C++
writer in ../src/Canon.cpp is held to by canon-vectors -- and the reader is
shown to refuse each way a record can be wrong.
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


def good_record(**over):
    """A record shaped the way WipePinGcc writes one, sealed here."""
    pkgs = [{"name": "gcc", "version": "13.3.0"}]
    rec = {
        "schemaVersion": "wipe-pin-v2", "component": "WipePinGcc", "module": "target.c",
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
        "unhandled": {"libcallMemset": 0, "memsetChk": 0, "nonZeroFill": 0, "atomicMemset": 0,
                      "inlineWrapperMemset": 0},
        "context": {"generatedAt": 1789136746, "timeSource": "wall-clock", "sourceDateEpoch": None},
    }
    rec.update(over)
    return reseal(rec)


def reseal(rec):
    rec = copy.deepcopy(rec)
    rec.pop("evidenceDigest", None)
    rec["evidenceDigest"] = wpr.evidence_digest(rec)
    return rec


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


class Validate(unittest.TestCase):
    def test_a_good_record_is_accepted(self):
        self.assertEqual(wpr.validate(good_record()), [])

    def test_context_is_outside_the_digest(self):
        rec = good_record()
        rec["context"]["generatedAt"] = 0
        self.assertEqual(wpr.validate(rec), [])

    def assertRefused(self, rec, needle):
        problems = wpr.validate(rec)
        self.assertTrue(any(needle in p for p in problems), f"{needle!r} not in {problems}")

    def test_an_edit_after_the_compile_is_refused(self):
        rec = good_record()
        rec["pinned"][0]["followedByUse"] = True
        self.assertRefused(rec, "digest-mismatch")

    def test_a_v1_record_is_refused(self):
        self.assertRefused(good_record(schemaVersion="wipe-pin-v1"), "unknown-schemaVersion")

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
        rec = good_record()
        rec["unhandled"]["atomicMemset"] = 1
        self.assertRefused(reseal(rec), "GCC has no such shape")

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


class Cli(unittest.TestCase):
    def run_main(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = wpr.main(["wpin_gcc_record.py", p])
            return rc, buf.getvalue().splitlines()

    def test_summary_lines_for_pin_gcc_sh(self):
        rec = good_record()
        rc, lines = self.run_main(json.dumps(rec))
        self.assertEqual(rc, 0)
        self.assertEqual(lines, ["pinnedCount=1", "wouldPinCount=1", "followedByUseCount=0",
                                 "unresolved=", "exactAll=true"])

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


if __name__ == "__main__":
    unittest.main()
