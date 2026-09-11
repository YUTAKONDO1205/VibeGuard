#!/usr/bin/env python3
"""Grade the fixture loop written by run-fixture-loop.sh. Compiles nothing.

    python3 compiler/llvm-repair/scripts/check-fixture-loop.py --lab DIR

The instrument being read in the loop cells is the IR observer (IrCheckpoints),
not WipePin. WipePin's own record is read too, but only to check that it says
what the cell asked of it -- it never decides whether the wipe survived. That is
the observer's verdict, taken from the same record shape the optimisation matrix
grades, on the same fixture, with the same effect-symbol list.

The shape and stale cells are about WipePin's own account of itself: what its
wipe-pin-v2 record and its stderr say for a source whose answer is known, and
whether a record from an earlier compile can outlive a compile that wrote none.
The lto cells are about the hosts where the pass cannot run at all: an LTO
link with the plugin on its link line (full and thin, -O2 and thin at -O0) must
say so, once, leave the linked output exactly as a stock link leaves it, and
say whether a file was at WPIN_OUT when the plugin loaded -- the record its
compile step wrote there, removed, or nothing; a compile under
-disable-llvm-passes that writes IR must say the same line and write no record.
The xtu cells are about a loss only a link can create: a wipe helper in another
translation unit, inlined by LTO into a caller whose buffer then dies. Their
output is an executable, which this script disassembles itself (objdump -d,
read by ../../gcc-repair/scripts/objdump_fill.py, imported and not copied, the
reader the WipePinGcc loop uses for the same cells). Which LTO a cell ran is
read from its objects -- the block each -flto object's module summary is in,
through llvm-bcanalyzer-18 -dump -- and from the executable, which linker from
its .comment and which link from whether it still defines the helper, not from
what the runner says it ran; so objdump and llvm-bcanalyzer-18 are required.

The expectations below were written from what each cell is for, before the
cells were first run. A cell that disagrees is printed as a disagreement and the
run fails; the tables are never edited into agreement.

Exit codes (compiler/schema/interfaces.md section 7):
    0  every expectation held
    2  at least one expectation did not
    3  a record was missing or unreadable, or an executable could not be
       disassembled or an object's summary read, so the loop could not be
       graded
"""

import argparse
import copy
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "gcc-repair", "scripts"))
import objdump_fill  # noqa: E402

SCHEMA = "wipe-pin-v2"

# --------------------------------------------------------------- expectations
#
# base-*       observer only. The erasure fixture's subject wipe is a dead
#              store: -O0/-O1 keep it through the IR optimiser, -O2/-O3 lose it
#              at DSEPass (compiler/llvm-pass/README.md, the erasure row).
# pin-*        observer + WipePin on the subject. The wipe must be PRESENT at
#              the post-optimisation checkpoint at every level, as a volatile
#              llvm.memset, and WipePin must say it pinned exactly one site --
#              the subject's trailing memset, which nothing uses afterwards
#              (followedByUse false). pin.sh on the same settings exits 0.
# dry-O2       the red control: WipePin loaded, told to change nothing. The loss
#              must come back exactly as in base-O2, and pin.sh exits 4: a
#              record was written and nothing was repaired.
# wrongname-O2 WipePin loaded against a name that does not exist. It must pin
#              nothing, say not-in-module, the loss must come back, and pin.sh
#              exits 4.
#
# The control (wipe_kept) must hold in every cell; a cell whose control fell
# says nothing about the subject.

LEVELS = ["-O0", "-O1", "-O2", "-O3"]

EXPECT = {}
for _o in LEVELS:
    _lost = _o in ("-O2", "-O3")
    EXPECT["base" + _o] = {
        "opt": _o, "pin": False,
        "state": "LOST" if _lost else "PRESENT",
        "fzt": "DSEPass" if _lost else None,
        "volatile": 0,
    }
    EXPECT["pin" + _o] = {
        "opt": _o, "pin": True,
        "state": "PRESENT", "fzt": None, "volatileAtLeast": 1,
        "pinnedCount": 1, "wouldPinCount": 1, "dryRun": False,
        "resolution": "resolved", "requested": "handle_request",
        "exact": True, "linkage": "external", "pinShRc": 0,
        "stderrLine": None,
    }
EXPECT["dry-O2"] = {
    "opt": "-O2", "pin": True,
    "state": "LOST", "fzt": "DSEPass", "volatile": 0,
    "pinnedCount": 0, "wouldPinCount": 1, "dryRun": True,
    "resolution": "resolved", "requested": "handle_request",
    "exact": True, "linkage": "external", "pinShRc": 4,
    "stderrLine": "WipePin: dry run: 1 zero-fill llvm.memset site(s) would be pinned; none was changed",
}
EXPECT["wrongname-O2"] = {
    "opt": "-O2", "pin": True,
    "state": "LOST", "fzt": "DSEPass", "volatile": 0,
    "pinnedCount": 0, "wouldPinCount": 0, "dryRun": False,
    "resolution": "not-in-module", "requested": "handle_requestX",
    "exact": None, "linkage": None, "pinShRc": 4,
    "stderrLine": "WipePin: target handle_requestX not-in-module",
}

ORDER = [f"base{o}" for o in LEVELS] + [f"pin{o}" for o in LEVELS] + ["dry-O2", "wrongname-O2"]

SPEEDUP = {"-O0": 0, "-O1": 1, "-O2": 2, "-O3": 3}

# pin.sh alone, where the only right answer is 3: no record from this compile.
PINSH_ONLY = {
    "notarget-O2": {"pinShRc": 3, "stderrLine": "WipePin: refusing to install: no target"},
    "nollvmpasses-O2": {"pinShRc": 3, "stderrLine": None},
}

# The shapes, all -g, one target each, at -O2 unless `opt` says otherwise.
# `sites` is followedByUse for each recorded site in order; `partial` is
# (pinned, followed) for the one line the plugin must print, or None where it
# must print none.
#
# loopreturn* (added with wipe-pin-v2): the error-path memset inside the loop is
# followed only by `return`, so it is false at every level -- at -O1 and -O2 the
# CFG has an edge from it back into the loop, through clang's cleanup dispatch,
# that no execution takes (wipe-pin-v1 read true there, and printed the partial
# line). The trailing memset is false everywhere.
# loopbreakuse*: the soundness guard. Same loop, `break` instead of `return`,
# and the buffer is read after the loop: true at every level, partial line
# included. The break reaches the read THROUGH the dispatch switch, on the edge
# its own stored constant selects.
LOOP_SHAPES = {}
for _o, _sfx in (("-O2", ""), ("-O0", "-O0"), ("-O1", "-O1")):
    LOOP_SHAPES["loopreturn" + _sfx] = {
        "module": "loopreturn.c", "target": "handle", "opt": _o, "sites": [False, False],
        "partial": None, "exact": True, "linkage": "external"}
    LOOP_SHAPES["loopbreakuse" + _sfx] = {
        "module": "loopbreakuse.c", "target": "handle", "opt": _o, "sites": [True],
        "partial": (1, 1), "exact": True, "linkage": "external"}

SHAPES = {
    "initloop": {"module": "initloop.c", "target": "handle", "sites": [True],
                 "partial": (1, 1), "exact": True, "linkage": "external"},
    "inithelper": {"module": "inithelper.c", "target": "handle", "sites": [True],
                   "partial": (1, 1), "exact": True, "linkage": "external"},
    "initwipe": {"module": "initwipe.c", "target": "handle", "sites": [True, False],
                 "partial": (2, 1), "exact": True, "linkage": "external"},
    "aliasinit": {"module": "aliasinit.c", "target": "handle", "sites": [True],
                  "partial": (1, 1), "exact": True, "linkage": "external"},
    "trailing": {"module": "trailing.c", "target": "handle", "sites": [False],
                 "partial": None, "exact": True, "linkage": "external"},
    "c99inline": {"module": "c99inline.c", "target": "wipe_inline", "sites": [False],
                  "partial": None, "exact": False, "linkage": "available_externally"},
    "cxxinline": {"module": "cxxinline.cpp", "target": "wipe_cxx", "sites": [False],
                  "partial": None, "exact": False, "linkage": "linkonce_odr"},
    **LOOP_SHAPES,
}
SHAPE_ORDER = ["initloop", "inithelper", "initwipe", "aliasinit", "trailing", "c99inline", "cxxinline",
               "loopreturn-O0", "loopreturn-O1", "loopreturn",
               "loopbreakuse-O0", "loopbreakuse-O1", "loopbreakuse"]

# A file that is not this compile's record sits at WPIN_OUT before each compile.
STALE = {
    "stale-refused": {"before": "file", "after": "absent",
                      "stderrLine": "WipePin: refusing to install: no target"},
    "stale-nopasses": {"before": "file", "after": "absent", "stderrLine": None},
    "stale-live": {"before": "file", "after": "file", "stderrLine": None},
    "stale-dir": {"before": "dir", "after": "dir",
                  "stderrLine": "WipePin: refusing to install: WPIN_OUT is a directory"},
}
STALE_ORDER = ["stale-refused", "stale-nopasses", "stale-live", "stale-dir"]

# The LTO cells, and the one compile that builds no pipeline, all on the
# trailing shape with target `handle`, at -O2 unless `opt` says otherwise.
#
# lto-full-compile   WipePin at -flto compile time. The compile builds a
#                    pipeline with pipeline start, so the pass runs there: a
#                    valid record (one site, followedByUse false, pinnedCount
#                    1), a bitcode object, and no WipePin line at all -- in
#                    particular not the link-time one.
# lto-*-linkline     the same compile, then a link with WipePin on the link line
#                    and the same WPIN_OUT / WPIN_TARGET_FNS. The link's
#                    pipeline has no pipeline start, so the pass does not run:
#                    link rc 0, exactly one WipePin line on the link's stderr and
#                    it is LINK_LINE_REMOVED (the compile's record was at
#                    WPIN_OUT and the plugin's load removed it), nothing at
#                    WPIN_OUT afterwards (no record written), and the linked
#                    shared object byte-identical to a stock link of the same
#                    bitcode. The compile half is graded as lto-full-compile is.
# lto-thin-linkline-O0
#                    the thin form with the compile and both links at -O0. A
#                    ThinLTO link at -O0 invokes no extension point at all
#                    (src/WipePin.cpp, "the pipeline without pipeline start"),
#                    which is why the line comes from a pass-instrumentation
#                    callback rather than a pass; this is the cell that shows
#                    it. Graded as the -O2 linkline cells are, the compile's
#                    record at optLevel.speedup 0.
# lto-full-linkline-nofile
#                    a full-LTO linkline whose compile record was moved aside
#                    before the link, so nothing is at WPIN_OUT when the plugin
#                    loads: exactly one line, and it is LINK_LINE_NOFILE.
#                    Otherwise graded as lto-full-linkline.
# nopasses-ir-O2     no LTO: a compile under -Xclang -disable-llvm-passes -S
#                    -emit-llvm with WipePin and nothing at WPIN_OUT. clang
#                    builds no optimisation pipeline, but runs the IR printer as
#                    a pass, so the same callback speaks: rc 0, exactly one
#                    WipePin line and it is LINK_LINE_NOFILE, no record at
#                    WPIN_OUT afterwards, and the IR it wrote still holds the
#                    trailing llvm.memset with none of them volatile.
NO_START_PREFIX = (
    "WipePin: loaded into a pipeline built without the pipeline-start extension point "
    "(an LTO link, or a compile under -disable-llvm-passes), where this pass does not run; "
    "nothing was pinned in this process, and ")
LINK_LINE_REMOVED = NO_START_PREFIX + "the file at WPIN_OUT was removed when the plugin loaded"
LINK_LINE_NOFILE = NO_START_PREFIX + "there was no file at WPIN_OUT when the plugin loaded"
LINK_LINE_PREFIX = "WipePin: loaded into a pipeline built without the pipeline-start extension point"
LTO = {
    "lto-full-compile": {"form": "full", "what": "compile", "opt": "-O2"},
    "lto-full-linkline": {"form": "full", "what": "linkline", "opt": "-O2", "line": LINK_LINE_REMOVED},
    "lto-thin-linkline": {"form": "thin", "what": "linkline", "opt": "-O2", "line": LINK_LINE_REMOVED},
    "lto-thin-linkline-O0": {"form": "thin", "what": "linkline", "opt": "-O0", "line": LINK_LINE_REMOVED},
    "lto-full-linkline-nofile": {"form": "full", "what": "linkline-nofile", "opt": "-O2",
                                 "line": LINK_LINE_NOFILE},
    "nopasses-ir-O2": {"form": "none", "what": "nopasses-ir", "opt": "-O2", "line": LINK_LINE_NOFILE},
}
LTO_ORDER = ["lto-full-compile", "lto-full-linkline", "lto-thin-linkline", "lto-thin-linkline-O0",
             "lto-full-linkline-nofile", "nopasses-ir-O2"]

# The xtu cells: a wipe helper in another translation unit, and the loss an LTO
# link creates for it. Every object of the LTO probe is linked alone
# (../../eval/repair-loop/tools/LTO.md, "What this does not claim"), so no helper
# from another unit is ever inlined there. Four units, generated by the runner
# into <lab>/xtu/src and linked into an executable at -O2:
#
#   wipe.c  secure_wipe(void *p, size_t n) { memset(p, 0, n); }, external
#   use.c   handle(): a 32-byte local filled by derive(), read by use(), then
#           secure_wipe(key, sizeof key), its last use -- the subject, and the
#           helper's one caller; and wipe_kept(): a 32-byte local zeroed by a
#           memset of its own and read by use() afterwards -- the control, whose
#           fill cannot be removed in any build. Both noinline, so the function
#           a fill ends up in is the same function in every link.
#   main.c  calls handle() and wipe_kept()
#   io.c    derive() and use(), compiled without -flto in every cell, so that no
#           link sees into them: the buffers must exist in memory, and the read
#           of the control's fill cannot be folded away.
#
# Read from the linked executable, which the checker disassembles itself
# (objdump -d) with gcc-repair's objdump_fill.py, imported and not copied. When
# no call to secure_wipe is left in handle, the helper was inlined and the fill
# can only be in handle: PRESENT when its zero stores cover the 32 bytes or it
# calls memset, ABSENT when there are none. When the call is left, the fill is
# wherever secure_wipe does it: PRESENT when its body calls or tail-calls memset.
# The control is read the same way in wipe_kept, with no helper involved.
#
# xtu-nolto       stock, no LTO. Each unit is optimised alone, so use.c cannot
#                 see into secure_wipe: the call stays (inlined: no) and the
#                 fill is secure_wipe's memset, on a length the helper does not
#                 know (PRESENT). The premise: the helper keeps the wipe.
# xtu-<f>-stock   -flto / -flto=thin compiles and a stock LTO link (lld). The link
#                 sees secure_wipe's body and inlines it into handle (inlined:
#                 yes), where the fill is a store to a local that dies right after
#                 it: a dead store, gone (ABSENT). The same source reads PRESENT
#                 in xtu-nolto; the loss is the link's.
# xtu-<f>-pin     WipePin at the compile of wipe.c only (WPIN_TARGET_FNS=
#                 secure_wipe, functions scope), every other unit and the link
#                 stock. The memset is volatile in wipe.o's bitcode and stays
#                 volatile where it is inlined: PRESENT in handle, the whole 32
#                 bytes (inlined: yes), and the executable is not the stock one.
#                 The record: one site in secure_wipe, destKind argument (the
#                 helper's parameter), lengthBytes null (not a constant inside
#                 the helper), followedByUse null (not a local), line null (no
#                 -g), pinnedCount 1; no WipePin line on the compile's stderr.
# xtu-<f>-dry     the same with WPIN_DRY_RUN=1: the red control. ABSENT and
#                 inlined as in xtu-<f>-stock, the executable byte-identical to
#                 xtu-<f>-stock's, pinnedCount 0 / wouldPinCount 1 and the dry-run
#                 line.
# In every cell the control (wipe_kept) is PRESENT; no link loads WipePin, so no
# link prints a WipePin line; every -flto object is bitcode, and io.o never is.
#
# What a cell was built as is read from what the build left, not from the
# runner's form=. Every main.o, use.o and wipe.o of an xtu-<f> cell holds one
# module summary, and it is of form <f>: clang -flto=thin writes the summary as
# a GLOBALVAL_SUMMARY_BLOCK, clang -flto as a FULL_LTO_GLOBALVAL_SUMMARY_BLOCK
# (llvm/Bitcode/LLVMBitCodes.h), read here with llvm-bcanalyzer-18 -dump. That
# block, not the flag on the link line, decides the LTO lld runs: with
# -Wl,--save-temps on this fixture's objects, the thin ones linked with plain
# -flto still ran a ThinLTO backend per module (wipe.o.3.import.bc,
# prog.index.bc), the full ones linked with -flto=thin still ran one merged
# module (prog.0.4.opt.bc), and each executable was byte-identical to the
# lab's of the objects' form. And every executable, xtu-nolto's included, was
# linked by lld, as the runner's -fuse-ld=lld asks: lld writes
# "Linker: <version>" into .comment, and GNU ld, which clang-18 runs without
# -fuse-ld=lld, wrote no such string.
#
# The executable itself says which link made it, and that is read too, from
# whether it still defines secure_wipe (XTU_HELPER_DEFINED). This one is
# measured, not predicted: without LTO the helper is defined and called; after
# a ThinLTO link it is defined and called from nowhere; after a full-LTO link it
# is not there. The same -Wl,--save-temps links show why: under ThinLTO each
# module has a backend of its own, wipe.o's keeps secure_wipe external
# (wipe.o.2.internalize.bc) while use.o's imports a copy, available_externally,
# and inlines it (use.o.3.import.bc); under full LTO the one merged module makes
# it internal (prog.0.2.internalize.bc) and drops it once inlined
# (prog.0.4.opt.bc). The summary blocks tie a cell to the objects beside its
# executable; this ties it to the executable.
#
# These checks came after the cells' first runs. A review showed that the
# four-byte magic, all that was read before, says bitcode for both forms: with
# the runner's thin line reduced to plain -flto, the three xtu-thin-* cells were
# full-LTO cells under another name, and this loop still read all 42 cells as
# expected; with -fuse-ld=lld taken out (and the thin form's lld-only
# --thinlto-jobs), every executable was GNU ld's, and it still did. The summary
# and linker checks expect what the cells were defined as; with them alone, the
# three thin executables replaced by the full ones, their objects left beside
# them, still read all 42 cells as expected, which is what the helper check is
# for (../README.md, the xtu cells).
#
# The first run was of another fixture, and this one replaced it. There the
# control went through the helper too (wipe_kept called secure_wipe on a buffer
# use() read afterwards), with the control expected PRESENT and inlined wherever
# handle's call was, so secure_wipe had two callers. Measured: this loop read all
# 42 cells as expected; the WipePinGcc loop read xtu-lto-pin as not inlined --
# gcc-13 kept the pinned helper out of line, as an IPA-CP clone called from both
# functions (../../gcc-repair/README.md, the xtu cells). The subject's
# expectations above are the ones first written; only the control's changed,
# with its design.
XTU_FILL_BYTES = 32
XTU_FORMS = ("full", "thin")
# Whether each form's executable defines secure_wipe: measured (above).
XTU_HELPER_DEFINED = {"none": True, "full": False, "thin": True}
XTU_SITE = {"function": "secure_wipe", "index": 0, "lengthBytes": None, "destKind": "argument",
            "alreadyVolatile": False, "followedByUse": None, "line": None}
XTU_RESOLUTION = [{"name": "secure_wipe", "resolution": "resolved", "exact": True, "linkage": "external"}]
XTU_DRY_LINE = "WipePin: dry run: 1 zero-fill llvm.memset site(s) would be pinned; none was changed"
XTU = {"xtu-nolto": {"form": "none", "mode": "stock", "inlined": False, "subject": "PRESENT",
                     "sameAsStock": None}}
for _f in XTU_FORMS:
    XTU[f"xtu-{_f}-stock"] = {"form": _f, "mode": "stock", "inlined": True, "subject": "ABSENT",
                              "sameAsStock": None}
    XTU[f"xtu-{_f}-pin"] = {"form": _f, "mode": "pin", "inlined": True, "subject": "PRESENT",
                            "sameAsStock": False, "pinnedCount": 1, "wouldPinCount": 1, "dryRun": False,
                            "lines": []}
    XTU[f"xtu-{_f}-dry"] = {"form": _f, "mode": "dry", "inlined": True, "subject": "ABSENT",
                            "sameAsStock": True, "pinnedCount": 0, "wouldPinCount": 1, "dryRun": True,
                            "lines": [XTU_DRY_LINE]}
XTU_ORDER = ["xtu-nolto"] + [f"xtu-{_f}-{_m}" for _f in XTU_FORMS for _m in ("stock", "pin", "dry")]

NO_UNHANDLED = "libcallMemset=0 memsetChk=0 nonZeroFill=0 atomicMemset=0 inlineWrapperMemset=0"


def partial_line(pinned, followed, module, unhandled=NO_UNHANDLED):
    return (f"WipePin: partial: pinned {pinned} site(s) in {module}; {followed} followed by a "
            f"later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: "
            f"{unhandled}")


def nonexact_line(name, linkage):
    return (f"WipePin: target {name} is not an exact definition ({linkage}); "
            f"the copy that runs may come from another translation unit")


class Incomplete(Exception):
    pass


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise Incomplete(f"{path}: {e}")


def load_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().split("\n")
    except OSError as e:
        raise Incomplete(f"{path}: {e}")


def load_kv(path):
    out = {}
    for line in load_lines(path):
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def digest_of(rec):
    """interfaces.md section 5, re-derived here rather than trusted."""
    stripped = {k: v for k, v in rec.items() if k not in ("context", "evidenceDigest")}
    return sha256_text(canonical(stripped))


ABS_PATH = re.compile(r"(^/|^[A-Za-z]:[\\/]|/home/|/root/|\\Users\\)")


def absolute_paths(node, where="$"):
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += absolute_paths(k, where + ".<key>")
            out += absolute_paths(v, f"{where}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += absolute_paths(v, f"{where}[{i}]")
    elif isinstance(node, str) and ABS_PATH.search(node):
        out.append(f"{where}={node!r}")
    return out


def v2_problems(pin):
    """What every wipe-pin-v2 record must be, whatever the cell asked of it."""
    bad = []
    if pin.get("schemaVersion") != SCHEMA:
        bad.append(f"schemaVersion {pin.get('schemaVersion')!r}, expected {SCHEMA!r}")
    if pin.get("component") != "WipePin":
        bad.append(f"component {pin.get('component')!r}")
    tc = pin.get("toolchain")
    if not isinstance(tc, dict) or sorted(tc) != ["clang", "digest", "packages"]:
        bad.append(f"toolchain is not {{digest, clang, packages}}: {tc!r}")
    else:
        want = sha256_text(canonical({"clang": tc["clang"], "packages": tc["packages"]}))
        if tc["digest"] != want:
            bad.append("toolchain.digest is not the sha256 of {clang, packages}")
        if not isinstance(tc["packages"], list) or not all(
                isinstance(p, dict) and sorted(p) == ["name", "version"] for p in tc["packages"]):
            bad.append(f"toolchain.packages is not a list of {{name, version}}: {tc['packages']!r}")
    for site in pin.get("pinned") or []:
        if "followedByUse" not in site or site["followedByUse"] not in (True, False, None):
            bad.append(f"pinned site without a true/false/null followedByUse: {site}")
        if site.get("destKind") == "alloca" and site.get("followedByUse") is None:
            bad.append(f"alloca site with followedByUse null: {site}")
        if site.get("destKind") != "alloca" and site.get("followedByUse") is not None:
            bad.append(f"non-alloca site with followedByUse not null: {site}")
    for r in pin.get("resolution") or []:
        if r.get("resolution") == "resolved":
            if not isinstance(r.get("exact"), bool) or not isinstance(r.get("linkage"), str):
                bad.append(f"resolved name without a boolean exact and a string linkage: {r}")
        elif r.get("exact") is not None or r.get("linkage") is not None:
            bad.append(f"unresolved name with a non-null exact or linkage: {r}")
    if pin.get("evidenceDigest") != digest_of(pin):
        bad.append("evidenceDigest does not re-derive")
    leaks = absolute_paths({k: v for k, v in pin.items() if k != "context"})
    if leaks:
        bad.append(f"record carries an absolute path: {leaks}")
    return bad


def wipepin_lines(lines):
    return [l for l in lines if l.startswith("WipePin:")]


def subject_ir(snapshot_path, fn):
    """The subject function's text from the observer's post-opt snapshot."""
    lines = load_lines(snapshot_path)
    start = None
    for i, line in enumerate(lines):
        if line.startswith("define ") and f"@{fn}(" in line:
            start = i
            break
    if start is None:
        return None
    body = []
    for line in lines[start:]:
        body.append(line)
        if line == "}":
            break
    return body


def volatile_memsets(body):
    return sum(1 for l in body if "call void @llvm.memset" in l and "i1 true)" in l)


def sha_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def grade(lab, registry_symbols):
    rows, problems, incomplete = [], [], []
    for cell in ORDER:
        exp = EXPECT[cell]
        try:
            obs = load_json(os.path.join(lab, "records", cell + ".json"))
            body = subject_ir(os.path.join(lab, "snapshots", cell, "post-opt-ir.ll"), "handle_request")
            stderr = load_lines(os.path.join(lab, "stderr", cell + ".txt"))
            kv = load_kv(os.path.join(lab, "cells", cell + ".kv"))
            pin = load_json(os.path.join(lab, "wipepin", cell + ".json")) if exp["pin"] else None
            pinsh_rec = pinsh_man = None
            if exp["pin"]:
                pinsh_man = load_kv(os.path.join(lab, "pinsh", cell + ".manifest.kv"))
                pinsh_rec = load_json(os.path.join(lab, "pinsh", cell + ".json"))
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue

        bad = []
        state = obs["verdict"]["state"]
        fzt = obs["firstZeroTransition"]["pass"]
        held = obs["control"]["held"]
        pre = obs["subject"]["preOptIr"]["effect"]
        post = obs["subject"]["postOptIr"]["effect"]
        vol = volatile_memsets(body) if body is not None else None

        if obs.get("oracle", {}).get("symbols") != registry_symbols:
            bad.append(f"observer counted with {obs.get('oracle', {}).get('symbols')}, not the registered list")
        if state != exp["state"]:
            bad.append(f"verdict {state}, expected {exp['state']}")
        if fzt != exp["fzt"]:
            bad.append(f"firstZeroTransition {fzt}, expected {exp['fzt']}")
        if held is not True:
            bad.append("control did not hold")
        if pre < 1:
            bad.append(f"subject pre-opt effect {pre}: the wipe was not there to begin with")
        if vol is None:
            bad.append("subject function absent from the post-opt snapshot")
        elif "volatile" in exp and vol != exp["volatile"]:
            bad.append(f"{vol} volatile llvm.memset in the subject post-opt, expected {exp['volatile']}")
        elif "volatileAtLeast" in exp and vol < exp["volatileAtLeast"]:
            bad.append(f"{vol} volatile llvm.memset in the subject post-opt, expected >= {exp['volatileAtLeast']}")

        pinsum, fbu, pinshrc = "-", "-", "-"
        if pin is not None:
            res = pin.get("resolution") or []
            resword = res[0]["resolution"] if len(res) == 1 else f"{len(res)} names"
            pinsum = f"{pin.get('pinnedCount')}/{pin.get('wouldPinCount')}/{'dry' if pin.get('dryRun') else 'live'}/{resword}"
            fbu = ",".join(str(s.get("followedByUse")).lower() for s in pin.get("pinned") or []) or "-"
            checks = [
                ("module", pin.get("module"), "target.c"),
                ("scope", pin.get("scope"), "functions"),
                ("requested", pin.get("requested"), [exp["requested"]]),
                ("resolution", resword, exp["resolution"]),
                ("resolution[0].exact", (res[0] if res else {}).get("exact"), exp["exact"]),
                ("resolution[0].linkage", (res[0] if res else {}).get("linkage"), exp["linkage"]),
                ("pinnedCount", pin.get("pinnedCount"), exp["pinnedCount"]),
                ("wouldPinCount", pin.get("wouldPinCount"), exp["wouldPinCount"]),
                ("dryRun", pin.get("dryRun"), exp["dryRun"]),
                ("optLevel.speedup", (pin.get("optLevel") or {}).get("speedup"), SPEEDUP[exp["opt"]]),
                ("pinned[] length", len(pin.get("pinned") or []), exp["wouldPinCount"]),
                ("toolchain", pin.get("toolchain"), obs.get("toolchain")),
            ]
            for name, got, want in checks:
                if got != want:
                    bad.append(f"WipePin {name} = {got!r}, expected {want!r}")
            for site in pin.get("pinned") or []:
                if site.get("function") != "handle_request" or site.get("destKind") != "alloca" \
                        or site.get("lengthBytes") != 32 or site.get("followedByUse") is not False:
                    bad.append(f"WipePin pinned an unexpected site {site}")
            bad += [f"WipePin {p}" for p in v2_problems(pin)]

            wl = wipepin_lines(stderr)
            if any(l.startswith("WipePin: partial:") for l in wl):
                bad.append("WipePin printed a partial line for the fixture's trailing wipe")
            if exp["stderrLine"] is None:
                if wl:
                    bad.append(f"WipePin printed {wl}, expected nothing")
            elif exp["stderrLine"] not in wl:
                bad.append(f"stderr lacks {exp['stderrLine']!r} (WipePin lines: {wl})")

            # pin.sh, same settings, WipePin alone.
            pinshrc = kv.get("pinShRc")
            if pinshrc != str(exp["pinShRc"]):
                bad.append(f"pin.sh exited {pinshrc}, expected {exp['pinShRc']}")
            if pinsh_man.get("status") != str(exp["pinShRc"]) or pinsh_man.get("rc") != "0":
                bad.append(f"pin.sh manifest status={pinsh_man.get('status')} rc={pinsh_man.get('rc')}")
            if pinsh_man.get("pinnedCount") != str(exp["pinnedCount"]):
                bad.append(f"pin.sh manifest pinnedCount={pinsh_man.get('pinnedCount')}")
            if pinsh_man.get("followedByUseCount") != "0":
                bad.append(f"pin.sh manifest followedByUseCount={pinsh_man.get('followedByUseCount')}")
            want_unres = "" if exp["resolution"] == "resolved" else exp["requested"]
            if pinsh_man.get("unresolved") != want_unres:
                bad.append(f"pin.sh manifest unresolved={pinsh_man.get('unresolved')!r}, expected {want_unres!r}")
            # Loading the observer first must not change what WipePin sees: the
            # two records are the same record, context aside.
            if pinsh_rec.get("evidenceDigest") != pin.get("evidenceDigest"):
                bad.append("the pin.sh record (WipePin alone) differs from the loop's (observer + WipePin)")

        base_obj = sha_file(os.path.join(lab, "objects", "base" + exp["opt"] + ".o"))
        this_obj = sha_file(os.path.join(lab, "objects", cell + ".o"))
        objdiff = "-" if cell.startswith("base") else (
            "?" if base_obj is None or this_obj is None else ("yes" if base_obj != this_obj else "no"))

        rows.append((cell, exp["opt"], "yes" if exp["pin"] else "no", state, f"{pre}->{post}",
                     fzt or "-", "yes" if held else "NO", "?" if vol is None else str(vol),
                     pinsum, fbu, objdiff, pinshrc, "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_pinsh_only(lab):
    rows, problems, incomplete = [], [], []
    for cell, exp in PINSH_ONLY.items():
        try:
            kv = load_kv(os.path.join(lab, "pinsh", cell + ".kv"))
            man = load_kv(os.path.join(lab, "pinsh", cell + ".manifest.kv"))
            stderr = load_lines(os.path.join(lab, "pinsh", cell + ".stderr.txt"))
            console = load_lines(os.path.join(lab, "pinsh", cell + ".console.txt"))
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue
        bad = []
        if kv.get("pinShRc") != str(exp["pinShRc"]):
            bad.append(f"pin.sh exited {kv.get('pinShRc')}, expected {exp['pinShRc']}")
        if man.get("rc") != "0":
            bad.append(f"clang rc {man.get('rc')}, expected 0")
        if man.get("record") != "" or os.path.exists(os.path.join(lab, "pinsh", cell + ".json")):
            bad.append("a record exists")
        if not any("no WipePin record was written" in l for l in console):
            bad.append("pin.sh did not say that no record was written")
        wl = wipepin_lines(stderr)
        if exp["stderrLine"] is None:
            if wl:
                bad.append(f"WipePin printed {wl}, expected nothing")
        elif exp["stderrLine"] not in wl:
            bad.append(f"stderr lacks {exp['stderrLine']!r} (WipePin lines: {wl})")
        rows.append((cell, kv.get("pinShRc"), man.get("rc"), man.get("record") or "-",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_shapes(lab):
    rows, problems, incomplete = [], [], []
    for cell in SHAPE_ORDER:
        exp = SHAPES[cell]
        try:
            kv = load_kv(os.path.join(lab, "shapes", cell + ".kv"))
            man = load_kv(os.path.join(lab, "shapes", cell + ".manifest.kv"))
            stderr = load_lines(os.path.join(lab, "shapes", cell + ".stderr.txt"))
            pin = load_json(os.path.join(lab, "shapes", cell + ".json"))
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue
        bad = [f"record: {p}" for p in v2_problems(pin)]
        sites = pin.get("pinned") or []
        got_fbu = [s.get("followedByUse") for s in sites]
        res = pin.get("resolution") or []
        r0 = res[0] if len(res) == 1 else {}
        followed = sum(1 for v in exp["sites"] if v is True)
        opt = exp.get("opt", "-O2")
        checks = [
            ("opt (runner)", kv.get("opt"), opt),
            ("optLevel.speedup", (pin.get("optLevel") or {}).get("speedup"), SPEEDUP[opt]),
            ("module", pin.get("module"), exp["module"]),
            ("requested", pin.get("requested"), [exp["target"]]),
            ("resolution", r0.get("resolution"), "resolved"),
            ("exact", r0.get("exact"), exp["exact"]),
            ("linkage", r0.get("linkage"), exp["linkage"]),
            ("pinnedCount", pin.get("pinnedCount"), len(exp["sites"])),
            ("followedByUse per site", got_fbu, exp["sites"]),
            ("pin.sh rc", kv.get("pinShRc"), "0"),
            ("manifest status", man.get("status"), "0"),
            ("manifest followedByUseCount", man.get("followedByUseCount"), str(followed)),
            ("manifest unresolved", man.get("unresolved"), ""),
            ("manifest exactAll", man.get("exactAll"), "true" if exp["exact"] else "false"),
        ]
        for name, got, want in checks:
            if got != want:
                bad.append(f"{name} = {got!r}, expected {want!r}")
        for s in sites:
            if s.get("function") != exp["target"] or s.get("destKind") != "alloca" \
                    or s.get("lengthBytes") != 32 or s.get("line") is None:
                bad.append(f"unexpected site {s}")

        wl = wipepin_lines(stderr)
        want_lines = []
        if exp["partial"] is not None:
            want_lines.append(partial_line(exp["partial"][0], exp["partial"][1], exp["module"]))
        if not exp["exact"]:
            want_lines.append(nonexact_line(exp["target"], exp["linkage"]))
        for w in want_lines:
            if w not in wl:
                bad.append(f"stderr lacks {w!r}")
        extra = [l for l in wl if l not in want_lines]
        if extra:
            bad.append(f"unexpected WipePin lines {extra}")

        rows.append((cell, opt, kv.get("pinShRc"), str(pin.get("pinnedCount")),
                     ",".join(str(v).lower() for v in got_fbu) or "-",
                     f"{r0.get('exact')}/{r0.get('linkage')}",
                     "yes" if any(l.startswith("WipePin: partial:") for l in wl) else "no",
                     "yes" if any("is not an exact definition" in l for l in wl) else "no",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_stale(lab):
    rows, problems, incomplete = [], [], []
    for cell in STALE_ORDER:
        exp = STALE[cell]
        out = os.path.join(lab, "stale", cell + ".json")
        try:
            kv = load_kv(os.path.join(lab, "stale", cell + ".kv"))
            stderr = load_lines(os.path.join(lab, "stale", cell + ".stderr.txt"))
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue
        bad = []
        if kv.get("before") != exp["before"]:
            bad.append(f"started with {kv.get('before')}, expected {exp['before']}")
        if kv.get("rc") != "0":
            bad.append(f"clang rc {kv.get('rc')}, expected 0")
        # Read from the disk, not only from what the runner wrote down.
        on_disk = "dir" if os.path.isdir(out) else ("file" if os.path.isfile(out) else "absent")
        if kv.get("after") != exp["after"] or on_disk != exp["after"]:
            bad.append(f"WPIN_OUT after the compile: {kv.get('after')} (runner), {on_disk} (now), "
                       f"expected {exp['after']}")
        wl = wipepin_lines(stderr)
        if exp["stderrLine"] is None:
            if wl:
                bad.append(f"WipePin printed {wl}, expected nothing")
        elif exp["stderrLine"] not in wl:
            bad.append(f"stderr lacks {exp['stderrLine']!r} (WipePin lines: {wl})")
        if cell == "stale-live":
            try:
                rec = load_json(out)
            except Incomplete as e:
                rec = None
                bad.append(f"the compile's record is not JSON: {e}")
            if rec is not None:
                bad += [f"record: {p}" for p in v2_problems(rec)]
                if rec.get("module") != "trailing.c" or rec.get("pinnedCount") != 1:
                    bad.append(f"record module={rec.get('module')} pinnedCount={rec.get('pinnedCount')}")
        if cell == "stale-dir" and not os.path.isfile(os.path.join(out, "keep.txt")):
            bad.append("the directory at WPIN_OUT lost its contents")
        rows.append((cell, kv.get("before"), kv.get("rc"), on_disk,
                     wl[0] if wl else "-", "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def is_bitcode(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"BC\xc0\xde"
    except OSError:
        return False


def trailing_record_problems(rec, opt="-O2"):
    """The trailing shape's record at `opt`, as the shape table expects it."""
    bad = [f"record: {p}" for p in v2_problems(rec)]
    sites = rec.get("pinned") or []
    checks = [
        ("module", rec.get("module"), "trailing.c"),
        ("requested", rec.get("requested"), ["handle"]),
        ("pinnedCount", rec.get("pinnedCount"), 1),
        ("dryRun", rec.get("dryRun"), False),
        ("optLevel.speedup", (rec.get("optLevel") or {}).get("speedup"), SPEEDUP[opt]),
        ("followedByUse per site", [s.get("followedByUse") for s in sites], [False]),
    ]
    for name, got, want in checks:
        if got != want:
            bad.append(f"record {name} = {got!r}, expected {want!r}")
    return bad


def on_disk_state(path):
    return "dir" if os.path.isdir(path) else ("file" if os.path.isfile(path) else "absent")


def grade_lto(lab):
    rows, problems, incomplete = [], [], []
    d = os.path.join(lab, "lto")
    for cell in LTO_ORDER:
        exp = LTO[cell]
        linking = exp["what"] in ("linkline", "linkline-nofile")
        try:
            kv = load_kv(os.path.join(d, cell + ".kv"))
            cerr = load_lines(os.path.join(d, cell + ".compile.stderr.txt"))
            crec, lerr, ir = None, None, None
            if exp["what"] == "compile":
                crec = load_json(os.path.join(d, cell + ".json"))
            elif linking:
                crec = load_json(os.path.join(d, cell + ".compile.json"))
                lerr = load_lines(os.path.join(d, cell + ".link.stderr.txt"))
            else:
                ir = load_lines(os.path.join(d, cell + ".ll"))
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue
        bad = []
        out = os.path.join(d, cell + ".json")
        if kv.get("form") != exp["form"] or kv.get("what") != exp["what"] or kv.get("opt") != exp["opt"]:
            bad.append(f"runner ran form={kv.get('form')} what={kv.get('what')} opt={kv.get('opt')}")
        if kv.get("beforeCompile") != "absent":
            bad.append(f"WPIN_OUT before the compile: {kv.get('beforeCompile')}, expected absent")
        if kv.get("compileRc") != "0":
            bad.append(f"compile rc {kv.get('compileRc')}, expected 0")
        cwl = wipepin_lines(cerr)
        bitcode = is_bitcode(os.path.join(d, cell + ".o"))

        line_n, after, same = "-", kv.get("afterLink"), "-"
        if exp["what"] == "nopasses-ir":
            # No pipeline is built, so no record, and the no-pipeline-start line
            # comes from the compile itself -- once, with the no-file ending.
            line_n = str(sum(1 for l in cwl if l == exp["line"]))
            if cwl != [exp["line"]]:
                bad.append(f"compile stderr WipePin lines {cwl}, expected exactly [{exp['line']!r}]")
            after = kv.get("afterCompile")
            if after != "absent" or on_disk_state(out) != "absent":
                bad.append(f"WPIN_OUT after the compile: {after} (runner), {on_disk_state(out)} (now), expected absent")
            memsets = [l for l in ir if "call void @llvm.memset" in l]
            if not ir or not ir[0].startswith("; ModuleID"):
                bad.append("the compile did not write textual IR")
            if not memsets:
                bad.append("the IR holds no llvm.memset (the trailing wipe should still be there, unpinned)")
            if any("i1 true)" in l for l in memsets):
                bad.append("the IR holds a volatile llvm.memset: something was pinned in a compile that ran no pass")
        else:
            if not bitcode:
                bad.append("the -flto compile did not leave a bitcode object")
            want_after_compile = "file"
            if kv.get("afterCompile") != want_after_compile:
                bad.append(f"WPIN_OUT after the compile: {kv.get('afterCompile')}, expected {want_after_compile}")
            bad += [f"compile {p}" for p in trailing_record_problems(crec, exp["opt"])]
            if cwl:
                bad.append(f"the compile printed {cwl}, expected nothing")

        if linking:
            want_before = "absent" if exp["what"] == "linkline-nofile" else "file"
            if kv.get("beforeLink") != want_before:
                bad.append(f"WPIN_OUT before the link: {kv.get('beforeLink')}, expected {want_before}")
            if kv.get("stockLinkRc") != "0":
                bad.append(f"stock link rc {kv.get('stockLinkRc')}, expected 0")
            if kv.get("pluginLinkRc") != "0":
                bad.append(f"link with WipePin on the link line rc {kv.get('pluginLinkRc')}, expected 0")
            lwl = wipepin_lines(lerr)
            line_n = str(sum(1 for l in lwl if l == exp["line"]))
            if lwl != [exp["line"]]:
                bad.append(f"link stderr WipePin lines {lwl}, expected exactly [{exp['line']!r}]")
            if after != "absent" or on_disk_state(out) != "absent":
                bad.append(f"WPIN_OUT after the link: {after} (runner), {on_disk_state(out)} (now), expected absent")
            s_stock = sha_file(os.path.join(d, cell + ".stock.so"))
            s_plug = sha_file(os.path.join(d, cell + ".plugin.so"))
            same = "?" if s_stock is None or s_plug is None else ("yes" if s_stock == s_plug else "NO")
            if same != "yes":
                bad.append(f"linked output byte-identical to the stock link: {same}")
        elif exp["what"] == "compile":
            # A compile runs pipeline start: its record stays, and it never says
            # the link-time line.
            if any(l.startswith(LINK_LINE_PREFIX) for l in cwl):
                bad.append("the compile printed the link-time line")

        ending = "-" if "line" not in exp else ("removed" if exp["line"] == LINK_LINE_REMOVED else "no file")
        rows.append((cell, exp["form"], exp["opt"], kv.get("compileRc"),
                     "-" if exp["what"] == "nopasses-ir" else ("yes" if bitcode else "no"),
                     f"{crec.get('schemaVersion')}/{crec.get('pinnedCount')}" if crec is not None else "-",
                     kv.get("beforeLink"), kv.get("pluginLinkRc"), f"{line_n} ({ending})" if line_n != "-" else "-",
                     after, same, "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def xtu_record_problems(rec, exp):
    """What the record of an xtu cell's wipe.c compile must say."""
    bad = [f"record: {p}" for p in v2_problems(rec)]
    checks = [
        ("module", rec.get("module"), "wipe.c"),
        ("scope", rec.get("scope"), "functions"),
        ("requested", rec.get("requested"), ["secure_wipe"]),
        ("resolution", rec.get("resolution"), XTU_RESOLUTION),
        ("dryRun", rec.get("dryRun"), exp["dryRun"]),
        ("pinnedCount", rec.get("pinnedCount"), exp["pinnedCount"]),
        ("wouldPinCount", rec.get("wouldPinCount"), exp["wouldPinCount"]),
        ("optLevel", rec.get("optLevel"), {"speedup": 2, "size": 0}),
        ("pinned", rec.get("pinned"), [XTU_SITE]),
    ]
    for name, got, want in checks:
        if got != want:
            bad.append(f"record {name} = {got!r}, expected {want!r}")
    return bad


XTU_RCS = ("mainRc", "useRc", "wipeRc", "ioRc", "linkRc")
XTU_UNITS = ("main", "use", "wipe", "io")
XTU_LTO_UNITS = ("main", "use", "wipe")

BCANALYZER = "llvm-bcanalyzer-18"

# The block a module summary is written in, and the LTO form it is.
SUMMARY_BLOCKS = {"GLOBALVAL_SUMMARY_BLOCK": "thin", "FULL_LTO_GLOBALVAL_SUMMARY_BLOCK": "full"}
_BLOCK_OPEN = re.compile(r"^\s*<([A-Za-z0-9_]+) NumWords=\d+ BlockCodeSize=\d+>$")


def summary_forms(dump):
    """The form of every module summary in `llvm-bcanalyzer -dump` output, in
    order: "thin" for a GLOBALVAL_SUMMARY_BLOCK, "full" for a
    FULL_LTO_GLOBALVAL_SUMMARY_BLOCK. Only a line that opens a block counts.
    Empty for bitcode that carries no summary."""
    forms = []
    for line in dump.split("\n"):
        m = _BLOCK_OPEN.match(line)
        if m and m.group(1) in SUMMARY_BLOCKS:
            forms.append(SUMMARY_BLOCKS[m.group(1)])
    return forms


def lto_form(path, bcanalyzer=BCANALYZER, timeout=120):
    """The LTO form of one bitcode object, from `llvm-bcanalyzer -dump`: "thin"
    or "full" when it holds one module summary, "no summary" when it holds
    none, the forms joined by "+" when it holds several. Raises RuntimeError,
    with a message that carries no path, when the object cannot be read."""
    tool = os.path.basename(bcanalyzer)
    try:
        out = subprocess.run([bcanalyzer, "-dump", path], capture_output=True, encoding="utf-8",
                             errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"{tool} could not run: {e.__class__.__name__}")
    if out.returncode != 0:
        raise RuntimeError(f"{tool} exited {out.returncode}")
    return "+".join(summary_forms(out.stdout)) or "no summary"


def bcanalyzer_version(bcanalyzer=BCANALYZER):
    """The first line `--version` prints, or why there is none."""
    try:
        out = subprocess.run([bcanalyzer, "--version"], capture_output=True, encoding="utf-8",
                             errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "not runnable"
    lines = [l.strip() for l in out.stdout.split("\n") if l.strip()]
    return lines[0] if lines else "no version printed"


def elf_comment(path):
    """The strings of the .comment section of a 64-bit little-endian ELF file,
    [] when it has no such section; None when the file cannot be read as one."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        if data[:6] != b"\x7fELF\x02\x01":
            return None
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)

        def section(i):
            # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size
            name, _, _, _, off, size = struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize)
            return name, off, size

        names = section(shstrndx)[1]
        for i in range(shnum):
            name, off, size = section(i)
            if data[names + name:data.index(b"\0", names + name)] == b".comment":
                return [s.decode("utf-8", "replace") for s in data[off:off + size].split(b"\0") if s]
        return []
    except (OSError, struct.error, ValueError):
        return None


def linkers(comment):
    """What .comment strings say linked the file: lld writes "Linker: <version>"."""
    return [s[len("Linker: "):] for s in comment if s.startswith("Linker: ")]


SUMMARY_WORDS = {"thin": "a thin module summary", "full": "a full module summary", "no summary": "no module summary"}


LINK_WORDS = {"none": "a link without LTO", "full": "a full-LTO link", "thin": "a ThinLTO link"}


def xtu_build_problems(exp, kinds, forms, comment, helper_defined):
    """What is wrong with how an xtu cell was built, read from what the build
    left rather than from the runner's form=: `kinds` is object_kind per unit,
    `forms` lto_form per bitcode unit, `comment` the executable's .comment
    strings, `helper_defined` whether the executable defines secure_wipe. A
    non-LTO build must not pass as an LTO one, nor one LTO form as the other;
    the producer and consumer must stay out of every link's sight; and every
    executable must be lld's, and look like the output of its form's link."""
    bad = []
    want_kind = "elf" if exp["form"] == "none" else "bitcode"
    for u in XTU_LTO_UNITS:
        if kinds[u] != want_kind:
            bad.append(f"{u}.o is {kinds[u]}, expected {want_kind}")
    wrong = [u for u in XTU_LTO_UNITS if kinds[u] == "bitcode" and forms.get(u) != exp["form"]]
    if wrong and want_kind == "bitcode":
        got = " / ".join(sorted({SUMMARY_WORDS.get(forms.get(u), str(forms.get(u))) for u in wrong}))
        bad.append(f"{', '.join(u + '.o' for u in wrong)}: {got}, expected {SUMMARY_WORDS[exp['form']]}: "
                   "the cell was not built as the LTO form it is named for")
    if kinds["io"] != "elf":
        bad.append(f"io.o is {kinds['io']}, expected elf: derive and use must be opaque to the link")
    named = linkers(comment)
    if not named:
        bad.append("the executable's .comment names no linker (lld writes 'Linker: <version>'): "
                   "not linked by lld, which every xtu link asks for")
    elif len(named) != 1 or not re.search(r"\bLLD\b", named[0]):
        bad.append(f"the executable's .comment names the linker {named}, expected lld")
    want = XTU_HELPER_DEFINED[exp["form"]]
    if helper_defined is not want:
        bad.append(f"the executable {'defines' if helper_defined else 'does not define'} secure_wipe, which "
                   f"{LINK_WORDS[exp['form']]} of these units {'keeps' if want else 'drops'} (measured): "
                   f"not the output of the link this cell is named for")
    return bad


def grade_xtu(lab, bcanalyzer=BCANALYZER):
    """The xtu cells, graded from what the compiles and the link left on disk
    and from the linked executable itself, disassembled here."""
    rows, problems, incomplete = [], [], []
    d = os.path.join(lab, "xtu")
    for cell in XTU_ORDER:
        exp = XTU[cell]
        cd = os.path.join(d, cell)
        prog = os.path.join(cd, "prog")
        try:
            kv = load_kv(os.path.join(d, cell + ".kv"))
            werr = wipepin_lines(load_lines(os.path.join(cd, "wipe.stderr.txt")))
            lerr = wipepin_lines(load_lines(os.path.join(cd, "link.stderr.txt")))
            rec = load_json(os.path.join(cd, "wipe.record.json")) if exp["mode"] != "stock" else None
            if not os.path.isfile(prog):
                raise Incomplete(f"xtu/{cell}/prog: no executable")
            try:
                text = objdump_fill.disassemble(prog)
            except RuntimeError as e:
                raise Incomplete(f"xtu/{cell}/prog: {e}")
            comment = elf_comment(prog)
            if comment is None:
                raise Incomplete(f"xtu/{cell}/prog: not a 64-bit little-endian ELF file")
            kinds = {u: objdump_fill.object_kind(os.path.join(cd, u + ".o")) for u in XTU_UNITS}
            forms = {}
            for u in XTU_LTO_UNITS:
                if kinds[u] == "bitcode":
                    try:
                        forms[u] = lto_form(os.path.join(cd, u + ".o"), bcanalyzer)
                    except RuntimeError as e:
                        raise Incomplete(f"xtu/{cell}/{u}.o: {e}")
        except Incomplete as e:
            # The lab's own path stays out of what this prints.
            incomplete.append(f"{cell}: {str(e).replace(lab, '<lab>')}")
            continue

        bad = []
        if kv.get("form") != exp["form"] or kv.get("mode") != exp["mode"]:
            bad.append(f"runner ran form={kv.get('form')} mode={kv.get('mode')}")
        rcs = [f"{k}={kv.get(k)}" for k in XTU_RCS if kv.get(k) != "0"]
        if rcs:
            bad.append(f"a step failed: {' '.join(rcs)}")
        helper_defined = objdump_fill.objdump_body(text, "secure_wipe") is not None
        bad += xtu_build_problems(exp, kinds, forms, comment, helper_defined)

        want_lines = exp.get("lines", [])
        if werr != want_lines:
            bad.append(f"wipe.c compile stderr WipePin lines {werr}, expected {want_lines}")
        if lerr:
            bad.append(f"the link printed {lerr}; no link here loads WipePin")
        if rec is not None:
            bad += xtu_record_problems(rec, exp)
        elif kv.get("record") != "not-loaded":
            bad.append(f"record={kv.get('record')} in a cell that does not load WipePin")

        subj = objdump_fill.wipe_reading(text, "handle", "secure_wipe", XTU_FILL_BYTES)
        ctl = objdump_fill.wipe_reading(text, "wipe_kept", None, XTU_FILL_BYTES)
        bad += objdump_fill.reading_problems(subj, ctl, exp["inlined"], exp["subject"], "handle", "secure_wipe")

        same = "-"
        if exp["sameAsStock"] is not None:
            stock = f"xtu-{exp['form']}-stock"
            s_stock = sha_file(os.path.join(d, stock, "prog"))
            s_this = sha_file(prog)
            same = "?" if s_stock is None or s_this is None else ("yes" if s_stock == s_this else "no")
            if same == "?":
                bad.append(f"no executable of {stock} to compare with")
            elif exp["sameAsStock"] and same != "yes":
                bad.append(f"told to change nothing, yet the executable differs from {stock}'s")
            elif not exp["sameAsStock"] and same == "yes":
                bad.append(f"pinned, yet the executable is byte-identical to {stock}'s")

        recsum = "-" if rec is None else (f"{rec.get('schemaVersion')}/{rec.get('pinnedCount')}/"
                                          f"{rec.get('wouldPinCount')}/{'dry' if rec.get('dryRun') else 'live'}")
        objs = "/".join(sorted({kinds[u] or "?" for u in XTU_LTO_UNITS})) + f" (io.o {kinds['io']})"
        rows.append((cell, exp["form"], exp["mode"], "0" if not rcs else "NO", objs,
                     "/".join(sorted(set(forms.values()))) or "-", "/".join(linkers(comment)) or "-",
                     "yes" if helper_defined else "no", recsum,
                     "-" if subj["inlined"] is None else ("yes" if subj["inlined"] else "no"),
                     objdump_fill.describe(subj), objdump_fill.describe(ctl), same,
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def digest_check_can_fail(lab):
    """A digest check that cannot fail checks nothing: alter a real record and
    confirm the re-derivation notices."""
    path = os.path.join(lab, "wipepin", "pin-O2.json")
    rec = load_json(path)
    if rec.get("evidenceDigest") != digest_of(rec):
        return False
    tampered = copy.deepcopy(rec)
    tampered["pinnedCount"] = (tampered.get("pinnedCount") or 0) + 1
    flipped = copy.deepcopy(rec)
    for s in flipped.get("pinned") or []:
        s["followedByUse"] = not s.get("followedByUse")
    moved_context = copy.deepcopy(rec)
    moved_context["context"] = {"generatedAt": 0}
    return tampered["evidenceDigest"] != digest_of(tampered) and \
        flipped["evidenceDigest"] != digest_of(flipped) and \
        moved_context["evidenceDigest"] == digest_of(moved_context)


def table(head, rows):
    widths = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    print("  ".join(str(h).ljust(w) for h, w in zip(head, widths)).rstrip())
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", required=True, help="the directory run-fixture-loop.sh wrote into")
    ap.add_argument("--bcanalyzer", default=BCANALYZER,
                    help=f"the llvm-bcanalyzer that reads the xtu objects' summaries (default {BCANALYZER})")
    args = ap.parse_args()
    lab = os.path.abspath(args.lab)

    here = os.path.dirname(os.path.abspath(__file__))
    registry = os.path.join(here, "..", "..", "schema", "effect-symbol-lists.json")
    try:
        registry_symbols = load_json(registry)["lists"]["wipe-6"]["symbols"]
    except (Incomplete, KeyError) as e:
        print(f"check-fixture-loop: cannot read the registered wipe list: {e}", file=sys.stderr)
        return 3

    rows, problems, incomplete = grade(lab, registry_symbols)
    prow, pprob, pinc = grade_pinsh_only(lab)
    srow, sprob, sinc = grade_shapes(lab)
    trow, tprob, tinc = grade_stale(lab)
    lrow, lprob, linc = grade_lto(lab)
    xrow, xprob, xinc = grade_xtu(lab, args.bcanalyzer)
    problems += pprob + sprob + tprob + lprob + xprob
    incomplete += pinc + sinc + tinc + linc + xinc

    table(("cell", "opt", "WipePin", "verdict", "effect pre->post", "firstZero", "ctl held",
           "volatile@post", "pinned/would/mode/res", "followedByUse", "obj!=base", "pin.sh", ""), rows)
    print(f"effect symbols: registered list wipe-6 ({len(registry_symbols)} spellings)")
    print()
    table(("pin.sh alone", "rc", "clang rc", "record", ""), prow)
    print()
    table(("shape (-g)", "opt", "pin.sh", "pinned", "followedByUse", "exact/linkage",
           "partial line", "non-exact line", ""), srow)
    print()
    table(("stale record", "before", "clang rc", "after", "WipePin stderr", ""), trow)
    print()
    table(("lto / no pipeline start", "form", "opt", "compile rc", "bitcode", "compile record",
           "WPIN_OUT before link", "link rc", "no-pipeline-start line", "WPIN_OUT after", "output==stock", ""), lrow)
    print()
    table(("xtu (-O2, executable)", "form", "mode", "rc", "objects", "summary", "linker", "secure_wipe",
           "wipe.c record", "inlined", "subject: handle", "control: wipe_kept", "==stock", ""), xrow)
    print(f"xtu: read with {objdump_fill.objdump_version()}, `objdump -d --no-show-raw-insn` of each "
          "executable; inlined = no call to secure_wipe (or a renamed copy) left in handle")
    print(f"xtu: summary = the block each -flto object's module summary is in, thin GLOBALVAL_SUMMARY_BLOCK, "
          f"full FULL_LTO_GLOBALVAL_SUMMARY_BLOCK ({os.path.basename(args.bcanalyzer)} -dump, "
          f"{bcanalyzer_version(args.bcanalyzer)}); linker = the executable's .comment; secure_wipe = "
          "whether the executable still defines it")

    if incomplete:
        print("\nINCOMPLETE -- these cells could not be graded:")
        for m in incomplete:
            print("  " + m)
        return 3

    try:
        can_fail = digest_check_can_fail(lab)
    except Incomplete as e:
        print(f"\nINCOMPLETE -- {e}")
        return 3
    print(f"\ndigest check can fail: {'yes' if can_fail else 'NO'}")
    if not can_fail:
        problems.append("the WipePin digest re-derivation did not notice an altered record")

    if problems:
        print("\nDISAGREEMENTS:")
        for p in problems:
            print("  " + p)
        return 2
    n = len(rows) + len(prow) + len(srow) + len(trow) + len(lrow) + len(xrow)
    print(f"\nall {n} cells as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
