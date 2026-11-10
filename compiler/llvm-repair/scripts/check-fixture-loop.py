#!/usr/bin/env python3
"""Grade the fixture loop written by run-fixture-loop.sh. Compiles nothing.

    python3 compiler/llvm-repair/scripts/check-fixture-loop.py --lab DIR

The instrument being read in the loop cells is the IR observer (IrCheckpoints),
not WipePin. WipePin's own record is read too, but only to check that it says
what the cell asked of it -- it never decides whether the wipe survived. That is
the observer's verdict, taken from the same record shape the optimisation matrix
grades, on the same fixture, with the same effect-symbol list.

The shape and stale cells are about WipePin's own account of itself: what its
wipe-pin-v3 record and its stderr say for a source whose answer is known, and
whether a record from an earlier compile can outlive a compile that wrote none.
Every one of those cells, and every loop, lto and xtu cell, runs with the three
v3 switches unset, and its record must say so (the three blocks not enabled)
and must say the version handshake compared the module's clang with the build's
(host.checked true).
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
through llvm-bcanalyzer-18 -dump, for the lto cells' objects as for the xtu
cells' -- and from the executable, which linker from its .comment and which link
from whether it still defines the helper, not from what the runner says it ran;
so objdump and llvm-bcanalyzer-18 are required.

The v3 cells are about what wipe-pin-v3 adds (../../schema/wipe-pin.md section
14). For each call-shaped wipe a switch repairs, four executables linked from
the same source with the same io.c and main.c -- stock, the switches off, the
switch on, the switch on as a dry run -- disassembled here and read with the
same objdump_fill.py as the xtu cells, beside the three records and pin.sh's
exit codes; with --baseline on the runner, the switches-off -S output is also
compared byte for byte with the v2 build's (--require-baseline makes its absence
a disagreement). Then the cells run through pin.sh alone: the buffer barrier
where it must not go or must not cover (initialisers, a variable-length array
in a branch, a musttail call after the wipe, a lifetime end and a musttail call
on two paths, a wipe loop bounded by a pointer comparison, a buffer declared in
a loop body)
and the inline zero copy, each read from its record, its stderr, its -S output
and the IR verifier's exit status on its -S -emit-llvm output; pin.sh refusing
switch values other than 0 and 1; and the version handshake on the trailing
shape's front-end IR read back with -x ir.

The expectations below were written from what each cell is for, before the
cells were first run, with one exception that says so where it is defined:
XTU_HELPER_DEFINED, which is measured. A cell that disagrees is printed as a
disagreement and the run fails; the tables are never edited into agreement.

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

SCHEMA = "wipe-pin-v3"

# wipe-pin.md section 14.1 and 14.3: the 20 top-level keys and the 9 counters.
TOP_KEYS = sorted(["schemaVersion", "component", "module", "toolchain", "optLevel", "scope", "requested",
                   "resolution", "dryRun", "pinned", "pinnedCount", "wouldPinCount", "seen", "unhandled",
                   "barrierCalls", "zeroCopy", "bufferBarriers", "host", "evidenceDigest", "context"])
UNHANDLED_KEYS = ["libcallMemset", "memsetChk", "nonZeroFill", "atomicMemset", "inlineWrapperMemset",
                  "bzeroCall", "inlineWrapperBzero", "zeroGlobalCopy", "zeroGlobalCopyCall"]
DEST_KINDS = ("alloca", "argument", "global", "other")
# What bufferBarriers is when WPIN_BUFFER_BARRIER is off (section 14.6, C1).
BUFFER_BARRIERS_OFF = {"enabled": False, "count": 0, "sites": []}
# Section 14.6's site keys and value sets; WipePin's anchors (C7).
BUFFER_SITE_KEYS = ["function", "buffer", "bytes", "reason", "anchor"]
BUFFER_REASONS = ("memset", "loop-store", "zero-copy")
BUFFER_ANCHORS = ("lifetime-end", "ret")

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

def unhandled_text(counts=None):
    """The `unhandled in scope:` tail of WipePin's stderr lines: the nine
    counters in section 14.3's order, `counts` giving the ones that are not 0."""
    counts = counts or {}
    return " ".join(f"{k}={counts.get(k, 0)}" for k in UNHANDLED_KEYS)


NO_UNHANDLED = unhandled_text()


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


def is_count(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def is_count_or_null(v):
    return v is None or is_count(v)


def is_name(v):
    return isinstance(v, str) and v != ""


_IDENT_SPACE = " \t\n\r\f\v"


def strip_ident(raw):
    """wipe-pin.md section 14.7's `ident`: every parenthesised group (nested
    ones included) and the whitespace directly before it removed, an unmatched
    ')' removed, surrounding whitespace trimmed. Re-derived here, not shared
    with the plugin."""
    out, depth = [], 0
    for ch in raw:
        if ch == "(":
            if depth == 0:
                while out and out[-1] in _IDENT_SPACE:
                    out.pop()
            depth += 1
            continue
        if ch == ")":
            if depth > 0:
                depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out).strip(_IDENT_SPACE)


def ident_major(ident):
    """The digits after the first `clang version ` that has digits after it, as
    the readers re-derive identMajor (section 14.9 C6); None when there are none."""
    m = re.search(r"clang version ([0-9]+)", ident) if isinstance(ident, str) else None
    return int(m.group(1)) if m else None


def _site_problems(block, site, keys, typed):
    if not isinstance(site, dict) or sorted(site) != sorted(keys):
        return [f"{block} site keys are not {sorted(keys)}: {site!r}"]
    return [f"{block} site {k} is {site[k]!r}: {why}" for k, ok, why in typed(site) if not ok]


def _barrier_site_types(s):
    callee = s["callee"]
    family = is_name(callee) and (callee in ("memset", "__memset_chk", "bzero")
                                  or callee.startswith("memset.") or callee.startswith("bzero."))
    return [("function", is_name(s["function"]), "not a non-empty string"),
            ("callee", family, "not memset, __memset_chk, bzero, memset.* or bzero.* (C7)"),
            ("lengthBytes", is_count_or_null(s["lengthBytes"]), "not an integer >= 0 or null"),
            ("line", is_count_or_null(s["line"]), "not an integer >= 0 or null")]


def _zero_copy_site_types(s):
    form, callee = s["form"], s["callee"]
    if form == "intrinsic":
        paired = callee == "llvm.memcpy"
    else:
        paired = is_name(callee) and (callee in ("memcpy", "__memcpy_chk") or callee.startswith("memcpy."))
    return [("function", is_name(s["function"]), "not a non-empty string"),
            ("form", form in ("intrinsic", "call"), "not intrinsic or call (C7)"),
            ("callee", paired, "not llvm.memcpy exactly for form intrinsic, else memcpy, __memcpy_chk or "
                               "memcpy.* (C7)"),
            ("source", isinstance(s["source"], str), "not a string"),
            ("destKind", s["destKind"] in DEST_KINDS, f"not one of {DEST_KINDS}"),
            ("lengthBytes", is_count_or_null(s["lengthBytes"]), "not an integer >= 0 or null"),
            ("line", is_count_or_null(s["line"]), "not an integer >= 0 or null")]


BARRIER_SITE_KEYS = ["function", "callee", "lengthBytes", "line"]
ZERO_COPY_SITE_KEYS = ["function", "form", "callee", "source", "destKind", "lengthBytes", "line"]


def block_problems(pin, name, done, would, site_keys, site_types):
    """Section 14.9 S3/S4, then C1, C2/C3 and C5, for barrierCalls or zeroCopy."""
    b = pin.get(name)
    keys = sorted(["enabled", "sites", done, would])
    if not isinstance(b, dict) or sorted(b) != keys:
        return [f"{name} keys are not {keys}: {b!r}"]
    bad = []
    if not isinstance(b["enabled"], bool):
        bad.append(f"{name}.enabled is not a boolean")
    if not isinstance(b["sites"], list):
        return bad + [f"{name}.sites is not a list"]
    for k in (done, would):
        if not is_count(b[k]):
            bad.append(f"{name}.{k} is not an integer >= 0")
    for s in b["sites"]:
        bad += _site_problems(name, s, site_keys, site_types)
    if bad:
        return bad
    if not b["enabled"]:
        if b["sites"] or b[done] or b[would]:
            bad.append(f"{name} is not enabled, yet has sites or counts (C1)")
    else:
        if b[would] != len(b["sites"]):
            bad.append(f"{name}.{would} {b[would]} is not the {len(b['sites'])} sites (C2/C3)")
        want = 0 if pin.get("dryRun") is True else b[would]
        if b[done] != want:
            bad.append(f"{name}.{done} {b[done]}, expected {want} (C2/C3)")
    if pin.get("scope") == "functions":
        req = pin.get("requested") or []
        bad += [f"{name} site in {s['function']!r}, which is not requested (C5)"
                for s in b["sites"] if s["function"] not in req]
    return bad


def _buffer_site_types(s):
    return [("function", is_name(s["function"]), "not a non-empty string"),
            ("buffer", s["buffer"] is None or is_name(s["buffer"]), "not a non-empty string or null"),
            ("bytes", is_count_or_null(s["bytes"]), "not an integer >= 0 or null"),
            ("reason", s["reason"] in BUFFER_REASONS, f"not one of {BUFFER_REASONS}"),
            ("anchor", s["anchor"] in BUFFER_ANCHORS, f"not one of {BUFFER_ANCHORS} (C7)")]


def buffer_block_problems(pin):
    """Section 14.9 S5, then C1, C4 and C5, for bufferBarriers (one count, no
    would-count: in a dry run `count` is 0, otherwise the length of `sites`)."""
    name = "bufferBarriers"
    b = pin.get(name)
    keys = sorted(["enabled", "count", "sites"])
    if not isinstance(b, dict) or sorted(b) != keys:
        return [f"{name} keys are not {keys}: {b!r}"]
    bad = []
    if not isinstance(b["enabled"], bool):
        bad.append(f"{name}.enabled is not a boolean")
    if not isinstance(b["sites"], list):
        return bad + [f"{name}.sites is not a list"]
    if not is_count(b["count"]):
        bad.append(f"{name}.count is not an integer >= 0")
    for s in b["sites"]:
        bad += _site_problems(name, s, BUFFER_SITE_KEYS, _buffer_site_types)
    if bad:
        return bad
    if not b["enabled"]:
        if b != BUFFER_BARRIERS_OFF:
            bad.append(f"{name} is not enabled, yet has sites or a count (C1)")
    else:
        want = 0 if pin.get("dryRun") is True else len(b["sites"])
        if b["count"] != want:
            bad.append(f"{name}.count {b['count']}, expected {want} (C4)")
    if pin.get("scope") == "functions":
        req = pin.get("requested") or []
        bad += [f"{name} site in {s['function']!r}, which is not requested (C5)"
                for s in b["sites"] if s["function"] not in req]
    return bad


HOST_KEYS = sorted(["ident", "identMajor", "builtMajor", "checked", "intrinsicsCompared"])


def host_problems(pin):
    """Section 14.9 S6 and C6, and this build's M6 check: intrinsicsCompared is
    never null here, because this build compares its intrinsic numbering."""
    h = pin.get("host")
    if not isinstance(h, dict) or sorted(h) != HOST_KEYS:
        return [f"host keys are not {HOST_KEYS}: {h!r}"]
    bad = []
    if not (h["ident"] is None or isinstance(h["ident"], str)):
        bad.append(f"host.ident {h['ident']!r} is not a string or null")
    if not (h["identMajor"] is None or (is_count(h["identMajor"]) and h["identMajor"] >= 1)):
        bad.append(f"host.identMajor {h['identMajor']!r} is not an integer >= 1 or null")
    if not (is_count(h["builtMajor"]) and h["builtMajor"] >= 1):
        bad.append(f"host.builtMajor {h['builtMajor']!r} is not an integer >= 1")
    if not isinstance(h["checked"], bool):
        bad.append(f"host.checked {h['checked']!r} is not a boolean")
    if not is_count(h["intrinsicsCompared"]):
        bad.append(f"host.intrinsicsCompared {h['intrinsicsCompared']!r} is not an integer >= 0 "
                   "(this build compares its intrinsic numbering, so it is never null)")
    if bad:
        return bad
    if h["checked"] != (h["identMajor"] is not None):
        bad.append(f"host.checked {h['checked']} with identMajor {h['identMajor']!r} (C6)")
    if h["identMajor"] is not None and h["identMajor"] != h["builtMajor"]:
        bad.append(f"host.identMajor {h['identMajor']} is not builtMajor {h['builtMajor']}: a mismatch must "
                   "be a refusal with no record (C6)")
    if h["identMajor"] != ident_major(h["ident"]):
        bad.append(f"host.identMajor {h['identMajor']!r} does not re-derive from ident {h['ident']!r} (C6)")
    if isinstance(h["ident"], str) and (("(" in h["ident"] or ")" in h["ident"])
                                        or h["ident"] != h["ident"].strip(_IDENT_SPACE)):
        bad.append(f"host.ident {h['ident']!r} is not stripped (C6)")
    tc = (pin.get("toolchain") or {}).get("clang")
    m = re.match(r"([0-9]+)\.", tc) if isinstance(tc, str) else None
    if not m or int(m.group(1)) != h["builtMajor"]:
        bad.append(f"host.builtMajor {h['builtMajor']} is not the major version of toolchain.clang {tc!r} (C6)")
    return bad


def record_problems(pin):
    """What every wipe-pin-v3 record must be, whatever the cell asked of it."""
    bad = []
    if not isinstance(pin, dict):
        return [f"the record is not an object: {pin!r}"]
    if sorted(pin) != TOP_KEYS:
        missing = [k for k in TOP_KEYS if k not in pin]
        extra = [k for k in pin if k not in TOP_KEYS]
        bad.append(f"top-level keys: missing {missing}, unknown {extra} (S1)")
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
        # `is`, not `in`: 1, 0 and 1.0 compare equal to True and False
        if "followedByUse" not in site or not (site["followedByUse"] is None or
                                               isinstance(site["followedByUse"], bool)):
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
    un = pin.get("unhandled")
    if not isinstance(un, dict) or sorted(un) != sorted(UNHANDLED_KEYS):
        bad.append(f"unhandled keys are not the nine of section 14.3: {un!r} (S2)")
    else:
        bad += [f"unhandled.{k} {un[k]!r} is not an integer >= 0 (S2)" for k in UNHANDLED_KEYS if not is_count(un[k])]
    bad += block_problems(pin, "barrierCalls", "barrierCount", "wouldBarrierCount", BARRIER_SITE_KEYS,
                          _barrier_site_types)
    bad += block_problems(pin, "zeroCopy", "repairedCount", "wouldRepairCount", ZERO_COPY_SITE_KEYS,
                          _zero_copy_site_types)
    bad += buffer_block_problems(pin)
    bad += host_problems(pin)
    if pin.get("evidenceDigest") != digest_of(pin):
        bad.append("evidenceDigest does not re-derive")
    leaks = absolute_paths({k: v for k, v in pin.items() if k != "context"})
    if leaks:
        bad.append(f"record carries an absolute path: {leaks}")
    return bad


def compile_problems(pin, barrier=False, zero=False, checked=True, buffer=False):
    """What this compile asked of the record (section 14.9 W1): which switches
    the cell set, and whether the module named a clang version for the
    handshake to compare."""
    bad = []
    for block, want in (("barrierCalls", barrier), ("zeroCopy", zero), ("bufferBarriers", buffer)):
        got = (pin.get(block) or {}).get("enabled") if isinstance(pin.get(block), dict) else None
        if got is not want:
            bad.append(f"{block}.enabled is {got!r}, and the cell {'set' if want else 'did not set'} its "
                       "switch (W1)")
    got = (pin.get("host") or {}).get("checked") if isinstance(pin.get("host"), dict) else None
    if got is not checked:
        bad.append(f"host.checked is {got!r}, expected {checked}")
    return bad


def v3_problems(pin, barrier=False, zero=False, checked=True, buffer=False):
    return record_problems(pin) + compile_problems(pin, barrier, zero, checked, buffer)


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
            bad += [f"WipePin {p}" for p in v3_problems(pin)]

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
        bad = [f"record: {p}" for p in v3_problems(pin)]
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
                bad += [f"record: {p}" for p in v3_problems(rec)]
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
    bad = [f"record: {p}" for p in v3_problems(rec)]
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


def grade_lto(lab, bcanalyzer=None):
    """The lto / no-pipeline-start cells. Returns rows, problems, incomplete, and
    the forms read from the -flto objects' module summaries as (cell, form)."""
    bcanalyzer = bcanalyzer or BCANALYZER  # defined with the xtu grading, below
    rows, problems, incomplete, forms = [], [], [], []
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
            else:
                # The magic says bitcode for -flto and -flto=thin alike. The block
                # the module summary is in says which the compile wrote, and so
                # which LTO the link ran: lto-thin-linkline-O0 is the cell that
                # shows a ThinLTO link at -O0, and with a full object it would show
                # nothing about one (read as the xtu cells' objects are).
                try:
                    form = lto_form(os.path.join(d, cell + ".o"), bcanalyzer)
                except RuntimeError as e:
                    incomplete.append(f"{cell}.o: {e}")
                    continue
                forms.append((cell, form))
                if form != exp["form"]:
                    bad.append(f"the object's module summary is {form}, expected {exp['form']}")
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
    return rows, problems, incomplete, forms


def xtu_record_problems(rec, exp):
    """What the record of an xtu cell's wipe.c compile must say."""
    bad = [f"record: {p}" for p in v3_problems(rec)]
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


# ------------------------------------------------------------------- v3 cells
#
# Written before the v3 cells were first run (2026-11-09; lab notes kept
# outside this repository). Each
# case is one source and one switch, target `handle`, -O2, no -g (so every
# site's line is null), and four executables the runner links from it: stock,
# off (pin.sh, switches unset), ext (pin.sh, the switch =1), dry (pin.sh, the
# switch =1 and WPIN_DRY_RUN=1).
#
#   stock  the subject (handle's 32-byte wipe) ABSENT -- it is a dead store --
#          except under -fno-builtin, where the call to memset is opaque and
#          stays (PRESENT; the existing README measurement).
#   off    the call or copy is not touched and is counted: its one unhandled
#          counter is 1, every other is 0, the block is not enabled, nothing is
#          pinned, the "nothing to pin" line names the counter, pin.sh exits 4.
#          Its -S output is byte-identical to stock's: with the switches unset
#          nothing in handle is a memset intrinsic, so nothing changes. With
#          --baseline it is also byte-identical to the v2 build's.
#   ext    one site in the switch's block, exactly the one in the table, done 1
#          and would 1, every counter 0, no WipePin line, pin.sh exits 0, the
#          -S output differs from stock's, and the subject is PRESENT.
#   dry    the same site, done 0 and would 1, dryRun true, the dry-run line,
#          pin.sh exits 4, and the -S output byte-identical to stock's.
# In every executable the control (wipe_kept, a fill use() reads afterwards) is
# PRESENT, or the reading is blind.

V3_FILL_BYTES = 32
V3_ARMS = ("off", "ext", "dry")
V3_LINKED = ("stock", "off", "ext", "dry")
V3_BARRIER_DRY = "WipePin: dry run: 1 zero-fill memset or bzero call(s) would get a barrier; none was changed"
V3_ZERO_COPY_DRY = "WipePin: dry run: 1 copy(ies) from an all-zero constant would be repaired; none was changed"
V3_RESOLUTION = [{"name": "handle", "resolution": "resolved", "exact": True, "linkage": "external"}]


def _v3_barrier(source, cflags, callee, counter, stock="ABSENT"):
    return {"source": source, "cflags": cflags, "switch": "WPIN_BARRIER_CALLS", "block": "barrierCalls",
            "done": "barrierCount", "would": "wouldBarrierCount", "counter": counter, "stock": stock,
            "site": {"function": "handle", "callee": callee, "lengthBytes": V3_FILL_BYTES, "line": None},
            "dryLine": V3_BARRIER_DRY}


def _v3_zero_copy(cflags, form, callee, counter):
    return {"source": "zcopy.c", "cflags": cflags, "switch": "WPIN_ZERO_COPY", "block": "zeroCopy",
            "done": "repairedCount", "would": "wouldRepairCount", "counter": counter, "stock": "ABSENT",
            "site": {"function": "handle", "form": form, "callee": callee, "source": "vg_zeros",
                     "destKind": "alloca", "lengthBytes": V3_FILL_BYTES, "line": None},
            "dryLine": V3_ZERO_COPY_DRY}


# The buffer barrier (section 14.6), on the wipe written as a loop of zero
# stores (loop.c). Written before these cells were first run, from what the
# landed switch is for and from the prototype's measured records (measured
# outside this repository, on the tree this one's v3 came from): with the switch
# off there is nothing at pipeline start to
# pin or count -- no memset, no call -- so the off arm is "nothing to pin" with
# every counter 0. The site's buffer is null without -g (the release clang
# discards value names) and the variable's name with -g. `controlSame`: the
# control function's -S text is the same in ext as in stock, i.e. the barrier
# changed nothing outside the function in scope; compared without -g only,
# where no module-wide .Ltmp numbering can shift it.
V3_BUFFER_DRY = "WipePin: dry run: 1 buffer barrier(s) would be placed; none was changed"


def _v3_buffer(cflags, buffer, control_same, source="loop.c"):
    return {"source": source, "cflags": cflags, "switch": "WPIN_BUFFER_BARRIER", "block": "bufferBarriers",
            "done": "count", "would": None, "counter": None, "stock": "ABSENT",
            "site": {"function": "handle", "buffer": buffer, "bytes": V3_FILL_BYTES, "reason": "loop-store",
                     "anchor": "lifetime-end"},
            "dryLine": V3_BUFFER_DRY, "controlSame": control_same}


# What reaches pipeline start (clang 18.1.3, glibc 2.39, measured in the lab
# before these cells were written): memset under =2/=3 is a call of the
# header's wrapper memset.inline; bzero under =2/=3 a call of bzero.inline
# (without FORTIFY clang's front end lowers bzero to llvm.memset, which the
# plain pin already covers, so that case is not here); __memset_chk through a
# local pointer stays a call; -fno-builtin leaves a call of memset; a memcpy
# from a static const all-zero array is llvm.memcpy, and under =2 a call of
# memcpy.inline.
V3 = {
    "v3-fort2": _v3_barrier("memset.c", "-D_FORTIFY_SOURCE=2", "memset.inline", "inlineWrapperMemset"),
    "v3-fort3": _v3_barrier("memset.c", "-D_FORTIFY_SOURCE=3", "memset.inline", "inlineWrapperMemset"),
    "v3-bzero-fort2": _v3_barrier("bzero.c", "-D_FORTIFY_SOURCE=2", "bzero.inline", "inlineWrapperBzero"),
    "v3-bzero-fort3": _v3_barrier("bzero.c", "-D_FORTIFY_SOURCE=3", "bzero.inline", "inlineWrapperBzero"),
    "v3-chk": _v3_barrier("chk.c", "", "__memset_chk", "memsetChk"),
    "v3-libcall": _v3_barrier("memset.c", "-fno-builtin", "memset", "libcallMemset", stock="PRESENT"),
    "v3-zcopy": _v3_zero_copy("", "intrinsic", "llvm.memcpy", "zeroGlobalCopy"),
    "v3-zcopy-fort2": _v3_zero_copy("-D_FORTIFY_SOURCE=2", "call", "memcpy.inline", "zeroGlobalCopyCall"),
    "v3-loop": _v3_buffer("", None, True),
    "v3-loop-g": _v3_buffer("-g", "key", False),
    # The loop wipe through an advancing pointer (`*p++ = 0`). Written before
    # the cell was first run, from the lab measurement that the pointer's
    # stack slot is followed and the write-back is not a use of the buffer.
    "v3-loop-ptr": _v3_buffer("", None, True, source="ptr.c"),
}
V3_ORDER = list(V3)

# The buffer barrier on an initialiser (init.c: `= {0}`, derive, use; no
# wipe), through pin.sh alone with WPIN_BUFFER_BARRIER=1. clang lowers `= {0}`
# to a zero-fill llvm.memset, which is pinned as it is without the switch
# (followedByUse true, the partial line). Every zero fill of the buffer is
# followed by a use, so the buffer gets no barrier -- its last stores are the
# secret, and a barrier would only keep them in memory -- and stderr counts
# it. (Until the fix of 2026-11-09 this cell expected a barrier with reason
# memset and the line "1 of 1 barrier site(s) are on buffers whose every zero
# fill is followed by a later use".)
V3_INIT = "v3-buffer-init"
V3_INIT_BLOCK = {"enabled": True, "count": 0, "sites": []}
V3_INITIALISER_LINE = ("WipePin: buffer barrier: 1 buffer(s) not barriered: every zero fill is followed by a "
                       "later use (read as an initialiser; a wipe that later code still touches, even code the "
                       "optimiser removes, is counted here too)")
V3_NO_PLACE_LINE = ("WipePin: buffer barrier: 1 buffer(s) not barriered: the buffer does not dominate a return "
                    "its wipe reaches, or there is no place (an alloca or variable-length array inside a branch "
                    "or loop, or a function that does not return)")
V3_INIT_LINES = [V3_INITIALISER_LINE]
# The barrier asm as it appears in textual IR.
V3_BARRIER_ASM = 'call void asm sideeffect "", "r,~{memory}"'


def _single(source, setting, cflags, pinsh, block, lines, apps, same_stock, zero_site=None,
            ir_barriers=None, musttail=False, no_memset=False):
    """A v3single cell (pin.sh alone, -S and -S -emit-llvm, target handle).
    `block` the expected bufferBarriers; `apps` the #APP count in handle's -S
    (None: at least one); `ir_barriers` the barrier calls in handle's .ll
    (checked at -O0 only, where the IR is the plugin's own output unoptimised);
    `musttail` that the .ll's musttail call is directly followed by its ret."""
    return {"source": source, "setting": setting, "cflags": cflags, "pinsh": pinsh, "block": block,
            "lines": lines, "apps": apps, "sameStock": same_stock, "zeroSite": zero_site,
            "irBarriers": ir_barriers, "musttail": musttail, "noMemset": no_memset}


_BB = "WPIN_BUFFER_BARRIER=1"
_NONE_BLOCK = {"enabled": True, "count": 0, "sites": []}


def _one_site(source_bytes, anchor):
    return {"enabled": True, "count": 1, "sites": [{"function": "handle", "buffer": None, "bytes": source_bytes,
                                                   "reason": "loop-store", "anchor": anchor}]}


def _sites(source_bytes, anchors):
    return {"enabled": True, "count": len(anchors),
            "sites": [{"function": "handle", "buffer": None, "bytes": source_bytes, "reason": "loop-store",
                       "anchor": a} for a in anchors]}


# Written in the lane's protocol before these cells were first run (2026-11-09):
#   v3-vla-branch-*   a VLA in a branch dominates no return: no barrier, the
#                     no-place line, nothing to pin (pin.sh 4), the IR verifies,
#                     and the -S is stock's.
#   v3-musttail-O0    the place is the return, so the barrier goes before the
#                     musttail call: one site (no dead return counted), the
#                     call still directly followed by its ret, the IR verifies.
#   v3-vla-musttail-O2  the same at -O2 for a VLA (no lifetime markers at any
#                     level): the backend does not fail, one site, bytes null.
# Added 2026-11-10, after a refuter found that at -O1 and above the barrier of
# musttail.c went before a lifetime end in a block no path reaches, was deleted
# with it, and the record still counted it (pin.sh 0, -S byte-identical to
# stock). Here the .ll is the optimised IR, so `irBarriers` asks that the
# barriers the record counts are still there after the optimiser:
#   v3-musttail-O2/-Os  one site, anchor ret, before the musttail call; one
#                     barrier in the optimised IR; the -S differs from stock.
#   v3-musttail-exits-O2  a return on one path (its lifetime end reachable) and
#                     a musttail call on the other: two sites in instruction
#                     order -- the call (its block comes first in clang's IR),
#                     then the lifetime end -- and two barriers left. The return
#                     path calls note() after its wipe: in a first probe without
#                     it, the optimiser hoisted both wipes and both barriers
#                     into the block before the branch, one barrier for two
#                     sites, which still covers both paths but is not what
#                     this count can check.
#   v3-loop-ptrcmp-O2  `for (p = key; p < key + n; p++) *p = 0`: the address
#                     comparison is not a later use, so a wipe: one site at the
#                     lifetime end, one barrier left, no initialiser line.
#   v3-exit-O2        the wipe only on a path that ends in exit(): no barrier,
#                     the no-place line, nothing to pin (pin.sh 4), the -S is
#                     stock's. Added after a reviewer found the build before
#                     barrier the other path's lifetime end, where no wipe is,
#                     and report the buffer repaired (record 1, pin.sh 0).
#   v3-buffer-initloop  an initialiser written as a loop: no barrier, the
#                     initialiser line, nothing to pin, the -S is stock's.
#   v3-buffer-inloop  the buffer declared in a loop body and wiped each
#                     iteration is a wipe: one site at its lifetime end, no
#                     initialiser line.
#   v3-zcopy-inline   __builtin_memcpy_inline from a zero constant, built
#                     -ffreestanding: repaired with a volatile memset.inline, so
#                     no call of memset appears in the -S.
V3_SINGLE = {
    "v3-vla-branch-O0": _single("vla.c", _BB, "-O0", "4", _NONE_BLOCK,
                                [V3_NO_PLACE_LINE, "nothing:vla.c"], 0, True, ir_barriers=0),
    "v3-vla-branch-O2": _single("vla.c", _BB, "-O2", "4", _NONE_BLOCK,
                                [V3_NO_PLACE_LINE, "nothing:vla.c"], 0, True),
    "v3-musttail-O0": _single("musttail.c", _BB, "-O0", "0", _one_site(V3_FILL_BYTES, "ret"), [], None, False,
                              ir_barriers=1, musttail=True),
    "v3-vla-musttail-O2": _single("vlamt.c", _BB, "-O2", "0", _one_site(None, "ret"), [], None, False,
                                  musttail=True),
    "v3-musttail-O2": _single("musttail.c", _BB, "-O2", "0", _one_site(V3_FILL_BYTES, "ret"), [], None, False,
                              ir_barriers=1, musttail=True),
    "v3-musttail-Os": _single("musttail.c", _BB, "-Os", "0", _one_site(V3_FILL_BYTES, "ret"), [], None, False,
                              ir_barriers=1, musttail=True),
    "v3-musttail-exits-O2": _single("mtexit.c", _BB, "-O2", "0", _sites(V3_FILL_BYTES, ["ret", "lifetime-end"]),
                                    [], None, False, ir_barriers=2, musttail=True),
    "v3-loop-ptrcmp-O2": _single("ptrcmp.c", _BB, "-O2", "0", _one_site(V3_FILL_BYTES, "lifetime-end"), [], None,
                                 False, ir_barriers=1),
    "v3-exit-O2": _single("exit.c", _BB, "-O2", "4", _NONE_BLOCK, [V3_NO_PLACE_LINE, "nothing:exit.c"], 0, True,
                          ir_barriers=0),
    "v3-buffer-initloop": _single("initloop.c", _BB, "-O2", "4", _NONE_BLOCK,
                                  [V3_INITIALISER_LINE, "nothing:initloop.c"], 0, True),
    "v3-buffer-inloop": _single("inloop.c", _BB, "-O2", "0", _one_site(V3_FILL_BYTES, "lifetime-end"), [], None,
                                False),
    "v3-zcopy-inline": _single("zinline.c", "WPIN_ZERO_COPY=1", "-O2 -ffreestanding", "0",
                               {"enabled": False, "count": 0, "sites": []}, [], 0, False,
                               zero_site={"function": "handle", "form": "intrinsic", "callee": "llvm.memcpy",
                                          "source": "vg_zeros", "destKind": "alloca",
                                          "lengthBytes": V3_FILL_BYTES, "line": None},
                               no_memset=True),
}
V3_SINGLE_ORDER = list(V3_SINGLE)


def ir_function(lines, fn):
    """The lines of `define ... @fn(` up to its closing brace in textual IR;
    None when there is no such definition."""
    for i, line in enumerate(lines):
        if line.startswith("define ") and f"@{fn}(" in line:
            body = []
            for m in lines[i:]:
                body.append(m)
                if m == "}":
                    return body
            return body
    return None


def musttail_followed_by_ret(body):
    """Every musttail call in `body` is directly followed by a ret (an
    optional bitcast in between is not produced by these sources); False when
    there is none."""
    seen = False
    for i, line in enumerate(body):
        if "musttail call" in line:
            seen = True
            nxt = body[i + 1].strip() if i + 1 < len(body) else ""
            if not nxt.startswith("ret "):
                return False
    return seen


def clang_asm_function(text, fn):
    """The lines of `fn` in a clang -S listing, from its label to its
    .Lfunc_end label; None when the listing has no such function."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(fn)}:", line):
            body = []
            for m in lines[i + 1:]:
                if re.match(r"^\.Lfunc_end\d+:", m):
                    return body
                body.append(m)
            return body
    return None

# pin.sh with a switch value the plugin must refuse: exit 3, no record, clang
# rc 0, and exactly the refusal line of section 14.2.
V3_REFUSE = {
    "v3-refuse-barrier2": ("WPIN_BARRIER_CALLS=2",
                           "WipePin: refusing to install: WPIN_BARRIER_CALLS='2' is neither 0 nor 1"),
    "v3-refuse-zerocopy-true": ("WPIN_ZERO_COPY=true",
                                "WipePin: refusing to install: WPIN_ZERO_COPY='true' is neither 0 nor 1"),
    "v3-refuse-buffer2": ("WPIN_BUFFER_BARRIER=2",
                          "WipePin: refusing to install: WPIN_BUFFER_BARRIER='2' is neither 0 nor 1"),
}
V3_REFUSE_ORDER = list(V3_REFUSE)

# The handshake (section 14.7), on the trailing shape's front-end IR compiled
# back with -x ir -S, through pin.sh and stock:
#   v3-ident-same   llvm.ident as clang wrote it: a record, host.ident the
#                   stripped ident, identMajor = builtMajor = the compiler's
#                   major, checked true, intrinsicsCompared the number of
#                   llvm.* declarations in the input that the plugin's table
#                   knows (re-counted here from the .ll); the trailing memset
#                   pinned (pin.sh 0), no WipePin line, -S not the stock one.
#   v3-ident-other  llvm.ident rewritten to the next major version: refused --
#                   exactly the refusal line, no record, pin.sh 3 -- and the -S
#                   output byte-identical to stock's: nothing was changed.
#   v3-ident-none   no llvm.ident: not refused. A record with ident null,
#                   identMajor null, checked false, intrinsicsCompared as above;
#                   exactly the "names no clang version (absent)" line; pinned
#                   as in v3-ident-same (pin.sh 0).
V3_IDENT = {"v3-ident-same": "ident-fe.ll", "v3-ident-other": "ident-other.ll", "v3-ident-none": "ident-none.ll"}
V3_IDENT_ORDER = list(V3_IDENT)

# The intrinsic table the plugin compares (src/WipePin.cpp, IntrinsicTable),
# copied so that intrinsicsCompared can be re-counted from the input IR.
INTRINSIC_BASES = ("memset", "memset.inline", "memset.element.unordered.atomic", "memcpy", "memcpy.inline",
                   "memcpy.element.unordered.atomic", "lifetime.start", "lifetime.end", "dbg.declare",
                   "dbg.value", "dbg.label")
_DECLARE = re.compile(r"^declare\b.*?@(llvm\.[A-Za-z0-9_.]+)\(")


def table_declarations(ll_lines):
    """How many llvm.* declarations in textual IR have a name the table knows:
    the name is llvm.<base>, or begins with llvm.<base>. for some base."""
    n = 0
    for line in ll_lines:
        m = _DECLARE.match(line)
        if m and any(m.group(1) == "llvm." + b or m.group(1).startswith("llvm." + b + ".")
                     for b in INTRINSIC_BASES):
            n += 1
    return n


def module_ident(ll_lines):
    """The first operand of !llvm.ident in textual IR, as written, or None."""
    node = None
    for line in ll_lines:
        m = re.match(r"^!llvm\.ident = !\{!(\d+)", line)
        if m:
            node = m.group(1)
    if node is None:
        return None
    for line in ll_lines:
        m = re.match(r"^!" + node + r' = !\{!"((?:[^"\\]|\\.)*)"', line)
        if m:
            return m.group(1)
    return None


def nothing_to_pin_line(module, counts):
    return (f"WipePin: nothing to pin in scope in {module} (zero-fill llvm.memset in scope: 0; "
            f"unhandled in scope: {unhandled_text(counts)})")


def grade_v3(lab, require_baseline=False):
    rows, problems, incomplete = [], [], []
    d = os.path.join(lab, "v3")
    for cell in V3_ORDER:
        exp = V3[cell]
        base = os.path.join(d, cell)
        try:
            kv = load_kv(base + ".kv")
            recs = {a: load_json(f"{base}-{a}.json") for a in V3_ARMS}
            mans = {a: load_kv(f"{base}-{a}.manifest.kv") for a in V3_ARMS}
            errs = {a: wipepin_lines(load_lines(f"{base}-{a}.stderr.txt")) for a in V3_ARMS}
            shas = {a: sha_file(f"{base}-{a}.s") for a in V3_LINKED + ("orig",)}
            for a in V3_LINKED:
                if shas[a] is None:
                    raise Incomplete(f"v3/{cell}-{a}.s: no -S output")
            texts = {}
            for a in V3_LINKED:
                prog = f"{base}-{a}.prog"
                if not os.path.isfile(prog):
                    raise Incomplete(f"v3/{cell}-{a}.prog: no executable")
                try:
                    texts[a] = objdump_fill.disassemble(prog)
                except RuntimeError as e:
                    raise Incomplete(f"v3/{cell}-{a}.prog: {e}")
        except Incomplete as e:
            incomplete.append(f"{cell}: {str(e).replace(lab, '<lab>')}")
            continue

        bad = []
        if (kv.get("source"), kv.get("switch"), kv.get("cflags")) != (exp["source"], exp["switch"], exp["cflags"]):
            bad.append(f"runner ran source={kv.get('source')} switch={kv.get('switch')} cflags={kv.get('cflags')!r}")
        steps = ["ioRc", "mainRc", "stockRc"] + [f"{a}{s}" for a in V3_LINKED for s in ("AsmRc", "LinkRc")]
        failed = [f"{k}={kv.get(k)}" for k in steps if kv.get(k) != "0"]
        if failed:
            bad.append(f"a step failed: {' '.join(failed)}")
        want_rc = {"off": "4", "ext": "0", "dry": "4"}
        for a in V3_ARMS:
            if kv.get(f"{a}PinShRc") != want_rc[a]:
                bad.append(f"{a}: pin.sh exited {kv.get(a + 'PinShRc')}, expected {want_rc[a]}")

        for a in V3_ARMS:
            rec, man, on, dry = recs[a], mans[a], a != "off", a == "dry"
            bad += [f"{a} record: {p}" for p in v3_problems(rec, barrier=on and exp["block"] == "barrierCalls",
                                                            zero=on and exp["block"] == "zeroCopy",
                                                            buffer=on and exp["block"] == "bufferBarriers")]
            counts = {exp["counter"]: 1} if a == "off" and exp["counter"] else {}
            checks = [
                ("module", rec.get("module"), exp["source"]),
                ("scope", rec.get("scope"), "functions"),
                ("requested", rec.get("requested"), ["handle"]),
                ("resolution", rec.get("resolution"), V3_RESOLUTION),
                ("dryRun", rec.get("dryRun"), dry),
                ("optLevel", rec.get("optLevel"), {"speedup": 2, "size": 0}),
                ("pinned", rec.get("pinned"), []),
                ("pinnedCount", rec.get("pinnedCount"), 0),
                ("wouldPinCount", rec.get("wouldPinCount"), 0),
                ("seen.zeroFillMemsetInScope", (rec.get("seen") or {}).get("zeroFillMemsetInScope"), 0),
                ("unhandled", rec.get("unhandled"), {k: counts.get(k, 0) for k in UNHANDLED_KEYS}),
            ]
            if on:
                blk = rec.get(exp["block"]) if isinstance(rec.get(exp["block"]), dict) else {}
                checks += [
                    (f"{exp['block']}.sites", blk.get("sites"), [exp["site"]]),
                    (f"{exp['block']}.{exp['done']}", blk.get(exp["done"]), 0 if dry else 1),
                ]
                if exp["would"]:
                    checks.append((f"{exp['block']}.{exp['would']}", blk.get(exp["would"]), 1))
            for name, got, want in checks:
                if got != want:
                    bad.append(f"{a} record {name} = {got!r}, expected {want!r}")
            want_lines = {"off": [nothing_to_pin_line(exp["source"], counts)], "ext": [],
                          "dry": [exp["dryLine"]]}[a]
            if errs[a] != want_lines:
                bad.append(f"{a}: WipePin lines {errs[a]}, expected {want_lines}")
            mchecks = [("rc", "0"), ("status", want_rc[a]), ("repairCount", "1" if a == "ext" else "0"),
                       ("pinnedCount", "0"), ("hostChecked", "true"), ("recordError", "")]
            for k, want in mchecks:
                if man.get(k) != want:
                    bad.append(f"{a}: pin.sh manifest {k}={man.get(k)!r}, expected {want!r}")

        if shas["dry"] != shas["stock"]:
            bad.append("dry: the -S output differs from stock's, in the arm told to change nothing")
        if shas["off"] != shas["stock"]:
            bad.append("off: the -S output differs from stock's, with the switches unset")
        if shas["ext"] == shas["stock"]:
            bad.append("ext: the -S output is byte-identical to stock's: the switch changed nothing")
        orig = "-"
        if kv.get("baseline") == "present":
            if kv.get("origRc") != "0":
                bad.append(f"orig: the v2 build's compile exited {kv.get('origRc')}")
            if shas["orig"] is None:
                orig = "?"
                bad.append("orig: no -S output from the v2 build")
            else:
                orig = "yes" if shas["off"] == shas["orig"] else "NO"
                if orig != "yes":
                    bad.append("off: the -S output differs from the v2 build's with the switches unset")
        elif require_baseline:
            orig = "not run"
            bad.append("no --baseline on the runner: the switches-off output was not compared with the v2 build's")
        else:
            orig = "not run"

        readings = {}
        for a in V3_LINKED:
            subj = objdump_fill.wipe_reading(texts[a], "handle", None, V3_FILL_BYTES)
            ctl = objdump_fill.wipe_reading(texts[a], "wipe_kept", None, V3_FILL_BYTES)
            readings[a] = subj
            want = "PRESENT" if a == "ext" else exp["stock"]
            if subj["verdict"] != want:
                bad.append(f"{a}: subject {objdump_fill.describe(subj)}, expected {want}")
            if ctl["verdict"] != "PRESENT":
                bad.append(f"{a}: control {objdump_fill.describe(ctl)}: the reading is blind in this executable")

        if exp.get("controlSame"):
            try:
                with open(f"{base}-stock.s", encoding="utf-8", errors="replace") as f:
                    ctl_stock = clang_asm_function(f.read(), "wipe_kept")
                with open(f"{base}-ext.s", encoding="utf-8", errors="replace") as f:
                    ctl_ext = clang_asm_function(f.read(), "wipe_kept")
            except OSError as e:
                ctl_stock = ctl_ext = None
                bad.append(f"the control's -S text could not be read: {e.__class__.__name__}")
            if ctl_stock is None or ctl_ext is None:
                bad.append("wipe_kept is missing from the stock or the ext -S output")
            elif ctl_stock != ctl_ext:
                bad.append("ext: the control wipe_kept's -S text differs from stock's: the barrier changed a "
                           "function outside the scope")

        ext_blk = recs["ext"].get(exp["block"]) if isinstance(recs["ext"].get(exp["block"]), dict) else {}
        site = (ext_blk.get("sites") or [{}])[0] if ext_blk.get("sites") else {}
        rows.append((cell, exp["cflags"] or "-", exp["switch"], site.get("callee") or site.get("reason", "-"),
                     "/".join(kv.get(f"{a}PinShRc", "?") for a in V3_ARMS),
                     "/".join(readings[a]["verdict"] for a in V3_LINKED),
                     "yes" if shas["dry"] == shas["stock"] else "NO",
                     "yes" if shas["off"] == shas["stock"] else "NO", orig,
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]

    cell = V3_INIT
    try:
        kv = load_kv(os.path.join(d, cell + ".kv"))
        man = load_kv(os.path.join(d, cell + ".manifest.kv"))
        wl = wipepin_lines(load_lines(os.path.join(d, cell + ".stderr.txt")))
        rec = load_json(os.path.join(d, cell + ".json"))
        s_pin = sha_file(os.path.join(d, cell + ".s"))
        s_stock = sha_file(os.path.join(d, cell + "-stock.s"))
        if s_pin is None or s_stock is None:
            raise Incomplete(f"v3/{cell}: no -S output (pin.sh {s_pin is not None}, stock {s_stock is not None})")
    except Incomplete as e:
        incomplete.append(f"{cell}: {str(e).replace(lab, '<lab>')}")
    else:
        bad = []
        if (kv.get("source"), kv.get("setting")) != ("init.c", "WPIN_BUFFER_BARRIER=1"):
            bad.append(f"runner ran source={kv.get('source')} setting={kv.get('setting')}")
        if kv.get("stockRc") != "0":
            bad.append(f"stockRc={kv.get('stockRc')}")
        if kv.get("pinShRc") != "0":
            bad.append(f"pin.sh exited {kv.get('pinShRc')}, expected 0")
        bad += [f"record: {p}" for p in v3_problems(rec, buffer=True)]
        sites = rec.get("pinned") or []
        for name, got, want in (("module", rec.get("module"), "init.c"),
                                ("requested", rec.get("requested"), ["handle"]),
                                ("pinnedCount", rec.get("pinnedCount"), 1),
                                ("followedByUse per site", [s.get("followedByUse") for s in sites], [True]),
                                ("bufferBarriers", rec.get("bufferBarriers"), V3_INIT_BLOCK)):
            if got != want:
                bad.append(f"record {name} = {got!r}, expected {want!r}")
        want_lines = V3_INIT_LINES + [partial_line(1, 1, "init.c")]
        if wl != want_lines:
            bad.append(f"WipePin lines {wl}, expected {want_lines}")
        for k, want in (("rc", "0"), ("status", "0"), ("repairCount", "1"), ("pinnedCount", "1"),
                        ("bufferBarrierCount", "0"), ("followedByUseCount", "1"), ("recordError", "")):
            if man.get(k) != want:
                bad.append(f"pin.sh manifest {k}={man.get(k)!r}, expected {want!r}")
        try:
            with open(os.path.join(d, cell + ".s"), encoding="utf-8", errors="replace") as f:
                body = clang_asm_function(f.read(), "handle")
        except OSError:
            body = None
        if body is None:
            bad.append("handle is missing from the -S output")
        elif any("#APP" in l for l in body):
            bad.append("handle's -S has a barrier (#APP) on a buffer that is only initialised")
        rows.append((cell, "-", kv.get("setting"), "memset (initialiser), no barrier", kv.get("pinShRc"), "-", "-",
                     "-", "-", "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]

    for cell in V3_SINGLE_ORDER:
        exp = V3_SINGLE[cell]
        base = os.path.join(d, cell)
        try:
            kv = load_kv(base + ".kv")
            recs = {k: load_json(f"{base}{sfx}.json") for k, sfx in (("s", ""), ("ll", "-ll"))}
            mans = {k: load_kv(f"{base}{sfx}.manifest.kv") for k, sfx in (("s", ""), ("ll", "-ll"))}
            errs = {k: wipepin_lines(load_lines(f"{base}{sfx}.stderr.txt")) for k, sfx in (("s", ""), ("ll", "-ll"))}
            s_text = "\n".join(load_lines(base + ".s"))
            stock_text = "\n".join(load_lines(base + "-stock.s"))
            ll = load_lines(base + ".ll")
        except Incomplete as e:
            incomplete.append(f"{cell}: {str(e).replace(lab, '<lab>')}")
            continue
        bad = []
        if (kv.get("source"), kv.get("setting"), kv.get("cflags")) != (exp["source"], exp["setting"], exp["cflags"]):
            bad.append(f"runner ran source={kv.get('source')} setting={kv.get('setting')} "
                       f"cflags={kv.get('cflags')!r}")
        if kv.get("stockRc") != "0":
            bad.append(f"stockRc={kv.get('stockRc')}")
        for k in ("pinShRc", "llPinShRc"):
            if kv.get(k) != exp["pinsh"]:
                bad.append(f"{k}={kv.get(k)}, expected {exp['pinsh']}")
        if kv.get("verifyRc") != "0":
            bad.append(f"the IR verifier ({kv.get('opt')}) exited {kv.get('verifyRc')} on the .ll the plugin left")
        buffer_on = exp["setting"] == _BB
        zero_on = exp["setting"] == "WPIN_ZERO_COPY=1"
        nothing = [nothing_to_pin_line(l.split(":", 1)[1], {}) if l.startswith("nothing:") else l
                   for l in exp["lines"]]
        for k in ("s", "ll"):
            rec, man = recs[k], mans[k]
            bad += [f"{k} record: {p}" for p in v3_problems(rec, zero=zero_on, buffer=buffer_on)]
            checks = [("module", rec.get("module"), exp["source"]), ("requested", rec.get("requested"), ["handle"]),
                      ("pinnedCount", rec.get("pinnedCount"), 0), ("unhandled", rec.get("unhandled"),
                                                                     {u: 0 for u in UNHANDLED_KEYS}),
                      ("bufferBarriers", rec.get("bufferBarriers"), exp["block"])]
            if exp["zeroSite"]:
                checks.append(("zeroCopy", rec.get("zeroCopy"),
                               {"enabled": True, "sites": [exp["zeroSite"]], "repairedCount": 1,
                                "wouldRepairCount": 1}))
            for name, got, want in checks:
                if got != want:
                    bad.append(f"{k} record {name} = {got!r}, expected {want!r}")
            if errs[k] != nothing:
                bad.append(f"{k}: WipePin lines {errs[k]}, expected {nothing}")
            # pin.sh's repairCount is every repair the record counts: here the
            # buffer barriers placed, plus the one zero copy where there is one.
            repairs = str(exp["block"]["count"] + (1 if exp["zeroSite"] else 0))
            for mk, want in (("rc", "0"), ("status", exp["pinsh"]), ("repairCount", repairs), ("recordError", "")):
                if man.get(mk) != want:
                    bad.append(f"{k}: pin.sh manifest {mk}={man.get(mk)!r}, expected {want!r}")
        if recs["s"].get("evidenceDigest") != recs["ll"].get("evidenceDigest"):
            bad.append("the -S and the -S -emit-llvm compiles wrote different records")
        body = clang_asm_function(s_text, "handle")
        if body is None:
            bad.append("handle is missing from the -S output")
        else:
            apps = sum(1 for l in body if "#APP" in l)
            if (exp["apps"] is None and apps < 1) or (exp["apps"] is not None and apps != exp["apps"]):
                bad.append(f"handle's -S has {apps} barrier(s) (#APP), expected "
                           f"{'at least 1' if exp['apps'] is None else exp['apps']}")
        same = s_text == stock_text
        if same != exp["sameStock"]:
            bad.append("the -S output " + ("is byte-identical to" if same else "differs from") + " stock's, expected "
                       + ("the same" if exp["sameStock"] else "a difference"))
        ir = ir_function(ll, "handle")
        if ir is None:
            bad.append("handle is missing from the .ll")
        else:
            if exp["irBarriers"] is not None:
                n = sum(1 for l in ir if V3_BARRIER_ASM in l)
                if n != exp["irBarriers"]:
                    bad.append(f"handle's .ll has {n} barrier call(s), expected {exp['irBarriers']}")
            if exp["musttail"] and not musttail_followed_by_ret(ir):
                bad.append("handle's musttail call is not directly followed by its ret")
        if exp["noMemset"]:
            for what, text in (("the plugin's", s_text), ("stock's", stock_text)):
                if re.search(r"\bmemset\b", text):
                    bad.append(f"{what} -S calls memset, in a -ffreestanding build of __builtin_memcpy_inline")
        blk = recs["s"].get("bufferBarriers") if isinstance(recs["s"].get("bufferBarriers"), dict) else {}
        summary = (f"count={blk.get('count')} " + ",".join(s.get("anchor", "?") for s in blk.get("sites") or [])
                   if buffer_on else "zeroCopy " + str((recs["s"].get("zeroCopy") or {}).get("repairedCount")))
        rows.append((cell, exp["cflags"], exp["setting"], summary.strip(), kv.get("pinShRc"),
                     f"IR verify rc {kv.get('verifyRc')}", "-", "-S=stock" if same else "-S!=stock", "-",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]

    for cell in V3_REFUSE_ORDER:
        setting, line = V3_REFUSE[cell]
        try:
            kv = load_kv(os.path.join(d, cell + ".kv"))
            man = load_kv(os.path.join(d, cell + ".manifest.kv"))
            wl = wipepin_lines(load_lines(os.path.join(d, cell + ".stderr.txt")))
            console = load_lines(os.path.join(d, cell + ".console.txt"))
        except Incomplete as e:
            incomplete.append(f"{cell}: {str(e).replace(lab, '<lab>')}")
            continue
        bad = []
        if kv.get("setting") != setting:
            bad.append(f"runner set {kv.get('setting')!r}, expected {setting!r}")
        if kv.get("pinShRc") != "3":
            bad.append(f"pin.sh exited {kv.get('pinShRc')}, expected 3")
        if man.get("rc") != "0":
            bad.append(f"clang rc {man.get('rc')}, expected 0: a refusal leaves the compile's status alone")
        if man.get("record") != "" or os.path.exists(os.path.join(d, cell + ".json")):
            bad.append("a record exists")
        if not any("no WipePin record was written" in l for l in console):
            bad.append("pin.sh did not say that no record was written")
        if wl != [line]:
            bad.append(f"WipePin lines {wl}, expected exactly [{line!r}]")
        rows.append((cell, "-", setting, "-", kv.get("pinShRc"), "-", "-", "-", "-",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]

    built = None
    for cell in V3_IDENT_ORDER:
        ll_name = V3_IDENT[cell]
        try:
            kv = load_kv(os.path.join(d, cell + ".kv"))
            man = load_kv(os.path.join(d, cell + ".manifest.kv"))
            wl = wipepin_lines(load_lines(os.path.join(d, cell + ".stderr.txt")))
            console = load_lines(os.path.join(d, cell + ".console.txt"))
            ll = load_lines(os.path.join(d, ll_name))
            s_pin = sha_file(os.path.join(d, cell + ".s"))
            s_stock = sha_file(os.path.join(d, cell + "-stock.s"))
            if s_pin is None or s_stock is None:
                raise Incomplete(f"v3/{cell}: no -S output (pin.sh {s_pin is not None}, stock {s_stock is not None})")
            rec = load_json(os.path.join(d, cell + ".json")) if cell != "v3-ident-other" else None
        except Incomplete as e:
            incomplete.append(f"{cell}: {str(e).replace(lab, '<lab>')}")
            continue
        bad = []
        if kv.get("input") != ll_name:
            bad.append(f"runner compiled {kv.get('input')!r}, expected {ll_name!r}")
        for k in ("frontEndRc", "stockRc"):
            if kv.get(k) != "0":
                bad.append(f"{k}={kv.get(k)}")
        try:
            cc_major = int(kv.get("ccMajor", ""))
        except ValueError:
            cc_major = None
            bad.append(f"runner did not record the compiler's major version: ccMajor={kv.get('ccMajor')!r}")
        raw = module_ident(ll)
        declared = table_declarations(ll)
        host = rec.get("host") if isinstance(rec, dict) and isinstance(rec.get("host"), dict) else {}
        if cell == "v3-ident-same":
            built = host.get("builtMajor")
        want_built = built if built is not None else cc_major

        if cell == "v3-ident-other":
            want_ident = f"clang version {cc_major + 1}.1.1" if cc_major is not None else None
            if raw != want_ident:
                bad.append(f"the input's llvm.ident is {raw!r}, expected {want_ident!r}")
            line = (f"WipePin: refusing to install: the module was produced by clang {ident_major(raw)} "
                    f"(llvm.ident \"{strip_ident(raw or '')}\") and this plugin was built against LLVM {want_built}")
            if kv.get("pinShRc") != "3":
                bad.append(f"pin.sh exited {kv.get('pinShRc')}, expected 3")
            if man.get("rc") != "0":
                bad.append(f"clang rc {man.get('rc')}, expected 0")
            if man.get("record") != "" or os.path.exists(os.path.join(d, cell + ".json")):
                bad.append("a record exists after a refusal")
            if not any("no WipePin record was written" in l for l in console):
                bad.append("pin.sh did not say that no record was written")
            if wl != [line]:
                bad.append(f"WipePin lines {wl}, expected exactly [{line!r}]")
            if s_pin != s_stock:
                bad.append("the refused compile's -S output differs from stock's: the IR was changed")
            summary = "refused"
        else:
            none = cell == "v3-ident-none"
            if none:
                if raw is not None or any(l.startswith("!llvm.ident") for l in ll):
                    bad.append("the input still has an llvm.ident")
            elif raw is None or ident_major(raw) != cc_major:
                bad.append(f"the input's llvm.ident {raw!r} does not name clang {cc_major}")
            bad += [f"record: {p}" for p in v3_problems(rec, checked=not none)]
            want_host = {"ident": None if none else strip_ident(raw or ""),
                         "identMajor": None if none else cc_major, "builtMajor": cc_major,
                         "checked": not none, "intrinsicsCompared": declared}
            if host != want_host:
                bad.append(f"record host = {host!r}, expected {want_host!r}")
            if declared < 1:
                bad.append("the input declares no intrinsic the table knows: intrinsicsCompared shows nothing")
            sites = rec.get("pinned") or []
            checks = [("module", rec.get("module"), ll_name), ("requested", rec.get("requested"), ["handle"]),
                      ("pinnedCount", rec.get("pinnedCount"), 1),
                      ("followedByUse per site", [s.get("followedByUse") for s in sites], [False])]
            for name, got, want in checks:
                if got != want:
                    bad.append(f"record {name} = {got!r}, expected {want!r}")
            want_lines = ([f"WipePin: the module's llvm.ident names no clang version (absent); the host compiler "
                           f"was not checked against LLVM {want_built}"] if none else [])
            if wl != want_lines:
                bad.append(f"WipePin lines {wl}, expected {want_lines}")
            if kv.get("pinShRc") != "0":
                bad.append(f"pin.sh exited {kv.get('pinShRc')}, expected 0")
            if man.get("hostChecked") != ("false" if none else "true"):
                bad.append(f"pin.sh manifest hostChecked={man.get('hostChecked')!r}")
            if s_pin == s_stock:
                bad.append("the -S output is byte-identical to stock's: the pin changed nothing")
            summary = f"checked={str(host.get('checked')).lower()} compared={host.get('intrinsicsCompared')}"
        rows.append((cell, "-x ir", raw if raw is not None else "(no llvm.ident)", summary, kv.get("pinShRc"),
                     "-", "-", "-", "-", "ok" if not bad else "DISAGREES"))
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
                    help=f"the llvm-bcanalyzer that reads the -flto objects' summaries, lto and xtu cells (default {BCANALYZER})")
    ap.add_argument("--require-baseline", action="store_true",
                    help="a v3 cell whose switches-off output was not compared with the v2 build's (the runner "
                         "had no --baseline) disagrees, rather than printing 'not run'")
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
    lrow, lprob, linc, lforms = grade_lto(lab, args.bcanalyzer)
    xrow, xprob, xinc = grade_xtu(lab, args.bcanalyzer)
    vrow, vprob, vinc = grade_v3(lab, args.require_baseline)
    problems += pprob + sprob + tprob + lprob + xprob + vprob
    incomplete += pinc + sinc + tinc + linc + xinc + vinc

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
    print("lto: module summary of each -flto object (" + os.path.basename(args.bcanalyzer) + " -dump): "
          + ", ".join(f"{c} {f}" for c, f in lforms))
    print()
    table(("xtu (-O2, executable)", "form", "mode", "rc", "objects", "summary", "linker", "secure_wipe",
           "wipe.c record", "inlined", "subject: handle", "control: wipe_kept", "==stock", ""), xrow)
    print(f"xtu: read with {objdump_fill.objdump_version()}, `objdump -d --no-show-raw-insn` of each "
          "executable; inlined = no call to secure_wipe (or a renamed copy) left in handle")
    print(f"xtu: summary = the block each -flto object's module summary is in, thin GLOBALVAL_SUMMARY_BLOCK, "
          f"full FULL_LTO_GLOBALVAL_SUMMARY_BLOCK ({os.path.basename(args.bcanalyzer)} -dump, "
          f"{bcanalyzer_version(args.bcanalyzer)}); linker = the executable's .comment; secure_wipe = "
          "whether the executable still defines it")
    print()
    table(("v3 (-O2, target handle)", "cflags", "switch / setting", "ext callee / host", "pin.sh off/ext/dry",
           "subject stock/off/ext/dry", "dry==stock", "off==stock", "off==v2", ""), vrow)
    print("v3: subject = handle's 32-byte wipe, read from each linked executable as the xtu cells are; "
          "dry==stock, off==stock, off==v2 compare the -S output byte for byte (v2 = the runner's --baseline build)")

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
    n = len(rows) + len(prow) + len(srow) + len(trow) + len(lrow) + len(xrow) + len(vrow)
    print(f"\nall {n} cells as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
