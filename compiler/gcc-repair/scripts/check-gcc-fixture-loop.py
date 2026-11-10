#!/usr/bin/env python3
"""Grade the lab written by run-gcc-fixture-loop.sh. Compiles nothing.

    python3 compiler/gcc-repair/scripts/check-gcc-fixture-loop.py --lab DIR

Whether a wipe is in a listing is decided by the repository's assembly oracle
(compiler/eval/second-vendor/lib/asm-oracle.mjs), which this script reaches
through lib/asm-presence.mjs -- imported there, never copied -- so node is
required. WipePinGcc's own record is read too, but only to check that it says
what the cell asked of it; it never decides whether the wipe survived. The two
exceptions to "a listing" are the lto group, whose output is a linked shared
object, and the xtu group, whose output is a linked executable: there the zero
stores are read from `objdump -d` by objdump_fill.py beside this script, which
recognises the oracle's two inline idioms in objdump's spelling. The lto group
reads the text the runner wrote; the xtu group disassembles each executable
here, so objdump is required too.

Object files are compared byte for byte. That is the claim for the cells where
the plugin is loaded and changes nothing (dry, wrongname, nothing): an object
identical to the one built without the plugin. The switch group's stock, off
and dry listings are compared the same way; its zero-copy cells are read twice,
by the oracle and by zcopy_reading below, because the repair keeps the copy and
a copy from a zero constant is a load and a store, not a zero store (the
oracle can read 0 there while the copy is in the listing). The previous group,
when the runner was given a previous plugin, compares the -S listings of this
plugin and of the previous one byte for byte.

Every record is read with wpin_gcc_record.py (wipe-pin-v3) and with what the
cell set of the three switches of compiler/schema/wipe-pin.md section 14.2 as
`expect`, so a record whose `<block>.enabled` says otherwise is refused.

The expectations below were written from what each cell is for. A cell that
disagrees is printed as a disagreement and the run fails; the tables are never
edited into agreement. Where a table records something measured rather than
predicted (the level at which gcc-13 removes the stock wipe), the comment says
so.

Exit codes (compiler/schema/interfaces.md section 7):
    0  every expectation held
    2  at least one expectation did not
    3  a file was missing or unreadable, or node could not read the listings,
       or objdump an executable, so the lab could not be graded
"""

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wpin_gcc_record as wpr  # noqa: E402
import objdump_fill  # noqa: E402
from objdump_fill import objdump_zero_stores  # noqa: E402

LEVELS = ["-O0", "-O1", "-O2", "-O3", "-Os"]

# What gcc-13 13.3.0 reports as {optimize, optimize_size} for each flag,
# measured with the plugin itself (README.md, "Optimisation levels").
OPT_LEVELS = {"-O0": (0, 0), "-O1": (1, 0), "-O2": (2, 0), "-O3": (3, 0), "-Os": (2, 1)}

# Measured, not predicted: gcc-13 13.3.0 keeps the fixture's subject wipe at -O0
# only; at -O1 and above tree DSE deletes it (README.md, the base rows).
STOCK_PRESENT = {"-O0"}

# The plugin's stderr lists the nine counters of compiler/schema/wipe-pin.md
# section 14.3, in that order (the v2 plugin listed the first five).
UNHANDLED_ORDER = ("libcallMemset", "memsetChk", "nonZeroFill", "atomicMemset", "inlineWrapperMemset",
                   "bzeroCall", "inlineWrapperBzero", "zeroGlobalCopy", "zeroGlobalCopyCall")


def unhandled_text(**counts):
    return " ".join(f"{k}={counts.get(k, 0)}" for k in UNHANDLED_ORDER)


NO_UNHANDLED = unhandled_text()

# What every cell outside the switch group set of the three switches: none.
SWITCHES_OFF = {"barrierCalls": False, "zeroCopy": False, "bufferBarriers": False}


def partial_line(pinned, followed, module, unhandled=NO_UNHANDLED):
    return (f"WipePinGcc: partial: pinned {pinned} site(s) in {module}; {followed} followed by a "
            f"later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: "
            f"{unhandled}")


def nothing_line(module, unhandled=NO_UNHANDLED):
    return (f"WipePinGcc: nothing to pin in scope in {module} (zero-fill memset in scope: 0; "
            f"unhandled in scope: {unhandled})")


def nonexact_line(name, linkage):
    return (f"WipePinGcc: target {name} is not an exact definition ({linkage}); "
            f"the copy that runs may come from another translation unit")


def dry_line(n):
    return f"WipePinGcc: dry run: {n} zero-fill memset site(s) would be pinned; none was changed"


def dry_barrier_line(n):
    return f"WipePinGcc: dry run: {n} zero-fill call(s) would get a barrier; none was changed"


def dry_zero_copy_line(n):
    return (f"WipePinGcc: dry run: {n} copy(ies) from an all-zero constant would get a barrier; "
            f"none was changed")


def dry_buffer_line(n):
    return f"WipePinGcc: dry run: {n} buffer barrier(s) would be placed; none was changed"


def not_barriered_line(n):
    """A buffer whose every zero fill is followed by a later use gets no
    barrier (compiler/schema/wipe-pin.md section 14.6), and is counted here."""
    return (f"WipePinGcc: buffer barrier: {n} buffer(s) not barriered: every zero fill is followed by a "
            f"later use (read as an initialiser; a wipe that later code still touches, even code the "
            f"optimiser removes, is counted here too)")


def refusal_line(reason):
    return f"WipePinGcc: refusing to install: {reason}"


# --------------------------------------------------------------- expectations
#
# base-L        no plugin. The subject's wipe is present at -O0 only (measured).
# pin-L         WPIN_TARGET_FNS=handle_request. The wipe must be PRESENT at every
#               level, the record must say one site pinned -- the trailing memset,
#               followed by nothing -- and pin-gcc.sh exits 0.
# dry-L         the red control: loaded, told to change nothing. The listing and
#               the object must be byte-identical to base-L, and pin-gcc.sh exits 4.
# wrongname-L   a name that does not exist: nothing pinned, not-in-module, listing
#               and object identical to base-L, pin-gcc.sh exits 4.
# nothing-L     opaque.c (no memset at all) in module scope: nothing to pin, and
#               listing and object identical to nothing-base-L. Measured, not
#               assumed: this is the claim that loading the plugin, with nothing to
#               pin, changes nothing.
# The control (wipe_kept) must be PRESENT in every target.c listing.

def loop_expectations():
    exp = {}
    for o in LEVELS:
        stock = "PRESENT" if o in STOCK_PRESENT else "ABSENT"
        exp["base" + o] = {"opt": o, "kind": "base", "subject": stock}
        exp["pin" + o] = {
            "opt": o, "kind": "pin", "subject": "PRESENT", "pinShRc": 0,
            "pinnedCount": 1, "wouldPinCount": 1, "dryRun": False, "scope": "functions",
            "requested": ["handle_request"], "resolution": "resolved", "exact": True,
            "linkage": "external", "sites": [False], "lines": [],
            "sameAsBase": None if o in STOCK_PRESENT else False,
        }
        exp["dry" + o] = {
            "opt": o, "kind": "dry", "subject": stock, "pinShRc": 4,
            "pinnedCount": 0, "wouldPinCount": 1, "dryRun": True, "scope": "functions",
            "requested": ["handle_request"], "resolution": "resolved", "exact": True,
            "linkage": "external", "sites": [False], "lines": [dry_line(1)], "sameAsBase": True,
        }
        exp["wrongname" + o] = {
            "opt": o, "kind": "wrongname", "subject": stock, "pinShRc": 4,
            "pinnedCount": 0, "wouldPinCount": 0, "dryRun": False, "scope": "functions",
            "requested": ["handle_requestX"], "resolution": "not-in-module", "exact": None,
            "linkage": None, "sites": [],
            "lines": ["WipePinGcc: target handle_requestX not-in-module", nothing_line("target.c")],
            "sameAsBase": True,
        }
        exp["nothing" + o] = {
            "opt": o, "kind": "nothing", "pinShRc": 4,
            "pinnedCount": 0, "wouldPinCount": 0, "dryRun": False, "scope": "module",
            "requested": [], "resolution": None, "exact": None, "linkage": None, "sites": [],
            "lines": [nothing_line("opaque.c")], "sameAsBase": True,
        }
    return exp


EXPECT = loop_expectations()
ORDER = [f"{k}{o}" for k in ("base", "pin", "dry", "wrongname", "nothing") for o in LEVELS]

# The refusal for "no target" is followed by one line saying how to give one,
# as WipePin's is.
NO_TARGET_LINES = ["WipePinGcc: refusing to install: no target",
                   "WipePinGcc: set WPIN_TARGET_FNS=<fn>[,<fn>...] or WPIN_SCOPE=module"]

# pin-gcc.sh alone.
ALONE = {
    "notarget-O2": {"pinShRc": 3, "record": False, "lines": NO_TARGET_LINES},
    "syntaxonly-O2": {"pinShRc": 3, "record": False, "lines": []},
    "baddry-O2": {"pinShRc": 3, "record": False,
                  "lines": ["WipePinGcc: refusing to install: WPIN_DRY_RUN='yes' is neither 0 nor 1"]},
    # compiler/schema/wipe-pin.md section 14.2: a switch that is neither 0 nor
    # 1. (WPIN_BUFFER_BARRIER=1 is implemented now: the buffer group.)
    "badbarrier-O2": {"pinShRc": 3, "record": False,
                      "lines": [refusal_line("WPIN_BARRIER_CALLS='2' is neither 0 nor 1")]},
    "badzerocopy-O2": {"pinShRc": 3, "record": False,
                       "lines": [refusal_line("WPIN_ZERO_COPY='2' is neither 0 nor 1")]},
    "badbuffer-O2": {"pinShRc": 3, "record": False,
                     "lines": [refusal_line("WPIN_BUFFER_BARRIER='2' is neither 0 nor 1")]},
    # Two cc1 processes, target.c then opaque.c: the record left is opaque.c's,
    # where handle_request does not exist, although target.c was pinned.
    "twosources-O2": {"pinShRc": 4, "record": True, "module": "opaque.c", "sourceOperands": "2",
                      "lines": ["WipePinGcc: target handle_request not-in-module",
                                nothing_line("opaque.c")]},
}
ALONE_ORDER = ["notarget-O2", "syntaxonly-O2", "baddry-O2", "badbarrier-O2", "badzerocopy-O2",
               "badbuffer-O2", "twosources-O2"]

# The shapes. `sites` is followedByUse per recorded site, in order; `lines` is
# every WipePinGcc line stderr must hold, and nothing else may appear.
SHAPES = {
    "initloop": {"module": "initloop.c", "target": "handle", "sites": [], "pinShRc": 4,
                 "lines": [nothing_line("initloop.c")]},
    "inithelper": {"module": "inithelper.c", "target": "handle", "sites": [], "pinShRc": 4,
                   "lines": [nothing_line("inithelper.c")]},
    "initwipe": {"module": "initwipe.c", "target": "handle", "sites": [True, False], "pinShRc": 0,
                 "lines": [partial_line(2, 1, "initwipe.c")]},
    "aliasinit": {"module": "aliasinit.c", "target": "handle", "sites": [True], "pinShRc": 0,
                  "lines": [partial_line(1, 1, "aliasinit.c")]},
    "trailing": {"module": "trailing.c", "target": "handle", "sites": [False], "pinShRc": 0,
                 "lines": []},
    # Already pinned by the source (volatile, a "memory" clobber, the buffer as
    # an input operand): listed, left alone, nothing counted as pinned (so
    # pin-gcc.sh exits 4), and -- a later statement that names the buffer is a
    # use (compiler/schema/wipe-pin.md section 8) -- the site reads
    # followedByUse. `store` is the subject's zero store in the listing with
    # the plugin, then in the stock one: the source's barrier keeps it in both.
    "srcbarrier": {"module": "srcbarrier.c", "target": "handle", "sites": [True], "pinShRc": 4,
                   "volatile": [True], "pinned": 0, "lines": [partial_line(0, 1, "srcbarrier.c")],
                   "store": ("PRESENT", "PRESENT")},
    # A barrier that is not a pin (compiler/schema/wipe-pin.md section 9): a
    # "memory" clobber with no operand, and one whose operand is another local.
    # Neither keeps the store in the stock listing; the plugin must pin the
    # site and the store must be back. Graded from the listings, not from the
    # record.
    "clobonly": {"module": "clobonly.c", "target": "handle", "sites": [False], "pinShRc": 0,
                 "volatile": [False], "pinned": 1, "lines": [], "length": 8,
                 "store": ("PRESENT", "ABSENT")},
    "otherbar": {"module": "otherbar.c", "target": "handle", "sites": [False], "pinShRc": 0,
                 "volatile": [False], "pinned": 1, "lines": [], "length": 8,
                 "store": ("PRESENT", "ABSENT")},
    "c99inline": {"module": "c99inline.c", "target": "wipe_inline", "sites": [False], "pinShRc": 0,
                  "exact": False, "linkage": "available_externally",
                  "lines": [nonexact_line("wipe_inline", "available_externally")]},
    "cxxinline": {"module": "cxxinline.cpp", "target": "wipe_cxx", "sites": [False], "pinShRc": 0,
                  "exact": False, "linkage": "linkonce_odr",
                  "lines": [nonexact_line("wipe_cxx", "linkonce_odr")]},
    "nobuiltin": {"module": "nobuiltin.c", "target": "handle", "sites": [], "pinShRc": 4,
                  "unhandled": {"libcallMemset": 1},
                  "lines": [nothing_line("nobuiltin.c", NO_UNHANDLED.replace("libcallMemset=0", "libcallMemset=1"))]},
    "nonzero": {"module": "nonzero.c", "target": "handle", "sites": [False], "pinShRc": 0,
                "unhandled": {"nonZeroFill": 2},
                "lines": [partial_line(1, 0, "nonzero.c", NO_UNHANDLED.replace("nonZeroFill=0", "nonZeroFill=2"))]},
    "chk": {"module": "chk.c", "target": "handle", "sites": [], "pinShRc": 4,
            "unhandled": {"memsetChk": 1},
            "lines": [nothing_line("chk.c", NO_UNHANDLED.replace("memsetChk=0", "memsetChk=1"))]},
    # Measured, not predicted (the first version of `chk` was this source and
    # expected memsetChk 1): with a constant object size the front end has
    # already folded the checked call into __builtin_memset when the pass runs.
    "chkconst": {"module": "chkconst.c", "target": "handle", "sites": [False], "pinShRc": 0,
                 "unhandled": {"memsetChk": 0}, "lines": []},
}
for _o in LEVELS:
    SHAPES["loopreturn" + _o] = {"module": "loopreturn.c", "target": "handle", "sites": [False, False],
                                 "pinShRc": 0, "lines": [], "opt": _o}
SHAPE_ORDER = ["initloop", "inithelper", "initwipe", "aliasinit", "trailing"] + \
    [f"loopreturn{o}" for o in LEVELS] + ["srcbarrier", "clobonly", "otherbar", "c99inline", "cxxinline",
                                          "nobuiltin", "nonzero", "chk", "chkconst"]

# Something that is not this compile's record sits at WPIN_OUT before each compile.
STALE = {
    "stale-refused": {"before": "file", "after": "absent", "lines": NO_TARGET_LINES},
    "stale-syntaxonly": {"before": "file", "after": "absent", "lines": []},
    "stale-live": {"before": "file", "after": "file", "lines": []},
    "stale-dir": {"before": "dir", "after": "dir",
                  "lines": ["WipePinGcc: refusing to install: WPIN_OUT is a directory"]},
}
STALE_ORDER = ["stale-refused", "stale-syntaxonly", "stale-live", "stale-dir"]

# The trailing shape through -flto (README.md, "Other forms").
LTO_REFUSAL = ("WipePinGcc: refusing to install: loaded into the LTO back end, where this pass does "
               "not run; load it into the compile step instead")
# Measured, not predicted: gcc-13 13.3.0 starts lto1 twice for this one-object
# -shared link (the whole-program analysis, then one partition), and each
# loads the plugin, so the refusal is printed twice.
LTO_REFUSALS = 2
# The site's buffer is 32 bytes; a zero fill that survived the link covers all
# of it.
LTO_FILL_BYTES = 32
LTO_ORDER = ["lto-compile", "lto-linkline", "lto-stock"]

# The xtu cells: a wipe helper in another translation unit, and the loss an LTO
# link creates for it. The lto group above links one object, so nothing from
# another unit is inlined there. Four units, generated by the runner into
# <lab>/xtu/src -- the same four sources as the WipePin loop's xtu cells -- and
# linked into an executable at -O2:
#
#   wipe.c  secure_wipe(void *p, size_t n) { memset(p, 0, n); }, external; the
#           memset is on line 3
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
# (objdump -d; the reader is objdump_fill.py, which the WipePin loop imports
# too). When no call to secure_wipe is left in handle, the helper was inlined
# and the fill can only be in handle: PRESENT when its zero stores cover the 32
# bytes or it calls memset, ABSENT when there are none. When the call is left,
# the fill is wherever secure_wipe does it: PRESENT when its body calls or
# tail-calls memset. The control is read the same way in wipe_kept, with no
# helper involved.
#
# xtu-nolto      stock, no LTO. Each unit is optimised alone, so use.c cannot
#                see into secure_wipe: the call stays (inlined: no) and the fill
#                is secure_wipe's memset, on a length the helper does not know
#                (PRESENT). The premise: the helper keeps the wipe.
# xtu-lto-stock  -flto compiles and a stock -flto link. The link sees
#                secure_wipe's body and inlines it into handle (inlined: yes),
#                where the fill is a store to a local that dies right after it:
#                a dead store, gone (ABSENT). The same source reads PRESENT in
#                xtu-nolto; the loss is the link's.
# xtu-lto-pin    WipePinGcc at the compile of wipe.c only (WPIN_TARGET_FNS=
#                secure_wipe, functions scope), every other unit and the link
#                stock. The barrier after the memset names the buffer, travels
#                in wipe.o's GIMPLE and comes along where the helper is
#                inlined: PRESENT in handle, the whole 32 bytes (inlined: yes),
#                and the executable is not the stock one. The record: one site
#                in secure_wipe, destKind argument (the helper's parameter),
#                lengthBytes null (not a constant inside the helper),
#                followedByUse null (not a local), line 3, pinnedCount 1; no
#                WipePinGcc line on the compile's stderr.
# xtu-lto-dry    the same with WPIN_DRY_RUN=1: the red control. ABSENT and
#                inlined as in xtu-lto-stock, the executable byte-identical to
#                xtu-lto-stock's, pinnedCount 0 / wouldPinCount 1 and the dry-run
#                line.
# In every cell the control (wipe_kept) is PRESENT; no link loads the plugin, so
# no link prints a WipePinGcc line; every -flto object carries GCC's LTO
# sections, and io.o never does.
#
# The first run was of another fixture, and this one replaced it. There the
# control went through the helper too -- wipe_kept called secure_wipe on a buffer
# that use() read afterwards, expected PRESENT and inlined wherever handle's call
# was -- so secure_wipe had two callers. Measured (README.md, the xtu cells):
# xtu-nolto, xtu-lto-stock and xtu-lto-dry as expected, and xtu-lto-pin
# DISAGREES: "secure_wipe was not inlined into handle". At the link, IPA-CP made
# secure_wipe.constprop.0 (the length 32 propagated), and in the stock build the
# WPA inliner put it into both callers, because that was estimated to grow
# nothing ("overall growth 0"; "Inlined 2 calls, eliminated 1 functions"); the
# dry run's executable was the stock one, byte for byte. The barrier adds one to
# the clone's estimated size (self size 12 -> 13), the growth became 1, and both
# calls were refused ("call is unlikely and code size would grow"), so the
# 32-byte fill stayed in the clone, called from handle and from wipe_kept. That
# cell could not show what it is for. The subject's expectations above are the
# ones first written; only the control's changed, with its design.
XTU_FILL_BYTES = 32
XTU_SITE = {"function": "secure_wipe", "index": 0, "lengthBytes": None, "destKind": "argument",
            "alreadyVolatile": False, "followedByUse": None, "line": 3}
XTU_RESOLUTION = [{"name": "secure_wipe", "resolution": "resolved", "exact": True, "linkage": "external"}]
XTU = {
    "xtu-nolto": {"form": "none", "mode": "stock", "inlined": False, "subject": "PRESENT", "sameAsStock": None},
    "xtu-lto-stock": {"form": "lto", "mode": "stock", "inlined": True, "subject": "ABSENT", "sameAsStock": None},
    "xtu-lto-pin": {"form": "lto", "mode": "pin", "inlined": True, "subject": "PRESENT", "sameAsStock": False,
                    "pinnedCount": 1, "wouldPinCount": 1, "dryRun": False, "lines": []},
    "xtu-lto-dry": {"form": "lto", "mode": "dry", "inlined": True, "subject": "ABSENT", "sameAsStock": True,
                    "pinnedCount": 0, "wouldPinCount": 1, "dryRun": True, "lines": [dry_line(1)]},
}
XTU_ORDER = ["xtu-nolto", "xtu-lto-stock", "xtu-lto-pin", "xtu-lto-dry"]

# The switch group (compiler/schema/wipe-pin.md sections 14.3-14.5): -O2, no
# -g, target handle, each shape four ways. Written before the first run of
# these cells, from what each is for:
#
# <id>-stock  no plugin. `stock` is the reading of the wipe in handle: ABSENT
#             means gcc-13 -O2 deleted it, which is what makes the cell able to
#             show a repair. (For chkvar this is the least certain prediction:
#             whether DSE deletes a __memset_chk whose length is not a constant
#             was not read anywhere before this run.)
# <id>-off    the plugin, no switch: the shape is counted in `counter`, the
#             block says enabled false and lists nothing, the plugin prints the
#             "nothing to pin" line with that count, pin-gcc.sh exits 4, and the
#             listing is the stock listing byte for byte.
# <id>-on     its switch =1: one site, `site`, done-count and would-count 1,
#             `counter` 0, no WipePinGcc line, pin-gcc.sh exits 0 (the repair is
#             the barrier; pinnedCount stays 0), the listing differs from stock
#             and the wipe reads PRESENT.
# <id>-dry    the switch and WPIN_DRY_RUN=1: the same site, done-count 0 and
#             would-count 1, the dry-run line, pin-gcc.sh exits 4, and the
#             listing is the stock listing byte for byte.
#
# zcopyhdr's form: `builtin` is predicted, by the analogy with memset, whose
# fortifying wrapper GCC keeps as BUILT_IN_MEMSET (README.md); not measured
# before this run. The zero-copy cells are read by the oracle and by
# zcopy_reading on `zeroSymbol` (D25: the repair keeps the copy, so the
# listing holds a load of vg_zeros and its store, which the oracle does not
# count as a zero store); either reading PRESENT makes the cell PRESENT, and
# the table shows both.
SWITCH_LINE = {"barrierCalls": dry_barrier_line, "zeroCopy": dry_zero_copy_line}
SWITCH_VAR = {"barrierCalls": "WPIN_BARRIER_CALLS", "zeroCopy": "WPIN_ZERO_COPY"}
SWITCH = {
    "bzero": {"module": "bzero.c", "switch": "barrierCalls", "counter": "bzeroCall", "stock": "ABSENT",
              "site": {"function": "handle", "callee": "bzero", "lengthBytes": 32, "line": 8}},
    "chkvar": {"module": "chkvar.c", "switch": "barrierCalls", "counter": "memsetChk", "stock": "ABSENT",
               "site": {"function": "handle", "callee": "__builtin___memset_chk", "lengthBytes": None, "line": 7}},
    "zcopyagg": {"module": "zcopy.c", "switch": "zeroCopy", "counter": "zeroGlobalCopy", "stock": "ABSENT",
                 "zeroSymbol": "vg_zeros",
                 "site": {"function": "handle", "form": "aggregate", "callee": None, "source": "vg_zeros",
                          "destKind": "alloca", "lengthBytes": 32, "line": 9}},
    "zcopyhdr": {"module": "zcopy.c", "switch": "zeroCopy", "counter": "zeroGlobalCopy", "stock": "ABSENT",
                 "zeroSymbol": "vg_zeros",
                 "site": {"function": "handle", "form": "builtin", "callee": "memcpy", "source": "vg_zeros",
                          "destKind": "alloca", "lengthBytes": 32, "line": 9}},
}
SWITCH_ORDER = ["bzero", "chkvar", "zcopyagg", "zcopyhdr"]
SWITCH_MODES = ("off", "on", "dry")


def switch_cell_expectation(shape, mode):
    """What the record, stderr, pin-gcc.sh and the listing of <shape>-<mode>
    must say (the table above)."""
    exp = SWITCH[shape]
    blk = exp["switch"]
    on = mode != "off"
    dry = mode == "dry"
    done, would = wpr.BLOCK_COUNTS[blk]
    block = {"enabled": on, "sites": [exp["site"]] if on else [], done: 0 if (dry or not on) else 1,
             would: 1 if on else 0}
    counts = {} if on else {exp["counter"]: 1}
    expect = dict(SWITCHES_OFF, **{blk: on})
    return {
        "expect": expect, "dryRun": dry, "block": blk, "blockValue": block,
        "unhandled": dict({k: 0 for k in UNHANDLED_ORDER}, **counts),
        "lines": ([nothing_line(exp["module"], unhandled_text(**counts))] if not on
                  else [SWITCH_LINE[blk](1)] if dry else []),
        "pinShRc": 0 if mode == "on" else 4, "repairCount": 1 if mode == "on" else 0,
        "sameAsStock": mode != "on", "wipe": "PRESENT" if mode == "on" else exp["stock"],
    }


# The buffer group (compiler/schema/wipe-pin.md section 14.6): -O2, no -g,
# target handle. Written before the first run of these cells, from what the
# landed switch is for and from the prototype's measured records (lab notes
# kept outside this repository):
#
# loopbar-stock  no plugin: gcc-13 -O2 deletes the loop of zero stores in
#                handle (ABSENT); the control wipe_kept, whose zeroed buffer
#                use() reads, is PRESENT.
# loopbar-off    no switch: nothing in scope to pin or count (the loop is not a
#                call), so "nothing to pin" with every counter 0, the block
#                says enabled false, pin-gcc.sh exits 4, the listing is stock's.
# loopbar-on     WPIN_BUFFER_BARRIER=1: one barrier before key's clobber, the
#                site BUFFER_SITE, count 1, no WipePinGcc line, pin-gcc.sh 0
#                (repairCount 1 with pinnedCount 0), the listing differs from
#                stock's, the wipe in handle PRESENT, and wipe_kept's body the
#                same as in the stock listing (labels renumbered in order of
#                appearance first: GCC numbers .L labels across the file).
# loopbar-dry    the switch and WPIN_DRY_RUN=1: the same site, count 0, the
#                dry-run line, pin-gcc.sh 4, the listing is stock's.
# initbar-on     `= {0}` and uses, no wipe, WPIN_BUFFER_BARRIER=1: GCC's
#                `key = {}` is not a zero fill the barrier counts, so the block
#                is enabled with count 0 and no site, "nothing to pin",
#                pin-gcc.sh 4, the listing is stock's. (On clang `= {0}` is an
#                llvm.memset, a zero fill the barrier does read.)
#
# Added with the rule that a buffer whose every zero fill is followed by a
# later use gets no barrier (an initialiser, not a wipe), and that the walk for
# that use stops at the buffer's own clobber:
#
# inloop-stock   no plugin: a buffer declared in a loop body and wiped by a loop
#                of zero stores in every iteration; gcc-13 -O2 deletes the wipe
#                (ABSENT), the control wipe_kept is PRESENT.
# inloop-on      WPIN_BUFFER_BARRIER=1: one barrier before key's clobber (the
#                end of the loop body), the site BUFFER_SITE, count 1, and no
#                WipePinGcc line at all -- in particular not the initialiser-like
#                one: the next iteration's uses are after the clobber, in
#                another lifetime. pin-gcc.sh 0, the wipe PRESENT, wipe_kept's
#                body the stock listing's.
# initzero-on    a loop of zero stores as an initialiser, then uses, no wipe:
#                the fill is read, every fill has a later use, so no barrier:
#                count 0 and no site, the not-barriered line for 1 buffer and
#                "nothing to pin", pin-gcc.sh 4, the listing is stock's.
BUFFER_SITE = {"function": "handle", "buffer": "key", "bytes": 32, "reason": "loop-store", "anchor": "clobber"}
BUFFER = {
    "loopbar": {"module": "loop.c", "modes": ("off", "on", "dry"), "stock": "ABSENT", "control": "wipe_kept",
                "site": BUFFER_SITE, "notBarriered": 0},
    "initbar": {"module": "init.c", "modes": ("on",), "stock": None, "control": None, "site": None,
                "notBarriered": 0},
    "inloop": {"module": "inloop.c", "modes": ("on",), "stock": "ABSENT", "control": "wipe_kept",
               "site": BUFFER_SITE, "notBarriered": 0},
    "initzero": {"module": "initzero.c", "modes": ("on",), "stock": None, "control": None, "site": None,
                 "notBarriered": 1},
}
BUFFER_ORDER = ["loopbar", "initbar", "inloop", "initzero"]


def buffer_cell_expectation(shape, mode):
    """What the record, stderr, pin-gcc.sh and the listing of <shape>-<mode>
    must say (the table above)."""
    exp = BUFFER[shape]
    on = mode != "off"
    dry = mode == "dry"
    sites = [exp["site"]] if (on and exp["site"]) else []
    placed = 1 if (mode == "on" and sites) else 0
    if not on:
        lines = [nothing_line(exp["module"])]
    elif not sites:
        lines = [nothing_line(exp["module"])]
    elif dry:
        lines = [dry_buffer_line(len(sites))]
    else:
        lines = []
    if on and exp["notBarriered"]:
        lines = [not_barriered_line(exp["notBarriered"])] + lines
    return {
        "expect": dict(SWITCHES_OFF, bufferBarriers=on), "dryRun": dry,
        "blockValue": {"enabled": on, "count": placed, "sites": sites},
        "lines": lines, "pinShRc": 0 if placed else 4, "repairCount": placed,
        "sameAsStock": not placed, "wipe": ("PRESENT" if placed else exp["stock"]) if exp["stock"] else None,
        "controlSame": bool(placed and exp["control"]),
    }


def canonical_labels(lines):
    """`.L<n>` labels renumbered in order of appearance (GCC numbers them
    across the whole file, so a body after a changed one can differ only in
    its label numbers)."""
    seen = {}
    out = []
    for line in lines:
        out.append(re.sub(r"\.L(\d+)\b", lambda m: ".Lc%d" % seen.setdefault(m.group(0), len(seen)), line))
    return out


# The previous group: every plugin compile of the loop (pin, dry, wrongname,
# nothing at each level), of the shapes, of the switch-off cells and of the
# buffer group's off cell, -S with this plugin and with the previous one at the
# same staged path, all switches off. Each pair must be the same bytes: with
# the switches off the v3 plugin changes GIMPLE exactly as the plugin it
# replaces (wipe-pin.md section 14.1).
def previous_ids():
    return ([f"{k}{o}" for o in LEVELS for k in ("pin", "dry", "wrongname", "nothing")] +
            [f"shape-{s}" for s in SHAPE_ORDER] + [f"switch-{s}-off" for s in SWITCH_ORDER] +
            ["buffer-loopbar-off"])


class Incomplete(Exception):
    pass


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise Incomplete(f"{os.path.basename(path)}: {e.__class__.__name__}")


def load_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().split("\n")
    except OSError as e:
        raise Incomplete(f"{os.path.basename(path)}: {e.__class__.__name__}")


def load_kv(path):
    out = {}
    for line in load_lines(path):
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def sha_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def plugin_lines(lines):
    return [l for l in lines if l.startswith("WipePinGcc:")]


def lines_problems(got, want):
    """`want` must all be there, and nothing else from the plugin."""
    bad = [f"stderr lacks {w!r}" for w in want if w not in got]
    extra = [l for l in got if l not in want]
    if extra:
        bad.append(f"unexpected WipePinGcc lines {extra}")
    return bad


def host_problems(rec):
    """Predicted: the version check makes the running compiler's basever the
    plugin's own, so host.ident repeats toolchain.gcc."""
    if rec["host"]["ident"] != rec["toolchain"]["gcc"]:
        return [f"record host.ident {rec['host']['ident']!r} is not toolchain.gcc {rec['toolchain']['gcc']!r}"]
    return []


def record_problems(rec, exp, module):
    """What a loop cell's record must say, beyond the v3 shape. Every loop cell
    runs with the three switches off."""
    bad = [f"record: {p}" for p in wpr.validate(rec, SWITCHES_OFF)]
    if bad:
        return bad
    bad += host_problems(rec)
    res = rec["resolution"]
    r0 = res[0] if len(res) == 1 else {}
    checks = [
        ("module", rec["module"], module),
        ("scope", rec["scope"], exp["scope"]),
        ("requested", rec["requested"], exp["requested"]),
        ("resolution", r0.get("resolution") if res else None, exp["resolution"]),
        ("exact", r0.get("exact"), exp["exact"]),
        ("linkage", r0.get("linkage"), exp["linkage"]),
        ("pinnedCount", rec["pinnedCount"], exp["pinnedCount"]),
        ("wouldPinCount", rec["wouldPinCount"], exp["wouldPinCount"]),
        ("dryRun", rec["dryRun"], exp["dryRun"]),
        ("optLevel", (rec["optLevel"]["speedup"], rec["optLevel"]["size"]), OPT_LEVELS[exp["opt"]]),
        ("followedByUse per site", [s["followedByUse"] for s in rec["pinned"]], exp["sites"]),
    ]
    for name, got, want in checks:
        if got != want:
            bad.append(f"record {name} = {got!r}, expected {want!r}")
    for s in rec["pinned"]:
        if s["function"] != "handle_request" or s["destKind"] != "alloca" or s["lengthBytes"] != 32 \
                or s["alreadyVolatile"] is not False or s["line"] is None:
            bad.append(f"record pinned an unexpected site {s}")
    return bad


def read_listings(lab, subject="handle_request", control="wipe_kept", subdir="asm"):
    script = os.path.join(HERE, "lib", "asm-presence.mjs")
    argv = ["node", script, "--lab", lab, "--subject", subject, "--dir", subdir]
    if control:
        argv += ["--control", control]
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Incomplete(f"node could not read the listings: {e.__class__.__name__}")
    if out.returncode != 0:
        raise Incomplete(f"asm-presence.mjs exited {out.returncode}: {out.stderr.strip()[:300]}")
    try:
        return json.loads(out.stdout)["cells"]
    except (ValueError, KeyError):
        raise Incomplete("asm-presence.mjs printed something that is not its JSON")


def grade_loop(lab, listings):
    rows, problems, incomplete = [], [], []
    for cell in ORDER:
        exp = EXPECT[cell]
        o = exp["opt"]
        try:
            kv = load_kv(os.path.join(lab, "cells", cell + ".kv"))
            if cell not in listings:
                raise Incomplete(f"no listing asm/{cell}.s")
            lst = listings[cell]
            rec_s = rec_c = man = None
            lines_s = lines_c = []
            if exp["kind"] != "base":
                rec_s = load_json(os.path.join(lab, "records", cell + ".s.json"))
                rec_c = load_json(os.path.join(lab, "pinsh", cell + ".json"))
                man = load_kv(os.path.join(lab, "pinsh", cell + ".manifest.kv"))
                lines_s = plugin_lines(load_lines(os.path.join(lab, "stderr", cell + ".s.txt")))
                lines_c = plugin_lines(load_lines(os.path.join(lab, "pinsh", cell + ".stderr.txt")))
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue

        bad = []
        is_target = exp["kind"] != "nothing"
        subj, ctl = lst["subject"], lst["control"]
        if is_target:
            if subj["verdict"] != exp["subject"]:
                bad.append(f"subject {subj['verdict']} (via {subj['via']}), expected {exp['subject']}")
            if ctl["verdict"] != "PRESENT":
                bad.append(f"control {ctl['verdict']}: the oracle is blind in this listing")

        base_id = ("nothing-base" if exp["kind"] == "nothing" else "base") + o
        base_obj = sha_file(os.path.join(lab, "obj", base_id + ".o"))
        this_obj = sha_file(os.path.join(lab, "obj", cell + ".o"))
        same_obj = None if base_obj is None or this_obj is None else base_obj == this_obj
        same_asm = None
        if exp["kind"] != "base":
            if base_id not in listings:
                bad.append(f"no listing for {base_id}")
            else:
                same_asm = listings[base_id]["sha256"] == lst["sha256"]
            if same_obj is None:
                bad.append("an object file is missing")
            elif exp["sameAsBase"] is True and not (same_obj and same_asm):
                bad.append(f"loaded and changing nothing, yet the output differs from {base_id} "
                           f"(object {'same' if same_obj else 'DIFFERENT'}, listing {'same' if same_asm else 'DIFFERENT'})")
            elif exp["sameAsBase"] is False and same_obj:
                bad.append(f"pinned, yet the object is byte-identical to {base_id}")

            module = "opaque.c" if exp["kind"] == "nothing" else "target.c"
            bad += record_problems(rec_s, exp, module)
            if rec_s.get("evidenceDigest") != rec_c.get("evidenceDigest"):
                bad.append("the -S record and the pin-gcc.sh -c record differ")
            bad += [f"-S {p}" for p in lines_problems(lines_s, exp["lines"])]
            bad += [f"-c {p}" for p in lines_problems(lines_c, exp["lines"])]
            if kv.get("pinShRc") != str(exp["pinShRc"]):
                bad.append(f"pin-gcc.sh exited {kv.get('pinShRc')}, expected {exp['pinShRc']}")
            if man.get("status") != str(exp["pinShRc"]) or man.get("rc") != "0":
                bad.append(f"pin-gcc.sh manifest status={man.get('status')} rc={man.get('rc')}")
            if man.get("pinnedCount") != str(exp["pinnedCount"]):
                bad.append(f"pin-gcc.sh manifest pinnedCount={man.get('pinnedCount')}")
            # With the switches off the repair count of section 14.8 is
            # pinnedCount: the other three counts are 0.
            if man.get("repairCount") != str(exp["pinnedCount"]):
                bad.append(f"pin-gcc.sh manifest repairCount={man.get('repairCount')}, "
                           f"expected {exp['pinnedCount']}")
            if man.get("followedByUseCount") != "0":
                bad.append(f"pin-gcc.sh manifest followedByUseCount={man.get('followedByUseCount')}")
            want_unres = exp["requested"][0] if exp["resolution"] == "not-in-module" else ""
            if man.get("unresolved") != want_unres:
                bad.append(f"pin-gcc.sh manifest unresolved={man.get('unresolved')!r}, expected {want_unres!r}")

        recsum = "-"
        if rec_s is not None:
            res = rec_s.get("resolution") or []
            word = res[0]["resolution"] if len(res) == 1 else ("module" if not res else f"{len(res)} names")
            recsum = (f"{rec_s.get('pinnedCount')}/{rec_s.get('wouldPinCount')}/"
                      f"{'dry' if rec_s.get('dryRun') else 'live'}/{word}")
        fbu = ",".join(str(s.get("followedByUse")).lower() for s in (rec_s or {}).get("pinned") or []) or "-"
        rows.append((cell, o, exp["kind"],
                     subj["verdict"] if is_target else "-", (subj["via"] or "-") if is_target else "-",
                     ctl["verdict"] + ("" if ctl["via"] in (None, "oracle") else f" ({ctl['via']})") if is_target else "-",
                     "-" if exp["kind"] == "base" else ("yes" if same_obj else "no"),
                     "-" if exp["kind"] == "base" else ("yes" if same_asm else "no"),
                     recsum, fbu, kv.get("pinShRc") if exp["kind"] != "base" else "-",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_alone(lab):
    rows, problems, incomplete = [], [], []
    for cell in ALONE_ORDER:
        exp = ALONE[cell]
        try:
            kv = load_kv(os.path.join(lab, "alone", cell + ".kv"))
            man = load_kv(os.path.join(lab, "alone", cell + ".manifest.kv"))
            lines = plugin_lines(load_lines(os.path.join(lab, "alone", cell + ".stderr.txt")))
            console = load_lines(os.path.join(lab, "alone", cell + ".console.txt"))
            rec = load_json(os.path.join(lab, "alone", cell + ".json")) if exp["record"] else None
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue
        bad = []
        if kv.get("pinShRc") != str(exp["pinShRc"]):
            bad.append(f"pin-gcc.sh exited {kv.get('pinShRc')}, expected {exp['pinShRc']}")
        if man.get("rc") != "0":
            bad.append(f"compiler rc {man.get('rc')}, expected 0")
        on_disk = os.path.exists(os.path.join(lab, "alone", cell + ".json"))
        if not exp["record"]:
            if man.get("record") != "" or on_disk:
                bad.append("a record exists")
            if not any("no WipePinGcc record was written" in l for l in console):
                bad.append("pin-gcc.sh did not say that no record was written")
        else:
            bad += [f"record: {p}" for p in wpr.validate(rec, SWITCHES_OFF)]
            if rec.get("module") != exp["module"]:
                bad.append(f"record module {rec.get('module')!r}, expected {exp['module']!r}")
            if man.get("sourceOperands") != exp["sourceOperands"]:
                bad.append(f"manifest sourceOperands={man.get('sourceOperands')}")
            if not any("source operand(s) on this line" in l for l in console):
                bad.append("pin-gcc.sh did not warn about the source operands")
        bad += lines_problems(lines, exp["lines"])
        rows.append((cell, kv.get("pinShRc"), man.get("rc"), man.get("record") or "-",
                     (rec or {}).get("module", "-"), "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_shapes(lab, listings):
    """`listings`: the oracle's reading of <lab>/shapes/*.s for `handle`."""
    rows, problems, incomplete = [], [], []
    for cell in SHAPE_ORDER:
        exp = SHAPES[cell]
        try:
            kv = load_kv(os.path.join(lab, "shapes", cell + ".kv"))
            man = load_kv(os.path.join(lab, "shapes", cell + ".manifest.kv"))
            lines = plugin_lines(load_lines(os.path.join(lab, "shapes", cell + ".stderr.txt")))
            rec = load_json(os.path.join(lab, "shapes", cell + ".json"))
            store = "-"
            if "store" in exp:
                for lid in (cell, cell + "-stock"):
                    if lid not in listings:
                        raise Incomplete(f"no listing shapes/{lid}.s")
                store = (listings[cell]["subject"]["verdict"], listings[cell + "-stock"]["subject"]["verdict"])
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue
        bad = [f"record: {p}" for p in wpr.validate(rec, SWITCHES_OFF)]
        if not bad:
            bad += host_problems(rec)
        sites = rec.get("pinned") or []
        got_fbu = [s.get("followedByUse") for s in sites]
        res = rec.get("resolution") or []
        r0 = res[0] if len(res) == 1 else {}
        followed = sum(1 for v in exp["sites"] if v is True)
        want_volatile = exp.get("volatile", [False] * len(exp["sites"]))
        want_pinned = exp.get("pinned", len(exp["sites"]))
        want_exact = exp.get("exact", True)
        checks = [
            ("module", rec.get("module"), exp["module"]),
            ("requested", rec.get("requested"), [exp["target"]]),
            ("resolution", r0.get("resolution"), "resolved"),
            ("exact", r0.get("exact"), want_exact),
            ("linkage", r0.get("linkage"), exp.get("linkage", "external")),
            ("pinnedCount", rec.get("pinnedCount"), want_pinned),
            ("followedByUse per site", got_fbu, exp["sites"]),
            ("alreadyVolatile per site", [s.get("alreadyVolatile") for s in sites], want_volatile),
            ("pin-gcc.sh rc", kv.get("pinShRc"), str(exp["pinShRc"])),
            ("manifest status", man.get("status"), str(exp["pinShRc"])),
            ("manifest followedByUseCount", man.get("followedByUseCount"), str(followed)),
            ("manifest unresolved", man.get("unresolved"), ""),
            ("manifest exactAll", man.get("exactAll"), "true" if want_exact else "false"),
        ]
        if "opt" in exp:
            checks.append(("optLevel", ((rec.get("optLevel") or {}).get("speedup"),
                                        (rec.get("optLevel") or {}).get("size")), OPT_LEVELS[exp["opt"]]))
        for k, v in exp.get("unhandled", {}).items():
            checks.append((f"unhandled.{k}", (rec.get("unhandled") or {}).get(k), v))
        if "store" in exp:
            checks.append(("zero store in the listing with the plugin", store[0], exp["store"][0]))
            checks.append(("zero store in the stock listing", store[1], exp["store"][1]))
        for name, got, want in checks:
            if got != want:
                bad.append(f"{name} = {got!r}, expected {want!r}")
        for s in sites:
            if s.get("function") != exp["target"] or s.get("destKind") != "alloca" \
                    or s.get("lengthBytes") != exp.get("length", 32) or s.get("line") is None:
                bad.append(f"unexpected site {s}")
        bad += lines_problems(lines, exp["lines"])
        rows.append((cell, kv.get("pinShRc"), str(rec.get("pinnedCount")),
                     ",".join(str(v).lower() for v in got_fbu) or "-",
                     ",".join(str(s.get("alreadyVolatile")).lower() for s in sites) or "-",
                     ",".join(str(s.get("line")) for s in sites) or "-",
                     f"{r0.get('exact')}/{r0.get('linkage')}",
                     "yes" if any(l.startswith("WipePinGcc: partial:") for l in lines) else "no",
                     "yes" if any(l.startswith("WipePinGcc: nothing to pin") for l in lines) else "no",
                     "/".join(store) if store != "-" else "-",
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
            lines = plugin_lines(load_lines(os.path.join(lab, "stale", cell + ".stderr.txt")))
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue
        bad = []
        if kv.get("before") != exp["before"]:
            bad.append(f"started with {kv.get('before')}, expected {exp['before']}")
        if kv.get("rc") != "0":
            bad.append(f"compiler rc {kv.get('rc')}, expected 0")
        # Read from the disk, not only from what the runner wrote down.
        on_disk = "dir" if os.path.isdir(out) else ("file" if os.path.isfile(out) else "absent")
        if kv.get("after") != exp["after"] or on_disk != exp["after"]:
            bad.append(f"WPIN_OUT after the compile: {kv.get('after')} (runner), {on_disk} (now), "
                       f"expected {exp['after']}")
        bad += lines_problems(lines, exp["lines"])
        if cell == "stale-live":
            try:
                rec = load_json(out)
            except Incomplete as e:
                rec = None
                bad.append(f"the compile's record is not JSON: {e}")
            if rec is not None:
                bad += [f"record: {p}" for p in wpr.validate(rec, SWITCHES_OFF)]
                if rec.get("module") != "trailing.c" or rec.get("pinnedCount") != 1:
                    bad.append(f"record module={rec.get('module')} pinnedCount={rec.get('pinnedCount')}")
        if cell == "stale-dir" and not os.path.isfile(os.path.join(out, "keep.txt")):
            bad.append("the directory at WPIN_OUT lost its contents")
        rows.append((cell, kv.get("before"), kv.get("rc"), on_disk, lines[0] if lines else "-",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_lto(lab):
    """The trailing shape through -flto. Each cell is graded from what the
    compiles left on disk: records, stderr, file states and objdump output."""
    rows, problems, incomplete = [], [], []
    d = os.path.join(lab, "lto")
    try:
        kc = load_kv(os.path.join(d, "lto-compile.kv"))
        kl = load_kv(os.path.join(d, "lto-linkline.kv"))
        ks = load_kv(os.path.join(d, "lto-stock.kv"))
        compile_lines = plugin_lines(load_lines(os.path.join(d, "compile.stderr.txt")))
        link_lines = plugin_lines(load_lines(os.path.join(d, "linkline.stderr.txt")))
        dumps = {}
        for so in ("stock-pinned", "stock-unpinned"):
            with open(os.path.join(d, so + ".objdump.txt"), encoding="utf-8", errors="replace") as f:
                dumps[so] = f.read()
    except (Incomplete, OSError) as e:
        incomplete.append(f"lto: {e.__class__.__name__ if isinstance(e, OSError) else e}")
        return rows, problems, incomplete

    # lto-compile: rc 0, a record written, nothing on stderr from the plugin.
    bad = []
    rec = None
    if kc.get("rc") != "0" or kc.get("unpinnedRc") != "0":
        bad.append(f"compile rc {kc.get('rc')}, unpinned compile rc {kc.get('unpinnedRc')}, expected 0 and 0")
    if kc.get("wpinOutAfter") != "file":
        bad.append(f"WPIN_OUT after the -flto compile: {kc.get('wpinOutAfter')}, expected a record")
    else:
        try:
            rec = load_json(os.path.join(d, "compile-record.json"))
        except Incomplete as e:
            bad.append(f"the compile's record: {e}")
    if rec is not None:
        bad += [f"record: {p}" for p in wpr.validate(rec, SWITCHES_OFF)]
        want = {"module": "trailing.c", "pinnedCount": 1, "scope": "functions", "requested": ["handle"]}
        for k, v in want.items():
            if rec.get(k) != v:
                bad.append(f"record {k} = {rec.get(k)!r}, expected {v!r}")
        if [s.get("followedByUse") for s in rec.get("pinned") or []] != [False]:
            bad.append(f"record sites {rec.get('pinned')}")
    bad += lines_problems(compile_lines, [])
    rows.append(("lto-compile", kc.get("rc"), "-",
                 f"{rec.get('schemaVersion')}/{rec.get('pinnedCount')}" if rec else "-",
                 "-", kc.get("wpinOutAfter"), "-", "-", "ok" if not bad else "DISAGREES"))
    problems += [f"lto-compile: {b}" for b in bad]

    # lto-linkline: the plugin on an -flto link line, same WPIN_OUT.
    bad = []
    if kl.get("rc") != "0":
        bad.append(f"link rc {kl.get('rc')}, expected 0")
    if kl.get("wpinOutBefore") != "file":
        bad.append(f"WPIN_OUT before the link: {kl.get('wpinOutBefore')}, expected the compile's record")
    on_disk = os.path.exists(os.path.join(d, "wpin-out.json"))
    if kl.get("wpinOutAfter") != "absent" or on_disk:
        bad.append(f"WPIN_OUT after the link: {kl.get('wpinOutAfter')} (runner), "
                   f"{'present' if on_disk else 'absent'} (now), expected absent")
    refusals = sum(1 for l in link_lines if l == LTO_REFUSAL)
    if refusals != LTO_REFUSALS:
        bad.append(f"the LTO refusal printed {refusals} time(s), expected {LTO_REFUSALS}")
    extra = [l for l in link_lines if l != LTO_REFUSAL]
    if extra:
        bad.append(f"unexpected WipePinGcc lines {extra}")
    same = sha_file(os.path.join(d, "linkline.so"))
    stock = sha_file(os.path.join(d, "stock-pinned.so"))
    same_as_stock = same is not None and same == stock
    if not same_as_stock:
        bad.append("the link with the refused plugin is not byte-identical to the stock link of the same object")
    rows.append(("lto-linkline", kl.get("rc"), str(refusals), "-", kl.get("wpinOutBefore"),
                 kl.get("wpinOutAfter"), "yes" if same_as_stock else "no", "-",
                 "ok" if not bad else "DISAGREES"))
    problems += [f"lto-linkline: {b}" for b in bad]

    # lto-stock: stock links; the zero fill read from the linked code.
    bad = []
    if ks.get("pinnedRc") != "0" or ks.get("unpinnedRc") != "0":
        bad.append(f"stock link rc {ks.get('pinnedRc')}/{ks.get('unpinnedRc')}, expected 0/0")
    zp = objdump_zero_stores(dumps["stock-pinned"], "handle")
    zu = objdump_zero_stores(dumps["stock-unpinned"], "handle")
    if zp is None or zu is None:
        bad.append("handle is not in the objdump output of both links")
    else:
        if zp["bytes"] != LTO_FILL_BYTES and zp["calls"] == 0:
            bad.append(f"pinned object, stock -flto link: {zp['bytes']} zero bytes stored in handle, "
                       f"expected {LTO_FILL_BYTES} (the whole buffer) or a memset call")
        if zu["stores"] != 0 or zu["calls"] != 0:
            bad.append(f"unpinned object, stock -flto link: the zero fill is still there ({zu['lines']}); "
                       "the cell cannot show the pin surviving the link")
    fmt = (lambda z: "-" if z is None else f"{z['stores']} store(s)/{z['bytes']}B/{z['calls']} call(s)")
    rows.append(("lto-stock", f"{ks.get('pinnedRc')}/{ks.get('unpinnedRc')}", "-", "-", "-", "-", "-",
                 f"pinned {fmt(zp)}; unpinned {fmt(zu)}", "ok" if not bad else "DISAGREES"))
    problems += [f"lto-stock: {b}" for b in bad]
    return rows, problems, incomplete


def xtu_record_problems(rec, exp):
    """What the record of an xtu cell's wipe.c compile must say."""
    bad = [f"record: {p}" for p in wpr.validate(rec, SWITCHES_OFF)]
    if bad:
        return bad
    checks = [
        ("module", rec["module"], "wipe.c"),
        ("scope", rec["scope"], "functions"),
        ("requested", rec["requested"], ["secure_wipe"]),
        ("resolution", rec["resolution"], XTU_RESOLUTION),
        ("dryRun", rec["dryRun"], exp["dryRun"]),
        ("pinnedCount", rec["pinnedCount"], exp["pinnedCount"]),
        ("wouldPinCount", rec["wouldPinCount"], exp["wouldPinCount"]),
        ("optLevel", (rec["optLevel"]["speedup"], rec["optLevel"]["size"]), OPT_LEVELS["-O2"]),
        ("pinned", rec["pinned"], [XTU_SITE]),
    ]
    for name, got, want in checks:
        if got != want:
            bad.append(f"record {name} = {got!r}, expected {want!r}")
    return bad


XTU_RCS = ("mainRc", "useRc", "wipeRc", "ioRc", "linkRc")


def grade_xtu(lab):
    """The xtu cells, graded from what the compiles and the link left on disk
    and from the linked executable itself, disassembled here."""
    rows, problems, incomplete = [], [], []
    d = os.path.join(lab, "xtu")
    for cell in XTU_ORDER:
        exp = XTU[cell]
        cd = os.path.join(d, cell)
        try:
            kv = load_kv(os.path.join(d, cell + ".kv"))
            werr = plugin_lines(load_lines(os.path.join(cd, "wipe.stderr.txt")))
            lerr = plugin_lines(load_lines(os.path.join(cd, "link.stderr.txt")))
            rec = load_json(os.path.join(cd, "wipe.record.json")) if exp["mode"] != "stock" else None
            if not os.path.isfile(os.path.join(cd, "prog")):
                raise Incomplete(f"xtu/{cell}/prog: no executable")
            try:
                text = objdump_fill.disassemble(os.path.join(cd, "prog"))
            except RuntimeError as e:
                raise Incomplete(f"xtu/{cell}/prog: {e}")
        except Incomplete as e:
            incomplete.append(f"{cell}: {e}")
            continue

        bad = []
        if kv.get("form") != exp["form"] or kv.get("mode") != exp["mode"]:
            bad.append(f"runner ran form={kv.get('form')} mode={kv.get('mode')}")
        rcs = [f"{k}={kv.get(k)}" for k in XTU_RCS if kv.get(k) != "0"]
        if rcs:
            bad.append(f"a step failed: {' '.join(rcs)}")

        # A non-LTO build must not pass as an LTO one, and the producer and
        # consumer must stay out of every link's sight.
        kinds = {u: objdump_fill.object_kind(os.path.join(cd, u + ".o")) for u in ("main", "use", "wipe", "io")}
        want_kind = "elf" if exp["form"] == "none" else "gcc-lto"
        for u in ("main", "use", "wipe"):
            if kinds[u] != want_kind:
                bad.append(f"{u}.o is {kinds[u]}, expected {want_kind}")
        if kinds["io"] != "elf":
            bad.append(f"io.o is {kinds['io']}, expected elf: derive and use must be opaque to the link")

        bad += [f"wipe.c compile: {p}" for p in lines_problems(werr, exp.get("lines", []))]
        if lerr:
            bad.append(f"the link printed {lerr}; no link here loads the plugin")
        if rec is not None:
            bad += xtu_record_problems(rec, exp)
        elif kv.get("record") != "not-loaded":
            bad.append(f"record={kv.get('record')} in a cell that does not load the plugin")

        subj = objdump_fill.wipe_reading(text, "handle", "secure_wipe", XTU_FILL_BYTES)
        ctl = objdump_fill.wipe_reading(text, "wipe_kept", None, XTU_FILL_BYTES)
        bad += objdump_fill.reading_problems(subj, ctl, exp["inlined"], exp["subject"], "handle", "secure_wipe")

        same = "-"
        if exp["sameAsStock"] is not None:
            stock = f"xtu-{exp['form']}-stock"
            s_stock = sha_file(os.path.join(d, stock, "prog"))
            s_this = sha_file(os.path.join(cd, "prog"))
            same = "?" if s_stock is None or s_this is None else ("yes" if s_stock == s_this else "no")
            if same == "?":
                bad.append(f"no executable of {stock} to compare with")
            elif exp["sameAsStock"] and same != "yes":
                bad.append(f"told to change nothing, yet the executable differs from {stock}'s")
            elif not exp["sameAsStock"] and same == "yes":
                bad.append(f"pinned, yet the executable is byte-identical to {stock}'s")

        recsum = "-" if rec is None else (f"{rec.get('schemaVersion')}/{rec.get('pinnedCount')}/"
                                          f"{rec.get('wouldPinCount')}/{'dry' if rec.get('dryRun') else 'live'}")
        objs = "/".join(sorted({kinds[u] or "?" for u in ("main", "use", "wipe")})) + f" (io.o {kinds['io']})"
        rows.append((cell, exp["form"], exp["mode"], "0" if not rcs else "NO", objs, recsum,
                     "-" if subj["inlined"] is None else ("yes" if subj["inlined"] else "no"),
                     objdump_fill.describe(subj), objdump_fill.describe(ctl), same,
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def checks_can_fail(lab):
    """A check that cannot fail checks nothing: alter a real record and confirm
    the reader notices, and that moving `context` alone does not."""
    rec = load_json(os.path.join(lab, "records", "pin-O2.s.json"))
    if wpr.validate(rec):
        return False
    tampered = copy.deepcopy(rec)
    tampered["pinnedCount"] += 1
    flipped = copy.deepcopy(rec)
    for s in flipped["pinned"]:
        s["followedByUse"] = not s["followedByUse"]
    toolchain = copy.deepcopy(rec)
    toolchain["toolchain"]["gcc"] = "13.2.0"
    toolchain["toolchain"]["packages"][0]["version"] = "13.2.0"
    toolchain["evidenceDigest"] = wpr.evidence_digest(toolchain)
    moved_context = copy.deepcopy(rec)
    moved_context["context"]["generatedAt"] = 0
    # v3: a switch the record says was on although the cell set none (sealed
    # again, so only the caller's expectation can refuse it), and a host whose
    # major is not the plugin's.
    switched = copy.deepcopy(rec)
    switched["barrierCalls"]["enabled"] = True
    switched["evidenceDigest"] = wpr.evidence_digest(switched)
    host = copy.deepcopy(rec)
    host["host"]["ident"], host["host"]["identMajor"] = "14.2.0", 14
    host["evidenceDigest"] = wpr.evidence_digest(host)
    return bool(wpr.validate(tampered)) and bool(wpr.validate(flipped)) and \
        bool(wpr.validate(toolchain)) and not wpr.validate(moved_context) and \
        not wpr.validate(switched) and bool(wpr.validate(switched, SWITCHES_OFF)) and \
        bool(wpr.validate(host))


# ------------------------------------------------------------------ zcopy --
# The repair of a copy from an all-zero constant keeps the copy (a barrier
# after it), so what reaches the listing is a load from the constant and a
# store of that register, or a call of memcpy with the constant's address:
# not a zero store, which is all the oracle counts (the copy reading of the lab
# notes kept outside this repository reads the same three forms). Read from
# the -S listing of
# one function, between its label and its `.size`.
_ZFAMILY = {"eax": "a", "rax": "a", "ax": "a", "al": "a", "ebx": "b", "rbx": "b", "bx": "b", "bl": "b",
            "ecx": "c", "rcx": "c", "cx": "c", "cl": "c", "edx": "d", "rdx": "d", "dx": "d", "dl": "d",
            "esi": "si", "rsi": "si", "sil": "si", "edi": "di", "rdi": "di", "dil": "di"}


def _zfamily(reg):
    if re.fullmatch(r"[xyz]mm\d+", reg):
        return "x" + reg[1:]
    return _ZFAMILY.get(reg, re.sub(r"^(r\d+)[dwb]?$", r"\1", reg))


def asm_body(text, fn):
    """The lines of `fn` in a gcc -S listing, from its label to its `.size`;
    None when the listing has no such function."""
    lines = text.split("\n")
    label = re.compile(rf"^{re.escape(fn)}:\s*$")
    size = re.compile(rf"^\s*\.size\s+{re.escape(fn)}\s*,")
    for i, l in enumerate(lines):
        if label.match(l):
            body = []
            for m in lines[i + 1:]:
                if size.match(m):
                    return body
                body.append(m)
            return body
    return None


def zcopy_reading(text, fn, sym):
    """{loads, stores, calls} of a copy from `sym` in `fn`, or None when `fn`
    is not in the listing. stores: a mov of a register that was loaded from
    `sym` to memory; calls: a call or tail call of memcpy / __memcpy_chk in a
    body that takes `sym`'s address."""
    body = asm_body(text, fn)
    if body is None:
        return None
    s = re.escape(sym)
    load = re.compile(rf"^\s*v?mov[a-z0-9]*\s+(?:\d+\+)?{s}(?:\+\d+)?\(%rip\),\s*%([a-z0-9]+)\s*$")
    lea = re.compile(rf"^\s*leaq?\s+(?:\d+\+)?{s}(?:\+\d+)?\(%rip\),\s*%[a-z0-9]+\s*$")
    store = re.compile(r"^\s*v?mov[a-z0-9]*\s+%([a-z0-9]+),\s*[^,]*\(%[a-z0-9]+[^)]*\)\s*$")
    call = re.compile(r"^\s*(?:call|jmp)q?\s+(?:memcpy|__memcpy_chk)(?:@PLT)?\s*$")
    loaded, n, addressed = set(), {"loads": 0, "stores": 0, "calls": 0}, False
    for l in body:
        m = load.match(l)
        if m:
            loaded.add(_zfamily(m.group(1)))
            n["loads"] += 1
            continue
        if lea.match(l):
            addressed = True
            continue
        m = store.match(l)
        if m and _zfamily(m.group(1)) in loaded:
            n["stores"] += 1
            continue
        if addressed and call.match(l):
            n["calls"] += 1
    return n


def wipe_reading(listing, text, sym):
    """PRESENT / ABSENT / NOT_OBSERVED for `handle` in one switch-group
    listing: the oracle's reading, or, for a zero-copy cell (`sym` given),
    PRESENT also when zcopy_reading finds a store or a call."""
    oracle = listing["subject"]["verdict"]
    if sym is None:
        return oracle, listing["subject"]["via"] or "-", None
    z = zcopy_reading(text, "handle", sym)
    if z is None:
        return "NOT_OBSERVED", "-", None
    if oracle == "PRESENT":
        return "PRESENT", listing["subject"]["via"] or "oracle", z
    if z["stores"] + z["calls"] > 0:
        return "PRESENT", "zcopy", z
    return oracle, listing["subject"]["via"] or "-", z


def grade_switch(lab, listings):
    """The switch group: `listings` is the oracle's reading of
    <lab>/switch/*.s for `handle`."""
    rows, problems, incomplete = [], [], []
    d = os.path.join(lab, "switch")
    for shape in SWITCH_ORDER:
        exp = SWITCH[shape]
        sym = exp.get("zeroSymbol")
        try:
            texts = {}
            for mode in ("stock",) + SWITCH_MODES:
                cid = f"{shape}-{mode}"
                if cid not in listings:
                    raise Incomplete(f"no listing switch/{cid}.s")
                with open(os.path.join(d, cid + ".s"), encoding="utf-8", errors="replace") as f:
                    texts[mode] = f.read()
            skv = load_kv(os.path.join(d, f"{shape}-stock.kv"))
            cells = {}
            for mode in SWITCH_MODES:
                cid = f"{shape}-{mode}"
                cells[mode] = (load_kv(os.path.join(d, cid + ".kv")), load_kv(os.path.join(d, cid + ".manifest.kv")),
                               plugin_lines(load_lines(os.path.join(d, cid + ".stderr.txt"))),
                               load_json(os.path.join(d, cid + ".json")))
        except (Incomplete, OSError) as e:
            incomplete.append(f"switch {shape}: {e}")
            continue

        stock_wipe, stock_via, stock_z = wipe_reading(listings[f"{shape}-stock"], texts["stock"], sym)
        bad = []
        if skv.get("rc") != "0":
            bad.append(f"stock compile rc {skv.get('rc')}")
        if stock_wipe != exp["stock"]:
            bad.append(f"stock: the wipe reads {stock_wipe} (via {stock_via}), expected {exp['stock']}")
        problems += [f"{shape}-stock: {b}" for b in bad]
        zfmt = (lambda z: "" if z is None else f" [zcopy {z['loads']}L/{z['stores']}S/{z['calls']}C]")
        rows.append((f"{shape}-stock", "-", "-", "-", "-", "-", f"{stock_wipe} ({stock_via}){zfmt(stock_z)}", "-",
                     "ok" if not bad else "DISAGREES"))

        for mode in SWITCH_MODES:
            cid = f"{shape}-{mode}"
            kv, man, lines, rec = cells[mode]
            want = switch_cell_expectation(shape, mode)
            bad = [f"record: {p}" for p in wpr.validate(rec, want["expect"])]
            if not bad:
                bad += host_problems(rec)
                blk = want["block"]
                other = "zeroCopy" if blk == "barrierCalls" else "barrierCalls"
                checks = [
                    ("module", rec["module"], exp["module"]),
                    ("requested", rec["requested"], ["handle"]),
                    ("resolution", rec["resolution"],
                     [{"name": "handle", "resolution": "resolved", "exact": True, "linkage": "external"}]),
                    ("dryRun", rec["dryRun"], want["dryRun"]),
                    ("optLevel", (rec["optLevel"]["speedup"], rec["optLevel"]["size"]), OPT_LEVELS["-O2"]),
                    ("pinned", rec["pinned"], []),
                    ("pinnedCount/wouldPinCount", (rec["pinnedCount"], rec["wouldPinCount"]), (0, 0)),
                    ("unhandled", rec["unhandled"], want["unhandled"]),
                    (blk, rec[blk], want["blockValue"]),
                    (f"{other}.enabled", rec[other]["enabled"], False),
                    ("bufferBarriers", rec["bufferBarriers"], {"enabled": False, "count": 0, "sites": []}),
                ]
                for name, got, w in checks:
                    if got != w:
                        bad.append(f"record {name} = {got!r}, expected {w!r}")
            bad += lines_problems(lines, want["lines"])
            for name, got, w in (("pin-gcc.sh rc", kv.get("pinShRc"), str(want["pinShRc"])),
                                 ("manifest status", man.get("status"), str(want["pinShRc"])),
                                 ("manifest rc", man.get("rc"), "0"),
                                 ("manifest repairCount", man.get("repairCount"), str(want["repairCount"]))):
                if got != w:
                    bad.append(f"{name} = {got!r}, expected {w!r}")
            same = listings[cid]["sha256"] == listings[f"{shape}-stock"]["sha256"]
            if want["sameAsStock"] and not same:
                bad.append("the listing differs from the stock listing, where nothing may have changed")
            if not want["sameAsStock"] and same:
                bad.append("the listing is the stock listing byte for byte, where a barrier was to be placed")
            wipe, via, z = wipe_reading(listings[cid], texts[mode], sym)
            if wipe != want["wipe"]:
                bad.append(f"the wipe reads {wipe} (via {via}), expected {want['wipe']}")
            blkv = rec.get(want["block"]) or {}
            done, would = wpr.BLOCK_COUNTS[want["block"]]
            site = (blkv.get("sites") or [{}])[0] if blkv.get("sites") else {}
            rows.append((cid, kv.get("pinShRc"), f"{'on' if blkv.get('enabled') else 'off'}"
                         f"{'/dry' if rec.get('dryRun') else ''}",
                         f"{blkv.get(done)}/{blkv.get(would)}",
                         ",".join(f"{k}={v}" for k, v in (rec.get("unhandled") or {}).items() if v) or "-",
                         site.get("form") or site.get("callee") or "-",
                         f"{wipe} ({via}){zfmt(z)}", "yes" if same else "no",
                         "ok" if not bad else "DISAGREES"))
            problems += [f"{cid}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_buffer(lab, listings):
    """The buffer group: `listings` is the oracle's reading of
    <lab>/buffer/*.s for `handle` (subject) and `wipe_kept` (control)."""
    rows, problems, incomplete = [], [], []
    d = os.path.join(lab, "buffer")
    for shape in BUFFER_ORDER:
        exp = BUFFER[shape]
        try:
            texts = {}
            for mode in ("stock",) + exp["modes"]:
                cid = f"{shape}-{mode}"
                if cid not in listings:
                    raise Incomplete(f"no listing buffer/{cid}.s")
                with open(os.path.join(d, cid + ".s"), encoding="utf-8", errors="replace") as f:
                    texts[mode] = f.read()
            skv = load_kv(os.path.join(d, f"{shape}-stock.kv"))
            cells = {}
            for mode in exp["modes"]:
                cid = f"{shape}-{mode}"
                cells[mode] = (load_kv(os.path.join(d, cid + ".kv")), load_kv(os.path.join(d, cid + ".manifest.kv")),
                               plugin_lines(load_lines(os.path.join(d, cid + ".stderr.txt"))),
                               load_json(os.path.join(d, cid + ".json")))
        except (Incomplete, OSError) as e:
            incomplete.append(f"buffer {shape}: {e}")
            continue

        stock = listings[f"{shape}-stock"]
        bad = []
        if skv.get("rc") != "0":
            bad.append(f"stock compile rc {skv.get('rc')}")
        if exp["stock"] and stock["subject"]["verdict"] != exp["stock"]:
            bad.append(f"stock: the wipe reads {stock['subject']['verdict']}, expected {exp['stock']}")
        if exp["control"] and (stock["control"] or {}).get("verdict") != "PRESENT":
            bad.append(f"stock: the control {exp['control']} reads {(stock['control'] or {}).get('verdict')}: "
                       "the reading is blind")
        problems += [f"{shape}-stock: {b}" for b in bad]
        rows.append((f"{shape}-stock", "-", "-", "-", "-", stock["subject"]["verdict"] if exp["stock"] else "-",
                     (stock["control"] or {}).get("verdict", "-") if exp["control"] else "-", "-",
                     "ok" if not bad else "DISAGREES"))

        for mode in exp["modes"]:
            cid = f"{shape}-{mode}"
            kv, man, lines, rec = cells[mode]
            want = buffer_cell_expectation(shape, mode)
            bad = [f"record: {p}" for p in wpr.validate(rec, want["expect"])]
            if not bad:
                bad += host_problems(rec)
                checks = [
                    ("module", rec["module"], exp["module"]),
                    ("requested", rec["requested"], ["handle"]),
                    ("resolution", rec["resolution"],
                     [{"name": "handle", "resolution": "resolved", "exact": True, "linkage": "external"}]),
                    ("dryRun", rec["dryRun"], want["dryRun"]),
                    ("optLevel", (rec["optLevel"]["speedup"], rec["optLevel"]["size"]), OPT_LEVELS["-O2"]),
                    ("pinned", rec["pinned"], []),
                    ("pinnedCount/wouldPinCount", (rec["pinnedCount"], rec["wouldPinCount"]), (0, 0)),
                    ("unhandled", rec["unhandled"], {k: 0 for k in UNHANDLED_ORDER}),
                    ("bufferBarriers", rec["bufferBarriers"], want["blockValue"]),
                    ("barrierCalls.enabled", rec["barrierCalls"]["enabled"], False),
                    ("zeroCopy.enabled", rec["zeroCopy"]["enabled"], False),
                ]
                for name, got, w in checks:
                    if got != w:
                        bad.append(f"record {name} = {got!r}, expected {w!r}")
            bad += lines_problems(lines, want["lines"])
            for name, got, w in (("pin-gcc.sh rc", kv.get("pinShRc"), str(want["pinShRc"])),
                                 ("manifest status", man.get("status"), str(want["pinShRc"])),
                                 ("manifest rc", man.get("rc"), "0"),
                                 ("manifest repairCount", man.get("repairCount"), str(want["repairCount"]))):
                if got != w:
                    bad.append(f"{name} = {got!r}, expected {w!r}")
            same = listings[cid]["sha256"] == stock["sha256"]
            if want["sameAsStock"] and not same:
                bad.append("the listing differs from the stock listing, where nothing may have changed")
            if not want["sameAsStock"] and same:
                bad.append("the listing is the stock listing byte for byte, where a barrier was to be placed")
            wipe = listings[cid]["subject"]["verdict"]
            if want["wipe"] and wipe != want["wipe"]:
                bad.append(f"the wipe in handle reads {wipe}, expected {want['wipe']}")
            ctl = (listings[cid]["control"] or {}).get("verdict") if exp["control"] else None
            if exp["control"] and ctl != "PRESENT":
                bad.append(f"the control {exp['control']} reads {ctl}: the reading is blind")
            ctl_same = "-"
            if want["controlSame"]:
                a = asm_body(texts["stock"], exp["control"])
                b = asm_body(texts[mode], exp["control"])
                if a is None or b is None:
                    bad.append(f"{exp['control']} is missing from the stock or this listing")
                    ctl_same = "?"
                else:
                    ctl_same = "yes" if canonical_labels(a) == canonical_labels(b) else "NO"
                    if ctl_same != "yes":
                        bad.append(f"the control {exp['control']}'s body differs from the stock listing's (labels "
                                   "renumbered): the barrier changed a function outside the scope")
            blk = rec.get("bufferBarriers") or {}
            site = (blk.get("sites") or [{}])[0] if blk.get("sites") else {}
            rows.append((cid, kv.get("pinShRc"), f"{'on' if blk.get('enabled') else 'off'}"
                         f"{'/dry' if rec.get('dryRun') else ''}",
                         f"{blk.get('count')}/{len(blk.get('sites') or [])}",
                         f"{site.get('reason', '-')}/{site.get('anchor', '-')}/{site.get('buffer', '-')}",
                         wipe if want["wipe"] else "-", f"{ctl or '-'} same={ctl_same}",
                         "yes" if same else "no", "ok" if not bad else "DISAGREES"))
            problems += [f"{cid}: {b}" for b in bad]
    return rows, problems, incomplete


def grade_previous(lab):
    """The previous group. Returns (rows, problems, incomplete, given): when
    the runner was not given a previous plugin, given is False and nothing
    is graded."""
    d = os.path.join(lab, "previous")
    if not os.path.isfile(os.path.join(d, "given.kv")):
        return [], [], [], False
    rows, problems, incomplete = [], [], []
    try:
        given = load_kv(os.path.join(d, "given.kv"))
        ran = [l for l in load_lines(os.path.join(d, "cells.txt")) if l]
    except Incomplete as e:
        return [], [], [f"previous: {e}"], True
    want = previous_ids()
    # The same plugin given as the previous one: every pair would be the same
    # bytes, and the group would show nothing about the plugin it replaces.
    if given.get("pluginSha256") and given.get("pluginSha256") == given.get("previousSha256"):
        problems.append(f"previous: the previous plugin is this plugin (both sha256 "
                        f"{given.get('pluginSha256')}); the group compares the plugin with itself")
    if ran != want:
        problems.append(f"previous: the runner compiled {len(ran)} cell(s), expected the {len(want)} "
                        f"of the loop, shapes, switch-off and buffer-off cells in order "
                        f"(missing {sorted(set(want) - set(ran))}, extra {sorted(set(ran) - set(want))})")
    for cid in ran:
        try:
            kv = load_kv(os.path.join(d, cid + ".kv"))
        except Incomplete as e:
            incomplete.append(f"previous {cid}: {e}")
            continue
        a = sha_file(os.path.join(d, "this", cid + ".s"))
        b = sha_file(os.path.join(d, "prev", cid + ".s"))
        bad = []
        if kv.get("thisRc") != "0" or kv.get("prevRc") != "0":
            bad.append(f"compile rc this={kv.get('thisRc')} prev={kv.get('prevRc')}")
        if kv.get("thisStagedSha256") != given.get("pluginSha256") or \
                kv.get("prevStagedSha256") != given.get("previousSha256"):
            bad.append("the staged plugin was not the one named")
        if a is None or b is None:
            bad.append("a listing is missing")
        elif a != b:
            bad.append("this plugin's listing differs from the previous plugin's, with every switch off")
        rows.append((cid, kv.get("thisRc"), kv.get("prevRc"), "yes" if a is not None and a == b else "no",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"previous {cid}: {b_}" for b_ in bad]
    return rows, problems, incomplete, True


def table(head, rows):
    widths = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    print("  ".join(str(h).ljust(w) for h, w in zip(head, widths)).rstrip())
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", required=True, help="the directory run-gcc-fixture-loop.sh wrote into")
    args = ap.parse_args()
    lab = os.path.abspath(args.lab)

    try:
        listings = read_listings(lab)
        shape_listings = read_listings(lab, subject="handle", control=None, subdir="shapes")
        switch_listings = read_listings(lab, subject="handle", control=None, subdir="switch")
        buffer_listings = read_listings(lab, subject="handle", control="wipe_kept", subdir="buffer")
    except Incomplete as e:
        print(f"INCOMPLETE -- {e}")
        return 3

    rows, problems, incomplete = grade_loop(lab, listings)
    arow, aprob, ainc = grade_alone(lab)
    srow, sprob, sinc = grade_shapes(lab, shape_listings)
    trow, tprob, tinc = grade_stale(lab)
    lrow, lprob, linc = grade_lto(lab)
    xrow, xprob, xinc = grade_xtu(lab)
    wrow, wprob, winc = grade_switch(lab, switch_listings)
    brow, bprob, binc = grade_buffer(lab, buffer_listings)
    prow, pprob, pinc, prev_given = grade_previous(lab)
    problems += aprob + sprob + tprob + lprob + xprob + wprob + bprob + pprob
    incomplete += ainc + sinc + tinc + linc + xinc + winc + binc + pinc

    table(("cell", "opt", "kind", "subject", "via", "control", "obj=base", "asm=base",
           "pinned/would/mode/res", "followedByUse", "pin-gcc.sh", ""), rows)
    print("oracle: compiler/eval/second-vendor/lib/asm-oracle.mjs observeEffect, effect CONTROL_EFFECT "
          "(ablation-cell.mjs); via rep-stos-fallback = the labelled fallback in lib/asm-presence.mjs")
    print()
    table(("pin-gcc.sh alone", "rc", "cc rc", "record", "module", ""), arow)
    print()
    table(("shape (-g)", "pin-gcc.sh", "pinned", "followedByUse", "alreadyVolatile", "lines",
           "exact/linkage", "partial line", "nothing line", "zero store plugin/stock", ""), srow)
    print("zero store: the same oracle on shapes/<id>.s (plugin) and shapes/<id>-stock.s, subject handle")
    print()
    table(("stale record", "before", "cc rc", "after", "WipePinGcc stderr", ""), trow)
    print()
    table(("lto (-O2)", "rc", "refusals", "compile record", "WPIN_OUT before", "WPIN_OUT after",
           "output==stock", "zero fill in handle (objdump -d)", ""), lrow)
    print()
    table(("xtu (-O2, executable)", "form", "mode", "rc", "objects", "wipe.c record", "inlined",
           "subject: handle", "control: wipe_kept", "==stock", ""), xrow)
    print(f"xtu: read with {objdump_fill.objdump_version()}, `objdump -d --no-show-raw-insn` of each "
          "executable; inlined = no call to secure_wipe (or a renamed copy) left in handle")
    print()
    table(("switch (-O2)", "pin-gcc.sh", "switch", "done/would", "unhandled", "site", "wipe in handle",
           "asm=stock", ""), wrow)
    print("wipe: the oracle on switch/<cell>.s, subject handle; for the zero-copy cells also zcopy_reading "
          "(loads of vg_zeros / their stores / memcpy calls), and PRESENT if either reads it")
    print()
    table(("buffer (-O2)", "pin-gcc.sh", "switch", "count/sites", "reason/anchor/buffer", "wipe in handle",
           "control", "asm=stock", ""), brow)
    print("buffer: the oracle on buffer/<cell>.s, subject handle, control wipe_kept; same = wipe_kept's body "
          "equals the stock listing's after .L labels are renumbered in order")
    print()
    if prev_given:
        table(("previous plugin (-S)", "rc this", "rc prev", "same bytes", ""), prow)
    else:
        print("previous plugin: not run (the runner was given no --previous-plugin); 0 cells")

    if incomplete:
        print("\nINCOMPLETE -- these cells could not be graded:")
        for m in incomplete:
            print("  " + m)
        return 3

    try:
        can_fail = checks_can_fail(lab)
    except (Incomplete, KeyError, TypeError) as e:
        print(f"\nINCOMPLETE -- {e}")
        return 3
    print(f"\nrecord checks can fail: {'yes' if can_fail else 'NO'}")
    if not can_fail:
        problems.append("the record reader did not notice an altered record")

    if problems:
        print("\nDISAGREEMENTS:")
        for p in problems:
            print("  " + p)
        return 2
    groups = [("loop", rows), ("alone", arow), ("shapes", srow), ("stale", trow), ("lto", lrow), ("xtu", xrow),
              ("switch", wrow), ("buffer", brow), ("previous", prow)]
    n = sum(len(r) for _, r in groups)
    print(f"\nall {n} cells as expected")
    print("by group: " + ", ".join(f"{g} {len(r)}" for g, r in groups) +
          ("" if prev_given else " (previous not run)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
