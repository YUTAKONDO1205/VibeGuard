#!/usr/bin/env python3
"""Grade the lab written by run-gcc-fixture-loop.sh. Compiles nothing.

    python3 compiler/gcc-repair/scripts/check-gcc-fixture-loop.py --lab DIR

Whether a wipe is in a listing is decided by the repository's assembly oracle
(compiler/eval/second-vendor/lib/asm-oracle.mjs), which this script reaches
through lib/asm-presence.mjs -- imported there, never copied -- so node is
required. WipePinGcc's own record is read too, but only to check that it says
what the cell asked of it; it never decides whether the wipe survived. The one
exception to "a listing" is the lto group, whose output is a linked shared
object: there the zero stores are read from `objdump -d` by
objdump_zero_stores below, which recognises the oracle's two inline idioms in
objdump's spelling.

Object files are compared byte for byte. That is the claim for the cells where
the plugin is loaded and changes nothing (dry, wrongname, nothing): an object
identical to the one built without the plugin.

The expectations below were written from what each cell is for. A cell that
disagrees is printed as a disagreement and the run fails; the tables are never
edited into agreement. Where a table records something measured rather than
predicted (the level at which gcc-13 removes the stock wipe), the comment says
so.

Exit codes (compiler/schema/interfaces.md section 7):
    0  every expectation held
    2  at least one expectation did not
    3  a file was missing or unreadable, or node could not read the listings,
       so the lab could not be graded
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

LEVELS = ["-O0", "-O1", "-O2", "-O3", "-Os"]

# What gcc-13 13.3.0 reports as {optimize, optimize_size} for each flag,
# measured with the plugin itself (README.md, "Optimisation levels").
OPT_LEVELS = {"-O0": (0, 0), "-O1": (1, 0), "-O2": (2, 0), "-O3": (3, 0), "-Os": (2, 1)}

# Measured, not predicted: gcc-13 13.3.0 keeps the fixture's subject wipe at -O0
# only; at -O1 and above tree DSE deletes it (README.md, the base rows).
STOCK_PRESENT = {"-O0"}

NO_UNHANDLED = "libcallMemset=0 memsetChk=0 nonZeroFill=0 atomicMemset=0 inlineWrapperMemset=0"


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
    # Two cc1 processes, target.c then opaque.c: the record left is opaque.c's,
    # where handle_request does not exist, although target.c was pinned.
    "twosources-O2": {"pinShRc": 4, "record": True, "module": "opaque.c", "sourceOperands": "2",
                      "lines": ["WipePinGcc: target handle_request not-in-module",
                                nothing_line("opaque.c")]},
}
ALONE_ORDER = ["notarget-O2", "syntaxonly-O2", "baddry-O2", "twosources-O2"]

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


def record_problems(rec, exp, module):
    """What a loop cell's record must say, beyond the v2 shape."""
    bad = [f"record: {p}" for p in wpr.validate(rec)]
    if bad:
        return bad
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
            bad += [f"record: {p}" for p in wpr.validate(rec)]
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
        bad = [f"record: {p}" for p in wpr.validate(rec)]
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
                bad += [f"record: {p}" for p in wpr.validate(rec)]
                if rec.get("module") != "trailing.c" or rec.get("pinnedCount") != 1:
                    bad.append(f"record module={rec.get('module')} pinnedCount={rec.get('pinnedCount')}")
        if cell == "stale-dir" and not os.path.isfile(os.path.join(out, "keep.txt")):
            bad.append("the directory at WPIN_OUT lost its contents")
        rows.append((cell, kv.get("before"), kv.get("rc"), on_disk, lines[0] if lines else "-",
                     "ok" if not bad else "DISAGREES"))
        problems += [f"{cell}: {b}" for b in bad]
    return rows, problems, incomplete


def objdump_body(text, fn):
    """The instruction lines of `fn` in `objdump -d` output, or None."""
    lines = text.split("\n")
    head = re.compile(r"^[0-9a-f]+ <" + re.escape(fn) + r">:$")
    for i, l in enumerate(lines):
        if head.match(l):
            body = []
            for x in lines[i + 1:]:
                if not x.strip():
                    break
                body.append(x)
            return body
    return None


_OBJ_SELF_XOR = re.compile(r"^v?(?:pxor|xorps|xorpd)\s+%([xyz]mm\d+),%([xyz]mm\d+)$")
_OBJ_VEC_STORE = re.compile(r"^v?(?:movaps|movups|movapd|movupd|movdqa|movdqu)\s+%([xyz]mm\d+),(\S*\(\S*\))$")
_OBJ_IMM_STORE = re.compile(r"^mov([bwlq])\s+\$0x0,(\S*\(\S*\))$")
_OBJ_MEMSET_CALL = re.compile(r"^call\s+\S+\s+<(?:memset|__memset_chk)(?:@plt)?>$")
_OBJ_WRITES_VEC = re.compile(r",%([xyz]mm\d+)$")


def objdump_zero_stores(text, fn):
    """The zero stores in `fn`, read from `objdump -d --no-show-raw-insn`.

    The assembly oracle's two inline idioms, in objdump's spelling: a vector
    register zeroed against itself and then stored to a memory operand (16, 32
    or 64 bytes by register width), and an immediate zero stored to a memory
    operand (by suffix), plus calls to memset / __memset_chk. A vector register
    that is written by anything else stops counting as zeroed. None when the
    function is not in the output."""
    body = objdump_body(text, fn)
    if body is None:
        return None
    zeroed, stores, calls, nbytes = set(), [], [], 0
    for raw in body:
        ins = raw.split("\t", 1)[1].strip() if "\t" in raw else raw.strip()
        ins = re.sub(r"\s+#.*$", "", ins)
        m = _OBJ_SELF_XOR.match(ins)
        if m and m.group(1) == m.group(2):
            zeroed.add(m.group(1))
            continue
        m = _OBJ_VEC_STORE.match(ins)
        if m and m.group(1) in zeroed:
            stores.append(ins)
            nbytes += {"x": 16, "y": 32, "z": 64}[m.group(1)[0]]
            continue
        m = _OBJ_IMM_STORE.match(ins)
        if m:
            stores.append(ins)
            nbytes += {"b": 1, "w": 2, "l": 4, "q": 8}[m.group(1)]
            continue
        if _OBJ_MEMSET_CALL.match(ins):
            calls.append(ins)
            continue
        m = _OBJ_WRITES_VEC.search(ins)
        if m:
            zeroed.discard(m.group(1))
    return {"stores": len(stores), "bytes": nbytes, "calls": len(calls), "lines": stores + calls}


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
        bad += [f"record: {p}" for p in wpr.validate(rec)]
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
    return bool(wpr.validate(tampered)) and bool(wpr.validate(flipped)) and \
        bool(wpr.validate(toolchain)) and not wpr.validate(moved_context)


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
    except Incomplete as e:
        print(f"INCOMPLETE -- {e}")
        return 3

    rows, problems, incomplete = grade_loop(lab, listings)
    arow, aprob, ainc = grade_alone(lab)
    srow, sprob, sinc = grade_shapes(lab, shape_listings)
    trow, tprob, tinc = grade_stale(lab)
    lrow, lprob, linc = grade_lto(lab)
    problems += aprob + sprob + tprob + lprob
    incomplete += ainc + sinc + tinc + linc

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
    n = len(rows) + len(arow) + len(srow) + len(trow) + len(lrow)
    print(f"\nall {n} cells as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
