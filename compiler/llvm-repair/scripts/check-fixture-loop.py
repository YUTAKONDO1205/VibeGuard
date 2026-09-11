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

The expectations below were written from what each cell is for, before the
cells were first run. A cell that disagrees is printed as a disagreement and the
run fails; the tables are never edited into agreement.

Exit codes (compiler/schema/interfaces.md section 7):
    0  every expectation held
    2  at least one expectation did not
    3  a record was missing or unreadable, so the loop could not be graded
"""

import argparse
import copy
import hashlib
import json
import os
import re
import sys

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
    problems += pprob + sprob + tprob + lprob
    incomplete += pinc + sinc + tinc + linc

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
    n = len(rows) + len(prow) + len(srow) + len(trow) + len(lrow)
    print(f"\nall {n} cells as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
