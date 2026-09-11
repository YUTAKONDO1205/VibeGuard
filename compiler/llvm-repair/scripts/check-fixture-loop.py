#!/usr/bin/env python3
"""Grade the fixture loop written by run-fixture-loop.sh. Compiles nothing.

    python3 compiler/llvm-repair/scripts/check-fixture-loop.py --lab DIR

The instrument being read in the loop cells is the IR observer (IrCheckpoints),
not WipePin. WipePin's own record is read too, but only to check that it says
what the cell asked of it -- it never decides whether the wipe survived. That is
the observer's verdict, taken from the same record shape the optimisation matrix
grades, on the same fixture, with the same effect-symbol list.

The shape and stale cells are about WipePin's own account of itself: what its
wipe-pin-v1 record and its stderr say for a source whose answer is known, and
whether a record from an earlier compile can outlive a compile that wrote none.

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

SCHEMA = "wipe-pin-v1"

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

# The shapes, all -O2 -g, one target each. `sites` is followedByUse for each
# recorded site in order; `partial` is (pinned, followed) for the one line the
# plugin must print, or None where it must print none.
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
}
SHAPE_ORDER = ["initloop", "inithelper", "initwipe", "aliasinit", "trailing", "c99inline", "cxxinline"]

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


def v1_problems(pin):
    """What every wipe-pin-v1 record must be, whatever the cell asked of it."""
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
            bad += [f"WipePin {p}" for p in v1_problems(pin)]

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
        bad = [f"record: {p}" for p in v1_problems(pin)]
        sites = pin.get("pinned") or []
        got_fbu = [s.get("followedByUse") for s in sites]
        res = pin.get("resolution") or []
        r0 = res[0] if len(res) == 1 else {}
        followed = sum(1 for v in exp["sites"] if v is True)
        checks = [
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

        rows.append((cell, kv.get("pinShRc"), str(pin.get("pinnedCount")),
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
                bad += [f"record: {p}" for p in v1_problems(rec)]
                if rec.get("module") != "trailing.c" or rec.get("pinnedCount") != 1:
                    bad.append(f"record module={rec.get('module')} pinnedCount={rec.get('pinnedCount')}")
        if cell == "stale-dir" and not os.path.isfile(os.path.join(out, "keep.txt")):
            bad.append("the directory at WPIN_OUT lost its contents")
        rows.append((cell, kv.get("before"), kv.get("rc"), on_disk,
                     wl[0] if wl else "-", "ok" if not bad else "DISAGREES"))
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
    problems += pprob + sprob + tprob
    incomplete += pinc + sinc + tinc

    table(("cell", "opt", "WipePin", "verdict", "effect pre->post", "firstZero", "ctl held",
           "volatile@post", "pinned/would/mode/res", "followedByUse", "obj!=base", "pin.sh", ""), rows)
    print(f"effect symbols: registered list wipe-6 ({len(registry_symbols)} spellings)")
    print()
    table(("pin.sh alone", "rc", "clang rc", "record", ""), prow)
    print()
    table(("shape (-O2 -g)", "pin.sh", "pinned", "followedByUse", "exact/linkage",
           "partial line", "non-exact line", ""), srow)
    print()
    table(("stale record", "before", "clang rc", "after", "WipePin stderr", ""), trow)

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
    n = len(rows) + len(prow) + len(srow) + len(trow)
    print(f"\nall {n} cells as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
