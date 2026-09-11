#!/usr/bin/env python3
"""Grade the fixture loop written by run-fixture-loop.sh. Compiles nothing.

    python3 compiler/llvm-repair/scripts/check-fixture-loop.py --lab DIR

The instrument being read is the IR observer (IrCheckpoints), not WipePin.
WipePin's own record is read too, but only to check that it says what the cell
asked of it -- it never decides whether the wipe survived. That is the
observer's verdict, taken from the same record shape the optimisation matrix
grades, on the same fixture, with the same effect-symbol list.

The expectations below were written from what each cell is for, before the
loop was first run. A cell that disagrees is printed as a disagreement and the
run fails; the table is never edited into agreement.

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

# --------------------------------------------------------------- expectations
#
# base-*       observer only. The erasure fixture's subject wipe is a dead
#              store: -O0/-O1 keep it through the IR optimiser, -O2/-O3 lose it
#              at DSEPass (compiler/llvm-pass/README.md, the erasure row).
# pin-*        observer + WipePin on the subject. The wipe must be PRESENT at
#              the post-optimisation checkpoint at every level, as a volatile
#              llvm.memset, and WipePin must say it pinned exactly one site.
# dry-O2       the red control: WipePin loaded, told to change nothing. The loss
#              must come back exactly as in base-O2.
# wrongname-O2 WipePin loaded against a name that does not exist. It must pin
#              nothing, say not-in-module, and the loss must come back.
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
    }
EXPECT["dry-O2"] = {
    "opt": "-O2", "pin": True,
    "state": "LOST", "fzt": "DSEPass", "volatile": 0,
    "pinnedCount": 0, "wouldPinCount": 1, "dryRun": True,
    "resolution": "resolved", "requested": "handle_request",
}
EXPECT["wrongname-O2"] = {
    "opt": "-O2", "pin": True,
    "state": "LOST", "fzt": "DSEPass", "volatile": 0,
    "pinnedCount": 0, "wouldPinCount": 0, "dryRun": False,
    "resolution": "not-in-module", "requested": "handle_requestX",
}

ORDER = [f"base{o}" for o in LEVELS] + [f"pin{o}" for o in LEVELS] + ["dry-O2", "wrongname-O2"]

SPEEDUP = {"-O0": 0, "-O1": 1, "-O2": 2, "-O3": 3}


class Incomplete(Exception):
    pass


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise Incomplete(f"{path}: {e}")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(rec):
    """interfaces.md section 5, re-derived here rather than trusted."""
    stripped = {k: v for k, v in rec.items() if k not in ("context", "evidenceDigest")}
    return hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()


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


def subject_ir(snapshot_path, fn):
    """The subject function's text from the observer's post-opt snapshot."""
    try:
        with open(snapshot_path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        raise Incomplete(f"{snapshot_path}: {e}")
    lines = text.split("\n")
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
            pin = load_json(os.path.join(lab, "wipepin", cell + ".json")) if exp["pin"] else None
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

        pinsum = "-"
        if pin is not None:
            res = pin.get("resolution") or []
            resword = res[0]["resolution"] if len(res) == 1 else f"{len(res)} names"
            pinsum = f"{pin.get('pinnedCount')}/{pin.get('wouldPinCount')}/{'dry' if pin.get('dryRun') else 'live'}/{resword}"
            checks = [
                ("schemaVersion", pin.get("schemaVersion"), "wipe-pin-v0"),
                ("component", pin.get("component"), "WipePin"),
                ("module", pin.get("module"), "target.c"),
                ("scope", pin.get("scope"), "functions"),
                ("requested", pin.get("requested"), [exp["requested"]]),
                ("resolution", resword, exp["resolution"]),
                ("pinnedCount", pin.get("pinnedCount"), exp["pinnedCount"]),
                ("wouldPinCount", pin.get("wouldPinCount"), exp["wouldPinCount"]),
                ("dryRun", pin.get("dryRun"), exp["dryRun"]),
                ("optLevel.speedup", (pin.get("optLevel") or {}).get("speedup"), SPEEDUP[exp["opt"]]),
                ("pinned[] length", len(pin.get("pinned") or []), exp["wouldPinCount"]),
            ]
            for name, got, want in checks:
                if got != want:
                    bad.append(f"WipePin {name} = {got!r}, expected {want!r}")
            for site in pin.get("pinned") or []:
                if site.get("function") != "handle_request" or site.get("destKind") != "alloca" \
                        or site.get("lengthBytes") != 32:
                    bad.append(f"WipePin pinned an unexpected site {site}")
            if pin.get("evidenceDigest") != digest_of(pin):
                bad.append("WipePin evidenceDigest does not re-derive")
            leaks = absolute_paths({k: v for k, v in pin.items() if k != "context"})
            if leaks:
                bad.append(f"WipePin record carries an absolute path: {leaks}")

        base_obj = sha_file(os.path.join(lab, "objects", "base" + exp["opt"] + ".o"))
        this_obj = sha_file(os.path.join(lab, "objects", cell + ".o"))
        objdiff = "-" if cell.startswith("base") else (
            "?" if base_obj is None or this_obj is None else ("yes" if base_obj != this_obj else "no"))

        rows.append((cell, exp["opt"], "yes" if exp["pin"] else "no", state, f"{pre}->{post}",
                     fzt or "-", "yes" if held else "NO", "?" if vol is None else str(vol),
                     pinsum, objdiff, "ok" if not bad else "DISAGREES"))
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
    moved_context = copy.deepcopy(rec)
    moved_context["context"] = {"generatedAt": 0}
    return tampered["evidenceDigest"] != digest_of(tampered) and \
        moved_context["evidenceDigest"] == digest_of(moved_context)


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

    head = ("cell", "opt", "WipePin", "verdict", "effect pre->post", "firstZero", "ctl held",
            "volatile@post", "pinned/would/mode/res", "obj!=base", "")
    widths = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    print("  ".join(str(h).ljust(w) for h, w in zip(head, widths)).rstrip())
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)).rstrip())
    print(f"effect symbols: registered list wipe-6 ({len(registry_symbols)} spellings)")

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
    print(f"digest check can fail: {'yes' if can_fail else 'NO'}")
    if not can_fail:
        problems.append("the WipePin digest re-derivation did not notice an altered record")

    if problems:
        print("\nDISAGREEMENTS:")
        for p in problems:
            print("  " + p)
        return 2
    print(f"\nall {len(rows)} cells as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
