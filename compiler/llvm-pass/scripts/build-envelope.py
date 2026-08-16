#!/usr/bin/env python3
"""Assemble one envelope.json from the cells run-envelope.sh produced.

A record says what was observed. It does not say what was built: the
optimisation level, the -D, the LTO mode and the target are in the invocation,
and the invocation is not in the record. Joining the two is the whole job here,
because a reading without its configuration cannot be compared with another
reading, and comparing readings across configurations is what a security
configuration envelope is.

This file assembles and labels. It does not decide whether the envelope is
acceptable -- check-envelope.py does that, from expectations written separately.

Every cell gets a handshake. The observer has three ways to produce nothing
while the compiler exits 0 -- an unloadable plugin, a missing OBS_* that leaves
it unregistered, and a pipeline whose extension points it never reaches -- and
in all three the build looks fine. A cell without a handshake is invalid before
its verdict is even read, so the handshake is computed first and the state is
overwritten with a label when it fails:

  measurement=UNSUPPORTED         the toolchain refused the invocation (rc 1)
  measurement=BROKEN_MEASUREMENT  the toolchain accepted it and nothing was observed
  (both carry state=NOT_OBSERVED: interfaces.md section 3 is the property state,
   and neither of these is a claim about the property. The measurement vocabulary
   and the pairing rule are interfaces.md section 3.1; see the note at the else.)

Neither is a hole to be filled in later by whatever the neighbouring cell said.

Writes:  compiler/llvm-pass/_results/envelope/envelope.json  (git-ignored)
Exit codes follow interfaces.md section 7: 0 written, 3 nothing to assemble.
"""

import base64
import hashlib
import json
import os
import sys

LAB = os.environ.get("IRCK_ENV_LAB", os.path.expanduser("~/vg-lab/llvm-pass-envelope"))
CELLS = os.path.join(LAB, "cells")
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.environ.get(
    "IRCK_ENVELOPE_OUT", os.path.join(HERE, "..", "_results", "envelope"))

SCHEMA = "ir-checkpoints-v0"
COMPONENT = "IrCheckpoints"

# The measurement vocabulary, from compiler/schema/interfaces.md section 3.1.
# Named here rather than spelled at each use because two other components read
# this column -- check-envelope.py grades off it, compiler/envelope/fragility.mjs
# validates it -- and a fourth word invented at one end of that is a contract
# change, not a local one. The section is the authority; these are its bindings.
MEASUREMENT_OK = "OK"
MEASUREMENT_UNSUPPORTED = "UNSUPPORTED"
MEASUREMENT_BROKEN = "BROKEN_MEASUREMENT"
MEASUREMENT_STATES = (MEASUREMENT_OK, MEASUREMENT_UNSUPPORTED, MEASUREMENT_BROKEN)

# The property-state vocabulary, interfaces.md section 3. Verbatim, in section
# order, because a state that arrives from a record is checked against it below.
KNOWN_STATES = ("PRESENT", "ABSENT", "LOST", "REINTRODUCED",
                "NOT_APPLICABLE", "NOT_OBSERVED")
STATE_NOT_OBSERVED = "NOT_OBSERVED"


def canonical(obj):
    """interfaces.md section 5, reimplemented here rather than imported, so the
    digest a record carries is checked by something other than the code that
    wrote it."""
    if isinstance(obj, float):
        raise ValueError("a record carried a non-integer number")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def recompute_digest(record):
    stripped = {k: v for k, v in record.items()
                if k not in ("context", "evidenceDigest")}
    return hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()


def read_kv(path):
    kv = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv[k] = v
    return kv


def b64(s):
    if not s:
        return ""
    return base64.b64decode(s.encode("ascii")).decode("utf-8", "replace")


def handshake_of(kv, rec):
    """Did the observer actually run, and is what it left behind its own work?

    Existence of a file is not the question. The question is whether this
    component stepped through a pipeline in this process and wrote a record
    whose contents still hash to the value it carries."""
    h = {
        "recordWritten": rec is not None,
        "component": None,
        "schemaVersion": None,
        "moduleId": None,
        "afterPassObservations": None,
        "digestVerified": False,
        "stage": kv.get("stage", "compile"),
        "pluginSha256": kv.get("pluginSha256", "absent"),
        "ok": False,
    }
    if rec is None:
        return h
    h["component"] = rec.get("component")
    h["schemaVersion"] = rec.get("schemaVersion")
    h["moduleId"] = rec.get("module")
    try:
        h["afterPassObservations"] = int(
            rec["oracleDivergence"]["totalAfterPassObservations"])
    except (KeyError, TypeError, ValueError):
        h["afterPassObservations"] = None
    h["digestVerified"] = recompute_digest(rec) == rec.get("evidenceDigest")

    h["ok"] = bool(
        h["component"] == COMPONENT
        and h["schemaVersion"] == SCHEMA
        and h["digestVerified"]
        and h["afterPassObservations"] is not None
        and h["afterPassObservations"] > 0
        and h["moduleId"]
    )
    # A link-stage cell that reports a compile-stage module identifier is
    # reporting the pre-link reading under a backend label. The bitcode for
    # these cells is compiled without the plugin so that cannot happen by
    # accident, but the check is cheap and the false attribution it prevents is
    # the one this axis exists to avoid.
    if h["ok"] and h["stage"] == "link" and h["moduleId"] != "ld-temp.o":
        h["ok"] = False
        h["stageMismatch"] = h["moduleId"]
    return h


def build():
    if not os.path.isdir(CELLS):
        print("no cells directory at %s; run-envelope.sh has not been run"
              % CELLS.replace(os.path.expanduser("~"), "~"), file=sys.stderr)
        return None

    names = sorted(n for n in os.listdir(CELLS) if n.endswith(".kv"))
    if not names:
        print("no cell manifests in %s" % CELLS.replace(os.path.expanduser("~"), "~"),
              file=sys.stderr)
        return None

    cells = []
    for name in names:
        kv = read_kv(os.path.join(CELLS, name))
        rc = int(kv.get("rc", "3"))
        rec = None
        rel = kv.get("record", "")
        if rel:
            p = os.path.join(LAB, rel)
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        rec = json.load(fh)
                except (ValueError, OSError):
                    rec = None

        hs = handshake_of(kv, rec)

        cell_id = kv.get("cellId", name[:-3])
        cell = {
            "cellId": cell_id,
            # A positive control shares its configuration with the ordinary cell
            # it is meant to be compared against, so the tag is what tells them
            # apart. "-" is an ordinary cell.
            "control": cell_id.split("+ctl=")[1] if "+ctl=" in cell_id else "-",
            "subject": kv.get("subject", "unnamed"),
            "propertyId": kv.get("propertyId", "unnamed"),
            "extractor": kv.get("extractor", ""),
            "subjectUnit": kv.get("subjectUnit", ""),
            "controlUnit": kv.get("controlUnit", ""),
            "config": {
                "opt": kv.get("opt", ""),
                "ndebug": kv.get("ndebug") == "1",
                "lto": kv.get("lto", "none"),
                "target": kv.get("target", "host"),
                "freestanding": kv.get("freestanding") == "1",
                "cc": kv.get("cc", ""),
            },
            # Provenance, not an axis, and it sits outside `config` for that
            # reason. These flags are DERIVED from the axes above -- lto=full
            # is what puts -flto here -- so a consumer that groups cells by
            # configuration would be splitting on a restatement of a column it
            # already has. It is also the only list-valued thing that was in
            # `config`, and a scorer that compares configurations across cells
            # is entitled to expect scalar axes. Nothing grades on it; it is
            # here so the exact invocation stays recoverable from the envelope.
            "extraArgs": [a for a in b64(kv.get("extraArgsB64", "")).split("\n") if a],
            "rc": rc,
            "pluginSha256": kv.get("pluginSha256", "absent"),
            "handshake": hs,
            "expectedBroken": kv.get("expectedBroken") == "1",
            "expectedBrokenReason": kv.get("expectedBrokenReason", ""),
        }

        if rec is not None and hs["ok"]:
            cell["state"] = rec["verdict"]["state"]
            cell["measurement"] = MEASUREMENT_OK
            cell["reason"] = rec["verdict"]["reason"]
            cell["controlHeld"] = rec["control"]["held"]
            cell["completesTheCheck"] = rec["verdict"]["completesTheCheck"]
            cell["firstZeroPass"] = rec["firstZeroTransition"]["pass"]
            cell["findings"] = [f["id"] for f in rec["findings"]]
            cell["subjectEffect"] = {
                "preOpt": rec["subject"]["preOptIr"]["effect"],
                "postOpt": rec["subject"]["postOptIr"]["effect"],
                "unitPresentPostOpt": rec["subject"]["postOptIr"]["unitPresent"],
            }
        else:
            # rc 1 is the toolchain saying no; anything else with no usable
            # record is a measurement that did not happen. Neither may inherit a
            # verdict from a neighbouring cell.
            #
            # WHY THE STATE IS NOT `UNSUPPORTED` / `BROKEN_MEASUREMENT`
            #
            # Both of those were written into `state` until 2026-08-16, and the
            # scorer in compiler/envelope/ refused the whole file over it (exit 3),
            # correctly: interfaces.md section 3 fixes six property states, and it
            # opens by saying that "we did not see it" and "it is not there" are
            # different claims and merging them is how a checker starts lying.
            # These two labels are claims about the apparatus, not about the
            # property, so putting them in the state column is that merge. The
            # state here is `NOT_OBSERVED` -- section 3's own word for "no
            # observation was made here" -- and WHY no observation was made moves
            # to `measurement`, where it is still first-class and still ungradeable.
            # Nothing is lost: every consumer that excluded the old labels excludes
            # `NOT_OBSERVED` already, and the reason is now readable without
            # widening a shared vocabulary from one end of it.
            #
            # That new column is not a free-form field. Its three words and the
            # rule that pairs them with `state` are interfaces.md section 3.1,
            # written there for the same reason section 3 is written there: a
            # vocabulary fixed in one implementation's comments is not fixed.
            cell["state"] = STATE_NOT_OBSERVED
            cell["measurement"] = (MEASUREMENT_UNSUPPORTED if rc == 1
                                   else MEASUREMENT_BROKEN)
            cell["reason"] = (b64(kv.get("stderrB64", "")).strip().split("\n") or [""])[0][:300]
            cell["controlHeld"] = None
            cell["completesTheCheck"] = False
            cell["firstZeroPass"] = None
            cell["findings"] = []
            cell["subjectEffect"] = None

        cells.append(cell)

    # interfaces.md section 3.1, checked on the way out. Two of the three ways
    # this can fail are reachable from input: `state` for a graded cell is copied
    # straight out of the record's verdict, so an observer that emits a word
    # section 3 does not define -- including either of the measurement words,
    # which is exactly the confusion 3.1 exists to stop -- would otherwise land it
    # in the state column and be graded. The third, a measurement outside the
    # vocabulary, can only come from an edit to the branches above; it is checked
    # anyway because the cost is one comparison and the failure it catches is a
    # silently mislabelled envelope.
    violations = []
    for c in cells:
        if c["measurement"] not in MEASUREMENT_STATES:
            violations.append(
                "%s: measurement=%r is not one of %s"
                % (c["cellId"], c["measurement"], "/".join(MEASUREMENT_STATES)))
        elif c["state"] not in KNOWN_STATES:
            violations.append(
                "%s: state=%r is not one of the six in interfaces.md section 3 (%s)"
                % (c["cellId"], c["state"], "/".join(KNOWN_STATES)))
        elif c["measurement"] != MEASUREMENT_OK and c["state"] != STATE_NOT_OBSERVED:
            violations.append(
                "%s: measurement=%s with state=%s; a cell that produced no reading "
                "has no property state to report, so section 3.1 pairs it with %s"
                % (c["cellId"], c["measurement"], c["state"], STATE_NOT_OBSERVED))
    if violations:
        print("interfaces.md section 3.1 is not satisfied by %d cell(s); refusing to "
              "write an envelope whose labels cannot be read:" % len(violations),
              file=sys.stderr)
        for v in violations:
            print("  " + v, file=sys.stderr)
        return None

    graded = [c for c in cells if c["measurement"] == MEASUREMENT_OK]
    env = {
        "schemaVersion": "security-configuration-envelope-v0",
        "component": "IrCheckpoints",
        "axes": {
            "opt": sorted({c["config"]["opt"] for c in cells}),
            "ndebug": [False, True],
            "lto": sorted({c["config"]["lto"] for c in cells}),
            "target": sorted({c["config"]["target"] for c in cells}),
            "freestanding": [False, True],
        },
        "counts": {
            "cells": len(cells),
            "graded": len(graded),
            "unsupported": sum(1 for c in cells
                               if c["measurement"] == MEASUREMENT_UNSUPPORTED),
            "brokenMeasurement": sum(1 for c in cells
                                     if c["measurement"] == MEASUREMENT_BROKEN),
            "handshakeOk": sum(1 for c in cells if c["handshake"]["ok"]),
        },
        # Split, because "absent" turns up here legitimately: one positive
        # control runs with no plugin at the configured path on purpose. Lumping
        # it in with the observers that did write a record would make the field
        # look like two builds had been mixed.
        "pluginSha256Observed": sorted(
            {c["pluginSha256"] for c in cells if c["handshake"]["recordWritten"]}),
        "pluginSha256Configured": sorted({c["pluginSha256"] for c in cells}),
        "cells": cells,
    }
    return env


def main():
    env = build()
    if env is None:
        return 3
    os.makedirs(OUT_DIR, exist_ok=True)
    out = os.path.join(OUT_DIR, "envelope.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(env, fh, indent=1, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    print("envelope.json: %d cells (%d graded, %d unsupported, %d broken)" %
          (env["counts"]["cells"], env["counts"]["graded"],
           env["counts"]["unsupported"], env["counts"]["brokenMeasurement"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
