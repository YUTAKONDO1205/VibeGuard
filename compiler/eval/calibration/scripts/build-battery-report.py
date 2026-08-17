#!/usr/bin/env python3
"""Assemble one configuration's records, listings and witnesses into a report.

    python3 build-battery-report.py <config-id> [--out <path>]

Reads:   $VG_CAL_LAB/records/<config>/*.json, $VG_CAL_LAB/witness/<config>.json,
         $VG_CAL_LAB/configs/<config>.kv, and ../battery.json
Writes:  $VG_CAL_LAB/_results/calibration/<config>.json
Decides: whether each cell is DATA, and nothing about whether it is RIGHT.

WHERE THIS FILE SITS IN THE SEPARATION OF POWERS

run-battery.sh produces, this file assembles, check-battery.py grades, and
check-claims.py holds the catalogue's prose against what was assembled. The seam
matters most here because this file is the ONE place two things happen that look
like grading and are not:

 1. interfaces.md section 3.1's PAIRING RULE is applied. A cell whose measurement
    is not OK must carry state NOT_OBSERVED and controlHeld null, because no
    reading came back and any other state is a verdict invented for a measurement
    that did not happen.

    The raw records do NOT obey that rule. Measured 2026-08-17: cal-wipe-broken at
    -O2 carries `verdict.state = LOST` beside `control.held = false` and
    `completesTheCheck = false`. The observer is not wrong to write that -- its
    record is a log of what its own oracle computed -- but a document that carried
    the word LOST forward for a cell whose control fell would be reporting a
    finding built on a blind oracle. So the raw word is kept, under
    `rawRecordState`, and it is never the `state`. Keeping it rather than dropping
    it is deliberate: a reconciliation that discards what it reconciled cannot be
    audited.

 2. The apparatus word is CHOSEN. Section 3.1 fixes three: OK, UNSUPPORTED (the
    toolchain refused the invocation, so there was nothing to read) and
    BROKEN_MEASUREMENT (the invocation was accepted and no usable reading came
    back). A fallen control is BROKEN_MEASUREMENT and never UNSUPPORTED -- nothing
    was refused, the compiler did exactly as asked -- and this file will not invent
    a fourth word.

WHAT IS REFUSED RATHER THAN WRITTEN

 * An absolute host path anywhere in the document. interfaces.md section 5, and
    the refusal is total: this file does not redact, because a digest over a
    redacted line would name an invocation nobody ran. Same posture as
    build-ladder-frontier.py.
 * A non-integer number anywhere. Section 5 rule 4. A ratio is written as
    {"num": n, "den": d} and never divided.
 * A cell present in the records and absent from ../battery.json, or the reverse.
    The report is drawn over the cell table; a report whose cell set has drifted
    from the table is a comparison over something nobody declared.

EXIT CODES (interfaces.md section 7)
  0  the document was assembled
  3  it could not be: a missing input, a drifted standard, a cell set that does
     not match the table, or a document that would have carried a host path or a
     float. Never 0 with a warning.
"""

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(HERE, "..", "battery.json")
LAB = os.environ.get("VG_CAL_LAB", os.path.join(os.path.expanduser("~"), "vg-lab", "calibration"))

SCHEMA = "vibeguard.calibration-report/1"
GENERATOR_VERSION = 1

# interfaces.md section 3, verbatim. Not extended here: a component that needs a
# seventh reports that and the section is amended first.
KNOWN_STATES = ("PRESENT", "ABSENT", "LOST", "REINTRODUCED",
                "NOT_APPLICABLE", "NOT_OBSERVED")
# interfaces.md section 3.1, verbatim.
KNOWN_MEASUREMENTS = ("OK", "UNSUPPORTED", "BROKEN_MEASUREMENT")

FAILURE_DIRECTION = (
    "Fails towards refusing to report. Every path in this file that cannot decide "
    "something leaves exit 3 and no document, rather than a document with a gap in "
    "it, because a report that is missing a cell reads as a battery that is missing "
    "a cell rather than as an assembler that could not finish. The one place it "
    "fails towards a WORD rather than towards silence is the apparatus column: a "
    "cell whose control fell is BROKEN_MEASUREMENT with state NOT_OBSERVED, which "
    "is ungradeable by every consumer that handles section 3 correctly -- so an "
    "assembler bug there removes a cell from the numerator AND the denominator "
    "instead of turning it into a finding. What this file does NOT do is measure "
    "anything: every number in the document below came out of a record or a "
    "listing, and a disagreement between this document and those inputs is a bug "
    "in this file."
)


def integers_only(obj, path="/"):
    """Section 5 rule 4, walked to every depth. A float anywhere means the document
    could not have been canonicalised the way the section says, so its digest would
    be unverifiable. Refused rather than rounded into shape."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            integers_only(v, path + str(k) + "/")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            integers_only(v, path + "%d/" % i)
    elif isinstance(obj, bool):
        return
    elif isinstance(obj, float):
        raise ValueError("non-integer number %r at %s" % (obj, path))


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + "/" + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + "/%d" % i)
    elif isinstance(obj, str):
        yield path, obj


def canonical(obj):
    integers_only(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest_of(doc):
    stripped = {k: v for k, v in doc.items()
                if k not in ("context", "evidenceDigest")}
    return hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()


def read_json(path, what):
    if not os.path.exists(path):
        raise SystemExit3("no %s at %s" % (what, os.path.basename(path)))
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError) as exc:
        raise SystemExit3("%s is unreadable: %s" % (what, exc))


class SystemExit3(Exception):
    """A check that could not be completed. Always exit 3, never 0."""


def read_manifest(path):
    if not os.path.exists(path):
        raise SystemExit3("no manifest at %s" % os.path.basename(path))
    kv = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if "=" in line:
                k, _, v = line.partition("=")
                kv[k] = v
    return kv


def measurement_of(record):
    """The apparatus column for one record, and the reason for it.

    Read from `control.held` and from whether the record has a reading at all --
    never from `verdict.state`, which is the column this one exists to be separate
    from. Section 3.1: `BROKEN_MEASUREMENT` is a claim about the observer,
    `UNSUPPORTED` is a claim about the compiler. run-battery.sh never gets as far
    as a record when the compiler refused, so no record reaching this function can
    be UNSUPPORTED: that word is reachable in this directory only through a lane
    status, and inventing it here would blame the toolchain for something else.
    """
    control = record.get("control") or {}
    held = control.get("held")
    if held is False:
        return ("BROKEN_MEASUREMENT",
                "the co-resident control's count also fell to zero, so this cell "
                "cannot tell a removed effect from an oracle that stopped working "
                "(interfaces.md section 4)")
    if held is None:
        return ("BROKEN_MEASUREMENT",
                "the record does not say whether its control held; a cell that "
                "makes no claim about its control is not data")
    return ("OK", None)


def cell_facts(record, shape):
    """The counts, as integers, from the record's own two checkpoints.

    Which key carries the count depends on the polarity, and picking the wrong one
    would silently report zeros: `ir.forbidden-callee` fills `forbiddenCallSites`
    and leaves `effect` at zero, so a reader keyed on `effect` alone would report
    every forbidden cell as clean.
    """
    key = "forbiddenCallSites" if shape == "forbidden" else "effect"
    out = {}
    for side in ("subject", "control"):
        block = record.get(side) or {}
        for cp in ("preOptIr", "postOptIr"):
            facts = block.get(cp) or {}
            out["%s.%s" % (side, cp)] = {
                "count": int(facts.get(key, 0)),
                "effectCallSites": int(facts.get("effectCallSites", 0)),
                "zeroStores": int(facts.get("zeroStores", 0)),
                "forbiddenCallSites": int(facts.get("forbiddenCallSites", 0)),
                "liveConditionalBranches": int(facts.get("liveConditionalBranches", 0)),
                "allocaCount": int(facts.get("allocaCount", 0)),
                "allocaSizesBytes": [int(x) for x in (facts.get("allocaSizesBytes") or [])],
                "unitPresent": bool(facts.get("unitPresent", False)),
            }
    return out


CLANG_VERSION_RE = re.compile(r"clang version (\d+\.\d+\.\d+)")


def toolchain_block(manifest):
    """interfaces.md section 5's `toolchain`, from the manifest and nothing else.

    `digest` is documented there as "sha256 of the pinned set". This lane pins no
    package set, so the digest is taken over exactly the toolchain facts the run
    recorded -- the compiler's own version line and the observer plugin's digest --
    and `digestCovers` says so in the document. A digest whose inputs are not stated
    is a provenance claim a reader cannot check, and inventing a package list to fill
    the field would be worse: it would assert a pin that does not exist.

    `clang` is the parsed version number when the version line yields one, and the
    whole line otherwise. It is never left empty: an empty version string is the one
    value a downstream reader treats as "this document makes no claim about the
    compiler" and skips its checks over, which is how the manifest of a run that
    never found a compiler comes to read as the manifest of a run that did.
    """
    cc_version = manifest.get("ccVersion") or "absent"
    plugin_sha = manifest.get("pluginSha256") or "absent"
    m = CLANG_VERSION_RE.search(cc_version)
    covers = "the compiler version line and the observer plugin's sha-256, in that order"
    digest = hashlib.sha256(("%s\n%s\n" % (cc_version, plugin_sha)).encode("utf-8")).hexdigest()
    return {
        "cc": manifest.get("cc") or "absent",
        "clang": m.group(1) if m else cc_version,
        "ccVersionLine": cc_version,
        "pluginSha256": plugin_sha,
        "digest": digest,
        "digestCovers": covers,
        "packages": [],
        "packagesNote": "Empty because this lane pins no package set. Not a claim that none exist.",
    }


def witness_for(witness_doc, fixture_id):
    for r in (witness_doc.get("readings") or []):
        if r.get("fixtureId") == fixture_id:
            return r
    return None


def build(config_id):
    table = read_json(TABLE, "cell table")
    manifest = read_manifest(os.path.join(LAB, "configs", "%s.kv" % config_id))

    if manifest.get("rc") != "0":
        raise SystemExit3(
            "the manifest for %s records rc=%s (refusal=%r), so this configuration "
            "was not fully measured and a report over it would be a report over a "
            "partial run" % (config_id, manifest.get("rc"), manifest.get("refusal")))

    if manifest.get("generatorSha256") != table.get("generatorSha256"):
        raise SystemExit3(
            "calibration-standard-drifted: the run used generator %s and the table "
            "pins %s. A generator that changed is a different standard, and a report "
            "assembled across the two is comparable with nothing."
            % (manifest.get("generatorSha256"), table.get("generatorSha256")))

    witness_doc = read_json(os.path.join(LAB, "witness", "%s.json" % config_id),
                            "witness document")
    if witness_doc.get("configId") != config_id:
        raise SystemExit3(
            "the witness document is for configuration %r and this report is for %r"
            % (witness_doc.get("configId"), config_id))

    records_dir = os.path.join(LAB, "records", config_id)
    if not os.path.isdir(records_dir):
        raise SystemExit3("no records directory for %s" % config_id)
    on_disk = sorted(n[:-5] for n in os.listdir(records_dir) if n.endswith(".json"))
    declared = sorted(c["fixtureId"] for c in table["cells"])
    if on_disk != declared:
        only_disk = [x for x in on_disk if x not in declared]
        only_table = [x for x in declared if x not in on_disk]
        raise SystemExit3(
            "the records and the cell table do not cover the same cells "
            "(records-only=%s table-only=%s). The report is drawn over the table, so "
            "a drifted cell set is a report over something nobody declared."
            % (only_disk, only_table))

    cells = []
    ok = 0
    broken = 0
    for spec in table["cells"]:
        fid = spec["fixtureId"]
        record = read_json(os.path.join(records_dir, "%s.json" % fid), "record for %s" % fid)
        verdict = record.get("verdict") or {}
        raw_state = verdict.get("state")
        if raw_state not in KNOWN_STATES:
            raise SystemExit3(
                "%s: the record's verdict.state is %r, which is not one of the six "
                "states in interfaces.md section 3. An unrecognised word is refused "
                "rather than carried forward as an opaque string."
                % (fid, raw_state))

        measurement, why = measurement_of(record)
        if measurement not in KNOWN_MEASUREMENTS:
            raise SystemExit3("%s: %r is not a section 3.1 measurement word" % (fid, measurement))

        control = record.get("control") or {}
        if measurement == "OK":
            state = raw_state
            control_held = True
            completes = bool(verdict.get("completesTheCheck", False))
            ok += 1
        else:
            # The pairing rule, section 3.1: no reading came back, so there is no
            # property state to report and completesTheCheck is false.
            state = "NOT_OBSERVED"
            completes = False
            broken += 1
            # But `controlHeld` is NOT unconditionally null, and getting this wrong
            # was a real defect here rather than a style question.
            #
            # Section 3.1's sentence -- "controlHeld is null, not false, which would
            # claim a control was run and failed" -- reads as null-always, and this
            # file did that. compiler/envelope/fragility.mjs:306-316 and 366-386
            # disambiguate it, and they are the component that SCORES:
            #
            #   false  the control was measured and FAILED -> excluded as
            #          CONTROL_DID_NOT_HOLD
            #   null   no control was measured at all -> excluded as NOT_OBSERVED,
            #          and permitted only on a NOT_OBSERVED cell
            #
            # A known-broken cell here has a control that WAS measured and DID fall,
            # so `false` is the true answer and null misdescribes it as a control
            # nobody ran. fragility.mjs records what that costs: collapsing the two
            # "was misstating 16 of the 20 removals in the first real envelope this
            # ran on". The score is unaffected either way -- both are excluded -- but
            # the list of removals is part of what makes a denominator quotable.
            #
            # So the record's own claim is carried through: false when it says the
            # control fell, null only when it makes no control claim at all.
            raw_held = control.get("held")
            control_held = False if raw_held is False else None

        w = witness_for(witness_doc, fid)
        cell = {
            "fixtureId": fid,
            "shape": spec["shape"],
            "role": spec["role"],
            "class": spec["class"],
            "extractor": table["shapes"][spec["shape"]]["extractor"],
            "subjectUnit": spec["subjectFn"],
            "controlUnit": spec["controlFn"],
            "state": state,
            "measurement": measurement,
            "measurementReason": why,
            "controlHeld": control_held,
            "completesTheCheck": completes,
            # Kept, and never the `state`. See this file's header.
            "rawRecordState": raw_state,
            "rawRecordReason": verdict.get("reason"),
            "rawRecordControlHeld": control.get("held"),
            "counts": cell_facts(record, spec["shape"]),
            "recordDigest": record.get("evidenceDigest"),
            "witness": w if w is not None else {
                "readable": False,
                "reason": "no witness reading for this cell in the witness document",
            },
        }
        cells.append(cell)

    lanes = []
    for shape_id, shape in sorted(table["shapes"].items()):
        if shape.get("extractor") is None:
            lanes.append({
                "shape": shape_id,
                "laneStatus": shape.get("laneStatus", "no-probe"),
                "laneReason": shape.get("laneReason"),
                "whyNotUnsupported": shape.get("whyNotUnsupported"),
                "cellCount": 0,
                "specimens": sorted(s["fixtureId"] for s in table.get("unmeasuredSpecimens", [])
                                    if s["shape"] == shape_id),
            })
        else:
            lanes.append({
                "shape": shape_id,
                "laneStatus": "measured",
                "laneReason": None,
                "whyNotUnsupported": None,
                "cellCount": sum(1 for c in table["cells"] if c["shape"] == shape_id),
                "specimens": [],
            })

    doc = {
        "component": "CalibrationBattery",
        "schemaVersion": SCHEMA,
        "generatorVersion": GENERATOR_VERSION,
        "configId": config_id,
        "config": {
            "opt": manifest.get("opt"),
            "cc": manifest.get("cc"),
            "ccVersion": manifest.get("ccVersion"),
            "argvB64": manifest.get("argvB64"),
        },
        "standard": {
            "revision": int(manifest.get("standardRevision") or table["standardRevision"]),
            "generator": table["generator"],
            "generatorSha256": manifest.get("generatorSha256"),
            "pluginSha256": manifest.get("pluginSha256"),
        },
        # interfaces.md section 5: every record carries this OUTSIDE `context`. It was
        # missing from the first version of this document, which is exactly the kind of
        # omission `context` cannot cover for -- `context` holds what a re-run cannot
        # reproduce, and the identity of the compiler that produced a reading is the
        # opposite of that. `packages` is the empty list rather than a guess: no
        # package set is pinned for this lane, and an invented list would be a claim
        # about provenance nobody measured.
        "toolchain": toolchain_block(manifest),
        "cells": cells,
        "lanes": lanes,
        "tally": {
            "cells": len(cells),
            # A pair of integers, never a quotient. Section 5 rule 4.
            "measurementOk": {"num": ok, "den": len(cells)},
            "measurementBroken": {"num": broken, "den": len(cells)},
            "referenceCells": sum(1 for c in cells if c["role"] == "reference"),
            "instrumentLimitProbes": sum(1 for c in cells if c["role"] == "instrument-limit-probe"),
        },
        "failureDirection": FAILURE_DIRECTION,
        "whatThisDocumentDoesNotSay": [
            "Whether any reading is RIGHT. No known true value is opened by this "
            "file; claims/expected.json is read only by check-battery.py.",
            "Anything about a real subject. Every cell is a (synthetic-specimen, "
            "configuration) measurement, and a battery pass is a shape "
            "qualification that is necessary for promotion and never sufficient.",
            "Anything about a configuration other than this one, about a second "
            "vendor, about LTO, or about the object, linked or artifact "
            "checkpoints.",
        ],
        "context": {
            "generatedAt": int(manifest.get("sourceDateEpoch") or 0),
            "timeSource": "SOURCE_DATE_EPOCH",
            "sourceDateEpoch": int(manifest.get("sourceDateEpoch") or 0),
            "host": "unrecorded",
        },
    }

    # Section 5, and it is a refusal rather than a redaction. The predicate is the
    # same one check-envelope.py and check-ladder.py apply, so a document this file
    # would not write is not one they would accept.
    for path, text in walk_strings(doc):
        if path.startswith("/context/"):
            continue
        if (text.startswith("/") or "/root/" in text or "/home/" in text
                or re.search(r"[A-Za-z]:\\", text)):
            raise SystemExit3(
                "refusing to assemble: an absolute host path would enter the document "
                "at %s (%r). interfaces.md section 5 keeps host paths out of a digested "
                "document, and this file refuses rather than redacting, because a digest "
                "over a redacted string names an invocation nobody ran."
                % (path, text[:120]))

    try:
        doc["evidenceDigest"] = digest_of(doc)
    except ValueError as exc:
        raise SystemExit3("refusing to assemble: %s (interfaces.md section 5 rule 4)" % exc)
    return doc


def main(argv):
    out_path = None
    positional = []
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            out_path = argv[i + 1] if i + 1 < len(argv) else None
            i += 2
            continue
        if argv[i].startswith("-"):
            print("usage: build-battery-report.py <config-id> [--out <path>]", file=sys.stderr)
            return 3
        positional.append(argv[i])
        i += 1

    if len(positional) != 1:
        print("usage: build-battery-report.py <config-id> [--out <path>]", file=sys.stderr)
        return 3

    config_id = positional[0]
    try:
        doc = build(config_id)
    except SystemExit3 as exc:
        print("build-battery-report.py: %s" % exc, file=sys.stderr)
        return 3

    target = out_path or os.path.join(LAB, "_results", "calibration", "%s.json" % config_id)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")

    print("%s: %d cell(s), %d ok / %d broken measurement(s)"
          % (config_id, doc["tally"]["cells"],
             doc["tally"]["measurementOk"]["num"],
             doc["tally"]["measurementBroken"]["num"]))
    for lane in doc["lanes"]:
        if lane["laneStatus"] != "measured":
            print("  lane %s: %s (%s)" % (lane["shape"], lane["laneStatus"],
                                          ", ".join(lane["specimens"]) or "no specimens"))
    print("digest %s" % doc["evidenceDigest"][:16])
    print("assembled only -- no grading. check-battery.py decides.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
