#!/usr/bin/env python3
"""Hold each cell's reading against the battery's known true value.

    python3 check-battery.py [report.json | directory ...]

With no arguments, $VG_CAL_LAB/_results/calibration is graded.

This is the only file in the directory that opens claims/expected.json. The thing
that produces a reading does not hold the answers, and the thing that assembles a
document does not decide whether it is right; both of those are separate files and
the seam is the reason a reading can be graded at all.

WHAT IS GRADED, AND WHY EACH ONE IS AN INVARIANT RATHER THAN A READING

  * A REFERENCE cell reads its known true value. That is what makes it a reference
    cell. A disagreement is a defect in the extractor, and it is exit 2 -- a
    positive finding about the instrument, not an average to be taken over cells.

  * An INSTRUMENT-LIMIT PROBE is NOT graded here. Its true value and its expected
    reading differ on purpose, and the expected READING lives in
    claims/degradation-claims.json, which check-claims.py reads. Grading a probe
    here would either fail it for behaving exactly as documented, or -- worse --
    quietly promote its misreading into a true value. Both readings are printed
    and neither moves the exit code.

  * Section 3.1's PAIRING RULE holds on every cell: a cell whose measurement is
    not OK carries state NOT_OBSERVED and controlHeld null. This is a check on the
    ASSEMBLER rather than on the extractor, and it is here because the raw records
    do not obey the rule (an observer record carries verdict.state = LOST beside a
    fallen control) and build-battery-report.py is the only thing standing between
    that word and a reader.

  * A known-BROKEN cell reports BROKEN_MEASUREMENT where expected.json says so and
    OK where it does not. Both directions, and the second is the load-bearing one:
    a cell that reported a broken apparatus at every configuration would be
    indistinguishable from a harness that always says so.

  * Every cell in the report has an expectation, and every expectation matches a
    cell. A silently uncovered cell reads as a passing cell.

  * The document hashes to the digest it carries. This is a PRECONDITION, not one
    grade among several: grading a document that cannot be trusted is exactly "we
    did not look" reported as a finding.

WHAT IS NOT GRADED HERE

Whether the catalogue's degradationRisk prose agrees with the measurement. That is
check-claims.py, and it is a different question -- "is the instrument right" versus
"does the tracked description of the instrument's weaknesses match what the
instrument does" -- with a different failure meaning. A single file grading both
would let one of them go green behind the other.

NOT ESTABLISHED

Sixteen cells agreeing is also what a switched-off grader reports. So when the
whole set graded contains no BROKEN_MEASUREMENT at all, the result is printed as
NOT ESTABLISHED rather than as a pass: the apparatus column has never been seen to
fire, and the negative-controls doctrine in this tree says a run whose negatives
are clean and whose paired positive control is also clean is not a pass. That is
not an error, so it does not by itself change the exit code -- it changes what the
last line says, which is what a reader takes away.

EXIT CODES (interfaces.md section 7)
  0  every invariant held on every document read
  2  an invariant was falsified. A reference cell misread its true value, or the
     pairing rule was broken.
  3  a document could not be read or graded: missing, wrong schema, a digest that
     does not recompute, a cell with no expectation, or an expectDefinedInAsm
     declaration that disagrees with the listing in EITHER direction.

2 outranks 3 when both are present, and both are printed. A falsified invariant is
a positive finding; an ungradeable cell is an absence, and reporting the absence in
its place would hide the finding.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(HERE, "..", "battery.json")
EXPECTED = os.path.join(HERE, "..", "claims", "expected.json")
LAB = os.environ.get("VG_CAL_LAB", os.path.join(os.path.expanduser("~"), "vg-lab", "calibration"))
RESULTS = os.path.join(LAB, "_results", "calibration")

SCHEMA = "vibeguard.calibration-report/1"
KNOWN_STATES = ("PRESENT", "ABSENT", "LOST", "REINTRODUCED",
                "NOT_APPLICABLE", "NOT_OBSERVED")
KNOWN_MEASUREMENTS = ("OK", "UNSUPPORTED", "BROKEN_MEASUREMENT")


def integers_only(obj, path="/"):
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


def canonical(obj):
    integers_only(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest_of(doc):
    stripped = {k: v for k, v in doc.items() if k not in ("context", "evidenceDigest")}
    return hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()


def load_report(path):
    """Returns (document, why-it-cannot-be-read)."""
    if not os.path.exists(path):
        return None, "no document at %s" % path
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (ValueError, OSError) as exc:
        return None, "unreadable: %s" % exc
    if not isinstance(doc, dict):
        return None, "not a JSON object"
    if doc.get("schemaVersion") != SCHEMA:
        return None, ("schemaVersion %r is not %r; this file grades one shape and will "
                      "not guess at another" % (doc.get("schemaVersion"), SCHEMA))
    try:
        recomputed = digest_of(doc)
    except (ValueError, TypeError) as exc:
        return None, ("cannot be canonicalised, so its digest cannot be checked and "
                      "nothing in it can be trusted: %s" % exc)
    if recomputed != doc.get("evidenceDigest"):
        return None, ("digest mismatch: carries %r, recomputes to %r"
                      % (doc.get("evidenceDigest"), recomputed))
    if not doc.get("failureDirection"):
        return None, ("no failureDirection; a graded instrument that does not say which "
                      "way it fails cannot be read as one")
    if not isinstance(doc.get("cells"), list) or not doc["cells"]:
        return None, "no cells"
    if not isinstance(doc.get("lanes"), list) or not doc["lanes"]:
        return None, "no lanes; a lane that is absent from a document is not the same "\
                     "claim as a lane that declares itself unmeasurable"
    # interfaces.md section 5: every record carries `toolchain` OUTSIDE `context`.
    # Demanded here rather than assumed, because the first version of the assembler
    # omitted it and nothing noticed -- a document that does not name the compiler
    # that produced its readings is not one whose readings can be attributed, and an
    # empty version string is precisely what a reader treats as "makes no claim" and
    # skips its checks over.
    tc = doc.get("toolchain")
    if not isinstance(tc, dict):
        return None, ("no `toolchain` block outside `context`. interfaces.md section 5 "
                      "requires one on every record: `context` holds what a re-run "
                      "cannot reproduce, and the identity of the compiler that produced "
                      "a reading is the opposite of that")
    for field in ("clang", "digest"):
        if not isinstance(tc.get(field), str) or not tc[field]:
            return None, ("toolchain.%s is %r; section 5 names this field and an empty "
                          "one is read downstream as 'this document makes no claim about "
                          "the compiler'" % (field, tc.get(field)))
    return doc, None


def grade(name, doc, expectations, table, expected_measured_on=None):
    """Returns (problems, ungradeable, notes). Problems are exit 2."""
    problems = []
    ungradeable = []
    notes = []

    config_id = doc.get("configId")
    by_id = {c["fixtureId"]: c for c in doc["cells"]}
    exp_here = {e["fixtureId"]: e for e in expectations
                if e.get("configId") == config_id}

    # --- coverage, both directions ------------------------------------------
    for fid in sorted(by_id):
        if fid not in exp_here:
            ungradeable.append(
                "%s %s: no expectation for this cell in configuration %s. A cell with "
                "no known true value cannot be graded, and a grader that skipped it "
                "silently would report it as passing."
                % (name, fid, config_id))
    for fid in sorted(exp_here):
        if fid not in by_id:
            # A NOT_MEASURED_NO_PROBE expectation is SUPPOSED to have no cell: the
            # dominance shape has no extractor, so its answers were written before any
            # probe existed and nothing compiles those specimens. That is the lane's
            # whole argument -- a standard that pre-dates its probe only counts if the
            # answer key pre-dates it too -- so an absent cell here is the expected
            # state and not a coverage hole.
            #
            # The converse IS a problem and is checked below: such a cell arriving WITH
            # a reading means something measured a shape this directory says has no
            # instrument.
            if exp_here[fid].get("expectedMeasurement") == "NOT_MEASURED_NO_PROBE":
                notes.append(
                    "%s %s: answer recorded (%s) and deliberately not measured -- the dominance "
                    "shape has no extractor. Whoever writes one must make it read this answer key, "
                    "which was written on %s, before it existed."
                    % (name, fid, exp_here[fid].get("trueState"),
                       expected_measured_on or "an earlier date"))
                continue
            ungradeable.append(
                "%s %s: claims/expected.json declares a true value for this cell and the "
                "document does not carry it" % (name, fid))
    for fid in sorted(by_id):
        e = exp_here.get(fid)
        if e is not None and e.get("expectedMeasurement") == "NOT_MEASURED_NO_PROBE":
            problems.append(
                "%s %s: expected.json declares this cell NOT_MEASURED_NO_PROBE and the document "
                "carries a reading for it (state %r, measurement %r). Either an extractor was "
                "written for a shape this directory declares has none, or a cell was pointed at "
                "the wrong specimen. Both are findings and neither is a pass."
                % (name, fid, by_id[fid].get("state"), by_id[fid].get("measurement")))

    # --- the dominance lane is present and says what it is -------------------
    lanes = {lane["shape"]: lane for lane in doc["lanes"]}
    for shape_id, shape in table["shapes"].items():
        if shape.get("extractor") is None:
            lane = lanes.get(shape_id)
            if lane is None:
                ungradeable.append(
                    "%s: the %s lane is not in the document at all. It has no probe, and a "
                    "lane that is missing reads as a shape nobody thought about, which is a "
                    "different claim from a lane that declares it has no probe."
                    % (name, shape_id))
            elif lane.get("laneStatus") == "measured":
                problems.append(
                    "%s: the %s lane claims laneStatus 'measured' and %s has extractor null "
                    "in compiler/schema/properties.json. A lane cannot have measured "
                    "anything with nothing to measure it."
                    % (name, shape_id, shape_id))
            elif lane.get("cellCount") not in (0, None):
                problems.append(
                    "%s: the %s lane has no probe and reports %r cells"
                    % (name, shape_id, lane.get("cellCount")))

    # --- per cell ------------------------------------------------------------
    for fid in sorted(by_id):
        cell = by_id[fid]
        exp = exp_here.get(fid)
        state = cell.get("state")
        measurement = cell.get("measurement")

        if state not in KNOWN_STATES:
            problems.append("%s %s: state %r is not one of the six in interfaces.md "
                            "section 3" % (name, fid, state))
            continue
        if measurement not in KNOWN_MEASUREMENTS:
            problems.append("%s %s: measurement %r is not one of the three in "
                            "interfaces.md section 3.1" % (name, fid, measurement))
            continue

        # The pairing rule, on every cell regardless of role. A check on the
        # assembler: the raw records do not obey it and this is what stands between
        # a state invented for a measurement that did not happen and a reader.
        if measurement != "OK":
            if state != "NOT_OBSERVED":
                problems.append(
                    "%s %s: measurement is %s and state is %s. interfaces.md section 3.1's "
                    "pairing rule says a cell whose measurement is not OK carries state "
                    "NOT_OBSERVED, because no reading came back and any other state is a "
                    "verdict invented for a measurement that did not happen. The record's own "
                    "word was %r, which is exactly what must not be quoted here."
                    % (name, fid, measurement, state, cell.get("rawRecordState")))
            # `controlHeld` on a non-OK cell is NOT unconditionally null, and this
            # check asserted that it was. The authority is
            # compiler/envelope/fragility.mjs:306-316 and 366-386 -- the component
            # that scores -- which separates the two rather than merging them:
            # `false` is a control that was measured and FAILED
            # (CONTROL_DID_NOT_HOLD), `null` is a control nobody measured
            # (NOT_OBSERVED). A known-broken cell's control was measured and fell, so
            # `false` is the true answer, and demanding null here forced the assembler
            # to describe it as a control that never ran. fragility.mjs records that
            # collapsing the two misstated 16 of 20 removal reasons in a real
            # envelope. So what is graded is agreement with the RECORD's own claim.
            raw_held = cell.get("rawRecordControlHeld")
            wanted = False if raw_held is False else None
            if cell.get("controlHeld") is not wanted:
                problems.append(
                    "%s %s: measurement is %s, the record says its control %s, and the document "
                    "reports controlHeld=%r where %r is the true answer. fragility.mjs separates "
                    "these: false means a control was measured and failed, null means none was "
                    "measured, and the exclusion reason a consumer prints depends on which."
                    % (name, fid, measurement,
                       "FELL" if raw_held is False else "made no claim",
                       cell.get("controlHeld"), wanted))
            if cell.get("completesTheCheck") is not False:
                problems.append(
                    "%s %s: measurement is %s and completesTheCheck is %r"
                    % (name, fid, measurement, cell.get("completesTheCheck")))

        if exp is None:
            continue

        # --- the apparatus column, both directions --------------------------
        if measurement != exp["expectedMeasurement"]:
            problems.append(
                "%s %s: measurement is %s and claims/expected.json says %s. %s"
                % (name, fid, measurement, exp["expectedMeasurement"],
                   "A cell expected to be data was not."
                   if exp["expectedMeasurement"] == "OK" else
                   "A known-broken cell did not report a broken apparatus. Both directions "
                   "are graded because a cell that reported one at every configuration "
                   "would be indistinguishable from a harness that always says so."))

        # --- the state, for reference cells only ----------------------------
        if cell.get("role") == "reference":
            if state != exp["trueState"]:
                problems.append(
                    "%s %s: this is a REFERENCE cell. It reads %s and its known true value is "
                    "%s, established by %s. A reference cell that misreads its true value is a "
                    "defect in %s, and the repair is in the extractor -- never in this "
                    "expectation, which is the failure "
                    "compiler/eval/negative-controls/README.md names. Why the true value is "
                    "what it is: %s"
                    % (name, fid, state, exp["trueState"],
                       "+".join(exp.get("truthArgument") or ["nothing"]),
                       cell.get("extractor"), exp.get("whyTrue", "")[:400]))
        else:
            # Reported, never graded. See this file's header.
            notes.append(
                "%s %s: instrument-limit probe. true=%s measured=%s (%s). Graded by "
                "check-claims.py against the catalogue's own prose, not here."
                % (name, fid, exp["trueState"], state,
                   "the documented degradation is expressed at this configuration"
                   if state != exp["trueState"] else
                   "the documented degradation is NOT expressed at this configuration"))

        # --- the label declaration, when the expectation makes one ----------
        # A disagreement in EITHER direction is exit 3 and never a reading. "The
        # subject is not in the listing" and "the observer could not resolve the
        # subject" look identical in a record, and this declaration is what keeps
        # them apart; a declaration that has itself drifted keeps nothing apart.
        if "expectDefinedInAsm" in exp:
            w = cell.get("witness") or {}
            label = (w.get("labelPresent") or {}).get("subject")
            if label is None:
                ungradeable.append(
                    "%s %s: expected.json declares expectDefinedInAsm=%r and the witness "
                    "carries no labelPresent.subject reading to hold it against"
                    % (name, fid, exp["expectDefinedInAsm"]))
            elif bool(label) != bool(exp["expectDefinedInAsm"]):
                ungradeable.append(
                    "%s %s: expected.json declares the subject's label %s in the %s listing "
                    "and the witness reads it %s. Either the specimen no longer behaves as the "
                    "expectation describes, or the listing is of something else; in neither "
                    "case is this cell's state evidence of anything, so it is reported as a "
                    "check that could not be completed rather than as a reading."
                    % (name, fid,
                       "present" if exp["expectDefinedInAsm"] else "absent", config_id,
                       "present" if label else "absent"))

        # --- the frame declaration, when the expectation makes one ----------
        # Added because an adversarial pass found this leg COMPUTED and graded by
        # nothing: `expectDefinedInAsm` was the only witness declaration in
        # expected.json, so the reading carrying cal-wipe-napp's NOT_APPLICABLE was
        # a sentence rather than a check. Graded in both directions, because a
        # witness only ever seen to return one answer has not been shown to
        # distinguish anything. Exit 3 and not 2: a disagreement means the specimen
        # or the reader stopped behaving as the expectation describes, and then the
        # cell's state is not evidence either way.
        if "expectFrameRulesOutObject" in exp:
            w = cell.get("witness") or {}
            got = ((w.get("structural") or {}).get("frameRulesOutObject") or {}).get("verdict")
            if got is None:
                ungradeable.append(
                    "%s %s: expected.json declares expectFrameRulesOutObject=%r and the witness "
                    "carries no frameRulesOutObject verdict to hold it against"
                    % (name, fid, exp["expectFrameRulesOutObject"]))
            elif got != exp["expectFrameRulesOutObject"]:
                ungradeable.append(
                    "%s %s: expected.json declares the frame witness would read %r in the %s "
                    "listing and it reads %r. Note that %r is the reader DECLINING -- it means the "
                    "body writes %%rsp in a form the reader does not account for, so the "
                    "reservation is not bounded from there and no frame reading is evidence about "
                    "this object at all."
                    % (name, fid, exp["expectFrameRulesOutObject"], config_id, got, "undecidable"))

        # --- single-legged truths, counted rather than hidden ---------------
        legs = exp.get("truthArgument") or []
        if legs == ["construction"]:
            notes.append(
                "%s %s: SINGLE-LEGGED truth (construction only). Nothing outside the language "
                "semantics corroborates this cell's true value, and a battery that presented "
                "that as a two-legged truth would be overstating its own authority."
                % (name, fid))

    return problems, ungradeable, notes


def print_table(name, doc):
    print("=== %s ===" % name)
    cfg = doc.get("config") or {}
    std = doc.get("standard") or {}
    print("config %s   %s   %s" % (doc.get("configId"), cfg.get("opt"), cfg.get("ccVersion")))
    print("standard revision %s   generator %s"
          % (std.get("revision"), (std.get("generatorSha256") or "")[:12]))
    fmt = "%-22s %-8s %-22s %-16s %-18s %-6s %s"
    hdr = fmt % ("cell", "role", "shape/extractor", "state", "measurement", "ctl", "witness")
    print(hdr)
    print("-" * len(hdr))
    for cell in doc["cells"]:
        w = cell.get("witness") or {}
        wcell = ((w.get("effect") or {}).get("cell") or {}).get("state", "-")
        print(fmt % (cell["fixtureId"],
                     "ref" if cell["role"] == "reference" else "probe",
                     cell["shape"],
                     cell["state"],
                     cell["measurement"],
                     {True: "held", False: "FELL", None: "-"}[cell.get("controlHeld")],
                     wcell))
    t = doc.get("tally") or {}
    print("tally: %s cells, measurement OK %s/%s, broken %s/%s"
          % (t.get("cells"),
             (t.get("measurementOk") or {}).get("num"), (t.get("measurementOk") or {}).get("den"),
             (t.get("measurementBroken") or {}).get("num"), (t.get("measurementBroken") or {}).get("den")))
    for lane in doc["lanes"]:
        if lane["laneStatus"] != "measured":
            print("lane %s: %s -- %s" % (lane["shape"], lane["laneStatus"], lane.get("laneReason")))
    print()


def targets(argv):
    paths = argv or [RESULTS]
    out, missing = [], []
    for p in paths:
        if os.path.isdir(p):
            found = sorted(n for n in os.listdir(p) if n.endswith(".json"))
            if not found:
                missing.append("no calibration reports in %s" % p)
            out.extend(os.path.join(p, n) for n in found)
        elif os.path.exists(p):
            out.append(p)
        else:
            missing.append("no such path: %s" % p)
    return out, missing


def main(argv):
    for arg in argv:
        if arg.startswith("-"):
            print("usage: check-battery.py [report.json | directory ...]", file=sys.stderr)
            return 3

    try:
        with open(TABLE, "r", encoding="utf-8") as fh:
            table = json.load(fh)
        with open(EXPECTED, "r", encoding="utf-8") as fh:
            expected_doc = json.load(fh)
    except (ValueError, OSError) as exc:
        print("check-battery.py: cannot read the standard or its expectations: %s" % exc,
              file=sys.stderr)
        return 3

    expectations = expected_doc.get("expectations") or []
    if not expectations:
        print("check-battery.py: claims/expected.json declares no expectations, so every "
              "cell would pass vacuously", file=sys.stderr)
        return 3

    paths, ungradeable = targets(argv)
    if not paths and not ungradeable:
        print("nothing to grade", file=sys.stderr)
        return 3

    problems, notes = [], []
    graded = 0
    broken_seen = 0
    seen_configs = set()
    for path in paths:
        name = os.path.basename(path)
        doc, why = load_report(path)
        if doc is None:
            ungradeable.append("%s: %s" % (name, why))
            continue
        print_table(name, doc)
        p, u, n = grade(name, doc, expectations, table,
                        expected_doc.get('measuredOn'))
        problems.extend(p)
        ungradeable.extend(u)
        notes.extend(n)
        broken_seen += sum(1 for c in doc["cells"] if c["measurement"] != "OK")
        seen_configs.add(doc.get("configId"))
        graded += 1

    print("%d document(s) graded of %d found." % (graded, len(paths)))

    # Every configuration the STANDARD declares has to be present, and this is the
    # only consumer battery.json's `configs` axis has.
    #
    # It closes the second half of a rubber-stamp path that was measured rather than
    # imagined. A refused run now removes its own report, so a stale document can no
    # longer be graded as a fresh one -- but with the report gone, the remaining
    # configuration graded cleanly ON ITS OWN and this file exited 0. Half a battery
    # passing is worse than a stale one: the half that survived is the -O0 column,
    # where nothing is folded, no known-BROKEN cell fires and no discrimination this
    # standard exists to calibrate is exercised at all.
    #
    # Skipped when the caller named documents explicitly -- grading one file on
    # purpose is a legitimate act and is what the -O0-only demonstrations do; the
    # sweep of the results directory is the mode a caller trusts, so that is the mode
    # this fence guards.
    if not argv:
        declared = [c.get("configId") for c in (table.get("configs") or [])]
        missing = [c for c in declared if c not in seen_configs]
        if missing:
            ungradeable.append(
                "battery.json declares configuration(s) %s and no document for them was graded. "
                "A battery is the set of configurations the standard names: the discriminations it "
                "exists to calibrate live in the optimising column, so a sweep that found only the "
                "others is not this battery passing -- it is a shorter battery reported as a longer "
                "one. Re-run the missing configuration; a refused run deliberately leaves no report "
                "behind, so this is what a refusal looks like from here."
                % ", ".join(repr(m) for m in missing))

    if notes:
        print("\n%d note(s) -- reported, not graded:" % len(notes))
        for n in notes:
            print("  " + n)

    if problems:
        print("\n%d disagreement(s):" % len(problems), file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
    if ungradeable:
        print("\n%d thing(s) that could not be graded:" % len(ungradeable), file=sys.stderr)
        for u in ungradeable:
            print("  " + u, file=sys.stderr)

    if problems:
        return 2
    if ungradeable:
        return 3
    if graded == 0:
        print("no document was graded", file=sys.stderr)
        return 3

    if broken_seen == 0:
        # Not an error, and deliberately not an exit code. What it changes is the
        # last line, which is what a reader takes away.
        print("\nNOT ESTABLISHED: every cell in every document read reported "
              "measurement OK, so the apparatus column has never been seen to fire "
              "in this set. A battery whose known-broken cells were not exercised is "
              "indistinguishable from a harness that always reports OK. Grade a "
              "configuration in which the known-broken cells are expected to break "
              "before reading this as a qualification.")
        return 0

    print("\nall %d document(s) satisfy the invariants in this file: every reference cell "
          "read its known true value, and the apparatus column fired on %d cell(s), so "
          "this set is not a switched-off grader reporting silence." % (graded, broken_seen))
    print("A battery pass is a SHAPE qualification. It is necessary for promotion to "
          "`implemented` in compiler/schema/properties.json and never sufficient: every "
          "cell here is a (synthetic-specimen, configuration) measurement and says nothing "
          "about any real subject.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
