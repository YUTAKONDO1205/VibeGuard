#!/usr/bin/env python3
"""Grade a `vibeguard.metamorphic-report/1` document against the relations the
catalogue DECLARES.

Same rule as check-ladder.py, check-envelope.py and check-matrix.py, and for the
same reason: the invariants below are written from what the metamorphic relations
ARE, never transcribed from a run. A document that disagrees is printed as a
disagreement. THIS FILE IS NOT EDITED TO MAKE A RUN PASS -- if a cell lands off
its declared edge, the repair is the fixture or the catalogue's classification,
and either way the argument for the change belongs in the commit rather than in a
quietly relaxed predicate here. compiler/eval/negative-controls/README.md says the
same thing in its own words: never repair a false positive by adding a symbol to
an exception list or moving a threshold, because that makes the fixture green
while leaving the instrument exactly as broken, behind a tick.

WHAT IS GRADED, AND WHY EACH ONE IS AN INVARIANT RATHER THAN A READING

  * R1 INVARIANCE. A property-preserving transformation must not move the verdict.
    This is the half of the lane that can catch the other half lying: an R2
    operator that moves proves that SOMETHING moved, and only an R1 operator that
    stayed put shows it was the property rather than the spelling, the position,
    the buffer size or a neighbouring function. Any change on an R1 cell is exit 2.

  * R2 DECLARED DIRECTION, and only the direction the catalogue declared. A cell
    that moved along its edge PASSES; a cell that did not move is `not-expressed`
    and is counted and reported by name; a cell that landed anywhere else is
    `off-axis-landing` and is exit 2, because either the classification or the
    discriminator is wrong and either way it is a finding about the instrument.

  * NO TOTAL ORDER ON THE SIX STATES. Only R2b is graded on the two-point survival
    axis PRESENT > LOST. R2a lands on ABSENT, R2c lands on NOT_APPLICABLE, and the
    forbidden polarity has no survival axis at all -- so `survivalAxisGraded` must
    be true for R2b cells and false for every other class, re-derived here from the
    catalogue's own `class` field. Grading an R2c cell as a loss would report a lost
    REFERENT as a lost PROPERTY, which is the confusion interfaces.md section 3's
    last two rows exist to prevent, and it would do so in the direction that looks
    like a result.

  * THE PAIRING RULE, interfaces.md section 3.1. A side whose `measurement` is not
    OK must carry `state` NOT_OBSERVED and `completesTheCheck`
    false. Any other state on such a side is a verdict invented for a measurement
    that did not happen, and it is exit 2 rather than exit 3 because it is a claim
    the document makes rather than a reading it lacks.

  * EVERY MEASURED LANE CARRIES BOTH KINDS. A lane with R2 operators and no R1
    operator can report movement it cannot attribute. This is not a matter of
    coverage taste: it is the difference between "the mutation did this" and
    "something in this run did this".

  * A LANE-LEVEL DECLARED ABSENCE IS PART OF THE DOCUMENT. The dominance lane must
    be present, must carry a status and a reason naming property
    `survive.input-validation`, and must emit no cells. A document from which the
    declared absence has been deleted reads as a document about three shapes, and
    "we do not measure this" silently becoming "there was never a fourth shape" is
    the failure the lane status exists to prevent.

  * THE CROSS-VENDOR AGREEMENT WORDS, RE-DERIVED. `vendor-unreadable` is never
    folded into `vendors-split`; a split is data and never exit 2, because two
    compilers may legitimately differ. And a shape in which some comparison was
    unreadable must ALSO carry a readable comparison of the same shape in the same
    document -- otherwise "I could not look" is indistinguishable from "this oracle
    cannot read this shape at all", which is the shape of failure the
    negative-controls corpus refuses to accept as a result.

  * THE DOCUMENT'S OWN ARITHMETIC. `transition`, `transitionReadable` and the
    cross-vendor `tally` are recomputed from the cells and the readings under them.
    The builder assembles and this file decides; a checker that read the builder's
    verdict would be grading a claim rather than a measurement.

WHAT IS NOT GRADED HERE

Two runs are never compared. Whether the -O0 column differs from the -O2 column is
a separate question, and a health checker that also compared would make an
unhealthy document look like a difference between configurations. `not-expressed`
at -O0 and `pass` at -O2 for the same operator is the expected shape of this lane
and is not a disagreement between the two documents.

Nothing here is a claim about any real subject. Every specimen is generated.

Exit codes follow interfaces.md section 7:

  0  every document was read and every invariant held
  2  an invariant was falsified, or the document contradicts itself
  3  a document could not be looked at, or a cell could not be graded: a missing
     document, an unknown schemaVersion, a digest that does not recompute, a
     catalogue that has moved since the run, a side that produced no reading, a
     base that was not at its declared origin, or an invariance over a base that
     never established the property

2 outranks 3 when both are present, and both are printed. A falsified invariant is
a positive finding about the instrument; an ungradeable cell is an absence, and
reporting the absence in its place would hide the finding. Neither is 0.

Digest verification is a precondition and not one grade among several: a document
that does not hash to the value it carries is refused at 3 and its invariants are
not graded at all, because grading a document that cannot be trusted is exactly
"we did not look" reported as a finding.
"""

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOGUE = os.path.join(HERE, "..", "catalogue.json")
LAB = os.environ.get("VG_META_LAB", os.path.expanduser("~/vg-lab/metamorphic"))
REPORTS = os.environ.get("VG_META_OUT", os.path.join(LAB, "_results"))

SCHEMA = "vibeguard.metamorphic-report/1"
CATALOGUE_SCHEMA = "vibeguard.metamorphic-catalogue/1"

# interfaces.md section 3, verbatim. Restated here rather than imported, so that a
# document is checked by something other than the code that wrote it -- the same
# reason build-envelope.py reimplements the canonicaliser instead of calling the
# observer's.
KNOWN_STATES = ("PRESENT", "ABSENT", "LOST", "REINTRODUCED",
                "NOT_APPLICABLE", "NOT_OBSERVED")
MEASUREMENTS = ("OK", "UNSUPPORTED", "BROKEN_MEASUREMENT")

# The two-point survival axis, and nothing else. There is deliberately no total
# order on the six states here or anywhere in this lane.
SURVIVAL_AXIS = ("PRESENT", "LOST")

INVARIANT = "INVARIANT"
DIRECTION_RE = re.compile(r"^([A-Z_]+)->([A-Z_]+)$")

ASM_READABLE = ("PRESERVED", "LOST")
AGREE = "vendors-agree"
SPLIT = "vendors-split"
UNREADABLE = "vendor-unreadable"
CROSS_STATUSES = ("OK", "UNSUPPORTED", "NOT_DECLARED", "NOT_RUN")

PASS = "pass"
NOT_EXPRESSED = "not-expressed"
OFF_AXIS = "off-axis-landing"
ORIGIN_MISMATCH = "origin-mismatch"
VACUOUS = "vacuous-invariance"


def integers_only(obj, path="/"):
    """interfaces.md section 5 rule 4, walked to every depth. A float anywhere
    means the document could not have been canonicalised the way the section says,
    so its digest is unverifiable and the document is refused rather than rounded
    into shape."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            integers_only(v, path + str(k) + "/")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            integers_only(v, path + "%d/" % i)
    elif isinstance(obj, float):
        raise ValueError("non-integer number %r at %s" % (obj, path))


def canonical(obj):
    integers_only(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest_of(doc):
    stripped = {k: v for k, v in doc.items()
                if k not in ("context", "evidenceDigest")}
    return hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + "/" + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + "/%d" % i)
    elif isinstance(obj, str):
        yield path, obj


def load_catalogue():
    with open(CATALOGUE, "r", encoding="utf-8") as fh:
        cat = json.load(fh)
    if cat.get("schemaVersion") != CATALOGUE_SCHEMA:
        raise SystemExit("check-meta.py: the catalogue declares schemaVersion %r, "
                         "not %r" % (cat.get("schemaVersion"), CATALOGUE_SCHEMA))
    return cat


def load(path, catalogue_sha):
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
        return None, ("schemaVersion %r is not %r; this file grades one shape and "
                      "will not guess at another"
                      % (doc.get("schemaVersion"), SCHEMA))
    try:
        recomputed = digest_of(doc)
    except (ValueError, TypeError) as exc:
        return None, ("cannot be canonicalised, so its digest cannot be checked and "
                      "nothing in it can be trusted: %s" % exc)
    if recomputed != doc.get("evidenceDigest"):
        return None, ("digest mismatch: carries %r, recomputes to %r"
                      % (doc.get("evidenceDigest"), recomputed))
    if not doc.get("failureDirection"):
        return None, ("no failureDirection; a graded instrument that does not say "
                      "which way it fails cannot be read as one")
    carried = (doc.get("catalogue") or {}).get("sha256")
    if carried != catalogue_sha:
        return None, ("the document was assembled against a catalogue whose sha256 "
                      "was %r and the tracked catalogue hashes to %r. The declared "
                      "directions this file would grade against are not the ones "
                      "the run was measured against, so no comparison is made."
                      % (carried, catalogue_sha))
    if not isinstance(doc.get("cells"), list) or not doc["cells"]:
        return None, "no cells; there is nothing to grade"
    if not isinstance(doc.get("lanes"), list) or not doc["lanes"]:
        return None, "no lanes; a document without its lane statuses cannot be read"
    return doc, None


def grade_cell(cell, op):
    """One cell, against the direction the CATALOGUE declares -- never against the
    direction the document carries, which is a copy that could have drifted.

    Returns (word, detail).
    """
    declared = op["declaredDirection"]
    base = cell["base"]["state"]
    mutant = cell["mutant"]["state"]

    # When the catalogue sets `gradeOn`, that COUNT pair is what is graded.
    #
    # The default pair above is the two VERDICTS, and a verdict is computed across
    # both checkpoints. For an introduction question on the must-not-appear
    # polarity that is the wrong object: F-R2S-PRINTF's mutant holds one forbidden
    # `printf` at pre-opt-ir and none after the pass, because clang rewrote the
    # call to `puts`, and section 3 spells that pair LOST -- a must-survive word on
    # a must-not-appear question. Grading it would report a forbidden call
    # DISAPPEARING as a finding against the instrument.
    #
    # Read at the declared checkpoint the same cell is ABSENT -> PRESENT at both
    # -O0 and -O2, which is the edge the catalogue states, so the cell is graded
    # instead of excused. The alternative in the tree before this was
    # `graded: false` on the operator, and that is an off switch with no condition
    # attached: nothing about that cell could ever be falsified again.
    #
    # It is an explicit opt-in and never inferred. The first version of this read
    # `checkpointRead`, which R2b and R2c operators also set to a single checkpoint
    # to document where their loss becomes visible; that collapsed their
    # PRESENT->LOST and PRESENT->NOT_APPLICABLE edges into PRESENT/ABSENT and sent
    # five correct cells off-axis. A single checkpoint can say PRESENT or ABSENT and
    # cannot say LOST or NOT_APPLICABLE, so those classes are refused below rather
    # than graded against a reading that could never reach their declared target.
    at_checkpoint = cell.get("transitionAtDeclaredCheckpoint")
    if at_checkpoint is not None:
        if op["class"] in ("R2b", "R2c"):
            return OFF_AXIS, (
                "the catalogue sets gradeOn=%r on a class %s operator. One checkpoint "
                "can only say PRESENT or ABSENT, and this class's declared edge ends "
                "on %s, which is a claim about a change BETWEEN checkpoints and is "
                "unreachable from one. The catalogue is wrong about this operator's "
                "gradeOn or about its class."
                % (op.get("gradeOn"), op["class"], declared))
        parts = at_checkpoint.split("->")
        if len(parts) == 2:
            base, mutant = parts[0], parts[1]

    if declared == INVARIANT:
        # An invariance over a base that never established the property is
        # invariance over nothing. It is exit 3 and not exit 2 because no
        # expectation was falsified: the relation was applied where it has no
        # subject, which is a fixture fault and, per the negative-controls README,
        # is fixed in the fixture and never in the expectation.
        if op["shape"] != "forbidden" and base != "PRESENT":
            return VACUOUS, ("the base reads %s rather than PRESENT, so the mutant "
                             "agreeing with it says nothing about the relation"
                             % base)
        if op["shape"] == "forbidden" and base not in ("PRESENT", "ABSENT"):
            return VACUOUS, ("the base reads %s, which is neither a hit nor a clean "
                             "reading for this polarity" % base)
        if base == mutant:
            return PASS, "the verdict did not move (%s on both sides)" % base
        return OFF_AXIS, ("the verdict moved %s -> %s under a property-PRESERVING "
                          "transformation. Something other than the property is "
                          "being read." % (base, mutant))

    m = DIRECTION_RE.match(declared)
    if not m:
        return OFF_AXIS, ("the catalogue declares direction %r, which is neither "
                          "INVARIANT nor an X->Y pair" % declared)
    origin, target = m.group(1), m.group(2)
    if origin not in KNOWN_STATES or target not in KNOWN_STATES:
        return OFF_AXIS, ("the catalogue declares %r and one of its two words is "
                          "not among the six in interfaces.md section 3" % declared)

    if base != origin:
        return ORIGIN_MISMATCH, ("the declared direction starts at %s and the base "
                                 "reads %s, so the mutant's landing cannot be "
                                 "attributed to the mutation" % (origin, base))
    if mutant == target:
        return PASS, "moved along its declared edge %s -> %s" % (origin, target)
    if mutant == origin:
        return NOT_EXPRESSED, ("the cell did not move; the compiler did not take "
                               "the bait at this configuration. Counted, not "
                               "dropped.")
    return OFF_AXIS, ("declared %s -> %s and landed on %s. Either the catalogue's "
                      "classification of this operator or the extractor's "
                      "discriminator is wrong, and either way it is a finding."
                      % (origin, target, mutant))


def rederive_agreement(cmp_row):
    """The three words, recomputed from the per-vendor readings the document
    carries. The builder computed them too; a disagreement between the two is the
    disagreement."""
    per = cmp_row.get("vendors") or []
    if not per:
        return None, None, "the comparison carries no vendor readings"
    unreadable = []
    transitions = []
    for v in per:
        b = (v.get("base") or {}).get("state")
        m = (v.get("mutant") or {}).get("state")
        if b in ASM_READABLE and m in ASM_READABLE:
            transitions.append("%s->%s" % (b, m))
        else:
            unreadable.append(v.get("vendorId"))
    if unreadable:
        side = "both" if len(unreadable) == len(per) else unreadable[0]
        return UNREADABLE, side, None
    return (AGREE if len(set(transitions)) == 1 else SPLIT), None, None


def grade(name, doc, cat):
    """Returns (problems, ungradeable, grades). Problems are exit 2; ungradeable
    cells are exit 3."""
    problems = []
    ungradeable = []
    grades = {}

    ops = {op["operatorId"]: op for op in cat["operators"]}
    measured_ops = [op for op in cat["operators"] if op.get("measured") is not False]

    # --- format rules, the same predicate the builder refuses on ---------------
    # Over every string, prose included. Under /run/extraArgs the strings are
    # command-line tokens rather than prose, so the stricter token rule applies
    # there: a document the writer would not have written must not be one the
    # reader accepts.
    for path, text in walk_strings(doc):
        absolute = (text.startswith("/") or "/root/" in text
                    or "/home/" in text or ":\\" in text)
        if not absolute and path.startswith("/run/extraArgs"):
            _head, sep, tail = text.partition("=")
            absolute = ((sep and tail.startswith("/"))
                        or bool(re.match(r"^-[A-Za-z]{1,2}/", text)))
        if absolute:
            problems.append("%s: absolute path at %s: %r" % (name, path, text[:120]))

    # --- the cell set is the catalogue's measured operator set, in order --------
    got = [c.get("operatorId") for c in doc["cells"]]
    want = [op["operatorId"] for op in measured_ops]
    if got != want:
        problems.append(
            "%s: the document's cells are %s and the catalogue's measured operators "
            "are %s. A document over a different operator set is a document from a "
            "different instrument, and grading it against these declared directions "
            "would be grading the wrong relations." % (name, got, want))

    # --- per cell --------------------------------------------------------------
    for cell in doc["cells"]:
        op_id = cell.get("operatorId")
        op = ops.get(op_id)
        if op is None:
            problems.append("%s: cell %r names an operator the catalogue does not "
                            "declare" % (name, op_id))
            continue

        # The pairing rule, interfaces.md section 3.1, on both sides.
        for side_name in ("base", "mutant"):
            side = cell.get(side_name) or {}
            meas = side.get("measurement")
            if meas not in MEASUREMENTS:
                problems.append("%s %s/%s: measurement %r is not one of the three "
                                "in interfaces.md section 3.1"
                                % (name, op_id, side_name, meas))
                continue
            if side.get("state") not in KNOWN_STATES:
                problems.append("%s %s/%s: state %r is not one of the six in "
                                "interfaces.md section 3"
                                % (name, op_id, side_name, side.get("state")))
            if meas != "OK":
                if side.get("state") != "NOT_OBSERVED":
                    problems.append(
                        "%s %s/%s: measurement is %s and state is %r. interfaces.md "
                        "section 3.1's pairing rule says such a side carries "
                        "NOT_OBSERVED; any other state is a verdict invented for a "
                        "measurement that did not happen."
                        % (name, op_id, side_name, meas, side.get("state")))
                # NOT null-always, and this check asserted it was. The authority is
                # compiler/envelope/fragility.mjs:306-316 and 366-386: `false` is a
                # control that was measured and FAILED (excluded as
                # CONTROL_DID_NOT_HOLD), `null` is a control nobody measured (excluded
                # as NOT_OBSERVED). A side whose control fell must say `false`, or a
                # consumer prints the wrong removal reason -- fragility.mjs records
                # that merging the two misstated 16 of 20 removals in a real envelope.
                fell = side.get("controlEffectPost") == 0 and side.get("controlEffectPre") not in (None, 0)
                wanted = False if fell else None
                if side.get("controlHeld") is not wanted:
                    problems.append(
                        "%s %s/%s: measurement is %s, the control %s, and controlHeld is %r "
                        "where %r is the true answer. false means a control was measured and "
                        "failed; null means none was measured, and the exclusion reason a "
                        "consumer prints depends on which."
                        % (name, op_id, side_name, meas,
                           "fell (%s -> %s)" % (side.get("controlEffectPre"),
                                                side.get("controlEffectPost"))
                           if fell else "made no claim",
                           side.get("controlHeld"), wanted))
                if side.get("completesTheCheck") is not False:
                    problems.append(
                        "%s %s/%s: measurement is %s and completesTheCheck is %r; "
                        "section 3.1 requires false"
                        % (name, op_id, side_name, meas,
                           side.get("completesTheCheck")))

        # The document's own arithmetic, recomputed.
        readable = ((cell.get("base") or {}).get("measurement") == "OK"
                    and (cell.get("mutant") or {}).get("measurement") == "OK")
        if bool(cell.get("transitionReadable")) != readable:
            problems.append(
                "%s %s: transitionReadable says %r and this file recomputes %r from "
                "the two measurements under it"
                % (name, op_id, cell.get("transitionReadable"), readable))
        expected_transition = ("%s->%s" % ((cell.get("base") or {}).get("state"),
                                           (cell.get("mutant") or {}).get("state"))
                               if readable else None)
        if cell.get("transition") != expected_transition:
            problems.append(
                "%s %s: transition says %r and the two states under it say %r. The "
                "transition is the object a relation is about, so one that has "
                "drifted from its sides is a relation read over nothing."
                % (name, op_id, cell.get("transition"), expected_transition))

        # The single-checkpoint transition, recomputed from the counts rather than
        # read from the document. This one is graded against for the operators whose
        # catalogue entry names one checkpoint, so a copy that had drifted would
        # move a verdict -- the assembler assembles and this file decides, and that
        # only holds while this file derives the object it grades.
        cp_key = {"count-at-pre-opt-ir": "effectPre",
                  "count-at-after-pass": "effectPost"}.get(op.get("gradeOn"))
        if cp_key is None or not readable:
            expected_at_cp = None
        else:
            got = []
            for side_name in ("base", "mutant"):
                count = (cell.get(side_name) or {}).get(cp_key)
                if not isinstance(count, int):
                    got = None
                    break
                got.append("PRESENT" if count > 0 else "ABSENT")
            expected_at_cp = "%s->%s" % (got[0], got[1]) if got else None
        if cell.get("transitionAtDeclaredCheckpoint") != expected_at_cp:
            problems.append(
                "%s %s: transitionAtDeclaredCheckpoint says %r and this file "
                "recomputes %r from the %s counts under it. That field is what this "
                "operator is GRADED against, so a drifted copy of it moves a verdict."
                % (name, op_id, cell.get("transitionAtDeclaredCheckpoint"),
                   expected_at_cp, op.get("gradeOn")))

        # The axis, re-derived from the catalogue's class rather than read from the
        # document. Only R2b sits on the two-point survival axis.
        on_axis = op["class"] == "R2b"
        if bool(cell.get("survivalAxisGraded")) != on_axis:
            problems.append(
                "%s %s: survivalAxisGraded says %r and class %s puts it %s the "
                "survival axis. Only R2b is graded PRESENT > LOST; ABSENT, "
                "NOT_APPLICABLE and the forbidden polarity are off it, and grading "
                "one of those as a loss would report a lost referent or a clean "
                "reading as a lost property."
                % (name, op_id, cell.get("survivalAxisGraded"), op["class"],
                   "on" if on_axis else "off"))
        if op["class"] == "R2c":
            if not (op["declaredDirection"] or "").endswith("NOT_APPLICABLE"):
                problems.append(
                    "%s %s: class R2c and declaredDirection %r. R2c is the "
                    "referent-removing class and its edge must end on "
                    "NOT_APPLICABLE." % (name, op_id, op["declaredDirection"]))
            if not op.get("notMonotonicWhen"):
                problems.append(
                    "%s %s: class R2c and no notMonotonicWhen. This is the named "
                    "class that must not be read as monotonicity, and the document "
                    "has to say so where a reader will see it."
                    % (name, op_id))
        if bool(cell.get("notMonotonic")) != (op.get("notMonotonicWhen") is not None):
            problems.append(
                "%s %s: notMonotonic says %r and the catalogue %s a notMonotonicWhen"
                % (name, op_id, cell.get("notMonotonic"),
                   "carries" if op.get("notMonotonicWhen") else "carries no"))

        if not op.get("graded"):
            grades[op_id] = ("reported-as-data",
                             op.get("whyUngraded") or "declared ungraded")
            continue
        if not readable:
            ungradeable.append(
                "%s %s: %s" % (name, op_id,
                               (cell.get("base") or {}).get("brokenReason")
                               or (cell.get("mutant") or {}).get("brokenReason")
                               or "a side produced no reading"))
            grades[op_id] = ("unreadable", "a side produced no reading")
            continue

        word, detail = grade_cell(cell, op)
        grades[op_id] = (word, detail)
        if word == OFF_AXIS:
            problems.append("%s %s: %s" % (name, op_id, detail))
        elif word in (ORIGIN_MISMATCH, VACUOUS):
            ungradeable.append("%s %s (%s): %s" % (name, op_id, word, detail))

    # --- every measured lane carries an R1 falsifier and an R2 mover -----------
    for lane in doc["lanes"]:
        if lane.get("status") != "MEASURED":
            continue
        shape = lane.get("shape")
        classes = {ops[c["operatorId"]]["class"]
                   for c in doc["cells"]
                   if c.get("operatorId") in ops and c.get("shape") == shape
                   and ops[c["operatorId"]].get("graded")}
        has_r1 = any(k.startswith("R1") for k in classes)
        has_r2 = any(k.startswith("R2") for k in classes)
        if not has_r1:
            problems.append(
                "%s: lane %s is MEASURED and carries no graded R1 operator. An R2 "
                "operator that moves proves that something moved; only an R1 "
                "operator that stayed put shows it was the property. A lane without "
                "one reports movement it cannot attribute."
                % (name, lane.get("laneId")))
        if not has_r2:
            problems.append(
                "%s: lane %s is MEASURED and carries no graded R2 operator, so "
                "nothing in it can move at all and its invariances are unfalsifiable "
                "in this document" % (name, lane.get("laneId")))

    # --- the lane-level declared absences are part of the document -------------
    lanes_by_id = {l.get("laneId"): l for l in doc["lanes"]}
    for lane in cat["lanes"]:
        got_lane = lanes_by_id.get(lane["laneId"])
        if got_lane is None:
            problems.append(
                "%s: the catalogue declares lane %s and the document has no such "
                "lane. A declared absence deleted from a document reads as a shape "
                "that was never there, which is a different fact from one nothing "
                "can measure." % (name, lane["laneId"]))
            continue
        if got_lane.get("status") != lane["status"]:
            problems.append("%s: lane %s carries status %r and the catalogue "
                            "declares %r"
                            % (name, lane["laneId"], got_lane.get("status"),
                               lane["status"]))
        if lane.get("emitsCells") is False:
            if got_lane.get("cellsEmitted") != 0:
                problems.append(
                    "%s: lane %s declares emitsCells false and the document reports "
                    "%r cells for it. N cells of NOT_OBSERVED read as a measurement "
                    "somebody skipped, which is a different fact from a measurement "
                    "nothing can take."
                    % (name, lane["laneId"], got_lane.get("cellsEmitted")))
            if not got_lane.get("statusReason"):
                problems.append("%s: lane %s emits no cells and carries no "
                                "statusReason" % (name, lane["laneId"]))
            elif lane.get("propertyId") and lane["propertyId"] not in (
                    got_lane.get("statusReason") or ""):
                problems.append(
                    "%s: lane %s's statusReason does not name property %s. A "
                    "deferred lane has to name the property whose extractor is "
                    "missing, or the absence in the document is not attributable "
                    "to anything." % (name, lane["laneId"], lane["propertyId"]))
        elif got_lane.get("cellsEmitted", 0) <= 0:
            problems.append("%s: lane %s emits cells and the document reports %r"
                            % (name, lane["laneId"], got_lane.get("cellsEmitted")))

    # --- the cross-vendor channel ---------------------------------------------
    cross = doc.get("crossVendor")
    if not isinstance(cross, dict):
        problems.append("%s: no crossVendor block. A channel the catalogue declares "
                        "and the document omits is a comparison nobody was told was "
                        "not made." % name)
    else:
        status = cross.get("status")
        if status not in CROSS_STATUSES:
            problems.append("%s: crossVendor.status %r is not one of %s"
                            % (name, status, "/".join(CROSS_STATUSES)))
        if status != "OK" and not cross.get("statusReason"):
            problems.append("%s: crossVendor.status is %r and there is no "
                            "statusReason" % (name, status))
        comparisons = cross.get("comparisons") or []
        if status == "OK" and not comparisons:
            problems.append("%s: crossVendor.status is OK and there are no "
                            "comparisons" % name)
        tally = {AGREE: 0, SPLIT: 0, UNREADABLE: 0}
        readable_shapes = set()
        unreadable_shapes = {}
        shape_of = {c["operatorId"]: c.get("shape") for c in doc["cells"]}
        for row in comparisons:
            op_id = row.get("operatorId")
            word, side, why = rederive_agreement(row)
            if word is None:
                problems.append("%s crossVendor %s: %s" % (name, op_id, why))
                continue
            tally[word] = tally.get(word, 0) + 1
            if row.get("agreement") != word:
                problems.append(
                    "%s crossVendor %s: the document says %r and this file "
                    "recomputes %r from the readings under it. The builder computes "
                    "the word and this file decides; a disagreement between them is "
                    "the disagreement." % (name, op_id, row.get("agreement"), word))
            if word == UNREADABLE:
                if row.get("unreadableSide") != side:
                    problems.append(
                        "%s crossVendor %s: unreadableSide says %r and the readings "
                        "say %r" % (name, op_id, row.get("unreadableSide"), side))
                unreadable_shapes.setdefault(shape_of.get(op_id), []).append(op_id)
            else:
                if row.get("unreadableSide") is not None:
                    problems.append(
                        "%s crossVendor %s: the comparison is %s and carries "
                        "unreadableSide %r; a readable comparison names no "
                        "unreadable side"
                        % (name, op_id, word, row.get("unreadableSide")))
                readable_shapes.add(shape_of.get(op_id))
        if cross.get("tally") != tally:
            problems.append(
                "%s: crossVendor.tally is %r and this file recomputes %r"
                % (name, cross.get("tally"), tally))
        # The negative-controls doctrine, one layer out: an unreadable comparison
        # with no readable comparison of the same shape beside it in the same run is
        # indistinguishable from an oracle that cannot read that shape at all.
        for shape, op_ids in sorted(unreadable_shapes.items()):
            if shape not in readable_shapes:
                ungradeable.append(
                    "%s: crossVendor has %d unreadable comparison(s) of shape %s "
                    "(%s) and no readable comparison of that shape in the same "
                    "document. 'I could not look' is then indistinguishable from "
                    "'this oracle cannot read this shape at all', so the unreadable "
                    "readings carry no information and no witness contradicts that."
                    % (name, len(op_ids), shape, ",".join(sorted(op_ids))))

    return problems, ungradeable, grades


def print_table(name, doc, cat, grades):
    ops = {op["operatorId"]: op for op in cat["operators"]}
    run = doc.get("run") or {}
    tc = doc.get("toolchain") or {}
    print("=== %s ===" % name)
    print("run %s   %s"
          % (run.get("id"),
             " ".join([run.get("opt", "")] + list(run.get("extraArgs") or []))))
    print("catalogue %s   generator %s/%s   %s clang %s   plugin %s"
          % ((doc.get("catalogue") or {}).get("sha256", "")[:12],
             (doc.get("generator") or {}).get("version"),
             ((doc.get("generator") or {}).get("sha256") or "")[:12],
             tc.get("cc"), tc.get("clang"),
             (tc.get("pluginSha256") or "absent")[:12]))

    fmt = "%-17s %-13s %-24s %-22s %-16s %s"
    hdr = fmt % ("operator", "class", "declared", "measured", "grade", "axis")
    print(hdr)
    print("-" * len(hdr))
    for cell in doc["cells"]:
        op_id = cell["operatorId"]
        word, _detail = grades.get(op_id, ("-", ""))
        print(fmt % (op_id, ops[op_id]["class"] if op_id in ops else "?",
                     ops[op_id]["declaredDirection"] if op_id in ops else "?",
                     cell.get("transition") or "unreadable",
                     word,
                     "survival" if cell.get("survivalAxisGraded") else "off-axis"))

    counts = {}
    for word, _d in grades.values():
        counts[word] = counts.get(word, 0) + 1
    print("grades: " + ", ".join("%s=%d" % kv for kv in sorted(counts.items())))

    cross = doc.get("crossVendor") or {}
    print("cross-vendor %s: %s"
          % (cross.get("status"),
             ", ".join("%s=%d" % kv
                       for kv in sorted((cross.get("tally") or {}).items()))))
    for row in cross.get("comparisons") or []:
        if row.get("agreement") == AGREE:
            continue
        print("  %-16s %-18s %s"
              % (row.get("operatorId"), row.get("agreement"),
                 "; ".join("%s %s" % (v.get("vendorId"),
                                      v.get("transition")
                                      or "%s->%s" % ((v.get("base") or {}).get("state"),
                                                     (v.get("mutant") or {}).get("state")))
                           for v in row.get("vendors") or [])))
    for lane in doc.get("lanes") or []:
        if lane.get("status") != "MEASURED":
            print("lane %s: %s (%d cell(s)) -- %s"
                  % (lane.get("laneId"), lane.get("status"),
                     lane.get("cellsEmitted"), lane.get("statusReason", "")[:150]))
    print()


def targets(argv):
    paths = argv or [REPORTS]
    out = []
    missing = []
    for p in paths:
        if os.path.isdir(p):
            found = sorted(n for n in os.listdir(p) if n.endswith(".json"))
            if not found:
                missing.append("no report documents in %s" % p)
            out.extend(os.path.join(p, n) for n in found)
        elif os.path.exists(p):
            out.append(p)
        else:
            missing.append("no such path: %s" % p)
    return out, missing


def usage():
    print("usage: check-meta.py [report.json | directory ...]", file=sys.stderr)
    print("  with no arguments, $VG_META_OUT is graded", file=sys.stderr)
    return 1


def main(argv):
    for arg in argv:
        if arg.startswith("-"):
            return usage()

    cat = load_catalogue()
    catalogue_sha = sha256_file(CATALOGUE)

    paths, ungradeable = targets(argv)
    if not paths and not ungradeable:
        print("nothing to grade", file=sys.stderr)
        return 3

    problems = []
    graded = 0
    for path in paths:
        name = os.path.basename(path)
        doc, why = load(path, catalogue_sha)
        if doc is None:
            ungradeable.append("%s: %s" % (name, why))
            continue
        p, u, grades = grade(name, doc, cat)
        print_table(name, doc, cat, grades)
        problems.extend(p)
        ungradeable.extend(u)
        graded += 1

    print("%d document(s) graded of %d found." % (graded, len(paths)))

    if problems:
        print("\n%d disagreement(s):" % len(problems), file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
    if ungradeable:
        print("\n%d thing(s) that could not be graded:" % len(ungradeable),
              file=sys.stderr)
        for u in ungradeable:
            print("  " + u, file=sys.stderr)

    if problems:
        return 2
    if ungradeable:
        return 3
    if graded == 0:
        print("no document was graded", file=sys.stderr)
        return 3
    print("all %d document(s) satisfy the relations declared in catalogue.json."
          % graded)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
