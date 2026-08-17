#!/usr/bin/env python3
"""Assemble one `vibeguard.metamorphic-report/1` document from the records one
metamorphic run produced.

It ASSEMBLES. It does not grade -- check-meta.py grades -- and it does not
measure: run-metamorphic.sh measures. The same three-way split as
run-ladder.sh / build-ladder-frontier.py / check-ladder.py, for the same reason a
component that decides whether its own reading is good is not a measurement.

WHAT THE DOCUMENT IS FOR

A metamorphic relation is a statement about a PAIR of programs, and neither
record in a pair carries the other. This file is the one place the two are put
beside each other and turned into a TRANSITION -- the object a relation is
actually about. It writes the transition and stops there. Whether the transition
is the one the catalogue declared is a separate question with a separate file,
because a component that both produced the comparison and graded it could not be
shown to have graded it honestly.

THE ONE DECISION THIS FILE DOES MAKE, AND WHY IT IS NOT GRADING

interfaces.md section 3.1's PAIRING RULE is applied here rather than left to a
reader: a cell whose `measurement` is not OK carries `state` NOT_OBSERVED,
`controlHeld` null and `completesTheCheck` false. That is not a verdict about the
relation, it is the refusal to write one -- the section says in as many words that
any other state on such a cell is "a verdict invented for a measurement that did
not happen".

`controlHeld` distinguishes two things section 3.1's own sentence reads as one, and
this file got it wrong first. `false` means the control WAS measured and FELL;
`null` means no control was measured at all. compiler/envelope/fragility.mjs -- the
component that scores -- separates them at :306-316 and :366-386, excluding the
first as CONTROL_DID_NOT_HOLD and the second as NOT_OBSERVED, and it records what
merging them cost: "misstating 16 of the 20 removals in the first real envelope this
ran on". The score is unaffected either way, since both are excluded; the LIST OF
REMOVALS is not, and that list is part of what makes a denominator quotable. So a
fallen control here is `false`, with `brokenReason` and the raw
`controlEffectPre` / `controlEffectPost` counts beside it.

The agreement word for the cross-vendor channel is computed here for the same
reason frontier-match.mjs computes its three words in one place: two callers that
each implemented "are these two readings the same reading" would drift on exactly
the case that matters, the one nobody could read. check-meta.py RE-DERIVES the
word from the per-vendor transitions in the document and reports a disagreement
between the two as the disagreement -- the builder assembles and the checker
decides.

WHAT IT READS

  $VG_META_LAB/runs/<run-id>.kv                   the manifest the producer wrote
  $VG_META_LAB/records/<run-id>/ir/<op>.{base,mutant}.json    ir-checkpoints-v0
  $VG_META_LAB/records/<run-id>/asm/<op>.<vendor>.{base,mutant}.json
  compiler/eval/metamorphic/catalogue.json        the declared relations

A record says what was observed and not what was built, so the manifest is not
optional garnish; and the catalogue is read from the tracked tree rather than from
the manifest, so that the document can be held against the declaration a reviewer
can also read. The manifest's `catalogueSha256` is compared against the tracked
file's actual digest: a run measured against a catalogue that has since changed is
refused rather than assembled, because the declared directions in the document
would then be directions nobody measured against.

REFUSALS

interfaces.md section 5's last rule is a refusal and not a redaction: no absolute
host path may appear anywhere in a digested document, and a component that cannot
avoid one reports the problem instead of emitting it. Every string in the finished
document, `context` included, is checked before the digest is taken. So is rule 4:
every number is an integer, walked to every depth, and a float makes the document
unassemblable rather than rounded.

Exit codes follow interfaces.md section 7: 0 a document was written. 1 a usage
error -- the caller was wrong and no assembly was attempted, deliberately not 3.
3 there was nothing to assemble or something in the way of assembling it.
"""

import base64
import hashlib
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOGUE = os.path.join(HERE, "..", "catalogue.json")
LAB = os.environ.get("VG_META_LAB", os.path.expanduser("~/vg-lab/metamorphic"))
MANIFESTS = os.environ.get("VG_META_MANIFESTS", os.path.join(LAB, "runs"))
OUT_DIR = os.environ.get("VG_META_OUT", os.path.join(LAB, "_results"))

SCHEMA = "vibeguard.metamorphic-report/1"
CATALOGUE_SCHEMA = "vibeguard.metamorphic-catalogue/1"
IR_RECORD_SCHEMA = "ir-checkpoints-v0"
IR_COMPONENT = "IrCheckpoints"
ASM_READING_SCHEMA = "vibeguard.metamorphic-asm-reading/1"

# interfaces.md section 3, verbatim and in section order.
KNOWN_STATES = ("PRESENT", "ABSENT", "LOST", "REINTRODUCED",
                "NOT_APPLICABLE", "NOT_OBSERVED")
# interfaces.md section 3.1, the whole vocabulary.
MEASUREMENTS = ("OK", "UNSUPPORTED", "BROKEN_MEASUREMENT")

# asm-oracle.mjs's classifyCell vocabulary. Only the first two are a transition;
# the other two mean the oracle was blind and the subject reading carries no
# information.
ASM_READABLE = ("PRESERVED", "LOST")

AGREE = "vendors-agree"
SPLIT = "vendors-split"
UNREADABLE = "vendor-unreadable"

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

FAILURE_DIRECTION = (
    "Fails towards not-expressed. Every R2 operator here asks the compiler to do "
    "something, and a compiler that declines leaves the cell reading exactly what "
    "an operator with no bite would read: the base's state, unchanged. So a run "
    "whose R2 cells are all not-expressed is INDISTINGUISHABLE, from this "
    "document alone, from a run whose mutants were never applied -- which is why "
    "the mutant's own sha-256 is beside the base's on every cell and why the "
    "generator refuses at emit time to write a mutant that hashes like its base. "
    "The opposite direction is clean: a cell that moved along its declared edge "
    "moved because the source differed, and an R1 cell that moved at all is a "
    "finding regardless of which way it went. Two further limits, stated rather "
    "than implied. The specimens are single translation units compiled with -c or "
    "-S and never linked, so cross-translation-unit inlining, link-time "
    "optimisation, profile data and everything downstream of the IR optimiser are "
    "invisible to the IR channel; an -flto command line is refused at measurement "
    "time rather than measured, because the plugin's extension points are never "
    "invoked by the LTO backend pipeline. And every specimen is SYNTHETIC and "
    "generated: no cell here says anything whatever about a real subject, and a "
    "cross-vendor split says only that these two compilers, at these versions and "
    "these flags, made a different difference to this generated specimen at the "
    "asm checkpoint.")

WHAT_THIS_DOES_NOT_MEASURE = (
    "whether any real program has any of these properties -- every specimen is "
    "generated by tools/make-mutants.py and is synthetic by construction",
    "the INSTRUMENT'S recognition limits. A mutation that leaves the property "
    "intact and merely defeats the extractor -- a non-zero fill byte, a guard "
    "written as a select or as arithmetic, an indirect call -- is not in this "
    "catalogue and belongs to the calibration battery. This lane breaks the "
    "property; that one measures the instrument.",
    "dominance. compiler/schema/properties.json declares survive.input-validation "
    "with extractor null, so the two dominance operators are declared and no cell "
    "is emitted for them. See lanes.",
    "pass attribution under gcc: UNSUPPORTED by construction, because gcc cannot "
    "load an LLVM -fpass-plugin at all. Not merely not-observed.",
    "any optimisation level other than the one in `run`. One invocation, one "
    "document.",
    "anything at the object, linked or artefact checkpoints. The IR channel stops "
    "at the end of the IR optimiser and the asm channel reads one listing.",
)


class Refused(Exception):
    """Something the document cannot be assembled without. Carried to main() so
    that every refusal leaves by one door and none of them can be a return 0."""


def integers_only(obj, path="/"):
    """interfaces.md section 5 rule 4, walked to every depth. `bool` is a subclass
    of `int` in Python and is not a number here -- it serialises as true/false --
    so the test is on `float` alone."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            integers_only(v, path + str(k) + "/")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            integers_only(v, path + "%d/" % i)
    elif isinstance(obj, float):
        raise ValueError(
            "non-integer number %r at %s; section 5 rule 4 says a ratio is a pair "
            "{\"num\":n,\"den\":d} and that the canonicaliser fails rather than "
            "rounding" % (obj, path))


def canonical(obj):
    integers_only(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest_of(doc):
    """Section 5 rule 1: `context` and `evidenceDigest` come off as whole subtrees
    at the top level, and nothing else comes off at any depth."""
    stripped = {k: v for k, v in doc.items()
                if k not in ("context", "evidenceDigest")}
    return hashlib.sha256(canonical(stripped).encode("utf-8")).hexdigest()


def looks_absolute(s):
    """The same predicate check-envelope.py and build-ladder-frontier.py apply,
    kept character-for-character identical so that the writer and the reader of a
    document cannot disagree about what an absolute path is."""
    return s.startswith("/") or "/root/" in s or "/home/" in s or ":\\" in s


def arg_carries_path(arg):
    """The stricter rule, applied only to command-line tokens. `looks_absolute`
    has a known blind spot on an argument: the path in `-I/opt/vendor` or
    `--sysroot=/opt/vendor` starts partway through the string and lies under
    neither /root nor /home."""
    if looks_absolute(arg):
        return True
    _head, sep, tail = arg.partition("=")
    if sep and tail.startswith("/"):
        return True
    return bool(re.match(r"^-[A-Za-z]{1,2}/", arg))


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + "/" + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + "/%d" % i)
    elif isinstance(obj, str):
        yield path, obj


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def read_kv_multi(path):
    """The manifest, with repeated keys kept as lists. run-metamorphic.sh writes
    `specimen=` and `cellSpec=` once per item, and a reader that let the last one
    win would silently assemble a one-specimen run."""
    kv = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv.setdefault(k, []).append(v)
    return kv


def one(kv, key, default=None):
    vals = kv.get(key)
    if not vals:
        return default
    return vals[-1]


def b64_lines(s):
    if not s:
        return []
    text = base64.b64decode(s.encode("ascii")).decode("utf-8", "replace")
    return [line for line in text.split("\n") if line]


def context_block():
    """interfaces.md section 5: everything a re-run cannot reproduce and nothing
    else. The host is not recorded -- the records do not record it either, and a
    machine's name in a document that may be quoted elsewhere is a disclosure
    rather than provenance."""
    sde = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if sde:
        return {"assembledBy": "build-meta-report.py", "generatedAt": int(sde),
                "host": "unrecorded", "sourceDateEpoch": int(sde),
                "timeSource": "SOURCE_DATE_EPOCH"}
    return {"assembledBy": "build-meta-report.py", "generatedAt": int(time.time()),
            "host": "unrecorded", "sourceDateEpoch": None,
            "timeSource": "wall-clock"}


def load_catalogue():
    with open(CATALOGUE, "r", encoding="utf-8") as fh:
        cat = json.load(fh)
    if cat.get("schemaVersion") != CATALOGUE_SCHEMA:
        raise Refused("the catalogue declares schemaVersion %r, not %r"
                      % (cat.get("schemaVersion"), CATALOGUE_SCHEMA))
    return cat


def read_json(path):
    """Returns (document, why-it-is-unusable). Never raises on bad input: one
    unreadable record makes one cell's side BROKEN_MEASUREMENT, not a reason to
    refuse the other thirty-nine."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None, "no record was written"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (ValueError, OSError) as exc:
        return None, "record unreadable: %s" % exc
    if not isinstance(doc, dict):
        return None, "record is not an object"
    return doc, None


def record_digest_recomputes(rec):
    """Recomputed here, independently of the C++ that wrote it. A record that no
    longer hashes to the value it carries is section 3.1's BROKEN_MEASUREMENT and
    its verdict is not read."""
    try:
        return digest_of(rec) == rec.get("evidenceDigest")
    except (ValueError, TypeError):
        return False


def broken_side(specimen_id, specimen_sha, reason):
    """One side of a cell, written under the pairing rule. See the header for why
    controlHeld is null here even when the control fell."""
    return {
        "brokenReason": reason,
        "completesTheCheck": False,
        "controlEffectPost": None,
        "controlEffectPre": None,
        "controlHeld": None,
        "effectPost": None,
        "effectPre": None,
        "findingCount": None,
        "firstLossPass": None,
        "measurement": "BROKEN_MEASUREMENT",
        "recordDigest": None,
        "recordDigestRecomputes": False,
        "specimenId": specimen_id,
        "specimenSha256": specimen_sha,
        "state": "NOT_OBSERVED",
        "unitPresentPreOpt": None,
    }


GRADE_ON_KEYS = {"count-at-pre-opt-ir": "effectPre",
                 "count-at-after-pass": "effectPost"}


def single_checkpoint_transition(grade_on, base, mutant, readable):
    """The base->mutant transition read as a COUNT at one checkpoint, or None.

    Driven by the catalogue's explicit `gradeOn`, and by nothing inferred. The
    first attempt at this read `checkpointRead` instead, and that was wrong in a way
    worth recording: `checkpointRead` documents WHERE a phenomenon is observed, and
    the R2b and R2c operators legitimately name `after-pass` for it. Treating that
    as "grade the count at after-pass" collapsed their PRESENT->LOST and
    PRESENT->NOT_APPLICABLE edges into PRESENT/ABSENT and sent five correct cells
    off-axis. An opt-in field cannot do that to an operator that did not ask for it.

    A count becomes a state by the only rule available at one checkpoint: non-zero
    is PRESENT, zero is ABSENT. `LOST` and `NOT_APPLICABLE` are unreachable here and
    must stay so -- both are assertions about a CHANGE between two checkpoints.
    """
    key = GRADE_ON_KEYS.get(grade_on)
    if key is None or not readable:
        return None
    out = []
    for side in (base, mutant):
        count = side.get(key)
        if not isinstance(count, int):
            return None
        out.append("PRESENT" if count > 0 else "ABSENT")
    return "%s->%s" % (out[0], out[1])


def ir_side(path, op, side, specimen_id, specimen_sha, subject, control, extractor,
            symbols):
    """Read one ir-checkpoints-v0 record into one side of a cell.

    Wiring is checked rather than assumed. A record whose extractor, subject,
    control or symbol list is not the one this cell declares is a mis-wired run,
    and reading its verdict would attribute one question's answer to another
    question -- the same check build-ladder-frontier.py makes on a rung, and for
    the same reason."""
    rec, why = read_json(path)
    if rec is None:
        return broken_side(specimen_id, specimen_sha, why)
    if (rec.get("schemaVersion") != IR_RECORD_SCHEMA
            or rec.get("component") != IR_COMPONENT):
        return broken_side(specimen_id, specimen_sha,
                           "record is %r/%r, not %r/%r"
                           % (rec.get("component"), rec.get("schemaVersion"),
                              IR_COMPONENT, IR_RECORD_SCHEMA))
    if not record_digest_recomputes(rec):
        return broken_side(specimen_id, specimen_sha,
                           "record does not hash to the digest it carries")

    got = (rec.get("extractor"), rec.get("subjectUnit"), rec.get("controlUnit"),
           tuple((rec.get("oracle") or {}).get("symbols") or ()))
    want = (extractor, subject, control, tuple(symbols))
    if got != want:
        return broken_side(
            specimen_id, specimen_sha,
            "record is wired to %s/%s/%s/%s; this cell declares %s/%s/%s/%s"
            % (got[0], got[1], got[2], ",".join(got[3]),
               want[0], want[1], want[2], ",".join(want[3])))

    state = (rec.get("verdict") or {}).get("state")
    if state not in KNOWN_STATES:
        return broken_side(specimen_id, specimen_sha,
                           "verdict state %r is not one of the six in "
                           "interfaces.md section 3" % (state,))

    subj = rec["subject"]
    ctl = rec["control"]
    out = {
        "brokenReason": None,
        "completesTheCheck": bool((rec.get("verdict") or {}).get("completesTheCheck")),
        "controlEffectPost": ctl["postOptIr"]["effect"],
        "controlEffectPre": ctl["preOptIr"]["effect"],
        "controlHeld": bool(ctl["held"]),
        "effectPost": subj["postOptIr"]["effect"],
        "effectPre": subj["preOptIr"]["effect"],
        "findingCount": len(rec.get("findings") or []),
        "firstLossPass": (rec.get("firstZeroTransition") or {}).get("pass"),
        "measurement": "OK",
        "recordDigest": rec.get("evidenceDigest"),
        "recordDigestRecomputes": True,
        "specimenId": specimen_id,
        "specimenSha256": specimen_sha,
        "state": state,
        "unitPresentPreOpt": bool(subj["preOptIr"]["unitPresent"]),
    }

    # interfaces.md section 4: a measurement whose control's count also fell to
    # zero is a broken measurement, not a finding. And a subject that was not in
    # the module at the first checkpoint was never established, so there is no
    # transition to read from it either.
    if not out["controlHeld"]:
        broken = broken_side(specimen_id, specimen_sha,
                             "the control did not hold (%s -> %s), so this side "
                             "cannot tell a removed effect from an oracle that "
                             "stopped working (interfaces.md section 4)"
                             % (out["controlEffectPre"], out["controlEffectPost"]))
        # false, not null. This control WAS measured and it DID fall.
        # compiler/envelope/fragility.mjs:306-316 and 366-386 -- the component that
        # scores -- separates the two rather than merging them: `false` excludes the
        # cell as CONTROL_DID_NOT_HOLD, `null` excludes it as NOT_OBSERVED and means
        # no control was measured at all. This side emitted null for a fallen control,
        # which describes it as a control nobody ran; fragility.mjs records that
        # collapsing the two "was misstating 16 of the 20 removals in the first real
        # envelope this ran on". Section 3.1's own sentence reads as null-always and is
        # what led here, so the disambiguation is now stated in that section too.
        broken["controlHeld"] = False
        broken["controlEffectPre"] = out["controlEffectPre"]
        broken["controlEffectPost"] = out["controlEffectPost"]
        broken["recordDigest"] = out["recordDigest"]
        broken["recordDigestRecomputes"] = True
        return broken
    if not out["unitPresentPreOpt"]:
        broken = broken_side(specimen_id, specimen_sha,
                             "the subject unit was not in the module at the "
                             "pre-optimisation checkpoint")
        broken["controlEffectPre"] = out["controlEffectPre"]
        broken["controlEffectPost"] = out["controlEffectPost"]
        broken["recordDigest"] = out["recordDigest"]
        broken["recordDigestRecomputes"] = True
        return broken
    return out


def asm_side(path):
    """One asm reading, or the reason there is none. `state` here is
    asm-oracle.mjs's classifyCell vocabulary and NOT interfaces.md section 3's:
    PRESERVED / LOST / VERIFICATION_INCOMPLETE / NOT_OBSERVED. They are kept in a
    field of their own rather than mapped onto the six, because this instrument
    cannot tell ABSENT, LOST and NOT_APPLICABLE apart and a mapping would invent
    the distinction it lacks."""
    doc, why = read_json(path)
    if doc is None:
        return {"bodyLineCount": None, "controlState": None, "evidenceCount": None,
                "listingSha256": None, "readable": False, "reason": why,
                "state": "NOT_OBSERVED"}
    if doc.get("schemaVersion") != ASM_READING_SCHEMA:
        return {"bodyLineCount": None, "controlState": None, "evidenceCount": None,
                "listingSha256": None, "readable": False,
                "reason": "reading declares schemaVersion %r, not %r"
                          % (doc.get("schemaVersion"), ASM_READING_SCHEMA),
                "state": "NOT_OBSERVED"}
    state = (doc.get("cell") or {}).get("state")
    subj = doc.get("subject") or {}
    ctl = doc.get("control") or {}
    return {
        "bodyLineCount": subj.get("bodyLineCount"),
        "controlState": ctl.get("verdict"),
        "evidenceCount": subj.get("evidenceCount"),
        "listingSha256": (doc.get("listing") or {}).get("sha256"),
        "readable": state in ASM_READABLE,
        "reason": (doc.get("cell") or {}).get("rationale"),
        "state": state,
    }


def agreement_of(per_vendor):
    """The three words, computed in one place.

    A side is readable only when BOTH its base and its mutant landed in
    {PRESERVED, LOST}: a transition needs two endpoints, and
    VERIFICATION_INCOMPLETE means the control did not show its effect, so the
    subject reading carries no information at all. `vendor-unreadable` is never
    folded into `vendors-split` -- "the two differ" and "I could not look" send a
    reader to two different places and only one of them is a finding."""
    unreadable = [v["vendorId"] for v in per_vendor if not v["readable"]]
    if unreadable:
        side = "both" if len(unreadable) == len(per_vendor) else unreadable[0]
        return UNREADABLE, side, (
            "%s could not be read (%s), so no comparison was made. This is not a "
            "split: a side nobody successfully read cannot be evidence that the "
            "two vendors differ, and it cannot be evidence that they agree either."
            % (" and ".join(unreadable),
               "; ".join("%s base=%s mutant=%s"
                         % (v["vendorId"], v["base"]["state"], v["mutant"]["state"])
                         for v in per_vendor if not v["readable"])))
    transitions = {v["transition"] for v in per_vendor}
    if len(transitions) == 1:
        return AGREE, None, (
            "both vendors read the same transition (%s). The mutation made the "
            "same difference to this specimen under both, at the asm checkpoint "
            "and at these flags."
            % next(iter(transitions)))
    return SPLIT, None, (
        "the vendors read different transitions (%s). At these versions and these "
        "flags the two compilers made a different difference to this specimen "
        "under this mutation, read at the asm checkpoint. Neither is wrong, and "
        "nothing here is a claim about any real subject or about any IR-level "
        "cause on the gcc side."
        % "; ".join("%s %s" % (v["vendorId"], v["transition"]) for v in per_vendor))


def read_manifest(run_id, catalogue_sha):
    path = os.path.join(MANIFESTS, run_id + ".kv")
    if not os.path.exists(path):
        raise Refused("%s: no manifest at %s. A record says what was observed and "
                      "not what was built; without the invocation the readings "
                      "cannot be compared with any other readings."
                      % (run_id, path.replace(os.path.expanduser("~"), "~")))
    kv = read_kv_multi(path)

    for required in ("runId", "opt", "argvB64", "generatorSha256",
                     "catalogueSha256", "cellSpec"):
        if not one(kv, required):
            raise Refused("%s: the manifest has no %s=" % (run_id, required))
    if one(kv, "runId") != run_id:
        raise Refused("%s: the manifest calls this run %r; the records are under a "
                      "different name and one of the two is wrong"
                      % (run_id, one(kv, "runId")))

    rc = one(kv, "rc", "0")
    if rc not in ("", "0"):
        raise Refused("%s: the manifest records rc=%s%s. The run did not complete, "
                      "so whatever is under records/ is not a reading of this "
                      "configuration."
                      % (run_id, rc,
                         " (%s)" % one(kv, "refusal") if one(kv, "refusal") else ""))
    if one(kv, "refusal"):
        raise Refused("%s: the producer recorded refusal=%s"
                      % (run_id, one(kv, "refusal")))

    if one(kv, "catalogueSha256") != catalogue_sha:
        raise Refused(
            "%s: the run was measured against a catalogue whose sha256 was %s and "
            "the tracked catalogue now hashes to %s. The declared directions in "
            "this document would be directions nobody measured against, so it is "
            "refused rather than assembled. Re-run the producer."
            % (run_id, one(kv, "catalogueSha256"), catalogue_sha))

    gen_sha = one(kv, "generatorSha256")
    if not HEX64_RE.match(gen_sha or ""):
        raise Refused("%s: generatorSha256=%r is not lowercase 64-hex"
                      % (run_id, gen_sha))

    argv = b64_lines(one(kv, "argvB64"))
    if not argv or argv[0] != one(kv, "opt"):
        raise Refused("%s: argv starts with %r and opt is %r; the document's `opt` "
                      "and `extraArgs` would not add up to the command line that "
                      "was run" % (run_id, argv[0] if argv else None, one(kv, "opt")))
    leaked = [a for a in argv if arg_carries_path(a)]
    if leaked:
        raise Refused("%s: %d argument(s) hold an absolute path (%s). interfaces.md "
                      "section 5 says a component that cannot avoid one reports the "
                      "problem instead of emitting it."
                      % (run_id, len(leaked), "; ".join(leaked)))

    specimens = []
    for line in kv.get("specimen", []):
        parts = line.split("|")
        if len(parts) != 3:
            raise Refused("%s: malformed specimen line %r" % (run_id, line))
        sid, rel, sha = parts
        if not HEX64_RE.match(sha):
            raise Refused("%s: specimen %s has sha256 %r, which is not lowercase "
                          "64-hex" % (run_id, sid, sha))
        if looks_absolute(rel):
            raise Refused("%s: specimen %s is recorded at an absolute path %r"
                          % (run_id, sid, rel))
        specimens.append({"relPath": rel, "sha256": sha, "specimenId": sid})
    if not specimens:
        raise Refused("%s: the manifest declares no specimens" % run_id)

    cells = []
    for line in kv.get("cellSpec", []):
        parts = line.split("|")
        if len(parts) != 11:
            raise Refused("%s: malformed cellSpec line %r (%d fields, expected 11)"
                          % (run_id, line, len(parts)))
        cells.append(parts)

    try:
        gen_version = int(one(kv, "generatorVersion", "0"))
    except ValueError:
        raise Refused("%s: generatorVersion=%r is not an integer, and section 5 "
                      "rule 4 will not let it into the document"
                      % (run_id, one(kv, "generatorVersion")))

    return {
        "argv": argv,
        "asmLane": one(kv, "asmLane", "NOT_RUN"),
        "asmLaneReason": one(kv, "asmLaneReason", ""),
        "catalogueSha256": one(kv, "catalogueSha256"),
        "cc": one(kv, "cc", ""),
        "cc2": one(kv, "cc2", ""),
        "cc2Version": one(kv, "cc2Version", "absent"),
        "ccVersion": one(kv, "ccVersion", ""),
        "cells": cells,
        "generatorSha256": gen_sha,
        "generatorVersion": gen_version,
        "opt": one(kv, "opt"),
        "pluginSha256": one(kv, "pluginSha256", "absent"),
        "specimens": specimens,
    }


def toolchain_from(seen, manifest):
    """The compiler is read off the RECORDS, not off the manifest: the manifest is
    what the producer meant to invoke and a record is what the observer saw. Two
    different compilers in one report is refused for the reason check-envelope.py
    refuses two plugin builds in one envelope -- readings from different observers
    are not one series."""
    if not seen:
        raise Refused("no record in this run names a toolchain")
    if len(seen) > 1:
        raise Refused("this run was measured by %d different toolchains (%s); "
                      "readings from different compilers are not one report"
                      % (len(seen), sorted(k[0] for k in seen)))
    clang, digest = next(iter(seen))
    if manifest["ccVersion"] and clang not in manifest["ccVersion"]:
        raise Refused("the manifest's compiler is %r and the records say clang %s"
                      % (manifest["ccVersion"], clang))
    return {"cc": manifest["cc"], "clang": clang, "digest": digest,
            "pluginSha256": manifest["pluginSha256"]}


def build(run_id):
    cat = load_catalogue()
    catalogue_sha = sha256_file(CATALOGUE)
    manifest = read_manifest(run_id, catalogue_sha)

    ops = {op["operatorId"]: op for op in cat["operators"]}
    spec_sha = {s["specimenId"]: s["sha256"] for s in manifest["specimens"]}

    ir_dir = os.path.join(LAB, "records", run_id, "ir")
    asm_dir = os.path.join(LAB, "records", run_id, "asm")
    if not os.path.isdir(ir_dir):
        raise Refused("%s: no ir record directory at %s"
                      % (run_id, ir_dir.replace(os.path.expanduser("~"), "~")))

    vendors = [manifest["cc"], manifest["cc2"]]

    cells = []
    comparisons = []
    toolchains = set()

    # Array order is significant and never sorted (section 5 rule 2). It is the
    # manifest's cellSpec order, which is the catalogue's operator order, which is
    # a constant -- so two runs of the same catalogue digest identically.
    for parts in manifest["cells"]:
        (op_id, extractor, bspec, mspec, bsubj, msubj, ctl, syms, xv, asmsyms,
         asmiz) = parts
        op = ops.get(op_id)
        if op is None:
            raise Refused("%s: the manifest names cell %s and the catalogue has no "
                          "such operator; the run and the catalogue are two "
                          "different instruments" % (run_id, op_id))
        symbols = [s for s in syms.split(",") if s]

        for rec_path in (os.path.join(ir_dir, op_id + ".base.json"),
                         os.path.join(ir_dir, op_id + ".mutant.json")):
            rec, _why = read_json(rec_path)
            if rec is not None:
                tc = rec.get("toolchain") or {}
                if tc.get("clang"):
                    toolchains.add((tc.get("clang"), tc.get("digest")))

        base = ir_side(os.path.join(ir_dir, op_id + ".base.json"), op_id, "base",
                       bspec, spec_sha.get(bspec), bsubj, ctl, extractor, symbols)
        mutant = ir_side(os.path.join(ir_dir, op_id + ".mutant.json"), op_id,
                         "mutant", mspec, spec_sha.get(mspec), msubj, ctl,
                         extractor, symbols)

        readable = base["measurement"] == "OK" and mutant["measurement"] == "OK"
        cells.append({
            "baseSubject": bsubj,
            "checkpointRead": op.get("checkpointRead"),
            "class": op["class"],
            "control": ctl,
            "declaredDirection": op["declaredDirection"],
            "extractor": extractor,
            "graded": bool(op.get("graded")),
            "mutantSubject": msubj,
            "notMonotonic": op.get("notMonotonicWhen") is not None,
            "notMonotonicWhen": op.get("notMonotonicWhen"),
            "operatorId": op_id,
            "shape": op["shape"],
            # False for every class that is off the two-point survival axis. R2c
            # is the named one; R2a lands on ABSENT and the forbidden polarity has
            # no survival axis at all, so neither of those is on it either.
            "survivalAxisGraded": op["class"] == "R2b",
            "symbols": symbols,
            "base": base,
            "mutant": mutant,
            "transition": ("%s->%s" % (base["state"], mutant["state"])
                           if readable else None),
            "transitionReadable": readable,
            # The same transition read as a COUNT at one checkpoint, present only
            # when the catalogue's `gradeOn` asks for it. Absent -- null -- on every
            # operator that does not, which is all but one.
            #
            # Why it exists: `transition` above pairs the two VERDICTS, and a
            # verdict is computed across both checkpoints. For an introduction
            # question that is the wrong object. F-R2S-PRINTF asks whether a
            # forbidden `printf` call APPEARS; at -O2 its mutant reads 1 at pre-opt
            # and 0 at after-pass, because clang rewrote the call to `puts`, and
            # interfaces.md section 3 spells that pair LOST -- a must-survive word
            # answering a must-not-appear question. Graded against the declared
            # ABSENT->PRESENT edge the cell then looks off-axis, and the operator
            # was declared ungraded to avoid reporting a forbidden call
            # DISAPPEARING as a finding.
            #
            # Reading the checkpoint the catalogue already names dissolves that: at
            # pre-opt-ir the base holds 0 and the mutant holds 1, so the declared
            # edge holds at both -O0 and -O2 and the cell is graded rather than
            # excused. An operator that is permanently ungraded is an off switch
            # with no condition on it, and this lane would then have one cell
            # nothing could ever falsify.
            #
            # ONLY TWO STATES ARE AVAILABLE HERE, and that is a limit rather than an
            # oversight: one checkpoint can say PRESENT or ABSENT and cannot say
            # LOST or NOT_APPLICABLE, both of which are claims about a CHANGE
            # between two checkpoints. So `gradeOn` must never be set on a
            # survival-axis (R2b) or referent (R2c) operator, whose whole edge is
            # such a change. check-meta.py refuses that combination outright, which
            # is how the first version of this field was caught: it inferred the
            # checkpoint from `checkpointRead`, which those classes also set, and
            # sent five correct cells off-axis.
            "transitionAtDeclaredCheckpoint": single_checkpoint_transition(
                op.get("gradeOn"), base, mutant, readable),
            "whyUngraded": op.get("whyUngraded"),
        })

        if xv != "1":
            continue
        per_vendor = []
        for vid in vendors:
            b = asm_side(os.path.join(asm_dir, "%s.%s.base.json" % (op_id, vid)))
            m = asm_side(os.path.join(asm_dir, "%s.%s.mutant.json" % (op_id, vid)))
            v_readable = b["readable"] and m["readable"]
            per_vendor.append({
                "base": b,
                "mutant": m,
                "readable": v_readable,
                "transition": ("%s->%s" % (b["state"], m["state"])
                               if v_readable else None),
                "vendorId": vid,
            })
        word, side, reason = agreement_of(per_vendor)
        comparisons.append({
            "agreement": word,
            "asmSymbols": [s for s in asmsyms.split(",") if s],
            "allowInlineZeroStore": asmiz == "1",
            "operatorId": op_id,
            "reason": reason,
            "unreadableSide": side,
            "vendors": per_vendor,
        })

    if not cells:
        raise Refused("%s: no cell was assembled" % run_id)
    if all(c["base"]["measurement"] != "OK" and c["mutant"]["measurement"] != "OK"
           for c in cells):
        raise Refused("%s: every side of every cell is a broken measurement; there "
                      "is no report here to assemble. First reason: %s"
                      % (run_id, cells[0]["base"]["brokenReason"]))

    toolchain = toolchain_from(toolchains, manifest)

    tally = {AGREE: 0, SPLIT: 0, UNREADABLE: 0}
    for c in comparisons:
        tally[c["agreement"]] += 1

    by_shape = {}
    for c in cells:
        by_shape[c["shape"]] = by_shape.get(c["shape"], 0) + 1
    declared_by_shape = {}
    for op in cat["operators"]:
        declared_by_shape[op["shape"]] = declared_by_shape.get(op["shape"], 0) + 1

    lanes = []
    for lane in cat["lanes"]:
        lanes.append({
            "cellsEmitted": by_shape.get(lane["shape"], 0),
            "extractor": lane["extractor"],
            "laneId": lane["laneId"],
            "operatorsDeclared": declared_by_shape.get(lane["shape"], 0),
            "propertyId": lane["propertyId"],
            "shape": lane["shape"],
            "status": lane["status"],
            "statusReason": lane["statusReason"],
        })

    cross = {
        "instrument": {
            "cannotDistinguish": ["ABSENT", "LOST", "NOT_APPLICABLE"],
            "checkpoint": "asm",
            "comparedObject": "the transition (base -> mutant) per vendor, never "
                              "the raw states",
            "module": "compiler/eval/second-vendor/lib/asm-oracle.mjs",
            "passAttribution": {
                manifest["cc"]: "NOT_OBSERVED -- pass names exist for this vendor "
                                "in the IR channel and are deliberately not "
                                "imported here, because importing one side's "
                                "richer instrument would silently change the "
                                "instrument mid-table",
                manifest["cc2"]: "UNSUPPORTED by construction -- this vendor "
                                 "cannot load an LLVM -fpass-plugin at all",
            },
            "vendorNeutral": True,
        },
        "status": manifest["asmLane"],
        "statusReason": manifest["asmLaneReason"],
        "tally": tally,
        "vendors": [{"vendorId": manifest["cc"], "version": manifest["ccVersion"]},
                    {"vendorId": manifest["cc2"], "version": manifest["cc2Version"]}],
        "words": cat["crossVendorChannel"]["words"],
        "comparisons": comparisons,
    }

    doc = {
        "schemaVersion": SCHEMA,
        "failureDirection": FAILURE_DIRECTION,
        "whatThisDoesNotMeasure": list(WHAT_THIS_DOES_NOT_MEASURE),
        "catalogue": {
            "operatorsDeclared": len(cat["operators"]),
            "operatorsMeasured": len(cells),
            "schemaVersion": cat["schemaVersion"],
            "sha256": catalogue_sha,
        },
        "generator": {
            "sha256": manifest["generatorSha256"],
            "version": manifest["generatorVersion"],
        },
        "run": {
            "extraArgs": manifest["argv"][1:],
            "id": run_id,
            "opt": manifest["opt"],
        },
        "toolchain": toolchain,
        "specimens": manifest["specimens"],
        "cells": cells,
        "crossVendor": cross,
        "lanes": lanes,
        "deferred": cat["deferred"],
        "survivalAxis": cat["survivalAxis"],
        "context": context_block(),
    }

    # Section 5's last rule, applied to the whole document including `context`,
    # which the section does not exempt. The reasons a record must not carry an
    # absolute path -- a machine's account name being a disclosure, and a digest
    # that changes with the checkout directory -- do not stop at the context
    # boundary.
    for path, text in walk_strings(doc):
        if looks_absolute(text):
            raise Refused("%s: absolute path at %s: %r" % (run_id, path, text[:120]))

    try:
        doc["evidenceDigest"] = digest_of(doc)
    except ValueError as exc:
        raise Refused("%s: %s" % (run_id, exc))
    return doc


def usage():
    print("usage: build-meta-report.py [run-id ...]", file=sys.stderr)
    print("  with no arguments, every manifest under $VG_META_LAB/runs is "
          "assembled", file=sys.stderr)
    return 1


def main(argv):
    for arg in argv:
        if arg.startswith("-"):
            return usage()
        if not RUN_ID_RE.match(arg):
            print("build-meta-report.py: %r is not a run id" % arg, file=sys.stderr)
            return usage()

    if argv:
        wanted = list(argv)
    else:
        if not os.path.isdir(MANIFESTS):
            print("no manifest directory at %s; the producer has not been run"
                  % MANIFESTS.replace(os.path.expanduser("~"), "~"),
                  file=sys.stderr)
            return 3
        wanted = sorted(n[:-3] for n in os.listdir(MANIFESTS)
                        if n.endswith(".kv") and RUN_ID_RE.match(n[:-3]))
        if not wanted:
            print("no manifests under %s"
                  % MANIFESTS.replace(os.path.expanduser("~"), "~"),
                  file=sys.stderr)
            return 3

    os.makedirs(OUT_DIR, exist_ok=True)
    refusals = []
    for run_id in wanted:
        try:
            doc = build(run_id)
        except Refused as exc:
            refusals.append(str(exc))
            continue
        out = os.path.join(OUT_DIR, run_id + ".json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
            fh.write("\n")
        broken = sum(1 for c in doc["cells"] if not c["transitionReadable"])
        print("%-8s %2d cell(s), %d unreadable; cross-vendor %s: %s"
              % (run_id, len(doc["cells"]), broken, doc["crossVendor"]["status"],
                 ", ".join("%s=%d" % (k, v)
                           for k, v in sorted(doc["crossVendor"]["tally"].items()))))

    # One refusal makes the whole invocation exit 3 even when other runs were
    # written. A caller that sweeps a directory and reads 0 would otherwise take a
    # partial set as a complete one, which is section 7's "we did not look"
    # reported as "it is clean".
    if refusals:
        print("\n%d run(s) not assembled:" % len(refusals), file=sys.stderr)
        for r in refusals:
            print("  " + r, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
