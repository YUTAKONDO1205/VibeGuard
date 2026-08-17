#!/usr/bin/env python3
"""Experiment 1: hold the catalogue's degradation prose against what was measured.

    python3 check-claims.py [report.json | directory ...]

With no arguments, $VG_CAL_LAB/_results/calibration is read.

THE QUESTION THIS FILE ASKS, AND WHY IT IS NOT check-battery.py's

check-battery.py asks "is the instrument right", by holding a reading against a
known true value. This file asks a different question with a different failure
meaning: "does the tracked English description of the instrument's weaknesses match
what the instrument actually does". compiler/schema/properties.json carries, for
each extractor, a `degradationRisk` list of sentences saying how it degrades and in
which direction it errs. Those sentences are quoted by other documents and are read
as fact. Until this file existed, none of them had ever been held against a
measurement.

A single grader doing both jobs would let one go green behind the other, which is
why there are two files and why this one RUNS NO COMPILER: it reads assembled
reports and the catalogue, and nothing else.

THE COVERAGE FENCE

The sentence list is recomputed from properties.json and held VERBATIM against
claims/degradation-claims.json. A sentence with no entry, or an entry whose copy of
a sentence has drifted from the catalogue, is exit 3 under the word
`claims-coverage-broken`. That fence is the whole honesty mechanism: without it a
maintainer could test the convenient sentences and leave the awkward ones
unmentioned, and the ledger would look complete. With it, an untested sentence has
to be entered WITH A REASON, and editing properties.json forces the ledger to move
in the same commit.

Its SCOPE is the degradationRisk arrays of the three implemented extractor entries.
The per-property arrays elsewhere in properties.json are not fenced by this
revision, and the ledger says so rather than leaving a reader to assume otherwise.

HOW A DISAGREEMENT IS TO BE READ

Exit 2, and it is a finding either way -- the prose is wrong about the code, or the
code is wrong and the prose described the intent. This file does not decide which,
because deciding it needs a reading of the extractor's source and that is a
different act from measuring. What it must never do is resolve the tension by
adjusting the ledger: that is the failure
compiler/eval/negative-controls/README.md names, where the fixture goes green and
the instrument stays exactly as broken, behind a tick.

An OMISSION is exit 2 for the same reason: a measured divergence that no sentence
in the fenced scope describes means the catalogue is not a complete description of
the instrument. The resolution is an amendment to properties.json, and this
directory deliberately does not make it -- a battery that edits the catalogue it is
calibrating in the same change has stopped being an independent measurement.

FAILURE DIRECTION

Fails towards reporting a finding rather than towards silence. Every path that
cannot decide something leaves exit 3 and names what could not be decided; a claim
whose fixture is missing from the report is `claim-unreadable`, never
`claim-agrees`. The one direction it deliberately does NOT protect against is a
sentence that is vague enough to be unfalsifiable: `scope` claims are recorded and
never graded, so a maintainer could in principle evade this file by writing prose
that predicts nothing. That is a real hole and the ledger's claimKind column is
where it is visible.

EXIT CODES (interfaces.md section 7)
  0  every measured claim agreed with the measurement, and nothing is omitted
  2  a claim disagreed, a doctrine failed, or an omission is open
  3  the fence is broken, or a claim could not be read at all

2 outranks 3 when both are present, and both are printed.
"""

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROPERTIES = os.path.join(HERE, "..", "..", "..", "schema", "properties.json")
LEDGER = os.path.join(HERE, "..", "claims", "degradation-claims.json")
EXPECTED = os.path.join(HERE, "..", "claims", "expected.json")
LAB = os.environ.get("VG_CAL_LAB", os.path.join(os.path.expanduser("~"), "vg-lab", "calibration"))
RESULTS = os.path.join(LAB, "_results", "calibration")

SCHEMA = "vibeguard.calibration-report/1"


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


def digest_of(doc):
    stripped = {k: v for k, v in doc.items() if k not in ("context", "evidenceDigest")}
    integers_only(stripped)
    return hashlib.sha256(json.dumps(stripped, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False)
                          .encode("utf-8")).hexdigest()


def load_reports(argv):
    """Every assembled report, keyed by configId. A report whose digest does not
    recompute is refused rather than read: grading prose against a document that
    cannot be trusted is exactly "we did not look" reported as a finding."""
    paths = argv or [RESULTS]
    found, unreadable = [], []
    for p in paths:
        if os.path.isdir(p):
            names = sorted(n for n in os.listdir(p) if n.endswith(".json"))
            if not names:
                unreadable.append("no calibration reports in %s" % p)
            found.extend(os.path.join(p, n) for n in names)
        elif os.path.exists(p):
            found.append(p)
        else:
            unreadable.append("no such path: %s" % p)

    reports = {}
    for path in found:
        name = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (ValueError, OSError) as exc:
            unreadable.append("%s: unreadable: %s" % (name, exc))
            continue
        if doc.get("schemaVersion") != SCHEMA:
            unreadable.append("%s: schemaVersion %r is not %r" % (name, doc.get("schemaVersion"), SCHEMA))
            continue
        try:
            recomputed = digest_of(doc)
        except (ValueError, TypeError) as exc:
            unreadable.append("%s: cannot be canonicalised: %s" % (name, exc))
            continue
        if recomputed != doc.get("evidenceDigest"):
            unreadable.append("%s: digest mismatch: carries %r, recomputes to %r"
                              % (name, doc.get("evidenceDigest"), recomputed))
            continue
        reports[doc.get("configId")] = doc
    return reports, unreadable


def fence(ledger):
    """Recompute the fenced sentence list from properties.json and hold the ledger
    against it, verbatim. Returns a list of breakages; empty means the fence held."""
    breaks = []
    try:
        with open(PROPERTIES, "r", encoding="utf-8") as fh:
            props = json.load(fh)
    except (ValueError, OSError) as exc:
        return ["claims-coverage-broken: cannot read %s: %s" % (PROPERTIES, exc)]

    scope = (ledger.get("fencedScope") or {}).get("coversDegradationRiskOf") or []
    if not scope:
        return ["claims-coverage-broken: the ledger declares no fenced scope, so the fence "
                "would cover nothing and every sentence would pass vacuously"]

    catalogue = {}
    for ex in scope:
        entry = (props.get("extractors") or {}).get(ex)
        if entry is None:
            breaks.append("claims-coverage-broken: the ledger fences %r and properties.json has "
                          "no such extractor entry" % ex)
            continue
        for i, sentence in enumerate(entry.get("degradationRisk") or []):
            catalogue["extractors.%s.degradationRisk[%d]" % (ex, i)] = sentence

    ledger_by_path = {}
    for c in ledger.get("claims") or []:
        ref = c.get("sourceRef") or {}
        ledger_by_path[ref.get("jsonPath")] = c

    for path, sentence in sorted(catalogue.items()):
        c = ledger_by_path.get(path)
        if c is None:
            breaks.append(
                "claims-coverage-broken: %s is in the catalogue and has no entry in the ledger. "
                "An untested sentence still has to be entered with a reason; quiet selection of "
                "the convenient sentences is what this fence exists to prevent.\n      sentence: %s"
                % (path, sentence[:200]))
            continue
        if c.get("sentence") != sentence:
            breaks.append(
                "claims-coverage-broken: %s has drifted. The ledger's copy and the catalogue's "
                "text are not the same string, so the claim graded below may be about a sentence "
                "that no longer exists.\n      catalogue: %s\n      ledger:    %s"
                % (path, (sentence or "")[:160], (c.get("sentence") or "")[:160]))

    for path in sorted(ledger_by_path):
        if path not in catalogue:
            breaks.append(
                "claims-coverage-broken: the ledger carries an entry for %s and the catalogue has "
                "no such sentence. An orphaned claim is a test of something nobody states." % path)

    return breaks


def cell_state(reports, config_id, fixture_id):
    """(state, measurement, controlHeld, why-not) for one fixture in one report."""
    doc = reports.get(config_id)
    if doc is None:
        return None, None, None, "no assembled report for configuration %s" % config_id
    for c in doc.get("cells") or []:
        if c.get("fixtureId") == fixture_id:
            return c.get("state"), c.get("measurement"), c.get("controlHeld"), None
    return None, None, None, "configuration %s carries no cell %s" % (config_id, fixture_id)


def cell_of(reports, config_id, fixture_id):
    doc = reports.get(config_id)
    if doc is None:
        return None
    for c in doc.get("cells") or []:
        if c.get("fixtureId") == fixture_id:
            return c
    return None


def claim_where(claim):
    """How to name a claim in a message.

    An OMISSION claim carries `sourceRef: null` by construction -- it exists
    because NO sentence in the fenced scope describes the divergence, so there is
    no jsonPath to point at. Three messages below subscripted it directly and
    raised TypeError on exactly the path this experiment exists to reach: the one
    taken after the catalogue is amended and the omission stops reproducing. A
    grader that crashes when the instrument is repaired is a grader nobody can use
    to confirm the repair.
    """
    ref = claim.get("sourceRef") or {}
    return ref.get("jsonPath") or "no sentence in the fenced scope (omission claim)"


def grade_degradation(claim, reports):
    """Returns (verdicts, findings). One verdict per declared configuration."""
    verdicts, findings = [], []
    for config_id in claim.get("configs") or []:
        state, measurement, _held, why = cell_state(reports, config_id, claim["fixtureId"])
        if why is not None:
            verdicts.append((config_id, "claim-unreadable", why))
            continue
        if measurement != "OK":
            verdicts.append((config_id, "claim-unreadable",
                             "the cell's measurement is %s, so no reading came back and the "
                             "prose cannot be held against one" % measurement))
            continue
        truth = claim["groundTruth"]
        predicted = claim["predictedReading"]
        # `configs` lists the configurations at which the sentence's mechanism is
        # CLAIMED to apply, so reading the true value at one of them is not a
        # non-event: it contradicts the sentence. Checking `state == truth` first
        # and calling it "not expressed" was the earlier logic here, and it
        # understated exactly the finding this experiment exists to produce -- an
        # extractor that is more careful than its own catalogue says. A
        # configuration where the mechanism is not expected is expressed by NOT
        # declaring it, not by declaring it and excusing the result.
        if state == truth:
            verdicts.append((config_id, "claim-contradicted",
                             "the extractor read the TRUE value %s at a configuration where the "
                             "sentence claims its degradation applies, so the predicted %s does "
                             "not occur under the arrangement the sentence NAMES. That is a "
                             "mis-stated trigger, and it says nothing yet about whether the "
                             "degradation is reachable by some other arrangement -- read the "
                             "claim's correctionNote before concluding either way"
                             % (truth, predicted)))
            findings.append(
                "%s (%s): at %s the extractor read the true value %s where the sentence predicts "
                "%s, so the degradation does not occur under the arrangement the sentence names. "
                "DO NOT read this as the catalogue merely being over-cautious. That was this "
                "grader's own wording until an adversarial pass on 2026-08-17 falsified it for "
                "wipe.same-size-census: a probe outside the sentence's stated arrangement produced "
                "the degradation with a HELD control, so the trigger was wrong rather than the "
                "weakness imaginary. Which of the two this instance is has to be established by a "
                "probe, and the ledger's correctionNote is where the answer belongs."
                % (claim["claimId"], claim_where(claim), config_id, truth, predicted))
        elif state == predicted:
            verdicts.append((config_id, "claim-agrees",
                             "read %s where the true value is %s, exactly as the sentence "
                             "predicts (%s)" % (state, truth, claim.get("declaredDirection"))))
        else:
            verdicts.append((config_id, "claim-disagrees",
                             "read %s. The true value is %s and the sentence predicts %s, so the "
                             "reading is neither: the catalogue and the instrument do not agree "
                             "about this degradation" % (state, truth, predicted)))
            findings.append(
                "%s (%s): measured %s at %s, true value %s, sentence predicts %s. Either the "
                "sentence is wrong about the code or the code is wrong and the sentence described "
                "the intent; this file does not decide which, and the repair is never an edit to "
                "the ledger."
                % (claim["claimId"], claim_where(claim), state, config_id,
                   claim["groundTruth"], claim["predictedReading"]))
    return verdicts, findings


def grade_doctrine(claim, reports):
    """A doctrine claim asserts how the apparatus must be ARRANGED. The predicate is
    the arrangement the sentence prescribes, and it is stated per claim rather than
    inferred, because a generic "the control held" test would pass for arrangements
    the sentence says prove nothing."""
    verdicts, findings = [], []
    for config_id in claim.get("configs") or []:
        cell = cell_of(reports, config_id, claim["fixtureId"])
        if cell is None:
            verdicts.append((config_id, "claim-unreadable",
                             "configuration %s carries no cell %s" % (config_id, claim["fixtureId"])))
            continue
        counts = cell.get("counts") or {}
        if claim["claimId"] == "forbidden.control-polarity":
            # The prescribed arrangement: the control is a unit where the forbidden
            # call is CERTAINLY STILL PRESENT, which is what shows the extractor can
            # still see one at this level, while the subject reads clean. A control
            # chosen the other way round -- one that could go away -- proves nothing,
            # so both halves are checked and the control is checked at BOTH
            # checkpoints rather than only after the optimiser.
            ctl_pre = ((counts.get("control.preOptIr") or {}).get("forbiddenCallSites"))
            ctl_post = ((counts.get("control.postOptIr") or {}).get("forbiddenCallSites"))
            subj_post = ((counts.get("subject.postOptIr") or {}).get("forbiddenCallSites"))
            ok = (ctl_pre or 0) > 0 and (ctl_post or 0) > 0 and (subj_post or 0) == 0 \
                and cell.get("controlHeld") is True and cell.get("state") == "ABSENT"
            if ok:
                verdicts.append((config_id, "doctrine-held",
                                 "the control's forbidden call is present at both checkpoints "
                                 "(%s then %s) while the subject reads ABSENT, so a clean reading "
                                 "here is a detector that is quiet rather than one that has "
                                 "stopped working" % (ctl_pre, ctl_post)))
            else:
                verdicts.append((config_id, "doctrine-broken",
                                 "the prescribed arrangement does not hold: control %s/%s, "
                                 "subject post %s, controlHeld %r, state %r"
                                 % (ctl_pre, ctl_post, subj_post, cell.get("controlHeld"),
                                    cell.get("state"))))
                findings.append(
                    "%s (%s) at %s: the arrangement the sentence prescribes did not hold, so the "
                    "sentence's own justification for reading this cell as clean is not present."
                    % (claim["claimId"], claim_where(claim), config_id))
        else:
            verdicts.append((config_id, "claim-unreadable",
                             "no predicate is implemented for doctrine claim %r. A doctrine graded "
                             "by a generic test would pass for arrangements the sentence says prove "
                             "nothing, so this file refuses rather than guessing at one"
                             % claim["claimId"]))
    return verdicts, findings


def main(argv):
    for arg in argv:
        if arg.startswith("-"):
            print("usage: check-claims.py [report.json | directory ...]", file=sys.stderr)
            return 3

    try:
        with open(LEDGER, "r", encoding="utf-8") as fh:
            ledger = json.load(fh)
    except (ValueError, OSError) as exc:
        print("check-claims.py: cannot read the claims ledger: %s" % exc, file=sys.stderr)
        return 3

    reports, unreadable = load_reports(argv)

    breaks = fence(ledger)

    # N1: the ledger's own revision, against the standard's and against every report
    # it is about to grade.
    #
    # Added because the skew was LIVE: battery.json moved to revision 4 and this
    # ledger, claims/expected.json and the README all still said 3, so this file
    # printed "ledger revision 3" while grading revision-4 documents. Every fence in
    # this directory pins something to something else and none of them pinned the
    # answer files to the standard -- the same failure as the producer's header
    # saying "fifteen cells" after a sixteenth landed, in the files that hold the
    # answers.
    try:
        with open(os.path.join(HERE, "..", "battery.json"), "r", encoding="utf-8") as fh:
            std_rev = json.load(fh).get("standardRevision")
    except (ValueError, OSError) as exc:
        breaks.append("cannot read the standard's revision: %s" % exc)
        std_rev = None
    if std_rev is not None:
        if ledger.get("standardRevision") != std_rev:
            breaks.append(
                "standard-revision-skew: battery.json is at revision %r and this ledger says %r. "
                "A ledger written against another revision of the standard is a set of predictions "
                "about specimens that may no longer be the ones measured."
                % (std_rev, ledger.get("standardRevision")))
        for cfg, doc in sorted(reports.items()):
            doc_rev = (doc.get("standard") or {}).get("revision")
            if doc_rev != std_rev:
                breaks.append(
                    "standard-revision-skew: the %s report was assembled against revision %r and "
                    "the standard is at %r" % (cfg, doc_rev, std_rev))

    print("=== Experiment 1: the catalogue's degradation prose against the measurement ===")
    print("ledger revision %s, measured %s" % (ledger.get("standardRevision"), ledger.get("measuredOn")))
    print("reports read: %s" % (", ".join(sorted(k for k in reports if k)) or "none"))
    print("fenced scope: %s" % ", ".join((ledger.get("fencedScope") or {}).get("coversDegradationRiskOf") or []))
    print()

    findings = []
    tally = {"claim-agrees": 0, "claim-disagrees": 0, "claim-contradicted": 0,
             "claim-unreadable": 0, "doctrine-held": 0, "doctrine-broken": 0,
             "claim-deferred": 0, "claim-untestable-here": 0, "claim-not-a-prediction": 0,
             "omission-open": 0}

    fmt = "%-38s %-14s %-24s %s"
    print(fmt % ("claimId", "config", "verdict", "why"))
    print("-" * 130)

    for claim in ledger.get("claims") or []:
        cid = claim["claimId"]
        kind = claim.get("claimKind")
        testability = claim.get("testability")

        if testability == "deferred":
            tally["claim-deferred"] += 1
            print(fmt % (cid, "-", "claim-deferred", (claim.get("whyNotTested") or "")[:70]))
            continue
        if testability == "untestable-here":
            word = "claim-not-a-prediction" if kind == "scope" else "claim-untestable-here"
            tally[word] += 1
            print(fmt % (cid, "-", word, (claim.get("whyNotTested") or "")[:70]))
            continue

        if kind == "degradation":
            verdicts, f = grade_degradation(claim, reports)
        elif kind == "doctrine":
            verdicts, f = grade_doctrine(claim, reports)
        else:
            verdicts, f = [("-", "claim-not-a-prediction",
                            "claimKind %r defines no divergence to measure" % kind)], []
        findings.extend(f)
        for config_id, word, why in verdicts:
            tally[word] = tally.get(word, 0) + 1
            print(fmt % (cid, config_id, word, why[:70]))

    for claim in ledger.get("omissionClaims") or []:
        cid = claim["claimId"]
        # An omission's evidence is graded like a degradation claim -- the divergence
        # has to be MEASURED, or the omission is an assertion rather than a finding.
        verdicts, _f = grade_degradation(claim, reports)
        expressed = [v for v in verdicts if v[1] == "claim-agrees"]
        for config_id, word, why in verdicts:
            print(fmt % (cid, config_id, "omission-evidence:" + word, why[:60]))
        if expressed and claim.get("catalogueStatus") == "omission-open":
            tally["omission-open"] += 1
            print(fmt % (cid, "-", "omission-open",
                         "measured divergence that no fenced sentence describes"))
            findings.append(
                "%s: a divergence was MEASURED (%s) that no sentence in the fenced scope "
                "describes, so compiler/schema/properties.json is not a complete description of "
                "%s. Resolution: %s"
                % (cid, ", ".join("%s: true=%s read=%s" % (c, claim["groundTruth"],
                                                           claim["predictedReading"])
                                  for c, _w, _y in expressed),
                   claim.get("extractor"), (claim.get("resolution") or "")[:200]))
        elif not expressed:
            print(fmt % (cid, "-", "omission-unexpressed",
                         "the divergence was not reproduced, so the omission is not evidenced"))

    print()
    print("tally (integer pairs, never quotients -- interfaces.md section 5 rule 4):")
    total = sum(tally.values())
    for word in sorted(tally):
        if tally[word]:
            print("  %-24s {num: %d, den: %d}" % (word, tally[word], total))

    if breaks:
        print("\n%d coverage fence breakage(s):" % len(breaks), file=sys.stderr)
        for b in breaks:
            print("  " + b, file=sys.stderr)
    if unreadable:
        print("\n%d document(s) that could not be read:" % len(unreadable), file=sys.stderr)
        for u in unreadable:
            print("  " + u, file=sys.stderr)
    if findings:
        print("\n%d finding(s) -- Experiment 1's result, not a malfunction:" % len(findings),
              file=sys.stderr)
        for f in findings:
            print("  " + f, file=sys.stderr)

    if findings:
        print("\nExit 2. %s" % (ledger.get("knownFindings") or {}).get("howToReadTheExitCode", ""))
        return 2
    if breaks or unreadable or tally["claim-unreadable"]:
        return 3
    if not reports:
        print("\nno report was read, so no sentence was held against anything", file=sys.stderr)
        return 3
    # Every key is read through .get with a default. This line raised KeyError on
    # `claim-not-expressed`, a word that was renamed to `claim-contradicted` and left
    # behind here -- on the ONLY path that reports success, which no run had reached
    # because standard revision 4 has two open findings. The exit-0 contract was
    # unrunnable and nothing said so, which is the same class of defect as a grader
    # never shown to fail.
    agreed = tally.get("claim-agrees", 0) + tally.get("doctrine-held", 0)
    print("\nEvery measured sentence in the fenced scope agrees with the measurement, and no "
          "unmentioned divergence was reproduced. That is a statement about %d measured claim(s) "
          "only: %d are deferred for want of a specimen and %d cannot be produced by this "
          "apparatus at all."
          % (agreed,
             tally.get("claim-deferred", 0),
             tally.get("claim-untestable-here", 0) + tally.get("claim-not-a-prediction", 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
