#!/usr/bin/env python3
"""Grade the health of the frontier documents build-ladder-frontier.py assembled.

Same rule as check-envelope.py and check-matrix.py, and for the same reason: the
invariants below were written from what the ladder is for, not transcribed from a
run. A document that disagrees is printed as a disagreement. This file is not
edited to make a run pass.

WHAT IS GRADED, AND WHY EACH ONE IS AN INVARIANT RATHER THAN A READING

  * Every control held. interfaces.md section 4: a measurement whose control's
    count also fell to zero is a broken measurement, not a finding. Day 0 found
    this the hard way -- `vgl_a3_twin` wiped through a static helper, so at the
    pre-optimisation checkpoint the call in the unit was to the helper, whose
    name is not an effect symbol, the control read 0/1, and the whole a3 rung was
    a broken measurement dressed as data.

  * The wipe chain reads as a surviving prefix. a0..a3 escalate; a later rung
    surviving where an earlier one did not would mean the escalation is not one,
    which is a statement about the specimen and not about any compiler.
    NOT_APPLICABLE and BROKEN rungs are skipped -- see build-ladder-frontier.py's
    header and the -O1 column that forced that choice.

  * Exactly one spelling reads PRESENT in each of {b1-intr, b1-lib, b1-chk} and
    {d1-printf, d1-puts, d1-chk}. These are one subject read through three
    disjoint symbol lists, so two of them reading PRESENT means the lists are not
    disjoint and the b1/d1 rungs are not measuring what their names say.

  * The document's own `health` block agrees with these three recomputed from
    `frontier`. The builder assembles and this file decides; a checker that read
    the builder's verdict would be grading a claim rather than a measurement.

  * `frontier` agrees with `observations` rung by rung. `frontier` is the object
    a comparison is drawn over, and a `frontier` that has drifted from the
    observations under it is a comparison drawn over nothing.

WHAT IS NOT GRADED HERE

Two exposures are never compared. Whether frontier(A) differs from frontier(B) --
`exposure-mismatch`, `exposure-consistent`, `exposure-incomparable` -- is a
separate file's job, and a health checker that also compared would make an
unhealthy document look like a mismatch. For the same reason the tables below are
printed one document at a time and never side by side: a rung x exposure matrix
is the first half of a comparison this file is not allowed to make.

Exit codes follow interfaces.md section 7:

  0  every document was read and every invariant held
  2  an invariant was falsified. The instrument's own model is wrong, which is a
     finding about the instrument and not an average to be taken over documents.
  3  a document could not be looked at: missing, an unknown schemaVersion, a
     digest that does not recompute, a rung set that is not the ladder's twelve,
     or a rung that is BROKEN for a reason other than a control -- a rung that is
     not data is a rung nothing can be concluded from.

2 outranks 3 when both are present, and both are printed. A falsified invariant
is a positive finding about the instrument; an unreadable rung is an absence, and
reporting the absence in its place would hide the finding. Neither is 0.

Digest verification is a precondition, not one grade among several: a document
that does not hash to the value it carries is refused (3) and its invariants are
not graded at all, because grading a document that cannot be trusted is exactly
"we did not look" reported as a finding.
"""

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FRONTIERS = os.environ.get(
    "IRCK_LADDER_OUT", os.path.join(HERE, "..", "_results", "ladder"))

SCHEMA = "vibeguard.ladder-frontier/1"

# interfaces.md section 3, verbatim, plus the word the frontier uses for a rung
# that is not data. BROKEN is not a seventh state and never appears in a record;
# it exists only in the `frontier` map, where it must not be able to compare equal
# to a reading.
KNOWN_STATES = ("PRESENT", "ABSENT", "LOST", "REINTRODUCED",
                "NOT_APPLICABLE", "NOT_OBSERVED")
BROKEN = "BROKEN"

# The ladder's twelve rungs, in the order build-ladder-frontier.py writes them.
# Restated here rather than imported, so that a document is checked by something
# other than the code that wrote it -- the same reason build-envelope.py
# reimplements the canonicaliser instead of calling the observer's.
RUNGS = ("a0", "a1", "a2", "a3", "b1-intr", "b1-lib", "b1-chk",
         "c1", "c2", "d1-printf", "d1-puts", "d1-chk")
WIPE_CHAIN = ("a0", "a1", "a2", "a3")
SPELLING_GROUPS = (("b1-intr", "b1-lib", "b1-chk"),
                   ("d1-printf", "d1-puts", "d1-chk"))


def integers_only(obj, path="/"):
    """interfaces.md section 5 rule 4, walked to every depth. A float anywhere
    means the document could not have been canonicalised the way the section
    says, so its digest is unverifiable and the document is refused rather than
    rounded into shape."""
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


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + "/" + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + "/%d" % i)
    elif isinstance(obj, str):
        yield path, obj


def chain_monotone(frontier):
    """Recomputed from `frontier`, never read from `health`. NOT_APPLICABLE is
    skipped: it is section 3's word for the question having lost its referent,
    and the -O1 column measured on 2026-08-17 has a0 NOT_APPLICABLE with a1, a2
    and a3 all PRESENT. BROKEN is skipped because it is not data."""
    gap = None
    for rung in WIPE_CHAIN:
        state = frontier.get(rung)
        if state in (BROKEN, "NOT_APPLICABLE"):
            continue
        if state == "PRESENT":
            if gap is not None:
                return False, "%s reads PRESENT after %s did not" % (rung, gap)
        elif gap is None:
            gap = rung
    return True, None


def spelling_exclusive(frontier):
    """Counted over PRESENT alone. LOST does not count: at F2/F3 b1-lib reads
    LOST while b1-chk reads PRESENT, and under -O1/-O2/-O3/-Os/NB/FM d1-printf
    reads LOST while d1-puts reads PRESENT, so counting it would fail six of the
    eleven exposures measured on 2026-08-17. A group holding a BROKEN rung is not
    countable and is skipped; that rung is already reported separately."""
    details = []
    ok = True
    for group in SPELLING_GROUPS:
        if any(frontier.get(r) == BROKEN for r in group):
            details.append((group, None))
            continue
        present = [r for r in group if frontier.get(r) == "PRESENT"]
        details.append((group, present))
        if len(present) != 1:
            ok = False
    return ok, details


def load(path):
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
        return None, ("cannot be canonicalised, so its digest cannot be checked "
                      "and nothing in it can be trusted: %s" % exc)
    if recomputed != doc.get("evidenceDigest"):
        return None, ("digest mismatch: carries %r, recomputes to %r"
                      % (doc.get("evidenceDigest"), recomputed))
    if not doc.get("failureDirection"):
        return None, ("no failureDirection; a graded instrument that does not say "
                      "which way it fails cannot be read as one")
    frontier = doc.get("frontier")
    if not isinstance(frontier, dict) or tuple(sorted(frontier)) != tuple(sorted(RUNGS)):
        return None, ("frontier does not hold the ladder's %d rungs (%s)"
                      % (len(RUNGS), sorted(frontier) if isinstance(frontier, dict)
                         else type(frontier).__name__))
    obs = doc.get("observations")
    if (not isinstance(obs, list) or not all(isinstance(o, dict) for o in obs)
            or [o.get("rung") for o in obs] != list(RUNGS)):
        return None, "observations are not the ladder's twelve rungs, in order"
    return doc, None


def grade(name, doc):
    """Returns (problems, unreadable). Problems are exit 2; unreadable rungs are
    exit 3."""
    problems = []
    unreadable = []
    frontier = doc["frontier"]
    obs_by_rung = {o["rung"]: o for o in doc["observations"]}
    health = doc.get("health") or {}

    # --- format rules, the same predicate check-envelope.py applies ----------
    # Over every string, prose included. Under /exposure/ the strings are
    # command-line tokens rather than prose, so the reader applies the stricter
    # token rule the builder refuses on -- a document the writer would not have
    # written must not be one the reader accepts.
    for path, text in walk_strings(doc):
        absolute = (text.startswith("/") or "/root/" in text
                    or "/home/" in text or ":\\" in text)
        if not absolute and path.startswith("/exposure/"):
            _head, sep, tail = text.partition("=")
            absolute = ((sep and tail.startswith("/"))
                        or bool(re.match(r"^-[A-Za-z]{1,2}/", text)))
        if absolute:
            problems.append("%s: absolute path at %s: %r" % (name, path, text[:120]))

    # --- the frontier says what the observations say -------------------------
    for rung in RUNGS:
        o = obs_by_rung[rung]
        expected = BROKEN if o.get("broken") else o.get("state")
        if frontier[rung] != expected:
            problems.append(
                "%s %s: frontier says %r and the observation under it says %r. The "
                "frontier is what a comparison is drawn over, so a frontier that "
                "has drifted from its observations is a comparison over nothing."
                % (name, rung, frontier[rung], expected))
        if frontier[rung] != BROKEN and frontier[rung] not in KNOWN_STATES:
            problems.append("%s %s: %r is neither BROKEN nor one of the six states "
                            "in interfaces.md section 3"
                            % (name, rung, frontier[rung]))

    # --- every control held --------------------------------------------------
    for rung in RUNGS:
        o = obs_by_rung[rung]
        if o.get("controlHeld") is False:
            problems.append(
                "%s %s: the control did not hold (%s -> %s), so this rung cannot "
                "tell a removed effect from an oracle that stopped working "
                "(interfaces.md section 4)"
                % (name, rung, o.get("controlEffectPre"), o.get("controlEffectPost")))

    # `is not False`, not `is True`. interfaces.md section 3.1 pairs a rung that
    # produced no reading with controlHeld null, which is not a claim that a
    # control was run and failed. A rung with no control to report on is reported
    # by `broken` and lands in `unreadable` below; calling its twin fallen would
    # be a fixture bug invented for a measurement that did not happen.
    twins_held = not any(obs_by_rung[r].get("controlHeld") is False for r in RUNGS)

    # --- the two structural invariants, recomputed ---------------------------
    monotone, why_not = chain_monotone(frontier)
    if not monotone:
        problems.append(
            "%s: the wipe chain is not a surviving prefix -- %s. a0..a3 escalate, "
            "so a later rung surviving where an earlier one did not says the "
            "specimen is not the ladder it claims to be." % (name, why_not))

    exclusive, spelling_detail = spelling_exclusive(frontier)
    if not exclusive:
        for group, present in spelling_detail:
            if present is None or len(present) == 1:
                continue
            problems.append(
                "%s: %s read PRESENT in {%s}; these are one subject read through "
                "three disjoint symbol lists, so anything but exactly one means "
                "the lists are not disjoint and the group is not measuring what "
                "its names say"
                % (name, ",".join(present) if present else "no rung", "/".join(group)))

    # --- the builder's own health block agrees with all of that --------------
    for key, recomputed in (("twinsHeld", twins_held),
                            ("chainMonotone", monotone),
                            ("spellingExclusive", exclusive),
                            ("broken", any(obs_by_rung[r].get("broken")
                                           for r in RUNGS))):
        if key not in health:
            problems.append("%s: health has no %s" % (name, key))
        elif bool(health[key]) != bool(recomputed):
            problems.append(
                "%s: health.%s says %r and this file recomputes %r from the "
                "frontier. The builder assembles and this file decides; a "
                "disagreement between them is the disagreement, not a tie."
                % (name, key, health[key], recomputed))

    # --- rungs that are not data --------------------------------------------
    # A control that did not hold is already a problem above; the rest are rungs
    # nothing can be concluded from, which is a check that could not be
    # completed rather than a check that failed.
    for rung in RUNGS:
        o = obs_by_rung[rung]
        if o.get("broken") and o.get("controlHeld") is not False:
            unreadable.append("%s %s: %s"
                              % (name, rung, o.get("brokenReason") or "broken"))

    return problems, unreadable


def print_table(name, doc):
    ex = doc.get("exposure") or {}
    ld = doc.get("ladder") or {}
    tc = doc.get("toolchain") or {}
    print("=== %s ===" % name)
    print("exposure %s   %s"
          % (ex.get("id"),
             " ".join([ex.get("opt", "")] + list(ex.get("extraArgs") or []))))
    print("ladder %s gen %s/%s src %s   %s clang %s   plugin %s"
          % (ld.get("id"), ld.get("generatorVersion"),
             (ld.get("generatorSha256") or "")[:12],
             (ld.get("sourceSha256") or "")[:12],
             tc.get("cc"), tc.get("clang"),
             (tc.get("pluginSha256") or "absent")[:12]))

    fmt = "%-10s %-15s %-6s %-5s %-5s %-18s %-9s %-19s %s"
    hdr = fmt % ("rung", "frontier", "twin", "pre", "post", "first-loss",
                 "subject", "control", "note")
    print(hdr)
    print("-" * len(hdr))
    obs_by_rung = {o["rung"]: o for o in doc["observations"]}
    for rung in RUNGS:
        o = obs_by_rung[rung]
        held = o.get("controlHeld")
        print(fmt % (rung, doc["frontier"][rung],
                     {True: "held", False: "FELL", None: "-"}[held],
                     "-" if o.get("effectPre") is None else o["effectPre"],
                     "-" if o.get("effectPost") is None else o["effectPost"],
                     o.get("firstLossPass") or "-",
                     o.get("subjectUnit") or "-", o.get("controlUnit") or "-",
                     o.get("brokenReason") or ""))
    h = doc.get("health") or {}
    print("health: twinsHeld=%s chainMonotone=%s spellingExclusive=%s broken=%s"
          % (h.get("twinsHeld"), h.get("chainMonotone"),
             h.get("spellingExclusive"), h.get("broken")))
    print()


def targets(argv):
    """A document, or a directory of them. Directories are expanded in name
    order so that a sweep prints in the same order twice."""
    paths = argv or [FRONTIERS]
    out = []
    missing = []
    for p in paths:
        if os.path.isdir(p):
            found = sorted(n for n in os.listdir(p) if n.endswith(".json"))
            if not found:
                missing.append("no frontier documents in %s" % p)
            out.extend(os.path.join(p, n) for n in found)
        elif os.path.exists(p):
            out.append(p)
        else:
            missing.append("no such path: %s" % p)
    return out, missing


def usage():
    print("usage: check-ladder.py [frontier.json | directory ...]", file=sys.stderr)
    print("  with no arguments, $IRCK_LADDER_OUT is graded", file=sys.stderr)
    return 1


def main(argv):
    for arg in argv:
        if arg.startswith("-"):
            return usage()

    paths, unreadable = targets(argv)
    if not paths and not unreadable:
        print("nothing to grade", file=sys.stderr)
        return 3

    problems = []
    graded = 0
    for path in paths:
        name = os.path.basename(path)
        doc, why = load(path)
        if doc is None:
            unreadable.append("%s: %s" % (name, why))
            continue
        print_table(name, doc)
        p, u = grade(name, doc)
        problems.extend(p)
        unreadable.extend(u)
        graded += 1

    print("%d document(s) graded of %d found." % (graded, len(paths)))

    if problems:
        print("\n%d disagreement(s):" % len(problems), file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
    if unreadable:
        print("\n%d thing(s) that could not be looked at:" % len(unreadable),
              file=sys.stderr)
        for u in unreadable:
            print("  " + u, file=sys.stderr)

    if problems:
        return 2
    if unreadable:
        return 3
    if graded == 0:
        print("no document was graded", file=sys.stderr)
        return 3
    print("all %d document(s) satisfy the health invariants in this file." % graded)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
