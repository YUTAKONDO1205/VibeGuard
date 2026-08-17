#!/usr/bin/env python3
"""Assemble one `vibeguard.ladder-frontier/1` document from the twelve records
a single ladder exposure produced.

WHAT THE DOCUMENT IS FOR

The fallback lookup keys a measured envelope by a nominal six-axis config key
(cc, freestanding, lto, ndebug, opt, target). Two command lines that differ in
nothing that key names produce the same key -- measured on 2026-08-17, `-O2` and
`-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3` and `-O2 -fno-builtin-memset` and
`-O2 -ffast-math` all key identically -- so a cell measured under one of them can
be quoted for another. The ladder is a small graded specimen compiled separately
under the real build's exact flags; the set of rungs that survived is a MEASURED
index of what this invocation's optimiser does to property-shaped code. This file
turns twelve records into the one comparable object, the `frontier` map, that a
guard can hold up against the frontier recorded for the cell it is about to
quote.

It ASSEMBLES. It does not grade -- check-ladder.py grades health, and comparing
two frontiers belongs to neither of them. The same split as run-envelope.sh and
build-envelope.py, for the same reason: a component that decides whether its own
reading is good is not a measurement.

WHAT IT IS NOT FOR

Filling or selecting envelope cells. A ladder cell is a (ladder-subject, config)
measurement and says nothing whatever about the user's subject; using one to
choose the other would repeat derive-fallback-table.mjs's documented mistake #1
one level up. The frontier is a guard input and nothing else, and this file
therefore emits nothing shaped like a `vibeguard.fallback-table/1` row.

WHY THERE IS NO `config` IN THE DOCUMENT

Deliberate, and not an omission for a later maintainer to fix. The document
records the exposure as it was measured -- `exposure.opt` and
`exposure.extraArgs` off the manifest's argv, `toolchain.cc` off the driver the
runner invoked -- and stops there. Turning those into
the nominal six-axis key the fallback table files its rows under is the
deriver's job: compiler/envelope/derive-frontier-sidecar.mjs runs the driver's
own `normalise()` and `driverConfigAxes()` over exactly these fields, so the key
a frontier is filed under and the key a build is looked up by come from one
definition instead of two.

Computing the key here, in Python, would be that second definition, and its
failure mode is silent. A key that differs from the driver's in one axis does not
raise: it simply never matches, and an entry that never matches reads as "no
frontier was measured for this build", which is a refusal -- so nothing goes red
and the guard stops guarding without saying so. That is the defect this whole
instrument exists to catch, reproduced one level up inside it.

WHAT IT READS

  $IRCK_LADDER_LAB/records/<exposure-id>/<rung>.json   twelve `ir-checkpoints-v0` records
  $IRCK_LADDER_MANIFESTS/<exposure-id>.kv              what was compiled, and with what

A record says what was observed and not what was built -- the same gap
build-envelope.py exists to close -- so the manifest is not optional garnish. The
runner owns it and this file reads the keys run-ladder.sh emits:

  exposureId=<id>       required; must match the directory the records are under
  opt=-O2               required; the optimisation token, and argv's first line
  argvB64=<base64>      required; opt then the extra arguments, newline
                        separated, already tilde-sanitised by the runner
  ladderSha256=<64 hex> required; sha256 of the emitted ladder.c
  generatorSha256=<hex> required; sha256 of the generator that emitted it
  rungs=a0,a1,...       required; the rung ids in table order
  rc=0                  non-zero refuses the exposure; absent reads 0
  refusal=<word>        the runner's word for why; non-empty refuses the exposure
  records=records/<id>  where the records went, relative to the lab
  cc / ccVersion / pluginSha256 / rungCount / rungsObserved / sourceDateEpoch
                        provenance. `rungsObserved` is not read: how many records
                        exist is answered by opening them, and a count that
                        disagreed with the directory would be the less trustworthy
                        of the two.

Two things are read rather than assumed. `rungs` is checked against this file's
rung table, because twelve records written by a different table are twelve
records of a different instrument and a frontier assembled from them would
compare against one measured here as though the rungs meant the same thing. And
the raw argv stays in the manifest: the document carries only `opt` plus the
sanitised remainder, because interfaces.md section 5 forbids an absolute path
anywhere in a record and says a component that cannot avoid one reports the
problem instead of emitting it. That is what the refusal below does.

`IRCK_LADDER_MANIFESTS` is the one knob if the runner puts them elsewhere.

`ladder.generatorVersion` is this file's own integer, not the runner's: the
runner identifies its generator by digest and a digest is the better identity, so
`generatorSha256` travels beside the integer and is what `exposure-incomparable`
should be decided on. The integer is kept because the document shape declares one
and because a change to what a rung *means* needs a coarse number a reader can
compare without holding both generators. A manifest that names one wins.

TWO DECISIONS THE MEASURED TABLE FORCED, WRITTEN DOWN RATHER THAN GUESSED

`health.chainMonotone` -- the wipe chain a0,a1,a2,a3 must read as a surviving
prefix: once a rung is not PRESENT no later rung may be PRESENT. NOT_APPLICABLE
is EXCLUDED from the chain rather than counted as a gap. The -O1 column measured
on 2026-08-17 is why: a0 reads NOT_APPLICABLE there (its two wipes are on an
object the optimiser promoted out of memory) while a1, a2 and a3 all read
PRESENT. Counting NOT_APPLICABLE as a gap would report -O1 as a falsified
instrument, and it would do so for the one reason section 3 says is not a loss --
"the question no longer has the same referent". A rung that is not data cannot
be evidence that the chain broke. BROKEN rungs are excluded for the same reason.

`health.spellingExclusive` -- within {b1-intr, b1-lib, b1-chk} and within
{d1-printf, d1-puts, d1-chk} exactly one rung may read PRESENT. LOST does NOT
count as present. The measured table decides this and not taste: at F2 and F3,
b1-lib reads LOST while b1-chk reads PRESENT, and at -O1/-O2/-O3/-Os/NB/FM
d1-printf reads LOST while d1-puts reads PRESENT. Counting LOST as present would
report six of the eleven measured exposures as a broken instrument. It would also
be asking the wrong question: these three rungs are one subject observed through
three disjoint spelling lists (matchesSymbol is exact-match or prefix-then-dot,
so "memset" never matches "llvm.memset.p0.i64"), and what exclusivity is for is
"which spelling survives to be compared", not "how many spellings the front end
ever emitted". A group containing a BROKEN rung cannot be counted and is skipped;
`health.broken` already says so.

Exit codes follow interfaces.md section 7: 0 a document was written, 3 there was
nothing to assemble or something in the way of assembling it. 1 is a usage error
-- the caller was wrong and no check was attempted, which is deliberately not 3,
because 3 is reserved for a check that could not be completed.
"""

import base64
import hashlib
import json
import os
import re
import sys
import time

LAB = os.environ.get("IRCK_LADDER_LAB",
                     os.path.expanduser("~/vg-lab/llvm-pass-ladder"))
RECORDS = os.path.join(LAB, "records")
MANIFESTS = os.environ.get("IRCK_LADDER_MANIFESTS", os.path.join(LAB, "exposures"))
HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.environ.get(
    "IRCK_LADDER_OUT", os.path.join(HERE, "..", "_results", "ladder"))

SCHEMA = "vibeguard.ladder-frontier/1"
RECORD_SCHEMA = "ir-checkpoints-v0"
COMPONENT = "IrCheckpoints"
LADDER_ID = "ladder"

# What a rung MEANS. Bumped only when the rung table below changes such that a
# frontier from before the change cannot be read against one from after it --
# a rung added, removed, or repointed at a different subject or symbol list.
# Not bumped for a change to the specimen's text, which `ladder.sourceSha256`
# already distinguishes, nor for a change to the generator, which
# `ladder.generatorSha256` already distinguishes.
LADDER_GENERATION = 1

# The property-state vocabulary, interfaces.md section 3, verbatim and in section
# order. A state that arrives from a record is checked against it: a word this
# file does not know is a record from something that is not the observer, and it
# is not put in a frontier that another component will compare.
KNOWN_STATES = ("PRESENT", "ABSENT", "LOST", "REINTRODUCED",
                "NOT_APPLICABLE", "NOT_OBSERVED")

# Not a seventh state and never written into one. This word only ever appears in
# the `frontier` map, where it means "this rung is not data" -- the control did
# not hold, or the subject was not in the unit at the first checkpoint, or no
# usable record came back. interfaces.md section 4: a run whose control reached
# zero is a broken measurement, not a finding.
BROKEN = "BROKEN"

# Verbatim from run-envelope.sh:55. Spelled here rather than imported because the
# ladder is compiled by its own runner and a shared constant that drifted would
# silently change what "a1 is PRESENT" means between two frontiers that are then
# compared as though they measured the same thing.
WIPE_SYMS = ("llvm.memset", "memset", "explicit_bzero", "bzero",
             "__memset_chk", "memset_s")

# rung -> (extractor, subject unit, control unit, oracle symbols).
#
# This is the ladder's identity. A frontier is only comparable with another
# frontier if "a1" names the same measurement in both, so a record whose
# extractor, subject, control or symbol list is not the one this rung declares is
# a mis-wired run and its rung is marked BROKEN rather than read. The three
# spelling lists are disjoint under matchesSymbol (Extractors.cpp:91-98), which is
# what makes b1-intr/b1-lib/b1-chk three readings of one subject.
RUNG_SPEC = (
    ("a0",        "ir.wipe-effect",      "vgl_a0", "vgl_a1_twin",        WIPE_SYMS),
    ("a1",        "ir.wipe-effect",      "vgl_a1", "vgl_a1_twin",        WIPE_SYMS),
    ("a2",        "ir.wipe-effect",      "vgl_a2", "vgl_a2_twin",        WIPE_SYMS),
    ("a3",        "ir.wipe-effect",      "vgl_a3", "vgl_a3_twin",        WIPE_SYMS),
    ("b1-intr",   "ir.wipe-effect",      "vgl_b1", "vgl_ctl_intr",       ("llvm.memset",)),
    ("b1-lib",    "ir.wipe-effect",      "vgl_b1", "vgl_ctl_lib",        ("memset",)),
    ("b1-chk",    "ir.wipe-effect",      "vgl_b1", "vgl_ctl_chk",        ("__memset_chk",)),
    ("c1",        "ir.guarded-call",     "vgl_c1", "vgl_c1_twin",        ("vgl_deny",)),
    ("c2",        "ir.guarded-call",     "vgl_c2", "vgl_c1_twin",        ("vgl_deny",)),
    ("d1-printf", "ir.forbidden-callee", "vgl_d1", "vgl_ctl_printf",     ("printf",)),
    ("d1-puts",   "ir.forbidden-callee", "vgl_d1", "vgl_ctl_puts",       ("puts",)),
    ("d1-chk",    "ir.forbidden-callee", "vgl_d1", "vgl_ctl_printf_chk", ("__printf_chk",)),
)

# The wipe chain, in escalating order. a0 wipes and returns, a3 wipes through the
# most indirection; a later rung surviving where an earlier one did not would mean
# the escalation is not an escalation.
WIPE_CHAIN = ("a0", "a1", "a2", "a3")

# One subject, three disjoint spellings. See the header for why exclusivity is
# counted over PRESENT alone.
SPELLING_GROUPS = (("b1-intr", "b1-lib", "b1-chk"),
                   ("d1-printf", "d1-puts", "d1-chk"))

# An LTO command line is refused at measurement time rather than measured: with
# -flto the optimisation this instrument reads happens in the linker, over a
# module the ladder's single translation unit is not, so a frontier taken from the
# pre-link compile would be a reading of something other than the build. Fenced
# here as well as in the runner, because assembling one would launder it.
#
# `-fno-lto` is deliberately NOT in this list. The refusal is not about the
# spelling but about where the optimiser runs, and -fno-lto is the flag that
# keeps it in the compile where this instrument can see it.
LTO_TOKENS = ("-flto", "--flto")

# interfaces.md section 5 puts this outside `context` and inside the digest.
# Restated by the document rather than left to a reader's memory, because the
# thing most easily misread about a graded instrument is which way it fails.
FAILURE_DIRECTION = (
    "Fails towards exposure-consistent. The ladder is a single-TU synthetic "
    "specimen: cross-translation-unit inlining, profile data, -march code "
    "generation, stack-protector variants and everything downstream of the IR "
    "optimiser are invisible to its three extractors, so two genuinely different "
    "exposures can present identical frontiers. A consistent reading is "
    "necessary, never sufficient. The opposite direction is clean: with a "
    "deterministic compiler a differing frontier under an identical ladder is "
    "evidence of a differing exposure, and refusing to quote the cell is the "
    "correct reading. Measured limits, clang 18.1.3 on 2026-08-17: -O2, -O3 and "
    "-Os are indistinguishable to this rung set, and so are _FORTIFY_SOURCE=2 "
    "and =3. Any command line carrying an LTO token is refused at measurement "
    "time rather than measured. What is bound is the flag sequence and the "
    "compiler, not the header set: no rung reads a header, so two builds whose "
    "flags and compiler agree present one exposure even where their include "
    "paths resolve to different headers. And a command line carrying a "
    "path-bearing flag -- -I/usr/local/include, --sysroot=/opt/vendor -- cannot "
    "have a frontier assembled at all, because section 5 will not let a host path "
    "into a digested document; vendor-sysroot and cross builds are therefore "
    "outside this guard's coverage rather than quietly inside it.")

EXPOSURE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class Refused(Exception):
    """Something the document cannot be assembled without. Carried to main() so
    that every refusal leaves by one door and none of them can be a return 0."""


def integers_only(obj, path="/"):
    """interfaces.md section 5 rule 4, walked to every depth.

    Written recursively on purpose. A top-level isinstance check never sees the
    numbers, which all live in nested objects, so it would pass a document
    carrying a float and the canonicaliser would be asserting nothing. `bool` is
    a subclass of `int` in Python and is not a number here -- it serialises as
    true/false -- so the test is on `float` alone."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            integers_only(v, path + str(k) + "/")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            integers_only(v, path + "%d/" % i)
    elif isinstance(obj, float):
        raise ValueError(
            "non-integer number %r at %s; section 5 rule 4 says a ratio is a "
            "pair {\"num\":n,\"den\":d} and that the canonicaliser fails rather "
            "than rounding" % (obj, path))


def canonical(obj):
    """interfaces.md section 5: keys sorted at every level, array order
    untouched, no insignificant whitespace, every number an integer."""
    integers_only(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest_of(doc):
    """Section 5 rule 1: `context` and `evidenceDigest` come off as whole
    subtrees at the top level, and nothing else comes off at any depth."""
    stripped = {k: v for k, v in doc.items()
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


def b64_lines(s):
    if not s:
        return []
    text = base64.b64decode(s.encode("ascii")).decode("utf-8", "replace")
    return [line for line in text.split("\n") if line]


def sanitise(arg):
    """observe-config.sh:60, in the same order and with the same two rules:

        sed -e "s#$HOME#~#g" -e "s#$LAB#<lab>#g"

    The order matters and is copied rather than improved. When the lab is under
    the home directory -- it is, by default -- the first substitution has already
    turned the lab prefix into `~/...` by the time the second runs, so the second
    is a no-op there and the lab is spelled `~/vg-lab/...`. Reordering would emit
    `<lab>` instead, and two frontiers whose only difference was which version of
    this function wrote them would not compare equal."""
    home = os.path.expanduser("~")
    out = arg
    if home and home != "/":
        out = out.replace(home, "~")
    if LAB and LAB != "/":
        out = out.replace(LAB, "<lab>")
    return out


def looks_absolute(s):
    """The same predicate check-envelope.py applies to a whole envelope, kept
    character-for-character identical so that the writer and the reader of a
    document cannot disagree about what an absolute path is. It runs over every
    string in the document, prose included, which is why it is not widened: a
    rule loose enough to catch every flag that can carry a path is also loose
    enough to fire on an English sentence."""
    return s.startswith("/") or "/root/" in s or "/home/" in s or ":\\" in s


def arg_carries_path(arg):
    """The stricter rule, applied only to command-line tokens.

    `looks_absolute` has a known blind spot on an argument: the path in
    `-I/opt/vendor` or `--sysroot=/opt/vendor` starts partway through the string
    and lies under neither /root nor /home, so none of its four tests fire.
    `extraArgs` are tokens rather than prose, so the blind spot can be closed
    here without the false positives that would follow from closing it
    everywhere. The sanitised form observe-config.sh emits -- `--sysroot=~/...`
    -- is deliberately still accepted: a tilde is what sanitising an in-home path
    produces, and refusing it would refuse every cross-target invocation."""
    if looks_absolute(arg):
        return True
    _head, sep, tail = arg.partition("=")
    if sep and tail.startswith("/"):
        return True
    return bool(re.match(r"^-[A-Za-z]{1,2}/", arg))


def context_block():
    """interfaces.md section 5: everything a re-run cannot reproduce, and
    nothing else. The host is not recorded -- the records do not record it
    either, and a machine's name in a document that may be quoted elsewhere is a
    disclosure, not provenance."""
    sde = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if sde:
        return {"assembledBy": "build-ladder-frontier.py",
                "generatedAt": int(sde), "host": "unrecorded",
                "sourceDateEpoch": int(sde), "timeSource": "SOURCE_DATE_EPOCH"}
    return {"assembledBy": "build-ladder-frontier.py",
            "generatedAt": int(time.time()), "host": "unrecorded",
            "sourceDateEpoch": None, "timeSource": "wall-clock"}


def walk_strings(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, path + "/" + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, path + "/%d" % i)
    elif isinstance(obj, str):
        yield path, obj


def read_record(path):
    """Returns (record, why-it-is-unusable). Never raises on bad input: a rung
    that cannot be read is a BROKEN rung in one exposure, not a reason to refuse
    the other eleven."""
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return None, "no record was written"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            rec = json.load(fh)
    except (ValueError, OSError) as exc:
        return None, "record unreadable: %s" % exc
    if not isinstance(rec, dict):
        return None, "record is not an object"
    return rec, None


def record_digest_verified(rec):
    """Recomputed here, independently of the C++ that wrote it. A record that no
    longer hashes to the value it carries is interfaces.md section 3.1's
    BROKEN_MEASUREMENT and its verdict is not read."""
    try:
        return digest_of(rec) == rec.get("evidenceDigest")
    except (ValueError, TypeError) as exc:
        # A record carrying a float cannot be canonicalised at all. That is not a
        # crash here: it is a record this assembler will not read, which is
        # exactly what an unverified digest already means.
        print("  record could not be canonicalised (%s)" % exc, file=sys.stderr)
        return False


def observation_for(spec, rec, why):
    """One row of `observations`, and the BROKEN decision for one rung.

    A rung is BROKEN when it is not data: no usable record, a record that is not
    this observer's, a record wired to a different subject/control/extractor/
    symbol list than the rung declares, a control that did not hold
    (interfaces.md section 4), or a subject unit that was not in the module at
    the pre-optimisation checkpoint. Nothing else is BROKEN -- in particular
    `subject.preOptIr.effect == 0` is NOT: that is the ABSENT reading, measured
    at a3 under -O0 and at b1-chk under everything but FORTIFY, and calling it
    broken would delete the rungs that discriminate."""
    rung, extractor, subject_unit, control_unit, symbols = spec
    obs = {
        "rung": rung,
        "extractor": extractor,
        "subjectUnit": subject_unit,
        "controlUnit": control_unit,
        "state": None,
        "controlHeld": None,
        "controlEffectPre": None,
        "controlEffectPost": None,
        "effectPre": None,
        "effectPost": None,
        "subjectUnitPresentPreOpt": None,
        "firstLossPass": None,
        "recordDigest": None,
        "recordDigestVerified": False,
        "broken": True,
        "brokenReason": "",
    }

    if rec is None:
        obs["brokenReason"] = why
        return obs

    if rec.get("schemaVersion") != RECORD_SCHEMA or rec.get("component") != COMPONENT:
        obs["brokenReason"] = ("record is %r/%r, not %r/%r"
                               % (rec.get("component"), rec.get("schemaVersion"),
                                  COMPONENT, RECORD_SCHEMA))
        return obs

    obs["recordDigest"] = rec.get("evidenceDigest")
    obs["recordDigestVerified"] = record_digest_verified(rec)
    if not obs["recordDigestVerified"]:
        obs["brokenReason"] = "record does not hash to the digest it carries"
        return obs

    got = (rec.get("extractor"), rec.get("subjectUnit"), rec.get("controlUnit"),
           tuple((rec.get("oracle") or {}).get("symbols") or ()))
    want = (extractor, subject_unit, control_unit, tuple(symbols))
    if got != want:
        obs["brokenReason"] = ("record is wired to %s/%s/%s/%s; this rung declares "
                               "%s/%s/%s/%s"
                               % (got[0], got[1], got[2], ",".join(got[3]),
                                  want[0], want[1], want[2], ",".join(want[3])))
        return obs

    state = (rec.get("verdict") or {}).get("state")
    if state not in KNOWN_STATES:
        obs["brokenReason"] = ("verdict state %r is not one of the six in "
                               "interfaces.md section 3" % (state,))
        return obs

    subject = rec["subject"]
    control = rec["control"]
    obs["state"] = state
    obs["controlHeld"] = bool(control["held"])
    obs["controlEffectPre"] = control["preOptIr"]["effect"]
    obs["controlEffectPost"] = control["postOptIr"]["effect"]
    obs["effectPre"] = subject["preOptIr"]["effect"]
    obs["effectPost"] = subject["postOptIr"]["effect"]
    obs["subjectUnitPresentPreOpt"] = bool(subject["preOptIr"]["unitPresent"])
    obs["firstLossPass"] = (rec.get("firstZeroTransition") or {}).get("pass")

    if not obs["controlHeld"]:
        obs["brokenReason"] = ("the control did not hold (%s -> %s), so this rung "
                               "cannot tell a removed effect from an oracle that "
                               "stopped working"
                               % (obs["controlEffectPre"], obs["controlEffectPost"]))
        return obs
    if not obs["subjectUnitPresentPreOpt"]:
        obs["brokenReason"] = ("the subject unit was not in the module at the "
                               "pre-optimisation checkpoint")
        return obs

    obs["broken"] = False
    return obs


def chain_monotone(frontier):
    """Returns (bool, offending rung). NOT_APPLICABLE and BROKEN are skipped --
    see the header, and the -O1 column that forced it."""
    gap = None
    for rung in WIPE_CHAIN:
        state = frontier[rung]
        if state in (BROKEN, "NOT_APPLICABLE"):
            continue
        if state == "PRESENT":
            if gap is not None:
                return False, rung
        elif gap is None:
            gap = rung
    return True, None


def spelling_exclusive(frontier):
    """Returns (bool, list of (group, rungs reading PRESENT)). Counted over
    PRESENT alone; a group holding a BROKEN rung is not countable and is
    skipped, which `health.broken` already reports."""
    bad = []
    for group in SPELLING_GROUPS:
        if any(frontier[r] == BROKEN for r in group):
            continue
        present = [r for r in group if frontier[r] == "PRESENT"]
        if len(present) != 1:
            bad.append((group, present))
    return (not bad), bad


def read_manifest(exposure_id):
    path = os.path.join(MANIFESTS, exposure_id + ".kv")
    if not os.path.exists(path):
        raise Refused("%s: no manifest at %s. A record says what was observed and "
                      "not what was built; without the invocation the reading "
                      "cannot be compared with any other reading."
                      % (exposure_id, path.replace(os.path.expanduser("~"), "~")))
    kv = read_kv(path)

    for required in ("exposureId", "opt", "argvB64", "ladderSha256",
                     "generatorSha256", "rungs"):
        if not kv.get(required):
            raise Refused("%s: the manifest has no %s=" % (exposure_id, required))
    if kv["exposureId"] != exposure_id:
        raise Refused("%s: the manifest calls this exposure %r; the records are "
                      "under a different name and one of the two is wrong"
                      % (exposure_id, kv["exposureId"]))
    if not HEX64_RE.match(kv["ladderSha256"]):
        raise Refused("%s: ladderSha256=%r is not lowercase 64-hex"
                      % (exposure_id, kv["ladderSha256"]))

    # The rung table, checked rather than assumed. Twelve records written by a
    # different table are twelve records of a different instrument, and a
    # frontier assembled from them would be compared against one measured here as
    # though `a1` named the same question in both.
    declared = tuple(r for r in kv["rungs"].split(",") if r)
    if declared != tuple(spec[0] for spec in RUNG_SPEC):
        raise Refused("%s: the runner's rung table is %s and this file's is %s; "
                      "two tables are two instruments"
                      % (exposure_id, ",".join(declared),
                         ",".join(spec[0] for spec in RUNG_SPEC)))

    rc = kv.get("rc", "0")
    if rc not in ("", "0"):
        raise Refused("%s: the manifest records rc=%s%s. The run did not complete, "
                      "so whatever is under records/ is not a reading of this "
                      "exposure."
                      % (exposure_id, rc,
                         " (%s)" % kv["refusal"] if kv.get("refusal") else ""))
    if kv.get("refusal"):
        raise Refused("%s: the runner recorded refusal=%s"
                      % (exposure_id, kv["refusal"]))

    # The runner writes opt as argv's first line. Splitting there rather than
    # asking for a second base64 field keeps one spelling of the invocation in
    # the manifest, which is the point of the manifest carrying the raw argv.
    argv = [sanitise(a) for a in b64_lines(kv["argvB64"])]
    if not argv or argv[0] != kv["opt"]:
        raise Refused("%s: argv starts with %r and opt is %r; the document's "
                      "`opt` and `extraArgs` would not add up to the command line "
                      "that was run"
                      % (exposure_id, argv[0] if argv else None, kv["opt"]))
    extra = argv[1:]

    leaked = [a for a in argv if arg_carries_path(a)]
    if leaked:
        raise Refused("%s: %d argument(s) still hold an absolute path after "
                      "sanitising (%s). interfaces.md section 5 says a component "
                      "that cannot avoid one reports the problem instead of "
                      "emitting it." % (exposure_id, len(leaked), "; ".join(leaked)))

    lto = [t for t in argv if t.split("=")[0] in LTO_TOKENS or t in LTO_TOKENS]
    if lto:
        raise Refused("%s: the command line carries %s. An LTO build optimises in "
                      "the linker over a module this single-TU specimen is not, so "
                      "the frontier would be a reading of something other than the "
                      "build. Refused rather than measured."
                      % (exposure_id, ", ".join(lto)))

    try:
        generator_version = int(kv.get("generatorVersion", LADDER_GENERATION))
    except ValueError:
        raise Refused("%s: generatorVersion=%r is not an integer, and section 5 "
                      "rule 4 will not let it into the document"
                      % (exposure_id, kv["generatorVersion"]))

    return {
        "generatorVersion": generator_version,
        "generatorSha256": kv["generatorSha256"],
        "sourceSha256": kv["ladderSha256"],
        "opt": kv["opt"],
        "extraArgs": extra,
        "records": kv.get("records", os.path.join("records", exposure_id)),
        "pluginSha256": kv.get("pluginSha256", "absent"),
        "ccVersion": kv.get("ccVersion", ""),
        "cc": kv.get("cc", ""),
    }


def toolchain_from(seen, manifest):
    """The compiler is read off the records, not off the manifest: the manifest
    is what the runner meant to invoke and the record is what the observer saw.
    Two different compilers in one frontier is refused for the same reason
    check-envelope.py refuses two plugin builds in one envelope -- readings from
    different observers cannot be compared."""
    if not seen:
        raise Refused("no record in this exposure names a toolchain")
    if len(seen) > 1:
        raise Refused("this exposure was measured by %d different toolchains (%s); "
                      "readings from different compilers are not one frontier"
                      % (len(seen), sorted(k[0] for k in seen)))
    clang, digest = next(iter(seen))
    # The runner records the driver's whole `--version` first line and the
    # observer records the version alone, so this is a containment test and not
    # an equality one. It still catches the case it is here for: a manifest left
    # behind by one compiler beside records written by another.
    if manifest["ccVersion"] and clang not in manifest["ccVersion"]:
        raise Refused("the manifest's compiler is %r and the records say clang %s"
                      % (manifest["ccVersion"], clang))
    # `cc` is the driver the runner invoked and `clang` is the version the
    # observer saw; both are here because `cc` is one of the six nominal axes the
    # fallback lookup keys on, and a frontier that does not say which driver
    # produced it cannot be held up against a cell that names one.
    # `pluginSha256` is here for the reason check-envelope.py checks it: two
    # observer builds are two instruments, and their readings are not one series.
    return {"cc": manifest["cc"], "clang": clang, "digest": digest,
            "pluginSha256": manifest["pluginSha256"]}


def build(exposure_id):
    # The manifest first, and the records where it says they went. Reading a
    # directory this file guessed at, rather than the one the run declared, is how
    # a frontier ends up assembled from a previous run's leftovers.
    manifest = read_manifest(exposure_id)
    records_dir = os.path.join(LAB, manifest["records"])
    if not os.path.isdir(records_dir):
        raise Refused("%s: the manifest points at %s and there is no such directory"
                      % (exposure_id,
                         records_dir.replace(os.path.expanduser("~"), "~")))

    observations = []
    toolchains = set()
    for spec in RUNG_SPEC:
        rec, why = read_record(os.path.join(records_dir, spec[0] + ".json"))
        if rec is not None:
            tc = rec.get("toolchain") or {}
            if tc.get("clang"):
                toolchains.add((tc.get("clang"), tc.get("digest")))
        observations.append(observation_for(spec, rec, why))

    if all(o["broken"] for o in observations):
        raise Refused("all %d rungs are broken in %s; there is no frontier here to "
                      "assemble. First reason: %s"
                      % (len(observations), exposure_id,
                         observations[0]["brokenReason"]))

    toolchain = toolchain_from(toolchains, manifest)

    # The comparable object. A BROKEN rung is not data and must not be able to
    # compare equal to a state, which is why the word is in the same column
    # rather than in a parallel one a comparator could forget to read.
    frontier = {o["rung"]: (BROKEN if o["broken"] else o["state"])
                for o in observations}

    monotone, offender = chain_monotone(frontier)
    exclusive, exclusivity_detail = spelling_exclusive(frontier)

    doc = {
        "schemaVersion": SCHEMA,
        "failureDirection": FAILURE_DIRECTION,
        "ladder": {
            "id": LADDER_ID,
            "generatorVersion": manifest["generatorVersion"],
            "generatorSha256": manifest["generatorSha256"],
            "sourceSha256": manifest["sourceSha256"],
        },
        "toolchain": toolchain,
        # Inside the digest. A frontier detached from the command line that
        # produced it is the exact defect this instrument exists to close.
        "exposure": {
            "id": exposure_id,
            "opt": manifest["opt"],
            "extraArgs": manifest["extraArgs"],
        },
        # Array order is significant and never sorted (section 5 rule 2). It is
        # RUNG_SPEC's order, which is a constant, so two runs of the same ladder
        # digest identically.
        "observations": observations,
        "frontier": frontier,
        "health": {
            # `is not False`, not `is True`. interfaces.md section 3.1: a rung
            # that produced no reading has controlHeld null -- not false, which
            # would claim a control was run and failed. A rung whose record never
            # arrived, or was wired to another subject, has no control to report
            # on; saying its twin fell would send a reader looking for a fixture
            # bug that is not there. `broken` next to this is what reports it.
            "twinsHeld": not any(o["controlHeld"] is False for o in observations),
            "chainMonotone": monotone,
            "spellingExclusive": exclusive,
            "broken": any(o["broken"] for o in observations),
        },
        "context": context_block(),
    }

    # Section 5's last rule, applied to the whole document including `context`,
    # which the section does not exempt. The reasons a record must not carry one
    # are a machine's account name being a disclosure and a digest that changes
    # with the checkout directory; neither stops at the context boundary.
    for path, text in walk_strings(doc):
        if looks_absolute(text):
            raise Refused("%s: absolute path at %s: %r"
                          % (exposure_id, path, text[:120]))

    try:
        doc["evidenceDigest"] = digest_of(doc)
    except ValueError as exc:
        raise Refused("%s: %s" % (exposure_id, exc))

    return doc, offender, exclusivity_detail


def usage():
    print("usage: build-ladder-frontier.py [exposure-id ...]", file=sys.stderr)
    print("  with no arguments, every exposure directory under "
          "$IRCK_LADDER_LAB/records is assembled", file=sys.stderr)
    return 1


def main(argv):
    for arg in argv:
        if arg.startswith("-"):
            return usage()
        if not EXPOSURE_ID_RE.match(arg):
            print("build-ladder-frontier.py: %r is not an exposure id" % arg,
                  file=sys.stderr)
            return usage()

    if argv:
        wanted = list(argv)
    else:
        if not os.path.isdir(RECORDS):
            print("no records directory at %s; the ladder runner has not been run"
                  % RECORDS.replace(os.path.expanduser("~"), "~"), file=sys.stderr)
            return 3
        wanted = sorted(n for n in os.listdir(RECORDS)
                        if os.path.isdir(os.path.join(RECORDS, n))
                        and EXPOSURE_ID_RE.match(n))
        if not wanted:
            print("no exposure directories under %s"
                  % RECORDS.replace(os.path.expanduser("~"), "~"), file=sys.stderr)
            return 3

    os.makedirs(OUT_DIR, exist_ok=True)
    refusals = []
    for exposure_id in wanted:
        try:
            doc, offender, exclusivity_detail = build(exposure_id)
        except Refused as exc:
            refusals.append(str(exc))
            continue

        out = os.path.join(OUT_DIR, exposure_id + ".json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True, ensure_ascii=False)
            fh.write("\n")

        h = doc["health"]
        notes = []
        if not h["twinsHeld"]:
            notes.append("a control did not hold")
        if not h["chainMonotone"]:
            notes.append("chain not monotone at %s" % offender)
        if not h["spellingExclusive"]:
            notes.append("spelling not exclusive (%s)"
                         % "; ".join("%s -> %s" % ("/".join(g), p or "none")
                                     for g, p in exclusivity_detail))
        broken = [o["rung"] for o in doc["observations"] if o["broken"]]
        if broken:
            notes.append("broken: %s" % ",".join(broken))
        print("%-8s %2d observations, %d broken -- %s"
              % (exposure_id, len(doc["observations"]), len(broken),
                 "; ".join(notes) if notes else "health invariants hold"))

    # One refusal makes the whole invocation exit 3 even when other exposures
    # were written. A caller that sweeps a directory and reads 0 would otherwise
    # take a partial set as a complete one, which is section 7's "we did not
    # look" reported as "it is clean". The documents that were assembled are
    # still on disk and still valid; what is refused is the clean exit.
    if refusals:
        print("\n%d exposure(s) not assembled:" % len(refusals), file=sys.stderr)
        for r in refusals:
            print("  " + r, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
