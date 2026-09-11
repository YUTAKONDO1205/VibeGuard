#!/usr/bin/env python3
"""Read a WipePinGcc record strictly, as compiler/schema/wipe-pin.md describes
the `wipe-pin-v2` record.

    python3 wpin_gcc_record.py <record.json>

prints key=value lines for pin-gcc.sh (pinnedCount, wouldPinCount,
followedByUseCount, unresolved, exactAll), or one `error=<why>` line when the
file is not a usable wipe-pin-v2 record from WipePinGcc. It always exits 0 when
it could run at all: the verdict is the `error=` line, which pin-gcc.sh turns
into exit 3.

Also imported, as a library, by check-gcc-fixture-loop.py and by the tests in
../test/. Nothing here compiles anything or reads anything but the one file it
is given.

Strict for the reason compiler/eval/repair-loop/lib/pin-record.mjs gives: a
tolerant reader that skipped a field it did not recognise would let a plugin
that silently changed what it reports keep being believed. The authoritative
reader for the repair loop is that JS file; this one exists so that pin-gcc.sh
does not need node. It checks the same rules and a few more
(compiler/schema/wipe-pin.md sections 11 and 13).

The digests are re-derived here with a canonical serialiser written from the
rules in compiler/schema/interfaces.md section 5 -- sharing no code with the
C++ writer in ../src/Canon.cpp -- and that serialiser is itself calibrated
against compiler/evidence/testdata/digest-vectors.json by the tests.
"""

import hashlib
import json
import re
import sys

SCHEMA = "wipe-pin-v2"
COMPONENT = "WipePinGcc"

TOP_KEYS = {
    "schemaVersion", "component", "module", "optLevel", "scope", "requested", "resolution",
    "dryRun", "pinned", "pinnedCount", "wouldPinCount", "seen", "unhandled", "toolchain",
    "evidenceDigest", "context",
}
PINNED_KEYS = {"function", "index", "lengthBytes", "destKind", "alreadyVolatile", "line", "followedByUse"}
RESOLUTION_KEYS = {"name", "resolution", "exact", "linkage"}
SEEN_KEYS = {"zeroFillMemsetInScope", "zeroFillMemsetInModule"}
UNHANDLED_KEYS = {"libcallMemset", "memsetChk", "nonZeroFill", "atomicMemset", "inlineWrapperMemset"}
CONTEXT_KEYS = {"generatedAt", "timeSource", "sourceDateEpoch"}
RESOLUTIONS = ("resolved", "declaration-only", "not-in-module")
DEST_KINDS = ("alloca", "argument", "global", "other")
# compiler/schema/wipe-pin.md section 5: LLVM's spelling, restricted to the
# five words the GCC mapping can produce.
GCC_LINKAGES = ("internal", "weak", "linkonce_odr", "available_externally", "external")
EXACT_LINKAGES = ("external", "internal")
# Shapes GCC does not have (compiler/schema/wipe-pin.md section 10): always 0
# on a WipePinGcc record.
ALWAYS_ZERO = ("atomicMemset", "inlineWrapperMemset")

SAFE_MAX = 2 ** 53 - 1


class CanonError(ValueError):
    pass


def _canon_into(v, out, where):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if abs(v) > SAFE_MAX:
            raise CanonError(f"integer outside the exact range at {where}")
        out.append(str(v))
    elif isinstance(v, float):
        raise CanonError(f"non-integer number {v!r} at {where}")
    elif isinstance(v, str):
        out.append(json.dumps(v, ensure_ascii=False))
    elif isinstance(v, list):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _canon_into(x, out, f"{where}[{i}]")
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        # Object.keys(v).sort() in canon.mjs compares UTF-16 code units; the
        # UTF-16-BE bytes of a string sort in exactly that order.
        for i, k in enumerate(sorted(v, key=lambda s: s.encode("utf-16-be", "surrogatepass"))):
            if re.fullmatch(r"0|[1-9][0-9]{0,9}", k) and int(k) < 4294967295:
                raise CanonError(f"array-index key {k!r} at {where}")
            if i:
                out.append(",")
            out.append(json.dumps(k, ensure_ascii=False))
            out.append(":")
            _canon_into(v[k], out, f"{where}.{k}")
        out.append("}")
    else:
        raise CanonError(f"value of type {type(v).__name__} at {where}")


def canonical_raw(v):
    out = []
    _canon_into(v, out, "$")
    return "".join(out)


def canonical(rec):
    """interfaces.md section 5, rules 1-3: top-level `context` and
    `evidenceDigest` removed as whole subtrees, keys sorted, no whitespace."""
    if isinstance(rec, dict):
        rec = {k: v for k, v in rec.items() if k not in ("context", "evidenceDigest")}
    return canonical_raw(rec)


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def evidence_digest(rec):
    return sha256_text(canonical(rec))


def _is_count(v):
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _is_name(v):
    return isinstance(v, str) and len(v) > 0


def _is_basename(v):
    return _is_name(v) and not re.search(r"[\\/]", v) and not re.match(r"^[A-Za-z]:", v) \
        and not v.startswith("~")


def _exact_keys(obj, keys, where, problems):
    for k in sorted(keys):
        if k not in obj:
            problems.append(f"missing-field: {where}{k}")
    for k in obj:
        if k not in keys:
            problems.append(f"unknown-field: {where}{k}")


def validate(rec):
    """Every problem with `rec` as a wipe-pin-v2 WipePinGcc record; [] if none.

    Problems are plain strings with no filesystem paths in them."""
    problems = []
    if not isinstance(rec, dict):
        return ["not-an-object"]
    _exact_keys(rec, TOP_KEYS, "", problems)
    if rec.get("schemaVersion") != SCHEMA:
        problems.append(f"unknown-schemaVersion: {rec.get('schemaVersion')!r} (this reader knows {SCHEMA})")
    if rec.get("component") != COMPONENT:
        problems.append(f"wrong-component: {rec.get('component')!r}")
    if not _is_basename(rec.get("module")):
        problems.append("module-not-a-basename")

    opt = rec.get("optLevel")
    if not isinstance(opt, dict):
        problems.append("bad-type: optLevel")
    else:
        _exact_keys(opt, {"speedup", "size"}, "optLevel.", problems)
        for k in ("speedup", "size"):
            if k in opt and not _is_count(opt[k]):
                problems.append(f"not-a-count: optLevel.{k}")

    if rec.get("scope") not in ("functions", "module"):
        problems.append(f"bad-scope: {rec.get('scope')!r}")
    if not isinstance(rec.get("dryRun"), bool):
        problems.append("bad-type: dryRun")

    requested = rec.get("requested")
    if not isinstance(requested, list) or not all(_is_name(n) for n in requested):
        problems.append("bad-type: requested must be a list of names")
        requested = None

    resolution = rec.get("resolution")
    if not isinstance(resolution, list):
        problems.append("bad-type: resolution")
        resolution = None
    else:
        for i, r in enumerate(resolution):
            if not isinstance(r, dict):
                problems.append(f"bad-type: resolution[{i}]")
                continue
            _exact_keys(r, RESOLUTION_KEYS, f"resolution[{i}].", problems)
            if not _is_name(r.get("name")):
                problems.append(f"bad-type: resolution[{i}].name")
            word = r.get("resolution")
            if word not in RESOLUTIONS:
                problems.append(f"bad-resolution: resolution[{i}].resolution = {word!r}")
            elif word == "resolved":
                if r.get("linkage") not in GCC_LINKAGES:
                    problems.append(f"bad-linkage: resolution[{i}].linkage = {r.get('linkage')!r}")
                elif r.get("exact") is not (r["linkage"] in EXACT_LINKAGES):
                    problems.append(f"inconsistent: resolution[{i}].exact {r.get('exact')!r} "
                                    f"for linkage {r['linkage']}")
            elif r.get("exact") is not None or r.get("linkage") is not None:
                problems.append(f"inconsistent: unresolved resolution[{i}] with a non-null exact or linkage")

    pinned = rec.get("pinned")
    if not isinstance(pinned, list):
        problems.append("bad-type: pinned")
        pinned = None
    else:
        for i, p in enumerate(pinned):
            if not isinstance(p, dict):
                problems.append(f"bad-type: pinned[{i}]")
                continue
            _exact_keys(p, PINNED_KEYS, f"pinned[{i}].", problems)
            if not _is_name(p.get("function")):
                problems.append(f"bad-type: pinned[{i}].function")
            if not _is_count(p.get("index")):
                problems.append(f"not-a-count: pinned[{i}].index")
            for k in ("lengthBytes", "line"):
                if not (p.get(k) is None or _is_count(p.get(k))):
                    problems.append(f"not-a-count: pinned[{i}].{k}")
            if p.get("destKind") not in DEST_KINDS:
                problems.append(f"bad-destKind: pinned[{i}].destKind = {p.get('destKind')!r}")
            if not isinstance(p.get("alreadyVolatile"), bool):
                problems.append(f"bad-type: pinned[{i}].alreadyVolatile")
            fbu = p.get("followedByUse", "absent")
            if fbu not in (True, False, None):
                problems.append(f"bad-type: pinned[{i}].followedByUse")
            elif (p.get("destKind") == "alloca") == (fbu is None):
                problems.append(f"inconsistent: pinned[{i}] destKind {p.get('destKind')!r} with "
                                f"followedByUse {fbu!r} (null exactly when the destination is not a local)")

    tc = rec.get("toolchain")
    if not isinstance(tc, dict):
        problems.append("bad-type: toolchain")
    else:
        _exact_keys(tc, {"digest", "gcc", "packages"}, "toolchain.", problems)
        if set(tc) == {"digest", "gcc", "packages"}:
            if not _is_name(tc["gcc"]):
                problems.append("bad-type: toolchain.gcc")
            elif tc["packages"] != [{"name": "gcc", "version": tc["gcc"]}]:
                problems.append("toolchain.packages is not [{name: gcc, version: <toolchain.gcc>}]")
            else:
                want = sha256_text(canonical_raw({"gcc": tc["gcc"], "packages": tc["packages"]}))
                if tc["digest"] != want:
                    problems.append("toolchain.digest is not the sha256 of the canonical {gcc, packages}")

    for key in ("pinnedCount", "wouldPinCount"):
        if not _is_count(rec.get(key)):
            problems.append(f"not-a-count: {key}")
    for field, keys in (("seen", SEEN_KEYS), ("unhandled", UNHANDLED_KEYS)):
        obj = rec.get(field)
        if not isinstance(obj, dict):
            problems.append(f"bad-type: {field}")
            continue
        _exact_keys(obj, keys, f"{field}.", problems)
        for k in keys:
            if k in obj and not _is_count(obj[k]):
                problems.append(f"not-a-count: {field}.{k}")
    unh = rec.get("unhandled")
    if isinstance(unh, dict):
        for k in ALWAYS_ZERO:
            if unh.get(k) not in (0, None):
                problems.append(f"inconsistent: unhandled.{k} is {unh.get(k)!r}; GCC has no such shape")

    ctx = rec.get("context")
    if not isinstance(ctx, dict):
        problems.append("bad-type: context")
    else:
        _exact_keys(ctx, CONTEXT_KEYS, "context.", problems)
        if not isinstance(ctx.get("generatedAt"), int) or isinstance(ctx.get("generatedAt"), bool):
            problems.append("bad-type: context.generatedAt")
        if ctx.get("timeSource") not in ("SOURCE_DATE_EPOCH", "wall-clock"):
            problems.append("bad-type: context.timeSource")
    if not isinstance(rec.get("evidenceDigest"), str) or not re.fullmatch(r"[0-9a-f]{64}", rec["evidenceDigest"]):
        problems.append("bad-type: evidenceDigest")

    if problems:
        return problems

    # ---- integrity ------------------------------------------------------------
    try:
        derived = evidence_digest(rec)
    except CanonError as e:
        return [f"digest-underivable: {e}"]
    if derived != rec["evidenceDigest"]:
        return ["digest-mismatch: evidenceDigest does not re-derive from the record"]

    # ---- internal consistency, as pin-record.mjs checks it -------------------
    eligible = sum(1 for p in pinned if not p["alreadyVolatile"])
    if rec["dryRun"]:
        if rec["pinnedCount"] != 0:
            problems.append("inconsistent: a dry run with pinnedCount > 0")
        if rec["wouldPinCount"] != eligible:
            problems.append("inconsistent: wouldPinCount differs from the listed sites not already pinned")
    else:
        if rec["pinnedCount"] != rec["wouldPinCount"]:
            problems.append("inconsistent: outside a dry run, pinnedCount differs from wouldPinCount")
        if rec["pinnedCount"] != eligible:
            problems.append("inconsistent: pinnedCount differs from the listed sites not already pinned")
    seen = rec["seen"]
    if seen["zeroFillMemsetInScope"] > seen["zeroFillMemsetInModule"]:
        problems.append("inconsistent: seen.zeroFillMemsetInScope exceeds seen.zeroFillMemsetInModule")
    if seen["zeroFillMemsetInScope"] != len(pinned):
        problems.append("inconsistent: seen.zeroFillMemsetInScope differs from the number of listed sites")
    if rec["scope"] == "functions":
        if [r["name"] for r in resolution] != requested:
            problems.append("inconsistent: resolution does not name exactly the requested functions, in order")
        if len(set(requested)) != len(requested):
            problems.append("inconsistent: a requested name is repeated")
        for p in pinned:
            if p["function"] not in requested:
                problems.append(f"inconsistent: pinned site in {p['function']}, which was not requested")
    elif requested or resolution:
        problems.append("inconsistent: module scope with requested or resolution entries")
    return problems


def summary(rec):
    """The key=value lines pin-gcc.sh writes to its manifest."""
    followed = sum(1 for p in rec["pinned"] if p["followedByUse"] is True)
    unresolved = [r["name"] for r in rec["resolution"] if r["resolution"] != "resolved"]
    exact_all = all(r["exact"] is True for r in rec["resolution"] if r["resolution"] == "resolved")
    return [
        f"pinnedCount={rec['pinnedCount']}",
        f"wouldPinCount={rec['wouldPinCount']}",
        f"followedByUseCount={followed}",
        "unresolved=" + ",".join(unresolved),
        "exactAll=" + ("true" if exact_all else "false"),
    ]


def read(path):
    """(record, problems). A missing or non-JSON file is a problem, not an exception."""
    try:
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
    except OSError as e:
        return None, [f"unreadable: {type(e).__name__}"]
    except ValueError:
        return None, ["not-json"]
    return rec, validate(rec)


def main(argv):
    if len(argv) != 2:
        print("error=usage: wpin_gcc_record.py <record.json>")
        return 0
    rec, problems = read(argv[1])
    if problems:
        print("error=" + "; ".join(problems[:5]))
        return 0
    for line in summary(rec):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
