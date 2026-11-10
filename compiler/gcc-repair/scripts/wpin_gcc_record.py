#!/usr/bin/env python3
"""Read a WipePinGcc record strictly, as compiler/schema/wipe-pin.md describes
the `wipe-pin-v3` record (section 14; sections 1-13 for everything v3 keeps
from v2).

    python3 wpin_gcc_record.py [--expect barrierCalls=0,zeroCopy=1,bufferBarriers=0] <record.json>

prints key=value lines for pin-gcc.sh (pinnedCount, wouldPinCount,
followedByUseCount, unresolved, exactAll, the done and would counts of the
three v3 blocks, and repairCount), or one `error=<why>` line when the file is
not a usable wipe-pin-v3 record from WipePinGcc. It always exits 0 when it
could run at all: the verdict is the `error=` line, which pin-gcc.sh turns
into exit 3.

`--expect` states which switches the caller set (1) or did not set (0); a
record whose `<block>.enabled` says otherwise is refused as `wrong-compile`
(section 14.9, W1). A switch the caller does not state is not compared.

Only `wipe-pin-v3` is accepted. A `wipe-pin-v2` record is read with the reader
of the commit that wrote it (section 14.10), and is refused here like any other
record of the wrong shape.

Also imported, as a library, by check-gcc-fixture-loop.py and by the tests in
../test/. Nothing here compiles anything or reads anything but the one file it
is given.

Strict for the reason compiler/eval/repair-loop/lib/pin-record.mjs gives: a
tolerant reader that skipped a field it did not recognise would let a plugin
that silently changed what it reports keep being believed. The authoritative
reader for the repair loop is that JS file; this one exists so that pin-gcc.sh
does not need node. It checks the same rules and a few more
(compiler/schema/wipe-pin.md sections 11, 13 and 14.9).

The digests are re-derived here with a canonical serialiser written from the
rules in compiler/schema/interfaces.md section 5 -- sharing no code with the
C++ writer in ../src/Canon.cpp -- and that serialiser is itself calibrated
against compiler/evidence/testdata/digest-vectors.json by the tests.
"""

import hashlib
import json
import re
import sys

SCHEMA = "wipe-pin-v3"
COMPONENT = "WipePinGcc"

# compiler/schema/wipe-pin.md section 14.1: the 16 keys of v2 and the four
# blocks v3 adds, which are written on every record.
TOP_KEYS = {
    "schemaVersion", "component", "module", "optLevel", "scope", "requested", "resolution",
    "dryRun", "pinned", "pinnedCount", "wouldPinCount", "seen", "unhandled", "toolchain",
    "barrierCalls", "zeroCopy", "bufferBarriers", "host",
    "evidenceDigest", "context",
}
PINNED_KEYS = {"function", "index", "lengthBytes", "destKind", "alreadyVolatile", "line", "followedByUse"}
RESOLUTION_KEYS = {"name", "resolution", "exact", "linkage"}
SEEN_KEYS = {"zeroFillMemsetInScope", "zeroFillMemsetInModule"}
# Section 14.3: nine keys, the same set for both vendors.
UNHANDLED_KEYS = {"libcallMemset", "memsetChk", "nonZeroFill", "atomicMemset", "inlineWrapperMemset",
                  "bzeroCall", "inlineWrapperBzero", "zeroGlobalCopy", "zeroGlobalCopyCall"}
CONTEXT_KEYS = {"generatedAt", "timeSource", "sourceDateEpoch"}
RESOLUTIONS = ("resolved", "declaration-only", "not-in-module")
DEST_KINDS = ("alloca", "argument", "global", "other")
# compiler/schema/wipe-pin.md section 5: LLVM's spelling, restricted to the
# five words the GCC mapping can produce.
GCC_LINKAGES = ("internal", "weak", "linkonce_odr", "available_externally", "external")
EXACT_LINKAGES = ("external", "internal")
# Shapes GCC does not have (compiler/schema/wipe-pin.md sections 10 and
# 14.3): always 0 on a WipePinGcc record.
ALWAYS_ZERO = ("atomicMemset", "inlineWrapperMemset", "inlineWrapperBzero")

# Sections 14.4-14.7 (S3-S6 of section 14.9).
BARRIER_KEYS = {"enabled", "sites", "barrierCount", "wouldBarrierCount"}
BARRIER_SITE_KEYS = {"function", "callee", "lengthBytes", "line"}
ZERO_KEYS = {"enabled", "sites", "repairedCount", "wouldRepairCount"}
ZERO_SITE_KEYS = {"function", "form", "callee", "source", "destKind", "lengthBytes", "line"}
BUFFER_KEYS = {"enabled", "count", "sites"}
BUFFER_SITE_KEYS = {"function", "buffer", "bytes", "reason", "anchor"}
HOST_KEYS = {"ident", "identMajor", "builtMajor", "checked", "intrinsicsCompared"}
BUFFER_REASONS = ("memset", "loop-store", "zero-copy")
BUFFER_ANCHORS = ("lifetime-end", "ret", "clobber")
# C7, the WipePinGcc column.
GCC_ZERO_FORMS = ("aggregate", "builtin", "call")
GCC_BUFFER_ANCHORS = ("clobber", "ret")
# W1: the blocks whose `enabled` echoes a switch, with the variable each echoes.
SWITCH_BLOCKS = {"barrierCalls": "WPIN_BARRIER_CALLS", "zeroCopy": "WPIN_ZERO_COPY",
                 "bufferBarriers": "WPIN_BUFFER_BARRIER"}
# Each block's done-count and would-count (bufferBarriers has only the first).
BLOCK_COUNTS = {"barrierCalls": ("barrierCount", "wouldBarrierCount"),
                "zeroCopy": ("repairedCount", "wouldRepairCount"),
                "bufferBarriers": ("count", None)}

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


def _count_or_null(v):
    return v is None or _is_count(v)


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


def ident_major(ident):
    """compiler/schema/wipe-pin.md section 14.7, the WipePinGcc column: the
    decimal integer before the first '.' of `ident`, or None."""
    if not isinstance(ident, str):
        return None
    m = re.match(r"([0-9]+)\.", ident)
    return int(m.group(1)) if m else None


def _block_structure(rec, name, keys, site_keys, problems):
    """S3-S5: the block's own keys and types, and each site's keys. The site
    fields' types are checked by the caller. Returns the site list, or None."""
    blk = rec.get(name)
    if not isinstance(blk, dict):
        problems.append(f"bad-type: {name}")
        return None
    _exact_keys(blk, keys, f"{name}.", problems)
    if not isinstance(blk.get("enabled"), bool):
        problems.append(f"bad-type: {name}.enabled")
    done, would = BLOCK_COUNTS[name]
    for k in (done, would):
        if k is not None and not _is_count(blk.get(k)):
            problems.append(f"not-a-count: {name}.{k}")
    sites = blk.get("sites")
    if not isinstance(sites, list):
        problems.append(f"bad-type: {name}.sites")
        return None
    ok = []
    for i, s in enumerate(sites):
        if not isinstance(s, dict):
            problems.append(f"bad-type: {name}.sites[{i}]")
            continue
        _exact_keys(s, site_keys, f"{name}.sites[{i}].", problems)
        ok.append((i, s))
    return ok


def validate(rec, expect=None):
    """Every problem with `rec` as a wipe-pin-v3 WipePinGcc record; [] if none.

    `expect` optionally maps a block name of SWITCH_BLOCKS to the boolean the
    caller set its switch to (section 14.9, W1).

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
                if not _count_or_null(p.get(k)):
                    problems.append(f"not-a-count: pinned[{i}].{k}")
            if p.get("destKind") not in DEST_KINDS:
                problems.append(f"bad-destKind: pinned[{i}].destKind = {p.get('destKind')!r}")
            if not isinstance(p.get("alreadyVolatile"), bool):
                problems.append(f"bad-type: pinned[{i}].alreadyVolatile")
            fbu = p.get("followedByUse", "absent")
            # `is`, not `in`: 1, 0 and 1.0 compare equal to True and False
            if not (fbu is None or isinstance(fbu, bool)):
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

    # ---- S3-S5: the three blocks ---------------------------------------------
    bsites = _block_structure(rec, "barrierCalls", BARRIER_KEYS, BARRIER_SITE_KEYS, problems)
    for i, s in bsites or []:
        w = f"barrierCalls.sites[{i}]."
        if not _is_name(s.get("function")):
            problems.append(f"bad-type: {w}function")
        if not _is_name(s.get("callee")):
            problems.append(f"bad-type: {w}callee")
        for k in ("lengthBytes", "line"):
            if not _count_or_null(s.get(k)):
                problems.append(f"not-a-count: {w}{k}")
    zsites = _block_structure(rec, "zeroCopy", ZERO_KEYS, ZERO_SITE_KEYS, problems)
    for i, s in zsites or []:
        w = f"zeroCopy.sites[{i}]."
        if not _is_name(s.get("function")):
            problems.append(f"bad-type: {w}function")
        if not isinstance(s.get("form"), str):
            problems.append(f"bad-type: {w}form")
        if not (s.get("callee") is None or _is_name(s.get("callee"))):
            problems.append(f"bad-type: {w}callee")
        if not isinstance(s.get("source"), str):
            problems.append(f"bad-type: {w}source")
        if s.get("destKind") not in DEST_KINDS:
            problems.append(f"bad-destKind: {w}destKind = {s.get('destKind')!r}")
        for k in ("lengthBytes", "line"):
            if not _count_or_null(s.get(k)):
                problems.append(f"not-a-count: {w}{k}")
    fsites = _block_structure(rec, "bufferBarriers", BUFFER_KEYS, BUFFER_SITE_KEYS, problems)
    for i, s in fsites or []:
        w = f"bufferBarriers.sites[{i}]."
        if not _is_name(s.get("function")):
            problems.append(f"bad-type: {w}function")
        if not (s.get("buffer") is None or _is_name(s.get("buffer"))):
            problems.append(f"bad-type: {w}buffer")
        if not _count_or_null(s.get("bytes")):
            problems.append(f"not-a-count: {w}bytes")
        if s.get("reason") not in BUFFER_REASONS:
            problems.append(f"bad-reason: {w}reason = {s.get('reason')!r}")
        if s.get("anchor") not in BUFFER_ANCHORS:
            problems.append(f"bad-anchor: {w}anchor = {s.get('anchor')!r}")

    # ---- S6: host ---------------------------------------------------------------
    host = rec.get("host")
    if not isinstance(host, dict):
        problems.append("bad-type: host")
    else:
        _exact_keys(host, HOST_KEYS, "host.", problems)
        if not (host.get("ident") is None or isinstance(host.get("ident"), str)):
            problems.append("bad-type: host.ident")
        im = host.get("identMajor")
        if not (im is None or (_is_count(im) and im >= 1)):
            problems.append("bad-type: host.identMajor")
        bm = host.get("builtMajor")
        if not (_is_count(bm) and bm >= 1):
            problems.append("bad-type: host.builtMajor")
        if not isinstance(host.get("checked"), bool):
            problems.append("bad-type: host.checked")
        if not _count_or_null(host.get("intrinsicsCompared")):
            problems.append("bad-type: host.intrinsicsCompared")

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

    # ---- section 14.9: C1-C7 -------------------------------------------------
    for name, (done, would) in BLOCK_COUNTS.items():
        blk = rec[name]
        if not blk["enabled"]:                                               # C1
            if blk["sites"]:
                problems.append(f"inconsistent: {name}.enabled is false but sites lists {len(blk['sites'])}")
            for c in (done, would):
                if c is not None and blk[c] != 0:
                    problems.append(f"inconsistent: {name}.enabled is false but {name}.{c} is {blk[c]}")
            continue
        n = len(blk["sites"])
        if would is not None and blk[would] != n:                            # C2, C3
            problems.append(f"inconsistent: {name}.{would} {blk[would]}, sites lists {n}")
        if rec["dryRun"]:                                                    # C2-C4
            if blk[done] != 0:
                problems.append(f"inconsistent: dry run with {name}.{done} {blk[done]}")
        elif blk[done] != (blk[would] if would is not None else n):
            what = f"{name}.{would} {blk[would]}" if would is not None else f"sites listing {n}"
            problems.append(f"inconsistent: outside a dry run {name}.{done} {blk[done]} differs from {what}"
                            + (" (a barrier that could not be placed)" if name != "bufferBarriers" else ""))
    if rec["scope"] == "functions":                                          # C5
        for name in BLOCK_COUNTS:
            for s in rec[name]["sites"]:
                if s["function"] not in requested:
                    problems.append(f"inconsistent: {name} site in {s['function']}, which was not requested")
    h = rec["host"]                                                          # C6
    if h["checked"] is not (h["identMajor"] is not None):
        problems.append(f"inconsistent: host.checked {h['checked']} with identMajor {h['identMajor']}")
    if h["identMajor"] is not None and h["identMajor"] != h["builtMajor"]:
        problems.append(f"inconsistent: host.identMajor {h['identMajor']} differs from builtMajor "
                        f"{h['builtMajor']} (a mismatch writes no record)")
    if h["identMajor"] != ident_major(h["ident"]):
        problems.append(f"inconsistent: host.identMajor {h['identMajor']} does not re-derive from host.ident")
    if isinstance(h["ident"], str) and re.search(r"[()]", h["ident"]):
        problems.append("inconsistent: host.ident keeps a parenthesised group")
    if ident_major(rec["toolchain"]["gcc"]) != h["builtMajor"]:
        problems.append(f"inconsistent: host.builtMajor {h['builtMajor']} is not the major of toolchain.gcc")
    for i, s in enumerate(rec["zeroCopy"]["sites"]):                         # C7, WipePinGcc
        if s["form"] not in GCC_ZERO_FORMS:
            problems.append(f"bad-form: zeroCopy.sites[{i}].form {s['form']!r} on WipePinGcc")
        elif (s["form"] == "aggregate") != (s["callee"] is None):
            problems.append(f"inconsistent: zeroCopy.sites[{i}] form {s['form']} with callee {s['callee']!r}")
    for i, s in enumerate(rec["bufferBarriers"]["sites"]):
        if s["anchor"] not in GCC_BUFFER_ANCHORS:
            problems.append(f"bad-anchor: bufferBarriers.sites[{i}].anchor {s['anchor']} on WipePinGcc")
    if h["checked"] is not True or h["ident"] is None:
        problems.append("inconsistent: WipePinGcc host must be checked, with an ident")
    if h["intrinsicsCompared"] is not None:
        problems.append("inconsistent: WipePinGcc host.intrinsicsCompared must be null")

    # ---- W1: what the caller set ---------------------------------------------
    for name, want in (expect or {}).items():
        if name not in SWITCH_BLOCKS:
            raise ValueError(f"unknown switch block {name!r}")
        if rec[name]["enabled"] is not bool(want):
            problems.append(f"wrong-compile: {name}.enabled {rec[name]['enabled']}, and the caller "
                            f"{'set' if want else 'did not set'} {SWITCH_BLOCKS[name]}=1")
    return problems


def repair_count(rec):
    """Section 14.8: what this compile repaired, summed over the four counts."""
    return (rec["pinnedCount"] + rec["barrierCalls"]["barrierCount"] + rec["zeroCopy"]["repairedCount"]
            + rec["bufferBarriers"]["count"])


def summary(rec):
    """The key=value lines pin-gcc.sh writes to its manifest. repairCount is
    last; pin-gcc.sh takes its presence as "the reader finished"."""
    followed = sum(1 for p in rec["pinned"] if p["followedByUse"] is True)
    unresolved = [r["name"] for r in rec["resolution"] if r["resolution"] != "resolved"]
    exact_all = all(r["exact"] is True for r in rec["resolution"] if r["resolution"] == "resolved")
    return [
        f"pinnedCount={rec['pinnedCount']}",
        f"wouldPinCount={rec['wouldPinCount']}",
        f"followedByUseCount={followed}",
        "unresolved=" + ",".join(unresolved),
        "exactAll=" + ("true" if exact_all else "false"),
        f"barrierCount={rec['barrierCalls']['barrierCount']}",
        f"wouldBarrierCount={rec['barrierCalls']['wouldBarrierCount']}",
        f"zeroCopyRepairedCount={rec['zeroCopy']['repairedCount']}",
        f"wouldZeroCopyCount={rec['zeroCopy']['wouldRepairCount']}",
        f"bufferBarrierCount={rec['bufferBarriers']['count']}",
        f"repairCount={repair_count(rec)}",
    ]


def read(path, expect=None):
    """(record, problems). A missing or non-JSON file is a problem, not an exception."""
    try:
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
    except OSError as e:
        return None, [f"unreadable: {type(e).__name__}"]
    except ValueError:
        return None, ["not-json"]
    return rec, validate(rec, expect)


def parse_expect(text):
    """`barrierCalls=0,zeroCopy=1` -> {"barrierCalls": False, "zeroCopy": True}.
    Raises ValueError on anything else."""
    out = {}
    for item in filter(None, (x.strip() for x in text.split(","))):
        k, sep, v = item.partition("=")
        if not sep or k not in SWITCH_BLOCKS or v not in ("0", "1"):
            raise ValueError(item)
        out[k] = v == "1"
    return out


def main(argv):
    args = argv[1:]
    expect = None
    if len(args) == 3 and args[0] == "--expect":
        try:
            expect = parse_expect(args[1])
        except ValueError as e:
            print(f"error=usage: --expect takes <block>=0|1[,...] with a block of "
                  f"{','.join(SWITCH_BLOCKS)}, not {str(e)!r}")
            return 0
        args = args[2:]
    if len(args) != 1:
        print("error=usage: wpin_gcc_record.py [--expect barrierCalls=0|1,...] <record.json>")
        return 0
    rec, problems = read(args[0], expect)
    if problems:
        print("error=" + "; ".join(problems[:5]))
        return 0
    for line in summary(rec):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
