/**
 * followedByUse across optimisation levels: the pure parts of ../fbu-levels.mjs.
 * Nothing here compiles, reads a file or looks at a directory; the tool runs the
 * compiles, reads every record through the strict reader, and hands the
 * accepted records in. The tests (../../test/fbu-levels.test.mjs) reach all of
 * it without a compiler.
 *
 * The question. Both repair plugins answer `followedByUse` on the body as the
 * front end wrote it, and clang's front end writes a different body at -O1 and
 * above: lifetime markers, and with them the shared cleanup block every jump
 * out of a scope goes through (compiler/llvm-repair/README.md, "What
 * `followedByUse` can and cannot say"). wipe-pin-v1 read that block's
 * infeasible edge as a later use, so four error-path sites read `true` at
 * -O1..-Os and `false` at -O0; wipe-pin-v2 follows only the edge a path can
 * take, and the per-level COUNTS of `true` sites have agreed since. Equal
 * counts are not equal sites: one site may go false -> true while another goes
 * true -> false. So the sites are joined across levels, one by one, on
 * (file, function, index), with the line as a second key, and every site that
 * does not join is counted rather than dropped.
 *
 * -O0 is the reference because the front end writes no lifetime markers there,
 * so a scope whose only cleanup would be its markers has no dispatch to read
 * through. That is not every scope: clang writes the dispatch at -O0 too for a
 * scope with a cleanup of another kind (a VLA, a cleanup attribute), and under
 * a sanitizer that writes the markers at -O0 as well (-fsanitize=address, with
 * its default use-after-scope, is one; the list is not complete); a reading
 * through such a dispatch can be the same at every level, and then it does not
 * show here. The erasure family has none of it: the -O0 front-end IR of its
 * 360 files has no cleanup.dest.slot (measured, compiler/llvm-repair/README.md,
 * "Where `-O0` has the dispatch too"). Nor is -O0 the truth. A site can read
 * `true` wrongly at every level alike -- a flag tested before a use, a constant
 * stored before the memset, the search bound -- and a site whose buffer leaves
 * through memory the analysis does not follow can read `false` wrongly at every
 * level alike. This measures whether the answer depends on the level, and
 * nothing else.
 */

/** The reference level every other level is compared with. */
export const REFERENCE_OPT = '-O0';

/**
 * The flag that makes every site carry a source line, per vendor.
 *
 * WipePin reads `line` from debug info and writes null without -g;
 * -gline-tables-only is the least debug info that gives it one. WipePinGcc
 * reads the statement's location, which GCC keeps with or without -g, so the
 * flag is not needed for the line there; `-g1` is GCC's line-tables level and
 * is passed so that both vendors run the same kind of compile and the same
 * line-flag control. gcc-13 13.3.0 refuses -gline-tables-only (measured: rc 1).
 */
export const LINE_FLAG = Object.freeze({ clang: '-gline-tables-only', gcc: '-g1' });

/** The directions a site's followedByUse can move in; `null` is any change into or out of null. */
export const CHANGES = Object.freeze(['false->true', 'true->false', 'null']);

/** Site fields compared for joined sites besides followedByUse (and besides line, a join key). */
export const OTHER_FIELDS = Object.freeze(['lengthBytes', 'destKind', 'alreadyVolatile']);

/** The sites of one accepted record, each carrying its file id. */
export function sitesOf(id, record) {
  return record.pinned.map((p) => ({
    id, function: p.function, index: p.index, line: p.line, followedByUse: p.followedByUse,
    destKind: p.destKind, lengthBytes: p.lengthBytes, alreadyVolatile: p.alreadyVolatile,
  }));
}

/** How a site is named in the results: `<id> <function>#<index> line <n>`. */
export function siteName(s) {
  return `${s.id} ${s.function}#${s.index}${s.line === null ? ' (no line)' : ` line ${s.line}`}`;
}

const keyOf = (s) => JSON.stringify([s.id, s.function, s.index]);

/**
 * Join two lists of sites on (file, function, index). With `line`, the line
 * must agree too: a pair whose key matches and whose line does not is put in
 * `lineDiffers` and is not compared, because it may be two different memsets
 * that happen to share an ordinal. A key listed twice in either list joins
 * nothing: every site with that key, from both lists, goes to `duplicate`.
 *
 * Every site of both lists lands in exactly one of joined (once per side),
 * lineDiffers (once per side), onlyRef, onlyOther or duplicate.
 *
 * @returns {{joined: {ref, other}[], lineDiffers: {ref, other}[], onlyRef: object[], onlyOther: object[], duplicate: object[]}}
 */
export function joinSites(ref, other, { line = true } = {}) {
  const index = (list) => {
    const m = new Map();
    const dup = new Set();
    for (const s of list) {
      const k = keyOf(s);
      if (m.has(k)) dup.add(k); else m.set(k, s);
    }
    return { m, dup };
  };
  const a = index(ref);
  const b = index(other);
  const dupKeys = new Set([...a.dup, ...b.dup]);
  const out = { joined: [], lineDiffers: [], onlyRef: [], onlyOther: [], duplicate: [] };
  for (const s of [...ref, ...other]) if (dupKeys.has(keyOf(s))) out.duplicate.push(s);
  for (const [k, s] of a.m) {
    if (dupKeys.has(k)) continue;
    const t = b.m.get(k);
    if (!t) out.onlyRef.push(s);
    else if (line && s.line !== t.line) out.lineDiffers.push({ ref: s, other: t });
    else out.joined.push({ ref: s, other: t });
  }
  for (const [k, t] of b.m) if (!dupKeys.has(k) && !a.m.has(k)) out.onlyOther.push(t);
  return out;
}

/** The direction of a followedByUse change, or null when there is none. */
export function fbuChange(from, to) {
  if (from === to) return null;
  if (from === false && to === true) return 'false->true';
  if (from === true && to === false) return 'true->false';
  return 'null';
}

/**
 * One level against the reference, site by site.
 *
 * `ref` and `other` map a file id to `{ok, sites}`: `ok` false for a compile
 * whose record was missing or refused (then `sites` is ignored). A file is
 * compared only when both of its records were accepted; otherwise it goes to
 * `notCompared`, with how many sites each accepted side listed, so that its
 * sites are counted, not lost.
 *
 * `sitesRef` and `sites` count the sites of the compared files. Every one is
 * accounted for (see accounted()).
 */
export function compareLevel(ref, other, { line = true } = {}) {
  const ids = [...new Set([...ref.keys(), ...other.keys()])].sort();
  const out = {
    files: ids.length, compared: 0, notCompared: [], sitesRef: 0, sites: 0,
    joined: 0, lineDiffers: [], onlyRef: [], onlyOther: [], duplicate: [],
    changes: Object.fromEntries(CHANGES.map((c) => [c, []])), otherFields: [],
  };
  for (const id of ids) {
    const r = ref.get(id);
    const o = other.get(id);
    const rOk = !!(r && r.ok);
    const oOk = !!(o && o.ok);
    if (!rOk || !oOk) {
      out.notCompared.push({ id, refOk: rOk, otherOk: oOk, refSites: rOk ? r.sites.length : 0, otherSites: oOk ? o.sites.length : 0 });
      continue;
    }
    out.compared++;
    out.sitesRef += r.sites.length;
    out.sites += o.sites.length;
    const j = joinSites(r.sites, o.sites, { line });
    out.joined += j.joined.length;
    out.lineDiffers.push(...j.lineDiffers);
    out.onlyRef.push(...j.onlyRef);
    out.onlyOther.push(...j.onlyOther);
    out.duplicate.push(...j.duplicate);
    for (const pair of j.joined) {
      const c = fbuChange(pair.ref.followedByUse, pair.other.followedByUse);
      if (c) out.changes[c].push(pair);
      const fields = OTHER_FIELDS.filter((f) => pair.ref[f] !== pair.other[f]);
      if (fields.length) out.otherFields.push({ ...pair, fields });
    }
  }
  return out;
}

/**
 * Whether every site of the compared files landed somewhere. A joined pair and
 * a line-differs pair hold one site of each side; `duplicate` holds sites of
 * both sides; so the sites of both sides together must equal
 * 2 x joined + 2 x line differs + only at the reference + only here + duplicate.
 */
export function accounted(cmp) {
  const listed = cmp.sitesRef + cmp.sites;
  const landed = 2 * cmp.joined + 2 * cmp.lineDiffers.length + cmp.onlyRef.length + cmp.onlyOther.length + cmp.duplicate.length;
  return listed === landed;
}

/** The number of followedByUse changes of every direction. */
export function changeCount(cmp) {
  return CHANGES.reduce((n, c) => n + cmp.changes[c].length, 0);
}

/**
 * True when a comparison found nothing: every file compared, every site joined
 * with its line, and no field of any joined site different. What the -O0
 * repeat must show.
 */
export function identical(cmp) {
  return cmp.notCompared.length === 0 && cmp.lineDiffers.length === 0 && cmp.onlyRef.length === 0
    && cmp.onlyOther.length === 0 && cmp.duplicate.length === 0 && changeCount(cmp) === 0
    && cmp.otherFields.length === 0 && cmp.sitesRef === cmp.sites && cmp.joined === cmp.sites;
}

/** Counts over one level's records: files, accepted records, sites, and the three values of followedByUse. */
export function tally(records) {
  const t = { files: records.size, accepted: 0, sites: 0, true: 0, false: 0, null: 0, noLine: 0 };
  for (const r of records.values()) {
    if (!r || !r.ok) continue;
    t.accepted++;
    for (const s of r.sites) {
      t.sites++;
      t[String(s.followedByUse)]++;
      if (s.line === null) t.noLine++;
    }
  }
  return t;
}

/**
 * A record with what may legitimately differ between two compiles of the same
 * unit removed: `context` (a clock), `evidenceDigest` (which covers the line),
 * and, with `dropLine`, every site's `line`. What is left is compared as JSON
 * with sorted keys.
 */
export function comparableRecord(record, { dropLine = false } = {}) {
  const sortKeys = (v) => {
    if (Array.isArray(v)) return v.map(sortKeys);
    if (v !== null && typeof v === 'object') {
      return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
    }
    return v;
  };
  const copy = JSON.parse(JSON.stringify(record));
  delete copy.context;
  delete copy.evidenceDigest;
  if (dropLine) for (const p of copy.pinned) delete p.line;
  return JSON.stringify(sortKeys(copy));
}

/**
 * The line-flag control: the same files, at the same level, compiled with and
 * without the line flag. `withFlag` and `without` map a file id to
 * `{ok, record}`. Every pair must be two accepted records that are equal on
 * every field but pinned[].line; `sitesWithLine` says how many sites carried a
 * line on each side (the flag's whole purpose on WipePin).
 */
export function lineControl(withFlag, without) {
  const out = { pairs: 0, equal: 0, unequal: [], notCompared: [], sites: 0, withLine: 0, withoutLine: 0 };
  for (const id of [...without.keys()].sort()) {
    const a = withFlag.get(id);
    const b = without.get(id);
    out.pairs++;
    if (!a || !a.ok || !b || !b.ok) { out.notCompared.push(id); continue; }
    if (comparableRecord(a.record, { dropLine: true }) === comparableRecord(b.record, { dropLine: true })) out.equal++;
    else out.unequal.push(id);
    out.sites += a.record.pinned.length;
    out.withLine += a.record.pinned.filter((p) => p.line !== null).length;
    out.withoutLine += b.record.pinned.filter((p) => p.line !== null).length;
  }
  return out;
}

/**
 * One row per site key (file, function, index) seen at any level, with its line
 * and followedByUse at each level where a record listed it (absent where none
 * did). Sorted by file, function, index.
 *
 * @param {string[]} opts
 * @param {Map<string, Map<string, {ok: boolean, sites: object[]}>>} byOpt
 */
export function siteRows(opts, byOpt) {
  const rows = new Map();
  for (const opt of opts) {
    const recs = byOpt.get(opt);
    if (!recs) continue;
    for (const r of recs.values()) {
      if (!r || !r.ok) continue;
      for (const s of r.sites) {
        const k = keyOf(s);
        if (!rows.has(k)) rows.set(k, { id: s.id, function: s.function, index: s.index, line: {}, followedByUse: {}, destKind: {} });
        const row = rows.get(k);
        row.line[opt] = s.line;
        row.followedByUse[opt] = s.followedByUse;
        row.destKind[opt] = s.destKind;
      }
    }
  }
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  return [...rows.values()].sort((x, y) => cmp(x.id, y.id) || cmp(x.function, y.function) || x.index - y.index);
}
