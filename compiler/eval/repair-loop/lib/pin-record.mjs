/**
 * Reader for the record the repair plugin writes (schemaVersion "wipe-pin-v0").
 *
 * The record is the plugin's own account of what it did. This lane never takes
 * it as the verdict -- the verdict comes from compiling and comparing, exactly as
 * the find step does -- but it does take it as evidence that the plugin RAN, on
 * the functions it was asked about, in the configuration it was loaded into. A
 * record that cannot show all three is not evidence of anything, so it is read
 * strictly: a missing file, an unknown field, a wrong type, a count that
 * contradicts the list it counts, or a record that describes a different compile
 * are all refusals, and a refused record turns the cell into BROKEN_REPAIR.
 *
 * Strict on purpose. A tolerant reader that skipped a field it did not recognise
 * would let a plugin that silently changed what it reports keep producing
 * RETAINED cells. If the plugin grows a field, this file grows it in the same
 * change, and the refusal is how that change is noticed.
 *
 * Problems are plain strings with NO filesystem paths in them: they travel into
 * the rows, and the rows may be tracked.
 *
 * Nothing here compiles anything or reads anything but the one file it is given.
 */
import { readFileSync } from 'node:fs';

export const SCHEMA_VERSION = 'wipe-pin-v0';
export const COMPONENT = 'WipePin';
export const RESOLUTIONS = Object.freeze(['resolved', 'declaration-only', 'not-in-module']);
export const SCOPES = Object.freeze(['functions', 'module']);

/**
 * What LLVM's OptimizationLevel reports for each driver flag. The plugin copies
 * the pair it was handed at the pipeline-start extension point; comparing it with
 * the flag this lane passed is how a record is tied to one compile rather than to
 * whichever compile last wrote that file.
 */
export const OPT_LEVELS = Object.freeze({
  '-O0': { speedup: 0, size: 0 },
  '-O1': { speedup: 1, size: 0 },
  '-O2': { speedup: 2, size: 0 },
  '-O3': { speedup: 3, size: 0 },
  '-Os': { speedup: 2, size: 1 },
  '-Oz': { speedup: 2, size: 2 },
});

const TOP_KEYS = Object.freeze([
  'schemaVersion', 'component', 'module', 'optLevel', 'scope', 'requested', 'resolution',
  'dryRun', 'pinned', 'pinnedCount', 'wouldPinCount', 'seen', 'unhandled',
]);
const OPT_KEYS = Object.freeze(['speedup', 'size']);
const RESOLUTION_KEYS = Object.freeze(['name', 'resolution']);
const PINNED_KEYS = Object.freeze(['function', 'index', 'lengthBytes', 'destKind', 'alreadyVolatile', 'line']);
export const SEEN_KEYS = Object.freeze(['zeroFillMemsetInScope', 'zeroFillMemsetInModule']);
export const UNHANDLED_KEYS = Object.freeze(['libcallMemset', 'memsetChk', 'nonZeroFill', 'atomicMemset']);

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isCount = (v) => Number.isInteger(v) && v >= 0;
const isName = (v) => typeof v === 'string' && v.length > 0;

/**
 * A module name must be a basename. The plugin is told to write one, and a path
 * here would carry the measuring machine's directory layout into every row that
 * quotes it. Checked by shape, both separators and a drive letter, because the
 * record may be produced on one side of a mount and read on the other.
 */
function isBasename(v) {
  return isName(v) && !/[\\/]/.test(v) && !/^[A-Za-z]:/.test(v) && !v.startsWith('~');
}

function exactKeys(obj, keys, where, problems) {
  for (const k of keys) if (!(k in obj)) problems.push(`missing-field: ${where}${k}`);
  for (const k of Object.keys(obj)) if (!keys.includes(k)) problems.push(`unknown-field: ${where}${k}`);
}

/**
 * Validate a parsed record.
 *
 * @param {unknown} rec
 * @param {{scope?: string, requested?: string[], dryRun?: boolean, opt?: string, module?: string}} [expect]
 *        what THIS compile asked for. Every key given is compared; a key left out
 *        is not. The runner passes all five.
 * @returns {{ok: boolean, record: object|null, problems: string[]}}
 */
export function validatePinRecord(rec, expect = {}) {
  const problems = [];
  if (!isObj(rec)) return { ok: false, record: null, problems: ['not-an-object'] };

  exactKeys(rec, TOP_KEYS, '', problems);

  if (rec.schemaVersion !== SCHEMA_VERSION) {
    problems.push(`unknown-schemaVersion: ${JSON.stringify(rec.schemaVersion)} (this reader knows ${SCHEMA_VERSION})`);
  }
  if (rec.component !== COMPONENT) problems.push(`wrong-component: ${JSON.stringify(rec.component)}`);
  if (!isName(rec.module)) problems.push('bad-type: module must be a non-empty string');
  else if (!isBasename(rec.module)) problems.push('module-not-a-basename: the record carries a path, not a module basename');

  if (!isObj(rec.optLevel)) problems.push('bad-type: optLevel must be an object');
  else {
    exactKeys(rec.optLevel, OPT_KEYS, 'optLevel.', problems);
    for (const k of OPT_KEYS) if (k in rec.optLevel && !isCount(rec.optLevel[k])) problems.push(`not-a-count: optLevel.${k}`);
  }

  if (!SCOPES.includes(rec.scope)) problems.push(`bad-scope: ${JSON.stringify(rec.scope)}`);
  if (typeof rec.dryRun !== 'boolean') problems.push('bad-type: dryRun must be a boolean');

  const requested = Array.isArray(rec.requested) ? rec.requested : null;
  if (!requested) problems.push('bad-type: requested must be an array');
  else requested.forEach((n, i) => { if (!isName(n)) problems.push(`bad-type: requested[${i}] must be a non-empty string`); });

  const resolution = Array.isArray(rec.resolution) ? rec.resolution : null;
  if (!resolution) problems.push('bad-type: resolution must be an array');
  else {
    resolution.forEach((r, i) => {
      if (!isObj(r)) { problems.push(`bad-type: resolution[${i}] must be an object`); return; }
      exactKeys(r, RESOLUTION_KEYS, `resolution[${i}].`, problems);
      if (!isName(r.name)) problems.push(`bad-type: resolution[${i}].name`);
      if (!RESOLUTIONS.includes(r.resolution)) problems.push(`bad-resolution: resolution[${i}].resolution = ${JSON.stringify(r.resolution)}`);
    });
  }

  const pinned = Array.isArray(rec.pinned) ? rec.pinned : null;
  if (!pinned) problems.push('bad-type: pinned must be an array');
  else {
    pinned.forEach((p, i) => {
      if (!isObj(p)) { problems.push(`bad-type: pinned[${i}] must be an object`); return; }
      exactKeys(p, PINNED_KEYS, `pinned[${i}].`, problems);
      if (!isName(p.function)) problems.push(`bad-type: pinned[${i}].function`);
      if (!isCount(p.index)) problems.push(`not-a-count: pinned[${i}].index`);
      // null is admitted for these two and nothing else: a memset whose length is
      // not a constant has no byte count, and a build without -g has no line.
      if (!(p.lengthBytes === null || isCount(p.lengthBytes))) problems.push(`not-a-count: pinned[${i}].lengthBytes (an integer >= 0, or null for a non-constant length)`);
      if (!(p.line === null || isCount(p.line))) problems.push(`not-a-count: pinned[${i}].line (an integer >= 0, or null without debug info)`);
      if (!isName(p.destKind)) problems.push(`bad-type: pinned[${i}].destKind`);
      if (typeof p.alreadyVolatile !== 'boolean') problems.push(`bad-type: pinned[${i}].alreadyVolatile`);
    });
  }

  if (!isCount(rec.pinnedCount)) problems.push('not-a-count: pinnedCount');
  if (!isCount(rec.wouldPinCount)) problems.push('not-a-count: wouldPinCount');

  for (const [field, keys] of [['seen', SEEN_KEYS], ['unhandled', UNHANDLED_KEYS]]) {
    if (!isObj(rec[field])) { problems.push(`bad-type: ${field} must be an object`); continue; }
    exactKeys(rec[field], keys, `${field}.`, problems);
    for (const k of keys) if (k in rec[field] && !isCount(rec[field][k])) problems.push(`not-a-count: ${field}.${k}`);
  }

  // Type problems make the cross-field checks below meaningless; stop here so
  // the problem list names causes rather than their consequences.
  if (problems.length) return { ok: false, record: null, problems };

  // ---- internal consistency ----------------------------------------------
  if (rec.dryRun && rec.pinnedCount !== 0) {
    problems.push(`inconsistent: dryRun is true but pinnedCount is ${rec.pinnedCount} (a dry run mutates nothing)`);
  }
  if (!rec.dryRun && rec.pinnedCount === 0 && rec.wouldPinCount > 0) {
    problems.push(`inconsistent: outside a dry run, wouldPinCount ${rec.wouldPinCount} with pinnedCount 0`);
  }
  if (!rec.dryRun && rec.pinnedCount > rec.pinned.length) {
    problems.push(`inconsistent: pinnedCount ${rec.pinnedCount} exceeds the ${rec.pinned.length} pinned site(s) listed`);
  }
  if (rec.seen.zeroFillMemsetInScope > rec.seen.zeroFillMemsetInModule) {
    problems.push('inconsistent: seen.zeroFillMemsetInScope exceeds seen.zeroFillMemsetInModule');
  }
  if (rec.pinnedCount > rec.seen.zeroFillMemsetInScope) {
    problems.push(`inconsistent: pinnedCount ${rec.pinnedCount} exceeds seen.zeroFillMemsetInScope ${rec.seen.zeroFillMemsetInScope}`);
  }
  if (rec.wouldPinCount > rec.seen.zeroFillMemsetInScope) {
    problems.push(`inconsistent: wouldPinCount ${rec.wouldPinCount} exceeds seen.zeroFillMemsetInScope ${rec.seen.zeroFillMemsetInScope}`);
  }
  if (rec.scope === 'functions') {
    const req = new Set(rec.requested);
    const counts = new Map();
    for (const r of rec.resolution) counts.set(r.name, (counts.get(r.name) || 0) + 1);
    for (const n of req) {
      const c = counts.get(n) || 0;
      if (c !== 1) problems.push(`inconsistent: requested name ${n} has ${c} resolution entries (expected exactly 1)`);
    }
    for (const n of counts.keys()) if (!req.has(n)) problems.push(`inconsistent: resolution names ${n}, which was not requested`);
    for (const p of rec.pinned) {
      if (!req.has(p.function)) problems.push(`inconsistent: pinned site in ${p.function}, which was not requested`);
    }
  }

  // ---- does the record describe THIS compile? -----------------------------
  if (expect.scope !== undefined && rec.scope !== expect.scope) {
    problems.push(`wrong-compile: scope ${rec.scope}, this compile asked for ${expect.scope}`);
  }
  if (expect.dryRun !== undefined && rec.dryRun !== expect.dryRun) {
    problems.push(`wrong-compile: dryRun ${rec.dryRun}, this compile asked for ${expect.dryRun}`);
  }
  if (expect.module !== undefined && rec.module !== expect.module) {
    problems.push(`wrong-compile: module ${JSON.stringify(rec.module)}, this compile read ${JSON.stringify(expect.module)}`);
  }
  if (expect.opt !== undefined) {
    const want = OPT_LEVELS[expect.opt];
    if (!want) problems.push(`wrong-compile: no known optimisation pair for ${expect.opt}`);
    else if (rec.optLevel.speedup !== want.speedup || rec.optLevel.size !== want.size) {
      problems.push(`wrong-compile: optLevel {${rec.optLevel.speedup},${rec.optLevel.size}} does not match ${expect.opt} {${want.speedup},${want.size}}`);
    }
  }
  if (expect.requested !== undefined && (expect.scope ?? rec.scope) === 'functions') {
    const a = [...new Set(rec.requested)].sort();
    const b = [...new Set(expect.requested)].sort();
    if (a.length !== b.length || a.some((x, i) => x !== b[i])) {
      problems.push(`wrong-compile: requested [${a.join(' ')}], this compile asked for [${b.join(' ')}]`);
    }
  }

  return problems.length ? { ok: false, record: null, problems } : { ok: true, record: rec, problems: [] };
}

/**
 * Read and validate a record file. A missing file is a problem, not an
 * exception: the plugin writes NO record when it refuses, and a refusal is one
 * of the things this lane exists to make loud.
 */
export function readPinRecord(file, expect = {}) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (e) {
    return { ok: false, record: null, problems: [e && e.code === 'ENOENT' ? 'record-missing' : `record-unreadable: ${e && e.code ? e.code : 'error'}`] };
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, record: null, problems: ['record-not-json'] };
  }
  return validatePinRecord(parsed, expect);
}

/** Names the record did not resolve, as "name:resolution". Empty for module scope. */
export function unresolvedNames(rec) {
  if (!rec || rec.scope !== 'functions') return [];
  return rec.resolution.filter((r) => r.resolution !== 'resolved').map((r) => `${r.name}:${r.resolution}`);
}
