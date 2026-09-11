/**
 * Reader for the record the repair plugins write (schemaVersion "wipe-pin-v2").
 *
 * Only "wipe-pin-v2" is accepted. A v1 record is refused like any other record
 * of the wrong shape, and so is v0. What v2 is, field by field, is the contract
 * the two plugins were written against (the LLVM one in compiler/llvm-repair/,
 * the GCC one in compiler/gcc-repair/); what this reader holds them to:
 *   - component                  "WipePin" (LLVM) or "WipePinGcc" (GCC), and the
 *                                one the caller says it drove (expect.component);
 *                                a mismatch is wrong-compile
 *   - toolchain                  exactly {digest, packages} plus exactly ONE
 *                                compiler key, the one the component names:
 *                                `clang` for WipePin, `gcc` for WipePinGcc. The
 *                                compiler key is the version the plugin was
 *                                built against; packages is exactly
 *                                [{name: "llvm" | "gcc", version: <that same
 *                                version>}]; digest is the SHA-256 of the
 *                                canonical serialisation of {<compiler key>,
 *                                packages}, and is re-derived here
 *   - optLevel                   compared with the flag through the component's
 *                                own table (OPT_LEVELS[component])
 *   - pinned[].followedByUse     true | false | null, as in v1 (v2 changes how
 *                                WipePin computes it, not what it may hold)
 *   - resolution[].exact         true | false | null
 *   - resolution[].linkage       a string, or null (GCC reports LLVM's words)
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
 * Each plugin seals its record the way every other native component here does
 * (interfaces.md section 5: `evidenceDigest` over the record minus `context`;
 * WipePin writes it with the same Record.cpp IrCheckpoints uses). This reader
 * re-derives the digest, and the toolchain digest, with
 * compiler/evidence/canon.mjs -- an implementation that shares no code with
 * either C++ writer -- so a record edited after the compile is refused rather
 * than believed.
 *
 * Nothing here compiles anything or reads anything but the one file it is given.
 */
import { readFileSync } from 'node:fs';
import { evidenceDigest, canonicalJsonRaw, sha256Hex } from '../../../evidence/canon.mjs';

export const SCHEMA_VERSION = 'wipe-pin-v2';
export const COMPONENTS = Object.freeze(['WipePin', 'WipePinGcc']);
export const RESOLUTIONS = Object.freeze(['resolved', 'declaration-only', 'not-in-module']);
export const SCOPES = Object.freeze(['functions', 'module']);

/**
 * Per component: the toolchain block's compiler key, and the one package the
 * block names. The key names the vendor; its value is the version of the
 * headers the plugin was compiled against.
 */
export const TOOLCHAIN_VENDOR = Object.freeze({
  WipePin: Object.freeze({ key: 'clang', package: 'llvm' }),
  WipePinGcc: Object.freeze({ key: 'gcc', package: 'gcc' }),
});
const VENDOR_KEYS = Object.freeze(['clang', 'gcc']);

/**
 * The flag -> optimisation pair each plugin reports, per component. The plugin
 * copies the pair its compiler hands it (LLVM: the OptimizationLevel at the
 * pipeline-start extension point; GCC: the global `optimize` and
 * `optimize_size`); comparing it with the flag this lane passed is how a record
 * is tied to one compile rather than to whichever compile last wrote that file.
 *
 * WipePin's column is what LLVM 18's OptimizationLevel reports (measured with
 * the plugin at -O0..-Os: {0,0} {1,0} {2,0} {3,0} {2,1}).
 *
 * WipePinGcc's column is what gcc-13 13.3.0 reports as `optimize` /
 * `optimize_size`, measured from the plugin's own record at each flag
 * (compiler/gcc-repair/README.md, "What is different on GCC"): -O0..-Oz give
 * {0,0} {1,0} {2,0} {3,0} {2,1} {2,2}, the same pairs as the LLVM column. The
 * columns are kept per component anyway, so that a vendor whose reading differs
 * changes its own column and nothing else. gcc also has -Ofast {3,0} and
 * -Og {1,0}; neither is in either table, so a record for them is refused as
 * "no known optimisation pair" rather than matched to a level it only
 * resembles.
 */
const LLVM_OPT_LEVELS = Object.freeze({
  '-O0': Object.freeze({ speedup: 0, size: 0 }),
  '-O1': Object.freeze({ speedup: 1, size: 0 }),
  '-O2': Object.freeze({ speedup: 2, size: 0 }),
  '-O3': Object.freeze({ speedup: 3, size: 0 }),
  '-Os': Object.freeze({ speedup: 2, size: 1 }),
  '-Oz': Object.freeze({ speedup: 2, size: 2 }),
});
const GCC_OPT_LEVELS = Object.freeze({
  '-O0': Object.freeze({ speedup: 0, size: 0 }),
  '-O1': Object.freeze({ speedup: 1, size: 0 }),
  '-O2': Object.freeze({ speedup: 2, size: 0 }),
  '-O3': Object.freeze({ speedup: 3, size: 0 }),
  '-Os': Object.freeze({ speedup: 2, size: 1 }),
  '-Oz': Object.freeze({ speedup: 2, size: 2 }),
});
export const OPT_LEVELS = Object.freeze({ WipePin: LLVM_OPT_LEVELS, WipePinGcc: GCC_OPT_LEVELS });

const TOP_KEYS = Object.freeze([
  'schemaVersion', 'component', 'module', 'optLevel', 'scope', 'requested', 'resolution',
  'dryRun', 'pinned', 'pinnedCount', 'wouldPinCount', 'seen', 'unhandled', 'toolchain',
  'evidenceDigest', 'context',
]);
const OPT_KEYS = Object.freeze(['speedup', 'size']);
const RESOLUTION_KEYS = Object.freeze(['name', 'resolution', 'exact', 'linkage']);
const PINNED_KEYS = Object.freeze(['function', 'index', 'lengthBytes', 'destKind', 'alreadyVolatile', 'line', 'followedByUse']);
const PACKAGE_KEYS = Object.freeze(['name', 'version']);
export const SEEN_KEYS = Object.freeze(['zeroFillMemsetInScope', 'zeroFillMemsetInModule']);
// inlineWrapperMemset: under -D_FORTIFY_SOURCE the target calls clang's
// `memset.inline` wrapper, whose body holds the __memset_chk; nothing in the
// target is an intrinsic, so nothing is pinned and the wipe can still go.
export const UNHANDLED_KEYS = Object.freeze(['libcallMemset', 'memsetChk', 'nonZeroFill', 'atomicMemset', 'inlineWrapperMemset']);

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isCount = (v) => Number.isInteger(v) && v >= 0;
const isName = (v) => typeof v === 'string' && v.length > 0;
const isTri = (v) => v === true || v === false || v === null;

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

/** The toolchain digest the contract defines: SHA-256 of canonical {<key>, packages}. */
export function toolchainDigest(key, version, packages) {
  return sha256Hex(canonicalJsonRaw({ [key]: version, packages }));
}

/**
 * The toolchain block, held to the component's shape. `component` is the
 * record's own, already known to be one of COMPONENTS, or null when it is not
 * (then only the vendor-neutral half is checked).
 */
function checkToolchain(tc, component, problems) {
  if (!isObj(tc)) { problems.push('bad-type: toolchain must be an object'); return; }
  const present = VENDOR_KEYS.filter((k) => k in tc);
  if (component === null) {
    if (present.length !== 1) problems.push(`toolchain-vendor: toolchain must carry exactly one of ${VENDOR_KEYS.join(', ')} (it carries ${present.length})`);
    exactKeys(tc, ['digest', 'packages', ...(present.length === 1 ? present : [])], 'toolchain.', problems);
    return;
  }
  const want = TOOLCHAIN_VENDOR[component];
  // Said once, in words, before the key-by-key list: a GCC record read as an
  // LLVM one (or the other way round) is the mistake this check exists for.
  for (const k of present) {
    if (k !== want.key) problems.push(`toolchain-vendor: component ${component} carries toolchain.${k}; its compiler key is toolchain.${want.key}`);
  }
  exactKeys(tc, ['digest', want.key, 'packages'], 'toolchain.', problems);
  const version = tc[want.key];
  if (want.key in tc && !isName(version)) problems.push(`bad-type: toolchain.${want.key} must be a non-empty string`);
  if ('packages' in tc) {
    const p = tc.packages;
    if (!Array.isArray(p)) problems.push('bad-type: toolchain.packages must be an array');
    else if (p.length !== 1 || !isObj(p[0])) {
      problems.push(`bad-toolchain: toolchain.packages must be exactly one {name, version} object (it has ${p.length} entr${p.length === 1 ? 'y' : 'ies'})`);
    } else {
      exactKeys(p[0], PACKAGE_KEYS, 'toolchain.packages[0].', problems);
      if ('name' in p[0] && p[0].name !== want.package) {
        problems.push(`bad-toolchain: toolchain.packages[0].name ${JSON.stringify(p[0].name)}, component ${component} names ${JSON.stringify(want.package)}`);
      }
      if ('version' in p[0] && isName(version) && p[0].version !== version) {
        problems.push(`bad-toolchain: toolchain.packages[0].version ${JSON.stringify(p[0].version)} differs from toolchain.${want.key} ${JSON.stringify(version)}`);
      }
    }
  }
  if ('digest' in tc) {
    if (typeof tc.digest !== 'string' || !/^[0-9a-f]{64}$/.test(tc.digest)) {
      problems.push('bad-type: toolchain.digest must be 64 lowercase hex characters');
    } else if (isName(version) && Array.isArray(tc.packages)) {
      let derived = null;
      try { derived = toolchainDigest(want.key, version, tc.packages); } catch { /* reported as a mismatch below */ }
      if (derived !== tc.digest) {
        problems.push(`toolchain-digest-mismatch: toolchain.digest is not the SHA-256 of the canonical {${want.key}, packages}`);
      }
    }
  }
}

/**
 * Validate a parsed record.
 *
 * @param {unknown} rec
 * @param {{component?: string, scope?: string, requested?: string[], dryRun?: boolean, opt?: string, module?: string}} [expect]
 *        what THIS compile asked for. Every key given is compared; a key left out
 *        is not. The runner passes all six; `component` is the plugin it loaded
 *        ("WipePin" for clang).
 * @returns {{ok: boolean, record: object|null, problems: string[]}}
 */
export function validatePinRecord(rec, expect = {}) {
  const problems = [];
  if (!isObj(rec)) return { ok: false, record: null, problems: ['not-an-object'] };

  exactKeys(rec, TOP_KEYS, '', problems);

  if (rec.schemaVersion !== SCHEMA_VERSION) {
    problems.push(`unknown-schemaVersion: ${JSON.stringify(rec.schemaVersion)} (this reader knows ${SCHEMA_VERSION})`);
  }
  const component = COMPONENTS.includes(rec.component) ? rec.component : null;
  if (component === null) problems.push(`wrong-component: ${JSON.stringify(rec.component)} (this reader knows ${COMPONENTS.join(', ')})`);
  if (expect.component !== undefined && !COMPONENTS.includes(expect.component)) {
    problems.push(`bad-expect: component ${JSON.stringify(expect.component)} is not one this reader knows`);
  }
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
      if ('exact' in r && !isTri(r.exact)) problems.push(`bad-type: resolution[${i}].exact must be true, false or null`);
      if ('linkage' in r && !(r.linkage === null || typeof r.linkage === 'string')) {
        problems.push(`bad-type: resolution[${i}].linkage must be a string or null`);
      }
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
      if ('followedByUse' in p && !isTri(p.followedByUse)) problems.push(`bad-type: pinned[${i}].followedByUse must be true, false or null`);
    });
  }

  // v1 typed this block loosely (any string digest, any package objects). v2's
  // contract names its content exactly, for both vendors, so it is read exactly:
  // the compiler key the component names and no other, one package that repeats
  // its version, and a digest that re-derives. Nothing in it comes from the
  // environment, so there is no "unavailable" case to admit.
  checkToolchain(rec.toolchain, component, problems);

  if (!isCount(rec.pinnedCount)) problems.push('not-a-count: pinnedCount');
  if (!isCount(rec.wouldPinCount)) problems.push('not-a-count: wouldPinCount');

  for (const [field, keys] of [['seen', SEEN_KEYS], ['unhandled', UNHANDLED_KEYS]]) {
    if (!isObj(rec[field])) { problems.push(`bad-type: ${field} must be an object`); continue; }
    exactKeys(rec[field], keys, `${field}.`, problems);
    for (const k of keys) if (k in rec[field] && !isCount(rec[field][k])) problems.push(`not-a-count: ${field}.${k}`);
  }

  if (!isObj(rec.context)) problems.push('bad-type: context must be an object');
  if (typeof rec.evidenceDigest !== 'string' || !/^[0-9a-f]{64}$/.test(rec.evidenceDigest)) {
    problems.push('bad-type: evidenceDigest must be 64 lowercase hex characters');
  }

  // Type problems make the cross-field checks below meaningless; stop here so
  // the problem list names causes rather than their consequences.
  if (problems.length) return { ok: false, record: null, problems };

  // ---- integrity ------------------------------------------------------------
  let derived = null;
  try { derived = evidenceDigest(rec); } catch (e) { problems.push(`digest-underivable: ${e && e.message ? e.message : 'error'}`); }
  if (derived !== null && derived !== rec.evidenceDigest) {
    problems.push('digest-mismatch: evidenceDigest does not re-derive from the record (edited after the compile?)');
  }
  if (problems.length) return { ok: false, record: null, problems };

  // ---- internal consistency ----------------------------------------------
  // The counts are tied to the list exactly. `pinned` lists every eligible site
  // (in a dry run too); a site that was already volatile is listed and left
  // alone, so it is in neither count. Outside a dry run:
  //   pinnedCount === wouldPinCount === (listed sites not already volatile)
  // and in a dry run pinnedCount is 0 while wouldPinCount is that number.
  const eligible = rec.pinned.filter((p) => !p.alreadyVolatile).length;
  if (rec.dryRun) {
    if (rec.pinnedCount !== 0) {
      problems.push(`inconsistent: dryRun is true but pinnedCount is ${rec.pinnedCount} (a dry run mutates nothing)`);
    }
    if (rec.wouldPinCount !== eligible) {
      problems.push(`inconsistent: dry run with wouldPinCount ${rec.wouldPinCount}, but ${eligible} listed site(s) are not already volatile`);
    }
  } else {
    if (rec.pinnedCount !== rec.wouldPinCount) {
      problems.push(`inconsistent: outside a dry run, pinnedCount ${rec.pinnedCount} differs from wouldPinCount ${rec.wouldPinCount}`);
    }
    if (rec.pinnedCount !== eligible) {
      problems.push(`inconsistent: pinnedCount ${rec.pinnedCount}, but ${eligible} listed site(s) are not already volatile`);
    }
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
  // The component first: a record from the other vendor's plugin describes a
  // different compiler, whatever else it says.
  if (expect.component !== undefined && rec.component !== expect.component) {
    problems.push(`wrong-compile: component ${rec.component}, this compile loaded ${expect.component}`);
  }
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
    // The table of the compiler this lane drove when it says which; otherwise the
    // record's own (already one this reader knows).
    const table = OPT_LEVELS[expect.component ?? rec.component];
    const want = table[expect.opt];
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

/**
 * How many sites carry followedByUse true, counted two ways.
 *
 * `pinned[]` lists every zero-fill memset site the plugin saw in scope, the ones
 * already volatile in the source included, and a dry run lists sites it did not
 * change. So:
 *   listed  sites in pinned[] with followedByUse true (what the list says)
 *   pinned  of those, the ones this compile actually made volatile: not
 *           alreadyVolatile, and not a dry run (a dry run changes nothing)
 * For a valid record outside a dry run the pinned set is exactly the listed
 * sites that are not already volatile (pinnedCount counts them).
 *
 * @returns {{listed: number, pinned: number}}
 */
export function followedByUseCounts(rec) {
  const sites = rec && Array.isArray(rec.pinned) ? rec.pinned : [];
  const listed = sites.filter((p) => p && p.followedByUse === true);
  const pinned = rec && rec.dryRun === false ? listed.filter((p) => p.alreadyVolatile === false) : [];
  return { listed: listed.length, pinned: pinned.length };
}

/** Names the record did not resolve, as "name:resolution". Empty for module scope. */
export function unresolvedNames(rec) {
  if (!rec || rec.scope !== 'functions') return [];
  return rec.resolution.filter((r) => r.resolution !== 'resolved').map((r) => `${r.name}:${r.resolution}`);
}
