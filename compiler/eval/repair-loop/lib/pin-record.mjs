/**
 * Reader for the record the repair plugins write (schemaVersion "wipe-pin-v3").
 *
 * Only "wipe-pin-v3" is accepted. A v2 record is refused like any other record
 * of the wrong shape, and so are v1 and v0: compiler/schema/wipe-pin.md §14.10
 * says each reader accepts one version, and a v2 record is read with the reader
 * of the commit that wrote it (22e7222 for the last v2 writers), which is how
 * tools/fbu-levels.mjs --reader already reads a v1 plugin. No tracked file holds
 * a v2 record: the tracked rows in ../data/ hold the runner's summaries of
 * records (counts, seen, unhandled), not records, and nothing here re-reads
 * them through this function. What v3 is, field by field and per vendor, is
 * wipe-pin.md §1-§13 (v2) with §14 on top (the LLVM writer is
 * compiler/llvm-repair/, the GCC one compiler/gcc-repair/).
 *
 * v3 over v2 (wipe-pin.md §14.1; checked here as §14.9 S1-S6, C1-C7, W1):
 *   - 20 top-level keys: v2's 16 plus barrierCalls, zeroCopy, bufferBarriers and
 *     host, written on every record whatever the configuration
 *   - unhandled has nine keys (UNHANDLED_KEYS), the same set for both vendors;
 *     WipePinGcc writes 0 for the three it cannot produce (GCC_ALWAYS_ZERO)
 *   - barrierCalls / zeroCopy: {enabled, sites[], done-count, would-count};
 *     not enabled => no site and every count 0; enabled => the would-count is
 *     the list's length, and the done-count is 0 in a dry run and the
 *     would-count otherwise. A dry run that says it placed a barrier, or a run
 *     that placed fewer than it listed, is refused
 *   - bufferBarriers: the buffer barrier (WPIN_BUFFER_BARRIER=1, wipe-pin.md
 *     §14.6), written by both plugins; the same rules with one count
 *   - host: the version handshake. checked exactly when identMajor is not
 *     null; a non-null identMajor equals builtMajor (a mismatch writes no
 *     record, so a record that shows one is refused); identMajor re-derives
 *     from ident; ident keeps no parenthesised group; builtMajor is the major
 *     of toolchain.<key>
 *   - context: exactly timeSource, sourceDateEpoch, generatedAt (§14.8). v2's
 *     reader admitted any object here (§13 item 2); v3 holds the three keys
 *     both writers write
 *   - W1: when the caller says whether it set WPIN_BARRIER_CALLS,
 *     WPIN_ZERO_COPY or WPIN_BUFFER_BARRIER (expect.barrierCalls / .zeroCopy /
 *     .bufferBarriers), the block's `enabled` must agree (wrong-compile)
 *
 * Everything below this paragraph that v2 already checked is unchanged:
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
 *   - pinned[].followedByUse     true | false | null, and null exactly when the
 *                                site's destKind is not `alloca` (v2 changed how
 *                                WipePin computes the boolean, wipe-pin.md §8)
 *   - pinned[].destKind          one of alloca, argument, global, other
 *   - resolution[].exact         a boolean for a resolved name, true exactly for
 *                                the linkages external, internal and private;
 *                                null for a name that did not resolve
 *   - resolution[].linkage       one of LLVM's textual linkage words for a
 *                                resolved name (GCC reports LLVM's words), null
 *                                otherwise; resolution[] in the order of
 *                                requested[], and both empty in module scope
 *   - seen.zeroFillMemsetInScope the number of sites pinned[] lists (both writers
 *                                list every in-scope zero-fill site)
 *   - unhandled.atomicMemset, .inlineWrapperMemset and (v3) .inlineWrapperBzero
 *                                are 0 on a WipePinGcc record: GCC has none of
 *                                the three shapes
 *
 * No real v2 record broke the structural rules in that list: 78,855 wipe-pin-v2
 * records (39,185 WipePin, 39,670 WipePinGcc; 22,360 distinct evidence
 * digests) from full repair-loop runs, red controls, plan replays, fixture
 * loops and module-scope corpus sweeps, 0 violations. No v3 writer existed when
 * this reader was written: its v3 rules were first checked against the two
 * constructed examples of wipe-pin.md §14.11 and the records built in
 * ../test/pin-record.test.mjs. Real v3 records it has read since, all accepted:
 * the records of the 2026-11-09 re-recording runs, summarised into the tracked
 * rows (3,395 valid summaries per vendor, ../data/r2-v3-rerecord.json), and, in
 * a lab sweep outside this repository the same day, 4,986 wipe-pin-v3 records
 * left by the plugins' fixture loops and lab measurements (52 of them with the
 * buffer barrier on, 120 with WPIN_BARRIER_CALLS, 64 with WPIN_ZERO_COPY, 15
 * with host.checked false), 0 refused.
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

export const SCHEMA_VERSION = 'wipe-pin-v3';
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
 * the plugin at -O0..-Oz: {0,0} {1,0} {2,0} {3,0} {2,1} {2,2}).
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

/** The 20 top-level keys of wipe-pin.md §14.1: v2's 16 and the four v3 blocks. */
export const TOP_KEYS = Object.freeze([
  'schemaVersion', 'component', 'module', 'optLevel', 'scope', 'requested', 'resolution',
  'dryRun', 'pinned', 'pinnedCount', 'wouldPinCount', 'seen', 'unhandled', 'toolchain',
  'barrierCalls', 'zeroCopy', 'bufferBarriers', 'host',
  'evidenceDigest', 'context',
]);
/** wipe-pin.md §2 and §14.8: `context` holds exactly these, and is outside the digest. */
export const CONTEXT_KEYS = Object.freeze(['timeSource', 'sourceDateEpoch', 'generatedAt']);
const OPT_KEYS = Object.freeze(['speedup', 'size']);
const RESOLUTION_KEYS = Object.freeze(['name', 'resolution', 'exact', 'linkage']);
const PINNED_KEYS = Object.freeze(['function', 'index', 'lengthBytes', 'destKind', 'alreadyVolatile', 'line', 'followedByUse']);
const PACKAGE_KEYS = Object.freeze(['name', 'version']);
/** The observer's classifyTarget words (compiler/llvm-pass/src/Extractors.cpp); wipe-pin.md §7. */
export const DEST_KINDS = Object.freeze(['alloca', 'argument', 'global', 'other']);
/** LLVM's textual-IR linkage words, which both writers use (wipe-pin.md §5). */
export const LINKAGES = Object.freeze(['external', 'internal', 'linkonce_odr', 'available_externally', 'weak',
  'weak_odr', 'linkonce', 'private', 'common', 'extern_weak', 'appending']);
/** The linkages whose definition cannot be replaced by another unit's: `exact` is true for these only. */
const EXACT_LINKAGES = Object.freeze(['external', 'internal', 'private']);
export const SEEN_KEYS = Object.freeze(['zeroFillMemsetInScope', 'zeroFillMemsetInModule']);
// inlineWrapperMemset: under -D_FORTIFY_SOURCE the target calls clang's
// `memset.inline` wrapper, whose body holds the __memset_chk; nothing in the
// target is an intrinsic, so nothing is pinned and the wipe can still go.
// The last four are v3's (wipe-pin.md §14.3): a bzero call, clang's name for a
// gnu_inline bzero wrapper (`bzero.<suffix>`, the patch's reading, not measured
// here), and a copy from an all-zero constant -- the compiler's own operation
// (zeroGlobalCopy) or a library / checked / wrapper call (zeroGlobalCopyCall).
// A call or copy a switch repairs is not counted.
export const UNHANDLED_KEYS = Object.freeze(['libcallMemset', 'memsetChk', 'nonZeroFill', 'atomicMemset', 'inlineWrapperMemset',
  'bzeroCall', 'inlineWrapperBzero', 'zeroGlobalCopy', 'zeroGlobalCopyCall']);
/**
 * The five keys a v2 record carried. Kept because the tracked rows in ../data/
 * were written by the v2 reader and carry exactly these: until those rows are
 * re-measured with a v3 writer, a counter outside this list is NOT MEASURED
 * for such a row, never 0 (wipe-pin.md §14.10). lib/routing.mjs and
 * lib/pin-families.mjs count only the records that carry a counter.
 */
export const UNHANDLED_KEYS_V2 = Object.freeze(['libcallMemset', 'memsetChk', 'nonZeroFill', 'atomicMemset', 'inlineWrapperMemset']);
/** The unhandled keys a WipePinGcc record writes as 0 on every record (§14.3, §14.9 C7). */
export const GCC_ALWAYS_ZERO = Object.freeze(['atomicMemset', 'inlineWrapperMemset', 'inlineWrapperBzero']);

/**
 * The three v3 switches: the block whose `enabled` echoes each, and the
 * environment variable that sets it (wipe-pin.md §14.2). The caller states what
 * it set through `expect[<block>]` (W1).
 */
export const SWITCHES = Object.freeze({
  barrierCalls: 'WPIN_BARRIER_CALLS',
  zeroCopy: 'WPIN_ZERO_COPY',
  bufferBarriers: 'WPIN_BUFFER_BARRIER',
});
const BARRIER_KEYS = Object.freeze(['enabled', 'sites', 'barrierCount', 'wouldBarrierCount']);
const BARRIER_SITE_KEYS = Object.freeze(['function', 'callee', 'lengthBytes', 'line']);
const ZERO_KEYS = Object.freeze(['enabled', 'sites', 'repairedCount', 'wouldRepairCount']);
const ZERO_SITE_KEYS = Object.freeze(['function', 'form', 'callee', 'source', 'destKind', 'lengthBytes', 'line']);
const BUFFER_KEYS = Object.freeze(['enabled', 'count', 'sites']);
const BUFFER_SITE_KEYS = Object.freeze(['function', 'buffer', 'bytes', 'reason', 'anchor']);
const HOST_KEYS = Object.freeze(['ident', 'identMajor', 'builtMajor', 'checked', 'intrinsicsCompared']);
/** §14.6: why a buffer gets a barrier at the end of its lifetime. */
export const BUFFER_REASONS = Object.freeze(['memset', 'loop-store', 'zero-copy']);
/** §14.5 and §14.6, per vendor: the zeroCopy forms and the bufferBarriers anchors. */
export const VENDOR_V3 = Object.freeze({
  WipePin: Object.freeze({ forms: Object.freeze(['intrinsic', 'call']), anchors: Object.freeze(['lifetime-end', 'ret']) }),
  WipePinGcc: Object.freeze({ forms: Object.freeze(['aggregate', 'builtin', 'call']), anchors: Object.freeze(['clobber', 'ret']) }),
});
const ALL_ANCHORS = Object.freeze(['lifetime-end', 'ret', 'clobber']);

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

/** The toolchain digest wipe-pin.md defines: SHA-256 of canonical {<key>, packages}. */
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

// ---- v3: the handshake's strings (wipe-pin.md §14.7) -------------------------

/**
 * What WipePin records as `host.ident` from the first operand of
 * `!llvm.ident`: every parenthesised group (nested ones included) and the
 * whitespace directly before it removed, an unmatched `)` removed, surrounding
 * whitespace trimmed. The groups hold build identifiers, repository URLs and,
 * for a clang built from a local checkout, an absolute path, which no record
 * may carry. Exported for readers of the record (and for the tests); the reader
 * itself only checks that `ident` keeps no parenthesis.
 */
export function stripIdent(raw) {
  let out = '';
  let depth = 0;
  for (const ch of String(raw)) {
    if (ch === '(') { if (depth === 0) out = out.replace(/\s+$/, ''); depth++; continue; }
    if (ch === ')') { if (depth > 0) depth--; continue; }
    if (depth === 0) out += ch;
  }
  return out.trim();
}

/** §14.7 `identMajor` re-derived: WipePin the digits after the first "clang version ", WipePinGcc the digits before the first ".". */
export function identMajorOf(component, ident) {
  if (typeof ident !== 'string') return null;
  const m = component === 'WipePin' ? /clang version ([0-9]+)/.exec(ident) : /^([0-9]+)\./.exec(ident);
  return m ? Number(m[1]) : null;
}

/** The integer before the first "." of a version string, or null. */
function majorOf(version) {
  const m = typeof version === 'string' ? /^([0-9]+)\./.exec(version) : null;
  return m ? Number(m[1]) : null;
}

/**
 * Did this compile change anything (wipe-pin.md §14.8)? The sum of the four
 * done-counts, which is what pin.sh and pin-gcc.sh test for their exit 4. Like
 * pinnedCount, it says what the plugin did to the IR, never whether a wipe
 * reached the object file. The repair loop never sets a switch, so on its
 * records this is pinnedCount.
 */
export function repairCount(rec) {
  if (!isObj(rec)) return 0;
  return (rec.pinnedCount ?? 0) + (rec.barrierCalls?.barrierCount ?? 0)
    + (rec.zeroCopy?.repairedCount ?? 0) + (rec.bufferBarriers?.count ?? 0);
}

const countOrNull = (v) => v === null || isCount(v);

/** §14.9 S3-S5: one v3 block and its sites, by structure only. */
function checkBlockShape(blk, name, keys, counts, siteKeys, checkSite, problems) {
  if (!isObj(blk)) { problems.push(`bad-type: ${name} must be an object`); return; }
  exactKeys(blk, keys, `${name}.`, problems);
  if ('enabled' in blk && typeof blk.enabled !== 'boolean') problems.push(`bad-type: ${name}.enabled must be a boolean`);
  for (const c of counts) if (c in blk && !isCount(blk[c])) problems.push(`not-a-count: ${name}.${c}`);
  if (!('sites' in blk)) return;
  if (!Array.isArray(blk.sites)) { problems.push(`bad-type: ${name}.sites must be an array`); return; }
  blk.sites.forEach((s, i) => {
    const at = `${name}.sites[${i}].`;
    if (!isObj(s)) { problems.push(`bad-type: ${at.slice(0, -1)} must be an object`); return; }
    exactKeys(s, siteKeys, at, problems);
    checkSite(s, at);
  });
}

/** §14.9 S3-S6. Structure only; nothing here compares one field with another. */
function checkV3Shapes(rec, problems) {
  checkBlockShape(rec.barrierCalls, 'barrierCalls', BARRIER_KEYS, ['barrierCount', 'wouldBarrierCount'], BARRIER_SITE_KEYS, (s, at) => {
    if (!isName(s.function)) problems.push(`bad-type: ${at}function must be a non-empty string`);
    if (!isName(s.callee)) problems.push(`bad-type: ${at}callee must be a non-empty string`);
    if (!countOrNull(s.lengthBytes)) problems.push(`not-a-count: ${at}lengthBytes (an integer >= 0, or null)`);
    if (!countOrNull(s.line)) problems.push(`not-a-count: ${at}line (an integer >= 0, or null)`);
  }, problems);
  checkBlockShape(rec.zeroCopy, 'zeroCopy', ZERO_KEYS, ['repairedCount', 'wouldRepairCount'], ZERO_SITE_KEYS, (s, at) => {
    if (!isName(s.function)) problems.push(`bad-type: ${at}function must be a non-empty string`);
    if (typeof s.form !== 'string') problems.push(`bad-type: ${at}form must be a string`);
    if (!(s.callee === null || isName(s.callee))) problems.push(`bad-type: ${at}callee must be a non-empty string or null`);
    if (typeof s.source !== 'string') problems.push(`bad-type: ${at}source must be a string`);
    if (!DEST_KINDS.includes(s.destKind)) problems.push(`bad-destKind: ${at}destKind ${JSON.stringify(s.destKind)} (one of ${DEST_KINDS.join(', ')})`);
    if (!countOrNull(s.lengthBytes)) problems.push(`not-a-count: ${at}lengthBytes (an integer >= 0, or null)`);
    if (!countOrNull(s.line)) problems.push(`not-a-count: ${at}line (an integer >= 0, or null)`);
  }, problems);
  checkBlockShape(rec.bufferBarriers, 'bufferBarriers', BUFFER_KEYS, ['count'], BUFFER_SITE_KEYS, (s, at) => {
    if (!isName(s.function)) problems.push(`bad-type: ${at}function must be a non-empty string`);
    if (!(s.buffer === null || isName(s.buffer))) problems.push(`bad-type: ${at}buffer must be a non-empty string or null`);
    if (!countOrNull(s.bytes)) problems.push(`not-a-count: ${at}bytes (an integer >= 0, or null)`);
    if (!BUFFER_REASONS.includes(s.reason)) problems.push(`bad-reason: ${at}reason ${JSON.stringify(s.reason)} (one of ${BUFFER_REASONS.join(', ')})`);
    if (!ALL_ANCHORS.includes(s.anchor)) problems.push(`bad-anchor: ${at}anchor ${JSON.stringify(s.anchor)} (one of ${ALL_ANCHORS.join(', ')})`);
  }, problems);
  const H = rec.host;
  if (!isObj(H)) { problems.push('bad-type: host must be an object'); return; }
  exactKeys(H, HOST_KEYS, 'host.', problems);
  if ('ident' in H && !(H.ident === null || typeof H.ident === 'string')) problems.push('bad-type: host.ident must be a string or null');
  if ('identMajor' in H && !(H.identMajor === null || (Number.isInteger(H.identMajor) && H.identMajor >= 1))) {
    problems.push('bad-type: host.identMajor must be an integer >= 1 or null');
  }
  if ('builtMajor' in H && !(Number.isInteger(H.builtMajor) && H.builtMajor >= 1)) problems.push('bad-type: host.builtMajor must be an integer >= 1');
  if ('checked' in H && typeof H.checked !== 'boolean') problems.push('bad-type: host.checked must be a boolean');
  if ('intrinsicsCompared' in H && !countOrNull(H.intrinsicsCompared)) problems.push('bad-type: host.intrinsicsCompared must be an integer >= 0 or null');
}

/** §14.9 C1-C7, on a record whose structure has already passed. */
function checkV3Consistency(rec, problems) {
  const blocks = [
    ['barrierCalls', rec.barrierCalls, 'barrierCount', 'wouldBarrierCount'],
    ['zeroCopy', rec.zeroCopy, 'repairedCount', 'wouldRepairCount'],
    ['bufferBarriers', rec.bufferBarriers, 'count', null],
  ];
  for (const [name, blk, done, would] of blocks) {
    if (!blk.enabled) {                                                              // C1
      if (blk.sites.length) problems.push(`inconsistent: ${name}.enabled is false but ${name}.sites lists ${blk.sites.length} site(s)`);
      for (const c of [done, would].filter(Boolean)) {
        if (blk[c] !== 0) problems.push(`inconsistent: ${name}.enabled is false but ${name}.${c} is ${blk[c]}`);
      }
      continue;
    }
    if (would !== null && blk[would] !== blk.sites.length) {                       // C2, C3
      problems.push(`inconsistent: ${name}.${would} ${blk[would]}, but ${name}.sites lists ${blk.sites.length} site(s)`);
    }
    if (rec.dryRun) {                                                                // C2-C4
      if (blk[done] !== 0) problems.push(`inconsistent: dry run with ${name}.${done} ${blk[done]} (a dry run changes nothing)`);
    } else if (would !== null) {
      if (blk[done] !== blk[would]) {
        problems.push(`inconsistent: outside a dry run ${name}.${done} ${blk[done]} differs from ${name}.${would} ${blk[would]} (a site that was listed and not repaired)`);
      }
    } else if (blk[done] !== blk.sites.length) {
      problems.push(`inconsistent: outside a dry run ${name}.${done} ${blk[done]}, but ${name}.sites lists ${blk.sites.length} site(s)`);
    }
  }
  if (rec.scope === 'functions') {                                                   // C5
    const req = new Set(rec.requested);
    for (const [name, blk] of blocks) {
      for (const s of blk.sites) if (!req.has(s.function)) problems.push(`inconsistent: ${name} site in ${s.function}, which was not requested`);
    }
  }
  const H = rec.host;                                                                // C6
  if (H.checked !== (H.identMajor !== null)) {
    problems.push(`inconsistent: host.checked ${H.checked} with host.identMajor ${H.identMajor} (checked exactly when identMajor is not null)`);
  }
  if (H.identMajor !== null && H.identMajor !== H.builtMajor) {
    problems.push(`inconsistent: host.identMajor ${H.identMajor} differs from host.builtMajor ${H.builtMajor} (a version mismatch writes no record)`);
  }
  if (H.identMajor !== identMajorOf(rec.component, H.ident)) {
    problems.push(`inconsistent: host.identMajor ${H.identMajor} does not re-derive from host.ident ${JSON.stringify(H.ident)}`);
  }
  if (typeof H.ident === 'string' && /[()]/.test(H.ident)) {
    problems.push('inconsistent: host.ident keeps a parenthesised group (wipe-pin.md §14.7 removes them)');
  }
  const key = TOOLCHAIN_VENDOR[rec.component].key;
  if (majorOf(rec.toolchain[key]) !== H.builtMajor) {
    problems.push(`inconsistent: host.builtMajor ${H.builtMajor} is not the major version of toolchain.${key} ${JSON.stringify(rec.toolchain[key])}`);
  }
  const V = VENDOR_V3[rec.component];                                                // C7
  rec.zeroCopy.sites.forEach((s, i) => {
    if (!V.forms.includes(s.form)) {
      problems.push(`bad-form: zeroCopy.sites[${i}].form ${JSON.stringify(s.form)} on a ${rec.component} record (one of ${V.forms.join(', ')})`);
      return;
    }
    if (rec.component === 'WipePin') {
      if ((s.form === 'intrinsic') !== (s.callee === 'llvm.memcpy')) {
        problems.push(`inconsistent: zeroCopy.sites[${i}] has form ${s.form} and callee ${JSON.stringify(s.callee)} (callee "llvm.memcpy" exactly for form intrinsic)`);
      } else if (s.form === 'call' && !(s.callee === 'memcpy' || s.callee === '__memcpy_chk' || (typeof s.callee === 'string' && s.callee.startsWith('memcpy.')))) {
        problems.push(`bad-callee: zeroCopy.sites[${i}].callee ${JSON.stringify(s.callee)} (memcpy, __memcpy_chk or memcpy.<suffix>)`);
      }
    } else if ((s.form === 'aggregate') !== (s.callee === null)) {
      problems.push(`inconsistent: zeroCopy.sites[${i}] has form ${s.form} and callee ${JSON.stringify(s.callee)} (callee null exactly for form aggregate)`);
    }
  });
  if (rec.component === 'WipePin') {
    rec.barrierCalls.sites.forEach((s, i) => {
      const c = s.callee;
      if (!(c === 'memset' || c === '__memset_chk' || c === 'bzero' || c.startsWith('memset.') || c.startsWith('bzero.'))) {
        problems.push(`bad-callee: barrierCalls.sites[${i}].callee ${JSON.stringify(c)} (memset, __memset_chk, bzero, memset.<suffix> or bzero.<suffix>)`);
      }
    });
  } else {
    for (const k of GCC_ALWAYS_ZERO) {
      if (rec.unhandled[k] !== 0) problems.push(`inconsistent: unhandled.${k} is ${rec.unhandled[k]} on a WipePinGcc record (GCC has no such shape)`);
    }
    if (H.checked !== true || H.ident === null) {
      problems.push('inconsistent: a WipePinGcc record\'s host must be checked, with an ident (plugin_default_version_check passed before it installed)');
    }
    if (H.intrinsicsCompared !== null) problems.push('inconsistent: host.intrinsicsCompared must be null on a WipePinGcc record');
  }
  rec.bufferBarriers.sites.forEach((s, i) => {
    if (!V.anchors.includes(s.anchor)) {
      problems.push(`bad-anchor: bufferBarriers.sites[${i}].anchor ${s.anchor} on a ${rec.component} record (one of ${V.anchors.join(', ')})`);
    }
  });
}

/**
 * Validate a parsed record.
 *
 * @param {unknown} rec
 * @param {{component?: string, scope?: string, requested?: string[], dryRun?: boolean, opt?: string, module?: string,
 *          barrierCalls?: boolean, zeroCopy?: boolean, bufferBarriers?: boolean}} [expect]
 *        what THIS compile asked for. Every key given is compared; a key left out
 *        is not. The runner passes all nine; `component` is the plugin it loaded
 *        ("WipePin" for clang), and the last three say whether it set
 *        WPIN_BARRIER_CALLS, WPIN_ZERO_COPY and WPIN_BUFFER_BARRIER (the repair
 *        loop sets none of them, so it says false for each: wipe-pin.md §14.9 W1).
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
  else exactKeys(rec.context, CONTEXT_KEYS, 'context.', problems);
  if (typeof rec.evidenceDigest !== 'string' || !/^[0-9a-f]{64}$/.test(rec.evidenceDigest)) {
    problems.push('bad-type: evidenceDigest must be 64 lowercase hex characters');
  }

  // v3's four blocks, by structure (wipe-pin.md §14.9 S3-S6).
  checkV3Shapes(rec, problems);
  for (const k of Object.keys(SWITCHES)) {
    if (expect[k] !== undefined && typeof expect[k] !== 'boolean') {
      problems.push(`bad-expect: ${k} must be true or false (whether this compile set ${SWITCHES[k]}=1)`);
    }
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
  // Both writers list every in-scope zero-fill site in pinned[], already-volatile
  // ones included, so the count of what was seen in scope is the list's length.
  if (rec.seen.zeroFillMemsetInScope !== rec.pinned.length) {
    problems.push(`inconsistent: seen.zeroFillMemsetInScope ${rec.seen.zeroFillMemsetInScope}, but pinned[] lists ${rec.pinned.length} site(s)`);
  }
  rec.pinned.forEach((p, i) => {
    if (!DEST_KINDS.includes(p.destKind)) {
      problems.push(`bad-destKind: pinned[${i}].destKind ${JSON.stringify(p.destKind)} (one of ${DEST_KINDS.join(', ')})`);
    }
    // The question "is this buffer used again" has an answer only for a local
    // stack object; for every other destination both writers say null, and only
    // then (wipe-pin.md §8).
    if ((p.followedByUse === null) !== (p.destKind !== 'alloca')) {
      problems.push(`inconsistent: pinned[${i}] has destKind ${p.destKind} and followedByUse ${p.followedByUse} (null exactly when destKind is not alloca)`);
    }
  });
  rec.resolution.forEach((r, i) => {
    if (r.resolution !== 'resolved') {
      if (r.exact !== null || r.linkage !== null) {
        problems.push(`inconsistent: resolution[${i}] (${r.name}) did not resolve but carries exact ${r.exact} / linkage ${JSON.stringify(r.linkage)}`);
      }
      return;
    }
    if (!LINKAGES.includes(r.linkage)) {
      problems.push(`bad-linkage: resolution[${i}].linkage ${JSON.stringify(r.linkage)} (one of LLVM's linkage words)`);
    } else if (r.exact !== EXACT_LINKAGES.includes(r.linkage)) {
      problems.push(`inconsistent: resolution[${i}] has linkage ${r.linkage} and exact ${r.exact} (exact is true for ${EXACT_LINKAGES.join(', ')} only)`);
    }
  });
  // v3: the four blocks against each other, the count rules, the handshake and
  // the per-vendor value sets (wipe-pin.md §14.9 C1-C7). The WipePinGcc
  // always-zero unhandled keys are checked there.
  checkV3Consistency(rec, problems);
  if (rec.scope === 'module' && (rec.requested.length || rec.resolution.length)) {
    problems.push('inconsistent: a module-scope record names requested functions or resolutions');
  }
  if (rec.scope === 'functions' && JSON.stringify(rec.resolution.map((r) => r.name)) !== JSON.stringify(rec.requested)) {
    problems.push('inconsistent: resolution[] is not in the order of requested[]');
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
  // W1: each switch is echoed as its block's `enabled`, as WPIN_DRY_RUN is as
  // dryRun. A record that says a switch was on when the caller set none was
  // made in another environment than the one this caller built.
  for (const [k, variable] of Object.entries(SWITCHES)) {
    if (typeof expect[k] === 'boolean' && rec[k].enabled !== expect[k]) {
      problems.push(`wrong-compile: ${k}.enabled ${rec[k].enabled}, this compile ${expect[k] ? 'set' : 'did not set'} ${variable}=1`);
    }
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
