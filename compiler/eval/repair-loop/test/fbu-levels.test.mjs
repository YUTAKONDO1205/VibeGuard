/**
 * followedByUse across levels (tools/lib/fbu.mjs) and the corpus selection it
 * shares with the repair loop (lib/corpus.mjs). Nothing here compiles. The
 * shapes are the ones that would let a level-dependent answer pass as equal: a
 * site that moves while the count stays, a second memset taking the first one's
 * ordinal, a site present at one level only, a refused record whose sites
 * vanish from the totals, and a comparison that drops what it cannot join.
 *
 * Two tests read tracked files, read-only: the corpus directory with
 * scenarios.json and the find step's rows, to pin the selection to the 360
 * erasure-family ids those rows cover; and the two scripts that select, to keep
 * them importing one rule rather than writing their own.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { corpusFiles, metaOf, erasureFamily } from '../lib/corpus.mjs';
import {
  REFERENCE_OPT, LINE_FLAG, CHANGES, OTHER_FIELDS, sitesOf, siteName, joinSites, fbuChange, compareLevel, accounted,
  changeCount, identical, tally, comparableRecord, lineControl, siteRows,
} from '../tools/lib/fbu.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const AIGEN = resolve(LANE, '..', 'ai-generated');

const site = (id, fn, index, line, followedByUse, extra = {}) => ({
  id, function: fn, index, line, followedByUse, destKind: followedByUse === null ? 'argument' : 'alloca', lengthBytes: 32,
  alreadyVolatile: false, ...extra,
});
const ok = (...sites) => ({ ok: true, sites });
const refused = () => ({ ok: false, sites: [] });
const recs = (entries) => new Map(Object.entries(entries));

// A record in the shape pin-record.mjs accepts, trimmed to what these functions read.
const record = (pinned, extra = {}) => ({
  schemaVersion: 'wipe-pin-v2', component: 'WipePin', module: 't.c', optLevel: { speedup: 0, size: 0 }, scope: 'module',
  requested: [], resolution: [], dryRun: true, pinned, pinnedCount: 0, wouldPinCount: pinned.length,
  seen: { zeroFillMemsetInScope: pinned.length, zeroFillMemsetInModule: pinned.length },
  unhandled: { libcallMemset: 0, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0, inlineWrapperMemset: 0 },
  toolchain: { clang: '18.1.3', packages: [{ name: 'llvm', version: '18.1.3' }], digest: 'd'.repeat(64) },
  evidenceDigest: 'e'.repeat(64), context: { generatedAt: 1, timeSource: 'wall-clock', sourceDateEpoch: null }, ...extra,
});
const pin = (fn, index, line, followedByUse, extra = {}) => ({
  function: fn, index, lengthBytes: 32, destKind: 'alloca', alreadyVolatile: false, followedByUse, line, ...extra,
});

// ---- the selection ------------------------------------------------------------

test('corpusFiles: the .c files of a listing, sorted; nothing else', () => {
  assert.deepEqual(corpusFiles(['b_N_token_r1.c', 'README.md', 'a_N_token_r2.c', 'a_N_token_r1.c.bak', 'a_N_token_r1.c']),
    ['a_N_token_r1.c', 'a_N_token_r2.c', 'b_N_token_r1.c']);
});

test('metaOf: model, framing, scenario and rep from the id; family and target from scenarios.json; null for an unknown scenario', () => {
  const scen = { token: { fam: 'erasure', fn: 'send_session_token' } };
  assert.deepEqual(metaOf('fable_N_token_r3.c', scen),
    { id: 'fable_N_token_r3', model: 'fable', framing: 'N', scen: 'token', rep: 'r3', fam: 'erasure', fn: 'send_session_token' });
  assert.equal(metaOf('fable_N_nosuch_r3.c', scen), null);
});

test('erasureFamily: only erasure scenarios, in the order given, with and without a wipe alike', () => {
  const scen = { token: { fam: 'erasure', fn: 't' }, adminop: { fam: 'authz', fn: 'a' }, auditlog: { fam: 'configguard', fn: 'c' } };
  const got = erasureFamily(['z_N_token_r1.c', 'a_N_adminop_r1.c', 'b_N_auditlog_r1.c', 'a_N_token_r2.c', 'a_N_ghost_r1.c'], scen);
  assert.deepEqual(got.map((x) => x.f), ['z_N_token_r1.c', 'a_N_token_r2.c']);
  assert.equal(got[0].meta.fn, 't');
});

test('the selection over the tracked corpus is the 360 erasure-family ids the find step\'s rows cover', () => {
  const scen = JSON.parse(readFileSync(join(AIGEN, 'scenarios.json'), 'utf8'));
  const fam = erasureFamily(corpusFiles(readdirSync(join(AIGEN, 'generated-corpus', 'r2'))), scen).map((x) => x.meta.id);
  const rows = JSON.parse(readFileSync(join(AIGEN, 'data', 'r2-build-rows.json'), 'utf8'));
  const tracked = [...new Set(rows.filter((r) => r.kind === 'erasure' || r.kind === 'none').map((r) => r.id))].sort();
  assert.equal(fam.length, 360);
  assert.deepEqual(fam, tracked);
});

test('run-repair-loop.mjs and tools/fbu-levels.mjs both take the erasure family from lib/corpus.mjs, and neither filters by family itself', () => {
  for (const [file, spec] of [['run-repair-loop.mjs', './lib/corpus.mjs'], [join('tools', 'fbu-levels.mjs'), '../lib/corpus.mjs']]) {
    const src = readFileSync(join(LANE, file), 'utf8');
    assert.match(src, new RegExp(`import \\{[^}]*\\berasureFamily\\b[^}]*\\} from '${spec.replace(/[.]/g, '\\.')}'`), `${file} does not import erasureFamily`);
    assert.doesNotMatch(src, /fam\s*===\s*'erasure'/, `${file} selects the erasure family itself`);
  }
});

// ---- sites and the join --------------------------------------------------------

test('sitesOf and siteName: the record\'s sites carry the file id; a site is named by file, function, index and line', () => {
  const s = sitesOf('f', record([pin('fn', 0, 17, false), pin('fn', 1, null, true)]));
  assert.equal(s.length, 2);
  assert.deepEqual(Object.keys(s[0]).sort(), ['alreadyVolatile', 'destKind', 'followedByUse', 'function', 'id', 'index', 'lengthBytes', 'line']);
  assert.equal(siteName(s[0]), 'f fn#0 line 17');
  assert.equal(siteName(s[1]), 'f fn#1 (no line)');
});

test('joinSites: the key is (file, function, index) and the line must agree too', () => {
  const ref = [site('f', 'a', 0, 10, false), site('f', 'a', 1, 20, true), site('f', 'b', 0, 30, false), site('f', 'c', 0, 40, false)];
  const other = [site('f', 'a', 0, 10, true), site('f', 'a', 1, 21, true), site('f', 'b', 0, 30, false), site('f', 'd', 0, 50, false)];
  const j = joinSites(ref, other);
  assert.deepEqual(j.joined.map((p) => siteName(p.ref)), ['f a#0 line 10', 'f b#0 line 30']);
  assert.deepEqual(j.lineDiffers.map((p) => [p.ref.line, p.other.line]), [[20, 21]]);
  assert.deepEqual(j.onlyRef.map(siteName), ['f c#0 line 40']);
  assert.deepEqual(j.onlyOther.map(siteName), ['f d#0 line 50']);
  assert.deepEqual(j.duplicate, []);
});

test('joinSites: a memset that takes another\'s ordinal is not joined to it -- the line catches it', () => {
  // -O0 lists the initialiser (line 5) and the wipe (line 9); a level that lost
  // the initialiser would list the wipe as index 0.
  const j = joinSites([site('f', 'h', 0, 5, true), site('f', 'h', 1, 9, false)], [site('f', 'h', 0, 9, false)]);
  assert.equal(j.joined.length, 0);
  assert.equal(j.lineDiffers.length, 1);
  assert.deepEqual(j.onlyRef.map(siteName), ['f h#1 line 9']);
});

test('joinSites: without the line key, pairs join on (file, function, index) alone', () => {
  const j = joinSites([site('f', 'a', 0, 10, false)], [site('f', 'a', 0, null, false)], { line: false });
  assert.equal(j.joined.length, 1);
  assert.equal(j.lineDiffers.length, 0);
});

test('joinSites: a key listed twice on either side joins nothing, and every site of that key is kept as a duplicate', () => {
  const j = joinSites([site('f', 'a', 0, 10, false), site('f', 'a', 1, 11, false)],
    [site('f', 'a', 0, 10, false), site('f', 'a', 0, 12, true), site('f', 'a', 1, 11, false)]);
  assert.equal(j.duplicate.length, 3);
  assert.deepEqual(j.joined.map((p) => p.ref.index), [1]);
  assert.equal(j.onlyRef.length + j.onlyOther.length + j.lineDiffers.length, 0);
});

test('fbuChange: every pair of the three values', () => {
  const vals = [true, false, null];
  const got = vals.flatMap((a) => vals.map((b) => `${a}>${b}:${fbuChange(a, b)}`));
  assert.deepEqual(got, [
    'true>true:null', 'true>false:true->false', 'true>null:null',
    'false>true:false->true', 'false>false:null', 'false>null:null',
    'null>true:null', 'null>false:null', 'null>null:null',
  ]);
  // "no change" is JavaScript null; a change into or out of null is the string 'null'
  assert.equal(fbuChange(true, true), null);
  assert.equal(fbuChange(null, true), 'null');
  assert.deepEqual(CHANGES, ['false->true', 'true->false', 'null']);
});

// ---- one level against the reference ----------------------------------------------

test('compareLevel: equal counts, different sites -- the case the per-level counts could not see', () => {
  // Both levels have one true site out of two; they are not the same site.
  const ref = recs({ f: ok(site('f', 'a', 0, 10, true), site('f', 'a', 1, 20, false)) });
  const lvl = recs({ f: ok(site('f', 'a', 0, 10, false), site('f', 'a', 1, 20, true)) });
  assert.equal(tally(ref).true, tally(lvl).true);
  const c = compareLevel(ref, lvl);
  assert.equal(c.joined, 2);
  assert.deepEqual(c.changes['true->false'].map((p) => siteName(p.ref)), ['f a#0 line 10']);
  assert.deepEqual(c.changes['false->true'].map((p) => siteName(p.ref)), ['f a#1 line 20']);
  assert.equal(changeCount(c), 2);
  assert.ok(accounted(c));
  assert.equal(identical(c), false);
});

test('compareLevel: the wipe-pin-v1 shape -- an error-path wipe false at -O0 and true above it -- counts once per level', () => {
  const at = (v) => recs({ tok: ok(site('tok', 'send_session_token', 0, 17, v), site('tok', 'send_session_token', 1, 23, false)) });
  const ref = at(false);
  const per = ['-O1', '-O2', '-O3', '-Os'].map(() => compareLevel(ref, at(true)));
  assert.deepEqual(per.map((c) => c.changes['false->true'].length), [1, 1, 1, 1]);
  assert.equal(per.reduce((n, c) => n + changeCount(c), 0), 4);
  assert.ok(per.every((c) => c.joined === 2 && c.otherFields.length === 0));
});

test('compareLevel: null changes, other fields, and sites on one side only are each counted', () => {
  const ref = recs({ f: ok(site('f', 'a', 0, 10, null), site('f', 'a', 1, 11, false), site('f', 'x', 0, 12, false)) });
  const lvl = recs({
    f: ok(site('f', 'a', 0, 10, false, { destKind: 'alloca' }), site('f', 'a', 1, 11, false, { lengthBytes: null }), site('f', 'y', 0, 13, true)),
  });
  const c = compareLevel(ref, lvl);
  assert.deepEqual(c.changes.null.map((p) => [p.ref.followedByUse, p.other.followedByUse]), [[null, false]]);
  assert.deepEqual(c.otherFields.map((p) => [siteName(p.ref), p.fields]), [['f a#0 line 10', ['destKind']], ['f a#1 line 11', ['lengthBytes']]]);
  assert.deepEqual(c.onlyRef.map(siteName), ['f x#0 line 12']);
  assert.deepEqual(c.onlyOther.map(siteName), ['f y#0 line 13']);
  assert.ok(accounted(c));
  assert.deepEqual(OTHER_FIELDS, ['lengthBytes', 'destKind', 'alreadyVolatile']);
});

test('compareLevel: a file whose record was refused on either side is not compared, and its sites are counted there, not dropped', () => {
  const ref = recs({ f: ok(site('f', 'a', 0, 1, false)), g: ok(site('g', 'b', 0, 2, true), site('g', 'b', 1, 3, false)), h: refused() });
  const lvl = recs({ f: ok(site('f', 'a', 0, 1, false)), g: refused(), h: ok(site('h', 'c', 0, 4, true)) });
  const c = compareLevel(ref, lvl);
  assert.equal(c.files, 3);
  assert.equal(c.compared, 1);
  assert.deepEqual(c.notCompared, [
    { id: 'g', refOk: true, otherOk: false, refSites: 2, otherSites: 0 },
    { id: 'h', refOk: false, otherOk: true, refSites: 0, otherSites: 1 },
  ]);
  assert.equal(c.sitesRef, 1);
  assert.equal(identical(c), false);
});

test('compareLevel: a file with a record at one level only is not compared', () => {
  const c = compareLevel(recs({ f: ok(site('f', 'a', 0, 1, false)) }), recs({}));
  assert.deepEqual(c.notCompared, [{ id: 'f', refOk: true, otherOk: false, refSites: 1, otherSites: 0 }]);
});

test('accounted: holds for every join outcome, and fails for a comparison that lost a site', () => {
  const ref = recs({ f: ok(site('f', 'a', 0, 1, false), site('f', 'a', 1, 2, false), site('f', 'a', 2, 3, false), site('f', 'b', 0, 4, false), site('f', 'b', 0, 5, false)) });
  const lvl = recs({ f: ok(site('f', 'a', 0, 1, true), site('f', 'a', 1, 9, false), site('f', 'c', 0, 6, false)) });
  const c = compareLevel(ref, lvl);
  assert.ok(accounted(c));
  assert.equal(c.joined, 1);
  assert.equal(c.lineDiffers.length, 1);
  assert.equal(c.onlyRef.length, 1);
  assert.equal(c.onlyOther.length, 1);
  assert.equal(c.duplicate.length, 2);
  const lost = { ...c, onlyOther: [] };
  assert.equal(accounted(lost), false);
});

test('identical: what the -O0 repeat must show; any category at all makes it false', () => {
  const ref = recs({ f: ok(site('f', 'a', 0, 1, false), site('f', 'a', 1, 2, true)) });
  assert.equal(identical(compareLevel(ref, recs({ f: ok(site('f', 'a', 0, 1, false), site('f', 'a', 1, 2, true)) }))), true);
  assert.equal(identical(compareLevel(ref, recs({ f: ok(site('f', 'a', 0, 1, false), site('f', 'a', 1, 2, true, { alreadyVolatile: true })) }))), false);
  assert.equal(identical(compareLevel(ref, recs({ f: ok(site('f', 'a', 0, 1, false)) }))), false);
  assert.equal(identical(compareLevel(ref, recs({ f: ok(site('f', 'a', 0, 1, false), site('f', 'a', 1, 3, true)) }))), false);
  assert.equal(identical(compareLevel(recs({}), recs({}))), true);
});

test('tally: accepted records only; the three values of followedByUse and the sites without a line', () => {
  const t = tally(recs({ f: ok(site('f', 'a', 0, 1, true), site('f', 'a', 1, null, false), site('f', 'b', 0, 3, null)), g: refused() }));
  assert.deepEqual(t, { files: 2, accepted: 1, sites: 3, true: 1, false: 1, null: 1, noLine: 1 });
});

// ---- the line-flag control ----------------------------------------------------------

test('comparableRecord: context and evidenceDigest never count; the line counts unless dropped', () => {
  const a = record([pin('fn', 0, 17, false)]);
  const b = record([pin('fn', 0, null, false)], { evidenceDigest: 'f'.repeat(64), context: { generatedAt: 2, timeSource: 'SOURCE_DATE_EPOCH', sourceDateEpoch: 2 } });
  assert.notEqual(comparableRecord(a), comparableRecord(b));
  assert.equal(comparableRecord(a, { dropLine: true }), comparableRecord(b, { dropLine: true }));
  // key order is not a difference
  const reordered = Object.fromEntries(Object.entries(a).reverse());
  assert.deepEqual(Object.keys(reordered), Object.keys(a).reverse());
  assert.equal(comparableRecord(reordered), comparableRecord(a));
  // and the input is left alone
  assert.equal(a.pinned[0].line, 17);
});

test('lineControl: equal on every field but the line holds; any other field, or a missing record, does not', () => {
  const withFlag = new Map([
    ['f', { ok: true, record: record([pin('fn', 0, 17, false), pin('fn', 1, 23, true)]) }],
    ['g', { ok: true, record: record([pin('gn', 0, 5, true)]) }],
    ['h', { ok: true, record: record([pin('hn', 0, 8, false)]) }],
  ]);
  const without = new Map([
    ['f', { ok: true, record: record([pin('fn', 0, null, false), pin('fn', 1, null, true)]) }],
    ['g', { ok: true, record: record([pin('gn', 0, null, false)]) }],
    ['h', { ok: false, record: null }],
  ]);
  const c = lineControl(withFlag, without);
  assert.equal(c.pairs, 3);
  assert.equal(c.equal, 1);
  assert.deepEqual(c.unequal, ['g']);
  assert.deepEqual(c.notCompared, ['h']);
  assert.deepEqual([c.sites, c.withLine, c.withoutLine], [3, 3, 0]);
});

test('lineControl: a record-level difference (seen, unhandled) is a difference too', () => {
  const a = record([pin('fn', 0, 17, false)]);
  const b = record([pin('fn', 0, null, false)], { unhandled: { libcallMemset: 1, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0, inlineWrapperMemset: 0 } });
  const c = lineControl(new Map([['f', { ok: true, record: a }]]), new Map([['f', { ok: true, record: b }]]));
  assert.deepEqual(c.unequal, ['f']);
});

// ---- the per-site rows ----------------------------------------------------------------

test('siteRows: one row per (file, function, index) over every level, sorted; a level that did not list the site is absent', () => {
  const byOpt = new Map([
    ['-O0', recs({ f: ok(site('f', 'b', 0, 9, false), site('f', 'a', 0, 5, true)), g: refused() })],
    ['-O1', recs({ f: ok(site('f', 'a', 0, 5, true), site('f', 'c', 0, 7, false)) })],
  ]);
  const rows = siteRows(['-O0', '-O1'], byOpt);
  assert.deepEqual(rows.map((r) => `${r.function}#${r.index}`), ['a#0', 'b#0', 'c#0']);
  assert.deepEqual(rows[0].followedByUse, { '-O0': true, '-O1': true });
  assert.deepEqual(rows[1].line, { '-O0': 9 });
  assert.deepEqual(rows[2].followedByUse, { '-O1': false });
});

test('the reference is -O0, and each vendor has a line flag its compiler takes', () => {
  assert.equal(REFERENCE_OPT, '-O0');
  assert.deepEqual(LINE_FLAG, { clang: '-gline-tables-only', gcc: '-g1' });
});
