/**
 * Routing, checked against the real table and synthetic rows.
 *
 * ../lib/routing.mjs derives "which shape goes back to the source" from
 * ../pin-families.json and this run's rows. Two things could make that
 * automation worse than the human it replaces, and both are what these tests
 * are about:
 *
 *   1. a mapping transcribed into routing.mjs instead of read out of the table
 *      (it would go stale silently), so the tests assert the vocabulary the
 *      CURRENT table produces -- counter names, scen names, counts -- and fail
 *      when the table changes without the routing being re-read;
 *   2. a signal quietly dropped. A counter no row names must throw, and a cell
 *      whose signal read 0 must be COUNTED as not routed rather than omitted.
 *
 * The rows here are synthetic. That is deliberate and it is also the limit of
 * what this file proves: over the r2 corpus all five `unhandled` counters are 0
 * in both tracked runs (../test/pin-families.test.mjs pins that), so the
 * erasure-side routing has never fired on real data and nothing here claims it
 * has. The configguard side does fire on the tracked rows, and the last test
 * reads those rows rather than synthesising them.
 *
 * No compiler, no plugin, no file written.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SIGNAL_CLAIMS, DECISIONS, LOUD, NO_SIGNAL_REASONS,
  signalIndex, counterOccurrences, scenOccurrences, decisionFor, routeRun, renderRouting,
} from '../lib/routing.mjs';
import { CLAIM_IDS, shapeVerdicts } from '../lib/pin-families.mjs';
import { UNHANDLED_KEYS } from '../lib/pin-record.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');
const TABLE = JSON.parse(readFileSync(path.join(LANE, 'pin-families.json'), 'utf8'));
const TRACKED = JSON.parse(readFileSync(path.join(LANE, 'data', 'r2-repair-rows.json'), 'utf8'));

/** One synthetic erasure row whose two plugin records carry the given counters. */
const erasureRow = (id, unhandled, opt = '-O2') => ({
  id, kind: 'erasure', cc: 'clang-18', opt, scen: 'keymaterial',
  recordW: { ok: true, seen: {}, unhandled: { ...zeroCounters(), ...unhandled } },
  recordWo: { ok: true, seen: {}, unhandled: { ...zeroCounters() } },
});
const zeroCounters = () => Object.fromEntries(UNHANDLED_KEYS.map((k) => [k, 0]));

/** One synthetic configguard row. */
const cfgRow = (id, scen, equalsEnabled) => ({
  id, kind: 'configguard', cc: 'clang-18', opt: '-O2', scen,
  outcome: 'OUT_OF_REACH_PREPROCESS', pluginDefaultEqualsEnabled: equalsEnabled,
});

// ---------------------------------------------------------------- the mapping ----

test('the signal vocabulary is DERIVED from the table, and is what the table currently holds', () => {
  const ix = signalIndex(TABLE);
  // The two claims that name a signal are claims the table's own reader knows.
  for (const c of Object.keys(SIGNAL_CLAIMS)) assert.ok(CLAIM_IDS.includes(c), `${c} is not a claim of pin-families.mjs`);

  assert.deepEqual(ix.counters, ['atomicMemset', 'inlineWrapperMemset', 'libcallMemset', 'memsetChk', 'nonZeroFill'],
    'the counters the table names have changed; lib/routing.mjs reads them from the table, this pin says which they are now');
  assert.deepEqual(ix.scens, ['auditlog', 'boundscheck', 'debugdump', 'ratelimit', 'tlsverify']);

  // every counter the plugin can emit has a row; that is what makes an unknown
  // counter an exception rather than the normal state
  assert.deepEqual([...ix.counters].sort(), [...UNHANDLED_KEYS].sort(),
    'the plugin emits a counter the table has no row for (or the other way round)');

  // one counter names exactly one cell, one scen names exactly one cell
  for (const [name, hits] of ix.byCounter) {
    assert.equal(new Set(hits.map((h) => h.cell)).size, 1, `counter ${name} names more than one cell`);
  }
  for (const [name, hits] of ix.byScen) {
    assert.equal(new Set(hits.map((h) => h.cell)).size, 1, `scen ${name} names more than one cell`);
    assert.equal(hits.length, 2, `scen ${name} should have one row per vendor`);
    assert.deepEqual(hits.map((h) => h.cc).sort(), ['clang-18', 'gcc-13']);
  }
});

test('a row citing a signal claim without the naming field is refused by the index', () => {
  const bad = { rows: [{ property: 'p', shape: 's', candidate: 'c', status: 'unmeasured', evidence: { tracked: true, cite: { claim: 'unhandled-shape-occurrences' } } }] };
  assert.throws(() => signalIndex(bad), /cites unhandled-shape-occurrences without a counter/);
});

// ---------------------------------------------------------------- counting ----

test('counterOccurrences sums every plugin record a row carries, and names what it does not know', () => {
  const rows = [
    erasureRow('a', { libcallMemset: 3 }),
    erasureRow('b', { libcallMemset: 1, memsetChk: 2 }),
    { id: 'c', kind: 'none', record: { ok: true, unhandled: { ...zeroCounters(), nonZeroFill: 5 } } },
    { id: 'd', kind: 'erasure', recordW: { ok: false, problems: ['refused'] }, recordWo: null },
  ];
  const got = counterOccurrences(rows, [...UNHANDLED_KEYS]);
  assert.equal(got.totals.get('libcallMemset'), 4);
  assert.equal(got.totals.get('memsetChk'), 2);
  assert.equal(got.totals.get('nonZeroFill'), 5);
  assert.equal(got.totals.get('atomicMemset'), 0);
  assert.equal(got.records, 5, 'four valid records from the erasure rows plus the no-wipe one');
  assert.deepEqual(got.unknown, [], 'nothing unknown here');
});

test('scenOccurrences splits the configguard rows into repaired / not / undecided', () => {
  const rows = [
    cfgRow('x', 'auditlog', false), cfgRow('y', 'auditlog', false), cfgRow('z', 'auditlog', null),
    cfgRow('w', 'tlsverify', true),
    { id: 'ignored', kind: 'erasure', scen: 'auditlog' },
  ];
  const got = scenOccurrences(rows, ['auditlog', 'tlsverify', 'ratelimit']);
  assert.deepEqual(got.seen.get('auditlog'), { rows: 3, repaired: 0, notRepaired: 2, undecided: 1 });
  assert.deepEqual(got.seen.get('tlsverify'), { rows: 1, repaired: 1, notRepaired: 0, undecided: 0 });
  assert.deepEqual(got.seen.get('ratelimit'), { rows: 0, repaired: 0, notRepaired: 0, undecided: 0 });
  assert.deepEqual(got.unknown, [], 'an erasure row does not carry a configguard signal');
});

// ---------------------------------------------------------------- the refusals ----

test('a counter the table names no row for THROWS -- it is never skipped', () => {
  const rows = [erasureRow('a', { libcallMemset: 0 })];
  rows[0].recordW.unhandled.rotatedMemsetXor = 7;
  assert.throws(() => routeRun({ table: TABLE, rows, cc: 'clang-18' }), (e) => {
    assert.match(e.message, /rotatedMemsetXor/);
    assert.match(e.message, /pin-families\.json holds no row for/);
    // the message has to say why, or the next reader deletes the throw
    assert.match(e.message, /"this shape did not occur"/);
    return true;
  });
});

test('a configguard scen the table names no row for THROWS too', () => {
  const rows = [cfgRow('x', 'sessionfixation', false)];
  assert.throws(() => routeRun({ table: TABLE, rows, cc: 'clang-18' }), (e) => {
    assert.match(e.message, /sessionfixation/);
    assert.match(e.message, /holds no row for/);
    return true;
  });
});

// ---------------------------------------------------------------- the decisions ----

test('decisionFor splits "a rule is named" by whether the rule\'s scope covers the shape', () => {
  const yes = [{ routesTo: { rule: 'VG-MEM-006', appliesToThisShape: 'yes' } }];
  const unv = [{ routesTo: { rule: 'VG-AUTH-001', appliesToThisShape: 'unverified' } }];
  const no = [{ routesTo: { rule: 'VG-MEM-006', appliesToThisShape: 'no' } }];
  const none = [{ routesTo: { rule: 'none', whyNone: 'nothing covers it' } }];
  assert.equal(decisionFor({ verdict: 'repairable-in-compiler' }, yes), 'repair-in-compiler');
  assert.equal(decisionFor({ verdict: 'routed-to-source' }, yes), 'route-to-source');
  assert.equal(decisionFor({ verdict: 'routed-to-source' }, unv), 'route-to-source-unverified');
  assert.equal(decisionFor({ verdict: 'routed-to-source' }, no), 'no-source-rule-covers-it',
    'a rule whose scope explicitly excludes the shape is not a routing');
  assert.equal(decisionFor({ verdict: 'unrouted' }, none), 'unrouted');
  assert.equal(decisionFor({ verdict: 'open' }, []), 'open');
  // yes wins over no when both are present, and unverified never over yes
  assert.equal(decisionFor({ verdict: 'routed-to-source' }, [...no, ...unv, ...yes]), 'route-to-source');
  assert.equal(decisionFor({ verdict: 'routed-to-source' }, [...no, ...unv]), 'route-to-source-unverified');
  // every word it can return is in the published list
  for (const d of ['repair-in-compiler', 'route-to-source', 'route-to-source-unverified',
    'no-source-rule-covers-it', 'unrouted', 'open']) assert.ok(DECISIONS.includes(d));
});

// ---------------------------------------------------------------- a routed run ----

test('a synthetic run in which a counter DOES fire routes that shape to its rule', () => {
  // libcallMemset is the shape "-fno-builtin left a memset call the pin does not
  // see". The table routes it to VG-MEM-006 with appliesToThisShape "yes".
  const rows = [erasureRow('a', { libcallMemset: 4 }), erasureRow('b', {})];
  const rep = routeRun({ table: TABLE, rows, cc: 'clang-18' });
  const cell = rep.cells.find((c) => c.shape === 'libcall-memset');
  assert.equal(cell.decision, 'route-to-source');
  assert.equal(cell.signalObserved, true);
  assert.equal(cell.noSignalReason, null);
  assert.deepEqual(cell.signals.map((s) => [s.kind, s.name, s.occurrences]), [['counter', 'libcallMemset', 4]]);
  assert.deepEqual(cell.routes.map((r) => r.rule), ['VG-MEM-006']);
  assert.equal(rep.counts['route-to-source'], 1);
  assert.deepEqual(rep.routedToSource, [{ cell: 'survive.secure-wipe / libcall-memset', decision: 'route-to-source', rules: ['VG-MEM-006'] }]);

  // and the shape the rule deliberately does NOT cover is loud rather than routed
  const rows2 = [erasureRow('a', { nonZeroFill: 2 })];
  const rep2 = routeRun({ table: TABLE, rows: rows2, cc: 'clang-18' });
  const nz = rep2.cells.find((c) => c.shape === 'non-zero-fill');
  assert.equal(nz.decision, 'no-source-rule-covers-it');
  assert.ok(LOUD.includes(nz.decision));
  assert.ok(rep2.loud.includes('survive.secure-wipe / non-zero-fill'));
});

test('every cell with no signal is COUNTED, with the reason, and the count adds up', () => {
  const rep = routeRun({ table: TABLE, rows: [erasureRow('a', {})], cc: 'clang-18' });
  const cells = rep.cells.length;
  assert.equal(cells, Object.keys(shapeVerdicts(TABLE)).length, 'one routing cell per (property, shape) group');
  assert.equal(Object.values(rep.counts).reduce((a, b) => a + b, 0), cells, 'every cell has exactly one decision');

  // nothing fired in this run: every cell is not-routed
  assert.equal(rep.counts['not-routed-no-signal'], cells);
  assert.equal(Object.values(rep.noSignal).reduce((a, b) => a + b, 0), cells);
  // five counters read 0, and this run measured no configguard row either
  assert.equal(rep.noSignal['zero-occurrences'], 10,
    'five unhandled counters and five configguard scens, all read 0 in this synthetic run');
  assert.equal(rep.noSignal['no-signal-defined'], cells - 10);
  assert.equal(rep.noSignal['not-measured'], 0);
  for (const k of NO_SIGNAL_REASONS) assert.ok(Number.isInteger(rep.noSignal[k]));

  // the reason is on the cell too, not only in the total
  const lm = rep.cells.find((c) => c.shape === 'libcall-memset');
  assert.equal(lm.noSignalReason, 'zero-occurrences');
  assert.match(lm.why, /no shape signal -- counter libcallMemset is defined for this cell and this run read 0/);
  const helper = rep.cells.find((c) => c.shape === 'wipe-in-a-helper-in-another-translation-unit');
  assert.equal(helper.noSignalReason, 'no-signal-defined');
  assert.match(helper.why, /defines no run-observable signal for this cell/);

  // and the count is printed
  const txt = renderRouting(rep);
  assert.match(txt, new RegExp(`not-routed-no-signal\\s+${cells}`));
  assert.match(txt, /zero-occurrences 10/);
});

test('a plan-driven run says configguard was NOT MEASURED, in the runner\'s own words', () => {
  const note = 'configguard: not measured in a plan-driven run (the plan names erasure cells only)';
  const rep = routeRun({ table: TABLE, rows: [erasureRow('a', {})], cc: 'clang-18', cfgNote: note });
  assert.equal(rep.configguardNote, note);
  const cg = rep.cells.filter((c) => c.shape === 'defence-behind-a-build-macro');
  assert.equal(cg.length, 5, 'five properties carry the build-macro shape');
  for (const c of cg) {
    assert.equal(c.noSignalReason, 'not-measured',
      'a plan-driven run measures no configguard cell; 0 rows there is an absent measurement, not an absent shape');
    assert.ok(c.why.includes(note), c.why);
  }
  assert.equal(rep.noSignal['not-measured'], 5);
  assert.equal(rep.noSignal['zero-occurrences'], 5, 'the five counters were measured and read 0');
  assert.match(renderRouting(rep), /not measured in a plan-driven run/);
});

// ---------------------------------------------------------------- real data ----

test('over the TRACKED clang-18 rows the configguard side routes and the erasure side does not', () => {
  const rep = routeRun({ table: TABLE, rows: TRACKED, cc: 'clang-18' });

  // This is the part that is backed by real measurement: the configguard cells
  // are in the tracked rows, the plugin did not bring any of them back, and four
  // of the five have no source-side rule verified to cover them.
  assert.equal(rep.counts.unrouted, 4);
  assert.deepEqual(rep.loud.sort(), [
    'notappear.debug-endpoint / defence-behind-a-build-macro',
    'survive.audit-record / defence-behind-a-build-macro',
    'survive.bounds-check / defence-behind-a-build-macro',
    'survive.fail-closed-branch / defence-behind-a-build-macro',
  ]);
  assert.deepEqual(rep.routedToSource, [{
    cell: 'survive.input-validation / defence-behind-a-build-macro',
    decision: 'route-to-source-unverified', rules: ['VG-AUTH-001'],
  }]);
  for (const c of rep.cells.filter((c2) => c2.shape === 'defence-behind-a-build-macro')) {
    const sig = c.signals.find((s) => s.kind === 'scen');
    assert.ok(sig.occurrences > 0, `${c.cell}: the tracked rows hold no configguard cell for it`);
    assert.equal(sig.repaired, 0, `${c.cell}: the plugin turned a default build into the enabled one`);
  }

  // And this is the part that is NOT: every erasure-side counter read 0 over the
  // r2 corpus, so no erasure shape is routed from real data at all.
  assert.equal(rep.counts['route-to-source'], 0);
  assert.equal(rep.counts['no-source-rule-covers-it'], 0);
  for (const c of ['libcallMemset', 'memsetChk', 'nonZeroFill', 'atomicMemset', 'inlineWrapperMemset']) {
    assert.equal(rep.counterTotals[c], 0, `${c} is no longer 0 in the tracked rows; the routing README's caveat is stale`);
  }
  assert.equal(rep.noSignal['zero-occurrences'], 5);
  assert.ok(rep.recordsRead > 3000, `only ${rep.recordsRead} records read`);

  // the cells the table still calls repairable are not miscounted as unhandled
  assert.deepEqual(rep.notRoutedButRepairable.sort(), [
    'survive.secure-wipe / backend-drop-after-ir-pipeline',
    'survive.secure-wipe / dead-store-builtin-memset-gimple',
    'survive.secure-wipe / dead-store-memset-intrinsic',
    'survive.secure-wipe / hidden-span-elimination',
  ]);

  const txt = renderRouting(rep);
  assert.match(txt, /NOT HELD BY EITHER SIDE: 4 cell\(s\)/);
  assert.ok(!/[A-Za-z]:\\|\/home\/|\/Users\//.test(txt), 'the routing text carries no absolute path');
});

test('the routing reads the table and changes NOTHING in it', () => {
  // The one way this automation could damage what it reads is by mutating the
  // parsed table (a sort in place, a pushed field). Compare the JSON before and
  // after a full route.
  const before = JSON.stringify(TABLE);
  routeRun({ table: TABLE, rows: TRACKED, cc: 'clang-18' });
  assert.equal(JSON.stringify(TABLE), before, 'routeRun mutated the parsed pin-families.json');
});
