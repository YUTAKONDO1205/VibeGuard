// Tests for the second-language oracle, record builder and checker.
//
//   node --test "compiler/llvm-pass/scripts/second-language-*.test.mjs"
//
// The IR in IR_O0 and IR_O2 is not invented. It is the text the front end
// actually emitted for the erasure-stack-local fixture at those two levels,
// trimmed to the two units the oracle looks at plus the declaration that the
// naive oracle trips over. If the oracle is changed and these stop reading 1
// and 0, the change is wrong about real output, not about a mock.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

import {
  countCallSitesByUnit,
  deriveStateHistory,
  firstLoss,
} from './second-language-oracle.mjs';
import {
  buildRecord,
  digestRecord,
  canonicalise,
  assertIntegers,
  assertNoAbsolutePaths,
  runLength,
  parseTrace,
  main as recordMain,
} from './second-language-record.mjs';
import { gradeRecord, main as checkMain } from './second-language-check.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const DECLARE = 'declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #4';

const IR_O0 = `; ModuleID = 'fixture'
${DECLARE}

define i64 @handle_request(i64 %seed) unnamed_addr #1 {
start:
  %buf = alloca %"core::mem::maybe_uninit::MaybeUninit<[u8; 64]>", align 1
; call fixture::derive_key
  call void @_ZN7fixture10derive_key17h9c19db72932d607eE(i64 %seed, ptr align 1 %buf)
; call fixture::fold
  %tag = call i64 @_ZN7fixture4fold17h377d3ec03c9a17e1E(ptr align 1 %buf)
  call void @llvm.memset.p0.i64(ptr align 1 %buf, i8 0, i64 64, i1 false)
  ret i64 %tag
}

define void @wipe_kept(ptr %out) unnamed_addr #1 {
start:
  call void @llvm.memset.p0.i64(ptr align 1 %out, i8 0, i64 64, i1 false)
  ret void
}
`;

const IR_O2 = `; ModuleID = 'fixture'
${DECLARE}

define noundef i64 @handle_request(i64 noundef %seed) unnamed_addr #2 {
start:
  %buf = alloca %"core::mem::maybe_uninit::MaybeUninit<[u8; 64]>", align 1
  call void @llvm.lifetime.start.p0(i64 64, ptr nonnull %buf)
; call fixture::derive_key
  call fastcc void @_ZN7fixture10derive_key17h9c19db72932d607eE(i64 noundef %seed, ptr noalias noundef nonnull align 1 dereferenceable(64) %buf)
; call fixture::fold
  %tag = call fastcc noundef i64 @_ZN7fixture4fold17h377d3ec03c9a17e1E(ptr noalias noundef nonnull readonly align 1 dereferenceable(64) %buf)
  call void @llvm.lifetime.end.p0(i64 64, ptr nonnull %buf)
  ret i64 %tag
}

define void @wipe_kept(ptr nocapture noundef writeonly %out) unnamed_addr #3 {
start:
  tail call void @llvm.memset.p0.i64(ptr noundef nonnull align 1 dereferenceable(64) %out, i8 0, i64 64, i1 false)
  ret void
}
`;

// ── the oracle ──────────────────────────────────────────────────────────────

test('oracle: counts call sites per unit at the level where the effect is present', () => {
  const c = countCallSitesByUnit(IR_O0);
  assert.equal(c.units.handle_request, 1);
  assert.equal(c.units.wipe_kept, 1);
  assert.equal(c.declareLines, 1);
  assert.equal(c.defineCount, 2);
});

test('oracle: the subject reads zero at the level where the effect is gone', () => {
  const c = countCallSitesByUnit(IR_O2);
  assert.equal(c.units.handle_request, 0, 'the subject lost its zeroing call');
  assert.equal(c.units.wipe_kept, 1, 'the control kept its zeroing call');
});

test('oracle: the naive symbol count disagrees with the call-site count', () => {
  // This is the whole reason for the rule. The symbol is still in the module
  // at the higher level; the call site is not.
  const c = countCallSitesByUnit(IR_O2);
  assert.equal(c.naiveTotal, 2, 'a name search still finds the declaration and the control');
  assert.equal(c.units.handle_request, 0);
  assert.notEqual(c.naiveTotal, c.units.handle_request + c.units.wipe_kept);
});

test('oracle: a declaration is never attributed to any unit', () => {
  const irWithTrailingDeclare = `${IR_O2}\n${DECLARE}\n`;
  const c = countCallSitesByUnit(irWithTrailingDeclare);
  assert.equal(c.units.handle_request, 0);
  assert.equal(c.units.wipe_kept, 1);
  assert.equal(c.declareLines, 2);
});

test('oracle: tail, musttail and invoke forms are all call sites', () => {
  const ir = [
    'define void @u() {',
    '  tail call void @llvm.memset.p0.i64(ptr null, i8 0, i64 1, i1 false)',
    '  musttail call void @llvm.memset.p0.i64(ptr null, i8 0, i64 1, i1 false)',
    '  invoke void @llvm.memset.p0.i64(ptr null, i8 0, i64 1, i1 false)',
    '  ret void',
    '}',
  ].join('\n');
  assert.equal(countCallSitesByUnit(ir).units.u, 3);
});

test('oracle: a quoted symbol name is a unit name too', () => {
  const ir = [
    'define void @"weird name"(ptr %p) {',
    '  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 1, i1 false)',
    '  ret void',
    '}',
  ].join('\n');
  assert.equal(countCallSitesByUnit(ir).units['weird name'], 1);
});

test('oracle: IR with no definitions reports zero definitions, so a caller can fail', () => {
  assert.equal(countCallSitesByUnit(`${DECLARE}\n`).defineCount, 0);
});

// ── state history ───────────────────────────────────────────────────────────

const pt = (label, t, c) => ({ label, targetCallSites: t, controlCallSites: c });

test('state: a zero before the effect exists is ABSENT, not LOST', () => {
  const d = deriveStateHistory([pt('before', 0, 0), pt('after', 1, 1)]);
  assert.deepEqual(d.states, ['ABSENT', 'PRESENT']);
  assert.equal(d.brokenControlAt, null);
});

test('state: a zero after the effect existed is LOST', () => {
  const d = deriveStateHistory([pt('O0', 1, 1), pt('O2', 0, 1)]);
  assert.deepEqual(d.states, ['PRESENT', 'LOST']);
  assert.equal(d.everPresent, true);
});

test('state: the whole sequence survives a later reintroduction', () => {
  const d = deriveStateHistory([pt('a', 1, 1), pt('b', 0, 1), pt('c', 1, 1), pt('d', 0, 1)]);
  assert.deepEqual(d.states, ['PRESENT', 'LOST', 'REINTRODUCED', 'LOST']);
  assert.equal(d.states.length, 4, 'the history is not truncated at the first loss');
});

test('state: a control that dies after being established is flagged', () => {
  const d = deriveStateHistory([pt('O0', 1, 1), pt('O2', 0, 0)]);
  assert.equal(d.brokenControlAt, 'O2');
});

test('state: a control that is zero before it is established is not flagged', () => {
  const d = deriveStateHistory([pt('pre', 0, 0), pt('O0', 1, 1), pt('O2', 0, 1)]);
  assert.equal(d.brokenControlAt, null);
});

test('state: a fractional or negative count is rejected rather than rounded', () => {
  assert.throws(() => deriveStateHistory([pt('a', 1.5, 1)]), /targetCallSites/);
  assert.throws(() => deriveStateHistory([pt('a', 1, -1)]), /controlCallSites/);
});

// ── pass attribution ────────────────────────────────────────────────────────

const row = (seq, phase, pass, unit, callSites) => ({ seq, phase, pass, unit, callSites });

test('attribution: the first loss is attributed to the pass that took it', () => {
  const rows = [
    row(0, 'before', 'AlwaysInlinerPass', 'handle_request', 0),
    row(1, 'before', 'AlwaysInlinerPass', 'wipe_kept', 0),
    row(2, 'after', 'AlwaysInlinerPass', 'handle_request', 1),
    row(3, 'after', 'AlwaysInlinerPass', 'wipe_kept', 1),
    row(4, 'before', 'DSEPass', 'handle_request', 1),
    row(5, 'after', 'DSEPass', 'handle_request', 0),
    row(6, 'after', 'GlobalDCEPass', 'handle_request', 0),
    row(7, 'after', 'GlobalDCEPass', 'wipe_kept', 1),
  ];
  const a = firstLoss(rows, { target: 'handle_request', control: 'wipe_kept' });
  assert.equal(a.firstLoss.pass, 'DSEPass');
  assert.equal(a.firstLoss.phase, 'after');
  assert.equal(a.firstLoss.from, 1);
  assert.equal(a.controlMin, 1, 'the leading zero before the control existed is not its minimum');
  assert.equal(a.observedPasses, 3);
});

test('attribution: no transition to zero means no loss, and that is an answer', () => {
  const rows = [
    row(0, 'after', 'AlwaysInlinerPass', 'handle_request', 1),
    row(1, 'after', 'DSEPass', 'handle_request', 1),
    row(2, 'after', 'DSEPass', 'wipe_kept', 1),
  ];
  const a = firstLoss(rows, { target: 'handle_request', control: 'wipe_kept' });
  assert.equal(a.firstLoss, null);
  assert.equal(a.targetLast, 1);
});

test('attribution: a later sweeper is not blamed for a loss an earlier pass took', () => {
  const rows = [
    row(0, 'after', 'DSEPass', 'handle_request', 0),
    row(1, 'after', 'GlobalDCEPass', 'handle_request', 0),
  ];
  const a = firstLoss(rows, { target: 'handle_request', control: 'wipe_kept' });
  assert.equal(a.firstLoss, null, 'nothing was ever seen present, so nothing was lost here');
});

// ── canonicalisation ────────────────────────────────────────────────────────

test('canonical: keys sort at every level, array order does not', () => {
  const c = canonicalise({ b: 1, a: [{ z: 1, y: 2 }, { m: 3 }] });
  assert.equal(JSON.stringify(c), '{"a":[{"y":2,"z":1},{"m":3}],"b":1}');
});

test('canonical: context and evidenceDigest are excluded, nothing else is', () => {
  const base = { a: 1, nested: { context: 'kept at depth' } };
  const d1 = digestRecord({ ...base, context: { host: 'x' }, evidenceDigest: 'zzz' });
  const d2 = digestRecord({ ...base, context: { host: 'y' }, evidenceDigest: 'qqq' });
  assert.equal(d1, d2, 'top-level context does not change the digest');
  const d3 = digestRecord({ a: 1, nested: { context: 'changed' } });
  assert.notEqual(d1, d3, 'a nested key named context is still digested');
});

test('canonical: a non-integer number is a malformed record, not a rounding problem', () => {
  assert.throws(() => assertIntegers({ ratio: 0.75 }), /non-integer number at \$\.ratio/);
  assert.doesNotThrow(() => assertIntegers({ ratio: { num: 3, den: 4 } }));
});

test('canonical: an absolute path anywhere in a record is refused', () => {
  assert.throws(() => assertNoAbsolutePaths({ p: '/home/someone/lab/x.ll' }), /absolute path/);
  assert.throws(() => assertNoAbsolutePaths({ p: 'C:\\Users\\someone\\x.ll' }), /absolute path/);
  assert.doesNotThrow(() => assertNoAbsolutePaths({ p: 'fixtures/erasure-stack-local.rs' }));
});

test('canonical: run-length encoding keeps the whole sequence', () => {
  const runs = runLength([
    { label: 'a', state: 'ABSENT' },
    { label: 'b', state: 'PRESENT' },
    { label: 'c', state: 'PRESENT' },
    { label: 'd', state: 'LOST' },
  ]);
  assert.deepEqual(
    runs.flatMap((r) => Array(r.count).fill(r.state)),
    ['ABSENT', 'PRESENT', 'PRESENT', 'LOST'],
  );
});

test('parseTrace: a line that is not JSON is an error, not a silently dropped row', () => {
  assert.throws(() => parseTrace('{"seq":0}\nnot json\n'), /line 2/);
});

// ── building a record ───────────────────────────────────────────────────────

const META = {
  language: { backend: 'llvm', backendVersion: '17.0.6', name: 'rust', version: '1.75.0' },
  optLevels: [0, 2],
  traceOptLevel: 2,
  toolchain: { clang: '18.1.3', digest: 'd', packages: ['rustc 1.75.0'], rustc: '1.75.0' },
};
const FX = {
  name: 'erasure-stack-local',
  propertyId: 'erasure.wipe',
  subject: 'handle_request',
  control: 'wipe_kept',
  sourceRel: 'fixtures/erasure-stack-local.rs',
  expectation: 'LOST_AT_HIGH_OPT',
};

test('record: both readings land in the same record', () => {
  const r = buildRecord(FX, META, [{ optLevel: 0, ir: IR_O0 }, { optLevel: 2, ir: IR_O2 }], null, {});
  assert.equal(r.readings.length, 2);
  assert.deepEqual(r.stateHistory, ['PRESENT', 'LOST']);
  assert.equal(r.readings[0].targetCallSites, 1);
  assert.equal(r.readings[1].targetCallSites, 0);
  assert.equal(r.readings[0].controlCallSites, 1);
  assert.equal(r.readings[1].controlCallSites, 1);
  assert.equal(r.evidenceDigest, digestRecord(r));
});

test('record: a measurement whose IR has no control unit is refused', () => {
  const noControl = IR_O2.replace('@wipe_kept', '@something_else');
  assert.throws(
    () => buildRecord(FX, META, [{ optLevel: 2, ir: noControl }], null, {}),
    /control unit wipe_kept is not in the IR/,
  );
});

test('record: IR with no definitions at all is refused', () => {
  assert.throws(
    () => buildRecord(FX, META, [{ optLevel: 2, ir: DECLARE }], null, {}),
    /no function definitions/,
  );
});

test('record: a pass trace is folded in and attributed', () => {
  const rows = [
    row(0, 'before', 'AlwaysInlinerPass', 'handle_request', 0),
    row(2, 'after', 'AlwaysInlinerPass', 'handle_request', 1),
    row(4, 'before', 'DSEPass', 'handle_request', 1),
    row(5, 'after', 'DSEPass', 'handle_request', 0),
    row(6, 'after', 'DSEPass', 'wipe_kept', 1),
  ];
  const r = buildRecord(
    FX,
    META,
    [{ optLevel: 0, ir: IR_O0 }, { optLevel: 2, ir: IR_O2 }],
    { optLevel: 2, rows },
    {},
  );
  assert.equal(r.passObservation.firstLoss.pass, 'DSEPass');
  assert.equal(r.passObservation.controlMin, 1);
  assert.deepEqual(
    r.passObservation.stateRuns.flatMap((x) => Array(x.count).fill(x.state)),
    ['ABSENT', 'PRESENT', 'PRESENT', 'LOST'],
  );
});

test("record: the control's count in the pass trace is carried forward, not assumed", () => {
  const rows = [
    row(0, 'after', 'AlwaysInlinerPass', 'handle_request', 1),
    row(1, 'after', 'AlwaysInlinerPass', 'wipe_kept', 1),
    row(2, 'after', 'SomethingBroken', 'handle_request', 0),
    row(3, 'after', 'SomethingBroken', 'wipe_kept', 0),
    row(4, 'after', 'Later', 'handle_request', 0),
  ];
  const r = buildRecord(
    FX,
    META,
    [{ optLevel: 0, ir: IR_O0 }, { optLevel: 2, ir: IR_O2 }],
    { optLevel: 2, rows },
    {},
  );
  assert.equal(r.passObservation.brokenControlAt, 'after:Later');
  assert.equal(r.passObservation.controlMin, 0, 'the control really did fall to zero here');
});

// ── grading ─────────────────────────────────────────────────────────────────

function mkRecord(over = {}) {
  const base = {
    context: {},
    evidenceDigest: '',
    expectation: 'LOST_AT_HIGH_OPT',
    fixture: 'erasure-stack-local',
    language: META.language,
    oracle: { countsDeclarations: false, effect: 'llvm.memset', kind: 'ir-call-site', scope: 'ir-unit' },
    passObservation: { controlMin: 1, firstLoss: { from: 1, pass: 'DSEPass', phase: 'after', seq: 166 }, observedPasses: 71, optLevel: 2, points: 380, stateRuns: [], transitions: [] },
    property: { control: 'wipe_kept', id: 'erasure.wipe', subject: 'handle_request' },
    readings: [
      { controlCallSites: 1, declareLines: 1, naiveTotal: 3, optLevel: 0, state: 'PRESENT', targetCallSites: 1 },
      { controlCallSites: 1, declareLines: 1, naiveTotal: 2, optLevel: 2, state: 'LOST', targetCallSites: 0 },
    ],
    schemaVersion: 1,
    sourceRel: 'fixtures/erasure-stack-local.rs',
    stateHistory: ['PRESENT', 'LOST'],
    toolchain: META.toolchain,
  };
  const rec = { ...base, ...over };
  rec.evidenceDigest = digestRecord(rec);
  return rec;
}

const ids = (g) => g.findings.map((f) => f.id).sort();

test('grade POSITIVE: a present-then-gone pair with a live control is the finding', () => {
  const g = gradeRecord(mkRecord(), 'erasure-stack-local.json');
  assert.equal(g.verdict, 'LOSS_OBSERVED');
  assert.deepEqual(ids(g), ['VG-PROP-022']);
  assert.equal(g.findings[0].severity, 'critical');
  assert.equal(g.findings[0].where.pass, 'DSEPass');
  assert.match(g.findings[0].detail, /-O0=1 -O2=0/);
});

test('grade NEGATIVE: a property that survives is not flagged at all', () => {
  const g = gradeRecord(
    mkRecord({
      expectation: 'SURVIVES',
      readings: [
        { controlCallSites: 1, declareLines: 1, naiveTotal: 3, optLevel: 0, state: 'PRESENT', targetCallSites: 1 },
        { controlCallSites: 1, declareLines: 1, naiveTotal: 3, optLevel: 2, state: 'PRESENT', targetCallSites: 1 },
      ],
      stateHistory: ['PRESENT', 'PRESENT'],
      passObservation: { controlMin: 1, firstLoss: null, observedPasses: 71, optLevel: 2, points: 380, stateRuns: [], transitions: [] },
    }),
    'erasure-retained-slot.json',
  );
  assert.equal(g.verdict, 'SURVIVED');
  assert.deepEqual(g.findings, [], 'the good case must produce nothing');
});

test('grade: an absence with no matching presence is not a loss', () => {
  const g = gradeRecord(
    mkRecord({
      readings: [
        { controlCallSites: 1, declareLines: 1, naiveTotal: 2, optLevel: 0, state: 'ABSENT', targetCallSites: 0 },
        { controlCallSites: 1, declareLines: 1, naiveTotal: 2, optLevel: 2, state: 'ABSENT', targetCallSites: 0 },
      ],
      stateHistory: ['ABSENT', 'ABSENT'],
    }),
    'r.json',
  );
  assert.equal(g.verdict, 'NOT_OBSERVED');
  assert.ok(ids(g).includes('VG-PROP-020'));
  assert.ok(!ids(g).includes('VG-PROP-022'), 'an absence alone must never be reported as a loss');
});

test('grade: a single reading cannot support a loss', () => {
  const g = gradeRecord(
    mkRecord({
      readings: [{ controlCallSites: 1, declareLines: 1, naiveTotal: 2, optLevel: 2, state: 'ABSENT', targetCallSites: 0 }],
      stateHistory: ['ABSENT'],
    }),
    'r.json',
  );
  assert.equal(g.verdict, 'UNUSABLE');
  assert.ok(ids(g).includes('VG-PROP-020'));
  assert.ok(!ids(g).includes('VG-PROP-022'));
});

test('grade: a control that also died makes the whole measurement unusable', () => {
  const g = gradeRecord(
    mkRecord({
      readings: [
        { controlCallSites: 1, declareLines: 1, naiveTotal: 3, optLevel: 0, state: 'PRESENT', targetCallSites: 1 },
        { controlCallSites: 0, declareLines: 1, naiveTotal: 1, optLevel: 2, state: 'LOST', targetCallSites: 0 },
      ],
    }),
    'r.json',
  );
  assert.equal(g.verdict, 'UNUSABLE');
  assert.ok(ids(g).includes('VG-PROP-021'));
  assert.ok(!ids(g).includes('VG-PROP-022'), 'no loss may be reported from a broken control');
});

test('grade: a control never seen at all is unusable', () => {
  const g = gradeRecord(
    mkRecord({
      readings: [
        { controlCallSites: 0, declareLines: 1, naiveTotal: 2, optLevel: 0, state: 'PRESENT', targetCallSites: 1 },
        { controlCallSites: 0, declareLines: 1, naiveTotal: 1, optLevel: 2, state: 'LOST', targetCallSites: 0 },
      ],
    }),
    'r.json',
  );
  assert.equal(g.verdict, 'UNUSABLE');
  assert.ok(ids(g).includes('VG-PROP-021'));
});

test('grade: a name-based oracle is called out', () => {
  const g = gradeRecord(
    mkRecord({ oracle: { countsDeclarations: true, effect: 'llvm.memset', kind: 'symbol-name', scope: 'module' } }),
    'r.json',
  );
  assert.ok(ids(g).includes('VG-PROP-023'));
});

test('grade: a truncated state history is called out', () => {
  const g = gradeRecord(mkRecord({ stateHistory: ['PRESENT'] }), 'r.json');
  assert.ok(ids(g).includes('VG-PROP-024'));
});

test('grade: a verdict that contradicts the declared expectation is a finding', () => {
  const g = gradeRecord(mkRecord({ expectation: 'SURVIVES' }), 'r.json');
  assert.equal(g.verdict, 'LOSS_OBSERVED');
  assert.ok(ids(g).includes('VG-PROP-025'));
});

// ── the counting contract, on both command-line programs ────────────────────

function withTmp(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'second-language-'));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function capture(mainFn, argv) {
  const out = [];
  const errs = [];
  const code = mainFn(argv, (m) => out.push(String(m)), (m) => errs.push(String(m)));
  return { code, out: out.join('\n'), err: errs.join('\n') };
}

test('counting contract: check on an empty directory prints the line and exits 3', () => {
  withTmp((dir) => {
    const r = capture(checkMain, ['--records', dir]);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m);
    assert.equal(r.code, 3, 'an empty scan is never 0');
    assert.match(r.err, /empty scan is not a clean scan/);
  });
});

test('counting contract: --allow-empty is the only way an empty scan reaches 0', () => {
  withTmp((dir) => {
    const r = capture(checkMain, ['--records', dir, '--allow-empty']);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m);
    assert.equal(r.code, 0);
  });
});

test('counting contract: a missing directory is 3, not 0', () => {
  const r = capture(checkMain, ['--records', join(tmpdir(), 'second-language-does-not-exist')]);
  assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m);
  assert.equal(r.code, 3);
});

test('counting contract: the real exit code out of the process is 3 for an empty scan', () => {
  withTmp((dir) => {
    let status = null;
    try {
      execFileSync(process.execPath, [join(HERE, 'second-language-check.mjs'), '--records', dir], {
        stdio: 'pipe',
      });
      status = 0;
    } catch (e) {
      status = e.status;
    }
    assert.equal(status, 3);
  });
});

test('check: three records grade to two losses and one survival, and exit 2', () => {
  withTmp((dir) => {
    writeFileSync(join(dir, 'a-lost.json'), JSON.stringify(mkRecord()));
    writeFileSync(join(dir, 'b-lost.json'), JSON.stringify(mkRecord({ fixture: 'erasure-opaque-consumer' })));
    writeFileSync(
      join(dir, 'c-survives.json'),
      JSON.stringify(
        mkRecord({
          expectation: 'SURVIVES',
          fixture: 'erasure-retained-slot',
          readings: [
            { controlCallSites: 1, declareLines: 1, naiveTotal: 3, optLevel: 0, state: 'PRESENT', targetCallSites: 1 },
            { controlCallSites: 1, declareLines: 1, naiveTotal: 3, optLevel: 2, state: 'PRESENT', targetCallSites: 1 },
          ],
          stateHistory: ['PRESENT', 'PRESENT'],
          passObservation: { controlMin: 1, firstLoss: null, observedPasses: 71, optLevel: 2, points: 380, stateRuns: [], transitions: [] },
        }),
      ),
    );
    const r = capture(checkMain, ['--records', dir]);
    assert.match(r.out, /^inputs=3 checked=3 skipped=0$/m);
    assert.match(r.out, /a-lost\.json: LOSS_OBSERVED/);
    assert.match(r.out, /c-survives\.json: SURVIVED/);
    assert.equal((r.out.match(/VG-PROP-022/g) ?? []).length, 2);
    assert.equal(r.code, 2, 'an observed loss is a finding, not a clean run');
  });
});

test('skip is not pass: an unreadable record fails unless a skip is authorised', () => {
  withTmp((dir) => {
    writeFileSync(join(dir, 'ok.json'), JSON.stringify(mkRecord()));
    writeFileSync(join(dir, 'broken.json'), '{ this is not json');
    const before = process.env.SECOND_LANGUAGE_ALLOW_SKIP;
    delete process.env.SECOND_LANGUAGE_ALLOW_SKIP;
    const strict = capture(checkMain, ['--records', dir]);
    assert.equal(strict.code, 3, 'an unreadable record is not silently skipped');
    assert.match(strict.out, /^inputs=2 checked=1 skipped=0$/m);
    assert.match(strict.err, /unreadable broken\.json/);

    process.env.SECOND_LANGUAGE_ALLOW_SKIP = '1';
    const lax = capture(checkMain, ['--records', dir]);
    assert.match(lax.out, /^inputs=2 checked=1 skipped=1$/m);
    assert.match(lax.out, /skipped: broken\.json/, 'every skipped case is named');
    if (before === undefined) delete process.env.SECOND_LANGUAGE_ALLOW_SKIP;
    else process.env.SECOND_LANGUAGE_ALLOW_SKIP = before;
  });
});

test('check: a record whose digest does not match its content exits 4', () => {
  withTmp((dir) => {
    const rec = mkRecord();
    rec.readings[1].targetCallSites = 1; // edited after signing
    writeFileSync(join(dir, 'tampered.json'), JSON.stringify(rec));
    const r = capture(checkMain, ['--records', dir]);
    assert.equal(r.code, 4);
    assert.match(r.err, /evidenceDigest does not match/);
  });
});

test('record: an empty measurement directory exits 3 and prints the line', () => {
  withTmp((dir) => {
    writeFileSync(
      join(dir, 'meta.json'),
      JSON.stringify({ ...META, fixtures: [] }),
    );
    const r = capture(recordMain, ['--lab', dir]);
    assert.match(r.out, /^inputs=0 checked=0 skipped=0$/m);
    assert.equal(r.code, 3);
  });
});

test('record: end to end from IR files on disk, and a missing level is a failure', () => {
  withTmp((dir) => {
    mkdirSync(join(dir, 'ir'), { recursive: true });
    writeFileSync(join(dir, 'meta.json'), JSON.stringify({ ...META, fixtures: [FX] }));
    writeFileSync(join(dir, 'ir', 'erasure-stack-local-O0.ll'), IR_O0);
    // -O2 deliberately absent
    const before = process.env.SECOND_LANGUAGE_ALLOW_SKIP;
    delete process.env.SECOND_LANGUAGE_ALLOW_SKIP;
    const missing = capture(recordMain, ['--lab', dir]);
    assert.match(missing.out, /^inputs=1 checked=0 skipped=0$/m);
    assert.equal(missing.code, 3);
    assert.match(missing.err, /erasure-stack-local-O2\.ll was not produced/);

    writeFileSync(join(dir, 'ir', 'erasure-stack-local-O2.ll'), IR_O2);
    const good = capture(recordMain, ['--lab', dir]);
    assert.match(good.out, /^inputs=1 checked=1 skipped=0$/m);
    assert.equal(good.code, 0);
    const written = JSON.parse(readFileSync(join(dir, 'records', 'erasure-stack-local.json'), 'utf8'));
    assert.deepEqual(written.stateHistory, ['PRESENT', 'LOST']);
    assert.equal(written.evidenceDigest, digestRecord(written));
    if (before === undefined) delete process.env.SECOND_LANGUAGE_ALLOW_SKIP;
    else process.env.SECOND_LANGUAGE_ALLOW_SKIP = before;

    const graded = capture(checkMain, ['--records', join(dir, 'records')]);
    assert.match(graded.out, /^inputs=1 checked=1 skipped=0$/m);
    assert.equal(graded.code, 2);
    assert.match(graded.out, /VG-PROP-022/);
  });
});
