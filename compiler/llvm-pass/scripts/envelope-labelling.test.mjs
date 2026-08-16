// The part of the configuration envelope that has to be right when nobody is
// looking: how a cell is labelled when the observation did not happen.
//
// run-envelope.sh needs clang, a pass plugin and a linker, so it does not run
// here. build-envelope.py and check-envelope.py need neither -- they read cell
// manifests and records -- and they are where the discipline actually lives.
// The observer has three ways to produce nothing while the compiler exits 0:
// an unloadable plugin, a missing OBS_* that leaves it unregistered, and a
// pipeline whose extension points it never reaches. In all three the build
// looks fine, so a labelling bug here turns an unexamined build into a clean
// one and no other test in this repository would notice.
//
// Every case below is written as a mutation: the input is a cell that did not
// work, and the assertion is that the label says so. A version of these scripts
// that returned a verdict anyway would pass no test in this file.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const BUILD = join(HERE, 'build-envelope.py');
const CHECK = join(HERE, 'check-envelope.py');

/** The first python that runs. Named rather than assumed, so a machine without
 *  one reports that instead of reporting a pass. */
function python() {
  for (const cmd of ['python3', 'python']) {
    const r = spawnSync(cmd, ['-c', 'print(1)'], { encoding: 'utf8' });
    if (r.status === 0) return cmd;
  }
  return null;
}
const PY = python();

/** interfaces.md section 5, spelled a third time -- the C++ writes it, the two
 *  python checkers recompute it, and this recomputes it again in another
 *  language. A record whose digest only ever agrees with the code that wrote it
 *  has not been checked by anything. */
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

function digestOf(record) {
  const stripped = {};
  for (const [k, v] of Object.entries(record)) {
    if (k !== 'context' && k !== 'evidenceDigest') stripped[k] = v;
  }
  return createHash('sha256').update(canonical(stripped), 'utf8').digest('hex');
}

function makeRecord(overrides = {}) {
  const unit = {
    allocaCount: 1, allocaSizesBytes: [32], allocasEscapingToOpaqueCall: 1,
    effect: 1, effectCallSites: 1, effectTargets: [], forbiddenCallSites: 0,
    liveConditionalBranches: 0, unitPresent: true, zeroStores: 0,
  };
  const rec = {
    schemaVersion: 'ir-checkpoints-v0',
    component: 'IrCheckpoints',
    propertyId: 'erasure.wipe',
    extractor: 'ir.wipe-effect',
    source: 'erasure/target.c',
    module: 'target.c',
    subjectUnit: 'handle_request',
    controlUnit: 'wipe_kept',
    subject: { preOptIr: { ...unit }, postOptIr: { ...unit, effect: 0, effectCallSites: 0 } },
    control: { held: true, minEffectObserved: 1, preOptIr: { ...unit }, postOptIr: { ...unit } },
    firstZeroTransition: { from: 1, pass: 'DSEPass', unit: 'handle_request' },
    oracleDivergence: { totalAfterPassObservations: 288 },
    verdict: { state: 'LOST', reason: 'effect removed', completesTheCheck: true },
    findings: [{ id: 'VG-PROP-001' }],
    ...overrides,
  };
  rec.evidenceDigest = digestOf(rec);
  return rec;
}

/** One lab on disk, one cell manifest per entry, then build-envelope.py over it. */
function buildEnvelope(cells) {
  const lab = mkdtempSync(join(tmpdir(), 'irck-env-'));
  const out = join(lab, 'out');
  mkdirSync(join(lab, 'cells'), { recursive: true });
  mkdirSync(join(lab, 'records'), { recursive: true });

  for (const c of cells) {
    const kv = {
      cellId: c.cellId, subject: c.subject ?? 'erasure',
      propertyId: 'erasure.wipe', extractor: 'ir.wipe-effect',
      subjectUnit: 'handle_request', controlUnit: 'wipe_kept',
      opt: c.opt ?? '-O2', ndebug: c.ndebug ?? '0', lto: c.lto ?? 'none',
      target: c.target ?? 'host', freestanding: c.freestanding ?? '0',
      stage: c.stage ?? 'compile', cc: 'clang-18', rc: String(c.rc),
      pluginSha256: c.pluginSha256 ?? 'deadbeef',
      expectedBroken: c.expectedBroken ?? '0',
      expectedBrokenReason: c.expectedBrokenReason ?? '',
      record: c.record ? `records/${c.cellId}.json` : '',
      extraArgsB64: '', stderrB64: Buffer.from(c.stderr ?? '').toString('base64'),
    };
    writeFileSync(join(lab, 'cells', `${c.cellId}.kv`),
      Object.entries(kv).map(([k, v]) => `${k}=${v}`).join('\n') + '\n');
    if (c.record) {
      writeFileSync(join(lab, 'records', `${c.cellId}.json`), JSON.stringify(c.record));
    }
  }

  const r = spawnSync(PY, [BUILD], {
    encoding: 'utf8',
    env: { ...process.env, IRCK_ENV_LAB: lab, IRCK_ENVELOPE_OUT: out },
  });
  const envelope = r.status === 0
    ? JSON.parse(readFileSync(join(out, 'envelope.json'), 'utf8'))
    : null;
  return { status: r.status, stderr: r.stderr, envelope, lab, out, cleanup: () => rmSync(lab, { recursive: true, force: true }) };
}

function cellOf(envelope, id) {
  return envelope.cells.find((c) => c.cellId === id);
}

test('a cell that observed nothing is never labelled with a verdict', { skip: PY ? false : 'no python on PATH' }, () => {
  const b = buildEnvelope([
    // The toolchain refused: rc 1, nothing written.
    { cellId: 'refused', rc: 1, stderr: "error: unable to load plugin 'x'" },
    // The toolchain agreed and the observer never registered: rc 3, nothing
    // written, compiler exit status 0. This is the silent mode.
    { cellId: 'silent', rc: 3, stderr: 'no record was written' },
    // Everything worked.
    { cellId: 'observed', rc: 0, record: makeRecord() },
  ]);
  try {
    assert.equal(b.status, 0, b.stderr);
    // The apparatus verdict and the property state are separate columns, and the
    // pair is asserted together on purpose. `state` stays inside the six words
    // interfaces.md section 3 fixes -- NOT_OBSERVED, its own word for "no
    // observation was made here" -- and WHY there was none is in `measurement`.
    // Asserting only one of the two would let a future edit put the apparatus
    // label back into the state column while this test still passed.
    assert.equal(cellOf(b.envelope, 'refused').state, 'NOT_OBSERVED');
    assert.equal(cellOf(b.envelope, 'refused').measurement, 'UNSUPPORTED');
    assert.equal(cellOf(b.envelope, 'silent').state, 'NOT_OBSERVED');
    assert.equal(cellOf(b.envelope, 'silent').measurement, 'BROKEN_MEASUREMENT');
    assert.equal(cellOf(b.envelope, 'observed').state, 'LOST');
    assert.equal(cellOf(b.envelope, 'observed').measurement, 'OK');
    for (const id of ['refused', 'silent']) {
      const c = cellOf(b.envelope, id);
      assert.equal(c.handshake.ok, false);
      assert.equal(c.completesTheCheck, false,
        `${id} must not read as a completed check`);
      assert.equal(c.controlHeld, null);
      assert.deepEqual(c.findings, []);
    }
  } finally { b.cleanup(); }
});

test('a record that no longer hashes to its own digest loses its verdict', { skip: PY ? false : 'no python on PATH' }, () => {
  const tampered = makeRecord();
  tampered.subjectUnit = 'somebody_else';   // digest now stale
  const b = buildEnvelope([{ cellId: 'tampered', rc: 0, record: tampered }]);
  try {
    const c = cellOf(b.envelope, 'tampered');
    assert.equal(c.handshake.digestVerified, false);
    assert.equal(c.handshake.ok, false);
    assert.equal(c.state, 'NOT_OBSERVED',
      'a record whose contents and digest disagree must not be graded');
    assert.equal(c.measurement, 'BROKEN_MEASUREMENT');
  } finally { b.cleanup(); }
});

test('a record from a pipeline the observer never stepped is not a handshake', { skip: PY ? false : 'no python on PATH' }, () => {
  // The file exists, the component and schema are right, and no pass was ever
  // observed. Existence of a record is not evidence that anything ran.
  const b = buildEnvelope([
    { cellId: 'zero-observations', rc: 0,
      record: makeRecord({ oracleDivergence: { totalAfterPassObservations: 0 } }) },
  ]);
  try {
    const c = cellOf(b.envelope, 'zero-observations');
    assert.equal(c.handshake.afterPassObservations, 0);
    assert.equal(c.handshake.ok, false);
    assert.equal(c.state, 'NOT_OBSERVED');
    assert.equal(c.measurement, 'BROKEN_MEASUREMENT');
  } finally { b.cleanup(); }
});

test('a link-stage cell may not report a pre-link module identifier', { skip: PY ? false : 'no python on PATH' }, () => {
  // The failure this prevents: the bitcode compile loads the plugin, writes the
  // record, and the link finds nothing to overwrite -- so a pre-link reading is
  // filed under a backend label and the LTO axis reports an attribution it
  // never made.
  const b = buildEnvelope([
    { cellId: 'backend-honest', rc: 0, stage: 'link', lto: 'full-backend',
      record: makeRecord({ module: 'ld-temp.o' }) },
    { cellId: 'backend-smuggled', rc: 0, stage: 'link', lto: 'full-backend',
      record: makeRecord({ module: 'target.c' }) },
  ]);
  try {
    assert.equal(cellOf(b.envelope, 'backend-honest').handshake.ok, true);
    const bad = cellOf(b.envelope, 'backend-smuggled');
    assert.equal(bad.handshake.ok, false);
    assert.equal(bad.handshake.stageMismatch, 'target.c');
    assert.equal(bad.state, 'NOT_OBSERVED');
    assert.equal(bad.measurement, 'BROKEN_MEASUREMENT');
  } finally { b.cleanup(); }
});

test('an envelope with no cell manifests is exit 3, not an empty pass', { skip: PY ? false : 'no python on PATH' }, () => {
  const lab = mkdtempSync(join(tmpdir(), 'irck-env-empty-'));
  try {
    const r = spawnSync(PY, [BUILD], {
      encoding: 'utf8',
      env: { ...process.env, IRCK_ENV_LAB: lab, IRCK_ENVELOPE_OUT: join(lab, 'out') },
    });
    assert.equal(r.status, 3, 'nothing to assemble must not assemble to nothing');
  } finally { rmSync(lab, { recursive: true, force: true }); }
});

// --- check-envelope.py: the checks that must fire ---------------------------
//
// Asserted on the message rather than the exit code. A partial envelope
// disagrees for many reasons at once, so "exit 2" alone would pass even if the
// check under test never ran.

function runCheck(envelope) {
  const dir = mkdtempSync(join(tmpdir(), 'irck-chk-'));
  const path = join(dir, 'envelope.json');
  writeFileSync(path, JSON.stringify(envelope));
  const r = spawnSync(PY, [CHECK], {
    encoding: 'utf8',
    env: { ...process.env, IRCK_ENVELOPE_JSON: path },
  });
  rmSync(dir, { recursive: true, force: true });
  return r;
}

function gradedCell(over = {}) {
  return {
    cellId: over.cellId ?? 'c', control: over.control ?? '-',
    subject: over.subject ?? 'erasure', propertyId: 'erasure.wipe',
    extractor: 'ir.wipe-effect', subjectUnit: 'handle_request', controlUnit: 'wipe_kept',
    config: { opt: '-O2', ndebug: false, lto: 'none', target: 'host',
              freestanding: false, extraArgs: [], cc: 'clang-18', ...(over.config ?? {}) },
    rc: over.rc ?? 0, pluginSha256: 'deadbeef',
    handshake: { recordWritten: true, component: 'IrCheckpoints',
                 schemaVersion: 'ir-checkpoints-v0', moduleId: 'target.c',
                 afterPassObservations: 288, digestVerified: true, stage: 'compile',
                 pluginSha256: 'deadbeef', ok: true, ...(over.handshake ?? {}) },
    expectedBroken: over.expectedBroken ?? false,
    expectedBrokenReason: over.expectedBrokenReason ?? '',
    state: over.state ?? 'LOST', reason: over.reason ?? 'effect removed',
    controlHeld: over.controlHeld ?? true, completesTheCheck: true,
    firstZeroPass: over.firstZeroPass ?? 'DSEPass',
    findings: over.findings ?? ['VG-PROP-001'],
    subjectEffect: { preOpt: 1, postOpt: 0, unitPresentPostOpt: true },
  };
}

function envelopeOf(cells) {
  return {
    schemaVersion: 'security-configuration-envelope-v0', component: 'IrCheckpoints',
    axes: {}, pluginSha256Observed: ['deadbeef'], pluginSha256Configured: ['deadbeef'],
    counts: { cells: cells.length, graded: cells.length, unsupported: 0,
              brokenMeasurement: 0, handshakeOk: cells.length },
    cells,
  };
}

test('the canary fires when erasure -O2 stops being LOST', { skip: PY ? false : 'no python on PATH' }, () => {
  const good = runCheck(envelopeOf([gradedCell()]));
  assert.ok(!/This cell is the canary/.test(good.stderr),
    'the canary must not fire on a cell that is LOST');
  const bad = runCheck(envelopeOf([
    gradedCell({ state: 'PRESENT', firstZeroPass: null, findings: [] }),
  ]));
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /This cell is the canary/);
});

test('a declaration that a cell is broken is refused when the cell works', { skip: PY ? false : 'no python on PATH' }, () => {
  const r = runCheck(envelopeOf([
    gradedCell({ expectedBroken: true, expectedBrokenReason: 'no-sysroot-for-triple' }),
  ]));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /declared broken .* and it was not/);
});

test('a graded cell with no handshake is refused', { skip: PY ? false : 'no python on PATH' }, () => {
  const r = runCheck(envelopeOf([gradedCell({ handshake: { ok: false } })]));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /graded with no handshake/);
});

test('an absolute path anywhere in the envelope is refused', { skip: PY ? false : 'no python on PATH' }, () => {
  const r = runCheck(envelopeOf([gradedCell({ reason: '/home/someone/lab/erasure/target.c' })]));
  assert.equal(r.status, 2);
  assert.match(r.stderr, /absolute path at/);
});

test('a cross-target cell with no native twin is refused', { skip: PY ? false : 'no python on PATH' }, () => {
  const twinned = runCheck(envelopeOf([
    gradedCell({ cellId: 'host' }),
    gradedCell({ cellId: 'arm', config: { target: 'arm-none-eabi' } }),
  ]));
  assert.ok(!/would cross a second axis/.test(twinned.stderr),
    'a cross-target cell with an exact native twin is comparable');
  const lonely = runCheck(envelopeOf([
    gradedCell({ cellId: 'host', config: { freestanding: false } }),
    gradedCell({ cellId: 'arm', config: { target: 'arm-none-eabi', freestanding: true } }),
  ]));
  assert.equal(lonely.status, 2);
  assert.match(lonely.stderr, /would cross a second axis/);
});
