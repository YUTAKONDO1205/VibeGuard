// `policy.fallback.exposureFrontiers` — refusing to quote a measured cell at a
// build that is not the one the cell was measured in.
//
// Like fallback-auto.test.mjs, nothing here spawns a compiler and nothing here
// compiles a ladder: the guard runs on two documents somebody else wrote, and
// the `compiler` handed in below is a name that does not exist so that a case
// which somehow reached a spawn fails instead of quietly measuring.
//
// The frontier documents are hand-written for the same reason the tables in
// fallback-auto.test.mjs are: a fixture produced by the deriver would go green
// whenever the deriver and this reader drifted together. The one case that IS
// built by the real `deriveSidecar` is marked as such, and it is there to catch
// the opposite failure — a hand-written fixture that has stopped describing what
// the producer emits.
//
// ★ THE FIXTURES ARE SEALED BY A SECOND IMPLEMENTATION OF §5. `seal()` below
// canonicalises by building a key-sorted copy and handing it to
// `JSON.stringify`, while `evidenceDigestOf` in the driver builds the canonical
// text directly. Two implementations of the same five rules, on the two sides of
// every digest assertion in this file: if either drifts, the fixtures stop
// verifying and every case here goes red. Sealing with the function under test
// would make the digest gate assert nothing at all.
//
// The rung readings below are fixture values chosen to exercise the reader. They
// are not a measurement of anything and must not be read as one.

import test from 'node:test';
import assert from 'node:assert/strict';

import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  CONFIG_KEYS, SIDECAR_SCHEMA_VERSION, canonConfig, configKey, deriveSidecar,
} from '../../envelope/derive-frontier-sidecar.mjs';
import {
  EXPOSURE_RESULTS, FAILURE_DIRECTION, LADDER_FRONTIER_SCHEMA_VERSION, compareFrontiers,
} from '../../envelope/frontier-match.mjs';
import { normalise, splitDriverArgs } from '../lib/cmdline.mjs';
import {
  AUTO_PROFILE, EXPOSURE_REFUSALS, FALLBACK_TABLE_SCHEMA_VERSION, checkExposure, evaluateFallback,
  evidenceDigestOf, exposureArgs, parseObservation,
} from '../lib/fallback.mjs';
import { findAbsolutePaths } from '../lib/paths.mjs';

const NOWHERE = 'clang-that-must-never-be-spawned';
const PROP = 'survive.authorization-check';

const LADDER_SHA = 'a'.repeat(64);

/** The six-axis key a `-c guard.c -O2` host build resolves against. */
const HOST_O2 = { cc: 'clang-18', freestanding: false, lto: 'none', ndebug: false, opt: '-O2', target: 'host' };

/** Fixture rung readings. Hand-written; see the header. */
const RUNGS = Object.freeze({ a1: 'PRESENT', 'b1-lib': 'PRESENT', c1: 'LOST', 'd1-printf': 'ABSENT' });

/**
 * interfaces.md §5, implemented a second way: a key-sorted deep copy handed to
 * `JSON.stringify`, rather than canonical text assembled directly. See the file
 * header for why the two must not be the same code.
 */
function sortedCopy(v) {
  if (Array.isArray(v)) return v.map(sortedCopy);
  if (v !== null && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortedCopy(v[k]);
    return out;
  }
  if (typeof v === 'number' && !Number.isInteger(v)) throw new Error(`§5 rule 4: ${v} is not an integer`);
  return v;
}

/** A document with the digest `build-ladder-frontier.py` would have sealed it with. */
function seal(doc) {
  const stripped = { ...doc };
  delete stripped.context;
  delete stripped.evidenceDigest;
  return { ...doc, evidenceDigest: createHash('sha256').update(JSON.stringify(sortedCopy(stripped)), 'utf8').digest('hex') };
}

/**
 * One `vibeguard.ladder-frontier/1` reading, sealed.
 *
 * It carries `exposure` and not `config`, which is what the assembler emits: the
 * document records the command line it was measured under and the deriver turns
 * that into the six axes. `over` is merged before sealing, so a case that mutates
 * a field gets a document that still verifies — every refusal below is then the
 * refusal it says it is, and not the digest gate firing first.
 */
function frontierDoc(over = {}) {
  return seal({
    exposure: { extraArgs: [], id: 'O2', opt: '-O2' },
    frontier: { ...RUNGS },
    health: { broken: false },
    ladder: { generatorVersion: '1', sourceSha256: LADDER_SHA },
    schemaVersion: LADDER_FRONTIER_SCHEMA_VERSION,
    toolchain: { cc: 'clang-18', clang: '18.1.3' },
    ...over,
  });
}

/** One sidecar entry, shaped as `derive-frontier-sidecar.mjs` writes them. */
function entryFor(config, over = {}) {
  return {
    config: canonConfig(config),
    configKey: configKey(config),
    frontier: { ...RUNGS },
    health: { broken: false },
    ladder: { generatorVersion: '1', sourceSha256: LADDER_SHA },
    sources: ['O2.json'],
    toolchain: { cc: 'clang-18', clang: '18.1.3' },
    unusableReason: null,
    usable: true,
    ...over,
  };
}

function sidecarDoc(entries, over = {}) {
  return {
    anomalies: [],
    configKeys: [...CONFIG_KEYS],
    counts: { brokenDocuments: 0, collisions: 0, documents: entries.length, keys: entries.length, unusableKeys: 0, usableKeys: entries.length },
    entries,
    generator: { name: 'derive-frontier-sidecar', version: '1' },
    instrument: {
      failureDirection: FAILURE_DIRECTION,
      resultVocabulary: [...EXPOSURE_RESULTS],
      use: 'guard-only: a frontier may refuse a cell, and may never fill one or choose one',
    },
    schemaVersion: SIDECAR_SCHEMA_VERSION,
    ...over,
  };
}

// ---- the fallback table the exposure guard sits on top of -------------------

const ENVELOPE_TEXT = '{"schemaVersion":"security-configuration-envelope-v0","cells":[]}\n';
const ENVELOPE_SHA = createHash('sha256').update(ENVELOPE_TEXT).digest('hex');

function row({ from = HOST_O2, to = '-O0' } = {}) {
  return {
    evidence: [{ cellId: `subject+opt=${to}`, controlHeld: true, measurement: 'OK', state: 'PRESENT', subject: 'authz-folded' }],
    from,
    lostSubjects: ['authz-folded'],
    profile: to,
    propertyId: PROP,
    rejected: [],
    resolution: 'fallback',
    to: { ...from, opt: to },
  };
}

function tableDoc(rows) {
  return {
    anomalies: [],
    counts: { cells: 74, controlCells: 2, lostCells: rows.length, rows: rows.length },
    generator: { name: 'derive-fallback-table', version: '1' },
    policy: { direction: 'weaken-only' },
    rows,
    schemaVersion: FALLBACK_TABLE_SCHEMA_VERSION,
    source: { cells: 74, path: 'envelope.json', schemaVersion: 'security-configuration-envelope-v0', sha256: ENVELOPE_SHA },
  };
}

/**
 * A root holding the table, the envelope it names, and whichever of the two
 * frontier documents the case wants. `null` leaves a file off disk, which is how
 * the unreadable cases are built; `text` writes bytes that are not JSON.
 */
function withRoot(t, {
  frontiers = sidecarDoc([entryFor(HOST_O2)]), measured = frontierDoc(), rows = [row()], text = {},
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'vg-fb-front-'));
  t.after(() => rmSync(root, { force: true, recursive: true }));
  writeFileSync(join(root, 'table.json'), JSON.stringify(tableDoc(rows), null, 2));
  writeFileSync(join(root, 'envelope.json'), ENVELOPE_TEXT);
  if (text.frontiers !== undefined) writeFileSync(join(root, 'frontiers.json'), text.frontiers);
  else if (frontiers !== null) writeFileSync(join(root, 'frontiers.json'), JSON.stringify(frontiers, null, 2));
  if (text.measured !== undefined) writeFileSync(join(root, 'measured.json'), text.measured);
  else if (measured !== null) writeFileSync(join(root, 'measured.json'), JSON.stringify(measured, null, 2));
  return root;
}

/** The digest the record names a reading by: the bytes that were read. */
function digestOf(root, name) {
  return createHash('sha256').update(readFileSync(join(root, name))).digest('hex');
}

const AUTO = { enabled: true, profile: AUTO_PROFILE, profileTable: 'table.json' };
const GUARDED = { ...AUTO, exposureFrontiers: 'frontiers.json' };

function policyFor(fallback) {
  return {
    failOn: 'high',
    fallback,
    policyVersion: 'policy-v0',
    properties: [{ id: PROP, kind: 'must-survive' }],
  };
}

function ctx(root, fallback, extra = {}) {
  const argv = ['-c', 'guard.c', '-O2'];
  return {
    blocked: null,
    compiler: NOWHERE,
    compilerArgv: argv,
    cwd: root,
    env: {},
    exposureFrontier: 'measured.json',
    normalised: normalise(argv, { mode: 'c' }),
    observer: null,
    policy: policyFor(fallback),
    root,
    workDir: 'work-dir-never-written',
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// The channel the reading arrives on
// ---------------------------------------------------------------------------

test('--vg-exposure-frontier is the driver\'s own flag and never reaches the compiler', () => {
  // Until this flag existed the guard had two reachable states, off and
  // refuse-everything: a policy could name a sidecar and nothing could supply
  // the half of the comparison that is taken per build.
  const { own, compilerArgv } = splitDriverArgs(
    ['-c', 'a.c', '--vg-exposure-frontier', 'lab/O2.json', '-O2'],
  );
  assert.equal(own.exposureFrontier, 'lab/O2.json');
  assert.deepEqual(compilerArgv, ['-c', 'a.c', '-O2']);

  assert.equal(splitDriverArgs(['--vg-exposure-frontier=lab/O2.json']).own.exposureFrontier, 'lab/O2.json');
  assert.deepEqual(splitDriverArgs(['--vg-exposure-frontier']).errors, ['--vg-exposure-frontier requires a value']);

  // After `--` it is the compiler's token, like every other driver flag: what
  // decides a check must not be reachable from the region the caller was
  // promised would be passed through untouched.
  const after = splitDriverArgs(['-c', 'a.c', '--', '--vg-exposure-frontier', 'weak.json']);
  assert.equal(after.own.exposureFrontier, null);
  assert.deepEqual(after.compilerArgv, ['-c', 'a.c', '--', '--vg-exposure-frontier', 'weak.json']);
});

// ---------------------------------------------------------------------------
// A policy that does not ask for the guard does not get it, or anything else
// ---------------------------------------------------------------------------

/** Every key `emptyRecord` wrote before this guard existed. */
const RECORD_KEYS = [
  'candidate', 'claim', 'complete', 'configured', 'counts', 'enabled', 'granularity', 'observer', 'profile',
  'profileResolution', 'profileSource', 'properties', 'reason', 'rejectIfStillLost', 'requested', 'status',
  'unit', 'verdict',
];

test('a policy that names no sidecar gets today\'s record, key for key', (t) => {
  const root = withRoot(t);
  const r = evaluateFallback(ctx(root, AUTO));

  // The lookup still resolved, and the run stopped at the next unmet
  // precondition — the missing observer — exactly as it does without any of
  // this. Any guard that had run would have reported its own reason here.
  assert.equal(r.record.profile, '-O0');
  assert.equal(r.record.reason, 'no-observer');
  assert.deepEqual(Object.keys(r.record).sort(), [...RECORD_KEYS].sort());
  assert.ok(!('exposureCheck' in r.record), 'a policy that never asked for the guard grew a key from it');
});

test('a measured frontier handed to a policy that names no sidecar is not read at all', (t) => {
  // The guard is opted into by the policy and by nothing else. A frontier
  // arriving on an invocation whose policy says nothing about exposure must not
  // start a comparison, and — the part that matters for evidence digests — must
  // not change a single byte of the record.
  const root = withRoot(t);
  const without = evaluateFallback(ctx(root, AUTO, { exposureFrontier: null }));
  const with_ = evaluateFallback(ctx(root, AUTO, { exposureFrontier: 'measured.json' }));
  assert.equal(JSON.stringify(with_.record), JSON.stringify(without.record));
});

// ---------------------------------------------------------------------------
// The positive case. Without it every assertion below is satisfied by a guard
// that refuses unconditionally, because refusing is the safe answer.
// ---------------------------------------------------------------------------

test('a frontier that separates nothing lets the resolution proceed, and is recorded as consistent', (t) => {
  const root = withRoot(t);
  const r = evaluateFallback(ctx(root, GUARDED));

  assert.equal(r.record.profile, '-O0');
  assert.equal(r.record.reason, 'no-observer', 'the guard, having found nothing, must not have stopped the run');

  const check = r.record.exposureCheck;
  assert.deepEqual(
    Object.keys(check).sort(),
    ['configKeys', 'exposure', 'frontierDigest', 'reason', 'result', 'rungs', 'sidecar'],
  );
  assert.equal(check.result, 'exposure-consistent');
  assert.equal(check.frontierDigest, digestOf(root, 'measured.json'));
  assert.equal(check.sidecar.path, 'frontiers.json');
  assert.equal(check.sidecar.sha256, digestOf(root, 'frontiers.json'));

  // ★ The pass carries the comparison's evidence, because it is the one outcome
  // a reader over-reads. Four rungs answered the same way; that is a small
  // ladder, and a record that said only "consistent" would read exactly like a
  // twelve-rung one.
  assert.equal(check.rungs, Object.keys(RUNGS).length);
  assert.deepEqual(check.configKeys, [configKey(HOST_O2)]);
  assert.match(check.reason, /all 4 rungs responded identically/);
  assert.match(check.reason, /[Nn]ecessary, never sufficient/);
  assert.deepEqual(check.exposure.build, { extraArgs: [], opt: '-O2' });
  assert.deepEqual(check.exposure.frontier, { extraArgs: [], opt: '-O2' });

  // `exposure-consistent` is necessary and never sufficient, and the record
  // must not say otherwise anywhere in it.
  assert.doesNotMatch(JSON.stringify(r.record), /verified|matched exposure|same exposure/i);
  assert.deepEqual(findAbsolutePaths(r.record), []);
});

test('★ a sidecar built by the real deriver is read by this reader', (t) => {
  // The seam with compiler/envelope, exercised end to end: the document under
  // `frontiers.json` here is whatever `deriveSidecar` emits, not what this file
  // believes it emits. Every other sidecar below is hand-written, and this case
  // is what stops all of them from quietly describing a shape nobody produces.
  const root = withRoot(t, { frontiers: null });
  const built = deriveSidecar([{ id: 'O2', doc: frontierDoc() }]);
  assert.equal(built.exitCode, 0, `the deriver refused the fixture: ${built.problems.join('; ')}`);
  writeFileSync(join(root, 'frontiers.json'), `${JSON.stringify(built.sidecar, null, 2)}\n`);

  // The key the deriver filed it under is the key this build resolves against —
  // the two ends of the lookup reading one command line the same way, which is
  // the whole reason `config-axes.mjs` exists.
  assert.deepEqual(built.sidecar.entries.map((e) => e.configKey), [configKey(HOST_O2)]);

  const r = evaluateFallback(ctx(root, GUARDED));
  assert.equal(r.record.reason, 'no-observer');
  assert.equal(r.record.exposureCheck.result, 'exposure-consistent');
});

test('the comparison is the one in compiler/envelope, called with the two documents', () => {
  // This driver does not own the comparison and must not grow a second one: a
  // rule written twice drifts on the case that matters, which here is a rung
  // that could not be read.
  const consistent = compareFrontiers(frontierDoc(), frontierDoc());
  assert.equal(consistent.result, 'exposure-consistent');
  assert.deepEqual(consistent.differingRungs, []);

  const differing = compareFrontiers(frontierDoc(), frontierDoc({ frontier: { ...RUNGS, c1: 'PRESENT' } }));
  assert.equal(differing.result, 'exposure-mismatch');
  assert.deepEqual(differing.differingRungs, ['c1']);

  const broken = compareFrontiers(frontierDoc(), frontierDoc({ health: { broken: true, reason: 'broken-measurement' } }));
  assert.equal(broken.result, 'exposure-incomparable');
  assert.deepEqual(broken.differingRungs, [], 'a reading that could not be compared has not disagreed about a rung');
});

// ---------------------------------------------------------------------------
// interfaces.md §5, recomputed on the reading side
// ---------------------------------------------------------------------------

test('evidenceDigestOf implements the five rules, pinned to a vector', () => {
  // A literal, so that "both implementations of §5 changed together" cannot go
  // green. `context` and `evidenceDigest` are stripped from the TOP LEVEL only,
  // `context` as a whole subtree; keys sort at every level; array order is kept.
  const doc = {
    evidenceDigest: 'this is not checked, it is removed',
    b: [2, { d: 4, c: 3 }],
    context: { generatedAt: 1700000000, host: 'unrecorded' },
    a: 1,
  };
  assert.equal(evidenceDigestOf(doc), '88c3cdf568e74603bc9ea42ed03f42ad6dcf46dbfbb56089d8a163f6b84a0c52');

  // Whatever goes into `context` cannot move the digest — that is the whole
  // convention, and it is why a re-assembly on another day still verifies.
  assert.equal(
    evidenceDigestOf({ ...doc, context: { generatedAt: 2, host: 'somewhere else', extra: [1, 2, 3] } }),
    evidenceDigestOf(doc),
  );
  // A `context` below the top level is an ordinary key.
  assert.notEqual(evidenceDigestOf({ ...doc, b: [2, { c: 3, d: 4, context: 1 }] }), evidenceDigestOf(doc));
  // Array order is significant and is never sorted.
  assert.notEqual(evidenceDigestOf({ ...doc, b: [{ c: 3, d: 4 }, 2] }), evidenceDigestOf(doc));
});

test('a document with a non-integer number has no verifiable digest and is refused, not rounded', (t) => {
  // §5 rule 4. The refusal is the digest one because that is what is lost: a
  // document that cannot be canonicalised cannot be checked against anything.
  const root = withRoot(t, { measured: { ...frontierDoc(), observations: { ratio: 0.5 } } });
  const r = evaluateFallback(ctx(root, GUARDED));
  assert.equal(r.record.reason, 'fallback-exposure-measurement-digest-mismatch');
  assert.match(r.findings[0].detail, /cannot be canonicalised/);
});

// ---------------------------------------------------------------------------
// Binding the reading to the build — the point of the exercise
// ---------------------------------------------------------------------------

test('exposureArgs is the one rule, and it names what changes the optimiser', () => {
  // ★ The CI job that runs the ladder generates its arguments with this
  // function and the guard compares against it. Two copies of this rule would
  // not disagree visibly — the frontier would simply be measured under a line
  // missing a flag, and would then bind clean against a build that has it.
  const argv = [
    '-c', 'guard.c', '-O2', '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3', '-fno-builtin-memset',
    '-march=native', '-std=c11', '-I', 'inc', '-isystem/opt/x', '-include', 'prelude.h',
    '-o', 'guard.o', '-MF', 'guard.d', '-Wall', '-Wl,-z,now', 'other.c',
  ];
  const got = exposureArgs(normalise(argv, { mode: 'c' }));
  assert.equal(got.opt, '-O2');
  assert.deepEqual(got.extraArgs, [
    '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3', '-fno-builtin-memset', '-march=native', '-std=c11',
    '-I', 'inc', '-isystem/opt/x', '-include', 'prelude.h',
  ]);

  // `-o`, `-MF`, `-Wall`, `-Wl,` and the sources are left out: none of them
  // reaches the ladder specimen's IR.
  for (const dropped of ['-o', 'guard.o', '-MF', 'guard.d', '-Wall', '-Wl,-z,now', 'other.c', 'guard.c', '-c']) {
    assert.ok(!got.extraArgs.includes(dropped), `${dropped} is not exposure-relevant`);
  }

  // The level travels in `opt` and never in `extraArgs`, and it is the LAST one,
  // as clang reads it — so the ladder is measured at the level this compiles at.
  const twice = exposureArgs(normalise(['-c', 'a.c', '-O3', '-O1'], { mode: 'c' }));
  assert.equal(twice.opt, '-O1');
  assert.deepEqual(twice.extraArgs, []);
  assert.equal(exposureArgs(normalise(['-c', 'a.c'], { mode: 'c' })).opt, '-O0');

  // A value-taking flag travels with its operand or the ladder's line will not
  // parse.
  assert.deepEqual(exposureArgs(normalise(['-c', 'a.c', '-D', 'NDEBUG'], { mode: 'c' })).extraArgs, ['-D', 'NDEBUG']);
});

test('a flag hidden inside a passthrough is still the flag', () => {
  // MEASURED 2026-08-17, and this guard failed it. `-O2 -Wp,-U_FORTIFY_SOURCE
  // -Wp,-D_FORTIFY_SOURCE=3` produced `extraArgs: []` and was cleared as
  // `exposure-consistent` against a frontier measured under plain `-O2` — while
  // the ladder separates those two builds on six rungs. The token begins `-W`
  // and fell past every joined prefix. A build hiding its fortification in a
  // passthrough is the same build; only its spelling differs.
  const viaWp = exposureArgs(normalise(
    ['-c', 'a.c', '-O2', '-Wp,-U_FORTIFY_SOURCE', '-Wp,-D_FORTIFY_SOURCE=3'], { mode: 'c' }));
  assert.deepEqual(viaWp.extraArgs, ['-Wp,-U_FORTIFY_SOURCE', '-Wp,-D_FORTIFY_SOURCE=3']);
  assert.notDeepEqual(viaWp.extraArgs, exposureArgs(normalise(['-c', 'a.c', '-O2'], { mode: 'c' })).extraArgs);

  // `-Xclang` used to be caught only by accident: its payload is a separate
  // token, so `-Xpreprocessor -D_FORTIFY_SOURCE=3` matched the `-D` prefix on
  // its own while `-Xclang -disable-llvm-passes` matched nothing and vanished.
  // A flag that hands the next token to a stage this driver does not model
  // cannot be judged by that token's spelling.
  assert.deepEqual(
    exposureArgs(normalise(['-c', 'a.c', '-O2', '-Xclang', '-disable-llvm-passes'], { mode: 'c' })).extraArgs,
    ['-Xclang', '-disable-llvm-passes'],
  );

  // `-Wl,` stays out. The linker runs after every checkpoint the specimen is
  // read at, so carrying it would refuse builds over a stage the ladder never
  // looked at — the assertion above in the previous test depends on this.
  assert.deepEqual(
    exposureArgs(normalise(['-c', 'a.c', '-O2', '-Wl,-z,now'], { mode: 'c' })).extraArgs, [],
  );
});

test('a frontier measured at another opt level does not clear this build', (t) => {
  // THE FAILURE THIS EXISTS TO CLOSE. Both documents are well formed, both
  // verify, and the four rungs agree — the frontier is simply a reading of
  // another command line, and without the binding check that reads as a pass.
  const root = withRoot(t, { measured: frontierDoc({ exposure: { extraArgs: [], id: 'O3', opt: '-O3' } }) });
  const r = evaluateFallback(ctx(root, GUARDED));

  assert.equal(r.record.reason, 'fallback-exposure-frontier-for-different-invocation');
  assert.match(r.findings[0].detail, /measured under `-O3` and this build compiles `-O2`/);
  assert.deepEqual(r.record.exposureCheck.exposure.frontier, { extraArgs: [], opt: '-O3' });
  assert.deepEqual(r.record.exposureCheck.exposure.build, { extraArgs: [], opt: '-O2' });
});

test('a frontier measured before the flags moved does not clear the build that moved them', (t) => {
  // The six-axis key cannot see `_FORTIFY_SOURCE`; that is why the ladder is
  // here at all. What the ladder cannot see is that it was run six weeks ago.
  const argv = ['-c', 'guard.c', '-O2', '-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3'];
  const root = withRoot(t);
  const r = evaluateFallback(ctx(root, GUARDED, { compilerArgv: argv, normalised: normalise(argv, { mode: 'c' }) }));

  assert.equal(r.record.reason, 'fallback-exposure-frontier-for-different-invocation');
  assert.match(r.findings[0].detail, /-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3/);

  // And the frontier taken under those flags does clear it, so the refusal
  // above is the binding check and not a guard that refuses everything.
  const matched = withRoot(t, {
    measured: frontierDoc({ exposure: { extraArgs: ['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3'], id: 'F3', opt: '-O2' } }),
  });
  const ok = evaluateFallback(ctx(matched, GUARDED, { compilerArgv: argv, normalised: normalise(argv, { mode: 'c' }) }));
  assert.equal(ok.record.reason, 'no-observer');
  assert.equal(ok.record.exposureCheck.result, 'exposure-consistent');
});

test('the runner\'s tilde rule is applied before the two command lines are compared', (t) => {
  // `run-ladder.sh:83` tilde-shortens before it writes the manifest, so the
  // document's side arrives sanitised. Comparing a sanitised token against a raw
  // one would refuse every build whose line names anything under $HOME.
  const home = join('C:', 'Users', 'ladder-home');
  const argv = ['-c', 'guard.c', '-O2', `--sysroot=${home}/sysroots/arm`];
  const root = withRoot(t, {
    measured: frontierDoc({ exposure: { extraArgs: ['--sysroot=~/sysroots/arm'], id: 'S', opt: '-O2' } }),
  });
  const r = checkExposure({
    cwd: root,
    frontiersPath: 'frontiers.json',
    home,
    measuredPath: 'measured.json',
    normalised: normalise(argv, { mode: 'c' }),
    root,
    rows: [row()],
  });
  assert.equal(r.ok, true, r.detail);

  // Sanitising is for the comparison; what reaches the record goes through
  // `relativiseToken` as well, because §5 admits neither an absolute path nor a
  // machine's home directory.
  assert.deepEqual(findAbsolutePaths(r.record), []);
});

test('the health invariants are read on the path that clears a build, by name', (t) => {
  // `check-ladder.py` refuses a document whose invariants are false and the
  // driver never invokes `check-ladder.py`. A guard that only holds when someone
  // remembers to run a second tool is not a guard.
  const root = withRoot(t, {
    measured: frontierDoc({ health: { broken: false, chainMonotone: true, spellingExclusive: false, twinsHeld: false } }),
  });
  const r = evaluateFallback(ctx(root, GUARDED));

  assert.equal(r.record.reason, 'fallback-exposure-incomparable');
  assert.match(r.findings[0].detail, /declares spellingExclusive and twinsHeld false/);
  // An invariant nobody stated is not an invariant somebody stated false.
  const silent = withRoot(t, { measured: frontierDoc({ health: { broken: false } }) });
  assert.equal(evaluateFallback(ctx(silent, GUARDED)).record.reason, 'no-observer');
});

test('a sidecar entry filed under a key that is not its own config is refused', (t) => {
  // The lookup is by the stated key and nothing downstream ever looks at the two
  // together, so an entry re-filed under another configuration's key is found by
  // that configuration's build and compared against a reading of somewhere else.
  const root = withRoot(t, {
    frontiers: sidecarDoc([entryFor(HOST_O2, { configKey: configKey({ ...HOST_O2, opt: '-O3' }) })]),
  });
  const r = evaluateFallback(ctx(root, GUARDED));
  assert.equal(r.record.reason, 'fallback-exposure-sidecar-digest-mismatch');
  assert.match(r.findings[0].detail, /whose own config keys to/);
});

test('a sidecar that carries a digest has it checked, and one that does not is still read', (t) => {
  // ★ `derive-frontier-sidecar.mjs` now seals its output (2026-08-18), and this
  // check fired without an edit here, exactly as the comment that used to sit in
  // this place predicted. The prediction is worth keeping as a record: the
  // verifying side was written and tested while the producing side still emitted
  // nothing to verify, and the reason it was written first is stated in
  // `fallback.mjs` — "an unverified digest that a reader assumes was verified is
  // worse than an absent one".
  //
  // What this test now covers is therefore TWO different things, and the second
  // one is no longer about the deriver:
  //
  //   * a sealed sidecar has its digest checked, and a tampered one is refused;
  //   * a sidecar with NO digest is still READ rather than refused — which from
  //     today is a statement about BACKWARDS COMPATIBILITY with sidecars derived
  //     before the seal existed, not a statement about what this project writes.
  //     Those documents exist on disk in the lab and are not being reissued, so
  //     refusing them outright would delete readings rather than check them.
  //
  // The assertion below pins the first half against the real producer, so that
  // "the deriver seals" cannot silently stop being true.
  const built = deriveSidecar([{ id: 'O2', doc: frontierDoc() }]);
  assert.equal(built.exitCode, 0, `the deriver refused the fixture: ${built.problems.join('; ')}`);
  assert.match(
    String(built.sidecar.evidenceDigest),
    /^[0-9a-f]{64}$/,
    'the deriver seals its output, so the digest branch above is reachable in production and not only from fixtures',
  );

  const sealed = seal(sidecarDoc([entryFor(HOST_O2)]));
  const good = withRoot(t, { frontiers: sealed });
  assert.equal(evaluateFallback(ctx(good, GUARDED)).record.reason, 'no-observer');

  const tampered = withRoot(t, { frontiers: { ...sealed, anomalies: ['a line somebody added afterwards'] } });
  const r = evaluateFallback(ctx(tampered, GUARDED));
  assert.equal(r.record.reason, 'fallback-exposure-sidecar-digest-mismatch');
  assert.match(r.findings[0].detail, /are not the bytes that were sealed/);
});

// ---------------------------------------------------------------------------
// Toolchain drift, at no extra compilation cost
// ---------------------------------------------------------------------------

test('parseObservation reads the observation\'s compiler, and absence is not agreement', () => {
  const base = {
    observationVersion: 'observation-v0',
    properties: [{
      control: { state: 'PRESENT', unit: 'ctl' }, finalState: 'PRESENT', historyComplete: true, id: PROP, kind: 'must-survive',
    }],
  };
  assert.equal(parseObservation(JSON.stringify(base)).clang, null);
  assert.equal(parseObservation(JSON.stringify({ ...base, toolchain: { clang: '18.1.3' } })).clang, '18.1.3');
  assert.equal(parseObservation(JSON.stringify({ ...base, toolchain: { clang: '' } })).clang, null);
});

test('the frontier\'s compiler is carried out of the check for the driver to compare', (t) => {
  // The comparison itself belongs to `evaluateFallback`, after the observation
  // build it already runs — so it costs no extra compilation, and it is NOT in
  // `compareFrontiers`, which deliberately compares readings and not labels.
  const root = withRoot(t);
  const r = checkExposure({
    cwd: root,
    frontiersPath: 'frontiers.json',
    measuredPath: 'measured.json',
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    root,
    rows: [row()],
  });
  assert.equal(r.ok, true, r.detail);
  assert.equal(r.clang, '18.1.3');

  const unlabelled = withRoot(t, { measured: frontierDoc({ toolchain: { cc: 'clang-18' } }) });
  assert.equal(checkExposure({
    cwd: unlabelled,
    frontiersPath: 'frontiers.json',
    measuredPath: 'measured.json',
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    root: unlabelled,
    rows: [row()],
  }).clang, null, 'a reading that names no compiler must not be read as naming this one');
});

test('drift between the frontier\'s clang and the build\'s is its own refusal', () => {
  // The word is kept apart from `exposure-mismatch` on purpose: the frontiers
  // compared clean, and what moved was the compiler underneath them. A reader
  // sent to "the frontiers differ" would go and diff two identical files.
  assert.equal(EXPOSURE_REFUSALS['toolchain-drift'], 'fallback-exposure-toolchain-drift');
  assert.ok(!Object.values(EXPOSURE_REFUSALS).includes('fallback-exposure-mismatch-toolchain'));
});

// ---------------------------------------------------------------------------
// The refusals, each with its own name
// ---------------------------------------------------------------------------

const DIFFERING = frontierDoc({ frontier: { ...RUNGS, 'b1-lib': 'ABSENT', 'd1-printf': 'PRESENT' } });

const REFUSALS = [
  {
    name: 'a frontier that differs from the one recorded beside the cell',
    reason: 'fallback-exposure-mismatch',
    setup: { measured: DIFFERING },
    detail: /differs on b1-lib, d1-printf from the frontier the sidecar at frontiers\.json records for/,
  },
  {
    name: 'a measured document whose bytes are not the bytes that were sealed',
    reason: 'fallback-exposure-measurement-digest-mismatch',
    // Sealed, then edited: exactly what a stale frontier "fixed up" by hand to
    // match a build looks like on disk.
    setup: { measured: { ...frontierDoc(), frontier: { ...RUNGS, c1: 'PRESENT' } } },
    detail: /recomputes to [0-9a-f]{12}…/,
  },
  {
    name: 'a measured document carrying no digest at all',
    reason: 'fallback-exposure-measurement-digest-mismatch',
    setup: { measured: (() => { const d = frontierDoc(); delete d.evidenceDigest; return d; })() },
    detail: /carries evidenceDigest null/,
  },
  {
    name: 'a frontier taken under a different command line',
    reason: 'fallback-exposure-frontier-for-different-invocation',
    setup: { measured: frontierDoc({ exposure: { extraArgs: ['-ffast-math'], id: 'FM', opt: '-O2' } }) },
    detail: /measured under `-O2 -ffast-math` and this build compiles `-O2`/,
  },
  {
    name: 'a frontier that cannot say which command line it read',
    reason: 'fallback-exposure-measurement-unreadable',
    setup: { measured: frontierDoc({ exposure: { id: 'O2' } }) },
    detail: /states no readable exposure\.opt and exposure\.extraArgs/,
  },
  {
    name: 'a measured document that declares a health invariant false',
    reason: 'fallback-exposure-incomparable',
    setup: { measured: frontierDoc({ health: { broken: false, twinsHeld: false } }) },
    detail: /declares twinsHeld false/,
  },
  {
    name: 'a sidecar entry whose stated key is not the key of its own config',
    reason: 'fallback-exposure-sidecar-digest-mismatch',
    setup: { frontiers: sidecarDoc([entryFor(HOST_O2, { configKey: '{"cc":"clang-19"}' })]) },
    detail: /whose own config keys to/,
  },
  {
    name: 'two readings taken of different specimens',
    reason: 'fallback-exposure-incomparable',
    setup: { measured: frontierDoc({ ladder: { generatorVersion: '1', sourceSha256: 'b'.repeat(64) } }) },
    detail: /ladder\.sourceSha256 differs/,
  },
  {
    name: 'two readings graded by different generators',
    reason: 'fallback-exposure-incomparable',
    setup: { measured: frontierDoc({ ladder: { generatorVersion: '2', sourceSha256: LADDER_SHA } }) },
    detail: /ladder\.generatorVersion differs/,
  },
  {
    name: 'a reading that declares its own measurement broken',
    reason: 'fallback-exposure-incomparable',
    setup: { measured: frontierDoc({ health: { broken: true, reason: 'broken-measurement' } }) },
    detail: /health\.broken is true on this build/,
  },
  {
    name: 'a cell the deriver wrote out unusable because two builds collided on its key',
    reason: 'fallback-exposure-incomparable',
    setup: {
      frontiers: sidecarDoc([entryFor(HOST_O2, {
        frontier: null,
        health: { broken: true, reason: 'config-key-collision' },
        ladder: null,
        usable: false,
        unusableReason: 'config-key-collision',
      })]),
    },
    detail: /health\.broken is true on the recorded cell \(config-key-collision\)/,
  },
  {
    name: 'a rung neither side successfully measured',
    reason: 'fallback-exposure-incomparable',
    setup: { measured: frontierDoc({ frontier: { ...RUNGS, c1: 'BROKEN' } }) },
    detail: /were not successfully measured on one or both sides \(c1\)/,
  },
  {
    name: 'a sidecar with no frontier for the cell being quoted',
    reason: 'fallback-exposure-incomparable',
    setup: { frontiers: sidecarDoc([entryFor({ ...HOST_O2, opt: '-O3' })]) },
    detail: /records no frontier for cc=clang-18/,
  },
  {
    name: 'no frontier measured for this build at all',
    reason: 'fallback-exposure-unmeasured',
    setup: {},
    ctx: { exposureFrontier: null },
    detail: /an unanswered guard is not a passed one/,
  },
  {
    name: 'a measured frontier that is not on disk',
    reason: 'fallback-exposure-measurement-unreadable',
    setup: { measured: null },
    detail: /could not be read \(ENOENT\)/,
  },
  {
    name: 'a measured frontier that cannot say which specimen it read',
    reason: 'fallback-exposure-measurement-unreadable',
    setup: { measured: frontierDoc({ ladder: { generatorVersion: '1', sourceSha256: 'not-a-digest' } }) },
    detail: /ladder\.sourceSha256 must be 64 lowercase hex/,
  },
  {
    name: 'a measured frontier that never says whether its run was usable',
    reason: 'fallback-exposure-measurement-unreadable',
    setup: { measured: frontierDoc({ health: {} }) },
    detail: /health\.broken must be a boolean/,
  },
  {
    name: 'a sidecar the policy names and the disk does not have',
    reason: 'fallback-exposure-sidecar-unreadable',
    setup: { frontiers: null },
    detail: /could not be read \(ENOENT\)/,
  },
  {
    name: 'a sidecar that is not JSON',
    reason: 'fallback-exposure-sidecar-unreadable',
    setup: { text: { frontiers: 'derive-frontier-sidecar: exit 3\n' } },
    detail: /is not JSON/,
  },
  {
    name: 'a sidecar written to a schema this driver does not read',
    reason: 'fallback-exposure-sidecar-unreadable',
    setup: { frontiers: sidecarDoc([entryFor(HOST_O2)], { schemaVersion: 'vibeguard.ladder-frontiers/2' }) },
    detail: /schemaVersion is "vibeguard\.ladder-frontiers\/2"/,
  },
  {
    name: 'a sidecar with the failure direction stripped out of it',
    reason: 'fallback-exposure-sidecar-unreadable',
    setup: { frontiers: sidecarDoc([entryFor(HOST_O2)], { instrument: { use: 'guard-only' } }) },
    detail: /states no instrument\.failureDirection/,
  },
  {
    name: 'a sidecar entry that is not a frontier document',
    reason: 'fallback-exposure-sidecar-unreadable',
    setup: { frontiers: sidecarDoc([entryFor(HOST_O2, { frontier: {} })]) },
    detail: /is malformed/,
  },
];

for (const c of REFUSALS) {
  test(`the exposure guard refuses, by name, for ${c.name}`, (t) => {
    const root = withRoot(t, c.setup);
    const r = evaluateFallback(ctx(root, GUARDED, c.ctx ?? {}));

    assert.equal(r.record.reason, c.reason);
    assert.equal(r.record.status, 'unsupported');
    assert.equal(r.record.verdict, 'unsupported');
    // interfaces.md §7: could-not-look is never a pass. `complete: false` is
    // what turns this into exit 3 rather than a quiet exit 0.
    assert.equal(r.complete, false);
    assert.equal(r.record.complete, false);
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].id, 'VG-CFG-022');
    assert.match(r.findings[0].detail, c.detail);

    // The refusal carries its own evidence, and the row that was about to be
    // quoted is still in the record: the reason a run stopped is not improved
    // by dropping what it stopped over.
    assert.equal(EXPOSURE_REFUSALS[r.record.exposureCheck.result], c.reason);
    assert.equal(r.record.profileResolution.rows.length, 1);

    // interfaces.md §5: nothing this path writes may carry an absolute path,
    // and these details all quote files the driver just resolved.
    assert.deepEqual(findAbsolutePaths(r.record), []);
    assert.deepEqual(findAbsolutePaths(r.findings), []);
  });
}

test('every way of refusing has its own name, and none of them is the pass', () => {
  // A guard whose refusals collapse into one word sends every reader to the same
  // wrong place, and a guard whose refusal set is smaller than its check set has
  // a check nobody can act on.
  const named = new Set(REFUSALS.map((c) => c.reason));
  named.add(EXPOSURE_REFUSALS['toolchain-drift']);
  assert.deepEqual([...named].sort(), Object.values(EXPOSURE_REFUSALS).sort());
});

test('the differing rungs are named, in the finding and in the record', (t) => {
  const root = withRoot(t, { measured: DIFFERING });
  const r = evaluateFallback(ctx(root, GUARDED));

  assert.equal(r.record.reason, 'fallback-exposure-mismatch');
  assert.deepEqual(r.record.exposureCheck.differingRungs, ['b1-lib', 'd1-printf']);
  assert.deepEqual(r.record.exposureCheck.config, HOST_O2);
  assert.equal(r.record.exposureCheck.frontierDigest, digestOf(root, 'measured.json'));
  // Which rungs separated the two builds is the whole content of the finding.
  // "the frontiers differ" without them sends a reader to diff two files by eye.
  assert.match(r.findings[0].detail, /b1-lib, d1-printf/);
});

test('a comparison that could not be made is never reported as one that found nothing', (t) => {
  // The two words are kept apart on purpose. `exposure-incomparable` means no
  // comparison was made; collapsing it into `exposure-mismatch` would invent a
  // difference, and collapsing it into `exposure-consistent` would invent a
  // clearance. It refuses, under its own name, and says which.
  const root = withRoot(t, { measured: frontierDoc({ ladder: { generatorVersion: '2', sourceSha256: LADDER_SHA } }) });
  const r = evaluateFallback(ctx(root, GUARDED));

  assert.equal(r.record.reason, 'fallback-exposure-incomparable');
  assert.equal(r.record.exposureCheck.result, 'exposure-incomparable');
  assert.notEqual(r.record.exposureCheck.result, 'exposure-mismatch');
  assert.ok(!('differingRungs' in r.record.exposureCheck), 'nothing was differenced, so no rung differed');
  assert.match(r.findings[0].detail, /No comparison was made/);
});

test('mismatch is reported over incomparable when a build hits both', (t) => {
  // Two rows match — a `-m32` line changes the triple without a `-target` on it,
  // so the target axis cannot be read — and the sidecar records a frontier for
  // one of them only. The differing frontier is the stronger claim and is the
  // one reported, for the same reason `no-safe-target` is reported over
  // `not-observed` one level up: it is evidence, and the gap is not.
  const cross = { ...HOST_O2, target: 'i386-unknown-linux-gnu' };
  const root = withRoot(t, {
    frontiers: sidecarDoc([entryFor(HOST_O2, { frontier: { ...RUNGS, c1: 'PRESENT' } })]),
    measured: frontierDoc({ exposure: { extraArgs: ['-m32'], id: 'M32', opt: '-O2' } }),
    rows: [row(), row({ from: cross })],
  });
  const argv = ['-c', 'guard.c', '-O2', '-m32'];
  const r = evaluateFallback(ctx(root, GUARDED, { compilerArgv: argv, normalised: normalise(argv, { mode: 'c' }) }));

  assert.equal(r.record.profileResolution.rows.length, 2, 'both rows must match, or this case is not the one it says it is');
  assert.equal(r.record.reason, 'fallback-exposure-mismatch');
  assert.deepEqual(r.record.exposureCheck.differingRungs, ['c1']);
});

// ---------------------------------------------------------------------------
// What the guard declines to judge
// ---------------------------------------------------------------------------

test('a hand-written level quotes no cell, and the record says the guard did not run', (t) => {
  // `exposure-consistent` would be a lie here and silence would be worse: the
  // policy asked for a guard and no comparison happened, because a level a
  // human wrote is not a measurement whose exposure could be wrong.
  const root = withRoot(t);
  const r = evaluateFallback(ctx(root, { enabled: true, profile: '-O0', exposureFrontiers: 'frontiers.json' }));

  assert.equal(r.record.reason, 'no-observer');
  assert.equal(r.record.exposureCheck.result, 'unchecked');
  assert.match(r.record.exposureCheck.detail, /no cell was quoted/);
  assert.equal(r.record.profileResolution, null);
});

test('the guard is never reached by a run that stopped before a level was resolved', (t) => {
  // It has nothing to say about a build with nothing to rescue, or one that had
  // already stopped: there is no cell in either, and a refusal about exposure
  // would be reported over the top of the reason the run really ended.
  const root = withRoot(t);
  const nothing = evaluateFallback({
    ...ctx(root, GUARDED),
    policy: { ...policyFor(GUARDED), properties: [] },
  });
  assert.equal(nothing.record.reason, 'no-must-survive-property');
  assert.ok(!('exposureCheck' in nothing.record));

  const blocked = evaluateFallback(ctx(root, GUARDED, { blocked: 'findings-at-threshold' }));
  assert.equal(blocked.record.status, 'not-attempted');
  assert.ok(!('exposureCheck' in blocked.record));
});

test('a table that refuses to resolve is still refused for its own reason', (t) => {
  // The exposure guard runs after resolution and must not overtake it. This
  // table has no row for a `-O3` build, and that is what the run reports —
  // with a frontier on disk that would have compared cleanly.
  const root = withRoot(t);
  const argv = ['-c', 'guard.c', '-O3'];
  const r = evaluateFallback(ctx(root, GUARDED, { compilerArgv: argv, normalised: normalise(argv, { mode: 'c' }) }));

  assert.equal(r.record.reason, 'fallback-no-matching-row');
  assert.ok(!('exposureCheck' in r.record), 'a run that quoted no cell must not carry an exposure reading');
});

// ---------------------------------------------------------------------------
// The reader, directly
// ---------------------------------------------------------------------------

test('checkExposure names one refusal per way of failing, and they stay distinct', () => {
  // Nine outcomes, nine names. "The frontiers differ", "they could not be
  // compared", "nobody measured this build", "the file the policy names is not
  // readable", "these are not the bytes that were measured", "this is a reading
  // of another command line" and "another compiler took the reading" call for
  // different pieces of work.
  assert.equal(new Set(Object.values(EXPOSURE_REFUSALS)).size, Object.keys(EXPOSURE_REFUSALS).length);
  for (const reason of Object.values(EXPOSURE_REFUSALS)) {
    assert.match(reason, /^fallback-exposure-/);
  }
  assert.ok(!Object.values(EXPOSURE_REFUSALS).includes('fallback-exposure-failed'));
  // The three words the instrument owns are reported under their own names and
  // are not renamed on the way through this driver.
  for (const word of ['exposure-mismatch', 'exposure-incomparable']) {
    assert.ok(word in EXPOSURE_REFUSALS, `${word} lost its own refusal`);
  }
});

test('checkExposure refuses a row that carries no configuration rather than matching one', (t) => {
  // A row with no `from` cannot be keyed against the sidecar. Matching it
  // against the first entry, or against nothing and calling that consistent,
  // would both be a clearance nobody measured.
  const root = withRoot(t);
  const r = checkExposure({
    cwd: root,
    frontiersPath: 'frontiers.json',
    measuredPath: 'measured.json',
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    root,
    rows: [{ from: null, profile: '-O0', propertyId: PROP, resolution: 'fallback', to: null }],
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'fallback-exposure-incomparable');
  assert.match(r.detail, /no configuration to key the sidecar by/);
});

test('checkExposure handed no rows refuses rather than clearing a comparison it never made', (t) => {
  // `evaluateFallback` only calls this with rows in hand, so this is a guard
  // against another caller — and the assumption it guards lives in another file.
  // Answering `exposure-consistent` for a comparison that never happened is the
  // single worst thing this function could do.
  const root = withRoot(t);
  const r = checkExposure({
    cwd: root,
    frontiersPath: 'frontiers.json',
    measuredPath: 'measured.json',
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    root,
    rows: [],
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'fallback-exposure-incomparable');
  assert.match(r.detail, /A guard that compared nothing has not found nothing/);
});

test('a measured frontier outside the fixture root is named without an absolute path', (t) => {
  // The ladder lab lives outside the repository by design — `run-ladder.sh`
  // writes under `$IRCK_LADDER_LAB`, which defaults into `$HOME`. Relativising
  // that against the root gives a `../..` chain, or a bare absolute path across
  // drives, and §5 forbids the second outright inside a sealed record.
  const root = withRoot(t);
  const lab = mkdtempSync(join(tmpdir(), 'vg-fb-lab-'));
  t.after(() => rmSync(lab, { force: true, recursive: true }));
  writeFileSync(join(lab, 'O2.json'), JSON.stringify(frontierDoc({ frontier: { ...RUNGS, c1: 'PRESENT' } }), null, 2));

  const r = checkExposure({
    cwd: lab,
    frontiersPath: 'frontiers.json',
    measuredPath: 'O2.json',
    normalised: normalise(['-c', 'guard.c', '-O2'], { mode: 'c' }),
    root,
    rows: [row()],
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'fallback-exposure-mismatch');
  assert.deepEqual(findAbsolutePaths(r.record), []);
  assert.deepEqual(findAbsolutePaths([r.detail]), []);
  assert.ok(!r.detail.includes('..'), 'a `../..` chain names the shape of the machine above the root');
});
