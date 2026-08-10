// Tests for the H2 self-hardening gate (scripts/sec-selftest.mjs).
//
// WHAT THIS FILE IS FOR, AND WHY IT IS NOT OPTIONAL
//
// sec-selftest.mjs is a gate. A gate that cannot fail is worse than no gate: it
// consumes a CI job, prints a green line, and licenses everyone downstream to
// believe the attack surface was checked. Every assertion below is about the
// FAILURE direction — the gate must go red, with a non-zero exit code and the
// offending gate NAMED, for each way the self-test can be hollowed out:
//
//   - the baseline file is gone            → red, not skipped
//   - the generated corpus is empty        → red (an empty corpus makes every
//                                            rate vacuously 0 and every ceiling
//                                            green)
//   - a threshold is impossible to meet    → red, naming the gate
//   - a pinned finding stops being found   → red, naming the finding
//   - the baseline promises a measurement
//     that was not made                    → red
//   - a gate is silently removed / a new
//     gate has no baseline entry           → red
//
// and then three NEGATIVE CONTROLS in the other direction, because "it fired"
// is only half of a working detector. A gate that fires on a healthy tree, on
// slack thresholds, or on a cosmetically different baseline is a gate that gets
// switched off within a month, and then none of the above matters.
//
// WHY CHILD PROCESSES
//
// Same reason as scripts/packaging-invariants.test.ts: the thing under test is
// the EXIT CODE an operator and CI see, plus the report they read to act on it.
// `sec-selftest.mjs` also sets `process.exitCode` at top level, so importing it
// as a program would entangle the Vitest worker's own exit status with the
// subject's. The pure functions it exports (`loadBaseline`, `evaluateGates`) are
// imported directly, and that split is deliberate: it is what lets the numeric
// threshold logic be tested exhaustively without paying for corpus generation.
//
// ⚠ COVERAGE LIMIT, STATED RATHER THAN HIDDEN. The subprocess tests drive the
// `corpus`, `a1` and `b3` arms only. The `b1` arm regenerates a 416-file evasion
// corpus and takes ~26 s, which does not belong in the unit suite; its gate
// logic is covered by the `evaluateGates` unit tests below instead. The gap is
// closed at the other end by `ci.yml runs every arm`, which asserts the CI job
// does not pass `--arms` and therefore exercises all four. If that assertion is
// ever deleted, b1 stops being end-to-end tested anywhere and nothing else would
// say so.
//
// ⚠ SIDE EFFECTS. Running the `a1` and `b3` arms writes deterministic artefacts
// under `security-experiment/_results/` (the regex catalogue, the B3 corpus and
// its manifest) — the same bytes a normal selftest run produces, in a gitignored
// tree. The gated `manifest.json` is redirected to a temp directory by every
// test here so a test run cannot leave a partial record behind as if it were a
// real one.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ARMS, evaluateGates, loadBaseline } from './sec-selftest.mjs';

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPTS_DIR, '..');
const SELFTEST = join(SCRIPTS_DIR, 'sec-selftest.mjs');
const BASELINE = join(SCRIPTS_DIR, 'sec-selftest-baseline.json');
const CI_YML = join(REPO_ROOT, '.github', 'workflows', 'ci.yml');

// Arms that regenerate what they measure from TRACKED inputs and finish in about
// a second. `b1` is excluded on purpose — see the coverage limit above.
const FAST_ARMS = 'corpus,a1,b3';
const TIMEOUT = 120_000;

let tmp: string;

beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'vg-h2-selftest-'));
});
afterAll(() => {
  rmSync(tmp, { recursive: true, force: true });
});

type Run = { status: number | null; stdout: string; stderr: string; all: string };

function runSelftest(args: string[]): Run {
  const r = spawnSync(process.execPath, [SELFTEST, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const stdout = r.stdout ?? '';
  const stderr = r.stderr ?? '';
  return { status: r.status, stdout, stderr, all: `${stdout}\n${stderr}` };
}

/** A run with its own scratch manifest path, so no test can clobber the real record. */
function runArms(args: string[], name: string): Run {
  return runSelftest([...args, '--manifest-out', join(tmp, `${name}.json`)]);
}

function readBaseline(): any {
  return JSON.parse(readFileSync(BASELINE, 'utf8'));
}

/** Write a mutated copy of the tracked baseline and return its path. */
function withBaseline(name: string, mutate: (b: any) => void): string {
  const b = readBaseline();
  mutate(b);
  const p = join(tmp, `${name}.json`);
  writeFileSync(p, `${JSON.stringify(b, null, 2)}\n`, 'utf8');
  return p;
}

// ---------------------------------------------------------------------------
// Negative controls — the gate must stay SILENT
// ---------------------------------------------------------------------------
describe('negative controls (the gate must not fire)', () => {
  // N1 — the plain one. Healthy tree, tracked baseline, nothing touched.
  it(
    'silent on a healthy tree with the tracked baseline',
    () => {
      const r = runArms(['--arms', FAST_ARMS], 'n1');
      expect(r.status, `expected exit 0, got ${r.status}:\n${r.all}`).toBe(0);
      expect(r.stdout).toMatch(/·\s0 failed/);
      expect(r.stdout).not.toContain('FAILED GATES');
    },
    TIMEOUT,
  );

  // N2 — slack. Every numeric threshold moved in the SAFE direction. If the gate
  // still went red here it would mean the ceilings are accidental equality
  // checks rather than comparisons, i.e. any movement at all fails and the
  // thresholds are decoration.
  it(
    'silent when every numeric threshold is loosened in the safe direction',
    () => {
      const path = withBaseline('n2-slack', (b) => {
        b.gates['b3:cr-gated-ceiling'].maxCrGated = 0.9;
        b.gates['b3:cr-gated-ceiling'].minDenominator = 1;
        b.gates['b3:undeclared-cr-ceiling'].maxCrGated = 0.9;
        b.gates['b3:undeclared-cr-ceiling'].minDenominator = 1;
        b.gates['b3:d1-reduction-floor'].minReduction = 0;
        b.gates['b3:harness-integrity'].expected.minPairingAgreement = 0.5;
      });
      const r = runArms(['--arms', 'b3', '--baseline', path], 'n2');
      expect(r.status, `expected exit 0, got ${r.status}:\n${r.all}`).toBe(0);
      expect(r.stdout).not.toContain('FAILED GATES');
    },
    TIMEOUT,
  );

  // N3 — representation. Same contract, different bytes: top-level and per-gate
  // keys reordered, extra annotation keys added. The comparison must read the
  // declared fields, not the shape of the file.
  it(
    'silent when the baseline is rewritten with reordered and annotated keys',
    () => {
      const original = readBaseline();
      const reordered: Record<string, unknown> = {};
      // Reverse the gate order, and give every gate an extra annotation key.
      const gates: Record<string, unknown> = {};
      for (const id of Object.keys(original.gates).reverse()) {
        const g = original.gates[id];
        const flipped: Record<string, unknown> = { _extraAnnotation: 'ignored by the harness' };
        for (const k of Object.keys(g).reverse()) flipped[k] = g[k];
        gates[id] = flipped;
      }
      for (const k of Object.keys(original).reverse()) reordered[k] = original[k];
      reordered.gates = gates;
      reordered.$note = 'cosmetic rewrite; the contract is unchanged';
      const path = join(tmp, 'n3-cosmetic.json');
      writeFileSync(path, `${JSON.stringify(reordered, null, 2)}\n`, 'utf8');

      const r = runArms(['--arms', FAST_ARMS, '--baseline', path], 'n3');
      expect(r.status, `expected exit 0, got ${r.status}:\n${r.all}`).toBe(0);
      expect(r.stdout).not.toContain('FAILED GATES');
    },
    TIMEOUT,
  );
});

// ---------------------------------------------------------------------------
// Positive controls — the gate must fire, non-zero, by name
// ---------------------------------------------------------------------------
describe('the gate fails loud', () => {
  it(
    'a missing baseline is a non-zero exit, not a skip',
    () => {
      const r = runArms(['--arms', 'corpus', '--baseline', join(tmp, 'does-not-exist.json')], 'p1');
      expect(r.status).not.toBe(0);
      expect(r.all).toContain('baseline not found');
      // The message has to say WHY a missing baseline is not a skip, or the next
      // person to hit it will add a skip.
      expect(r.all).toContain('not a skip');
      // And it must not have written a record that looks like a completed run.
      expect(existsSync(join(tmp, 'p1.json'))).toBe(false);
    },
    TIMEOUT,
  );

  it(
    'an empty generated corpus fails instead of passing with a vacuous rate',
    () => {
      // A manifest that parses, declares zero pairs, and would make every CR
      // computed from it either null or 0. This is the exact accident the scale
      // pin exists for: a generator that silently stops producing.
      const empty = join(tmp, 'b3-empty-manifest.json');
      writeFileSync(empty, `${JSON.stringify({ generatedBy: 'test', pairs: [], transforms: [] }, null, 2)}\n`, 'utf8');
      const r = runArms(['--arms', 'b3', '--b3-manifest', empty], 'p2');
      expect(r.status, `expected a non-zero exit, got ${r.status}:\n${r.all}`).not.toBe(0);
      expect(r.stdout).toContain('FAILED GATES');
      expect(r.stdout).toContain('b3:corpus-scale');
      // The report must say what an empty corpus does to the measurement, so the
      // failure is not read as "the pin is too strict, bump it".
      expect(r.stdout).toContain('vacuous');
    },
    TIMEOUT,
  );

  it(
    'an impossible threshold fails and names the gate that failed',
    () => {
      const path = withBaseline('p3-impossible', (b) => {
        // A concealment rate can never be below zero, so this can only fail.
        b.gates['b3:cr-gated-ceiling'].maxCrGated = -1;
      });
      const r = runArms(['--arms', 'b3', '--baseline', path], 'p3');
      expect(r.status, `expected a non-zero exit, got ${r.status}:\n${r.all}`).not.toBe(0);
      expect(r.stdout).toContain('FAILED GATES: b3:cr-gated-ceiling');
      expect(r.stdout).toMatch(/FAIL\s+b3:cr-gated-ceiling/);
      // Naming the gate is not enough on its own — the operator needs the two
      // numbers to decide whether this is a regression or a deliberate change.
      expect(r.stdout).toContain('expected: <= -1');
    },
    TIMEOUT,
  );

  it(
    'a pinned finding that stops being reported fails and names the finding',
    () => {
      const path = withBaseline('p4-lost-finding', (b) => {
        // Simulate the regression the multiset snapshot exists to catch: the
        // baseline says this finding should be there and the product no longer
        // reports it. (Injecting a key the product never produces is the same
        // comparison as a real rule going silent, without editing samples/.)
        b.gates['corpus:samples/vulnerable'].snapshot.push('VG-INJ-001@a_file_that_does_not_exist.py');
        b.gates['corpus:samples/vulnerable'].snapshot.sort();
      });
      const r = runArms(['--arms', 'corpus', '--baseline', path], 'p4');
      expect(r.status).not.toBe(0);
      expect(r.stdout).toContain('FAILED GATES: corpus:samples/vulnerable');
      expect(r.stdout).toContain('disappeared: VG-INJ-001@a_file_that_does_not_exist.py');
    },
    TIMEOUT,
  );

  it(
    'a baseline that promises a recheck measurement fails when recheck is absent',
    () => {
      const path = withBaseline('p5-promised', (b) => {
        b.gates['a1:recheck-superlinear'].measured = true;
        b.gates['a1:recheck-superlinear'].superLinearRuleIds = [];
        b.optionalGates = [];
      });
      const r = runArms(['--arms', 'a1', '--baseline', path], 'p5');
      // recheck is not a devDependency (JVM jar); if a future environment does
      // install it, this assertion is the thing that says so out loud rather
      // than the test silently changing meaning.
      const recheckInstalled = r.stdout.includes('PASS        a1:recheck-superlinear');
      expect(
        recheckInstalled,
        'recheck appears to be installed in this environment — re-record the baseline with a real ' +
          'recheck measurement and rewrite this test; it can no longer prove what it claims',
      ).toBe(false);
      expect(r.status).not.toBe(0);
      expect(r.stdout).toContain('FAILED GATES: a1:recheck-superlinear');
      expect(r.stdout).toContain('promises a measurement this run did not make');
    },
    TIMEOUT,
  );

  it(
    'a gate the baseline declares but the harness never evaluates is a failure',
    () => {
      const path = withBaseline('p6-missing-verdict', (b) => {
        b.gates['corpus:samples/a-corpus-nobody-scans'] = { snapshot: [] };
      });
      const r = runArms(['--arms', 'corpus', '--baseline', path], 'p6');
      expect(r.status).not.toBe(0);
      expect(r.stdout).toContain('corpus:samples/a-corpus-nobody-scans');
      expect(r.stdout).toContain('produced no verdict');
    },
    TIMEOUT,
  );

  it(
    'an observation with no baseline entry is a failure, not an ungoverned pass',
    () => {
      const path = withBaseline('p7-ungoverned', (b) => {
        delete b.gates['corpus:samples/safe'];
        b.optionalGates = (b.optionalGates ?? []).filter((id: string) => id !== 'corpus:samples/safe');
      });
      const r = runArms(['--arms', 'corpus', '--baseline', path], 'p7');
      expect(r.status).not.toBe(0);
      expect(r.stdout).toContain('FAILED GATES: corpus:samples/safe');
      expect(r.stdout).toContain('baseline is out of date');
    },
    TIMEOUT,
  );
});

// ---------------------------------------------------------------------------
// loadBaseline — every degenerate contract is refused, loudly
// ---------------------------------------------------------------------------
describe('loadBaseline refuses a contract that cannot gate anything', () => {
  const write = (name: string, body: unknown) => {
    const p = join(tmp, `${name}.json`);
    writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
    return p;
  };

  it('throws on a missing file rather than returning an empty contract', () => {
    expect(() => loadBaseline(join(tmp, 'nope.json'))).toThrow(/baseline not found/);
  });

  it('throws on malformed JSON', () => {
    expect(() => loadBaseline(write('bad-json', '{ not json'))).toThrow(/not valid JSON/);
  });

  it('throws when there is no gates object', () => {
    expect(() => loadBaseline(write('no-gates', { recordedAt: 'x' }))).toThrow(/no "gates" object/);
  });

  // The one that matters most: `{"gates": {}}` is valid JSON, has the right
  // shape, and passes everything forever.
  it('throws on zero declared gates — an empty contract passes everything', () => {
    expect(() => loadBaseline(write('zero-gates', { gates: {} }))).toThrow(/declares 0 gates/);
  });

  it('throws when a gate names an arm the harness does not run', () => {
    expect(() => loadBaseline(write('bad-arm', { gates: { 'b9:whatever': {} } }))).toThrow(
      /does not run/,
    );
  });

  it('throws when optionalGates names a gate that does not exist', () => {
    expect(() =>
      loadBaseline(write('bad-optional', { gates: { 'a1:surface-census': {} }, optionalGates: ['a1:ghost'] })),
    ).toThrow(/not a declared gate/);
  });

  it('accepts the tracked baseline', () => {
    const b = loadBaseline(BASELINE);
    expect(Object.keys(b.gates).length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// evaluateGates — pure. This is where the b1 numeric logic is covered, and where
// the vacuous-pass guards are pinned without paying for corpus generation.
// ---------------------------------------------------------------------------
describe('evaluateGates', () => {
  // A minimal, fully-passing b1 observation + baseline pair. Every test below
  // starts from this and breaks exactly one thing, so a failure names the cause.
  const healthyB1 = () => ({
    b1: {
      scale: { sourceFiles: 14, pairs: 416, transformedFiles: 416, transforms: 19, corpusFiles: 416 },
      metrics: {
        erFalse: 0.24,
        erTrue: 0.19,
        deltaEr: 0.05,
        denominatorFalse: 237,
        denominatorTrue: 237,
      },
      integrity: { censusAllAgree: true, assertionsAllOk: true },
      gen: { ok: true },
      evalRun: { ok: true },
    },
  });
  const healthyBaseline = () => ({
    gates: {
      'b1:corpus-scale': {
        expected: { sourceFiles: 14, pairs: 416, transformedFiles: 416, transforms: 19, corpusFiles: 416 },
      },
      'b1:er-true-ceiling': { maxEr: 0.19, minDenominator: 237 },
      'b1:er-false-ceiling': { maxEr: 0.24, minDenominator: 237 },
      'b1:delta-er-floor': { minDeltaEr: 0.05 },
      'b1:harness-integrity': { expected: { censusAllAgree: true, assertionsAllOk: true } },
    },
    optionalGates: [],
  });
  const verdictOf = (gates: Array<{ id: string; verdict: string }>, id: string) =>
    gates.find((g) => g.id === id)?.verdict;

  it('passes on the healthy pair (so the failures below mean something)', () => {
    const r = evaluateGates(healthyB1(), healthyBaseline(), ['b1']);
    expect(r.summary.failed, JSON.stringify(r.summary.failedGateIds)).toBe(0);
    expect(r.summary.ok).toBe(true);
    expect(r.summary.allGatesPassed).toBe(true);
  });

  it('fails the ER ceiling when the shipped engine gets easier to evade', () => {
    const o = healthyB1();
    o.b1.metrics.erTrue = 0.2;
    const r = evaluateGates(o, healthyBaseline(), ['b1']);
    expect(verdictOf(r.gates, 'b1:er-true-ceiling')).toBe('fail');
    expect(r.summary.ok).toBe(false);
  });

  // The gate D2's removal would slip past: turning the pre-pass off leaves both
  // arms at the control's rate, so both CEILINGS are satisfied and only the
  // delta floor moves.
  it('fails the delta floor when D2 stops covering evasion, with both ceilings still satisfied', () => {
    const o = healthyB1();
    o.b1.metrics.erTrue = o.b1.metrics.erFalse; // D2 disabled: shipped == control
    o.b1.metrics.deltaEr = 0;
    const b = healthyBaseline();
    b.gates['b1:er-true-ceiling'].maxEr = 0.24; // ceiling deliberately loose enough to pass
    const r = evaluateGates(o, b, ['b1']);
    expect(verdictOf(r.gates, 'b1:er-true-ceiling')).toBe('pass');
    expect(verdictOf(r.gates, 'b1:delta-er-floor')).toBe('fail');
    expect(r.summary.ok).toBe(false);
  });

  it('fails an ER gate whose denominator collapsed even when the rate itself looks fine', () => {
    const o = healthyB1();
    o.b1.metrics.denominatorTrue = 3;
    o.b1.metrics.erTrue = 0;
    const r = evaluateGates(o, healthyBaseline(), ['b1']);
    expect(verdictOf(r.gates, 'b1:er-true-ceiling')).toBe('fail');
  });

  it('fails an ER gate whose rate is null instead of treating null as 0', () => {
    const o = healthyB1();
    (o.b1.metrics as Record<string, unknown>).erTrue = null;
    const r = evaluateGates(o, healthyBaseline(), ['b1']);
    expect(verdictOf(r.gates, 'b1:er-true-ceiling')).toBe('fail');
  });

  it('fails the scale pin on an empty corpus (the vacuous-rate accident)', () => {
    const o = healthyB1();
    o.b1.scale = { sourceFiles: 0, pairs: 0, transformedFiles: 0, transforms: 19, corpusFiles: 0 };
    const r = evaluateGates(o, healthyBaseline(), ['b1']);
    expect(verdictOf(r.gates, 'b1:corpus-scale')).toBe('fail');
  });

  // The bug this guard was written for, kept as a test: comparing only the
  // baseline's keys meant `{"expected": {}}` checked nothing and reported PASS.
  it('fails an empty baseline record instead of passing it vacuously', () => {
    const b = healthyBaseline();
    b.gates['b1:harness-integrity'].expected = {};
    const r = evaluateGates(healthyB1(), b, ['b1']);
    expect(verdictOf(r.gates, 'b1:harness-integrity')).toBe('fail');
  });

  it('fails when an observed field has no expectation in the baseline', () => {
    const o = healthyB1();
    (o.b1.integrity as Record<string, unknown>).aBrandNewIntegrityFlag = false;
    const r = evaluateGates(o, healthyBaseline(), ['b1']);
    expect(verdictOf(r.gates, 'b1:harness-integrity')).toBe('fail');
  });

  it('fails when the whole arm produced nothing, rather than skipping it', () => {
    const r = evaluateGates(
      { b1: { scale: null, metrics: null, integrity: null, gen: { ok: false, spawnError: 'boom' }, evalRun: { ok: false } } },
      healthyBaseline(),
      ['b1'],
    );
    expect(r.summary.failed).toBe(5);
    expect(r.summary.ok).toBe(false);
  });

  // Gates for arms that did not run are neither passed nor failed — but the run
  // is then not authoritative, which is why the CI job runs every arm.
  it('does not evaluate gates for arms that were not selected', () => {
    const r = evaluateGates(healthyB1(), healthyBaseline(), ['corpus']);
    expect(r.gates.filter((g: { arm: string }) => g.arm === 'b1')).toHaveLength(0);
  });

  it('never counts an unmeasured gate as a pass', () => {
    const observed = {
      a1: {
        ran: true,
        recheckReason: 'recheck is not installed',
        summary: {
          totalRules: 1,
          rulesWithPatterns: 1,
          totalPatterns: 1,
          rulesWithoutLiteral: 0,
          patternsFailingToCompile: 0,
          ruleInvocationErrors: 0,
          recheckAvailable: false,
          recheckSuperLinearRuleIds: null,
        },
        shapeSuspicious: [],
        unreachedRuleIds: [],
        // The cross-file half of the A1 arm. Present here with a healthy
        // observation because this test is about `unmeasured` never counting as a
        // pass; a missing `crossFile` block would make three gates fail for an
        // unrelated reason and stop the assertion below from proving anything.
        crossFile: {
          ran: true,
          summary: {
            crossFileRules: 1,
            exportedUnregisteredRuleIds: 0,
            staticFilesScanned: 1,
            staticLiterals: 1,
            staticConstructionSites: 0,
            staticUncompilable: 0,
            dynamicPatternPairs: 5,
            dynamicFixtureProjects: 2,
            dynamicRulesWithNoPattern: 0,
            dynamicAnalyzeErrors: 0,
            positiveControlOk: true,
            positiveControlMissing: [],
            crossCheckDynamicNotStatic: 4,
            crossCheckStaticNotDynamic: 0,
            shapeChecker: {
              ok: true,
              fired: ['adjacent-unbounded', 'nested-quantifier', 'quantified-alternation'],
              missing: [],
              benignHits: [],
            },
          },
          shapeSuspicious: [],
        },
      },
    };
    const baseline = {
      gates: {
        'a1:surface-census': { expected: { totalRules: 1, rulesWithPatterns: 1, totalPatterns: 1 } },
        'a1:shape-suspicious-set': { patterns: [] },
        'a1:unreached-literals': { ruleIds: [] },
        'a1:catalog-errors': {
          expected: { rulesWithoutLiteral: 0, patternsFailingToCompile: 0, ruleInvocationErrors: 0 },
        },
        'a1:crossfile-surface-census': {
          expected: {
            crossFileRules: 1,
            exportedUnregisteredRuleIds: 0,
            staticFilesScanned: 1,
            staticLiterals: 1,
            staticConstructionSites: 0,
            staticUncompilable: 0,
          },
        },
        'a1:crossfile-shape-suspicious-set': { patterns: [] },
        'a1:crossfile-probe-liveness': {
          expected: {
            positiveControlOk: true,
            positiveControlMissing: [],
            dynamicRulesWithNoPattern: 0,
            dynamicAnalyzeErrors: 0,
          },
          minDynamicPatternPairs: 1,
          minFixtureProjects: 1,
          minRuntimeOnlyPatterns: 1,
        },
        'a1:recheck-superlinear': { measured: false, superLinearRuleIds: null },
      },
      optionalGates: ['a1:recheck-superlinear'],
    };
    const r = evaluateGates(observed, baseline, ['a1']);
    expect(verdictOf(r.gates, 'a1:recheck-superlinear')).toBe('unmeasured');
    expect(r.summary.passed).toBe(7);
    // Tolerated (exit 0) because the baseline pre-declares it optional …
    expect(r.summary.ok).toBe(true);
    // … but the run still has NOT demonstrated everything the baseline names.
    expect(r.summary.allGatesPassed).toBe(false);

    // Remove the pre-declaration and the same unmeasured gate becomes a failure.
    const strict = { ...baseline, optionalGates: [] };
    const r2 = evaluateGates(observed, strict, ['a1']);
    expect(r2.summary.ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// A1, cross-file half — the gates that close MEASURED LIMIT 8
// ---------------------------------------------------------------------------
// These are unit tests over `evaluateGates` rather than end-to-end runs on
// purpose. The end-to-end property (a super-linear regex injected into a
// cross-file rule makes the build fail) was verified by mutating a scratchpad
// COPY of `packages/analysis-graph/dist`, which is not something a test in this
// repo may do — it would have to write into the built product. What is testable
// here is the decision function: given an observation, does the gate reach the
// verdict the mutation experiment showed it must?
describe('evaluateGates — a1 cross-file', () => {
  const verdictOf = (gates: Array<{ id: string; verdict: string }>, id: string) =>
    gates.find((g) => g.id === id)?.verdict;

  const healthySummary = () => ({
    crossFileRules: 11,
    exportedUnregisteredRuleIds: 0,
    staticFilesScanned: 23,
    staticLiterals: 194,
    staticConstructionSites: 24,
    staticUncompilable: 0,
    dynamicPatternPairs: 332,
    dynamicFixtureProjects: 130,
    dynamicRulesWithNoPattern: 0,
    dynamicAnalyzeErrors: 0,
    positiveControlOk: true,
    positiveControlMissing: [] as string[],
    crossCheckDynamicNotStatic: 101,
    crossCheckStaticNotDynamic: 13,
    // The shape checker's own positive control. Present here because a healthy
    // observation has it; `a1:crossfile-shape-suspicious-set` fails without it
    // on purpose, since the suspicious set it compares is EMPTY and an empty
    // actual matching an empty expectation is also what a removed checker
    // produces. See the `shapeChecker` cases below.
    shapeChecker: {
      ok: true,
      fired: ['adjacent-unbounded', 'nested-quantifier', 'quantified-alternation'],
      missing: [] as string[],
      benignHits: [] as string[],
    },
  });

  const observedWith = (patch: Record<string, unknown> = {}, shapeSuspicious: string[] = []) => ({
    a1: {
      ran: true,
      summary: {
        totalRules: 1,
        rulesWithPatterns: 1,
        totalPatterns: 1,
        rulesWithoutLiteral: 0,
        patternsFailingToCompile: 0,
        ruleInvocationErrors: 0,
        recheckAvailable: false,
        recheckSuperLinearRuleIds: null,
      },
      shapeSuspicious: [],
      unreachedRuleIds: [],
      crossFile: { ran: true, summary: { ...healthySummary(), ...patch }, shapeSuspicious },
    },
  });

  const cfBaseline = () => ({
    gates: {
      'a1:surface-census': { expected: { totalRules: 1, rulesWithPatterns: 1, totalPatterns: 1 } },
      'a1:shape-suspicious-set': { patterns: [] },
      'a1:unreached-literals': { ruleIds: [] },
      'a1:catalog-errors': {
        expected: { rulesWithoutLiteral: 0, patternsFailingToCompile: 0, ruleInvocationErrors: 0 },
      },
      'a1:crossfile-surface-census': {
        expected: {
          crossFileRules: 11,
          exportedUnregisteredRuleIds: 0,
          staticFilesScanned: 23,
          staticLiterals: 194,
          staticConstructionSites: 24,
          staticUncompilable: 0,
        },
      },
      'a1:crossfile-shape-suspicious-set': { patterns: [] as string[] },
      'a1:crossfile-probe-liveness': {
        expected: {
          positiveControlOk: true,
          positiveControlMissing: [] as string[],
          dynamicRulesWithNoPattern: 0,
          dynamicAnalyzeErrors: 0,
        },
        minDynamicPatternPairs: 200,
        minFixtureProjects: 60,
        minRuntimeOnlyPatterns: 40,
      },
      'a1:recheck-superlinear': { measured: false, superLinearRuleIds: null },
    },
    optionalGates: ['a1:recheck-superlinear'],
  });

  it('passes on the healthy observation', () => {
    const r = evaluateGates(observedWith(), cfBaseline(), ['a1']);
    expect(r.summary.failed).toBe(0);
    expect(verdictOf(r.gates, 'a1:crossfile-surface-census')).toBe('pass');
    expect(verdictOf(r.gates, 'a1:crossfile-shape-suspicious-set')).toBe('pass');
    expect(verdictOf(r.gates, 'a1:crossfile-probe-liveness')).toBe('pass');
  });

  // ★ The vacuous-pass experiment, as a verdict.
  //
  // On 2026-08-03 the shape checker was stubbed to return no hits at all, and
  // NOTHING changed: the catalogue printed the same lines, `--check` exited 0,
  // and this gate passed. The suspicious set it pins is empty, and an empty
  // actual equalling an empty expectation is exactly what a removed checker
  // produces. The core gate does not have this hole only because its expected
  // set is non-empty; that is luck, not design.
  //
  // These two cases are the fix's reason for existing. If they are ever relaxed
  // to make an unrelated refactor pass, the gate goes back to certifying
  // nothing — so they assert the two ways a checker dies: it stops answering
  // (missing) and it answers indiscriminately (benignHits).
  it('fails when the shape checker itself is dead, even though the suspicious set is empty', () => {
    const r = evaluateGates(
      observedWith({
        shapeChecker: { ok: false, fired: [], missing: ['adjacent-unbounded', 'nested-quantifier', 'quantified-alternation'], benignHits: [] },
      }),
      cfBaseline(),
      ['a1'],
    );
    expect(verdictOf(r.gates, 'a1:crossfile-shape-suspicious-set')).toBe('fail');
    // The census is a different axis and must be unmoved: a dead judge is not a
    // changed surface, and conflating them sends the next reader to the wrong file.
    expect(verdictOf(r.gates, 'a1:crossfile-surface-census')).toBe('pass');
  });

  it('fails when the shape checker calls a benign literal suspicious', () => {
    const r = evaluateGates(
      observedWith({
        shapeChecker: {
          ok: false,
          fired: ['adjacent-unbounded', 'nested-quantifier', 'quantified-alternation'],
          missing: [],
          benignHits: ['nested-quantifier'],
        },
      }),
      cfBaseline(),
      ['a1'],
    );
    expect(verdictOf(r.gates, 'a1:crossfile-shape-suspicious-set')).toBe('fail');
  });

  // An older catalogue predates the canary and reports no `shapeChecker` at all.
  // It must FAIL rather than inherit a pass: "the field is absent" is the same
  // evidence as "the checker is gone", and defaulting absence to healthy is how
  // the original hole was built.
  it('fails when the catalogue reports no canary at all', () => {
    const r = evaluateGates(observedWith({ shapeChecker: null }), cfBaseline(), ['a1']);
    expect(verdictOf(r.gates, 'a1:crossfile-shape-suspicious-set')).toBe('fail');
  });

  // The mutation experiment, as a verdict: injecting `/(\s+)+$/` as a literal
  // into a cross-file rule moved staticLiterals 194→195 AND put entries in the
  // suspicious set. Both halves must fail, because either one alone would let a
  // reader conclude the other is fine.
  it('fails both gates when a super-linear literal is added to a cross-file rule', () => {
    const r = evaluateGates(
      observedWith({ staticLiterals: 195, dynamicPatternPairs: 335 }, [
        'dynamic:VG-SMELL-013#a2r1en=nested-quantifier',
        'static:design-smells-crossfile/authz-lexicon.js#4=nested-quantifier',
      ]),
      cfBaseline(),
      ['a1'],
    );
    expect(verdictOf(r.gates, 'a1:crossfile-surface-census')).toBe('fail');
    expect(verdictOf(r.gates, 'a1:crossfile-shape-suspicious-set')).toBe('fail');
    // The CORE census must be untouched — that difference is the whole point of
    // the second gate, and a change that made the core gate absorb this would
    // silently re-merge two censuses that are not on the same axis.
    expect(verdictOf(r.gates, 'a1:surface-census')).toBe('pass');
    expect(verdictOf(r.gates, 'a1:shape-suspicious-set')).toBe('pass');
  });

  // The residue, MEASURED LIMIT 8a: a pattern constructed in a branch no fixture
  // reaches is counted but never resolved, so the COUNT is the only defence.
  it('fails the census (not the shape set) when only a construction site appears', () => {
    const r = evaluateGates(observedWith({ staticConstructionSites: 25 }), cfBaseline(), ['a1']);
    expect(verdictOf(r.gates, 'a1:crossfile-surface-census')).toBe('fail');
    expect(verdictOf(r.gates, 'a1:crossfile-shape-suspicious-set')).toBe('pass');
  });

  // The accident this repo has already had twice: a probe that observed nothing
  // and reported PASS. An empty observation must be a FAILURE, not a clean sheet.
  it('fails when the positive control did not fire', () => {
    const r = evaluateGates(
      observedWith({ positiveControlOk: false, positiveControlMissing: ['TEST_PATH'] }),
      cfBaseline(),
      ['a1'],
    );
    expect(verdictOf(r.gates, 'a1:crossfile-probe-liveness')).toBe('fail');
  });

  it('fails when the fixture driver silently shrinks past the floor', () => {
    const r = evaluateGates(observedWith({ dynamicPatternPairs: 3, dynamicFixtureProjects: 1 }), cfBaseline(), ['a1']);
    expect(verdictOf(r.gates, 'a1:crossfile-probe-liveness')).toBe('fail');
  });

  it('fails when a cross-file rule stops executing any pattern', () => {
    const r = evaluateGates(observedWith({ dynamicRulesWithNoPattern: 1 }), cfBaseline(), ['a1']);
    expect(verdictOf(r.gates, 'a1:crossfile-probe-liveness')).toBe('fail');
  });

  // A baseline that declares no floor governs nothing; an unfloored liveness
  // number is the same vacuous pass as an empty `expected` record.
  it('fails when the baseline declares a liveness number with no floor', () => {
    const b = cfBaseline();
    delete (b.gates['a1:crossfile-probe-liveness'] as Record<string, unknown>).minDynamicPatternPairs;
    const r = evaluateGates(observedWith(), b, ['a1']);
    expect(verdictOf(r.gates, 'a1:crossfile-probe-liveness')).toBe('fail');
  });

  // A dead cross-file child must not take the core gates down with it, and must
  // not read as a skip.
  it('fails only the cross-file gates when the cross-file census could not run', () => {
    const o = observedWith();
    (o.a1 as Record<string, unknown>).crossFile = { ran: false, run: { ok: false, spawnError: 'boom' }, summary: null, shapeSuspicious: null };
    const r = evaluateGates(o, cfBaseline(), ['a1']);
    expect(verdictOf(r.gates, 'a1:crossfile-surface-census')).toBe('fail');
    expect(verdictOf(r.gates, 'a1:crossfile-shape-suspicious-set')).toBe('fail');
    expect(verdictOf(r.gates, 'a1:crossfile-probe-liveness')).toBe('fail');
    expect(verdictOf(r.gates, 'a1:surface-census')).toBe('pass');
    expect(r.gates.find((g: { id: string }) => g.id === 'a1:crossfile-surface-census')?.detail).toContain('boom');
  });

  // A candidate rule joining the registry is exactly the event this census
  // exists to notice, from either direction.
  it('fails when a rule-shaped export appears outside the registry', () => {
    const r = evaluateGates(observedWith({ exportedUnregisteredRuleIds: 1 }), cfBaseline(), ['a1']);
    expect(verdictOf(r.gates, 'a1:crossfile-surface-census')).toBe('fail');
  });
});

// ---------------------------------------------------------------------------
// The CI wiring itself
// ---------------------------------------------------------------------------
describe('ci.yml', () => {
  // scripts/packaging-invariants.test.ts records the precedent: an invariant
  // that lives only in a workflow file evaporates during the refactor that
  // merges three jobs into two. The same applies here, with an extra twist —
  // this gate is the only end-to-end exercise of the b1 arm anywhere, so a
  // silently narrowed job would take that coverage with it.
  const yml = () => readFileSync(CI_YML, 'utf8');

  it('has a security-selftest job that runs the selftest script', () => {
    const text = yml();
    expect(text).toContain('security-selftest:');
    expect(text).toContain('node scripts/sec-selftest.mjs');
  });

  it('runs every arm — the job must not narrow itself with --arms', () => {
    const line = yml()
      .split('\n')
      .find((l) => l.includes('node scripts/sec-selftest.mjs'));
    expect(line, 'the selftest invocation disappeared from ci.yml').toBeTruthy();
    expect(
      line!.includes('--arms'),
      `ci.yml narrows the selftest to a subset of arms (${ARMS.join(', ')}); ` +
        'the b1 arm has no other end-to-end coverage',
    ).toBe(false);
  });

  it('is a blocking job — continue-on-error would make the gate advisory', () => {
    // Line-based, not a slice-and-regex over the whole text: ci.yml is stored
    // with CRLF terminators, and a `:\n` boundary pattern silently matches
    // nothing there. The first version of this test did exactly that, found no
    // next job, and ended up scanning perf-bench's `continue-on-error` as if it
    // belonged to this job — a test that fails for the wrong reason today and
    // would pass for the wrong reason tomorrow.
    const lines = yml().split(/\r?\n/);
    const start = lines.findIndex((l) => l.trim() === 'security-selftest:');
    expect(start, 'the security-selftest job disappeared from ci.yml').toBeGreaterThanOrEqual(0);
    const rest = lines.slice(start + 1);
    const end = rest.findIndex((l) => /^ {2}[a-z][a-z0-9-]*:\s*$/.test(l));
    const body = (end === -1 ? rest : rest.slice(0, end)).join('\n');
    expect(body).not.toContain('continue-on-error');
    // And it must actually be the job that runs the gate, not an empty stub.
    expect(body).toContain('node scripts/sec-selftest.mjs');
  });

  it('redacts on the public runner, and uploads no manifest artefact', () => {
    const text = yml();
    const line = text.split('\n').find((l) => l.includes('node scripts/sec-selftest.mjs'));
    expect(line!.includes('--redact-metrics'), 'ci.yml runs the gate without --redact-metrics').toBe(true);
    // The artefact was the third public surface (log, step summary, download).
    // Named explicitly rather than by a generic upload-artifact check, because
    // this job legitimately may grow other uploads.
    expect(text).not.toContain('security-selftest-manifest');
  });
});

// ---------------------------------------------------------------------------
// Public-surface redaction
// ---------------------------------------------------------------------------
//
// Measured 2026-08-10 on run 31353542731: the public job log carried the B1
// evasion rates verbatim, and 357 downloadable artefacts carried the whole run
// record. Both surfaces are fed by the same stdout this asserts on.
//
// The assertions run against the WHOLE RENDERED REPORT of a real run, not
// against the redaction helper. A helper test would pass while a newly added
// `console.log` printed a rate around it — which is exactly how the surface
// grew in the first place. The pair matters as much as the redacted run: a
// redacted run with no numbers proves nothing if the plain run had none
// either, so the plain run is this test's positive control.
describe('--redact-metrics withholds the readings and keeps the gate', () => {
  let plain: Run;
  let redacted: Run;

  beforeAll(() => {
    plain = runArms([], 'redact-control');
    redacted = runArms(['--redact-metrics'], 'redact-subject');
  }, 240_000);

  // Positive control first. If this fails the subject assertions are vacuous.
  it('the plain run does print measured rates (control)', () => {
    expect(plain.stdout).toMatch(/0\.\d{4,}/);
  });

  it('the redacted run prints no measured rate anywhere', () => {
    expect(redacted.stdout).not.toMatch(/0\.\d{4,}/);
  });

  it('the redacted run does not print where the manifest went', () => {
    // The real default path names the withheld directory. These runs redirect
    // it into tmp (runArms) so no test clobbers the tracked record, so the
    // control here is the redirected path — same shape, same surface, and it
    // proves the `wrote …` line reaches stdout at all before the subject
    // asserts that it does not.
    expect(plain.stdout).toContain('redact-control.json');
    expect(redacted.stdout).not.toContain('redact-subject.json');
    expect(redacted.stdout).toContain('path withheld');
  });

  it('the gate still gates — same verdicts, same exit status', () => {
    const verdicts = (r: Run) => r.stdout.split(/\r?\n/).filter((l) => /^(PASS|FAIL|UNMEASURED)\s/.test(l));
    expect(verdicts(redacted).length).toBeGreaterThan(0);
    expect(verdicts(redacted)).toEqual(verdicts(plain));
    expect(redacted.status).toBe(plain.status);
  });

  it('the b1/b3 gates are still named, so a red run is still actionable', () => {
    expect(redacted.stdout).toMatch(/^\S+\s+b1:/m);
    expect(redacted.stdout).toMatch(/^\S+\s+b3:/m);
  });
});
