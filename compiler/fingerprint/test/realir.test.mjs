// The checks that need a real compiler.
//
// These build the fixture with clang-18 at all four optimisation levels and ask
// the fingerprint the questions the hand-written pairs cannot: does it hold up
// against output a compiler actually produced, and is the CONTROL -- the unit
// whose effect cannot be removed -- comparable across levels?
//
// PREREQUISITE HANDLING. There is no such thing as a skipped pass here. If
// clang-18 is absent the whole file fails, and the only way out is to set
// VG_FP_ALLOW_MISSING_TOOLS=1, which turns the failures into skips AND makes
// the file print every skipped case by name. A prebuilt directory of IR can be
// supplied instead with VG_FP_IR_DIR (tools/make-fixtures.sh writes one).

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { parseModule } from '../lib/parse.mjs';
import { fingerprintFunction } from '../lib/fingerprint.mjs';
import { countCallSites, naiveNameHits } from '../lib/oracle.mjs';
import { skipAuthorised, SKIP_ENV } from '../lib/count.mjs';
import { PKG } from './helpers.mjs';

const LEVELS = ['O0', 'O1', 'O2', 'O3'];
const CONTROL = '@control_wipe';
const SUBJECT = '@subject_wipe';

function whichClang() {
  for (const name of [process.env.VG_FP_CC, 'clang-18'].filter(Boolean)) {
    try {
      execFileSync('sh', ['-c', `command -v ${JSON.stringify(name)}`], { stdio: ['ignore', 'pipe', 'ignore'] });
      return name;
    } catch { /* keep looking */ }
  }
  return null;
}

/** @returns {{dir:string|null, why:string|null}} */
function locateIr() {
  const given = process.env.VG_FP_IR_DIR;
  if (given !== undefined && existsSync(join(given, `fixture.${LEVELS[0]}.ll`))) {
    return { dir: given, why: null };
  }
  const cc = whichClang();
  if (cc === null) return { dir: null, why: 'clang-18 is not on PATH and VG_FP_IR_DIR was not set' };
  const scratch = mkdtempSync(join(tmpdir(), 'vg-fp-ir-'));
  const r = spawnSync('bash', [join(PKG, 'tools', 'make-fixtures.sh'), scratch], {
    encoding: 'utf8', env: { ...process.env, CC: cc },
  });
  if (r.status !== 0) return { dir: null, why: `make-fixtures.sh failed (${r.status}): ${r.stderr ?? ''}` };
  return { dir: join(scratch, 'ir'), why: null };
}

const located = locateIr();
const IR = located.dir;
const authorised = skipAuthorised();

/**
 * Register a case that needs the compiler. Absent one it fails, unless the
 * environment authorised the skip -- and then the case is named on stdout, so
 * a green run cannot hide how much of it did not happen.
 */
const skippedCases = [];
function needsIr(name, fn) {
  test(name, (t) => {
    if (IR !== null) return fn(t);
    if (!authorised) {
      assert.fail(`prerequisite missing: ${located.why}. Set ${SKIP_ENV}=1 to authorise a skip.`);
    }
    skippedCases.push(name);
    console.log(`  SKIPPED (authorised by ${SKIP_ENV}): ${name}`);
    t.skip(`no compiler: ${located.why}`);
    return undefined;
  });
}

const cache = new Map();
function mod(variant, level) {
  const key = `${variant}.${level}`;
  if (!cache.has(key)) {
    const text = readFileSync(join(IR, `${key}.ll`), 'utf8');
    cache.set(key, { text, mod: parseModule(text) });
  }
  return cache.get(key);
}
const digest = (variant, level, fn) => fingerprintFunction(mod(variant, level).mod, fn).digest;

// ── the oracle, on real output ──────────────────────────────────────────────

needsIr('the call-site oracle sees 2 call sites at -O0 and 1 at -O2, and the control keeps its own', () => {
  const perLevel = LEVELS.map((L) => {
    const m = mod('fixture', L);
    return {
      level: L,
      subject: countCallSites(m.mod.byName.get(SUBJECT), 'llvm.memset'),
      control: countCallSites(m.mod.byName.get(CONTROL), 'llvm.memset'),
      naive: naiveNameHits(m.text, 'llvm.memset'),
    };
  });
  const at = (L) => perLevel.find((r) => r.level === L);
  assert.equal(at('O0').subject + at('O0').control, 2, JSON.stringify(perLevel));
  assert.equal(at('O2').subject + at('O2').control, 1, JSON.stringify(perLevel));
  // The control cannot be optimised away at any level. If it ever is, every
  // other number in this file is measuring a broken oracle.
  for (const r of perLevel) assert.equal(r.control, 1, `control lost its effect at ${r.level}`);
  // 0 versus non-zero for the subject, which is the thing being detected.
  assert.equal(at('O0').subject > 0, true);
  assert.equal(at('O2').subject, 0);
  // And the naive oracle is wrong in the direction the interface warns about:
  // it still counts the surviving declaration after the call has gone.
  assert.equal(at('O2').naive > at('O2').subject + at('O2').control, true);
});

// ── both directions, on real output ─────────────────────────────────────────

needsIr('PERTURBATION: renaming every local in the source does not move any fingerprint', () => {
  for (const L of LEVELS) {
    for (const f of mod('fixture', L).mod.functions) {
      assert.equal(digest('fixture', L, f.name), digest('fixture-renamed', L, f.name),
        `${f.name} at ${L} moved when the source identifiers were renamed`);
    }
  }
});

needsIr('PERTURBATION: building without -g does not move any fingerprint', () => {
  for (const L of LEVELS) {
    for (const f of mod('fixture', L).mod.functions) {
      assert.equal(digest('fixture', L, f.name), digest('fixture-nodbg', L, f.name),
        `${f.name} at ${L} moved when debug information was dropped`);
    }
  }
});

needsIr('SEMANTIC: deleting the control\'s wipe moves its fingerprint and nothing else\'s', () => {
  const untouched = [SUBJECT, '@control_pure', '@subject_branch', '@control_branch'];
  for (const L of LEVELS) {
    assert.notEqual(digest('fixture', L, CONTROL), digest('fixture-nowipe', L, CONTROL),
      `at ${L} the control's wipe was deleted and the fingerprint did not move`);
    for (const f of untouched) {
      assert.equal(digest('fixture', L, f), digest('fixture-nowipe', L, f),
        `at ${L} ${f} moved although its source did not change`);
    }
  }
});

// ── the headline, recorded rather than asserted away ────────────────────────

needsIr('MEASURED: the control is NOT comparable across all four levels (the negative result)', () => {
  const seen = new Set(LEVELS.map((L) => digest('fixture', L, CONTROL)));
  const optOnly = new Set(['O1', 'O2', 'O3'].map((L) => digest('fixture', L, CONTROL)));
  // This asserts the measurement as it stands, so that if a later change makes
  // the general fingerprint stable the test fails and the claim gets rewritten
  // rather than quietly inherited.
  assert.equal(seen.size, 4, `expected 4 distinct control fingerprints across O0..O3, got ${seen.size}`);
  assert.equal(optOnly.size, 3, `expected 3 distinct control fingerprints across O1..O3, got ${optOnly.size}`);
});

needsIr('MEASURED: a straight-line unit IS comparable across O1..O3, and never across the -O0 boundary', () => {
  for (const f of ['@control_pure', '@subject_branch', '@control_branch']) {
    const optOnly = new Set(['O1', 'O2', 'O3'].map((L) => digest('fixture', L, f)));
    assert.equal(optOnly.size, 1, `${f}: expected one fingerprint across O1..O3, got ${optOnly.size}`);
    assert.notEqual(digest('fixture', 'O0', f), digest('fixture', 'O1', f),
      `${f}: -O0 and -O1 agreed, which the seven normalisations do not explain`);
  }
});

needsIr('MEASURED: the general fingerprint raises more alarms than the targeted oracle, including on the control', () => {
  let general = 0;
  let targeted = 0;
  let generalOnControl = 0;
  for (let i = 1; i < LEVELS.length; i += 1) {
    for (const f of [SUBJECT, CONTROL]) {
      const changed = digest('fixture', LEVELS[i - 1], f) !== digest('fixture', LEVELS[i], f);
      const before = countCallSites(mod('fixture', LEVELS[i - 1]).mod.byName.get(f), 'llvm.memset');
      const after = countCallSites(mod('fixture', LEVELS[i]).mod.byName.get(f), 'llvm.memset');
      if (changed) general += 1;
      if (changed && f === CONTROL) generalOnControl += 1;
      if (before > 0 && after === 0) targeted += 1;
    }
  }
  assert.equal(general, 6);
  assert.equal(targeted, 1);
  assert.equal(generalOnControl, 3);
  assert.equal(general > targeted, true);
});

// ── the runner, end to end ──────────────────────────────────────────────────

needsIr('the stability runner prints the counting line and exits 2 on its findings', () => {
  const r = spawnSync(process.execPath, [join(PKG, 'cli', 'stability.mjs'), '--ir', IR, '--out', mkdtempSync(join(tmpdir(), 'vg-fp-out-'))], { encoding: 'utf8' });
  assert.match(r.stdout, /inputs=16 checked=16 skipped=0/, r.stdout + r.stderr);
  assert.equal(r.status, 2, `exit was ${r.status}\n${r.stdout}${r.stderr}`);
  assert.match(r.stdout, /VG-PROP-010/);
});

needsIr('the stability runner refuses to report a clean run against an empty directory', () => {
  const empty = mkdtempSync(join(tmpdir(), 'vg-fp-stab-empty-'));
  const r = spawnSync(process.execPath, [join(PKG, 'cli', 'stability.mjs'), '--ir', empty], { encoding: 'utf8' });
  assert.equal(r.status, 3, `exit was ${r.status}\n${r.stdout}${r.stderr}`);
  assert.match(r.stdout, /inputs=16 checked=0 skipped=16/);
});

test('a run that skipped anything says so, by name', () => {
  if (IR !== null) {
    assert.deepEqual(skippedCases, []);
    return;
  }
  assert.equal(authorised, true, 'unauthorised skips should already have failed the cases above');
  console.log(`  ${skippedCases.length} case(s) skipped, all named above`);
  assert.equal(skippedCases.length > 0, true);
});
