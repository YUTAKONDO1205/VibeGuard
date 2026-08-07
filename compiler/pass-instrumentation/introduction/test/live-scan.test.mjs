// The live half of the object-level check: compile the two fixtures with a real
// toolchain and assert the verdicts.
//
// THE CONTRACT ON THE NEGATIVE FIXTURE. Zero Unexplained. Not "few", not "the
// known ones filtered out" -- zero. It is a C++ file with templates, a virtual
// class, RTTI, a lambda, a thunk, a guard variable and a dynamically
// initialised global, and every one of those is legitimate compiler output. If
// one of them comes out Unexplained the rules are wrong and the rules get
// fixed; there is no exception list in this component and adding one would
// make the test pass while leaving the detector exactly as broken.
//
// SKIP IS NOT PASS. Without a toolchain these tests FAIL. Setting
// VG_INTRO_ALLOW_SKIP=1 authorises the skip and every skipped case is named.

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK } from '../lib/exit.mjs';
import { probeTool } from '../lib/toolchain.mjs';
import { main as scanMain } from '../cli/intro-scan.mjs';
import { captureConsole, SUBJECTS } from './helpers.mjs';

const NEGATIVE = join(SUBJECTS, 'negative', 'normal_cxx.cpp');
const POSITIVE = join(SUBJECTS, 'positive', 'injected.c');

let toolchainNote = null;
function toolchain() {
  if (toolchainNote !== null) return toolchainNote;
  const missing = [];
  for (const [tool, arg] of [['clang-18', '--version'], ['clang++-18', '--version'], ['llvm-readelf-18', '--version']]) {
    if (probeTool(tool, arg) === null) missing.push(tool);
  }
  toolchainNote = missing.length === 0 ? '' : `missing: ${missing.join(', ')}`;
  return toolchainNote;
}

/**
 * Skip only when the environment authorises it, and then name the case in the
 * output. When it does not, the test is left to run and fails inside
 * `requireToolchain` -- one clear failure per case, rather than a module that
 * refused to load.
 */
function gate(caseName) {
  const note = toolchain();
  if (note === '') return undefined;
  if (process.env.VG_INTRO_ALLOW_SKIP !== '1') return undefined;
  // eslint-disable-next-line no-console
  console.log(`SKIPPED CASE: ${caseName} -- ${note} (authorised by VG_INTRO_ALLOW_SKIP=1)`);
  return `${caseName}: ${note}`;
}

/**
 * A suite that skipped itself reports the same green as a suite that passed,
 * and that is the failure this component exists to complain about one level up.
 */
function requireToolchain(caseName) {
  const note = toolchain();
  if (note === '') return;
  assert.fail(
    `${caseName}: ${note}. This is a failure, not a skip: a check that did not run `
    + 'must not report the same green as a check that passed. Set VG_INTRO_ALLOW_SKIP=1 '
    + 'to authorise skipping it, and the skipped case will be named in the output.',
  );
}

function run(argv) {
  const cap = captureConsole();
  const status = scanMain(argv, cap.out);
  return { status, stdout: cap.stdout, stderr: cap.stderr };
}

for (const opt of ['-O0', '-O2']) {
  test(`the negative C++ fixture has zero Unexplained at ${opt}`, { skip: gate(`negative ${opt}`) }, () => {
    requireToolchain(`negative ${opt}`);
    const r = run([NEGATIVE, '--opt', opt, '--std', 'c++17']);
    const m = /introduced elements: (\d+)/.exec(r.stdout);
    assert.ok(m, `no subtraction report:\n${r.stdout}\n${r.stderr}`);
    const total = Number(m[1]);
    assert.ok(total > 40, `only ${total} elements: the fixture is not exercising the compiler`);
    assert.match(r.stdout, /Unexplained: 0/, r.stdout);
    assert.match(r.stdout, /Unresolved: 0/, r.stdout);
    assert.match(r.stdout, /findings=0 incomplete=0/);
    assert.equal(r.status, EXIT_OK);
  });
}

test('the negative fixture really does contain the machinery it claims to', {
  skip: gate('negative feature coverage'),
}, () => {
  requireToolchain('negative feature coverage');
  // Without this the zero above could mean "the rules work" or "the fixture
  // stopped producing anything interesting", and those look identical.
  const dir = mkdtempSync(join(tmpdir(), 'intro-neg-'));
  try {
    const jsonPath = join(dir, 'neg.json');
    const r = run([NEGATIVE, '--opt', '-O0', '--std', 'c++17', '--quiet', '--json', jsonPath]);
    assert.equal(r.status, EXIT_OK, r.stderr);
    const rows = JSON.parse(readFileSync(jsonPath, 'utf8'));
    const shapes = {
      'virtual table': /^_ZTV/,
      'VTT': /^_ZTT/,
      'typeinfo': /^_ZTI/,
      'typeinfo name': /^_ZTS/,
      'virtual thunk': /^_ZTv/,
      'guard variable': /^_ZGV/,
      'static-init entry': /^_GLOBAL__sub_I_/,
      'lambda call operator': /\$_0/,
      'template instantiation': /Accumulator/,
      'unwind table': /^GCC_except_table/,
    };
    for (const [what, re] of Object.entries(shapes)) {
      const hits = rows.filter((row) => re.test(row.name));
      assert.ok(hits.length > 0, `the fixture produced no ${what}`);
      const bad = hits.filter((row) => row.verdict !== 'Explained');
      assert.deepEqual(bad.map((b) => b.name), [], `${what} came out ${bad[0]?.verdict}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the positive fixture produces exactly the four findings', { skip: gate('positive') }, () => {
  requireToolchain('positive');
  const r = run([POSITIVE, '--opt', '-O2']);
  assert.equal(r.status, EXIT_FINDINGS, r.stdout + r.stderr);
  assert.match(r.stdout, /findings=4 incomplete=0/, r.stdout);
  for (const id of ['VG-INTRO-001', 'VG-INTRO-002', 'VG-INTRO-003', 'VG-INTRO-004']) {
    assert.match(r.stdout, new RegExp(`${id} \\[`), `${id} did not fire:\n${r.stdout}`);
  }
  assert.match(r.stdout, /VG-INTRO-001 \[high\][^\n]*intro_injected_thunk/);
  assert.match(r.stdout, /VG-INTRO-002 \[high\][^\n]*dlopen/);
  assert.match(r.stdout, /VG-INTRO-003 \[critical\][^\n]*intro_injected_thunk/);
  assert.match(r.stdout, /VG-INTRO-004 \[high\][^\n]*\.text\.intro_injected/);
});

test('the positive fixture does NOT flag its honest static initialiser', {
  skip: gate('positive precision'),
}, () => {
  requireToolchain('positive precision');
  // Both fixtures put an entry in .init_array. One is the compiler running a
  // constructor the source wrote; the other is injected. A detector that
  // cannot tell them apart is a detector that flags .init_array.
  const r = run([POSITIVE, '--opt', '-O2']);
  assert.doesNotMatch(r.stdout, /VG-INTRO-003[^\n]*intro_positive_boot/, r.stdout);
  assert.match(r.stdout, /source-derived: \d+/);
});

test('an empty input set is INCOMPLETE, and --allow-empty is the only way to 0', () => {
  const empty = run([]);
  assert.equal(empty.status, EXIT_INCOMPLETE);
  assert.match(empty.stdout, /inputs=0 checked=0 skipped=0/);
  assert.match(empty.stderr, /exit 3 \(INCOMPLETE\), not exit 0/);

  const allowed = run(['--allow-empty']);
  assert.equal(allowed.status, EXIT_OK);
  assert.match(allowed.stdout, /inputs=0 checked=0 skipped=0 allowEmpty=1/);
});

test('a malformed policy is exit 4, and nothing else runs', () => {
  const r = run([NEGATIVE, '--intro-policy', join(SUBJECTS, 'does-not-exist.json')]);
  assert.equal(r.status, 4);
  assert.doesNotMatch(r.stdout, /introduced elements/);
});
