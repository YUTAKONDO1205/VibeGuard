// The map must be produced BY the wrapper.
//
// If the wrapper accepts a map handed to it from outside, the attacker supplies
// the map, and the wrapper then reports on a link that never happened. The
// report is worse than no report: it carries the authority of a check.
//
// The refusal is enforced in three places, and all three are asserted here,
// because each of them is a complete bypass on its own:
//
//   1. the CLI has no flag that names a map, and an unknown flag is refused
//      rather than ignored;
//   2. the CLI refuses a link command line that names the map itself, BEFORE it
//      runs the linker (so this test needs no toolchain);
//   3. the pure verdict refuses an observation whose provenance is not the
//      wrapper's, so a future caller that assembles an observation by hand
//      cannot get a verdict out of it either.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { buildObservation } from '../lib/observe.mjs';
import { readLinkPolicy } from '../lib/policy-link.mjs';
import { verdict } from '../lib/verdict.mjs';
import { LINK } from '../lib/findings.mjs';
import { EXIT_INTEGRITY } from '../lib/exit.mjs';
import { approvingPolicy, CLI, elfHeader, fixture, LINK_ROOT, NEG_ARGV, scratch, WRAPPER_PROVENANCE } from './helpers.mjs';

function runCli(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
}

function policyFile(dir, policy = approvingPolicy()) {
  const p = join(dir, 'policy.json');
  writeFileSync(p, JSON.stringify(policy), 'utf8');
  return p;
}

function observationWith(provenance) {
  return buildObservation({
    linkRoot: LINK_ROOT,
    argv: NEG_ARGV,
    mapText: fixture('neg.map.txt'),
    mapProvenance: provenance,
    traceText: fixture('neg.trace'),
    artifactPath: `${LINK_ROOT}/neg.bin`,
    artifactBytes: elfHeader('neg.elfhdr.hex'),
  });
}

// ── 3. the pure verdict ──────────────────────────────────────────────────────

test('a verdict is refused on a map the wrapper did not produce', () => {
  const v = verdict({
    observation: observationWith({ producedBy: 'external', existedBefore: true, writtenByThisRun: false, nonce: null }),
    policyResult: readLinkPolicy(approvingPolicy()),
  });
  assert.equal(v.exitCode, EXIT_INTEGRITY);
  assert.equal(v.findings[0].id, LINK.MAP_NOT_PRODUCED_HERE);
  assert.match(v.findings[0].detail, /account of the link, not an observation/);
  assert.deepEqual(v.counts, { inputs: 0, checked: 0, skipped: 0 }, 'nothing is counted as checked');
});

test('an observation with no provenance at all is refused the same way', () => {
  for (const provenance of [undefined, {}, { producedBy: null }, { producedBy: 'Wrapper' }]) {
    const v = verdict({ observation: observationWith(provenance), policyResult: readLinkPolicy(approvingPolicy()) });
    assert.equal(v.exitCode, EXIT_INTEGRITY, `provenance ${JSON.stringify(provenance)} was accepted`);
  }
});

test('the same observation with the wrapper’s provenance is accepted — the refusal is about origin, not content', () => {
  const v = verdict({ observation: observationWith(WRAPPER_PROVENANCE), policyResult: readLinkPolicy(approvingPolicy()) });
  assert.notEqual(v.exitCode, EXIT_INTEGRITY);
  assert.ok(v.counts.inputs > 0);
});

// ── 1. the CLI has no way to name a map ──────────────────────────────────────

test('the CLI refuses --map rather than ignoring it', () => {
  const dir = scratch('extmap');
  const r = runCli(['link', '--policy', policyFile(dir), `--map=${join(dir, 'theirs.txt')}`, '--', 'clang-18', 'main.o'], dir);
  assert.equal(r.status, EXIT_INTEGRITY);
  assert.match(r.stderr, /unknown option --map/);
});

test('the CLI refuses every other name a map flag might take', () => {
  const dir = scratch('extmap2');
  const p = policyFile(dir);
  for (const flag of ['--map-file=x', '--mapfile=x', '--map-path=x', '--use-map=x']) {
    const r = runCli(['link', '--policy', p, flag, '--', 'clang-18', 'main.o'], dir);
    assert.equal(r.status, EXIT_INTEGRITY, `${flag} was not refused`);
  }
});

// ── 2. the CLI refuses a command line that names the map ─────────────────────

test('a link command that names the map is refused before the linker runs', () => {
  const dir = scratch('extmap3');
  const p = policyFile(dir);
  for (const arg of ['-Wl,-Map=theirs.txt', '-Wl,--print-map', '-Wl,-M']) {
    // `no-such-compiler` would fail if it were ever executed; the refusal has to
    // happen first, which is what its absence from the output proves.
    const r = runCli(['link', '--policy', p, '--', 'no-such-compiler', 'main.o', arg, '-o', 'app'], dir);
    assert.equal(r.status, EXIT_INTEGRITY, `${arg} was not refused`);
    assert.match(r.stdout, /VG-LINK-007/);
    assert.equal(/could not run/.test(r.stderr), false, 'the linker must not have been invoked');
  }
});

test('the refusal prints the counting line and does not claim to have checked anything', () => {
  const dir = scratch('extmap4');
  const r = runCli(['link', '--policy', policyFile(dir), '--', 'no-such-compiler', 'main.o', '-Wl,-Map=x', '-o', 'app'], dir);
  assert.match(r.stdout, /inputs=0 checked=0 skipped=0/);
  assert.match(r.stdout, /exit 4 \(integrity\)/);
});
