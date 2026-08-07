// The counting contract.
//
// Every runner prints `inputs=N checked=N skipped=S`, and exits NON-ZERO when N
// is 0 unless `--allow-empty` was passed. This repository has shipped an empty
// scan reporting success more than once; the shape of that failure is a zero
// that reads as a pass, and it is invisible in a green tick.
//
// The empty case is asserted three ways — the pure verdict, the CLI against an
// empty directory, and the CLI against a directory with nothing relevant in it —
// because each one reaches the zero by a different route.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { buildObservation } from '../lib/observe.mjs';
import { readLinkPolicy } from '../lib/policy-link.mjs';
import { verdict } from '../lib/verdict.mjs';
import { EXIT_OK, EXIT_INCOMPLETE } from '../lib/exit.mjs';
import { approvingPolicy, CLI, elfHeader, fixture, LINK_ROOT, NEG_ARGV, scratch, WRAPPER_PROVENANCE } from './helpers.mjs';

function runCli(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
}

const EMPTY_OBSERVATION = buildObservation({
  linkRoot: LINK_ROOT,
  argv: ['clang-18', '-fuse-ld=lld', '-o', 'app'],
  mapText: '             VMA              LMA     Size Align Out     In      Symbol\n',
  mapProvenance: WRAPPER_PROVENANCE,
  traceText: '',
  artifactPath: null,
  artifactBytes: null,
});

test('zero inputs is exit 3, not exit 0', () => {
  const v = verdict({ observation: EMPTY_OBSERVATION, policyResult: readLinkPolicy(approvingPolicy()) });
  assert.equal(v.counts.inputs, 0);
  assert.equal(v.exitCode, EXIT_INCOMPLETE);
  assert.ok(v.incomplete.some((i) => i.what === 'inputs' && /broken observation/.test(i.why)));
});

test('--allow-empty removes the empty-scan objection and nothing else', () => {
  const without = verdict({ observation: EMPTY_OBSERVATION, policyResult: readLinkPolicy(approvingPolicy()) });
  const with_ = verdict({
    observation: EMPTY_OBSERVATION,
    policyResult: readLinkPolicy(approvingPolicy()),
    options: { allowEmpty: true },
  });
  assert.equal(without.incomplete.some((i) => i.what === 'inputs'), true);
  assert.equal(with_.incomplete.some((i) => i.what === 'inputs'), false);
  // The flag says "zero inputs is what I meant". It does not say "and stop
  // checking everything else" — the artefact still went unread here, and that
  // is still exit 3.
  assert.equal(with_.exitCode, EXIT_INCOMPLETE);
  assert.ok(with_.incomplete.some((i) => i.what === 'entry-point'));
});

test('a non-empty run counts what it checked and what it did not', () => {
  const o = buildObservation({
    linkRoot: LINK_ROOT,
    argv: NEG_ARGV,
    mapText: fixture('neg.map.txt'),
    mapProvenance: WRAPPER_PROVENANCE,
    traceText: fixture('neg.trace'),
    artifactPath: `${LINK_ROOT}/neg.bin`,
    artifactBytes: elfHeader('neg.elfhdr.hex'),
  });
  const v = verdict({ observation: o, policyResult: readLinkPolicy(approvingPolicy()) });
  assert.equal(v.counts.inputs, o.inputs.length);
  assert.equal(v.counts.checked + v.counts.skipped, v.counts.inputs);
  assert.ok(v.counts.inputs >= 8, `only ${v.counts.inputs} inputs observed for a two-object link`);
  assert.equal(v.counts.skipped, v.skipped.length, 'the skipped count and the skipped names must be the same set');
});

// ── the CLI, against nothing ─────────────────────────────────────────────────

test('recheck against an EMPTY directory exits 3 and says nothing was examined', () => {
  const dir = scratch('empty');
  const records = join(dir, 'records');
  mkdirSync(records);
  const r = runCli(['recheck', records, '--root', dir], dir);
  assert.equal(r.status, EXIT_INCOMPLETE, `exit was ${r.status}; an empty scan must never be 0`);
  assert.match(r.stdout, /inputs=0 checked=0 skipped=0/);
  assert.match(r.stdout, /no link records were found/);
  assert.match(r.stdout, /--allow-empty was not passed/);
});

test('recheck against an empty directory WITH --allow-empty still prints the count', () => {
  const dir = scratch('empty-ok');
  const records = join(dir, 'records');
  mkdirSync(records);
  const r = runCli(['recheck', records, '--root', dir, '--allow-empty'], dir);
  assert.equal(r.status, EXIT_OK);
  assert.match(r.stdout, /inputs=0 checked=0 skipped=0/);
  assert.match(r.stdout, /accepted because --allow-empty/);
});

test('a directory holding files that are not link records is not silently empty', () => {
  const dir = scratch('junk');
  const records = join(dir, 'records');
  mkdirSync(records);
  writeFileSync(join(records, 'notes.json'), '{"hello":1}', 'utf8');
  const r = runCli(['recheck', records, '--root', dir], dir);
  assert.equal(r.status, EXIT_INCOMPLETE);
  assert.match(r.stdout, /inputs=1 checked=0 skipped=1/);
  assert.match(r.stdout, /notes\.json/, 'the skipped case is named');
});

test('recheck without --root refuses rather than guessing', () => {
  const dir = scratch('noroot');
  const r = runCli(['recheck', dir], dir);
  assert.notEqual(r.status, EXIT_OK);
  assert.match(r.stderr, /--root is required/);
});

test('the counting line is printed by the link subcommand too', () => {
  const dir = scratch('countline');
  writeFileSync(join(dir, 'policy.json'), JSON.stringify(approvingPolicy()), 'utf8');
  const r = runCli(['link', '--policy', join(dir, 'policy.json'), '--', 'no-such-compiler', 'main.o', '-Wl,-M', '-o', 'app'], dir);
  assert.match(r.stdout, /^inputs=\d+ checked=\d+ skipped=\d+$/m);
});
