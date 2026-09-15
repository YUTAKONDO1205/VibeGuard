/**
 * Two things about the runner that are not functions, and were not tested.
 *
 * 1. THE ORDER OF THE LAST TWO STEPS. `--write-data` writes the tracked rows;
 *    `--emit-observation` tries to express them in the schema's words and has
 *    five `die(5)` sites of its own. Those sites used to sit BEFORE the
 *    `--write-data` block, so a run that measured the whole matrix cleanly and
 *    then could not express it -- no record, a gate that did not refuse, a
 *    schema that would not load -- exited 5 with `data/` untouched and two hours
 *    of ptrace measurement thrown away. Measuring and expressing are different
 *    concerns and the second may not discard the first. That is a fact about
 *    source order, so it is asserted over the source: there is nothing to call.
 *
 * 2. `--emit-observation` WITHOUT A TOOLCHAIN PIN IS REFUSED, in the process,
 *    with an exit code. The lane used to compute its own `toolchain.digest` from
 *    a version string; now it either has the digest this tree computes or it has
 *    none, and "none" is a setup failure rather than a fallback. parseArgs dies
 *    before the runner makes a directory or looks for a compiler, so this costs
 *    one node start and needs no toolchain.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(HERE, '..', 'run-residue-tracer.mjs');
const SRC = readFileSync(RUNNER, 'utf8');

/** Where a block starts in the source, asserted to exist exactly once. */
function at(needle) {
  const first = SRC.indexOf(needle);
  assert.notEqual(first, -1, `the runner no longer contains ${JSON.stringify(needle)}`);
  assert.equal(SRC.indexOf(needle, first + 1), -1, `${JSON.stringify(needle)} appears more than once`);
  return first;
}

test('the rows are written BEFORE anything tries to express them', () => {
  const writeData = at('\n  if (args.writeData) {');
  const emit = at('\n  if (args.emitObservation) {');
  assert.ok(writeData < emit,
    'the --emit-observation block runs before --write-data again: a run that measured cleanly and could not '
    + 'express its records exits 5 and never writes the tracked rows');

  // Specifically: every exit inside the expression step is after the rows.
  const expressionDies = [
    '--emit-observation would write inside the repository',
    '--emit-observation: observation.schema.json could not be read',
    "the emitter's clean-verdict gate did not behave in both directions",
    'die(outcome.exitCode',
  ];
  for (const d of expressionDies) {
    assert.ok(at(d) > writeData, `an expression failure (${d}) can still discard the measurement`);
  }
});

test('--emit-observation without --toolchain-pin exits 5 and says why', () => {
  let status = 0;
  let stderr = '';
  try {
    execFileSync(process.execPath, [RUNNER, '--emit-observation'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr ?? '');
  }
  assert.equal(status, 5, 'a run that cannot name its toolchain was allowed to start');
  assert.match(stderr, /--emit-observation needs --toolchain-pin/);
  assert.match(stderr, /evidenceDigest\(pinnedSet/);
});

test('--toolchain-pin without --emit-observation is refused rather than quietly ignored', () => {
  let status = 0;
  let stderr = '';
  try {
    execFileSync(process.execPath, [RUNNER, '--toolchain-pin', 'toolchain.pin'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    status = e.status;
    stderr = String(e.stderr ?? '');
  }
  assert.equal(status, 5);
  assert.match(stderr, /--toolchain-pin without --emit-observation/);
});

test('the two kinds of outcome are written to two different files', () => {
  // A deliberate refusal and an apparatus failure do not share a file any more
  // than they share an exit code.
  assert.ok(SRC.includes("join(OBSDIR, 'refusals.json')"));
  assert.ok(SRC.includes("join(OBSDIR, 'failures.json')"),
    'the apparatus failures are not written anywhere of their own');
  assert.ok(SRC.includes('observationOutcome(all)'),
    'the runner no longer takes its exit from the outcome function that separates them');
});
