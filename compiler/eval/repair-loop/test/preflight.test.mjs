/**
 * The preflight's refusal checks: held only when both refusals were observed,
 * and every other observation is a named problem, never a silent pass.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { preflightProblems } from '../lib/preflight.mjs';

test('both refusals observed: held', () => {
  assert.deepEqual(preflightProblems({ noRecordWithoutTarget: true, noRecordWithoutOut: 'stderr-nonempty' }), []);
});

test('a record written without a target is a problem', () => {
  assert.deepEqual(preflightProblems({ noRecordWithoutTarget: false, noRecordWithoutOut: 'stderr-nonempty' }),
    ['a record was written although no target was given']);
});

test('a silent refusal, or a build an unconfigured plugin broke, is a problem', () => {
  assert.match(preflightProblems({ noRecordWithoutTarget: true, noRecordWithoutOut: 'stderr-empty' })[0], /silent/);
  assert.match(preflightProblems({ noRecordWithoutTarget: true, noRecordWithoutOut: 'compile-failed' })[0], /compile failed/);
});

test('a check that did not run is never a pass', () => {
  assert.equal(preflightProblems({ noRecordWithoutTarget: null, noRecordWithoutOut: null }).length, 2);
  assert.equal(preflightProblems({}).length, 2);
  assert.equal(preflightProblems(null).length, 2);
  assert.match(preflightProblems({ noRecordWithoutTarget: true, noRecordWithoutOut: 'something-else' })[0], /did not run/);
});

test('both failures are listed together', () => {
  assert.equal(preflightProblems({ noRecordWithoutTarget: false, noRecordWithoutOut: 'stderr-empty' }).length, 2);
});
