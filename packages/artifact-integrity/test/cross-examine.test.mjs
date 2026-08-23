// The one property worth more than all the others here: a claim cannot settle
// itself, and therefore cannot turn a screen green. Everything else in this
// file is a way of trying to break that.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  CLAIM_BEARING_RULES,
  identifierWitness,
  claimsFromFindings,
  claimsFromAssistantProse,
  crossExamine,
} from '../src/cross-examine.mjs';

/**
 * The transition guard, restated here rather than imported.
 *
 * `@vibeguard/findings-schema` is a TypeScript package that this plain-ESM one
 * does not depend on, which is why `crossExamine` takes the guard as an
 * argument. Restating it means this file tests the CONTRACT — if the real one
 * ever weakens, the mismatch shows up as this suite passing while the CLI
 * misbehaves, which is why `crossExamine` is also given a deliberately broken
 * guard below and must still refuse.
 */
const illegal = (claim, observedAt, next) => {
  if (next === 'NOT_OBSERVED') return null;
  if (observedAt === claim.claimantLayer) {
    return `a claim made at layer "${claim.claimantLayer}" cannot be settled by an observation at the same layer`;
  }
  return null;
};

const observationWith = (witnesses) => ({
  dir: '/tmp/dist',
  skipped: [],
  records: [{ artefact: 'app.js', bytes: 100, state: 'PRESENT', controlHeld: true, witnesses }],
});

test('every claim-bearing rule is one whose finding asserts a protection EXISTS', () => {
  // A finding that says "this code is dangerous" is not a claim that a
  // protection is present, and its disappearance from the artefact would be
  // good news reported as a failure. The list is small and deliberate.
  for (const id of Object.keys(CLAIM_BEARING_RULES)) {
    assert.match(id, /^VG-(AUTH|MEM)-\d{3}$/, `${id} is not an auth/memory protection rule`);
  }
});

test('identifierWitness skips language and environment names', () => {
  assert.equal(identifierWitness("if (process.env.NODE_ENV !== 'production') { … }"), null);
  assert.equal(identifierWitness("if (…) { … session.isAdmin … }"), 'isAdmin');
  assert.equal(identifierWitness('assert hasPermission'), 'hasPermission');
});

test('claims are born NOT_OBSERVED — unconditionally', () => {
  const claims = claimsFromFindings([
    { ruleId: 'VG-AUTH-009', snippet: 'if (dev) { if (!s.isAdmin) throw }', filePath: 'a.js', startLine: 3 },
    { ruleId: 'VG-AUTH-010', evidence: ['console.assert(s.hasPermission)'], filePath: 'a.js' },
    { ruleId: 'VG-INJ-001', snippet: 'db.query("SELECT " + x)', filePath: 'a.js' },
  ]);
  // The injection finding is not a protection claim and must not appear.
  assert.equal(claims.length, 2);
  assert.ok(claims.every((c) => c.state === 'NOT_OBSERVED'));
  assert.ok(claims.every((c) => c.crossExaminedAt === undefined));
  assert.ok(claims.every((c) => c.claimantLayer === 'source'));
});

test('a claim with no extractable witness stays NOT_OBSERVED and says why', () => {
  const claims = claimsFromFindings([
    { ruleId: 'VG-AUTH-009', snippet: "if (process.env.NODE_ENV !== 'production') { }" },
  ]);
  assert.equal(claims[0].witness, undefined);
  const settled = crossExamine(claims, observationWith([]), illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /nothing that can be looked for/);
});

test('an artefact observation settles a source claim three ways', () => {
  const claims = claimsFromFindings([
    { ruleId: 'VG-AUTH-009', snippet: 'if (dev) { !s.isAdmin }' },
    { ruleId: 'VG-AUTH-010', snippet: 'console.assert(s.hasPermission)' },
    { ruleId: 'VG-AUTH-008', snippet: 'assert(is_authorized(u))' },
  ]);
  const settled = crossExamine(
    claims,
    observationWith([
      { witness: 'isAdmin', state: 'PRESENT', inCode: true, inSidecar: true },
      { witness: 'hasPermission', state: 'REINTRODUCED', inCode: false, inSidecar: true },
      { witness: 'is_authorized', state: 'ABSENT', inCode: false, inSidecar: false },
    ]),
    illegal,
  );
  const by = Object.fromEntries(settled.map((c) => [c.witness, c.state]));
  assert.equal(by.isAdmin, 'PRESENT');
  assert.equal(by.hasPermission, 'REINTRODUCED');
  assert.equal(by.is_authorized, 'LOST');
  assert.ok(settled.every((c) => c.crossExaminedAt === 'artifact' || c.crossExaminedAt === 'sidecar'));
});

test('no artefact held its control, so nothing is settled', () => {
  const claims = claimsFromFindings([{ ruleId: 'VG-AUTH-009', snippet: 'if (dev) { !s.isAdmin }' }]);
  const blind = {
    dir: '/tmp/dist',
    skipped: [],
    records: [{ artefact: 'app.js', bytes: 1, state: 'NOT_OBSERVED', controlHeld: false, witnesses: [] }],
  };
  const settled = crossExamine(claims, blind, illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /live control/);
});

test('assistant prose becomes claims, and every one of them is NOT_OBSERVED', () => {
  const prose = [
    'I added an authorization check so only admins can delete accounts.',
    'The isAdmin flag is now validated before db.remove runs.',
    'I also renamed a variable for clarity.',
  ].join('\n');
  const claims = claimsFromAssistantProse(prose, { filePath: 'a.js' });
  assert.ok(claims.length >= 1, 'the prose fixture must produce at least one claim');
  assert.ok(claims.every((c) => c.claimantLayer === 'assistant'));
  // THE property. An assistant may add work; it may not discharge it.
  assert.ok(claims.every((c) => c.state === 'NOT_OBSERVED'));
  assert.ok(claims.every((c) => c.crossExaminedAt === undefined));
});

test('an assistant claim is settled by the artefact, not by the assistant', () => {
  const claims = claimsFromAssistantProse('I added an authorization check on isAdmin before deleting.');
  assert.equal(claims.length, 1);
  const settled = crossExamine(
    claims,
    observationWith([{ witness: claims[0].witness, state: 'ABSENT', inCode: false, inSidecar: false }]),
    illegal,
  );
  assert.equal(settled[0].state, 'LOST');
  assert.equal(settled[0].crossExaminedAt, 'artifact');
});

test('a guard that permits self-settlement is refused by crossExamine anyway', () => {
  // The day somebody adds an artefact-layer claimant, or weakens the guard,
  // this is the line that keeps the party under examination from grading its
  // own homework. `crossExamine` must honour whatever the guard returns.
  const alwaysIllegal = () => 'refused by the guard under test';
  const claims = claimsFromFindings([{ ruleId: 'VG-AUTH-009', snippet: 'if (dev) { !s.isAdmin }' }]);
  const settled = crossExamine(
    claims,
    observationWith([{ witness: 'isAdmin', state: 'PRESENT', inCode: true, inSidecar: true }]),
    alwaysIllegal,
  );
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.equal(settled[0].note, 'refused by the guard under test');
  assert.equal(settled[0].crossExaminedAt, undefined);
});

test('vacuity guard: the fixtures above really do produce witnesses', () => {
  const claims = claimsFromFindings([
    { ruleId: 'VG-AUTH-009', snippet: 'if (dev) { !s.isAdmin }' },
  ]);
  // Without this, every "settled three ways" assertion could be passing over
  // claims that carry no witness and were never looked up at all.
  assert.equal(claims[0].witness, 'isAdmin');
});
