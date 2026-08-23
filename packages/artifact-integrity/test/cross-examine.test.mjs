// Two properties are worth more than everything else here:
//
//   1. a claim cannot settle itself, so it cannot turn a screen green;
//   2. a claim is settled only by an artefact that is demonstrably about the
//      same source, so a token collision in an unrelated chunk cannot report a
//      removed defence as present.
//
// Everything below is an attempt to break one of the two.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Only the adjudicator is this package's. Claim CONSTRUCTION moved to
// `@vibeguard/findings-schema` and is tested there; the claims below are built
// by hand so this suite depends on nothing but the file it is about.
import { crossExamine } from '../src/cross-examine.mjs';

/**
 * The transition guard, restated rather than imported.
 *
 * `@vibeguard/findings-schema` is a TypeScript package this plain-ESM one does
 * not depend on, which is why `crossExamine` takes the guard as an argument.
 */
const illegal = (claim, observedAt, next) => {
  if (next === 'NOT_OBSERVED') return null;
  if (observedAt === claim.claimantLayer) {
    return `a claim made at layer "${claim.claimantLayer}" cannot be settled by an observation at the same layer`;
  }
  return null;
};

/** The source line every fixture claim is about. Long enough to be a probe. */
const PROBE = 'if (!session.isAdmin) throw new Error("forbidden");';

const artefact = (name, code, sidecar) => ({
  artefact: name,
  bytes: code.length,
  code,
  sidecar,
  controlHeld: true,
});

const observation = (records, skipped = []) => ({
  dir: '/tmp/dist',
  skipped,
  records,
  readable: records.length,
  controlHeld: records.filter((r) => r.controlHeld).length,
});

const sourceClaim = (over = {}) => ({
  id: 'c1',
  claimant: 'VG-AUTH-009',
  claimantLayer: 'source',
  subject: 'an authorization check that only runs in development',
  witness: 'isAdmin',
  sourceProbe: PROBE,
  filePath: 'src/app.js',
  state: 'NOT_OBSERVED',
  ...over,
});

test('a vendor chunk that happens to contain the witness cannot settle the claim', () => {
  // THE test. `isAdmin` is an ordinary property name and a vendor bundle is
  // full of other people's code. Before jurisdiction, this fixture reported
  // PRESENT and the user's own guard disappeared behind a green line.
  const settled = crossExamine(
    [sourceClaim()],
    observation([
      // The artefact that really is about this source: the guard is gone from
      // the code and still published in the map.
      artefact('app.js', 'function o(s,e){return db.remove(e)}', `x\n${PROBE}\ny`),
      // An unrelated chunk that mentions isAdmin and knows nothing of this file.
      artefact('vendor.js', 'export function can(u){return u.isAdmin}', 'export function can(u){return u.isAdmin}'),
    ]),
    illegal,
  );
  assert.equal(settled[0].state, 'REINTRODUCED');
  assert.match(settled[0].note, /still published in the source map/);
});

test('a stale source map from an earlier build cannot settle the claim', () => {
  // Content, not timestamps: a map written before this line existed does not
  // contain it, so it is not about this claim. No mtime comparison anywhere.
  const settled = crossExamine(
    [sourceClaim()],
    observation([artefact('app.js', 'function o(){}', 'function older(){ return 1 } // nothing about the guard')]),
    illegal,
  );
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /none of them is about this claim/);
});

test('present in the code of the artefact that carries the source', () => {
  const settled = crossExamine(
    [sourceClaim()],
    observation([artefact('app.js', 'function o(s){if(!s.isAdmin)throw 0}', `head\n${PROBE}\ntail`)]),
    illegal,
  );
  assert.equal(settled[0].state, 'PRESENT');
  assert.equal(settled[0].crossExaminedAt, 'artifact');
  assert.deepEqual(settled[0].history.map((h) => h.state), ['PRESENT']);
});

test('absent from both halves of the jurisdiction artefact is LOST, and only there', () => {
  const settled = crossExamine(
    [sourceClaim({ witness: 'neverAppears' })],
    observation([artefact('app.js', 'function o(){}', `head\n${PROBE}\ntail`)]),
    illegal,
  );
  assert.equal(settled[0].state, 'LOST');
  assert.match(settled[0].note, /which is the artefact that carries this source/);
});

test('REINTRODUCED is recorded with the loss in front of it', () => {
  // `evidence-bundle/states.mjs`: REINTRODUCED means PRESENT again after being
  // LOST, and a record that asserts it with no preceding loss is malformed.
  const settled = crossExamine(
    [sourceClaim()],
    observation([artefact('app.js', 'function o(s,e){return e}', `head\n${PROBE}\ntail`)]),
    illegal,
  );
  assert.deepEqual(settled[0].history.map((h) => h.state), ['LOST', 'REINTRODUCED']);
  assert.equal(settled[0].state, 'REINTRODUCED');
});

test('a probe too short to identify anything is refused rather than guessed', () => {
  const settled = crossExamine(
    [sourceClaim({ sourceProbe: 'throw 0;' })],
    observation([artefact('app.js', 'throw 0;', 'throw 0;')]),
    illegal,
  );
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /below the 20 needed/);
});

test('a claim with no probe cannot be settled, however good its witness is', () => {
  const settled = crossExamine(
    [sourceClaim({ sourceProbe: undefined })],
    observation([artefact('app.js', 'x.isAdmin', 'x.isAdmin')]),
    illegal,
  );
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /no source text/);
});

test('a claim with no witness cannot be settled either', () => {
  const settled = crossExamine([sourceClaim({ witness: undefined })], observation([]), illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /nothing that can be looked for/);
});

test('when nothing was measurable, nothing is settled and the count is reported', () => {
  const settled = crossExamine(
    [sourceClaim()],
    observation([{ artefact: 'app.js', bytes: 1, code: null, sidecar: null, controlHeld: false }]),
    illegal,
  );
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /1 read, none passed its controls/);
});

test('a LOST verdict says how many artefacts could not be measured', () => {
  // b-4: a confident LOST alongside unmeasured artefacts is a partial view
  // presented as a whole one. The verdict stands — it is scoped to the
  // jurisdiction artefact — but the reader is told what was not looked at.
  const settled = crossExamine(
    [sourceClaim({ witness: 'neverAppears' })],
    observation([
      artefact('app.js', 'function o(){}', `head\n${PROBE}\ntail`),
      { artefact: 'broken.js', bytes: 1, code: null, sidecar: null, controlHeld: false },
    ]),
    illegal,
  );
  assert.equal(settled[0].state, 'LOST');
  assert.match(settled[0].note, /1 artefact\(s\) could not be measured/);
});

test('CRLF on one side and LF on the other still finds the jurisdiction', () => {
  const settled = crossExamine(
    [sourceClaim({ sourceProbe: PROBE.replace(/ /g, ' ') })],
    observation([artefact('app.js', 'function o(){}', `head\r\n${PROBE}\r\ntail`)]),
    illegal,
  );
  assert.notEqual(settled[0].state, 'NOT_OBSERVED');
});

// ── SELF-SETTLEMENT ─────────────────────────────────────────────────────────

test('an assistant claim is settled by the artefact, never by the assistant', () => {
  const claims = [sourceClaim({ id: 'a1', claimant: 'assistant', claimantLayer: 'assistant',
    subject: 'I added an authorization check on session.isAdmin before deleting.' })];
  const settled = crossExamine(
    claims,
    observation([artefact('app.js', 'function o(s,e){return e}', `head\n${PROBE}\ntail`)]),
    illegal,
  );
  assert.notEqual(settled[0].state, 'NOT_OBSERVED');
  assert.equal(settled[0].crossExaminedAt, 'sidecar');
});

test('a guard that refuses is honoured, whatever the observation said', () => {
  // The day somebody adds an artefact-layer claimant, or weakens the guard,
  // this is the line that keeps the party under examination from grading its
  // own homework.
  const settled = crossExamine(
    [sourceClaim()],
    observation([artefact('app.js', 'x.isAdmin', `head\n${PROBE}\ntail`)]),
    () => 'refused by the guard under test',
  );
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.equal(settled[0].note, 'refused by the guard under test');
  assert.equal(settled[0].crossExaminedAt, undefined);
});

test('a probe common enough to match many artefacts identifies none of them', () => {
  // Length is not identity, and MIN_PROBE_CHARS only buys length. Measured on
  // this repository's corpus: VG-AUTH-009's probe is
  // `if (process.env.NODE_ENV !== 'production') {` — 44 characters, and one of
  // the most common lines in the ecosystem. Without this guard it hands
  // jurisdiction to whichever chunk happens to carry it.
  const common = "if (process.env.NODE_ENV !== 'production') {";
  const settled = crossExamine(
    [sourceClaim({ sourceProbe: common, filePath: undefined })],
    observation([
      artefact('a.js', 'x.isAdmin', common),
      artefact('b.js', 'y', common),
      artefact('c.js', 'z', common),
      artefact('d.js', 'w', common),
    ]),
    illegal,
  );
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /does not identify one of them/);
});

test('the source file narrows jurisdiction when the map names its sources', () => {
  // A tie-break on the basename, never the primary test: bundlers rewrite these
  // paths, so a miss must leave the wider set rather than empty it.
  const common = "if (process.env.NODE_ENV !== 'production') {";
  const mine = { ...artefact('app.js', 'function o(){}', common), sources: ['src/app.js'] };
  const theirs = { ...artefact('vendor.js', 'u.isAdmin', common), sources: ['node_modules/react/index.js'] };
  const settled = crossExamine(
    [sourceClaim({ sourceProbe: common, filePath: 'src/app.js', witness: 'isAdmin' })],
    observation([mine, theirs]),
    illegal,
  );
  // The vendor chunk carries the witness. Narrowing keeps it out, so the
  // verdict is the true one: gone from the artefact that holds this source.
  assert.equal(settled[0].state, 'LOST');
});

test('a basename that matches nothing leaves the jurisdiction as it was', () => {
  const common = "if (process.env.NODE_ENV !== 'production') {";
  const a = { ...artefact('app.js', 'function o(){}', common), sources: ['webpack:///./weird.ts'] };
  const settled = crossExamine(
    [sourceClaim({ sourceProbe: common, filePath: 'src/app.js', witness: 'neverAppears' })],
    observation([a]),
    illegal,
  );
  assert.equal(settled[0].state, 'LOST');
});
