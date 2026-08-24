// Three properties are worth more than everything else here:
//
//   1. a claim cannot settle itself, so it cannot turn a screen green;
//   2. a claim is settled only by an artefact that is demonstrably about the
//      same source, so a token collision in an unrelated chunk cannot report a
//      removed defence as present;
//   3. and within that artefact, PRESENT is only said of an occurrence that can
//      be attributed to the claim's own region of the generated text — because
//      one chunk holds hundreds of modules and (2) says nothing about which of
//      them the hit is in.
//
// Everything below is an attempt to break one of the three.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Only the adjudicator is this package's. Claim CONSTRUCTION moved to
// `@vibeguard/findings-schema` and is tested there; the claims below are built
// by hand so this suite depends on nothing but the files it is about.
import { crossExamine } from '../src/cross-examine.mjs';
import { decodeSourceRegions } from '../src/source-map-regions.mjs';
import { observeArtefact } from '../src/bundle.mjs';

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

// ── FIXTURES ────────────────────────────────────────────────────────────────
//
// A record with regions in it cannot be written out by hand: the regions come
// from a real VLQ mapping table, and a table typed as a string literal would
// be unreadable and unmaintainable. So the fixtures below describe the
// generated text as PIECES — a run of characters and the source it came from —
// encode a real revision-3 mapping table from that, and decode it with the
// production decoder. The encoder here and the decoder there are independent,
// which is the point: a fixture that used the decoder to build its own input
// would prove nothing about either.

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Base64 VLQ, the encoding side. Deliberately not shared with `src/`. */
function vlq(n) {
  let v = n < 0 ? -n * 2 + 1 : n * 2;
  let out = '';
  do {
    let digit = v % 32;
    v = Math.floor(v / 32);
    if (v > 0) digit += 32;
    out += B64[digit];
  } while (v > 0);
  return out;
}

/**
 * One artefact record, built the way `observeArtefact` builds it.
 *
 * `pieces` are laid end to end on ONE generated line. A piece with
 * `source: -1` is generated text the map attributes to nobody — a bundler
 * runtime helper, a module wrapper — and is encoded as the one-field segment
 * revision 3 defines for exactly that.
 *
 * The shape this returns is pinned against the real `observeArtefact` by the
 * last test in this file, so the fixture cannot drift away from the thing it
 * is standing in for.
 */
function chunk(name, pieces, contents) {
  const code = pieces.map((p) => p.text).join('');
  const segments = [];
  let col = 0;
  let prevCol = 0;
  let prevSrc = 0;
  let prevLine = 0;
  let prevOrigCol = 0;
  for (const p of pieces) {
    if (p.source >= 0) {
      segments.push(vlq(col - prevCol) + vlq(p.source - prevSrc) + vlq(0 - prevLine) + vlq(0 - prevOrigCol));
      prevSrc = p.source;
      prevLine = 0;
      prevOrigCol = 0;
    } else {
      segments.push(vlq(col - prevCol));
    }
    prevCol = col;
    col += p.text.length;
  }
  const sources = contents.map((_, i) => `src/mod${i}.js`);
  const map = { version: 3, sources, sourcesContent: contents, mappings: segments.join(',') };
  return { record: recordFrom(name, code, contents, sources, map), map, code };
}

/** The half of `observeArtefact` that does not touch the filesystem. */
function recordFrom(name, code, contents, sources, map) {
  const { regions, coarse, why } = decodeSourceRegions(code, map);
  return {
    artefact: name,
    bytes: code.length,
    code,
    sidecar: contents.filter((c) => c !== null).join('\n'),
    contents,
    regions: regions ?? null,
    coarse: coarse ?? [],
    ...(regions ? {} : { regionsWhy: why }),
    sources,
    sourcesContentEntries: contents.filter((c) => typeof c === 'string').length,
    measured: true,
  };
}

/** A record with no map at all — the shape most of the older tests want. */
const artefact = (name, code, sidecar) => ({
  artefact: name,
  bytes: code.length,
  code,
  sidecar,
  measured: true,
});

const observation = (records, skipped = []) => ({
  dir: '/tmp/dist',
  skipped,
  records,
  readable: records.length,
  measured: records.filter((r) => r.measured).length,
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

/** The claimant's own module, as the map republishes it. */
const MINE = `export function deleteUser(session, targetId) {\n  ${PROBE}\n  return db.remove(targetId);\n}`;

/** Somebody else's module, in the same chunk, spelling the same token. */
const THEIRS = 'export function can(user) { return user.isAdmin && user.isActive; }';

// ── JURISDICTION: THE CROSS-CHUNK HALF ──────────────────────────────────────

test('a vendor chunk that happens to contain the witness cannot settle the claim', () => {
  // `isAdmin` is an ordinary property name and a vendor bundle is full of other
  // people's code. Before jurisdiction, this fixture reported PRESENT and the
  // user's own guard disappeared behind a green line.
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

// ── ATTRIBUTION: THE WITHIN-CHUNK HALF ──────────────────────────────────────

test('THE test: a vendor module in the SAME chunk cannot settle the claim either', () => {
  // The load-bearing case, and the one jurisdiction alone gets wrong. ONE
  // artefact, and it legitimately holds jurisdiction — its `sourcesContent`
  // carries the claim's own source, so it is unarguably the file this claim is
  // about. The claimant's guard has been minified away: nothing in the
  // generated region belonging to `src/mod0.js` says `isAdmin` any more. A
  // different module bundled into the same chunk does.
  //
  // Before region attribution this read PRESENT, off a token belonging to
  // somebody else's code, and the user's deleted authorization check was
  // reported as shipped.
  const { record } = chunk(
    'app.js',
    [
      { source: 0, text: 'function o(s,e){return db.remove(e)}' },
      { source: 1, text: 'function can(u){return u.isAdmin&&u.isActive}' },
    ],
    [MINE, THEIRS],
  );
  const settled = crossExamine([sourceClaim()], observation([record]), illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /could not be attributed to the source this claim came from/);
  assert.match(settled[0].note, /region its map gives to a different source/);
});

test('the true positive: a witness that survives in the claim\'s OWN region is PRESENT', () => {
  // Without this the change above is not an improvement, it is a channel that
  // says NOT_OBSERVED to everything. Same two modules, same chunk, same map —
  // the only difference is which region the token is in.
  const { record } = chunk(
    'app.js',
    [
      { source: 0, text: 'function o(s,e){if(!s.isAdmin)throw 0;return db.remove(e)}' },
      { source: 1, text: 'function can(u){return u.isActive}' },
    ],
    [MINE, THEIRS],
  );
  const settled = crossExamine([sourceClaim()], observation([record]), illegal);
  assert.equal(settled[0].state, 'PRESENT');
  assert.equal(settled[0].crossExaminedAt, 'artifact');
  assert.deepEqual(settled[0].history.map((h) => h.state), ['PRESENT']);
  assert.match(settled[0].note, /found in app\.js/);
});

test('a witness in generated text the map attributes to nobody is not attributed to us', () => {
  // Bundler runtime, a module wrapper, a helper esbuild synthesised: real maps
  // leave between 0.2% and 16.1% of the generated bytes unmapped in the five
  // bundles measured for `SPAN_ATTRIBUTION_CAP`. Unmapped is not ours.
  const { record } = chunk(
    'app.js',
    [
      { source: 0, text: 'function o(s,e){return db.remove(e)}' },
      { source: -1, text: 'var __helper=function(u){return u.isAdmin};' },
    ],
    [MINE, THEIRS],
  );
  const settled = crossExamine([sourceClaim()], observation([record]), illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /the map attributes to none/);
});

test('a mapping too coarse to attribute anything says so, and does not say PRESENT', () => {
  // A single segment covering more than `SPAN_ATTRIBUTION_CAP` characters is
  // the line-granular map the cap exists to reject. It names a source, and
  // believing it would rebuild the exact false PRESENT this whole mechanism
  // removes — so an occurrence inside one is unattributable, and the reason is
  // distinguishable from every other reason in this file.
  const filler = 'x'.repeat(600);
  const { record } = chunk(
    'app.js',
    [
      { source: 0, text: 'function o(s,e){return db.remove(e)}' },
      { source: 1, text: `function can(u){return u.isAdmin/*${filler}*/}` },
    ],
    [MINE, THEIRS],
  );
  const settled = crossExamine([sourceClaim()], observation([record]), illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /above the 512 at which a mapping stops attributing anything/);
});

test('a map that cannot be decoded is NOT_OBSERVED, not LOST and not PRESENT', () => {
  const { record } = chunk(
    'app.js',
    [{ source: 0, text: 'function o(s,e){if(!s.isAdmin)throw 0}' }],
    [MINE],
  );
  record.regions = null;
  record.regionsWhy = 'segment 3 of the mappings has 2 fields, and revision 3 allows 1, 4 or 5';
  const settled = crossExamine([sourceClaim()], observation([record]), illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /revision 3 allows 1, 4 or 5/);
});

test('an index map is refused end to end rather than mis-decoded', () => {
  // `sections` is a shape this decoder does not read. Reading `mappings` off it
  // — or off the nested maps, without applying their offsets — would produce
  // regions that are confidently wrong, which is worse than none.
  const code = 'function o(s,e){return db.remove(e)}function can(u){return u.isAdmin}';
  const record = recordFrom('app.js', code, [MINE, THEIRS], ['a.js', 'b.js'], {
    version: 3,
    sections: [{ offset: { line: 0, column: 0 }, map: { version: 3, sources: ['a.js'], mappings: 'AAAA' } }],
  });
  const settled = crossExamine([sourceClaim()], observation([record]), illegal);
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.match(settled[0].note, /index map/);
});

test('ABSENCE needs no attribution: a chunk with no usable map still reports LOST', () => {
  // The asymmetry, pinned. Absence over the whole chunk is sound as absence
  // over the part, so nothing added for PRESENT is allowed to narrow this. If
  // a future change makes the regions a precondition of the whole settlement,
  // this goes red — and it should, because it would mean every real build
  // without a decodable map silently stopped reporting removed defences.
  const { record } = chunk('app.js', [{ source: 0, text: 'function o(s,e){return db.remove(e)}' }], [MINE]);
  record.regions = null;
  record.regionsWhy = 'the source map has no "mappings" string';
  const settled = crossExamine([sourceClaim()], observation([record]), illegal);
  assert.equal(settled[0].state, 'REINTRODUCED');
  assert.deepEqual(settled[0].history.map((h) => h.state), ['LOST', 'REINTRODUCED']);
});

// ── THE OLDER PROPERTIES, WHICH MUST NOT HAVE MOVED ─────────────────────────

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

// ── THE NEEDLE ──────────────────────────────────────────────────────────────

test('a witness under the length floor is refused, including a whitespace one', () => {
  // `haystack.includes('')` is true for every haystack, and a witness of two
  // characters is barely better. `identifierWitness` will not produce either,
  // but this function's only falsiness test is `!claim.witness` and the next
  // claim source is a fixer ledger read off disk.
  for (const witness of ['', '   ', 'ab', '.*']) {
    const settled = crossExamine(
      [sourceClaim({ witness })],
      observation([artefact('app.js', 'anything at all', `head\n${PROBE}\ntail`)]),
      illegal,
    );
    assert.equal(settled[0].state, 'NOT_OBSERVED', `witness ${JSON.stringify(witness)}`);
    assert.match(settled[0].note, witness ? /under the 4 characters/ : /nothing that can be looked for/);
  }
});

test('the matcher is literal: a witness of regex metacharacters matches only itself', () => {
  // The day somebody swaps `includes()` for a `RegExp`, this goes red. `.*Admin`
  // as a pattern matches `s.isAdmin`; as a string it is not in that code.
  //
  // The bare `.*` was the obvious spelling and is the wrong one: `MIN_WITNESS_CHARS`
  // now answers it first, so the assertion would pass on the length floor and
  // keep passing after the matcher stopped being literal. A pin that passes for
  // the wrong reason is not a pin.
  const asRegex = chunk(
    'app.js',
    [{ source: 0, text: 'function o(s,e){if(!s.isAdmin)throw 0}' }],
    [MINE],
  ).record;
  const settled = crossExamine([sourceClaim({ witness: '.*Admin' })], observation([asRegex]), illegal);
  assert.notEqual(settled[0].state, 'PRESENT');

  // And the vacuity half: the same witness IS found when the code literally
  // contains it, so the assertion above is about literalness and not about
  // `.*Admin` being unusable as a witness.
  const asLiteral = chunk(
    'app.js',
    [{ source: 0, text: 'function o(s,e){return s[".*Admin"]}' }],
    [MINE],
  ).record;
  const found = crossExamine([sourceClaim({ witness: '.*Admin' })], observation([asLiteral]), illegal);
  assert.equal(found[0].state, 'PRESENT');
});

// ── BLINDNESS IS REPORTED, NOT SWALLOWED ────────────────────────────────────

test('when nothing was measurable, nothing is settled and the count is reported', () => {
  const settled = crossExamine(
    [sourceClaim()],
    observation([{ artefact: 'app.js', bytes: 1, code: null, sidecar: null, measured: false }]),
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
      { artefact: 'broken.js', bytes: 1, code: null, sidecar: null, measured: false },
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
  // own homework. The fixture carries real regions so the witness is genuinely
  // attributed and the run really does reach the guard — otherwise this would
  // pass on the unattributable branch and pin nothing.
  const { record } = chunk(
    'app.js',
    [{ source: 0, text: 'function o(s,e){if(!s.isAdmin)throw 0}' }],
    [MINE],
  );
  const settled = crossExamine([sourceClaim()], observation([record]), () => 'refused by the guard under test');
  assert.equal(settled[0].state, 'NOT_OBSERVED');
  assert.equal(settled[0].note, 'refused by the guard under test');
  assert.equal(settled[0].crossExaminedAt, undefined);
});

// ── JURISDICTION, THE REMAINING EDGES ───────────────────────────────────────

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

// ── THE FIXTURE IS PINNED TO THE THING IT STANDS IN FOR ─────────────────────

test('the hand-built record has the same shape observeArtefact produces', async () => {
  // Every attribution test above runs against a record this file assembled. If
  // `observeArtefact` renames a field or stops emitting one, those tests keep
  // passing against a shape that no longer exists and the suite quietly stops
  // testing the product. This is the only test here that touches a disk.
  const built = chunk(
    'app.js',
    [
      { source: 0, text: 'function o(s,e){return db.remove(e)}' },
      { source: 1, text: 'function can(u){return u.isAdmin}' },
    ],
    [MINE, THEIRS],
  );
  const dir = mkdtempSync(join(tmpdir(), 'vg-xexam-'));
  const file = join(dir, 'app.js');
  writeFileSync(file, `${built.code}\n//# sourceMappingURL=app.js.map\n`, 'utf8');
  writeFileSync(join(dir, 'app.js.map'), JSON.stringify(built.map), 'utf8');
  const real = await observeArtefact(file, 'app.js', built.code.length);
  assert.deepEqual(Object.keys(real).sort(), Object.keys(built.record).sort());
  assert.equal(real.measured, true);
  assert.deepEqual(real.regions, built.record.regions);
  assert.deepEqual(real.contents, built.record.contents);
  rmSync(dir, { recursive: true, force: true });
});
