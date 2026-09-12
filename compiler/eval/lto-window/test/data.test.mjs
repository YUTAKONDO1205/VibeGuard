// The tracked records of the intervention pair, pinned to what was measured.
//
// WHY THIS FILE EXISTS
//
// Until 2026-09-12 this lane wrote nothing into the checkout. Its results lived
// in a lab directory outside the repository and the only record of what it had
// measured was prose in README.md. A reviewer asking "show me the run" for the
// version ladder gets data/version-ladder-sweep.json with its anchor counts and
// its resolved compiler digests; asking the same of this lane got a paragraph.
//
// `--write-pair` keeps the half that does not rebuild by itself: the attribution
// WITH the intervention, the reading WITHOUT it, and the verdict comparing them,
// one file per optimisation level. The fifteen cells with their guards and pass
// logs stay in the lab, and the record says so in `fullResult.tracked: false`.
//
// These pins are the point of keeping them at all. The pair verdict at -O2, -O3
// and -Os is CONTRADICTED -- the lane reporting against its own expectation --
// and a record whose numbers are free to move is not evidence of that or of
// anything else.

import { strict as assert } from 'node:assert';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = join(HERE, '..', 'data');
const LEVELS = ['O1', 'O2', 'O3', 'Os'];
const load = (l) => JSON.parse(readFileSync(join(DATA, `intervention-pair${l}.json`), 'utf8'));

test('all four levels were recorded, and nothing else is in data/', () => {
  const files = readdirSync(DATA).filter((f) => f.endsWith('.json')).sort();
  assert.deepEqual(files, LEVELS.map((l) => `intervention-pair${l}.json`).sort());
});

test('each record says which level it is, and carries no machine path', () => {
  for (const l of LEVELS) {
    const text = readFileSync(join(DATA, `intervention-pair${l}.json`), 'utf8');
    assert.deepEqual(absolutePathHits(text), [], `${l} carries an absolute path`);
    const d = JSON.parse(text);
    assert.equal(d.optLevel, `-${l}`);
    assert.equal(d.fullResult.tracked, false, 'the 15-cell result must stay a lab artefact');
    assert.equal(d.fullResult.cells, 15);
    // the toolchain the numbers belong to, so a later disagreement is readable
    assert.match(d.toolchain.cc, /clang/);
    assert.ok(d.plugin, `${l} does not say which observer produced it`);
  }
});

test('the intervened family attributes a pass at -O2, -O3 and -Os, and at -O1 it does not', () => {
  for (const l of ['O2', 'O3', 'Os']) {
    const d = load(l);
    const cell = d.cells.find((c) => c && c.id === 'xtu.full.link');
    assert.equal(cell.measurement, 'OK', l);
    assert.equal(cell.state, 'LOST', l);
    assert.deepEqual(
      { pass: cell.attribution.pass, unit: cell.attribution.unit },
      { pass: 'DSEPass', unit: 'handle' }, l,
    );
  }
  // -O1 is the level where the WITH side produces nothing, so the pair has
  // nothing to be about. Recorded rather than omitted.
  const one = load('O1');
  const cell = one.cells.find((c) => c && c.id === 'xtu.full.link');
  assert.equal(cell.state, 'ABSENT');
  assert.equal(cell.attribution, null);
});

test('the pair verdict is CONTRADICTED above -O1 and NOT ESTABLISHED at -O1', () => {
  for (const l of ['O2', 'O3', 'Os']) {
    const p = load(l).interventionPairs[0];
    // `false` and `null` are DIFFERENT verdicts and the distinction is the
    // whole reason this record is worth keeping: false is CONTRADICTED (the
    // pair was measured and the claim's second half fell), null is NOT
    // ESTABLISHED (there was nothing to compare). Collapsing them would let a
    // level that produced no attribution read as a level that refuted one.
    assert.equal(p.verdict.supported, false, `${l}: expected CONTRADICTED (false)`);
    assert.equal(p.readingWithoutIntervention.reading, 'unit-survived-attribution-still-possible', l);
    assert.match(p.verdict.why, /contradicted/, l);
  }
  const p1 = load('O1').interventionPairs[0];
  assert.equal(p1.verdict.supported, null, '-O1 must be NOT ESTABLISHED (null), not CONTRADICTED (false)');
  assert.match(p1.verdict.why, /no \(pass, unit\) attribution|nothing for the pair to be about/i);
});

test('the negative control ran for every family in every record', () => {
  for (const l of LEVELS) {
    const nc = load(l).negativeControl;
    assert.deepEqual(Object.keys(nc).sort(), ['erasure', 'xtu', 'xtu-inline']);
    for (const [name, rec] of Object.entries(nc)) {
      assert.ok(rec, `${l}/${name} has no negative-control record`);
    }
  }
});

test('the non-invasiveness check passed on every recorded link cell', () => {
  // Every clang/full/link cell in these records compared stock against observed
  // and found them identical. If one ever comes back false or null, the record
  // is of a run whose observer changed the program it was observing.
  for (const l of LEVELS) {
    for (const c of load(l).cells) {
      if (!c || !c.id.endsWith('.full.link')) continue;
      assert.equal(c.byteIdentical, true, `${l} ${c.id}: byteIdentical ${JSON.stringify(c.byteIdentical)}`);
    }
  }
});
