/**
 * Static fence for catalogue.json.
 *
 * check-meta.py already enforces most of these, but only against a DOCUMENT: it
 * needs a run to have happened. A catalogue edited into an inconsistent state
 * therefore stays green until someone measures, and the person who measures is not
 * usually the person who edited. These assertions need no compiler, no lab and no
 * document, so a bad edit fails before it can be measured against.
 *
 * Nothing here is a measurement. It reads one tracked file.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CATALOGUE = JSON.parse(readFileSync(path.join(HERE, '..', 'catalogue.json'), 'utf8'));
const OPS = CATALOGUE.operators;

/** interfaces.md section 3, and there is deliberately no seventh. */
const STATES = ['PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED'];
const CLASSES = ['R1', 'R1-spelling', 'R2a', 'R2b', 'R2c', 'R2-spelling'];
const SHAPES = ['wipe', 'guarded', 'forbidden', 'dominance'];

test('the catalogue declares operators at all -- an empty one fences nothing', () => {
  assert.ok(Array.isArray(OPS) && OPS.length >= 15,
    `catalogue.json declares ${OPS?.length ?? 0} operator(s); 21 were declared when this fence was `
    + 'written. A catalogue that has emptied out would make every assertion below pass vacuously.');
});

test('every operator has a known shape and a known class', () => {
  for (const op of OPS) {
    assert.ok(SHAPES.includes(op.shape), `${op.operatorId}: shape ${JSON.stringify(op.shape)}`);
    assert.ok(CLASSES.includes(op.class), `${op.operatorId}: class ${JSON.stringify(op.class)}`);
    assert.ok(typeof op.operatorId === 'string' && op.operatorId.length > 0);
  }
});

test('operator ids are unique', () => {
  const seen = new Map();
  for (const op of OPS) {
    assert.ok(!seen.has(op.operatorId), `${op.operatorId} is declared twice`);
    seen.set(op.operatorId, true);
  }
});

test('a declared direction is INVARIANT or an X->Y over the six states, and nothing else', () => {
  for (const op of OPS) {
    const d = op.declaredDirection;
    if (d === 'INVARIANT') {
      assert.ok(op.class.startsWith('R1'),
        `${op.operatorId}: only an R1 class may be INVARIANT; this is ${op.class}`);
      continue;
    }
    const m = /^([A-Z_]+)->([A-Z_]+)$/.exec(d || '');
    assert.ok(m, `${op.operatorId}: declaredDirection ${JSON.stringify(d)} is neither INVARIANT nor X->Y`);
    for (const word of [m[1], m[2]]) {
      assert.ok(STATES.includes(word),
        `${op.operatorId}: ${word} is not one of interfaces.md section 3's six states`);
    }
    assert.ok(op.class.startsWith('R2'),
      `${op.operatorId}: a moving edge belongs to an R2 class; this is ${op.class}`);
  }
});

test('R2c is the named non-monotonic class: it ends on NOT_APPLICABLE and says so', () => {
  // The whole reason there is no total order on the six states. Grading an R2c cell
  // as a loss would report a lost REFERENT as a lost PROPERTY, in the direction that
  // looks like a result.
  const r2c = OPS.filter((o) => o.class === 'R2c');
  assert.ok(r2c.length > 0, 'no R2c operator is declared; the referent-removing class is the one '
    + 'that must exist for the survival axis to be shown NOT to be a total order');
  for (const op of r2c) {
    assert.match(op.declaredDirection, /->NOT_APPLICABLE$/,
      `${op.operatorId}: an R2c edge must end on NOT_APPLICABLE`);
    assert.ok(typeof op.notMonotonicWhen === 'string' && op.notMonotonicWhen.length > 0,
      `${op.operatorId}: R2c must carry notMonotonicWhen where a reader will see it`);
  }
});

test('gradeOn is an opt-in, is spelled from the fixed set, and is never on R2b or R2c', () => {
  // The mistake this pins: gradeOn was first INFERRED from checkpointRead, which R2b
  // and R2c operators also set to a single checkpoint to document where their loss
  // becomes visible. That collapsed their PRESENT->LOST and PRESENT->NOT_APPLICABLE
  // edges into PRESENT/ABSENT and sent five correct cells off-axis. One checkpoint
  // can say PRESENT or ABSENT and cannot say either of those two words.
  const allowed = ['count-at-pre-opt-ir', 'count-at-after-pass'];
  const withGradeOn = OPS.filter((o) => o.gradeOn !== undefined);
  for (const op of withGradeOn) {
    assert.ok(allowed.includes(op.gradeOn),
      `${op.operatorId}: gradeOn ${JSON.stringify(op.gradeOn)} is not one of ${allowed.join('/')}`);
    assert.ok(!['R2b', 'R2c'].includes(op.class),
      `${op.operatorId}: gradeOn on a class ${op.class} operator. Its edge is a claim about a `
      + 'change BETWEEN checkpoints and is unreachable from one.');
    assert.ok(typeof op.whyGradeOn === 'string' && op.whyGradeOn.length > 40,
      `${op.operatorId}: gradeOn must carry whyGradeOn -- an opt-in with no argument is a switch`);
  }
});

test('no operator is exempt from grading without a stated reason', () => {
  // `graded: false` is an off switch with no condition on it: nothing about such a
  // cell can ever be falsified again. One operator shipped that way and was
  // converted to an explicit gradeOn instead.
  //
  // A SHORT reason is allowed when it is a cross-reference that RESOLVES. The two
  // dominance operators say "No extractor. See lanes.dominance." and that is a
  // complete argument -- but only while the lane it points at exists and still says
  // it is unmeasured. A demand for length alone would have pushed the same sentence
  // into two places to satisfy a character count; what matters is that the pointer
  // is not dangling.
  const lanes = CATALOGUE.lanes || [];
  const unmeasuredLane = (shape) => lanes.find(
    (l) => l.shape === shape && typeof l.status === 'string' && l.status !== 'MEASURED',
  );
  for (const op of OPS) {
    if (op.graded === false) {
      const why = typeof op.whyUngraded === 'string' ? op.whyUngraded : '';
      assert.ok(why.length > 0, `${op.operatorId}: graded:false with no whyUngraded at all. An `
        + 'operator nothing can falsify needs an argument, not a flag.');
      if (why.length <= 80) {
        const lane = unmeasuredLane(op.shape);
        assert.ok(lane, `${op.operatorId}: whyUngraded is a short cross-reference (${JSON.stringify(why)}) `
          + `and there is no lane for shape ${JSON.stringify(op.shape)} declaring a non-MEASURED `
          + 'status to carry the argument. A dangling "see X" is a flag with a footnote.');
        assert.ok(typeof lane.statusReason === 'string' && lane.statusReason.length > 40,
          `${op.operatorId}: the ${op.shape} lane it defers to carries no substantial statusReason`);
        assert.ok(/[a-z]+\.[a-z-]+/.test(lane.propertyId || lane.statusReason),
          `${op.operatorId}: the ${op.shape} lane must name the property whose extractor is null, `
          + 'so the absence is traceable rather than asserted');
      }
    } else {
      assert.equal(op.graded, true, `${op.operatorId}: graded must be an explicit boolean`);
    }
  }
});

test('every measured shape carries both an R1 falsifier and an R2 mover', () => {
  // A lane with R2 operators and no R1 operator can report movement it cannot
  // attribute: something moved, and nothing shows it was the property rather than
  // the spelling, the position or a neighbouring function.
  const measured = new Set(OPS.filter((o) => o.shape !== 'dominance').map((o) => o.shape));
  for (const shape of measured) {
    const classes = OPS.filter((o) => o.shape === shape).map((o) => o.class);
    assert.ok(classes.some((c) => c.startsWith('R1')),
      `shape ${shape} has no R1 operator, so any movement it reports is unattributable`);
    assert.ok(classes.some((c) => c.startsWith('R2')),
      `shape ${shape} has no R2 operator, so its R1 invariance is over a relation nothing moves`);
  }
});

test('the dominance shape is declared and deliberately unmeasured', () => {
  const dom = OPS.filter((o) => o.shape === 'dominance');
  assert.ok(dom.length > 0,
    'the dominance operators must be DECLARED even though nothing measures them: a shape absent '
    + 'from the catalogue reads as one nobody thought about, which is a different claim from one '
    + 'with no extractor.');
  const lane = (CATALOGUE.lanes || []).find((l) => l.shape === 'dominance')
    || (CATALOGUE.deferred || {});
  assert.ok(JSON.stringify(lane).includes('survive.input-validation'),
    'the dominance lane must name the property whose extractor is null '
    + '(compiler/schema/properties.json, survive.input-validation), so the absence is traceable '
    + 'to the catalogue that records it rather than being folk knowledge.');
});

test('the instrument-limit boundary is stated: H breaks the property, the battery measures the probe', () => {
  // Without this line in the catalogue, the two lanes drift into each other and R2
  // silently acquires mutations that defeat the extractor without touching the
  // property -- which would make every off-axis-landing ambiguous.
  const text = JSON.stringify(CATALOGUE);
  assert.ok(/instrument|calibration/i.test(text),
    'the catalogue must state the division of labour with the calibration lane somewhere a reader '
    + 'will find it');
});
