/**
 * Tests for lib/spike.mjs.
 *
 * No compiler is needed and none is used: every reading below is a literal, so
 * what these pin is the grading rule and nothing else. That is the part other
 * harnesses import and must not see change underneath them.
 *
 * They are written in BOTH directions on purpose. A gate tested only on the
 * readings that should pass is a gate nobody has watched refuse, and this lane's
 * whole argument is that a check which has never been shown to go red has not
 * been shown to work.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { gradeSpike, gradeInjected, gateVerdict, SPIKES, NOT_A_READING, VIOLATION } from '../lib/spike.mjs';

const EXPECTED = { disappearing: 'WIPE_ELIMINATED', surviving: 'WIPE_SURVIVED' };

const good = () => ([
  { spike: 'disappearing', verdict: 'WIPE_ELIMINATED', control: 'PRESENT' },
  { spike: 'surviving', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
]);

// What the claims file registers at -O0 on BOTH vendors, and what the instrument
// reads there: one word, twice. The pair is real and the readings are right --
// and they are also exactly what an instrument that can only ever say
// WIPE_SURVIVED would produce.
const EXPECTED_O0 = { disappearing: 'WIPE_SURVIVED', surviving: 'WIPE_SURVIVED' };

const goodAtO0 = () => ([
  { spike: 'disappearing', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
  { spike: 'surviving', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
]);

// ------------------------------------------------------------------ green ---

test('the registered pair recovers 2/2 and holds', () => {
  const g = gradeSpike(good(), EXPECTED);
  assert.equal(g.recovery, '2/2');
  assert.deepEqual(g.recovered, { num: 2, den: 2 });
  assert.equal(g.held, true);
  assert.deepEqual(g.violations, []);
});

test('order does not matter: the pair is matched by name', () => {
  const g = gradeSpike(good().reverse(), EXPECTED);
  assert.equal(g.held, true);
});

test('recovery is a ratio of integers, never a float', () => {
  const g = gradeSpike(good(), EXPECTED);
  assert.equal(Number.isInteger(g.recovered.num), true);
  assert.equal(Number.isInteger(g.recovered.den), true);
});

// -------------------------------------------------------------------- red ---

test('a spike that did not compile is FAILED, never held -- the vacuous pass', () => {
  for (const word of NOT_A_READING) {
    const g = gradeSpike([
      { spike: 'disappearing', verdict: word, control: 'PRESENT' },
      { spike: 'surviving', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
    ], EXPECTED);
    assert.equal(g.held, false, `${word} must not hold`);
    assert.equal(g.recovery, '1/2');
    assert.equal(g.violations[0].code, VIOLATION.NOT_A_READING);
    assert.equal(g.violations[0].got, word);
  }
});

test('a failure word cannot be smuggled in as the registered answer', () => {
  const g = gradeSpike([
    { spike: 'disappearing', verdict: 'COMPILE_ERROR', control: 'PRESENT' },
    { spike: 'surviving', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
  ], { disappearing: 'COMPILE_ERROR', surviving: 'WIPE_SURVIVED' });
  assert.equal(g.held, false);
  assert.equal(g.violations[0].code, VIOLATION.MALFORMED_EXPECTATION);
});

test('an unregistered configuration recovers nothing', () => {
  for (const expected of [null, undefined, {}, { disappearing: 'WIPE_ELIMINATED' }]) {
    const g = gradeSpike(good(), expected);
    assert.equal(g.held, false);
    assert.equal(g.violations.some((v) => v.code === VIOLATION.NO_EXPECTATION), true);
  }
  assert.equal(gradeSpike(good(), null).recovery, '0/2');
});

test('a missing reading is a violation, not an absent one', () => {
  const g = gradeSpike([good()[0]], EXPECTED);
  assert.equal(g.held, false);
  assert.equal(g.recovery, '1/2');
  assert.equal(g.violations[0].code, VIOLATION.MISSING_READING);
  assert.equal(g.violations[0].spike, 'surviving');
});

test('no readings at all is 0/2, not a pass', () => {
  const g = gradeSpike([], EXPECTED);
  assert.equal(g.held, false);
  assert.equal(g.recovery, '0/2');
  assert.equal(g.violations.length, 2);
});

test('two readings for one spike are refused rather than resolved', () => {
  const g = gradeSpike([...good(), { spike: 'surviving', verdict: 'WIPE_SURVIVED', control: 'PRESENT' }], EXPECTED);
  assert.equal(g.held, false);
  assert.equal(g.violations[0].code, VIOLATION.DUPLICATE_READING);
});

test('a reading that is not one of the two spikes is reported', () => {
  const g = gradeSpike([...good(), { spike: 'something-else', verdict: 'WIPE_SURVIVED', control: 'PRESENT' }], EXPECTED);
  assert.equal(g.held, false);
  assert.equal(g.violations[0].code, VIOLATION.UNKNOWN_SPIKE);
});

test('a reading with no verdict is refused', () => {
  const g = gradeSpike([{ spike: 'disappearing', control: 'PRESENT' }, good()[1]], EXPECTED);
  assert.equal(g.held, false);
  assert.equal(g.violations[0].code, VIOLATION.NO_VERDICT);
});

test('the co-resident control must be PRESENT', () => {
  const g = gradeSpike([
    { spike: 'disappearing', verdict: 'WIPE_ELIMINATED', control: 'ABSENT' },
    good()[1],
  ], EXPECTED);
  assert.equal(g.held, false);
  assert.equal(g.violations[0].code, VIOLATION.CONTROL_NOT_PRESENT);
  assert.equal(g.violations[0].got, 'ABSENT');
});

test('requireControl:false is for a channel whose control is its own reading', () => {
  const g = gradeSpike([
    { spike: 'disappearing', verdict: 'WIPE_ELIMINATED' },
    { spike: 'surviving', verdict: 'WIPE_SURVIVED' },
  ], EXPECTED, { requireControl: false });
  assert.equal(g.held, true);
});

test('the wrong verdict is named with what was registered and what came back', () => {
  const g = gradeSpike([
    { spike: 'disappearing', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
    good()[1],
  ], EXPECTED);
  assert.equal(g.held, false);
  assert.equal(g.violations[0].code, VIOLATION.WRONG_VERDICT);
  assert.equal(g.violations[0].expected, 'WIPE_ELIMINATED');
  assert.equal(g.violations[0].got, 'WIPE_SURVIVED');
});

// -------------------------------------------------------------- injection ---

test('the injected run passes exactly when the gate REFUSED it', () => {
  const inj = gradeInjected([
    { spike: 'disappearing', verdict: 'NOT_OBSERVED', control: 'PRESENT' },
    { spike: 'surviving', verdict: 'NOT_OBSERVED', control: 'PRESENT' },
  ], EXPECTED);
  assert.equal(inj.wentRed, true);
  assert.equal(inj.held, true);
  assert.deepEqual(inj.violations, []);
  assert.equal(inj.recovery, '0/2');
});

test('an injected run the gate let through is INJECTION_NOT_DETECTED', () => {
  const inj = gradeInjected(good(), EXPECTED);
  assert.equal(inj.wentRed, false);
  assert.equal(inj.held, false);
  assert.equal(inj.violations[0].code, VIOLATION.INJECTION_NOT_DETECTED);
});

test('an injection at an unregistered configuration proves nothing and is refused', () => {
  // `--inject-at -Ofast` is accepted by the CLI and nothing is registered for
  // -Ofast, so the injected grade is red before a reading is compared: red for
  // ANY readings, including the readings of a run in which nothing was injected
  // at all. Measured on the pristine lane: `--opt -O2 --inject-at -Ofast`
  // printed "injection RED (as required)" and exited 0 with a MISSPELT_SUFFIX
  // emptied to ''. A check that cannot fail is not evidence that the gate can
  // refuse, so it is INJECTION_NOT_GRADEABLE rather than a pass.
  for (const readings of [
    [{ spike: 'disappearing', verdict: 'NOT_OBSERVED', control: 'PRESENT' },
      { spike: 'surviving', verdict: 'NOT_OBSERVED', control: 'PRESENT' }],
    good(),
  ]) {
    const inj = gradeInjected(readings, null);
    assert.equal(inj.gradeable, false);
    assert.equal(inj.wentRed, false, 'an unregistered configuration cannot show the gate going red');
    assert.equal(inj.held, false);
    assert.equal(inj.violations[0].code, VIOLATION.INJECTION_NOT_GRADEABLE);
  }
  // Same for an expectation that registers a failure word: the comparison never
  // happened, so the refusal is about the claim and not about the injection.
  const malformed = gradeInjected(good(), { disappearing: 'COMPILE_ERROR', surviving: 'WIPE_SURVIVED' });
  assert.equal(malformed.held, false);
  assert.equal(malformed.violations[0].code, VIOLATION.INJECTION_NOT_GRADEABLE);
});

test('a graded injection records what its refusal actually rested on', () => {
  // So that "injection RED" can be read as "red because the misspelt name left
  // nothing to read", which is the failure being injected, rather than as a
  // statement about the claims file.
  const inj = gradeInjected([
    { spike: 'disappearing', verdict: 'NOT_OBSERVED', control: 'PRESENT' },
    { spike: 'surviving', verdict: 'NOT_OBSERVED', control: 'PRESENT' },
  ], EXPECTED);
  assert.equal(inj.gradeable, true);
  assert.deepEqual(inj.redBecause, [VIOLATION.NOT_A_READING]);
});

// ------------------------------------------------------------ run verdict ---

const heldCfg = (vendor, opt) => ({ vendor, opt, grade: gradeSpike(good(), EXPECTED) });
const redInjection = gradeInjected([
  { spike: 'disappearing', verdict: 'NOT_OBSERVED', control: 'PRESENT' },
  { spike: 'surviving', verdict: 'NOT_OBSERVED', control: 'PRESENT' },
], EXPECTED);

// --------------------------------------------------- discriminating pairs ---

test('a configuration is discriminating only when its two registered answers differ', () => {
  assert.equal(gradeSpike(good(), EXPECTED).discriminating, true);
  assert.equal(gradeSpike(good(), EXPECTED).sharedAnswer, null);

  // -O0: both registered WIPE_SURVIVED. The readings are right and recovery is
  // 2/2, and the configuration still carries no information about whether the
  // instrument can report anything else.
  const o0 = gradeSpike(goodAtO0(), EXPECTED_O0);
  assert.equal(o0.held, true);
  assert.equal(o0.recovery, '2/2');
  assert.equal(o0.discriminating, false);
  assert.equal(o0.sharedAnswer, 'WIPE_SURVIVED');

  // Nothing registered: nothing to be discriminating about.
  assert.equal(gradeSpike(good(), null).discriminating, false);
  assert.equal(gradeSpike(good(), null).sharedAnswer, null);
});

test('a run made only of non-discriminating configurations is NOT ESTABLISHED', () => {
  // The vacuous pass this rule exists for, and it was measured rather than
  // imagined: with verdictOf made structurally unable to report an elimination,
  // `run-spike.mjs --cc clang-18,gcc-13 --opt -O0` printed ESTABLISHED 2/2 on
  // both vendors and exited 0. Every reading below is what that blind instrument
  // produces, and every one of them is the registered answer.
  const v = gateVerdict([
    { vendor: 'clang-18', opt: '-O0', grade: gradeSpike(goodAtO0(), EXPECTED_O0) },
    { vendor: 'gcc-13', opt: '-O0', grade: gradeSpike(goodAtO0(), EXPECTED_O0) },
  ], redInjection);
  assert.equal(v.established, false);
  assert.deepEqual(v.configurations, { num: 2, den: 2 });
  assert.deepEqual(v.discriminating, { num: 0, den: 2 });
  const why = v.reasons.find((r) => r.includes(VIOLATION.NO_DISCRIMINATING_CONFIGURATION));
  assert.ok(why, `expected a ${VIOLATION.NO_DISCRIMINATING_CONFIGURATION} reason, got ${JSON.stringify(v.reasons)}`);
  // It must say WHICH configurations were non-discriminating, and why.
  assert.equal(why.includes('clang-18 -O0'), true);
  assert.equal(why.includes('gcc-13 -O0'), true);
  assert.equal(why.includes('both spikes registered WIPE_SURVIVED'), true);
});

test('-O0 is not dropped: one discriminating configuration establishes the run', () => {
  // The rule refuses a run made ONLY of such rungs, not the rung. An elimination
  // read at -O0 would be a finding about the instrument, which is why it stays.
  const v = gateVerdict([
    { vendor: 'clang-18', opt: '-O0', grade: gradeSpike(goodAtO0(), EXPECTED_O0) },
    { vendor: 'clang-18', opt: '-O2', grade: gradeSpike(good(), EXPECTED) },
  ], redInjection);
  assert.equal(v.established, true);
  assert.deepEqual(v.reasons, []);
  assert.deepEqual(v.discriminating, { num: 1, den: 2 });
});

test('a blind instrument is caught by the discriminating configuration, not by the injection', () => {
  // An instrument that reports WIPE_SURVIVED for everything. At -O0 it recovers
  // 2/2 (both answers are that word) and the injection still goes red, because
  // the injection misspells the subject's NAME and name resolution is not what
  // this instrument broke. Only a configuration that registers two different
  // answers separates it from a working one.
  const blindAtO0 = gradeSpike(goodAtO0(), EXPECTED_O0);
  const blindAtO2 = gradeSpike([
    { spike: 'disappearing', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
    { spike: 'surviving', verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
  ], EXPECTED);
  assert.equal(blindAtO0.held, true, 'the blind instrument holds at -O0');
  assert.equal(redInjection.held, true, 'and it passes the injection, which tests something else');
  assert.equal(gateVerdict([{ vendor: 'clang-18', opt: '-O0', grade: blindAtO0 }], redInjection).established, false);

  assert.equal(blindAtO2.held, false, 'at a discriminating level it is caught');
  assert.equal(blindAtO2.violations[0].code, VIOLATION.WRONG_VERDICT);
});

test('a run is established only when every configuration held and the injection went red', () => {
  const v = gateVerdict([heldCfg('clang-18', '-O2'), heldCfg('gcc-13', '-O2')], redInjection);
  assert.equal(v.established, true);
  assert.deepEqual(v.configurations, { num: 2, den: 2 });
  assert.deepEqual(v.reasons, []);
});

test('one short configuration is enough to make the run invalid, and it is named', () => {
  const bad = { vendor: 'gcc-13', opt: '-Os', grade: gradeSpike([good()[0]], EXPECTED) };
  const v = gateVerdict([heldCfg('clang-18', '-O2'), bad], redInjection);
  assert.equal(v.established, false);
  assert.equal(v.reasons.some((r) => r.includes('gcc-13 -Os')), true);
});

test('a run with no configuration is NOT ESTABLISHED', () => {
  const v = gateVerdict([], redInjection);
  assert.equal(v.established, false);
  assert.equal(v.reasons.some((r) => r.includes('no configuration')), true);
});

test('a run that never performed the injection is NOT ESTABLISHED', () => {
  const v = gateVerdict([heldCfg('clang-18', '-O2')], null);
  assert.equal(v.established, false);
  assert.equal(v.reasons.some((r) => r.includes('never shown to go red')), true);
});

test('a run whose injection stayed green is NOT ESTABLISHED', () => {
  const v = gateVerdict([heldCfg('clang-18', '-O2')], gradeInjected(good(), EXPECTED));
  assert.equal(v.established, false);
  assert.equal(v.reasons.some((r) => r.includes('NOT ESTABLISHED')), true);
});

test('the channel is named in a reason when it is not the differential one', () => {
  const bad = { channel: 'observer', vendor: 'clang-18', opt: '-O2', grade: gradeSpike([], EXPECTED) };
  const v = gateVerdict([bad], redInjection);
  assert.equal(v.reasons.some((r) => r.includes('[observer]')), true);
});

test('the pair is exactly two, and the denominator follows it', () => {
  assert.deepEqual([...SPIKES], ['disappearing', 'surviving']);
  assert.equal(gradeSpike([], EXPECTED).recovered.den, SPIKES.length);
});
