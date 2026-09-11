/**
 * The outcome table and its precedence, and the surgicality checks beside it.
 *
 * Every outcome is reached at least once, and every place where two rules could
 * both apply is pinned to the one that must win. The inputs are the objects the
 * runner passes -- verdictOf-shaped verdicts and pin-record results -- built here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { outcomeOf, brokenReasons, absentAfterAblation, gradeRedControl, verdictWord, OUTCOMES } from '../lib/outcome.mjs';
import {
  ablatedUnchanged, controlUntouched, controlRenumberedOnly, canonicalLocalLabels, differsOnlyInLabels, noPinNoChange, pinDelta,
} from '../lib/surgicality.mjs';

const E = 'WIPE_ELIMINATED';
const S = 'WIPE_SURVIVED';

function rec({ pinnedCount = 1, wouldPinCount = pinnedCount, dryRun = false, scope = 'functions',
  resolution = [{ name: 'encrypt_blob', resolution: 'resolved' }] } = {}) {
  return {
    ok: true,
    problems: [],
    record: {
      // outcomeOf takes records pin-record.mjs already accepted; the shape is v1's,
      // but the lists are not filled in because nothing here reads them.
      schemaVersion: 'wipe-pin-v1', component: 'WipePin', module: 'x.w.c', optLevel: { speedup: 2, size: 0 },
      scope, requested: resolution.map((r) => r.name), resolution, dryRun,
      pinned: [], pinnedCount, wouldPinCount,
      seen: { zeroFillMemsetInScope: 2, zeroFillMemsetInModule: 3 },
      unhandled: { libcallMemset: 0, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0, inlineWrapperMemset: 0 },
      toolchain: { digest: '', clang: '', packages: [] },
    },
  };
}
const refusedRec = (problems = ['record-missing']) => ({ ok: false, record: null, problems });
const v = (verdict, control = 'PRESENT') => ({ verdict, control, control_via: 'oracle' });

test('one case per outcome, and every declared outcome is reachable', () => {
  const cases = [
    ['RETAINED', v(E), v(S), rec(), rec(), true],
    ['ALREADY_SURVIVED', v(S), v(S), rec(), rec(), true],
    ['PIN_INEFFECTIVE', v(E), v(E), rec(), rec(), true],
    ['PIN_NOT_APPLIED', v(E), v(E), rec({ pinnedCount: 0 }), rec({ pinnedCount: 0 }), true],
    ['BROKEN_REPAIR', v(E), v(S), refusedRec(), rec(), true],
    ['REGRESSED', v(S), v(E), rec(), rec(), true],
    ['SURVIVED_WITHOUT_PIN', v(E), v(S), rec({ pinnedCount: 0 }), rec({ pinnedCount: 0 }), true],
    ['NOT_SCORED', v('COMPILE_ERROR'), v('COMPILE_ERROR'), rec(), rec(), true],
  ];
  const seen = new Set();
  for (const [want, b, r, w, wo, ctl] of cases) {
    const got = outcomeOf(b, r, w, wo, ctl);
    assert.equal(got.outcome, want, `${want}: got ${got.outcome} (${got.reason})`);
    assert.equal(typeof got.reason, 'string');
    seen.add(got.outcome);
  }
  assert.deepEqual([...seen].sort(), [...OUTCOMES].sort());
});

test('both verdicts are carried on every outcome, including NOT_SCORED', () => {
  const got = outcomeOf(v(E), v('NOT_OBSERVED'), rec(), rec(), true);
  assert.equal(got.outcome, 'NOT_SCORED');
  assert.equal(got.baseline, E);
  assert.equal(got.repaired, 'NOT_OBSERVED');
  assert.match(got.reason, /repaired-not-scorable/);
});

test('verdicts may be bare strings or verdictOf objects', () => {
  assert.equal(outcomeOf(E, S, rec(), rec(), true).outcome, 'RETAINED');
  assert.equal(verdictWord(undefined), 'MISSING');
  assert.equal(outcomeOf(undefined, S, rec(), rec(), true).outcome, 'NOT_SCORED');
});

// ---- precedence -------------------------------------------------------------

test('precedence 1: an unscorable baseline wins over a broken repair', () => {
  // A file that does not compile without the plugin has no record either; that
  // is not the plugin's failure and must not be counted as one.
  const got = outcomeOf(v('COMPILE_ERROR'), v('COMPILE_ERROR'), refusedRec(), refusedRec(), false);
  assert.equal(got.outcome, 'NOT_SCORED');
  assert.match(got.reason, /baseline-not-scorable: COMPILE_ERROR/);
  for (const b of ['ABLATION_DID_NOT_COMPILE', 'VERIFICATION_INCOMPLETE', 'NOT_OBSERVED']) {
    assert.equal(outcomeOf(v(b), v(S), rec(), rec(), true).outcome, 'NOT_SCORED', b);
  }
});

test('precedence 2: a broken repair wins over an unscorable repaired verdict', () => {
  // The plugin made the build fail: the control is gone with it. That is a
  // broken repair, not "not scored".
  const got = outcomeOf(v(E), { verdict: 'COMPILE_ERROR' }, refusedRec(), refusedRec(), false);
  assert.equal(got.outcome, 'BROKEN_REPAIR');
  // The plugin made the oracle blind in the on compile.
  assert.equal(outcomeOf(v(E), v('VERIFICATION_INCOMPLETE', 'ABSENT'), rec(), rec(), false).outcome, 'BROKEN_REPAIR');
});

test('precedence 2: a broken repair wins over RETAINED, whatever the verdicts say', () => {
  assert.equal(outcomeOf(v(E), v(S), refusedRec(), rec(), true).outcome, 'BROKEN_REPAIR');
  assert.equal(outcomeOf(v(E), v(S), rec(), refusedRec(['unknown-field: extra']), true).outcome, 'BROKEN_REPAIR');
  assert.equal(outcomeOf(v(E), v(S), rec(), rec(), false).outcome, 'BROKEN_REPAIR');
  assert.equal(outcomeOf(v(E), v(S), undefined, rec(), true).outcome, 'BROKEN_REPAIR');
});

test('precedence 2: any requested name that did not resolve is a broken repair', () => {
  const partial = [{ name: 'encrypt_blob', resolution: 'resolved' }, { name: 'wipe', resolution: 'not-in-module' }];
  for (const [w, wo] of [[rec({ resolution: partial }), rec()], [rec(), rec({ resolution: partial })]]) {
    const got = outcomeOf(v(E), v(S), w, wo, true);
    assert.equal(got.outcome, 'BROKEN_REPAIR');
    assert.match(got.reason, /wipe \(not-in-module\)/);
  }
  const decl = [{ name: 'encrypt_blob', resolution: 'declaration-only' }];
  assert.equal(outcomeOf(v(S), v(S), rec({ resolution: decl }), rec({ resolution: decl }), true).outcome, 'BROKEN_REPAIR');
});

test('a helper gone from the ablated unit only is tolerated, and only in that exact shape', () => {
  // Measured shape: a static secure_wipe whose only call is the wipe statement.
  // Ablation removes the call, the compiler stops emitting the helper, and the
  // wo record says not-in-module. The w record, where the wipe exists, resolves it.
  const both = [{ name: 'encrypt_blob', resolution: 'resolved' }, { name: 'secure_wipe', resolution: 'resolved' }];
  const gone = [{ name: 'encrypt_blob', resolution: 'resolved' }, { name: 'secure_wipe', resolution: 'not-in-module' }];
  const w = rec({ pinnedCount: 0, resolution: both });
  const wo = rec({ pinnedCount: 0, resolution: gone });
  assert.deepEqual(absentAfterAblation(w, wo), ['secure_wipe']);
  assert.equal(outcomeOf(v(S), v(S), w, wo, true).outcome, 'ALREADY_SURVIVED');
  assert.deepEqual(brokenReasons(w, wo, true), []);

  // not resolved in w either: broken
  assert.equal(outcomeOf(v(S), v(S), rec({ pinnedCount: 0, resolution: gone }), wo, true).outcome, 'BROKEN_REPAIR');
  // gone from w and present in wo is the wrong way round: broken
  assert.equal(outcomeOf(v(S), v(S), rec({ pinnedCount: 0, resolution: gone }), rec({ pinnedCount: 0, resolution: both }), true).outcome, 'BROKEN_REPAIR');
  // declaration-only in wo is not what ablation produces: broken
  const decl = [{ name: 'encrypt_blob', resolution: 'resolved' }, { name: 'secure_wipe', resolution: 'declaration-only' }];
  assert.equal(outcomeOf(v(S), v(S), w, rec({ pinnedCount: 0, resolution: decl }), true).outcome, 'BROKEN_REPAIR');
  // an unusable w record cannot vouch for anything
  assert.deepEqual(absentAfterAblation(refusedRec(), wo), []);
  assert.equal(outcomeOf(v(S), v(S), refusedRec(), wo, true).outcome, 'BROKEN_REPAIR');
});

test('the red control shape: every name suffixed, nothing resolved, BROKEN_REPAIR on every baseline', () => {
  const none = [{ name: 'encrypt_blob__nx', resolution: 'not-in-module' }];
  for (const b of [E, S]) {
    for (const r of [E, S]) {
      const got = outcomeOf(v(b), v(r), rec({ pinnedCount: 0, resolution: none }), rec({ pinnedCount: 0, resolution: none }), true);
      assert.equal(got.outcome, 'BROKEN_REPAIR', `${b} -> ${r}`);
    }
  }
});

test('module scope has no resolution list and is not broken for lacking one', () => {
  const m = rec({ scope: 'module', resolution: [] });
  assert.equal(outcomeOf(v(E), v(S), m, m, true).outcome, 'RETAINED');
});

test('two records that disagree about being a dry run are a broken repair', () => {
  const got = outcomeOf(v(E), v(E), rec({ pinnedCount: 0, wouldPinCount: 1, dryRun: true }), rec(), true);
  assert.equal(got.outcome, 'BROKEN_REPAIR');
  assert.match(got.reason, /dry-run-mismatch/);
});

test('precedence 4: survival without a pin is never RETAINED', () => {
  const got = outcomeOf(v(E), v(S), rec({ pinnedCount: 0, wouldPinCount: 0 }), rec({ pinnedCount: 0, wouldPinCount: 0 }), true);
  assert.equal(got.outcome, 'SURVIVED_WITHOUT_PIN');
  assert.match(got.reason, /investigate/);
});

test('precedence 4: a dry run can never produce RETAINED', () => {
  const dry = rec({ pinnedCount: 0, wouldPinCount: 2, dryRun: true });
  assert.equal(outcomeOf(v(E), v(S), dry, dry, true).outcome, 'SURVIVED_WITHOUT_PIN');
  // ... and a dry run that would have pinned something reads as ineffective, not as not-applied
  assert.equal(outcomeOf(v(E), v(E), dry, dry, true).outcome, 'PIN_INEFFECTIVE');
  const dryNothing = rec({ pinnedCount: 0, wouldPinCount: 0, dryRun: true });
  assert.equal(outcomeOf(v(E), v(E), dryNothing, dryNothing, true).outcome, 'PIN_NOT_APPLIED');
});

test('precedence 4: the baseline SURVIVED rows do not look at the pins at all', () => {
  for (const w of [rec(), rec({ pinnedCount: 0 })]) {
    assert.equal(outcomeOf(v(S), v(S), w, w, true).outcome, 'ALREADY_SURVIVED');
    assert.equal(outcomeOf(v(S), v(E), w, w, true).outcome, 'REGRESSED');
  }
});

test('only the wipe-kept record decides RETAINED versus SURVIVED_WITHOUT_PIN', () => {
  assert.equal(outcomeOf(v(E), v(S), rec({ pinnedCount: 1 }), rec({ pinnedCount: 0 }), true).outcome, 'RETAINED');
  assert.equal(outcomeOf(v(E), v(S), rec({ pinnedCount: 0 }), rec({ pinnedCount: 1 }), true).outcome, 'SURVIVED_WITHOUT_PIN');
});

test('a record the reader would have refused is still not trusted here (the function is total)', () => {
  const contradictory = rec({ pinnedCount: 0, wouldPinCount: 3, dryRun: false });
  const got = outcomeOf(v(E), v(E), contradictory, contradictory, true);
  assert.equal(got.outcome, 'BROKEN_REPAIR');
  assert.match(got.reason, /record-inconsistent/);
});

test('brokenReasons lists every reason, in a fixed order', () => {
  const partial = [{ name: 'f', resolution: 'not-in-module' }];
  const reasons = brokenReasons(refusedRec(['record-missing']), rec({ resolution: partial }), false);
  assert.deepEqual(reasons, ['record-w: record-missing', 'unresolved-wo: f (not-in-module)', 'control-not-present-in-on-compile']);
  assert.deepEqual(brokenReasons(rec(), rec(), true), []);
});

// ---- red controls --------------------------------------------------------------

const row = (id, baseline, outcome, extra = {}) => ({ id, opt: '-O2', kind: 'erasure', baseline, outcome, ...extra });

test('gradeRedControl: not a red control, nothing to grade', () => {
  assert.equal(gradeRedControl([row('a', E, 'RETAINED')], {}), null);
});

test('gradeRedControl --dry-run: held when nothing changed, failed on any change', () => {
  const ok = [row('a', E, 'PIN_INEFFECTIVE'), row('b', S, 'ALREADY_SURVIVED'), row('c', 'COMPILE_ERROR', 'NOT_SCORED'),
    { id: 'd', opt: '-O2', kind: 'none', noPinNoChange: true }];
  const g = gradeRedControl(ok, { dryRun: true });
  assert.equal(g.held, true, JSON.stringify(g.violations));
  assert.equal(g.control, '--dry-run');
  for (const bad of ['RETAINED', 'SURVIVED_WITHOUT_PIN', 'REGRESSED']) {
    const b = gradeRedControl([...ok, row('x', E, bad)], { dryRun: true });
    assert.equal(b.held, false, bad);
    assert.match(b.violations.join('\n'), new RegExp(`x -O2: ${bad}`));
  }
  const changed = gradeRedControl([...ok, row('y', E, 'PIN_INEFFECTIVE', { noPinNoChangeW: false })], { dryRun: true });
  assert.equal(changed.held, false);
  assert.match(changed.violations[0], /noPinNoChangeW violated/);
  const noneChanged = gradeRedControl([...ok, { id: 'z', opt: '-O2', kind: 'none', noPinNoChange: false }], { dryRun: true });
  assert.equal(noneChanged.held, false);
});

test('gradeRedControl --target-suffix: every scorable cell must be BROKEN_REPAIR', () => {
  const ok = [row('a', E, 'BROKEN_REPAIR'), row('b', S, 'BROKEN_REPAIR'), row('c', 'ABLATION_DID_NOT_COMPILE', 'NOT_SCORED')];
  assert.equal(gradeRedControl(ok, { targetSuffix: '__absent' }).held, true);
  const leak = gradeRedControl([...ok, row('d', S, 'ALREADY_SURVIVED')], { targetSuffix: '__absent' });
  assert.equal(leak.held, false);
  assert.deepEqual(leak.violations, ['d -O2: ALREADY_SURVIVED']);
});

test('gradeRedControl refuses to call a control that never ran "held"', () => {
  const g = gradeRedControl([row('c', 'COMPILE_ERROR', 'NOT_SCORED')], { targetSuffix: '__absent' });
  assert.equal(g.held, false);
  assert.match(g.violations[0], /vacuous/);
  assert.equal(gradeRedControl([], { dryRun: true }).held, false);
});

// ---- surgicality ---------------------------------------------------------------

const bodyOf = (asm, fn) => {
  const m = new RegExp(`^${fn}:\\n([\\s\\S]*?)^\\.end ${fn}$`, 'm').exec(asm || '');
  return m ? m[1] : null;
};
const listing = (fnBody, ctlBody = 'ctl') => `f:\n${fnBody}\n.end f\nvgctl_control:\n${ctlBody}\n.end vgctl_control\n`;

test('ablatedUnchanged: holds, is violated, or does not apply', () => {
  assert.equal(ablatedUnchanged({ asmWoOff: listing('a'), asmWoOn: listing('a'), fn: 'f', recordWo: rec({ pinnedCount: 0 }), bodyOf }), true);
  assert.equal(ablatedUnchanged({ asmWoOff: listing('a'), asmWoOn: listing('b'), fn: 'f', recordWo: rec({ pinnedCount: 0 }), bodyOf }), false);
  // the ablated compile pinned something: the check does not apply
  assert.equal(ablatedUnchanged({ asmWoOff: listing('a'), asmWoOn: listing('b'), fn: 'f', recordWo: rec({ pinnedCount: 1 }), bodyOf }), null);
  // no usable record, or a compile missing: undecided, never a pass
  assert.equal(ablatedUnchanged({ asmWoOff: listing('a'), asmWoOn: listing('a'), fn: 'f', recordWo: refusedRec(), bodyOf }), null);
  assert.equal(ablatedUnchanged({ asmWoOff: null, asmWoOn: listing('a'), fn: 'f', recordWo: rec({ pinnedCount: 0 }), bodyOf }), null);
  assert.equal(ablatedUnchanged({ asmWoOff: listing('a'), asmWoOn: listing('a'), fn: 'g', recordWo: rec({ pinnedCount: 0 }), bodyOf }), null);
});

test('controlUntouched: functions scope only, every pair must match', () => {
  const same = [listing('a', 'c1'), listing('b', 'c1')];
  const moved = [listing('a', 'c1'), listing('a', 'c2')];
  assert.equal(controlUntouched({ scope: 'functions', pairs: [same, same], bodyOf }), true);
  assert.equal(controlUntouched({ scope: 'functions', pairs: [same, moved], bodyOf }), false);
  assert.equal(controlUntouched({ scope: 'module', pairs: [moved], bodyOf }), null);
  assert.equal(controlUntouched({ scope: 'functions', pairs: [[null, listing('a')]], bodyOf }), null);
  assert.equal(controlUntouched({ scope: 'functions', pairs: [], bodyOf }), null);
});

// The gcc-13 shape, measured on fable_N_token_r3 -O2: the pin in the target
// renumbers the unit-wide .L labels, and the control that follows it differs in
// nothing else.
const ctlOff = '\tcall\tvgctl_use@PLT\n\tjne\t.L15\n\taddq\t$40, %rsp\n\tret\n.L15:\n\tcall\t__stack_chk_fail@PLT';
const ctlOn = ctlOff.replaceAll('.L15', '.L14');

test('canonicalLocalLabels renames .L<n> by first appearance, and nothing clang writes', () => {
  assert.equal(canonicalLocalLabels(ctlOff), canonicalLocalLabels(ctlOn));
  assert.match(canonicalLocalLabels(ctlOff), /jne\t\.L#0\n[\s\S]*^\.L#0:$/m);
  assert.equal(canonicalLocalLabels('jmp .L3\n.L10:\njmp .L3'), 'jmp .L#0\n.L#1:\njmp .L#0');
  // clang's per-function labels, constant pools and gcc's .LC constants are left alone
  const clang = 'jne .LBB0_2\n.LBB0_2:\n.Ltmp0:\nmovaps .LCPI1_0(%rip), %xmm0\nleaq .LC0(%rip), %rdi\n.Lfunc_end1:';
  assert.equal(canonicalLocalLabels(clang), clang);
  assert.equal(canonicalLocalLabels(null), null);
});

test('canonicalLocalLabels keeps a structural change visible: a branch to a different label still differs', () => {
  const a = 'jne .L3\n.L3:\nret\n.L4:\nret';
  const b = 'jne .L4\n.L3:\nret\n.L4:\nret';
  assert.notEqual(canonicalLocalLabels(a), canonicalLocalLabels(b));
  assert.equal(differsOnlyInLabels(a, b), false);
});

test('differsOnlyInLabels: true only for text that differs and is equal after renaming', () => {
  assert.equal(differsOnlyInLabels(ctlOff, ctlOn), true);
  assert.equal(differsOnlyInLabels(ctlOff, ctlOff), false);
  assert.equal(differsOnlyInLabels(ctlOff, ctlOn + '\n\tpxor\t%xmm0, %xmm0'), false);
  assert.equal(differsOnlyInLabels(null, ctlOn), null);
});

test('controlUntouched holds across a renumbering, and controlRenumberedOnly says that is why', () => {
  const renum = [listing('a', ctlOff), listing('b', ctlOn)];
  const exact = [listing('a', ctlOff), listing('b', ctlOff)];
  const moved = [listing('a', ctlOff), listing('b', ctlOn + '\n\tnop')];
  assert.equal(controlUntouched({ scope: 'functions', pairs: [exact, renum], bodyOf }), true);
  assert.equal(controlRenumberedOnly({ scope: 'functions', pairs: [exact, renum], bodyOf }), true);
  assert.equal(controlRenumberedOnly({ scope: 'functions', pairs: [exact, exact], bodyOf }), false);
  // a real change is still a violation, and then nothing is "renumbered only"
  assert.equal(controlUntouched({ scope: 'functions', pairs: [renum, moved], bodyOf }), false);
  assert.equal(controlRenumberedOnly({ scope: 'functions', pairs: [renum, moved], bodyOf }), null);
  assert.equal(controlRenumberedOnly({ scope: 'module', pairs: [renum], bodyOf }), null);
  assert.equal(controlRenumberedOnly({ scope: 'functions', pairs: [], bodyOf }), null);
});

test('noPinNoChange compares the whole listing, not the target body', () => {
  const a = listing('x', 'c1');
  const elsewhere = listing('x', 'c2'); // target body identical, something else moved
  assert.equal(noPinNoChange({ asmOff: a, asmOn: a, record: rec({ pinnedCount: 0 }) }), true);
  assert.equal(noPinNoChange({ asmOff: a, asmOn: elsewhere, record: rec({ pinnedCount: 0 }) }), false);
  assert.equal(noPinNoChange({ asmOff: a, asmOn: elsewhere, record: rec({ pinnedCount: 2 }) }), null);
  assert.equal(noPinNoChange({ asmOff: a, asmOn: a, record: refusedRec() }), null);
  assert.equal(noPinNoChange({ asmOff: a, asmOn: null, record: rec({ pinnedCount: 0 }) }), null);
});

test('pinDelta attributes pins to the wipe statement, and uses would-pin counts in a dry run', () => {
  assert.equal(pinDelta(rec({ pinnedCount: 2 }), rec({ pinnedCount: 1 })), 1);
  assert.equal(pinDelta(rec({ pinnedCount: 1 }), rec({ pinnedCount: 1 })), 0);
  const dw = rec({ pinnedCount: 0, wouldPinCount: 3, dryRun: true });
  const dwo = rec({ pinnedCount: 0, wouldPinCount: 1, dryRun: true });
  assert.equal(pinDelta(dw, dwo), 2);
  assert.equal(pinDelta(refusedRec(), rec()), null);
});
