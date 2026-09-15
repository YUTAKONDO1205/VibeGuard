/**
 * The gcc DRIVER's fail-closed guards, pinned. No compiler runs here.
 *
 * WHY THIS FILE EXISTS. `../lib/gcc-disable-tree.mjs` is pure and was tested;
 * `../tools/intervene.mjs` is what USES it, and every decision that keeps this
 * channel honest -- the walk's four refusals, the misspell control, the
 * intervention fatalities, the controls, what the gate is told -- lived only
 * there. Not one of them was pinned by anything: deleting the fatality check,
 * the misspell-control guard, the NO_DUMPS guard, the DUMP_BUILD_FAILED guard or
 * the control guard left the whole suite green. A guard no test fails without is
 * decorative, and these guards are the reason the channel is allowed to exist at
 * all, so each one below has a case that goes red when it is removed.
 *
 * HOW IT DRIVES A COMPILER-LESS RUN. `gccChannel` takes its instruments from its
 * context: `observe` (the pair of builds and everything read from them),
 * `misspellControl` (control (b)) and `finish` (the exit). The defaults are the
 * real ones, so a lab run is unchanged; here they are scripted, and `finish`
 * throws so that a guard which fails to stop the run is visible as a run that
 * continued rather than as a silently ignored exit code.
 *
 * The scripted readings are NOT hand-written objects. They are built by the
 * tool's own `readingFrom`, from synthetic builds -- two exit codes, two
 * stderrs, two dump listings -- so what these tests drive is the product's own
 * reading assembly, and the dump texts are read by the same
 * `buildDumpSequence`/`firstIndifferentDump` a real run uses.
 *
 * WHAT NONE OF THIS IS. It is evidence about the apparatus and none whatsoever
 * about gcc. The catalogue row stays `unmeasured` until the channel is actually
 * run in WSL; see `../PIN-FAMILIES.md`.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gccChannel, readingFrom, INVOKED_AS_CLI } from '../tools/intervene.mjs';
import { GCC_EXIT_REASONS } from '../lib/gcc-disable-tree.mjs';

const TOOL = join(dirname(fileURLToPath(import.meta.url)), '..', 'tools', 'intervene.mjs');

const FN = 'handle_request';

// ---------------------------------------------------------------------------
// synthetic builds, and the readings the tool assembles from them

/** gcc-13's own two sentences, quoted so a change in its wording fails loudly. */
const NOTE = (pass) => `cc1: note: disable pass tree-${pass} for functions in the range of [0, 4294967295]\n`;
const REFUSAL = (pass) => `cc1: error: unknown pass tree-${pass} specified in '-fdisable'\n`;

const region = (fn, body) =>
  `\n;; Function ${fn} (${fn}, funcdef_no=0, decl_uid=1234, cgraph_uid=1, symbol_order=0)\n\n${fn} ()\n{\n${body}\n}\n`;

const WITH_WIPE = region(FN, '  consume (&secret);\n  __builtin_memset (&secret, 0, 32);');
const ABLATED = region(FN, '  consume (&secret);');
const ELSEWHERE = region('wipe_kept', '  __builtin_memset (&kept, 0, 32);');

/** One dump in both units, in the state asked for. */
function dumpPair(i, state, stage = 't') {
  const key = `${String(i).padStart(3, '0')}${stage}.p${i}`;
  const file = `out.s.${key}`;
  const entry = { file, key, num: i, stage, pass: `p${i}` };
  if (state === 'NOT_OBSERVED') return { entry, w: ELSEWHERE, wo: ELSEWHERE };
  if (state === 'WIPE_SURVIVED') return { entry, w: WITH_WIPE, wo: ABLATED };
  return { entry, w: ABLATED, wo: ABLATED }; // WIPE_ELIMINATED: the same region either way
}

/**
 * A reading, assembled by the tool from builds that never happened.
 *
 * `notes` and `refusal` say what gcc printed in each unit, which is the whole
 * point of the two controls: a note in one unit only, or a refusal in one unit
 * only, must not read as a reading that happened.
 */
function reading({
  disabled = [],
  states = ['WIPE_SURVIVED', 'WIPE_ELIMINATED', 'WIPE_ELIMINATED'],
  stage = 't',
  codes = { w: 0, wo: 0 },
  notes = 'both',
  refusal = 'none',
  asm = 'WIPE_ELIMINATED',
  control = 'PRESENT',
  fixture = 'PRESENT',
  onlyW = [],
  onlyWo = [],
} = {}) {
  const pairs = states.map((state, i) => dumpPair(i, state, stage));
  const texts = { w: {}, wo: {} };
  for (const p of pairs) { texts.w[p.entry.file] = p.w; texts.wo[p.entry.file] = p.wo; }
  const extra = (names) => names.map((n, k) => ({ file: `out.s.${n}`, key: n, num: 900 + k, stage: 't', pass: n }));
  const say = (unit) => {
    let out = '';
    for (const p of disabled) {
      if ((refusal === 'both') || (refusal === 'w-only' && unit === 'w')) { out += REFUSAL(p); continue; }
      if (notes === 'both' || (notes === 'w-only' && unit === 'w')) out += NOTE(p);
    }
    return out;
  };
  const bw = { dir: 'w', code: codes.w, stderr: say('w'), asm: '(assembly)', dumps: [...pairs.map((p) => p.entry), ...extra(onlyW)], texts: texts.w };
  const bwo = { dir: 'wo', code: codes.wo, stderr: say('wo'), asm: '(assembly)', dumps: [...pairs.map((p) => p.entry), ...extra(onlyWo)], texts: texts.wo };
  for (const n of onlyW) texts.w[`out.s.${n}`] = WITH_WIPE;
  for (const n of onlyWo) texts.wo[`out.s.${n}`] = WITH_WIPE;
  return readingFrom(bw, bwo, {
    fn: FN,
    disabled,
    asm: { verdict: asm, control },
    fixtureControl: { verdict: fixture, via: 'oracle' },
    readDump: (b, file) => b.texts[file],
  });
}

/** The exit, which must stop the run rather than be noted and ignored. */
class Exited extends Error {
  constructor(code, report) { super(`exit ${code}`); this.code = code; this.report = report; }
}

/**
 * Run the gcc channel over scripted readings.
 * @param {(tag: string, disabled: string[]) => object} observe
 */
async function drive(observe, { misspellOk = true } = {}) {
  const lines = [];
  const report = { steps: [], interventions: [] };
  const ctx = {
    args: { cc: 'gcc-13', fn: FN, fixtureControl: 'wipe_kept' },
    level: '-O2', work: '(work)', out: '(lab)', suffix: 'gcc-13-O2',
    report, say: (s) => lines.push(s), srcW: '(w.c)', srcWo: '(wo.c)',
    observe: async (tag, disabled) => observe(tag, disabled),
    misspellControl: async (c, rep, s, base) => {
      rep.channelControls = { misspelledPass: `${base}xx`, builtFrom: base, exitCode: misspellOk ? 1 : 0, refused: misspellOk };
      return misspellOk;
    },
    finish: (rep, out, suffix, code) => { throw new Exited(code, rep); },
  };
  try {
    await gccChannel(ctx);
  } catch (e) {
    if (e instanceof Exited) return { code: e.code, report: e.report, lines };
    throw e;
  }
  throw new Error('gccChannel returned without finishing: every path through it must end in finish()');
}

/** The routine walk: p1 is where the wipe stops making a difference. */
const goodWalk = () => reading({});
/** A cut reading that does not bring the property back, and moves the walk on. */
const deadCut = (pass, over = {}) => reading({ disabled: [pass], ...over });

/** The default script: a clean walk, two cuts that change nothing, one cut-both. */
function script(over = {}) {
  return (tag, disabled) => {
    if (tag.startsWith('walk')) return over.walk ?? goodWalk();
    if (tag === 'cut-both') return over.both ?? deadCut(disabled.join('+'), { disabled });
    const key = `cut:${disabled.join('+')}`;
    if (over[key]) return over[key];
    return deadCut(disabled[0], { disabled });
  };
}

// ---------------------------------------------------------------------------
// the four refusals of the walk itself

test('the run that is not refused: two positions, both channels read, nothing came back', async () => {
  const r = await drive(script());
  assert.equal(r.code, 0);
  assert.equal(r.report.verdict.verdict, 'NEVER_CAME_BACK');
  assert.equal(r.report.gateEvidence.positionsTried, 2);
  assert.equal(r.report.gateEvidence.asmChannelRead, true);
  assert.equal(r.report.gateEvidence.controlHeld, true);
  assert.equal(r.report.dumpWalk.status, 'first-indifferent-dump-located');
  assert.equal(r.report.dumpWalk.firstIndifferentDump, '001t.p1');
  assert.equal(r.report.interventions.length, 3, 'two positions and the both-at-once reading');
});

test('DUMP_BUILD_FAILED: the dump build that did not compile is not a walk with nothing in it', async () => {
  const r = await drive(script({ walk: reading({ codes: { w: 1, wo: 0 } }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'DUMP_BUILD_FAILED');
  assert.equal(r.report.verdict.verdict, 'BROKEN_MEASUREMENT');
  assert.equal(r.report.gateEvidence.fatality, 'DUMP_BUILD_FAILED');
});

test('NO_DUMPS: a walk with no dump to read says so, and says it in its own words', async () => {
  const r = await drive(script({ walk: reading({ states: [] }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'NO_DUMPS');
  assert.equal(r.report.gateEvidence.fatality, 'NO_DUMPS');
});

test('FUNCTION_IN_NO_DUMP: a walk that found nothing to read is not a finding about the wipe', async () => {
  // THE SILENT PASS THIS WAVE IS ABOUT. Every dump exists, every dump compiles,
  // and not one of them holds the target function -- so nothing was compared.
  // This used to be `absent-from-first-dump`, reported as "the wipe made no
  // difference in any dump gcc emits", at exit 0.
  const r = await drive(script({ walk: reading({ states: ['NOT_OBSERVED', 'NOT_OBSERVED', 'NOT_OBSERVED'] }) }));
  assert.equal(r.code, 2, 'a walk that read nothing must not exit 0');
  assert.equal(r.report.verdict.reason, 'FUNCTION_IN_NO_DUMP');
  assert.equal(r.report.dumpWalk.dumpsCompared, 3);
  assert.equal(r.report.dumpWalk.dumpsObserved, 0, 'the positive control the channel was missing');
  assert.match(r.report.verdict.why, /not one dump held the target function/);
  assert.ok(!/made no difference/.test(r.report.verdict.why),
    'the apparatus finding nothing must not be reported in the words of a finding about the wipe');
});

test('DUMP_SETS_DISAGREE: dumps one unit wrote and the other did not are counted, not dropped in silence', async () => {
  const r = await drive(script({ walk: reading({ states: ['WIPE_SURVIVED', 'WIPE_ELIMINATED'], onlyW: ['400t.x', '401t.y'], onlyWo: ['500t.z'] }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'DUMP_SETS_DISAGREE');
  assert.equal(r.report.dumpWalk.unpaired.unpaired, 3);
  assert.equal(r.report.dumpWalk.unpaired.union, 5);
  assert.ok(r.lines.some((l) => /unpaired dumps 3\/5/.test(l)), 'the summary must say how many dumps were dropped');
});

test('a few unpaired dumps are reported and the run goes on: the threshold is a threshold', async () => {
  const states = Array.from({ length: 20 }, (_, i) => (i === 0 ? 'WIPE_SURVIVED' : 'WIPE_ELIMINATED'));
  const r = await drive(script({ walk: reading({ states, onlyW: ['400t.x'] }) }));
  assert.equal(r.code, 0);
  assert.equal(r.report.dumpWalk.unpaired.unpaired, 1);
  assert.equal(r.report.dumpWalk.unpaired.overThreshold, false);
});

test('REPLAY_DID_NOT_REPRODUCE: the dump build has to lose what the stock build lost', async () => {
  const r = await drive(script({ walk: reading({ asm: 'WIPE_SURVIVED' }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'REPLAY_DID_NOT_REPRODUCE');
});

test('CONTROL_NOT_PRESENT: a blind oracle produces no readings, on either control', async () => {
  const coResident = await drive(script({ walk: reading({ control: 'ABSENT' }) }));
  assert.equal(coResident.code, 2);
  assert.equal(coResident.report.verdict.reason, 'CONTROL_NOT_PRESENT');
  assert.equal(coResident.report.gateEvidence.controlHeld, false);
  const fixtureOwn = await drive(script({ walk: reading({ fixture: 'ABSENT' }) }));
  assert.equal(fixtureOwn.code, 2);
  assert.equal(fixtureOwn.report.verdict.reason, 'CONTROL_NOT_PRESENT');
});

test('NO_GIMPLE_DUMP: a walk with no GIMPLE dump has no pass name to ask gcc about', async () => {
  const r = await drive(script({ walk: reading({ stage: 'r', states: ['WIPE_ELIMINATED', 'WIPE_ELIMINATED'] }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'NO_GIMPLE_DUMP');
});

test('CHANNEL_NOT_CHECKED: if gcc accepts a name it cannot know, no later reading means anything', async () => {
  const r = await drive(script(), { misspellOk: false });
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'CHANNEL_NOT_CHECKED');
  assert.equal(r.report.interventions.length, 0, 'control (b) runs BEFORE any reading is taken');
});

// ---------------------------------------------------------------------------
// the intervention fatalities

test('INTERVENTION_NOT_ANNOUNCED: a build that succeeded is not a build that was intervened in', async () => {
  const r = await drive(script({ 'cut:p1': deadCut('p1', { disabled: ['p1'], notes: 'none' }) }));
  assert.equal(r.code, 2, 'a no-note reading is fatal, not a row the walk moves past');
  assert.equal(r.report.verdict.reason, 'INTERVENTION_NOT_ANNOUNCED');
  assert.equal(r.report.interventions[0].status, 'no-note');
  // THE FALSE REASON. This path used to ask the gate for its sentence with
  // controlHeld:false, so a run in which both controls were PRESENT reported
  // "the positive control was not PRESENT in every replay" -- and that is the
  // field a reader transcribes.
  assert.ok(!/positive control/.test(r.report.verdict.why), r.report.verdict.why);
  assert.match(r.report.verdict.why, /announc/);
  assert.equal(r.report.verdict.why.startsWith(GCC_EXIT_REASONS.INTERVENTION_NOT_ANNOUNCED), true);
});

test('a note in ONE unit is not a note: the disable has to be announced in both compiles', async () => {
  const r = await drive(script({ 'cut:p1': deadCut('p1', { disabled: ['p1'], notes: 'w-only' }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'INTERVENTION_NOT_ANNOUNCED');
});

test('INTERVENTION_BUILD_FAILED: a build that failed for another reason measured nothing', async () => {
  const r = await drive(script({ 'cut:p1': deadCut('p1', { disabled: ['p1'], codes: { w: 1, wo: 0 }, notes: 'none' }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'INTERVENTION_BUILD_FAILED');
});

test('a refusal in ONE unit is not a refusal, and does not let the walk stroll past half a reading', async () => {
  // gcc refuses the name in the with-wipe unit and builds the ablated one. The
  // refusal used to be read from the with-wipe stderr alone, which made this a
  // `refused-by-gcc` row the walk moved past -- with the other compile
  // unclassified, in a channel whose every reading is a differential pair.
  const r = await drive(script({ 'cut:p1': deadCut('p1', { disabled: ['p1'], refusal: 'w-only', codes: { w: 1, wo: 0 } }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'INTERVENTION_BUILD_FAILED');
  assert.deepEqual(r.report.interventions[0].refusedBy, [], 'half a refusal is not a refusal');
  assert.deepEqual(r.report.interventions[0].refusalAsymmetric, ['p1']);
  assert.match(r.report.verdict.why, /in one unit only/);
});

test('a refusal in BOTH units is the channel working: the walk records it and moves on', async () => {
  const refused = deadCut('p1', { disabled: ['p1'], refusal: 'both', codes: { w: 1, wo: 1 } });
  const r = await drive(script({ 'cut:p1': refused }));
  assert.equal(r.report.interventions[0].status, 'refused-by-gcc');
  assert.notEqual(r.report.verdict.reason, 'INTERVENTION_BUILD_FAILED');
});

// ---------------------------------------------------------------------------
// the cut-both reading, under the same rules as every other reading

test('a cut-both that gcc did not announce is as fatal as any other unannounced intervention', async () => {
  // It was recorded and ignored: the one reading whose whole purpose is to catch
  // an elimination handed on to the next pass entitled to make it, allowed to
  // fail in silence while the run reported NEVER_CAME_BACK at exit 0.
  const r = await drive(script({ both: reading({ disabled: ['p1', 'p2'], notes: 'none' }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'INTERVENTION_NOT_ANNOUNCED');
  assert.match(r.report.verdict.why, /both positions at once/);
});

test('a cut-both whose build failed is fatal too', async () => {
  const r = await drive(script({ both: reading({ disabled: ['p1', 'p2'], notes: 'none', codes: { w: 0, wo: 1 } }) }));
  assert.equal(r.code, 2);
  assert.equal(r.report.verdict.reason, 'INTERVENTION_BUILD_FAILED');
});

test('the cut-both reading\'s controls are the gate\'s evidence, not a reading kept off the books', async () => {
  const r = await drive(script({ both: reading({ disabled: ['p1', 'p2'], control: 'ABSENT' }) }));
  assert.equal(r.report.gateEvidence.controlHeld, false,
    'a control that went missing in the both-at-once reading is a control that went missing');
  assert.equal(r.report.verdict.verdict, 'BROKEN_MEASUREMENT');
  assert.equal(r.code, 2);
});

test('a cut-both that brings the property back is CAME_BACK, and the row says which passes', async () => {
  const r = await drive(script({ both: reading({ disabled: ['p1', 'p2'], asm: 'WIPE_SURVIVED' }) }));
  assert.equal(r.code, 0);
  assert.equal(r.report.verdict.verdict, 'CAME_BACK');
  assert.deepEqual(r.report.gateEvidence.cameBackAt, ['p1+p2']);
  assert.equal(r.report.gateEvidence.positionsTried, 2,
    'cut-both is a third reading of two positions already counted, not a third position');
});

// ---------------------------------------------------------------------------
// what the gate is told, and what a reader is handed

test('asmChannelRead is false when no intervention reading was taken', async () => {
  // A walk that locates nothing in this channel tries no position. Passing
  // `asmChannelRead: true` there asserted a control that could not have failed.
  const r = await drive(script({ walk: reading({ states: ['WIPE_ELIMINATED', 'WIPE_ELIMINATED'] }) }));
  assert.equal(r.code, 0);
  assert.equal(r.report.attributionOutOfChannel.status, 'indifferent-from-first-dump');
  assert.equal(r.report.gateEvidence.positionsTried, 0);
  assert.equal(r.report.gateEvidence.asmChannelRead, false,
    'no intervention was made, so the asm channel was not read for one');
  assert.equal(r.report.verdict.verdict, 'NOT_ENOUGH_EVIDENCE');
});

test('a loss located in an RTL dump is out of this channel and says so, without trying to disable it', async () => {
  // -fdisable-rtl- is a real flag and this tool does not drive it. The run is a
  // result (exit 0) that names no pass, tries no position, and tells the gate it
  // read no asm channel -- rather than sending an RTL pass name to
  // -fdisable-tree- and reading whatever came back.
  const walk = reading({ stage: 'r', states: ['WIPE_SURVIVED', 'WIPE_ELIMINATED'] });
  const r = await drive(script({ walk }));
  assert.equal(r.code, 0);
  assert.equal(r.report.attributionOutOfChannel.stage, 'RTL');
  assert.equal(r.report.attributionOutOfChannel.dump, '001r.p1');
  assert.equal(r.report.interventions.length, 0, 'nothing in this channel was disabled');
  assert.equal(r.report.gateEvidence.positionsTried, 0);
  assert.equal(r.report.gateEvidence.asmChannelRead, false);
  assert.equal(r.report.verdict.verdict, 'NOT_ENOUGH_EVIDENCE');
});

test('every exit writes the gate evidence a reader is told to copy', async () => {
  const cases = [
    script({ walk: reading({ codes: { w: 1, wo: 0 } }) }),
    script({ walk: reading({ states: [] }) }),
    script({ walk: reading({ states: ['NOT_OBSERVED'] }) }),
    script({ walk: reading({ asm: 'WIPE_SURVIVED' }) }),
    script({ walk: reading({ control: 'ABSENT' }) }),
    script({ walk: reading({ states: ['WIPE_ELIMINATED', 'WIPE_ELIMINATED'] }) }),
    script({ 'cut:p1': deadCut('p1', { disabled: ['p1'], notes: 'none' }) }),
    script(),
  ];
  for (const s of cases) {
    const r = await drive(s);
    assert.ok(r.report.gateEvidence, 'gateEvidence is missing on an exit path');
    for (const k of ['positionsTried', 'asmChannelRead', 'irChannelRead', 'cameBackAt', 'replayReproducedLoss', 'controlHeld']) {
      assert.ok(k in r.report.gateEvidence, `gateEvidence has no ${k}`);
    }
    assert.ok(r.report.verdict.verdict, 'every exit records a verdict');
    if (r.code === 2 && r.report.verdict.reason) {
      assert.equal(r.report.gateEvidence.fatality, r.report.verdict.reason);
      assert.equal(r.report.verdict.why, GCC_EXIT_REASONS[r.report.verdict.reason].length > 0
        ? r.report.verdict.why : null);
      assert.ok(r.report.verdict.why.startsWith(GCC_EXIT_REASONS[r.report.verdict.reason]),
        'the sentence a reader transcribes must be the named reason for the exit');
    }
  }
});

test('the misspell control runs once, before any reading, and its outcome is in the report', async () => {
  const seen = [];
  const observe = (tag, disabled) => { seen.push(tag); return script()(tag, disabled); };
  const r = await drive(observe);
  assert.equal(r.code, 0);
  assert.deepEqual(seen, ['walk-gcc-13-O2', 'cut-p1', 'cut-p2', 'cut-both']);
  assert.equal(r.report.channelControls.refused, true);
});

// ---------------------------------------------------------------------------
// the reading itself, assembled from two builds

test('a reading is two compiles: both stderrs, both exit codes, both dump sets', async () => {
  const both = reading({ disabled: ['p1'], notes: 'both' });
  assert.equal(both.noteOk, true);
  assert.deepEqual(both.notes, [{ pass: 'p1', w: true, wo: true }]);
  const oneSided = reading({ disabled: ['p1'], notes: 'w-only' });
  assert.equal(oneSided.noteOk, false, 'a note in one unit is not the intervention having happened');
  const refusedBoth = reading({ disabled: ['p1'], refusal: 'both', codes: { w: 1, wo: 1 } });
  assert.deepEqual(refusedBoth.refusedBy, ['p1']);
  assert.deepEqual(refusedBoth.refusal.asymmetric, []);
  const refusedOne = reading({ disabled: ['p1'], refusal: 'w-only', codes: { w: 1, wo: 0 } });
  assert.deepEqual(refusedOne.refusedBy, []);
  assert.deepEqual(refusedOne.refusal.asymmetric, ['p1']);
});

test('the walk the reading carries is the differential one, and counts what it could read', async () => {
  const r = reading({ states: ['WIPE_SURVIVED', 'NOT_OBSERVED', 'WIPE_ELIMINATED'] });
  assert.deepEqual(r.sequence.map((e) => e.state), ['WIPE_SURVIVED', 'NOT_OBSERVED', 'WIPE_ELIMINATED']);
  assert.equal(r.dumpsCompared, 3);
  assert.equal(r.observedDumps, 2);
  assert.equal(r.located.status, 'first-indifferent-dump-located');
  assert.equal(r.located.entry.key, '002t.p2');
  assert.equal(r.unpaired.unpaired, 0);
});

// ---------------------------------------------------------------------------
// the entry guard, which has a silent-pass shape of its own

test('importing the tool runs nothing, and running it still runs', () => {
  // Importing must not start a measurement -- that is why the guards above can
  // be driven at all. But a guard that fails to recognise its own file makes the
  // tool print nothing and exit 0, which is the quietest failure in this
  // directory, so the CLI is exercised for real.
  assert.equal(INVOKED_AS_CLI, false, 'this file is the entry point here, not the tool');
  const out = execFileSync(process.execPath, [TOOL, '--selftest'], { encoding: 'utf8' });
  assert.match(out, /^PASS  selftest:/m, 'node intervene.mjs --selftest must still run the tool');
});
