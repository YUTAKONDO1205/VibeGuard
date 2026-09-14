/**
 * gcc's `-fdisable-tree-<pass>` channel: everything about it that is pure.
 *
 * `../tools/intervene.mjs` asks one question on clang -- does the property come
 * back if the pass that ate it is taken out of the pipeline -- by replaying the
 * pipeline string clang printed. gcc prints no such string and `opt`/`llc` have
 * no gcc counterpart, so the same question is asked the only way gcc offers:
 *
 *   1. compile once with `-fdump-tree-all`, and walk gcc's own numbered dumps to
 *      find where the wipe stops making a difference;
 *   2. compile again with `-fdisable-tree-<that pass>` and see whether it does.
 *
 * VOCABULARY. THREE READINGS, THREE WORDS, AND WHY THIS FILE OWNS THE THIRD.
 * There are now three things in this repository that a careless sentence would
 * call "where the wipe disappeared", and three different oracles produce them:
 *
 *   clang, in intervene.mjs : the pipeline string the compiler printed, replayed
 *                             under an instrument we drive, prefix by prefix. Its
 *                             result is an attributed POSITION IN A PIPELINE, and
 *                             the pass-plugin observer's word for that is
 *                             `firstLossPass`, which this file never emits.
 *   ../../second-vendor/run-gcc-dump-probe.mjs : gcc's own dumps, read by
 *                             SEARCHING ONE UNIT'S DUMP REGION FOR A TOKEN
 *                             (`memset` and friends). Its word is
 *                             `firstAbsentDump`, and "absent" there means the
 *                             token was not found.
 *   gcc, here               : gcc's own dumps, read DIFFERENTIALLY -- the target
 *                             function's region in the unit as written against
 *                             the same region with the wipe ablated. "The wipe
 *                             made no difference by this dump" is a different
 *                             statement from "no memset token is in this dump"
 *                             and is reached by a different oracle, so it does
 *                             NOT reuse the neighbour's word either. Its word is
 *                             `firstIndifferentDump`.
 *
 * This file therefore emits `firstIndifferentDump`. It never emits `firstLossPass`,
 * never emits `firstAbsentDump` and never emits `attributed.pass`, so no channel's
 * number can be quoted as another's by accident. "gcc's first indifferent dump
 * was 042t.dse1" is supportable. "the loss under gcc was attributed to dse1" is
 * not, and "gcc's first absent dump was 042t.dse1" is the neighbour's sentence
 * about the neighbour's oracle, not a sentence about this one.
 *
 * What the two gcc readings DO share is their weakness, and `../../metamorphic`
 * excludes them for it in the same breath: both are gcc describing its own
 * behaviour to itself through `-fdump-tree-all`, with nothing instrumented and
 * nothing independently confirming that the dump boundary is where the
 * transformation happened. Neither may enter an agreement evidence base.
 *
 * WHAT "INDIFFERENT" MEANS HERE, AND WHAT IT DOES NOT.  The state of a dump is
 * DIFFERENTIAL, exactly as every other verdict in this lane is: the target
 * function's region of the unit as written, against the same region of the unit
 * with the wipe statement ablated. Equal regions mean the wipe made no
 * difference by that dump -- `WIPE_ELIMINATED`; different regions mean it still
 * did -- `WIPE_SURVIVED`. The token reading is computed beside it, separately
 * labelled, and never used as the verdict.
 *
 * The comparison is deliberately strict: the regions are compared as text, minus
 * the `;; Function` header line (which carries uids that are not the body) and
 * blank lines. A renumbered SSA name or a changed block count therefore reads as
 * `WIPE_SURVIVED`. That can only push the located dump LATER, never invent one,
 * which is the direction an over-claim cannot come from -- and the whole
 * sequence is kept and reported (`../../../schema/interfaces.md` section 3), so
 * a state that flips back is visible rather than smoothed away.
 *
 * THE POSITIVE CONTROL THE WALK ITSELF NEEDS. A dump that does not hold the
 * function in both units reads `NOT_OBSERVED`, and a walk made entirely of those
 * read nothing at all. Until 2026-09-14 such a walk returned the substantive
 * finding "the wipe made no difference in any dump gcc emits", so an apparatus
 * that found nothing to read was reported as a result about the wipe and the run
 * exited 0. It is its own named outcome now (`function-in-no-dump`, in
 * `FATAL_WALK_STATUSES`), and `observedDumps()` is the control that separates
 * the two: gcc-13 `-O2 -fdump-tree-all` emits ~122 dumps for a small file on the
 * machine this channel was written for, so zero readable ones is a broken
 * instrument, not a finding about any pass.
 *
 * Nothing here compiles, reads a file or has a top-level side effect.
 */

/** The dump-file suffix gcc writes: `.042t.dse1` in `out.s.042t.dse1`. */
export const DUMP_SUFFIX_RE = /\.(\d+)([tri])\.([A-Za-z0-9_+.-]+)$/;

/**
 * The three dump stages, and the `-fdisable-` family each one belongs to.
 * Only `t` (GIMPLE) is in this file's scope: `-fdisable-rtl-` and
 * `-fdisable-ipa-` are real channels and are NOT driven here, so a loss located
 * in one of those stages is reported as out of this channel's reach rather than
 * disabled with the wrong prefix.
 */
export const STAGES = Object.freeze({
  t: Object.freeze({ what: 'GIMPLE (tree)', flag: '-fdisable-tree-', inScope: true }),
  r: Object.freeze({ what: 'RTL', flag: '-fdisable-rtl-', inScope: false }),
  i: Object.freeze({ what: 'IPA', flag: '-fdisable-ipa-', inScope: false }),
});

/**
 * Read a dump file name. Returns null for anything that is not one, so the
 * assembly and the object in the same directory are not mistaken for dumps.
 * @returns {{num: number, stage: string, pass: string, key: string}|null}
 */
export function dumpSuffix(file) {
  const m = DUMP_SUFFIX_RE.exec(String(file));
  if (!m) return null;
  return { num: Number(m[1]), stage: m[2], pass: m[3], key: `${m[1]}${m[2]}.${m[3]}` };
}

/**
 * gcc's dumps in the order gcc produced them. The number is the whole order:
 * it is one counter over every stage, so `042t` runs before `116t` and before
 * `229r`. Ties (which gcc does not produce) fall back to the stage letter and
 * then the name, so the ordering is total and a run is reproducible.
 */
export function orderDumps(files) {
  return [...files]
    .map((f) => ({ file: f, s: dumpSuffix(f) }))
    .filter((x) => x.s !== null)
    .sort((a, b) => a.s.num - b.s.num || a.s.stage.localeCompare(b.s.stage) || a.s.pass.localeCompare(b.s.pass))
    .map((x) => ({ file: x.file, ...x.s }));
}

/**
 * One function's region out of a gcc dump, normalised.
 *
 * gcc marks each function with `;; Function <name> (<asmname>, funcdef_no=...)`;
 * the header line is dropped because its uids move for reasons that are not the
 * body, exactly as `irBodyOf` drops clang's `define` line. Blank lines and
 * trailing whitespace go; nothing else is rewritten.
 *
 * @returns {string|null} null when this dump holds no such function -- which is
 *   NOT the same as an empty body, and the caller must not read it as one.
 */
export function gimpleRegionOf(text, fn) {
  const lines = String(text ?? '').split('\n');
  const header = /^;; Function\s+(\S+)[\s(]/;
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    const m = header.exec(lines[i]);
    if (m && m[1] === fn) { start = i; break; }
  }
  if (start < 0) return null;
  let end = lines.length;
  for (let j = start + 1; j < lines.length; j++) {
    if (header.test(lines[j])) { end = j; break; }
  }
  return lines.slice(start + 1, end).map((l) => l.replace(/\s+$/, '')).filter((l) => l !== '').join('\n');
}

/**
 * The differential state of one dump: the same question `verdictOf` asks of the
 * assembly, asked of gcc's dump of the same function.
 *
 * `NOT_OBSERVED` when either unit's dump does not hold the function at all --
 * never `WIPE_ELIMINATED`, because a dump that never shows the function is a
 * dump that saw nothing, and reading it as a loss is how a walk manufactures
 * one.
 */
export function dumpState(textW, textWo, fn) {
  const a = gimpleRegionOf(textW, fn);
  const b = gimpleRegionOf(textWo, fn);
  if (a === null || b === null) return 'NOT_OBSERVED';
  return a === b ? 'WIPE_ELIMINATED' : 'WIPE_SURVIVED';
}

/**
 * Does the target's region still spell a zero-fill call? The neighbour probe's
 * kind of reading (`run-gcc-dump-probe.mjs`, `dumpTokens`), kept beside the
 * differential state and never used as it. Corroboration only.
 */
export function memsetTokenPresent(text, fn) {
  const region = gimpleRegionOf(text, fn);
  if (region === null) return null;
  return /\b(?:__builtin_)?(?:memset|__memset_chk|bzero|__builtin_memset_chk)\b/.test(region);
}

/**
 * The whole sequence, one entry per dump the two units share.
 *
 * @param {{key: string, num: number, stage: string, pass: string, w: string, wo: string}[]} dumps
 *   each dump's text in both units, in gcc's order.
 */
export function buildDumpSequence(dumps, fn) {
  return dumps.map((d) => ({
    key: d.key,
    num: d.num,
    stage: d.stage,
    pass: d.pass,
    state: dumpState(d.w, d.wo, fn),
    memsetToken: memsetTokenPresent(d.w, fn),
  }));
}

/**
 * THE WALK'S POSITIVE CONTROL: how many dumps the walk actually read the
 * function in, in BOTH units. Zero is not a reading about the wipe; it is a walk
 * that had nothing to compare, and `firstIndifferentDump` names that case
 * separately for exactly this reason.
 */
export function observedDumps(sequence) {
  return sequence.filter((e) => e.state !== 'NOT_OBSERVED').length;
}

/** The four answers the walk can give, and the one that is an apparatus failure. */
export const WALK_STATUSES = Object.freeze([
  'first-indifferent-dump-located',
  'indifferent-from-first-dump',
  'no-indifference-observed',
  'function-in-no-dump',
]);
export const FATAL_WALK_STATUSES = Object.freeze(['function-in-no-dump']);

/**
 * Where the wipe stops making a difference -- gcc's self-report, read
 * differentially.
 *
 * Four answers. Three are results; the fourth is the apparatus saying it read
 * nothing, and it is deliberately not spelled like any of the three:
 *
 *   `first-indifferent-dump-located` some dump read WIPE_SURVIVED and a later
 *                                 one read WIPE_ELIMINATED. That later one is it.
 *   `indifferent-from-first-dump` the function WAS read, in at least one dump,
 *                                 and no dump ever read WIPE_SURVIVED. The wipe
 *                                 made no difference in any dump gcc emits, so
 *                                 no pass in the sequence can be named for it.
 *   `no-indifference-observed`    the wipe still made a difference in the last
 *                                 dump that holds the function. If the assembly
 *                                 says the wipe is gone, the loss is after the
 *                                 dump that read it, which `-fdisable-tree-` at
 *                                 any position in the walk cannot reach.
 *   `function-in-no-dump`         NOT ONE dump held the function in both units.
 *                                 Nothing was compared, so this says nothing
 *                                 about the wipe, about any pass, or about gcc.
 *                                 FATAL: see `FATAL_WALK_STATUSES`.
 */
export function firstIndifferentDump(sequence) {
  let everSurvived = false;
  let everObserved = false;
  for (const e of sequence) {
    if (e.state === 'NOT_OBSERVED') continue;
    everObserved = true;
    if (e.state === 'WIPE_SURVIVED') { everSurvived = true; continue; }
    if (e.state === 'WIPE_ELIMINATED' && everSurvived) return { status: 'first-indifferent-dump-located', entry: e };
  }
  if (!everObserved) return { status: 'function-in-no-dump', entry: null };
  return { status: everSurvived ? 'no-indifference-observed' : 'indifferent-from-first-dump', entry: null };
}

/** Every state change in the walk, kept because the first transition is not the whole story. */
export function transitionsOf(sequence) {
  const out = [];
  for (let i = 1; i < sequence.length; i++) {
    if (sequence[i].state !== sequence[i - 1].state) {
      out.push({ at: sequence[i].key, from: sequence[i - 1].state, to: sequence[i].state });
    }
  }
  return out;
}

/**
 * A walk that reads eliminated and then survived again later. It is not an
 * error -- a renumbered region is enough to produce one -- but it means the
 * located dump is a boundary in a sequence that is not monotone, and a reader
 * who is not told that would over-read it.
 */
export function flipBacks(sequence) {
  const out = [];
  let seenEliminated = false;
  for (const e of sequence) {
    if (e.state === 'WIPE_ELIMINATED') seenEliminated = true;
    else if (e.state === 'WIPE_SURVIVED' && seenEliminated) out.push(e.key);
  }
  return out;
}

/**
 * THE DUMP SETS THEMSELVES, COMPARED.
 *
 * Both units are compiled with the same flags, so gcc runs the same passes and
 * should write the same set of dump files for each. A dump that exists in one
 * unit and not in the other cannot be read differentially and is dropped --
 * which is correct, and was silent: a walk that dropped most of its dumps
 * reported the same sequence shape as a walk that dropped none.
 *
 * The share is reported always, and a walk that lost more than `maxShare` of the
 * union is refused rather than read, because at that point the sequence being
 * walked is not the sequence either compilation produced.
 */
export const MAX_UNPAIRED_SHARE = 0.1;

export function unpairedReading({ paired, onlyW = [], onlyWo = [] }, maxShare = MAX_UNPAIRED_SHARE) {
  const unpaired = onlyW.length + onlyWo.length;
  const union = paired + unpaired;
  const share = union === 0 ? 0 : unpaired / union;
  return {
    paired, unpaired, union, maxShare,
    share: Number(share.toFixed(4)),
    onlyW: [...onlyW], onlyWo: [...onlyWo],
    overThreshold: union > 0 && share > maxShare,
  };
}

/** The flag that takes one GIMPLE pass out of gcc's pipeline. */
export const disableTreeFlag = (pass) => `-fdisable-tree-${pass}`;

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\-]/g, '\\$&');

/**
 * POSITIVE CONTROL (a). gcc announces a disable on stderr:
 *
 *   cc1: note: disable pass tree-dse1 for functions in the range of [0, 4294967295]
 *
 * The note naming the pass that was asked for is the only evidence that the
 * intervention HAPPENED. A build that succeeds is not evidence: a flag gcc
 * ignored and a flag gcc honoured produce the same exit code, and the second
 * compile would then be the first compile with a longer command line.
 */
export function disableNoteSeen(stderr, pass) {
  return new RegExp(`disable pass\\s+tree-${escapeRe(pass)}\\s+for functions`).test(String(stderr ?? ''));
}

/**
 * POSITIVE CONTROL (b), the other half. gcc refuses a pass name it does not
 * know:
 *
 *   cc1: error: unknown pass tree-dsexx specified in '-fdisable'
 *
 * A channel that silently ignored an unknown name would make control (a)'s
 * absence unreadable -- "no note" would be indistinguishable from "gcc does not
 * announce disables" -- so the refusal is measured rather than assumed, once per
 * run, before any reading is taken from the channel.
 *
 * @param {{code: number, stderr: string}} r the result of the misspelled build
 */
export function unknownPassRefused(r, pass) {
  if (!r || r.code === 0) return false;
  return new RegExp(`unknown pass\\s+tree-${escapeRe(pass)}\\b`).test(String(r.stderr ?? ''));
}

/**
 * gcc's refusal, read in BOTH units of a differential reading.
 *
 * It used to be read in the with-wipe build's stderr only, in a channel whose
 * whole premise is that a reading is two compiles: gcc refusing a name in one
 * unit and accepting it in the other would have been recorded as a plain
 * refusal, and the other half of the pair would have been a compile nobody
 * classified.
 *
 * `refusedBy` is the passes BOTH units refused -- the only shape in which
 * "refused-by-gcc" describes the reading rather than half of it. A pass refused
 * in exactly one unit is `asymmetric`, and the caller must not read that as a
 * refusal: the unit that refused exits non-zero, so `readingStatus` calls the
 * reading `compile-failed`, which is fatal.
 */
export function refusalSplit(w, wo, passes) {
  const refusedInW = passes.filter((p) => unknownPassRefused(w, p));
  const refusedInWo = passes.filter((p) => unknownPassRefused(wo, p));
  const both = refusedInW.filter((p) => refusedInWo.includes(p));
  const asymmetric = [...new Set([...refusedInW, ...refusedInWo])].filter((p) => !both.includes(p));
  return { refusedBy: both, asymmetric, refusedInW, refusedInWo };
}

/**
 * WHAT ONE INTERVENTION READING IS, before anything is concluded from it. The
 * four words are the whole vocabulary, and two of them are fatal to the run:
 *
 *   `intervened`      gcc built both units and ANNOUNCED the disable in both.
 *                     This is the only status a reading may be read from.
 *   `refused-by-gcc`  gcc refused the pass name (`unknown pass tree-...`) in
 *                     BOTH units. Not a fault: it is the channel being checked,
 *                     which is what control (b) proves it does. The walk moves
 *                     to the next candidate.
 *   `compile-failed`  the build failed for some other reason -- including gcc
 *                     refusing the name in one unit only. Fatal: nothing was
 *                     measured and the reason is not this channel's answer.
 *   `no-note`         gcc built it, exit 0, and said nothing about disabling the
 *                     pass. Fatal, and the reason this vocabulary exists: an
 *                     ignored flag and an honoured flag produce the same exit
 *                     code, so "it built" is never evidence that the
 *                     intervention happened.
 */
export const READING_STATUSES = Object.freeze(['intervened', 'refused-by-gcc', 'compile-failed', 'no-note']);
export const FATAL_READING_STATUSES = Object.freeze(['compile-failed', 'no-note']);

/** @param {{refusedBy: string[], codes: {w: number, wo: number}, noteOk: boolean}} r */
export function readingStatus(r) {
  if (r.refusedBy?.length > 0) return 'refused-by-gcc';
  if (r.codes.w !== 0 || r.codes.wo !== 0) return 'compile-failed';
  if (!r.noteOk) return 'no-note';
  return 'intervened';
}

/**
 * Did the property come back in this reading?
 *
 * Four conditions, and dropping any of them is a way to report a repair that was
 * not one: the intervention has to have happened (`intervened`), the ASSEMBLY --
 * not the dump -- has to read `WIPE_SURVIVED` differentially, and both controls
 * have to have been PRESENT in the compile that says so. A survival read in a
 * unit where the control went missing is a blind oracle, not a repair.
 */
export function cameBack(r) {
  return readingStatus(r) === 'intervened'
    && r.asm?.verdict === 'WIPE_SURVIVED'
    && r.asm?.control === 'PRESENT'
    && r.fixtureControl?.verdict === 'PRESENT';
}

/**
 * A pass name gcc cannot know, built from one it does.
 *
 * `taken` is every pass name the run actually saw, and a candidate that collides
 * with one of them is extended until it does not: a "misspelling" that happens
 * to name a real pass would turn control (b) into a pass-disabling build that
 * succeeds, and the control would read as failed for the wrong reason.
 */
export function misspell(pass, taken = []) {
  const seen = new Set(taken);
  let name = `${pass}xx`;
  while (seen.has(name)) name += 'x';
  return name;
}

/**
 * EVERY WAY THIS CHANNEL REFUSES TO PRODUCE A READING, in one place and under
 * one name each.
 *
 * They are here rather than as ten string literals in the driver for two
 * reasons. The first is that `report.verdict.why` is what a reader transcribes
 * when a run lands, and it used to be produced by asking the gate for a sentence
 * about evidence the run had not gathered: a `no-note` fatality -- gcc building
 * without announcing the disable -- was reported as "the positive control was
 * not PRESENT in every replay", which was not what happened. A machine-readable
 * reason that is false is worse than none.
 *
 * The second is that the set itself is documented: `../PIN-FAMILIES.md` names
 * every key below, and `../test/gcc-disable-tree.test.mjs` fails if one of them
 * is missing from that prose, so a refusal reason cannot be added without a
 * reader being told it exists.
 */
export const GCC_EXIT_REASONS = Object.freeze({
  DUMP_BUILD_FAILED: 'the stock compilation compiled and the same compilation with the dumps turned on did not, so there is no walk to read',
  NO_DUMPS: 'gcc produced no dump file this walk could read, so nothing was tracked; that is not evidence about any pass',
  FUNCTION_IN_NO_DUMP: 'not one dump held the target function in both units, so every entry in the walk is NOT_OBSERVED and the walk read nothing about the wipe',
  DUMP_SETS_DISAGREE: 'the two units wrote dump sets that do not match, so most of the walk could not be compared at all and the sequence read is not the sequence either compilation produced',
  REPLAY_DID_NOT_REPRODUCE: 'the stock compilation loses the property and the same compilation with the dumps turned on does not, so the walk would be over a different compilation',
  CONTROL_NOT_PRESENT: 'a positive control was not PRESENT in a compile this reading was taken from, so the oracle was blind there and nothing taken from it is a reading',
  CHANNEL_NOT_CHECKED: 'gcc accepted a pass name it cannot know, so -fdisable-tree- is not checked here and a missing "disable pass" note would prove nothing',
  NO_GIMPLE_DUMP: 'the walk holds no GIMPLE dump at all, so there is no pass name to ask gcc about',
  INTERVENTION_NOT_ANNOUNCED: 'gcc built the intervention without announcing the disable, so nothing says the intervention happened; a build that succeeded is not a build that was intervened in',
  INTERVENTION_BUILD_FAILED: 'the build with the pass disabled failed for a reason that is not gcc refusing the pass name in both units, so nothing was measured',
});

/**
 * The verdict for one of those refusals. `BROKEN_MEASUREMENT` is the gate's own
 * word for "nothing here is a reading" and is kept; the REASON is this channel's
 * and has to be the true one, which is why it is looked up rather than written
 * at the call site. An unknown key throws: a refusal nobody named is not allowed
 * to become a sentence.
 */
export function brokenBecause(key, detail = '') {
  const reason = GCC_EXIT_REASONS[key];
  if (!reason) {
    throw new Error(`brokenBecause: ${key} is not one of this channel's named exit reasons (${Object.keys(GCC_EXIT_REASONS).join(', ')})`);
  }
  return { verdict: 'BROKEN_MEASUREMENT', reason: key, why: detail ? `${reason} -- ${detail}` : reason };
}
