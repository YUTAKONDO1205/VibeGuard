// The checkpoint vocabularies this tree uses, and the map between them.
//
// WHY THIS IS A MODULE, AND NOT A SECTION OF `../schema/interfaces.md`
//
//   Two reasons, and the second is the one that lasts.
//
//   The first is procedural, and the sentence that used to be here got its
//   attribution wrong, so read this one carefully. `../schema/interfaces.md`
//   does NOT ask for this table. Grep it: the file is 313 lines and contains
//   "mapping" zero times, "evidence-v1" zero times and "argv" zero times. The
//   sentence "A canonical mapping table belongs in this section" is real, but it
//   is at `README.md` in THIS directory, under a heading that says exactly what
//   it is — "Suggested text, to be appended to §5". It is a request this lane
//   wrote and §5 has never carried.
//
//   That distinction is the whole point of the rule it was invoking. Quoting the
//   governing document for a requirement the governing document does not make is
//   how a lane's own preference becomes, two readers later, a constraint nobody
//   can find the origin of. What is true is narrower and enough: §5's rule is
//   that nobody edits it while implementing against it, so a table needed NOW
//   cannot go there now. When §5 is next opened for editing, the rows below are
//   the proposal — and it is a proposal, not a deferred obligation.
//
//   The second is that a mapping written in prose is a mapping nobody executes.
//   `produce.mjs` imports this file, so a row that is wrong is a failing test
//   rather than a paragraph that quietly stopped matching the code. The whole
//   reason this table is needed is a defect of exactly that kind: `README.md`
//   records that a producer which copies a policy's `observeAt` straight into
//   `ledger.plannedCheckpoints` gets an imbalance at every checkpoint naming
//   every declared property — a true report whose cause is a spelling
//   difference, and which will not say so. A table that cannot be run would not
//   have prevented it.
//
// WHY THE SPELLINGS WERE NOT SIMPLY UNIFIED
//
//   Not from neglect. `../schema/observation.schema.json`, in the description of
//   `definitions.checkpoint`, states the reason and this module does not restate
//   it differently: the other spellings in this tree "are NOT renamed to these,
//   because pinned digest vectors and frozen manuscript macros are computed over
//   those bytes. They are aliases, and the alias table is the place that says
//   so." Renaming moves bytes; moving bytes moves digests; a digest that moved
//   without a measurement moving is precisely the accident `README.md`'s section
//   "Why rule 1 is a place and not a list of names" is written about.
//
//   So the vocabularies stay where they are and the conversion is explicit,
//   checked, and refusable.
//
// Pure data and pure functions. Nothing here reads a file, a clock or a process.

/**
 * The observation vocabulary: `policy.schema.json` properties[].observeAt and
 * `observation.schema.json` definitions.checkpoint, which
 * `observation-schema.test.mjs` holds identical to each other. In pipeline
 * order, which is the order those two files carry.
 */
export const OBSERVATION_CHECKPOINTS = Object.freeze([
  'invocation',
  'ast',
  'pre-opt-ir',
  'after-pass',
  'object',
  'linked',
  'artifact',
  'process',
]);

/**
 * The record vocabulary: what an `evidence-v0`/`evidence-v1` record's
 * `states[].checkpoint` holds, which is what `STAGE_TABLE` in `./verify.mjs`
 * names the intervals between, and what `compiler/eval/ablation` uses for its
 * layers. In pipeline order.
 */
export const RECORD_CHECKPOINTS = Object.freeze([
  'preprocess',
  'ast',
  'ir-pre',
  'ir-post',
  'asm',
  'artifact',
]);

/**
 * The third spelling, recorded here because the alias table is supposed to be
 * one table rather than one per pair. `compiler/clang-plugin` uses it
 * (`src/Derivation.cpp`, `src/Findings.cpp`). Nothing in this component
 * converts to or from it yet; it is listed so that the next component that has
 * to adds a column here instead of starting a second table somewhere else.
 */
export const PLUGIN_CHECKPOINTS = Object.freeze([
  'ast',
  'ir-pre-opt',
  'ir-post-opt',
  'object',
  'link',
]);

/**
 * How much of the meaning survives one conversion.
 *
 * `near` is not a softer `exact`. It is a row where the two vocabularies cut the
 * pipeline in slightly different places, and a reader who needs the difference
 * has to go back to the original spelling — which is why `produce.mjs` writes
 * the mapping it used into the record rather than only the mapping's output.
 */
export const FIDELITY = Object.freeze({
  EXACT: 'exact',
  NEAR: 'near',
  REFUSED: 'refused',
});

/** A conversion that has no honest answer. Refused, never guessed. */
export class CheckpointVocabularyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CheckpointVocabularyError';
  }
}

/**
 * The table. One row per observation checkpoint, all eight of them, including
 * the two that convert to nothing — a table that listed only the rows with an
 * answer would be indistinguishable from a table somebody forgot to finish.
 */
export const CHECKPOINT_MAP = Object.freeze([
  Object.freeze({
    observation: 'invocation',
    record: null,
    fidelity: FIDELITY.REFUSED,
    why:
      'the record vocabulary begins at the preprocessed translation unit. A command line, before any '
      + 'translation has happened, is not one of its six points, and `preprocess` is a different claim: '
      + 'it says text came out of the preprocessor, which at `invocation` has not run.',
  }),
  Object.freeze({
    observation: 'ast',
    record: 'ast',
    fidelity: FIDELITY.EXACT,
    why: 'the same point under the same name in both vocabularies.',
  }),
  Object.freeze({
    observation: 'pre-opt-ir',
    record: 'ir-pre',
    fidelity: FIDELITY.EXACT,
    why: 'the IR as it enters the optimisation pipeline; two spellings of one point.',
  }),
  Object.freeze({
    observation: 'after-pass',
    record: 'ir-post',
    fidelity: FIDELITY.EXACT,
    why:
      'the IR after a pass of the optimisation pipeline. `STAGE_TABLE` names the ir-pre -> ir-post '
      + 'interval `ir-pass`, and that is the only interval allowed to name a pass (VG-ART-055), which '
      + 'is the same claim `after-pass` makes.',
  }),
  Object.freeze({
    observation: 'object',
    record: 'asm',
    fidelity: FIDELITY.NEAR,
    why:
      'both name the point between the end of the IR pipeline and the link, and `STAGE_TABLE` calls '
      + 'that interval `backend`. They are not the same file: `asm` is the textual assembly, `object` '
      + 'the relocatable it is assembled into. A property that survives the assembler is at the same '
      + 'place under both names; one that does not is at neither, and this row cannot tell you that.',
  }),
  Object.freeze({
    observation: 'linked',
    record: 'artifact',
    fidelity: FIDELITY.NEAR,
    why:
      'the record vocabulary has one point after `asm` and the observation vocabulary has two. '
      + '`STAGE_TABLE` names the asm -> artifact interval `link`, so `linked` lands there — and so does '
      + '`artifact` below. That is what makes the reverse direction not a function.',
  }),
  Object.freeze({
    observation: 'artifact',
    record: 'artifact',
    fidelity: FIDELITY.EXACT,
    why: 'the same point under the same name in both vocabularies.',
  }),
  Object.freeze({
    observation: 'process',
    record: null,
    fidelity: FIDELITY.REFUSED,
    why:
      'an observation read from a process that is RUNNING the linked image, at a defined instant, from '
      + 'outside it. The record vocabulary runs from a translation unit to an artefact and stops; it has '
      + 'no point after the artefact exists, and `artifact` is a claim about a file rather than about a '
      + 'process. A record that needs this checkpoint needs a record vocabulary that has one.',
  }),
]);

const BY_OBSERVATION = new Map(CHECKPOINT_MAP.map((r) => [r.observation, r]));

/**
 * Convert one observation checkpoint to the record vocabulary.
 *
 * @param {string} checkpoint  a member of OBSERVATION_CHECKPOINTS
 * @returns {{checkpoint: string, fidelity: string, why: string}}
 * @throws {CheckpointVocabularyError} for a word this table refuses, and for a
 *   word that is in neither vocabulary. The second case is deliberately not
 *   passed through: a producer handed `ir-post` where an `observeAt` was
 *   expected has read the wrong field, and returning it unchanged would make
 *   that read like a successful conversion.
 */
export function toRecordCheckpoint(checkpoint) {
  const row = BY_OBSERVATION.get(checkpoint);
  if (row === undefined) {
    const known = RECORD_CHECKPOINTS.includes(checkpoint)
      ? ` ${JSON.stringify(checkpoint)} is already a RECORD checkpoint; this converts the other`
        + ' direction, and converting a record checkpoint again is how one silently becomes another.'
      : '';
    throw new CheckpointVocabularyError(
      `${JSON.stringify(checkpoint)} is not one of the observation checkpoints `
        + `${OBSERVATION_CHECKPOINTS.join(', ')}.${known}`,
    );
  }
  if (row.record === null) {
    throw new CheckpointVocabularyError(
      `the observation checkpoint ${JSON.stringify(checkpoint)} has no counterpart in the record `
        + `vocabulary (${RECORD_CHECKPOINTS.join(', ')}): ${row.why}`,
    );
  }
  return { checkpoint: row.record, fidelity: row.fidelity, why: row.why };
}

/**
 * Which observation checkpoints land on one record checkpoint.
 *
 * There is no `fromRecordCheckpoint`, and the absence is the point: `linked`
 * and `artifact` both map to `artifact`, so the reverse is a relation and not a
 * function. A helper that returned one of the two would be choosing, and a
 * producer that needs to choose has to say on what grounds.
 *
 * @returns {string[]} possibly empty — nothing maps to `preprocess`.
 */
export function recordCheckpointSources(checkpoint) {
  if (!RECORD_CHECKPOINTS.includes(checkpoint)) {
    throw new CheckpointVocabularyError(
      `${JSON.stringify(checkpoint)} is not one of the record checkpoints ${RECORD_CHECKPOINTS.join(', ')}`,
    );
  }
  return CHECKPOINT_MAP.filter((r) => r.record === checkpoint).map((r) => r.observation);
}

/** Where a checkpoint sits in the record pipeline. For ordering `states[]`. */
export function recordCheckpointOrder(checkpoint) {
  const i = RECORD_CHECKPOINTS.indexOf(checkpoint);
  if (i === -1) {
    throw new CheckpointVocabularyError(
      `${JSON.stringify(checkpoint)} is not one of the record checkpoints ${RECORD_CHECKPOINTS.join(', ')}`,
    );
  }
  return i;
}

/**
 * The lane maps: which record checkpoint one lane's CELL sits at.
 *
 * WHY THIS IS A SECOND TABLE AND NOT MORE ROWS IN THE FIRST
 *
 *   The table above answers "which record checkpoint does this observation
 *   checkpoint name", for one pipeline. A lane can observe the same checkpoint
 *   word in TWO pipelines in one run, and then the word alone no longer decides.
 *
 *   `compiler/eval/lto-window` is that lane and is why this table exists. Every
 *   cell it writes carries `checkpoint: 'after-pass'` — the constant
 *   `CHECKPOINT_AFTER_PASS` in `compiler/eval/lto-window/lib/cell.mjs` — and the
 *   cells are told apart by `stage`, which is `compile` for a reading taken at
 *   the end of the compile-time pass pipeline and `lto-backend` for one taken in
 *   the LTO backend at link time. Sent through `toRecordCheckpoint` alone both
 *   land on `ir-post`, two cells then post to one ledger cell, and `postLedger`
 *   books the pair as UNACCOUNTED with the reason "2 states carry this
 *   checkpoint". The lane's whole result disappears into a finding about its own
 *   producer.
 *
 *   The re-basing that fixes it has to be stated rather than inferred. The
 *   record this lane produces is a record ABOUT THE LTO BACKEND PIPELINE: that
 *   is the window the lane exists to measure. Relative to that pipeline the
 *   compile-time reading is the state of the IR that ENTERS it — `ir-pre` — and
 *   the link-time reading is the state after its passes have run — `ir-post`.
 *   The compile-time cell is not being called something it is not; it is being
 *   placed in the pipeline the record is written about, and under the
 *   observation vocabulary the same reading would be that pipeline's
 *   `pre-opt-ir`.
 *
 *   WHY, IN THE ORDER THAT MATTERS. An adversarial review of this file read the
 *   paragraph that used to be here and asked the right question: is this row
 *   chosen because of what the verifier will accept? The answer is no, and the
 *   reason it used to look like yes is that this paragraph led with the
 *   consequence instead of the reason. Measured, the two are separable:
 *
 *     GENERAL TABLE   (after-pass, compile)     -> ir-post
 *                     (after-pass, lto-backend) -> ir-post
 *
 *   Both readings land on ONE record checkpoint. For `xtu.full` the compile
 *   reading is `ABSENT` and the link reading is `LOST`, so such a record asserts
 *   two different states at a single point in the pipeline. That is incoherent
 *   on its own terms, before any check is consulted: the whole finding of this
 *   lane is a state CHANGE, and a change needs two points. The general table has
 *   exactly one word for "after a pass" and this lane observes two pass
 *   pipelines, so the general table cannot express what was measured.
 *
 *   THEN the consequence, which is real but is not the reason. `STAGE_TABLE`
 *   maps ir-pre -> ir-post to `ir-pass`, and `ir-pass` is the only interval
 *   `verify.mjs` lets a record name a pass at (VG-ART-055). Distinguishing the
 *   two readings — which the paragraph above requires independently — also makes
 *   the interval one that may name a pass. Had the general table been able to
 *   hold the two readings apart in some other way, that placement would have
 *   been the right one and this row would not exist.
 *
 *   The test `the general table cannot hold this lane's two readings apart` in
 *   test/checkpoint-map.test.mjs pins the first paragraph, so the justification
 *   is checkable rather than argued.
 */
export const LANE_CHECKPOINT_MAPS = Object.freeze({
  'lto-window': Object.freeze([
    Object.freeze({
      checkpoint: 'after-pass',
      stage: 'compile',
      record: 'ir-pre',
      fidelity: FIDELITY.NEAR,
      why:
        'the end of the compile-time pass pipeline is the IR that enters the LTO backend pipeline, '
        + 'which is the pipeline this lane\'s record is written about. Under the observation vocabulary '
        + 'the same reading is that pipeline\'s `pre-opt-ir`.',
    }),
    Object.freeze({
      checkpoint: 'after-pass',
      stage: 'lto-backend',
      record: 'ir-post',
      fidelity: FIDELITY.EXACT,
      why: 'after a pass of the LTO backend pipeline, which is what `after-pass` says.',
    }),
  ]),
});

/**
 * The record checkpoint one lane cell sits at.
 *
 * @param {string} lane  the lane's own name, as its result's `lane` field spells it
 * @param {{checkpoint: string, stage: string}} cell
 * @returns {{checkpoint: string, fidelity: string, why: string}}
 * @throws {CheckpointVocabularyError} when the lane has no table, or the table
 *   has no row for this (checkpoint, stage) pair. Falling back to
 *   `toRecordCheckpoint` here would be the exact failure this table exists to
 *   prevent: it would answer for a pair nobody has decided about.
 */
export function laneCheckpoint(lane, cell) {
  const rows = LANE_CHECKPOINT_MAPS[lane];
  if (rows === undefined) {
    throw new CheckpointVocabularyError(
      `no checkpoint table for the lane ${JSON.stringify(lane)}. Tables are per lane because a lane can `
        + 'observe one checkpoint word in more than one pipeline, and which pipeline a record is written '
        + 'about is a decision rather than a lookup. Add a row set for it here.',
    );
  }
  const cp = cell === null || typeof cell !== 'object' ? undefined : cell.checkpoint;
  const stage = cell === null || typeof cell !== 'object' ? undefined : cell.stage;
  const row = rows.find((r) => r.checkpoint === cp && r.stage === stage);
  if (row === undefined) {
    throw new CheckpointVocabularyError(
      `${lane} has no row for checkpoint ${JSON.stringify(cp ?? null)} at stage `
        + `${JSON.stringify(stage ?? null)}. The rows it has are `
        + `${rows.map((r) => `${r.checkpoint}@${r.stage}`).join(', ')}.`,
    );
  }
  return { checkpoint: row.record, fidelity: row.fidelity, why: row.why };
}

/**
 * The field separator for the composite keys below.
 *
 * Built from a code point rather than written as a literal, and that is not a
 * flourish: a NUL byte in the source makes `scripts/check-disclosure-shape.mjs`
 * classify the file as binary and SKIP it — counted in its `skipped:` line,
 * invisible in a normal run, and never scanned again. That happened once, to
 * `machine.mjs`, and `test/store-cli.test.mjs` carries the case that catches it.
 */
const SEP = String.fromCharCode(0);

/**
 * The mapping a producer used, in the shape it writes into a record.
 *
 * Recording which mapping was used is this lane's own rule, proposed for §5 in
 * `README.md` and not yet part of it (see the header: `interfaces.md` says
 * nothing about mappings). It is not decoration: every `near` row above loses a
 * distinction, and a
 * reader who needs it back has to know which row was applied. Only the rows that
 * were actually used are written — a record carrying the whole table would say
 * nothing about that record.
 *
 * @param {string} lane
 * @param {Array<{from: string, stage?: string|null, to: string, fidelity: string}>} used
 */
export function mappingRecord(lane, used) {
  const seen = new Set();
  const rows = [];
  for (const u of used) {
    const key = `${u.from}${SEP}${u.stage ?? ''}${SEP}${u.to}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push({ from: u.from, stage: u.stage ?? null, to: u.to, fidelity: u.fidelity });
  }
  rows.sort((a, b) => a.from.localeCompare(b.from) || String(a.stage).localeCompare(String(b.stage)));
  return {
    from: 'observation',
    to: 'record',
    lane,
    table: 'compiler/evidence/checkpoint-map.mjs',
    // Not `interfaces.md section 5`, which this field said until 2026-09-12.
    // Section 5 fixes the canonicalisation rules and the `toolchain` block and
    // says nothing about checkpoint vocabularies or mappings between them (grep
    // it for "mapping": zero). Naming it here put a citation to an unratified
    // proposal inside every record this producer writes, where it would have
    // outlived the comment that made the same claim. The rule this record obeys
    // is this directory's own, and the field says so.
    contract: 'compiler/evidence/checkpoint-map.mjs (this lane\'s rule; proposed for interfaces.md section 5 in compiler/evidence/README.md, not part of it)',
    rows,
  };
}
