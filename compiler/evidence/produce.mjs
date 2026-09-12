#!/usr/bin/env node
// The producer: one lane result in, one `evidence-v1` record out.
//
// WHY THIS FILE EXISTS
//
//   Until it did, this component was a verifier with nothing to verify.
//   `README.md` said so in as many words — "the producer side of this is a
//   specification and nothing more" — and every `evidence-v1` record the suite
//   scored was a fixture written by hand in `testdata/`, which means every check
//   here had been exercised against records authored to exercise it. A verifier
//   calibrated only on its own fixtures is calibrated on the verifier's author's
//   idea of what a producer does.
//
//   So this converts an actual lane result into a record and a declaration, and
//   the tests in `test/produce.test.mjs` run the result of that conversion
//   through `verify.mjs` as a subprocess. What it finds is what a real producer
//   hits, not what a fixture was shaped to hit.
//
// THE ONE RULE THIS FILE IS ORGANISED AROUND
//
//   `declared` comes from the DECLARATION and never from the record being
//   written. `ledger.mjs` states it, `README.md` states it, and it is the whole
//   value of VG-ART-064..068: a producer that computed both books from one
//   source would emit records that balance by construction, the ledger would
//   hold for every record ever written, and the check would be theatre that
//   costs CI time.
//
//   Mechanically that means two entry points, run at two different times
//   against two different inputs:
//
//     --declare   policy  ->  evidence-declaration-v1 document   (before the run)
//     (default)   lane result + that document  ->  evidence-v1 record  (after it)
//
//   The second reads the first's OUTPUT as an input and copies its counts; it
//   never recomputes them from what was measured. When the declaration is
//   absent it refuses and writes nothing — see `DECLARATION_ABSENT`. Inventing
//   a declaration from the record's own properties is the single failure this
//   design exists to prevent, so it is not a fallback, a default, or a warning.
//
//   The residual limit is the one `README.md` already discloses and this file
//   does not pretend to close: both documents pass through one producer, so a
//   producer that mis-read the policy mis-reads it into both. What closes THAT
//   is the policy — a document neither of them wrote — and pointing
//   `verify.mjs --declared` at the declaration built from it is what makes the
//   external source the one in force.
//
// WHAT THIS FILE DELIBERATELY DOES NOT IMPORT
//
//   `verify.mjs`'s `STAGE_TABLE`, and `ledger.mjs`'s `postLedger` and
//   `VERDICT_ACCOUNT`. All three are reimplemented below. That is not an
//   oversight and it is not duplication for its own sake: `README.md`'s
//   "Independence" section refuses to let the verifier import the generator,
//   for the reason that two sides sharing an implementation agree by
//   construction and prove nothing. The same argument runs in this direction.
//   A producer that derived `firstLoss.stage` from the verifier's own table
//   could never trip VG-ART-054, and one that wrote `ledger.entries` with
//   `postLedger` could never trip VG-ART-065 — the two checks would be
//   permanently silent for exactly the records they were added for.
//
//   `readDeclaration` IS imported, and the asymmetry is deliberate. The
//   declaration is an INPUT to both sides rather than an output of either, and
//   a producer that accepted declarations the verifier refuses would emit
//   records whose ledger is UNCHECKED — exit 3 — with nothing pointing at the
//   cause.
//
// NO CLOCK IS READ HERE. `clock.mjs` is the only file in this component allowed
// to, `verify.mjs --clock-audit` walks this directory, and `sealRecord` attaches
// `context` from that one source.
//
// Licence: Apache-2.0 WITH LLVM-exception (see ../LICENSE).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sealRecord } from './canon.mjs';
import { reportCounts } from './counting.mjs';
import {
  laneCheckpoint,
  mappingRecord,
  recordCheckpointOrder,
  toRecordCheckpoint,
  CheckpointVocabularyError,
} from './checkpoint-map.mjs';
import { DECLARATION_SCHEMA_VERSION, LEDGER_SCHEMA_VERSION, readDeclaration } from './ledger.mjs';
import { REPO_ROOT } from './store.mjs';

const EXIT_OK = 0;
const EXIT_INCOMPLETE = 3;
const EXIT_REFUSED = 4;

/** A refusal. Nothing is written after one is thrown. */
export class ProducerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProducerError';
  }
}

/**
 * The message for the refusal this whole file is arranged around, spelled once
 * so that the test asserting it and the code raising it cannot drift.
 */
export const DECLARATION_ABSENT =
  'no declaration was given, and a declaration is not something a producer may supply for itself. '
  + 'The ledger holds the record against the accounts that were opened BEFORE the run; derived from '
  + 'the record the identity holds for every record ever written and VG-ART-064..068 check nothing. '
  + `Build one first with \`--declare --policy <policy.json> --out <declaration.json>\`, or name an `
  + `existing ${DECLARATION_SCHEMA_VERSION} document with --declaration.`;

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

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

/* ---------------------------------------------------------- declaration -- */

/**
 * Build an `evidence-declaration-v1` document from a policy.
 *
 * This is the step where the checkpoint vocabularies meet. A policy states its
 * checkpoints in `observeAt`, whose words are `checkpoint-map.mjs`'s
 * OBSERVATION_CHECKPOINTS; a record's `states[].checkpoint` uses
 * RECORD_CHECKPOINTS. Copying `observeAt` across unchanged is the defect
 * `README.md` names under "A checkpoint vocabulary mismatch": every cell would
 * be unaccounted, at every checkpoint, for every declared property, and the
 * finding would be true and would not say why.
 *
 * Two refusals are worth reading before the code:
 *
 *   - A property with no `observeAt` is refused rather than given the policy's
 *     whole list. `ledger.mjs`'s `readDeclaration` already refuses a property
 *     planned at no checkpoint, for the reason that it opens no account while
 *     still counting as declared. Guessing a list for it here would put the same
 *     property back, with a plan nobody wrote.
 *
 *   - Two `observeAt` words that land on ONE record checkpoint are refused, not
 *     de-duplicated. `linked` and `artifact` both map to `artifact`; a policy
 *     that plans both plans two observations, and a declaration that turned them
 *     into one cell would quietly halve that property's denominator. The record
 *     vocabulary cannot hold them apart, so this is reported rather than
 *     emitted, which is what `../schema/interfaces.md` §5 asks of a component
 *     that cannot express what it was given.
 *
 * @param {unknown} policy  a `.vgpolicy.json` document (`../schema/policy.schema.json`)
 * @param {{lane?: string|null}} [opts]
 * @returns {object} the declaration document, ready to write
 */
export function declarationFromPolicy(policy, opts = {}) {
  if (!isObject(policy)) throw new ProducerError('the policy is not a JSON object');
  const props = policy.properties;
  if (!Array.isArray(props) || props.length === 0) {
    throw new ProducerError(
      'the policy declares no properties. A declaration with no accounts balances for every record and '
        + 'says nothing about any of them, which is why `readDeclaration` refuses one.',
    );
  }

  const properties = [];
  const used = [];
  const plannedAll = new Set();
  for (let i = 0; i < props.length; i += 1) {
    const p = props[i];
    if (!isObject(p) || !isNonEmptyString(p.id)) {
      throw new ProducerError(`the policy's property ${i} has no id; an account with no name cannot be posted to`);
    }
    if (!Array.isArray(p.observeAt) || p.observeAt.length === 0) {
      throw new ProducerError(
        `${p.id} names no observeAt. A property planned at no checkpoint opens no account, posts to no `
          + 'column, and still counts as declared; the policy has to say where it is observed, and this '
          + 'does not choose for it.',
      );
    }
    const own = [];
    const from = new Map();
    for (const word of p.observeAt) {
      let mapped;
      try {
        mapped = toRecordCheckpoint(word);
      } catch (e) {
        if (!(e instanceof CheckpointVocabularyError)) throw e;
        throw new ProducerError(`${p.id}: ${e.message}`);
      }
      if (from.has(mapped.checkpoint)) {
        throw new ProducerError(
          `${p.id} plans both ${JSON.stringify(from.get(mapped.checkpoint))} and ${JSON.stringify(word)}, `
            + `which both convert to the record checkpoint ${JSON.stringify(mapped.checkpoint)}. Those are `
            + 'two observations in the policy and would be one cell in the ledger, so the property\'s '
            + 'denominator would silently halve. The record vocabulary cannot hold them apart; this is '
            + 'reported rather than emitted.',
        );
      }
      from.set(mapped.checkpoint, word);
      own.push(mapped.checkpoint);
      used.push({ from: word, stage: null, to: mapped.checkpoint, fidelity: mapped.fidelity });
      plannedAll.add(mapped.checkpoint);
    }
    own.sort((a, b) => recordCheckpointOrder(a) - recordCheckpointOrder(b));
    properties.push({ propertyId: p.id, plannedCheckpoints: own });
  }

  const plannedCheckpoints = [...plannedAll].sort((a, b) => recordCheckpointOrder(a) - recordCheckpointOrder(b));
  const declaration = {
    schemaVersion: DECLARATION_SCHEMA_VERSION,
    plannedCheckpoints,
    properties,
    // Where the accounts came from, carried so that a reader of the declaration
    // alone can tell a plan from a summary of what happened. `readDeclaration`
    // ignores it; it is here for the person, not for the check.
    source: {
      kind: 'policy',
      lane: opts.lane ?? null,
      checkpointMapping: mappingRecord(opts.lane ?? null, used),
    },
  };
  // Refused here rather than at the far end: a declaration this component's own
  // reader will not accept is one `verify.mjs` reports as UNCHECKED, exit 3,
  // with nothing naming the producer that wrote it.
  readDeclaration(declaration, 'the declaration about to be written');
  return declaration;
}

/* ------------------------------------------------------------ the lane -- */

/**
 * The subject a lane cell is a reading OF.
 *
 * `compiler/eval/lto-window` names its cells `<fixture>.<form>.<window>`, and
 * the window is the checkpoint axis — `compile` and `link` are two readings of
 * one subject, which is the pair this producer has to turn into one property
 * with two states. So the subject is what is left when the window is taken off.
 *
 * The vendor is part of it, and that is not decoration. `gccProbes` pushes a
 * cell with id `<fixture>.gcc.link` whose `form` is `full` — the same
 * `<fixture>.full` as the clang link cell beside it. Two cells sharing a subject
 * key post twice to one ledger cell, `postLedger` books the pair as UNACCOUNTED
 * ("2 states carry this checkpoint"), and the lane's gcc row takes the clang row
 * down with it.
 *
 * A cell that carries its own `propertyId` wins, so that a lane which grows one
 * does not have to be understood by this function at all.
 */
export function subjectKeyOf(lane, cell) {
  if (!isObject(cell)) throw new ProducerError('a lane cell is not a JSON object');
  if (isNonEmptyString(cell.propertyId)) return cell.propertyId;
  for (const k of ['fixture', 'form', 'vendor']) {
    if (!isNonEmptyString(cell[k])) {
      throw new ProducerError(
        `the lane cell ${JSON.stringify(cell.id ?? null)} has no ${k}, and no propertyId either. A `
          + 'property this producer cannot name is a property nothing can be declared about.',
      );
    }
  }
  return `${lane}.${cell.fixture}.${cell.form}.${cell.vendor}`;
}

/**
 * The lane's section-3 state word, and the record's coarse verdict for it.
 *
 * `../schema/interfaces.md` §3 has six state words and the record's ledger has
 * three verdicts, so this is many-to-one on purpose. The two that matter:
 * `LOST` is ABSENT — it was there and it is not now, which is a claim about the
 * property — and `NOT_OBSERVED` is UNOBSERVED and never ABSENT, which is the
 * distinction the whole component is built to keep.
 */
const VERDICT_FOR_STATE = Object.freeze({
  PRESENT: 'PRESENT',
  REINTRODUCED: 'PRESENT',
  ABSENT: 'ABSENT',
  LOST: 'ABSENT',
  NOT_OBSERVED: 'UNOBSERVED',
});

/**
 * The interval a loss is attributed to.
 *
 * A DELIBERATE SECOND COPY of `STAGE_TABLE` in `verify.mjs`. See the header:
 * importing it would make VG-ART-054 unfireable for every record this file
 * writes, which is the one record population the check was added for. If the two
 * tables disagree, `test/produce.test.mjs`'s round trip fails — which is the
 * check working, and is the only thing that should ever bring them back into
 * line.
 */
const LOSS_INTERVAL = Object.freeze([
  Object.freeze({ last: null, first: 'preprocess', stage: 'preprocess' }),
  Object.freeze({ last: 'preprocess', first: 'ast', stage: 'ast' }),
  Object.freeze({ last: 'ast', first: 'ir-pre', stage: 'frontend-codegen' }),
  Object.freeze({ last: 'preprocess', first: 'ir-pre', stage: 'frontend-codegen' }),
  Object.freeze({ last: 'ir-pre', first: 'ir-post', stage: 'ir-pass' }),
  Object.freeze({ last: 'ir-post', first: 'asm', stage: 'backend' }),
  Object.freeze({ last: 'asm', first: 'artifact', stage: 'link' }),
]);

/** The one interval allowed to name a pass — VG-ART-055. */
const PASS_NAMING_STAGE = 'ir-pass';

function stageOfLoss(lastSeen, firstMissing) {
  if (firstMissing === null) return null;
  const row = LOSS_INTERVAL.find((r) => r.last === lastSeen && r.first === firstMissing);
  return row ? row.stage : 'compile';
}

/**
 * `agreement.level` and the `confidence` word it maps to.
 *
 * A SECOND COPY of `CONFIDENCE_BY_LEVEL` in `verify.mjs`, for the reason in the
 * header: shared, VG-ART-053 could not fire for anything this file writes.
 *
 * Only the three levels this producer can reach are here. A lane that reads a
 * property by two methods gets a row when there is a lane that does; writing the
 * other four now would be writing a mapping nothing has exercised.
 */
const CONFIDENCE_FOR_LEVEL = Object.freeze({
  single: 'provisional',
  'not-applicable': 'no-loss-observed',
  none: 'unresolved',
});

/**
 * How sure the run is about one property, from what it managed to read.
 *
 * `single` is the honest level for `lto-window`: every verdict it reaches comes
 * from one instrument, the pass observer's own history, and a second method
 * would be a second instrument rather than a second reading from this one.
 */
function agreementFor(states, unit) {
  const read = states.filter((s) => s.verdict !== 'UNOBSERVED');
  if (read.length === 0) return { level: 'none', methods: [], reportedUnits: {} };
  const level = read.some((s) => s.verdict === 'ABSENT') ? 'single' : 'not-applicable';
  return {
    level,
    methods: ['ir'],
    reportedUnits: isNonEmptyString(unit) ? { ir: unit } : {},
  };
}

/**
 * Turn one lane cell into one record state.
 *
 * `effect` and `control` are not written. The v0 fixtures carry them as 0/1
 * counts of a differential this lane does not take; what it measures instead is
 * whether the positive control HELD, which is a different fact and is carried
 * under its own name. Writing a plausible integer into a field this lane never
 * measured is the one thing a producer must not do.
 */
function stateFrom(checkpoint, cell) {
  const verdict = VERDICT_FOR_STATE[cell.state];
  if (verdict === undefined) {
    throw new ProducerError(
      `the lane cell ${JSON.stringify(cell.id ?? null)} has state ${JSON.stringify(cell.state ?? null)}, `
        + `which is not one of ${Object.keys(VERDICT_FOR_STATE).join(', ')}. There is no verdict to post `
        + 'it under, and choosing the nearest one is how a state nobody read becomes a state somebody did.',
    );
  }
  const reasons = Array.isArray(cell.reasons) ? cell.reasons.filter(isNonEmptyString) : [];
  if (verdict === 'UNOBSERVED' && reasons.length === 0) {
    throw new ProducerError(
      `the lane cell ${JSON.stringify(cell.id ?? null)} read nothing and gives no reason. `
        + '`compiler/eval/lto-window/lib/cell.mjs` refuses to produce that cell; a record carrying one '
        + 'would say "we did not look" with no answer to "why not", which is the suspense account with '
        + 'the narrative taken out.',
    );
  }
  return {
    checkpoint,
    verdict,
    state: cell.state,
    measurement: cell.measurement ?? null,
    // The lane's own word for whether the positive control held: true measured
    // and held, false measured and fell, null never measured. Kept apart from
    // the verdict on purpose — a control that fell is why a reading means
    // nothing, not a reading in itself.
    controlHeld: cell.controlHeld ?? null,
    reasons,
  };
}

/**
 * One record property, from the readings of one subject.
 *
 * @param {string} propertyId
 * @param {Array<{checkpoint: string, cell: object}>} readings  already in pipeline order
 */
function propertyFrom(propertyId, readings) {
  const states = readings.map((r) => stateFrom(r.checkpoint, r.cell));

  // The first ABSENT, and the last PRESENT before it. Walked over the record's
  // own states in pipeline order, which is the same walk `verify.mjs` makes and
  // has to be, because the field it produces is the one that is compared.
  const idx = states.findIndex((s) => s.verdict === 'ABSENT');
  let lastSeen = null;
  for (let k = idx - 1; k >= 0; k -= 1) {
    if (states[k].verdict === 'PRESENT') {
      lastSeen = states[k].checkpoint;
      break;
    }
  }
  const firstMissing = idx === -1 ? null : states[idx].checkpoint;
  const stage = stageOfLoss(lastSeen, firstMissing);

  // The lane attributes a pass; the record may only carry one when the interval
  // is `ir-pass`. When it is not, the attribution is NOT dropped — it is carried
  // beside `firstLoss` under a name `verify.mjs` does not read, because a
  // measurement that was taken and then omitted for want of a field to put it in
  // is a measurement nobody can check. `lineKinds` in
  // `compiler/eval/lto-window/lib/record.mjs` was lost exactly that way.
  const attributed = idx === -1 ? null : (readings[idx].cell.attribution ?? null);
  const mayNamePass = stage === PASS_NAMING_STAGE;
  const seq = idx === -1 ? null : (readings[idx].cell.subjectHistory?.firstLoss?.seq ?? null);

  const evaluated = states.filter((s) => s.verdict !== 'UNOBSERVED').length;
  const lost = states.filter((s) => s.verdict === 'ABSENT').length;

  const agreement = agreementFor(states, attributed?.unit ?? null);
  return {
    propertyId,
    states,
    firstLoss: {
      stage,
      pass: mayNamePass ? (attributed?.pass ?? null) : null,
      unit: attributed?.unit ?? null,
      occurrence: mayNamePass && Number.isInteger(seq) ? seq : null,
    },
    // The lane's reading, verbatim, whether or not `firstLoss` was allowed to
    // repeat it. `null` when the run attributed nothing.
    laneAttribution: attributed,
    agreement,
    confidence: CONFIDENCE_FOR_LEVEL[agreement.level],
    fragility: { lost, evaluated },
  };
}

/* ------------------------------------------------------------- envelope -- */

/**
 * The `../schema/interfaces.md` §5 blocks the lane result does not carry.
 *
 * `toolchain` there is `{digest, clang|gcc, packages}` where `digest` is the
 * sha256 of the PINNED SET — a measurement `record-run.mjs` takes by hashing
 * each binary. A lane result carries version strings and a plugin hash and no
 * such digest, and `command.argv` it carries not at all. Both are therefore
 * inputs to this producer rather than derivations from the lane: there is
 * nothing to derive them from, and a producer that filled them in with what was
 * to hand would be writing a claim about a toolchain nobody hashed.
 *
 * One file, named on the command line, so that the person who knows what ran
 * writes it down once.
 */
export function readEnvelope(envelope) {
  if (!isObject(envelope)) {
    throw new ProducerError(
      'no envelope was given. interfaces.md §5 requires `toolchain` and a non-empty `command.argv` on '
        + 'every record, a lane result carries neither in that shape, and nothing here will invent them. '
        + 'Pass --envelope <file> holding {"toolchain": {...}, "command": {"argv": [...]}}.',
    );
  }
  if (!isObject(envelope.toolchain)) {
    throw new ProducerError('the envelope has no `toolchain` object (interfaces.md §5)');
  }
  if (!isObject(envelope.command) || !Array.isArray(envelope.command.argv) || envelope.command.argv.length === 0) {
    throw new ProducerError(
      'the envelope has no non-empty `command.argv`. VG-ART-052: a record describes a compilation, and '
        + 'its argv is never empty.',
    );
  }
  const out = { toolchain: envelope.toolchain, command: envelope.command };
  if (envelope.artifact !== undefined) out.artifact = envelope.artifact;
  return out;
}

/* ------------------------------------------------------------ producing -- */

/**
 * Produce one `evidence-v1` record from one lane result and one declaration.
 *
 * @param {object} args
 * @param {object} args.lane         the lane's own result document
 * @param {object} args.declaration  an `evidence-declaration-v1` document. REQUIRED.
 * @param {object} args.envelope     interfaces.md §5's `toolchain` and `command`
 * @param {object} [args.context]    passed to `sealRecord`; omitted, `clock.mjs` decides
 * @returns {{record: object, counts: {inputs: number, checked: number, skipped: number}, imbalances: object[]}}
 */
export function produceRecord({ lane, declaration, envelope, context } = {}) {
  if (declaration === undefined || declaration === null) throw new ProducerError(DECLARATION_ABSENT);
  if (!isObject(lane)) throw new ProducerError('the lane result is not a JSON object');
  const laneName = lane.lane;
  if (!isNonEmptyString(laneName)) {
    throw new ProducerError(
      'the lane result does not name its lane. The checkpoint table is per lane — see '
        + '`checkpoint-map.mjs` LANE_CHECKPOINT_MAPS — so a result that does not say which lane it is '
        + 'cannot be placed in a pipeline.',
    );
  }
  const cells = Array.isArray(lane.cells) ? lane.cells : null;
  if (cells === null) throw new ProducerError('the lane result has no `cells` array');

  const decl = readDeclaration(declaration, 'external');
  const env = readEnvelope(envelope);

  // ── Place every cell. ────────────────────────────────────────────────────
  //
  // A cell that cannot be placed is COUNTED as skipped and named, never quietly
  // dropped: `counting.mjs` exists because this component has three times
  // reported success over inputs it never looked at, and a producer that
  // silently discards a reading is the same bug one component upstream.
  const readings = new Map(); // subjectKey -> Map<recordCheckpoint, cell>
  const used = [];
  const skipped = [];
  for (const cell of cells) {
    let key;
    let placed;
    try {
      key = subjectKeyOf(laneName, cell);
      placed = laneCheckpoint(laneName, cell);
    } catch (e) {
      if (e instanceof ProducerError || e instanceof CheckpointVocabularyError) {
        skipped.push({ id: isObject(cell) ? (cell.id ?? null) : null, why: e.message });
        continue;
      }
      throw e;
    }
    if (!readings.has(key)) readings.set(key, new Map());
    const byCheckpoint = readings.get(key);
    if (byCheckpoint.has(placed.checkpoint)) {
      // Refused rather than resolved. Two readings of one cell is a question
      // about which of them the run means, and the producer is not the thing
      // that answers it; picking one writes a record whose ledger balances over
      // an arbitrary half of what was measured.
      throw new ProducerError(
        `two cells place at ${key} / ${placed.checkpoint}: `
          + `${JSON.stringify(byCheckpoint.get(placed.checkpoint).id ?? null)} and `
          + `${JSON.stringify(cell.id ?? null)}. A ledger cell posts once, and which of them is the `
          + 'posting is not a question this producer may answer for the run.',
      );
    }
    byCheckpoint.set(placed.checkpoint, cell);
    used.push({ from: cell.checkpoint, stage: cell.stage, to: placed.checkpoint, fidelity: placed.fidelity });
  }

  // ── Build the properties. ────────────────────────────────────────────────
  //
  // Declared first, in the declaration's order, so that the record reads in the
  // order the accounts were opened. Then anything the run measured that the
  // declaration did NOT open an account for — kept, not dropped, so that
  // VG-ART-066 can name it. A producer that dropped it would be answering a
  // question about the plan by editing what happened.
  const properties = [];
  const declaredIds = new Set(decl.properties.map((p) => p.propertyId));
  for (const p of decl.properties) {
    const byCheckpoint = readings.get(p.propertyId);
    if (byCheckpoint === undefined) continue;
    const ordered = [...p.plannedCheckpoints]
      .sort((a, b) => recordCheckpointOrder(a) - recordCheckpointOrder(b))
      .filter((c) => byCheckpoint.has(c))
      .map((c) => ({ checkpoint: c, cell: byCheckpoint.get(c) }));
    if (ordered.length === 0) continue;
    properties.push(propertyFrom(p.propertyId, ordered));
  }
  for (const [key, byCheckpoint] of readings) {
    if (declaredIds.has(key)) continue;
    const ordered = [...byCheckpoint.keys()]
      .sort((a, b) => recordCheckpointOrder(a) - recordCheckpointOrder(b))
      .map((c) => ({ checkpoint: c, cell: byCheckpoint.get(c) }));
    properties.push(propertyFrom(key, ordered));
  }

  // ── The suspense account. ────────────────────────────────────────────────
  //
  // One entry per cell the run did not get a reading out of AND said why. A cell
  // whose state is UNOBSERVED posts to `unobserved`, not to `unresolved`, so
  // this adds nothing to the ledger; what it answers is VG-ART-059, which asks
  // for the coverage shortfall to be accounted for somewhere a reader can see
  // the reason.
  //
  // Nothing is written for a cell that is simply MISSING. The lane's
  // `unobserved[]` is free text and its `skipped` flags name a flag rather than
  // a (property, checkpoint) pair, so there is no reason to copy — and an entry
  // invented here would settle a cell nobody looked at, which is the suspense
  // account swallowing the ledger. Such a cell stays unaccounted and
  // `verify.mjs` reports VG-ART-064, which is the correct answer.
  const unresolved = [];
  for (const pr of properties) {
    for (const s of pr.states) {
      if (s.verdict !== 'UNOBSERVED') continue;
      unresolved.push({ propertyId: pr.propertyId, checkpoint: s.checkpoint, reason: s.reasons.join('; ') });
    }
  }

  // ── Coverage. ────────────────────────────────────────────────────────────
  //
  // `observed` is defined as the number of states whose verdict is not
  // UNOBSERVED, over the whole record — the same definition `verify.mjs`
  // recomputes. That one IS the definition of the field rather than a second
  // implementation of a check, so computing it the same way is not collusion;
  // computing it differently would just be wrong.
  //
  // `planned` comes from the DECLARATION's cells and never from what ran.
  const observed = properties.reduce(
    (n, pr) => n + pr.states.filter((s) => s.verdict !== 'UNOBSERVED').length,
    0,
  );
  const planned = decl.properties.reduce((n, p) => n + p.plannedCheckpoints.length, 0);

  // ── The ledger's own entries. ────────────────────────────────────────────
  //
  // Tallied here, from this record's own states, WITHOUT `postLedger`. The
  // verifier recomputes them and VG-ART-065 reports a disagreement; sharing the
  // arithmetic would make that check permanently silent.
  //
  // And the entries are written as they come out. A cell in no account leaves
  // the row short, and the row is emitted short — VG-ART-064 is then a true
  // report about a real gap. Balancing the row by adjusting `declared` would be
  // the producer covering its own shortfall with the number it was supposed to
  // be held against.
  const stateAt = new Map();
  for (const pr of properties) {
    for (const s of pr.states) stateAt.set(`${pr.propertyId}${SEP}${s.checkpoint}`, s);
  }
  const settled = new Set(unresolved.map((u) => `${u.propertyId}${SEP}${u.checkpoint}`));
  const entries = [];
  const imbalances = [];
  for (const checkpoint of decl.plannedCheckpoints) {
    const row = { checkpoint, declared: 0, present: 0, absent: 0, unobserved: 0, unresolved: 0 };
    for (const p of decl.properties) {
      if (!p.plannedCheckpoints.includes(checkpoint)) continue;
      row.declared += 1;
      const s = stateAt.get(`${p.propertyId}${SEP}${checkpoint}`);
      if (s === undefined) {
        if (settled.has(`${p.propertyId}${SEP}${checkpoint}`)) row.unresolved += 1;
        continue; // unaccounted: left out of every column, on purpose
      }
      if (s.verdict === 'PRESENT') row.present += 1;
      else if (s.verdict === 'ABSENT') row.absent += 1;
      else row.unobserved += 1;
    }
    const posted = row.present + row.absent + row.unobserved + row.unresolved;
    if (posted !== row.declared) imbalances.push({ checkpoint, declared: row.declared, posted });
    entries.push(row);
  }

  const record = {
    schemaVersion: LEDGER_SCHEMA_VERSION,
    lane: laneName,
    producedBy: 'compiler/evidence/produce.mjs',
    toolchain: env.toolchain,
    command: env.command,
    ...(env.artifact !== undefined ? { artifact: env.artifact } : {}),
    coverage: { observed, planned },
    // Copied from the declaration, which came from the policy. NOT from
    // `properties` below, which is the record's other book.
    declaredProperties: decl.properties.map((p) => ({
      propertyId: p.propertyId,
      plannedCheckpoints: [...p.plannedCheckpoints],
    })),
    ledger: {
      declarationSource: isObject(declaration.source) ? (declaration.source.kind ?? 'declaration') : 'declaration',
      plannedCheckpoints: [...decl.plannedCheckpoints],
      entries,
      // interfaces.md §5: "The producer maps between them and records which
      // mapping it used". Only the rows that were applied.
      checkpointMapping: mappingRecord(laneName, used),
    },
    properties,
    unresolved,
    evidenceDigest: null,
  };

  const counts = {
    inputs: cells.length,
    checked: cells.length - skipped.length,
    skipped: skipped.length,
  };
  return {
    record: sealRecord(record, context === undefined ? {} : { context }),
    counts,
    imbalances,
    skippedCells: skipped,
  };
}

/* ----------------------------------------------------------------- CLI -- */

const USAGE = [
  'produce.mjs — write an evidence-v1 record from a lane result.',
  '',
  '  node produce.mjs --declare --policy <policy.json> --out <declaration.json>',
  '  node produce.mjs --lane <lane-result.json> --declaration <declaration.json> \\',
  '                   --envelope <envelope.json> --out <evidence.json>',
  '',
  'The two are run at two different times. `--declare` opens the accounts from the',
  'policy, BEFORE the measurement; the default mode holds the measurement against',
  'them afterwards and refuses to run without one. The declaration is also what to',
  'pass to `verify.mjs --record <evidence.json> --declared <declaration.json>`,',
  'which is the only source that can catch a record that shrank both of its books.',
  '',
  'The envelope holds what interfaces.md §5 requires and a lane result does not',
  'carry: {"toolchain": {...}, "command": {"argv": [...]}, "artifact": {...}?}.',
  '',
  'Exit codes (interfaces.md §7): 0 written, 3 an input could not be read or',
  'nothing was produced, 4 a refusal — nothing is written after one.',
].join('\n');

function readJson(file, what) {
  if (!existsSync(file)) throw new ProducerError(`cannot read the ${what}: ${file}`);
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    throw new ProducerError(`the ${what} does not parse: ${e.message}`);
  }
}

/**
 * Records are measurement output and live where measurement output lives
 * (interfaces.md §1), the same rule `run-lto-window.mjs --out` and
 * `record-run.mjs --store` already apply. A declaration is a PLAN rather than a
 * measurement, so it is not held to it: a repository is exactly where a plan
 * written before the run belongs.
 */
function refuseInsideCheckout(file) {
  const abs = resolve(file);
  if (abs === REPO_ROOT || abs.startsWith(REPO_ROOT + sep)) {
    throw new ProducerError(
      '--out is inside the checkout. A record is measurement output and lives on the side that '
        + 'produced it (interfaces.md §1); a record committed beside the code that wrote it is a record '
        + 'nobody can tell from a fixture.',
    );
  }
  return abs;
}

function writeJson(file, value) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function main(argv) {
  const flag = (name) => argv.includes(name);
  const val = (name) => {
    const i = argv.indexOf(name);
    return i === -1 || i + 1 >= argv.length ? null : argv[i + 1];
  };
  if (argv.length === 0 || flag('--help') || flag('-h')) {
    process.stdout.write(`${USAGE}\n`);
    return EXIT_OK;
  }

  try {
    if (flag('--declare')) {
      const policyFile = val('--policy');
      const out = val('--out');
      if (!policyFile) throw new ProducerError('--declare needs --policy <policy.json>');
      if (!out) throw new ProducerError('--declare needs --out <declaration.json>');
      const declaration = declarationFromPolicy(readJson(policyFile, 'policy'), { lane: val('--lane') });
      writeJson(out, declaration);
      const settled = reportCounts({
        inputs: declaration.properties.length,
        checked: declaration.properties.length,
        skipped: 0,
        what: 'declared property',
      });
      process.stdout.write(
        `wrote ${out}: ${declaration.properties.length} account(s) over `
          + `${declaration.plannedCheckpoints.join(', ')}\n`,
      );
      return settled.code ?? EXIT_OK;
    }

    const laneFile = val('--lane');
    const out = val('--out');
    if (!laneFile) throw new ProducerError(`--lane <lane-result.json> is required.\n\n${USAGE}`);
    if (!out) throw new ProducerError('--out <evidence.json> is required');
    const declarationFile = val('--declaration');
    // The refusal this file is arranged around. Checked before anything is read,
    // so that a run with no declaration cannot get far enough to have produced
    // something it would be tempting to write.
    if (!declarationFile) throw new ProducerError(DECLARATION_ABSENT);
    const outAbs = refuseInsideCheckout(out);

    const { record, counts, imbalances, skippedCells } = produceRecord({
      lane: readJson(laneFile, 'lane result'),
      declaration: readJson(declarationFile, 'declaration'),
      envelope: val('--envelope') === null ? null : readJson(val('--envelope'), 'envelope'),
    });

    for (const s of skippedCells) {
      process.stderr.write(`skipped cell ${JSON.stringify(s.id)}: ${s.why}\n`);
    }
    const settled = reportCounts({ ...counts, what: 'lane cell' });
    // The record is written even when it does not balance, and the imbalance is
    // announced rather than repaired. A producer that could not emit a failing
    // record could not be held to anything: the verifier would only ever see
    // what this file already agreed with.
    for (const im of imbalances) {
      process.stderr.write(
        `the ledger does not balance at ${im.checkpoint}: the declaration opens ${im.declared} `
          + `account(s) and ${im.posted} are posted. The record is written as it stands; `
          + 'verify.mjs will report VG-ART-064.\n',
      );
    }
    if (settled.code !== null) return settled.code;
    writeJson(outAbs, record);
    process.stdout.write(`wrote ${out}: ${record.properties.length} propert(y/ies), digest ${record.evidenceDigest}\n`);
    return EXIT_OK;
  } catch (e) {
    if (e instanceof ProducerError || e instanceof CheckpointVocabularyError) {
      process.stderr.write(`produce: ${e.message}\n`);
      return EXIT_REFUSED;
    }
    process.stderr.write(`produce: ${e.stack ?? e.message}\n`);
    return EXIT_INCOMPLETE;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv.slice(2)));
}
