// policy.fallback — the security-preserving fallback, and its reader.
//
// `policy.schema.json` has carried a `fallback` block since the schema was
// written ("Recompiling a function that lost a property, at a lower optimisation
// level, and checking again. Off by default"), and until now nothing in
// compiler/ read it. A schema key with no consumer is a policy the build ignores
// while appearing to honour it, which is the same class of hole as
// `policy.properties[]` having no consumer.
//
// ── WHERE "LOST" COMES FROM, AND WHY IT IS NOT DECIDED HERE ─────────────────
//
// The driver cannot decide `must-survive` for itself and does not pretend to.
// `compiler/schema/properties.json` names the two implemented extractors for
// that kind — `ir.wipe-effect` and `ir.guarded-call` — and both live in the C++
// pass in `compiler/llvm-pass/`, reachable only by loading a pass plugin into
// the compilation. `invoke.mjs` rule 2 forbids folding such a plugin into the
// shipping build, and writing a third JavaScript re-implementation of the
// counting rule here would be a second definition of a measurement that already
// has one home — exactly what `evidence-binding.mjs` refuses to do for
// canonicalisation.
//
// So the verdict is READ, not derived. The driver:
//
//   1. emits textual IR for the invocation as the caller configured it, in a
//      separate observation build whose output the caller never sees;
//   2. hands that IR to an OBSERVER named by `--vg-observer`, and reads back the
//      subset of `compiler/schema/observation.schema.json` it needs:
//      `properties[].{id, kind, control, historyComplete, finalState}`;
//   3. if a declared `must-survive` property is not PRESENT, recompiles at the
//      policy's approved `fallback.profile` and asks THE SAME observer again.
//
// One observer for both readings is the point. A "before" from one oracle and an
// "after" from another is not a comparison, it is two unrelated sentences, and
// the difference between them would be attributed to the recompile.
//
// If no observer is supplied, the honest answer is not "nothing was lost" — it
// is that the question was never put. That is `status: "unsupported"`,
// `complete: false`, and `VG-CFG-022`; never a pass.
//
// ── GRANULARITY: TRANSLATION UNIT, SAID IN AS MANY WORDS ────────────────────
//
// The schema's prose says "recompiling a function". A function is not a unit a
// compiler driver can recompile: `clang` takes translation units, and there is
// no supported way to ask it for one function of one TU at a different
// optimisation level. Emitting a record that said `function` while recompiling a
// whole TU would be a claim about a resolution the measurement does not have, so
// the record says `granularity: "translation-unit"` and nothing else, and an
// invocation with more than one source is refused outright rather than
// recompiled wholesale and described as a unit.
//
// ── WHAT THIS CAN AND CANNOT DO TO AN EXIT CODE ─────────────────────────────
//
// Fallback is not a bypass and there is no setting of it that makes a lost
// property pass:
//
//   - restored  -> VG-CFG-020 at `high`, and the candidate artefact is recorded.
//   - still lost -> VG-CFG-020 stays `critical`, plus VG-CFG-021, and no
//     candidate is recorded at all.
//
// `critical` is the top of the severity ladder, so a still-lost property is at
// or above every legal `failOn` and is exit 2 under all of them.
// `rejectIfStillLost: false` lowers VG-CFG-021 from `critical` to `high` — it
// records that the policy chose not to treat the failed rescue as its own
// separate refusal. It does not touch VG-CFG-020 and it does not produce a
// candidate.

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { CFG, makeFinding } from './findings.mjs';
import { runObservation } from './invoke.mjs';
import { toRecordPath } from './paths.mjs';
import { sha256File } from './toolchain.mjs';

/** interfaces.md section 3, the same six the observation schema declares. */
export const PROPERTY_STATES = Object.freeze([
  'PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED',
]);

/** The only state that means a `must-survive` property is still there. */
export const PRESERVED_STATE = 'PRESENT';

export const OBSERVATION_VERSION = 'observation-v0';

/** Written into every record this module produces. See the header. */
export const GRANULARITY = 'translation-unit';

/** Flags the driver adds to get textual IR out of an observation build. */
export const IR_FLAGS = Object.freeze(['-emit-llvm', '-S']);

const OBSERVER_TIMEOUT_MS = 120000;

/** Actions that cannot produce IR, so cannot be observed this way. */
const UNOBSERVABLE_ACTIONS = new Set(['preprocess', 'syntax-only']);

const where = { kind: 'invocation', path: null, unit: null, pass: null };

/**
 * Keep a peer's string out of the record's face: one line, short, and with
 * anything path-shaped taken out.
 *
 * The redaction is not cosmetic. These strings are quoted into findings, the
 * findings go into the record, and interfaces.md §5 forbids an absolute path
 * anywhere in one — so an observer that prints `/opt/…: no such file` to stderr
 * would otherwise cost the whole record: the driver's own gate would refuse to
 * write it, and the run would report exit 3 with nothing on disk to say why.
 * Reporting the problem instead of emitting the path is what §5 asks for.
 */
function clip(s, n = 120) {
  const one = String(s ?? '')
    .replace(/\s+/g, ' ')
    .replace(/[A-Za-z]:[\\/][^\s'"]*/g, '<path>')
    .replace(/(^|[\s:="'(,[])\/[^\s'"]*/g, '$1<path>')
    .trim();
  return one.length > n ? `${one.slice(0, n)}…` : one;
}

/**
 * `policy.fallback`, with the schema's defaults applied here rather than written
 * into the parsed policy — so that "the policy did not say" stays
 * distinguishable from "the policy said the default", the same rule policy.mjs
 * follows for `failOnIncomplete` and `requireDigestMatch`.
 *
 * @returns {{configured: boolean, enabled: boolean, profile: string|null, rejectIfStillLost: boolean}}
 */
export function readFallbackPolicy(policy) {
  const raw = policy?.fallback;
  const configured = !!raw && typeof raw === 'object' && !Array.isArray(raw);
  if (!configured) return { configured: false, enabled: false, profile: null, rejectIfStillLost: true };
  return {
    configured: true,
    enabled: raw.enabled === true,
    profile: typeof raw.profile === 'string' ? raw.profile : null,
    rejectIfStillLost: typeof raw.rejectIfStillLost === 'boolean' ? raw.rejectIfStillLost : true,
  };
}

/**
 * The ids of the `must-survive` properties the policy declared, in policy order,
 * without duplicates. Other kinds are not this component's business: nothing
 * here can be rescued by recompiling at a lower level.
 */
export function mustSurviveIds(policy) {
  const out = [];
  const seen = new Set();
  for (const p of Array.isArray(policy?.properties) ? policy.properties : []) {
    if (!p || p.kind !== 'must-survive' || typeof p.id !== 'string') continue;
    if (seen.has(p.id)) continue;
    seen.add(p.id);
    out.push(p.id);
  }
  return out;
}

// ── profile: "auto" ─────────────────────────────────────────────────────────
//
// `fallback.profile` used to be a level a human wrote into the policy, which is
// a guess unless that human had measured this program at that level. `"auto"`
// replaces the guess with a lookup: the driver reads a `vibeguard.fallback-table/1`
// document derived from the measured configuration envelope, finds the row for
// the property and the configuration this build is in, and uses the level that
// row says was observed to keep the property.
//
// Everything below resolves `"auto"` to a concrete `-O` string BEFORE the rest
// of this file runs, and the rest of this file is unchanged. `fb.profile` is
// consumed as a compiler flag in a dozen places downstream — `flags.optLevels`
// membership, the `after` observation's extra flags, the candidate build, six
// finding strings — and letting the literal `"auto"` reach any of them would
// put a word that is not a flag on a command line and into a record. So the
// word is spent here and never travels.
//
// ── WHAT THE DRIVER MAY MATCH ON, WHICH IS DECIDED PER INVOCATION ───────────
//
// The table's rows are keyed by a six-axis configuration: cc, freestanding,
// lto, ndebug, opt, target. This used to match on `opt` alone, on the argument
// that recovering the other five would mean inventing rules the driver does not
// have. That argument was right about the axes it was really about and wrong as
// a blanket rule, and the difference is measurable: against the sweep's own
// table, every `-O2` build — the level almost everything ships at — matched
// eleven rows at once, four of them `not-observed`, and was refused. Nine
// usable `fallback` rows sat in the file and not one of them was reachable.
//
// What the old note got right is that some of these axes cannot be read off a
// command line:
//
//   - `lto`: `-flto=thin` does not say whether the envelope's `"thin-prelink"`
//     or `"thin-backend"` cell is the one to compare against. The two differ by
//     WHEN the observation was taken, not by any flag, so no reading of the
//     line can choose between them. ★ But that argument only bites when an LTO
//     token is present. A command line with no `-flto*` and no `-fno-lto` on it
//     is `lto: "none"` — that is not a convention, it is what the line says.
//   - `cc`: which clang this is, is a toolchain fact rather than a command-line
//     one. `toolchain.mjs` knows it; this reader does not ask.
//
// And what it got wrong is that the remaining axes ARE on the line:
// `-target`/`--target=` (both spellings, last one winning as clang's own
// `getLastArgValue` makes it win), `-DNDEBUG`/`-UNDEBUG` in argv order,
// `-ffreestanding`/`-fhosted`. `cmdline.mjs` now recovers each of them, and no
// axis is read from a token that is not there — except one, named below.
//
// So the set of axes matched on is not a fixed list any more. It is whatever
// THIS command line turned out to say, and it is written into the record as
// `knownAxes` so that a reader can see how tight the match that produced a
// level actually was. An axis that could not be read stays in `unmatchedAxes`
// and is paid for exactly as before: every row that matches must name the same
// level, or the run is refused.
//
// ── THE ONE CONVENTION, STATED RATHER THAN HIDDEN ───────────────────────────
//
// No `-target` at all is matched against the envelope's `"host"`. That is a
// convention: clang with no `-target` compiles for the machine's default
// triple, and the envelope's `host` cells were swept on SOME machine's default
// triple, and nothing here checks those are the same machine. It is written
// down here rather than buried because it is the one place this reader assumes
// instead of reads.
//
// ── WHY A WRONG ROW IS BOUNDED ──────────────────────────────────────────────
//
// A resolved level is a level to TRY. `evaluateFallback` recompiles at it and
// asks the observer again, and a property that does not come back is
// `still-lost` and rejected, exactly as it is for a hand-written profile. A
// wrong row cannot turn a lost property into a passing build; it can only waste
// a recompile.

/** The one `fallback.profile` value that is not a compiler flag. */
export const AUTO_PROFILE = 'auto';

/** The `schemaVersion` this driver knows how to read. */
export const FALLBACK_TABLE_SCHEMA_VERSION = 'vibeguard.fallback-table/1';

/**
 * Levels `auto` is allowed to arrive at: the ones `policy.fallback.profile`
 * admits when written by hand. `auto` picking a level a policy author could not
 * have written would be the schema's enum meaning one thing for a human and
 * another for a lookup.
 */
export const AUTO_PROFILES = Object.freeze(['-O0', '-O1']);

/** The three the table contract fixes, kept apart on purpose. */
const TABLE_RESOLUTIONS = Object.freeze(['fallback', 'no-safe-target', 'not-observed']);

/**
 * Every axis of the table's key that a command line CAN carry. Which of them a
 * given invocation actually carries is decided per invocation by
 * `driverConfigAxes`; this list is the ceiling, and it exists so that a future
 * axis has to be added deliberately in two places rather than appear because a
 * normalised object grew a field with an axis-shaped name.
 *
 * `cc` is not here: which clang this is, is not on the command line.
 */
export const DRIVER_READABLE_AXES = Object.freeze(['freestanding', 'lto', 'ndebug', 'opt', 'target']);

/**
 * The axes a fallback RECOMPILE can move. This is `-O` and nothing else: the
 * recompile re-runs one translation unit with an extra `-O` flag appended, so a
 * row whose `to` differs from its `from` on any other axis is describing a build
 * that will not happen.
 *
 * Kept apart from `DRIVER_READABLE_AXES` on purpose, and the two must not be
 * merged. The `fallback-row-moves-inapplicable-axis` check below is keyed on
 * THIS list; keying it on the readable set instead would let a row that moves
 * `target` from `host` to `arm-none-eabi` through, because `target` became
 * readable. Reading an axis and being able to change it are different powers.
 */
export const RECOMPILE_MUTABLE_AXES = Object.freeze(['opt']);

/**
 * The level this invocation actually compiles at. Last `-O` wins, as clang does
 * it, and no `-O` at all is `-O0`, as clang does that too.
 */
export function shippingOptLevel(normalised) {
  const levels = Array.isArray(normalised?.optLevels) ? normalised.optLevels : [];
  return levels.length > 0 ? levels[levels.length - 1] : '-O0';
}

/**
 * This build's value for each axis this command line actually stated — no key
 * for an axis it did not.
 *
 * Every branch below is guarded on the FIELD's presence and type rather than on
 * its value, so that a normalised object which never reported an axis is not
 * read as having reported the axis's default. "cmdline.mjs did not tell me" and
 * "cmdline.mjs told me false" are different sentences and produce different
 * objects: the first omits the key, the second sets it.
 *
 * Insertion order is deliberate — `opt` first, because it is the axis every
 * refusal message leads with.
 */
export function driverConfigAxes(normalised) {
  const axes = { opt: shippingOptLevel(normalised) };
  const n = normalised ?? {};

  // No `-target` is the envelope's `host`. The one convention here; see the
  // header. A stated triple is used verbatim, so a triple the sweep never
  // measured matches no row and is refused rather than rounded to a neighbour.
  // `-m32`/`-m64` change the triple without a `-target` on the line, so the
  // build is not the `host` the envelope measured and the axis is not readable.
  if (Object.prototype.hasOwnProperty.call(n, 'target') && n.targetOpaque !== true) {
    axes.target = typeof n.target === 'string' && n.target.length > 0 ? n.target : 'host';
  }
  if (typeof n.ndebug === 'boolean') axes.ndebug = n.ndebug;
  if (typeof n.freestanding === 'boolean') axes.freestanding = n.freestanding;
  // The asymmetry that makes this whole change safe: no LTO token on the line
  // is `lto: "none"`, which is a reading. Any LTO token at all leaves the axis
  // out, because `-flto=thin` cannot be resolved to a prelink/backend cell from
  // the line, and a guess here would pick which measurement gets quoted.
  if (Array.isArray(n.ltoTokens) && n.ltoTokens.length === 0) axes.lto = 'none';

  return axes;
}

/**
 * Axes this driver can normally read off a command line. An axis in here that
 * is MISSING from `driverConfigAxes` was suppressed by something on this
 * particular line — `-flto`, `-m32`, `-Wp,-DNDEBUG` — as opposed to `cc`, which
 * no command line ever states and which this driver has never claimed to read.
 *
 * The distinction matters for the spanning check below: not being able to read
 * an axis this time is a fact about THIS build that the table may not cover,
 * while never modelling `cc` at all is a standing limitation of the whole table.
 */
export const READABLE_IN_PRINCIPLE_AXES = Object.freeze(['target', 'ndebug', 'freestanding', 'lto']);

/** `opt=-O2, target=host, …` for the refusal messages, in insertion order. */
function describeAxes(ours) {
  return Object.keys(ours).map((a) => `${a}=${ours[a]}`).join(', ');
}

function resolutionRecord(extra = {}) {
  return {
    envelopeCheck: null,
    error: null,
    // Always overwritten by `resolveAutoProfile`, which computes it from the
    // invocation before it opens anything. It is not a fixed list: two records
    // written by the same driver can name different axes, and an older record
    // saying `["opt"]` is a true statement about the run that wrote it.
    knownAxes: [],
    matchedOn: null,
    profile: null,
    rows: [],
    source: AUTO_PROFILE,
    table: null,
    unmatchedAxes: [],
    ...extra,
  };
}

function baseReject(reason, detail, extra = {}) {
  return { ok: false, reason, detail, record: resolutionRecord({ ...extra, error: { detail, reason } }) };
}

/** The row fields the record quotes as the reason a level was chosen. */
function rowIdentity(row) {
  return {
    from: row.from ?? null,
    profile: typeof row.profile === 'string' ? row.profile : null,
    propertyId: row.propertyId,
    resolution: row.resolution,
    to: row.to ?? null,
  };
}

/**
 * Turn `fallback.profile: "auto"` into a concrete level, or refuse and say
 * which of the ways it could not be done happened.
 *
 * The refusals are deliberately not one refusal. "There is no table" and "the
 * table says there is nowhere safe to fall back to" are opposite situations —
 * the first is a missing artefact and the second is a measured result — and a
 * single `fallback-auto-failed` would send a reader to look for a file that is
 * exactly where it should be.
 *
 * @returns {{ok: true, profile: string, record: object}
 *          | {ok: false, reason: string, detail: string, record: object}}
 */
export function resolveAutoProfile({ tablePath, requested, normalised, root }) {
  // Read the invocation first, before any file is opened. Which axes this line
  // states is a property of the line alone, and every refusal below — including
  // the ones that never reach a row — records it, so that "no table" and "no
  // matching row" are both readable as answers to the same question.
  const ours = driverConfigAxes(normalised);
  const axisNames = Object.keys(ours);
  const knownAxes = [...axisNames].sort();
  const autoReject = (reason, detail, extra = {}) => baseReject(reason, detail, { knownAxes, ...extra });

  if (typeof tablePath !== 'string' || tablePath.length === 0) {
    return autoReject(
      'no-profile-table',
      'policy.fallback.profile is "auto" and policy.fallback.profileTable names no table, so there is nothing to read a '
      + 'level out of. "auto" means the level is measured elsewhere; with nowhere to look it is not a level at all',
    );
  }

  const tableAbs = resolve(root, tablePath);
  const tableRel = toRecordPath(tableAbs, root);

  let text;
  try {
    text = readFileSync(tableAbs, 'utf8');
  } catch (err) {
    return autoReject(
      'fallback-table-unreadable',
      `the fallback table at ${tableRel} could not be read (${clip(err.code ?? err.message, 40)})`,
    );
  }

  let table;
  try {
    table = JSON.parse(text);
  } catch (err) {
    return autoReject('fallback-table-unreadable', `the fallback table at ${tableRel} is not JSON (${clip(err.message, 60)})`);
  }
  const malformed = (why) => autoReject(
    'fallback-table-unreadable',
    `the fallback table at ${tableRel} is not a ${FALLBACK_TABLE_SCHEMA_VERSION} document: ${why}`,
  );
  if (!table || typeof table !== 'object' || Array.isArray(table)) return malformed('it is not a JSON object');
  if (table.schemaVersion !== FALLBACK_TABLE_SCHEMA_VERSION) {
    return malformed(`schemaVersion is ${clip(JSON.stringify(table.schemaVersion), 40)}`);
  }
  if (!Array.isArray(table.rows)) return malformed('rows is not an array');
  const src = table.source;
  if (!src || typeof src !== 'object' || Array.isArray(src)) return malformed('source is not an object');
  if (typeof src.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(src.sha256)) {
    return malformed('source.sha256 is not a sha-256 digest, so the table cannot say which envelope it came from');
  }

  const tableInfo = {
    path: tableRel,
    rows: table.rows.length,
    schemaVersion: table.schemaVersion,
    sha256: sha256File(tableAbs),
  };

  // ---- is the table still describing the envelope on disk? -----------------
  //
  // The envelope is a build artefact of compiler/llvm-pass and is not shipped.
  // On a machine that has never run the sweep, the check cannot be made — and
  // "could not check" is written down rather than passed off as "checked".
  let envelopeCheck = 'skipped-no-envelope-path';
  if (typeof src.path === 'string' && src.path.length > 0) {
    const candidates = [resolve(dirname(tableAbs), src.path), resolve(root, src.path)];
    const found = candidates.find((p) => existsSync(p) && statSync(p).isFile()) ?? null;
    if (found === null) {
      envelopeCheck = 'skipped-envelope-not-present';
    } else {
      const actual = sha256File(found);
      if (actual !== src.sha256) {
        return autoReject(
          'fallback-table-stale',
          `the fallback table at ${tableRel} was derived from an envelope digesting to ${src.sha256.slice(0, 12)}…, and the `
          + `envelope at ${toRecordPath(found, root)} now digests to ${actual.slice(0, 12)}…. The table describes measurements `
          + 'that are not the ones on disk, and a level chosen from it would be chosen from a superseded sweep',
          { envelopeCheck: 'mismatch', table: tableInfo },
        );
      }
      envelopeCheck = 'matched';
    }
  }

  // ---- which rows speak about this build? ----------------------------------
  const wanted = new Set(requested);
  const axisKeys = new Set();
  for (const row of table.rows) {
    if (row && typeof row.from === 'object' && row.from !== null && !Array.isArray(row.from)) {
      for (const k of Object.keys(row.from)) axisKeys.add(k);
    }
  }
  const unmatchedAxes = [...axisKeys].filter((k) => !axisNames.includes(k)).sort();
  const common = { envelopeCheck, knownAxes, matchedOn: ours, table: tableInfo, unmatchedAxes };

  const matched = table.rows.filter((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
    if (!wanted.has(row.propertyId)) return false;
    const from = row.from;
    if (!from || typeof from !== 'object' || Array.isArray(from)) return false;
    // Strict equality on every axis this line stated, including the ones a row
    // may simply not carry: a row whose `from` has no `target` has not said it
    // was measured on this target, and a missing field is not agreement.
    return axisNames.every((axis) => from[axis] === ours[axis]);
  });

  // A property with no row of its own must not ride along on another
  // property's rows. `matched` is the union over the declared must-survive
  // set, so without this check a policy declaring two properties where the
  // table speaks about one of them would resolve on the strength of the one —
  // the same substitution the table itself refuses when it insists that every
  // subject of a property hold at the target, one level up.
  const uncovered = [...wanted].filter((id) => !matched.some((r) => r.propertyId === id)).sort();
  if (uncovered.length > 0 && matched.length > 0) {
    return autoReject(
      'fallback-property-not-in-table',
      `the fallback table at ${tableRel} has no row for ${uncovered.join(', ')} at `
      + `${describeAxes(ours)}, and the rows it does have are about other `
      + 'must-survive propert'
      + `${uncovered.length === 1 ? 'ies' : 'ies'}. A level chosen for one property is not a level observed to keep `
      + 'another, and this policy declares both',
      { ...common, rows: matched.map(rowIdentity), uncoveredProperties: uncovered },
    );
  }

  if (matched.length === 0) {
    return autoReject(
      'fallback-no-matching-row',
      `the fallback table at ${tableRel} has ${tableInfo.rows} row(s) and none of them is about a must-survive property this `
      + `policy declares at ${describeAxes(ours)}. A table with nothing to say about this `
      + 'configuration has not said that nothing was lost in it',
      common,
    );
  }
  const rows = matched.map(rowIdentity);

  // ---- an axis we could not read has to be one the table actually spans -----
  //
  // The looseness of matching on fewer axes is paid for by the agreement rule:
  // every matching row must name the same level, so the level does not depend
  // on the axis that could not be read. That argument has a hole, and it is a
  // hole of vacuity: if every matching row carries the SAME value for the
  // unreadable axis, they agree trivially, and what they agree on is a
  // measurement of one side of an axis this build might be on the other side of.
  //
  // Concretely (measured against the real 17-row table, 2026-08-17):
  // `-Xclang -ffreestanding` makes `freestanding` unreadable, and the table has
  // no `freestanding: true` row at all, so the freestanding build would be
  // handed a level measured on a hosted one and nothing would disagree.
  //
  // So an unreadable axis is only survivable when the matched rows show more
  // than one value for it — that is when "they agree anyway" carries weight.
  // `cc` is excluded because it is not an axis this driver ever reads; that is a
  // standing limitation of the table, disclosed in `unmatchedAxes`, not a fact
  // about this command line.
  const unreadableHere = READABLE_IN_PRINCIPLE_AXES
    .filter((axis) => axisKeys.has(axis) && !(axis in ours));
  for (const axis of unreadableHere) {
    const values = [...new Set(matched.map((r) => JSON.stringify(r.from?.[axis])))];
    if (values.length < 2) {
      return autoReject(
        'fallback-unreadable-axis-not-spanned',
        `this command line does not state ${axis}, and every row the table has for these properties at `
        + `${describeAxes(ours)} was measured at the same ${axis}. Those rows agree about the level only because `
        + `they are all one side of ${axis}, so their agreement says nothing about the side this build may be on. `
        + `A level is not adopted from a configuration the sweep never varied`,
        { ...common, rows, unreadableAxis: axis },
      );
    }
  }

  for (const row of matched) {
    if (!TABLE_RESOLUTIONS.includes(row.resolution)) {
      return autoReject(
        'fallback-table-unreadable',
        `the fallback table at ${tableRel} has a row for ${clip(row.propertyId, 60)} whose resolution is `
        + `${clip(JSON.stringify(row.resolution), 30)}, which is not one of ${TABLE_RESOLUTIONS.join(', ')}`,
        { ...common, rows },
      );
    }
  }

  // `no-safe-target` first, and not because it is worse to read. It is the
  // stronger claim: the weaker configurations WERE measured and all of them
  // lost the property too. Measuring more will not produce a level. Reporting
  // `not-observed` over the top of it would send someone to run a sweep that
  // has already been run and already answered.
  const noSafe = matched.filter((r) => r.resolution === 'no-safe-target');
  if (noSafe.length > 0) {
    return autoReject(
      'fallback-resolution-no-safe-target',
      `the fallback table at ${tableRel} records no-safe-target for ${noSafe.map((r) => r.propertyId).join(', ')} at `
      + `${describeAxes(ours)}: every weaker configuration it measured lost the property `
      + 'as well, so there is no level to recompile at and none is invented here',
      { ...common, rows },
    );
  }
  const notObserved = matched.filter((r) => r.resolution === 'not-observed');
  if (notObserved.length > 0) {
    return autoReject(
      'fallback-resolution-not-observed',
      `the fallback table at ${tableRel} records not-observed for ${notObserved.map((r) => r.propertyId).join(', ')} at `
      + `${describeAxes(ours)}: the weaker configurations were not all measured, so no `
      + 'level has been observed to keep the property. That is a gap in the sweep, not a level',
      { ...common, rows },
    );
  }

  // ---- every matching row is a `fallback`; do they agree? ------------------
  const levels = [...new Set(matched.map((r) => r.profile))];
  for (const level of levels) {
    if (typeof level !== 'string' || !AUTO_PROFILES.includes(level)) {
      return autoReject(
        'fallback-profile-not-permitted',
        `the fallback table at ${tableRel} names ${clip(JSON.stringify(level), 30)} as the level to fall back to, and `
        + `policy.fallback.profile admits only ${AUTO_PROFILES.join(', ')}. A lookup may not reach a level a policy author `
        + 'could not have written by hand',
        { ...common, rows },
      );
    }
  }
  for (const row of matched) {
    const to = row.to;
    if (!to || typeof to !== 'object' || Array.isArray(to) || to.opt !== row.profile) {
      return autoReject(
        'fallback-table-unreadable',
        `the fallback table at ${tableRel} has a row for ${clip(row.propertyId, 60)} whose profile is `
        + `${clip(JSON.stringify(row.profile), 20)} and whose to.opt is ${clip(JSON.stringify(to?.opt), 20)}; the row disagrees `
        + 'with itself about which configuration it is recommending',
        { ...common, rows },
      );
    }
  }
  // A row may only ask for something this recompile can actually do: change
  // the `-O` level of one translation unit. If `to` differs from `from` on any
  // other axis — target, lto, ndebug, freestanding, cc — then applying the row
  // means building something else, and the row's evidence was gathered for
  // that something else rather than for the recompile the driver would run.
  //
  // ★ Keyed on RECOMPILE_MUTABLE_AXES, not on the axes this invocation could
  // read. Those two lists were the same object when the driver read `opt` and
  // nothing else, and letting them stay the same as reading widened would have
  // opened the hole this check exists to close: a row moving `target` from
  // `host` to `arm-none-eabi` would have been waved through the moment `target`
  // became readable, and the driver would have recompiled for the host while
  // quoting a measurement taken on a cross target. Being able to see an axis is
  // not being able to move it.
  //
  // The comparison is still row-against-itself rather than row-against-build,
  // which is what makes it independent of how much of the line was readable.
  for (const row of matched) {
    const moved = Object.keys(row.from)
      .filter((axis) => !RECOMPILE_MUTABLE_AXES.includes(axis) && row.to[axis] !== row.from[axis])
      .sort();
    if (moved.length > 0) {
      return autoReject(
        'fallback-row-moves-inapplicable-axis',
        `the fallback table at ${tableRel} has a row for ${clip(row.propertyId, 60)} whose target differs from its `
        + `source on ${moved.join(', ')}, and this fallback recompiles one translation unit at a different -O level. `
        + 'Its evidence was measured somewhere this recompile does not go',
        { ...common, rows },
      );
    }
  }
  if (levels.length > 1) {
    return autoReject(
      'fallback-profile-disagreement',
      `the fallback table at ${tableRel} has ${matched.length} rows matching this build and they name different levels `
      + `(${levels.join(', ')}) for ${[...new Set(matched.map((r) => r.propertyId))].join(', ')}. One recompile happens at one `
      + 'level, so there is no single level that carries every property the policy requires',
      { ...common, rows },
    );
  }

  return {
    ok: true,
    profile: levels[0],
    record: resolutionRecord({ ...common, profile: levels[0], rows }),
  };
}

/**
 * The subset of `compiler/schema/observation.schema.json` the driver reads,
 * checked rather than trusted — the same discipline `isWellFormedFinding`
 * applies to a peer's findings. A record that does not parse is not an empty
 * record; it is an answer the driver refuses to interpret.
 *
 * @returns {{ok: true, byId: Map<string, object>} | {ok: false, reason: string, detail: string}}
 */
export function parseObservation(text) {
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    return { ok: false, reason: 'not-json', detail: clip(err.message) };
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, reason: 'not-an-object', detail: 'the observer did not write a JSON object' };
  }
  if (raw.observationVersion !== OBSERVATION_VERSION) {
    return {
      ok: false,
      reason: 'bad-version',
      detail: `expected observationVersion ${OBSERVATION_VERSION}, got ${clip(JSON.stringify(raw.observationVersion), 40)}`,
    };
  }
  if (!Array.isArray(raw.properties)) {
    return { ok: false, reason: 'no-properties', detail: 'properties is not an array' };
  }

  const byId = new Map();
  for (const e of raw.properties) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      return { ok: false, reason: 'bad-entry', detail: 'a properties[] item is not an object' };
    }
    if (typeof e.id !== 'string' || e.id.length === 0) {
      return { ok: false, reason: 'bad-entry', detail: 'a properties[] item has no id' };
    }
    if (!PROPERTY_STATES.includes(e.finalState)) {
      return {
        ok: false,
        reason: 'unknown-state',
        detail: `${clip(e.id, 60)}: finalState ${clip(JSON.stringify(e.finalState), 30)} is not one of ${PROPERTY_STATES.join(', ')}`,
      };
    }
    if (typeof e.historyComplete !== 'boolean') {
      return { ok: false, reason: 'bad-entry', detail: `${clip(e.id, 60)}: historyComplete is not a boolean` };
    }
    // The control is required by the observation schema and it is required here.
    // A measurement whose own control did not survive has disowned itself, and
    // reading a property state out of it would be quoting a broken instrument.
    const control = e.control;
    if (!control || typeof control !== 'object' || Array.isArray(control) || !PROPERTY_STATES.includes(control.state)) {
      return { ok: false, reason: 'bad-control', detail: `${clip(e.id, 60)}: control.state is missing or not a declared state` };
    }
    byId.set(e.id, {
      id: e.id,
      kind: typeof e.kind === 'string' ? e.kind : null,
      finalState: e.finalState,
      historyComplete: e.historyComplete,
      controlState: control.state,
    });
  }
  return { ok: true, byId };
}

/**
 * Is this entry one the driver may quote? Two ways to be unusable, and both are
 * "we cannot tell" rather than "it is gone".
 */
export function usable(entry) {
  return !!entry && entry.historyComplete === true && entry.controlState === PRESERVED_STATE;
}

function emptyRecord(fb, requested, extra) {
  return {
    candidate: null,
    claim: '',
    complete: true,
    configured: true,
    counts: { lost: 0, preserved: 0, requested: requested.length, restored: 0, stillLost: 0, unusable: 0 },
    enabled: fb.enabled,
    granularity: GRANULARITY,
    observer: { sha256: null, supplied: false },
    profile: fb.profile,
    // Where `profile` above came from. Without this a record showing `-O0`
    // cannot be told apart from a policy that wrote `-O0` and a table that was
    // consulted and answered `-O0`, and only one of those two is a measurement.
    profileResolution: fb.profileResolution ?? null,
    profileSource: fb.profileSource ?? null,
    properties: [],
    reason: 'ok',
    rejectIfStillLost: fb.rejectIfStillLost,
    requested,
    status: 'disabled',
    unit: null,
    verdict: 'disabled',
    ...extra,
  };
}

/**
 * Run one observation: emit IR with `extraFlags`, then ask the observer about
 * it. Returns the parsed map, or the reason it could not be had.
 */
function observe({ compiler, compilerArgv, cwd, env, workDir, label, extraFlags, observerPath, observerArgv, unit, profile }) {
  const obs = runObservation({
    compiler, argv: compilerArgv, cwd, scratchDir: workDir, extraFlags, label, env,
  });
  if (!obs.ok) {
    return {
      ok: false,
      reason: 'observation-build-failed',
      detail: `the ${label} observation build exited ${obs.spawnError ? `with ${clip(obs.spawnError, 40)}` : String(obs.exitCode)}; `
        + 'no IR was produced, so nothing could be observed',
      durationMs: obs.durationMs,
    };
  }
  const args = [...observerArgv, '--profile', profile, '--unit', unit, '--ir', obs.outputPath];
  const res = spawnSync(observerPath.exec, [...observerPath.prefix, ...args], {
    cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: OBSERVER_TIMEOUT_MS,
  });
  if (res.error) {
    return { ok: false, reason: 'observer-not-runnable', detail: clip(res.error.code ?? res.error.message, 60), durationMs: obs.durationMs };
  }
  if (res.status !== 0) {
    return {
      ok: false,
      reason: 'observer-failed',
      detail: `the observer exited ${res.status}${res.signal ? ` (signal ${res.signal})` : ''}: ${clip(res.stderr, 80)}`,
      durationMs: obs.durationMs,
    };
  }
  const parsed = parseObservation(res.stdout ?? '');
  if (!parsed.ok) {
    return { ok: false, reason: `observer-record-${parsed.reason}`, detail: parsed.detail, durationMs: obs.durationMs };
  }
  return { ok: true, byId: parsed.byId, durationMs: obs.durationMs };
}

/**
 * How to spawn the observer. A `.mjs`/`.js`/`.cjs` is run with the node that is
 * already running; anything else is executed directly, because a real observer
 * is a compiled tool and wrapping it in node would be nonsense.
 */
function observerCommand(path) {
  if (/\.(mjs|cjs|js)$/i.test(path)) return { exec: process.execPath, prefix: [path] };
  return { exec: path, prefix: [] };
}

/**
 * Read `policy.fallback` and, when it says so, act on it.
 *
 * Called only when `policy.fallback` is present: an absent block means this
 * function is never entered and no `checks.fallback` key is written, so a policy
 * that has never heard of fallback produces the same record, byte for byte, as
 * it did before this file existed.
 *
 * @returns {{record: object, findings: object[], complete: boolean, timings: object}}
 */
export function evaluateFallback({
  policy, normalised, compilerArgv, compiler, cwd, root, workDir, observer, env = process.env, blocked = null,
}) {
  const declared = readFallbackPolicy(policy);
  // `fb` is rebound once, when `profile: "auto"` is resolved to a level. Every
  // reader below — including the `unsupported` closure — sees the resolved
  // value, which is the point: `"auto"` must not reach a command line.
  let fb = {
    ...declared,
    profileResolution: null,
    profileSource: declared.profile === null ? null : declared.profile === AUTO_PROFILE ? AUTO_PROFILE : 'policy',
  };
  const requested = mustSurviveIds(policy);
  const findings = [];
  const timings = {};

  const unsupported = (reason, detail) => {
    findings.push(makeFinding({
      id: CFG.FALLBACK_UNSUPPORTED,
      severity: 'high',
      title: 'The policy enables the security-preserving fallback, but it could not be applied',
      detail: `${detail}. The build was not checked for lost must-survive properties, and "not checked" is not "nothing was lost".`,
      where,
    }));
    return {
      record: emptyRecord(fb, requested, {
        claim: `fallback is enabled and could not run (${reason}); no must-survive property was observed and none is claimed to hold`,
        complete: false,
        reason,
        status: 'unsupported',
        verdict: 'unsupported',
      }),
      findings,
      complete: false,
      timings,
    };
  };

  if (!fb.enabled) {
    return {
      record: emptyRecord(fb, requested, {
        claim: 'policy.fallback.enabled is false, which is the default: no observation was made and no recompilation was attempted',
        reason: 'disabled',
        status: 'disabled',
        verdict: 'disabled',
      }),
      findings,
      complete: true,
      timings,
    };
  }

  // An already-failing build is not rescued by compiling it again. Nothing runs
  // after an integrity failure (interfaces.md section 7), and a configuration
  // the policy has already refused does not get a second opinion here.
  if (blocked) {
    return {
      record: emptyRecord(fb, requested, {
        claim: `fallback was not attempted because the build had already stopped (${blocked})`,
        reason: blocked,
        status: 'not-attempted',
        verdict: 'not-attempted',
      }),
      findings,
      complete: true,
      timings,
    };
  }

  if (requested.length === 0) {
    return unsupported(
      'no-must-survive-property',
      'policy.fallback.enabled is true and policy.properties[] declares no must-survive property, '
      + 'so there is nothing this could rescue and the enablement describes a build that was never at issue',
    );
  }
  // `"auto"` is spent here: from this line on `fb.profile` is a compiler flag
  // or the run has already been refused. It sits after the must-survive check
  // so that a policy with nothing to rescue is told that, rather than being
  // sent to look at a table that was never going to matter, and before the
  // `no-profile` and `flags.optLevels` checks so that both judge the level that
  // will actually be compiled at rather than the word that stood in for it.
  if (fb.profile === AUTO_PROFILE) {
    const auto = resolveAutoProfile({
      normalised,
      requested,
      root,
      tablePath: policy?.fallback?.profileTable,
    });
    fb = { ...fb, profile: auto.ok ? auto.profile : AUTO_PROFILE, profileResolution: auto.record };
    if (!auto.ok) return unsupported(auto.reason, auto.detail);
  }

  if (fb.profile === null) {
    return unsupported(
      'no-profile',
      'policy.fallback.profile is not set, so no approved lower optimisation profile exists to recompile at',
    );
  }
  const evaluated = policy?.flags?.optLevels;
  if (Array.isArray(evaluated) && evaluated.length > 0 && !evaluated.includes(fb.profile)) {
    return unsupported(
      'profile-not-in-evaluated-opt-levels',
      `policy.fallback.profile is ${fb.profile} and flags.optLevels is [${evaluated.join(', ')}]; `
      + 'recompiling at a level the policy has never been evaluated at is the complaint VG-CFG-003 exists to make, '
      + 'and doing it as a remedy would make that check meaningless',
    );
  }
  if (workDir === null) {
    return unsupported('no-evidence-work-directory', 'the policy sets no evidence.out, so there is nowhere to put an observation or a candidate');
  }
  if (UNOBSERVABLE_ACTIONS.has(normalised.action)) {
    return unsupported('action-produces-no-ir', `the invocation's action is ${normalised.action}, which produces no IR to observe`);
  }
  if (normalised.sources.length === 0) {
    return unsupported('no-source-to-recompile', 'the invocation compiles no source file, so there is no translation unit to rebuild');
  }
  if (normalised.sources.length > 1) {
    return unsupported(
      'multi-source-invocation',
      `the invocation names ${normalised.sources.length} sources. This works at translation-unit granularity; `
      + 'recompiling all of them and describing the result as the unit that lost the property would claim a resolution the measurement does not have',
    );
  }
  if (typeof observer !== 'string' || observer.length === 0) {
    return unsupported(
      'no-observer',
      'no --vg-observer was given. The driver does not decide must-survive for itself — the implemented extractors for '
      + 'that kind live in the LLVM pass — so with no observer there is no verdict to act on',
    );
  }
  const observerPath = resolve(cwd, observer);
  if (!existsSync(observerPath) || !statSync(observerPath).isFile()) {
    return unsupported('observer-not-a-file', 'the path given to --vg-observer is not a file');
  }
  const observerSha = sha256File(observerPath);
  const cmd = observerCommand(observerPath);
  const unit = normalised.sources[0];
  const unitPath = toRecordPath(resolve(cwd, unit), root);
  // The same function `driverConfigAxes` matched the table on. Two spellings of
  // "the level this build compiles at" could drift, and then the record would
  // name one level as the shipping configuration while a row chosen for another
  // was quoted as the reason for the fallback.
  const shippingProfile = shippingOptLevel(normalised);

  const withObserver = (extra) => emptyRecord(fb, requested, {
    observer: { sha256: observerSha, supplied: true },
    unit: unitPath,
    ...extra,
  });

  // ---- before: the configuration the caller asked for ----------------------
  const before = observe({
    compiler, compilerArgv, cwd, env, workDir, label: 'before', extraFlags: IR_FLAGS,
    observerPath: cmd, observerArgv: [], unit, profile: shippingProfile,
  });
  timings.fallbackBeforeMs = before.durationMs ?? 0;
  if (!before.ok) {
    findings.push(makeFinding({
      id: CFG.FALLBACK_UNSUPPORTED,
      severity: 'high',
      title: 'The security-preserving fallback could not observe the build it was enabled for',
      detail: `${before.reason}: ${before.detail}. No must-survive property was observed, and that is not "nothing was lost".`,
      where,
    }));
    return {
      record: withObserver({
        claim: `the shipping configuration could not be observed (${before.reason}); no property state was read`,
        complete: false,
        reason: before.reason,
        status: 'unsupported',
        verdict: 'unsupported',
      }),
      findings,
      complete: false,
      timings,
    };
  }

  const rows = [];
  let preserved = 0;
  let unusableCount = 0;
  const lostIds = [];
  for (const id of requested) {
    const entry = before.byId.get(id);
    if (!usable(entry)) {
      unusableCount += 1;
      rows.push({ after: null, before: entry ? entry.finalState : null, id, verdict: 'unusable' });
      continue;
    }
    if (entry.finalState === PRESERVED_STATE) {
      preserved += 1;
      rows.push({ after: null, before: entry.finalState, id, verdict: 'preserved' });
      continue;
    }
    lostIds.push(id);
    rows.push({ after: null, before: entry.finalState, id, verdict: 'lost' });
  }

  if (unusableCount > 0) {
    findings.push(makeFinding({
      id: CFG.FALLBACK_UNSUPPORTED,
      severity: 'high',
      title: 'The observer gave no usable state for a must-survive property the policy declared',
      detail: `${unusableCount} of ${requested.length} declared must-survive propert${requested.length === 1 ? 'y' : 'ies'} came back `
        + 'absent from the observation, with an incomplete history, or with a control that did not survive. '
        + 'None of those is a reading that a property held.',
      where,
    }));
  }

  if (lostIds.length === 0) {
    return {
      record: withObserver({
        claim: unusableCount > 0
          ? `${preserved} of ${requested.length} declared must-survive properties were observed PRESENT and ${unusableCount} could not be read; nothing was recompiled`
          : `all ${requested.length} declared must-survive propert${requested.length === 1 ? 'y was' : 'ies were'} observed PRESENT at ${shippingProfile}; nothing needed rescuing`,
        complete: unusableCount === 0,
        counts: { lost: 0, preserved, requested: requested.length, restored: 0, stillLost: 0, unusable: unusableCount },
        properties: rows,
        reason: unusableCount > 0 ? 'unusable-observation' : 'no-loss',
        status: 'observed',
        // Not `no-loss`. Nothing was observed to be lost, and that sentence is
        // only a verdict when everything was observed; with an unreadable entry
        // in the set it is the absence of a verdict.
        verdict: unusableCount > 0 ? 'unusable' : 'no-loss',
      }),
      findings,
      complete: unusableCount === 0,
      timings,
    };
  }

  // ---- after: the same translation unit at the approved lower profile ------
  const after = observe({
    compiler, compilerArgv, cwd, env, workDir, label: 'after', extraFlags: [fb.profile, ...IR_FLAGS],
    observerPath: cmd, observerArgv: [], unit, profile: fb.profile,
  });
  timings.fallbackAfterMs = after.durationMs ?? 0;
  if (!after.ok) {
    for (const row of rows) if (row.verdict === 'lost') row.verdict = 'still-lost';
    findings.push(lostFinding(lostIds, shippingProfile, 'critical',
      `the recompile at ${fb.profile} could not be observed (${after.reason}: ${after.detail}), so nothing says the property came back`));
    findings.push(makeFinding({
      id: CFG.FALLBACK_UNSUPPORTED,
      severity: 'high',
      title: 'The fallback recompile could not be observed',
      detail: `${after.reason}: ${after.detail}.`,
      where,
    }));
    return {
      record: withObserver({
        claim: `${lostIds.length} must-survive propert${lostIds.length === 1 ? 'y is' : 'ies are'} not PRESENT at ${shippingProfile} and the ${fb.profile} recompile could not be observed`,
        complete: false,
        counts: { lost: lostIds.length, preserved, requested: requested.length, restored: 0, stillLost: lostIds.length, unusable: unusableCount },
        properties: rows,
        reason: after.reason,
        status: 'observed',
        verdict: 'reject',
      }),
      findings,
      complete: false,
      timings,
    };
  }

  let restored = 0;
  let stillLost = 0;
  const restoredIds = [];
  const stillLostIds = [];
  for (const row of rows) {
    if (row.verdict !== 'lost') continue;
    const entry = after.byId.get(row.id);
    if (!usable(entry)) {
      row.after = entry ? entry.finalState : null;
      row.verdict = 'still-lost';
      stillLost += 1;
      stillLostIds.push(row.id);
      continue;
    }
    row.after = entry.finalState;
    if (entry.finalState === PRESERVED_STATE) {
      row.verdict = 'restored';
      restored += 1;
      restoredIds.push(row.id);
    } else {
      row.verdict = 'still-lost';
      stillLost += 1;
      stillLostIds.push(row.id);
    }
  }

  const counts = { lost: lostIds.length, preserved, requested: requested.length, restored, stillLost, unusable: unusableCount };

  if (stillLost > 0) {
    findings.push(lostFinding(stillLostIds, shippingProfile, 'critical',
      `recompiling the translation unit at ${fb.profile} did not bring ${stillLost === 1 ? 'it' : 'them'} back`));
    findings.push(makeFinding({
      id: CFG.FALLBACK_DID_NOT_RESTORE,
      severity: fb.rejectIfStillLost ? 'critical' : 'high',
      title: 'The security-preserving fallback ran and did not restore the property',
      detail: `${stillLostIds.join(', ')} ${stillLostIds.length === 1 ? 'is' : 'are'} still not PRESENT after recompiling `
        + `${unitPath} at ${fb.profile} (granularity: ${GRANULARITY}). rejectIfStillLost is ${fb.rejectIfStillLost}. `
        + 'No candidate artefact was produced: an artefact that does not preserve the property is not a candidate for anything.',
      where,
    }));
    if (restored > 0) {
      findings.push(lostFinding(restoredIds, shippingProfile, 'high',
        `recompiling at ${fb.profile} does restore ${restored === 1 ? 'it' : 'them'}, but the same recompile left ${stillLost} other propert${stillLost === 1 ? 'y' : 'ies'} lost, so no candidate was kept`));
    }
    return {
      record: withObserver({
        claim: `${stillLost} of ${lostIds.length} lost must-survive propert${stillLost === 1 ? 'y is' : 'ies are'} still not PRESENT after recompiling at ${fb.profile}; rejected`,
        counts,
        properties: rows,
        reason: 'still-lost',
        status: 'observed',
        verdict: 'reject',
      }),
      findings,
      complete: unusableCount === 0,
      timings,
    };
  }

  // ---- restored: build the candidate the record will name ------------------
  const cand = runObservation({
    compiler, argv: compilerArgv, cwd, scratchDir: workDir, extraFlags: [fb.profile], label: 'candidate', env,
  });
  timings.fallbackCandidateMs = cand.durationMs ?? 0;
  let candidate = null;
  if (cand.ok && existsSync(cand.outputPath)) {
    candidate = {
      bytes: statSync(cand.outputPath).size,
      path: toRecordPath(cand.outputPath, root),
      profile: fb.profile,
      sha256: sha256File(cand.outputPath),
    };
  }
  findings.push(lostFinding(restoredIds, shippingProfile, 'high',
    candidate
      ? `recompiling ${unitPath} at ${fb.profile} restores ${restored === 1 ? 'it' : 'them'}; that candidate artefact is recorded, and the artefact this command line asks for is not it`
      : `recompiling ${unitPath} at ${fb.profile} restores ${restored === 1 ? 'it' : 'them'}, but the candidate artefact could not be built, so there is nothing to point at`));
  if (!candidate) {
    findings.push(makeFinding({
      id: CFG.FALLBACK_UNSUPPORTED,
      severity: 'high',
      title: 'The fallback restored the property but produced no candidate artefact',
      detail: `the recompile at ${fb.profile} was observed to restore the property and then failed to leave an artefact behind`
        + `${cand.spawnError ? ` (${clip(cand.spawnError, 40)})` : ` (exit ${String(cand.exitCode)})`}.`,
      where,
    }));
  }
  return {
    record: withObserver({
      candidate,
      claim: `${restored} must-survive propert${restored === 1 ? 'y was' : 'ies were'} not PRESENT at ${shippingProfile} and ${restored === 1 ? 'is' : 'are'} PRESENT after `
        + `recompiling ${unitPath} at ${fb.profile}; the candidate is recorded and the shipping artefact is unchanged`,
      complete: unusableCount === 0 && candidate !== null,
      counts,
      properties: rows,
      reason: 'restored',
      status: 'observed',
      verdict: 'restored',
    }),
    findings,
    complete: unusableCount === 0 && candidate !== null,
    timings,
  };
}

function lostFinding(ids, shippingProfile, severity, tail) {
  return makeFinding({
    id: CFG.PROPERTY_LOST,
    severity,
    title: 'A must-survive property the policy declares is not present in the build it configured',
    detail: `${ids.join(', ')} ${ids.length === 1 ? 'was' : 'were'} observed as not PRESENT at ${shippingProfile}, and ${tail}. `
      + `Granularity: ${GRANULARITY} — a function-level recompile is not something a compiler driver can ask for, and this does not pretend to.`,
    where,
  });
}
