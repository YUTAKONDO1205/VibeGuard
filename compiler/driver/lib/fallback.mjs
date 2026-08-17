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
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, resolve } from 'node:path';

import { SIDECAR_SCHEMA_VERSION, configKey } from '../../envelope/derive-frontier-sidecar.mjs';
import {
  FrontierError, compareFrontiers, declaresBroken, declaresUnhealthy, readHealthyDocument,
} from '../../envelope/frontier-match.mjs';
import { OPT_LEVELS } from './cmdline.mjs';
import { driverConfigAxes, shippingOptLevel } from './config-axes.mjs';
import { CFG, makeFinding } from './findings.mjs';
import { runObservation } from './invoke.mjs';
import { relativiseToken, toRecordPath } from './paths.mjs';
import { sha256File } from './toolchain.mjs';

// Re-exported rather than redefined. Both moved to `config-axes.mjs` because
// `derive-frontier-sidecar.mjs` has to read a command line into the six axes the
// same way this file does, and this file imports the sidecar's `configKey` — so
// the sidecar importing them back out of here would close a cycle. They stay
// exported under this name because this is where every caller in the tree has
// imported them from since they existed, and moving a file should not move a
// name out from under its callers.
export { driverConfigAxes, shippingOptLevel };

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

// ── the exposure guard: a nominal key is not an exposure ────────────────────
//
// Everything above keys the table on a NOMINAL six-axis configuration, and the
// nominal key is coarser than the optimiser it is standing in for. Run the
// `normalise` and `driverConfigAxes` in this repository over these five command
// lines and four of them come back as the same key — measured 2026-08-17:
//
//   -O2                                                -> {freestanding:false,
//   -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3             lto:"none",
//   -O2 -fno-builtin-memset                               ndebug:false,
//   -O2 -ffast-math                                       opt:"-O2",
//   -O2 -fstack-protector-strong -fPIC -march=native      target:"host"}
//
// `-ffreestanding` is the one flag of that family that lands somewhere else,
// and only because freestanding is an axis. The rest are not axes and they are
// not neutral: `_FORTIFY_SOURCE` changes which wipe symbol the front end emits
// and `-fno-builtin-memset` changes whether it emits an intrinsic at all, and
// both of those are exactly what the wipe extractors count. So the lookup can
// quote a row measured under plain `-O2` at a build that is really FORTIFY=3,
// and nothing in the six axes notices.
//
// ── WHAT THE GUARD DOES, AND THE ONE THING IT MAY NEVER DO ──────────────────
//
// A small graded specimen — the ladder — is compiled SEPARATELY, under this
// build's exact flags, by `run-ladder.sh`; its graded response, rung by rung, is
// a frontier. `derive-frontier-sidecar.mjs` files those readings under the same
// six-axis key the table uses, and `policy.fallback.exposureFrontiers` names the
// result. If the frontier measured for this build differs from the frontier
// recorded beside the cell being quoted, at least one probed mechanism differs
// between the two builds and the cell is not quoted for this one.
//
// ★ The frontier is never used to FILL or to CHOOSE a cell, and must not be. A
// ladder cell is a measurement of the ladder under a configuration; it says
// nothing whatever about the user's subject. Selecting an envelope cell by
// frontier would be `derive-fallback-table.mjs`'s documented mistake #1 — one
// property's evidence standing in for another's — repeated one level up. This
// guard only ever subtracts: it turns a resolution that would have happened
// into a refusal, and there is no setting of it that produces a level.
//
// ── THE THREE WORDS ─────────────────────────────────────────────────────────
//
// `compareFrontiers` in compiler/envelope/frontier-match.mjs owns the
// comparison and its vocabulary, and this file does not re-implement either.
// `exposure-consistent` is the one that has to be read carefully: it means no
// probed mechanism separated the two builds, which is necessary and never
// sufficient. The instrument fails towards it — the ladder is a single
// translation unit, so cross-TU inlining, profile data, -march code generation
// and everything below the IR optimiser are invisible to it, and two genuinely
// different exposures can present identical frontiers. The other direction is
// clean, which is why refusal is the only thing this guard emits.
//
// ── WHY THE MEASURED FRONTIER ARRIVES AS DATA ───────────────────────────────
//
// `exposureFrontier` is a path to a reading somebody else took. This driver
// does not compile the ladder: measuring is the measuring script's job, and a
// driver that shells out to a compiler to decide a lookup has stopped being a
// driver. The sidecar is resolved against the fixture root because a policy
// names it, and the measured reading against the working directory because an
// invocation carries it — the same split `profileTable` and `--vg-observer`
// already have.
//
// ── WHY A FRONTIER HAS TO BE BOUND TO THE BUILD IT CLEARS ───────────────────
//
// Everything above is about two frontiers agreeing. None of it says the
// frontier in hand is a reading of THIS build, and without that the guard
// reproduces, one level up, exactly the defect it exists to close. CI runs the
// ladder once; six weeks later CFLAGS gain `-D_FORTIFY_SOURCE=3`, or the base
// image moves to a new clang; nobody re-runs the ladder; and every build after
// that reads `exposure-consistent` off a measurement of a different exposure.
// A stale measured frontier clearing builds is worse than no guard, because the
// record then carries a positive reading nobody took.
//
// So five things are checked here, on the driver's side, before any comparison
// is made — and all five are checks this side is the only one able to make. The
// document is `exposure`-bearing and config-free by design (see
// `build-ladder-frontier.py`), the sidecar is keyed by the driver's own reader,
// and the invocation in hand exists nowhere else:
//
//   1. the measured document's `evidenceDigest` recomputes from its own bytes,
//      so an edited or truncated reading is not read at all;
//   2. the document's `exposure.opt` is this build's shipping level and its
//      `exposure.extraArgs` are this invocation's exposure-relevant arguments,
//      so a reading of another command line cannot clear this one;
//   3. the sidecar's entries agree with their own keys (and its digest
//      recomputes, when it carries one), so a hand-edited key cannot redirect a
//      lookup;
//   4. the measured document declares no health invariant false, asked through
//      `declaresUnhealthy` rather than re-derived here;
//   5. the clang that took the reading is the clang that compiled this build —
//      checked in `evaluateFallback` against the observation the fallback path
//      already runs, so it costs no extra compilation.
//
// What none of them can reach is the HEADER SET: `_FORTIFY_SOURCE` is a header
// rewrite, so an image that ships different headers under an identical argv and
// an identical clang binds clean here. That gap is closed operationally and by
// nothing in this file — THE LADDER IS MEASURED IN THE SAME IMAGE AND THE SAME
// JOB AS THE BUILD IT GUARDS — and it is stated in the sidecar's own
// `instrument.failureDirection`, which this reader refuses a sidecar for
// omitting.

// ── interfaces.md §5, recomputed here rather than imported ──────────────────
//
// `compiler/evidence/canon.mjs` implements the same five rules and this file
// deliberately does not call it, for the reason that file gives in its own first
// paragraph: it is the GENERATOR side, and `compiler/evidence/verify.mjs`
// "deliberately does not import this file and re-derives the digest from the
// written rules instead, because two sides that share an implementation agree by
// construction and the agreement proves nothing". This is the verifying side of
// somebody else's document — one written by `build-ladder-frontier.py`, in
// Python — and `check-ladder.py:112-121` re-derives the same rules a third time
// for the same reason. `evidence-binding.mjs`'s rule that the driver carries no
// canonicaliser of its own is about the record this driver WRITES, and it still
// holds: nothing below seals anything.
//
// Verified against the three real measurements on disk (2026-08-17): all three
// `evidenceDigest` values recompute from these rules exactly.

/** A document could not be canonicalised, so its digest cannot be checked. */
class NotCanonical extends Error {}

/**
 * The canonical text of a value: keys sorted at every level, no insignificant
 * whitespace, integers only.
 *
 * The text is built directly rather than by canonicalising an object and handing
 * it to `JSON.stringify`, which is what lets a key like `"0"` be sorted where §5
 * rule 2 puts it instead of where a JS engine's property order puts it —
 * `canon.mjs` refuses such a key for exactly that reason, and the producer here
 * is Python's `json.dumps(sort_keys=True)`, which also builds text directly. The
 * one place the two could still part is a key outside the BMP: Python sorts by
 * code point and `Array.prototype.sort` by UTF-16 code unit. No field of a
 * ladder frontier is non-ASCII, and this is written down rather than guarded
 * because a guard would be a rule §5 does not state.
 */
function canonicalText(value, where) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    // §5 rule 4: the canonicaliser fails rather than rounds. A float in a
    // document means it was not canonicalised the way §5 says, so its digest is
    // unverifiable and the document is refused rather than reshaped.
    if (!Number.isSafeInteger(value)) throw new NotCanonical(`${where || '(root)'} is ${value}, not an exact integer`);
    return String(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    // Array order is significant and is never sorted.
    return `[${value.map((v, i) => canonicalText(v, `${where}/${i}`)).join(',')}]`;
  }
  if (t === 'object') {
    return `{${Object.keys(value).sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalText(value[k], `${where}/${k}`)}`)
      .join(',')}}`;
  }
  throw new NotCanonical(`${where || '(root)'} holds a value of type ${t}, which canonical JSON has no form for`);
}

/**
 * §5 rule 1 and rule 5: strip `context` and `evidenceDigest` from the TOP LEVEL
 * as whole subtrees, then sha-256 the canonical text as UTF-8, lowercase hex.
 *
 * Nothing is stripped at any depth below the top: a key called `context` inside
 * `observations[]` is an ordinary key and is digested like any other.
 *
 * @throws {NotCanonical} the document has no canonical form, so it has no
 *         verifiable digest either
 */
export function evidenceDigestOf(doc) {
  const stripped = { ...doc };
  delete stripped.context;
  delete stripped.evidenceDigest;
  return createHash('sha256').update(canonicalText(stripped, ''), 'utf8').digest('hex');
}

// ── which arguments are exposure-relevant ───────────────────────────────────
//
// ★ ONE DEFINITION, TWO USERS. The CI job that invokes `run-ladder.sh` has to
// generate the ladder's command line, and this reader has to check the document
// that came back against the build in hand. If those two rules are written twice
// they drift on the first flag one of them learns about, and the drift does not
// present as a disagreement: the frontier is measured under a line missing a
// flag, binds clean against a build that has it, and the guard reports a
// clearance for an exposure nobody measured. So `exposureArgs` is exported, and
// the generating side is expected to call it rather than to reimplement it.
//
// The families are the ones that change what the optimiser is handed:
// `-O`, `-D`, `-U`, `-f`, `-m`, `-std=`, `--sysroot`, `-isystem`, `-I`,
// `-include`, and the long spellings clang documents for the macro flags. What
// is left out is left out because it cannot move a rung: `-o`, `-c`, `-MF`, the
// linker's tokens, and the source files themselves — the ladder compiles its own
// specimen and none of those reach the specimen's IR.

/**
 * Exposure-relevant flags whose value is the NEXT token. A subset of
 * `SEPARATE_VALUE_FLAGS` in cmdline.mjs, kept as its own list because the
 * question here is not "does this flag take a value" but "does this flag change
 * the exposure": both tokens travel together or neither does, and emitting
 * `-D` without its operand would hand `run-ladder.sh` a line clang cannot parse.
 */
export const EXPOSURE_VALUE_FLAGS = Object.freeze([
  '-D', '-I', '-U', '--define-macro', '--sysroot', '--undefine-macro',
  '-include', '-isystem', '-mllvm', '--param',
  // The rest of the header-search family. `-imacros fortify.h` installs the
  // fortifying macro set by hand, which is the very thing the b1 and d1 rungs
  // separate, and it was reading as plain `-O2`. Listed by name as well as
  // caught by the `-i` prefix below, because these spellings take their operand
  // as a separate token and a prefix match alone would leave the operand behind.
  '-idirafter', '-imacros', '-iprefix', '-iquote', '-isysroot', '-iwithprefix',
  // The passthroughs, which are here because they can carry anything. Their
  // payload is a separate token, so `-Xpreprocessor -D_FORTIFY_SOURCE=3` was
  // already caught -- but only by accident, because `-D…` matches a joined
  // prefix on its own. `-Xclang -disable-llvm-passes` is the same shape and
  // matches nothing, so it was dropped and a build carrying it compared equal
  // to one without. A flag whose meaning is "hand the next token to a stage
  // this driver does not model" cannot be judged by its payload's spelling.
  '-Xassembler', '-Xclang', '-Xpreprocessor',
]);

/**
 * Driver passthroughs whose payload is comma-joined into the token itself.
 *
 * Measured 2026-08-17, and the reason this list exists: `-O2 -Wp,-U_FORTIFY_SOURCE
 * -Wp,-D_FORTIFY_SOURCE=3` produced `extraArgs: []` and was cleared as
 * `exposure-consistent` against a frontier measured under plain `-O2`. The
 * ladder separates those two builds on six rungs; the binding did not separate
 * them at all, because `-Wp,…` begins `-W` and no joined prefix matches it. That
 * is this guard's own defect wearing the shape of the defect it exists to close,
 * and it failed towards quoting.
 *
 * The whole token is carried rather than its pieces: what comes out of here is
 * what a caller hands to `run-ladder.sh`, and clang reads the joined spelling.
 */
export const EXPOSURE_COMMA_PASSTHROUGHS = Object.freeze(['-Wa,', '-Wp,']);

/**
 * Exposure-relevant flags in their joined spelling. Matched as prefixes, so
 * `-D_FORTIFY_SOURCE=3`, `-ffast-math`, `-march=native`, `-std=c11` and
 * `--sysroot=~/x` are all caught in the one form clang also accepts them in.
 */
export const EXPOSURE_JOINED_PREFIXES = Object.freeze([
  '--define-macro', '--param', '--sysroot', '--undefine-macro',
  '-D', '-I', '-O', '-U', '-f', '-m', '-std=',
  // The whole `-i` family rather than the two spellings that had been named.
  // Every clang flag beginning `-i` decides where headers are found, and where
  // headers are found decides what a wipe is spelled as -- fortification lives
  // in a header. Naming them one at a time is how `-imacros`, `-idirafter` and
  // `-iquote` all read as plain `-O2`; measured 2026-08-17.
  '-i',
]);

/**
 * Exposure-relevant flags that take no operand. They are here for the same
 * reason as the `-i` family: each one changes which headers and which built-ins
 * the compilation sees, so two builds that differ only by one of these are two
 * different exposures while their command lines differ by a token that carries
 * no value to match on.
 */
export const EXPOSURE_BARE_FLAGS = Object.freeze([
  '-nobuiltininc', '-nostdinc', '-nostdinc++', '-nostdlibinc', '-undef',
]);

/**
 * The invocation's exposure, in the two pieces `run-ladder.sh` takes: the level
 * as its `<opt>` argument and everything else as its extra clang arguments.
 *
 * `-O` tokens are carried in `opt` and NEVER in `extraArgs`. Clang takes the
 * last `-O` on the line, so a line reading `-O2 -O1` compiles at `-O1`; putting
 * the level in one field and the rest in another makes that reading explicit,
 * and it is the same reading `driverConfigAxes` files the row under and the same
 * one `derive-frontier-sidecar.mjs` derives the sidecar's key from. A level left
 * in both fields would be applied twice and would still be right, but it would
 * make two documents of the same build differ in their `extraArgs`.
 *
 * The tokens come back UNSANITISED, because this is also what a caller hands to
 * `run-ladder.sh`, and `run-ladder.sh` hands them to a compiler: a `~` that this
 * function had already substituted would reach clang, which does not expand it,
 * and the ladder would be measured under a path that does not exist. Sanitising
 * happens where the comparison happens; see `sanitiseExposureToken`.
 *
 * @param {object} normalised the object `normalise()` returns
 * @returns {{opt: string, extraArgs: string[]}}
 */
export function exposureArgs(normalised) {
  const argv = Array.isArray(normalised?.argv) ? normalised.argv : [];
  const extraArgs = [];
  // Everything after a bare `--` is an input rather than a flag, which is the
  // rule `normalise` itself follows; reading a source file's name as a flag
  // family here would put it on the ladder's command line.
  let sawDashDash = false;
  for (let i = 0; i < argv.length; i += 1) {
    const tok = argv[i];
    if (typeof tok !== 'string' || tok.length < 2 || !tok.startsWith('-')) continue;
    if (tok === '--') { sawDashDash = true; continue; }
    if (sawDashDash) continue;
    if (EXPOSURE_VALUE_FLAGS.includes(tok)) {
      const value = argv[i + 1];
      // A flag with nothing after it is passed on alone rather than dropped: the
      // caller wrote it, `normalise` recorded it, and swallowing it here would
      // make a malformed line and a clean one produce the same exposure.
      if (value === undefined) { extraArgs.push(tok); continue; }
      i += 1;
      extraArgs.push(tok, value);
      continue;
    }
    // The recognised levels only. `-Ofast` is not one `normalise` reads, so it
    // is not in `opt` either, and it travels in `extraArgs` where it will be the
    // last `-O` on the ladder's line exactly as it is on this one.
    if (OPT_LEVELS.has(tok) || tok === '-O') continue;
    if (EXPOSURE_BARE_FLAGS.includes(tok)) { extraArgs.push(tok); continue; }
    // Before the prefix test, because `-Wp,-D…` starts with `-W` and would
    // otherwise fall past every prefix and be dropped. Carried whenever the
    // passthrough has a payload at all, without reading what the payload says:
    // deciding relevance by the spelling inside is how the token got dropped in
    // the first place, and a token carried needlessly costs a refusal while a
    // token dropped wrongly costs a pass.
    if (EXPOSURE_COMMA_PASSTHROUGHS.some((p) => tok.length > p.length && tok.startsWith(p))) {
      extraArgs.push(tok);
      continue;
    }
    if (EXPOSURE_JOINED_PREFIXES.some((p) => tok.length > p.length && tok.startsWith(p))) {
      extraArgs.push(tok);
    }
  }
  return { opt: shippingOptLevel(normalised), extraArgs };
}

/**
 * `run-ladder.sh:83`'s first rule — `sed -e "s#$HOME#~#g"` — applied to one
 * token, so that the two sides of the comparison spell a home-relative path the
 * same way. The runner's second rule, `s#$LAB#<lab>#g`, is not applied: the lab
 * is the measuring script's own directory and no build's command line names it,
 * so substituting it here could only rewrite a token that meant something else.
 */
function sanitiseExposureToken(token, home) {
  if (typeof token !== 'string' || typeof home !== 'string' || home.length === 0 || home === '/') return token;
  return token.split(home).join('~');
}

/**
 * Every way the exposure check can refuse, and the reason each one is reported
 * under. One table, so that a result written into a record and the reason
 * written next to it cannot drift apart; and nine entries rather than one,
 * because they call for nine different pieces of work. "The frontiers differ",
 * "the two readings could not be compared", "nobody measured this build", "the
 * file the policy names is not readable", "the reading taken for this build is
 * not the documented shape", "these are not the bytes that were measured", "this
 * reading is of another command line", "the sidecar's keys do not agree with its
 * own entries" and "another compiler took the reading" are not the same
 * sentence, and a single `fallback-exposure-failed` would send every one of them
 * to the wrong place.
 *
 * The four added by the binding check are separate from the five above them for
 * the same reason those five are separate from each other, and the split matters
 * most here: a digest that does not recompute sends a reader to whoever edited
 * the file, a frontier taken at another opt level sends them to the CI job that
 * measures it, and a clang that moved sends them to the base image. One word for
 * all three would send all three to the same wrong place.
 *
 * `unchecked` is deliberately absent: it is the one result that is not a
 * refusal, and giving it a reason here would make it look like one.
 */
export const EXPOSURE_REFUSALS = Object.freeze({
  'exposure-incomparable': 'fallback-exposure-incomparable',
  'exposure-mismatch': 'fallback-exposure-mismatch',
  'frontier-for-different-invocation': 'fallback-exposure-frontier-for-different-invocation',
  'measurement-digest-mismatch': 'fallback-exposure-measurement-digest-mismatch',
  'measurement-unreadable': 'fallback-exposure-measurement-unreadable',
  'sidecar-digest-mismatch': 'fallback-exposure-sidecar-digest-mismatch',
  'sidecar-unreadable': 'fallback-exposure-sidecar-unreadable',
  'toolchain-drift': 'fallback-exposure-toolchain-drift',
  unmeasured: 'fallback-exposure-unmeasured',
});

/**
 * Read one document off disk, or say which of the three ways it was not there.
 * Split out because the sidecar and the measured reading fail in the same three
 * ways and are reported under two different names.
 *
 * The BYTES come back beside the parsed document, and every digest this file
 * writes into a record is taken from them. Reading the file a second time to
 * hash it — which is what `sha256File` here used to do — names a file rather
 * than a reading: between the two reads the file can change, and the record
 * would then carry the digest of bytes no decision was made on. The digest in a
 * record has to name the reading that actually cleared the build.
 */
function readJsonDocument(abs, rel, refuse, result, what) {
  let bytes;
  try {
    bytes = readFileSync(abs);
  } catch (err) {
    return { bytes: null, doc: null, refusal: refuse(result, `the ${what} at ${rel} could not be read (${clip(err.code ?? err.message, 40)})`) };
  }
  let doc;
  try {
    doc = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    return { bytes, doc: null, refusal: refuse(result, `the ${what} at ${rel} is not JSON (${clip(err.message, 60)})`) };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return { bytes, doc: null, refusal: refuse(result, `the ${what} at ${rel} is not a JSON object`) };
  }
  return { bytes, doc, refusal: null };
}

/** interfaces.md §5 rule 5, over bytes already in hand. Lowercase hex. */
function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Which side of a comparison a malformed document was on.
 *
 * `compareFrontiers` throws one `FrontierInputError` for two documents, and the
 * driver has to say which file to go and fix — a sidecar the policy points at
 * and a reading taken for this build are two different people's problems. So
 * each side is put through the module's own two validators first, in the order
 * the comparison itself uses them. This is not a second implementation of the
 * comparison: nothing here compares anything, and both calls are imported.
 *
 * A document that declares itself broken is NOT a shape error — it is a
 * measurement that reported its own apparatus failure, and `compareFrontiers`
 * reads it as `exposure-incomparable`, which is the honest answer.
 */
function frontierShapeError(doc, where) {
  try {
    if (!declaresBroken(doc, where)) readHealthyDocument(doc, where);
    return null;
  } catch (err) {
    if (!(err instanceof FrontierError)) throw err;
    return clip(err.message, 160);
  }
}

/**
 * Was this build's exposure the one the cell being quoted was measured in?
 *
 * @param {{cwd: string, frontiersPath: string, home?: string,
 *          measuredPath: string|null, normalised: object, root: string,
 *          rows: object[]}} args `rows` are the quoted rows, each carrying the
 *        `from` the sidecar is keyed by; `normalised` is the invocation in hand,
 *        which is what the measured reading is bound to. `home` is a parameter
 *        only so that a test can pin the runner's tilde rule to a directory it
 *        controls; nothing passes it in production.
 * @returns {{ok: true, clang: string|null, record: object}
 *          | {ok: false, reason: string, detail: string, record: object}}
 *          `clang` is the compiler the measured reading names, for the drift
 *          check `evaluateFallback` makes after the observation build. It is not
 *          compared here: `compareFrontiers` deliberately does not compare
 *          labels, and knowing which compiler THIS build actually ran is the
 *          driver's business rather than the comparator's.
 */
export function checkExposure({
  cwd, frontiersPath, home = homedir(), measuredPath, normalised, root, rows,
}) {
  const sidecarAbs = resolve(root, frontiersPath);
  const sidecar = { path: toRecordPath(sidecarAbs, root), sha256: null };
  const refuse = (result, detail, extra = {}) => ({
    ok: false,
    reason: EXPOSURE_REFUSALS[result],
    detail,
    record: { detail, result, sidecar, ...extra },
  });

  const read = readJsonDocument(sidecarAbs, sidecar.path, refuse, 'sidecar-unreadable', 'exposure sidecar');
  if (read.refusal) return read.refusal;
  const sidecarDoc = read.doc;
  sidecar.sha256 = sha256Bytes(read.bytes);

  const badSidecar = (why) => refuse(
    'sidecar-unreadable',
    `the exposure sidecar at ${sidecar.path} is not a ${SIDECAR_SCHEMA_VERSION} document: ${why}`,
  );
  if (sidecarDoc.schemaVersion !== SIDECAR_SCHEMA_VERSION) {
    return badSidecar(`schemaVersion is ${clip(JSON.stringify(sidecarDoc.schemaVersion), 40)}`);
  }
  if (!Array.isArray(sidecarDoc.entries)) return badSidecar('entries is not an array');
  // The disclosure is required to travel with the document. This instrument
  // fails towards `exposure-consistent`, and a sidecar that has had that
  // sentence stripped out of it reads like a stronger guarantee than it is — so
  // a document without one is refused rather than read. `derive-frontier-
  // sidecar.mjs` writes it at `instrument.failureDirection` on every run.
  const failureDirection = sidecarDoc.instrument?.failureDirection;
  if (typeof failureDirection !== 'string' || failureDirection.length === 0) {
    return badSidecar(
      'it states no instrument.failureDirection. The ladder fails towards exposure-consistent, and a sidecar that '
      + 'does not carry that sentence gets quoted as a stronger reading than it is',
    );
  }

  // ---- the sidecar says what it says about itself --------------------------
  //
  // A lookup keyed by `configKey` trusts `entry.configKey` to be the key of
  // `entry.config`, and nothing downstream ever looks at the two together: an
  // entry whose stated key was edited to the key of some other configuration is
  // found by that other configuration's build and compared against a frontier
  // measured somewhere else, and every step of that reads as an ordinary hit.
  // Recomputing the key from the config the entry itself carries is the whole
  // check, and it is cheap enough to run over every entry rather than over the
  // one that happens to be wanted — the entry that was tampered with is not
  // necessarily the entry this build looks up.
  for (const entry of sidecarDoc.entries) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return badSidecar('an entries[] item is not an object');
    }
    const recomputed = configKey(entry.config);
    if (entry.configKey !== recomputed) {
      return refuse(
        'sidecar-digest-mismatch',
        `the exposure sidecar at ${sidecar.path} has an entry filed under ${clip(JSON.stringify(entry.configKey), 90)} whose own `
        + `config keys to ${clip(recomputed, 90)}. The lookup is by the stated key, so an entry that disagrees with itself is `
        + 'found by a configuration it was not measured in, and the comparison that follows would be a real comparison against '
        + 'the wrong reading',
      );
    }
  }
  // The deriver does not yet seal the sidecar, so this is checked only when a
  // digest is there to check — and it is written now rather than later because
  // an unverified digest that a reader assumes was verified is worse than an
  // absent one. When `derive-frontier-sidecar.mjs` starts sealing its output
  // this fires without another edit here.
  if (sidecarDoc.evidenceDigest !== undefined) {
    let recomputed;
    try {
      recomputed = evidenceDigestOf(sidecarDoc);
    } catch (err) {
      if (!(err instanceof NotCanonical)) throw err;
      return refuse(
        'sidecar-digest-mismatch',
        `the exposure sidecar at ${sidecar.path} carries an evidenceDigest and cannot be canonicalised, so the digest cannot be `
        + `checked and nothing in the document can be relied on (${clip(err.message, 80)})`,
      );
    }
    if (recomputed !== sidecarDoc.evidenceDigest) {
      return refuse(
        'sidecar-digest-mismatch',
        `the exposure sidecar at ${sidecar.path} carries evidenceDigest ${clip(JSON.stringify(sidecarDoc.evidenceDigest), 24)} and `
        + `recomputes to ${recomputed.slice(0, 12)}…. The bytes on disk are not the bytes that were sealed, so the entries in it `
        + 'are not the entries the deriver wrote',
      );
    }
  }

  if (typeof measuredPath !== 'string' || measuredPath.length === 0) {
    return refuse(
      'unmeasured',
      `the policy names an exposure sidecar at ${sidecar.path} and no frontier was measured for this build, so there is `
      + 'nothing to compare against it. The guard was asked for and not answered, and an unanswered guard is not a passed one',
    );
  }
  const measuredAbs = resolve(cwd, measuredPath);
  // `relativiseToken`, not `toRecordPath`. The ladder lab lives outside the
  // fixture root by design — `run-ladder.sh` writes under `$IRCK_LADDER_LAB`,
  // which defaults to a directory in `$HOME` — and relativising an out-of-root
  // path against the root yields a `../../..` chain, or on Windows a bare
  // absolute path when the two are on different drives. Either one goes into a
  // sealed record, and §5 forbids the second outright. `relativiseToken` is the
  // helper written for exactly this case: inside the root it gives the relative
  // path, outside it gives `<outside:sha>`, which is stable on this machine and
  // meaningless off it.
  const measuredRel = relativiseToken(measuredAbs, root);
  const measuredRead = readJsonDocument(
    measuredAbs, measuredRel, refuse, 'measurement-unreadable', 'frontier measured for this build',
  );
  if (measuredRead.refusal) return measuredRead.refusal;
  const measured = measuredRead.doc;
  // The reading is named in the record by the digest of the bytes that were
  // read — the bytes this decision was actually made on, not a second read of
  // the same path. That is the same identity the table gets, and it is what
  // makes a record say WHICH reading cleared this build. It is deliberately not
  // `evidenceDigest`: that one names the measurement, this one names the file,
  // and a record that quoted only the first could not be checked against a file.
  const frontierDigest = sha256Bytes(measuredRead.bytes);

  // ---- are these the bytes somebody measured? ------------------------------
  //
  // First, because everything after it reads fields out of these bytes. §5 puts
  // the digest over the document with `context` and `evidenceDigest` stripped,
  // so a document whose measurement was edited — a rung flipped, an `exposure`
  // rewritten to match a build it was not taken under — no longer recomputes,
  // while a re-assembly on another day with another clock still does.
  //
  // A document that states no digest at all is refused here too, under the same
  // name. `build-ladder-frontier.py` seals every document it writes, so an
  // unsealed one either came from something else or had the field removed, and
  // the two are the same problem: there is nothing to check the bytes against.
  // Splitting them would give an attacker the shorter path of deleting a field.
  let recomputedDigest = null;
  try {
    recomputedDigest = evidenceDigestOf(measured);
  } catch (err) {
    if (!(err instanceof NotCanonical)) throw err;
    return refuse(
      'measurement-digest-mismatch',
      `the frontier measured for this build at ${measuredRel} cannot be canonicalised, so its digest cannot be recomputed and `
      + `nothing in it can be checked (${clip(err.message, 80)})`,
      { frontierDigest },
    );
  }
  if (recomputedDigest !== measured.evidenceDigest) {
    return refuse(
      'measurement-digest-mismatch',
      `the frontier measured for this build at ${measuredRel} carries evidenceDigest `
      + `${clip(JSON.stringify(measured.evidenceDigest ?? null), 24)} and recomputes to ${recomputedDigest.slice(0, 12)}…. `
      + 'Its bytes are not the bytes that were sealed when the ladder was read, so what it says was measured is not what it says '
      + 'it is',
      { frontierDigest },
    );
  }

  const measuredShape = frontierShapeError(measured, 'the frontier measured for this build');
  if (measuredShape !== null) {
    return refuse('measurement-unreadable', `${measuredRel}: ${measuredShape}`, { frontierDigest });
  }
  // The three invariants, asked of the document that is about to clear a build.
  // `compareFrontiers` asks the same question of both sides, and would catch
  // this one too — but it is asked here as well because the answer names the
  // instrument rather than the pair, and because a reader sent to "the two
  // readings could not be compared" goes looking for a version skew that is not
  // there. The names are `frontier-match.mjs`'s, not re-derived: a second list
  // of the three would go stale the day a fourth invariant is measured.
  const failing = declaresUnhealthy(measured);
  if (failing !== null) {
    return refuse(
      'exposure-incomparable',
      `the frontier measured for this build at ${measuredRel} declares ${failing.join(' and ')} false. The specimen stopped `
      + 'behaving like a graded ladder during the run that produced it, so its rungs are not readings and nothing is compared '
      + 'against them',
      { frontierDigest },
    );
  }

  // ---- is this a reading of THIS invocation? -------------------------------
  //
  // The comparison below establishes that two frontiers agree. It says nothing
  // at all about whether the frontier in hand was measured under the command
  // line being compiled now, and without this check the answer is routinely no:
  // a frontier measured once and left on disk clears every later build,
  // including the one whose CFLAGS grew `-D_FORTIFY_SOURCE=3` — which is
  // precisely the exposure the whole ladder exists to notice.
  const wanted = exposureArgs(normalised);
  const stated = measured.exposure;
  if (!stated || typeof stated !== 'object' || Array.isArray(stated)
      || typeof stated.opt !== 'string'
      || !Array.isArray(stated.extraArgs) || stated.extraArgs.some((a) => typeof a !== 'string')) {
    return refuse(
      'measurement-unreadable',
      `${measuredRel}: the document states no readable exposure.opt and exposure.extraArgs, so it cannot say which invocation `
      + 'it is a reading of, and a reading that names no command line cannot be bound to one',
      { frontierDigest },
    );
  }
  // Sanitised for the comparison, relativised for the message, and the two are
  // different transforms on purpose. `run-ladder.sh` tilde-shortens before it
  // writes the manifest, so the document's side is already sanitised and the
  // build's side has to be to match; but a tilde is not what §5 asks of a record,
  // so what gets printed goes through `relativiseToken` as well.
  const ours = wanted.extraArgs.map((a) => sanitiseExposureToken(a, home));
  const sameOpt = sanitiseExposureToken(wanted.opt, home) === stated.opt;
  const sameArgs = ours.length === stated.extraArgs.length && ours.every((a, i) => a === stated.extraArgs[i]);
  const forRecord = (opt, args) => clip([opt, ...args].map((a) => relativiseToken(a, root)).join(' '), 200);
  const exposureCompared = {
    build: { extraArgs: ours.map((a) => relativiseToken(a, root)), opt: wanted.opt },
    frontier: { extraArgs: stated.extraArgs.map((a) => relativiseToken(a, root)), opt: stated.opt },
  };
  if (!sameOpt || !sameArgs) {
    return refuse(
      'frontier-for-different-invocation',
      `the frontier at ${measuredRel} was measured under \`${forRecord(stated.opt, stated.extraArgs)}\` and this build compiles `
      + `\`${forRecord(wanted.opt, ours)}\`. A frontier is a reading of one command line, so a reading of another one says `
      + 'nothing about this build — and a measurement left on disk while the flags moved underneath it is the exact failure this '
      + 'guard exists to catch, one level up',
      { exposure: exposureCompared, frontierDigest },
    );
  }

  // One comparison per distinct configuration among the quoted rows. Usually
  // one; more when an axis this command line could not state left several rows
  // matching, and then every one of them has to survive, because any of them
  // could be the cell whose level was adopted.
  //
  // The key is `derive-frontier-sidecar.mjs`'s own `configKey`, imported rather
  // than rebuilt. Two spellings of "the same configuration" would drift on the
  // first axis whose value is written differently on the two sides, and the
  // drift would show up as a sidecar that silently has nothing to say about any
  // build. That does not read as a clean run from here — the missing entry is
  // refused just below, as `exposure-incomparable` — but it does read as a build
  // nobody has measured, on every build, and a guard that refuses everything for
  // a reason that is not about the build is a guard someone switches off.
  const byConfig = new Map();
  for (const row of rows) {
    const from = row?.from;
    if (!from || typeof from !== 'object' || Array.isArray(from)) {
      return refuse(
        'exposure-incomparable',
        'a row quoted for this build carries no configuration to key the sidecar by, so the cell it came from '
        + 'could not be found and no comparison was made',
      );
    }
    const key = configKey(from);
    if (byConfig.has(key)) continue;
    const entry = sidecarDoc.entries.find((e) => e && e.configKey === key);
    if (entry === undefined) {
      byConfig.set(key, {
        config: from,
        differingRungs: [],
        reason: `the sidecar at ${sidecar.path} records no frontier for ${describeAxes(from)}.`,
        result: 'exposure-incomparable',
      });
      continue;
    }
    const entryShape = frontierShapeError(entry, 'the frontier the sidecar records');
    if (entryShape !== null) return badSidecar(`the entry for ${describeAxes(from)} is malformed: ${entryShape}`);
    // An entry the deriver wrote out unusable — two builds collided on its key,
    // or the only measurement of it was broken — carries `health.broken`, so it
    // arrives here as a document that declares its own measurement broken and
    // comes back `exposure-incomparable`. That is not special-cased: the
    // deriver shaped its entries so that a consumer would not have to know its
    // vocabulary, and knowing it anyway would be a second place deciding what
    // an unusable key means.
    byConfig.set(key, {
      config: from,
      ...compareFrontiers(measured, entry, { whereA: 'this build', whereB: 'the recorded cell' }),
    });
  }

  const results = [...byConfig.values()];
  // Mismatch is reported over incomparable when both happened, and the ordering
  // is the same one `no-safe-target` has over `not-observed` above: the
  // stronger claim goes first. A measured difference is evidence; a comparison
  // that could not be made is a gap, and reporting the gap over the top of the
  // evidence would send someone to fix the wrong thing.
  const mismatched = results.filter((r) => r.result === 'exposure-mismatch');
  if (mismatched.length > 0) {
    const differingRungs = [...new Set(mismatched.flatMap((r) => r.differingRungs))].sort();
    return refuse(
      'exposure-mismatch',
      `the ladder frontier measured for this build differs on ${differingRungs.join(', ')} from the frontier the sidecar at `
      + `${sidecar.path} records for ${describeAxes(mismatched[0].config)}. At least one probed mechanism differs between `
      + 'this build and the build that cell was measured in, so the cell is not quoted for this one',
      { config: mismatched[0].config, differingRungs, frontierDigest },
    );
  }
  const incomparable = results.filter((r) => r.result === 'exposure-incomparable');
  if (incomparable.length > 0) {
    return refuse(
      'exposure-incomparable',
      `${clip(incomparable[0].reason, 200)} No comparison was made between the frontier measured for this build and the one `
      + `the sidecar at ${sidecar.path} records for ${describeAxes(incomparable[0].config)}, and that is not the same as a `
      + 'comparison that found nothing',
      { config: incomparable[0].config, frontierDigest },
    );
  }
  // Nothing was compared. `evaluateFallback` only calls this with rows in hand,
  // so reaching here means a caller passed an empty set — and answering
  // `exposure-consistent` for a comparison that never happened is the single
  // worst thing this function could do. It is checked rather than assumed
  // because the assumption lives in another file.
  if (results.length === 0) {
    return refuse(
      'exposure-incomparable',
      'no quoted row named a configuration, so the sidecar was never looked in and no frontier was compared. A guard that '
      + 'compared nothing has not found nothing',
      { frontierDigest },
    );
  }
  // The word is `exposure-consistent`: no probed mechanism separated the two
  // builds. Not "matched", not "verified".
  //
  // ★ And the pass carries its evidence, which it used to drop. Every refusal
  // above names what it found — the rungs, the configuration, the reason — and
  // the one outcome that went out with three bare fields was the one a reader
  // over-reads. `reason` is the comparator's own sentence, which says HOW MANY
  // rungs answered identically and then says in as many words that this is
  // necessary and never sufficient; `rungs` is that number on its own, so a
  // twelve-rung ladder and a one-rung ladder do not clear a build looking alike;
  // and `configKeys` names the cells the comparison was actually made against,
  // because "consistent" is a statement about a lookup and the lookup has a key.
  //
  // Every entry compared clean against the SAME measured document, so they all
  // cover the same rung set and the comparator returns the same sentence for
  // each; `results[0]` is that sentence rather than a choice among several.
  return {
    ok: true,
    clang: typeof measured.toolchain?.clang === 'string' ? measured.toolchain.clang : null,
    record: {
      configKeys: [...byConfig.keys()].sort(),
      exposure: exposureCompared,
      frontierDigest,
      reason: clip(results[0].reason, 400),
      result: 'exposure-consistent',
      rungs: Object.keys(measured.frontier).length,
      sidecar,
    },
  };
}

/**
 * The subset of `compiler/schema/observation.schema.json` the driver reads,
 * checked rather than trusted — the same discipline `isWellFormedFinding`
 * applies to a peer's findings. A record that does not parse is not an empty
 * record; it is an answer the driver refuses to interpret.
 *
 * `clang` is read alongside the property states and is deliberately NOT
 * required. The observation schema requires `toolchain`, but this reader has
 * always taken a documented subset rather than validating the whole record, and
 * the day it starts refusing a record for a field it never used is the day every
 * observer in the tree stops working for a reason unrelated to what it observed.
 * A record that names no compiler yields `null`, and `null` is read downstream
 * as "this observation made no claim about the toolchain" rather than as
 * agreement — see the drift check in `evaluateFallback`.
 *
 * @returns {{ok: true, byId: Map<string, object>, clang: string|null}
 *          | {ok: false, reason: string, detail: string}}
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
  const clang = raw.toolchain?.clang;
  return { ok: true, byId, clang: typeof clang === 'string' && clang.length > 0 ? clang : null };
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
    // Spread, not an `exposureCheck: null`. run.mjs makes exactly this argument
    // one level up about `checks.fallback` itself — "a key holding null is
    // still a key: it changes the canonical text and therefore the digest of
    // every build in the world that never asked for this" — and it holds again
    // here. A policy that names no exposure sidecar gets the record it got
    // before this guard existed, byte for byte, and the key appears only once
    // something was actually looked at.
    ...(fb.exposureCheck ? { exposureCheck: fb.exposureCheck } : {}),
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
  return { ok: true, byId: parsed.byId, clang: parsed.clang, durationMs: obs.durationMs };
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
 * `exposureFrontier` is a path to the frontier somebody else measured for this
 * exact invocation, and it is read only when the policy also names a sidecar to
 * compare it against. Absent, with a sidecar named, is a refusal rather than a
 * pass: see `checkExposure`.
 *
 * @returns {{record: object, findings: object[], complete: boolean, timings: object}}
 */
export function evaluateFallback({
  policy, normalised, compilerArgv, compiler, cwd, root, workDir, observer, env = process.env, blocked = null,
  exposureFrontier = null,
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

  // `extra` is merged last so that a refusal taken AFTER the observer has been
  // resolved can still name it. Without it the drift refusal below would emit a
  // record saying no observer was supplied, on a run whose observer had just
  // answered.
  const unsupported = (reason, detail, extra = {}) => {
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
        ...extra,
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

  // ---- was this build the exposure that cell was measured in? --------------
  //
  // Only when the policy named a sidecar, and only after a level has otherwise
  // resolved: the guard's whole subject is the cell that is about to be quoted,
  // so it has nothing to say about a run that never reached one. It sits before
  // every remaining precondition because a level read out of a cell measured
  // somewhere else should not be reported as this build's level even in a
  // refusal about something else.
  const frontiersPath = policy?.fallback?.exposureFrontiers;
  // The compiler the measured frontier says took the reading, carried down to
  // the observation build below. Null when no guard ran, or when the reading
  // names no compiler.
  let frontierClang = null;
  if (typeof frontiersPath === 'string' && frontiersPath.length > 0) {
    const quoted = fb.profileResolution?.rows ?? [];
    if (quoted.length === 0) {
      // A hand-written `profile` quotes no measurement, so there is no cell
      // whose exposure could be compared. Recorded rather than skipped
      // silently, so that a policy naming a sidecar next to a hand-written
      // level can see that its guard never ran.
      fb = {
        ...fb,
        exposureCheck: {
          detail: 'the level came from policy.fallback.profile rather than from a measured row, so no cell was quoted '
            + 'and there was nothing whose exposure could be compared',
          result: 'unchecked',
        },
      };
    } else {
      const exposure = checkExposure({
        cwd, frontiersPath, measuredPath: exposureFrontier, normalised, root, rows: quoted,
      });
      fb = { ...fb, exposureCheck: exposure.record };
      if (!exposure.ok) return unsupported(exposure.reason, exposure.detail);
      frontierClang = exposure.clang;
    }
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

  // ---- did the same compiler take the reading and compile this build? ------
  //
  // The cheapest of the five binding checks and the last one that can be made,
  // because it is the only one that needs a fact no file on disk carries: which
  // clang actually ran just now. It costs no compilation — the observation above
  // has already been built and read, and its record names its own toolchain.
  //
  // ★ NOT in `compareFrontiers`, and this is the reason. That module compares
  // two readings and deliberately refuses to compare their labels: two clang
  // builds with different package digests that produce an identical frontier
  // have behaved identically on every mechanism the ladder probes, and a guard
  // that cried mismatch on every toolchain refresh would be switched off. What
  // is being asked here is a different question — not "did the two readings
  // agree" but "was the reading taken by the compiler that is compiling now" —
  // and only the driver is in a position to ask it, because only the driver ran
  // the compiler.
  //
  // An observation that names no compiler is not agreement; it is a check that
  // could not be made, and it is recorded as one rather than passed off as a
  // comparison that succeeded.
  if (frontierClang !== null) {
    const observedClang = before.clang;
    const drift = { frontier: frontierClang, observed: observedClang };
    if (observedClang !== null && observedClang !== frontierClang) {
      const detail = `the frontier is a reading of clang ${clip(frontierClang, 60)} and this build was compiled by clang `
        + `${clip(observedClang, 60)}. A frontier binds the flag sequence and the compiler, so a reading taken by another `
        + 'compiler says nothing about what this one does to property-shaped code, however cleanly the two frontiers compare';
      // `detail` is written over the pass's, not added beside it. The record
      // still carries `reason` — the comparator's "all N rungs responded
      // identically" — and without a detail of its own beside it, a record whose
      // result reads `toolchain-drift` would explain itself with the sentence
      // for the outcome it did not have.
      fb = { ...fb, exposureCheck: { ...fb.exposureCheck, detail, result: 'toolchain-drift', toolchain: drift } };
      return unsupported(
        EXPOSURE_REFUSALS['toolchain-drift'],
        detail,
        { observer: { sha256: observerSha, supplied: true }, unit: unitPath },
      );
    }
    fb = {
      ...fb,
      exposureCheck: {
        ...fb.exposureCheck,
        toolchain: { ...drift, compared: observedClang !== null },
      },
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
