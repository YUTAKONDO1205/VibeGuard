#!/usr/bin/env node
// derive-fallback-table — turn a measured security-configuration envelope into a
// lookup table that answers one question and refuses to answer any other:
//
//   "Property P was LOST at configuration C. Is there a weaker configuration C'
//    where P was actually measured to survive?"
//
//   node tools/derive-fallback-table.mjs --envelope <path> --out <path>
//
// WHAT THIS IS NOT
//
// It is not a model of the optimiser. Nothing here predicts. Every answer is a
// citation of a cell that was compiled, linked and observed, or it is one of the
// two words that say we have no such citation. The three-word resolution
// vocabulary is load-bearing and must not be collapsed:
//
//   fallback        a C' exists whose cells are all PRESENT under a held control
//   no-safe-target  every candidate C' was measured, and every one of them LOST
//   not-observed    some candidate is missing, broken or unsupported, and no
//                   candidate held. We do not know. Saying "no-safe-target" here
//                   would upgrade an absence of measurement into a measurement.
//
// THREE THINGS THAT LOOK LIKE DETAILS AND ARE NOT
//
// 1. The envelope's identity is (subject, config), never (propertyId, config).
//    One property can be carried by more than one program — `authz.failclosed`
//    is carried by both `authz-folded` and `authz-live`. Keying by propertyId
//    silently merges two different programs, and then a fallback is chosen
//    because *the other* program survived there.
//
// 2. Even (subject, config) collides, because the envelope carries positive
//    controls for the observer's two silent-failure modes (plugin absent,
//    observer unregistered) at the same coordinates as a real measurement. They
//    are statements about the instrument, not about the property. Cells whose
//    cellId contains `ctl=` are removed from the search population, counted in
//    `counts.controlCells`, and listed one by one in `anomalies` — excluded, but
//    never silently.
//
// 3. Aggregation across subjects is conservative on purpose. At run time the
//    driver knows a property, not a subject: the user's program is not in the
//    envelope. So a row is looked up by (propertyId, config) but is only allowed
//    to say `fallback` when EVERY subject carrying that property held at C'.
//    "One of them held" is exactly the mistake in (1) wearing a different hat.
//    A property whose second subject was only ever measured on one target will
//    therefore report `not-observed` on the other targets. That is the correct
//    answer, not a gap to be papered over.
//
// EXIT CODES
//   0  a table was written
//   1  the command line is wrong
//   2  an invariant failed: a LOST cell exists that no row accounts for. No
//      table is written, because a table that quietly drops a loss is worse
//      than none
//   3  nothing to reason from: the envelope could not be read, or not one cell
//      in it carries `measurement === "OK"`
//
// There is no path that finishes quietly with rc=0 and no summary. The last
// thing written to stderr on success is always the counting line.

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const EXIT_OK = 0;
export const EXIT_USAGE = 1;
export const EXIT_INVARIANT = 2;
export const EXIT_INCOMPLETE = 3;

export const TABLE_SCHEMA_VERSION = 'vibeguard.fallback-table/1';
export const GENERATOR_VERSION = '1';

/** Weakest first. "Weakening" the opt axis means moving towards index 0. */
export const OPT_ORDER = Object.freeze(['-O0', '-O1', '-O2', '-O3']);

/** Emitted in this order everywhere, so two runs produce identical bytes. */
const CONFIG_KEYS = Object.freeze(['cc', 'freestanding', 'lto', 'ndebug', 'opt', 'target']);

/**
 * Axes a candidate may vary. Anything else would be a different program.
 *
 * `lto` is NOT one of them, and the reason is in the sweep rather than in the
 * driver. `compiler/llvm-pass/scripts/observe-config.sh` maps `full-prelink`
 * and `full-backend` onto the *same* compiler invocation — both add `-flto` —
 * and separates them by `STAGE`, i.e. by where the observer looks. The same
 * holds for the two `thin-*` values. So the envelope's `lto` label is a build
 * flag fused with an observation stage, not a build axis on its own, and
 * "weakening" it would compare a build against a measurement position. On top
 * of that, link-time optimisation is a whole-programme link decision while
 * this fallback recompiles one translation unit, so a row telling the driver
 * to drop LTO would not be a thing the driver could do.
 */
const VARIABLE_AXES = Object.freeze(['opt']);
const FIXED_AXES = Object.freeze(['cc', 'target', 'ndebug', 'freestanding', 'lto']);

/**
 * The profiles compiler/schema/policy.schema.json's `fallback.profile` enum can
 * express today. A row may legitimately point at a configuration outside this
 * set; when it does we say so in `anomalies` rather than hiding the row, because
 * the measurement is real even when the driver cannot yet act on it.
 */
const DRIVER_EXPRESSIBLE_PROFILES = Object.freeze(['-O0', '-O1']);

// ── shapes ──────────────────────────────────────────────────────────────────

/** A config object with exactly CONFIG_KEYS, in CONFIG_KEYS order. */
export function canonConfig(config) {
  const out = {};
  for (const k of CONFIG_KEYS) out[k] = config?.[k] ?? null;
  return out;
}

/** Stable identity string for a config. Used for keys and for sorting. */
export function configKey(config) {
  return JSON.stringify(canonConfig(config));
}

/** A cell is a positive control iff its id carries the `ctl=` discriminator. */
export function isControlCell(cell) {
  return String(cell?.cellId ?? '').includes('ctl=');
}

function subjectKey(subject, config) {
  return `${subject}\u0000${configKey(config)}`;
}

/** Count cells by one field, key order sorted so two runs agree byte for byte. */
function tallyBy(cells, field) {
  const seen = new Map();
  for (const c of cells) {
    const k = String(c?.[field] ?? 'null');
    seen.set(k, (seen.get(k) ?? 0) + 1);
  }
  const out = {};
  for (const k of [...seen.keys()].sort()) out[k] = seen.get(k);
  return out;
}

// ── candidate generation ────────────────────────────────────────────────────

/**
 * Every configuration reachable from `from` by weakening only, strongest first.
 *
 * Preference order, in the order it is applied:
 *   1. highest-opt-first — give up as little optimisation as possible
 *   2. lexicographic-config — a tie-break that never fires with one axis, kept
 *      so the order is total rather than accidentally total
 *
 * `from` itself is never a candidate. An `opt` this ladder does not know
 * (`-Os`, `-Oz`, `-Og`) yields no candidates and is reported separately by the
 * caller: not knowing what is weaker than `-Os` is a gap in the ladder, not a
 * finding that nothing weaker holds.
 */
export function candidatesFor(from) {
  const base = canonConfig(from);
  const fromOpt = OPT_ORDER.indexOf(base.opt);
  if (fromOpt < 0) return [];

  const out = [];
  for (let i = fromOpt - 1; i >= 0; i -= 1) {
    out.push(canonConfig({ ...base, opt: OPT_ORDER[i] }));
  }
  // (2) only orders what (1) left tied; with one axis it is a no-op, and it is
  // here so that adding a second variable axis cannot make the output flap.
  return out;
}

/** Is this `opt` a rung of the ladder at all? */
export function knownOptLevel(opt) {
  return OPT_ORDER.includes(opt);
}

// ── verdict on a single (subject, candidate) cell ───────────────────────────

/**
 * Does this cell count as evidence that the property survives here?
 * Returns `{ held: true }` or `{ held: false, why, note? }`.
 *
 * The `why` vocabulary keeps four distinguishable failures distinguishable:
 * the property was measured to be lost; the property was measured to be absent
 * (a different fact — it was never there to lose); the instrument failed; the
 * cell was never run at all.
 */
export function verdictFor(cell) {
  if (!cell) return { held: false, why: 'absent-from-envelope' };

  const m = cell.measurement;
  if (m === 'BROKEN_MEASUREMENT') return { held: false, why: 'broken-measurement' };
  if (m === 'UNSUPPORTED') return { held: false, why: 'unsupported' };
  if (m !== 'OK') {
    return {
      held: false,
      why: 'broken-measurement',
      note: `unknown measurement word ${JSON.stringify(m)} treated as a broken instrument`,
    };
  }

  switch (cell.state) {
    case 'PRESENT':
      if (cell.controlHeld === true) return { held: true };
      // A PRESENT with no held control is an observation we cannot underwrite:
      // the same rc=0 is produced by an observer that ran and by one that never
      // registered. It is not evidence, and it is not a loss either.
      return {
        held: false,
        why: 'not-observed',
        note: `PRESENT with controlHeld=${JSON.stringify(cell.controlHeld)} is not underwritten by a control`,
      };
    case 'LOST':
      return { held: false, why: 'measured-lost' };
    case 'ABSENT':
      return { held: false, why: 'measured-absent' };
    case 'NOT_OBSERVED':
      return { held: false, why: 'not-observed' };
    default:
      return {
        held: false,
        why: 'not-observed',
        note: `unknown state word ${JSON.stringify(cell.state)} treated as not observed`,
      };
  }
}

// ── the derivation ──────────────────────────────────────────────────────────

/**
 * @returns {{ table: object, exitCode: number, summary: string, problems: string[] }}
 * `table` is null when exitCode is not 0.
 */
export function deriveTable(envelope, { sourcePath, sourceSha256 }) {
  const cells = Array.isArray(envelope?.cells) ? envelope.cells : [];
  const anomalies = [];
  const problems = [];

  // ── 1. split off the positive controls, loudly ────────────────────────────
  const controls = cells.filter(isControlCell);
  const population = cells.filter((c) => !isControlCell(c));

  for (const c of [...controls].sort((a, b) => String(a.cellId).localeCompare(String(b.cellId)))) {
    anomalies.push(
      `control-excluded: ${c.cellId} state=${c.state} measurement=${c.measurement} `
      + '(positive control for an observer silent-failure mode; not a measurement of the property)',
    );
    // A positive control is supposed to fail to observe. One that reports a
    // healthy PRESENT means the control did not control anything.
    if (c.measurement === 'OK' && c.state === 'PRESENT') {
      anomalies.push(`control-did-not-fail: ${c.cellId} reports PRESENT/OK — the silent-failure control did not trip`);
    }
  }

  // ── 2. refuse to reason from an envelope with no usable cell ──────────────
  const okCells = population.filter((c) => c.measurement === 'OK');
  if (okCells.length === 0) {
    return {
      table: null,
      exitCode: EXIT_INCOMPLETE,
      summary: `no usable cells: cells=${cells.length} control=${controls.length} measurementOK=0`,
      problems: ['not one cell carries measurement="OK"; there is nothing to derive a fallback from'],
    };
  }

  // ── 3. index by (subject, config) — never by (propertyId, config) ─────────
  const bySubjectConfig = new Map();
  for (const c of population) {
    const k = subjectKey(c.subject, c.config);
    if (!bySubjectConfig.has(k)) bySubjectConfig.set(k, []);
    bySubjectConfig.get(k).push(c);
  }
  const duplicated = [...bySubjectConfig.entries()].filter(([, v]) => v.length > 1);
  for (const [k, v] of duplicated.sort((a, b) => a[0].localeCompare(b[0]))) {
    anomalies.push(
      `duplicate-cell: subject=${k.split('\u0000')[0]} config=${k.split('\u0000')[1]} `
      + `cellIds=${JSON.stringify(v.map((c) => c.cellId).sort())} — first by cellId used for lookups`,
    );
  }
  const lookup = (subject, config) => {
    const v = bySubjectConfig.get(subjectKey(subject, config));
    if (!v || v.length === 0) return null;
    return [...v].sort((a, b) => String(a.cellId).localeCompare(String(b.cellId)))[0];
  };

  // ── 4. which subjects carry which property ────────────────────────────────
  const subjectsOfProperty = new Map();
  for (const c of population) {
    if (!subjectsOfProperty.has(c.propertyId)) subjectsOfProperty.set(c.propertyId, new Set());
    subjectsOfProperty.get(c.propertyId).add(c.subject);
  }

  // ── 5. non-monotonic survival, recorded rather than smoothed ──────────────
  const ladders = new Map();
  for (const c of population) {
    if (c.measurement !== 'OK') continue;
    const k = [c.subject, c.config?.cc, c.config?.target, c.config?.freestanding, c.config?.ndebug, c.config?.lto].join('|');
    if (!ladders.has(k)) ladders.set(k, []);
    ladders.get(k).push(c);
  }
  for (const k of [...ladders.keys()].sort()) {
    const rung = ladders.get(k).slice().sort((a, b) => OPT_ORDER.indexOf(a.config.opt) - OPT_ORDER.indexOf(b.config.opt));
    for (let i = 0; i < rung.length; i += 1) {
      for (let j = i + 1; j < rung.length; j += 1) {
        if (rung[i].state === 'LOST' && rung[j].state === 'PRESENT') {
          anomalies.push(
            `non-monotonic: ${k} is LOST at ${rung[i].config.opt} (${rung[i].cellId}) `
            + `but PRESENT at ${rung[j].config.opt} (${rung[j].cellId}) — weakening is not a total order here`,
          );
        }
      }
    }
  }

  // ── 6. one row per (propertyId, lost config) ──────────────────────────────
  const lostEverywhere = cells.filter((c) => c.state === 'LOST');

  // A LOST reported by an instrument that also declared itself broken is a
  // statement about the instrument, not about the property. verdictFor()
  // already refuses such a cell when it appears on the candidate side; the row
  // side has to refuse it too, or the table would recommend a recompile on the
  // strength of a measurement it would not accept as evidence.
  const lostButUnmeasured = population.filter((c) => c.state === 'LOST' && c.measurement !== 'OK');
  const lostInPopulation = population.filter((c) => c.state === 'LOST' && c.measurement === 'OK');
  for (const c of [...lostButUnmeasured].sort((a, b) => String(a.cellId).localeCompare(String(b.cellId)))) {
    anomalies.push(
      `lost-under-broken-instrument: ${c.cellId} reports state=LOST with measurement=${c.measurement}, so it is not `
      + 'a measurement of the property and gets no row. The same cell would be refused as evidence on the candidate side',
    );
  }

  const groups = new Map();
  for (const c of lostInPopulation) {
    const k = `${c.propertyId}\u0000${configKey(c.config)}`;
    if (!groups.has(k)) groups.set(k, { propertyId: c.propertyId, from: canonConfig(c.config), cells: [] });
    groups.get(k).cells.push(c);
  }

  const rows = [];
  const coveredLostCellIds = new Set();
  const rowAnomalies = [];

  for (const key of [...groups.keys()].sort()) {
    const g = groups.get(key);
    for (const c of g.cells) coveredLostCellIds.add(c.cellId);

    const lostSubjects = [...new Set(g.cells.map((c) => c.subject))].sort();
    const subjects = [...(subjectsOfProperty.get(g.propertyId) ?? new Set())].sort();
    const candidates = candidatesFor(g.from);

    const rejected = [];
    let accepted = null;
    let evidence = [];

    for (const cand of candidates) {
      const perSubject = subjects.map((s) => ({ subject: s, cell: lookup(s, cand), verdict: verdictFor(lookup(s, cand)) }));
      const failures = perSubject.filter((p) => !p.verdict.held);
      if (failures.length === 0) {
        accepted = cand;
        evidence = perSubject.map((p) => ({
          subject: p.subject,
          cellId: p.cell.cellId,
          state: p.cell.state,
          measurement: p.cell.measurement,
          controlHeld: p.cell.controlHeld,
        }));
        break;
      }
      for (const f of failures) {
        rejected.push({ config: cand, why: f.verdict.why, subject: f.subject });
        if (f.verdict.note) {
          rowAnomalies.push(`cell-note: ${g.propertyId} candidate=${configKey(cand)} subject=${f.subject}: ${f.verdict.note}`);
        }
      }
    }

    let resolution;
    if (accepted) {
      resolution = 'fallback';
    } else if (!knownOptLevel(g.from.opt)) {
      // `-Os` / `-Oz` / `-Og` are real levels this ladder does not rank. There
      // is no candidate because we do not know what is weaker, which is the
      // definition of not-observed. Calling it no-safe-target would turn "we
      // never looked" into "we looked and there is nothing", which is the one
      // substitution the state vocabulary exists to prevent.
      resolution = 'not-observed';
      rowAnomalies.push(
        `opt-off-ladder: ${g.propertyId} at ${configKey(g.from)} sits at opt=${g.from.opt}, which is not a rung of `
        + `${JSON.stringify(OPT_ORDER)}. No candidate could be formed, so this row is "not-observed" (extend the `
        + 'ladder and re-run) rather than "no-safe-target"',
      );
    } else if (candidates.length === 0) {
      resolution = 'no-safe-target';
      rowAnomalies.push(
        `already-weakest: ${g.propertyId} at ${configKey(g.from)} is already at ${OPT_ORDER[0]}, the weakest rung of `
        + `the ${VARIABLE_AXES.join('/')} axis, so there is nothing weaker to try. Unlike opt-off-ladder, measuring `
        + 'more cannot produce a level here',
      );
    } else if (rejected.every((r) => r.why === 'measured-lost')) {
      resolution = 'no-safe-target';
    } else {
      resolution = 'not-observed';
    }

    if (rejected.some((r) => r.why === 'measured-absent')) {
      rowAnomalies.push(
        `measured-absent-candidate: ${g.propertyId} at ${configKey(g.from)} has a candidate where the property `
        + 'is ABSENT, not LOST. ABSENT is an observation, so this row is not "no-safe-target"; it is "not-observed" '
        + 'because no candidate produced a held PRESENT',
      );
    }

    if (accepted) {
      // Every fixed axis is fixed by construction, so a difference here would
      // mean candidatesFor() had drifted from VARIABLE_AXES. The driver cannot
      // read most of these axes, so it could not catch such a row itself.
      for (const axis of FIXED_AXES) {
        if (accepted[axis] !== g.from[axis]) {
          rowAnomalies.push(
            `fixed-axis-moved: ${g.propertyId} at ${configKey(g.from)} resolved to a target differing on ${axis} `
            + `(${g.from[axis]} -> ${accepted[axis]}), which VARIABLE_AXES does not permit`,
          );
        }
      }
      if (!DRIVER_EXPRESSIBLE_PROFILES.includes(accepted.opt)) {
        rowAnomalies.push(
          `profile-outside-driver-enum: ${g.propertyId} at ${configKey(g.from)} resolves to profile ${accepted.opt}, `
          + `which is outside policy.schema.json fallback.profile ${JSON.stringify(DRIVER_EXPRESSIBLE_PROFILES)}`,
        );
      }
    }

    rows.push({
      propertyId: g.propertyId,
      from: g.from,
      lostSubjects,
      resolution,
      to: accepted ? canonConfig(accepted) : null,
      profile: accepted ? accepted.opt : null,
      evidence,
      rejected,
    });
  }

  anomalies.push(...rowAnomalies);

  // ── 7. the invariant: every LOST cell is accounted for ────────────────────
  //
  // "Accounted for" is a row, or an exclusion this run wrote down. A LOST cell
  // under a broken instrument is excluded and named in `anomalies`, which is a
  // data condition rather than a fault in the derivation. A *control* cell that
  // reports LOST stays an alarm however it is measured: a control is not
  // supposed to measure a loss, and letting the instrument column excuse that
  // would hand the alarm an off switch.
  const excusedLostCellIds = new Set(lostButUnmeasured.filter((c) => !isControlCell(c)).map((c) => c.cellId));
  const uncovered = lostEverywhere.filter(
    (c) => !coveredLostCellIds.has(c.cellId) && !excusedLostCellIds.has(c.cellId),
  );
  if (uncovered.length > 0) {
    for (const c of uncovered) {
      problems.push(
        `LOST cell ${c.cellId} (${c.propertyId}/${c.subject}) produced no row`
        + (isControlCell(c) ? ' — it is a positive control, and a control is not supposed to measure a loss' : ''),
      );
    }
    return {
      table: null,
      exitCode: EXIT_INVARIANT,
      summary: `rows=${rows.length} lost=${lostEverywhere.length} control=${controls.length} uncovered=${uncovered.length}`,
      problems,
    };
  }

  const byResolution = { fallback: 0, 'no-safe-target': 0, 'not-observed': 0 };
  for (const r of rows) byResolution[r.resolution] += 1;

  const table = {
    schemaVersion: TABLE_SCHEMA_VERSION,
    source: {
      path: sourcePath,
      sha256: sourceSha256,
      cells: cells.length,
      schemaVersion: envelope?.schemaVersion ?? null,
    },
    generator: { name: 'derive-fallback-table', version: GENERATOR_VERSION },
    policy: {
      variableAxes: [...VARIABLE_AXES],
      fixedAxes: [...FIXED_AXES],
      direction: 'weaken-only',
      preferenceOrder: ['highest-opt-first', 'lexicographic-config'],
      subjectAggregation: 'all-subjects-of-the-property-must-hold',
    },
    counts: {
      cells: cells.length,
      controlCells: controls.length,
      lostCells: lostEverywhere.length,
      lostCellsUnderBrokenInstrument: lostButUnmeasured.length,
      rows: rows.length,
      byResolution,
      // The envelope's own two columns, carried through so the table can be
      // reconciled against it without opening the envelope. `state` is about
      // the property, `measurement` is about the instrument, and they are
      // counted apart for the same reason they are stored apart.
      byState: tallyBy(cells, 'state'),
      byMeasurement: tallyBy(cells, 'measurement'),
    },
    rows,
    anomalies,
  };

  return {
    table,
    exitCode: EXIT_OK,
    summary:
      `rows=${rows.length} lost=${lostEverywhere.length} control=${controls.length} `
      + `byResolution=${JSON.stringify(byResolution)}`,
    problems,
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

export function parseArgs(argv) {
  const out = { envelope: null, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--envelope') out.envelope = argv[++i];
    else if (a === '--out') out.out = argv[++i];
    else throw new Error(`unknown argument ${a}`);
  }
  if (!out.envelope) throw new Error('--envelope <path> is required');
  if (!out.out) throw new Error('--out <path> is required');
  return out;
}

/** Windows backslashes would make the same run on the same tree hash differently. */
function portablePath(p) {
  return String(p).split('\\').join('/');
}

/**
 * How the table should name the envelope it came from.
 *
 * Not the command-line argument. That argument is whatever the caller typed, so
 * the same envelope derived twice by two invocations produces two different
 * tables — and when it is absolute it writes the operator's home directory into
 * an artefact, which is the thing `interfaces.md` §5 refuses. Relative to the
 * table's own directory is both stable and anchored where the reader is: the
 * driver's staleness check already resolves `source.path` against the table's
 * directory first.
 */
function envelopeRefFor(envelopeAbs, outAbs) {
  const rel = relative(dirname(outAbs), envelopeAbs);
  // `relative` can escape upwards, which is fine and stays machine-independent.
  // It can also come back empty (same path), which cannot happen here but would
  // be meaningless if it did.
  return rel === '' ? portablePath(envelopeAbs) : portablePath(rel);
}

export function main(argv, { stdout = process.stdout, stderr = process.stderr } = {}) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    stderr.write(`derive-fallback-table: ${err.message}\n`);
    stderr.write('usage: derive-fallback-table.mjs --envelope <path> --out <path>\n');
    return EXIT_USAGE;
  }

  let raw;
  let envelope;
  try {
    raw = readFileSync(resolve(args.envelope));
    envelope = JSON.parse(raw.toString('utf8'));
  } catch (err) {
    stderr.write(`derive-fallback-table: cannot read envelope ${args.envelope}: ${err.message}\n`);
    return EXIT_INCOMPLETE;
  }

  const { table, exitCode, summary, problems } = deriveTable(envelope, {
    sourcePath: envelopeRefFor(resolve(args.envelope), resolve(args.out)),
    sourceSha256: createHash('sha256').update(raw).digest('hex'),
  });

  for (const p of problems) stderr.write(`derive-fallback-table: ${p}\n`);

  if (exitCode !== EXIT_OK) {
    stderr.write(`derive-fallback-table: no table written (exit ${exitCode})\n`);
    stderr.write(`${summary}\n`);
    return exitCode;
  }

  const outPath = resolve(args.out);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(table, null, 2)}\n`, 'utf8');
  stdout.write(`${portablePath(args.out)}\n`);
  stderr.write(`${summary}\n`);
  return EXIT_OK;
}

const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) process.exit(main(process.argv.slice(2)));
