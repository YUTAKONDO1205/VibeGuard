/**
 * Pin families: which repair candidate brings which disappearance shape back,
 * per property, and which shapes never come back at all.
 *
 * WipePin was written for one shape -- a zero-fill `llvm.memset` in the target
 * function that dead-store elimination deletes. `../pin-families.json` is the
 * table that generalises that into a per-property catalogue: one row per
 * (property, disappearance shape, repair candidate), each row carrying the
 * status of that candidate against that shape and the evidence for it. The
 * table exists because "the repair works" is not a sentence about a compiler;
 * it is a sentence about a shape, and this lane has measured the repair against
 * exactly two of the shapes the plugin READMEs enumerate.
 *
 * This module is the table's reader, its validator and -- the part that matters
 * -- the recomputation of every claim the table calls MEASURED, from the tracked
 * rows in `../data/`. A number typed into a JSON file and read by nobody is not
 * evidence, so `../test/pin-families.test.mjs` recomputes each one here, from
 * the rows, with nothing but the definition, and fails on drift.
 *
 * Three things are kept apart on purpose, because merging them is how a table
 * like this starts lying (`../../../schema/interfaces.md` section 3):
 *
 *   measured here      a claim the drift test recomputes from ../data/.
 *   one lab run        an intervention or a fixture-loop reading that exists but
 *                      is not tracked. It rides along as `labObservation` /
 *                      `intervention` and is NEVER a `measured-*` status.
 *   not looked at      `unmeasured`, with the reason stated. A shape with zero
 *                      instances in this corpus is unmeasured, not absent from
 *                      the world, and the row says which of the two it is.
 *
 * The pipeline parser at the bottom belongs to `../tools/intervene.mjs`, which
 * drives compilers and therefore cannot be unit-tested. It is pure, so it lives
 * here with the rest of the pure code and is tested with the table.
 *
 * Nothing here compiles, reads a file or has a top-level side effect.
 */

/** The four words a row's `status` may be, and nothing else. */
export const STATUSES = Object.freeze([
  'measured-retained',
  'measured-not-retained',
  'unmeasured',
  'not-repairable-in-compiler',
]);

/**
 * A `not-repairable-in-compiler` row must justify itself one of these three ways,
 * and they are not equally strong. `measured-here` is tracked evidence the drift
 * test recomputes; `one-lab-run` is a single intervention whose gate read
 * NEVER_CAME_BACK and which nobody can recheck from the tree; `by-construction`
 * is an argument about where the repair sits in the pipeline, with the stage
 * named. The word in the row says which one it is.
 */
export const NOT_REPAIRABLE_BASES = Object.freeze(['measured-here', 'one-lab-run', 'by-construction']);

/** How far a routing target's scope was checked against the shape being routed. */
export const APPLIES = Object.freeze(['yes', 'no', 'unverified']);

/** The two channels a replay must be read on. Neither is an observation.schema.json checkpoint. */
export const CHANNELS = Object.freeze(['ir', 'asm']);

/**
 * The claims the table may cite, and what each one MEANS, as code.
 *
 * Every function takes the rows it needs and returns `{num, den}` -- integers,
 * never a float (`interfaces.md` section 5). The table stores the same pair; the
 * test compares. The point of writing the definition here rather than in the test
 * is that the definition is then part of the lane and can be read beside the
 * table; the point of the test recomputing rather than trusting is that a
 * hand-typed number is exactly the defect this file exists to prevent.
 *
 * `rows` is the repair lane's tracked rows for one compiler (../data/), `find`
 * is the find step's rows (../../ai-generated/data/r2-build-rows.json).
 */
export const CLAIMS = Object.freeze({
  /**
   * Cell-level: of the eliminations the find step reported for this compiler,
   * how many does the repair loop score RETAINED. The denominator comes from
   * the find step's rows, not from the repair lane's own summary, so a repair
   * run that silently stopped scoring cells shrinks the numerator and not the
   * denominator.
   */
  'cell-eliminations-reversed': ({ rows, find, cc, opt }) => {
    const found = find.filter((r) => r.kind === 'erasure' && r.cc === cc && r.verdict === 'WIPE_ELIMINATED'
      && (opt === undefined || r.opt === opt));
    const outcome = new Map(rows.filter((r) => r.kind === 'erasure').map((r) => [`${r.id}|${r.opt}`, r.outcome]));
    return { num: found.filter((r) => outcome.get(`${r.id}|${r.opt}`) === 'RETAINED').length, den: found.length };
  },

  /**
   * Per span: a cell the find step scored WIPE_SURVIVED in which one removable
   * span is eliminated on its own. The cell-level oracle cannot see these, and
   * they are the shape the per-span layer was added for.
   */
  'hidden-span-eliminations-retained': ({ rows }) => {
    const hidden = rows.filter((r) => r.kind === 'erasure' && r.hiddenElimination === true);
    return { num: hidden.filter((r) => r.hiddenRetained === true).length, den: hidden.length };
  },

  /**
   * Per span, inside RETAINED cells: every removable span that was compiled on
   * its own with the plugin loaded, and whether it survived. A span whose
   * per-span verdict was not taken (`on` null) is not counted either way.
   */
  'removable-spans-in-retained-cells': ({ rows }) => {
    let num = 0, den = 0;
    for (const r of rows) {
      if (r.kind !== 'erasure' || r.outcome !== 'RETAINED') continue;
      for (const s of r.spans ?? []) {
        if (s.kind !== 'removable' || s.on === null || s.on === undefined) continue;
        den++;
        if (s.on === 'WIPE_SURVIVED') num++;
      }
    }
    return { num, den };
  },

  /**
   * configguard: with the plugin loaded in module scope, does the default build
   * become the all-macros build. This is the direct form of "a defence the
   * preprocessor removed cannot be brought back by a pass", and it is measured
   * rather than argued.
   */
  'configguard-default-equals-enabled': ({ rows, scen }) => {
    const cg = rows.filter((r) => r.kind === 'configguard' && (scen === undefined || r.scen === scen));
    return { num: cg.filter((r) => r.pluginDefaultEqualsEnabled === true).length, den: cg.length };
  },

  /** configguard: and did loading it leave the default target body alone (the observable half). */
  'configguard-default-body-unchanged': ({ rows, scen }) => {
    const cg = rows.filter((r) => r.kind === 'configguard' && (scen === undefined || r.scen === scen));
    return { num: cg.filter((r) => r.pluginLeftDefaultBodyUnchanged === true).length, den: cg.length };
  },

  /**
   * authz: how often -DNDEBUG changed the target body at all. A denominator of
   * compiling configurations and a numerator of 0 is NO_LOSS_OBSERVED -- which
   * is not the same claim as "out of reach", and the table says which it is.
   */
  'authz-ndebug-changed-body': ({ find }) => {
    const az = find.filter((r) => r.kind === 'authz');
    const changed = az.filter((r) => r.verdict === 'CHANGED_BY_NDEBUG').length;
    const noEffect = az.filter((r) => r.verdict === 'NDEBUG_NO_EFFECT').length;
    return { num: changed, den: changed + noEffect };
  },

  /**
   * A shape the plugin counts but does not pin, summed over every record the
   * strict reader accepted in this lane's tracked run. `num` 0 with a positive
   * `den` is "this corpus contains no instance of the shape", which is a reason
   * for `unmeasured` and never a reason for `measured-*`.
   */
  'unhandled-shape-occurrences': ({ rows, counter }) => {
    let num = 0, den = 0;
    for (const r of rows) {
      if (r.kind !== 'erasure') continue;
      for (const key of ['recordW', 'recordWo']) {
        const rec = r[key];
        if (!rec || rec.ok !== true) continue;
        den++;
        num += rec.unhandled?.[counter] ?? 0;
      }
    }
    return { num, den };
  },

  /**
   * The positive control, in the compiles the repair was loaded into. A
   * measurement whose control went missing is a broken instrument, not a
   * finding, so this is quoted beside the family's measured rows.
   */
  'positive-control-present-plugin-on': ({ rows }) => {
    const er = rows.filter((r) => r.kind === 'erasure');
    return { num: er.filter((r) => r.controlOnW === true).length, den: er.length };
  },

  /**
   * How many wipes in the corpus are written as a plain `bzero(` call, out of
   * how many files. This one reads source text rather than rows, because the
   * shape it is about is a spelling: `compiler/gcc-repair/README.md` states that
   * the r2 corpus contains none, and the row that leaves that shape UNMEASURED
   * rests on that statement. `sources` is [{id, src}].
   *
   * `explicit_bzero(` and a helper called `secure_bzero(` are not it -- the
   * lookbehind is what keeps them out, and it is the same distinction the gcc
   * plugin's README draws.
   */
  'plain-bzero-calls-in-corpus': ({ sources }) => {
    let num = 0;
    for (const f of sources ?? []) num += (String(f.src).match(/(?<![\w])bzero\s*\(/g) ?? []).length;
    return { num, den: (sources ?? []).length };
  },
});

/** Claim ids, for the validator and for the test. */
export const CLAIM_IDS = Object.freeze(Object.keys(CLAIMS));

/**
 * Recompute one row's cited claim.
 * @param {{claim: string, cc?: string, counter?: string}} cite
 * @param {{rowsByCc: Record<string, object[]>, find: object[]}} data
 */
export function recompute(cite, data) {
  const fn = CLAIMS[cite.claim];
  if (!fn) throw new Error(`no such claim: ${cite.claim}`);
  const rows = cite.cc ? data.rowsByCc[cite.cc] : undefined;
  if (cite.cc && !rows) throw new Error(`claim ${cite.claim} cites ${cite.cc}, which has no tracked rows here`);
  return fn({
    rows: rows ?? [], find: data.find ?? [], sources: data.sources ?? [],
    cc: cite.cc, opt: cite.opt, scen: cite.scen, counter: cite.counter,
  });
}

/**
 * THE GATE. "Never comes back" is a strong sentence and this is the only place
 * allowed to say it.
 *
 * Two things make the difference between a finding and a guess here, and both
 * were learned the expensive way in this repository:
 *
 *  1. ONE intervention position proves nothing. Deleting the attributed pass can
 *     simply hand the same elimination to the next pass that is entitled to make
 *     it, and the result then reads exactly like "the shape is unrepairable".
 *     At least two positions must have been tried.
 *  2. THE IR CHANNEL ALONE MISREADS IT. `../../calibration/README.md` records a
 *     wipe that survives the whole IR optimiser at -O1 and is dropped after it,
 *     so an IR-only reading calls a shape repairable that the artefact says is
 *     still gone. The asm channel must have been read.
 *
 * @param {{positionsTried: number, asmChannelRead: boolean, irChannelRead: boolean,
 *          cameBackAt: number[], replayReproducedLoss: boolean, controlHeld: boolean}} ev
 * @returns {{verdict: string, why: string}}  one of CAME_BACK, NEVER_CAME_BACK,
 *   NOT_ENOUGH_EVIDENCE, BROKEN_MEASUREMENT
 */
export function interventionVerdict(ev) {
  const {
    positionsTried = 0, asmChannelRead = false, irChannelRead = false,
    cameBackAt = [], replayReproducedLoss = false, controlHeld = false,
  } = ev ?? {};
  if (!controlHeld) {
    return {
      verdict: 'BROKEN_MEASUREMENT',
      why: 'the positive control was not PRESENT in every replay; nothing here is a reading',
    };
  }
  if (!replayReproducedLoss) {
    return {
      verdict: 'BROKEN_MEASUREMENT',
      why: 'the unmodified replay did not reproduce the loss, so the interventions were not made against the pipeline the loss came from',
    };
  }
  if (cameBackAt.length > 0) {
    return { verdict: 'CAME_BACK', why: `the property came back at intervention position(s) ${cameBackAt.join(', ')}` };
  }
  if (positionsTried === 0) {
    return {
      verdict: 'NOT_ENOUGH_EVIDENCE',
      why: 'no intervention position was tried, so nothing here says anything about whether the property would come back',
    };
  }
  if (!asmChannelRead) {
    return {
      verdict: 'NOT_ENOUGH_EVIDENCE',
      why: 'the asm channel was not read; an IR-only reading cannot tell a repaired shape from one the backend drops afterwards',
    };
  }
  if (!irChannelRead) {
    return {
      verdict: 'NOT_ENOUGH_EVIDENCE',
      why: 'the IR channel was not read, so the loss is attributed to no stage',
    };
  }
  if (positionsTried < 2) {
    return {
      verdict: 'NOT_ENOUGH_EVIDENCE',
      why: `${positionsTried} intervention position(s) tried; at least 2 are required before "never comes back" may be written`,
    };
  }
  return {
    verdict: 'NEVER_CAME_BACK',
    why: `${positionsTried} positions tried, both channels read, the property came back at none of them`,
  };
}

/**
 * Validate the table's shape. Returns a list of problems, empty when it is well
 * formed. Everything here is about the table's own integrity; whether its
 * numbers are true is the drift test's question.
 */
/**
 * The row checks, one question each.
 *
 * These were one 108-line `validateTable` until 2026-09-12, when the shipped
 * analyser reported VG-SMELL-003 on it. `.vibeguardrc.json` says of that rule,
 * for this very directory: "it fired on three long dispatchers here and all
 * three were split rather than silenced, so the rule is live over this directory
 * and the next one that grows will report." This is the next one. It is split
 * rather than suppressed, and the split is along the questions the validator was
 * already asking in sequence, so no check changed and no message moved.
 *
 * Each returns the problems it found. None of them decides anything about the
 * table as a whole -- that stays in validateTable, which is now short enough to
 * read as the list of questions it is.
 */
function checkRowFields(r, at, ctx) {
  const problems = [];
  const p = (m) => problems.push(m);
  for (const k of ['property', 'shape', 'candidate', 'status', 'shapeSeenAs', 'note']) {
    if (typeof r[k] !== 'string' || r[k] === '') p(`${at}: ${k} is missing or not a non-empty string`);
  }
  const key = `${r.property}|${r.shape}|${r.candidate}`;
  if (ctx.seen.has(key)) p(`${at}: duplicate (property, shape, candidate)`);
  ctx.seen.add(key);
  if (!STATUSES.includes(r.status)) p(`${at}: status ${JSON.stringify(r.status)} is not one of ${STATUSES.join(' | ')}`);
  if (r.candidate !== 'none' && !ctx.candidates[r.candidate]) p(`${at}: candidate is not in candidates{}`);
  return problems;
}

/** What a `measured-*` status has to be able to show, and what evidence must look like. */
function checkRowEvidence(r, at) {
  const problems = [];
  const p = (m) => problems.push(m);
  const measured = r.status === 'measured-retained' || r.status === 'measured-not-retained';
  if (measured) {
    if (!r.evidence || r.evidence.tracked !== true) p(`${at}: a measured-* status needs evidence.tracked === true`);
    if (!r.evidence?.cite) p(`${at}: a measured-* status needs evidence.cite`);
  }
  if (r.evidence) {
    const e = r.evidence;
    if (typeof e.tracked !== 'boolean') p(`${at}: evidence.tracked must be a boolean`);
    if (e.tracked === true) {
      if (!e.cite || !CLAIM_IDS.includes(e.cite.claim)) {
        p(`${at}: evidence.cite.claim is not one of ${CLAIM_IDS.join(', ')}`);
      }
      if (!e.value || !Number.isInteger(e.value.num) || !Number.isInteger(e.value.den)) {
        p(`${at}: evidence.value must be {num, den} integers -- a ratio is never a float here`);
      }
      if (typeof e.means !== 'string' || e.means === '') {
        p(`${at}: evidence.means must say what the ratio counts; a bare ratio invites being read as the repair's score when it is not`);
      }
      if (typeof e.source !== 'string' || e.source === '') {
        p(`${at}: evidence.source must name the tracked file the claim is recomputed from`);
      }
    }
  }
  // A lab run may ride along, but it may never carry the measured word.
  if (r.labObservation && measured) p(`${at}: a labObservation is one untracked run and cannot support a measured-* status`);
  return problems;
}

/** What each basis for "not repairable in the compiler" has to bring with it. */
function checkRowNotRepairable(r, at) {
  if (r.status !== 'not-repairable-in-compiler') return [];
  const problems = [];
  const p = (m) => problems.push(m);
  if (!NOT_REPAIRABLE_BASES.includes(r.basis)) {
    p(`${at}: not-repairable-in-compiler needs basis one of ${NOT_REPAIRABLE_BASES.join(' | ')}`);
  }
  if (r.basis === 'measured-here' && r.evidence?.tracked !== true) p(`${at}: basis measured-here needs tracked evidence`);
  if (r.basis === 'one-lab-run' && r.intervention?.verdict !== 'NEVER_CAME_BACK') {
    p(`${at}: basis one-lab-run needs an intervention block the gate reads NEVER_CAME_BACK`);
  }
  if (r.basis === 'by-construction' && (typeof r.stage !== 'string' || r.stage === '')) {
    p(`${at}: basis by-construction must name the stage at which the shape is already gone`);
  }
  return problems;
}

/** Where a shape routes when the compiler cannot hold it, and what the routing must prove. */
function checkRowRouting(r, at) {
  if (!r.routesTo) return [];
  const problems = [];
  const p = (m) => problems.push(m);
  const t = r.routesTo;
  const named = typeof t.rule === 'string' && /^VG-[A-Z]+-\d{3}$/.test(t.rule);
  if (!named && t.rule !== 'none') p(`${at}: routesTo.rule is neither a rule id nor "none"`);
  if (t.rule === 'none' && (typeof t.whyNone !== 'string' || t.whyNone === '')) {
    p(`${at}: routesTo.rule "none" must say why there is no source-side rule for this shape`);
  }
  if (!named) return problems;
  if (!APPLIES.includes(t.appliesToThisShape)) {
    p(`${at}: routesTo.appliesToThisShape must be one of ${APPLIES.join(' | ')} -- routing a shape to a rule whose scope does not cover it is the quiet overclaim this table exists to prevent`);
  }
  if (typeof t.appliesWhy !== 'string' || t.appliesWhy === '') p(`${at}: routesTo.appliesWhy must say how the scope was checked`);
  if (t.recallVerified !== true && t.recallVerified !== false) p(`${at}: routesTo.recallVerified must be a boolean`);
  if (t.recallVerified === true) {
    if (!t.recall || !Number.isInteger(t.recall.num) || !Number.isInteger(t.recall.den)) {
      p(`${at}: a verified recall must be {num, den} integers`);
    }
    if (typeof t.recallQuote !== 'string' || t.recallQuote === '') p(`${at}: a verified recall must quote the sentence it comes from`);
    if (typeof t.recallSource !== 'string' || t.recallSource === '') p(`${at}: a verified recall must name the file the sentence is in`);
    if (typeof t.recallScope !== 'string' || t.recallScope === '') p(`${at}: a verified recall must state its scope (in-sample or not)`);
  } else if (typeof t.recallUnverifiedWhy !== 'string' || t.recallUnverifiedWhy === '') {
    p(`${at}: an unverified recall must say why it could not be verified`);
  }
  return problems;
}

/** The recorded intervention verdict, re-derived rather than believed. */
function checkRowIntervention(r, at) {
  if (!r.intervention) return [];
  const problems = [];
  const v = interventionVerdict(r.intervention);
  if (v.verdict !== r.intervention.verdict) {
    problems.push(`${at}: intervention.verdict is ${r.intervention.verdict}, the gate says ${v.verdict} (${v.why})`);
  }
  if (r.status === 'not-repairable-in-compiler' && r.intervention.verdict !== 'NEVER_CAME_BACK') {
    problems.push(`${at}: an intervention block on a not-repairable row must read NEVER_CAME_BACK or not be there`);
  }
  return problems;
}

/**
 * The clonal-selection rule, and the only cross-row one: a shape that no
 * candidate is measured to retain has to say where it goes instead. A shape
 * that HAS a retaining candidate does not, because it is not routed anywhere
 * -- and requiring a routing there would put a rule id beside every repaired
 * shape, which reads as "and the rule catches it too" when nobody checked.
 */
function checkShapeRouting(rows) {
  const problems = [];
  for (const [key, group] of Object.entries(byShape(rows))) {
    if (group.some((r) => r.status === 'measured-retained')) continue;
    if (!group.some((r) => r.routesTo)) {
      problems.push(`${key}: no candidate is measured to retain this shape and no row says where it routes instead`);
    }
  }
  return problems;
}

/**
 * Validate the table's shape. Returns a list of problems, empty when it is well
 * formed. Everything here is about the table's own integrity; whether its
 * numbers are true is the drift test's question.
 */
export function validateTable(table) {
  const problems = [];
  if (!table || typeof table !== 'object') return ['the table is not an object'];
  if (table.schemaVersion !== 'pin-families-v1') {
    problems.push(`schemaVersion is ${JSON.stringify(table.schemaVersion)}, not "pin-families-v1"`);
  }
  if (!Array.isArray(table.rows) || table.rows.length === 0) return [...problems, 'rows is not a non-empty array'];

  const ctx = { candidates: table.candidates ?? {}, seen: new Set() };
  table.rows.forEach((r, i) => {
    const at = `rows[${i}] (${r.property ?? '?'} / ${r.shape ?? '?'} / ${r.candidate ?? '?'})`;
    problems.push(
      ...checkRowFields(r, at, ctx),
      ...checkRowEvidence(r, at),
      ...checkRowNotRepairable(r, at),
      ...checkRowRouting(r, at),
      ...checkRowIntervention(r, at),
    );
  });
  problems.push(...checkShapeRouting(table.rows));
  return problems;
}

/** Rows grouped by (property, shape). */
export function byShape(rows) {
  const out = {};
  for (const r of rows) (out[`${r.property} / ${r.shape}`] ??= []).push(r);
  return out;
}

/**
 * What the table says about each shape once its candidates are read together --
 * the selection step: keep the candidates that bind, route the rest.
 *
 *   repairable-in-compiler  at least one candidate is measured to retain it
 *   routed-to-source        none does, and a source-side rule is named
 *   unrouted                none does, and there is no rule to route it to --
 *                           the state worth printing loudest, because it is a
 *                           shape nothing in this project currently catches
 *   open                    none does and the row says nothing about where it goes
 */
export function shapeVerdicts(table) {
  const out = {};
  for (const [key, group] of Object.entries(byShape(table.rows ?? []))) {
    const retained = group.filter((r) => r.status === 'measured-retained');
    const routes = [...new Set(group.filter((r) => r.routesTo).map((r) => r.routesTo.rule))];
    const named = routes.filter((x) => x !== 'none');
    out[key] = {
      verdict: retained.length > 0 ? 'repairable-in-compiler'
        : named.length > 0 ? 'routed-to-source'
          : routes.length > 0 ? 'unrouted' : 'open',
      retainedBy: retained.map((r) => r.candidate),
      routesTo: routes,
      candidates: group.length,
    };
  }
  return out;
}

/**
 * The two claims whose numerator counts OCCURRENCES OF A SHAPE rather than
 * outcomes of a repair. A zero numerator here is the reason a row may be
 * `unmeasured` -- "this corpus holds no instance" -- and it is never a reason
 * for `measured-not-retained`.
 */
export const OCCURRENCE_CLAIMS = Object.freeze(['unhandled-shape-occurrences', 'plain-bzero-calls-in-corpus']);

/** Where a row's numbers come from. `PROVENANCES` is the whole vocabulary. */
export const PROVENANCES = Object.freeze(['recomputed', 'lab-run', 'no-number']);

/**
 * WHO PRODUCED THIS ROW'S NUMBER -- the question the four status words do not
 * answer. `measured-retained` says the property came back; it does not say
 * whether the ratio beside it is recomputed from `../data/` on every test run or
 * was typed in once by a human. A table where the reader cannot tell those apart
 * is the defect this repository exists to prevent, so the distinction is a
 * function rather than a sentence in the prose.
 *
 *   'recomputed'  tracked evidence with a cite: ../test/pin-families.test.mjs
 *                 recomputes the ratio from ../data/ (or from the corpus text)
 *                 and fails on drift.
 *   'lab-run'     the row's only reading is an `intervention` or a
 *                 `labObservation`: a real run, typed in by hand, that nothing
 *                 recomputes. The gate is re-run over it and its quote is checked
 *                 against the file it names, but the numbers in its prose are not
 *                 evidence in this lane's sense.
 *   'no-number'   no reading at all -- `[SPEC]`, or an argument about where in
 *                 the pipeline the repair sits (`by-construction`).
 *
 * A 'recomputed' row may still carry a hand-typed `labObservation` beside its
 * recomputed count; `alsoLabQuote` in the census counts those separately,
 * because the sentence a reader takes away from such a row can be the typed half.
 */
export function rowProvenance(row) {
  if (row?.evidence?.tracked === true && row.evidence.cite) return 'recomputed';
  if (row?.intervention || row?.labObservation) return 'lab-run';
  return 'no-number';
}

/**
 * The table's structural counts, COMPUTED FROM THE TABLE.
 *
 * Every ratio in `../PIN-FAMILIES.md` was already recomputed by the drift test,
 * but the document's counts of its own rows were not -- how many rows there are,
 * how many route to a rule whose scope does not cover the shape, how many of the
 * wipe rows are `unmeasured`. Those were the only numbers in the deliverable no
 * test could fail on, and an adversarial read found two of them wrong (the prose
 * said three rows carried `appliesToThisShape: "no"` where four do, and eight
 * `survive.secure-wipe` rows `unmeasured` where nine are). They are computed
 * here now, and the drift test reads them back out of the prose.
 */
export function tableCensus(table) {
  const rows = table?.rows ?? [];
  const label = (r) => `${r.shape} / ${r.candidate}`;
  const provenance = Object.fromEntries(PROVENANCES.map((k) => [k, 0]));
  const statuses = {};
  for (const r of rows) {
    provenance[rowProvenance(r)]++;
    statuses[r.status] = (statuses[r.status] ?? 0) + 1;
  }
  const notApplicable = rows.filter((r) => r.routesTo?.appliesToThisShape === 'no');
  const wipe = rows.filter((r) => r.property === 'survive.secure-wipe');
  const wipeUnmeasured = wipe.filter((r) => r.status === 'unmeasured');
  const zeroInstance = wipeUnmeasured.filter((r) => OCCURRENCE_CLAIMS.includes(r.evidence?.cite?.claim)
    && r.evidence?.value?.num === 0 && r.evidence?.value?.den > 0);
  return {
    rows: rows.length,
    properties: new Set(rows.map((r) => r.property)).size,
    shapeGroups: Object.keys(byShape(rows)).length,
    statuses,
    provenance,
    labRun: rows.filter((r) => rowProvenance(r) === 'lab-run').map(label),
    noNumber: rows.filter((r) => rowProvenance(r) === 'no-number').map(label),
    alsoLabQuote: rows.filter((r) => rowProvenance(r) === 'recomputed' && (r.labObservation || r.intervention)).length,
    routedNotApplicable: notApplicable.length,
    routedNotApplicableShapes: [...new Set(notApplicable.map((r) => r.shape))],
    wipeRows: wipe.length,
    wipeUnmeasured: wipeUnmeasured.length,
    wipeUnmeasuredZeroInstance: zeroInstance.length,
  };
}

// ---------------------------------------------------------------------------
// clang's printed pipeline string: parse, render, and take passes out of it.
//
// `-print-pipeline-passes` prints a nested, comma-separated string:
//
//   annotation2metadata,forceattrs,function<eager-inv>(lower-expect,sroa<modify-cfg>),
//   cgscc(devirt<4>(inline<only-mandatory>,instcombine<max-iterations=1>))
//
// An item is `name`, optionally `<params>` (balanced, and its commas are not
// separators), optionally `(sub-pipeline)`. Only the leaves are passes; the
// adaptors that hold them are structure. Deleting pass number k means deleting
// exactly the k-th LEAF in print order -- not every pass with that name, of
// which `instcombine` alone has a dozen.

/** Split one level of the string on commas that are not inside `<>` or `()`. */
function splitTop(s) {
  const out = [];
  let depth = 0, start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '<' || c === '(') depth++;
    else if (c === '>' || c === ')') depth--;
    else if (c === ',' && depth === 0) { out.push(s.slice(start, i)); start = i + 1; }
  }
  out.push(s.slice(start));
  return out.filter((x) => x !== '');
}

/**
 * Parse a pipeline string into a list of nodes.
 * A node is `{name, params, children}`; `children` is null for a leaf.
 */
export function parsePipeline(s) {
  return splitTop(String(s).trim()).map((item) => {
    const t = item.trim();
    // The optional `(...)` is the LAST balanced parenthesis group and it closes
    // at the end of the item; anything else belongs to the name or the params.
    let params = '', children = null, name = t;
    if (t.endsWith(')')) {
      let depth = 0, open = -1;
      for (let i = t.length - 1; i >= 0; i--) {
        if (t[i] === ')') depth++;
        else if (t[i] === '(') { depth--; if (depth === 0) { open = i; break; } }
      }
      if (open > 0) { children = parsePipeline(t.slice(open + 1, -1)); name = t.slice(0, open); }
    }
    const lt = name.indexOf('<');
    if (lt >= 0 && name.endsWith('>')) { params = name.slice(lt); name = name.slice(0, lt); }
    return { name, params, children };
  });
}

/** Render a parsed pipeline back to a string. `render(parse(s)) === s` for what clang prints. */
export function renderPipeline(nodes) {
  return nodes.map((n) => n.name + n.params + (n.children ? `(${renderPipeline(n.children)})` : '')).join(',');
}

/** Every leaf, in print order, with the adaptors that enclose it. */
export function leaves(nodes, path = []) {
  const out = [];
  for (const n of nodes) {
    if (n.children) out.push(...leaves(n.children, [...path, n.name + n.params]));
    else out.push({ index: -1, name: n.name, params: n.params, path });
  }
  return out.map((l, i) => ({ ...l, index: i }));
}

/**
 * Keep the leaves `keep(index)` accepts, in print order, and drop every adaptor
 * left holding nothing -- `function()` is not a pipeline opt will accept.
 */
export function filterLeaves(nodes, keep, counter = { i: 0 }) {
  const out = [];
  for (const n of nodes) {
    if (n.children) {
      const kids = filterLeaves(n.children, keep, counter);
      if (kids.length > 0) out.push({ ...n, children: kids });
    } else {
      const i = counter.i++;
      if (keep(i)) out.push({ ...n });
    }
  }
  return out;
}

/** The pipeline with leaf `k` removed. */
export const withoutLeaf = (nodes, k) => filterLeaves(nodes, (i) => i !== k);

/** The pipeline truncated to its first `k` leaves. */
export const prefixLeaves = (nodes, k) => filterLeaves(nodes, (i) => i < k);
