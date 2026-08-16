#!/usr/bin/env node
/**
 * Optimisation Fragility Score — a summary statistic over a configuration
 * envelope matrix.
 *
 * The number this file produces answers one question: across the configurations
 * that were actually measured, in what fraction did a declared security
 * property fail to hold? 0 means it held everywhere that was measured; 1 means
 * it failed everywhere that was measured.
 *
 * "Fail to hold" is polarity-dependent and is read from the cell rather than
 * assumed — see POLARITY_TABLE. For a must-survive property that is `LOST`; for
 * a must-not-appear one it is `PRESENT`, because there the forbidden thing
 * going away is the property working.
 *
 * Everything difficult about this file is in the word "measured".
 *
 * A cell whose control did not hold is a broken measurement, not a survival
 * (compiler/schema/interfaces.md section 4: "A measurement where the control's
 * count also fell to zero is a broken measurement, not a finding"). A cell whose
 * verdict did not complete, or whose state is NOT_OBSERVED, is an absence of
 * evidence, not evidence of survival (section 3: the last two states "exist
 * because 'we did not see it' and 'it is not there' are different claims and
 * merging them is how a checker starts lying"). Counting any of those on the
 * surviving side lowers the score, which is the direction that reads as safe —
 * so this file removes them from the denominator instead, and reports every
 * removal. An envelope in which most cells were thrown away must not be
 * indistinguishable from one in which most cells survived.
 *
 * Two consequences follow, and they are the reason this is a module rather than
 * three lines at a call site:
 *
 *   * A matrix with no eligible cells has no score. It is refused (exit 3,
 *     interfaces.md section 7), never reported as 0.0. Zero divided by zero
 *     rendered as "nothing was lost" is the exact shape of claim this directory
 *     exists to prevent.
 *   * A score is never emitted without the envelope it was measured over. A
 *     property observed to survive -O0 and -O1 has not been observed to survive
 *     -O3, and "fragility 0.00" quoted without the config list says otherwise.
 *     `toEvidenceJson` and `formatReport` both refuse to render a report whose
 *     `measuredConfigs` is missing or empty.
 *
 * Numbers in the emitted evidence are integers and the score is a `{num, den}`
 * pair, per interfaces.md section 5 rule 4. `scoreAsFloat` exists for callers
 * that want to compare or display one; its result never reaches the record.
 */

/** @typedef {'PRESENT'|'ABSENT'|'LOST'|'REINTRODUCED'|'NOT_APPLICABLE'|'NOT_OBSERVED'} PropertyState */

export const SCHEMA_VERSION = 'envelope-fragility-v0';
export const COMPONENT = 'EnvelopeFragility';

/**
 * The property-state vocabulary, from interfaces.md section 3. Kept identical
 * to what compiler/llvm-pass/scripts/check-matrix.py grades against, so a state
 * spelled a new way in one place fails loudly here rather than being silently
 * bucketed.
 */
export const KNOWN_STATES = Object.freeze([
  'PRESENT',
  'ABSENT',
  'LOST',
  'REINTRODUCED',
  'NOT_APPLICABLE',
  'NOT_OBSERVED',
]);

/**
 * Which way round a property's states read.
 *
 * Not every declared property is one that must survive. properties.json has a
 * `notappear` family, and the observer records the direction in
 * `oracle.findingWhenPresent`: for `notappear.deny-path-call` it is true, and
 * for every `survive` property it is false. That distinction is not cosmetic —
 * for a must-not-appear property `LOST` is the DESIRED outcome, so scoring it
 * on the must-survive table counts a success as a failure.
 *
 * The score therefore measures one thing across both families: the fraction of
 * measured configurations in which the declared property DID NOT HOLD.
 */
export const POLARITIES = Object.freeze(['must-survive', 'must-not-appear']);
export const DEFAULT_POLARITY = 'must-survive';

/**
 * Per polarity: which states put a cell in the denominator, and which of those
 * count as the property failing.
 *
 * REINTRODUCED is a survival for a must-survive property (interfaces.md
 * section 3 defines it as observed PRESENT again, so the effect is there at the
 * last checkpoint) and a violation for a must-not-appear one, for the same
 * reason read the other way. It stays visible in `stateCounts` either way, so a
 * reader can see how much of a score rests on reconstruction.
 *
 * ABSENT differs between the two, which is the whole reason this is a table.
 * For a must-survive property it means the effect was never established, so
 * nothing was there for an optimiser to remove and the cell says nothing about
 * fragility — it is excluded. For a must-not-appear property the forbidden
 * thing being absent is exactly the property holding, so it counts.
 */
const POLARITY_TABLE = Object.freeze({
  'must-survive': {
    eligible: Object.freeze(['PRESENT', 'LOST', 'REINTRODUCED']),
    failing: Object.freeze(['LOST']),
  },
  'must-not-appear': {
    eligible: Object.freeze(['PRESENT', 'LOST', 'REINTRODUCED', 'ABSENT']),
    failing: Object.freeze(['PRESENT', 'REINTRODUCED']),
  },
});

/** The polarity a cell is scored under, defaulting explicitly. */
const polarityOf = (cell) => cell.polarity ?? DEFAULT_POLARITY;

/**
 * State labels a neighbouring component emits that interfaces.md section 3 does
 * not define. Listed only so the refusal can name the conflict; they are NOT
 * accepted. Measured against that component's envelope output: 16 of its 74
 * cells carry one of these, and the same 16 carry `controlHeld: null`.
 */
const UNJOINED_NEIGHBOUR_STATES = Object.freeze(['BROKEN_MEASUREMENT', 'UNSUPPORTED']);

/**
 * Why a cell was removed from the denominator. Every exclusion carries one of
 * these and every one of them is counted in the output.
 */
export const EXCLUSION_REASONS = Object.freeze({
  CONTROL_DID_NOT_HOLD: 'control-did-not-hold',
  CHECK_DID_NOT_COMPLETE: 'check-did-not-complete',
  NOT_OBSERVED: 'state-not-observed',
  NOT_APPLICABLE: 'state-not-applicable',
  NEVER_ESTABLISHED: 'state-absent-never-established',
});

/**
 * The configuration axes a full envelope would vary. Axes from this list that
 * no eligible cell carries are reported as `unmeasuredAxes` — the difference
 * between "measured at every optimisation level" and "measured across the
 * envelope" is most of what a fragility number means, and it is invisible
 * unless something states which axes were never moved.
 */
export const DEFAULT_EXPECTED_AXES = Object.freeze(['opt', 'ndebug', 'lto', 'target']);

/** Base class so a caller can branch on "this component could not answer". */
export class FragilityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FragilityError';
    /** interfaces.md section 7: a check that could not be completed. Never 0. */
    this.exitCode = 3;
  }
}

/** The matrix was not the shape this module is documented to take. */
export class FragilityInputError extends FragilityError {
  constructor(message) {
    super(message);
    this.name = 'FragilityInputError';
  }
}

/** The matrix was well formed but left nothing to measure. */
export class FragilityIncompleteError extends FragilityError {
  constructor(message, detail) {
    super(message);
    this.name = 'FragilityIncompleteError';
    /** @type {object|undefined} counts, so a caller can say what was thrown away */
    this.detail = detail;
  }
}

const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * A deterministic string for a configuration. Keys sort, so two cells that
 * spell the same configuration in a different key order are one column.
 */
export function configKey(config) {
  return Object.keys(config)
    .sort()
    .map((k) => `${k}=${String(config[k])}`)
    .join(',');
}

/**
 * interfaces.md section 5: absolute paths must not appear anywhere in a record.
 * A fragility report echoes cell ids, property ids and config values straight
 * out of its input, so a producer that put a build directory in a cell id would
 * launder it through this module into a committable file. Checked on the way
 * out rather than on the way in: the input is somebody else's to fix, but what
 * this module emits is this module's problem.
 */
function assertNoAbsolutePaths(value, path, found) {
  if (typeof value === 'string') {
    if (value.startsWith('/') || value.includes('/mnt/') || value.includes(':\\')) {
      found.push(`${path}: ${JSON.stringify(value)}`);
    }
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoAbsolutePaths(v, `${path}/${i}`, found));
  } else if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) assertNoAbsolutePaths(v, `${path}/${k}`, found);
  }
  return found;
}

/**
 * Validate one cell. Throwing rather than skipping is deliberate: a cell that
 * silently failed to parse would shrink the denominator without appearing in
 * the exclusion list, which is the one way a cell can leave this computation
 * unaccounted for.
 */
function validateCell(cell, index) {
  const where = `cells[${index}]`;
  if (!isPlainObject(cell)) throw new FragilityInputError(`${where} is not an object`);

  for (const field of ['cellId', 'propertyId']) {
    if (typeof cell[field] !== 'string' || cell[field].length === 0) {
      throw new FragilityInputError(`${where}.${field} must be a non-empty string`);
    }
  }
  if (!KNOWN_STATES.includes(cell.state)) {
    throw new FragilityInputError(
      `${where}.state is ${JSON.stringify(cell.state)}, which is not one of the states in ` +
        `interfaces.md section 3 (${KNOWN_STATES.join(', ')}). An unrecognised state is not ` +
        `bucketed as surviving — a vocabulary drift would silently lower every score.` +
        (UNJOINED_NEIGHBOUR_STATES.includes(cell.state)
          ? `\n\n  This label is one the envelope assembler in compiler/llvm-pass/scripts/ ` +
            `writes for a cell that produced no usable reading. Both of its labels describe ` +
            `cells this module would exclude from the denominator anyway, so the two components ` +
            `agree on the substance and differ only on the vocabulary — but interfaces.md ` +
            `section 3 is the shared list, and a component does not quietly widen it on its own ` +
            `(section 0: "If a component needs a shape that is not here, it reports that and the ` +
            `shape is added here first"). Reported rather than mapped.`
          : ''),
    );
  }
  // `null` is allowed for exactly one cell shape: one already declared
  // NOT_OBSERVED. Such a cell is excluded from the denominator on its state
  // alone, so demanding a boolean here does not protect the score — it forces
  // the producer to invent a control verdict for a measurement that never
  // happened, and an invented `false` is indistinguishable downstream from a
  // control that was measured and failed. Refusing null everywhere looked
  // fail-closed and was: it just moved the fabrication one component upstream.
  //
  // For every other state the rule is unchanged and deliberately unforgiving:
  // a cell that could be counted must say what its control did.
  const nullAllowed = cell.state === 'NOT_OBSERVED';
  for (const field of ['controlHeld', 'completesTheCheck']) {
    const v = cell[field];
    if (typeof v === 'boolean') continue;
    if (nullAllowed && v === null) continue;
    throw new FragilityInputError(
      `${where}.${field} must be a boolean; got ${JSON.stringify(v)}. A missing ` +
        `control verdict is not the same as a control that held, and this module will not ` +
        `pick the permissive reading for a producer that did not state one.` +
        (v === null
          ? ` \`null\` is accepted only on a NOT_OBSERVED cell, which is excluded on its state ` +
            `alone; this cell is ${JSON.stringify(cell.state)}, so its control verdict is load-bearing.`
          : ''),
    );
  }
  if (cell.polarity !== undefined && !POLARITIES.includes(cell.polarity)) {
    throw new FragilityInputError(
      `${where}.polarity is ${JSON.stringify(cell.polarity)}; expected one of ` +
        `${POLARITIES.join(', ')}, or omitted for the ${DEFAULT_POLARITY} default. An ` +
        `unrecognised polarity is refused rather than defaulted: scoring a must-not-appear ` +
        `property on the must-survive table turns its successes into failures.`,
    );
  }
  if (!isPlainObject(cell.config) || Object.keys(cell.config).length === 0) {
    throw new FragilityInputError(
      `${where}.config must be a non-empty object. A cell with no configuration cannot be ` +
        `placed in an envelope, and a fragility score without an envelope is unquotable.`,
    );
  }
  for (const [axis, value] of Object.entries(cell.config)) {
    const t = typeof value;
    if (value === null || (t !== 'string' && t !== 'number' && t !== 'boolean')) {
      throw new FragilityInputError(
        `${where}.config.${axis} must be a string, number or boolean; got ` +
          `${JSON.stringify(value)}. Omit an axis that was not varied rather than setting it ` +
          `null — null would have to mean both "not applicable" and "not measured".`,
      );
    }
  }
}

/**
 * Decide whether one cell may sit in the denominator.
 *
 * Order matters. A cell whose control did not hold has a meaningless state, so
 * the broken measurement is reported as the reason rather than whatever the
 * state happened to say.
 *
 * @returns {{eligible: true} | {eligible: false, reason: string}}
 */
export function classifyCell(cell) {
  // `false` and `null` are different answers and they are separated here, not
  // merged. A control that was measured and failed is a broken measurement and
  // dominates whatever the state column says — that is the test below this one.
  // A control that was never measured at all arrives as `null` on a cell already
  // marked NOT_OBSERVED, and there the two are not equivalent: reporting it as
  // CONTROL_DID_NOT_HOLD says "the control failed" about a control nobody ran.
  //
  // Testing `controlHeld !== true` first collapsed both into the first bucket,
  // which left NOT_OBSERVED unreachable for exactly the cells it was written for.
  // The score is unaffected — both are excluded — but the list of removals is
  // part of what makes a denominator quotable, and that list was misstating 16
  // of the 20 removals in the first real envelope this ran on. It is
  // interfaces.md section 3's "we did not see it" versus "it is not there",
  // reappearing one layer out from where section 3 guards it.
  if (cell.state === 'NOT_OBSERVED' && cell.controlHeld === null) {
    return { eligible: false, reason: EXCLUSION_REASONS.NOT_OBSERVED };
  }
  if (cell.controlHeld !== true) {
    return { eligible: false, reason: EXCLUSION_REASONS.CONTROL_DID_NOT_HOLD };
  }
  if (cell.completesTheCheck !== true) {
    return { eligible: false, reason: EXCLUSION_REASONS.CHECK_DID_NOT_COMPLETE };
  }
  if (cell.state === 'NOT_APPLICABLE') {
    return { eligible: false, reason: EXCLUSION_REASONS.NOT_APPLICABLE };
  }
  const table = POLARITY_TABLE[polarityOf(cell)];
  if (cell.state === 'ABSENT' && !table.eligible.includes('ABSENT')) {
    // interfaces.md section 3: observed missing at a point where the property
    // had not yet been established. For a must-survive property nothing was
    // there for an optimiser to remove, so this says nothing about fragility
    // either way. Counting it as survival would let a property nobody
    // implemented score 0.
    return { eligible: false, reason: EXCLUSION_REASONS.NEVER_ESTABLISHED };
  }
  if (!table.eligible.includes(cell.state)) {
    return { eligible: false, reason: EXCLUSION_REASONS.NOT_OBSERVED };
  }
  return { eligible: true };
}

/** Whether an eligible cell is one in which the declared property did not hold. */
export function cellFailed(cell) {
  return POLARITY_TABLE[polarityOf(cell)].failing.includes(cell.state);
}

/** Build the envelope description for one set of cells. */
function describeEnvelope(eligibleCells, allCells, expectedAxes) {
  const byKey = new Map();
  for (const cell of eligibleCells) {
    const key = configKey(cell.config);
    if (!byKey.has(key)) byKey.set(key, { key, config: { ...cell.config }, eligibleCells: 0 });
    byKey.get(key).eligibleCells += 1;
  }
  const measuredConfigs = [...byKey.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

  // Configurations that were attempted and contributed nothing. Without this a
  // matrix whose every -O2 cell was thrown away looks identical to one that was
  // only ever run at -O0, and the first is a broken run while the second is a
  // narrow one.
  const attempted = new Map();
  for (const cell of allCells) {
    const key = configKey(cell.config);
    if (!attempted.has(key)) attempted.set(key, { key, config: { ...cell.config }, cells: 0 });
    attempted.get(key).cells += 1;
  }
  const configsAttemptedWithoutEligibleCells = [...attempted.values()]
    .filter((c) => !byKey.has(c.key))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));

  const axes = {};
  for (const cell of eligibleCells) {
    for (const [axis, value] of Object.entries(cell.config)) {
      (axes[axis] ??= new Set()).add(String(value));
    }
  }
  const axisReport = {};
  for (const axis of Object.keys(axes).sort()) {
    const values = [...axes[axis]].sort();
    axisReport[axis] = { values, varied: values.length > 1 };
  }
  const unmeasuredAxes = expectedAxes.filter((a) => !(a in axisReport));

  return { measuredConfigs, configsAttemptedWithoutEligibleCells, axes: axisReport, unmeasuredAxes };
}

/** Score one group of already-validated cells, or explain why it has none. */
function scoreGroup(cells, expectedAxes) {
  const eligible = [];
  // The itemised denominator. Emitted alongside the exclusions so that both
  // halves of the split are auditable: a score whose denominator cannot be
  // enumerated is a score nobody can check.
  const counted = [];
  const excluded = [];
  const stateCounts = Object.fromEntries(KNOWN_STATES.map((s) => [s, 0]));

  for (const cell of cells) {
    stateCounts[cell.state] += 1;
    const verdict = classifyCell(cell);
    if (verdict.eligible) {
      eligible.push(cell);
      counted.push({
        cellId: cell.cellId,
        propertyId: cell.propertyId,
        configKey: configKey(cell.config),
        state: cell.state,
        polarity: polarityOf(cell),
        heldHere: !cellFailed(cell),
      });
    } else {
      excluded.push({
        cellId: cell.cellId,
        propertyId: cell.propertyId,
        configKey: configKey(cell.config),
        state: cell.state,
        reason: verdict.reason,
      });
    }
  }

  const excludedByReason = Object.fromEntries(Object.values(EXCLUSION_REASONS).map((r) => [r, 0]));
  for (const e of excluded) excludedByReason[e.reason] += 1;

  const failed = eligible.filter(cellFailed).length;
  const envelope = describeEnvelope(eligible, cells, expectedAxes);

  // Which reading each counted cell was scored under. A blended score is
  // legitimate — "the property did not hold" means the same thing for both
  // families — but it must be visible that two readings were blended.
  const polarityCounts = Object.fromEntries(POLARITIES.map((p) => [p, 0]));
  for (const c of eligible) polarityCounts[polarityOf(c)] += 1;

  const counts = {
    total: cells.length,
    eligible: eligible.length,
    excluded: excluded.length,
    // "failed"/"held" rather than "lost"/"survived": for a must-not-appear
    // property the failing state is PRESENT, and calling that column "lost"
    // would misname exactly the cells this table exists to get right.
    failed,
    held: eligible.length - failed,
  };

  if (eligible.length === 0) {
    return {
      score: null,
      scoreText: null,
      incomplete: true,
      incompleteReason:
        'no cell in this group survived the eligibility rules, so there is no denominator; ' +
        'see excludedByReason for what was removed and why',
      counts,
      stateCounts,
      polarityCounts,
      counted,
      excluded,
      excludedByReason,
      ...envelope,
    };
  }

  return {
    score: { num: failed, den: eligible.length },
    scoreText: (failed / eligible.length).toFixed(3),
    incomplete: false,
    counts,
    stateCounts,
    polarityCounts,
    counted,
    excluded,
    excludedByReason,
    ...envelope,
  };
}

/**
 * Compute the fragility report for a configuration envelope matrix.
 *
 * @param {Array<object>} cells one entry per (property, configuration) observation
 * @param {{expectedAxes?: string[]}} [options]
 * @returns {object} a frozen report; `score` is `{num, den}`, never a float
 * @throws {FragilityInputError} the matrix is not the documented shape
 * @throws {FragilityIncompleteError} the matrix left no eligible cell
 */
export function computeFragility(cells, options = {}) {
  if (!Array.isArray(cells)) {
    throw new FragilityInputError('the matrix must be an array of cells');
  }
  const expectedAxes = options.expectedAxes ?? DEFAULT_EXPECTED_AXES;
  if (!Array.isArray(expectedAxes) || expectedAxes.some((a) => typeof a !== 'string')) {
    throw new FragilityInputError('options.expectedAxes must be an array of strings');
  }

  if (cells.length === 0) {
    throw new FragilityIncompleteError(
      'the matrix is empty: nothing was measured, so there is no fragility to report. ' +
        'An empty envelope is refused rather than scored 0.000 — a component that reports a ' +
        'clean number for a run that observed nothing is the failure this directory exists ' +
        'to prevent.',
      { total: 0, eligible: 0, excluded: 0 },
    );
  }

  const seen = new Set();
  cells.forEach((cell, i) => {
    validateCell(cell, i);
    if (seen.has(cell.cellId)) {
      throw new FragilityInputError(
        `cells[${i}].cellId ${JSON.stringify(cell.cellId)} appears more than once. A repeated ` +
          `cell is weighted twice, which moves the score without moving the envelope.`,
      );
    }
    seen.add(cell.cellId);
  });

  const overall = scoreGroup(cells, expectedAxes);

  if (overall.incomplete) {
    throw new FragilityIncompleteError(
      `every one of the ${cells.length} cell(s) was removed from the denominator, so there is ` +
        `no fragility score. Removals: ` +
        Object.entries(overall.excludedByReason)
          .filter(([, n]) => n > 0)
          .map(([r, n]) => `${r}=${n}`)
          .join(', ') +
        '. This is refused rather than reported as 0.000: no configuration was successfully ' +
        'measured, which is not the same as a property that survived every configuration.',
      { counts: overall.counts, excludedByReason: overall.excludedByReason, excluded: overall.excluded },
    );
  }

  const propertyIds = [...new Set(cells.map((c) => c.propertyId))].sort();
  const byProperty = {};
  for (const id of propertyIds) {
    byProperty[id] = scoreGroup(
      cells.filter((c) => c.propertyId === id),
      expectedAxes,
    );
  }
  // Named rather than left for a reader to derive: a property whose every cell
  // was thrown away has no score, and an `overall` that quietly excludes it
  // should say which properties it is not speaking for.
  const propertiesWithoutScore = propertyIds.filter((id) => byProperty[id].incomplete);

  return Object.freeze({
    schemaVersion: SCHEMA_VERSION,
    component: COMPONENT,
    ...overall,
    propertyIds,
    propertiesWithoutScore,
    byProperty,
  });
}

/** Convert a `{num, den}` score to a float. Never write the result to a record. */
export function scoreAsFloat(score) {
  if (!isPlainObject(score) || !Number.isInteger(score.num) || !Number.isInteger(score.den)) {
    throw new FragilityInputError('a score is an object of two integers, {num, den}');
  }
  if (score.den === 0) {
    throw new FragilityIncompleteError('a score with a zero denominator is not a number; it is a refusal');
  }
  return score.num / score.den;
}

/**
 * The guard behind requirement "a score must not be quotable on its own".
 * Both serialisers call it, so there is no supported path from this module to a
 * bare number.
 */
function assertQuotable(report) {
  if (!isPlainObject(report)) throw new FragilityInputError('not a fragility report');
  if (!Array.isArray(report.measuredConfigs) || report.measuredConfigs.length === 0) {
    throw new FragilityInputError(
      'refusing to render a fragility report without a non-empty measuredConfigs. The score is ' +
        'a statement about the configurations it was measured over; detached from them it reads ' +
        'as a statement about all configurations, which is a stronger claim than was measured.',
    );
  }
  if (!isPlainObject(report.score) || !Number.isInteger(report.score.num) || !Number.isInteger(report.score.den)) {
    throw new FragilityInputError('refusing to render a report whose score is not an integer pair');
  }
}

/**
 * The record form. Integers only, score as a pair, envelope mandatory —
 * interfaces.md section 5 rules 4 and the absolute-path rule.
 */
export function toEvidenceJson(report) {
  assertQuotable(report);
  const out = {
    schemaVersion: report.schemaVersion,
    component: report.component,
    score: { num: report.score.num, den: report.score.den },
    scoreText: report.scoreText,
    counts: report.counts,
    stateCounts: report.stateCounts,
    polarityCounts: report.polarityCounts,
    counted: report.counted,
    excludedByReason: report.excludedByReason,
    excluded: report.excluded,
    measuredConfigs: report.measuredConfigs,
    configsAttemptedWithoutEligibleCells: report.configsAttemptedWithoutEligibleCells,
    axes: report.axes,
    unmeasuredAxes: report.unmeasuredAxes,
    propertyIds: report.propertyIds,
    propertiesWithoutScore: report.propertiesWithoutScore,
    byProperty: report.byProperty,
  };
  const offenders = assertNoAbsolutePaths(out, '', []);
  if (offenders.length > 0) {
    throw new FragilityInputError(
      `the report would carry ${offenders.length} absolute path(s), which interfaces.md ` +
        `section 5 forbids in a record: ${offenders.slice(0, 5).join('; ')}`,
    );
  }
  return out;
}

/** Human-readable form. Also refuses to print a score without its envelope. */
export function formatReport(report) {
  assertQuotable(report);
  const lines = [];
  const env = report.measuredConfigs.map((c) => c.key).join(' | ');
  lines.push(
    `fragility ${report.scoreText} (the property did not hold in ${report.score.num} of ` +
      `${report.score.den} eligible cells) ` +
      `over ${report.measuredConfigs.length} measured config(s): ${env}`,
  );
  if (report.unmeasuredAxes.length > 0) {
    lines.push(`  axes never varied in this envelope: ${report.unmeasuredAxes.join(', ')}`);
  }
  const flat = Object.entries(report.axes)
    .filter(([, a]) => !a.varied)
    .map(([k, a]) => `${k}=${a.values[0]}`);
  if (flat.length > 0) lines.push(`  axes present but held constant: ${flat.join(', ')}`);
  lines.push(
    `  cells: ${report.counts.total} total, ${report.counts.eligible} eligible, ` +
      `${report.counts.excluded} excluded from the denominator`,
  );
  const mixedPolarity = Object.values(report.polarityCounts).filter((n) => n > 0).length > 1;
  if (mixedPolarity) {
    lines.push(
      `  two property families are blended here, each scored against its own definition of ` +
        `failure: ` +
        Object.entries(report.polarityCounts)
          .filter(([, n]) => n > 0)
          .map(([p, n]) => `${p}=${n}`)
          .join(', '),
    );
  }
  for (const [reason, n] of Object.entries(report.excludedByReason)) {
    if (n > 0) lines.push(`    excluded ${n} for ${reason}`);
  }
  if (report.configsAttemptedWithoutEligibleCells.length > 0) {
    lines.push(
      `  configs attempted that contributed no eligible cell: ` +
        report.configsAttemptedWithoutEligibleCells.map((c) => c.key).join(' | '),
    );
  }
  if (report.propertiesWithoutScore.length > 0) {
    lines.push(`  properties with no score at all: ${report.propertiesWithoutScore.join(', ')}`);
  }
  lines.push('  per property:');
  for (const id of report.propertyIds) {
    const p = report.byProperty[id];
    if (p.incomplete) {
      lines.push(`    ${id}: NO SCORE — ${p.counts.excluded}/${p.counts.total} cell(s) excluded`);
      continue;
    }
    lines.push(
      `    ${id}: ${p.scoreText} (${p.score.num}/${p.score.den}) over ` +
        `${p.measuredConfigs.map((c) => c.key).join(' | ')}` +
        (p.counts.excluded > 0 ? ` [${p.counts.excluded} excluded]` : ''),
    );
  }
  return lines.join('\n');
}

/** Parse a `N/D` threshold. Kept strict so a typo is not read as a loose bound. */
export function parseThreshold(text) {
  const m = /^(\d+)\/([1-9]\d*)$/.exec(String(text));
  if (!m) {
    throw new FragilityInputError(
      `--max-score takes an integer ratio such as 1/2; got ${JSON.stringify(text)}. It is not a ` +
        `decimal because a threshold compared as a float is a threshold that can be crossed by ` +
        `rounding.`,
    );
  }
  return { num: Number(m[1]), den: Number(m[2]) };
}

/** `a > b` for two integer ratios, without floating point. */
export function ratioExceeds(a, b) {
  return a.num * b.den > b.num * a.den;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = `usage: node fragility.mjs <matrix.json> [--json] [--max-score N/D] [--expected-axes a,b]

  <matrix.json>   either an array of cells, or an object with a "cells" array.
                  A cell is {cellId, propertyId, config:{...}, state, controlHeld,
                  completesTheCheck}; state is one of ${KNOWN_STATES.join('/')}.

exit codes (compiler/schema/interfaces.md section 7)
  0  a score was computed
  2  --max-score was given and the score exceeded it
  3  the matrix was unreadable, malformed, or left no eligible cell

There is deliberately no flag that prints the score by itself.`;

async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    process.stdout.write(USAGE + '\n');
    return args.length === 0 ? 3 : 0;
  }

  let file = null;
  let asJson = false;
  let threshold = null;
  let expectedAxes = DEFAULT_EXPECTED_AXES;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json') asJson = true;
    else if (a === '--max-score') threshold = parseThreshold(args[++i]);
    else if (a === '--expected-axes') expectedAxes = String(args[++i]).split(',').filter(Boolean);
    else if (a.startsWith('-')) throw new FragilityInputError(`unknown option ${a}`);
    else if (file === null) file = a;
    else throw new FragilityInputError('more than one matrix file was given');
  }
  if (file === null) throw new FragilityInputError('no matrix file was given');

  const { readFile } = await import('node:fs/promises');
  let raw;
  try {
    raw = await readFile(file, 'utf8');
  } catch (err) {
    throw new FragilityIncompleteError(`could not read the matrix: ${err.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new FragilityInputError(`the matrix is not JSON: ${err.message}`);
  }
  const cells = Array.isArray(parsed) ? parsed : parsed?.cells;
  if (!Array.isArray(cells)) {
    throw new FragilityInputError('the matrix must be an array, or an object with a "cells" array');
  }

  const report = computeFragility(cells, { expectedAxes });
  process.stdout.write(
    (asJson ? JSON.stringify(toEvidenceJson(report), null, 2) : formatReport(report)) + '\n',
  );

  if (threshold && ratioExceeds(report.score, threshold)) {
    process.stderr.write(
      `fragility ${report.scoreText} exceeds the threshold ${threshold.num}/${threshold.den}\n`,
    );
    return 2;
  }
  return 0;
}

// Matched on the entry path rather than by comparing `import.meta.url` to a
// file URL: the URL forms disagree across platforms on drive-letter case, and a
// mismatch there leaves the CLI silently inert instead of loudly broken.
if (process.argv[1] && /(^|[/\\])fragility\.mjs$/.test(process.argv[1].replace(/\\/g, '/'))) {
  main(process.argv)
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      process.stderr.write(`${err.message}\n`);
      process.exitCode = err instanceof FragilityError ? err.exitCode : 3;
    });
}
