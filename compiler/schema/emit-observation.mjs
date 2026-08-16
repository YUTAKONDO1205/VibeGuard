#!/usr/bin/env node
// emit-observation — the reference writer for observation.schema.json.
//
//   node compiler/schema/emit-observation.mjs --self-check
//   node compiler/schema/emit-observation.mjs --from-draft <file> [--out <file>] [--seal]
//   node compiler/schema/emit-observation.mjs --from-driver-record <file> [--out <file>] [--seal]
//
// WHY THIS FILE EXISTS
//
// observation.schema.json used to say, in its own description, that "there is no
// consumer of this file in the repository yet; the deliverable is the form and
// its validator". That was true and it was the honest hole: a form nobody can
// write is a form nobody has tested against a writer. validate-observation.mjs
// had exactly one caller — its own test file. This is the writer. It does not
// invent a consumer for the records (there is no Beyond-side component in this
// tree, and building a fake one would be worse than the hole), but it closes the
// half that can be closed: there is now an implementation that produces the
// form, and the validator accepts what it produces.
//
// THE ONE RULE THIS FILE IS FOR
//
// A writer that copies a caller's `verdict.state` into the record is a writer
// that will write VERIFIED_CLEAN over a run that looked at nothing. So:
//
//   * with no claim from the caller, the verdict is DERIVED, and the derivation
//     picks the weakest state the evidence supports. Claiming less than you
//     measured is never a lie; claiming more always is.
//   * with a claim from the caller, the claim is GATED. VERIFIED_CLEAN is
//     refused outright when anything at all was unobserved; FINDINGS_PRESENT is
//     refused when the control did not survive; UNSUPPORTED is refused when
//     findings were recorded. A refused draft produces no record.
//
// The gates are written here as code, independently of the OBS-S* rules in
// validate-observation.mjs, and they are deliberately NOT imported from there.
// Two sides that share an implementation agree by construction and the
// agreement proves nothing — the same reason compiler/evidence/verify.mjs
// re-derives the digest instead of importing compiler/evidence/canon.mjs. The
// test file checks the agreement from outside, by feeding this file's output to
// that file's validator.
//
// WHAT IS DERIVED AND WHAT IS CARRIED
//
//   derived   history[].index, finalState, firstLoss, lossEpisodes,
//             properties[].verdict, counts.pointCoverage, verdict.exitCode,
//             and verdict.state when the caller does not claim one
//   carried   everything a re-run cannot recompute: what was observed, where,
//             by which pass, with which count, and the prose of a reason
//
// A field that is absent from the draft is absent from the record. `null` is
// carried through as `null`, because "not applicable" and "not written down"
// are different claims and collapsing them is the failure this directory is
// about (compiler/evidence/canon.mjs makes the same distinction).
//
// EXIT CODES — interfaces.md section 7.
//   0 a record was emitted and it validates
//   1 a prerequisite is missing (the schema could not be read)
//   3 an input could not be read, or nothing was emitted
//   4 the draft could not be turned into an honest record, or the record this
//     file produced does not validate. Never conflated with 0.
//
// The exit code of THIS command is about the emission, not about the build it
// describes. The build's own verdict and exit code are fields inside the record.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, relative, sep } from 'node:path';

import {
  loadSchema,
  validateDocument,
  EXIT_OK,
  EXIT_TOOL_FAILED,
  EXIT_INCOMPLETE,
  EXIT_INTEGRITY,
} from './validate-observation.mjs';

export { EXIT_OK, EXIT_TOOL_FAILED, EXIT_INCOMPLETE, EXIT_INTEGRITY };

export const OBSERVATION_VERSION = 'observation-v0';

/** The record form this tree already writes; see compiler/driver/lib/record.mjs. */
export const DRIVER_RECORD_VERSION = 'compiler-evidence-v0';

// ── the vocabularies, mirrored from the schema and checked against it ────────
//
// These are copies. The test file asserts each against observation.schema.json,
// so a vocabulary that grows in one place and not the other fails loudly rather
// than being silently half-applied.

export const PROPERTY_STATES = Object.freeze([
  'PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED',
]);

export const VERDICT_STATES = Object.freeze([
  'VERIFIED_CLEAN', 'FINDINGS_PRESENT', 'VERIFICATION_INCOMPLETE', 'UNSUPPORTED', 'EVIDENCE_MISMATCH',
]);

/** interfaces.md section 7, the same table validate-observation.mjs enforces. */
export const VERDICT_EXIT = Object.freeze({
  VERIFIED_CLEAN: 0,
  FINDINGS_PRESENT: 2,
  VERIFICATION_INCOMPLETE: 3,
  UNSUPPORTED: 3,
  EVIDENCE_MISMATCH: 4,
});

export const STAGES = Object.freeze(['compile', 'lto-backend', 'link', 'artifact']);

/** Which stage a checkpoint is reached in when nothing says otherwise. */
export const DEFAULT_STAGE_FOR_CHECKPOINT = Object.freeze({
  ast: 'compile',
  'pre-opt-ir': 'compile',
  'after-pass': 'compile',
  object: 'compile',
  linked: 'link',
});

export const CHECKPOINTS = Object.freeze(Object.keys(DEFAULT_STAGE_FOR_CHECKPOINT));

/**
 * The final states that SATISFY each property kind.
 *
 * This is the table that turns "the record ends LOST" into "and nobody said so".
 * A must-survive property that ends LOST with no finding naming it is a record
 * that measured a failure and reported nothing, which is the exact shape this
 * directory exists to refuse — so the emitter refuses to write it.
 */
export const SATISFIED_FINAL_STATES = Object.freeze({
  'must-survive': Object.freeze(['PRESENT', 'REINTRODUCED', 'NOT_APPLICABLE']),
  'must-not-appear': Object.freeze(['ABSENT', 'NOT_APPLICABLE']),
  'must-originate-from': Object.freeze(['PRESENT', 'REINTRODUCED', 'NOT_APPLICABLE']),
  'must-be-configured': Object.freeze(['PRESENT', 'REINTRODUCED', 'NOT_APPLICABLE']),
  'must-remain-unobservable': Object.freeze(['ABSENT', 'NOT_APPLICABLE']),
});

export const PROPERTY_KINDS = Object.freeze(Object.keys(SATISFIED_FINAL_STATES));

const FINDING_ID = /^VG-(CFG|PLG|PROP|INTRO|LINK|ART)-[0-9]{3}$/;
const POINT_ID = /^[a-z0-9][a-z0-9._-]*$/;
const HEX64 = /^[0-9a-f]{64}$/;
const OPT_LEVELS = new Set(['-O0', '-O1', '-O2', '-O3', '-Os', '-Oz']);

/**
 * Shapes that name one machine rather than a fixture.
 *
 * A second, independent copy of the list in validate-observation.mjs, on
 * purpose: this one has to fire BEFORE a record exists, so that a draft
 * carrying a machine path produces no file at all rather than a file the
 * validator later rejects. Written as shapes rather than as directory names
 * for the reason that file gives — the next one is spelled in a way nobody
 * enumerated.
 */
const MACHINE_PATH_SHAPES = [
  /^[/\\]/,
  /[A-Za-z]:[\\/]/,
  /(?:^|[\s"'(=])~[/\\]/,
  /(?:^|[\s"'(=])\/[A-Za-z_.]/,
];

// ── small helpers ───────────────────────────────────────────────────────────

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const has = (o, k) => isObject(o) && Object.prototype.hasOwnProperty.call(o, k);
const isNonEmptyString = (v) => typeof v === 'string' && v.trim().length > 0;

/** Copy `keys` from `src` to `dst`, but only the ones that are actually there. */
function carry(dst, src, keys) {
  for (const k of keys) if (has(src, k)) dst[k] = src[k];
  return dst;
}

function walk(node, pointer, visit) {
  visit(node, pointer);
  if (Array.isArray(node)) { node.forEach((n, i) => walk(n, `${pointer}/${i}`, visit)); return; }
  if (isObject(node)) for (const [k, v] of Object.entries(node)) walk(v, `${pointer}/${k}`, visit);
}

/** Every string in the record that names one machine. */
export function findMachinePaths(record) {
  const out = [];
  walk(record, '', (node, pointer) => {
    if (typeof node !== 'string') return;
    for (const shape of MACHINE_PATH_SHAPES) {
      if (shape.test(node)) { out.push({ pointer, value: node }); return; }
    }
  });
  return out;
}

/** Every number in the record that is not an integer (interfaces.md section 5 rule 4). */
export function findNonIntegers(record) {
  const out = [];
  walk(record, '', (node, pointer) => {
    if (typeof node === 'number' && !Number.isInteger(node)) out.push({ pointer, value: node });
  });
  return out;
}

// ── the pure function ───────────────────────────────────────────────────────

/**
 * Turn a draft into an observation record, or refuse.
 *
 * Pure: reads no clock, no environment and no file. `draft.context.generatedAt`
 * is required precisely so that this function cannot be the place a wall clock
 * sneaks into a record — the caller decides, and the CLI below is the one that
 * looks at SOURCE_DATE_EPOCH.
 *
 * @param {object} draft
 * @returns {{ok: true, record: object, derived: object}
 *         | {ok: false, errors: {reason: string, message: string}[]}}
 */
export function buildObservation(draft) {
  /** @type {{reason: string, message: string}[]} */
  const errors = [];
  const fail = (reason, message) => { errors.push({ reason, message }); };

  if (!isObject(draft)) {
    return { ok: false, errors: [{ reason: 'no-draft', message: 'a draft must be a JSON object' }] };
  }

  const context = buildContextBlock(draft.context, fail);
  const toolchain = buildToolchainBlock(draft.toolchain, fail);
  const policy = buildPolicyBlock(draft.policy, fail);
  const counts = buildCountsBlock(draft.counts, fail);
  const points = buildPoints(draft.observationPoints, fail);
  const layers = buildLayers(draft.layers, fail);

  const pointIds = new Set(points.map((p) => p.id));
  const declaredPropertyIds = new Set(
    (Array.isArray(draft.properties) ? draft.properties : [])
      .map((p) => (isObject(p) ? p.id : null))
      .filter((id) => typeof id === 'string'),
  );
  const findings = buildFindings(draft.findings, pointIds, declaredPropertyIds, fail);

  const findingsByProperty = new Set(findings.map((f) => f.property).filter((p) => typeof p === 'string'));

  const unsupportedReason = isNonEmptyString(draft.unsupportedReason) ? draft.unsupportedReason.trim() : null;

  const built = buildProperties(draft.properties, {
    pointIds,
    findingsByProperty,
    unsupported: unsupportedReason !== null,
  }, fail);
  const properties = built.properties;

  // ── the blockers, derived from the evidence and from nothing else ──────────
  const unobservedBlockers = [];
  for (const p of points) {
    if (p.reached === false) unobservedBlockers.push(`observation point \`${p.id}\` was not reached`);
  }
  unobservedBlockers.push(...built.unobserved);
  for (const [name, layer] of Object.entries(layers ?? {})) {
    if (isObject(layer) && layer.observed === false) unobservedBlockers.push(`the ${name} layer was not observed`);
  }
  if (isObject(layers?.link)
      && (layers.link.ltoMode === 'full' || layers.link.ltoMode === 'thin')
      && layers.link.backendObserved === false) {
    unobservedBlockers.push(`an LTO backend ran (ltoMode ${layers.link.ltoMode}) and its passes were not observed`);
  }
  for (const chk of (isObject(layers?.artifact) && Array.isArray(layers.artifact.checks) ? layers.artifact.checks : [])) {
    if (isObject(chk) && chk.result === 'NOT_OBSERVED') {
      unobservedBlockers.push(`artefact requirement \`${chk.require}\` was not observed`);
    }
  }
  if (unsupportedReason !== null) {
    unobservedBlockers.push(`the configuration is outside the measured envelope: ${unsupportedReason}`);
  }

  const suppliedUnobserved = Array.isArray(draft.verdict?.unobserved)
    ? draft.verdict.unobserved.filter((s) => typeof s === 'string')
    : null;
  const unobserved = suppliedUnobserved ?? unobservedBlockers.slice();

  const cleanBlockers = unobservedBlockers.slice();
  if (findings.length) cleanBlockers.push(`${findings.length} finding(s) are present`);
  if (unobserved.length) cleanBlockers.push(`verdict.unobserved lists ${unobserved.length} item(s)`);
  for (const p of properties) {
    if (p.verdict !== 'VERIFIED_CLEAN') cleanBlockers.push(`property \`${p.id}\` is ${p.verdict}`);
  }
  if (built.anyControlDead) cleanBlockers.push('a control did not survive');

  // ── the verdict: derived, or claimed and then gated ────────────────────────
  const claim = draft.verdict?.state;
  let state;
  if (claim === undefined || claim === null) {
    if (built.anyControlDead) state = 'EVIDENCE_MISMATCH';
    else if (unsupportedReason !== null) state = 'UNSUPPORTED';
    else if (unobservedBlockers.length || unobserved.length) state = 'VERIFICATION_INCOMPLETE';
    else if (findings.length) state = 'FINDINGS_PRESENT';
    else state = 'VERIFIED_CLEAN';
  } else if (!VERDICT_STATES.includes(claim)) {
    fail('unknown-verdict', `verdict.state ${JSON.stringify(claim)} is not one of ${VERDICT_STATES.join(', ')}`);
    state = 'EVIDENCE_MISMATCH';
  } else {
    state = claim;
    if (built.anyControlDead && claim !== 'EVIDENCE_MISMATCH') {
      fail('control-did-not-survive',
        `a control did not survive, so the only verdict this measurement can carry is EVIDENCE_MISMATCH, not ${claim}: `
        + built.deadControls.join('; '));
    }
    if (claim === 'VERIFIED_CLEAN' && cleanBlockers.length) {
      for (const why of cleanBlockers) fail('clean-over-unobserved', `VERIFIED_CLEAN is not available: ${why}`);
    }
    if (claim === 'FINDINGS_PRESENT') {
      if (findings.length === 0) fail('findings-present-without-findings', 'verdict FINDINGS_PRESENT with an empty findings array');
      for (const u of built.unobservedControls) {
        fail('findings-without-control', `${u}, so a finding taken from this run has no control`);
      }
    }
    if (claim === 'UNSUPPORTED') {
      if (findings.length) {
        fail('findings-under-unsupported',
          `${findings.length} finding(s) recorded under an UNSUPPORTED verdict; a configuration outside the envelope has not been checked, so it has no findings`);
      }
      if (unsupportedReason === null) {
        fail('unsupported-without-reason',
          'a claim of UNSUPPORTED needs draft.unsupportedReason: which part of the configuration is outside the measured envelope is not derivable from the record');
      }
    }
  }

  const reason = isNonEmptyString(draft.verdict?.reason)
    ? draft.verdict.reason
    : defaultReason(state, { cleanBlockers, unobservedBlockers, findings, properties, unsupportedReason, deadControls: built.deadControls });

  const reachedCount = points.filter((p) => p.reached === true).length;

  const record = {
    observationVersion: OBSERVATION_VERSION,
    context: context ?? {},
    toolchain: toolchain ?? {},
    ...(policy ? { policy } : {}),
    verdict: {
      state,
      exitCode: VERDICT_EXIT[state],
      reason,
      unobserved,
    },
    counts: {
      ...(counts ?? {}),
      pointCoverage: { num: reachedCount, den: points.length },
    },
    observationPoints: points,
    properties,
    layers: layers ?? {},
    findings,
  };

  for (const { pointer, value } of findMachinePaths(record)) {
    fail('absolute-path', `${pointer || '(root)'} names one machine: ${JSON.stringify(value.slice(0, 80))}`);
  }
  for (const { pointer, value } of findNonIntegers(record)) {
    fail('non-integer-number', `${pointer || '(root)'} is ${value}; a ratio is a pair {num, den}, never a float`);
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    record,
    derived: {
      state,
      exitCode: VERDICT_EXIT[state],
      pointCoverage: { num: reachedCount, den: points.length },
      cleanBlockers,
      unobservedBlockers,
      propertyVerdicts: properties.map((p) => p.verdict),
    },
  };
}

function defaultReason(state, ctx) {
  const first = (list) => (list.length ? list[0] : null);
  switch (state) {
    case 'VERIFIED_CLEAN':
      return 'every declared observation point was reached, every property ended in a state its kind requires, '
        + 'and every control survived the same pipeline';
    case 'FINDINGS_PRESENT':
      return `${ctx.findings.length} finding(s) were recorded and every control survived the pipeline that produced them`;
    case 'UNSUPPORTED':
      return ctx.unsupportedReason ?? 'the configuration is outside the measured envelope';
    case 'EVIDENCE_MISMATCH':
      return first(ctx.deadControls) ?? 'the measurement contradicts itself and is not evidence about the program';
    default:
      return `the run did not finish looking: ${first(ctx.unobservedBlockers) ?? 'a checkpoint was not reached'}`;
  }
}

// ── the blocks ──────────────────────────────────────────────────────────────

function buildContextBlock(c, fail) {
  if (!isObject(c)) {
    fail('no-context', 'draft.context is required and must carry generatedAt and timeSource; this emitter reads no clock of its own');
    return null;
  }
  if (!isNonEmptyString(c.generatedAt)) {
    fail('no-context', 'context.generatedAt must be a non-empty string');
  }
  if (c.timeSource !== 'SOURCE_DATE_EPOCH' && c.timeSource !== 'wall-clock') {
    fail('no-context', `context.timeSource must be SOURCE_DATE_EPOCH or wall-clock, got ${JSON.stringify(c.timeSource)}`);
  }
  const out = { generatedAt: c.generatedAt, timeSource: c.timeSource };
  return carry(out, c, ['sourceDateEpoch', 'host', 'repository']);
}

function buildToolchainBlock(t, fail) {
  if (!isObject(t)) {
    fail('no-toolchain', 'draft.toolchain is required and must carry digest, clang and packages');
    return null;
  }
  if (typeof t.digest !== 'string' || !HEX64.test(t.digest)) {
    fail('no-toolchain-digest',
      `toolchain.digest must be 64 lowercase hex characters, got ${JSON.stringify(t.digest)}; `
      + 'a record that cannot identify the toolchain it measured is not evidence about a build');
  }
  if (typeof t.clang !== 'string') {
    fail('no-toolchain', `toolchain.clang must be a string, got ${JSON.stringify(t.clang)}`);
  }
  const packages = [];
  const raw = Array.isArray(t.packages) ? t.packages : null;
  if (raw === null) {
    fail('no-toolchain', 'toolchain.packages must be an array; an empty array is legal and means none were pinned');
  } else {
    raw.forEach((p, i) => {
      if (!isObject(p) || typeof p.name !== 'string' || typeof p.version !== 'string') {
        fail('bad-package', `toolchain.packages[${i}] must carry a string name and a string version`);
        return;
      }
      const q = { name: p.name, version: p.version };
      if (has(p, 'sha256')) {
        if (typeof p.sha256 === 'string' && HEX64.test(p.sha256)) q.sha256 = p.sha256;
        else fail('bad-package', `toolchain.packages[${i}].sha256 must be 64 lowercase hex characters`);
      }
      packages.push(q);
    });
  }
  return { digest: typeof t.digest === 'string' ? t.digest : '', clang: typeof t.clang === 'string' ? t.clang : '', packages };
}

function buildPolicyBlock(p, fail) {
  if (p === undefined || p === null) return null;
  if (!isObject(p)) { fail('bad-policy', 'draft.policy must be an object when it is present'); return null; }
  if (p.policyVersion !== 'policy-v0') {
    fail('bad-policy', `policy.policyVersion must be "policy-v0", got ${JSON.stringify(p.policyVersion)}`);
  }
  if (typeof p.digest !== 'string' || !HEX64.test(p.digest)) {
    fail('bad-policy', `policy.digest must be 64 lowercase hex characters, got ${JSON.stringify(p.digest)}`);
  }
  const out = { policyVersion: 'policy-v0', digest: typeof p.digest === 'string' ? p.digest : '' };
  return carry(out, p, ['failOn']);
}

function buildCountsBlock(c, fail) {
  if (!isObject(c)) {
    fail('no-counts', 'draft.counts is required: inputs, checked and skipped are the counting contract and are not optional');
    return null;
  }
  for (const k of ['inputs', 'checked', 'skipped']) {
    if (!Number.isInteger(c[k])) fail('no-counts', `counts.${k} must be an integer, got ${JSON.stringify(c[k])}`);
  }
  const out = {
    inputs: Number.isInteger(c.inputs) ? c.inputs : 0,
    checked: Number.isInteger(c.checked) ? c.checked : 0,
    skipped: Number.isInteger(c.skipped) ? c.skipped : 0,
  };
  if (has(c, 'skippedNames')) {
    if (!Array.isArray(c.skippedNames)) fail('no-counts', 'counts.skippedNames must be an array; a count without names is not auditable');
    else out.skippedNames = c.skippedNames.slice();
  }
  return out;
}

function buildPoints(list, fail) {
  if (!Array.isArray(list)) {
    fail('no-points', 'draft.observationPoints must be an array; an empty array is legal and says nothing was looked at');
    return [];
  }
  const out = [];
  const seen = new Set();
  list.forEach((p, i) => {
    if (!isObject(p)) { fail('bad-point', `observationPoints[${i}] is not an object`); return; }
    if (typeof p.id !== 'string' || !POINT_ID.test(p.id)) {
      fail('bad-point', `observationPoints[${i}].id ${JSON.stringify(p.id)} does not match ${POINT_ID.source}`);
      return;
    }
    if (seen.has(p.id)) {
      fail('duplicate-point-id', `two observation points carry the id \`${p.id}\`; a history entry naming it would be ambiguous`);
      return;
    }
    seen.add(p.id);
    if (!CHECKPOINTS.includes(p.checkpoint)) {
      fail('bad-point', `observationPoints[${i}].checkpoint must be one of ${CHECKPOINTS.join(', ')}, got ${JSON.stringify(p.checkpoint)}`);
    }
    if (!STAGES.includes(p.stage)) {
      fail('bad-point', `observationPoints[${i}].stage must be one of ${STAGES.join(', ')}, got ${JSON.stringify(p.stage)}`);
    }
    if (typeof p.reached !== 'boolean') {
      fail('bad-point', `observationPoints[${i}].reached must be a boolean; "we could not tell" is not a third value`);
    }
    if (p.reached === false && !isNonEmptyString(p.unreachedReason)) {
      fail('unreached-without-reason',
        `observation point \`${p.id}\` was not reached and the draft gives no reason; `
        + 'deleting the reason turns "we could not look" into "there was nothing to look at"');
    }
    const q = {
      id: p.id,
      checkpoint: p.checkpoint,
      stage: p.stage,
      reached: p.reached,
    };
    out.push(carry(q, p, ['unreachedReason', 'target', 'optLevel', 'tool']));
  });
  return out;
}

function buildLayers(l, fail) {
  if (!isObject(l)) {
    fail('no-layers', 'draft.layers is required and must carry compile, link and artifact');
    return null;
  }
  const out = {};
  for (const name of ['compile', 'link', 'artifact']) {
    const layer = l[name];
    if (!isObject(layer)) { fail('no-layers', `layers.${name} is missing`); out[name] = {}; continue; }
    if (typeof layer.observed !== 'boolean') {
      fail('bad-layer', `layers.${name}.observed must be a boolean; a layer that was never looked at must not read as a layer that was clean`);
    }
    if (layer.observed === false && !isNonEmptyString(layer.unobservedReason)) {
      fail('unobserved-without-reason', `layers.${name}.observed is false and no unobservedReason says why`);
    }
    const q = { observed: layer.observed };
    if (name === 'link') {
      if (!['none', 'full', 'thin', 'unknown'].includes(layer.ltoMode)) {
        fail('bad-layer', `layers.link.ltoMode must be none, full, thin or unknown, got ${JSON.stringify(layer.ltoMode)}; "unknown" is a real answer and is not "none"`);
      }
      if (typeof layer.backendObserved !== 'boolean') {
        fail('bad-layer', `layers.link.backendObserved must be a boolean, got ${JSON.stringify(layer.backendObserved)}`);
      }
      // Emitted in the schema's own declaration order, so that a record written
      // here and one written by hand diff against each other line for line.
      carry(q, layer, ['unobservedReason', 'linker']);
      q.ltoMode = layer.ltoMode;
      q.backendObserved = layer.backendObserved;
      carry(q, layer, ['backendUnobservedReason', 'inputs']);
    } else if (name === 'compile') {
      carry(q, layer, ['unobservedReason', 'target', 'optLevel', 'passPluginsLoaded', 'passesSeen', 'unitsTracked']);
    } else {
      carry(q, layer, ['unobservedReason', 'path', 'format', 'machine', 'checks']);
    }
    out[name] = q;
  }
  return out;
}

function buildFindings(list, pointIds, propertyIds, fail) {
  if (list === undefined || list === null) return [];
  if (!Array.isArray(list)) { fail('bad-findings', 'draft.findings must be an array'); return []; }
  const out = [];
  list.forEach((f, i) => {
    if (!isObject(f)) { fail('bad-findings', `findings[${i}] is not an object`); return; }
    if (typeof f.id !== 'string' || !FINDING_ID.test(f.id)) {
      fail('bad-finding-id',
        `findings[${i}].id ${JSON.stringify(f.id)} is outside the reserved namespaces `
        + '(VG-CFG, VG-PLG, VG-PROP, VG-INTRO, VG-LINK, VG-ART, three digits); a component cannot invent a seventh by writing one');
      return;
    }
    if (!['low', 'medium', 'high', 'critical'].includes(f.severity)) {
      fail('bad-findings', `findings[${i}].severity must be low, medium, high or critical, got ${JSON.stringify(f.severity)}`);
    }
    if (!isNonEmptyString(f.title)) fail('bad-findings', `findings[${i}].title must be a non-empty string`);
    if (!isNonEmptyString(f.detail)) fail('bad-findings', `findings[${i}].detail must be a non-empty string`);
    const w = f.where;
    if (!isObject(w) || !['invocation', 'source', 'ir', 'object', 'link', 'artifact'].includes(w.kind)) {
      fail('bad-findings', `findings[${i}].where.kind must be one of invocation, source, ir, object, link, artifact`);
      return;
    }
    if (has(f, 'point') && f.point !== null && !pointIds.has(f.point)) {
      fail('dangling-finding', `findings[${i}] (${f.id}) names point \`${f.point}\`, which no observationPoint declares`);
    }
    if (has(f, 'property') && f.property !== null && !propertyIds.has(f.property)) {
      fail('dangling-finding', `findings[${i}] (${f.id}) names property \`${f.property}\`, which no property declares`);
    }
    const q = {
      id: f.id,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      where: {
        kind: w.kind,
        path: has(w, 'path') ? w.path : null,
        unit: has(w, 'unit') ? w.unit : null,
        pass: has(w, 'pass') ? w.pass : null,
      },
    };
    out.push(carry(q, f, ['property', 'point']));
  });
  return out;
}

function buildProperties(list, ctx, fail) {
  const properties = [];
  const unobserved = [];
  const deadControls = [];
  const unobservedControls = [];
  if (!Array.isArray(list)) {
    fail('no-properties', 'draft.properties must be an array; an empty array is legal and says no property was observed');
    return { properties, unobserved, deadControls, unobservedControls, anyControlDead: false };
  }
  const seen = new Set();
  list.forEach((p, i) => {
    if (!isObject(p)) { fail('bad-property', `properties[${i}] is not an object`); return; }
    if (!isNonEmptyString(p.id)) { fail('bad-property', `properties[${i}].id must be a non-empty string`); return; }
    if (seen.has(p.id)) { fail('duplicate-property-id', `two properties carry the id \`${p.id}\``); return; }
    seen.add(p.id);
    if (!PROPERTY_KINDS.includes(p.kind)) {
      fail('bad-property', `properties[${i}] (${p.id}).kind must be one of ${PROPERTY_KINDS.join(', ')}, got ${JSON.stringify(p.kind)}`);
      return;
    }

    const control = buildControl(p.control, p.id, fail);
    const history = buildHistory(p.history, p.id, ctx.pointIds, fail);
    if (control === null || history === null) return;

    const historyComplete = p.historyComplete;
    if (typeof historyComplete !== 'boolean') {
      fail('bad-property', `properties[${i}] (${p.id}).historyComplete must be a boolean; a sequence that was cut short must say so`);
      return;
    }

    const finalState = history.entries.length
      ? history.entries[history.entries.length - 1].state
      : 'NOT_OBSERVED';

    // NOT_OBSERVED is "we did not look"; a zero call-site count on a control we
    // DID look at is "the oracle stopped counting". They are separated here
    // because the first is an incomplete run and the second is a broken one.
    const controlUnobserved = control.state === 'NOT_OBSERVED';
    const controlDead = !controlUnobserved
      && (control.state === 'LOST' || control.state === 'ABSENT' || control.count.callSites === 0);

    const mine = [];
    if (history.entries.length === 0) mine.push(`property \`${p.id}\` carries no history`);
    for (const e of history.entries) {
      if (e.state === 'NOT_OBSERVED') mine.push(`property \`${p.id}\` is NOT_OBSERVED at \`${e.point}\``);
    }
    if (historyComplete === false) mine.push(`property \`${p.id}\` has an incomplete history`);
    if (controlUnobserved) {
      const line = `the control \`${control.unit}\` for \`${p.id}\` was never observed`;
      mine.push(line);
      unobservedControls.push(line);
    }
    unobserved.push(...mine);
    if (controlDead) {
      deadControls.push(`the control \`${control.unit}\` for \`${p.id}\` did not survive (state ${control.state}, callSites ${control.count.callSites})`);
    }

    let verdict;
    if (controlDead) verdict = 'EVIDENCE_MISMATCH';
    else if (ctx.unsupported) verdict = 'UNSUPPORTED';
    else if (mine.length) verdict = 'VERIFICATION_INCOMPLETE';
    else if (ctx.findingsByProperty.has(p.id)) verdict = 'FINDINGS_PRESENT';
    else verdict = 'VERIFIED_CLEAN';

    // The rule that stops a measured failure being written down as nothing.
    if (!controlDead && !controlUnobserved && !ctx.unsupported && finalState !== 'NOT_OBSERVED') {
      const satisfied = SATISFIED_FINAL_STATES[p.kind].includes(finalState);
      if (!satisfied && !ctx.findingsByProperty.has(p.id)) {
        fail('unaccounted-violation',
          `property \`${p.id}\` is ${p.kind} and ends ${finalState}, which does not satisfy it, and no finding names it; `
          + 'a record that measures a failure and reports nothing is the shape this schema exists to refuse');
      }
    }

    const q = { id: p.id, kind: p.kind };
    carry(q, p, ['scope']);
    q.control = control;
    q.history = history.entries;
    q.historyComplete = historyComplete;
    q.firstLoss = history.firstLoss;
    q.finalState = finalState;
    q.lossEpisodes = history.lossEpisodes;
    carry(q, p, ['fate']);
    q.verdict = verdict;
    carry(q, p, ['note']);
    properties.push(q);
  });
  return {
    properties,
    unobserved,
    deadControls,
    unobservedControls,
    anyControlDead: deadControls.length > 0,
  };
}

function buildEffectCount(c, where, fail) {
  if (!isObject(c)) { fail('bad-count', `${where}.count is missing`); return null; }
  if (!Number.isInteger(c.callSites)) {
    fail('bad-count', `${where}.count.callSites must be an integer, got ${JSON.stringify(c.callSites)}`);
    return null;
  }
  if (c.oracle !== 'call-site') {
    fail('bad-oracle',
      `${where}.count.oracle must be "call-site", got ${JSON.stringify(c.oracle)}; `
      + 'a deleted call leaves its `declare` behind, so a name search blames the pass that swept the declaration away');
    return null;
  }
  const q = { callSites: c.callSites, oracle: 'call-site' };
  return carry(q, c, ['naiveSymbolMatches']);
}

function buildControl(c, propertyId, fail) {
  if (!isObject(c)) {
    fail('no-control',
      `property \`${propertyId}\` has no control; every fixture carries one whose effect cannot be removed, `
      + 'and a measurement with no control cannot tell a finding from a broken run');
    return null;
  }
  if (!isNonEmptyString(c.unit)) { fail('no-control', `property \`${propertyId}\`: control.unit must be a non-empty string`); return null; }
  if (!PROPERTY_STATES.includes(c.state)) {
    fail('no-control', `property \`${propertyId}\`: control.state must be one of ${PROPERTY_STATES.join(', ')}, got ${JSON.stringify(c.state)}`);
    return null;
  }
  const count = buildEffectCount(c.count, `property \`${propertyId}\` control`, fail);
  if (count === null) return null;
  return { unit: c.unit, state: c.state, count };
}

function buildHistory(list, propertyId, pointIds, fail) {
  if (!Array.isArray(list)) {
    fail('no-history', `property \`${propertyId}\`.history must be an array; the whole sequence, in order, to the end of the pipeline`);
    return null;
  }
  const entries = [];
  let everPresent = false;
  let everLost = false;
  let previous = null;
  let lossEpisodes = 0;
  let firstLoss = null;
  let bad = false;

  list.forEach((e, idx) => {
    if (!isObject(e)) { fail('bad-history', `property \`${propertyId}\` history[${idx}] is not an object`); bad = true; return; }
    if (!PROPERTY_STATES.includes(e.state)) {
      fail('bad-history', `property \`${propertyId}\` history[${idx}].state must be one of ${PROPERTY_STATES.join(', ')}, got ${JSON.stringify(e.state)}`);
      bad = true;
      return;
    }
    if (typeof e.point !== 'string' || !pointIds.has(e.point)) {
      fail('dangling-point',
        `property \`${propertyId}\` history[${idx}] names point ${JSON.stringify(e.point)}, which no observationPoint declares`);
      bad = true;
      return;
    }
    if (e.state === 'LOST' && !everPresent) {
      fail('impossible-transition',
        `property \`${propertyId}\` history[${idx}] is LOST with no preceding PRESENT; `
        + 'LOST means missing where it had been present, and a history that opens with it is using the word for something else');
      bad = true;
    }
    if (e.state === 'REINTRODUCED' && !everLost) {
      fail('impossible-transition',
        `property \`${propertyId}\` history[${idx}] is REINTRODUCED with no preceding LOST`);
      bad = true;
    }

    const attribution = buildAttribution(e.attribution, `property \`${propertyId}\` history[${idx}]`, fail);
    const count = buildEffectCount(e.count, `property \`${propertyId}\` history[${idx}]`, fail);
    if (attribution === null || count === null) { bad = true; return; }

    const entry = { index: idx, point: e.point };
    carry(entry, e, ['phase']);
    entry.state = e.state;
    entry.attribution = attribution;
    entry.count = count;
    entries.push(entry);

    if (e.state === 'LOST' && previous !== 'LOST') {
      lossEpisodes += 1;
      if (firstLoss === null) {
        firstLoss = {
          pass: attribution.pass,
          unit: attribution.unit,
          seq: has(attribution, 'seq') ? attribution.seq : null,
          historyIndex: idx,
        };
      }
    }
    if (e.state === 'PRESENT' || e.state === 'REINTRODUCED') everPresent = true;
    if (e.state === 'LOST') everLost = true;
    previous = e.state;
  });

  if (bad) return null;
  return { entries, firstLoss, lossEpisodes };
}

function buildAttribution(a, where, fail) {
  if (!isObject(a)) {
    fail('no-attribution',
      `${where}.attribution is missing; blame is a (pass, IR unit) pair and never a pass alone, `
      + 'because LLVM nests module inside call graph inside function inside loop and "the seventh pass" is not a position anyone can point at');
    return null;
  }
  if (!has(a, 'pass') || !has(a, 'unit')) {
    fail('no-attribution', `${where}.attribution must carry both pass and unit; null means not applicable, never not looked at`);
    return null;
  }
  const q = { pass: a.pass, unit: a.unit };
  return carry(q, a, ['unitKind', 'lineage', 'seq']);
}

// ── schema-gated emission ───────────────────────────────────────────────────

/**
 * Build, then check the result against the schema and the semantic rules before
 * anyone sees it. The emitter never hands out a record its own validator
 * rejects, which is what makes "the validator accepts what this file writes" a
 * property of the code rather than a property of one test.
 */
export function emitObservation(schema, draft) {
  const built = buildObservation(draft);
  if (!built.ok) return { ok: false, stage: 'draft', errors: built.errors.map((e) => `${e.reason}: ${e.message}`) };
  const text = `${JSON.stringify(built.record, null, 2)}\n`;
  const check = validateDocument(schema, JSON.parse(text), text);
  if (!check.ok) {
    return {
      ok: false,
      stage: 'validate',
      errors: [`the emitted record does not validate (${check.kind})`, ...check.errors],
    };
  }
  return { ok: true, record: built.record, text, derived: built.derived };
}

/**
 * Add `evidenceDigest`: SHA-256 over the canonical bytes with `context` and
 * `evidenceDigest` removed as whole subtrees. The canonicaliser is imported
 * lazily so that nothing in this file's pure path depends on compiler/evidence.
 */
export async function sealObservation(record) {
  const { evidenceDigest } = await import('../evidence/canon.mjs');
  return { ...record, evidenceDigest: evidenceDigest(record) };
}

// ── the adapter for the record form this tree already writes ────────────────

/**
 * Turn a driver evidence record (compiler-evidence-v0) into a draft.
 *
 * WHAT THIS CANNOT DO, AND WHY IT SAYS SO
 *
 * A driver record has no `properties[]` in the observation sense. It carries a
 * *reachability cross-check* — which properties the policy asked for and which
 * of them the catalogue can answer — and no measurement of any of them. An
 * observation property needs a control, and there is no control in a driver
 * record. Manufacturing one would be the exact failure this directory exists to
 * prevent, so `properties` comes out empty and every checkpoint the policy
 * asked for is declared as an observation point that was NOT reached, with the
 * reason in as many words. The resulting record is honest and thin, and its
 * derived verdict is VERIFICATION_INCOMPLETE rather than clean.
 *
 * @returns {{ok: true, draft: object, counts: object}
 *         | {ok: false, errors: {reason: string, message: string}[]}}
 */
export function draftFromDriverRecord(rec) {
  const errors = [];
  const fail = (reason, message) => errors.push({ reason, message });

  if (!isObject(rec)) return { ok: false, errors: [{ reason: 'not-a-record', message: 'a driver record must be a JSON object' }] };
  if (rec.recordVersion !== DRIVER_RECORD_VERSION) {
    fail('wrong-record-version', `expected recordVersion ${DRIVER_RECORD_VERSION}, got ${JSON.stringify(rec.recordVersion)}`);
  }

  const ctx = isObject(rec.context) ? rec.context : {};
  const context = { generatedAt: ctx.generatedAt, timeSource: ctx.timeSource };
  if (has(ctx, 'sourceDateEpoch')) context.sourceDateEpoch = ctx.sourceDateEpoch;
  if (isObject(ctx.host)) context.host = ctx.host;

  const tc = isObject(rec.toolchain) ? rec.toolchain : {};
  if (typeof tc.digest !== 'string' || !HEX64.test(tc.digest)) {
    fail('no-toolchain-digest',
      'the driver record carries no toolchain.digest (it is null when no pin was configured). '
      + 'An observation record has to name the toolchain it measured, and this adapter will not invent a digest for it.');
  }

  // A pinned package whose version was never observed is recorded as skipped BY
  // NAME rather than dropped. The observation form requires a version string,
  // and `version: null` is what the driver writes when the pin did not carry
  // one; turning that into `"version": "unknown"` would be this file inventing
  // a measurement, and dropping it silently would make the packages array read
  // as "these are all of them".
  const packages = [];
  const skippedNames = [];
  for (const p of Array.isArray(tc.packages) ? tc.packages : []) {
    if (isObject(p) && typeof p.name === 'string' && typeof p.version === 'string') {
      const q = { name: p.name, version: p.version };
      if (typeof p.sha256 === 'string' && HEX64.test(p.sha256)) q.sha256 = p.sha256;
      packages.push(q);
    } else if (isObject(p) && typeof p.name === 'string') {
      skippedNames.push(`toolchain package \`${p.name}\`: its version was not observed (${JSON.stringify(p.version ?? null)}), and this form has no way to record a package without one`);
    } else {
      skippedNames.push(`a toolchain package entry with no name: ${JSON.stringify(p)}`);
    }
  }

  const toolchain = { digest: tc.digest, clang: typeof tc.clang === 'string' ? tc.clang : '', packages };

  let policy;
  const pol = isObject(rec.policy) ? rec.policy : null;
  if (pol && pol.policyVersion === 'policy-v0' && typeof pol.sha256 === 'string' && HEX64.test(pol.sha256)) {
    policy = { policyVersion: 'policy-v0', digest: pol.sha256 };
    if (['low', 'medium', 'high', 'critical'].includes(pol.failOn)) policy.failOn = pol.failOn;
  }

  // Observation points: one per (property, checkpoint) the policy asked for.
  const NOT_REACHED = 'the driver observes the invocation layer only; nothing in this tree observed this checkpoint during the run that wrote the record';
  const entries = Array.isArray(rec.checks?.properties?.entries) ? rec.checks.properties.entries : [];
  const observationPoints = [];
  const usedIds = new Set();
  for (const e of entries) {
    if (!isObject(e)) continue;
    const wanted = Array.isArray(e.requestedCheckpoints) && e.requestedCheckpoints.length
      ? e.requestedCheckpoints
      : (Array.isArray(e.reachableCheckpoints) ? e.reachableCheckpoints : []);
    for (const checkpoint of wanted) {
      if (!CHECKPOINTS.includes(checkpoint)) {
        skippedNames.push(`checkpoint ${JSON.stringify(checkpoint)} requested for ${e.id}: not one of ${CHECKPOINTS.join(', ')}`);
        continue;
      }
      const base = `${slugForPointId(e.id)}.${checkpoint}`;
      let id = base;
      let n = 2;
      while (usedIds.has(id)) { id = `${base}-${n}`; n += 1; }
      usedIds.add(id);
      observationPoints.push({
        id,
        checkpoint,
        stage: DEFAULT_STAGE_FOR_CHECKPOINT[checkpoint],
        reached: false,
        unreachedReason: NOT_REACHED,
        target: null,
        optLevel: null,
        tool: null,
      });
    }
  }

  const inv = isObject(rec.invocation) ? rec.invocation : {};
  const argv = Array.isArray(inv.argv) ? inv.argv.filter((t) => typeof t === 'string') : [];
  const optLevels = Array.isArray(inv.optLevels) ? inv.optLevels.filter((t) => OPT_LEVELS.has(t)) : [];
  const optLevel = optLevels.length === 1 ? optLevels[0] : null;

  const obs = isObject(rec.build?.observation) ? rec.build.observation : null;
  const pipelineLength = obs && Number.isInteger(obs.pipelineLength) ? obs.pipelineLength : null;
  const compile = pipelineLength !== null
    ? { observed: true, unobservedReason: null, target: null, optLevel, passesSeen: pipelineLength }
    : {
      observed: false,
      unobservedReason: 'no pass pipeline was observed: the driver spawns the compiler and records the invocation, and the record carries no pipeline listing',
      target: null,
      optLevel,
    };

  const linkedAction = inv.action === 'link' || inv.action === 'compile-and-link';
  const link = linkedAction
    ? {
      observed: false,
      unobservedReason: 'the driver spawns the linker and does not observe what runs inside it',
      linker: null,
      ltoMode: ltoModeFromArgv(argv),
      backendObserved: false,
      backendUnobservedReason: 'no component in this tree observed the LTO backend during the run that wrote this record',
      inputs: [],
    }
    : {
      observed: false,
      unobservedReason: `the invocation action is ${JSON.stringify(inv.action ?? null)}, which runs no link`,
      linker: null,
      ltoMode: 'none',
      backendObserved: false,
      backendUnobservedReason: null,
      inputs: [],
    };

  const artifacts = Array.isArray(rec.build?.artifacts) ? rec.build.artifacts : [];
  const first = artifacts.find((a) => isObject(a) && typeof a.path === 'string' && a.path.length > 0);
  const artifact = {
    observed: false,
    unobservedReason: 'the driver digests the artefact bytes and does not read its headers, so no artefact requirement was decided',
    format: null,
    machine: null,
    checks: [],
  };
  if (first) artifact.path = first.path;

  const findings = [];
  for (const f of Array.isArray(rec.findings) ? rec.findings : []) {
    if (!isObject(f) || typeof f.id !== 'string' || !FINDING_ID.test(f.id)) {
      fail('unrepresentable-finding',
        `the driver record carries a finding this form cannot express (${JSON.stringify(isObject(f) ? f.id : f)}); `
        + 'dropping it would turn a reported problem into a clean record, so nothing is emitted');
      continue;
    }
    const w = isObject(f.where) ? f.where : {};
    findings.push({
      id: f.id,
      severity: f.severity,
      title: f.title,
      detail: f.detail,
      where: { kind: w.kind, path: w.path ?? null, unit: w.unit ?? null, pass: w.pass ?? null },
      property: null,
      point: null,
    });
  }

  if (errors.length) return { ok: false, errors };

  const draft = {
    context,
    toolchain,
    ...(policy ? { policy } : {}),
    counts: { inputs: 1, checked: 1, skipped: skippedNames.length, skippedNames },
    observationPoints,
    properties: [],
    layers: { compile, link, artifact },
    findings,
    verdict: {
      unobserved: [
        'every security property the policy named: a driver record carries a reachability cross-check and no measurement, and an observation property needs a control',
        ...observationPoints.map((p) => `the checkpoint \`${p.checkpoint}\` for \`${p.id}\``),
      ],
    },
  };
  return { ok: true, draft, counts: { inputs: 1, checked: 1, skipped: skippedNames.length } };
}

function slugForPointId(id) {
  const s = String(id ?? 'property').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[^a-z0-9]+/, '');
  return s.length ? s : 'property';
}

function ltoModeFromArgv(argv) {
  let mode = 'none';
  for (const t of argv) {
    if (t === '-flto' || t === '-flto=full') mode = 'full';
    else if (t === '-flto=thin') mode = 'thin';
    else if (t.startsWith('-flto=')) mode = 'unknown';
  }
  return mode;
}

// ── the runnable positive control ───────────────────────────────────────────

/**
 * A draft that ends VERIFIED_CLEAN. Frozen, deterministic and clock-free: the
 * point of `--self-check` is that one command shows a record being written and
 * then accepted, so it must not depend on anything outside this file.
 */
export const SELF_CHECK_DRAFT = Object.freeze({
  context: {
    generatedAt: '1970-01-01T00:00:00Z',
    timeSource: 'SOURCE_DATE_EPOCH',
    sourceDateEpoch: 0,
  },
  toolchain: {
    digest: '0'.repeat(64),
    clang: '18.1.3',
    packages: [{ name: 'clang-18', version: '18.1.3' }],
  },
  counts: { inputs: 1, checked: 1, skipped: 0, skippedNames: [] },
  observationPoints: [
    { id: 'pre-opt', checkpoint: 'pre-opt-ir', stage: 'compile', reached: true, unreachedReason: null, target: 'x86_64-linux-gnu', optLevel: '-O2', tool: 'clang-18' },
    { id: 'compile-end', checkpoint: 'after-pass', stage: 'compile', reached: true, unreachedReason: null, target: 'x86_64-linux-gnu', optLevel: '-O2', tool: 'clang-18' },
  ],
  properties: [
    {
      id: 'prop.erasure.stack-buffer',
      kind: 'must-survive',
      scope: { functions: ['wipe_kept'], files: ['fixtures/secret.c'] },
      control: { unit: 'guard_volatile', state: 'PRESENT', count: { callSites: 1, oracle: 'call-site', naiveSymbolMatches: 2 } },
      history: [
        { point: 'pre-opt', phase: 'before', state: 'PRESENT', attribution: { pass: 'VerifierPass', unit: 'wipe_kept', unitKind: 'function', lineage: 'wipe_kept', seq: 1 }, count: { callSites: 1, oracle: 'call-site', naiveSymbolMatches: 2 } },
        { point: 'compile-end', phase: 'after', state: 'PRESENT', attribution: { pass: 'AnnotationRemarksPass', unit: 'wipe_kept', unitKind: 'function', lineage: 'wipe_kept', seq: 578 }, count: { callSites: 1, oracle: 'call-site', naiveSymbolMatches: 2 } },
      ],
      historyComplete: true,
      fate: 'LIVE',
    },
  ],
  layers: {
    compile: { observed: true, unobservedReason: null, target: 'x86_64-linux-gnu', optLevel: '-O2', passesSeen: 578, unitsTracked: 2 },
    link: { observed: true, unobservedReason: null, linker: 'ld.lld-18', ltoMode: 'none', backendObserved: true, backendUnobservedReason: null, inputs: [] },
    artifact: { observed: true, unobservedReason: null, path: 'build/secret.o', format: 'elf', machine: 'Advanced Micro Devices X86-64', checks: [{ require: 'nx', result: 'PASS', decidedBy: 'PT_GNU_STACK p_flags has no PF_X' }] },
  },
  findings: [],
});

// ── the runner ──────────────────────────────────────────────────────────────

function readJson(path) {
  const raw = readFileSync(path, 'utf8');
  return { raw, doc: JSON.parse(raw) };
}

export async function run(argv, log = console.log, errLog = console.error) {
  const flag = (name) => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
  };
  const selfCheck = argv.includes('--self-check');
  const fromDraft = flag('--from-draft');
  const fromDriver = flag('--from-driver-record');
  const out = flag('--out');
  const seal = argv.includes('--seal');

  const chosen = [selfCheck && '--self-check', fromDraft && '--from-draft', fromDriver && '--from-driver-record'].filter(Boolean);
  if (chosen.length !== 1) {
    errLog('usage: emit-observation.mjs (--self-check | --from-draft <file> | --from-driver-record <file>) [--out <file>] [--seal]');
    errLog(chosen.length === 0 ? 'no input was named' : `these are mutually exclusive: ${chosen.join(', ')}`);
    log('inputs=0 checked=0 skipped=0');
    return EXIT_INCOMPLETE;
  }

  let schema;
  try {
    schema = loadSchema();
  } catch (err) {
    errLog(`FATAL: the schema could not be read (${err.message}). This is a missing prerequisite, not a skip.`);
    return EXIT_TOOL_FAILED;
  }

  let draft;
  let counts = { inputs: 1, checked: 1, skipped: 0 };
  if (selfCheck) {
    draft = structuredClone(SELF_CHECK_DRAFT);
  } else {
    const path = fromDraft ?? fromDriver;
    let doc;
    try {
      ({ doc } = readJson(path));
    } catch (err) {
      errLog(`FATAL: ${path} could not be read as JSON (${err.code ?? err.message})`);
      log('inputs=0 checked=0 skipped=0');
      return EXIT_INCOMPLETE;
    }
    if (fromDriver) {
      const adapted = draftFromDriverRecord(doc);
      if (!adapted.ok) {
        log('inputs=1 checked=1 skipped=0');
        errLog(`REFUSED ${shortPath(path)}: this driver record cannot be expressed as an observation record`);
        for (const e of adapted.errors) errLog(`  ${e.reason}: ${e.message}`);
        return EXIT_INTEGRITY;
      }
      draft = adapted.draft;
      counts = adapted.counts;
    } else {
      draft = doc;
    }
  }

  const emitted = emitObservation(schema, draft);
  log(`inputs=${counts.inputs} checked=${counts.checked} skipped=${counts.skipped}`);
  if (!emitted.ok) {
    errLog(`REFUSED (${emitted.stage}): no record was written`);
    for (const e of emitted.errors) errLog(`  ${e}`);
    return EXIT_INTEGRITY;
  }

  let record = emitted.record;
  if (seal) {
    try {
      record = await sealObservation(record);
    } catch (err) {
      errLog(`FATAL: the record could not be sealed (${err.message})`);
      return EXIT_TOOL_FAILED;
    }
  }
  const text = `${JSON.stringify(record, null, 2)}\n`;

  if (out) {
    try {
      mkdirSync(dirname(out), { recursive: true });
      writeFileSync(out, text, 'utf8');
    } catch (err) {
      errLog(`FATAL: ${out} could not be written (${err.code ?? err.message})`);
      return EXIT_INCOMPLETE;
    }
    log(`wrote ${shortPath(out)} (${Buffer.byteLength(text, 'utf8')} bytes)`);
  } else {
    log(text.trimEnd());
  }
  // The record's verdict is a fact about the build; this command's exit code is
  // a fact about the emission. They are printed side by side so nobody has to
  // guess which one they are reading.
  log(`record verdict=${record.verdict.state} recordExitCode=${record.verdict.exitCode}; emission ok`);
  return EXIT_OK;
}

function shortPath(p) {
  const r = relative(process.cwd(), p);
  return (r && !r.startsWith('..') ? r : p).split(sep).join('/');
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  process.exit(await run(process.argv.slice(2)));
}
