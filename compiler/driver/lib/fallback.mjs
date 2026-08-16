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
import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

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
  const fb = readFallbackPolicy(policy);
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
  const shippingProfile = normalised.optLevels.length > 0
    ? normalised.optLevels[normalised.optLevels.length - 1]
    : '-O0';

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
