#!/usr/bin/env node
// Independent verifier for evidence records and bundles.
//
// INDEPENDENCE
//
//   Nothing on the verification path imports `canon.mjs`. The canonical text
//   is re-derived here from the written rules, with a different shape of code
//   (an explicit serialiser rather than sort-then-stringify), because a
//   verifier that shares the generator's implementation agrees with it by
//   construction and therefore proves nothing about any record. The only place
//   `canon.mjs` is loaded is the optional cross-check inside `--self-test`,
//   which is reported as its own section and is not part of verifying anything.
//
//   The shared calibration is `testdata/digest-vectors.json`: input/output
//   pairs that both sides must reproduce. A verifier that reproduces all of
//   them has a calibrated canonicaliser; one that does not has a bug in its own
//   serialisation, not a finding about a record.
//
// EXIT CODES (interfaces.md §7)
//
//   0  everything asked for was checked and nothing was found
//   2  findings at or above the failure threshold
//   3  a check could not be completed — a missing file, an unreadable record,
//      a schema version this verifier does not know. Never conflated with 0.
//   4  the record is malformed: it cannot be canonicalised at all (a
//      non-integer number, say), so nothing downstream of it means anything.
//
// FINDING IDS
//
//   This component emits `VG-ART-05N`. The namespace is the artefact
//   verifier's (interfaces.md §2); the 050–069 band is reserved here for
//   record-internal checks so that no other component in the namespace
//   collides with it.

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findAbsolutePaths } from './paths.mjs';
import { auditDirectClockUse } from './clock.mjs';
import { reportCounts } from './counting.mjs';
import { assertNoSymlink, findSymlinks, SymlinkRefused } from './fsguard.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Re-derivation of the canonical text, written from the rules.
// ---------------------------------------------------------------------------

export class MalformedRecordError extends Error {
  constructor(message, where) {
    super(where ? `${message} (at ${where})` : message);
    this.name = 'MalformedRecordError';
    this.where = where ?? null;
  }
}

/** Rule 1: the top-level keys removed before digesting. `context` goes whole. */
const EXCLUDED = ['context', 'evidenceDigest'];

/** A key the language treats as an array index. Derived here, not imported. */
function isArrayIndexKey(k) {
  if (typeof k !== 'string' || k.length === 0 || k.length > 10) return false;
  if (!/^(0|[1-9][0-9]*)$/.test(k)) return false;
  return Number(k) < 4294967295;
}

function serialise(v, where) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  // Rule 3 is satisfied by construction: nothing here emits a space.
  if (t === 'string') return JSON.stringify(v);
  if (t === 'number') {
    // Rule 4.
    if (!Number.isFinite(v)) throw new MalformedRecordError(`non-finite number ${String(v)}`, where);
    if (!Number.isInteger(v)) {
      throw new MalformedRecordError(
        `non-integer number ${v}; a ratio is a pair of integer counts, and this is not ` +
          'a rounding question',
        where,
      );
    }
    if (!Number.isSafeInteger(v)) {
      throw new MalformedRecordError(`integer ${v} is outside the exact-integer range`, where);
    }
    return String(v);
  }
  if (Array.isArray(v)) {
    // Rule 2, second half: array order is significant and is never sorted.
    let s = '[';
    for (let i = 0; i < v.length; i++) {
      if (i > 0) s += ',';
      s += serialise(v[i], `${where}[${i}]`);
    }
    return `${s}]`;
  }
  if (t === 'object') {
    // Rule 2, first half: keys sort at every level, arrays of objects included.
    const keys = Object.keys(v).sort();
    let s = '{';
    for (let i = 0; i < keys.length; i++) {
      // A key a JS engine treats as an array index is moved to the front of the
      // property order ahead of every string key, so an implementation that
      // builds an object and stringifies it and one that emits the text
      // directly disagree on the bytes while both obey rule 2. The rule does
      // not say which wins, so the key is refused rather than guessed at.
      if (isArrayIndexKey(keys[i])) {
        throw new MalformedRecordError(
          `the key ${JSON.stringify(keys[i])} is an array index in JavaScript, and rule 2 does ` +
            'not determine the byte order for it',
          where,
        );
      }
      if (i > 0) s += ',';
      s += `${JSON.stringify(keys[i])}:${serialise(v[keys[i]], `${where}.${keys[i]}`)}`;
    }
    return `${s}}`;
  }
  throw new MalformedRecordError(`a value of type ${t} cannot appear in a record`, where);
}

/** The canonical text a digest is taken over, re-derived from the rules. */
export function rederiveCanonicalText(record) {
  let subject = record;
  if (record !== null && typeof record === 'object' && !Array.isArray(record)) {
    subject = {};
    for (const k of Object.keys(record)) {
      if (!EXCLUDED.includes(k)) subject[k] = record[k];
    }
  }
  return serialise(subject, '$');
}

/** Rule 5. */
export function rederiveDigest(record) {
  return createHash('sha256').update(rederiveCanonicalText(record), 'utf8').digest('hex');
}

// ---------------------------------------------------------------------------
// Record-level checks (evidence-v0).
// ---------------------------------------------------------------------------

const CONFIDENCE_BY_LEVEL = Object.freeze({
  'three-method': 'confirmed',
  'two-method': 'provisional',
  single: 'provisional',
  conflict: 'conflict',
  'stage-only': 'stage-only',
  'not-applicable': 'no-loss-observed',
  none: 'unresolved',
});

// A stage names the INTERVAL between the last checkpoint at which the property
// was seen and the first at which it was not. It is not a checkpoint name.
const STAGE_TABLE = Object.freeze([
  { last: null, first: 'preprocess', stage: 'preprocess', namesPass: false },
  { last: 'preprocess', first: 'ast', stage: 'ast', namesPass: false },
  { last: 'ast', first: 'ir-pre', stage: 'frontend-codegen', namesPass: false },
  { last: 'preprocess', first: 'ir-pre', stage: 'frontend-codegen', namesPass: false },
  { last: 'ir-pre', first: 'ir-post', stage: 'ir-pass', namesPass: true },
  { last: 'ir-post', first: 'asm', stage: 'backend', namesPass: false },
  { last: 'asm', first: 'artifact', stage: 'link', namesPass: false },
]);

/** The stage the interval maps to. Total: anything unlisted is `compile`. */
export function stageForInterval(lastSeen, firstMissing) {
  if (firstMissing === null) return null;
  const row = STAGE_TABLE.find((r) => r.last === lastSeen && r.first === firstMissing);
  return row ? row.stage : 'compile';
}

function finding(id, severity, title, detail, where = {}) {
  return {
    id,
    severity,
    title,
    detail,
    where: {
      kind: where.kind ?? 'artifact',
      path: where.path ?? null,
      unit: where.unit ?? null,
      pass: where.pass ?? null,
    },
  };
}

/**
 * Check one record. Does not touch the filesystem — see `verifyBundle` for the
 * checks that need the bytes on disk.
 *
 * @returns {{findings: object[], checked: string[], unchecked: string[]}}
 */
export function verifyRecord(record, opts = {}) {
  const findings = [];
  const checked = [];
  const unchecked = [];
  const path = opts.path ?? null;

  // 2. evidenceDigest matches a re-derivation under the rules.
  const recomputed = rederiveDigest(record);
  if (typeof record.evidenceDigest !== 'string') {
    findings.push(
      finding(
        'VG-ART-050',
        'high',
        'The record carries no evidenceDigest',
        `Re-derivation gives ${recomputed}; the record has no digest to compare it with.`,
        { path },
      ),
    );
  } else if (record.evidenceDigest !== recomputed) {
    findings.push(
      finding(
        'VG-ART-050',
        'critical',
        'evidenceDigest does not match the record it seals',
        `Recorded ${record.evidenceDigest}, re-derived ${recomputed}. This is a disagreement ` +
          'inside the evidence, not a tamper detection: nothing binds a record to an authority, ' +
          'so a record regenerated wholesale would agree with itself.',
        { path },
      ),
    );
  } else {
    checked.push('evidenceDigest');
  }

  // Absolute paths (interfaces.md §5).
  const leaks = findAbsolutePaths(record, { mode: opts.pathMode ?? 'strict' });
  if (leaks.length > 0) {
    findings.push(
      finding(
        'VG-ART-051',
        'medium',
        'The record carries an absolute path',
        leaks.map((l) => `${l.where} (${l.kind}): ${JSON.stringify(l.value)}`).join('; '),
        { path },
      ),
    );
  } else {
    checked.push('pathHygiene');
  }

  // command.argv is never empty.
  if (!record.command || !Array.isArray(record.command.argv)) {
    unchecked.push('command.argv');
  } else if (record.command.argv.length === 0) {
    findings.push(
      finding('VG-ART-052', 'medium', 'command.argv is empty', 'A record describes a compilation; its argv is never empty.', {
        kind: 'invocation',
        path,
      }),
    );
  } else {
    checked.push('command.argv');
  }

  const props = Array.isArray(record.properties) ? record.properties : [];
  if (props.length === 0) unchecked.push('properties');

  let observedFromStates = 0;
  for (const pr of props) {
    const pid = pr.propertyId ?? '(unnamed property)';
    const states = Array.isArray(pr.states) ? pr.states : [];
    observedFromStates += states.filter((s) => s.verdict !== 'UNOBSERVED').length;

    // 5. confidence is what the table maps agreement.level to.
    const level = pr.agreement?.level;
    if (level === undefined) {
      unchecked.push(`${pid}.agreement.level`);
    } else if (!(level in CONFIDENCE_BY_LEVEL)) {
      findings.push(
        finding('VG-ART-053', 'medium', 'Unknown agreement level', `${pid}: agreement.level ${JSON.stringify(level)} is not in the table.`, { path }),
      );
    } else if (pr.confidence !== CONFIDENCE_BY_LEVEL[level]) {
      findings.push(
        finding(
          'VG-ART-053',
          'high',
          'confidence disagrees with agreement.level',
          `${pid}: level ${level} maps to ${CONFIDENCE_BY_LEVEL[level]}, record says ${JSON.stringify(pr.confidence)}. ` +
            'The map is many-to-one, so only this direction is checked.',
          { path },
        ),
      );
    }

    // 3. firstLoss.stage is the stage the interval maps to; 6. a pass is named
    //    only when the stage is ir-pass.
    const idx = states.findIndex((s) => s.verdict === 'ABSENT');
    let lastSeen = null;
    if (idx > 0) {
      for (let k = idx - 1; k >= 0; k--) {
        if (states[k].verdict === 'PRESENT') {
          lastSeen = states[k].checkpoint;
          break;
        }
      }
    }
    const firstMissing = idx === -1 ? null : states[idx].checkpoint;
    const expectedStage = stageForInterval(lastSeen, firstMissing);
    const recordedStage = pr.firstLoss?.stage ?? null;
    if (states.length === 0) {
      unchecked.push(`${pid}.firstLoss`);
    } else if (recordedStage !== expectedStage) {
      findings.push(
        finding(
          'VG-ART-054',
          'high',
          'firstLoss.stage is not the stage the interval maps to',
          `${pid}: last PRESENT ${lastSeen ?? '(none)'} -> first ABSENT ${firstMissing ?? '(none)'} maps to ` +
            `${JSON.stringify(expectedStage)}, record says ${JSON.stringify(recordedStage)}. A stage names an ` +
            'interval, not a checkpoint.',
          { path },
        ),
      );
    }

    const namedPass = pr.firstLoss?.pass ?? null;
    if (namedPass !== null && recordedStage !== 'ir-pass') {
      findings.push(
        finding(
          'VG-ART-055',
          'high',
          'A pass is named for a stage that cannot attribute one',
          `${pid}: stage ${JSON.stringify(recordedStage)} names pass ${JSON.stringify(namedPass)}; only ir-pass may.`,
          { path, pass: namedPass },
        ),
      );
    }

    // Chain consistency: PRESENT after a loss needs an explicit REINTRODUCED.
    let lost = false;
    for (const s of states) {
      if (s.verdict === 'ABSENT') lost = true;
      else if (s.verdict === 'PRESENT' && lost && s.state !== 'REINTRODUCED') {
        findings.push(
          finding(
            'VG-ART-056',
            'high',
            'A property reappears as PRESENT after a loss without a REINTRODUCED marker',
            `${pid}: checkpoint ${JSON.stringify(s.checkpoint)} is PRESENT again with state ${JSON.stringify(s.state)}.`,
            { path },
          ),
        );
        lost = false;
      }
    }

    // fragility is range-checked only; it is a property of the whole grid and
    // cannot be derived from one bundle's states[].
    const fr = pr.fragility;
    if (fr && typeof fr === 'object') {
      const ok =
        Number.isInteger(fr.lost) && Number.isInteger(fr.evaluated) && fr.lost >= 0 && fr.lost <= fr.evaluated;
      if (!ok) {
        findings.push(
          finding('VG-ART-057', 'medium', 'fragility is out of range', `${pid}: ${JSON.stringify(fr)} violates 0 <= lost <= evaluated, both integers.`, { path }),
        );
      }
    } else {
      unchecked.push(`${pid}.fragility`);
    }
  }
  if (props.length > 0) checked.push('properties');

  // 4. coverage agrees with states[].
  const cov = record.coverage;
  if (!cov || !Number.isInteger(cov.observed) || !Number.isInteger(cov.planned)) {
    unchecked.push('coverage');
  } else {
    if (cov.observed !== observedFromStates) {
      findings.push(
        finding(
          'VG-ART-058',
          'high',
          'coverage.observed disagrees with states[]',
          `coverage.observed is ${cov.observed}; states[] holds ${observedFromStates} entries whose verdict is not UNOBSERVED.`,
          { path },
        ),
      );
    }
    if (cov.observed > cov.planned) {
      findings.push(
        finding('VG-ART-058', 'high', 'coverage.observed exceeds coverage.planned', `${cov.observed} > ${cov.planned}. planned comes from the manifest, never from what happened to run.`, { path }),
      );
    }
    const shortfall = cov.planned - cov.observed;
    const unresolved = Array.isArray(record.unresolved) ? record.unresolved : [];
    if (shortfall > 0 && unresolved.length === 0) {
      findings.push(
        finding('VG-ART-059', 'medium', 'A coverage shortfall is not accounted for', `${shortfall} planned checkpoint(s) were not observed and unresolved[] is empty.`, { path }),
      );
    }
    if (cov.observed === observedFromStates && cov.observed <= cov.planned) checked.push('coverage');
  }

  return { findings, checked, unchecked };
}

/**
 * Verify a bundle directory: the record, plus the checks that need bytes.
 *
 * @returns {{verdict: string, findings: object[], checked: string[], unchecked: string[], digest: string|null}}
 */
export function verifyBundle(dir, opts = {}) {
  const evidencePath = join(dir, 'evidence.json');
  // Inside a bundle the boundary is the bundle: a link above it is the
  // caller's problem and was already refused when the caller was handed the
  // path, but a link on `evidence.json` or on the artefact is this function's.
  try {
    assertNoSymlink(evidencePath, { boundary: dir, role: 'the record' });
  } catch (e) {
    if (!(e instanceof SymlinkRefused)) throw e;
    return {
      verdict: 'FINDINGS_PRESENT',
      findings: [
        finding('VG-ART-063', 'critical', 'A symbolic link on the path to the record', e.message, { path: 'evidence.json' }),
      ],
      checked: [],
      unchecked: ['*'],
      digest: null,
      error: e.message,
    };
  }
  if (!existsSync(evidencePath)) {
    return {
      verdict: 'VERIFICATION_INCOMPLETE',
      findings: [],
      checked: [],
      unchecked: ['evidence.json'],
      digest: null,
      error: `no evidence.json under ${dir}`,
    };
  }
  let record;
  try {
    record = JSON.parse(readFileSync(evidencePath, 'utf8'));
  } catch (e) {
    return {
      verdict: 'VERIFICATION_INCOMPLETE',
      findings: [],
      checked: [],
      unchecked: ['evidence.json'],
      digest: null,
      error: `evidence.json does not parse: ${e.message}`,
    };
  }
  if (record.schemaVersion !== 'evidence-v0') {
    return {
      verdict: 'UNSUPPORTED',
      findings: [],
      checked: [],
      unchecked: ['*'],
      digest: null,
      error: `schemaVersion ${JSON.stringify(record.schemaVersion)} is not evidence-v0`,
    };
  }

  let res;
  try {
    res = verifyRecord(record, { ...opts, path: 'evidence.json' });
  } catch (e) {
    if (e instanceof MalformedRecordError) {
      return {
        verdict: 'EVIDENCE_MISMATCH',
        findings: [],
        checked: [],
        unchecked: ['*'],
        digest: null,
        malformed: true,
        error: e.message,
      };
    }
    throw e;
  }
  const { findings, checked, unchecked } = res;

  // 1. artifact.sha256 matches the bytes on disk.
  const art = record.artifact;
  if (art && typeof art.path === 'string' && typeof art.sha256 === 'string') {
    const p = join(dir, art.path);
    if (!existsSync(p)) {
      unchecked.push('artifact.sha256');
      findings.push(
        finding('VG-ART-060', 'medium', 'The referenced artefact is not in the bundle', `${art.path} is missing; its digest could not be checked.`, {
          kind: 'artifact',
          path: art.path,
        }),
      );
    } else if (findSymlinks(p, { boundary: dir }).length > 0) {
      unchecked.push('artifact.sha256');
      findings.push(
        finding('VG-ART-063', 'critical', 'The referenced artefact is reached through a symbolic link', `${art.path} is, or is under, a link; its bytes were neither read nor hashed. A digest taken through a link is a true statement about a file the report does not name.`, {
          kind: 'artifact',
          path: art.path,
        }),
      );
    } else {
      const actual = createHash('sha256').update(readFileSync(p)).digest('hex');
      if (actual !== art.sha256) {
        findings.push(
          finding(
            'VG-ART-061',
            'critical',
            'The artefact does not match the record',
            `${art.path}: record says ${art.sha256}, bytes hash to ${actual}. This is a disagreement between ` +
              'the artefact and the evidence, not tamper detection.',
            { kind: 'artifact', path: art.path },
          ),
        );
      } else {
        checked.push('artifact.sha256');
      }
    }
  } else {
    unchecked.push('artifact.sha256');
  }

  // Cross-check against the bundle manifest when there is one.
  const manifestPath = join(dir, 'manifest.json');
  if (existsSync(manifestPath)) {
    try {
      const man = JSON.parse(readFileSync(manifestPath, 'utf8'));
      if (typeof man.evidenceDigest === 'string') {
        if (man.evidenceDigest !== record.evidenceDigest) {
          findings.push(
            finding('VG-ART-062', 'high', 'The manifest names a different evidenceDigest', `manifest.json says ${man.evidenceDigest}, evidence.json says ${record.evidenceDigest}.`, {
              path: 'manifest.json',
            }),
          );
        } else {
          checked.push('manifest.evidenceDigest');
        }
      }
    } catch {
      unchecked.push('manifest.json');
    }
  }

  // A field nobody could check is not a field that passed. Reporting
  // VERIFIED_CLEAN over an unchecked field is exactly the conflation of "we did
  // not look" with "it is clean" that the exit codes exist to prevent, so an
  // unchecked field lands on 3 rather than on 0.
  const verdict =
    findings.length > 0
      ? 'FINDINGS_PRESENT'
      : unchecked.length > 0
        ? 'VERIFICATION_INCOMPLETE'
        : 'VERIFIED_CLEAN';
  return { verdict, findings, checked, unchecked, digest: record.evidenceDigest ?? null };
}

// ---------------------------------------------------------------------------
// Self-test against the vectors.
// ---------------------------------------------------------------------------

export function loadVectors(file) {
  const p = file ?? join(HERE, 'testdata', 'digest-vectors.json');
  // A vector file reached through a link calibrates this verifier against
  // whatever is at the far end while the report names the near end.
  assertNoSymlink(p, { role: 'the vector file' });
  return JSON.parse(readFileSync(p, 'utf8'));
}

/**
 * Reproduce every vector with the re-derivation above, and, unless asked not
 * to, confirm the generator in `canon.mjs` produces the same bytes.
 *
 * `total` and `negativesTotal` are the counting contract's `inputs` for this
 * entry point. They can be zero — a vector file holding `{"vectors":[]}`
 * reproduces every one of its nought vectors — and the caller must not read
 * that as success. See counting.mjs.
 */
export async function selfTest({ crossCheck = true, file, log = () => {} } = {}) {
  const vec = loadVectors(file);
  const results = { total: 0, passed: 0, failed: [], negativesTotal: 0, negativesPassed: 0, cross: null };

  for (const v of vec.vectors) {
    results.total++;
    let text;
    let digest;
    try {
      text = rederiveCanonicalText(v.input);
      digest = createHash('sha256').update(text, 'utf8').digest('hex');
    } catch (e) {
      results.failed.push({ name: v.name, reason: `threw: ${e.message}` });
      continue;
    }
    if (text !== v.canonicalText) {
      results.failed.push({ name: v.name, reason: `canonicalText\n    want ${JSON.stringify(v.canonicalText)}\n    got  ${JSON.stringify(text)}` });
      continue;
    }
    if (digest !== v.digest) {
      results.failed.push({ name: v.name, reason: `digest want ${v.digest} got ${digest}` });
      continue;
    }
    results.passed++;
    log(`  ok   ${v.name}`);
  }

  for (const v of vec.mustFail ?? []) {
    results.negativesTotal++;
    let threw = null;
    try {
      rederiveCanonicalText(v.input);
    } catch (e) {
      threw = e;
    }
    if (threw) {
      results.negativesPassed++;
      log(`  ok   ${v.name} (rejected: ${threw.message.split('\n')[0].slice(0, 70)})`);
    } else {
      results.failed.push({ name: v.name, reason: 'expected the canonicaliser to refuse this input, it did not' });
    }
  }

  if (crossCheck) {
    const canon = await import('./canon.mjs');
    const mismatches = [];
    for (const v of vec.vectors) {
      const a = canon.canonicalJson(v.input);
      const d = canon.evidenceDigest(v.input);
      if (a !== v.canonicalText) mismatches.push(`${v.name}: canonicalJson ${JSON.stringify(a)}`);
      if (d !== v.digest) mismatches.push(`${v.name}: evidenceDigest ${d}`);
    }
    for (const v of vec.mustFail ?? []) {
      let threw = false;
      try {
        canon.canonicalJson(v.input);
      } catch {
        threw = true;
      }
      if (!threw) mismatches.push(`${v.name}: canon.mjs accepted an input it must refuse`);
    }
    results.cross = { checked: vec.vectors.length + (vec.mustFail?.length ?? 0), mismatches };
  }

  return results;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const SEVERITY_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

function findBundleDirs(root) {
  const out = [];
  if (existsSync(join(root, 'evidence.json'))) return [root];
  for (const e of readdirSync(root, { withFileTypes: true })) {
    if (!e.isDirectory()) continue;
    const d = join(root, e.name);
    if (existsSync(join(d, 'evidence.json'))) out.push(d);
  }
  return out.sort();
}

function usage() {
  return [
    'usage: node verify.mjs <mode>',
    '',
    '  --self-test [--no-cross-check]   reproduce every vector in testdata/',
    '  --bundle <dir>                   verify one bundle directory',
    '  --bundles <dir>                  verify every bundle directory under <dir>',
    '  --record <file>                  verify one evidence.json, no filesystem checks',
    '  --digest <file>                  print the re-derived digest of a JSON file',
    '  --clock-audit <dir>              fail if anything but clock.mjs reads a clock',
    '  --paths <file> [--mode m]        report absolute paths in a JSON file',
    '',
    '  --json                           machine-readable output',
    '  --fail-on <low|medium|high|critical>   threshold for exit 2 (default low)',
    '  --allow-empty                    an empty input set is the expected outcome',
    '  --link-boundary <dir>            stop the symlink walk at <dir>',
    '',
    'Every mode prints `inputs=N checked=N skipped=S`, and N=0 exits 3 unless',
    '--allow-empty was passed. A symlink anywhere on the path to an input is',
    'refused rather than followed.',
    '',
    'exit: 0 clean, 2 findings at/above threshold, 3 could not complete, 4 malformed record',
  ].join('\n');
}

/**
 * The argv reader, the counting reporter and the link guard, built once and
 * handed to whichever mode runs.
 *
 * These four used to be closures at the top of `main`, which is what made every
 * mode below a branch of one 217-line body: seven modes deep, ten-odd decision
 * points, and no way to read the exit-code contract of one of them without
 * scrolling past the other six. Each mode is now its own function taking this,
 * and `main` is the dispatch table it always claimed to be.
 */
function cliContext(argv) {
  const flag = (name) => argv.includes(name);
  const val = (name, dflt = null) => {
    const i = argv.indexOf(name);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : dflt;
  };
  const asJson = flag('--json');
  const allowEmpty = flag('--allow-empty');
  const failOn = SEVERITY_ORDER[val('--fail-on', 'low')] ?? 0;
  const counts = (inputs, checked, skipped, what, where = null) =>
    reportCounts({ inputs, checked, skipped, allowEmpty, what, where }, { json: asJson });
  /**
   * Refuse a linked input. Returns the exit code to use, or `null` when the
   * path is fine. A link is a finding (2), not an incompleteness (3): the tool
   * could have read something, and the reason it did not is that what it would
   * have read is not what it was asked for.
   */
  const refuseLink = (p, role) => {
    if (!p) return null;
    try {
      assertNoSymlink(p, { role, boundary: val('--link-boundary') });
      return null;
    } catch (e) {
      if (!(e instanceof SymlinkRefused)) throw e;
      process.stderr.write(`${e.message}\n`);
      counts(1, 0, 1, 'input', p);
      return 2;
    }
  };
  return { flag, val, asJson, failOn, counts, refuseLink };
}

/** `--self-test`: reproduce every calibration vector. */
async function runSelfTest({ flag, val, asJson, counts }) {
  const r = await selfTest({
    crossCheck: !flag('--no-cross-check'),
    file: val('--vectors'),
    log: asJson ? () => {} : (s) => process.stdout.write(`${s}\n`),
  });
  if (asJson) {
    process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
  } else {
    process.stdout.write(`\nvectors: ${r.passed}/${r.total} reproduced, must-fail: ${r.negativesPassed}/${r.negativesTotal} refused\n`);
    if (r.cross) {
      process.stdout.write(
        r.cross.mismatches.length === 0
          ? `cross-check: canon.mjs agrees on all ${r.cross.checked} vectors\n`
          : `cross-check: ${r.cross.mismatches.length} disagreement(s):\n  ${r.cross.mismatches.join('\n  ')}\n`,
      );
    }
    for (const f of r.failed) process.stdout.write(`  FAIL ${f.name}: ${f.reason}\n`);
  }
  // A vector file with nothing in it reproduced every one of its nought
  // vectors and exited 0, from the day this file was written until the day
  // the counting contract was applied to it. `inputs` is both halves of the
  // file — the vectors and the must-fail inputs — because a file that lost
  // one half is as empty a calibration as one that lost both.
  //
  // Every vector that was loaded was examined, so `checked` is `inputs` and
  // `skipped` is nought: a vector that failed to reproduce was checked, and
  // calling it skipped would hide a failure inside a count that reads as
  // housekeeping.
  const inputs = r.total + r.negativesTotal;
  const settled = counts(inputs, inputs, 0, 'vector', val('--vectors') ?? 'testdata/digest-vectors.json');
  const bad = r.failed.length > 0 || (r.cross && r.cross.mismatches.length > 0);
  if (bad) return 3;
  return settled.code ?? 0;
}

/** `--clock-audit`: fail if anything but clock.mjs reads a clock. */
function runClockAudit({ val, asJson, counts }) {
  const dir = val('--clock-audit', HERE);
  const r = auditDirectClockUse(resolve(dir));
  if (asJson) process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
  else {
    process.stdout.write(`clock audit: ${r.filesExamined} of ${r.filesScanned} file(s) examined, ${r.sites.length} direct clock read(s)\n`);
    for (const s of r.sites) process.stdout.write(`  ${s.file}:${s.line}  ${s.kind}  ${s.text}\n`);
  }
  // An empty scan is not a clean scan. Nought findings out of nought files
  // read is the shape of a guard pointed at the wrong directory, and returning
  // 0 for it is how it stays pointed there. The emptiness test now lives in
  // counting.mjs so that this mode and every other one share it.
  // `filesScanned` counts the exempt file too; `filesExamined` is what was
  // read. The difference is the skip, and it is named rather than absorbed.
  const settled = counts(r.filesScanned, r.filesExamined, r.filesScanned - r.filesExamined, 'file', dir);
  if (r.sites.length > 0) return 2;
  return settled.code ?? 0;
}

/** `--paths`: report absolute paths in a JSON file. */
function runPaths({ val, asJson, counts, refuseLink }) {
  const f = val('--paths');
  const guard = refuseLink(f, 'the file to scan');
  if (guard !== null) return guard;
  if (!f || !existsSync(f)) {
    process.stderr.write(`cannot read ${f}\n`);
    counts(1, 0, 1, 'file');
    return 3;
  }
  const leaks = findAbsolutePaths(JSON.parse(readFileSync(f, 'utf8')), { mode: val('--mode', 'strict') });
  if (asJson) process.stdout.write(`${JSON.stringify(leaks, null, 2)}\n`);
  else {
    process.stdout.write(`${leaks.length} absolute path(s)\n`);
    for (const l of leaks) process.stdout.write(`  ${l.where} (${l.in}, ${l.kind}): ${JSON.stringify(l.value)}\n`);
  }
  const settled = counts(1, 1, 0, 'file', f);
  if (leaks.length > 0) return 2;
  return settled.code ?? 0;
}

/** `--digest`: print the re-derived digest of a JSON file. */
function runDigest({ val, counts, refuseLink }) {
  const f = val('--digest');
  const guard = refuseLink(f, 'the file to digest');
  if (guard !== null) return guard;
  if (!f || !existsSync(f)) {
    process.stderr.write(`cannot read ${f}\n`);
    counts(1, 0, 1, 'file');
    return 3;
  }
  try {
    process.stdout.write(`${rederiveDigest(JSON.parse(readFileSync(f, 'utf8')))}\n`);
    const settled = counts(1, 1, 0, 'file', f);
    return settled.code ?? 0;
  } catch (e) {
    process.stderr.write(`malformed record: ${e.message}\n`);
    counts(1, 0, 1, 'file', f);
    return 4;
  }
}

/** Read and parse the record named by `--record`, or the exit code to use. */
function readRecord(f, counts) {
  if (!f || !existsSync(f)) {
    process.stderr.write(`cannot read ${f}\n`);
    counts(1, 0, 1, 'record');
    return { code: 3 };
  }
  try {
    return { rec: JSON.parse(readFileSync(f, 'utf8')) };
  } catch (e) {
    process.stderr.write(`does not parse: ${e.message}\n`);
    counts(1, 0, 1, 'record', f);
    return { code: 3 };
  }
}

/** `--record`: verify one evidence.json, no filesystem checks. */
function runRecord({ val, asJson, failOn, counts, refuseLink }) {
  const f = val('--record');
  const guard = refuseLink(f, 'the record');
  if (guard !== null) return guard;
  const read = readRecord(f, counts);
  if (read.code !== undefined) return read.code;
  let r;
  try {
    r = verifyRecord(read.rec, { path: f });
  } catch (e) {
    process.stderr.write(`malformed record: ${e.message}\n`);
    counts(1, 0, 1, 'record', f);
    return 4;
  }
  if (asJson) process.stdout.write(`${JSON.stringify(r, null, 2)}\n`);
  else {
    process.stdout.write(`checked: ${r.checked.join(', ') || '(nothing)'}\n`);
    if (r.unchecked.length) process.stdout.write(`unchecked: ${r.unchecked.join(', ')}\n`);
    for (const x of r.findings) process.stdout.write(`  [${x.severity}] ${x.id} ${x.title}\n    ${x.detail}\n`);
  }
  const settled = counts(1, 1, 0, 'record', f);
  if (r.findings.some((x) => SEVERITY_ORDER[x.severity] >= failOn)) return 2;
  // A field nobody could check is not a field that passed. `verifyBundle`
  // has always said so by returning VERIFICATION_INCOMPLETE; this mode used
  // to return 0 over the same unchecked list, so the same record answered
  // differently depending on which flag was used to look at it.
  if (r.unchecked.length > 0) return 3;
  return settled.code ?? 0;
}

/** One line per bundle, on the human-readable path. */
function printBundle(name, r) {
  const n = r.findings.length;
  process.stdout.write(`${n === 0 ? 'ok  ' : 'FAIL'} ${name}  ${r.verdict}  digest=${(r.digest ?? '-').slice(0, 16)}  checked=${r.checked.length} unchecked=${r.unchecked.length}\n`);
  for (const f of r.findings) process.stdout.write(`       [${f.severity}] ${f.id} ${f.title}\n         ${f.detail}\n`);
  if (r.error) process.stdout.write(`       ${r.error}\n`);
}

/** `--bundle` / `--bundles`: verify one bundle directory, or every one under a root. */
function runBundles({ flag, val, asJson, failOn, counts, refuseLink }) {
  const given = val('--bundle') ?? val('--bundles');
  const guard = refuseLink(given, 'the bundle directory');
  if (guard !== null) return guard;
  const root = resolve(given);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    process.stderr.write(`not a directory: ${root}\n`);
    counts(0, 0, 0, 'bundle', root);
    return 3;
  }
  const dirs = flag('--bundle') ? [root] : findBundleDirs(root);
  if (dirs.length === 0) {
    process.stderr.write(`no bundle directories under ${root}\n`);
    const settled = counts(0, 0, 0, 'bundle', root);
    return settled.code ?? 0;
  }
  const report = [];
  let worst = 0;
  let incomplete = 0;
  let malformed = 0;
  for (const d of dirs) {
    const r = verifyBundle(d, {});
    const name = d.split(sep).pop();
    report.push({ bundle: name, ...r });
    if (r.malformed) malformed++;
    else if (r.verdict === 'VERIFICATION_INCOMPLETE' || r.verdict === 'UNSUPPORTED') incomplete++;
    for (const f of r.findings) worst = Math.max(worst, SEVERITY_ORDER[f.severity] + 1);
    if (!asJson) printBundle(name, r);
  }
  if (asJson) process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else process.stdout.write(`\n${dirs.length} bundle(s): ${report.filter((r) => r.findings.length === 0 && !r.error).length} clean, ${report.filter((r) => r.findings.length > 0).length} with findings, ${incomplete} incomplete, ${malformed} malformed\n`);
  const settled = counts(dirs.length, dirs.length - malformed, malformed, 'bundle', root);
  if (malformed > 0) return 4;
  if (worst > failOn) return 2;
  if (incomplete > 0) return 3;
  return settled.code ?? 0;
}

async function main(argv) {
  const cli = cliContext(argv);

  if (argv.length === 0 || cli.flag('--help') || cli.flag('-h')) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }

  // Order matters and is the order it always was: the first flag present wins.
  if (cli.flag('--self-test')) return runSelfTest(cli);
  if (cli.flag('--clock-audit')) return runClockAudit(cli);
  if (cli.flag('--paths')) return runPaths(cli);
  if (cli.flag('--digest')) return runDigest(cli);
  if (cli.flag('--record')) return runRecord(cli);
  if (cli.flag('--bundle') || cli.flag('--bundles')) return runBundles(cli);

  process.stderr.write(`${usage()}\n`);
  return 3;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      // A refused link is an answer, not a crash: the tool could have read
      // something and declined to, because what it would have read is not what
      // it was asked for. That is a finding, and 2 is what a finding exits.
      if (e instanceof SymlinkRefused) {
        process.stderr.write(`${e.message}\n`);
        process.exit(2);
      }
      process.stderr.write(`${e.stack ?? e}\n`);
      process.exit(3);
    },
  );
}
