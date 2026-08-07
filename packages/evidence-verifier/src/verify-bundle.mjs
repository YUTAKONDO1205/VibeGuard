// Verify an evidence-carrying artefact bundle.
//
// ── WHAT THIS ANSWERS, AND WHAT IT CANNOT ───────────────────────────────────
//
// The question is "do the files in this directory agree with each other, and
// does the record agree with the artefact it names?" Every check below is a
// re-derivation from bytes on disk, so a disagreement is a fact about the
// bundle rather than an opinion about it.
//
// It is NOT tamper detection, and the difference is not a technicality:
//
//   * a MODIFIED bundle is caught, because the modification makes two things
//     that were written together stop matching;
//   * a REGENERATED bundle is not caught, and cannot be. Every digest here is
//     computed from the bundle's own contents, so a bundle rebuilt from
//     different inputs agrees with itself perfectly and verifies clean —
//     correctly, given the question. Closing that needs a signature over the
//     canonical form, a key, and a way to distribute the public half; none of
//     the three exists in this package. Anyone who can write the directory can
//     write a bundle that passes.
//
// That limit is reported in the result as `limits[]` and printed by the CLI on
// every clean run, so a reader who never opens the README still meets it.
//
// ── WHICH BYTES ARE COVERED ─────────────────────────────────────────────────
//
//   every byte of every file except manifest.json   manifest.files[].sha256
//   manifest.json's meaning                         manifest.bundleDigest
//   manifest.json's context subtree                 manifest.contextDigest
//   manifest.json's insignificant whitespace        NOT COVERED, on purpose
//
// The last row is what a canonical form IS: reformatting a JSON file does not
// change what it claims, and a check that reddened on an indent would be
// telling the truth about bytes and lying about evidence. A file also cannot
// commit to its own bytes — only to its own meaning.
//
// ── FINDING IDS ─────────────────────────────────────────────────────────────
//
//   VG-ART-050  the record's evidenceDigest does not seal the record  (shared)
//   VG-ART-060  the artefact the record names is not in the bundle    (shared)
//   VG-ART-061  the artefact's bytes do not hash to what the record says (shared)
//   VG-ART-062  the manifest names a different evidenceDigest         (shared)
//   VG-ART-080  bundleDigest does not match the manifest it seals
//   VG-ART-081  the manifest's two copies of evidenceDigest disagree
//   VG-ART-082  the manifest lists no files, so it commits to nothing
//   VG-ART-083  a file the manifest lists is missing from the bundle
//   VG-ART-084  a listed file's length differs — truncated or extended
//   VG-ART-085  a listed file's content differs
//   VG-ART-086  the bundle holds a file the manifest does not list
//   VG-ART-087  the manifest and the record name different artefacts
//   VG-ART-088  a measurement's control count is zero
//   VG-ART-089  a verdict and its effect count disagree on zero-vs-nonzero
//   VG-ART-090  a state name outside the six-state vocabulary
//   VG-ART-091  REINTRODUCED with no preceding loss in the same history
//   VG-ART-092  contextDigest does not match the context it commits to
//
// The four marked `(shared)` name conditions the toolchain-side verifier
// already names. Reusing the id is deliberate: one condition, one id.

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

import {
  MalformedRecordError,
  rederiveCanonicalTextRaw,
  rederiveDigest,
  sha256Hex,
} from './rederive.mjs';

export const BUNDLE_SCHEMA_VERSION = 'evidence-bundle-v0';
export const RECORD_SCHEMA_VERSION = 'evidence-v0';
export const EVIDENCE_FILE = 'evidence.json';
export const MANIFEST_FILE = 'manifest.json';
export const BUNDLE_SELF_DIGEST_KEY = 'bundleDigest';

export const VERDICT = Object.freeze({
  CLEAN: 'VERIFIED_CLEAN',
  FINDINGS: 'FINDINGS_PRESENT',
  INCOMPLETE: 'VERIFICATION_INCOMPLETE',
  UNSUPPORTED: 'UNSUPPORTED',
  MALFORMED: 'EVIDENCE_MISMATCH',
});

export const SEVERITY_ORDER = Object.freeze({ low: 0, medium: 1, high: 2, critical: 3 });

/** The six states of schema/interfaces.md section 3. Listed here, not imported. */
const PROPERTY_STATES = new Set([
  'PRESENT',
  'ABSENT',
  'LOST',
  'REINTRODUCED',
  'NOT_APPLICABLE',
  'NOT_OBSERVED',
]);

/**
 * What this verifier cannot see, stated on every run rather than in a footnote.
 * Order matters: the first one is the one people assume is covered.
 */
export const LIMITS = Object.freeze([
  'A bundle that was REGENERATED is not detected. Every digest here is computed from the ' +
    "bundle's own contents, so a bundle rebuilt from different inputs is internally consistent " +
    'and verifies clean. Detecting it requires a signature over the canonical form by a key the ' +
    'forger does not hold; there is none in this package, so anyone who can write the bundle ' +
    'directory can write a bundle that passes.',
  'A change confined to insignificant whitespace in manifest.json is not detected, because the ' +
    'manifest commits to its canonical MEANING and a file cannot commit to its own bytes. Every ' +
    'other file in the bundle is covered byte-for-byte by manifest.files[].',
  'The record\'s internal semantics — the confidence table, the stage table, coverage against ' +
    'states[] — are the toolchain-side verifier\'s job and are not re-checked here. What this ' +
    'package checks is the BINDING between the artefact, the record and the manifest.',
]);

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

function posixRelative(root, abs) {
  return relative(root, abs).split(sep).join('/');
}

/** Every regular file under `dir`, as sorted POSIX-relative paths. */
function walk(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const abs = join(current, entry.name);
      if (entry.isDirectory()) stack.push(abs);
      else if (entry.isFile()) out.push(posixRelative(dir, abs));
    }
  }
  return out.sort();
}

function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'));
}

/**
 * The state and oracle checks, re-derived here rather than imported from the
 * generator. Section 3's rule — keep the WHOLE sequence, never stop at the
 * first loss — is why this walks to the end instead of using `findIndex`.
 *
 * @param {Record<string, unknown>} record
 * @param {string[]} checked
 * @param {string[]} unchecked
 * @returns {object[]} findings
 */
function checkStatesAndOracle(record, checked, unchecked) {
  const findings = [];
  const props = Array.isArray(record?.properties) ? record.properties : [];
  if (props.length === 0) {
    unchecked.push('properties');
    return findings;
  }

  let countsSeen = 0;
  for (const property of props) {
    const pid = typeof property?.propertyId === 'string' ? property.propertyId : '(unnamed)';
    const states = Array.isArray(property?.states) ? property.states : [];
    let everGone = false;

    for (let i = 0; i < states.length; i += 1) {
      const entry = states[i] ?? {};
      const explicit = typeof entry.state === 'string' ? entry.state : null;
      const verdict = typeof entry.verdict === 'string' ? entry.verdict : null;
      const state = explicit ?? (verdict === 'UNOBSERVED' ? 'NOT_OBSERVED' : verdict);

      if (state !== null && !PROPERTY_STATES.has(state)) {
        findings.push(
          finding(
            'VG-ART-090',
            'high',
            'A state name is outside the property-state vocabulary',
            `${pid}: checkpoint ${JSON.stringify(entry.checkpoint ?? null)} is ${JSON.stringify(state)}. ` +
              `The vocabulary is ${[...PROPERTY_STATES].join(', ')}; a name outside it means ` +
              '"we did not see it" and "it is not there" have been merged somewhere upstream.',
            { path: EVIDENCE_FILE },
          ),
        );
      }

      if (state === 'REINTRODUCED' && !everGone) {
        findings.push(
          finding(
            'VG-ART-091',
            'high',
            'REINTRODUCED with no preceding loss',
            `${pid}: checkpoint ${JSON.stringify(entry.checkpoint ?? null)} claims the effect was ` +
              'reconstructed, but nothing earlier in this history recorded it going missing. ' +
              'The whole sequence is kept precisely so this can be checked.',
            { path: EVIDENCE_FILE },
          ),
        );
      }
      // The walk does not stop here. A history is PRESENT, LOST, REINTRODUCED,
      // LOST often enough that stopping at the first loss reports the one a
      // later pass undid and drops the one that reached the artefact.
      if (state === 'ABSENT' || state === 'LOST') everGone = true;

      const effect = entry.effect;
      const control = entry.control;
      if (!Number.isInteger(effect) || !Number.isInteger(control)) {
        unchecked.push(`${pid}.states[${i}].oracle`);
        continue;
      }
      countsSeen += 1;

      if (control === 0) {
        findings.push(
          finding(
            'VG-ART-088',
            'high',
            'A measurement whose control fell to zero',
            `${pid}: checkpoint ${JSON.stringify(entry.checkpoint ?? null)} reports control=0. ` +
              'Every fixture carries a control whose effect cannot be optimised away, so a zero ' +
              'there means the harness measured nothing — a broken measurement, not a finding ' +
              'about the subject. Reporting the subject from such a run is how a false loss gets ' +
              'a plausible story attached.',
            { path: EVIDENCE_FILE },
          ),
        );
        continue;
      }
      if (control < 0 || effect < 0) {
        findings.push(
          finding(
            'VG-ART-089',
            'high',
            'A negative call-site count',
            `${pid}: effect=${effect} control=${control}. These count call sites and cannot be negative.`,
            { path: EVIDENCE_FILE },
          ),
        );
        continue;
      }
      if (verdict === 'PRESENT' && effect === 0) {
        findings.push(
          finding(
            'VG-ART-089',
            'high',
            'A verdict and its effect count disagree on zero-versus-nonzero',
            `${pid}: checkpoint ${JSON.stringify(entry.checkpoint ?? null)} is PRESENT with ` +
              'effect=0. The verdict was not written by the measurement it is attached to.',
            { path: EVIDENCE_FILE },
          ),
        );
      } else if (verdict === 'ABSENT' && effect !== 0) {
        findings.push(
          finding(
            'VG-ART-089',
            'high',
            'A verdict and its effect count disagree on zero-versus-nonzero',
            `${pid}: checkpoint ${JSON.stringify(entry.checkpoint ?? null)} is ABSENT with ` +
              `effect=${effect}, which is not zero.`,
            { path: EVIDENCE_FILE },
          ),
        );
      }
    }
  }

  if (countsSeen > 0) checked.push('oracle.controls');
  checked.push('properties.states');
  return findings;
}

/**
 * Verify one bundle directory.
 *
 * @param {string} dir
 * @param {{}} [opts]
 * @returns {{
 *   dir: string, verdict: string, findings: object[], checked: string[],
 *   unchecked: string[], evidenceDigest: string|null, bundleDigest: string|null,
 *   limits: readonly string[], error?: string, malformed?: boolean,
 * }}
 */
export function verifyBundle(dir, opts = {}) {
  const base = {
    dir,
    findings: [],
    checked: [],
    unchecked: [],
    evidenceDigest: null,
    bundleDigest: null,
    limits: LIMITS,
  };

  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    return { ...base, verdict: VERDICT.INCOMPLETE, unchecked: ['*'], error: `not a directory: ${dir}` };
  }

  const onDisk = walk(dir);
  if (onDisk.length === 0) {
    // An EMPTY bundle. Not clean, not "nothing to do": a directory with no
    // files makes no claim, and a verifier that answers "verified" to no claim
    // is the empty-scan failure wearing a different hat.
    return {
      ...base,
      verdict: VERDICT.INCOMPLETE,
      unchecked: ['*'],
      error:
        `${dir} contains no files. An empty bundle carries no evidence, so there is nothing to ` +
        'verify — which is a different answer from "verified", and must not be reported as one.',
    };
  }

  const findings = [];
  const checked = [];
  const unchecked = [];

  // ── The manifest ──────────────────────────────────────────────────────────
  const manifestPath = join(dir, MANIFEST_FILE);
  let manifest = null;
  if (!existsSync(manifestPath)) {
    unchecked.push(MANIFEST_FILE, 'files[]', 'bundleDigest', 'contextDigest');
  } else {
    try {
      manifest = readJson(manifestPath);
    } catch (e) {
      return {
        ...base,
        verdict: VERDICT.INCOMPLETE,
        unchecked: ['*'],
        error: `${MANIFEST_FILE} does not parse: ${e.message}`,
      };
    }
    if (manifest?.schemaVersion !== BUNDLE_SCHEMA_VERSION) {
      return {
        ...base,
        verdict: VERDICT.UNSUPPORTED,
        unchecked: ['*'],
        error:
          `${MANIFEST_FILE} declares schemaVersion ${JSON.stringify(manifest?.schemaVersion)}, ` +
          `and this verifier only knows ${BUNDLE_SCHEMA_VERSION}. Refusing to guess: a verifier ` +
          'that checks an unknown schema on a best-effort basis reports a pass it has not earned.',
      };
    }
  }

  if (manifest) {
    // bundleDigest — the manifest sealing itself.
    let recomputed = null;
    try {
      recomputed = rederiveDigest(manifest, { selfKey: BUNDLE_SELF_DIGEST_KEY });
    } catch (e) {
      if (e instanceof MalformedRecordError) {
        return {
          ...base,
          verdict: VERDICT.MALFORMED,
          malformed: true,
          unchecked: ['*'],
          error: `${MANIFEST_FILE} cannot be canonicalised: ${e.message}`,
        };
      }
      throw e;
    }
    base.bundleDigest = manifest.bundleDigest ?? null;
    if (typeof manifest.bundleDigest !== 'string') {
      findings.push(
        finding('VG-ART-080', 'high', 'The manifest carries no bundleDigest', `Re-derivation gives ${recomputed}; the manifest has no digest to compare it with.`, {
          path: MANIFEST_FILE,
        }),
      );
    } else if (manifest.bundleDigest !== recomputed) {
      findings.push(
        finding(
          'VG-ART-080',
          'critical',
          'bundleDigest does not match the manifest it seals',
          `Recorded ${manifest.bundleDigest}, re-derived ${recomputed}. The manifest was changed ` +
            'after it was sealed, or was sealed by something that does not implement the rules.',
          { path: MANIFEST_FILE },
        ),
      );
    } else {
      checked.push('bundleDigest');
    }

    // contextDigest — the field that closes the hole rule 1 opens.
    if (typeof manifest.contextDigest !== 'string') {
      unchecked.push('contextDigest');
    } else {
      let actual = null;
      try {
        actual = sha256Hex(Buffer.from(rederiveCanonicalTextRaw(manifest.context ?? null), 'utf8'));
      } catch (e) {
        actual = `uncanonicalisable: ${e.message}`;
      }
      if (actual !== manifest.contextDigest) {
        findings.push(
          finding(
            'VG-ART-092',
            'high',
            'contextDigest does not match the context it commits to',
            `Recorded ${manifest.contextDigest}, re-derived ${actual}. Rule 1 keeps \`context\` out ` +
              'of every other digest, so this field is the only thing standing between the ' +
              'volatile block and a silent edit.',
            { path: MANIFEST_FILE },
          ),
        );
      } else {
        checked.push('contextDigest');
      }
    }

    // The two copies of the record digest.
    const outer = manifest.evidenceDigest ?? null;
    const inner = manifest.binds?.evidenceDigest ?? null;
    if (typeof outer !== 'string' || typeof inner !== 'string') {
      unchecked.push('manifest.evidenceDigest');
    } else if (outer !== inner) {
      findings.push(
        finding(
          'VG-ART-081',
          'high',
          "The manifest's two copies of evidenceDigest disagree",
          `Top level says ${outer}, binds.evidenceDigest says ${inner}. Rule 1 excludes the ` +
            'top-level copy from bundleDigest, so it is the editable one; the inner copy is ' +
            'inside the digest. They disagreeing means the outer one was moved.',
          { path: MANIFEST_FILE },
        ),
      );
    } else {
      checked.push('manifest.evidenceDigest');
    }

    // files[] — the byte coverage.
    const files = Array.isArray(manifest.files) ? manifest.files : null;
    if (files === null || files.length === 0) {
      findings.push(
        finding(
          'VG-ART-082',
          'high',
          'The manifest lists no files',
          'A manifest with an empty files[] commits to nothing. Every file in the bundle except ' +
            'the manifest itself is supposed to be listed with its digest and its length.',
          { path: MANIFEST_FILE },
        ),
      );
    } else {
      const listed = new Set();
      for (const entry of files) {
        const rel = typeof entry?.path === 'string' ? entry.path : null;
        if (rel === null) {
          findings.push(
            finding('VG-ART-082', 'high', 'A files[] entry has no path', JSON.stringify(entry), {
              path: MANIFEST_FILE,
            }),
          );
          continue;
        }
        listed.add(rel);
        const abs = join(dir, rel);
        if (!existsSync(abs)) {
          findings.push(
            finding(
              'VG-ART-083',
              'critical',
              'A file the manifest lists is missing from the bundle',
              `${rel} is listed with digest ${entry.sha256} and ${entry.bytes} byte(s), and is not there.`,
              { path: rel },
            ),
          );
          continue;
        }
        const bytes = readFileSync(abs);
        if (Number.isInteger(entry.bytes) && bytes.length !== entry.bytes) {
          findings.push(
            finding(
              'VG-ART-084',
              'critical',
              'A listed file has a different length',
              `${rel}: manifest says ${entry.bytes} byte(s), the file is ${bytes.length}. A copy ` +
                'that stopped early and an edit have different causes, which is why the length is ' +
                'recorded next to the digest instead of being left implied by it.',
              { path: rel },
            ),
          );
          continue;
        }
        const actual = sha256Hex(bytes);
        if (actual !== entry.sha256) {
          findings.push(
            finding(
              'VG-ART-085',
              'critical',
              'A listed file has different content',
              `${rel}: manifest says ${entry.sha256}, the bytes hash to ${actual}.`,
              { path: rel },
            ),
          );
          continue;
        }
      }
      checked.push('files[]');

      for (const rel of onDisk) {
        if (rel === MANIFEST_FILE) continue;
        if (listed.has(rel)) continue;
        findings.push(
          finding(
            'VG-ART-086',
            'high',
            'The bundle holds a file the manifest does not list',
            `${rel} is present and unlisted, so nothing commits to its bytes. A bundle is what ` +
              'the manifest says it is; anything else in the directory arrived after it was sealed.',
            { path: rel },
          ),
        );
      }
    }
  }

  // ── The record ────────────────────────────────────────────────────────────
  const evidencePath = join(dir, EVIDENCE_FILE);
  if (!existsSync(evidencePath)) {
    return {
      ...base,
      verdict: findings.length > 0 ? VERDICT.FINDINGS : VERDICT.INCOMPLETE,
      findings,
      checked,
      unchecked: [...unchecked, EVIDENCE_FILE, 'evidenceDigest', 'artifact.sha256'],
      error: `no ${EVIDENCE_FILE} under ${dir}`,
    };
  }

  let record;
  try {
    record = readJson(evidencePath);
  } catch (e) {
    return {
      ...base,
      verdict: findings.length > 0 ? VERDICT.FINDINGS : VERDICT.INCOMPLETE,
      findings,
      checked,
      unchecked: [...unchecked, EVIDENCE_FILE],
      error: `${EVIDENCE_FILE} does not parse: ${e.message}`,
    };
  }

  if (record?.schemaVersion !== RECORD_SCHEMA_VERSION) {
    return {
      ...base,
      verdict: VERDICT.UNSUPPORTED,
      findings,
      checked,
      unchecked: [...unchecked, '*'],
      error: `${EVIDENCE_FILE} declares schemaVersion ${JSON.stringify(record?.schemaVersion)}, not ${RECORD_SCHEMA_VERSION}`,
    };
  }

  let recomputedRecord;
  try {
    recomputedRecord = rederiveDigest(record);
  } catch (e) {
    if (e instanceof MalformedRecordError) {
      return {
        ...base,
        verdict: VERDICT.MALFORMED,
        malformed: true,
        findings,
        checked,
        unchecked: [...unchecked, '*'],
        error: `${EVIDENCE_FILE} cannot be canonicalised: ${e.message}`,
      };
    }
    throw e;
  }
  base.evidenceDigest = typeof record.evidenceDigest === 'string' ? record.evidenceDigest : null;

  if (typeof record.evidenceDigest !== 'string') {
    findings.push(
      finding('VG-ART-050', 'high', 'The record carries no evidenceDigest', `Re-derivation gives ${recomputedRecord}; the record has no digest to compare it with.`, {
        path: EVIDENCE_FILE,
      }),
    );
  } else if (record.evidenceDigest !== recomputedRecord) {
    findings.push(
      finding(
        'VG-ART-050',
        'critical',
        'evidenceDigest does not match the record it seals',
        `Recorded ${record.evidenceDigest}, re-derived ${recomputedRecord}. This is a disagreement ` +
          'inside the evidence, not a tamper detection: nothing binds a record to an authority, ' +
          'so a record regenerated wholesale would agree with itself.',
        { path: EVIDENCE_FILE },
      ),
    );
  } else {
    checked.push('evidenceDigest');
  }

  if (manifest && typeof manifest.binds?.evidenceDigest === 'string') {
    if (manifest.binds.evidenceDigest !== record.evidenceDigest) {
      findings.push(
        finding(
          'VG-ART-062',
          'high',
          'The manifest names a different evidenceDigest',
          `${MANIFEST_FILE} says ${manifest.binds.evidenceDigest}, ${EVIDENCE_FILE} says ${record.evidenceDigest}.`,
          { path: MANIFEST_FILE },
        ),
      );
    } else {
      checked.push('manifest.binds.evidenceDigest');
    }
  }

  // ── The artefact ──────────────────────────────────────────────────────────
  const art = record.artifact;
  if (art && typeof art.path === 'string' && typeof art.sha256 === 'string') {
    const abs = join(dir, art.path);
    if (!existsSync(abs)) {
      unchecked.push('artifact.sha256');
      findings.push(
        finding('VG-ART-060', 'medium', 'The referenced artefact is not in the bundle', `${art.path} is missing, so its digest could not be checked.`, {
          path: art.path,
        }),
      );
    } else {
      const actual = sha256Hex(readFileSync(abs));
      if (actual !== art.sha256) {
        findings.push(
          finding(
            'VG-ART-061',
            'critical',
            'The artefact does not match the record',
            `${art.path}: the record says ${art.sha256}, the bytes hash to ${actual}. This is a ` +
              'disagreement between the artefact and the evidence that describes it.',
            { path: art.path },
          ),
        );
      } else {
        checked.push('artifact.sha256');
      }
    }
    if (manifest && manifest.binds?.artifact) {
      const bound = manifest.binds.artifact;
      if (bound.path !== art.path || bound.sha256 !== art.sha256) {
        findings.push(
          finding(
            'VG-ART-087',
            'high',
            'The manifest and the record name different artefacts',
            `manifest binds ${JSON.stringify(bound)}, the record names ` +
              `${JSON.stringify({ path: art.path, sha256: art.sha256 })}.`,
            { path: MANIFEST_FILE },
          ),
        );
      } else {
        checked.push('manifest.binds.artifact');
      }
    }
  } else {
    unchecked.push('artifact.sha256');
  }

  findings.push(...checkStatesAndOracle(record, checked, unchecked));

  // A field nobody could check is not a field that passed. An unchecked field
  // lands on INCOMPLETE rather than on CLEAN, which is the whole reason exit 3
  // exists.
  const verdict =
    findings.length > 0
      ? VERDICT.FINDINGS
      : unchecked.length > 0
        ? VERDICT.INCOMPLETE
        : VERDICT.CLEAN;

  return {
    ...base,
    verdict,
    findings,
    checked,
    unchecked,
  };
}

/**
 * Every bundle directory at or under `root`. A directory holding an
 * `evidence.json` is a bundle; a directory holding bundles is not itself one.
 *
 * @param {string} root
 * @returns {string[]}
 */
export function findBundleDirs(root) {
  if (!existsSync(root) || !statSync(root).isDirectory()) return [];
  if (existsSync(join(root, EVIDENCE_FILE))) return [root];
  const out = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const dir = join(root, entry.name);
    if (existsSync(join(dir, EVIDENCE_FILE))) out.push(dir);
  }
  return out.sort();
}

/** The worst severity in a set of findings, as an index into SEVERITY_ORDER. */
export function worstSeverity(findings) {
  let worst = -1;
  for (const f of findings) worst = Math.max(worst, SEVERITY_ORDER[f.severity] ?? 0);
  return worst;
}
