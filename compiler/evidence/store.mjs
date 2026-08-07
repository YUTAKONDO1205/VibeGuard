// The measurement record store: where records live, and what makes one valid.
//
// WHERE THEY LIVE, AND WHY NOT HERE
//
//   Records do not go under `compiler/`. That is a standing rule of this tree,
//   enforced from outside this component by
//   `scripts/check-packaging-invariants.mjs`, which fails the build if a path
//   containing a `_results` or `fixtures` segment becomes committable beneath
//   the directory. The reasoning is not tidiness: a record embeds the digests
//   of one machine's toolchain binaries and the state of one checkout, so a
//   committed one is machine-specific noise at best, and history here is not
//   rewritten, so it is permanent noise.
//
//   The store root is therefore given, never assumed: `--store <path>`, or
//   `VG_EVIDENCE_STORE`, or — only when neither is set — `vg-lab/evidence-store`
//   under the invoking user's home directory, which is the same `vg-lab`
//   convention the driver's tests already use for scratch. A root that resolves
//   inside the checkout is refused rather than used, so that the rule holds
//   even when the environment is set wrongly.
//
// WHY THE VALIDATOR EXISTS BEFORE THE FIRST RECORD
//
//   At the time this was written `git ls-files` matched no record at all: every
//   number in the plan was a number somebody remembered. The order matters
//   because of the same no-rewrite rule — the first bad record that reaches a
//   commit is permanent, and "we will check them later" has no later. So the
//   check is written first, and the writer is built to be run past it.
//
// WHAT A RECORD MUST CARRY
//
//   * `provenance.gitSha` and a dirty-tree flag. A measurement whose inputs
//     were an uncommitted working tree cannot be re-run from the sha alone, so
//     `dirty: true` is allowed but must come with `diffSha256`, which pins the
//     difference. A dirty flag with nothing pinning the difference is a sha
//     that describes inputs the run did not use.
//   * `toolchain[]`, each entry with a version AND the sha256 of the binary.
//     The version alone is a claim about a package name; the digest is the
//     thing that was executed.
//   * a call-site oracle and, in every observation, a CONTROL that survived.
//     interfaces.md §4: count the zeroing instruction, never the symbol name —
//     a naive count of the symbol also matches the surviving `declare` line and
//     attributes the first loss to a declaration cleanup. A control whose count
//     is zero means the measurement apparatus itself produced nothing, and a
//     subject count of zero next to it means nothing at all.
//   * `reproduction.pairId` and `run`. Byte-identity on re-run is a property of
//     TWO records, so a single record can only declare which pair it belongs
//     to; the comparison happens when both halves are in the store, and until
//     they are, the check is reported as not completed rather than as passed.

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { findAbsolutePaths } from './paths.mjs';
import { findMachineIdentity, runShapeChecker } from './machine.mjs';
import { assertNoSymlink, findSymlinks, isWithin } from './fsguard.mjs';
import { MalformedRecordError, rederiveCanonicalText, rederiveDigest } from './verify.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The repository this component is checked out in. */
export const REPO_ROOT = resolve(HERE, '..', '..');

/** The environment variable that names the store. */
export const STORE_ENV = 'VG_EVIDENCE_STORE';

/** The schema this store holds. */
export const MEASUREMENT_SCHEMA = 'measurement-v0';

/** Where records go when nothing says otherwise. Computed, never written down. */
export function defaultStoreRoot() {
  return join(homedir(), 'vg-lab', 'evidence-store');
}

/**
 * Work out the store root and say where the answer came from.
 *
 * @param {{cli?: string|null, env?: Record<string, string|undefined>}} [opts]
 * @returns {{root: string, source: 'flag'|'env'|'default', insideWorkTree: boolean}}
 */
export function resolveStoreRoot(opts = {}) {
  const env = opts.env ?? process.env;
  const cli = opts.cli ?? null;
  const fromEnv = env[STORE_ENV];
  const raw = cli ?? (fromEnv && fromEnv.trim() !== '' ? fromEnv : null);
  const source = cli ? 'flag' : raw ? 'env' : 'default';
  const root = resolve(raw ?? defaultStoreRoot());
  return { root, source, insideWorkTree: isWithin(REPO_ROOT, root) };
}

// ---------------------------------------------------------------------------
// Findings. VG-ART-0NN is the artefact verifier's namespace (interfaces.md §2);
// verify.mjs holds 050-069 for record-internal checks and this file holds
// 070-079 for the store, so nothing in the namespace collides.
// ---------------------------------------------------------------------------

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

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Validate one parsed record. Touches no filesystem except through the
 * delegated shape checker, which the caller supplies a result for.
 *
 * @param {unknown} record
 * @param {{
 *   path?: string|null,
 *   identity?: {hostname: string|null, account: string|null},
 *   shapeHits?: Array<{shape: string, line: number, match: string}>|null,
 * }} [opts] `shapeHits` is `null` when the delegate could not be run, which
 *   makes the disclosure check UNCHECKED rather than clean.
 * @returns {{findings: object[], checked: string[], unchecked: string[]}}
 */
export function validateRecord(record, opts = {}) {
  const findings = [];
  const checked = [];
  const unchecked = [];
  const path = opts.path ?? null;
  const at = { path };

  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new MalformedRecordError('a record must be a JSON object');
  }
  if (record.schemaVersion !== MEASUREMENT_SCHEMA) {
    findings.push(
      finding(
        'VG-ART-072',
        'high',
        'The record is not a measurement record',
        `schemaVersion ${JSON.stringify(record.schemaVersion ?? null)} is not ${MEASUREMENT_SCHEMA}; ` +
          'nothing below this line is meaningful for it.',
        at,
      ),
    );
    return { findings, checked, unchecked: ['*'] };
  }
  checked.push('schemaVersion');

  // ── The seal. Re-derived, not trusted. VG-ART-050 is verify.mjs's id for
  //    this exact disagreement and is reused rather than duplicated.
  const recomputed = rederiveDigest(record);
  if (typeof record.evidenceDigest !== 'string') {
    findings.push(finding('VG-ART-050', 'high', 'The record carries no evidenceDigest', `Re-derivation gives ${recomputed}.`, at));
  } else if (record.evidenceDigest !== recomputed) {
    findings.push(
      finding(
        'VG-ART-050',
        'critical',
        'evidenceDigest does not match the record it seals',
        `Recorded ${record.evidenceDigest}, re-derived ${recomputed}. This is a disagreement inside ` +
          'the evidence, not tamper detection: a record regenerated wholesale agrees with itself.',
        at,
      ),
    );
  } else {
    checked.push('evidenceDigest');
  }

  // ── Provenance.
  const prov = record.provenance;
  if (!prov || typeof prov !== 'object' || Array.isArray(prov)) {
    findings.push(finding('VG-ART-072', 'high', 'The record carries no provenance block', 'A measurement with no gitSha and no dirty-tree flag cannot be re-run.', at));
  } else {
    if (typeof prov.gitSha !== 'string' || !HEX40.test(prov.gitSha)) {
      findings.push(
        finding('VG-ART-072', 'high', 'provenance.gitSha is missing or is not a commit id', `Got ${JSON.stringify(prov.gitSha ?? null)}; forty lowercase hex digits are expected.`, at),
      );
    } else {
      checked.push('provenance.gitSha');
    }
    if (typeof prov.dirty !== 'boolean') {
      findings.push(
        finding(
          'VG-ART-073',
          'high',
          'The dirty-tree flag is missing',
          `provenance.dirty is ${JSON.stringify(prov.dirty ?? null)}. Absent is not the same as false: ` +
            'a record that does not say whether the tree was clean gives its gitSha no meaning.',
          at,
        ),
      );
    } else if (prov.dirty === true && (typeof prov.diffSha256 !== 'string' || !HEX64.test(prov.diffSha256))) {
      findings.push(
        finding(
          'VG-ART-073',
          'high',
          'A dirty tree is declared with nothing pinning the difference',
          'provenance.dirty is true, so the gitSha alone does not describe the inputs; ' +
            'provenance.diffSha256 must carry the sha256 of the working-tree diff.',
          at,
        ),
      );
    } else {
      checked.push('provenance.dirty');
    }
  }

  // ── Toolchain: a version AND the digest of the binary that ran.
  const tc = record.toolchain;
  if (!Array.isArray(tc) || tc.length === 0) {
    findings.push(finding('VG-ART-074', 'high', 'The record names no toolchain', 'A measurement of a compiler that does not say which compiler is not a measurement.', at));
  } else {
    const bad = [];
    for (const [i, e] of tc.entries()) {
      const problems = [];
      if (!e || typeof e !== 'object' || Array.isArray(e)) problems.push('not an object');
      else {
        if (typeof e.name !== 'string' || e.name.trim() === '') problems.push('no name');
        if (typeof e.version !== 'string' || e.version.trim() === '') problems.push('no version');
        if (typeof e.sha256 !== 'string' || !HEX64.test(e.sha256)) problems.push('no sha256 of the binary');
      }
      if (problems.length > 0) bad.push(`toolchain[${i}] (${e && e.name ? String(e.name) : 'unnamed'}): ${problems.join(', ')}`);
    }
    if (bad.length > 0) {
      findings.push(
        finding(
          'VG-ART-074',
          'high',
          'A toolchain entry is incomplete',
          `${bad.join('; ')}. The version names a package; the sha256 names what was executed, and ` +
            'two machines with the same version string routinely run different bytes.',
          at,
        ),
      );
    } else {
      checked.push('toolchain');
    }
  }

  // ── The oracle. interfaces.md §4.
  const oracle = record.oracle;
  if (!oracle || typeof oracle !== 'object' || Array.isArray(oracle)) {
    findings.push(finding('VG-ART-077', 'high', 'The record names no oracle', 'A count with no statement of what was counted cannot be checked or reproduced.', at));
  } else if (oracle.kind !== 'call-site' || typeof oracle.pattern !== 'string' || !/^call\s/.test(oracle.pattern)) {
    findings.push(
      finding(
        'VG-ART-077',
        'high',
        'The oracle counts something other than a call site',
        `kind ${JSON.stringify(oracle.kind ?? null)}, pattern ${JSON.stringify(oracle.pattern ?? null)}. ` +
          'The rule is to count the zeroing instruction, never the symbol name: a bare symbol match also ' +
          'matches the surviving `declare` line, so the first loss gets attributed to a declaration cleanup ' +
          'that never touched the store.',
        at,
      ),
    );
  } else {
    checked.push('oracle');
  }

  // ── Observations, each with a control that survived.
  const obs = record.observations;
  if (!Array.isArray(obs) || obs.length === 0) {
    findings.push(
      finding(
        'VG-ART-079',
        'high',
        'The record contains no observation',
        'An empty observation set is the same empty scan the counting contract refuses one level up: ' +
          'nothing was measured, so nothing is reported.',
        at,
      ),
    );
  } else {
    const bad = [];
    for (const [i, o] of obs.entries()) {
      const problems = [];
      if (!o || typeof o !== 'object' || Array.isArray(o)) problems.push('not an object');
      else {
        if (typeof o.config !== 'string' || o.config.trim() === '') problems.push('no config');
        if (!Number.isInteger(o.subject) || o.subject < 0) problems.push(`subject ${JSON.stringify(o.subject ?? null)} is not a count`);
        if (!Number.isInteger(o.control)) problems.push(`control ${JSON.stringify(o.control ?? null)} is not a count`);
        else if (o.control < 1) problems.push('the control did not survive (control = 0)');
      }
      if (problems.length > 0) bad.push(`observations[${i}] (${o && o.config ? String(o.config) : 'unnamed'}): ${problems.join(', ')}`);
    }
    if (bad.length > 0) {
      findings.push(
        finding(
          'VG-ART-079',
          'high',
          'An observation has no surviving control',
          `${bad.join('; ')}. Every measurement carries a control that cannot be optimised away, and it ` +
            'has to be non-zero: a subject count of zero beside a control count of zero says the apparatus ' +
            'produced nothing, not that the property was lost.',
          at,
        ),
      );
    } else {
      checked.push('observations');
    }
  }

  // ── Machine identity, absolute paths, disclosure shapes.
  const leaks = findAbsolutePaths(record, { mode: 'strict' });
  if (leaks.length > 0) {
    findings.push(
      finding('VG-ART-051', 'high', 'The record carries an absolute path', leaks.map((l) => `${l.where} (${l.in}, ${l.kind}): ${JSON.stringify(l.value)}`).join('; '), at),
    );
  } else {
    checked.push('pathHygiene');
  }

  const ids = findMachineIdentity(record, { identity: opts.identity });
  if (ids.length > 0) {
    findings.push(
      finding(
        'VG-ART-075',
        'high',
        'The record carries machine identity',
        ids.map((l) => `${l.where} (${l.in}, ${l.kind}): ${JSON.stringify(l.match)}`).join('; '),
        at,
      ),
    );
  } else {
    checked.push('machineIdentity');
  }

  if (opts.shapeHits === null || opts.shapeHits === undefined) {
    unchecked.push('disclosureShape');
  } else if (opts.shapeHits.length > 0) {
    findings.push(
      finding(
        'VG-ART-076',
        'high',
        'The record carries a disclosure-shaped string',
        opts.shapeHits.map((h) => `line ${h.line}: ${h.shape} ${JSON.stringify(h.match)}`).join('; ') +
          '. Reported by scripts/check-disclosure-shape.mjs, which matches shapes rather than words; ' +
          'each hit is either a real leak or a shape that checker should learn to exempt.',
        at,
      ),
    );
  } else {
    checked.push('disclosureShape');
  }

  // ── Reproduction. Declared here, compared at store level.
  const rep = record.reproduction;
  if (!rep || typeof rep !== 'object' || typeof rep.pairId !== 'string' || rep.pairId.trim() === '' || ![1, 2].includes(rep.run)) {
    findings.push(
      finding(
        'VG-ART-078',
        'medium',
        'The record does not say which re-run pair it belongs to',
        `reproduction is ${JSON.stringify(rep ?? null)}; a pairId and a run of 1 or 2 are expected. ` +
          'Byte-identity on re-run is a property of two records, and a record that names no sibling can ' +
          'never have it checked.',
        at,
      ),
    );
  } else {
    checked.push('reproduction.declared');
  }

  return { findings, checked, unchecked };
}

/**
 * The part of a record that a re-run must reproduce byte for byte.
 *
 * Two things come out. `context` goes because rule 1 already excludes it from
 * the digest and it is where every volatile field lives by convention — that
 * is what "with timestamps excluded" means here, expressed as a place rather
 * than as a list of field names that would need keeping current. `reproduction`
 * goes because it is bookkeeping ABOUT the pair: run 1 and run 2 differ in it
 * by definition, and comparing it would make every pair fail while proving
 * nothing about the measurement.
 *
 * Nothing else is removed. A difference anywhere else — a toolchain digest, an
 * observation, the git sha, the dirty flag — is a real difference between two
 * runs that claimed to be the same run twice.
 */
export function reproducibleCore(record) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) return record;
  const copy = { ...record };
  delete copy.reproduction;
  return copy;
}

/**
 * Are the two runs of a pair byte-identical once the clock and the pair
 * bookkeeping are out of the comparison? `rederiveCanonicalText` drops the
 * top-level `context` subtree on its own; {@link reproducibleCore} drops the
 * other one.
 */
export function comparePair(a, b) {
  const ta = rederiveCanonicalText(reproducibleCore(a));
  const tb = rederiveCanonicalText(reproducibleCore(b));
  if (ta === tb) return { identical: true, detail: null };
  let at = 0;
  while (at < ta.length && at < tb.length && ta[at] === tb[at]) at += 1;
  return {
    identical: false,
    detail:
      `the canonical texts diverge at byte ${at}:\n` +
      `  run 1 …${JSON.stringify(ta.slice(Math.max(0, at - 40), at + 40))}\n` +
      `  run 2 …${JSON.stringify(tb.slice(Math.max(0, at - 40), at + 40))}`,
  };
}

// ---------------------------------------------------------------------------
// Walking the store.
// ---------------------------------------------------------------------------

/**
 * Every `.json` file beneath `root`, sorted, without following a link.
 *
 * A linked entry is not descended into and not read; it comes back in
 * `refused` so the caller can raise it as a finding. Silently skipping it would
 * make a substituted directory look like an empty one.
 *
 * @returns {{files: string[], refused: string[]}}
 */
export function listRecordFiles(root) {
  const files = [];
  const refused = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of [...entries].sort((x, y) => (x.name < y.name ? -1 : x.name > y.name ? 1 : 0))) {
      const p = join(dir, e.name);
      if (e.isSymbolicLink()) {
        refused.push(p);
        continue;
      }
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && e.name.endsWith('.json')) files.push(p);
    }
  };
  walk(root);
  return { files: files.sort(), refused: refused.sort() };
}

/**
 * Validate a whole store.
 *
 * @param {string} root
 * @param {{identity?: object, delegate?: boolean, linkBoundary?: string|null}} [opts]
 * @returns {{
 *   root: string,
 *   inputs: number, checked: number, skipped: number,
 *   findings: object[], records: object[],
 *   unchecked: string[], delegate: {available: boolean, reason: string|null},
 *   malformed: number,
 * }}
 */
export function validateStore(root, opts = {}) {
  const abs = resolve(root);
  const findings = [];
  const records = [];
  const unchecked = [];
  let malformed = 0;

  // The root itself and everything above it, before anything under it is
  // trusted to be under it.
  const rootLinks = findSymlinks(abs, { boundary: opts.linkBoundary ?? null });
  if (rootLinks.length > 0) {
    findings.push(
      finding(
        'VG-ART-071',
        'critical',
        'A symbolic link on the path to the store root',
        `${rootLinks.join(', ')} — refusing to follow it. A store restored as a link to an older copy ` +
          'verifies clean and dates from last month. Pass --link-boundary if a link above the store is ' +
          'the expected arrangement on this machine.',
        { path: abs },
      ),
    );
    return { root: abs, inputs: 0, checked: 0, skipped: 0, findings, records, unchecked: ['*'], delegate: { available: true, reason: null }, malformed };
  }
  if (isWithin(REPO_ROOT, abs)) {
    findings.push(
      finding(
        'VG-ART-070',
        'critical',
        'The store is inside the checkout',
        `${abs} is under the repository work tree. Records embed one machine's toolchain digests and ` +
          'one checkout\'s state; this tree does not rewrite history, so a record that reaches a commit ' +
          'here is permanent. Point the store outside the checkout.',
        { path: abs },
      ),
    );
    return { root: abs, inputs: 0, checked: 0, skipped: 0, findings, records, unchecked: ['*'], delegate: { available: true, reason: null }, malformed };
  }

  let st = null;
  try {
    st = statSync(abs);
  } catch {
    st = null;
  }
  if (st === null || !st.isDirectory()) {
    unchecked.push('store');
    return {
      root: abs,
      inputs: 0,
      checked: 0,
      skipped: 0,
      findings,
      records,
      unchecked,
      delegate: { available: true, reason: null },
      malformed,
      error: `not a directory: ${abs}`,
    };
  }

  const { files, refused } = listRecordFiles(abs);
  for (const r of refused) {
    findings.push(finding('VG-ART-071', 'high', 'A symbolic link inside the store', `${relative(abs, r).split(sep).join('/')} is a link; it was neither read nor followed.`, { path: r }));
  }

  const inputs = files.length + refused.length;
  let skipped = refused.length;

  // One delegated run over every file, rather than one per file: the checker
  // fires all its needles against their positive controls on each invocation,
  // and paying for that once is the difference between a check that is run and
  // a check that is switched off for being slow.
  const delegate = opts.delegate === false
    ? { available: false, reason: 'delegation disabled by the caller', hits: [], scanned: 0 }
    : runShapeChecker(files);
  const hitsByFile = new Map();
  for (const h of delegate.hits ?? []) {
    const key = resolve(REPO_ROOT, h.file);
    if (!hitsByFile.has(key)) hitsByFile.set(key, []);
    hitsByFile.get(key).push(h);
  }
  if (!delegate.available && files.length > 0) {
    unchecked.push('disclosureShape');
  }

  let okCount = 0;
  const pairs = new Map();
  for (const f of files) {
    const rel = relative(abs, f).split(sep).join('/');
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(f, 'utf8'));
    } catch (e) {
      findings.push(finding('VG-ART-072', 'high', 'A record does not parse', `${rel}: ${e.message}`, { path: rel }));
      skipped += 1;
      continue;
    }
    let res;
    try {
      res = validateRecord(parsed, {
        path: rel,
        identity: opts.identity,
        shapeHits: delegate.available ? (hitsByFile.get(resolve(f)) ?? []) : null,
      });
    } catch (e) {
      if (e instanceof MalformedRecordError) {
        malformed += 1;
        skipped += 1;
        findings.push(finding('VG-ART-072', 'critical', 'A record cannot be canonicalised', `${rel}: ${e.message}`, { path: rel }));
        continue;
      }
      throw e;
    }
    okCount += 1;
    findings.push(...res.findings);
    for (const u of res.unchecked) unchecked.push(`${rel}:${u}`);
    records.push({ file: rel, findings: res.findings, checked: res.checked, unchecked: res.unchecked });

    const rep = parsed.reproduction;
    if (rep && typeof rep.pairId === 'string' && [1, 2].includes(rep.run)) {
      if (!pairs.has(rep.pairId)) pairs.set(rep.pairId, new Map());
      pairs.get(rep.pairId).set(rep.run, { file: rel, record: parsed });
    }
  }

  // Byte-identity on re-run, which only exists once both halves are present.
  for (const [pairId, runs] of [...pairs.entries()].sort()) {
    const one = runs.get(1);
    const two = runs.get(2);
    if (!one || !two) {
      unchecked.push(`pair:${pairId}`);
      findings.push(
        finding(
          'VG-ART-078',
          'medium',
          'A re-run pair is missing a half',
          `pair ${pairId} holds only run ${one ? 1 : 2} (${(one ?? two).file}). Byte-identity on re-run is ` +
            'the claim this pair exists to support, and with one half it is not a claim that has been checked.',
          { path: (one ?? two).file },
        ),
      );
      continue;
    }
    const cmp = comparePair(one.record, two.record);
    if (!cmp.identical) {
      findings.push(
        finding(
          'VG-ART-078',
          'critical',
          'The two runs of a pair are not byte-identical',
          `pair ${pairId}: ${one.file} and ${two.file} differ outside the excluded \`context\` subtree. ` +
            `${cmp.detail}`,
          { path: two.file },
        ),
      );
    }
  }

  return {
    root: abs,
    inputs,
    checked: okCount,
    skipped,
    findings,
    records,
    unchecked,
    delegate: { available: delegate.available, reason: delegate.reason ?? null },
    malformed,
    pairs: pairs.size,
  };
}

/** Read one record file, refusing a link on the way to it. */
export function readRecordFile(file, opts = {}) {
  assertNoSymlink(file, { boundary: opts.boundary ?? null, role: 'the record' });
  return JSON.parse(readFileSync(file, 'utf8'));
}

/** sha256 of bytes, lowercase hex. Local so the store has no generator import. */
export function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}
