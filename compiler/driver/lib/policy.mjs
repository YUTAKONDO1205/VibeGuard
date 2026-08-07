// Locating, parsing and validating `.vgpolicy.json`. interfaces.md §6.
//
// Everything here is fail-closed: a policy that cannot be read, parsed, or
// validated is exit 4 and nothing else runs. There is no "carry on with
// defaults" path, because the defaults would be the driver's opinion rather
// than the build's policy, and a build checked against an opinion is unchecked.

import { readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join, parse, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validate, formatErrors } from './jsonschema.mjs';
import { CFG } from './findings.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

export const POLICY_FILENAME = '.vgpolicy.json';
export const SCHEMA_PATH = resolve(HERE, '..', '..', 'schema', 'policy.schema.json');
export const COMPILER_DIR = resolve(HERE, '..', '..');

/** Search upward from `startDir` for `.vgpolicy.json`. Returns null if none. */
export function findPolicyFile(startDir) {
  let dir = resolve(startDir);
  const stopAt = parse(dir).root;
  for (;;) {
    const candidate = join(dir, POLICY_FILENAME);
    try {
      if (statSync(candidate).isFile()) return candidate;
    } catch { /* keep walking */ }
    if (dir === stopAt) return null;
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function isInside(child, parent) {
  const c = resolve(child);
  const p = resolve(parent);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
}

/**
 * Load and validate a policy.
 *
 * @returns {{ok: true, policy: object, path: string, dir: string, sha256: string}
 *         | {ok: false, reason: string, detail: string, path: string|null}}
 */
export function loadPolicy({ cwd, policyPath = null }) {
  const path = policyPath ? resolve(cwd, policyPath) : findPolicyFile(cwd);
  if (!path) {
    return {
      ok: false,
      reason: 'not-found',
      detail: `no ${POLICY_FILENAME} found searching upward from ${'<cwd>'}, and no --policy given`,
      path: null,
    };
  }

  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (err) {
    return { ok: false, reason: 'unreadable', detail: err.message, path };
  }
  const sha256 = createHash('sha256').update(bytes).digest('hex');

  let policy;
  try {
    policy = JSON.parse(bytes.toString('utf8'));
  } catch (err) {
    return { ok: false, reason: 'not-json', detail: err.message, path, sha256 };
  }

  let schema;
  try {
    schema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'));
  } catch (err) {
    // The schema is part of this repository. If it is gone, we cannot claim to
    // have validated anything, and claiming so is the failure this exists to stop.
    return { ok: false, reason: 'schema-unreadable', detail: `${SCHEMA_PATH}: ${err.message}`, path, sha256 };
  }

  const errors = validate(schema, policy);
  if (errors.length > 0) {
    return { ok: false, reason: 'schema-invalid', detail: formatErrors(errors), path, sha256 };
  }

  const dir = dirname(path);

  // policy.schema.json states this as prose on `evidence.out` ("Must resolve
  // outside compiler/") and prose is not enforcement. Enforce it: a bundle
  // written under compiler/ becomes a build product in a tracked tree, which
  // compiler/README.md forbids for reasons that outlive this driver.
  const out = policy.evidence?.out;
  if (typeof out === 'string') {
    const resolved = isAbsolute(out) ? resolve(out) : resolve(dir, out);
    if (isInside(resolved, COMPILER_DIR)) {
      return {
        ok: false,
        reason: 'evidence-out-inside-compiler',
        detail: `evidence.out resolves inside compiler/ (${CFG.EVIDENCE_OUT_INSIDE_COMPILER}); it must resolve outside`,
        path,
        sha256,
      };
    }
  }

  return { ok: true, policy, path, dir, sha256 };
}

// Defaults live here rather than being written into the parsed object, so that
// "the policy did not say" stays distinguishable from "the policy said the
// default" when the record is read back later.

export function failOnIncomplete(policy) {
  return policy.verification?.failOnIncomplete ?? true;
}

export function requireDigestMatch(policy) {
  return policy.toolchain?.requireDigestMatch ?? true;
}

export function evidenceOutDir(policy, policyDir) {
  const out = policy.evidence?.out;
  if (typeof out !== 'string') return null;
  return isAbsolute(out) ? resolve(out) : resolve(policyDir, out);
}

export function pinPath(policy, policyDir) {
  const pin = policy.toolchain?.pin;
  if (typeof pin !== 'string') return null;
  return isAbsolute(pin) ? resolve(pin) : resolve(policyDir, pin);
}

export function sourceDateEpoch(policy) {
  const fromPolicy = policy.evidence?.sourceDateEpoch;
  if (Number.isInteger(fromPolicy)) return { value: fromPolicy, source: 'policy' };
  if (fromPolicy === null) return { value: null, source: 'policy' };
  const fromEnv = process.env.SOURCE_DATE_EPOCH;
  if (fromEnv !== undefined && /^\d+$/.test(fromEnv)) {
    return { value: Number.parseInt(fromEnv, 10), source: 'environment' };
  }
  return { value: null, source: 'absent' };
}
