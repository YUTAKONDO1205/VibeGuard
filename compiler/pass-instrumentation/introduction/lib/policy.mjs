// What the operator is allowed to say about introductions.
//
// WHY THIS IS NOT IN .vgpolicy.json. `compiler/schema/policy.schema.json` sets
// `additionalProperties: false` at its top level, so a policy file carrying an
// `introduction` key is rejected as malformed -- exit 4 -- by the driver that
// validates it. Adding the key means editing that schema, which belongs to
// another component. Until it is added, introduction settings live in their own
// file, named with `--intro-policy`, and the defaults below are what runs when
// nobody names one. This is recorded here rather than worked around silently so
// that the schema change is a decision someone makes rather than a surprise.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { readFileSync } from 'node:fs';

/**
 * `externalCalls.mode`:
 *
 *   `baseline`   -- the default. An external call is approved when the
 *                   toolchain baseline explains it (it is a runtime entry
 *                   point, an ABI entity, or an export of a declared
 *                   dependency) or when the source declared it. This is the
 *                   mode in which VG-INTRO-002 means "something is calling out
 *                   of this object that this build cannot account for".
 *
 *   `allowlist`  -- stricter. A source-declared external call must additionally
 *                   appear in `approvedExternalCalls`. Runtime and ABI calls
 *                   are still explained by the baseline, because requiring an
 *                   operator to list `__cxa_throw` would make the list useless.
 */
export const DEFAULT_INTRO_POLICY = {
  introPolicyVersion: 'intro-policy-v0',
  failOn: 'high',
  externalCalls: {
    mode: 'baseline',
    approved: [],
  },
  sections: {
    approvedExecutable: [],
  },
  dependencies: [],
  generatedSources: [],
};

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

export function severityAtLeast(severity, threshold) {
  return SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(threshold);
}

class PolicyError extends Error {}
export { PolicyError };

/**
 * Read and check an introduction policy. Throws `PolicyError` on anything
 * malformed -- the caller turns that into exit 4, because a policy that cannot
 * be read is not a policy that permits everything.
 */
export function loadIntroPolicy(path) {
  if (!path) return { ...DEFAULT_INTRO_POLICY, source: '(built-in defaults)' };
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new PolicyError(`cannot read intro policy ${path}: ${e.message}`);
  }
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new PolicyError(`intro policy ${path} is not valid JSON: ${e.message}`);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new PolicyError(`intro policy ${path} must be a JSON object`);
  }

  const merged = {
    ...DEFAULT_INTRO_POLICY,
    ...raw,
    externalCalls: { ...DEFAULT_INTRO_POLICY.externalCalls, ...(raw.externalCalls ?? {}) },
    sections: { ...DEFAULT_INTRO_POLICY.sections, ...(raw.sections ?? {}) },
    source: path,
  };

  const mode = merged.externalCalls.mode;
  if (mode !== 'baseline' && mode !== 'allowlist') {
    throw new PolicyError(`intro policy ${path}: externalCalls.mode must be "baseline" or "allowlist", not ${JSON.stringify(mode)}`);
  }
  if (!SEVERITY_ORDER.includes(merged.failOn)) {
    throw new PolicyError(`intro policy ${path}: failOn must be one of ${SEVERITY_ORDER.join(', ')}`);
  }
  for (const [key, value] of [
    ['externalCalls.approved', merged.externalCalls.approved],
    ['sections.approvedExecutable', merged.sections.approvedExecutable],
    ['generatedSources', merged.generatedSources],
    ['dependencies', merged.dependencies],
  ]) {
    if (!Array.isArray(value)) throw new PolicyError(`intro policy ${path}: ${key} must be an array`);
  }
  return merged;
}

/** symbol -> dependency name, from the policy's declared dependency exports. */
export function dependencyExportMap(policy) {
  const out = new Map();
  for (const dep of policy.dependencies ?? []) {
    for (const sym of dep.exports ?? []) out.set(sym, dep.name ?? '(unnamed dependency)');
  }
  return out;
}
