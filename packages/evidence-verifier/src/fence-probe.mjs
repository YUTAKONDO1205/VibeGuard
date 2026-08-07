// Is a new package under `packages/` actually fenced out of the shipped
// bundles? Asked of the packaging probe's own source, rather than assumed.
//
// ── WHY THIS FILE EXISTS ────────────────────────────────────────────────────
//
// The four shipped channels — the Action, the editor extension, the browser
// extension, the CLI tarball — must not carry code that only the toolchain side
// has any use for. The release-time probe enforces that, and the load-bearing
// half of it is a check on IMPORT SPECIFIERS, because a bundler can tree-shake
// a marker constant out of a bundle while still shipping the module (measured
// in that file's own notes: a side-effect import left NO sentinel behind).
//
// The catch, which the toolchain README states in as many words: that check
// works from a LIST OF NAMES. A package that is not on the list is not fenced.
// It is not an oversight in the probe — a universal rule would forbid the CLI
// its own dependencies — but it does mean a new package is unprotected on the
// day it lands and stays unprotected until somebody edits a file somewhere else.
//
// "Somebody edits a file somewhere else" is exactly the manual step that gets
// forgotten, so this probe reads the packaging script and reports whether these
// two package names are on both lists. It cannot ADD them: the packaging script
// is not this package's to edit. What it can do is turn a silent gap into a
// named one, with the exact edit spelled out.
//
// ── WHY IT PARSES THE ARRAYS RATHER THAN GREPPING THE FILE ──────────────────
//
// A bare substring search would match the package name in a comment — and that
// file is mostly comments, several of which discuss which packages are CLI-only
// and why. Matching prose would report a fence that does not exist, which is
// strictly worse than reporting no fence at all. So the two array literals are
// located by name and only their contents are searched. If either array cannot
// be found, that is reported as UNDETERMINED and is a failure: a probe that
// cannot find its subject must not answer the question.

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Where the packaging invariants live, relative to the repository root. */
export const PACKAGING_SCRIPT = 'scripts/check-packaging-invariants.mjs';

/** The arrays that decide whether a package is fenced. */
export const PACKAGE_LIST = 'CLI_ONLY_PACKAGES';
export const TOKEN_LIST = 'CLI_ONLY_PATH_TOKENS';

/** The two packages this pair introduces. */
export const OUR_PACKAGES = Object.freeze([
  '@vibeguard/evidence-bundle',
  '@vibeguard/evidence-verifier',
]);

/** The bare directory names, for a specifier that omitted the scope. */
export const OUR_TOKENS = Object.freeze(['evidence-bundle', 'evidence-verifier']);

export class FenceProbeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FenceProbeError';
  }
}

/**
 * The quoted strings inside `const <name> = [ … ];`, or `null` when the array
 * is not there.
 *
 * @param {string} source
 * @param {string} name
 * @returns {string[]|null}
 */
export function arrayLiteralEntries(source, name) {
  const re = new RegExp(`const\\s+${name}\\s*=\\s*\\[([\\s\\S]*?)\\]`, 'm');
  const m = re.exec(source);
  if (m === null) return null;
  const entries = [];
  const item = /['"`]([^'"`\n]*)['"`]/g;
  let hit;
  while ((hit = item.exec(m[1])) !== null) entries.push(hit[1]);
  return entries;
}

/**
 * Probe a packaging script's source for the fence.
 *
 * @param {string} source
 * @param {{packages?: readonly string[], tokens?: readonly string[]}} [opts]
 * @returns {{
 *   determined: boolean,
 *   reason: string|null,
 *   packageList: string[]|null,
 *   tokenList: string[]|null,
 *   fenced: string[],
 *   unfenced: Array<{package: string, missingFrom: string[]}>,
 * }}
 */
export function probeFence(source, opts = {}) {
  const packages = opts.packages ?? OUR_PACKAGES;
  const tokens = opts.tokens ?? OUR_TOKENS;

  const packageList = arrayLiteralEntries(source, PACKAGE_LIST);
  const tokenList = arrayLiteralEntries(source, TOKEN_LIST);

  if (packageList === null || tokenList === null) {
    const missing = [packageList === null ? PACKAGE_LIST : null, tokenList === null ? TOKEN_LIST : null]
      .filter(Boolean)
      .join(' and ');
    return {
      determined: false,
      reason:
        `${missing} could not be found in the packaging script, so whether these packages are ` +
        'fenced is UNDETERMINED. That is reported as a failure rather than as "not fenced" or ' +
        '"fenced": the probe could not see its subject, and either answer would be invented. ' +
        'If the lists were renamed, rename them here in the same commit.',
      packageList,
      tokenList,
      fenced: [],
      unfenced: [],
    };
  }

  const fenced = [];
  const unfenced = [];
  for (let i = 0; i < packages.length; i += 1) {
    const pkg = packages[i];
    const token = tokens[i];
    const missingFrom = [];
    if (!packageList.includes(pkg)) missingFrom.push(PACKAGE_LIST);
    if (!tokenList.includes(token)) missingFrom.push(TOKEN_LIST);
    if (missingFrom.length === 0) fenced.push(pkg);
    else unfenced.push({ package: pkg, missingFrom });
  }

  return { determined: true, reason: null, packageList, tokenList, fenced, unfenced };
}

/**
 * Read the packaging script from a repository root and probe it.
 *
 * @param {string} repoRoot
 * @param {{packages?: readonly string[], tokens?: readonly string[]}} [opts]
 */
export function probeFenceAt(repoRoot, opts = {}) {
  const file = join(repoRoot, PACKAGING_SCRIPT);
  if (!existsSync(file)) {
    throw new FenceProbeError(
      `${PACKAGING_SCRIPT} is not at ${repoRoot}. The fence probe has nothing to read, and a ` +
        'probe with nothing to read reports neither "fenced" nor "not fenced" — it fails.',
    );
  }
  return { file, ...probeFence(readFileSync(file, 'utf8'), opts) };
}

/**
 * The exact edit that would close the gap, so the report does not stop at
 * "something is wrong".
 *
 * @param {Array<{package: string, missingFrom: string[]}>} unfenced
 * @returns {string}
 */
export function remedyFor(unfenced) {
  if (unfenced.length === 0) return '';
  const names = unfenced.map((u) => u.package);
  const bare = names.map((n) => n.split('/').pop());
  return [
    `Add to ${PACKAGING_SCRIPT}:`,
    `  ${PACKAGE_LIST}  += ${names.map((n) => `'${n}'`).join(', ')}`,
    `  ${TOKEN_LIST} += ${bare.map((n) => `'${n}'`).join(', ')}`,
    'Until then the import-boundary invariant does not look for these packages in the shipped',
    'extension sources, and neither does the bundle-leak probe. Nothing else fences them: the',
    'workspace glob already includes them, so they install and resolve like any other package.',
  ].join('\n');
}
