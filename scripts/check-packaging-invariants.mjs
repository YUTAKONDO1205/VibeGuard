// check-packaging-invariants — assert the things that only break at release time.
//
// WHY THIS EXISTS
//
// `vsce package` refuses to build when `@types/vscode` is newer than
// `engines.vscode`: the extension would be type-checked against APIs a supported
// host does not have. That is a real constraint, and it has now broken TWICE.
//
// It was fixed once, in the commit that cut v0.1.3 ("fix vsce engines/types
// mismatch"), and reintroduced afterwards by an automated dependency bump that
// moved `@types/vscode` forward on its own. Nobody noticed for weeks, because
// packaging only runs from `release.yml`, which only fires on a `v*` tag. The
// window between two releases is exactly the window in which nothing checks it.
//
// A no-egress workflow added later happens to package the real artefacts on every
// push, so it would now catch this as a side effect. That is not a guarantee: it
// is one refactor of an unrelated workflow away from disappearing, and a check
// nobody named is a check nobody will miss. This file names it.
//
// Detection rather than suppression. Telling the dependency bot to ignore
// `@types/vscode` would stop the noise and also stop the signal — raising
// `engines.vscode` deliberately is a legitimate change, and this should permit it
// while refusing the accidental half of it.
//
//   node scripts/check-packaging-invariants.mjs
//
// Exit 0 if every invariant holds, 1 otherwise, with the failing pair named.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Lowest version a `^`/`~`/bare range admits. Comparing the floors is the
 * question `vsce` actually asks: "could this build be type-checked against an
 * API newer than the oldest host it claims to support?"
 */
function floor(range) {
  const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(range ?? ''));
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function cmp(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

const failures = [];

// ── Invariant 1: VS Code types must not outrun the declared engine ──────────
{
  const pkgPath = join(REPO_ROOT, 'extensions/vscode/package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  const engine = pkg.engines?.vscode;
  const types = pkg.devDependencies?.['@types/vscode'];
  const engineFloor = floor(engine);
  const typesFloor = floor(types);

  if (!engineFloor || !typesFloor) {
    failures.push(
      `extensions/vscode/package.json: could not read a version out of ` +
        `engines.vscode=${JSON.stringify(engine)} / @types/vscode=${JSON.stringify(types)}. ` +
        `If the field moved, update this check rather than deleting it.`,
    );
  } else if (cmp(typesFloor, engineFloor) > 0) {
    failures.push(
      `extensions/vscode: @types/vscode ${types} is newer than engines.vscode ${engine}.\n` +
        `  \`vsce package\` will refuse to build, so the next release fails at packaging time.\n` +
        `  Fix by lowering @types/vscode to match the engine (type-check against the OLDEST\n` +
        `  host you support), NOT by raising engines.vscode — that silently drops every user\n` +
        `  between the two versions, which is a compatibility decision and not a build fix.`,
    );
  }
}

// ── Invariant 2: the CLI stays unpublishable ────────────────────────────────
// Publishing to npm was abandoned permanently, and the package name is unclaimed
// on the registry: a stray `npm publish` would not overwrite anything, it would
// newly expose a name that has never been ours. `private: true` is what makes npm
// refuse; this asserts nobody removed it while tidying.
{
  const pkgPath = join(REPO_ROOT, 'apps/cli/package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  if (pkg.private !== true) {
    failures.push(
      `apps/cli/package.json: "private" is ${JSON.stringify(pkg.private)}, expected true.\n` +
        `  The CLI is deliberately not published to npm; "private" is the only thing that\n` +
        `  makes \`npm publish\` refuse. It ships as the release tarball and via the action.`,
    );
  }
}

if (failures.length) {
  console.error('packaging invariants FAILED:\n');
  for (const f of failures) console.error(`  - ${f}\n`);
  process.exit(1);
}

console.log('packaging invariants OK (vscode engine/types, CLI stays unpublished)');
