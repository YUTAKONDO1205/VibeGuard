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
// Invariants 3–5 answer a different release-time question — "did the cross-file
// analysis package leak into a shipped extension bundle?" — and they exist for
// the same reason invariant 1 does. Until they were written, that boundary was
// the single manually-managed item in the 0.3.0-α plan: someone was expected to
// look at it. Nobody looks at something forever, and the failure is invisible
// (the extension still works, it is just hundreds of KB heavier and now carries
// a project-wide graph builder into a service worker).
//
//   node scripts/check-packaging-invariants.mjs               # everything
//   node scripts/check-packaging-invariants.mjs --pre-build   # source-only subset
//
// Exit 0 if every invariant holds, 1 otherwise, with the failing pair named.
//
// ── WHY THERE ARE TWO MODES ────────────────────────────────────────────────
//
// The invariants split cleanly by what they read, and the split is forced by
// where this runs in CI:
//
//   source-only (1, 2, 4)  read package.json files and source imports. They need
//                          no build, which is the whole reason `ci.yml` calls
//                          this BEFORE `npm run build` — a `vsce` engines
//                          mismatch should be reported in seconds with the fix
//                          spelled out, not after a full build.
//   bundle       (3, 5)    read `extensions/*/dist`. They cannot run before the
//                          build, because the artefacts do not exist yet.
//
// Running everything in the pre-build step would make invariant 3 fail on every
// push — dist is legitimately absent there — and the obvious repair (treat a
// missing dist as a skip) is precisely the failure this file exists to prevent:
// a probe that silently passes when it has nothing to inspect is the manual
// review it replaced, wearing a green tick. So the modes are explicit instead.
// `--pre-build` promises less and delivers it; the default promises everything
// and hard-fails when it cannot deliver.
//
// The default is the STRICT one on purpose. A developer running this by hand,
// and the vitest wrapper in `scripts/packaging-invariants.test.ts`, both get the
// full check without having to know a flag exists; only the one caller that
// genuinely cannot satisfy it opts down, and it says so on the command line
// where a reviewer of `ci.yml` can see it.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';
// Builtin, not a dependency — the zero-install property above still holds. It is
// here for one question invariant 7 cannot answer from the filesystem alone:
// "would this file reach a commit?" Disk contents cannot distinguish a local
// build tree from a staged file, and that distinction is the whole check.
import { execFileSync } from 'node:child_process';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Skip the invariants that need built bundles. See the mode note above. */
const PRE_BUILD = process.argv.includes('--pre-build');

/** Repo-relative POSIX path, so failure messages read the same on both platforms. */
function rel(absPath) {
  return relative(REPO_ROOT, absPath).split(sep).join('/');
}

/**
 * Every file under `dir`, recursively. Returns `[]` when `dir` does not exist —
 * callers that care about absence check for it explicitly and say so, because
 * "directory missing" and "directory empty" mean very different things to the
 * bundle probe and conflating them is how a check starts passing vacuously.
 *
 * Hand-rolled rather than `readdirSync(dir, { recursive: true })`: that option
 * landed in Node 18.17, and `engines.node` here is `>=18`. Nothing else in the
 * repo would notice the difference, and a packaging probe that itself fails to
 * run on a supported Node is worse than no probe.
 */
function walkFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) out.push(full);
    }
  }
  return out;
}

/**
 * Module specifiers mentioned by a line of source.
 *
 * Shared by the two import-boundary invariants below (4 and 7), which ask the
 * same question of different needles: does the light side reach for something
 * only the CLI side may have?
 *
 * A regex rather than a parser, and a line-oriented one, because this script
 * must run with zero dependencies before anything is built — it cannot import
 * `blankCommentsAndStrings` from `@vibeguard/rules` (that would require the
 * package to be compiled first, so the probe would stop working in exactly
 * the broken-checkout situation where you most want it).
 *
 * Comment lines are dropped by shape (`//`, `/*`, or a continuation `*`)
 * rather than by real lexing. That is enough here: prose ABOUT the package is
 * legitimate and common — `design-smells-single.ts` says "is 0.3.0's
 * analysis-graph" in a header comment — while prose that also happens to
 * contain `from '@vibeguard/analysis-graph'` in quotes is not something the
 * repo contains and, if it ever did, flagging it is the safe direction to be
 * wrong in. The cost of a false negative here (a real leak, caught only at
 * release) is much higher than the cost of rewording a comment.
 *
 * Multi-line import forms are covered because the specifier always sits on
 * the line carrying `from`, which is the line this matches.
 */
function importSpecifiersOnLine(line) {
  const trimmed = line.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
    return [];
  }
  const specs = [];
  const re = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"\n]+)['"]/g;
  let m;
  while ((m = re.exec(line)) !== null) specs.push(m[1]);
  return specs;
}

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

/**
 * What invariant 7 concluded about compiler/, reported in the success line.
 * A guard whose subject may legitimately be absent has to say which case it saw,
 * or "OK" means both "checked and clean" and "nothing to check".
 */
let compilerNote = 'compiler/ not evaluated';

/**
 * Which top-level directories the composite action builds, and which merely
 * ride in the tag. Printed on success so the split is visible in a log rather
 * than only in a failure.
 */
let passengerNote = 'Action tree: not classified';

/** Whether every workspace npm would resolve is present in the lockfile. */
let lockNote = 'workspaces: not compared against the lockfile';

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

// ── INVARIANT: the Chrome manifest version tracks the package version ───────
//
// `extensions/chrome/manifest.json` is a hand-maintained static file that
// `copy-static.mjs` copies verbatim into `dist/`. Its `version` is what the
// Chrome Web Store reads, and nothing kept it in step with the `package.json`
// the rest of the release bumps.
//
// The failure mode is late and expensive: the tag is pushed, the Release
// workflow goes green, the VSIX and the CLI tarball publish correctly, and the
// mismatch only surfaces when a human uploads the zip to the Web Store and is
// told "version 0.3.1 is not greater than the published 0.3.1". By then the
// release exists and the fix means replacing an asset on it. That is exactly
// the shape of failure this file was written for — something that only breaks
// at release time, long after the change that caused it.
//
// It happened on 0.3.2. Source-only, so it runs in the `--pre-build` subset and
// fails in seconds, before anything is packaged.
{
  const manifestPath = join(REPO_ROOT, 'extensions/chrome/manifest.json');
  const chromePkgPath = join(REPO_ROOT, 'extensions/chrome/package.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const chromePkg = JSON.parse(readFileSync(chromePkgPath, 'utf8'));

  if (manifest.version !== chromePkg.version) {
    failures.push(
      `extensions/chrome: manifest.json version ${JSON.stringify(manifest.version)} does not match ` +
        `package.json ${JSON.stringify(chromePkg.version)}.\n` +
        '  The Chrome Web Store reads manifest.json, and it refuses an upload whose version is not\n' +
        '  GREATER than the published one — so this is caught by a human at the very end of a\n' +
        '  release, after the tag and the GitHub Release already exist. Bump manifest.json in the\n' +
        '  same commit as every other version.',
    );
  }

  // The root package.json is what the release is named after, and the tag check
  // in release.yml compares against apps/cli. Every shipped surface should agree
  // with it, so a partial bump cannot ship.
  const rootVersion = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')).version;
  const shipped = [
    ['apps/cli/package.json', 'apps/cli'],
    ['extensions/vscode/package.json', 'extensions/vscode'],
    ['extensions/chrome/package.json', 'extensions/chrome'],
    ['extensions/chrome/manifest.json', 'extensions/chrome (manifest)'],
  ];
  for (const [relPath, label] of shipped) {
    const version = JSON.parse(readFileSync(join(REPO_ROOT, relPath), 'utf8')).version;
    if (version !== rootVersion) {
      failures.push(
        `${label}: version ${JSON.stringify(version)} does not match the root package.json ` +
          `${JSON.stringify(rootVersion)}.\n` +
          '  All four channels ship under one tool version; a partial bump publishes a channel\n' +
          '  under a number that names a different build.',
      );
    }
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

// ── Shared vocabulary for invariants 3–5 ────────────────────────────────────

/**
 * The sentinel exported by `packages/analysis-graph/src/index.ts`, assembled
 * from two halves at runtime.
 *
 * WHY THE CONCATENATION, which otherwise looks like pointless obfuscation: this
 * file's job is to search shipped artefacts for a literal. If the literal is
 * present in this file contiguously, then this file can never be part of any
 * artefact the probe searches — and "never" is not something a build system
 * guarantees. Scripts get vendored into release tarballs, copied next to the
 * thing they check, or pulled into a bundle by an `import` someone adds later.
 * The moment that happens, the probe finds its own needle and reports a leak
 * that is not there, and the standard response to a check that cries wolf is to
 * delete the check. Splitting the literal costs one `+` and removes the entire
 * failure mode.
 *
 * The halves are also deliberately unequal and split mid-token so that neither
 * fragment is independently greppable as the real value.
 */
const SENTINEL = 'vibeguard:analysis-graph' + ':must-not-ship-in-extensions';

/**
 * The two directories whose contents are handed to end users: the Chrome
 * extension's unpacked `dist/` and the `.vsix`'s bundled entry point. Anything
 * here is code that runs on a user's machine, which is the only place the
 * boundary actually matters — a leak into `apps/cli/dist` is not a leak.
 */
const SHIPPED_BUNDLE_DIRS = ['extensions/chrome/dist', 'extensions/vscode/dist'];

/** Substring identifying the forbidden package, used by the declaration checks. */
const AG_PACKAGE_NAME = '@vibeguard/analysis-graph';

/**
 * The other packages that are CLI/Action-only and must never reach a bundle.
 *
 * ★ WHY THEY ARE LISTED HERE RATHER THAN GIVEN THEIR OWN SENTINELS.
 *
 * 0.3.0-β added two: `@vibeguard/external-adapters` (H3, ingests Semgrep and
 * CodeQL reports) and `@vibeguard/mcp-guard` (H5, a stdio MCP server). Both
 * carry a bundle sentinel of their own, and both sentinels are as defeatable as
 * `analysis-graph`'s turned out to be — the note on invariant 3 records the
 * measurement: an `import "@vibeguard/analysis-graph";` for side effects left
 * NO sentinel in the bundle, because the constant was tree-shaken away while
 * the package was still shipped.
 *
 * So the load-bearing check for a new package is invariant 4, which reads
 * import specifiers in source and cannot be tree-shaken. Adding a name to this
 * array is what actually protects it; a sentinel is a second opinion.
 *
 * Matched as a SUBSTRING of the specifier, so `@vibeguard/mcp-guard` and any
 * deep path into it are both caught.
 */
const CLI_ONLY_PACKAGES = [
  AG_PACKAGE_NAME,
  '@vibeguard/external-adapters',
  '@vibeguard/mcp-guard',
];

/** The bare directory names, for matching a specifier that omitted the scope. */
const CLI_ONLY_PATH_TOKENS = ['analysis-graph', 'external-adapters', 'mcp-guard'];

/**
 * Subpath exports that are Node-only inside an otherwise browser-safe package.
 *
 * ★ A HOLE THAT THE PACKAGE-LEVEL LIST CANNOT SEE. `@vibeguard/sarif-adapter` is
 * legitimately imported by both extensions, so it can never go in
 * `CLI_ONLY_PACKAGES`. But 0.3.0-β gave it a second entry point —
 * `./node` → `provenance-node.js` — which reads git history and therefore
 * touches `node:child_process`. The package is allowed; that door in it is not.
 *
 * Matched on the specifier tail so `@vibeguard/sarif-adapter/node` is caught
 * while `@vibeguard/sarif-adapter` stays permitted.
 */
const FORBIDDEN_SUBPATHS = ['@vibeguard/sarif-adapter/node'];

// ── Invariant 3: the sentinel appears in no shipped bundle ──────────────────
//
// The empirical check, and the only one of the three that asks what the bundler
// DID rather than what the source SAYS. Invariant 4 reads declarations; a
// transitive re-export, a dynamic import esbuild chose to inline, or a
// hand-patched `dist` satisfies it while shipping the package to every user. A
// string literal survives bundling and minification, so this one is answered by
// reading the artefact.
//
// ★ MEASURED — and re-measured, because the needle changed underneath it.
//
// HISTORY, kept because the reasoning is still the reason this needle is what it
// is. When the needle was the `AG_BUNDLE_SENTINEL` string, the invariant was
// falsified three ways against the real esbuild config and fired in only one:
//
//   `import "@vibeguard/analysis-graph";`           bundle 7.0 KB → 7.0 KB, NO hit
//   `import { createBudget } ...; createBudget({})` bundle 7.0 KB → 9.4 KB, NO hit
//   `import { AG_BUNDLE_SENTINEL } ...; log(it)`    bundle 7.0 KB → 7.2 KB, HIT
//
// The reason was tree shaking: esbuild includes the MODULE and then drops the
// individual declarations nothing references, and a `const` string nobody reads
// is exactly such a declaration. A realistic leak therefore left no sentinel.
//
// THAT IS WHY THE PRIMARY NEEDLE IS NOW `MODULE_MARKER` (below) — the module-path
// comment esbuild emits for every module it includes, which survives exactly when
// the module is included, i.e. the thing we actually want to detect.
//
// RE-MEASURED 2026-07-28 against the current needle, by injecting into the VS
// Code extension entry, rebuilding, running this probe, and reverting:
//
//   `import "@vibeguard/analysis-graph";`                     invariant 3 FAILS
//   `import { createBudget } ...; const b = createBudget();`   invariant 3 FAILS
//   `import { crossFileRules } ...; log(crossFileRules.length)` invariant 3 FAILS
//   (clean tree)                                               all invariants PASS
//
// So with the module-path needle this invariant does catch the ordinary leak, and
// the "fires in only one of three" limit above belongs to the sentinel era. Do not
// weaken this check on the strength of the historical numbers. Invariant 4 still
// catches the same three at the import and the manifest, and remains the cheaper
// and earlier signal — this one additionally covers what 4 is blind to: a
// hand-patched `dist`, a vendored copy, or a build shipping an artefact the
// source tree no longer explains.
//
// `.map` files are excluded on purpose. Source maps embed `sourcesContent` —
// the ORIGINAL text of every module, including modules whose exports were
// tree-shaken away — so a map can legitimately contain the sentinel while the
// shipped `.js` does not. Maps are also not loaded by the browser or by VS Code
// unless a developer opens devtools. Scanning them would produce hits that are
// real strings but not real leaks, i.e. exactly the false positives that get a
// probe switched off.
if (!PRE_BUILD) {
  for (const dirRel of SHIPPED_BUNDLE_DIRS) {
    const dirAbs = join(REPO_ROOT, dirRel);

    if (!existsSync(dirAbs)) {
      // Deliberately a FAILURE and not a skip. A probe that passes when the
      // artefact is missing reports "no leak found" for a build that was never
      // produced, which is indistinguishable from success in CI logs and is the
      // manual management this check was written to replace. If you are on a
      // fresh clone, the fix is `npm run build`, not deleting this branch.
      failures.push(
        `${dirRel} does not exist, so the bundle-leak probe has nothing to inspect.\n` +
          `  Run \`npm run build\` at the repo root first. This is a FAILURE rather than a\n` +
          `  skip on purpose: "no artefact" and "clean artefact" must not look alike, or the\n` +
          `  probe silently degrades into the manual review it replaced.`,
      );
      continue;
    }

    const jsFiles = walkFiles(dirAbs).filter((f) => f.endsWith('.js'));

    if (jsFiles.length === 0) {
      failures.push(
        `${dirRel} exists but contains no .js files — a partial or cleaned build.\n` +
          `  Run \`npm run build\` at the repo root. Same reasoning as a missing directory:\n` +
          `  an empty scan must not read as a passing scan.`,
      );
      continue;
    }

    // The PRIMARY needle. esbuild prefixes every module it includes with a
    // comment naming that module's path (`// ../../packages/analysis-graph/dist/
    // budget.js`). Unlike a string constant it is emitted per INCLUDED MODULE,
    // so it survives the two mechanisms that defeated the sentinel: it does not
    // depend on any declaration being referenced, and it appears for whichever
    // module a flattened re-export actually resolved to.
    const MODULE_MARKER = `packages/${AG_PACKAGE_NAME.split('/')[1]}/`;

    // Viability gate. The marker is a build-output convention, not a guarantee:
    // turning on minification would remove every module comment and this check
    // would then pass on any input at all — the silent-vacuum failure that the
    // missing-directory branch above exists to prevent, arriving by a different
    // road. So before trusting a clean result, require evidence the convention
    // still holds: a bundle that includes ANY workspace module must show at
    // least one such comment.
    let markerConventionHolds = false;
    const contents = new Map();
    for (const file of jsFiles) {
      const text = readFileSync(file, 'utf8');
      contents.set(file, text);
      if (/^\/\/ (?:\.\.\/)*packages\/[\w-]+\//m.test(text)) markerConventionHolds = true;
    }

    if (!markerConventionHolds) {
      failures.push(
        `${dirRel}: no per-module path comments found in the shipped .js, so the primary\n` +
          `  bundle-leak needle cannot be trusted here.\n` +
          `  These comments are how this probe detects ${AG_PACKAGE_NAME} in a bundle. They\n` +
          `  disappear when minification is enabled. If that was deliberate, this check must\n` +
          `  be reworked to a needle that survives minification (a string literal from inside\n` +
          `  the package's own code) BEFORE the minification lands — not after, because in\n` +
          `  between the check passes on everything and nobody finds out.`,
      );
      continue;
    }

    for (const file of jsFiles) {
      const text = contents.get(file);
      const hasModule = text.includes(MODULE_MARKER);
      const hasSentinel = text.includes(SENTINEL);
      if (!hasModule && !hasSentinel) continue;
      failures.push(
        `${rel(file)} contains ${AG_PACKAGE_NAME} code ` +
          `(${hasModule ? 'module path comment' : ''}${hasModule && hasSentinel ? ' + ' : ''}` +
          `${hasSentinel ? 'AG_BUNDLE_SENTINEL' : ''}): it was bundled into a shipped\n` +
          `  extension artefact.\n` +
          `  Cross-file analysis is CLI/Action-only by design. Shipping it here puts a\n` +
          `  project-wide graph builder inside a service worker and weighs down a bundle\n` +
          `  that has to stay light enough to run on every keystroke.\n` +
          `  Find the path with: npx esbuild --analyze on the failing entry point, or grep\n` +
          `  the .map's sourcesContent for the module that pulled it in.`,
      );
    }
  }
}

// ── Invariant 3b: no compiler/ module reaches a shipped bundle ──────────────
//
// Same needle, same artefacts, a different tenant. `compiler/` is a native
// toolchain workspace that sits at the repo root, OUTSIDE the three workspace
// globs, so `npm ci` and `npm run build` never walk it and nothing in the four
// shipped channels has a reason to reference it. That is a property of the
// current layout, not a law: one relative import from an extension entry point
// is all it takes, and because the directory is outside the workspaces the
// manifest-level check (invariant 7 below) would not see a bare relative path.
// This asks the artefact instead.
//
// Deliberately NOT re-reporting a missing/empty/marker-less bundle dir:
// invariant 3 above already failed the run for that, and two failures for one
// cause reads as two problems. The consequence is that this loop can go quiet
// when the run is ALREADY red — never when it is green.
if (!PRE_BUILD) {
  // `// ../../compiler/driver/x.js` — the same per-module comment convention
  // invariant 3 relies on, anchored so a mention inside a string does not count.
  const COMPILER_MODULE_COMMENT = /^\/\/ (?:\.\.\/)*compiler\//m;
  const WORKSPACE_MODULE_COMMENT = /^\/\/ (?:\.\.\/)*packages\/[\w-]+\//m;

  for (const dirRel of SHIPPED_BUNDLE_DIRS) {
    const dirAbs = join(REPO_ROOT, dirRel);
    if (!existsSync(dirAbs)) continue;
    const jsFiles = walkFiles(dirAbs).filter((f) => f.endsWith('.js'));
    if (jsFiles.length === 0) continue;

    const texts = jsFiles.map((f) => [f, readFileSync(f, 'utf8')]);
    if (!texts.some(([, t]) => WORKSPACE_MODULE_COMMENT.test(t))) continue; // gate: see above

    for (const [file, text] of texts) {
      if (!COMPILER_MODULE_COMMENT.test(text)) continue;
      failures.push(
        `${rel(file)} contains a module from compiler/: it was bundled into a shipped\n` +
          `  extension artefact.\n` +
          `  compiler/ is a native toolchain workspace with clang/LLVM expectations. Nothing\n` +
          `  in the browser or editor channels may depend on it — a user who installs the\n` +
          `  extension has not agreed to install a compiler. If the extension needs a result\n` +
          `  the toolchain produces, it reads the produced JSON; it does not import the\n` +
          `  producer.`,
      );
    }
  }
}

// ── Invariant 4: nothing on the light side declares the package ─────────────
//
// Two halves, because there are two ways to acquire a dependency: state it in a
// manifest, or import it and let the workspace resolution find it. npm
// workspaces symlink every package into the root `node_modules`, so an
// undeclared `import '@vibeguard/analysis-graph'` from `analyzer-core` resolves
// and bundles perfectly well — the manifest check alone would never see it.
//
// `apps/cli` is absent from both lists on purpose: the CLI is the sanctioned
// consumer, and the whole point of the boundary is that ONE consumer exists.
{
  const FORBIDDEN_MANIFESTS = [
    'extensions/chrome/package.json',
    'extensions/vscode/package.json',
    'packages/analyzer-core/package.json',
    'packages/rules/package.json',
    'packages/findings-schema/package.json',
    'packages/sarif-adapter/package.json',
    'packages/remediation-engine/package.json',
  ];

  for (const manifestRel of FORBIDDEN_MANIFESTS) {
    const manifestAbs = join(REPO_ROOT, manifestRel);
    if (!existsSync(manifestAbs)) {
      failures.push(
        `${manifestRel} is missing. If a package was renamed or removed, update this list\n` +
          `  rather than letting the check quietly stop covering it.`,
      );
      continue;
    }
    const pkg = JSON.parse(readFileSync(manifestAbs, 'utf8'));
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
      if (pkg[field] && Object.prototype.hasOwnProperty.call(pkg[field], AG_PACKAGE_NAME)) {
        failures.push(
          `${manifestRel}: ${field} declares ${AG_PACKAGE_NAME}.\n` +
            `  Only apps/cli may depend on it. Everything listed here either ships to a\n` +
            `  browser/editor or is bundled BY something that does, so a dependency here is a\n` +
            `  dependency in the extension.`,
        );
      }
    }
  }

  const FORBIDDEN_SRC_DIRS = [
    'extensions/chrome/src',
    'extensions/vscode/src',
    'packages/analyzer-core/src',
    'packages/rules/src',
    'packages/findings-schema/src',
    'packages/sarif-adapter/src',
    'packages/remediation-engine/src',
  ];

  const CODE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];

  for (const dirRel of FORBIDDEN_SRC_DIRS) {
    const dirAbs = join(REPO_ROOT, dirRel);
    if (!existsSync(dirAbs)) {
      failures.push(
        `${dirRel} is missing. Update this list if the layout changed; do not let the\n` +
          `  import check quietly stop covering a package.`,
      );
      continue;
    }
    for (const file of walkFiles(dirAbs)) {
      if (!CODE_EXTENSIONS.some((ext) => file.endsWith(ext))) continue;
      const lines = readFileSync(file, 'utf8').split(/\r\n|\r|\n/);
      for (let i = 0; i < lines.length; i++) {
        for (const spec of importSpecifiersOnLine(lines[i])) {
          const badSubpath = FORBIDDEN_SUBPATHS.find((sp) => spec === sp || spec.endsWith(sp));
          if (badSubpath) {
            failures.push(
              `${rel(file)}:${i + 1} imports '${spec}'.\n` +
                `  That subpath is the Node-only half of an otherwise browser-safe package —\n` +
                `  it reads git history and pulls in node:child_process. Import the package\n` +
                `  root instead, and keep the provenance collection on the CLI/Action side.`,
            );
          }
          const forbidden = CLI_ONLY_PATH_TOKENS.find((token) => spec.includes(token));
          if (forbidden) {
            const pkg = CLI_ONLY_PACKAGES.find((p) => p.includes(forbidden)) ?? forbidden;
            failures.push(
              `${rel(file)}:${i + 1} imports '${spec}'.\n` +
                `  ${pkg} is CLI/Action-only. If this package genuinely needs that\n` +
                `  capability, the capability moves to the CLI side of the seam —\n` +
                `  the import does not move to the light side.`,
            );
          }
        }
      }
    }
  }
}

// ── Invariant 5: shipped bundles stay near their recorded size ──────────────
//
// A coarse backstop BEHIND invariants 3 and 4, not a size budget. Its job is to
// catch a leak neither of them can see — a vendored copy, a fork of the package
// under another name, an artefact whose source tree no longer explains it — by
// noticing that the shipped bundle suddenly got much bigger.
//
// ★ WHAT IT WILL AND WILL NOT CATCH TODAY, measured rather than assumed.
//
// The intended argument is "a full `analysis-graph` inclusion is hundreds of KB
// against ~200 KB bundles, so it cannot hide inside a 10% band". That argument
// is about the package this will GROW into, and it is not yet true of the
// package that exists: `analysis-graph` is a 0.3.0-α skeleton, and forcing a
// real consuming import into `background.ts` moved it 7.0 KB → 9.4 KB — well
// inside the band, invisible here. Invariant 4 caught that leak; this one did
// not, and would not have.
//
// So the honest reading is: this is a tripwire that becomes load-bearing as the
// package fills out (structure indexer, dependency graph, symbol table, taint),
// and until then it is a cheap guard against gross regressions. It was verified
// to fire — dropping the vscode baseline to 100 KB produced the expected failure
// at 209,016 bytes — so it is a live check and not decoration.
//
// The 10% headroom is chosen so ordinary work does not trip it: adding rules and
// messages moves these totals by single-digit KB. When legitimate growth does
// exceed it, the fix is to update the constants below IN A COMMIT. That is the
// entire mechanism — it converts silent bundle growth into a reviewed diff with
// a number in it, which is a thing a human can argue with.
//
// Baselines measured on the build at the time this invariant was added
// (esbuild output is LF-normalised regardless of the checkout's line endings,
// so these are stable between the Windows dev machine and Linux CI):
//   extensions/chrome/dist   background.js 7,117 + sidepanel/index.js 201,933
//   extensions/vscode/dist   extension.js  209,016
//
// REBASELINED after the 2026-07-29 audit fixes, which is the mechanism working
// as designed: the vscode bundle crossed the ceiling by 154 bytes and that is
// now a reviewed number rather than silent drift. What grew, and why it is
// bundle weight rather than accident:
//   - `maskSecret` gained two more redaction shapes plus a placeholder
//     allowlist, so a credential that is not written as a long quoted token no
//     longer reaches `snippet`/`evidence` verbatim (both extensions embed
//     analyzer-core, so both pay for it);
//   - `parseSuppressions` gained the per-line scan that stops a pragma quoted
//     inside a string literal from silencing the file;
//   - the VS Code extension gained `comment-syntax.ts`, the per-language table
//     that stops the suppression Quick Fix from writing `//` into JSON.
// Measured on the build immediately after those changes:
//   extensions/chrome/dist   226,200
//   extensions/vscode/dist   230,071
//
// REBASELINED AGAIN for 0.3.0-β, and the cause was checked before the number was
// moved rather than after. `VG-AISC-004` (Mock/Dummy Security Leftover) landed in
// `packages/rules/src/rules/ai-supply-chain.ts`, which BOTH extensions embed:
// that one file went 12,621 → 58,326 bytes (+900 lines). Chrome went 226,200 →
// 255,326 and VS Code 230,071 → 257,428, so both crossed the 10% band — the
// backstop firing on a real change, which is the mechanism working.
//
// ★ THE CHECK THAT MATTERED IS NOT THE SIZE, IT IS WHAT THE SIZE IS MADE OF.
// 0.3.0-β also created two CLI-only packages (`external-adapters`, `mcp-guard`),
// and a leak of either would ALSO have shown up here as growth. Verified before
// rebaselining: `packages/analysis-graph/`, `packages/external-adapters/` and
// `packages/mcp-guard/` each appear ZERO times across every shipped `.js`, and
// invariants 3 and 4 both passed. The growth is one rule's own weight.
// Measured on the build immediately after those changes:
//   extensions/chrome/dist   255,326
//   extensions/vscode/dist   257,428
if (!PRE_BUILD) {
  const CHROME_DIST_JS_BASELINE_BYTES = 255_326;
  const VSCODE_DIST_JS_BASELINE_BYTES = 257_428;
  const GROWTH_TOLERANCE = 1.1;

  const SIZE_TARGETS = [
    ['extensions/chrome/dist', CHROME_DIST_JS_BASELINE_BYTES],
    ['extensions/vscode/dist', VSCODE_DIST_JS_BASELINE_BYTES],
  ];

  for (const [dirRel, baseline] of SIZE_TARGETS) {
    const dirAbs = join(REPO_ROOT, dirRel);
    // A missing directory is already reported by invariant 3 with the right
    // remedy; repeating it here would just double the noise on a fresh clone.
    if (!existsSync(dirAbs)) continue;

    const total = walkFiles(dirAbs)
      .filter((f) => f.endsWith('.js'))
      .reduce((sum, f) => sum + statSync(f).size, 0);

    const ceiling = Math.floor(baseline * GROWTH_TOLERANCE);
    if (total > ceiling) {
      failures.push(
        `${dirRel}: shipped .js totals ${total} bytes, over the ${ceiling}-byte ceiling\n` +
          `  (baseline ${baseline} + ${Math.round((GROWTH_TOLERANCE - 1) * 100)}%).\n` +
          `  First check invariants 3 and 4 above — this is a backstop, and they name the\n` +
          `  cause. If the growth is legitimate, update the baseline constant in\n` +
          `  scripts/check-packaging-invariants.mjs in the same commit, so the new size is\n` +
          `  something a reviewer saw and accepted rather than something that just happened.`,
      );
    }
  }
}

// ── Invariant 6: action.yml builds everything the CLI needs ────────────────
//
// `action.yml` does not call the root `build` script. It lists the workspaces to
// build one by one, deliberately, so the Action does not pay for the two
// extension bundles it never uses. That is a reasonable optimisation and it is
// also a SECOND COPY of the dependency order — the kind of duplication that only
// announces itself at the worst moment.
//
// It announced itself once already. `@vibeguard/analysis-graph` was added to the
// CLI's dependencies and to the root build chain, and not to this list. Nothing
// locally noticed, because the root build had already produced the `dist` that
// every local command then read. The Action, which starts from a clean checkout,
// compiled the CLI against a package that had never been built and failed with
// `Cannot find module '@vibeguard/analysis-graph' or its corresponding type
// declarations` — followed by a trail of `implicitly has an 'any' type` errors
// that made the real cause harder to see rather than easier.
//
// So this asserts the two lists agree: every workspace package the CLI depends
// on, transitively, must appear in action.yml's build block BEFORE the CLI
// itself. Order is checked as well as membership, because `tsc` needs the
// dependency's `.d.ts` to exist already — a name in the right list at the wrong
// position fails in exactly the same way as a name that is missing.
{
  const actionYml = readFileSync(join(REPO_ROOT, 'action.yml'), 'utf8');

  // Transitive closure over workspace (`@vibeguard/*`) dependencies only.
  const needed = [];
  const seen = new Set();
  const visit = (name) => {
    if (seen.has(name) || !name.startsWith('@vibeguard/')) return;
    seen.add(name);
    const dir =
      name === '@vibeguard/cli' ? 'apps/cli' : `packages/${name.slice('@vibeguard/'.length)}`;
    let pkg;
    try {
      pkg = JSON.parse(readFileSync(join(REPO_ROOT, dir, 'package.json'), 'utf8'));
    } catch {
      return;
    }
    for (const dep of Object.keys(pkg.dependencies ?? {})) visit(dep);
    if (name !== '@vibeguard/cli') needed.push(name);
  };
  visit('@vibeguard/cli');

  const position = new Map();
  const buildLine = /npm run build -w (\S+)/g;
  for (let m = buildLine.exec(actionYml); m; m = buildLine.exec(actionYml)) {
    if (!position.has(m[1])) position.set(m[1], m.index);
  }
  const cliAt = position.get('@vibeguard/cli');

  if (cliAt === undefined) {
    failures.push(
      'action.yml: no `npm run build -w @vibeguard/cli` line found, so the build-order\n' +
        '  invariant cannot be checked. If the Action stopped building the CLI from source,\n' +
        '  update this check rather than deleting it.',
    );
  } else {
    for (const name of needed) {
      const at = position.get(name);
      if (at === undefined) {
        failures.push(
          `action.yml does not build ${name}, but @vibeguard/cli depends on it.\n` +
            `  The Action builds from a clean checkout, so an unbuilt dependency has no .d.ts\n` +
            `  and tsc fails with "Cannot find module ${name} or its corresponding type\n` +
            `  declarations" — in CI only, long after the change looked fine locally.\n` +
            `  Fix: add \`npm run build -w ${name}\` to the build block in action.yml,\n` +
            `  BEFORE the @vibeguard/cli line.`,
        );
      } else if (at > cliAt) {
        failures.push(
          `action.yml builds ${name} AFTER @vibeguard/cli, but the CLI depends on it.\n` +
            `  tsc needs the dependency's declarations to exist already, so the order is part\n` +
            `  of the contract rather than a formatting detail. Move the line above the CLI's.`,
        );
      }
    }
  }
}

// ── Invariant 7: compiler/ is additive, self-contained and silent ───────────
//
// A native toolchain workspace at the repo root. Three things make it different
// from every other directory here, and each one is a way to break the four
// shipped channels without touching them:
//
//   1. It is OUTSIDE the workspace globs (`packages/*`, `apps/*`, `extensions/*`),
//      so `npm ci` and `npm run build` do not walk it. That is what keeps a
//      clang/LLVM dependency out of the release path — and it holds only as long
//      as nobody adds `compiler` to the globs, which is a one-word edit.
//   2. It compiles. Object files, shared libraries and linked binaries are large,
//      machine-specific, and permanent once pushed: history is not rewritten here,
//      because a force-push breaks every consumer of the four channels.
//   3. It is the first place in this repo where C and C++ live. The scanners,
//      censuses and gates that walk the whole tree meet those files for the first
//      time when this directory appears.
//
// Everything below is source-only, so it runs in the `--pre-build` subset and
// costs a CI step nothing. Written BEFORE the directory exists on purpose: a
// boundary guard added after the boundary is crossed has already missed the
// crossing it was for. Until then the first three checks still bind (they are
// about the light side, which exists today) and the rest report as inapplicable.
{
  const COMPILER = 'compiler';

  // ---- 7a. The workspace globs must not swallow it ------------------------
  const rootPkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
  const globs = Array.isArray(rootPkg.workspaces)
    ? rootPkg.workspaces
    : (rootPkg.workspaces?.packages ?? []);
  for (const glob of globs) {
    if (/(^|\/)compiler(\/|$|\*)/.test(glob)) {
      failures.push(
        `package.json workspaces contains '${glob}', which pulls compiler/ into the npm\n` +
          `  workspace graph.\n` +
          `  Then \`npm ci\` installs it, \`npm run build\` builds it, and every CI job for the\n` +
          `  four shipped channels acquires a clang/LLVM prerequisite it has no way to satisfy.\n` +
          `  compiler/ is built by its own toolchain, out of band. Remove the glob.`,
      );
    }
  }

  // ---- 7b. No manifest may declare a dependency that resolves into it -----
  //
  // The npm-visible half of "purely additive". A `file:`/`link:` dependency is
  // how a directory outside the workspaces gets pulled back inside one.
  const manifestDirs = [];
  for (const group of ['packages', 'apps', 'extensions']) {
    const groupAbs = join(REPO_ROOT, group);
    if (!existsSync(groupAbs)) {
      failures.push(
        `${group}/ is missing, so this invariant cannot enumerate the workspaces it must\n` +
          `  check. Fix the layout or update this list — do not let the boundary check\n` +
          `  quietly stop covering a whole group.`,
      );
      continue;
    }
    for (const entry of readdirSync(groupAbs, { withFileTypes: true })) {
      if (entry.isDirectory()) manifestDirs.push(`${group}/${entry.name}`);
    }
  }

  for (const dirRel of manifestDirs) {
    const manifestAbs = join(REPO_ROOT, dirRel, 'package.json');
    if (!existsSync(manifestAbs)) continue; // not every subdirectory is a workspace
    const pkg = JSON.parse(readFileSync(manifestAbs, 'utf8'));
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
      for (const [name, spec] of Object.entries(pkg[field] ?? {})) {
        // Match the LOCATION, not the word. `@angular/compiler`,
        // `vue-template-compiler` and `@vue/compiler-sfc` are ordinary registry
        // packages whose names contain the word, and a check that reddens on
        // them is a check that gets an exclusion list, then a wildcard, then
        // deleted. What is forbidden is a dependency resolved from the local
        // directory: a filesystem protocol, or a path with `compiler` as a
        // segment.
        const value = String(spec);
        const isLocalPath =
          /^(file|link|portal):/.test(value) || value.startsWith('.') || value.startsWith('/');
        const pointsAtCompiler = /(^|[:/\\])compiler([/\\]|$)/.test(value);
        const isOurScope = /^@vibeguard\//.test(name) && /compiler/i.test(name);
        if (!((isLocalPath && pointsAtCompiler) || isOurScope)) continue;
        failures.push(
          `${dirRel}/package.json: ${field} declares '${name}': '${spec}', which reaches into\n` +
            `  compiler/.\n` +
            `  Nothing that ships may depend on the toolchain workspace. The evidence it\n` +
            `  produces is JSON on disk; consume that, not the producer.`,
        );
      }
    }
  }

  // ---- 7c. No import specifier on the light side may resolve into it ------
  //
  // Enumerated from the filesystem rather than hard-coded, unlike invariant 4.
  // The lists there name the packages that must NOT have a specific dependency,
  // so a package missing from the list is a coverage hole worth failing over.
  // Here the rule is universal — NO workspace may import compiler/ — so
  // enumeration is the safer direction: a package added next month is covered
  // the day it appears, with nobody remembering to add it. The floor below is
  // what keeps that from degrading into a vacuous pass.
  // Enumerated from the filesystem rather than hard-coded, unlike invariant 4.
  // The lists there name the packages that must NOT have a specific dependency,
  // so a package missing from the list is a coverage hole worth failing over.
  // Here the rule is universal — NO workspace may reach into compiler/ — so
  // enumeration is the safer direction: a package added next month is covered
  // the day it appears, with nobody remembering to add it. The floors below are
  // what keep that from degrading into a vacuous pass.
  //
  // ★ WHOLE WORKSPACE, NOT JUST src/. The first version of this check scanned
  // `<workspace>/src` and nothing else, which left the build scripts out —
  // `extensions/chrome/{build,copy-static,gen-icons}.mjs` all sit at the
  // workspace root, and `copy-static.mjs` contains a general `copyTree(src,dst)`
  // that already copies whole directories into `dist`. A build script that
  // copied a compiler artefact into the shipped bundle would have satisfied
  // every invariant in this file.
  //
  // ★ AND NOT ONLY IMPORTS. `importSpecifiersOnLine` sees `from`/`import`/
  // `require` and nothing else, so the natural way for an editor extension to
  // use a compiler driver — spawning it —
  //
  //     execFileSync(join(__dirname, '../../compiler/build/driver'), ['--json'])
  //
  // produced no specifier, no module-path comment in the bundle, and no
  // finding. Measured: the specifier extractor returns `[]` for that line. The
  // path in a spawn is a STRING, so the second needle below is a string one.
  // There is no `child_process` use in either extension's source today, which
  // is what makes it safe to forbid the shape now rather than after the first
  // one appears.
  const WORKSPACE_DIR_FLOOR = 11; // measured 2026-08-06: 8 packages + 1 app + 2 extensions
  // Measured 2026-08-06: 172 files. The floor sits below that so ordinary
  // deletions do not trip it, and far enough above zero that a skip rule which
  // swallowed a whole workspace would.
  const SCANNED_FILE_FLOOR = 150;
  const CODE_EXT = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
  const SKIP_SEGMENTS = new Set(['node_modules', 'dist', 'out', 'build', 'coverage', '.turbo']);
  const workspaceDirs = manifestDirs
    .map((d) => join(REPO_ROOT, d))
    .filter((abs) => existsSync(abs));

  if (workspaceDirs.length < WORKSPACE_DIR_FLOOR) {
    failures.push(
      `only ${workspaceDirs.length} workspace directories were found, below the measured\n` +
        `  floor of ${WORKSPACE_DIR_FLOOR}. Either the layout changed — in which case update the floor in\n` +
        `  the same commit — or this check is now scanning less than it claims to.`,
    );
  }

  // A quoted path that reaches into compiler/. Anchored on the quote so that
  // prose in a string ("see compiler/README.md") is the only false positive
  // shape, and requiring the separator so the English word alone never matches.
  const COMPILER_PATH_LITERAL = /['"`]([^'"`\n]*(?:^|\/)compiler\/[^'"`\n]*)['"`]/;
  let lightSideFilesScanned = 0;

  for (const dirAbs of workspaceDirs) {
    for (const file of walkFiles(dirAbs)) {
      if (!CODE_EXT.some((ext) => file.endsWith(ext))) continue;
      const relPath = rel(file);
      if (relPath.split('/').some((seg) => SKIP_SEGMENTS.has(seg))) continue;
      lightSideFilesScanned++;
      const lines = readFileSync(file, 'utf8').split(/\r\n|\r|\n/);
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trimStart();
        const isComment =
          trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*');
        const literal = isComment ? null : COMPILER_PATH_LITERAL.exec(lines[i]);
        if (literal && importSpecifiersOnLine(lines[i]).length === 0) {
          failures.push(
            `${rel(file)}:${i + 1} contains the path literal '${literal[1]}'.\n` +
              `  Reaching compiler/ by spawning it, or by copying out of it in a build script,\n` +
              `  breaks the same promise an import does — that every shipped channel behaves\n` +
              `  identically on a machine where compiler/ was never built — while being\n` +
              `  invisible to the import and bundle checks.\n` +
              `  If this is documentation rather than a path, put it in a comment.`,
          );
        }
        for (const spec of importSpecifiersOnLine(lines[i])) {
          // `(\/|$)` and not just `\/`: `import '../../compiler'` resolves to
          // the directory's index and is exactly as forbidden as a deep import,
          // but a trailing-slash-only pattern walks straight past it.
          if (!/(^|\/)compiler(\/|$)/.test(spec)) continue;
          failures.push(
            `${rel(file)}:${i + 1} imports '${spec}', which resolves into compiler/.\n` +
              `  The toolchain workspace is additive: every shipped channel must behave\n` +
              `  identically on a machine where compiler/ was never built. An import here is\n` +
              `  that promise broken, and it is also what makes the directory impossible to\n` +
              `  split out later.`,
          );
        }
      }
    }
  }

  if (lightSideFilesScanned < SCANNED_FILE_FLOOR) {
    failures.push(
      `the light-side boundary scan read only ${lightSideFilesScanned} file(s), below the measured\n` +
        `  floor of ${SCANNED_FILE_FLOOR}. A skip rule or an extension list has narrowed what this covers;\n` +
        `  the count is here so that narrowing is an event rather than a silent pass.`,
    );
  }

  // ---- 7d/7e. Everything that only applies once the directory exists ------
  //
  // "Exists" means "would reach a commit", which is neither "is on disk" (a local
  // build tree is on disk and is ignored) nor "is committed" (files being written
  // right now are not yet). `--cached --others --exclude-standard` is exactly the
  // set `git add .` would stage, so this asks the question the push will ask.
  let listed = null;
  try {
    // `-z`: NUL-separated, and — the reason it is not optional — NUL output is
    // not path-quoted. Git's default `core.quotepath=true` renders a non-ASCII
    // path as `"compiler/\346\227\245.c"`, complete with surrounding quotes and
    // octal escapes. Every extension test below would then miss, and the file
    // would be reported as one this probe cannot read. One Japanese filename in
    // the directory was enough to turn the whole gate into a puzzle.
    listed = execFileSync(
      'git',
      ['ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', COMPILER],
      { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 32 * 1024 * 1024 },
    )
      .split('\0')
      .map((s) => s.trim())
      .filter(Boolean);
  } catch {
    listed = null;
  }

  if (listed === null) {
    // Not a skip. This branch means the probe could not determine what would be
    // committed, and reporting "boundary clean" on the strength of a failed
    // subprocess is the vacuum this file keeps refusing elsewhere.
    failures.push(
      'could not list compiler/ via git, so the publication-hygiene half of this invariant\n' +
        '  did not run. It needs a git checkout (CI has one). If you are running from an\n' +
        '  extracted tarball, that is the reason — and it is reported rather than skipped so\n' +
        '  the difference between "checked" and "could not check" stays visible.',
    );
  } else if (listed.length === 0) {
    compilerNote = 'compiler/ absent — its publication-hygiene checks were inapplicable';
  } else if (existsSync(join(REPO_ROOT, COMPILER)) === false) {
    failures.push(
      `git lists ${listed.length} path(s) under compiler/ but the directory is not on disk.\n` +
        `  Something is half-removed; resolve it before pushing.`,
    );
  } else {
    compilerNote = `compiler/ present — ${listed.length} committable path(s) checked`;

    // Build products must not be committable. The .gitignore rules cover them;
    // this is what notices when those rules are edited away, which is the only
    // way an .o gets in now.
    const ARTEFACT_EXT = ['.o', '.obj', '.so', '.a', '.dylib', '.elf', '.bc'];
    // `.dSYM` is a DIRECTORY, so no committable path ever ends with it — the
    // committable things are the files inside. Matched as a path segment for
    // that reason; the same is true of any other bundle-shaped artefact.
    const ARTEFACT_DIR_SEGMENT = /(^|\/)[^/]+\.dSYM\//;
    for (const path of listed) {
      if (ARTEFACT_EXT.some((ext) => path.endsWith(ext)) || ARTEFACT_DIR_SEGMENT.test(path)) {
        failures.push(
          `${path} is a build product and is committable.\n` +
            `  Native artefacts are machine-specific, large, and permanent: history here is\n` +
            `  not rewritten, because a force-push breaks every installed consumer of the four\n` +
            `  channels. Restore the ignore rule rather than deleting the file after the fact.`,
        );
        continue;
      }
      const abs = join(REPO_ROOT, path);
      let head;
      try {
        head = readFileSync(abs).subarray(0, 4);
      } catch {
        continue;
      }
      if (head.length === 4 && head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) {
        failures.push(
          `${path} has an ELF header and is committable — a linked binary under an\n` +
            `  extension that the ignore rules do not recognise. Same reasoning as above.`,
        );
      }
    }

    // Measurement inputs and outputs stay on the side where they are produced.
    // They embed machine-specific paths and per-machine toolchain digests, and
    // moving them here is how those reach a public commit.
    for (const path of listed) {
      if (/(^|\/)(fixtures|_results)(\/|$)/.test(path)) {
        failures.push(
          `${path} puts measurement ${/fixtures/.test(path) ? 'inputs' : 'outputs'} under compiler/.\n` +
            `  Those live on the side that produces them, not in the published tree — they\n` +
            `  carry absolute paths and per-machine toolchain digests.`,
        );
      }
    }

    // Licensing. The directory links against headers under Apache-2.0 WITH
    // LLVM-exception; the rest of the repo is MIT. Both facts have to be
    // findable from the tree, and the moment that matters is the first commit —
    // not the first release, because the tree is public from the first push.
    for (const [file, why] of [
      [`${COMPILER}/LICENSE`, 'compiler/ carries different licence terms from the MIT root'],
      ['NOTICE', 'the root NOTICE is where the per-directory terms are stated'],
    ]) {
      if (!existsSync(join(REPO_ROOT, file))) {
        failures.push(`${file} is missing, but compiler/ is committable — ${why}.`);
      }
    }

    // Zero egress, asked of the toolchain in the crudest possible way. The
    // runtime assertion for the shipped channels lives in its own workflow and
    // runs the packaged bytes in a network namespace; nothing equivalent exists
    // for a native build, so this is a source-level tripwire rather than proof.
    // It is worth having anyway: the first person to add a socket here will be
    // told at the pre-build step instead of at review time, or never.
    const NETWORK_INCLUDES = [
      'sys/socket.h', 'netinet/in.h', 'netdb.h', 'arpa/inet.h', 'curl/curl.h', 'winsock2.h',
    ];
    // Both spellings. `node:` is the modern form and the one this repo uses, but
    // the bare specifier still resolves to the same builtin, so listing only the
    // prefixed form would leave a hole the width of one missing prefix.
    const NETWORK_MODULES = new Set();
    for (const m of ['http', 'https', 'net', 'dgram', 'tls', 'dns', 'http2']) {
      NETWORK_MODULES.add(m).add(`node:${m}`);
    }
    // The build description fetches too, and it is the likeliest place for a
    // network dependency to arrive innocently — `FetchContent` and
    // `ExternalProject_Add` exist to download things, and both read as ordinary
    // CMake. Treating the build files as inert while the comment above names
    // `file(DOWNLOAD ...)` as the thing to catch would be the check disagreeing
    // with its own reason for existing.
    const NETWORK_BUILD = [
      /\bfile\s*\(\s*DOWNLOAD\b/i,
      /\bFetchContent_(Declare|MakeAvailable|Populate)\b/i,
      /\bExternalProject_Add\b/i,
      /\b(curl|wget|git\s+clone)\b/i,
      /\bhttps?:\/\//i,
    ];
    const NATIVE_EXT = ['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp'];
    const isBuildFile = (p) => p.endsWith('.cmake') || p.split('/').pop() === 'CMakeLists.txt';

    // Shell and Python reach a network by running a command, not by importing a
    // module, so they need needles of their own — and an extensionless file
    // whose first two bytes are `#!` is one of these too. The driver's two entry
    // points are exactly that shape. Before this branch existed they were
    // counted as unreadable, and the vacuity guard below said so out loud rather
    // than letting the summary claim a boundary it had not looked at.
    const SHELLISH_EXT = ['.sh', '.bash', '.py'];
    const SHELLISH_NETWORK = [
      /\b(curl|wget|ftp|scp|sftp|rsync|ncat|telnet)\b/,
      /\bnc\s+-/,
      /\bgit\s+(clone|fetch|pull|push|ls-remote|remote)\b/,
      /\b(import|from)\s+(socket|ssl|urllib|urllib2|requests|httplib|http\.client|ftplib|smtplib|telnetlib)\b/,
      /\bhttps?:\/\//,
    ];
    const hasShebang = (p) => {
      try {
        return readFileSync(join(REPO_ROOT, p)).subarray(0, 2).toString('latin1') === '#!';
      } catch {
        return false;
      }
    };
    const isShellish = (p) =>
      SHELLISH_EXT.some((ext) => p.endsWith(ext)) ||
      (!p.split('/').pop().includes('.') && hasShebang(p));

    let sourcesScanned = 0;
    for (const path of listed) {
      const isNative = NATIVE_EXT.some((ext) => path.endsWith(ext));
      const isScript = CODE_EXT.some((ext) => path.endsWith(ext));
      const isBuild = isBuildFile(path);
      if (isBuild) {
        let text;
        try {
          text = readFileSync(join(REPO_ROOT, path), 'utf8');
        } catch {
          continue;
        }
        sourcesScanned++;
        const lines = text.split(/\r\n|\r|\n/);
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].replace(/#.*$/, ''); // CMake comments
          const hit = NETWORK_BUILD.find((re) => re.test(line));
          if (hit) {
            failures.push(
              `${path}:${i + 1} fetches from the network in the build description:\n` +
                `    ${lines[i].trim().slice(0, 100)}\n` +
                `  A build that downloads is a build whose output depends on what a server\n` +
                `  returned that day — the opposite of the pinned, reproducible toolchain this\n` +
                `  directory is built around. Vendor it, or install it through the pinned\n` +
                `  package set.`,
            );
          }
        }
        continue;
      }
      if (isShellish(path)) {
        let text;
        try {
          text = readFileSync(join(REPO_ROOT, path), 'utf8');
        } catch {
          continue;
        }
        sourcesScanned++;
        const lines = text.split(/\r\n|\r|\n/);
        for (let i = 0; i < lines.length; i++) {
          // The shebang is not a finding, and a comment is a place to cite a
          // document rather than to fetch one — the same reading the CMake
          // branch above takes. A `#` inside a quoted string takes the rest of
          // that line out of scope with it, which errs towards scanning less;
          // it is named here rather than left as a surprise.
          if (i === 0 && lines[i].startsWith('#!')) continue;
          const line = lines[i].replace(/(^|\s)#.*$/, '$1');
          const hit = SHELLISH_NETWORK.find((re) => re.test(line));
          if (hit) {
            failures.push(
              `${path}:${i + 1} reaches the network from a script here:\n` +
                `    ${lines[i].trim().slice(0, 100)}\n` +
                `  Same rule as the native and build sides: this toolchain reads and writes\n` +
                `  local files and nothing else. A measurement that fetched something is a\n` +
                `  measurement of what a server returned that day.`,
            );
          }
        }
        continue;
      }
      if (!isNative && !isScript) continue;
      let text;
      try {
        text = readFileSync(join(REPO_ROOT, path), 'utf8');
      } catch {
        continue;
      }
      sourcesScanned++;
      const lines = text.split(/\r\n|\r|\n/);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (isNative) {
          const hit = NETWORK_INCLUDES.find((h) =>
            // Every metacharacter escaped, not just the slash: an unescaped `.`
            // in `socket.h` matches any character, which widens the needle in a
            // direction nobody chose.
            new RegExp(`#\\s*include\\s*[<"]${h.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}[>"]`).test(line),
          );
          if (hit) {
            failures.push(
              `${path}:${i + 1} includes <${hit}>.\n` +
                `  The toolchain reads and writes local files and nothing else. If a genuine\n` +
                `  reason to speak to a network appears, it is a design decision to be made in\n` +
                `  the open — not a header that arrived with a refactor.`,
            );
          }
        } else {
          for (const spec of importSpecifiersOnLine(line)) {
            if (NETWORK_MODULES.has(spec)) {
              failures.push(
                `${path}:${i + 1} imports '${spec}'.\n` +
                  `  Same reason as the native side: the toolchain has no network business.`,
              );
            }
          }
        }
      }
    }

    // "Nothing to scan" is a legitimate state for a directory holding only a
    // licence and a README, so the vacuity guard is not `sourcesScanned === 0`.
    // The failure worth catching is narrower and much more likely: a source file
    // written in something this list does not name — say a .S, or a .cmake with
    // a `file(DOWNLOAD ...)` in it — which the tripwire then walks straight past
    // while the summary still says the boundary is clean.
    // `.trace` and `.hex` are recorded tool OUTPUT kept as test input: a
    // captured linker trace, and a hex dump of an ELF header. They are inert for
    // the same reason .txt is — nothing executes them, and an egress sink cannot
    // hide in a file no interpreter reads. They are named here rather than left
    // to fall through the classifier, because the whole point of this list is
    // that a file type is either understood or declared, never merely unmatched.
    const INERT_EXT = ['.md', '.txt', '.json', '.yml', '.yaml', '.toml', '.gitignore', '.trace', '.hex'];
    const INERT_NAMES = ['LICENSE', 'NOTICE', 'README', '.gitignore'];
    const unreadable = listed.filter((path) => {
      const name = path.split('/').pop();
      if (INERT_NAMES.includes(name)) return false;
      if (INERT_EXT.some((ext) => path.endsWith(ext))) return false;
      if (isBuildFile(path)) return false;
      if (isShellish(path)) return false;
      return !NATIVE_EXT.some((e) => path.endsWith(e)) && !CODE_EXT.some((e) => path.endsWith(e));
    });
    if (unreadable.length) {
      failures.push(
        `compiler/ contains ${unreadable.length} committable file(s) this invariant does not\n` +
          `  know how to read, so the egress tripwire walked past them: ${unreadable.slice(0, 5).join(', ')}\n` +
          `  Add the extension to NATIVE_EXT/CODE_EXT (or to the inert list, with a reason) in\n` +
          `  the same commit. A scan that silently covers less than it claims to is the\n` +
          `  failure mode this whole file is written against.`,
      );
    }
    compilerNote =
      `compiler/ present — ${listed.length} committable path(s), ${sourcesScanned} source file(s) scanned`;
  }
}

// ── INVARIANT: the blanket-suppression surface does not grow unnoticed ──────
//
// `vibeguard:disable-file` turns a rule off for a whole file. Every current use
// is legitimate — a test fixture is supposed to contain the pattern it tests,
// and a rule's own source contains the strings it matches — and every one names
// the rule IDs rather than wildcarding. That is exactly why the count needs a
// guard: the mechanism is normal enough here that adding one more never looks
// like an event, and a pragma added to silence a REAL finding is
// indistinguishable in a diff from a pragma added for a fixture.
//
// Same mechanism as the bundle-size ceiling above, and the same instruction:
// when the growth is legitimate, update the constant IN A COMMIT, so the new
// number is something a reviewer saw rather than something that happened. This
// is a source-only check, so it runs in the `--pre-build` subset too.
{
  // 2026-08-03: 53 → 56. Three file-scope exemptions were added in the 0.3.0-β
  // close-out, each for a rule firing on PROSE OR ON RULE DATA rather than on
  // executable code, and each naming its rule id rather than blanket-suppressing:
  //   · packages/external-adapters/src/weakness-class.ts       VG-INJ-004
  //     The eval-exec family table holds `eval-detected` / `eval-injection` /
  //     `user-eval` check-id patterns and prose about CWE-95. It is a copy of the
  //     table in scripts/sec-transfer-semgrep.mjs, which already carries exactly
  //     this exemption for exactly this reason. Without it the main-push gate
  //     (`--fail-on critical`) goes red on 2 findings — measured, not predicted.
  //   · packages/analysis-graph/src/design-smells-crossfile/temporal-security-coupling.ts  VG-INJ-006
  //     The doc comment quotes `el.innerHTML = escapeHtml(name)` to explain why
  //     the sink span stops at the first `(`. Quoting a CORRECTLY sanitised
  //     assignment in order to explain a false positive is not an unsafe write.
  //   · packages/mcp-guard/README.md                            VG-SEC-001
  //     The smoke check hands the guard an AWS-shaped key so the refusal it
  //     documents actually occurs. Same exemption, same reason, as CHANGELOG.md:1.
  // The count is 53 + 3. Raising it is the designed workflow — this invariant
  // exists so the raise appears in a diff a human reads.
  // 2026-08-04: 56 → 59 (#46 CODESCAN). Three more file-scope exemptions, all
  // three the same shape as the ones above — a rule firing on PROSE THAT QUOTES
  // THE PATTERN THE RULE DETECTS — and each naming one rule id:
  //   · packages/analysis-graph/src/design-smells-crossfile/generated-boilerplate-unintegrated.ts  VG-AUTH-002
  //   · packages/analysis-graph/src/design-smells-crossfile/refused-security-inheritance.ts        VG-AUTH-002
  //     Both doc comments quote an unfinished-authorization marker as the
  //     EXAMPLE of the shape being detected, and VG-AUTH-002 reads the quotation
  //     as a real unimplemented check. (Described rather than quoted here on
  //     purpose: writing the marker itself made THIS file the 60th pragma
  //     candidate, which is the same trap MEASURED LIMIT 8e records for the A1
  //     census. The comment was reworded rather than the baseline raised.)
  //   · packages/analyzer-core/src/declared-veto.ts                                                VG-AISC-001
  //     The doc comment quotes `require('bodyparser')`, a typosquat of
  //     body-parser, to explain what the lockfile veto is for.
  // These were the last three open code-scanning alerts attributed to product
  // code after the test-suite noise moved to .vibeguardrc.json; the remaining
  // 32 were suppressed by path there rather than by pragma, so this count grew
  // by three rather than by eighteen. Measured before and after: the
  // CI-equivalent self-scan goes 39 findings → 0.
  const PRAGMA_FILE_BASELINE = 59; // measured 2026-08-04, counting directives only (prose mentions excluded)
  const PRAGMA = 'vibeguard:disable-' + 'file';
  // Comment-opening token, then the directive. `m` so it applies per line.
  // Built from a raw source string, not a template literal: `\s` inside a
  // backtick string is just `s`, which silently turns this into a regex that
  // matches almost nothing — the kind of quiet miscompile a probe must not have.
  const PRAGMA_LINE = new RegExp(
    '(?:^|\\s)(?://|#|<!--|\\*)\\s*' + PRAGMA.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b',
    'm',
  );
  const skipDirs = new Set([
    'node_modules', '.git', 'dist', 'build', 'out', 'coverage',
    '.claude', '.codex', 'paper_data', 'security-experiment', 'docs', 'dock', 'video', '.wrangler',
  ]);
  const withPragma = [];
  const walkPragma = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (skipDirs.has(e.name)) continue;
      const full = `${dir}/${e.name}`;
      if (e.isDirectory()) { walkPragma(full); continue; }
      if (!/\.(ts|js|mjs|cjs|tsx|jsx|md|yml|yaml|html)$/.test(e.name)) continue;
      let text;
      try { text = readFileSync(full, 'utf8'); } catch { continue; }
      // A file COUNTS only when the directive would actually parse — the
      // parser matches raw line text, so prose ABOUT the pragma is
      // indistinguishable from a use of it unless the check is stricter than
      // `includes`. Requiring the directive to open a comment (or to follow
      // code on the line, as `x(); // …` does) keeps documentation out while
      // still catching every real one, including the accidental kind: this file
      // found two live pragmas inside `suppress.ts`'s own doc comment.
      if (PRAGMA_LINE.test(text)) withPragma.push(full.replace(/^\.\//, ''));
    }
  };
  walkPragma('.');

  if (withPragma.length > PRAGMA_FILE_BASELINE) {
    failures.push(
      `${withPragma.length} file(s) carry a file-scope suppression pragma, over the ` +
        `${PRAGMA_FILE_BASELINE}-file baseline.\n` +
        '  Adding one is often correct (a fixture must contain what it tests), but it is also how\n' +
        '  a real finding gets silenced without anyone noticing. Check that the new one names its\n' +
        '  rule IDs and is a fixture rather than a suppression, then raise the constant in\n' +
        '  scripts/check-packaging-invariants.mjs in the same commit.\n' +
        `  Newest by path: ${withPragma.slice(-3).join(', ')}`,
    );
  }

  // A file-scope pragma with no rule IDs is a WILDCARD: it silences every rule
  // in the file. Two exist today and both are deliberate, with the reason
  // written on the line below them — an adversarial-string fixture, and the
  // bundled package-name table. Neither is dangerous on its own, because the
  // severity gate refuses a wildcard for critical/high/medium, so what they
  // actually cover is low/info noise.
  //
  // So the check has the same shape as the count above: not "no wildcards", but
  // "no NEW wildcards". A third one appearing is a decision someone should make
  // on purpose, with the reason written next to it.
  const WILDCARD_BASELINE = 2; // measured 2026-07-29
  const wildcards = [];
  for (const file of withPragma) {
    let text;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    for (const line of text.split(/\r\n|\r|\n/)) {
      const at = line.indexOf(PRAGMA);
      if (at === -1) continue;
      if (!PRAGMA_LINE.test(line)) continue; // prose about the pragma, not a use of it
      const rest = line.slice(at + PRAGMA.length);
      if (!/VG-[A-Z]+-\d+/.test(rest)) {
        wildcards.push(`${file}: ${line.trim().slice(0, 80)}`);
      }
    }
  }
  if (wildcards.length > WILDCARD_BASELINE) {
    failures.push(
      `${wildcards.length} file-scope WILDCARD pragma(s) (no rule IDs), over the ` +
        `${WILDCARD_BASELINE} baseline.\n` +
        '  A wildcard silences every rule in the file. The severity gate spares\n' +
        '  critical/high/medium, so what one really covers is low/info — but that is a bound,\n' +
        '  not a justification. If the new one is deliberate, write the reason beside it and\n' +
        '  raise the constant in the same commit.\n' +
        `  All: ${wildcards.join(' | ')}`,
    );
  }
}

// ── INVARIANT: every workspace is in the lockfile ───────────────────────────
//
// `npm ci` refuses to install when package.json and package-lock.json disagree,
// and adding a directory under a workspace glob makes them disagree. Nothing a
// developer runs locally notices: `npm test` and `npm run build` use the
// node_modules already on disk, so a tree with three unlocked workspaces tests
// green, builds green, and passes every other invariant in this file.
//
// The first thing that runs `npm ci` is the runner, which is to say the first
// notice is a red default branch. That happened: three new packages went in,
// every local check passed, and all four workflows then failed at their first
// step — including the Action's own smoke test, because the composite action
// runs `npm ci` in the consumer's checkout too.
//
// This is precisely the shape this file exists for: correct locally, broken at
// release. Checked here rather than by adding `npm ci` to a local hook, because
// `npm ci` deletes node_modules and takes minutes; reading two manifests takes
// milliseconds and catches the same mistake.
{
  let manifest = null;
  let lock = null;
  try { manifest = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')); } catch { manifest = null; }
  try { lock = JSON.parse(readFileSync(join(REPO_ROOT, 'package-lock.json'), 'utf8')); } catch { lock = null; }

  if (manifest === null || lock === null) {
    failures.push(
      'package.json or package-lock.json could not be read, so workspace/lockfile agreement\n' +
        '  was not checked. Reported rather than skipped.',
    );
  } else if (!lock.packages || typeof lock.packages !== 'object') {
    failures.push(
      'package-lock.json has no `packages` map (lockfileVersion 1?), so this invariant cannot\n' +
        '  read it. Update the check together with the lockfile format.',
    );
  } else {
    // Resolve the globs the same way npm does for the only form used here,
    // `<dir>/*`: one level down, directories holding a package.json.
    const found = [];
    for (const glob of manifest.workspaces ?? []) {
      const g = String(glob);
      if (!g.endsWith('/*')) {
        if (existsSync(join(REPO_ROOT, g, 'package.json'))) found.push(g);
        continue;
      }
      const base = g.slice(0, -2);
      let entries = [];
      try { entries = readdirSync(join(REPO_ROOT, base), { withFileTypes: true }); } catch { entries = []; }
      for (const e of entries) {
        if (!e.isDirectory()) continue;
        const rel = `${base}/${e.name}`;
        if (existsSync(join(REPO_ROOT, rel, 'package.json'))) found.push(rel);
      }
    }

    // Counting contract. Zero resolved workspaces would make the loop below
    // vacuously true, which is the failure mode this file keeps refusing.
    if (found.length === 0) {
      failures.push(
        `no workspace resolved from ${JSON.stringify(manifest.workspaces ?? [])}, so the\n` +
          '  lockfile-agreement check compared nothing. Either the globs changed or the\n' +
          '  resolver here did; both are events, neither is a pass.',
      );
    } else {
      const missing = found.filter((rel) => !(rel in lock.packages));
      if (missing.length) {
        failures.push(
          `${missing.length} workspace(s) are not in package-lock.json: ${missing.join(', ')}.\n` +
            '  `npm ci` fails outright on this, so every workflow — and every consumer of the\n' +
            '  composite action, which runs `npm ci` in its own checkout — breaks at the first\n' +
            '  step. Local `npm test` will not tell you: it uses the node_modules already on\n' +
            '  disk. Run `npm install --package-lock-only` and commit the lockfile with the\n' +
            '  package that needed it.',
        );
      }
      lockNote = `workspaces: ${found.length} resolved, ${found.length - missing.length} present in the lockfile`;
    }
  }
}

// ── INVARIANT: a directory that ships in the Action but is not built by it
//    must be INERT ────────────────────────────────────────────────────────────
//
// The composite action expands the tag's WHOLE TREE into
// `${{ github.action_path }}` and then runs `npm ci` and a series of
// `npm run build -w` in it. So every top-level directory in the tag is
// distributed to every consumer, whether or not the action has any use for it.
// That is not a bug to be fixed by deleting directories — it is a property of
// composite actions — but it does mean the tree has two populations, and only
// one of them was ever reasoned about:
//
//   BUILT      the action installs and compiles it. Its dependencies, its build
//              time and its failure modes are the consumer's problem.
//   PASSENGER  it rides along and is never touched. Costs bytes, nothing else.
//
// A passenger becomes a BUILT directory the moment something makes npm see it —
// a workspace glob widened, a package.json added at a path a glob already
// covers, a build step that names it. The change that does this is one line and
// looks harmless in review; the consequence is that every consumer's CI starts
// acquiring that directory's toolchain. For the native directory here that
// means a clang/LLVM prerequisite on machines that have never needed one.
//
// So the rule is not "keep directory X out of the tag" — that battle is already
// lost and re-fighting it would mean rewriting published history. The rule is:
// a passenger stays inert, and any directory moving between the two populations
// does so in a diff someone reads.
{
  let listed = [];
  try {
    listed = execFileSync(
      'git',
      ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
      { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 },
    ).split('\0').map((s) => s.trim()).filter(Boolean);
  } catch {
    listed = [];
  }

  // Counting contract. An empty enumeration here would classify nothing and
  // report success, which is the failure this file exists to refuse.
  if (listed.length === 0) {
    failures.push(
      'could not enumerate committable paths, so the shipped-but-inert classification did\n' +
        '  not run. Reported rather than skipped: "checked nothing" and "checked and found\n' +
        '  nothing wrong" are different claims and must not share an exit code.',
    );
  } else {
    const topDirs = new Set();
    for (const p of listed) {
      const slash = p.indexOf('/');
      if (slash > 0) topDirs.add(p.slice(0, slash));
    }

    let workspaceGlobs = [];
    try {
      workspaceGlobs = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8')).workspaces ?? [];
    } catch { workspaceGlobs = []; }
    // Only the leading directory of each glob matters for this question: npm
    // resolves `packages/*` by reading `packages/`, so a directory is reachable
    // iff some glob starts with its name.
    const globRoots = new Set(workspaceGlobs.map((g) => String(g).split('/')[0]));

    let actionText = '';
    try { actionText = readFileSync(join(REPO_ROOT, 'action.yml'), 'utf8'); } catch { actionText = ''; }
    if (!actionText) {
      failures.push('action.yml is unreadable, so no directory could be classified as built-or-passenger.');
    }
    // The lines that can make npm or a shell reach a directory. Comments are
    // dropped first: this file's own prose names the native directory, and a
    // raw substring search over the whole document would classify it as built
    // on the strength of a sentence explaining that it is not.
    const actionRunText = actionText
      .split(/\r?\n/)
      .filter((l) => !/^\s*#/.test(l))
      .map((l) => l.replace(/\s#.*$/, ''))
      .join('\n');

    const built = [];
    const passengers = [];
    for (const d of [...topDirs].sort()) {
      const reachableByNpm = globRoots.has(d);
      const namedByAction = new RegExp(`(^|[^\\w./-])${d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`, 'm').test(actionRunText);
      (reachableByNpm || namedByAction ? built : passengers).push(d);

      // The transition that must never happen silently: a passenger that has
      // acquired a manifest npm would read. `packages/x/package.json` is fine —
      // that directory is declared. `<passenger>/package.json` is not.
      if (!reachableByNpm && existsSync(join(REPO_ROOT, d, 'package.json'))) {
        failures.push(
          `${d}/package.json exists but ${d}/ is not covered by any workspace glob ` +
            `(${workspaceGlobs.join(', ') || 'none'}).\n` +
            `  Either it is meant to be installed — then declare it, and accept that every\n` +
            `  Action consumer now installs it — or it is not, and the manifest should go.\n` +
            `  A manifest one glob-widening away from being installed is the state where the\n` +
            `  decision gets made by accident.`,
        );
      }
    }

    if (built.length === 0) {
      failures.push(
        'no directory was classified as built by the Action. The action.yml parse or the\n' +
          '  workspace globs came back empty, so the passenger list below means nothing.',
      );
    }
    passengerNote =
      `Action tree: ${built.length} built (${built.join(', ')}), ` +
      `${passengers.length} inert passenger(s) (${passengers.join(', ') || 'none'})`;
  }
}

if (failures.length) {
  console.error('packaging invariants FAILED:\n');
  for (const f of failures) console.error(`  - ${f}\n`);
  process.exit(1);
}

console.log(
  PRE_BUILD
    ? 'packaging invariants OK, SOURCE-ONLY subset (vscode engine/types, CLI stays ' +
      'unpublished, analysis-graph absent from declarations / imports, compiler/ boundary, ' +
      'action.yml build order). ' +
      'The bundle-leak and bundle-size invariants did NOT run — rerun without ' +
      '--pre-build after `npm run build` to check the shipped artefacts.'
    : 'packaging invariants OK (vscode engine/types, CLI stays unpublished, ' +
      'analysis-graph and compiler/ absent from shipped bundles / declarations / imports, ' +
      'bundle sizes in band, action.yml builds every CLI dependency)',
);
console.log(`  ${compilerNote}`);
console.log(`  ${passengerNote}`);
console.log(`  ${lockNote}`);
