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

// ── Invariant 3: the sentinel appears in no shipped bundle ──────────────────
//
// The empirical check, and the only one of the three that asks what the bundler
// DID rather than what the source SAYS. Invariant 4 reads declarations; a
// transitive re-export, a dynamic import esbuild chose to inline, or a
// hand-patched `dist` satisfies it while shipping the package to every user. A
// string literal survives bundling and minification, so this one is answered by
// reading the artefact.
//
// ★ MEASURED LIMIT — do not over-trust this invariant.
//
// It was falsified three ways against the real esbuild config, and it fires in
// only one of them:
//
//   `import "@vibeguard/analysis-graph";`           bundle 7.0 KB → 7.0 KB, NO hit
//   `import { createBudget } ...; createBudget({})` bundle 7.0 KB → 9.4 KB, NO hit
//   `import { AG_BUNDLE_SENTINEL } ...; log(it)`    bundle 7.0 KB → 7.2 KB, HIT
//
// The reason is tree shaking, and it contradicts the optimistic claim in the
// sentinel's own doc comment ("cannot be tree-shaken out of a module whose code
// was included"). esbuild includes the MODULE and then drops the individual
// declarations nothing references, and a `const` string nobody reads is exactly
// such a declaration. So a realistic leak — code that imports the package to
// USE it — pulls in real graph code and still leaves no sentinel behind.
//
// This invariant therefore catches the cases the declaration checks are blind to
// (hand-patched `dist`, vendored copy, a build that ships an artefact the source
// tree no longer explains) and NOT the ordinary case. The ordinary case is
// invariant 4's, which caught all three leaks above at the import and at the
// manifest. Making this one catch everything requires giving the sentinel a
// side effect esbuild cannot elide, which is a change to `analysis-graph`'s
// public surface and belongs to that package's owner, not to this script.
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

  /**
   * Module specifiers mentioned by a line of source.
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
          if (spec.includes('analysis-graph')) {
            failures.push(
              `${rel(file)}:${i + 1} imports '${spec}'.\n` +
                `  ${AG_PACKAGE_NAME} is CLI/Action-only. If this package genuinely needs a\n` +
                `  cross-file capability, the capability moves to the CLI side of the seam —\n` +
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
if (!PRE_BUILD) {
  const CHROME_DIST_JS_BASELINE_BYTES = 209_050;
  const VSCODE_DIST_JS_BASELINE_BYTES = 209_016;
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

if (failures.length) {
  console.error('packaging invariants FAILED:\n');
  for (const f of failures) console.error(`  - ${f}\n`);
  process.exit(1);
}

console.log(
  PRE_BUILD
    ? 'packaging invariants OK, SOURCE-ONLY subset (vscode engine/types, CLI stays ' +
      'unpublished, analysis-graph absent from declarations / imports). ' +
      'The bundle-leak and bundle-size invariants did NOT run — rerun without ' +
      '--pre-build after `npm run build` to check the shipped artefacts.'
    : 'packaging invariants OK (vscode engine/types, CLI stays unpublished, ' +
      'analysis-graph absent from shipped bundles / declarations / imports, bundle sizes in band)',
);
