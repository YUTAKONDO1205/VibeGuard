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
if (!PRE_BUILD) {
  const CHROME_DIST_JS_BASELINE_BYTES = 226_200;
  const VSCODE_DIST_JS_BASELINE_BYTES = 230_071;
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
  const PRAGMA_FILE_BASELINE = 53; // measured 2026-07-29, counting directives only (prose mentions excluded)
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

if (failures.length) {
  console.error('packaging invariants FAILED:\n');
  for (const f of failures) console.error(`  - ${f}\n`);
  process.exit(1);
}

console.log(
  PRE_BUILD
    ? 'packaging invariants OK, SOURCE-ONLY subset (vscode engine/types, CLI stays ' +
      'unpublished, analysis-graph absent from declarations / imports, action.yml build order). ' +
      'The bundle-leak and bundle-size invariants did NOT run — rerun without ' +
      '--pre-build after `npm run build` to check the shipped artefacts.'
    : 'packaging invariants OK (vscode engine/types, CLI stays unpublished, ' +
      'analysis-graph absent from shipped bundles / declarations / imports, bundle sizes in band, ' +
      'action.yml builds every CLI dependency)',
);
