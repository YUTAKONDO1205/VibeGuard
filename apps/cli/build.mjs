// esbuild driver for the VibeGuard CLI.
//
// WHY THIS FILE EXISTS AT ALL
//
// The CLI is not published to npm — that decision is permanent and is asserted
// by `check-packaging-invariants.mjs` invariant 2 (`private: true`). It ships as
// the tarball `release.yml` attaches to the GitHub Release. But that tarball was
// produced from a `tsc` build whose `dist/index.js` still began with
// `import … from '@vibeguard/analyzer-core'`, and `apps/cli/package.json` listed
// six `@vibeguard/*` packages as runtime `dependencies`. None of those names
// exists on any registry — deliberately, permanently — so
// `npm i vibeguard-cli-0.3.5.tgz` could not resolve them and the artefact the
// README points users at was uninstallable.
//
// Bundling is what makes the tarball self-contained: every workspace package the
// CLI reaches is inlined into `dist/index.js`, the manifest declares no runtime
// dependencies, and `npm i <tarball>` needs nothing from a registry. The
// manifest change and this file are two halves of ONE fix — bundling without
// moving the dependencies leaves the tarball broken, and moving them without
// bundling leaves it unrunnable.
//
// ── OUTPUT SHAPE IS LOAD-BEARING ────────────────────────────────────────────
//
// `dist/index.js` is not a name this file may choose. Every consumer in the
// repository invokes that exact path — `action.yml`, `security-scan.yml` (13
// call sites), `no-network-assert.yml`, the root `scan` script and the README —
// and none of them goes through the `bin` shim. A rename here silently breaks
// the Action, which is the channel with the most users and the least visible
// failure.
//
// ── ONE FILE, NOT CODE SPLITTING: THE LAZY-IMPORT DECISION ──────────────────
//
// `src/index.ts` has three deliberate dynamic imports, each carrying a comment
// that says the point is NOT to pay for a heavy path most runs never take:
//
//   :199  @vibeguard/analysis-graph      cross-file analysis   --include-design-smells
//   :252  @vibeguard/external-adapters   SAST ensemble         --ensemble
//   :403  @vibeguard/sarif-adapter/node  git provenance        --format sarif
//
// Bundling could destroy that in two different ways, so the question was asked
// deliberately rather than assumed away.
//
//   (a) Hoisting. If the bundler turned `await import(x)` into a static import,
//       every `vibeguard --help` would evaluate the cross-file rule table.
//       esbuild does NOT do this: an inlined module becomes an `__esm(...)` init
//       closure and the call site becomes
//       `await Promise.resolve().then(() => (init_x(), x_exports))`. Verified in
//       the emitted bundle — all three sites have exactly that shape, and
//       `assertLazyBoundaries()` below re-verifies it on every build, so a
//       future esbuild that changes its mind fails the BUILD rather than
//       silently discarding the property. EVALUATION laziness is preserved.
//
//   (b) Parse cost. A single file makes node read and parse ~655 KB even for
//       `--help`. `splitting: true` would avoid that by emitting the deferred
//       packages as separate chunks node only opens on demand. So it was built
//       both ways and timed rather than argued about.
//
// MEASURED on this machine (node v24.14.1, Windows, `--help`, 9 runs each,
// best / median wall clock including process spawn):
//
//   tsc output, 12 files, analyzer-core loaded eagerly     90.1 ms / 94.6 ms
//   single-file bundle, 655 KB                             57.5 ms / 61.3 ms
//   split bundle, 6 files (index 54 KB + 5 chunks)         63.8 ms / 71.2 ms
//
// Splitting is SLOWER here, not faster: node pays more to open and link six ES
// modules than to parse one larger file, and V8's lazy compilation means the
// unreferenced ~600 KB is never fully compiled anyway. It would also cost three
// content-hashed chunk names that change on every build (churning the tarball)
// and make `bin` depend on sibling files rather than one artefact.
//
// ★ AND THE HONEST HALF OF THE MEASUREMENT, which cuts against the assertion
// below rather than for it. The three lazy imports were deliberately hoisted
// into static ones and re-timed: 58.7 ms / 62.5 ms — indistinguishable from the
// 57.5 ms / 59.6 ms the lazy build gives. At 0.3.5's package sizes the laziness
// buys nothing measurable, because V8 compiles function bodies on first call
// whether or not esbuild wrapped the module.
//
// The assertion is kept anyway, and the reason is not the number today. It is
// that `analysis-graph` is a 0.3.0-α skeleton — `check-packaging-invariants.mjs`
// says so where it declines to lean on bundle size — and the whole point of a
// property that will matter later is that it must not be silently dropped in
// the meantime. `assertLazyBoundaries()` costs one regex per build and converts
// "esbuild happens to defer" into "this build refuses to ship if it stops".
// What it must NOT be read as is evidence that the CLI is faster because of it.
//
// ── NO SOURCEMAP ────────────────────────────────────────────────────────────
//
// Deliberate, not a convenience. A sourcemap embeds `sourcesContent` — the full
// text of every module — which would roughly triple the tarball, and its
// `sources` array is the classic way an absolute build path (a CI runner's
// working directory, a developer's home directory) gets baked into a shipped
// artefact. The CLI is the one artefact users download and unpack. A checkout
// still debugs against the `.ts` sources; a stack trace from the bundle names
// `dist/index.js` and a line, which the per-module path comments below resolve
// to a module by inspection.
import { build } from 'esbuild';
import { readFileSync, rmSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, '../..');
const OUTDIR = resolve(HERE, 'dist');
const OUTFILE = resolve(OUTDIR, 'index.js');

// ── WIPE dist/ FIRST, AND WHY IT IS NOT HOUSEKEEPING ────────────────────────
//
// `apps/cli/package.json` ships `"files": ["dist"]`, so `npm pack` takes
// whatever is in this directory — and esbuild writes one file and leaves every
// other one alone. Before this change `dist/` held twelve tsc outputs plus
// their `.d.ts` and `.map` siblings, INCLUDING `args.test.js`, `diff.test.js`
// and `fix.test.js`, so without this line a developer's tarball would carry the
// test suite and a fresh CI checkout's would not: two different artefacts from
// one commit. Those stale bytes would also be read by
// `scripts/sec-a2-egress-scan.mjs`, which scans this directory as the shipped
// CLI, so they would be audited as if they were shipped code — which, in that
// tarball, they were.
//
// Removing the directory makes the output a function of the input. `force` so a
// first build on a fresh clone is not an error.
rmSync(OUTDIR, { recursive: true, force: true });

/**
 * The three specifiers `src/index.ts` loads lazily, with the flag that reaches
 * each one and the package directory each resolves into. Data rather than
 * prose because `assertLazyBoundaries()` reads it.
 */
const LAZY_SPECIFIERS = [
  { spec: '@vibeguard/analysis-graph', dir: 'analysis-graph', reachedBy: '--include-design-smells' },
  { spec: '@vibeguard/external-adapters', dir: 'external-adapters', reachedBy: '--ensemble' },
  // Resolves to packages/sarif-adapter/dist/provenance-node.js — the package
  // root is imported statically too, so this one is matched on the module file.
  { spec: '@vibeguard/sarif-adapter/node', dir: 'sarif-adapter', reachedBy: '--format sarif' },
];

/**
 * Packages whose ABSENCE would make the scanner silently useless.
 *
 * `analyzer-core` drives the scan and `rules` carries every rule definition. A
 * bundle missing either still starts, still prints a report, still exits 0 —
 * and reports nothing. "Exit 0, zero findings" is indistinguishable from a
 * clean repository, which makes it the worst failure this change can have and
 * the one worth naming explicitly rather than leaving to the byte floor.
 */
const REQUIRED_PACKAGE_DIRS = ['analyzer-core', 'rules', 'findings-schema', 'remediation-engine'];

/**
 * The smallest bundle that could plausibly contain the analyzer.
 *
 * Measured 682,746 bytes on 2026-08-16 (0.3.5 + the unreleased work). The
 * number moves with ordinary source edits — a docstring added to
 * findings-schema moved it 11,801 bytes — so treat it as the scale, not as a
 * value to assert. The floor sits ~40% below that so ordinary
 * rule work never trips it, and far enough above a stub that no stub can pass.
 * A tripwire, not a size budget. `scripts/sec-a2-egress-scan.mjs` carries the
 * same idea for the SHIPPED bytes, because the two are audited separately.
 */
const MIN_BUNDLE_BYTES = 400_000;

/** The per-module path comment esbuild emits for every module it includes. */
function modulesFrom(code, dir) {
  return new RegExp(`^// (?:\\.\\./)*packages/${dir}/`, 'm').test(code);
}

/**
 * Assert that the bundle is complete AND that the three lazy paths stayed lazy.
 *
 * WHY THIS IS A BUILD STEP AND NOT A COMMENT. Both properties are invisible in
 * normal use. A bundle missing `rules` scans clean; a bundle that hoisted the
 * dynamic imports is merely slower. Neither shows up in a test that runs the
 * CLI and checks its output, so both are asserted here, against the emitted
 * bytes, on every build.
 */
function assertLazyBoundaries(code) {
  const problems = [];

  // ── completeness ────────────────────────────────────────────────────────
  for (const dir of REQUIRED_PACKAGE_DIRS) {
    if (!modulesFrom(code, dir)) {
      problems.push(
        `no module from packages/${dir}/ is in the bundle. The CLI would still start and ` +
          'still exit 0 while finding nothing, which reads exactly like a clean repository. ' +
          'Check that no @vibeguard/* package was marked external or aliased to a stub.',
      );
    }
  }

  for (const { spec, dir, reachedBy } of LAZY_SPECIFIERS) {
    if (!modulesFrom(code, dir)) {
      problems.push(
        `no module from packages/${dir}/ appears in the bundle, but src/index.ts loads ` +
          `'${spec}' for ${reachedBy}. If it was left external the tarball is broken again — ` +
          'that name resolves on no registry.',
      );
    }
    // A surviving runtime `import("@vibeguard/…")` is the tarball-breaking
    // outcome this whole change exists to prevent, and it fails differently
    // from the case above (the module is absent AND the call site still asks
    // for it by name), so it gets its own message.
    const escaped = spec.replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&');
    if (new RegExp(`import\\(\\s*["'\`]${escaped}["'\`]`).test(code)) {
      problems.push(
        `the bundle still performs a runtime \`import("${spec}")\`. That name exists on no ` +
          'registry, so an installed tarball throws ERR_MODULE_NOT_FOUND the moment the flag ' +
          'is used. The package must be inlined.',
      );
    }
  }

  // ── laziness ────────────────────────────────────────────────────────────
  //
  // esbuild's shape for "dynamically import a module I inlined": the module
  // body is wrapped in `__esm({...})` and the call site becomes a resolved
  // promise that runs the init on first await. One occurrence per lazy import.
  const LAZY_CALL = /Promise\.resolve\(\)\.then\(\(\) => \(init_/g;
  const lazySites = (code.match(LAZY_CALL) ?? []).length;
  if (lazySites < LAZY_SPECIFIERS.length) {
    problems.push(
      `found ${lazySites} deferred-import call site(s), expected at least ${LAZY_SPECIFIERS.length} ` +
        `(${LAZY_SPECIFIERS.map((l) => l.spec).join(', ')}). esbuild hoisted at least one of them ` +
        'into startup, so every `vibeguard --help` now evaluates a heavy package it was ' +
        'deliberately built not to touch. Either pin the esbuild version that defers, or move ' +
        'to `splitting: true` with an outdir — and re-time `--help` before deciding, because ' +
        'splitting measured SLOWER here (see the header).',
    );
  }
  if (!code.includes('__esm(')) {
    problems.push(
      'the bundle contains no `__esm(` wrapper, so no module is deferred at all. See above.',
    );
  }

  return problems;
}

/**
 * Assert that `action.yml` builds every workspace package this bundle inlined,
 * BEFORE it builds the CLI.
 *
 * ★ WHY THIS LIVES HERE AND NOT WHERE IT USED TO.
 *
 * `scripts/check-packaging-invariants.mjs` invariant 6 owned this property. It
 * derived the CLI's transitive workspace closure from `dependencies` in the
 * package manifests and required each name to appear in action.yml's build
 * block ahead of the CLI's own line — because the Action builds from a clean
 * checkout, so an unbuilt dependency has no `dist` and the CLI build fails in
 * CI only, long after it looked fine locally. That is not hypothetical; the
 * comment there records it happening with `@vibeguard/analysis-graph`.
 *
 * Moving the six `@vibeguard/*` packages to devDependencies (they are inlined,
 * so nothing resolves them at run time) empties the field that invariant read.
 * Its closure becomes `[]`, its loop runs zero times, and it reports OK for any
 * action.yml whatsoever. The property did NOT stop mattering — esbuild resolves
 * `@vibeguard/analyzer-core` to `packages/analyzer-core/dist/index.js`, so the
 * Action still has to build every one of them first — only its enforcement
 * evaporated. Silently gutting a check while claiming the same green line is
 * exactly what this repository refuses everywhere else, so the check moves to
 * the one place that cannot be fooled about what the CLI needs: the build that
 * just consumed it.
 *
 * It is also STRICTLY STRONGER than what it replaces. The old version asked a
 * manifest what the CLI declares; this asks esbuild's metafile what the bundle
 * actually contains. A package pulled in transitively, or by a relative import
 * that no manifest mentions, is invisible to the first and unavoidable to the
 * second.
 */
function assertActionBuildsWhatWeInlined(metafile) {
  const actionPath = resolve(REPO_ROOT, 'action.yml');
  let actionYml;
  try {
    actionYml = readFileSync(actionPath, 'utf8');
  } catch {
    // A hard failure rather than a skip. "could not check" and "checked and
    // clean" must not produce the same output, or the guard degrades into the
    // manual review it replaced.
    return [
      `could not read ${actionPath}, so the Action build-order check did not run. It is not ` +
        'optional: the composite action builds the workspaces one by one and a missing or ' +
        'mis-ordered line fails the CLI build on a clean checkout only.',
    ];
  }

  // esbuild reports input paths relative to absWorkingDir (the repo root).
  const inlined = new Set();
  for (const input of Object.keys(metafile.inputs)) {
    const m = /^(?:\.\.\/)*packages\/([\w-]+)\//.exec(input.split('\\').join('/'));
    if (m) inlined.add(`@vibeguard/${m[1]}`);
  }

  const position = new Map();
  const re = /npm run build -w (\S+)/g;
  for (let m = re.exec(actionYml); m; m = re.exec(actionYml)) {
    if (!position.has(m[1])) position.set(m[1], m.index);
  }
  const cliAt = position.get('@vibeguard/cli');

  const problems = [];
  if (inlined.size === 0) {
    problems.push(
      'esbuild reported no packages/*/ inputs, so this check has nothing to compare against. ' +
        'Either the bundle no longer contains any workspace package — see the completeness ' +
        'assertions above — or the metafile path shape changed and this parser needs updating.',
    );
    return problems;
  }
  if (cliAt === undefined) {
    problems.push(
      'action.yml has no `npm run build -w @vibeguard/cli` line, so the build-order check ' +
        'cannot run. If the Action stopped building the CLI from source, update this check ' +
        'rather than deleting it.',
    );
    return problems;
  }

  for (const name of [...inlined].sort()) {
    const at = position.get(name);
    if (at === undefined) {
      problems.push(
        `action.yml does not build ${name}, but this bundle inlined code from it. The Action ` +
          'builds from a clean checkout, so that package has no dist there and esbuild fails ' +
          `to resolve it. Add \`npm run build -w ${name}\` before the @vibeguard/cli line.`,
      );
    } else if (at > cliAt) {
      problems.push(
        `action.yml builds ${name} AFTER @vibeguard/cli, but this bundle inlined code from ` +
          'it. Order is part of the contract, not formatting — move the line above the CLI\'s.',
      );
    }
  }
  return problems;
}

const result = await build({
  entryPoints: [resolve(HERE, 'src/index.ts')],
  outfile: OUTFILE,
  bundle: true,
  // Read by assertActionBuildsWhatWeInlined(). Not written to disk — it is an
  // in-memory answer to "what did this bundle actually swallow?".
  metafile: true,
  platform: 'node',
  format: 'esm',
  // The floor the repository already commits to (`engines.node: >=18`). Naming
  // it makes esbuild refuse to emit syntax an 18.x runtime cannot parse, rather
  // than us hearing about it from a user.
  target: 'node18',
  // ★ DETERMINISM. esbuild writes each module's path comment RELATIVE TO THE
  // WORKING DIRECTORY, so `node apps/cli/build.mjs` from the repo root and
  // `npm run build -w @vibeguard/cli` (npm chdirs into apps/cli) produced
  // byte-different bundles — `// packages/rules/...` versus
  // `// ../../packages/rules/...`. Pinning it here makes the artefact depend on
  // the commit and not on how the build was invoked, which is the difference
  // between a diffable release and one nobody can reproduce.
  absWorkingDir: REPO_ROOT,
  // See the header. Not negotiable without re-reading the paragraph on
  // `sourcesContent` and absolute build paths.
  sourcemap: false,
  // Minification would strip the per-module path comments that
  // `assertLazyBoundaries()` above — and any forensic read of a shipped
  // artefact — depend on. The CLI is not fetched over a slow link a hundred
  // times a day; legibility wins.
  minify: false,
  //
  // ── NO `banner: { js: '#!/usr/bin/env node' }` — MEASURED ──────────────────
  //
  // The obvious way to put a shebang on a bundle is the banner. Here it is
  // wrong, and wrong in a way that only appears at runtime: `src/index.ts`
  // ALREADY starts with `#!/usr/bin/env node`, and esbuild preserves an entry
  // point's hashbang at offset 0 of the output. A banner therefore emits it
  // TWICE, and the second copy is not at the start of the file, so it is not a
  // hashbang — it is a syntax error. Measured on esbuild 0.21.5:
  //
  //   #!/usr/bin/env node     ← banner
  //   #!/usr/bin/env node     ← preserved from src/index.ts
  //   SyntaxError: Invalid or unexpected token
  //
  // and `node dist/index.js` refused to start at all. So the shebang comes from
  // the source, where it already lived, and the check below makes that a
  // verified property rather than an accident: exactly one, at offset 0. If a
  // future esbuild stops preserving hashbangs, or someone tidies the line out
  // of `src/index.ts`, the BUILD fails — not the user's `vibeguard`.
  //
  // Nothing else may be external. `node:*` builtins already are, implicitly, on
  // platform:node; any other external name is a name `npm i <tarball>` would
  // have to resolve, which is the bug being fixed.
  logLevel: 'info',
});

const code = readFileSync(OUTFILE, 'utf8');
const problems = [...assertLazyBoundaries(code), ...assertActionBuildsWhatWeInlined(result.metafile)];

const bytes = statSync(OUTFILE).size;
if (bytes < MIN_BUNDLE_BYTES) {
  problems.push(
    `dist/index.js is ${bytes} bytes, under the ${MIN_BUNDLE_BYTES}-byte floor. A bundle this ` +
      'small cannot contain the analyzer, so the CLI would start, exit 0 and report nothing.',
  );
}

const SHEBANG = '#!/usr/bin/env node';
if (!code.startsWith(`${SHEBANG}\n`)) {
  problems.push(
    'dist/index.js does not start with `#!/usr/bin/env node`, so the `bin` entry is not ' +
      'executable on POSIX. It comes from line 1 of src/index.ts, which esbuild preserves as ' +
      'the entry point hashbang — check that the line is still there and still first.',
  );
}
const shebangCount = code.split(SHEBANG).length - 1;
if (shebangCount !== 1) {
  problems.push(
    `dist/index.js contains ${shebangCount} copies of the shebang; only the one at offset 0 is ` +
      'a hashbang, and any other is a syntax error that stops node loading the file at all. ' +
      'Do not add a banner — the entry point already carries it.',
  );
}

if (problems.length > 0) {
  for (const p of problems) console.error(`[vibeguard-cli] BUILD ASSERTION FAILED: ${p}`);
  process.exit(1);
}

console.log(
  `[vibeguard-cli] bundled ${bytes} bytes → dist/index.js ` +
    `(${REQUIRED_PACKAGE_DIRS.length} required packages inlined, ${LAZY_SPECIFIERS.length} lazy boundaries intact)`,
);
