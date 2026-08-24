// The shipping shape of the CLI, pinned.
//
// WHY THIS FILE EXISTS
//
// The CLI is distributed as one thing: the tarball `release.yml` attaches to a
// GitHub Release. For several releases that tarball could not be installed at
// all. `apps/cli/dist/index.js` was `tsc` output that still imported
// `@vibeguard/analyzer-core`, and the manifest declared six `@vibeguard/*`
// packages as runtime `dependencies` — names that are deliberately and
// permanently absent from every registry — so `npm i vibeguard-cli-X.Y.Z.tgz`
// stopped at dependency resolution.
//
// Nothing caught it. `npm pack` succeeds on a package that cannot be installed,
// every test passed, the self-scan was green, and the a2 egress audit was green.
// The failure lived exclusively in the gap between "the workspace runs" and
// "the artefact runs", and no assertion in the repository straddled that gap.
//
// So the assertions below come in two halves, and both halves are load-bearing:
//
//   MANIFEST   — always runs. What the tarball will DECLARE. These are the
//                cheap checks that would have caught the original bug on the
//                commit that introduced it.
//   ARTEFACT   — runs when `dist/index.js` exists. What the tarball will
//                CONTAIN, including a parity check against the workspace
//                analyzer, because the specific way bundling fails silently is
//                a bundle that installs, runs, exits 0 and finds nothing.
//
// ★ THE FAILURE THIS FILE IS MOST AFRAID OF is not "the build broke". It is
// "the build succeeded and tree-shook the rule registry away". A scanner that
// reports zero findings looks exactly like a clean repository, in CI and to a
// user, so the artefact half never asserts a property of the bundle without
// also asserting that the bundle still FINDS something.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';
import { describe, expect, it } from 'vitest';
import { scanPath } from '@vibeguard/analyzer-core';

const CLI_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = join(CLI_DIR, '..', '..');
const BUNDLE = join(CLI_DIR, 'dist', 'index.js');

const pkg = JSON.parse(readFileSync(join(CLI_DIR, 'package.json'), 'utf8')) as {
  main: string;
  files: string[];
  bin: Record<string, string>;
  scripts: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

/** The workspace packages the CLI reaches, in either import form. */
const WORKSPACE_DEPS = [
  '@vibeguard/analysis-graph',
  '@vibeguard/analyzer-core',
  '@vibeguard/external-adapters',
  '@vibeguard/findings-schema',
  '@vibeguard/remediation-engine',
  '@vibeguard/sarif-adapter',
] as const;

describe('CLI manifest: the tarball must be installable with no registry', () => {
  // THE assertion. Exact equality on the whole key list rather than "does not
  // contain @vibeguard": a third-party runtime dependency would be just as
  // unwelcome (see PROD_DEP_ALLOWLIST in scripts/sec-a2-egress-scan.mjs, which
  // makes the same demand from the other side), and `toEqual([])` says what the
  // shipping shape IS instead of listing one thing it is not.
  it('declares zero runtime dependencies', () => {
    expect(Object.keys(pkg.dependencies ?? {})).toEqual([]);
  });

  // The other half of the same fact. If these ever vanish entirely rather than
  // moving, esbuild resolves them through the workspace symlinks anyway and the
  // manifest stops recording what the bundle is made of.
  it('keeps every workspace package as a devDependency, because the bundle inlines them', () => {
    const dev = Object.keys(pkg.devDependencies ?? {});
    for (const name of WORKSPACE_DEPS) expect(dev).toContain(name);
    // esbuild is what does the inlining; leaving it undeclared would make the
    // build depend on a package hoisted here only as a transitive of vitest.
    expect(dev).toContain('esbuild');
  });

  // Every `@vibeguard/*` specifier in the sources must be declared. This is the
  // check that survives someone adding a seventh package: the import resolves
  // through the workspace symlink whether or not the manifest mentions it, so
  // without this the manifest silently stops describing the bundle.
  it('declares every @vibeguard/* package the sources actually import', () => {
    const sources = ['index.ts', 'args.ts', 'diff.ts', 'fix.ts', 'format.ts', 'declared-packages.ts'];
    const imported = new Set<string>();
    for (const file of sources) {
      const text = readFileSync(join(CLI_DIR, 'src', file), 'utf8');
      for (const line of text.split(/\r?\n/)) {
        // Skip comment lines: index.ts discusses these package names in prose.
        const trimmed = line.trimStart();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;
        for (const m of line.matchAll(/['"](@vibeguard\/[\w-]+)(?:\/[\w-]+)?['"]/g)) {
          imported.add(m[1]!);
        }
      }
    }
    // Positive control for the extractor itself: a regex that matched nothing
    // would make this test pass while checking nothing at all.
    expect(imported.size).toBeGreaterThanOrEqual(4);
    expect(imported.has('@vibeguard/analyzer-core')).toBe(true);

    const declared = new Set(Object.keys(pkg.devDependencies ?? {}));
    for (const name of imported) expect(declared.has(name)).toBe(true);
  });

  // Measured 2026-08-15: 38 references to the literal path
  // `apps/cli/dist/index.js` across 14 files outside this one — action.yml (2),
  // security-scan.yml (13), no-network-assert.yml (2), README.md (10), the root
  // `scan` script, the demo and fix-pr scripts, several corpus READMEs. None of
  // them goes through the `bin` shim, so renaming the output silently breaks the
  // GitHub Action, which is the channel with the most users and the least
  // visible failure.
  it('keeps dist/index.js as the entry point every consumer hard-codes', () => {
    expect(pkg.bin.vibeguard).toBe('dist/index.js');
    expect(pkg.main).toBe('./dist/index.js');
  });

  // With `files` narrowed to the built bundle, an unbuilt tarball is EMPTY
  // rather than quietly full of stale tsc output and test sources. `prepack` is
  // what guarantees it is never empty: npm runs it for `npm pack`, so the
  // tarball is correct even when someone packs without building first.
  it('ships only the bundle, and rebuilds it on pack', () => {
    expect(pkg.files).toEqual(['dist']);
    expect(pkg.scripts.prepack).toContain('build.mjs');
  });
});

// ── Artefact half ──────────────────────────────────────────────────────────
//
// Same split, and same reasoning, as scripts/packaging-invariants.test.ts: the
// BUILD never skips, this TEST skips exactly once, for the one case where a
// developer has done nothing wrong (fresh clone, no build yet), and the skip is
// written into the test NAME so it cannot scroll past as an unread grey line.
const built = existsSync(BUNDLE);
const name = (what: string): string =>
  built ? what : `!!! SKIPPED — NOT BUILT: run \`npm run build\`; ${what} was NOT verified`;

describe('CLI bundle: what the tarball will contain', () => {
  it.runIf(built)(name('the bundle carries the rules and the analyzer, not a stub'), () => {
    const code = readFileSync(BUNDLE, 'utf8');
    // esbuild writes a path comment for every module it includes. These two
    // packages are the ones whose absence produces a scanner that runs, exits 0
    // and reports nothing.
    expect(/^\/\/ (?:\.\.\/)*packages\/rules\//m.test(code)).toBe(true);
    expect(/^\/\/ (?:\.\.\/)*packages\/analyzer-core\//m.test(code)).toBe(true);
    // A floor, not a budget: measured 682,746 bytes on 2026-08-16. The exact
    // figure moves with ordinary source edits, which is why the assertion is a
    // floor an order of magnitude below it rather than the number itself.
    expect(statSync(BUNDLE).size).toBeGreaterThan(400_000);
  });

  it.runIf(built)(name('nothing is left to resolve at run time'), () => {
    const code = readFileSync(BUNDLE, 'utf8');
    // A surviving `import("@vibeguard/…")` is the original bug in a new costume:
    // the name resolves on no registry, so an installed tarball throws the
    // moment the flag that reaches it is used.
    for (const dep of WORKSPACE_DEPS) {
      expect(code).not.toContain(`import("${dep}`);
      expect(code).not.toContain(`import('${dep}`);
    }
    // `from "@vibeguard/…"` would mean a static import survived as an external.
    expect(/from\s*["']@vibeguard\//.test(code)).toBe(false);
  });

  it.runIf(built)(name('the three lazy imports are still lazy'), () => {
    const code = readFileSync(BUNDLE, 'utf8');
    // src/index.ts loads analysis-graph, external-adapters and
    // sarif-adapter/node on demand, each with a comment saying why the heavy
    // path must not be paid for by `--help`. esbuild expresses a deferred
    // inlined module as `Promise.resolve().then(() => (init_x(), x_exports))`;
    // one per lazy import.
    const deferred = code.match(/Promise\.resolve\(\)\.then\(\(\) => \(init_/g) ?? [];
    expect(deferred.length).toBeGreaterThanOrEqual(3);
  });

  it.runIf(built)(name('the shebang appears exactly once, at offset 0'), () => {
    const code = readFileSync(BUNDLE, 'utf8');
    const SHEBANG = '#!/usr/bin/env node';
    // Both halves are real failures that were observed while building this:
    // none at all makes `bin` unrunnable on POSIX, and a second copy (what a
    // `banner` produces on top of the entry point's own hashbang) is a
    // SyntaxError that stops node loading the file at all.
    expect(code.startsWith(`${SHEBANG}\n`)).toBe(true);
    expect(code.split(SHEBANG).length - 1).toBe(1);
  });

  // ★ THE POSITIVE CONTROL. Everything above reads the bundle as text; this runs
  // it. The bundled CLI and the workspace analyzer are pointed at the same
  // corpus and their rule-id multisets must be EQUAL — which is a statement
  // neither side can satisfy by finding nothing, because the workspace side is
  // separately required to be non-empty.
  //
  // Comparing against the live analyzer rather than a recorded list is what
  // keeps this from going stale: adding or removing a rule moves both sides
  // together, while a bundle that lost the registry moves only one.
  it.runIf(built)(
    name('the bundled CLI and the workspace analyzer report the same rules'),
    async () => {
      const target = join(REPO_ROOT, 'samples', 'vulnerable');

      const fromSource = await scanPath(target, { mode: 'standard' });
      const sourceRules = fromSource.findings.map((f) => f.ruleId).sort();
      // Vacuity guard. If the corpus ever stops producing findings, an equal
      // pair of empty arrays would report success while proving nothing.
      expect(sourceRules.length).toBeGreaterThan(0);

      const stdout = execFileSync(
        process.execPath,
        [BUNDLE, target, '--mode', 'standard', '--format', 'json', '--fail-on', 'never'],
        { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] },
      );
      const fromBundle = JSON.parse(stdout) as { findings: { ruleId: string }[] };
      const bundleRules = fromBundle.findings.map((f) => f.ruleId).sort();

      expect(bundleRules).toEqual(sourceRules);
    },
    60_000,
  );
});

describe('--after-build, exercised through the BUILT CLI', () => {
  // ── WHY THIS SPAWNS dist/index.js AND NOT THE SOURCE ──────────────────────
  //
  // The feature reaches its dependencies through two dynamic imports and a
  // subpath export. Every one of those is a thing that resolves in a workspace
  // and can fail in a tarball, and the failure mode is quiet by design: the
  // catch writes one line to stderr and the run continues. A unit test over the
  // source would pass while the shipped CLI silently never checked anything —
  // which is precisely the class of defect this whole feature exists to detect,
  // and it would be embarrassing to ship it inside the detector.
  //
  // ★ WHAT IT DOES NOT PIN, corrected here because the first version of this
  // comment claimed it did. `crossExamine` takes `illegalClaimTransition` as an
  // argument, and the states asserted below would appear identically if a
  // refactor passed `() => null` — a guard that permits everything produces
  // exactly the PRESENT and REINTRODUCED this test looks for. All these asserts
  // exclude is a guard that refuses everything.
  //
  // The refusing half is covered by `crossExamine`'s own suite, which hands it
  // a guard that always refuses and requires NOT_OBSERVED. Through the CLI it
  // is currently unpinnable: nothing the CLI builds is an artefact-layer
  // claimant, so no input to the shipped binary can reach the illegal
  // transition. That is a real gap in the pin, and naming it is worth more than
  // a comment that implies otherwise.

  const SOURCE = [
    'export function deleteUser(session, targetId) {',
    "  if (process.env.NODE_ENV !== 'production') {",
    "    if (!session.isAdmin) throw new Error('forbidden');",
    '  }',
    '  return db.remove(targetId);',
    '}',
    'export function purge(session, id) {',
    '  if (import.meta.env.DEV) {',
    "    if (!session.isOwner) throw new Error('unauthorized');",
    '  }',
    '  return db.drop(id);',
    '}',
  ].join('\n');

  function project(): { root: string; src: string; dist: string } {
    const root = mkdtempSync(join(tmpdir(), 'vg-afterbuild-'));
    const src = join(root, 'src');
    const dist = join(root, 'dist');
    mkdirSync(src);
    mkdirSync(dist);
    writeFileSync(join(src, 'app.js'), `${SOURCE}\n`, 'utf8');
    return { root, src, dist };
  }

  /**
   * ★ esbuild's JS API, never `node node_modules/esbuild/bin/esbuild`. See the
   * long note on the same function in `fix-ledger.test.ts`: on anything that is
   * not Windows, esbuild's installer replaces that path with the NATIVE
   * executable, so feeding it to `process.execPath` parses an ELF header as
   * JavaScript. Green here, red on every runner.
   */
  function build(src: string, dist: string): void {
    buildSync({
      entryPoints: [join(src, 'app.js')],
      outfile: join(dist, 'app.js'),
      minify: true,
      format: 'esm',
      drop: ['console'],
      sourcemap: true,
    });
  }

  function scan(target: string, extra: string[]): { findings: unknown[]; [k: string]: unknown } {
    const stdout = execFileSync(
      process.execPath,
      [BUNDLE, target, '--mode', 'standard', '--format', 'json', '--fail-on', 'never', ...extra],
      { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    return JSON.parse(stdout);
  }

  it.runIf(built)(
    name('the shipped CLI settles claims against the shipped bytes'),
    () => {
      const { src, dist } = project();
      build(src, dist);
      const report = scan(src, ['--after-build', dist]) as {
        protectionClaims?: { state: string; witness?: string }[];
        afterBuild?: { artefactsRead: number; artefactsMeasured: number };
      };
      const claims = report.protectionClaims ?? [];
      // Vacuity guard: if the rules stop firing, every assertion below passes
      // over an empty array.
      expect(claims.length, 'the fixture must produce claims').toBeGreaterThan(0);
      expect(report.afterBuild?.artefactsMeasured).toBeGreaterThan(0);

      const states = new Set(claims.map((c) => c.state));
      // The guard that esbuild folds away is gone from the code and still in
      // the map; the one behind import.meta.env.DEV survives this build. If the
      // dynamic imports had failed, everything would be NOT_OBSERVED.
      expect(states.has('REINTRODUCED'), `states were ${[...states].join(', ')}`).toBe(true);
      expect(states.has('PRESENT'), `states were ${[...states].join(', ')}`).toBe(true);
    },
    120_000,
  );

  it.runIf(built)(
    name('a vendor chunk carrying the same tokens cannot turn a loss into a pass'),
    () => {
      const { src, dist } = project();
      build(src, dist);
      // Another chunk that mentions every witness and knows nothing of this
      // source. Before jurisdiction, this flipped the verdicts to PRESENT.
      writeFileSync(
        join(dist, 'vendor.js'),
        'export function can(u){return u.isAdmin && u.isOwner}\n//# sourceMappingURL=vendor.js.map\n',
        'utf8',
      );
      writeFileSync(
        join(dist, 'vendor.js.map'),
        JSON.stringify({
          version: 3,
          sources: ['v.js'],
          sourcesContent: ['export function can(u){return u.isAdmin && u.isOwner}'],
        }),
        'utf8',
      );
      const report = scan(src, ['--after-build', dist]) as {
        protectionClaims?: { state: string }[];
      };
      const states = (report.protectionClaims ?? []).map((c) => c.state);
      expect(states).toContain('REINTRODUCED');
    },
    120_000,
  );

  it.runIf(built)(
    name('claims are reported without --after-build, as claims rather than results'),
    () => {
      const { src } = project();
      const report = scan(src, []) as { protectionClaims?: { state: string }[]; afterBuild?: unknown };
      const claims = report.protectionClaims ?? [];
      expect(claims.length).toBeGreaterThan(0);
      // Nothing settled anything, and nothing pretended to.
      expect(claims.every((c) => c.state === 'NOT_OBSERVED')).toBe(true);
      expect(report.afterBuild).toBeUndefined();
    },
    120_000,
  );

  it.runIf(built)(
    name('a build directory with nothing to read is reported, not passed over'),
    () => {
      const { src, dist } = project();
      const report = scan(src, ['--after-build', dist]) as {
        afterBuild?: { artefactsRead: number };
        protectionClaims?: { state: string }[];
      };
      // dist exists and is empty. "We looked and there was nothing" must be
      // distinguishable from "we never looked".
      expect(report.afterBuild).toBeDefined();
      expect(report.afterBuild?.artefactsRead).toBe(0);
      expect((report.protectionClaims ?? []).every((c) => c.state === 'NOT_OBSERVED')).toBe(true);
    },
    120_000,
  );
});
