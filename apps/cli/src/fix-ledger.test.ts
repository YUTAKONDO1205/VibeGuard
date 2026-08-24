// The fixer ledger, end to end, through the SHIPPED binary.
//
// Every test here spawns `dist/index.js` rather than calling the module. The
// ledger's whole job is to carry a claim across two separate runs of the tool,
// so a test that calls the functions in one process proves the least
// interesting half. It also has to survive the same dynamic-import and subpath
// resolution the `--after-build` channel depends on, and those resolve in a
// workspace and can fail in a tarball.
//
// ★ THESE TESTS SKIP SILENTLY WITHOUT A BUILD. `it.runIf(built)` is what the
// neighbouring suite uses, and the failure mode is that an unbuilt tree reports
// green having verified nothing. The name carries the reason so a skipped run
// says why in its own output.

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';
import { describe, expect, it } from 'vitest';

const CLI_DIR = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = join(CLI_DIR, '..', '..');
const BUNDLE = join(CLI_DIR, 'dist', 'index.js');
const built = existsSync(BUNDLE);
const name = (s: string): string => (built ? s : `${s} [SKIPPED: apps/cli/dist is not built]`);

/**
 * A file the fixer will INSERT a protection into.
 *
 * VG-INJ-020 is the right fixture and `console.assert` was the wrong one: the
 * ledger is about a protection the fixer ADDED, and only a rule with an actual
 * fixer produces one. This recursive merge lets an attacker-controlled key
 * reach `__proto__`, and the fix anchors a guard line inside the loop —
 * a real runtime check, so a minifier keeps it, which is what makes the
 * PRESENT case reachable at all.
 */
const SOURCE = [
  'export function merge(dst, src) {',
  '  for (const k in src) {',
  '    if (typeof src[k] === "object") merge(dst[k], src[k]);',
  '    else dst[k] = src[k];',
  '  }',
  '  return dst;',
  '}',
].join(String.fromCharCode(10));

/** The text the fixer inserts, and therefore the probe the ledger records. */
const GUARD = 'if (k === "__proto__" || k === "constructor" || k === "prototype") continue;';

function project(): { root: string; src: string; dist: string; file: string } {
  const root = mkdtempSync(join(tmpdir(), 'vg-fixledger-'));
  const src = join(root, 'src');
  const dist = join(root, 'dist');
  mkdirSync(src);
  mkdirSync(dist);
  const file = join(src, 'app.js');
  writeFileSync(file, `${SOURCE}\n`, 'utf8');
  return { root, src, dist, file };
}

/**
 * Run the shipped CLI and capture BOTH streams.
 *
 * `spawnSync` rather than `execFileSync`, and the difference is not cosmetic:
 * `execFileSync` hands back stderr only on the error object, so a run that
 * SUCCEEDS loses it entirely. Half of what this channel says — the ledger
 * notes, the ordering warning — is written to stderr on successful runs, so an
 * `execFileSync` harness would assert against an empty string and pass by
 * looking at nothing.
 */
function run(args: string[]): { stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [BUNDLE, ...args], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return { stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const fix = (target: string): { stdout: string; stderr: string } =>
  run([target, '--fix', '--mode', 'standard', '--fail-on', 'never']);

const scan = (
  target: string,
  extra: string[] = [],
): { protectionClaims?: { claimant: string; claimantLayer: string; state: string; note?: string }[] } =>
  JSON.parse(
    run([target, '--mode', 'standard', '--format', 'json', '--fail-on', 'never', ...extra]).stdout ||
      '{}',
  );

/**
 * Minify the fixture the way a real project's build step would.
 *
 * ★ THROUGH esbuild's JS API, NEVER `node node_modules/esbuild/bin/esbuild`.
 * That spelling is green on Windows and red on every runner, and the asymmetry
 * is not a flake — it is what esbuild's own installer does. `install.js`
 * ends in `maybeOptimizePackage`, which on `platform !== 'win32'` hard-links
 * the platform's NATIVE executable over `bin/esbuild` to save a node start-up
 * per invocation. So the same path is a JS shim on a developer's Windows
 * machine and an ELF binary in CI, and handing the ELF to `process.execPath`
 * fails at parse: `SyntaxError: Invalid or unexpected token` on a line whose
 * first four bytes are `\x7fELF`. Six tests here and two in `bundle.test.ts`
 * failed exactly that way on the merge of #85, having passed locally.
 *
 * The API has no such platform seam — esbuild resolves its own binary — and
 * the flags map one-to-one onto what the command line took.
 */
function build(src: string, dist: string): void {
  buildSync({
    entryPoints: [join(src, 'app.js')],
    outfile: join(dist, 'app.js'),
    minify: true,
    format: 'esm',
    sourcemap: true,
  });
}

// The ledger lives under the directory that was SCANNED, which is src/ and not
// the project root above it. Getting this wrong makes every assertion below
// read a file the CLI never writes, and pass or fail for the wrong reason.
const ledgerFile = (scanned: string): string => join(scanned, '.vibeguard', 'fix-ledger.json');
const ledgerOf = (scanned: string): { entries: unknown[] } =>
  JSON.parse(readFileSync(ledgerFile(scanned), 'utf8'));
const fixerClaims = (
  r: ReturnType<typeof scan>,
): { claimant: string; state: string; note?: string }[] =>
  (r.protectionClaims ?? []).filter((c) => c.claimantLayer === 'fixer');

describe('the fixer ledger carries a claim across two runs', () => {
  it.runIf(built)(
    name('an inserted protection is recorded, and a later scan settles it against the build'),
    () => {
      const { src, dist, file } = project();

      const fixed = fix(src);
      expect(fixed.stdout).toContain('protection(s) were inserted');
      // Vacuity guard: without a recorded entry every assertion below passes
      // over an empty ledger.
      expect(existsSync(ledgerFile(src)), 'the fixer must write a ledger').toBe(true);
      expect(ledgerOf(src).entries.length).toBeGreaterThan(0);
      expect(readFileSync(file, 'utf8')).toContain(GUARD);

      // The build the ledger is waiting for. Before it, there is nothing on
      // disk that could carry the line just written.
      build(src, dist);

      const claims = fixerClaims(scan(src, ['--after-build', dist]));
      expect(claims.length, 'the ledger must produce a fixer claim').toBeGreaterThan(0);
      // The point of the whole file: a claim whose finding no longer exists is
      // still adjudicated. NOT_OBSERVED here would mean the ledger round-trip
      // ran and settled nothing, which is the outcome this replaces.
      expect(
        claims.some((c) => c.state === 'PRESENT'),
        `fixer claim states were ${claims.map((c) => c.state).join(', ')}`,
      ).toBe(true);
    },
    180_000,
  );

  it.runIf(built)(
    name('an edit that was reverted expires instead of reading as a removed protection'),
    () => {
      const { src, dist, file } = project();
      fix(src);
      build(src, dist);
      // ★ THE MUTATION DETECTOR FOR THE LINE BINDING. Put the file back the way
      // it was: the recorded edit is gone from the source, so the claim is
      // about nothing. Reporting LOST here would be the ledger inventing a
      // removed protection out of a repair the user undid.
      writeFileSync(file, `${SOURCE}\n`, 'utf8');

      const claims = fixerClaims(scan(src, ['--after-build', dist]));
      expect(claims.length, 'the expired claim must still be reported').toBeGreaterThan(0);
      for (const c of claims) {
        expect(c.state).toBe('NOT_OBSERVED');
        expect(c.note ?? '').toContain('no longer in the source');
      }
      // And it is pruned, so it cannot come back and cost a reader attention
      // on every future scan.
      expect(ledgerOf(src).entries.length).toBe(0);
    },
    180_000,
  );

  it.runIf(built)(
    name('a ledger that cannot be read is said aloud and settles nothing'),
    () => {
      const { src, dist } = project();
      build(src, dist);
      mkdirSync(join(src, '.vibeguard'), { recursive: true });
      writeFileSync(ledgerFile(src), '{ this is not json', 'utf8');

      const out = run([src, '--mode', 'standard', '--format', 'json', '--fail-on', 'never', '--after-build', dist]);
      // The scan continues — a broken ledger degrades this channel and nothing
      // else — and it does not pass in silence.
      expect(out.stderr).toContain('did not parse as JSON');
      const report = JSON.parse(out.stdout || '{}') as ReturnType<typeof scan>;
      expect(fixerClaims(report)).toHaveLength(0);
      for (const c of report.protectionClaims ?? []) {
        expect(c.claimantLayer).not.toBe('artifact');
      }
    },
    180_000,
  );

  it.runIf(built)(
    name('--fix with --after-build refuses to settle against a build older than the edit'),
    () => {
      const { src, dist } = project();
      // A ledger has to exist for there to be anything to say this about, so
      // fix once and build, which is the state a user combining the flags is
      // actually in.
      fix(src);
      build(src, dist);
      const out = run([src, '--fix', '--mode', 'standard', '--fail-on', 'never', '--after-build', dist]);
      const said = `${out.stdout}${out.stderr}`;
      // The ordering is what gets said. The correctness does not rest on this
      // message — jurisdiction already refuses to settle a claim against a
      // build that does not carry its probe — but a user who asked for both
      // reasonably expects to be told which half happened.
      expect(said).toMatch(/made before this run wrote anything|Rebuild, then scan again/);
    },
    180_000,
  );
});

describe('the ledger refuses what it cannot trust', () => {
  it.runIf(built)(
    name('an entry naming a path outside the target is ignored, not opened'),
    () => {
      const { src, dist } = project();
      build(src, dist);
      mkdirSync(join(src, '.vibeguard'), { recursive: true });
      writeFileSync(
        ledgerFile(src),
        JSON.stringify({
          version: 1,
          entries: [
            {
              ruleId: 'VG-AUTH-010',
              title: 'traversal',
              safety: 'recorded',
              filePath: '../../../../etc/passwd',
              startLine: 1,
              insertedLine: GUARD,
              witness: '__proto__',
              createdAt: '2026-08-24T00:00:00.000Z',
            },
            {
              // Degenerate witness: the one input that would make a substring
              // matcher report PRESENT for everything.
              ruleId: 'VG-AUTH-010',
              title: 'empty witness',
              safety: 'recorded',
              filePath: 'app.js',
              startLine: 1,
              insertedLine: GUARD,
              witness: '',
              createdAt: '2026-08-24T00:00:00.000Z',
            },
          ],
        }),
        'utf8',
      );

      const claims = fixerClaims(scan(src, ['--after-build', dist]));
      // The traversal entry must not appear at all; the witness-less one may
      // appear only as something unsettled.
      expect(claims.some((c) => JSON.stringify(c).includes('passwd'))).toBe(false);
      for (const c of claims) expect(c.state).not.toBe('PRESENT');
    },
    180_000,
  );

  it.runIf(built)(
    name('a ledger cannot promote itself to a layer that would settle itself'),
    () => {
      const { src, dist } = project();
      build(src, dist);
      mkdirSync(join(src, '.vibeguard'), { recursive: true });
      writeFileSync(
        ledgerFile(src),
        JSON.stringify({
          version: 1,
          entries: [
            {
              ruleId: 'VG-AUTH-010',
              title: 'self-settling attempt',
              safety: 'recorded',
              // The field a hand-written ledger would most want to control.
              claimantLayer: 'artifact',
              filePath: 'app.js',
              startLine: 2,
              insertedLine: GUARD,
              witness: '__proto__',
              createdAt: '2026-08-24T00:00:00.000Z',
            },
          ],
        }),
        'utf8',
      );

      const all = scan(src, ['--after-build', dist]).protectionClaims ?? [];
      const mine = all.filter((c) => c.claimant.startsWith('fixer:'));
      expect(mine.length, 'the entry must be read, or this asserts nothing').toBeGreaterThan(0);
      // `claimantLayer` is hard-coded in `claimsFromLedger`, so the file's own
      // value is discarded. If it were ever read, this claim would be an
      // artefact-layer claimant settling an artefact-layer observation.
      for (const c of mine) expect(c.claimantLayer).toBe('fixer');
    },
    180_000,
  );
});
