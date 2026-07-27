// Runs the packaging probe as a test, so it cannot be lost by a workflow edit.
//
// WHY A TEST AND NOT JUST A CI STEP
//
// `check-packaging-invariants.mjs` already runs from `.github/workflows/ci.yml`.
// That is a real safety net and it is also a single line in a YAML file that
// nobody owns. The header of the script itself records the precedent: the
// `@types/vscode` invariant it protects was reintroduced once already, and the
// only thing that would have caught it was a workflow whose author had a
// different goal in mind. Invariants that live exclusively in CI configuration
// evaporate during the refactor that consolidates three jobs into two.
//
// Spawning the script from the suite means the boundary is checked by whatever
// runs the tests — CI, a pre-push hook, a developer iterating locally — and not
// only by one named job.
//
// WHY `execFileSync` ON A CHILD PROCESS RATHER THAN IMPORTING THE SCRIPT
//
// The script is a top-level program: it computes, prints, and calls
// `process.exit(1)`. Importing it into the Vitest worker would kill the worker
// on failure and report the run as a crash rather than as a failed assertion,
// and any second import would be a no-op because ESM caches modules. A child
// process gives the thing this test actually cares about — the exit code the
// operator and CI see — plus the real human-readable output on failure.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPTS_DIR, '..');
const PROBE = join(SCRIPTS_DIR, 'check-packaging-invariants.mjs');

/**
 * The build outputs invariants 3 and 5 read. Their absence is the ONE condition
 * under which this test is allowed to stand down.
 *
 * The probe itself treats a missing `dist/` as a hard failure, deliberately: in
 * CI, "nothing was built" must not be reported as "nothing leaked". But a
 * developer who has just cloned the repo and typed `npx vitest run` has not done
 * anything wrong, and a red suite that only means "you have not built yet"
 * teaches people to ignore red suites. So the split is: the PROBE never skips,
 * this TEST skips exactly once, for exactly that case, and says so at the top of
 * its own volume.
 */
const DIST_DIRS = [
  join(REPO_ROOT, 'extensions', 'chrome', 'dist'),
  join(REPO_ROOT, 'extensions', 'vscode', 'dist'),
];
const distsBuilt = DIST_DIRS.every((d) => existsSync(d));

// The skip is encoded in the test NAME, not only in a `skip` flag, because a
// skipped test scrolls past as a grey line nobody reads. Anyone scanning the
// output for why the packaging boundary was not verified gets told in the same
// glance.
const probeTestName = distsBuilt
  ? 'exits 0: analysis-graph is absent from every shipped extension bundle'
  : '!!! SKIPPED — NOT BUILT: run `npm run build`; the extension bundles were never ' +
    'produced, so the analysis-graph packaging boundary was NOT verified';

describe('packaging invariants probe', () => {
  it.runIf(distsBuilt)(probeTestName, () => {
    let stdout = '';
    try {
      stdout = execFileSync(process.execPath, [PROBE], {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        // Merge the script's failure report into what Vitest prints. Without
        // this the assertion says "exit code 1" and the operator has to re-run
        // the script by hand to learn which invariant fired and why — which is
        // most of the value the script's error messages were written to carry.
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; status?: number };
      throw new Error(
        `scripts/check-packaging-invariants.mjs exited with status ${String(e.status)}.\n\n` +
          `${e.stdout ?? ''}${e.stderr ?? ''}`,
      );
    }
    expect(stdout).toContain('packaging invariants OK');
  });

  // Guards the failure mode the sentinel's own doc comment names: the probe
  // hard-codes the string it searches for, so if the exported constant is ever
  // edited without editing the probe, the probe keeps passing forever while
  // searching for a string nothing emits. That is worse than having no probe,
  // because it looks green.
  //
  // Both sides are read as TEXT rather than imported. Importing the constant
  // would put the literal in this file's module graph, and the probe searches
  // built artefacts for exactly that literal — a test that plants the needle it
  // is checking for is one bundler config away from causing the failure it
  // exists to detect.
  it('probe searches for the same sentinel that analysis-graph exports', () => {
    const exported = readFileSync(
      join(REPO_ROOT, 'packages', 'analysis-graph', 'src', 'index.ts'),
      'utf8',
    );
    const exportedMatch = /AG_BUNDLE_SENTINEL\s*=\s*'([^']+)'/.exec(exported);
    expect(exportedMatch, 'AG_BUNDLE_SENTINEL export not found in analysis-graph/src/index.ts')
      .not.toBeNull();

    const probeSource = readFileSync(PROBE, 'utf8');
    // The probe assembles its needle from two quoted halves on purpose (see the
    // comment on `SENTINEL` there); reconstruct it the same way.
    const probeMatch = /const SENTINEL = '([^']+)'\s*\+\s*'([^']+)'/.exec(probeSource);
    expect(probeMatch, 'concatenated SENTINEL not found in check-packaging-invariants.mjs')
      .not.toBeNull();

    expect(probeMatch![1] + probeMatch![2]).toBe(exportedMatch![1]);
  });

  // The two-mode contract, pinned.
  //
  // `ci.yml` runs this probe twice: `--pre-build` before `npm run build`, and
  // strict afterwards. The first call MUST tolerate absent bundles (dist does
  // not exist yet) and the second MUST NOT (absent bundles there mean the build
  // silently produced nothing). Getting that backwards in either direction is
  // invisible: one way CI fails on every push, the other way the packaging
  // boundary stops being checked at all and nothing says so.
  it('--pre-build reports the source-only subset and names what it skipped', () => {
    const stdout = execFileSync(process.execPath, [PROBE, '--pre-build'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    expect(stdout).toContain('SOURCE-ONLY');
    // The operator must be told which invariants did not run, or a green line
    // reads as full coverage.
    expect(stdout).toContain('did NOT run');
  });

  it('--pre-build still enforces the declaration-level isolation invariant', () => {
    // The mode drops the bundle checks, not the boundary. Invariant 4 (nothing
    // on the light side may declare or import the package) runs in both modes,
    // which is what keeps the cheap pre-build step worth running.
    const stdout = execFileSync(process.execPath, [PROBE, '--pre-build'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    expect(stdout).toContain('declarations / imports');
  });
});
