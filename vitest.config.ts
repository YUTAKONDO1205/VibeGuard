import { configDefaults, defineConfig } from 'vitest/config';

// Root-level Vitest defaults.
//
// `npm test` does not use this file: it runs `vitest run` inside each workspace,
// where the cwd already scopes collection to that package. This config exists
// for the other way the suite gets invoked — `npx vitest run <path>` from the
// repo root, which is how you iterate on a single test file without cd-ing into
// its workspace first.
//
// Run that way, Vitest also walks `.claude/worktrees/`, where parallel agents
// keep their own checkouts of this repository. Those are stale copies of our own
// test files: identical suite names, older assertions, silently double-counted
// in the summary (`apps/cli/src/diff.test.ts` collected as 2 files / 28 tests
// instead of 1 / 18). A test count you cannot trust is worse than no test count,
// and a green run there may be green against code we deleted.
export default defineConfig({
  test: {
    // Spreading `configDefaults.exclude` back in is load-bearing, not decorative:
    // `exclude` replaces Vitest's defaults rather than extending them, so listing
    // only the `.claude` pattern would drop `**/node_modules/**` and `**/dist/**`
    // from the exclusions and pull every dependency's shipped tests into the run.
    exclude: [
      ...configDefaults.exclude,
      '**/.claude/**',
      // `paper_data/` is the vendored evaluation corpus (corpus1k /
      // corpus1k_vibe) — cloned upstream repositories carrying ~25k test files
      // of their own, none of them ours. A root-level run
      // tries to collect all of them and dies with EMFILE before executing a
      // single one of ours. (That failure predates this config; it is listed
      // here because the fix belongs in the same place, not because the
      // `.claude` exclusion caused it.)
      '**/paper_data/**',
    ],
  },
});
