/**
 * Version of the cross-file analysis, reported as
 * `engineVersions['analysis-graph']` on scans that actually ran it.
 *
 * A SEPARATE axis from `ENGINE_VERSION` in `analyzer-core`, and it has to be.
 * `ENGINE_VERSION` answers "would this build produce the same verdicts as that
 * one", and the answer for every scan that does not pass `--include-design-
 * smells` is unchanged by anything in this package — the core path does not
 * import it, does not run it, and cannot be affected by it. Folding this into
 * `ENGINE_VERSION` would announce a detection change to every consumer for whom
 * nothing changed, and would invalidate the paper tags pinned to 0.2.1 for no
 * reason at all.
 *
 * It appears in `engineVersions` only when the cross-file pass ran, so the
 * presence of the key is itself the "this scan saw the whole project" bit.
 *
 * Lives in its own module rather than in `index.ts` so that `project.ts` can
 * read it without importing the barrel that re-exports `project.ts` — a cycle
 * that resolves at runtime in ESM but leaves the constant `undefined` at module
 * evaluation time, which would silently stamp every scan with no version.
 */
export const ANALYSIS_GRAPH_VERSION = '0.3.0-alpha.1';
