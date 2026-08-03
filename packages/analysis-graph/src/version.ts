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
/**
 * ★ 0.3.0-alpha.1 → 0.3.0-beta.1 (0.3.0-β).
 *
 * It should have moved when the β wave landed and did not, and the consequence
 * was measurable rather than cosmetic: a scan run against the four rules added
 * in β (VG-SMELL-020/021/041/052) reported `engineVersions['analysis-graph'] =
 * '0.3.0-alpha.1'` — the same string an alpha build reported while running half
 * as many rules. This axis exists precisely so that two runs which can disagree
 * are not labelled identically, so leaving it still was the one failure it is
 * supposed to make impossible.
 *
 * β adds VG-SMELL-011, VG-SMELL-013 and VG-SMELL-030 to the four above, turns on
 * VG-SMELL-010's Python arm, and repairs a VG-AISC-002 false-positive class that
 * removed 23 findings across `paper_data/corpus1k`. Verdicts move in BOTH
 * directions across this boundary, which is what a version change on this axis
 * means.
 */
/**
 * ★ 0.3.0-beta.1 → 0.3.0-beta.2 (#35 TYPEERASE).
 *
 * VG-SMELL-021 no longer counts imports the TypeScript compiler deletes. Two
 * builds either side of this line answer differently about the same input —
 * measured on `paper_data/corpus1k`, 1,000 repositories: 021 goes 3 → 2 and the
 * finding that leaves is `whyour/qinglong back/loaders/express.ts`, whose
 * reported fan-out of 9 included an `interface` and a `type`. Nothing else in
 * the registry moved. A verdict change in either direction is exactly what this
 * axis exists to make visible, so it moves with the rule and not after it.
 */
/**
 * ★ 0.3.0-beta.2 → 0.3.0-beta.3 (#41 JSEXPORT-COUPLING).
 *
 * beta.2 asked `exportedNames` whether a name is a runtime value. It got the
 * right answer for the wrong reason: the structure indexer's `JS_EXPORT` has no
 * `interface`/`type` in its modifier list, so `export interface Cfg` binds the
 * WORD `interface` and `Cfg` never appears at all. Measured, not read —
 * `indexFile` on a file exporting `Cfg` and `Scope` returns
 * `exportedNames: ['interface','type']` and no symbols. The erasure filter now
 * asks a question that means what it says, so repairing the indexer (which #36
 * must do) cannot silently resurrect the false positives #35 removed.
 *
 * That much is a no-op on today's inputs. What DOES move is a second omission in
 * the same modifier list: `namespace` is not in it either, and a namespace IS a
 * runtime value. So `export type N` beside `export namespace N` — declaration
 * merging — used to have `N` read as type-only and its edge DELETED, dropping a
 * dependency that exists at run time. It is now kept. Verified directly:
 * `importsOnlyTypes` returns `false` for that shape where it previously returned
 * `true`. `enum` is repaired the same way.
 *
 * The direction is edges KEPT rather than dropped, so fan-out and cycles can only
 * grow, never shrink. That is the conservative direction, but it is still a
 * verdict change, which is what this axis exists to make visible.
 *
 * ⚠ NOT YET MEASURED ON corpus1k. #35 re-ran the 1,000-repository corpus before
 * moving this constant, because it changed findings in the direction that can
 * only shrink them; this change moves them in the direction that can only grow
 * them, and no equivalent A/B has been run. How often `type`/`interface` merges
 * with `namespace` in real code is unmeasured. Recorded here rather than in a
 * commit message because the gap belongs beside the number it qualifies.
 */
export const ANALYSIS_GRAPH_VERSION = '0.3.0-beta.3';
