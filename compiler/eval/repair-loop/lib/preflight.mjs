/**
 * The preflight's refusal checks, judged. Pure: the runner makes the compiles
 * and hands in what it saw.
 *
 * The plugin's contract has two refusals the lane can observe before any cell:
 *   - WPIN_OUT set and no target given: no record may be written.
 *   - no WPIN_OUT: the plugin must say so on stderr, and clang's rc must be
 *     unaffected.
 * A record written without a target, a refusal nobody can hear, or a build an
 * unconfigured plugin broke is how a repair that did not run comes to look like
 * one that did. Each is an integrity failure: the run exits 2, and a run meant
 * for data/ is refused before any cell.
 *
 * @param pre {noRecordWithoutTarget: boolean|null,
 *             noRecordWithoutOut: 'stderr-nonempty'|'stderr-empty'|'compile-failed'|null}
 * @returns {string[]} problems, empty when the checks held
 */
export function preflightProblems(pre) {
  const problems = [];
  const target = pre ? pre.noRecordWithoutTarget : null;
  if (target === false) problems.push('a record was written although no target was given');
  else if (target !== true) problems.push(`the no-target check did not run (${JSON.stringify(target)})`);
  const out = pre ? pre.noRecordWithoutOut : null;
  if (out === 'stderr-empty') problems.push('without WPIN_OUT the plugin was silent (no refusal on stderr)');
  else if (out === 'compile-failed') problems.push('without WPIN_OUT the compile failed (an unconfigured plugin broke the build)');
  else if (out !== 'stderr-nonempty') problems.push(`without WPIN_OUT the check did not run (${JSON.stringify(out)})`);
  return problems;
}
