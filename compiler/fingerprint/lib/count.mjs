// The counting contract.
//
// An empty scan that prints a confident zero and exits 0 has shipped in this
// repository three times. Every runner in this package routes its final line
// through here, and the guard is not advisory: with no inputs the function
// returns exit code 3 (INCOMPLETE, per compiler/schema/interfaces.md section 7)
// unless the caller was explicitly told to allow it.
//
// `skipped` is not a synonym for `checked`. A prerequisite that is missing
// fails the run; the only escape is an environment variable, and taking it
// obliges the caller to list every skipped case by name.

/** Exit codes, matching compiler/driver/lib/exit.mjs. Do not renumber. */
export const EXIT = Object.freeze({
  OK: 0, TOOL_FAILED: 1, FINDINGS: 2, INCOMPLETE: 3, INTEGRITY: 4,
});

/** The environment variable that authorises a skip. Nothing else does. */
export const SKIP_ENV = 'VG_FP_ALLOW_MISSING_TOOLS';

/**
 * Print the mandatory counting line and decide the exit code contribution.
 *
 * @param {{inputs:number, checked:number, skipped:number, allowEmpty?:boolean,
 *          skippedNames?:string[], out?:(s:string)=>void}} arg
 * @returns {number} 0 when the count is acceptable, EXIT.INCOMPLETE otherwise.
 */
export function reportCounts({
  inputs, checked, skipped, allowEmpty = false, skippedNames = [], out = console.log,
}) {
  for (const n of [inputs, checked, skipped]) {
    if (!Number.isInteger(n) || n < 0) throw new TypeError('counts must be non-negative integers');
  }
  out(`inputs=${inputs} checked=${checked} skipped=${skipped}`);
  if (skipped > 0) {
    if (skippedNames.length !== skipped) {
      out(`SKIPPED ${skipped} case(s) but only ${skippedNames.length} were named -- refusing to report a pass`);
      return EXIT.INCOMPLETE;
    }
    for (const name of skippedNames) out(`  skipped: ${name}`);
  }
  if (inputs === 0 && !allowEmpty) {
    out('no inputs: refusing to report a clean scan (pass --allow-empty if an empty set is the expected case)');
    return EXIT.INCOMPLETE;
  }
  if (checked + skipped !== inputs) {
    out(`accounting does not close: ${checked} + ${skipped} != ${inputs}`);
    return EXIT.INCOMPLETE;
  }
  // `inputs > 0` is not the same question as "was anything examined". A run can
  // find sixteen files, skip all sixteen for a named reason, close the
  // accounting perfectly, and have measured nothing — and the guard above lets
  // it through because the emptiness moved from the input set to the checked
  // set. Measured on this file's own callers: a directory of three .ll files
  // that define no functions gave `inputs=3 checked=0 skipped=3` and exit 0.
  //
  // The rule the rest of this file states is that "not checked" and "clean" are
  // different claims. `checked === 0` is the purest case of "not checked", so it
  // gets the same answer as an empty input set: exit 3, and only `--allow-empty`
  // may say otherwise, because that flag is the caller asserting on the record
  // that measuring nothing was the expected outcome.
  if (inputs > 0 && checked === 0 && !allowEmpty) {
    out(`every one of the ${inputs} input(s) was skipped: nothing was examined, so this is not a clean scan`);
    return EXIT.INCOMPLETE;
  }
  return EXIT.OK;
}

/**
 * A prerequisite is missing. Fail, unless the environment authorises the skip.
 * @returns {boolean} true when the caller may skip, false when it must fail.
 */
export function skipAuthorised(env = process.env) {
  return env[SKIP_ENV] === '1';
}
