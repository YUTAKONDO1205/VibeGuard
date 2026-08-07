// The counting contract, in one place so that every runner in this package
// obeys the same one.
//
// WHY IT IS A CONTRACT AND NOT A CONVENTION
//
// A scan that found nothing to scan reports the same "0 problems" as a scan
// that examined everything and found nothing wrong. That has happened in this
// repository more than once: a probe pointed at the wrong directory, a glob
// that stopped matching after a rename, a filter that silently swallowed a
// whole workspace. In every case the exit code was 0 and the log was green.
//
// So two things are required of every runner here:
//
//   1. it prints `inputs=N checked=N skipped=S`, always, on every path,
//      including the failing ones. A number that is only printed on success is
//      a number nobody reads on the day it matters;
//   2. `inputs === 0` exits NON-ZERO unless the caller passed `--allow-empty`.
//      An empty scan is not a clean scan, and the only way to be told it is
//      acceptable is for a human to say so on the command line.
//
// `skipped` is never allowed to stand in for "checked". A skip is a case that
// was NOT checked, it is listed by name, and if a prerequisite is missing the
// runner fails rather than skipping — unless an environment variable
// authorises it, in which case every skipped case is named in the output.

/** Exit codes, shared with the toolchain workspace so a caller can branch. */
export const EXIT = Object.freeze({
  OK: 0,
  TOOL_FAILED: 1,
  FINDINGS: 2,
  INCOMPLETE: 3,
  INTEGRITY: 4,
});

/**
 * The one line every runner prints.
 *
 * @param {{inputs: number, checked: number, skipped: number}} counts
 * @returns {string}
 */
export function countingLine({ inputs, checked, skipped }) {
  return `inputs=${inputs} checked=${checked} skipped=${skipped}`;
}

/**
 * Print the counting line and every skipped case by name.
 *
 * @param {(s: string) => void} write
 * @param {{inputs: number, checked: number, skipped: number, skippedNames?: string[]}} counts
 */
export function reportCounts(write, counts) {
  write(`${countingLine(counts)}\n`);
  for (const name of counts.skippedNames ?? []) {
    write(`  skipped: ${name}\n`);
  }
}

/**
 * The empty-scan rule. Returns `null` when the run may proceed to report its
 * real verdict, or an exit code when it may not.
 *
 * @param {{inputs: number, allowEmpty: boolean, subject: string, write: (s: string) => void}} args
 * @returns {number|null}
 */
export function emptyScanVerdict({ inputs, allowEmpty, subject, write }) {
  if (inputs > 0) return null;
  if (allowEmpty) {
    write(`no ${subject} found; --allow-empty was passed, so this is not a failure.\n`);
    return EXIT.OK;
  }
  write(
    `no ${subject} found, so nothing was checked. Reporting success here would say "clean"\n` +
      'about an empty set, which is the failure this exit code exists for. Point the runner\n' +
      'at something, or pass --allow-empty to say out loud that an empty run is expected.\n',
  );
  return EXIT.INCOMPLETE;
}
