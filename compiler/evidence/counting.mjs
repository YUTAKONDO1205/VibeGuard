// The counting contract, in one place so that every entry point in this
// component obeys the same one.
//
// WHY THIS IS A MODULE AND NOT A HABIT
//
//   Three separate checks in this repository have reported success over an
//   empty input set. Each time the code was correct for every case it had been
//   given something to look at, and each time the bug was the same: a loop over
//   nothing runs cleanly, a findings array stays empty, and the exit code says
//   the thing that was never examined is fine. `--self-test` handed a vector
//   file containing `{"vectors":[]}` exited 0 here until the day this file was
//   written, and the clock audit pointed at an empty directory did the same
//   before it grew the guard it now has. The guards were added one at a time,
//   after the fact, by whoever noticed — which is why there were three.
//
//   So the rule is stated once and imported, and it is stated as an arithmetic
//   identity rather than as an inequality:
//
//       inputs = checked + skipped,  and  inputs = 0 is not success
//
//   The identity matters as much as the emptiness test. A runner that counts
//   ten inputs, checks three and reports nothing skipped has lost seven, and a
//   report of "no findings" over it is the same lie in a costume. Both
//   conditions land on exit 3 — the code that means "a check could not be
//   completed" — and never on 0.
//
// THE ESCAPE HATCH, AND WHY IT IS A FLAG
//
//   Some runs legitimately have nothing to do: a store that has not been
//   written to yet, a filter that matched nothing on purpose. Those pass
//   `--allow-empty`. It is a flag and not an inferred condition because the
//   caller has to say out loud that an empty run was expected; a tool that
//   works it out for itself is back to guessing, and guessing is what produced
//   the three.

/**
 * interfaces.md §7. Mirrored rather than imported so that this component has
 * no build-order dependency on the driver; the numbers are fixed by the
 * contract and are not renumbered.
 */
export const EXIT_INCOMPLETE = 3;

/** The one line every entry point prints. Its shape is part of the contract. */
export function countingLine({ inputs, checked, skipped }) {
  return `inputs=${inputs} checked=${checked} skipped=${skipped}`;
}

/**
 * Apply the contract to one run's counts.
 *
 * @param {{
 *   inputs: number,
 *   checked: number,
 *   skipped: number,
 *   allowEmpty?: boolean,
 *   what?: string,
 *   where?: string|null,
 * }} counts
 * @returns {{line: string, code: number|null, empty: boolean, problems: string[]}}
 *   `code` is `null` when the contract has nothing to say and the caller's own
 *   verdict decides the exit status; otherwise it is the exit code the contract
 *   forces, which the caller must not lower.
 */
export function settleCounts({
  inputs,
  checked,
  skipped,
  allowEmpty = false,
  what = 'input',
  where = null,
}) {
  const line = countingLine({ inputs, checked, skipped });
  const problems = [];
  const whole = [inputs, checked, skipped].every((n) => Number.isInteger(n) && n >= 0);

  if (!whole) {
    problems.push(`the counts are not whole numbers: ${line}`);
  } else if (checked + skipped !== inputs) {
    problems.push(
      `the counts do not add up: ${line}. checked + skipped must equal inputs — ` +
        `${inputs - checked - skipped} ${what}(s) are unaccounted for, and a verdict over a set ` +
        'that lost members is a verdict about a different set.',
    );
  }

  // ── The line the whole contract rests on. ────────────────────────────────
  //
  // It keys on `checked`, not on `inputs`, and the difference is deliberate.
  // Nought inputs and nought checked out of ten are the same bug wearing two
  // hats: in both cases the run examined nothing and is about to report that
  // nothing was wrong. The second hat is the one that gets away with it —
  // "10 files, 0 findings" reads like work was done.
  //
  // Reverting this to `const empty = false;` restores the bug the module exists
  // for: every entry point in this component goes back to exiting 0 over an
  // empty input set. compiler/evidence/test/counting.test.mjs and the empty-run
  // cases in selftest-empty.test.mjs and store-cli.test.mjs all fail when it is.
  const empty = whole && checked === 0 && !allowEmpty;

  if (empty) {
    problems.push(
      (inputs === 0
        ? `no ${what} was examined${where ? ` under ${where}` : ''}: ${line}. A clean report over an empty set`
        : `every one of the ${inputs} ${what}(s)${where ? ` under ${where}` : ''} was skipped: ${line}. ` +
          'A clean report over a set none of which was read') +
        ' says nothing about anything, so it is not reported as clean. Pass --allow-empty if that was ' +
        'the expected outcome.',
    );
  }

  return { line, code: problems.length > 0 ? EXIT_INCOMPLETE : null, empty, problems };
}

/**
 * Print the counting line and the contract's complaints, and return the exit
 * code the contract forces (or `null`).
 *
 * In `--json` mode the line goes to stderr so that stdout stays parseable; the
 * counts are also handed back so the caller can put them in the document. The
 * line is printed either way — an entry point that reports counts only when a
 * human is watching is an entry point whose counts nobody checks.
 */
export function reportCounts(counts, { json = false, out = process.stdout, err = process.stderr } = {}) {
  const settled = settleCounts(counts);
  (json ? err : out).write(`${settled.line}\n`);
  for (const p of settled.problems) err.write(`${p}\n`);
  return settled;
}
