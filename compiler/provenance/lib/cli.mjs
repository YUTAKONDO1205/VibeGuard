// The counting contract, in one place so that three runners cannot each get it
// slightly wrong.
//
// THE RULE
//
//   Every runner prints exactly one line of the form
//
//       inputs=N checked=N skipped=S
//
//   and exits non-zero when N is 0, unless `--allow-empty` was passed. A scan
//   that found nothing to scan and reported success is the shape of a check
//   pointed at the wrong directory, and it has happened in this repository more
//   than once. Exit 3 is the honest code for it: not "clean", "not checked".
//
//   Two further invariants, both enforced here rather than trusted:
//
//     checked + skipped === inputs   — an input that was neither checked nor
//                                      declared skipped has been lost, and a
//                                      runner that loses inputs cannot be read
//                                      as covering its input set.
//     every skip is named            — a count of skips tells a reader how much
//                                      was not done and not WHAT, so the names
//                                      are printed, every one of them.
//
//   SKIP IS NOT PASS. A skip is only legal when the caller authorised it: a
//   `--allow-empty` for the empty set, or the environment variable named in
//   `SKIP_ENV` for a missing prerequisite tool. Without authorisation a missing
//   prerequisite is a failure, because "we could not look" reported as "we
//   looked and it was fine" is the exact failure this toolchain exists to stop.

import { EXIT_INCOMPLETE, EXIT_OK } from '../../driver/lib/exit.mjs';

/** The environment variable that authorises skipping a case whose tool is absent. */
export const SKIP_ENV = 'PROVENANCE_ALLOW_MISSING_TOOLS';

export function skipsAuthorised(env = process.env) {
  const v = env[SKIP_ENV];
  return v !== undefined && v !== '' && v !== '0';
}

/** The one line every runner prints. */
export function countingLine({ inputs, checked, skipped }) {
  return `inputs=${inputs} checked=${checked} skipped=${skipped}`;
}

/**
 * Print the counting line, the skip list, and decide whether the counts alone
 * already determine the exit code.
 *
 * @param {{inputs: number, checked: number, skipped: number,
 *          skippedNames?: string[], allowEmpty?: boolean,
 *          out?: (s: string) => void, err?: (s: string) => void}} args
 * @returns {number|null} an exit code when the counts decide it, else null —
 *   null means "the counts are sound, the caller's own result decides".
 */
export function reportCounts(args) {
  const {
    inputs, checked, skipped,
    // Set ONLY when skipping everything is a legitimate finished state (the
    // work was already done), never when a prerequisite was missing. The string
    // is printed. See the checked === 0 branch below.
    allSkippedMeans = null,
    skippedNames = [],
    allowEmpty = false,
    out = (s) => process.stdout.write(s),
    err = (s) => process.stderr.write(s),
  } = args;

  out(`${countingLine({ inputs, checked, skipped })}\n`);
  for (const name of skippedNames) out(`  skipped: ${name}\n`);

  if (skippedNames.length !== skipped) {
    err(`counting contract broken: ${skipped} skip(s) counted but ${skippedNames.length} named. `
      + 'A skip that is not named cannot be reviewed.\n');
    return EXIT_INCOMPLETE;
  }
  if (checked + skipped !== inputs) {
    err(`counting contract broken: checked ${checked} + skipped ${skipped} != inputs ${inputs}. `
      + 'Some input was neither checked nor declared skipped.\n');
    return EXIT_INCOMPLETE;
  }
  if (inputs === 0) {
    if (allowEmpty) {
      out('inputs=0 and --allow-empty was given: reporting success over an empty set, '
        + 'which proves nothing about anything.\n');
      return EXIT_OK;
    }
    err('nothing to check. An empty run is not a clean run; pass --allow-empty if an '
      + 'empty input set is genuinely expected here.\n');
    return EXIT_INCOMPLETE;
  }
  // The guard above asks whether anything was FOUND. This one asks whether
  // anything was EXAMINED, and they come apart the moment a skip is authorised:
  // a run can enumerate eleven cases, skip all eleven because the compiler is
  // absent, close the accounting exactly, and return success having built
  // nothing. Measured on this repository: `PROVENANCE_ALLOW_MISSING_TOOLS=1`
  // with an absent compiler printed `cases=0 reproduced=0 differed=0 broken=0`
  // and exited 0. A reproducibility matrix that compiled nothing had reported
  // that the build reproduces.
  //
  // Note the asymmetry with the `inputs === 0` branch: there, `--allow-empty`
  // buys success because the caller is asserting the empty set was expected.
  // Here the caller has asserted no such thing — an authorised skip says "this
  // machine lacks the tool", which is a statement about the machine, not a
  // claim that measuring nothing is the right answer. So the honest code is 3
  // in both the authorised and unauthorised cases, and `--allow-empty` does not
  // launder it.
  if (checked === 0) {
    // Two kinds of "everything was skipped" wear the same counting line, and
    // collapsing them is how this guard would become either useless or wrong:
    //
    //   nothing COULD be done   the compiler is absent, the tool is missing.
    //                           Nothing was measured. Exit 3.
    //   nothing LEFT to do      every record was already signed. The work is
    //                           complete; there was simply none outstanding.
    //                           Exit 0 is the truth here.
    //
    // The caller knows which it is and nothing else does, so the caller says so
    // by naming the reason. Requiring a STRING rather than a boolean is
    // deliberate: the reason is printed, so choosing this branch leaves a
    // sentence in the log that a reviewer can disagree with, instead of a silent
    // `true` that reads as boilerplate.
    if (allSkippedMeans) {
      out(`nothing was examined, and that is the expected outcome here: ${allSkippedMeans}\n`);
      return EXIT_OK;
    }
    err(`all ${inputs} input(s) were skipped, so nothing was examined. That is `
      + 'VERIFICATION_INCOMPLETE, not success: an authorised skip records that a '
      + 'prerequisite is missing, it does not turn an unmeasured run into a clean one.\n');
    return EXIT_INCOMPLETE;
  }
  return null;
}

/** Minimal argv reader. Repeated flags collect; `--k v` and `--k` both work. */
export function parseArgv(argv) {
  const flags = new Map();
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) { positional.push(a); continue; }
    const eq = a.indexOf('=');
    let name; let value;
    if (eq >= 0) { name = a.slice(2, eq); value = a.slice(eq + 1); } else {
      name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { value = next; i += 1; } else value = true;
    }
    const prev = flags.get(name);
    if (prev === undefined) flags.set(name, value);
    else if (Array.isArray(prev)) prev.push(value);
    else flags.set(name, [prev, value]);
  }
  return {
    positional,
    has: (n) => flags.has(n),
    get: (n, dflt = null) => {
      const v = flags.get(n);
      if (v === undefined) return dflt;
      return Array.isArray(v) ? v[v.length - 1] : v;
    },
    all: (n) => {
      const v = flags.get(n);
      if (v === undefined) return [];
      return Array.isArray(v) ? v : [v];
    },
    names: () => [...flags.keys()],
  };
}
