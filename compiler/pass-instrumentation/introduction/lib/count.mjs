// The counting contract.
//
// Three times in this repository a scan has reported success over nothing at
// all: the input glob matched no files, every loop body was skipped, and the
// process exited 0 because no step had failed. Nothing failed because nothing
// ran. A green tick over an empty input set is the most expensive kind of false
// negative, because it is indistinguishable from a real pass at the only place
// anyone looks.
//
// So this module makes the count part of the output rather than part of the
// implementation. Every runner in this component builds a Tally, calls
// `counted`/`skipped` as it goes, prints `render()`, and takes `exitFor()` as
// its floor. An empty run is exit 3 -- INCOMPLETE, "we did not look" -- and
// never exit 0, unless the caller passed `--allow-empty`, which is a claim the
// caller is making on the record and is printed back as `allowEmpty=1`.
//
// `skip is not pass` is enforced here too. A skip must carry a name and a
// reason; `render()` lists every one of them, so a run that skipped its way to
// green says so in its own output instead of looking like a run that passed.

import { EXIT_INCOMPLETE, EXIT_OK } from './exit.mjs';

export class Tally {
  /**
   * @param {string} label   what is being counted, for the human reading it
   * @param {{allowEmpty?: boolean}} opts
   */
  constructor(label, { allowEmpty = false } = {}) {
    this.label = label;
    this.allowEmpty = Boolean(allowEmpty);
    this.inputs = 0;
    this.checked = 0;
    /** @type {{name: string, reason: string}[]} */
    this.skips = [];
  }

  /** One more thing arrived on the input side, whatever happens to it next. */
  input(n = 1) {
    this.inputs += n;
    return this;
  }

  /** One more thing was actually examined. */
  counted(n = 1) {
    this.checked += n;
    return this;
  }

  /**
   * One thing was not examined, and why. Both are required: an unnamed skip
   * cannot be audited, and this component's contract is that every skipped case
   * appears by name in the output.
   */
  skip(name, reason) {
    if (!name || !reason) throw new Error('skip(name, reason): both are required');
    this.skips.push({ name: String(name), reason: String(reason) });
    return this;
  }

  get skipped() {
    return this.skips.length;
  }

  /** True when the run examined nothing and did not say in advance that it might. */
  get emptyAndUnauthorised() {
    return this.inputs === 0 && !this.allowEmpty;
  }

  /**
   * The mandatory one-line summary. The three numbers are always present and
   * always in this order, so a caller can grep them out of a log without
   * knowing which runner produced it.
   */
  render() {
    const head = `${this.label}: inputs=${this.inputs} checked=${this.checked} skipped=${this.skipped}`;
    const tail = this.allowEmpty ? ' allowEmpty=1' : '';
    if (this.skips.length === 0) return head + tail;
    const lines = this.skips.map((s) => `  skipped: ${s.name} -- ${s.reason}`);
    return [head + tail, ...lines].join('\n');
  }

  /**
   * The floor for the process exit code.
   *
   * Empty and unauthorised is INCOMPLETE, never OK. A caller that has findings
   * of its own takes the maximum of this and its own code, so the empty case
   * can never be argued down to 0 by a later step deciding it was happy.
   */
  exitFor(codeIfNonEmpty = EXIT_OK) {
    if (this.emptyAndUnauthorised) return EXIT_INCOMPLETE;
    return codeIfNonEmpty;
  }

  /** The reason line to print alongside an INCOMPLETE caused by emptiness. */
  emptyReason() {
    return `${this.label}: no inputs were found, so nothing was checked. `
      + 'This is exit 3 (INCOMPLETE), not exit 0 -- pass --allow-empty if an '
      + 'empty input set is the expected result here.';
  }
}

/**
 * A prerequisite is missing. Skipping is only allowed when an environment
 * variable authorises it, and then the case is named in the tally so the
 * output shows what the green tick is not covering.
 *
 * Returns true when the caller may skip. Throws otherwise, because a missing
 * tool is a failure and a checker that quietly downgrades it to a pass is the
 * thing this component exists to complain about in other people's builds.
 */
export function skipAuthorised(tally, name, reason, env = process.env) {
  if (env.VG_INTRO_ALLOW_SKIP === '1') {
    tally.skip(name, `${reason} (skip authorised by VG_INTRO_ALLOW_SKIP=1)`);
    return true;
  }
  throw new Error(
    `${name}: ${reason}. This is a failure, not a skip. `
    + 'Set VG_INTRO_ALLOW_SKIP=1 to authorise skipping it, and the skipped case '
    + 'will be listed by name in the output.',
  );
}
