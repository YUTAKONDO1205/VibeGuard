/**
 * What a run writes down about itself, and what it exits with.
 *
 * Four decisions live here: what a skipped check leaves behind in the record,
 * which guard figures a cell publishes, what the provenance scan refuses, and
 * what the whole run's exit code is. All four used to be inline in
 * `../run-lto-window.mjs`, where no test could reach them -- and all four were
 * wrong in the same direction, which is the direction that reads as "fine":
 *
 *   - `--skip-negative-control` and `--skip-gcc` left NO record at all. The
 *     README said the result records the skip; the field was simply left `{}`.
 *   - a run with the lane's only mechanical demonstration that guard 1 can fire
 *     turned off exited 0 with a clean all-OK table. `../../schema/interfaces.md`
 *     section 7 reserves 0 for "everything asked for was checked and nothing was
 *     found", and 3 for "a check could not be completed -- **never conflated
 *     with 0**".
 *   - `lineKinds` was computed by parseLldPassLog, carried as far as the cell,
 *     and dropped before the record was written, so per-kind linker line counts
 *     quoted in prose could not be reconciled against the artifact by anyone.
 *
 * Pure functions over plain objects. Nothing here runs or reads anything.
 */

import { MEASUREMENT, STATE } from './cell.mjs';

/* ------------------------------------------------------------- skipping -- */

/** The flags that turn a check off, spelled once. */
export const SKIP_FLAG = Object.freeze({
  negativeControl: '--skip-negative-control',
  gcc: '--skip-gcc',
  thinltoEvidence: '--skip-thinlto-evidence',
});

/**
 * What a check that did not run leaves in the record.
 *
 * The shape `--skip-thinlto-evidence` already used -- `attempted: false` plus a
 * note saying the word below is not earned here -- generalised to the other two,
 * because a skip that leaves no trace turns into a clean row when someone reads
 * the JSON later. `ran: false` is carried as well so that a consumer looking for
 * either spelling finds it.
 */
export function skippedRecord(what, why) {
  const flag = SKIP_FLAG[what];
  if (!flag) throw new Error(`no skip flag known for ${what}`);
  return { attempted: false, ran: false, skipped: true, flag, note: `not run in this run (${flag}): ${why}` };
}

export const SKIP_WHY = Object.freeze({
  negativeControl:
    'guard 1 was not shown to fire, so nothing in this run distinguishes a link-time reading from a compile-time one',
  gcc: 'gcc was not probed, so no UNSUPPORTED row is earned here',
  thinltoEvidence: 'the ThinLTO link that earns the BROKEN_MEASUREMENT word was not run; the word is not earned here',
});

/**
 * The lines the run prints about itself under the table.
 *
 * A skip is stated in the report's own summary, not only buried in the JSON:
 * the table a reader looks at is the table that has to say that the
 * demonstration behind it was turned off.
 */
export function skipSummaryLines(skipped = {}) {
  const lines = [];
  for (const [what, flag] of Object.entries(SKIP_FLAG)) {
    if (skipped[what]) lines.push(`${what}: SKIPPED (${flag}) -- ${SKIP_WHY[what]}`);
  }
  return lines;
}

/* --------------------------------------------------------------- guards -- */

/**
 * The guard figures a link cell publishes.
 *
 * `lldLineKinds` is here because a number that is measured, quoted and then not
 * recorded cannot be checked: the linker's per-kind line counts (`Running
 * pass:`, `Running analysis:`, `Invalidating analysis:`, ...) were computed on
 * every run and thrown away at exactly this point.
 */
export function linkGuardRecord({ inputs, linkerPipeline, agreement = null, byteIdentical = null, debugFlagChangedBytes = null } = {}) {
  return {
    inputsOk: inputs?.ok ?? null,
    inputProblems: inputs?.problems ?? [],
    lldRunningPassLines: linkerPipeline?.runs ?? null,
    lldLineKinds: linkerPipeline?.lineKinds ?? null,
    passAgreement: agreement,
    byteIdentical,
    debugFlagChangedBytes,
  };
}

/* ----------------------------------------------------------- provenance -- */

/**
 * No record leaves here carrying a machine path.
 *
 * The pattern used to be a seven-root whitelist -- `/(home|root|mnt|Users|tmp|
 * var|usr)/` -- which is a check for "a path under the roots this machine
 * happens to use", not for an absolute path. `/opt/vg-lab/...`,
 * `/srv/...`, `/data/<name>/...` and `/workspace/...` all went straight
 * through. What is actually refused now is any rooted, multi-segment path
 * token: a leading `/` followed by at least two path segments, or a Windows
 * drive letter. The preceding-character class keeps `5/10` and
 * `PassManager<...>` out of it, and this pattern was run over the lane's real
 * 10-cell result before being adopted: 0 hits, the same as the old one.
 */
export const ABSOLUTE_PATH_RE = /(^|["'\s:=(,[])(\/[\w.+@~-]+(?:\/[\w.+@~-]*)+|[A-Za-z]:[\\/])/;

export function scrubbed(json) {
  const hits = [];
  for (const line of String(json).split('\n')) {
    if (ABSOLUTE_PATH_RE.test(line)) hits.push(line.trim().slice(0, 160));
  }
  return hits;
}

/* ------------------------------------------------------------ exit code -- */

/**
 * The exit code for a whole run, from what the run actually established.
 *
 * `../../schema/interfaces.md` section 7 is the vocabulary: 0 "everything asked
 * for was checked and nothing was found", 1 the underlying tool failed, 2
 * findings at threshold, 3 "a check could not be completed -- never conflated
 * with 0", 4 a policy/integrity refusal (handled at the call sites, before
 * anything is measured).
 *
 * Two of these codes are decided here rather than by counting OK cells:
 *
 *   - A run whose NEGATIVE CONTROL was skipped cannot be 0. Guard 1's only
 *     mechanical demonstration is the thing that was turned off, so that run has
 *     not established the claim its whole table rests on -- that a compile-time
 *     reading would have been refused. It is 3, and the reason is printed. The
 *     same holds for `--skip-gcc` and `--skip-thinlto-evidence`: each removes a
 *     cell or a piece of evidence the lane otherwise reports, so each is a check
 *     that did not complete.
 *
 *   - A cell that is `OK` with state `NOT_OBSERVED` is 3 as well. The instrument
 *     worked and there was no reading of that property, which interfaces.md 3.1
 *     calls ungradeable either way -- a completed run, not a completed check.
 */
export function exitDecision({
  cells = [],
  skipped = {},
  toolFailure = null,
  byteFinding = null,
  negativeControls = {},
} = {}) {
  if (toolFailure) return { code: 1, messages: [toolFailure] };
  if (byteFinding) {
    return {
      code: 2,
      messages: ['the linked executable differed with the plugin loaded: the observer is not non-invasive here'],
    };
  }
  for (const [name, nc] of Object.entries(negativeControls)) {
    if (nc && nc.ran && !nc.fired) {
      return {
        code: 2,
        messages: [`the negative control for ${name} was NOT refused: guard 1 did not fire on a non-LTO link, `
          + 'so nothing in this lane distinguishes a link-time reading from a compile-time one'],
      };
    }
  }

  const messages = [];
  const incomplete = cells.filter((c) => c.measurement !== MEASUREMENT.OK);
  const unread = cells.filter((c) => c.measurement === MEASUREMENT.OK && c.state === STATE.NOT_OBSERVED);
  if (incomplete.length) {
    messages.push(`${incomplete.length} of ${cells.length} cells could not be completed; see \`reasons\` in the result`);
  }
  if (unread.length) {
    messages.push(`${unread.length} cell(s) measured OK with nothing to read (state NOT_OBSERVED); see \`reasons\``);
  }
  for (const line of skipSummaryLines(skipped)) messages.push(line);
  return { code: messages.length ? 3 : 0, messages };
}
