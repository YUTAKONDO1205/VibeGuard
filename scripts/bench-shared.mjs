// bench-shared — the vocabulary the four bench-*.mjs entry points agree on.
//
// WHY A SHARED FILE AND NOT FOUR COPIES
//
// The scorer, the fetcher, the manifest builder and the leaderboard all have to
// agree on three things, and a disagreement in any of them is silent: what a
// repository is CALLED (the manifest id, which is the join key against a label
// and against a SARIF run), what counts as the SAME LOCATION (the line window),
// and what a manifest DIGEST is taken over. Duplicate any of those and the
// leaderboard starts comparing rows that were scored under different rules while
// every file involved still parses.
//
// The digest is the sharpest case. It is taken over a canonical serialisation of
// the ENTRY LIST rather than over the bytes on disk, because the bytes change
// when the file is reformatted and the benchmark has not. A result that records a
// digest is making a claim about WHICH corpus it ran on; if the digest moves for
// a reason that is not a corpus change, submitters re-run for nothing and then
// stop recording it at all.
import { createHash } from 'node:crypto';

/** Every count this benchmark publishes is an integer. Rates are {num, den}. */
export const ratio = (num, den) => ({ num, den });

/**
 * The one line-distance rule, in one place.
 *
 * A design smell is reported at a REPRESENTATIVE site, and two tools looking at
 * the same duplication will not choose the same one — VibeGuard anchors on the
 * first decision site it reaches, a pattern-shaped tool on whichever line its
 * pattern happened to hit. Requiring an exact line would score a real agreement
 * as a miss. Accepting the whole file would score any finding anywhere in a
 * 900-line route module as a hit.
 *
 * So a finding matches a label when it lands within WINDOW lines of ANY site the
 * label lists in that same file, not only of the label's anchor. The window is
 * recorded in every result file: a number that is not carried with the reading is
 * a number the next reader will assume.
 */
export const DEFAULT_LINE_WINDOW = 3;

export function withinWindow(findingLine, siteLine, window) {
  return Math.abs(findingLine - siteLine) <= window;
}

/** A backslash, written so no shell here-doc on any platform can eat it. */
const BACKSLASH = String.fromCharCode(92);

/** Repo-relative, forward slashes, no leading `./` — the one spelling of a path. */
export function normaliseFilePath(p) {
  return String(p)
    .split(BACKSLASH)
    .join('/')
    .replace(/^\.\//, '')
    .replace(/^\/+/, '');
}

/**
 * Canonical JSON: object keys sorted, no insignificant whitespace.
 *
 * Used only for digesting. The files on disk are written pretty-printed, because
 * a manifest a human cannot read in a diff is a manifest nobody audits.
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

/**
 * The digest a result file records, over the part of the manifest that decides
 * WHAT WAS SCANNED: the entry list, reduced to id / url / commit and sorted.
 * Prose, generation timestamps and the builder's own name are excluded on
 * purpose — editing the benchmark's README must not invalidate every result
 * anybody has already recorded.
 */
export function manifestDigest(manifest) {
  const entries = Array.isArray(manifest?.entries) ? manifest.entries : null;
  if (entries === null) {
    throw new Error('manifest has no `entries` array; refusing to digest a shape this is not');
  }
  if (entries.length === 0) {
    throw new Error('manifest `entries` is empty; a digest over nothing identifies nothing');
  }
  const material = entries
    .map((e) => ({ id: e.id, repositoryUrl: e.repositoryUrl, commit: e.commit }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return `sha256:${createHash('sha256').update(canonicalJson(material)).digest('hex')}`;
}

export function sha256Hex(text) {
  return createHash('sha256').update(text).digest('hex');
}

/**
 * Read a JSON file, or throw naming the file and the reason.
 *
 * Deliberately not a try/return-null: every caller here is a check, and a check
 * that turns an unreadable input into an empty set reports a clean zero over
 * nothing. That is the failure the exit-3 convention below exists for.
 */
export function readJsonOrFail(fs, path, what) {
  let text;
  try {
    text = fs.readFileSync(path, 'utf8');
  } catch (err) {
    throw new Error(`${what}: cannot read ${path} — ${err.code ?? err.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`${what}: ${path} is not valid JSON — ${err.message}`);
  }
}

/**
 * Exit codes, shared so the tests can name them rather than spell 2 and 3.
 *
 * EXIT_VACUOUS is the one that matters. Every other code says the run happened
 * and came out a particular way; this one says the run did not happen, and it
 * exists because the alternative — printing `scored: 0` and exiting 0 — is
 * indistinguishable, in a CI log, from a tool that found nothing wrong.
 */
export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1; // the run completed and the verdict is negative
export const EXIT_USAGE = 2; // the caller asked for something impossible
export const EXIT_VACUOUS = 3; // nothing was measured; a zero here would be a lie

/**
 * ★ THE CEILING ON THE MATCHER.
 *
 * `--line-window` widens what counts as the same location. A floor alone is not
 * a bound: a submitter who passes `--line-window 100000` makes every finding
 * anywhere in a labelled file match a site in it, which inflates `recovered` and
 * `reportedKnownFalsePositive` at the same time and does so with a flag that is
 * faithfully recorded in the result file and still reads like a tuning knob.
 *
 * A public benchmark must not ship a knob that improves your score. The ceiling
 * is the length of a handler body rather than a round number: the claim the
 * window exists to tolerate is "two tools chose different representative lines
 * for the same decision", and those lines are inside one function. Past that the
 * window is no longer tolerating disagreement about a site, it is matching a
 * file.
 */
export const MAX_LINE_WINDOW = 25;

/**
 * What each `groundTruth` value ASSERTS about human confirmation.
 *
 * ★ This table exists because the benchmark shipped a contradiction: every row
 * of the real label set carried `groundTruth: "human-review"` beside
 * `humanConfirmed: false` and a `labeledBy` naming an AI drafter. A benchmark
 * whose whole value is its labels cannot carry a field that says a human read
 * them when no human did, and prose in a README does not stop the next builder
 * from writing the same constant again.
 *
 *   human-review          a person read the implicated code and judged it
 *   by-construction       the code was WRITTEN to be an instance (the control)
 *   ai-draft-unconfirmed  a draft verdict nobody has confirmed
 *
 * The first two assert confirmation, the third asserts its absence, and a row
 * that disagrees with its own provenance is refused rather than scored.
 */
export const GROUND_TRUTH_CONFIRMATION = Object.freeze({
  'human-review': true,
  'by-construction': true,
  'ai-draft-unconfirmed': false,
});

/** The vocabulary, for an error message that can name what was allowed. */
export const GROUND_TRUTH_VALUES = Object.freeze(Object.keys(GROUND_TRUTH_CONFIRMATION));

/**
 * Every row whose `groundTruth` and `humanConfirmed` disagree, described.
 *
 * Returns a list rather than throwing so a caller can name ALL of them at once:
 * a builder that fixes one contradiction per run teaches the next person that
 * the check is noise.
 */
export function labelProvenanceContradictions(labelSet) {
  const out = [];
  const labels = Array.isArray(labelSet?.labels) ? labelSet.labels : [];
  labels.forEach((l, i) => {
    const where = `label[${i}] ${l?.repository ?? '(no repository)'} ${l?.anchor?.file ?? '?'}:${l?.anchor?.line ?? '?'}`;
    const gt = l?.groundTruth;
    if (typeof gt !== 'string' || !Object.hasOwn(GROUND_TRUTH_CONFIRMATION, gt)) {
      out.push(
        `${where}: groundTruth is ${JSON.stringify(gt ?? null)}, which is not one of ` +
          `${GROUND_TRUTH_VALUES.join(' / ')}. A provenance nobody can check is not a provenance.`,
      );
      return;
    }
    if (typeof l.humanConfirmed !== 'boolean') {
      out.push(`${where}: humanConfirmed is ${JSON.stringify(l?.humanConfirmed ?? null)}, not a boolean, so the row's own provenance cannot be checked against it.`);
      return;
    }
    const asserted = GROUND_TRUTH_CONFIRMATION[gt];
    if (asserted !== l.humanConfirmed) {
      out.push(
        `${where}: groundTruth "${gt}" asserts humanConfirmed ${asserted}, but the row carries ` +
          `humanConfirmed ${l.humanConfirmed}. One of the two is false and the file does not say which.`,
      );
    }
  });
  return out;
}

/** How many rows of a label set are confirmed, and how many are not. */
export function labelConfirmation(labelSet) {
  const labels = Array.isArray(labelSet?.labels) ? labelSet.labels : [];
  const confirmed = labels.filter((l) => l?.humanConfirmed === true).length;
  return { confirmed, unconfirmed: labels.length - confirmed, total: labels.length };
}
