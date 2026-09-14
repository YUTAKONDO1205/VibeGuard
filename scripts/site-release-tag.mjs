// site-release-tag — which rule IDs a visitor can actually run today.
//
// WHY THIS IS ITS OWN FILE
//
// Two things need the same answer and they used to have one and a half of it.
//
//   `site-export-rules.mjs` filters the built registries down to the rules that
//   exist at the newest release tag, so `/rules` cannot list a detector that no
//   channel carries. It learned to do that after the public site advertised
//   four rules merged AFTER the tag in the footer — 89 IDs under a footer
//   reading `Latest: v0.3.6`, which ships 85.
//
//   `site-copy-lint.mjs`'s R4 asks whether every rule ID printed on the site is
//   a real one. Until this file existed it asked that of the CHECKOUT, so the
//   same four IDs passed R4 while the page carrying them was exactly the lie R4
//   is for. A linter that accepts what the generator refuses is not a second
//   layer; it is a green tick over the first layer's failure mode.
//
// So the answer lives here once, and both of them import it. The functions have
// no top-level side effects on purpose: the exporter used to call this at
// module scope, which meant importing the answer meant running the generator.
//
// ── WHY A TAG AND NOT A VERSION NUMBER ──────────────────────────────────────
//
// The root `package.json` version is what the NEXT release will be called, not
// what the last one was. Between cutting a release and publishing it those two
// disagree, and the direction they disagree in is the one that publishes
// unreleased rules. A tag exists only once the release does.
//
// ── WHY IT PARSES SOURCE TEXT AT THE TAG ────────────────────────────────────
//
// Building two packages at an arbitrary tag inside a generator is a much larger
// machine than this needs, and the parse only has to answer "which IDs", not
// "what do they do" — the built registry supplies every other field. The
// direction that would hurt is a parse that finds an ID the build does not
// have; the exporter asserts exactly that (its assertion E), and the linter
// intersects this set with the registries for the same reason.
//
// ── EVERY FAILURE IS AN EXCEPTION, NEVER AN EMPTY SET ───────────────────────
//
// An empty `Set` returned from here would be indistinguishable from "nothing
// has shipped", and both callers would then do something catastrophic and
// quiet: the generator would publish a page with no rules on it, and R4 would
// either reject every ID on the site or — had it been written to shrug — accept
// every one. So each failure throws a `ReleaseTagError` carrying a `code`, and
// the caller appends its own guidance to the fact this file names. Neither
// caller is allowed to treat one as a skip.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Both packages that contribute rules to `/rules`.
 *
 * The cross-file set is listed on the same page, under the same sentence, and
 * is therefore under the same promise. Leaving it out here would make the
 * release gate silently reject every design smell.
 */
export const RULE_SOURCES = [
  'packages/rules/src/rules',
  'packages/analysis-graph/src/design-smells-crossfile',
];

/** The declaration this file parses. One spelling, used by both halves. */
export const RULE_ID_PATTERN = "ruleId: '(VG-[A-Z]+-[0-9]+)'";

/**
 * A named failure to answer "which rules have shipped".
 *
 * `code` is what a caller switches on to append its own guidance; `message` is
 * the fact, phrased so that it reads correctly whichever caller prints it.
 */
export class ReleaseTagError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ReleaseTagError';
    this.code = code;
  }
}

/**
 * The newest release tag out of the raw text `git tag --list` prints.
 *
 * Split out from the git call so that the SELECTION can be tested without a
 * repository. The interesting input is not "a clone with tags" but "a clone
 * whose only tags are the moving ones", and constructing that with real git
 * would mean writing tags into somebody's checkout to prove a two-line regex.
 *
 * `v0` is the moving tag the GitHub Action resolves and `v0-remote-check` is a
 * working tag; neither is a release. Requiring all three numbers drops both
 * without maintaining a list of names to ignore.
 */
export function pickReleaseTag(tagListText) {
  const tag = String(tagListText ?? '')
    .split('\n')
    .map((line) => line.trim())
    .find((line) => /^v\d+\.\d+\.\d+$/.test(line));

  if (!tag) {
    throw new ReleaseTagError(
      'NO_RELEASE_TAG',
      'no release tag of the form vMAJOR.MINOR.PATCH was found.',
    );
  }
  return tag;
}

/** `git`, in `cwd`, with stderr captured rather than leaked to the console. */
function git(args, cwd) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/**
 * The newest release tag in `cwd`.
 *
 * A shallow or `--no-tags` checkout reaches one of the two failure branches
 * rather than a helpful default, which is correct: it genuinely does not know,
 * and the caller has to choose between failing and being told the answer.
 */
export function newestReleaseTag({ cwd = REPO_ROOT } = {}) {
  let tags;
  try {
    tags = git(['tag', '--list', 'v*', '--sort=-v:refname'], cwd);
  } catch (error) {
    throw new ReleaseTagError('GIT_TAG_LIST', `could not list git tags: ${error?.message ?? error}`);
  }
  return pickReleaseTag(tags);
}

/**
 * Every rule ID declared in the rule-bearing packages at a release tag.
 *
 * @param {{cwd?: string, tag?: string|null}} [options] `tag` short-circuits the
 *   lookup, for a caller that already knows which release it means.
 * @returns {{tag: string, ids: Set<string>}}
 */
export function releasedRuleIds({ cwd = REPO_ROOT, tag = null } = {}) {
  const releaseTag = tag ?? newestReleaseTag({ cwd });

  let matched = '';
  try {
    matched = git(['grep', '-h', '-E', RULE_ID_PATTERN, releaseTag, '--', ...RULE_SOURCES], cwd);
  } catch (error) {
    // `git grep` exits 1 for "no matches", which here means the parse found
    // nothing at all - indistinguishable from a moved directory, and either way
    // not something to build a page from.
    throw new ReleaseTagError(
      'RULE_SOURCE_READ',
      `could not read the rule sources at ${releaseTag}: ${error?.message ?? error}`,
    );
  }

  const ids = new Set([...matched.matchAll(new RegExp(RULE_ID_PATTERN, 'g'))].map((m) => m[1]));

  if (ids.size === 0) {
    throw new ReleaseTagError(
      'EMPTY_PARSE',
      `parsed zero rule IDs out of ${releaseTag}. The shape this generator looks for is\n` +
        "  `ruleId: 'VG-FAMILY-NNN'`. If that spelling changed, this parse has to change with\n" +
        '  it - an empty set here would publish a page with no rules on it.',
    );
  }

  return { tag: releaseTag, ids };
}
