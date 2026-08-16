// site-export-releases — the release list, from the only place that knows it.
//
// WHY THIS EXISTS
//
// `/news` and the front page's News strip are the site's proof that the project
// is alive. That makes them the two places where being out of date does the most
// damage: a release list whose newest entry is four months old says something
// about the project that no amount of copy elsewhere can argue with.
//
// So the list is not maintained. It is fetched from the GitHub Releases API at
// build time, and the site deploy is wired to run after a successful release
// (site design chapter 9.5), which is what closes the loop.
//
// ── WHY RELEASES AND NOT TAGS ──────────────────────────────────────────────
//
// The obvious implementation reads tags, and it breaks on this repository. The
// tag list contains three things that are not releases:
//
//   v0                    the moving tag the GitHub Action resolves. It is
//                         re-pointed at every release, so it carries a real
//                         release's date and commit.
//   v0-remote-check       working tags from earlier investigations.
//   pre-51-repopulation
//
// `v0` is the dangerous one, because it is not obviously wrong: it sorts to the
// front, it has a plausible date, and it duplicates whichever release it
// currently points at. A visitor would see the newest release listed twice,
// once under a version number that does not exist. Hence the shape filter
// below — the site shows `v<major>.<minor>.<patch>` and nothing else.
//
// ── WHY A FETCH FAILURE STOPS THE BUILD ────────────────────────────────────
//
// The tempting behaviour on a 5xx or a rate limit is to keep the previous
// `releases.json` and carry on. This file refuses to, and that refusal is the
// point of the whole design (chapter 9.2).
//
// Falling back means a build that cannot see the release list still succeeds,
// still deploys, and still publishes a page dated today that lists releases
// from whenever the fallback was written. Nothing is red. Nobody is told. The
// alternative — the build fails and the previously deployed site stays up — is
// strictly better: the site is equally stale either way, and in the failing
// case somebody knows.
//
//   node scripts/site-export-releases.mjs
//
// Reads GH_TOKEN (or GITHUB_TOKEN) when present. Unauthenticated works fine for
// a local build: this is one request against a 60/hour budget.
//
// Exit 0 when releases.json was written, 1 with the reason otherwise. Never
// writes a partial or recycled file.
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_FILE = join(REPO_ROOT, 'site', 'src', 'data', 'releases.json');

const OWNER = 'YUTAKONDO1205';
const REPO = 'VibeGuard';

/**
 * Tag names the site is willing to call a release.
 *
 * Anchored at the start rather than the whole string so a future
 * `v1.0.0-rc.1` is recognised as a version — the draft/prerelease flags are
 * what decide whether such a thing is shown, and they are a better judge of it
 * than the tag's punctuation.
 */
const RELEASE_TAG = /^v\d+\.\d+\.\d+/;

/**
 * Marker for "this generator has already explained itself and is unwinding".
 * Never printed; `die` has already written the message a human should read.
 */
class Abort extends Error {}

/**
 * Report and stop.
 *
 * This sets `exitCode` and throws instead of calling `process.exit()`, and the
 * difference is not stylistic. Calling `process.exit()` while an HTTP response
 * is in flight aborts Node inside libuv's socket teardown; on Windows that
 * fires an assertion (`!(handle->flags & UV_HANDLE_CLOSING)`) which prints a C
 * crash dump over the top of the message above and exits 127. A build that
 * fails for a reason nobody can read is barely better than one that silently
 * publishes a stale list, which is the whole thing this file is defending
 * against. Unwinding to the top and letting Node exit on its own gives a clean
 * exit 1 with the explanation as the last thing on stderr.
 */
function die(message) {
  process.stderr.write(`site-export-releases: ${message}\n`);
  process.exitCode = 1;
  throw new Abort(message);
}

const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || '';
const headers = {
  accept: 'application/vnd.github+json',
  'x-github-api-version': '2022-11-28',
  // The API rejects requests without one. Naming the generator rather than
  // spoofing a browser means an abuse report from GitHub would arrive with the
  // thing that caused it already identified.
  'user-agent': 'vibeguard-site-export',
  ...(token ? { authorization: `Bearer ${token}` } : {}),
};

/**
 * Every release, following pagination.
 *
 * Ten releases fit in one page today. The loop is here because the failure mode
 * of assuming otherwise is silent truncation — `/news` would simply stop at the
 * hundredth release and nothing would say so.
 */
async function fetchAllReleases() {
  const collected = [];
  let url = `https://api.github.com/repos/${OWNER}/${REPO}/releases?per_page=100`;

  while (url) {
    let response;
    try {
      response = await fetch(url, { headers });
    } catch (error) {
      die(
        `GET ${url} failed: ${error.message}\n` +
          'The release list cannot be recovered from anywhere else, and this build will not ' +
          'publish a stale one. Re-run when the network or the API is back.',
      );
    }

    if (!response.ok) {
      // Drain the body before reporting. `process.exit()` while a response
      // stream is still open trips a libuv assertion on Windows, which replaces
      // this file's carefully worded failure message with a C-level crash dump
      // and an exit code that says nothing about what went wrong.
      await response.text().catch(() => {});
      const remaining = response.headers.get('x-ratelimit-remaining');
      const resets = response.headers.get('x-ratelimit-reset');
      const rateLimited = response.status === 403 && remaining === '0';
      let hint = '';
      if (rateLimited) {
        const at = resets ? new Date(Number(resets) * 1000).toISOString() : 'an unknown time';
        hint =
          `\nThe unauthenticated rate limit is exhausted until ${at}. Set GH_TOKEN to a token ` +
          'with public read access (CI passes ${{ github.token }}).';
      }
      die(`GET ${url} returned HTTP ${response.status} ${response.statusText}.${hint}`);
    }

    let page;
    try {
      page = await response.json();
    } catch (error) {
      die(`GET ${url} returned a body that is not JSON: ${error.message}`);
    }
    if (!Array.isArray(page)) {
      die(`GET ${url} returned ${typeof page}, not an array of releases.`);
    }
    collected.push(...page);

    // GitHub paginates with a Link header. Parsing it is the documented way to
    // walk the pages; incrementing a page counter until an empty page comes
    // back costs an extra request and gets the same answer.
    const link = response.headers.get('link') || '';
    const next = /<([^>]+)>;\s*rel="next"/.exec(link);
    url = next ? next[1] : null;
  }

  return collected;
}

async function main() {
  const raw = await fetchAllReleases();

  // Drafts are invisible to anyone but the maintainer, and prereleases are not
  // what the front page's "latest" means. Both are decided by GitHub, so the
  // site does not need an opinion beyond honouring them.
  const published = raw.filter((release) => !release.draft && !release.prerelease);

  const shaped = published.filter((release) => RELEASE_TAG.test(String(release.tag_name || '')));

  // Keep the newest entry per tag. Two releases on one tag should not happen,
  // but if it ever does the older one is a re-cut and showing both would read
  // as two separate releases of the same version.
  const newestByTag = new Map();
  for (const release of shaped) {
    const previous = newestByTag.get(release.tag_name);
    if (!previous || Date.parse(release.published_at) > Date.parse(previous.published_at)) {
      newestByTag.set(release.tag_name, release);
    }
  }

  const releases = [...newestByTag.values()]
    .map((release) => ({
      tag_name: release.tag_name,
      // `name` is the release title; several releases here title themselves
      // with the tag, which is fine — the page decides how to render a title
      // that repeats the tag. `body` is deliberately absent: transcribing
      // release notes would give them two homes, and the copy on GitHub would
      // be the one that gets corrected.
      name: release.name || release.tag_name,
      published_at: release.published_at,
      html_url: release.html_url,
    }))
    .sort((a, b) => Date.parse(b.published_at) - Date.parse(a.published_at));

  // An empty list is a successful fetch that produced nothing usable — a filter
  // that stopped matching, or a repository rename. It would render as a `/news`
  // page with a heading and no rows, which deploys perfectly well and says the
  // project has never shipped.
  if (releases.length === 0) {
    die(
      `the API returned ${raw.length} release(s), none of which survived the filters ` +
        `(published: ${published.length}, tag shaped like v0.0.0: ${shaped.length}). ` +
        'Refusing to publish an empty release list.',
    );
  }

  mkdirSync(dirname(OUT_FILE), { recursive: true });
  writeFileSync(OUT_FILE, `${JSON.stringify({ releases }, null, 2)}\n`, 'utf8');

  const dropped = raw.length - releases.length;
  process.stdout.write(
    `site-export-releases: ${releases.length} releases, newest ${releases[0].tag_name} ` +
      `(${releases[0].published_at})` +
      `${dropped > 0 ? `, ${dropped} filtered out` : ''}` +
      `${token ? '' : ', unauthenticated'} -> site/src/data/releases.json\n`,
  );
}

try {
  await main();
} catch (error) {
  // `die` has already printed the reason and set the exit code. Anything else
  // is a bug in this file and deserves its stack trace.
  if (!(error instanceof Abort)) throw error;
}
