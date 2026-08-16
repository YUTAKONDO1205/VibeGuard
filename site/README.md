# VibeGuard — the website

The public site. Astro, statically rendered, deployed to Cloudflare Workers.

Two things about it are unusual enough to state before anything else:

- **The site ships no client-side JavaScript and loads nothing from another
  host.** No `<script>`, no web fonts, no remote images, no analytics. The
  Content-Security-Policy that goes out with it is `default-src 'self'` and
  `script-src 'none'`, so anything that violated the rule would fail to run in a
  browser rather than fail quietly. Disclosure widgets are `<details>`.
- **No number on the site is typed by hand.** Rule counts, the version in the
  footer, release dates, the code in the demo cards and the scanner output next
  to it are all produced at build time from this repository and from the GitHub
  Releases API. This directory therefore does not build from a fresh clone until
  the generators have run. That is the trade, and it is deliberate: the
  alternative is a page full of numbers that were true once.

## What is generated

Both paths are git-ignored (`site/.gitignore`).

| Path | Written by | Contents |
|---|---|---|
| `src/data/meta.json` | `scripts/site-export-meta.mjs` | `toolVersion`, from the root `package.json`. The footer's `Latest: v…`. |
| `src/data/rules.json` | `scripts/site-export-rules.mjs` | Every rule in `@vibeguard/rules`, grouped into the eight buckets defined in `src/shared/taxonomy.ts`, each marked with whether a fixer exists for it and how that fixer is labelled. Plus the totals. |
| `src/data/releases.json` | `scripts/site-export-releases.mjs` | The GitHub Releases list, newest first, with moving and working tags filtered out. |
| `src/data/triptych.json` | `scripts/site-export-triptych.mjs` | The three Before / finding / After cards, including the CLI's own output verbatim. |
| `src/data/hero.json` | `scripts/site-export-hero.mjs` | The single finding the front page leads with — `VG-AUTH-001` scanned out of `samples/vulnerable/auth_bypass.py`. Absent, the front page falls back to the first triptych card; present, it wins. |
| `demo/` | `scripts/site-export-triptych.mjs` | The code shown in those cards: fixtures from `samples/`, copied with the trailing rule-naming comments removed and nothing else changed. |

The generators live in `scripts/` at the repository root, not here, because they
read the built packages and `samples/` — they are part of the repository's build,
and the site is their consumer.

Three of them fail the build rather than produce something plausible:

- `site-export-rules.mjs` stops if a rule ID family appears that no bucket
  claims. Adding a detector family without deciding which of the eight circles
  it belongs under is a decision, not an omission, and the site would otherwise
  describe a smaller product than the one that ships.
- `site-export-releases.mjs` stops if the API call fails or is rate-limited. It
  never falls back to the previous file. A stale release list that deploys
  successfully is worse than a build that goes red: both leave the site out of
  date, and only one of them tells anybody.
- `site-export-triptych.mjs` stops if the demo copy differs from its fixture by
  anything other than a removed comment, if stripping those comments changed
  what the scanner reports, or if `--fix` did not touch the rule the card is
  about.

## Building it

From the repository root. The three package builds are what `rules.json` and the
demo cards read; the CLI build is what actually produces the scanner output shown
on the front page.

```sh
npm ci
npm run build -w @vibeguard/findings-schema
npm run build -w @vibeguard/rules
npm run build -w @vibeguard/remediation-engine
npm run build -w @vibeguard/cli

node scripts/site-export-meta.mjs
node scripts/site-export-rules.mjs
node scripts/site-export-releases.mjs
node scripts/site-export-triptych.mjs
node scripts/site-export-hero.mjs
```

Then, in this directory:

```sh
npm ci
npm run build
```

`npm run dev` works the same way — the generators have to have run first, because
the pages import the JSON directly and Astro will not start without it.

`site-export-releases.mjs` reads `GH_TOKEN` (or `GITHUB_TOKEN`) when it is set.
Without one it makes a single unauthenticated request, which fits comfortably in
the 60-per-hour budget; CI passes the workflow's own token.

## Re-running the generators

They are all idempotent and produce byte-identical output for unchanged inputs —
every timing field the CLI emits is stripped before serialisation, precisely so
that a diff in `src/data/` means something changed in the product. Run any of
them on its own whenever the thing it reads has moved:

| Something changed | Re-run |
|---|---|
| The root version | `site-export-meta.mjs` |
| A rule, or a fixer | `site-export-rules.mjs` (rebuild the packages first) |
| A release was published | `site-export-releases.mjs` |
| A `samples/` fixture used by a card, or the CLI's output format | `site-export-triptych.mjs` (rebuild the CLI first) |
