// site-copy-lint — refuse to publish a promise the repository cannot keep.
//
// WHY THIS EXISTS
//
// Release 0.3.5 was cut with this commit message:
//
//   `Release 0.3.5: ship the two C/C++ rules, and stop the README promising
//    them early`
//
// The author had already written, in the README, that something existed before
// it did — and then had to go back and unwrite it. That is the exact accident
// this file is aimed at, moved one surface over. A README lives in a repository
// that a reader arrives at with context; a website is indexed, quoted, shared,
// and screenshotted, and the wrong sentence on it outlives the commit that
// fixed it.
//
// The design document's chapter 0 puts five defences against that accident on
// five different layers. Two of them are structural and the other three are
// conventions people have to remember. This file is the second structural one:
// `ResearchLayout.astro` makes the promise impossible to *compose* (there is no
// CTA component in its import graph), and this makes it impossible to *write*
// (the words do not survive CI). Everything else is a guideline, and guidelines
// are what produced 0.3.5.
//
//   node scripts/site-copy-lint.mjs            # source mode: site/src, site/public
//   node scripts/site-copy-lint.mjs --dist     # artefact mode: site/dist
//   node scripts/site-copy-lint.mjs --site DIR # point either mode at another tree
//
// Exit 0 when every rule holds, 1 otherwise, with the file, line and reason
// named.
//
// ── WHY THERE ARE TWO MODES ─────────────────────────────────────────────────
//
// They ask different questions and neither subsumes the other.
//
//   SOURCE   reads what a person typed. It runs before anything is built, so a
//            banned word is reported in seconds by the same `npm test` a
//            developer already runs, and it can see things the artefact cannot:
//            colour literals in the CSS a bundler will later concatenate, and
//            the constant tables in `site/src/shared/links.ts` / `headers.ts`.
//   ARTEFACT reads what will actually be served. Source mode cannot answer
//            "did a <script> tag reach the HTML?" or "does _headers exist?",
//            because both are produced by the build. A CSP that says
//            `script-src 'none'` is a declaration until something checks that
//            the pages contain no script; then it is a measured property.
//
// Running only one of them would leave a whole half unchecked, so `site/`'s
// build pipeline runs source mode before `astro build` and artefact mode after.
//
// ── ZERO DEPENDENCIES, ON PURPOSE ───────────────────────────────────────────
//
// Same reasoning as `scripts/check-packaging-invariants.mjs`, which this file
// is modelled on: a guard that needs an install step is a guard that stops
// running in exactly the broken checkout where you most want it. Everything
// here is `node:fs` plus regular expressions over text, with one optional
// dynamic import (the built rules package) that has a source-text fallback.
//
// ── AND A VACUITY GUARD, FOR THE SAME REASON THAT FILE HAS ONE ──────────────
//
// The single most likely way for this linter to stop working is not a bug in a
// regex. It is a rename — `src/pages` moves, the glob stops matching, the walk
// returns zero files, and every rule below passes over nothing. That failure is
// invisible: the CI line stays green and says "OK". So the number of content
// pages actually read is compared against a floor, and a scan that fell below
// it is a FAILURE and not a warning. Chapter 2 of the design document freezes
// the site at six content URLs; if that number is ever deliberately reduced,
// the constant moves in the same commit, which is a diff a reviewer can argue
// with.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/** Artefact mode. See the mode note above. */
const DIST_MODE = process.argv.includes('--dist');

/**
 * Which site tree to read.
 *
 * Defaults to `site/`. The override exists for `scripts/site-copy-lint.test.ts`,
 * which builds small fixture trees in a temp directory and mutates exactly one
 * thing in each — that is the only way to demonstrate that a rule can actually
 * fail, and a rule nobody has ever seen fail is a green tick rather than a
 * check. README.md and packages/rules are always read from the real repository,
 * because they are what the site is checked AGAINST rather than part of it.
 */
function flagValue(name) {
  const i = process.argv.indexOf(name);
  const value = i >= 0 ? process.argv[i + 1] : undefined;
  return value && !value.startsWith('--') ? value : null;
}
const SITE_DIR = flagValue('--site') ?? join(REPO_ROOT, 'site');

/**
 * Repo-relative POSIX path, so failure messages read the same on both
 * platforms. A `--site` pointed outside the repository (the test fixtures) gets
 * its absolute path instead: `../../AppData/Local/Temp/…` is a path nobody can
 * paste into an editor.
 */
function rel(absPath) {
  const relPath = relative(REPO_ROOT, absPath).split(sep).join('/');
  return relPath.startsWith('..') ? absPath.split(sep).join('/') : relPath;
}

/** Every file under `dir`, recursively; `[]` when it does not exist. */
function walkFiles(dir, skipSegments = new Set(['node_modules', '.astro', '.wrangler'])) {
  if (!existsSync(dir)) return [];
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (skipSegments.has(entry.name)) continue;
      const full = join(current, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) out.push(full);
    }
  }
  return out;
}

const failures = [];

/**
 * Blank a region of text while keeping every newline.
 *
 * Every rule below reports `file:line:col`, and a report that points at the
 * wrong line costs more time than no report at all — the reader goes to the
 * line, sees nothing wrong, and concludes the linter is broken. So nothing is
 * ever deleted from a document; the parts a rule must not see are overwritten
 * with spaces and the line structure survives intact.
 */
const blank = (s) => s.replace(/[^\n]/g, ' ');

/**
 * The site's six content URLs, per chapter 2 of the design document. The floor
 * is exact rather than generous: a page is never added or removed by accident.
 */
const CONTENT_PAGE_FLOOR = 6;

// ── The deny-lists ──────────────────────────────────────────────────────────

/**
 * R1. Vocabulary that promises a future the repository has not shipped.
 *
 * The test is not the spelling, it is the speech act: every entry claims that
 * something will exist later. Chapter 0 admits exactly two product states —
 * `Available` (a URL you can press today) and `Research` (there is no artefact)
 * — and each of these words invents a third one in the reader's head.
 *
 * ★ BOTH LANGUAGES, and this is not symmetry for its own sake. Chapter 7 makes
 * `/research/compiler` the site's one bilingual page: English body, full
 * Japanese text underneath in a `<section lang="ja">`. That is also the single
 * page with the strongest pull toward "coming soon", because it is the page
 * about work that has not shipped. A deny-list holding only English would wave
 * 近日公開 straight through on the one page it was written for.
 *
 * English entries carry `\b` because the words have boundaries; Japanese
 * entries are plain substrings because it has none.
 */
const BANNED_VOCABULARY = [
  [/\bbeta\b/gi, 'implies "nearly the real version" — a third state chapter 0 does not have'],
  [/\bcoming\s+soon\b/gi, 'promises a date; the Compiler has none'],
  [/\broadmap\b/gi, 'a published list of unbuilt things dies visibly the day it stops moving'],
  [/\bpreview\b/gi, 'same promise as Beta, different spelling'],
  [/\balpha\b/gi, 'same promise as Beta, different spelling'],
  [/\bexperimental\b/gi, 'invites "try it now"; if it ships it is Available, if not it is Research'],
  [/\bplanned\b/gi, 'commits the author to work the site cannot deliver'],
  [/\bWIP\b/g, 'an unfinished thing announced as unfinished is still an announcement'],
  [/\bTBA\b/g, 'announces that an announcement is coming'],
  [/近日公開/g, 'Japanese "coming soon" — see the note above about half-covered deny-lists'],
  [/近日/g, 'Japanese "shortly"'],
  [/予定/g, 'Japanese "scheduled/planned"'],
  [/まもなく/g, 'Japanese "any moment now"'],
  [/今後対応/g, 'Japanese "will be supported later"'],
];

/**
 * R2. Acquisition vocabulary, forbidden on /research/* only.
 *
 * `/research/compiler` describes work with no packaged release and no channel
 * carrying it. Every word here is one a reader would take as "so there is a
 * build I can fetch": the version number most of all, because a version is what
 * a shipped thing has.
 */
const ACQUISITION_VOCABULARY = [
  [/\binstall\w*\b/gi, 'there is nothing to install'],
  [/\bdownloads?\b/gi, 'there is no artefact to download'],
  [/\bnpm\b/gi, 'nothing here is on a package registry'],
  [/\bbrew\b/gi, 'nothing here is in a package manager'],
  [/\bv\d/g, 'a version number is what a shipped thing has; this has no release'],
];

/**
 * R3. The two commands that cannot work, in the two shapes people write them.
 *
 * `apps/cli/package.json` carries `private: true` and the name is unclaimed on
 * the registry — `check-packaging-invariants.mjs` asserts that and explains why.
 * So neither line installs VibeGuard; the second would fetch whatever a
 * stranger publishes under that name tomorrow. Printing either on a website is
 * worse than useless, and this is a deliberate double of the deny-list above
 * because it must hold on EVERY page, not only the research one.
 */
const IMPOSSIBLE_COMMANDS = [
  [
    /npm\s+i(?:nstall)?\s+(?:-g|--global)\s+vibeguard/gi,
    'the CLI is private:true and unpublished; this command cannot work, and the name is ' +
      'unclaimed on the registry so it could one day install a stranger\'s package',
  ],
  [
    /npx\s+vibeguard/gi,
    'same reason: npx resolves from the registry, where this package does not exist',
  ],
];

/**
 * R9. A scan mode the shipped tool does not distinguish.
 *
 * There is no `deep` mode to select. Advertising one is not a broken promise
 * about the future — it is a wrong statement about the present, which is worse,
 * because a visitor can go and fail to find the flag today.
 */
const UNSHIPPED_MODE = [
  [/mode\s*:\s*deep\b/gi, 'there is no `mode: deep` to configure'],
  [/--mode\s+deep\b/gi, 'there is no `--mode deep` flag'],
  [/\bdeep(?:er)?\s+scans?\b/gi, 'the tool does not offer a separate deep scan'],
];

/**
 * R8. Colour literals outside the token file.
 *
 * `tokens.css` is the one place a colour is allowed to be a number. Everywhere
 * else it is `var(--vg-…)`, so that dark mode, contrast fixes and the two
 * research/product palettes are one edit instead of a search. A single stray
 * `#1a1a1a` in a component is invisible until the theme changes underneath it.
 *
 * The hex pattern demands a complete 3/4/6/8-digit literal and refuses a
 * trailing identifier character, so a CSS id selector (`#main`, `#install`)
 * does not read as a colour.
 */
const COLOUR_LITERALS = [
  /#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})(?![0-9a-zA-Z_-])/g,
  /\brgba?\s*\(/gi,
  /\bhsla?\s*\(/gi,
];

// ── Reading a page ──────────────────────────────────────────────────────────

/**
 * Split a document into the text a copy rule may read and the CSS an R8 check
 * may read, with line numbers preserved in both.
 *
 * Three things are removed from the copy text, and each removal is a false
 * positive that would otherwise have been reported forever:
 *
 *   · Comments. Both this repository's house style and the layouts themselves
 *     write long prose explanations ABOUT the deny-list — ResearchLayout's own
 *     header comment contains the words `install`, `download`, `npm` and `brew`
 *     while explaining that they are forbidden. Flagging the explanation is how
 *     a linter teaches people to delete the explanation.
 *   · `<style>` blocks, which are CSS: `--vg-alpha-weak` would trip the `alpha`
 *     deny-list, and a token name is not copy.
 *   · `class=` and `style=` attribute values, for the same reason — a class
 *     named `vg-preview` is a name, not a sentence.
 *
 * Note what is deliberately NOT removed: `href` values and Astro frontmatter
 * string literals. A link to `/download.zip` on the research page and a
 * `const blurb = 'Coming soon'` in frontmatter are both real violations that
 * reach the rendered page, and both would be invisible if this stripped markup
 * down to text nodes.
 */
function readDocument(file) {
  const raw = readFileSync(file, 'utf8');
  const isAstro = file.endsWith('.astro');

  let text = raw;

  // Astro frontmatter: a `---` fence pair at the very top. Its comments are JS
  // comments, so they are blanked by shape (the same line-oriented approach
  // check-packaging-invariants.mjs uses) rather than by lexing.
  if (isAstro && text.startsWith('---')) {
    const end = text.indexOf('\n---', 3);
    if (end !== -1) {
      const head = text.slice(0, end);
      const tail = text.slice(end);
      const cleanedHead = head
        .split('\n')
        .map((line) => {
          const t = line.trimStart();
          return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') ? blank(line) : line;
        })
        .join('\n');
      text = cleanedHead + tail;
    }
  }

  text = text.replace(/<!--[\s\S]*?-->/g, blank);

  // Pull the CSS out before the copy rules see it, and keep it for R8 — at the
  // same offsets, so both scans report the line the author is looking at.
  const styleChars = blank(text).split('');
  const styleBlock = /<style[^>]*>([\s\S]*?)<\/style>/gi;
  for (let m = styleBlock.exec(text); m; m = styleBlock.exec(text)) {
    const innerStart = m.index + m[0].indexOf('>') + 1;
    for (let i = 0; i < m[1].length; i++) styleChars[innerStart + i] = m[1][i];
  }
  const styleText = styleChars.join('');
  text = text.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, blank);

  text = text.replace(/\b(?:class|style)\s*=\s*"[^"]*"/gi, blank);
  text = text.replace(/\b(?:class|style)\s*=\s*'[^']*'/gi, blank);

  return { raw, copy: text, style: styleText };
}

/**
 * The part of a page a visitor reads, as opposed to the chrome around it.
 *
 * ★ THIS SCOPING IS WHAT KEEPS R2 ALIVE. The product footer carries a sitemap,
 * and a sitemap contains the word "Install". Applied to a whole page, R2 would
 * fail `/research/compiler` on every build from the day the footer shipped, and
 * a linter that is permanently red is a linter somebody deletes on a Friday.
 * The design document names this trap explicitly and asks for two independent
 * repairs: this one, and a sitemap-free footer on the research layout. Both are
 * in place — either alone would do, which is the point of having two.
 *
 * In source mode an Astro page file usually contains no `<main>` at all: the
 * layout supplies it and the page file IS the main content. So an absent
 * `<main>` means "the whole file" in source mode, and is a FAILURE in artefact
 * mode, where the tag must have been rendered. Treating a missing `<main>` in
 * built HTML as "scan nothing" would be the vacuous pass this file exists to
 * refuse.
 */
function mainRegion(text, { builtHtml }) {
  const open = text.search(/<main[\s>]/i);
  const close = text.toLowerCase().lastIndexOf('</main>');
  if (open === -1 || close === -1 || close < open) {
    return builtHtml ? null : text;
  }
  return blank(text.slice(0, open)) + text.slice(open, close) + blank(text.slice(close));
}

/**
 * Report every match of `patterns` in `text`, one failure per match.
 *
 * Overlapping matches are collapsed to the longest: `近日公開` and `近日` both
 * fire at the same offset, and two failures for one word reads as two problems.
 */
function scan(file, text, patterns, ruleName) {
  const hits = [];
  for (const [pattern, why] of patterns) {
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    for (let m = re.exec(text); m; m = re.exec(text)) {
      hits.push({ start: m.index, end: m.index + m[0].length, text: m[0], why });
      if (m[0].length === 0) re.lastIndex++;
    }
  }
  const kept = hits.filter(
    (h) => !hits.some((o) => o !== h && o.start <= h.start && o.end >= h.end && o.end - o.start > h.end - h.start),
  );

  for (const hit of kept.sort((a, b) => a.start - b.start)) {
    const before = text.slice(0, hit.start);
    const line = before.split('\n').length;
    const column = hit.start - (before.lastIndexOf('\n') + 1) + 1;
    failures.push(
      `${rel(file)}:${line}:${column} [${ruleName}] ${JSON.stringify(hit.text)}\n` +
        `  ${hit.why}.\n` +
        `  Rewrite the sentence around it; do not add an exception here. Chapter 0.7 of\n` +
        `  docs/公式サイト公開設計.md has a same-meaning replacement for every one of these.`,
    );
  }
}

// ── The constant tables the site is checked against ─────────────────────────

/**
 * Parse `site/src/shared/links.ts` as TEXT rather than importing it.
 *
 * It is TypeScript, and this script must run with no build and no loader. The
 * shape it parses is a flat `Record<Channel, string>` of single-quoted URLs,
 * which is what that file is documented to be; a parse that comes back short is
 * treated as a failure below rather than as an empty comparison.
 */
function parseGoTargets() {
  const path = join(SITE_DIR, 'src', 'shared', 'links.ts');
  if (!existsSync(path)) return { path, targets: null };
  const source = readFileSync(path, 'utf8');
  const block = /export const GO_TARGETS[^=]*=\s*\{([\s\S]*?)\n\};/.exec(source);
  if (!block) return { path, targets: null };
  const targets = {};
  const entry = /^\s*(\w+)\s*:\s*'([^']+)'/gm;
  for (let m = entry.exec(block[1]); m; m = entry.exec(block[1])) targets[m[1]] = m[2];
  return { path, targets };
}

/** Keys of an object literal exported from `site/src/headers.ts`, by text. */
function parseHeaderKeys(name) {
  const path = join(SITE_DIR, 'src', 'headers.ts');
  if (!existsSync(path)) return null;
  const source = readFileSync(path, 'utf8');
  const block = new RegExp(`export const ${name}[^=]*=\\s*\\{([\\s\\S]*?)\\n\\};`).exec(source);
  if (!block) return null;
  const keys = [];
  const entry = /^\s*'([A-Za-z][A-Za-z0-9-]*)'\s*:/gm;
  for (let m = entry.exec(block[1]); m; m = entry.exec(block[1])) keys.push(m[1]);
  return keys;
}

/** Rule IDs read out of TypeScript source, for a checkout that was never built. */
function ruleIdsFromSource(dir) {
  const ids = new Set();
  for (const file of walkFiles(dir)) {
    if (!file.endsWith('.ts') || file.endsWith('.test.ts')) continue;
    const re = /ruleId:\s*'(VG-[A-Z]+-\d+)'/g;
    const text = readFileSync(file, 'utf8');
    for (let m = re.exec(text); m; m = re.exec(text)) ids.add(m[1]);
  }
  return ids;
}

/**
 * Every rule ID a user can actually be shown, from BOTH registries.
 *
 * ★ THERE ARE TWO, AND THIS CHECK WAS WRONG UNTIL IT KNEW THAT. `allRules` in
 * `@vibeguard/rules` holds the single-file rules that every channel runs. The
 * cross-file design smells — `VG-SMELL-010`, `-011`, `-013`, `-020`, `-021`,
 * `-030`, `-041`, `-052` and the two `VG-AISC` / one `VG-RTOS` companions —
 * live in `crossFileRules` in `@vibeguard/analysis-graph`, which is CLI and
 * Action only (`check-packaging-invariants.mjs` invariants 3 and 4 exist to
 * keep it out of the extensions). Checking only the first registry rejects
 * eight real, shipped, documentable rule IDs, so `/rules` would have had to
 * choose between being incomplete and turning this rule off.
 *
 * ★ AND `crossFileRules` RATHER THAN "every ruleId in that package", which is
 * the sharper half. `analysis-graph` deliberately exports rules it has NOT
 * registered — `VG-SMELL-031` is exported so the corpus sweep can measure it,
 * and is not in the registry, so it never runs for anybody. Documenting it
 * would be the 0.3.5 accident exactly: describing a rule that produces no
 * finding on any user's machine. The registry is what ships; the export is not.
 *
 * Preferred source is therefore the BUILT packages, because only the modules
 * know what those two arrays evaluate to. The fallback reads source text so
 * this still works in a checkout that has never been built — and it is more
 * permissive, because a text scan cannot see the registry boundary. Which
 * source answered is printed in the summary, since "checked against the
 * registry" and "checked against every ID written down anywhere" are different
 * claims and must not print the same line.
 */
async function loadKnownRuleIds() {
  const ids = new Set();
  const notes = [];

  try {
    const mod = await import('@vibeguard/rules');
    const single = (mod.allRules ?? []).map((r) => r.ruleId).filter(Boolean);
    if (!single.length) throw new Error('allRules empty');
    for (const id of single) ids.add(id);
    notes.push(`@vibeguard/rules allRules (built, ${single.length})`);
  } catch {
    const fromSource = ruleIdsFromSource(join(REPO_ROOT, 'packages', 'rules', 'src', 'rules'));
    for (const id of fromSource) ids.add(id);
    notes.push(`packages/rules/src text (NOT BUILT, ${fromSource.size})`);
  }

  try {
    const mod = await import('@vibeguard/analysis-graph');
    const cross = (mod.crossFileRules ?? []).map((r) => r.ruleId).filter(Boolean);
    if (!cross.length) throw new Error('crossFileRules empty');
    for (const id of cross) ids.add(id);
    notes.push(`analysis-graph crossFileRules (built, ${cross.length})`);
  } catch {
    const fromSource = ruleIdsFromSource(
      join(REPO_ROOT, 'packages', 'analysis-graph', 'src', 'design-smells-crossfile'),
    );
    for (const id of fromSource) ids.add(id);
    notes.push(
      `analysis-graph src text (NOT BUILT, ${fromSource.size} — includes unregistered candidates)`,
    );
  }

  return { ids, source: notes.join(' + ') };
}

// ── Collect the documents to read ───────────────────────────────────────────

/**
 * A page, in whichever mode we are in.
 *
 * `route` is what a visitor would type. It is derived from the file path in
 * both modes so that "is this a research page?" is one question with one
 * answer, rather than two path conventions that can disagree.
 */
function collectPages() {
  const pages = [];
  if (DIST_MODE) {
    const dist = join(SITE_DIR, 'dist');
    for (const file of walkFiles(dist)) {
      if (!file.endsWith('.html')) continue;
      const route =
        '/' + relative(dist, file).split(sep).join('/').replace(/index\.html$/, '').replace(/\.html$/, '');
      pages.push({ file, route, isContent: !/^\/404\/?$/.test(route) });
    }
  } else {
    const pagesDir = join(SITE_DIR, 'src', 'pages');
    for (const file of walkFiles(pagesDir)) {
      if (!/\.(astro|md|mdx|html)$/.test(file)) continue;
      const base = relative(pagesDir, file).split(sep).join('/');
      if (base.split('/').some((seg) => seg.startsWith('_'))) continue;
      const route = '/' + base.replace(/\.(astro|md|mdx|html)$/, '').replace(/(^|\/)index$/, '$1');
      pages.push({ file, route, isContent: !/^\/404\/?$/.test(route) });
    }
  }
  return pages.sort((a, b) => a.route.localeCompare(b.route));
}

/**
 * Shared markup that is not a page but still renders into every page: layouts
 * and components in source mode. R1/R3/R9 must reach them — a banned word in
 * the footer appears on all six pages while appearing in none of the six page
 * files. R2 must NOT reach them, for the scoping reason above.
 */
function collectSharedMarkup() {
  if (DIST_MODE) return [];
  return [
    ...walkFiles(join(SITE_DIR, 'src', 'layouts')),
    ...walkFiles(join(SITE_DIR, 'src', 'components')),
  ].filter((f) => f.endsWith('.astro'));
}

/** Generated data and static files that end up as visible text. */
function collectDataAndPublic() {
  if (DIST_MODE) return [];
  return [
    ...walkFiles(join(SITE_DIR, 'src', 'data')).filter((f) => f.endsWith('.json')),
    ...walkFiles(join(SITE_DIR, 'public')).filter((f) => /\.(txt|json|html|xml|svg)$/.test(f)),
  ];
}

// ── Run ─────────────────────────────────────────────────────────────────────

const pages = collectPages();
const contentPages = pages.filter((p) => p.isContent);
const sharedMarkup = collectSharedMarkup();
const dataFiles = collectDataAndPublic();

let pagesNote = `pages: ${contentPages.length} content page(s) read (${contentPages.map((p) => p.route).join(', ') || 'none'})`;
let rulesNote = 'rule IDs: not compared';
let linksNote = 'go targets: not compared against README.md';
let headersNote = DIST_MODE ? '_headers: not inspected' : '_headers: artefact mode only';

// ---- Vacuity guard -------------------------------------------------------
//
// Deliberately the first thing checked and a hard failure. Every rule below
// this line is a loop over `pages`; if that array is short, they all pass
// having read almost nothing, and the run prints OK. "I checked six pages and
// found no lies" and "I found no pages" must never share an exit code.
if (contentPages.length < CONTENT_PAGE_FLOOR) {
  failures.push(
    `only ${contentPages.length} content page(s) were found under ` +
      `${rel(DIST_MODE ? join(SITE_DIR, 'dist') : join(SITE_DIR, 'src', 'pages'))}, ` +
      `below the required ${CONTENT_PAGE_FLOOR}.\n` +
      `  Found: ${contentPages.map((p) => p.route).join(', ') || '(nothing)'}\n` +
      `  This is a FAILURE and not a skip. Every rule in this linter is a loop over the\n` +
      `  pages it found, so a short list makes all of them pass over nothing while the log\n` +
      `  still says OK — the one failure mode that would let the 0.3.5 accident through\n` +
      `  the CI job written to stop it.\n` +
      `  In artefact mode this usually means \`astro build\` did not run. If the site\n` +
      `  genuinely has fewer pages now, lower CONTENT_PAGE_FLOOR in this file in the same\n` +
      `  commit, so the decision is something a reviewer saw.`,
  );
}

// ---- R1 / R3 / R9 on every page and every shared component ---------------
for (const { file } of [...pages.map((p) => ({ file: p.file })), ...sharedMarkup.map((f) => ({ file: f }))]) {
  const { copy } = readDocument(file);
  scan(file, copy, BANNED_VOCABULARY, 'R1 banned vocabulary');
  scan(file, copy, IMPOSSIBLE_COMMANDS, 'R3 impossible command');
  scan(file, copy, UNSHIPPED_MODE, 'R9 unshipped mode');
}

// Generated JSON and public files: same three rules, read as plain text. A
// build script that copies a release note verbatim is exactly how "Beta" gets
// onto a page nobody wrote.
for (const file of dataFiles) {
  const text = readFileSync(file, 'utf8');
  scan(file, text, BANNED_VOCABULARY, 'R1 banned vocabulary');
  scan(file, text, IMPOSSIBLE_COMMANDS, 'R3 impossible command');
  scan(file, text, UNSHIPPED_MODE, 'R9 unshipped mode');
}

// ---- R2: acquisition vocabulary, research pages, <main> only -------------
let researchPagesScanned = 0;
for (const page of pages.filter((p) => p.route.startsWith('/research'))) {
  const { copy } = readDocument(page.file);
  const region = mainRegion(copy, { builtHtml: DIST_MODE });
  if (region === null) {
    failures.push(
      `${rel(page.file)} contains no <main> element, so rule R2 had nothing to scope to.\n` +
        `  R2 is deliberately limited to the content region — a shared footer's sitemap\n` +
        `  would otherwise put the word "Install" on this page and fail every build. With no\n` +
        `  <main> in the built HTML there is no content region, and scanning nothing would\n` +
        `  report this page as clean. Give the layout a <main>.`,
    );
    continue;
  }
  researchPagesScanned++;
  scan(page.file, region, ACQUISITION_VOCABULARY, 'R2 acquisition vocabulary on /research');
}

// The research page is not optional: chapter 2 freezes it into the six URLs,
// and it is the page the whole deny-list was written for.
if (contentPages.length >= CONTENT_PAGE_FLOOR && researchPagesScanned === 0) {
  failures.push(
    'no /research page was scanned, so rule R2 did not run at all.\n' +
      '  The site has a research page by construction (chapter 2 freezes six URLs, one of\n' +
      '  them /research/compiler). Zero here means the route moved and R2 is now checking\n' +
      '  an empty set — the rule that exists specifically to stop an unshipped compiler\n' +
      '  being advertised as obtainable.',
  );
}

// ---- R4: every rule ID on the site exists in the engine ------------------
{
  const { ids: knownIds, source } = await loadKnownRuleIds();
  rulesNote = `rule IDs: checked against ${source}`;

  if (knownIds.size === 0) {
    failures.push(
      'could not load a single rule ID from @vibeguard/rules or from packages/rules/src,\n' +
        '  so R4 would have accepted any ID the site prints. Fix the load path rather than\n' +
        '  letting the one check that ties copy to the real product pass over nothing.',
    );
  }

  const RULE_ID = /\bVG-[A-Z]+-\d+\b/g;
  const seen = new Map();
  const sources = [...pages.map((p) => p.file), ...sharedMarkup, ...dataFiles];
  for (const file of sources) {
    const text = file.endsWith('.json') ? readFileSync(file, 'utf8') : readDocument(file).copy;
    for (let m = RULE_ID.exec(text); m; m = RULE_ID.exec(text)) {
      if (!seen.has(m[0])) seen.set(m[0], file);
    }
  }

  for (const [id, file] of seen) {
    if (knownIds.has(id)) continue;
    failures.push(
      `${rel(file)} mentions rule ${id}, which does not exist in @vibeguard/rules.\n` +
        `  A rule ID is the one element of this site that can be checked one-to-one against\n` +
        `  the product. An ID nobody can look up is direct evidence the copy was written\n` +
        `  without reading the engine, and it tells a visitor to search for something that\n` +
        `  will never appear in their output.`,
    );
  }

  if (knownIds.size > 0 && seen.size === 0) {
    failures.push(
      'no rule ID appears anywhere on the site, so R4 compared an empty set.\n' +
        '  The site documents a rule catalogue; at least /rules renders IDs. Zero of them\n' +
        '  means the generated data is missing or the page stopped printing them, and in\n' +
        '  either case the strongest check available here just became decoration.',
    );
  }
  rulesNote += `, ${seen.size} distinct ID(s) found on the site`;
}

// ---- R5: /go/* targets equal README's Install table ----------------------
//
// The README is parsed, not transcribed. A hard-coded expectation here would be
// a THIRD copy of the five URLs, and the entire reason links.ts exists is that
// the second copy is where drift lives.
{
  const { path: linksPath, targets } = parseGoTargets();
  if (!targets || Object.keys(targets).length < 5) {
    failures.push(
      `${rel(linksPath)}: could not parse five GO_TARGETS entries out of it ` +
        `(found ${targets ? Object.keys(targets).length : 0}).\n` +
        `  Every redirect the site serves comes from that table, and this comparison is what\n` +
        `  keeps it equal to the README. If the shape of the export changed, update this\n` +
        `  parser in the same commit — an unparseable table silently stops being compared.`,
    );
  } else {
    const readmePath = join(REPO_ROOT, 'README.md');
    const readme = readFileSync(readmePath, 'utf8');

    // The Install table is the section between the `## Install` heading and the
    // next `## ` heading. Everything else in the README (badges, prose) is a
    // weaker authority: the design document names the table as the source of
    // truth for the four channels, and the badges for the repository link.
    const section = /\n##\s+Install\s*\n([\s\S]*?)(?=\n##\s)/.exec(readme);
    if (!section) {
      failures.push(
        'README.md has no "## Install" section, so the /go/* targets could not be compared\n' +
          '  against their source of truth. If the heading was renamed, update this parser.',
      );
    } else {
      const tableUrls = new Set();
      const link = /\]\((https?:\/\/[^)\s]+)\)/g;
      for (let m = link.exec(section[1]); m; m = link.exec(section[1])) tableUrls.add(m[1]);

      if (tableUrls.size === 0) {
        failures.push(
          'README.md\'s Install section contains no absolute URLs, so R5 compared nothing.\n' +
            '  The table is the authority for the four channel URLs; an empty parse means the\n' +
            '  table changed shape and this check stopped seeing it.',
        );
      }

      // Both directions. Missing-from-README catches a URL invented on the site;
      // missing-from-links.ts catches a channel added to the README that the
      // site's redirect table never learned about — the direction a one-way
      // check would wave through.
      for (const channel of ['vscode', 'openvsx', 'chrome', 'action']) {
        const url = targets[channel];
        if (!url || tableUrls.has(url)) continue;
        failures.push(
          `${rel(linksPath)}: GO_TARGETS.${channel} is ${JSON.stringify(url)}, which does not\n` +
            `  appear in README.md's Install table.\n` +
            `  The table is the source of truth for where a channel lives. A /go/ redirect that\n` +
            `  disagrees with it sends visitors to the wrong listing, and nothing about the site\n` +
            `  would look broken while it happened.`,
        );
      }
      const declared = new Set(['vscode', 'openvsx', 'chrome', 'action'].map((c) => targets[c]));
      for (const url of tableUrls) {
        if (declared.has(url)) continue;
        failures.push(
          `README.md's Install table lists ${JSON.stringify(url)}, which no GO_TARGETS entry\n` +
            `  points at.\n` +
            `  Either a channel was added to the README and not to the site, or a URL moved on\n` +
            `  one side only. Both are the same fix: one table, in ${rel(linksPath)}.`,
        );
      }

      // The repository link's authority is the badge block rather than the
      // table, per the design document's /go/* specification.
      if (targets.github && !readme.includes(targets.github)) {
        failures.push(
          `${rel(linksPath)}: GO_TARGETS.github is ${JSON.stringify(targets.github)}, which\n` +
            `  appears nowhere in README.md. That URL is the repository itself; if it is wrong\n` +
            `  here it is wrong in the footer of every page.`,
        );
      }
      linksNote =
        `go targets: ${Object.keys(targets).length} parsed, ` +
        `${tableUrls.size} URL(s) in README.md's Install table, compared both ways`;
    }
  }
}

// ---- R8 (source mode): colour literals outside tokens.css ----------------
//
// Artefact mode cannot run this. The build concatenates every stylesheet into
// one hashed file, tokens.css included, so the literals that are legitimately
// in the token file would be indistinguishable from the ones that are not.
if (!DIST_MODE) {
  const tokensPath = join(SITE_DIR, 'src', 'styles', 'tokens.css');
  const cssFiles = walkFiles(join(SITE_DIR, 'src')).filter((f) => f.endsWith('.css'));
  const patterns = COLOUR_LITERALS.map((p) => [
    p,
    'colour literals live only in styles/tokens.css; everywhere else uses var(--vg-…) so ' +
      'that a palette change is one edit rather than a search',
  ]);
  for (const file of cssFiles) {
    if (file === tokensPath) continue;
    scan(file, readFileSync(file, 'utf8'), patterns, 'R8 colour literal');
  }
  // Scoped <style> blocks inside components are CSS too, and are the likeliest
  // place for a one-off colour to be typed without thinking about the palette.
  for (const file of [...pages.map((p) => p.file), ...sharedMarkup]) {
    scan(file, readDocument(file).style, patterns, 'R8 colour literal');
  }
}

// ---- R6 (artefact mode): no script, nothing loaded from off-site ---------
//
// The CSP declares `script-src 'none'` and `default-src 'self'`. A declaration
// is a claim about a build nobody inspected: if a `<script>` tag reaches a page,
// the browser silently refuses to run that one element and the page looks
// subtly broken with nothing in the logs. This is what turns the header into a
// measured property of the artefact.
if (DIST_MODE) {
  const { targets } = parseGoTargets();
  const goUrls = new Set(Object.values(targets ?? {}));
  // The one navigational exception, and it is derived from the same constant
  // table rather than typed here: the footer's MIT-licence and NOTICE links
  // point into the repository that GO_TARGETS.github already names. They are
  // links a visitor clicks, not resources the page loads, so they cost the
  // reader nothing and the CSP nothing.
  const repoPrefix = targets?.github ? targets.github + '/' : null;

  for (const page of pages) {
    const html = readFileSync(page.file, 'utf8');

    const scriptTag = /<script\b/gi;
    for (let m = scriptTag.exec(html); m; m = scriptTag.exec(html)) {
      const line = html.slice(0, m.index).split('\n').length;
      failures.push(
        `${rel(page.file)}:${line} contains a <script> tag.\n` +
          `  The site ships zero client-side JavaScript and the CSP says script-src 'none',\n` +
          `  so this element will be blocked in the browser: whatever it was for will not\n` +
          `  happen, and nothing will report that it did not. Menus and disclosure use\n` +
          `  <details>/<summary>; there is no case where a script is the answer here.`,
      );
    }

    // The same argument as the script rule, for the header nobody thinks about.
    //
    // The CSP says `style-src 'self'`, which blocks an inline <style> element
    // exactly as `script-src 'none'` blocks a <script>. The trap is that Astro
    // INLINES small stylesheets by default — a scoped <style> block in a .astro
    // page becomes a <style> element in <head> — so a page can be perfectly
    // styled under `astro preview`, where no CSP is applied, and arrive in
    // production with its rules dropped on the floor. That failure is silent
    // and it is invisible locally, which is the combination that makes it worth
    // a check rather than a convention. Four pages had already shipped into
    // this state before it was noticed.
    //
    // The fix is always the same: move the rules into site/src/styles/*.css,
    // which is served from the origin and is what 'self' permits.
    const styleTag = /<style\b/gi;
    for (let m = styleTag.exec(html); m; m = styleTag.exec(html)) {
      const line = html.slice(0, m.index).split('\n').length;
      failures.push(
        `${rel(page.file)}:${line} contains an inline <style> element.\n` +
          `  The CSP says style-src 'self', so the browser will refuse this block and render\n` +
          `  the page without those rules — while astro preview, which applies no CSP,\n` +
          `  shows it looking correct. Astro inlines small scoped <style> blocks into <head>\n` +
          `  by default, so writing one in a .astro file is enough to cause this.\n` +
          `  Move the rules into site/src/styles/*.css.`,
      );
    }

    // Nothing that identifies the author's machine or person reaches the page.
    //
    // Every other rule here is about the site telling the truth. This one is
    // about the site not saying more than it meant to, and no existing check
    // covers it: check-disclosure-shape scans the TRACKED TREE, so it never
    // looks at dist/, and the rest of this file reads vocabulary rather than
    // shape. That leaves a real route open. Findings, code snippets and the
    // hero are produced by running the scanner at build time, and the scanner
    // reports whatever path it was handed — an absolute one for a single-file
    // scan. The hero generator normalises it to a basename, and the only thing
    // keeping that normalisation honest today is that somebody looked once.
    //
    // The CI build runs on a clean Linux checkout, so the mistake will not
    // surface there. It surfaces when a human generates locally and deploys by
    // hand, which is precisely the path the deploy notes describe for the first
    // release. So the check belongs on the artefact, where both routes meet.
    //
    // There is NO allow-list here, and the first draft's was worse than none.
    //
    // It held the author's name and GitHub handle, and it was tested with
    // `match.includes(entry)` — against the matched text rather than its
    // surroundings. So a Windows home path under that handle, and an address at
    // any domain under that handle, both contained an allow-listed string and
    // both were waved through: the author's own home directory and the author's
    // own address, which are the two things this rule exists to catch. An
    // allow-list keyed on the name of the person whose identifiers are being
    // protected inverts the check.
    //
    // ★ 2026-08-16: this paragraph used to make the point by SPELLING those two
    // strings out, and `scripts/check-disclosure-shape.mjs` reported the home
    // path as a HOME-DIRECTORY shape in the tracked tree — correctly. Writing an
    // example of the identifier a rule protects is the same disclosure as
    // leaking it by accident; the reader does not care which one the author
    // meant. Describe the shape, never instantiate it.
    //
    // It also bought nothing. None of those three strings can match any pattern
    // below — `Author: Kondo Yuta` has no `@` and no path separator, and the
    // GitHub and Open VSX URLs contain neither `/home/` nor `/Users/` nor an
    // `@`. Verified against the built site, which passes with the list gone.
    const identityPatterns = [
      [/[A-Za-z]:[\\/]{1,2}[Uu]sers[\\/][^\s"'<>]+/g, 'a Windows home-directory path'],
      [/\/(?:home|Users)\/[A-Za-z0-9._-]+/g, 'a home-directory path'],
      [/\/mnt\/[a-z]\/[Uu]sers\/[^\s"'<>]+/g, 'a WSL home-directory path'],
      [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, 'an email address'],
    ];
    for (const [pattern, what] of identityPatterns) {
      for (let m = pattern.exec(html); m; m = pattern.exec(html)) {
        const line = html.slice(0, m.index).split('\n').length;
        failures.push(
          `${rel(page.file)}:${line} contains ${what}: ${JSON.stringify(m[0].slice(0, 80))}\n` +
            `  This is served to every visitor. The likeliest source is generated data: the\n` +
            `  scanner reports the path it was given, and a single-file scan gives it an\n` +
            `  absolute one. Normalise it in the generator that produced it — not here, and\n` +
            `  not by editing the built file, which is overwritten on the next build.`,
        );
      }
    }

    // No HTML comments survive into the artefact.
    //
    // This is a disclosure rule, not a tidiness one. Astro emits a template
    // `<!-- ... -->` verbatim into the built page, while a comment in the
    // frontmatter fence or a `{/* ... */}` expression is dropped. The three
    // kinds look equally private while you are editing the file, and exactly
    // one of them is not.
    //
    // The comments this repository writes are long, and they explain reasoning
    // that is genuinely internal: which numbers the working notes have ruled
    // out of the paper and why, what an earlier draft got wrong, what a guard
    // is defending against. The research page shipped three such blocks —
    // including one explaining that naming a submission venue would let a later
    // deletion announce a rejection. That comment was written to protect the
    // very thing it then published, which is the whole argument for checking
    // this mechanically rather than remembering it.
    //
    // Move the text into the frontmatter (`---`) block, or into `{/* ... */}`.
    const htmlComment = /<!--/g;
    for (let m = htmlComment.exec(html); m; m = htmlComment.exec(html)) {
      const line = html.slice(0, m.index).split('\n').length;
      failures.push(
        `${rel(page.file)}:${line} contains an HTML comment, which is served to every visitor.\n` +
          `  Astro emits template <!-- --> comments into the built page; frontmatter comments and\n` +
          `  {/* ... */} expressions are dropped. This repository's comments explain internal\n` +
          `  reasoning — draft history, which measurements are not trusted, what a guard defends\n` +
          `  against — and none of that is written for the public.\n` +
          `  Move it into the --- frontmatter block, or into {/* ... */}.`,
      );
    }

    // Subresources get NO exception. Anything the page LOADS from another host
    // is a third party who learns the visitor's IP and can change the payload
    // later — the property the whole no-external-hosts rule exists to keep.
    const sub = /\b(src|srcset)\s*=\s*["']([^"']+)["']/gi;
    for (let m = sub.exec(html); m; m = sub.exec(html)) {
      if (!/^https?:\/\//i.test(m[2])) continue;
      const line = html.slice(0, m.index).split('\n').length;
      failures.push(
        `${rel(page.file)}:${line} loads ${JSON.stringify(m[2])} via ${m[1]}=.\n` +
          `  The site loads nothing from another host — no fonts, no CDN, no remote images —\n` +
          `  and the CSP's default-src 'self' will block this. A subresource has no exception\n` +
          `  list: inline it, or copy the asset into site/public/.`,
      );
    }

    // The site's own origin is not an off-site destination.
    //
    // Once SITE_ORIGIN is set, canonical and og:url become absolute — they have
    // to be; both are defined as absolute URLs and a relative canonical is
    // ignored. Those are self-references, and reading them as external links
    // made this rule fail on every page the moment the site learned its own
    // address, which is a linter punishing a build for being more correct.
    //
    // Matched on origin rather than on the exact strings, so it covers the
    // canonical, og:url, and the sitemap URL in robots.txt alike, and nothing
    // else: a link to any OTHER host is still a finding.
    //
    // Read out of THIS DOCUMENT'S canonical rather than out of the environment,
    // and that choice is the point. Taking it from SITE_ORIGIN couples the
    // linter to a variable the build may have been given and the check may not:
    // a tree built with an origin and linted without one fails on every page,
    // which is a difference between two shells rather than a defect in the
    // site. That is the same shape as the three CI failures this deployment
    // already produced, all of them invisible locally.
    //
    // A document's canonical is written by the layouts from Astro.site, so it
    // IS the origin this artefact was built for, by construction. Self-exempting
    // is not a risk worth guarding here: the canonical comes from the same build
    // as the links being checked, so a wrong origin would make every URL on the
    // page wrong together and visibly.
    const ownOrigin = (() => {
      const canonical = /<link\s[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)["']/i.exec(html);
      if (!canonical) return null;
      try {
        return new URL(canonical[1]).origin;
      } catch {
        return null;
      }
    })();

    const anchors = /\bhref\s*=\s*["']([^"']+)["']/gi;
    for (let m = anchors.exec(html); m; m = anchors.exec(html)) {
      const url = m[1];
      if (!/^https?:\/\//i.test(url)) continue;
      if (goUrls.has(url)) continue;
      if (repoPrefix && url.startsWith(repoPrefix)) continue;
      if (ownOrigin && url.startsWith(ownOrigin)) continue;
      const line = html.slice(0, m.index).split('\n').length;
      failures.push(
        `${rel(page.file)}:${line} links to the external URL ${JSON.stringify(url)}.\n` +
          `  Off-site destinations go through /go/<channel>, which is the only place a store\n` +
          `  URL is written and the only place a click is counted. The exceptions are the\n` +
          `  /go/* targets themselves and paths inside the repository GO_TARGETS.github names.`,
      );
    }
  }

  for (const file of walkFiles(join(SITE_DIR, 'dist')).filter((f) => f.endsWith('.css'))) {
    const css = readFileSync(file, 'utf8');
    const remote = /url\(\s*['"]?(https?:\/\/[^)'"]+)/gi;
    for (let m = remote.exec(css); m; m = remote.exec(css)) {
      const line = css.slice(0, m.index).split('\n').length;
      failures.push(
        `${rel(file)}:${line} fetches ${JSON.stringify(m[1])} from a stylesheet.\n` +
          `  Same rule as a subresource in the HTML, and easier to miss: an @font-face or a\n` +
          `  background-image is a third-party request the visitor never sees in the markup.`,
      );
    }
  }
}

// ---- R7 (artefact mode): _headers shipped, and complete ------------------
//
// Cloudflare's static-asset layer reads `_headers`; it is generated from
// headers.ts at build time. Forgetting to generate it is a silent failure —
// the site serves perfectly, with no CSP, and the only symptom is a header that
// is not there.
if (DIST_MODE) {
  const headersFile = join(SITE_DIR, 'dist', '_headers');
  // BASE_HEADERS only. GO_HEADERS are attached by the Worker to /go/* responses,
  // which `_headers` provably does not cover (Cloudflare documents that it does
  // not apply to Worker-generated responses), and HSTS is conditional on a
  // custom domain existing. Demanding either here would make this rule red on a
  // correct build.
  const required = parseHeaderKeys('BASE_HEADERS');
  if (!required || required.length === 0) {
    failures.push(
      `${rel(join(SITE_DIR, 'src', 'headers.ts'))}: no BASE_HEADERS keys could be parsed, so\n` +
        `  the generated _headers was compared against an empty list and would have passed\n` +
        `  while containing nothing.`,
    );
  } else if (!existsSync(headersFile)) {
    failures.push(
      `${rel(headersFile)} does not exist.\n` +
        `  Cloudflare reads that file to attach the CSP and the other security headers to\n` +
        `  every static response. Without it the site still serves every page perfectly and\n` +
        `  every header is missing — a failure with no visible symptom. It is generated from\n` +
        `  site/src/headers.ts during the build; that step did not run.`,
    );
  } else {
    const text = readFileSync(headersFile, 'utf8');
    const missing = required.filter((key) => !new RegExp(`^\\s*${key}\\s*:`, 'mi').test(text));
    if (missing.length) {
      failures.push(
        `${rel(headersFile)} is missing header(s): ${missing.join(', ')}.\n` +
          `  headers.ts is the single definition and this file is generated from it, so a\n` +
          `  missing key means the generator and the definition have drifted apart. Every one\n` +
          `  of them is a header a browser will not receive.`,
      );
    }
    headersNote = `_headers: ${required.length - missing.length}/${required.length} BASE_HEADERS key(s) present`;
  }
}

// ── Report ──────────────────────────────────────────────────────────────────

if (failures.length) {
  console.error(`site copy lint FAILED (${DIST_MODE ? 'artefact' : 'source'} mode):\n`);
  for (const f of failures) console.error(`  - ${f}\n`);
  process.exit(1);
}

console.log(
  DIST_MODE
    ? 'site copy lint OK, ARTEFACT mode (banned vocabulary, impossible install commands, ' +
      'unshipped scan mode, acquisition vocabulary inside /research <main>, rule IDs, ' +
      'README/go-target agreement, no home path or email address, no <script>, no inline <style>, no HTML comment and no off-site subresource in the built ' +
      'HTML, _headers complete). ' +
      'The colour-literal rule did NOT run — the build concatenates tokens.css into the ' +
      'same file, so run source mode for that.'
    : 'site copy lint OK, SOURCE mode (banned vocabulary, impossible install commands, ' +
      'unshipped scan mode, acquisition vocabulary inside /research <main>, rule IDs, ' +
      'README/go-target agreement, colour literals outside tokens.css). ' +
      'The built-HTML and _headers rules did NOT run — rerun with --dist after ' +
      '`npm run build` in site/ to check the artefact.',
);
console.log(`  ${pagesNote}`);
console.log(`  ${rulesNote}`);
console.log(`  ${linksNote}`);
console.log(`  ${headersNote}`);
