#!/usr/bin/env node
/**
 * Generates site/src/data/hero.json — the single finding the front page leads with.
 *
 * WHY THIS FILE EXISTS AT ALL
 *
 * The design document contradicts itself about which finding belongs in the
 * hero, and the contradiction is not a typo — the two chapters want different
 * things for stated reasons:
 *
 *   §5.9 wants the hero to show the same sample the triptych then works
 *   through, so that reading down the page is one continuous story: here is a
 *   finding, and here is that finding being answered.
 *
 *   §3.1.2 wants the DEBUG-bypass in samples/vulnerable/auth_bypass.py, on
 *   three grounds — it is `critical` rather than `high`, it is the exact
 *   failure this product is named after ("a debug bypass an assistant left in"),
 *   and it is six lines of Python that a reader of any language can follow.
 *
 * §3.8 settles it: page copy is chapter 3's authority, and which finding the
 * hero shows is page copy. So §3.1.2 wins, and this generator is how it wins —
 * index.astro reads this file when it exists and falls back to the triptych's
 * first card when it does not.
 *
 * WHY IT IS GENERATED AND NOT WRITTEN
 *
 * The same rule that governs every other number on this site: the hero is real
 * CLI output, produced by running the real scanner over a real fixture at build
 * time. A hand-transcribed finding is a screenshot that cannot be re-taken —
 * when the rule's wording or severity changes, a literal in a template becomes
 * quietly false and nothing reports it. Running the scanner means the front
 * page either shows what the product currently says or fails the build.
 *
 * It also means the caption cannot lie: index.astro asserts that the path in
 * `sourceFile` is under samples/, because a finding shown without provenance
 * reads as somebody's real breach on display.
 */

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(REPO_ROOT, 'site', 'src', 'data', 'hero.json');

/**
 * The fixture and the rule, named together on purpose.
 *
 * The scan below returns every finding in the directory, and picking "the first
 * one" would make the hero depend on file-walk order — a new fixture landing in
 * samples/vulnerable/ would silently replace the front page's headline. Naming
 * the rule means a change to the hero is a change to this line.
 */
const SOURCE_FILE = 'samples/vulnerable/auth_bypass.py';
const RULE_ID = 'VG-AUTH-001';

/**
 * Timing and identity fields are stripped rather than passed through. They
 * change on every run, so leaving them in would make each build produce a
 * different hero.json and every deploy carry a diff that means nothing. The
 * list is a whitelist for the same reason the triptych generator uses one: a
 * blacklist silently admits whatever field the schema gains next.
 */
const KEEP = [
  'ruleId',
  'title',
  'description',
  'severity',
  'confidence',
  'category',
  'language',
  'filePath',
  'startLine',
  'endLine',
  'startColumn',
  'endColumn',
  'snippet',
  'evidence',
  'remediation',
  'tags',
];

const fail = (message) => {
  process.stderr.write(`site-export-hero: ${message}\n`);
  process.exit(1);
};

let raw;
try {
  raw = execFileSync(
    process.execPath,
    [join(REPO_ROOT, 'apps', 'cli', 'dist', 'index.js'), join(REPO_ROOT, SOURCE_FILE), '--format', 'json'],
    { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
} catch (error) {
  // The CLI exits non-zero when it finds something at or above the severity
  // gate, which for a deliberately vulnerable fixture is the expected outcome.
  // Its stdout is still the report, so a non-zero exit is only fatal when it
  // produced nothing to read.
  raw = error?.stdout ?? '';
  if (!raw.trim()) {
    fail(`the scanner produced no output for ${SOURCE_FILE}: ${error?.message ?? 'unknown error'}`);
  }
}

let report;
try {
  report = JSON.parse(raw);
} catch {
  fail(`the scanner's --format json output for ${SOURCE_FILE} did not parse as JSON`);
}

const findings = Array.isArray(report) ? report : (report.findings ?? []);
const match = findings.find((f) => f.ruleId === RULE_ID);

if (!match) {
  // Not a warning. If the rule that the front page is built around stops firing
  // on the fixture it was chosen for, the honest outcome is a failed build —
  // the alternative is a front page quietly showing a different finding under a
  // caption written for this one.
  fail(
    `${RULE_ID} did not fire on ${SOURCE_FILE}. The front page leads with this finding, so ` +
      `the build stops rather than substituting another one. Either the rule changed, or the ` +
      `fixture did; decide which, and update this generator in the same commit.\n` +
      `  rules that did fire: ${[...new Set(findings.map((f) => f.ruleId))].join(', ') || '(none)'}`,
  );
}

const hero = { sourceFile: SOURCE_FILE };
for (const key of KEEP) {
  if (match[key] !== undefined) hero[key] = match[key];
}

/**
 * Two normalisations, and neither is cosmetic.
 *
 * `filePath` comes back as whatever path the scanner was handed, which for a
 * single-file scan is absolute: C:\Users\<name>\VibeGuard\samples\... The hero
 * prints it after `at`, so passing it through would publish the author's home
 * directory — and their account name — on the front page of the site. The
 * repository already refuses that shape anywhere in the tracked tree
 * (scripts/check-disclosure-shape.mjs, HOME-DIRECTORY), on the grounds that an
 * account name is a real identifier that no word list can anticipate. The CLI's
 * own human output prints the basename here, so the basename is also what the
 * hero should show: it is what a reader would see running the tool themselves.
 *
 * CRLF is stripped because the fixture is checked out with Windows line endings
 * on this machine and Unix ones in CI. Left in, the same source file produces a
 * different hero.json on each, and every deploy from the other platform carries
 * a diff that means nothing.
 */
hero.filePath = String(hero.filePath).split(/[\\/]/).pop();
const stripCr = (s) => String(s).replace(/\r/g, '');
if (hero.snippet) hero.snippet = stripCr(hero.snippet);
if (Array.isArray(hero.evidence)) hero.evidence = hero.evidence.map(stripCr);

if (/[\\/][Uu]sers[\\/]|\/[Hh]ome\//.test(JSON.stringify(hero))) {
  fail('an absolute home-directory path survived normalisation and would be published on the front page');
}

if (!hero.remediation?.why || !hero.remediation?.how) {
  fail(`${RULE_ID} came back without a remediation; the hero renders "why:" and "fix:" from it`);
}

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(hero, null, 2) + '\n');

process.stdout.write(
  `site-export-hero: ${hero.severity.toUpperCase()} ${hero.ruleId} "${hero.title}" ` +
    `from ${SOURCE_FILE} -> site/src/data/hero.json\n`,
);
