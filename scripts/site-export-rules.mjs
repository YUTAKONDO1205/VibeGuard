// site-export-rules — the rule set, as the site is allowed to describe it.
//
// WHY THIS EXISTS
//
// `/rules` is a table of every rule, and the front page puts a count under each
// of eight circles. Both of those are facts about `packages/rules`, and both of
// them change whenever someone adds a rule. Written by hand, they would be
// correct for exactly as long as it takes to merge the next detector — and the
// site would not look wrong while it was wrong, which is the part that matters.
// So the site never writes a rule fact down: it reads this file's output.
//
// The same argument applies, harder, to the auto-fix badge. Seven of the
// seventy-four rules have a fixer and exactly one of those is labelled `safe`.
// Those two numbers are the ones a reader will hold the product to, and they are
// the ones a marketing sentence is most tempted to round up. They are derived
// here from the keys of the real `fixers` registry, so the page can only ever
// claim what the registry actually contains.
//
// ── WHY THE GROUPING LIVES ON THE SITE SIDE ────────────────────────────────
//
// The rule IDs carry eleven family prefixes; the front page shows eight
// circles. The mapping between them is an editorial decision about how to
// explain the product to someone who has never run it, not a property of the
// rules, so it lives in `site/src/shared/taxonomy.ts` next to the labels and
// the one-line blurbs that go with it.
//
// This generator READS that file rather than restating the mapping in JS. A
// second copy of `INJ -> injection` would be a second thing to edit, and the
// half that nobody edited would be the half that decides the counts. Parsing
// TypeScript with a regex is normally a bad idea; it is the right trade here
// because the alternative is a duplicated constant, the file being parsed is a
// small literal in this repository, and a parse that stops matching the file
// fails the build loudly (see the assertions below) instead of quietly
// producing the wrong grouping.
//
// ── THE ASSERTIONS ─────────────────────────────────────────────────────────
//
// All of them exit non-zero. None of them warn. A warning in a build log is a
// message to nobody.
//
//   A. Every ID prefix present in `allRules` maps to a bucket. A new family —
//      `VG-NET-*`, say — stops the build until somebody decides which circle it
//      belongs in. Without this, the site would quietly go on describing the
//      product it described last year, minus a category, and the omission would
//      be invisible: eight circles is eight circles either way.
//   B. The bucket counts sum to `allRules.length`. Catches the other direction —
//      a mapping edit that double-counts a family or drops one.
//   C. No bucket ends up empty. An empty circle advertises a category the
//      product no longer detects, which is the same lie as A with the sign
//      flipped.
//   D. Every key of the `fixers` registry is a real rule ID. A fixer left behind
//      by a deleted rule would otherwise inflate the auto-fix count with a badge
//      that can never appear next to anything.
//
//   node scripts/site-export-rules.mjs
//
// Exit 0 when rules.json was written, 1 with the failing invariant named.
import { readFileSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_FILE = join(REPO_ROOT, 'site', 'src', 'data', 'rules.json');
const TAXONOMY_FILE = join(REPO_ROOT, 'site', 'src', 'shared', 'taxonomy.ts');

function die(message) {
  process.stderr.write(`site-export-rules: ${message}\n`);
  process.exit(1);
}

/**
 * Import a built package, or explain how to build it.
 *
 * The site is deliberately built from `dist`, not from the TypeScript sources:
 * it must see the same array the CLI and the extensions see, and the only way
 * to be sure of that is to load the artefact they load. The cost is that a
 * fresh clone has to build three packages first, so a missing `dist` prints the
 * exact command instead of a module-resolution stack trace.
 */
async function importBuilt(relPath, buildCommand) {
  const abs = join(REPO_ROOT, relPath);
  if (!existsSync(abs)) {
    die(`${relPath} does not exist. Build it first:\n    ${buildCommand}`);
  }
  try {
    return await import(pathToFileURL(abs).href);
  } catch (error) {
    die(`${relPath} could not be imported: ${error.message}`);
  }
}

/**
 * The eight buckets, read out of taxonomy.ts.
 *
 * Only `id` and `families` are taken. The label and the blurb are read by the
 * pages directly from the TypeScript, where an editor can see them next to each
 * other; copying them through JSON would put the site's prose in a generated
 * file, which is the one place nobody thinks to proofread.
 *
 * The two field lists are collected separately and then zipped, rather than
 * matched with one expression spanning a whole object literal. A single
 * spanning regex silently swallows the NEXT object when a field it expects is
 * missing, and "silently produces a plausible wrong answer" is the failure mode
 * this entire file exists to prevent. Zipping makes a missing field a length
 * mismatch, which is loud.
 */
function readBuckets() {
  let source;
  try {
    source = readFileSync(TAXONOMY_FILE, 'utf8');
  } catch (error) {
    die(`cannot read site/src/shared/taxonomy.ts: ${error.message}`);
  }

  const ids = [...source.matchAll(/^\s*id:\s*'([a-z0-9-]+)',/gm)];
  const familyLists = [...source.matchAll(/^\s*families:\s*\[([^\]]*)\],/gm)];

  if (ids.length !== familyLists.length) {
    die(
      `taxonomy.ts has ${ids.length} bucket ids but ${familyLists.length} family lists. ` +
        'Every bucket must declare both; this generator cannot guess which family list ' +
        'belongs to which bucket.',
    );
  }
  if (ids.length !== 8) {
    die(
      `taxonomy.ts declares ${ids.length} buckets. The front page is a 4x2 grid of eight ` +
        'circles (site design chapter 2.5). Changing the count is a layout decision, not ' +
        'a data one, so it has to be made in the page as well as in taxonomy.ts.',
    );
  }

  const buckets = [];
  for (let i = 0; i < ids.length; i++) {
    // Interleaving check: bucket i's family list must sit between bucket i's id
    // and bucket i+1's id. If it does not, the file has been reordered into a
    // shape this parser reads wrongly, and the counts it produces would be
    // attached to the wrong circles.
    const idAt = ids[i].index;
    const familiesAt = familyLists[i].index;
    const nextIdAt = i + 1 < ids.length ? ids[i + 1].index : Number.MAX_SAFE_INTEGER;
    if (!(idAt < familiesAt && familiesAt < nextIdAt)) {
      die(
        `taxonomy.ts bucket '${ids[i][1]}' does not have its families list between its own ` +
          'id and the next bucket\'s id. Keep one bucket per object literal, in the order ' +
          'id / label / blurb / families.',
      );
    }

    const families = [...familyLists[i][1].matchAll(/'([A-Z]+)'/g)].map((m) => m[1]);
    if (families.length === 0) {
      die(`taxonomy.ts bucket '${ids[i][1]}' claims no ID families, so no rule can land in it.`);
    }
    buckets.push({ id: ids[i][1], families });
  }
  return buckets;
}

const { allRules } = await importBuilt(
  'packages/rules/dist/index.js',
  'npm run build -w @vibeguard/findings-schema && npm run build -w @vibeguard/rules',
);
const { fixers } = await importBuilt(
  'packages/remediation-engine/dist/index.js',
  'npm run build -w @vibeguard/remediation-engine',
);

if (!Array.isArray(allRules) || allRules.length === 0) {
  die('@vibeguard/rules exported no `allRules` array. Nothing here can be generated without it.');
}
if (!fixers || typeof fixers !== 'object') {
  die('@vibeguard/remediation-engine exported no `fixers` registry.');
}

const buckets = readBuckets();

/** `VG-INJ-004` -> `INJ`. Kept identical to `familyOf` in taxonomy.ts. */
function familyOf(ruleId) {
  const m = /^VG-([A-Z]+)-\d+$/.exec(ruleId);
  return m ? m[1] : null;
}

const familyToBucket = new Map();
for (const bucket of buckets) {
  for (const family of bucket.families) {
    if (familyToBucket.has(family)) {
      die(
        `taxonomy.ts gives family ${family} to two buckets ('${familyToBucket.get(family)}' and ` +
          `'${bucket.id}'). A rule would be counted twice and shown twice.`,
      );
    }
    familyToBucket.set(family, bucket.id);
  }
}

// Duplicate IDs would make assertion B pass while the page showed a rule twice,
// so they are ruled out before anything is counted.
const seen = new Set();
for (const rule of allRules) {
  if (seen.has(rule.ruleId)) die(`allRules contains ${rule.ruleId} more than once.`);
  seen.add(rule.ruleId);
}

// ── Assertion A: every prefix maps somewhere ───────────────────────────────
const unmapped = new Map();
for (const rule of allRules) {
  const family = familyOf(rule.ruleId);
  if (family === null) {
    die(
      `rule id ${JSON.stringify(rule.ruleId)} is not in the VG-<FAMILY>-<number> shape that the ` +
        'site groups by. Either the id is wrong or the grouping needs a new rule.',
    );
  }
  if (!familyToBucket.has(family)) {
    if (!unmapped.has(family)) unmapped.set(family, []);
    unmapped.get(family).push(rule.ruleId);
  }
}
if (unmapped.size > 0) {
  const detail = [...unmapped.entries()]
    .map(([family, ids]) => `  VG-${family}-* (${ids.length} rule(s), e.g. ${ids[0]})`)
    .join('\n');
  die(
    'these ID families are in allRules but belong to no bucket in ' +
      `site/src/shared/taxonomy.ts:\n${detail}\n` +
      'Decide which of the eight circles each one belongs under and add the family there. ' +
      'The build stops here on purpose: an unmapped family would be dropped from the site ' +
      'silently, and the page would look exactly as complete as it does today.',
  );
}

// ── Group ──────────────────────────────────────────────────────────────────
const safetyOf = new Map();
for (const [ruleId, fixer] of Object.entries(fixers)) {
  // Assertion D. A fixer whose rule no longer exists inflates the auto-fix
  // count with a badge that can never be shown next to anything.
  if (!seen.has(ruleId)) {
    die(
      `the fixers registry has an entry for ${ruleId}, which is not in allRules. Either the ` +
        'rule was removed and its fixer was not, or the id is misspelled in one of the two.',
    );
  }
  safetyOf.set(ruleId, fixer);
}

function exportRule(rule) {
  const fixer = safetyOf.get(rule.ruleId) ?? null;
  return {
    ruleId: rule.ruleId,
    name: rule.name,
    severity: rule.severity,
    // `languages` and `cwe` are arrays on every rule inspected, but a rule
    // without a CWE is a legitimate thing (the AI-leftover family has several),
    // so the page must be handed an empty array rather than `undefined` — the
    // difference between "no CWE" and "field missing" is invisible in a
    // template and shows up as `undefined` in the rendered HTML.
    languages: [...(rule.languages ?? [])],
    cwe: [...(rule.cwe ?? [])],
    hasFixer: fixer !== null,
    fixerSafety: fixer ? fixer.safety : null,
    fixerTitle: fixer ? fixer.title : null,
  };
}

const byId = (a, b) => (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0);

const exported = buckets.map((bucket) => {
  const rules = allRules
    .filter((rule) => bucket.families.includes(familyOf(rule.ruleId)))
    .map(exportRule)
    .sort(byId);
  return { id: bucket.id, families: [...bucket.families], count: rules.length, rules };
});

// ── Assertion C: no empty circle ───────────────────────────────────────────
const empty = exported.filter((bucket) => bucket.count === 0);
if (empty.length > 0) {
  die(
    `these buckets matched no rules: ${empty.map((b) => b.id).join(', ')}. The front page would ` +
      'show a circle with a count of zero, which advertises a category the product does not ' +
      'detect. Remove the bucket from taxonomy.ts, or restore the rules it names.',
  );
}

// ── Assertion B: the parts add up to the whole ─────────────────────────────
const summed = exported.reduce((total, bucket) => total + bucket.count, 0);
if (summed !== allRules.length) {
  die(
    `the eight buckets account for ${summed} rules but allRules has ${allRules.length}. ` +
      'A rule is being counted twice or not at all.',
  );
}

// ── The rules that reason across files ─────────────────────────────────────
//
// `allRules` is every rule that judges one file on its own. It is not every
// rule the product ships. @vibeguard/analysis-graph carries a second set that
// reasons over the whole tree — authorization spread across a dozen handlers, a
// generated validator nothing calls — and the CLI and the GitHub Action run
// them behind --include-design-smells. They are deliberately absent from the
// two extensions, which is a packaging invariant rather than an oversight.
//
// Leaving them out of this file is what made /rules say "every rule VibeGuard
// ships" over a list of 74 when 85 ship. The honest options were to narrow the
// sentence or to list them; listing them is better, because a reader who hits
// VG-RTOS-003 in CI output should be able to look it up.
//
// They are kept in their own array rather than folded into the eight buckets on
// purpose. The buckets carry the counts under the front page's circles, and
// those circles describe what runs everywhere; quietly adding CLI-only rules to
// them would inflate a number shown to someone about to install a VS Code
// extension that does not run them.
let crossFileRules = [];
try {
  ({ crossFileRules = [] } = await import('@vibeguard/analysis-graph'));
} catch (error) {
  die(
    'could not load @vibeguard/analysis-graph to read crossFileRules: ' +
      `${error?.message ?? error}\n` +
      '  /rules claims to list every rule that ships, and the cross-file set is part of that\n' +
      '  claim. Build it first: npm run build -w @vibeguard/analysis-graph',
  );
}

if (crossFileRules.length === 0) {
  // Same reasoning as every other vacuity guard here: an empty list would
  // render a section with a heading, a paragraph of prose and nothing under it,
  // which reads as "there are none" rather than as "these did not load".
  die('@vibeguard/analysis-graph exported an empty crossFileRules array; /rules would silently list none');
}

const exportedCrossFile = crossFileRules
  .map((rule) => ({
    ...exportRule(rule),
    // Stated per rule rather than only in the section's prose, because these
    // get linked to individually and a reader arriving at #vg-rtos-003 from a
    // CI log never reads the section header above it.
    availability: 'CLI and GitHub Action only, with --include-design-smells',
  }))
  .sort(byId);

const fixerEntries = Object.values(fixers);
const payload = {
  totals: {
    rules: allRules.length,
    crossFileRules: exportedCrossFile.length,
    shipped: allRules.length + exportedCrossFile.length,
    fixers: fixerEntries.length,
    safeFixers: fixerEntries.filter((f) => f.safety === 'safe').length,
    needsReviewFixers: fixerEntries.filter((f) => f.safety === 'needs-review').length,
  },
  buckets: exported,
  crossFile: exportedCrossFile,
};

mkdirSync(dirname(OUT_FILE), { recursive: true });
writeFileSync(OUT_FILE, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

process.stdout.write(
  `site-export-rules: ${payload.totals.rules} rules in ${exported.length} buckets ` +
    `(${exported.map((b) => `${b.id}=${b.count}`).join(' ')}), ` +
    `${payload.totals.fixers} fixers of which ${payload.totals.safeFixers} safe ` +
    '-> site/src/data/rules.json\n',
);
