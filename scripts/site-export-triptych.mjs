// site-export-triptych — the three Before / finding / After cards, produced by
// running the product rather than by describing it.
//
// WHY THIS EXISTS
//
// The front page's middle band shows three cards, each with a piece of code, the
// finding VibeGuard reports on it, and what `--fix` does to it. That is the one
// part of the site that makes a falsifiable claim about behaviour, so none of it
// is typed: every string this file emits was either read out of a file in this
// repository or printed by `apps/cli/dist/index.js` a moment earlier.
//
// The rule that forces this (site design 3.0.4) exists because hand-formatted
// tool output does not decay visibly. When the CLI's layout changes — a column
// moves, `why:` stops wrapping, a confidence label appears — regenerated output
// follows it and hand-written output becomes a picture of a program that no
// longer exists, indistinguishable from a screenshot of the real thing.
//
// ── WHY site/demo/ EXISTS AT ALL ───────────────────────────────────────────
//
// The natural source for the cards is `samples/`, and it cannot be used
// directly. Every vulnerable line in there is annotated with the rule it is
// supposed to trip:
//
//     #define BYPASS_AUTH 1              // VG-EMB-021: auth bypass flag
//     http.begin("http://api.example.com/telemetry"); // VG-EMB-010: cleartext HTTP
//
// That is correct for a regression fixture and fatal for a demonstration: a
// reader sees a scanner finding the answer that was written next to the
// question. So the fixtures are copied into `site/demo/` with those trailing
// annotations removed and NOTHING ELSE CHANGED. Every retained line is a byte
// prefix of the line it came from, and that is asserted below rather than
// trusted — because the moment the code differs from `samples/`, the CI job
// that proves "this shape is detected" stops covering what the site shows.
//
// The copies are generated and git-ignored for the same reason the data files
// are: a checked-in copy would be a second place for the fixture to live, and
// the two would drift apart in the direction nobody is looking.
//
// ── WHY THE OUTPUT IS SCRUBBED OF TIME ─────────────────────────────────────
//
// The CLI's JSON carries `executionTimeMs`, `generatedAt`, and a per-finding
// `findingId` derived from the clock. Serialising any of them would make every
// single build produce a different `triptych.json`, which trains everyone to
// ignore the diff — and the diff is the only thing that would show a real
// change in what the scanner says. The sanitiser below is therefore a
// whitelist: a timing field added to the CLI tomorrow is dropped by default
// instead of quietly reintroducing the churn.
//
//   node scripts/site-export-triptych.mjs
//
// Exit 0 when triptych.json and site/demo/ were written, 1 with the reason
// otherwise.
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, basename } from 'node:path';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CLI = join(REPO_ROOT, 'apps', 'cli', 'dist', 'index.js');
const DEMO_DIR = join(REPO_ROOT, 'site', 'demo');
const OUT_FILE = join(REPO_ROOT, 'site', 'src', 'data', 'triptych.json');

/**
 * The three subjects, fixed by the site design (3.1.4).
 *
 * One card per audience: the JavaScript one is for the largest group of
 * readers, and the two embedded ones are the part of the product nothing else
 * on the market is doing. Each names the rule it is about; the source file is
 * verified at runtime to actually produce that rule, so a fixture that gets
 * rewritten cannot silently turn a card into a card about something else.
 */
const CARDS = [
  { ruleId: 'VG-INJ-020', source: 'samples/proto-pollution/proto_merge.js' },
  { ruleId: 'VG-EMB-010', source: 'samples/embedded/vulnerable/net_insecure.ino' },
  { ruleId: 'VG-EMB-021', source: 'samples/embedded/vulnerable/debug_remnants.ino' },
];

function die(message) {
  process.stderr.write(`site-export-triptych: ${message}\n`);
  process.exit(1);
}

// ── Reading the fixture ────────────────────────────────────────────────────

/**
 * Index of the `//` that opens the line comment, ignoring `//` inside string
 * literals.
 *
 * Needed for exactly one line in the corpus, and it is the line the whole card
 * is about:
 *
 *     http.begin("http://api.example.com/telemetry"); // VG-EMB-010: cleartext HTTP
 *
 * A naive `indexOf('//')` finds the one in the URL and truncates the vulnerable
 * code itself, which would produce a demo file that does not compile, does not
 * trip the rule, and looks fine in a diff.
 */
function commentStart(line) {
  let quote = null;
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote !== null) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (c === '/' && line[i + 1] === '/') return i;
  }
  return -1;
}

/** `// VG-EMB-021: auth bypass flag` — the annotation form, and only that form. */
const ANNOTATION = /^\/\/\s*VG-[A-Z]+-\d+\s*:/;

/**
 * A line with its rule-naming annotation removed, or null if the whole line was
 * one.
 *
 * The search is for the LAST annotation on the line, not the first comment,
 * because of this fixture line:
 *
 *     // TODO: remove before production // VG-EMB-023: removal reminder
 *
 * The TODO is not decoration — it is the thing VG-EMB-023 detects. Cutting at
 * the first `//` would delete the finding along with the label for it.
 */
function stripAnnotation(line) {
  const start = commentStart(line);
  if (start < 0) return line;

  let cut = -1;
  for (let i = start; i < line.length - 1; i++) {
    if (line[i] === '/' && line[i + 1] === '/' && ANNOTATION.test(line.slice(i))) cut = i;
  }
  if (cut < 0) return line;

  const kept = line.slice(0, cut).replace(/\s+$/, '');
  // A line that was nothing but an annotation leaves an empty line behind. That
  // is a blank line the fixture author never wrote, so the line goes instead.
  return kept === '' ? null : kept;
}

/** Whitespace, or a comment and nothing else. */
function isCommentOrBlank(line) {
  const trimmed = line.trim();
  return trimmed === '' || trimmed.startsWith('//');
}

/**
 * The fixture, ready to show a stranger.
 *
 * Two things come off: the trailing annotations, and the banner comment at the
 * top of the file (`// Intentionally vulnerable — VG-EMB debug-remnant family`).
 * The banner is removed for the same reason as the annotations — it announces
 * the answer — and only when it actually names a rule family, so an ordinary
 * leading comment in some future fixture survives.
 *
 * Line endings are preserved as found. The fixtures are a mix of LF and CRLF;
 * rewriting them would make every line differ from `samples/` and defeat the
 * byte-identity check that follows.
 */
function toDemoSource(original) {
  const eol = original.includes('\r\n') ? '\r\n' : '\n';
  const trailingNewline = /\r?\n$/.test(original);
  const lines = original.replace(/\r?\n$/, '').split(/\r?\n/);

  let firstCode = 0;
  while (firstCode < lines.length && lines[firstCode].trimStart().startsWith('//')) firstCode++;
  const banner = lines.slice(0, firstCode);
  const bannerNamesARule = banner.some((line) => /VG-[A-Z]+/.test(line));

  let body = bannerNamesARule ? lines.slice(firstCode) : lines;
  // A banner is usually followed by a blank line separating it from the code.
  // Dropping the banner and keeping the blank line would start the file with an
  // empty line, which reads as a formatting mistake in a code card.
  if (bannerNamesARule) while (body.length > 0 && body[0].trim() === '') body = body.slice(1);

  const stripped = body.map(stripAnnotation).filter((line) => line !== null);
  return stripped.join(eol) + (trailingNewline ? eol : '');
}

/**
 * Prove the demo file is the fixture minus comments.
 *
 * This is the assertion the whole `site/demo/` arrangement rests on. If the
 * code differs from `samples/` in any way, then the CI job that scans `samples/`
 * on every push is no longer evidence about the code on the front page — and
 * the site would be showing an unreviewed snippet with a detection result
 * attached to it.
 *
 * The check walks both files in order: every demo line must be a byte prefix of
 * some source line whose remainder is a comment, and every source line skipped
 * along the way must have been a comment or blank.
 */
function assertOnlyCommentsRemoved(sourcePath, original, demo) {
  const src = original.replace(/\r?\n$/, '').split(/\r?\n/);
  const out = demo.replace(/\r?\n$/, '').split(/\r?\n/);

  const isPrefixWithCommentRemainder = (s, o) =>
    s === o || (s.startsWith(o) && s.slice(o.length).trimStart().startsWith('//'));

  let si = 0;
  for (const line of out) {
    while (si < src.length && !isPrefixWithCommentRemainder(src[si], line)) {
      if (!isCommentOrBlank(src[si])) {
        die(
          `stripping ${sourcePath} dropped a line that is not a comment:\n    ${src[si]}\n` +
            'The demo copy must differ from the fixture only by removed comments.',
        );
      }
      si++;
    }
    if (si >= src.length) {
      die(
        `stripping ${sourcePath} produced a line with no counterpart in the fixture:\n    ${line}`,
      );
    }
    si++;
  }
  for (; si < src.length; si++) {
    if (!isCommentOrBlank(src[si])) {
      die(`stripping ${sourcePath} lost a code line at the end of the file:\n    ${src[si]}`);
    }
  }
}

// ── Running the product ────────────────────────────────────────────────────

// Written as an escape rather than a literal control byte in the source: an
// editor or a copy-paste that swallows the ESC would leave a regex matching
// `[0m` in ordinary code, and that corruption is invisible in review.
const ANSI = /\u001B\[[0-9;]*m/g;

/**
 * Run the CLI and return its stdout.
 *
 * `--fail-on never` is not cosmetic. The default exit code is non-zero when a
 * high-severity finding is present, which is exactly what every one of these
 * fixtures produces, so without it the generator could not tell "the scan found
 * the vulnerability it was supposed to" from "the CLI crashed".
 *
 * `--no-config` keeps the output reproducible: config auto-discovery walks the
 * scan target, and a `.vibeguardrc.json` left in a working tree would change
 * what the published cards say without changing anything this file reads.
 */
function runCli(args, cwd) {
  const result = spawnSync(
    process.execPath,
    [CLI, ...args, '--fail-on', 'never', '--no-config', '--no-color'],
    { cwd, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 },
  );
  if (result.error) die(`could not run the CLI: ${result.error.message}`);
  if (result.status !== 0) {
    die(
      `the CLI exited ${result.status} for \`${args.join(' ')}\` in ${cwd}.\n` +
        `stderr:\n${result.stderr}`,
    );
  }
  return result.stdout.replace(ANSI, '');
}

/** Scan one file and parse the JSON report the CLI wrote. */
function scanJson(file, cwd, scratch) {
  const out = join(scratch, `${basename(file)}.report.json`);
  runCli([file, '--format', 'json', '--out', out], cwd);
  try {
    return JSON.parse(readFileSync(out, 'utf8'));
  } catch (error) {
    die(`the CLI's JSON report for ${file} could not be parsed: ${error.message}`);
  }
}

/**
 * A finding with everything non-deterministic taken out.
 *
 * A whitelist, not a blacklist. `findingId` is minted from the clock
 * (`vg-msvkmayh-l`), `executionTimeMs` and `generatedAt` live on the report
 * around it, and the next field of that kind is unknown by definition — so the
 * default for an unrecognised field is "not published" rather than "published
 * until someone notices the daily diff".
 *
 * Trailing carriage returns are removed from the quoted text because the two
 * `.ino` fixtures are CRLF, and the CLI quotes the raw line: an unstripped
 * `\r` would sit inside a JSON string and land in the rendered HTML.
 */
function sanitiseFinding(finding) {
  const text = (value) => (typeof value === 'string' ? value.replace(/\r$/, '') : value);
  return {
    ruleId: finding.ruleId,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    confidence: finding.confidence,
    category: finding.category,
    language: finding.language,
    filePath: finding.filePath,
    startLine: finding.startLine,
    endLine: finding.endLine,
    startColumn: finding.startColumn,
    endColumn: finding.endColumn,
    snippet: text(finding.snippet),
    evidence: (finding.evidence ?? []).map(text),
    remediation: finding.remediation
      ? {
          why: finding.remediation.why,
          how: finding.remediation.how,
          exampleFix: finding.remediation.exampleFix ?? null,
          references: [...(finding.remediation.references ?? [])],
        }
      : null,
    tags: [...(finding.tags ?? [])],
  };
}

/** `HIGH  Prototype-polluting merge  [VG-INJ-020] (confidence: medium)` */
const HUMAN_HEADER = /^(CRITICAL|HIGH|MEDIUM|LOW|INFO) {2}(.+?) {2}\[(VG-[A-Z]+-\d+)\]/;

/**
 * The human-format report, split into one verbatim block per finding.
 *
 * The site shows the CLI's own rendering, wrapping and all, so the block is
 * captured rather than rebuilt from the JSON. Blocks are recognised by their
 * header line and continue for as long as the following lines are indented,
 * which is what separates them from the `Summary` trailer — the one part of the
 * human output that does contain a timing (`elapsed: 18ms`) and therefore the
 * one part that must never reach the page.
 */
function humanBlocks(output) {
  const lines = output.split(/\r?\n/).map((line) => line.replace(/\s+$/, ''));
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const header = HUMAN_HEADER.exec(lines[i]);
    if (!header) continue;
    const block = [lines[i]];
    let j = i + 1;
    while (j < lines.length && lines[j].startsWith('  ')) block.push(lines[j++]);
    const at = /^ {2}at .+?:(\d+):(\d+)$/.exec(block[1] ?? '');
    blocks.push({
      ruleId: header[3],
      line: at ? Number(at[1]) : -1,
      column: at ? Number(at[2]) : -1,
      text: block.join('\n'),
    });
    i = j - 1;
  }
  return blocks;
}

/** `    L4  [needs-review]  VG-INJ-020  Skip prototype keys in the merge loop` */
const APPLIED_FIX = /^ {4}L(\d+) {2}\[([a-z-]+)\] +(VG-[A-Z]+-\d+) {2}(.+)$/;

// ── Build the cards ────────────────────────────────────────────────────────

if (!existsSync(CLI)) {
  die(
    'apps/cli/dist/index.js does not exist. The cards are produced by running the real CLI, ' +
      'so it has to be built first:\n    npm run build -w @vibeguard/cli',
  );
}

const { fixers } = await import(
  pathToFileURL(join(REPO_ROOT, 'packages', 'remediation-engine', 'dist', 'index.js')).href
).catch((error) =>
  die(
    `packages/remediation-engine/dist could not be imported (${error.message}). Build it first:` +
      '\n    npm run build -w @vibeguard/remediation-engine',
  ),
);

mkdirSync(DEMO_DIR, { recursive: true });
const scratchRoot = mkdtempSync(join(tmpdir(), 'vibeguard-triptych-'));

const cards = [];
const engineVersionsSeen = new Set();

try {
  for (const card of CARDS) {
    // The card promises an "After". Only a rule with a fixer can honestly show
    // one, so the promise is checked against the registry before any work is
    // done rather than discovered halfway through as a missing diff.
    const fixer = fixers[card.ruleId];
    if (!fixer) {
      die(
        `card ${card.ruleId} has no entry in the fixers registry, so there is no honest "After" ` +
          'to show for it. Pick a rule that has a fixer, or drop the card.',
      );
    }

    const sourceAbs = join(REPO_ROOT, card.source);
    if (!existsSync(sourceAbs)) die(`${card.source} does not exist.`);
    const original = readFileSync(sourceAbs, 'utf8');

    const demoName = basename(card.source);
    const demoAbs = join(DEMO_DIR, demoName);
    const demoSource = toDemoSource(original);
    assertOnlyCommentsRemoved(card.source, original, demoSource);
    writeFileSync(demoAbs, demoSource, 'utf8');

    // Scanning the fixture as well as the copy, and comparing what came back,
    // is what turns "we only removed comments" from a claim about text into a
    // claim about behaviour. If removing a comment changed what the scanner
    // says — a rule that matches inside comments, a line-number-sensitive
    // check — the card would be demonstrating something `samples/` does not
    // cover, and the build stops instead.
    const fixtureReport = scanJson(card.source, REPO_ROOT, scratchRoot);
    const demoReport = scanJson(demoName, DEMO_DIR, scratchRoot);
    const idsOf = (report) => report.findings.map((f) => f.ruleId).sort().join(', ');
    if (idsOf(fixtureReport) !== idsOf(demoReport)) {
      die(
        `stripping the annotations changed what is detected in ${card.source}.\n` +
          `  fixture: ${idsOf(fixtureReport)}\n  demo:    ${idsOf(demoReport)}`,
      );
    }
    if (demoReport.engineVersions) engineVersionsSeen.add(JSON.stringify(demoReport.engineVersions));

    const matching = demoReport.findings.filter((f) => f.ruleId === card.ruleId);
    if (matching.length === 0) {
      die(
        `${card.source} does not produce ${card.ruleId}. It reports ` +
          `${idsOf(demoReport) || 'nothing'}. The card and the fixture have come apart.`,
      );
    }
    // Lowest line first: for the prototype-pollution fixture this picks the
    // merge loop over the direct `__proto__` write further down, and the merge
    // loop is the one the fixer can repair — which is what the card is about.
    matching.sort((a, b) => a.startLine - b.startLine);
    const primary = matching[0];

    // The human rendering of that same finding, verbatim.
    const blocks = humanBlocks(runCli([demoName], DEMO_DIR));
    const block = blocks.filter(
      (b) => b.ruleId === card.ruleId && b.line === primary.startLine && b.column === primary.startColumn,
    );
    if (block.length !== 1) {
      die(
        `expected exactly one human-output block for ${card.ruleId} at ${demoName}:` +
          `${primary.startLine}:${primary.startColumn}, found ${block.length}. The CLI's human ` +
          'format has changed shape and the parser here has to be updated with it.',
      );
    }

    // `--fix` writes to disk, so it runs against a throwaway copy holding this
    // card's file and nothing else. One file per run is what makes the fix
    // report quotable: run over a directory, the report interleaves files and
    // the counts in it belong to the batch rather than to the card.
    const fixDir = mkdtempSync(join(scratchRoot, 'fix-'));
    writeFileSync(join(fixDir, demoName), demoSource, 'utf8');
    // Trailing whitespace goes, and so do carriage returns. The two .ino
    // fixtures are checked out with CRLF on Windows and LF in CI, and the fix
    // report quotes their lines back — so without this the same commit produces
    // a different triptych.json depending on which machine built it. That is
    // invisible here (the file is generated, never committed) and would surface
    // as stray control characters inside the rendered card, or as two deploys
    // of one commit disagreeing about their own bytes.
    const fixReport = runCli([demoName, '--fix'], fixDir)
      .replace(new RegExp(String.fromCharCode(13), 'g'), '')
      .replace(/\s+$/, '');
    const after = readFileSync(join(fixDir, demoName), 'utf8');

    if (after === demoSource) {
      die(
        `--fix changed nothing in ${demoName}, so the card's "After" would be identical to its ` +
          `"Before". ${card.ruleId} has a fixer registered; it declined to apply here.`,
      );
    }

    const applied = fixReport
      .split(/\r?\n/)
      .map((line) => APPLIED_FIX.exec(line))
      .filter(Boolean)
      .map((m) => ({ line: Number(m[1]), safety: m[2], ruleId: m[3], title: m[4] }));
    const appliedHere = applied.find((fix) => fix.ruleId === card.ruleId);
    if (!appliedHere) {
      die(
        `--fix on ${demoName} applied ${applied.length} fix(es), none of them for ${card.ruleId}. ` +
          'The card would show an "After" produced by a different rule.',
      );
    }
    // The registry and the CLI both label the edit; if they disagree, the badge
    // on the page and the label in the quoted output would contradict each
    // other on the same card.
    if (appliedHere.safety !== fixer.safety) {
      die(
        `the fixers registry labels ${card.ruleId} '${fixer.safety}' but the CLI printed ` +
          `'${appliedHere.safety}'.`,
      );
    }

    // What the fixer refused to touch. This is the honest half of the card and
    // the reason the band exists: a fix that cannot prove its edit is right
    // leaves the finding standing, and the page can only say so if it is handed
    // the surviving findings rather than a sentence about them.
    const afterReport = scanJson(demoName, fixDir, scratchRoot);

    cards.push({
      ruleId: card.ruleId,
      language: primary.language,
      severity: primary.severity,
      demoFile: demoName,
      sourceFile: card.source,
      fixer: { title: fixer.title, safety: fixer.safety },
      before: {
        // Normalised to LF for display only. The file on disk keeps the
        // fixture's own line endings, which is what the byte-identity check
        // above is about.
        code: demoSource.replace(/\r\n/g, '\n').replace(/\n$/, ''),
        focusLine: primary.startLine,
      },
      finding: sanitiseFinding(primary),
      findingText: block[0].text,
      allFindings: demoReport.findings.map(sanitiseFinding),
      fixReport,
      appliedFixes: applied,
      after: {
        code: after.replace(/\r\n/g, '\n').replace(/\n$/, ''),
      },
      remainingFindings: afterReport.findings.map(sanitiseFinding),
    });
  }
} finally {
  rmSync(scratchRoot, { recursive: true, force: true });
}

if (engineVersionsSeen.size !== 1) {
  die(
    `the three scans reported ${engineVersionsSeen.size} different engine versions. They are one ` +
      'CLI invoked three times; this cannot happen without something being rebuilt mid-run.',
  );
}

const payload = {
  engineVersions: JSON.parse([...engineVersionsSeen][0]),
  cards,
};

mkdirSync(dirname(OUT_FILE), { recursive: true });
writeFileSync(OUT_FILE, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

process.stdout.write(
  `site-export-triptych: ${cards.length} cards (` +
    cards
      .map(
        (c) =>
          `${c.ruleId} ${c.appliedFixes.length} fix/${c.remainingFindings.length} left`,
      )
      .join(', ') +
    ') -> site/src/data/triptych.json, site/demo/\n',
);
