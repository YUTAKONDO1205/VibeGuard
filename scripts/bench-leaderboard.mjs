#!/usr/bin/env node
// bench-leaderboard — build the leaderboard FROM result files. Never by hand.
//
// WHY THIS IS A GENERATOR AND NOT A MARKDOWN TABLE SOMEBODY EDITS
//
// A hand-maintained leaderboard drifts in one direction. Nobody edits a row to
// make their own tool look worse, and nobody deletes a row when the manifest
// moves underneath it, so the table slowly becomes a list of each tool's best
// remembered day, scored against corpora that no longer match. Every row here is
// read out of a result file written by bench-score.mjs, and every row carries
// the manifest digest it was scored against — so a row scored against a
// different corpus is visible AS a different corpus rather than silently
// comparable.
//
// ★ WHAT THIS FILE REFUSES TO DO
//
//   * Rank. There is no ORDER BY score. The label set the real benchmark ships
//     carries `rateWithheld`, so the only honest presentation is counts, and
//     sorting counts by one column invents the ranking the rate was withheld to
//     avoid. Rows are sorted by tool name, which is not a claim.
//   * Publish over an empty results directory. A leaderboard with no rows reads
//     as "nobody has entered yet" and is indistinguishable from "the generator
//     could not see the results". Exit 3 instead.
//   * Silently mix digests. A row whose manifestDigest differs from the current
//     manifest is printed with a marker and counted; the count is in the header,
//     not a footnote.
//   * Drop a bucket. ★ The table used to publish `matched`, `UNSCORED` and
//     `UNMAPPED` and no `unattributed` and no `refused`, while the scorer
//     asserted four-bucket exhaustiveness and the README promised it. A reader
//     meets the numbers HERE, not in the scorer, and here they did not have to
//     add up. Every bucket is a column now, the addition is checked per row, and
//     a row that does not add up is rejected by name rather than rendered.
//   * Hide what the labels are worth. Each row states how many of the labels it
//     was scored over have been confirmed by a human. A count over an
//     AI-prepared draft and a count over ground truth are different readings.
//
// Usage:
//   node scripts/bench-leaderboard.mjs --results <dir> --out <file.md> \
//        [--manifest <file>]
//
// Exit 0 on success, 2 on usage, 3 when there is nothing to publish.
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { EXIT_OK, EXIT_USAGE, EXIT_VACUOUS, MAX_LINE_WINDOW, manifestDigest, readJsonOrFail } from './bench-shared.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const BENCH = join(REPO, 'bench', 'ai-code-security-design-smells');

/**
 * The four finding buckets, restated here on purpose.
 *
 * The scorer asserts they are exhaustive. This file asserts it again, over the
 * FILE rather than over the in-memory object, because a result file can be
 * hand-edited, can come from a submitter, and can have been written by an older
 * scorer — and the leaderboard is where a reader actually meets the numbers.
 */
export function bucketSum(counts) {
  const c = counts ?? {};
  return (
    Number(c.findingsMatched ?? NaN) +
    Number(c.findingsUnscored ?? NaN) +
    Number(c.findingsUnmapped ?? NaN) +
    Number(c.findingsUnattributed ?? NaN)
  );
}

/** Every way a row's own counts can fail to describe a partition. Empty is good. */
export function exhaustivenessFailures(counts) {
  const c = counts ?? {};
  const out = [];
  const sum = bucketSum(c);
  if (!Number.isInteger(sum) || sum !== c.findingsTotal) {
    out.push(
      `matched ${c.findingsMatched} + UNSCORED ${c.findingsUnscored} + UNMAPPED ${c.findingsUnmapped} + ` +
        `unattributed ${c.findingsUnattributed} = ${sum}, but findingsTotal is ${c.findingsTotal}`,
    );
  }
  if (c.labelsCovered + c.labelsUncovered !== c.labelsTotal) {
    out.push(`labelsCovered ${c.labelsCovered} + labelsUncovered ${c.labelsUncovered} does not equal labelsTotal ${c.labelsTotal}`);
  }
  if (c.labelsTPCovered + c.labelsFPCovered !== c.labelsCovered) {
    out.push(`labelsTPCovered ${c.labelsTPCovered} + labelsFPCovered ${c.labelsFPCovered} does not equal labelsCovered ${c.labelsCovered}`);
  }
  if (c.recovered + c.missed !== c.labelsTPCovered) {
    out.push(`recovered ${c.recovered} + missed ${c.missed} does not equal labelsTPCovered ${c.labelsTPCovered}`);
  }
  return out;
}

/**
 * Every `*.json` in the results directory, parsed, in a stable order.
 *
 * Three outcomes, and the third one is why this returns a triple. A file that is
 * not a usable result is REJECTED with its name and the reason. A file that is
 * not JSON at all is SKIPPED with its name — it used to be filtered out in
 * silence by `.endsWith('.json')`, while the comment above claimed non-result
 * files were rejected by name. A directory README is a legitimate skip; a
 * misnamed result file is not, and the two were indistinguishable because
 * neither was printed.
 */
export function loadResults(fs, dir) {
  let names;
  try {
    names = readdirSync(dir).sort();
  } catch (err) {
    throw new Error(`cannot read the results directory ${dir} — ${err.code ?? err.message}`);
  }
  const rows = [];
  const rejected = [];
  const skipped = [];
  for (const name of names) {
    if (!name.endsWith('.json')) {
      skipped.push({ name, reason: 'not a .json file, so it is not a result file; listed rather than filtered out in silence' });
      continue;
    }
    const path = join(dir, name);
    let doc;
    try {
      doc = readJsonOrFail(fs, path, 'result file');
    } catch (err) {
      rejected.push({ name, reason: err.message });
      continue;
    }
    if (doc?.schema !== 'bench/result@1') {
      rejected.push({ name, reason: `schema is ${JSON.stringify(doc?.schema ?? null)}, not "bench/result@1"` });
      continue;
    }
    if (doc?.counts === undefined || doc?.manifestDigest === undefined) {
      rejected.push({ name, reason: 'no counts or no manifestDigest — the row would claim a reading it does not carry' });
      continue;
    }
    if (doc.counts.labelsCovered === undefined || doc.counts.labelsTPCovered === undefined) {
      rejected.push({
        name,
        reason:
          'no labelsCovered/labelsTPCovered — written by a scorer that took the denominator as EVERY ' +
          'label whether or not the run covered it, so its `missed` counts repositories that were ' +
          'never scanned. Re-score the run.',
      });
      continue;
    }
    // The window, before the row is published. The table prints `doc.lineWindow`
    // and the legend under it says the value is bounded -- but the bound was
    // enforced only in the scorer, in a different process, on a file anyone can
    // write by hand. A row carrying 9999 rendered, and the legend then asserted of
    // it the one thing that was not true. A generator that prints a claim has to
    // be the thing that checks it.
    const w = doc.lineWindow;
    if (!Number.isInteger(w) || w < 1 || w > MAX_LINE_WINDOW) {
      rejected.push({
        name,
        reason:
          `lineWindow is ${JSON.stringify(w ?? null)}, not an integer in 1..${MAX_LINE_WINDOW} -- the table `
          + 'states of every row it prints that the window is bounded, so a row that is not cannot be one of them',
      });
      continue;
    }
    if (doc.lineWindowMax !== undefined && doc.lineWindowMax !== MAX_LINE_WINDOW) {
      rejected.push({
        name,
        reason:
          `the row was scored against a maximum window of ${JSON.stringify(doc.lineWindowMax)} and this `
          + `generator publishes ${MAX_LINE_WINDOW}: the rows would not be comparable on the axis the legend claims`,
      });
      continue;
    }
    const failures = exhaustivenessFailures(doc.counts);
    if (failures.length > 0) {
      rejected.push({ name, reason: `the counts do not partition: ${failures.join('; ')}` });
      continue;
    }
    rows.push({ name, doc });
  }
  return { rows, rejected, skipped };
}

const cell = (v) => (v === null || v === undefined ? '—' : String(v));

/** `confirmed/total` for the labels a row was scored over, or `—` if unstated. */
function confirmationCell(doc) {
  const p = doc.labelProvenance;
  if (p === undefined || p === null || typeof p.total !== 'number') return '—';
  return `${p.confirmed}/${p.total}`;
}

export function render(rows, currentDigest, options = {}) {
  const stale = rows.filter((r) => r.doc.manifestDigest !== currentDigest).length;
  const withheld = rows.filter((r) => r.doc.rateWithheld !== null && r.doc.rateWithheld !== undefined).length;
  const unconfirmed = rows.filter((r) => (r.doc.labelProvenance?.unconfirmed ?? 0) > 0).length;
  const notPartitioned = rows.filter((r) => exhaustivenessFailures(r.doc.counts).length > 0).length;

  const out = [];
  out.push('<!-- GENERATED BY scripts/bench-leaderboard.mjs — DO NOT EDIT BY HAND.');
  out.push('     Every row is read out of a result file written by scripts/bench-score.mjs.');
  out.push('     Edits here are overwritten on the next run and prove nothing in between. -->');
  out.push('');
  out.push(`# Leaderboard — ${options.title ?? 'ai-code-security-design-smells'}`);
  out.push('');
  out.push(`Rows: **${rows.length}**. Scored against manifest \`${currentDigest}\`.`);
  if (stale > 0) {
    out.push('');
    out.push(
      `**${stale} row(s) were scored against a DIFFERENT manifest** and are marked \`≠\` below. ` +
        'They are kept rather than hidden — a row that disappears when the corpus changes takes ' +
        'the evidence of the change with it — but they are not comparable with the rest.',
    );
  }
  if (unconfirmed > 0) {
    out.push('');
    out.push(
      `**THE LABELS ARE NOT CONFIRMED.** ${unconfirmed} row(s) were scored over labels that are an ` +
        'AI-prepared draft which no human has read, and the `confirmed` column says how many of ' +
        'each row&rsquo;s labels have been. A leaderboard computed over unconfirmed labels is a ' +
        'different artefact from one computed over ground truth: every count below is a reading ' +
        'against that draft, and a disagreement between a tool and a row may be the row&rsquo;s.',
    );
  }
  if (withheld > 0) {
    out.push('');
    out.push(
      `**No rate is published.** ${withheld} row(s) were scored against a label set carrying ` +
        '`rateWithheld`: the verdicts are an unreviewed draft, and a precision or recall figure ' +
        'over unreviewed verdicts measures the person who drafted them. The integer counts below ' +
        'are what the run actually observed. Do not divide them.',
    );
  }
  if (notPartitioned > 0) {
    out.push('');
    out.push(
      `**${notPartitioned} row(s) do not add up** and are marked \`!\` in the findings column. Their ` +
        'buckets do not partition the findings they claim, so at least one number in the row is ' +
        'wrong and the row cannot be read as a measurement.',
    );
  }
  out.push('');
  out.push(
    '| tool | version | date | manifest | labels confirmed | labels TP covered | recovered | missed | ' +
      'NOT COVERED | known-FP reported | findings | matched | UNSCORED | UNMAPPED | unattributed | refused | window |',
  );
  out.push('| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |');

  for (const { doc } of [...rows].sort(byToolThenDate)) {
    const c = doc.counts ?? {};
    const partitioned = exhaustivenessFailures(c).length === 0;
    out.push(
      `| ${cell(doc.tool)} | ${cell(doc.toolVersion)} | ${cell(doc.date)} | ` +
        `${doc.manifestDigest === currentDigest ? '=' : '≠'} | ` +
        `${confirmationCell(doc)} | ${cell(c.labelsTPCovered)} | ${cell(c.recovered)} | ${cell(c.missed)} | ` +
        `${cell(c.labelsUncovered)} | ${cell(c.reportedKnownFalsePositive)} | ` +
        `${cell(c.findingsTotal)}${partitioned ? '' : ' !'} | ${cell(c.findingsMatched)} | ${cell(c.findingsUnscored)} | ` +
        `${cell(c.findingsUnmapped)} | ${cell(c.findingsUnattributed)} | ${cell(doc.refusedSarifResults)} | ${cell(doc.lineWindow)} |`,
    );
  }

  out.push('');
  out.push('## Reading the columns');
  out.push('');
  out.push('- **labels confirmed** is how many of the labels this row was scored over have been confirmed by a human, out of how many it was scored over. `0/1` means the row is a reading against an unconfirmed AI-prepared draft.');
  out.push('- **labels TP covered / recovered / missed** are over the labelled true positives IN THE REPOSITORIES THE RUN COVERED. A repository the run never scanned is not a miss.');
  out.push('- **NOT COVERED** is the labelled rows that lie outside this run\'s coverage. They are published rather than folded into `missed`, because "the tool did not find it" and "the tool was never pointed at it" are different sentences.');
  out.push('- **UNSCORED** is a finding whose rule maps to a family but whose location no label covers. It is *not* a false positive: nobody has decided what it is. It is printed in its own column so it can never be folded into a zero.');
  out.push('- **UNMAPPED** is a finding whose rule id maps to no family. A row with only UNMAPPED findings is refused at scoring time and never reaches this table.');
  out.push('- **unattributed** is a finding that could not be tied to any manifest entry. **refused** is a SARIF result with no ruleId or no usable location, which never became a finding at all.');
  out.push('- matched + UNSCORED + UNMAPPED + unattributed = **findings**, in every row. A row where they do not is marked `!` and is rejected by the generator rather than published.');
  out.push('- **manifest** is `=` when the row was scored against the manifest named above and `≠` when it was not.');
  out.push('- **window** is the `--line-window` the row was scored with. It is bounded, so a row cannot have been widened until everything matched.');
  out.push('');
  if (options.footer !== undefined) {
    out.push(options.footer);
    out.push('');
  }
  return out.join(String.fromCharCode(10));
}

function byToolThenDate(a, b) {
  const t = String(a.doc.tool ?? '').localeCompare(String(b.doc.tool ?? ''));
  return t !== 0 ? t : String(a.doc.date ?? '').localeCompare(String(b.doc.date ?? ''));
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function flagValue(argv, name, fallback) {
  const i = argv.indexOf(name);
  return i === -1 || argv[i + 1] === undefined ? fallback : argv[i + 1];
}

export function main(argv) {
  const fs = { readFileSync };
  const resultsDir = flagValue(argv, '--results', join(BENCH, 'results'));
  const manifestPath = flagValue(argv, '--manifest', join(BENCH, 'manifest.json'));
  const outPath = flagValue(argv, '--out', null);
  if (outPath === null) {
    console.error('bench-leaderboard: --out <file.md> is required.');
    return EXIT_USAGE;
  }

  let manifest;
  let loaded;
  try {
    manifest = readJsonOrFail(fs, manifestPath, 'manifest');
    loaded = loadResults(fs, resultsDir);
  } catch (err) {
    console.error(`bench-leaderboard: ${err.message}`);
    return EXIT_USAGE;
  }

  for (const r of loaded.rejected) console.error(`REJECTED  ${r.name} — ${r.reason}`);
  // Named, not filtered in silence. A misnamed result file and a directory
  // README look identical to `readdir`; only the reader can tell them apart, and
  // only if the file is printed.
  for (const s of loaded.skipped) console.error(`SKIPPED   ${s.name} — ${s.reason}`);

  if (loaded.rows.length === 0) {
    console.error(
      `bench-leaderboard: no usable result files in ${resultsDir}` +
        (loaded.rejected.length > 0 ? ` (${loaded.rejected.length} rejected, listed above)` : '') +
        (loaded.skipped.length > 0 ? ` (${loaded.skipped.length} skipped, listed above)` : '') +
        '.\nRefusing to write a leaderboard with no rows: an empty table reads as "nobody has ' +
        'entered yet", and that is indistinguishable from "the generator was pointed at the ' +
        'wrong directory". Score a run first: node scripts/bench-score.mjs --out <result.json>',
    );
    return EXIT_VACUOUS;
  }

  let digest;
  try {
    digest = manifestDigest(manifest);
  } catch (err) {
    console.error(`bench-leaderboard: ${err.message}`);
    return EXIT_USAGE;
  }

  const md = render(loaded.rows, digest, {
    title: manifest.benchmark ?? 'ai-code-security-design-smells',
    footer: flagValue(argv, '--footer', undefined),
  });
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${md}${String.fromCharCode(10)}`, 'utf8');
  console.log(
    `wrote ${outPath} — ${loaded.rows.length} row(s), ${loaded.rejected.length} rejected, ${loaded.skipped.length} skipped`,
  );
  return EXIT_OK;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
