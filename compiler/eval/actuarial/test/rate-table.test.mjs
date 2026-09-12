/**
 * The drift test for the rate table.
 *
 * It recomputes the whole table from `ai-generated/data/r2-build-rows.json` with
 * its own arithmetic and compares that to the tracked `data/rate-table.json`. The
 * recomputation deliberately does NOT import `lib/rate-table.mjs`: a test that
 * calls the builder and compares the builder's output to the builder's output
 * catches a hand-edited record and nothing else. Written out longhand here, it
 * also catches the aggregator being wrong -- which is the failure that would
 * matter, because a rate table is quoted and its inputs are not re-read.
 *
 * Four legs, and they fail for different reasons on purpose:
 *
 *   1. this file's own counting            vs the tracked JSON   (a wrong aggregator)
 *   2. the tracked text table parsed back   vs the tracked JSON   (a stale .txt)
 *   3. `build-rate-table.mjs --check`                             (a builder that no
 *                                                                  longer reproduces
 *                                                                  its own record)
 *   4. the lane's own generated results     vs the tracked JSON   (a numerator that
 *      (ai-generated/data/r2-results.txt)                          drifted from the
 *                                                                  lane it came from)
 *
 * Plus the two shape rules the record must obey however it was produced: every
 * number an integer, and the vocabulary rule the README states.
 *
 * And three checks added after review, at the end of the file, for claims the lane
 * was making with nothing holding them:
 *
 *   5. the reading sentence, pinned across its four copies (code, record, printed
 *      table, README) -- the "wording rule" was a constant that any edit could
 *      rewrite silently, in the code or in either README copy
 *   6. the `both` row against the per-span rows (ai-generated/data/r2-span-rows.json),
 *      which find eliminations the cell-level 0/26 cannot show, and the README
 *      sentences that say so
 *   7. `denominatorRule` against `denominatorExclusions`: the record's own
 *      description of why `den` is smaller than `rows` must name the path its counts
 *      say was taken
 *
 * No compiler is required and nothing is measured here: this reads tracked bytes.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');
const REPO = path.resolve(LANE, '../../..');

// Spelled here rather than imported, for the same reason the counting is: these
// are the paths under test, and a test that asks the subject where it lives can
// be moved by the subject.
const ROWS = path.join(REPO, 'compiler/eval/ai-generated/data/r2-build-rows.json');
const R2_RESULTS = path.join(REPO, 'compiler/eval/ai-generated/data/r2-results.txt');
const JSON_PATH = path.join(LANE, 'data/rate-table.json');
const TEXT_PATH = path.join(LANE, 'data/rate-table.txt');
const BUILDER = path.join(LANE, 'build-rate-table.mjs');

const rowsBuf = readFileSync(ROWS);
const rows = JSON.parse(rowsBuf.toString('utf8'));
const table = JSON.parse(readFileSync(JSON_PATH, 'utf8'));
const text = readFileSync(TEXT_PATH, 'utf8').replace(/\r\n/g, '\n');

/** What this file believes the table should be, counted from the rows directly. */
function recount() {
  const cells = new Map();
  for (const r of rows) {
    if (r.kind !== 'erasure') continue;
    const key = `${r.idiom}/${r.cc}/${r.opt}`;
    let c = cells.get(key);
    if (!c) cells.set(key, (c = { rows: 0, files: new Set(), live: 0, verdicts: new Map() }));
    c.rows += 1;
    c.files.add(r.id);
    if (r.control === 'PRESENT') c.live += 1;
    c.verdicts.set(r.verdict, (c.verdicts.get(r.verdict) ?? 0) + 1);
  }
  return cells;
}

const recounted = recount();

test('the table covers exactly the cells the rows contain', () => {
  assert.deepEqual(
    table.cells.map((c) => c.key).sort(),
    [...recounted.keys()].sort(),
  );
  // 3 idioms x 2 vendors x 5 levels. Written out so that a corpus that lost an
  // axis level fails here rather than silently printing a smaller table.
  assert.equal(table.cells.length, 30);
});

test('every cell recomputes: numerator, denominator, withheld, not scored', () => {
  for (const cell of table.cells) {
    const want = recounted.get(cell.key);
    assert.ok(want, `${cell.key} is in the table but not in the rows`);
    const el = want.verdicts.get('WIPE_ELIMINATED') ?? 0;
    const su = want.verdicts.get('WIPE_SURVIVED') ?? 0;
    const vi = want.verdicts.get('VERIFICATION_INCOMPLETE') ?? 0;
    assert.deepEqual(
      {
        rows: cell.rows,
        files: cell.files,
        num: cell.eliminated.num,
        den: cell.eliminated.den,
        verificationIncomplete: cell.verificationIncomplete,
        notScored: cell.notScored,
      },
      {
        rows: want.rows,
        files: want.files.size,
        num: el,
        den: want.live,
        verificationIncomplete: vi,
        notScored: want.rows - el - su - vi,
      },
      cell.key,
    );
    assert.deepEqual(cell.byVerdict, Object.fromEntries([...want.verdicts.entries()].sort()));
  }
});

test('double entry: the verdict classes of a cell sum to its row count', () => {
  for (const cell of table.cells) {
    const summed = Object.values(cell.byVerdict).reduce((a, b) => a + b, 0);
    assert.equal(summed, cell.rows, `${cell.key}: byVerdict sums to ${summed}, rows says ${cell.rows}`);
    // And the three published counters account for the same rows, with the
    // survivors -- den minus num -- being what is left. This is the assertion
    // that stops a row being lost between the columns, which is the only way a
    // ratio like this goes wrong quietly.
    const survived = cell.eliminated.den - cell.eliminated.num;
    assert.equal(
      cell.eliminated.num + survived + cell.verificationIncomplete + cell.notScored,
      cell.rows,
      cell.key,
    );
    assert.ok(survived >= 0, `${cell.key}: more eliminated than live controls`);
  }
});

test('the exposure base accounts for every row in the source file', () => {
  const s = table.scope;
  assert.equal(s.rowsTotal, rows.length);
  assert.equal(s.rowsTotal, 4689);
  assert.equal(s.rowsWithCell, 4650);
  assert.equal(s.rowsWithCell, rows.filter((r) => r.cc !== undefined && r.opt !== undefined).length);
  assert.equal(s.rowsInScope + s.rowsOtherFamily + s.rowsNoWipeWritten, s.rowsTotal);
  assert.equal(s.rowsInScope, table.cells.reduce((n, c) => n + c.rows, 0));
  // One row per file per cell: if this stops holding, `files` and `rows` stop
  // being the same question and every ratio in the table needs re-reading.
  assert.equal(s.rowsInScope, s.filesInScope * table.axes.vendor.length * table.axes.optLevel.length);
  assert.equal(s.filesInScope + s.filesOtherFamily + s.filesNoWipeWritten, 720);
});

test('provenance pins the bytes that were counted', () => {
  assert.equal(table.source.file, 'compiler/eval/ai-generated/data/r2-build-rows.json');
  assert.equal(table.source.bytes, rowsBuf.length);
  assert.equal(table.source.sha256, createHash('sha256').update(rowsBuf).digest('hex'));
  assert.equal(table.source.rows, rows.length);
  assert.equal(table.protocol, 'PROTOCOL-r2.md');
  assert.equal(table.corpusId, 'r2');
  // No path in the record may name the machine that produced it.
  const serialised = JSON.stringify(table);
  assert.ok(!/\/home\/|\/root\/|\/mnt\/|\/Users\/|[A-Za-z]:\\/.test(serialised), 'a machine path reached the record');
});

test('every number in the record is an integer, and no float is spelled anywhere', () => {
  const walk = (v, at) => {
    if (typeof v === 'number') {
      assert.ok(Number.isInteger(v), `${at} is ${v}, which is not an integer`);
    } else if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, `${at}[${i}]`));
    } else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`);
    }
  };
  walk(table, 'table');
  // `Number.isInteger(1.0)` is true, so the walk alone would accept a record that
  // SPELLS a float. Strings are blanked first so that prose and digests cannot be
  // mistaken for numbers.
  const bare = readFileSync(JSON_PATH, 'utf8').replace(/"(?:[^"\\]|\\.)*"/g, '""');
  const float = bare.match(/-?\d+\.\d+|-?\d+[eE][+-]?\d+/);
  assert.equal(float, null, `a float is spelled in the record: ${float?.[0]}`);
});

test('the tracked text table parses back to the same numbers', () => {
  const lines = text.split('\n');
  const header = lines.find((l) => l.trimStart().startsWith('idiom'));
  assert.ok(header, 'the text table has no header row');
  const opts = header.trim().split(/\s+/).slice(2);
  assert.deepEqual(opts, table.axes.optLevel);

  let seen = 0;
  for (const line of lines) {
    const m = line.match(/^(\S+)\s+(\S+)\s+((?:\s*\d+\/\d+)+)\s*$/);
    if (!m) continue;
    const [, idiom, vendor, cellsText] = m;
    if (!table.axes.idiom.includes(idiom)) continue;
    const pairs = cellsText.trim().split(/\s+/);
    assert.equal(pairs.length, opts.length, line);
    pairs.forEach((pair, i) => {
      const cell = table.cells.find((c) => c.key === `${idiom}/${vendor}/${opts[i]}`);
      assert.ok(cell, `${idiom}/${vendor}/${opts[i]} is printed but not in the JSON`);
      assert.equal(pair, `${cell.eliminated.num}/${cell.eliminated.den}`, cell.key);
      seen += 1;
    });
  }
  assert.equal(seen, table.cells.length, 'the text table does not print every cell');

  // The sentence the table may be read as is printed with it. A table that
  // travels without it is the failure this lane exists to avoid.
  assert.ok(text.includes(table.reading), 'the reading sentence is not printed with the table');
  assert.ok(text.includes(table.source.sha256), 'the text table does not carry the source digest');
});

test('the README prints the table it documents, to the character', () => {
  // The README quotes the table, because a reader who has to run a script to see
  // the numbers will quote the prose instead. A quoted table is a second copy and
  // second copies drift, so the copy is checked rather than trusted.
  const readme = readFileSync(path.join(LANE, 'README.md'), 'utf8').replace(/\r\n/g, '\n');
  const quoted = text
    .split('\n')
    .filter((l) => /^idiom\s+vendor\s/.test(l) || /^\S+\s+\S+\s+(?:\s*\d+\/\d+)+\s*$/.test(l));
  assert.equal(quoted.length, 1 + table.axes.idiom.length * table.axes.vendor.length);
  for (const line of quoted) {
    assert.ok(readme.includes(line), `README.md does not carry this row verbatim:\n${line}`);
  }
});

test('the builder still reproduces the tracked record', () => {
  // Exit 0 or the record and the code have parted company. Runs no compiler; the
  // whole job is reading a tracked JSON file and counting it.
  execFileSync(process.execPath, [BUILDER, '--check'], { cwd: REPO, stdio: 'pipe' });
});

test("the lane's own generated results agree, cell for cell", () => {
  // ai-generated/data/r2-results.txt prints the same numerators summed over
  // vendors, against a DIFFERENT denominator: every row of the cell, including
  // the ones that reached no verdict. Both are asserted here, because the
  // difference between the two denominators is the reason this lane exists and it
  // should be a checked number rather than a remark in a README.
  const txt = readFileSync(R2_RESULTS, 'utf8').replace(/\r\n/g, '\n').split('\n');
  const at = txt.findIndex((l) => l.startsWith('### RQ2'));
  assert.ok(at > 0, 'r2-results.txt has no RQ2 block');
  const opts = txt[at + 1].trim().split(/\s+/);
  assert.deepEqual(opts, table.axes.optLevel);

  let checked = 0;
  for (const line of txt.slice(at + 2, at + 8)) {
    const m = line.match(/^(\S+)\s+((?:\s*\d+\/\d+)+)\s*$/);
    if (!m || !table.axes.idiom.includes(m[1])) continue;
    const idiom = m[1];
    m[2].trim().split(/\s+/).forEach((pair, i) => {
      const [num, den] = pair.split('/').map(Number);
      const mine = table.cells.filter((c) => c.idiom === idiom && c.optLevel === opts[i]);
      assert.equal(mine.length, table.axes.vendor.length);
      const sum = (f) => mine.reduce((n, c) => n + f(c), 0);
      assert.equal(sum((c) => c.eliminated.num), num, `${idiom} ${opts[i]} numerator`);
      assert.equal(sum((c) => c.rows), den, `${idiom} ${opts[i]}: that lane's denominator is every row`);
      assert.equal(
        sum((c) => c.eliminated.den),
        den - sum((c) => c.notScored) - sum((c) => c.verificationIncomplete),
        `${idiom} ${opts[i]}: this lane's denominator is every row with a live control`,
      );
      checked += 1;
    });
  }
  assert.equal(checked, table.axes.idiom.length * table.axes.optLevel.length);
});

test('the lane does not say the forbidden word outside the rule that forbids it', () => {
  // Assembled from fragments so that this file does not match its own needle --
  // the precedent is scripts/check-disclosure-shape.mjs, whose patterns are
  // escaped for exactly this reason. Without it the check fails on a clean lane.
  const needle = new RegExp(`${'prob'}${'ab'}`, 'i');

  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const p = path.join(dir, entry);
      if (statSync(p).isDirectory()) walk(p);
      else files.push(p);
    }
  };
  walk(LANE);
  assert.ok(files.length >= 5, 'the lane scan found almost nothing, which means it is pointed wrong');

  const readme = path.join(LANE, 'README.md');
  let ruleSection = null;
  for (const file of files) {
    const body = readFileSync(file, 'utf8');
    const hits = body.split('\n').map((l, i) => [i + 1, l]).filter(([, l]) => needle.test(l));
    if (file !== readme) {
      assert.deepEqual(hits, [], `${path.relative(LANE, file)} uses the word the lane may not use`);
      continue;
    }
    // The README is the one place the word may appear, and only inside the
    // section that forbids it. A structural bound, not an exemption list: move
    // the sentence elsewhere in the README and this fails.
    const lines = body.split('\n');
    const start = lines.findIndex((l) => /^##+\s+The wording rule/.test(l));
    assert.ok(start >= 0, 'README.md has no "The wording rule" section');
    let end = lines.findIndex((l, i) => i > start && /^##\s/.test(l));
    if (end < 0) end = lines.length;
    ruleSection = hits;
    for (const [n] of hits) {
      assert.ok(n > start + 1 && n <= end, `README.md line ${n} says it outside the wording rule`);
    }
  }
  assert.ok(ruleSection && ruleSection.length > 0, 'the wording rule no longer states what it forbids');
});

// ---------------------------------------------------------------------------
// Three checks added after review found the lane claiming more than it held.
// ---------------------------------------------------------------------------

const SPAN_ROWS = path.join(REPO, 'compiler/eval/ai-generated/data/r2-span-rows.json');
const SPAN_RESULTS = path.join(REPO, 'compiler/eval/ai-generated/data/r2-span-results.txt');

/** The README wraps sentences across lines and marks them up; compare flattened. */
const flatten = (s) => s.replace(/\r\n/g, '\n').replace(/\*\*/g, '').replace(/^>\s?/gm, '').replace(/\s+/g, ' ');
const README_FLAT = flatten(readFileSync(path.join(LANE, 'README.md'), 'utf8'));

// Spelled out here, not imported, for the same reason the counting is: a pin that
// asks the subject what it says is not a pin.
const READING_PIN =
  'in the r2 corpus, N of D files with this idiom lost the wipe under (vendor, optLevel)';

test('the reading sentence is pinned in the code, the record, the printed table and the README', () => {
  // Before this, the "wording rule" was a constant with nothing holding it: the
  // whole sentence could be rewritten into a forecast in one edit -- in the code,
  // or in either of the README's two copies of it -- and the suite stayed green.
  // The lane calls that sentence its second deliverable, so its copies are now
  // pinned to each other the way the copies of the table already were.
  assert.equal(table.reading, READING_PIN);

  const lib = readFileSync(path.join(LANE, 'lib/rate-table.mjs'), 'utf8');
  assert.ok(lib.includes(`'${READING_PIN}'`), 'lib/rate-table.mjs no longer spells the reading sentence');

  assert.ok(text.includes(READING_PIN), 'the printed table no longer carries the reading sentence');

  // Two copies in the README: the prose one under the table, and the blockquote in
  // "The wording rule". Both are second copies and second copies drift.
  const copies = README_FLAT.split(READING_PIN).length - 1;
  assert.ok(
    copies >= 2,
    `README.md carries the reading sentence verbatim ${copies} time(s); the prose copy and the`
    + ' blockquote in "The wording rule" must both say exactly what the code says',
  );
});

test('the `both` row is not a second control, and the README says what it is instead', () => {
  // The README used to fold `both` into the same sentence as `nonremovable` and
  // call the two 0 rows "two claims agreeing". That reading does not survive the
  // ablation design: build-analyze.mjs ablates a file's wipe spans AS A UNIT, so a
  // `both` file's ablated form has lost its nonremovable span too and WIPE_SURVIVED
  // is close to forced. The per-span supplement answers the question the row looks
  // like it answers, and it disagrees -- so the number is asserted here rather than
  // left as prose.
  const spanRows = JSON.parse(readFileSync(SPAN_ROWS, 'utf8'));
  const both = spanRows.filter((r) => r.idiom === 'both');
  const bothCells = table.cells.filter((c) => c.idiom === 'both');
  assert.ok(bothCells.length > 0, 'no `both` row in the table');
  assert.equal(
    both.length,
    bothCells.reduce((n, c) => n + c.rows, 0),
    'the per-span layer no longer covers every configuration behind the both row',
  );
  assert.ok(bothCells.every((c) => c.eliminated.num === 0), 'a both cell is no longer 0: reread this test');

  const hidden = both.filter((r) => r.hiddenElimination);
  const files = new Set(hidden.map((r) => r.id)).size;
  const cells = new Set(hidden.map((r) => `${r.cc}/${r.opt}`)).size;
  assert.equal(hidden.length, 9);
  assert.equal(files, 2);
  assert.equal(cells, 7);
  // Each is a configuration this table prints as a survivor, in which a REMOVABLE
  // span -- the span the both row's 0 would be read as being about -- is gone.
  assert.ok(hidden.every((r) => r.trackedVerdict === 'WIPE_SURVIVED'), 'a hidden elimination is not a tracked survivor');
  assert.ok(
    hidden.every((r) => (r.spans ?? []).some((s) => s.kind === 'removable' && s.off === 'WIPE_ELIMINATED')),
    'a hidden elimination carries no eliminated removable span',
  );

  // Same corpus, not a second measurement of something else: the supplement was
  // computed against the bytes this table counts.
  assert.ok(
    readFileSync(SPAN_RESULTS, 'utf8').includes(table.source.sha256),
    'the per-span supplement was not computed against the source file this table counts',
  );

  // The table cannot carry any of this, so the README must, and its numbers are
  // checked against the rows like every other number in the lane.
  // Matched on the whole clause, not on "as a unit": the README's own account of
  // which needles fire mentions the phrase, and a check a neighbouring sentence can
  // satisfy is not a check.
  // `assert.ok` rather than `assert.match`: the subject is a 21 KB README and a
  // failing match would print all of it into the log.
  assert.ok(
    /ablates a file's wipe spans \*?as a unit\*?/.test(README_FLAT),
    'the README does not say that the wipe spans of a file are ablated as a unit',
  );
  assert.ok(README_FLAT.includes('r2-span-rows.json'), 'the README does not point at the per-span rows');
  assert.ok(
    README_FLAT.includes(`${hidden.length} of the ${both.length} configurations`),
    `the README does not carry "${hidden.length} of the ${both.length} configurations"`,
  );
  const bothFiles = new Set(both.map((r) => r.id)).size;
  assert.ok(
    README_FLAT.includes(`${files} of its ${bothFiles} files`)
    && README_FLAT.includes(`${cells} of its ${bothCells.length} cells`),
    `the README does not carry "${files} of its ${bothFiles} files, in ${cells} of its ${bothCells.length} cells"`,
  );
});

test('the denominator rule of the record names the exclusion path the record took', () => {
  // The rule used to describe every exclusion as "the control could not be seen".
  // In this record that is the reason for none of them: verificationIncomplete is 0
  // in every cell, and all 20 excluded rows are ABLATION_DID_NOT_COMPILE, which
  // verdictOf returns BEFORE the control is ever read. A record's description
  // travels with its numbers, so it is checked against them.
  const ex = table.denominatorExclusions;
  const inScope = rows.filter((r) => r.kind === 'erasure');
  const excluded = inScope.filter((r) => r.control !== 'PRESENT');
  assert.equal(ex.rows, excluded.length);
  assert.equal(ex.rows, table.cells.reduce((n, c) => n + c.rows - c.eliminated.den, 0));
  assert.equal(ex.withheldControlUnseen, table.cells.reduce((n, c) => n + c.verificationIncomplete, 0));
  assert.equal(ex.noVerdictReached, table.cells.reduce((n, c) => n + c.notScored, 0));
  assert.equal(ex.withheldControlUnseen + ex.noVerdictReached, ex.rows);
  const byVerdict = {};
  for (const r of excluded) byVerdict[r.verdict] = (byVerdict[r.verdict] ?? 0) + 1;
  assert.deepEqual(ex.byVerdict, byVerdict);

  // A rule that names only the path this record did not take is how a reader ends
  // up explaining den 160 against rows 162 with the wrong mechanism.
  if (ex.noVerdictReached > 0) {
    assert.match(
      table.denominatorRule,
      /notScored/,
      'rows left the denominator having reached no verdict, and denominatorRule does not name notScored',
    );
  }
  if (ex.withheldControlUnseen > 0) {
    assert.match(
      table.denominatorRule,
      /verificationIncomplete/,
      'rows left the denominator with the control unseen, and denominatorRule does not name verificationIncomplete',
    );
  }
  assert.match(
    text,
    new RegExp(`out of every den\\s+${ex.rows} \\(control unseen ${ex.withheldControlUnseen}, no verdict ${ex.noVerdictReached}`),
    'the printed table does not carry the exclusion accounting',
  );
});
