/**
 * The README's per-span numbers, pinned to the tracked data they were read
 * from. Nothing compiles and nothing is written: this reads README.md,
 * data/r2-build-rows.json (the find step's cells), data/r2-span-rows.json (the
 * per-span supplement's rows) and data/r2-span-results.txt (the text the same
 * full --write-data run printed from those rows), all read-only.
 *
 * Every per-span number the README quotes from tracked data is derived here from
 * the rows -- with lib/span-summary.mjs where it has the function -- or read from
 * the results text, and the two have to agree. A README edit, a re-recorded data
 * file or a hand edit of the text that moves one of them without the others
 * fails here, the way ../../repair-loop/test/stage-gate.test.mjs pins its authz
 * sentence to the tracked rows. The repair loop's clang-18 count that the
 * supplement starts from is pinned to these rows and to the cross-check the
 * results text records, not to the repair loop's rows file itself, which the
 * repair loop re-records on its own.
 *
 * Not pinned, because no tracked file holds them: what the README takes from
 * lab-only output -- the label-check.mjs paragraph (its setup, agreement counts,
 * ids, span indices and WipePin builds), what the listings behind the -O1
 * sentence show, and the red runs of the cross-check on lab copies of the repair
 * rows (the 71 mismatches) -- and what it says about build-spans.mjs itself (its
 * input files, usage and exit codes).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ELIMINATED, SURVIVED, ALL_OPTS, VENDORS, multiSpanFiles, hiddenSummary, undercountLine, spansMeasuredAlone,
} from '../lib/span-summary.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const bytes = (rel) => readFileSync(path.join(ROOT, rel));
const text = (rel) => bytes(rel).toString('utf8').replace(/\r\n/g, '\n');

const README = text('README.md');
const BUILD_BYTES = bytes('data/r2-build-rows.json');
const build = JSON.parse(BUILD_BYTES.toString('utf8'));
const spanRows = JSON.parse(text('data/r2-span-rows.json'));
const resultLines = text('data/r2-span-results.txt').split('\n');

const flat = (s) => s.replace(/\s+/g, ' ');
const key = (r) => `${r.id}|${r.cc}|${r.opt}`;
const spanByCell = new Map(spanRows.map((r) => [key(r), r]));
const { files: MULTI } = multiSpanFiles(build);
const HIDDEN = hiddenSummary(build, spanRows);
const hiddenAt = (cc, opt) => HIDDEN.find((h) => h.cc === cc && h.opt === opt);
const ROW_OF = { '`memset`': 'removable', 'non-removable': 'nonremovable', both: 'both' };
/** The results text's cross-check, per vendor: [compared, agree, not compared, hiddenElimination compared, disagree]. */
const CROSS = {};
for (const l of resultLines) {
  const m = /^ {2}(\S+) {2}span verdicts compared (\d+), agree (\d+), not compared (\d+); hiddenElimination compared (\d+), disagree (\d+)$/.exec(l);
  if (m) CROSS[m[1]] = m.slice(2).map(Number);
}

/** The README from `## <name>` to the next `## ` heading. */
function section(name) {
  const start = README.indexOf(`\n## ${name}\n`);
  assert.ok(start >= 0, `README.md has no "## ${name}" section`);
  const end = README.indexOf('\n## ', start + 1);
  return README.slice(start, end < 0 ? undefined : end);
}

/** The headline survival table (idiom x level), and the paragraph directly under it. */
function headline() {
  const lines = section('Results').split('\n');
  const h = lines.findIndex((l) => l.trim() === '| idiom | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |');
  assert.ok(h >= 0, 'the headline survival table is not in README.md "## Results"');
  const rows = new Map();
  let i = h + 2;
  for (; i < lines.length && lines[i].startsWith('|'); i++) {
    const cells = lines[i].split('|').slice(1, -1).map((c) => c.trim());
    rows.set(cells[0], cells.slice(1).map((c) => {
      const m = /^(?:\*\*)?(\d+)\/(\d+)(?:\*\*)?$/.exec(c);
      assert.ok(m, `headline cell ${JSON.stringify(c)} is not k/n`);
      return [Number(m[1]), Number(m[2])];
    }));
  }
  while (i < lines.length && lines[i].trim() === '') i++;
  const note = [];
  for (; i < lines.length && lines[i].trim() !== ''; i++) note.push(lines[i]);
  return { rows, note: flat(note.join(' ')) };
}

/**
 * One headline row per level, from the rows:
 *   n         the idiom's cells (the table's denominator)
 *   tracked   scored WIPE_ELIMINATED (the table's numerator)
 *   gone      tracked, plus the hidden eliminations: a cell scored WIPE_SURVIVED
 *             in which a removable span, ablated alone, is WIPE_ELIMINATED
 *   strict    a one-span cell by its verdict, a multi-span cell only by its
 *             removable spans ablated alone
 *   onlyCell  multi-span cells in `tracked` that `strict` does not count
 *   onlySpan  multi-span cells in `strict` that `gone` does not count (a span
 *             eliminated alone in a cell scored neither ELIMINATED nor SURVIVED)
 */
function idiomRow(idiom, opt) {
  const out = { n: 0, tracked: 0, gone: 0, strict: 0, onlyCell: [], onlySpan: [] };
  for (const c of build) {
    if (c.kind !== 'erasure' || c.idiom !== idiom || c.opt !== opt) continue;
    out.n++;
    const elim = c.verdict === ELIMINATED;
    if (elim) out.tracked++;
    if (!(c.n_spans >= 2)) {
      if (elim) { out.gone++; out.strict++; }
      continue;
    }
    const s = spanByCell.get(key(c));
    assert.ok(s, `no per-span row for the multi-span cell ${key(c)}`);
    assert.equal(s.trackedVerdict, c.verdict, `${key(c)}: the per-span row carries another tracked verdict`);
    const alone = s.spans.some((x) => x.kind === 'removable' && x.source === 'span' && x.off === ELIMINATED);
    if (elim || s.hiddenElimination) out.gone++;
    if (alone) out.strict++;
    if (elim && !alone) out.onlyCell.push(c);
    if (alone && !elim && !s.hiddenElimination) out.onlySpan.push(c);
  }
  return out;
}
const MEMSET = Object.fromEntries(ALL_OPTS.map((o) => [o, idiomRow('removable', o)]));

test('the headline table is still the tracked cell-level count, all three rows', () => {
  const { rows } = headline();
  assert.deepEqual([...rows.keys()], Object.keys(ROW_OF));
  for (const [label, idiom] of Object.entries(ROW_OF)) {
    const want = ALL_OPTS.map((o) => { const r = idiomRow(idiom, o); return [r.tracked, r.n]; });
    assert.deepEqual(rows.get(label), want, `the headline ${label} row no longer matches data/r2-build-rows.json`);
  }
});

test('the note directly under the headline table gives the memset row per span, from the tracked rows', () => {
  const { note } = headline();
  const m = /\*\*(\d+)\/(\d+)\*\* cells at `-O1` and \*\*(\d+)\/(\d+)\*\* at `-O2`, `-O3` and `-Os`/.exec(note);
  assert.ok(m, `the paragraph under the headline table is not the per-span note: "${note.slice(0, 100)}..."`);
  // -O2, -O3 and -Os are quoted as one number, so they have to be one number
  for (const o of ['-O3', '-Os']) {
    assert.deepEqual([MEMSET[o].gone, MEMSET[o].n], [MEMSET['-O2'].gone, MEMSET['-O2'].n], `${o} differs from -O2`);
  }
  assert.deepEqual(m.slice(1).map(Number), [MEMSET['-O1'].gone, MEMSET['-O1'].n, MEMSET['-O2'].gone, MEMSET['-O2'].n]);
  // and "gone" is the cell-level count plus the supplement's hidden eliminations of the idiom
  for (const o of ALL_OPTS) {
    const hidden = VENDORS.reduce((n, cc) => n + (hiddenAt(cc, o).hiddenByIdiom.removable || 0), 0);
    assert.equal(MEMSET[o].gone, MEMSET[o].tracked + hidden, o);
  }
  assert.match(note, /the same `verdictOf`/);
  assert.match(note, /\*Per-span supplement\*/);
  assert.match(note, /`data\/r2-span-results\.txt`/);
});

test('the supplement reads the memset row the same way, and says what counting strictly span by span gives', () => {
  const p = flat(section('Per-span supplement'));
  const m = /\*\*(\d+)\/(\d+)\*\* at `-O1` \(tracked (\d+)\) and \*\*(\d+)\/(\d+)\*\* at `-O2`, `-O3` and `-Os` \(tracked (\d+)\)/.exec(p);
  assert.ok(m, 'the supplement no longer reads the memset row against the headline table');
  for (const o of ['-O3', '-Os']) assert.equal(MEMSET[o].tracked, MEMSET['-O2'].tracked, o);
  assert.deepEqual(m.slice(1).map(Number), [MEMSET['-O1'].gone, MEMSET['-O1'].n, MEMSET['-O1'].tracked,
    MEMSET['-O2'].gone, MEMSET['-O2'].n, MEMSET['-O2'].tracked]);

  const s = /`-O1` gives (\d+), not (\d+): (\d+) `clang-18 -O1` cells, in (\d+) files, score `WIPE_ELIMINATED` while every removable span, ablated alone, reads `WIPE_SURVIVED`/.exec(p);
  assert.ok(s, 'the strict span-by-span count at -O1 is no longer stated');
  const odd = MEMSET['-O1'].onlyCell;
  assert.deepEqual(s.slice(1).map(Number), [MEMSET['-O1'].strict, MEMSET['-O1'].gone, odd.length, new Set(odd.map((c) => c.id)).size]);
  assert.ok(odd.every((c) => c.cc === 'clang-18'), 'a cell scored eliminated with no span eliminated alone is not clang-18');
  let alone = 0;
  for (const c of odd) {
    const measured = spanByCell.get(key(c)).spans.filter((x) => x.source === 'span');
    assert.ok(measured.every((x) => x.off === SURVIVED), `${key(c)}: not every span reads WIPE_SURVIVED`);
    alone += measured.length;
  }
  // how many single-span ablations the listing sentence is about, and at which
  // vendor and level (the listings themselves are lab-only)
  const l = /each of those (\d+) single-span ablations adds zero stores \(an `xorps` and `movaps`\) to the body: with every `memset` in the source, `(\S+) (-O[0-3s])` emits none of them/.exec(p);
  assert.ok(l, 'the listing sentence is no longer there');
  assert.deepEqual([Number(l[1]), `${l[2]} ${l[3]}`], [alone, ...new Set(odd.map((c) => `${c.cc} ${c.opt}`))]);
  // nothing is counted per span that the cell-level-plus-hidden count leaves out
  for (const o of ALL_OPTS) assert.deepEqual(MEMSET[o].onlySpan, [], o);
  assert.match(p, /`-O2`, `-O3` and `-Os` have no such cell/);
  for (const o of ['-O2', '-O3', '-Os']) assert.deepEqual([MEMSET[o].onlyCell.length, MEMSET[o].strict], [0, MEMSET[o].gone], o);

  // the `both` row: one k/n quoted for every level, the hidden cells it holds, and
  // the one whose removable span is initialiser-like
  const b = /The `both` row's (\d+)\/(\d+) hides (\d+) \(`clang-18 -O2`, `-Os`\), (\d+) \(`clang-18 -O3`\) and (\d+) \(`gcc-13 -O1`\.\.`-Os`\) cells in which the removable span is gone on its own; in `(\w+)` \(`(\S+) (-O[0-3s])`, `(-O[0-3s])`\) that span is initialiser-like/.exec(p);
  assert.ok(b, 'the both-row sentence is no longer there');
  for (const o of ALL_OPTS) {
    const r = idiomRow('both', o);
    assert.deepEqual([r.tracked, r.n], [Number(b[1]), Number(b[2])], `the both row at ${o}`);
  }
  const both = (cc, o) => hiddenAt(cc, o).hiddenByIdiom.both || 0;
  assert.equal(both('clang-18', '-Os'), both('clang-18', '-O2'));
  for (const o of ['-O2', '-O3', '-Os']) assert.equal(both('gcc-13', o), both('gcc-13', '-O1'), o);
  assert.deepEqual(b.slice(3, 6).map(Number), [both('clang-18', '-O2'), both('clang-18', '-O3'), both('gcc-13', '-O1')]);
  assert.deepEqual([both('clang-18', '-O0'), both('clang-18', '-O1'), both('gcc-13', '-O0')], [0, 0, 0]);
  // over every vendor and level, not only the two the sentence names
  const init = HIDDEN.flatMap((h) => h.hiddenIds
    .filter((x) => x.idiom === 'both' && x.eliminatedInitialiserLike.length).map((x) => `${x.id} ${h.cc} ${h.opt}`));
  assert.deepEqual(init, [`${b[6]} ${b[7]} ${b[8]}`, `${b[6]} ${b[7]} ${b[9]}`]);
});

test('the supplement table is hiddenSummary over the tracked rows, vendor by vendor and level by level', () => {
  const re = /^\| `([^`]+)` \| `(-O[0-3s])` \| (\d+) \| (\d+)(?: \((\d+) \/ (\d+)\))? \| (\d+) \| (\d+) \|$/;
  const got = [];
  for (const l of section('Per-span supplement').split('\n')) {
    const m = re.exec(l.trim());
    if (!m) continue;
    const [, cc, opt, tracked, hidden, rem, both, withHidden, initOnly] = m;
    assert.ok(rem !== undefined || hidden === '0', `${cc} ${opt}: ${hidden} hidden with no (removable / both) split`);
    got.push([cc, opt, +tracked, +hidden, +(rem ?? 0), +(both ?? 0), +withHidden, +initOnly]);
  }
  const want = HIDDEN.map((h) => [h.cc, h.opt, h.trackedEliminated, h.hidden, h.hiddenByIdiom.removable || 0,
    h.hiddenByIdiom.both || 0, h.withHidden, h.hiddenOnlyInitialiserLike]);
  assert.equal(want.length, VENDORS.length * ALL_OPTS.length);
  assert.deepEqual(got, want);
});

test('the supplement\'s counts are the rows\'', () => {
  const p = flat(section('Per-span supplement'));
  const erasureFiles = new Set(build.filter((r) => r.fam === 'erasure').map((r) => r.id)).size;
  const byIdiom = { removable: 0, both: 0, nonremovable: 0 };
  for (const v of MULTI.values()) byIdiom[v.idiom]++;
  const measuredRows = spanRows.filter((r) => r.measured);
  const measured = measuredRows.length;
  const perSpan = spanRows.reduce((n, r) => n + r.spans.filter((s) => s.source === 'span' && s.off !== null).length, 0);
  assert.deepEqual([...new Set(spanRows.map((r) => r.id))].sort(), [...MULTI.keys()]);

  const shown = (re) => { const m = re.exec(p); assert.ok(m, String(re)); return m.slice(1).map(Number); };
  assert.deepEqual(shown(/two or more wipe spans \((\d+) of (\d+)\)/), [MULTI.size, erasureFiles]);
  assert.deepEqual(shown(/Of the (\d+) files, (\d+) have a removable span \((\d+) `removable`, (\d+) `both`\); the other (\d+) have only nonremovable spans/),
    [MULTI.size, byIdiom.removable + byIdiom.both, byIdiom.removable, byIdiom.both, byIdiom.nonremovable]);
  // every file that wrote both idioms has two spans or more, so the Why paragraph's
  // `both` files are the multi-span ones
  const bothFiles = new Set(build.filter((r) => r.kind === 'erasure' && r.idiom === 'both').map((r) => r.id)).size;
  assert.equal(byIdiom.both, bothFiles);
  assert.deepEqual(shown(/the `both` row above says nothing about the `memset` those (\d+) files contain/), [bothFiles]);
  assert.deepEqual(shown(/`data\/r2-span-rows\.json`, (\d+) rows/), [spanRows.length]);
  const ccs = new Set(measuredRows.map((r) => r.cc)).size;
  const levels = new Set(measuredRows.map((r) => r.opt)).size;
  assert.deepEqual([ccs, levels], [VENDORS.length, ALL_OPTS.length]);
  assert.deepEqual(shown(/(\d+) multi-span files, (\d+) measured cells \((\d+) files with a removable span × (\d+) vendors × (\d+) levels\), (\d+) per-span verdicts/),
    [MULTI.size, measured, byIdiom.removable + byIdiom.both, ccs, levels, perSpan]);
  assert.equal(measured, (byIdiom.removable + byIdiom.both) * ccs * levels);
  assert.deepEqual(shown(/"Hidden" counts cells of those (\d+) files\./), [byIdiom.removable + byIdiom.both]);

  // gcc-13: every removable multi-span cell scored WIPE_SURVIVED at -O1..-Os is a hidden elimination
  const [n] = shown(/gcc-13 had no per-span view before this run; every one of its (\d+) removable multi-span cells scored `WIPE_SURVIVED` at `-O1`\.\.`-Os` holds a span that is eliminated on its own/);
  for (const o of ['-O1', '-O2', '-O3', '-Os']) {
    const cells = spanRows.filter((r) => r.cc === 'gcc-13' && r.opt === o && r.idiom === 'removable' && r.measured && r.trackedVerdict === SURVIVED);
    assert.equal(cells.length, n, `gcc-13 ${o}`);
    assert.ok(cells.every((r) => r.hiddenElimination), `gcc-13 ${o}: a removable SURVIVED cell with no span eliminated alone`);
  }

  // the compiler versions quoted are the ones the results text was run with
  const [clangV, gccV] = /stock `clang-18` (\S+) and `gcc-13` (\S+);/.exec(p).slice(1);
  assert.ok(resultLines.some((l) => l.startsWith('compiler        clang-18  (') && l.includes(`version ${clangV} `)), clangV);
  assert.ok(resultLines.some((l) => l.startsWith('compiler        gcc-13  (') && l.endsWith(` ${gccV})`)), gccV);
});

test('data/r2-span-results.txt prints what the rows hold, over this data/r2-build-rows.json', () => {
  const has = (line, why) => assert.ok(resultLines.includes(line), `${why}: no line ${JSON.stringify(line)}`);
  has(`tracked rows    (default) sha256 ${createHash('sha256').update(BUILD_BYTES).digest('hex')}`,
    'the results text was printed over another data/r2-build-rows.json');
  has(`opts            ${ALL_OPTS.join(' ')}`, 'not every level');
  has(`file subset     (all ${MULTI.size} multi-span files)`, 'not every multi-span file');
  for (const cc of VENDORS) {
    assert.ok(resultLines.some((l) => l.startsWith(`compiler        ${cc}  (`)), `no compiler line for ${cc}`);
    assert.ok(resultLines.some((l) => new RegExp(`^repair rows {5}${cc} \\(default\\) sha256 [0-9a-f]{64}$`).test(l)),
      `${cc} was not cross-checked against its default repair rows`);
  }
  const measured = spanRows.filter((r) => r.measured);
  has(`cells           ${spanRows.length} (${measured.length} measured; the rest have no removable span to ablate alone)`, 'cells');
  has(`per-span verdicts ${spanRows.reduce((n, r) => n + r.spans.filter((s) => s.source === 'span' && s.off !== null).length, 0)}`, 'per-span verdicts');
  const cmp = spanRows.filter((r) => r.cellMatchesTracked !== null);
  const at = resultLines.indexOf(`  cell verdicts   ${cmp.filter((r) => r.cellMatchesTracked).length}/${cmp.length} agree with the tracked rows`);
  assert.ok(at >= 0, 'cell verdicts line');
  assert.equal(resultLines[at + 1], '  held', 'integrity did not hold');
  has(`  held for ${VENDORS.length} of ${VENDORS.length} vendor(s) (${VENDORS.join(', ')})`, 'the cross-check');

  // the hidden eliminations, block by block: counts and ids
  const blocks = [];
  for (const l of resultLines) {
    const h = /^ {2}(\S+) (-O[0-3s]) {2}(\d+) of (\d+) measured SURVIVED multi-span cells(?: \(([^)]*)\))?; in (\d+) of them every eliminated span is itself initialiser-like$/.exec(l);
    if (h) {
      const byIdiom = Object.fromEntries((h[5] ? h[5].split(', ') : []).map((kv) => { const [k, v] = kv.split(' '); return [k, Number(v)]; }));
      blocks.push({ cc: h[1], opt: h[2], hidden: +h[3], survived: +h[4], byIdiom, initOnly: +h[6], ids: [] });
      continue;
    }
    const x = /^ {4}HIDDEN (\S+) \[(\w+)\] span\(s\) ([\d,]+)/.exec(l);
    if (x) blocks[blocks.length - 1].ids.push([x[1], x[2], x[3]]);
  }
  assert.deepEqual(blocks, HIDDEN.map((h) => ({
    cc: h.cc, opt: h.opt, hidden: h.hidden, survived: h.survivedCells, byIdiom: h.hiddenByIdiom,
    initOnly: h.hiddenOnlyInitialiserLike, ids: h.hiddenIds.map((x) => [x.id, x.idiom, x.spans.join(',')]),
  })));
  for (const h of HIDDEN) has(`  ${undercountLine(h)}`, `the undercount line for ${h.cc} ${h.opt}`);
});

test('the initialiserLike counts the README quotes are the ones data/r2-span-results.txt printed', () => {
  const head = resultLines.map((l) => /^initialiserLike \(.*\) over every erasure file with a wipe span: (\d+) files, (\d+) spans$/.exec(l)).find(Boolean);
  assert.ok(head, 'no initialiserLike line in the results text');
  const count = (kind) => resultLines.reduce((n, l) => {
    const m = new RegExp(`^ {2}${kind}:(?:true|false|null) +(\\d+)$`).exec(l);
    return n + (m ? Number(m[1]) : 0);
  }, 0);
  const p = flat(section('Per-span supplement'));
  // the agreement counts in the same sentence come from label-check.mjs, a lab-only run, and are not pinned here
  const m = /Over (\d+) files and (\d+) spans, the (\d+) removable spans: [^;]*; the (\d+) nonremovable spans have no site/.exec(p);
  assert.ok(m, 'the initialiserLike cross-check sentence is no longer there');
  assert.deepEqual(m.slice(1).map(Number), [Number(head[1]), Number(head[2]), count('removable'), count('nonremovable')]);
  assert.equal(count('removable') + count('nonremovable'), Number(head[2]));

  const one = /`(\w+)` and `(\w+)`, whose only span is a `memset` before the buffer is filled, come out initialiser-like/.exec(p);
  assert.ok(one, 'the one-span initialiser sentence is no longer there');
  const at = resultLines.findIndex((l) => l.startsWith('  one-span files whose only span is initialiser-like'));
  assert.ok(at >= 0);
  const listed = [];
  for (let i = at + 1; i < resultLines.length && resultLines[i].startsWith('    '); i++) listed.push(resultLines[i].trim());
  assert.match(resultLines[at], new RegExp(`: ${listed.length}$`));
  assert.deepEqual(listed, one.slice(1));
});

test('the README\'s cross-check numbers are the ones data/r2-span-results.txt printed', () => {
  assert.deepEqual(Object.keys(CROSS), [...VENDORS]);
  // and the text's counts are the rows': every span measured alone was compared or
  // counted as not compared, and every measured cell had its hiddenElimination compared
  for (const cc of VENDORS) {
    assert.equal(CROSS[cc][0] + CROSS[cc][2], spansMeasuredAlone(spanRows, cc), `${cc}: spans measured alone`);
    assert.equal(CROSS[cc][3], spanRows.filter((r) => r.cc === cc && r.measured).length, `${cc}: measured cells`);
  }
  const p = flat(section('Per-span supplement'));
  const m = /Re-derived cell verdicts agreeing with the tracked rows: (\d+)\/(\d+)\. Cross-check against the repair rows, per vendor: `clang-18` (\d+) span verdicts compared, (\d+) agree, (\d+) `hiddenElimination` flags compared, (\d+) disagree; `gcc-13` the same, (\d+)\/(\d+) and (\d+) with (\d+) disagreeing\./.exec(p);
  assert.ok(m, 'the cross-check sentence is no longer there');
  // "770/770" and "835/835" read as agreeing / compared
  const [agreeCells, cells, cC, cA, cH, cD, gA, gC, gH, gD] = m.slice(1).map(Number);
  const cmp = spanRows.filter((r) => r.cellMatchesTracked !== null);
  assert.deepEqual([agreeCells, cells], [cmp.filter((r) => r.cellMatchesTracked).length, cmp.length]);
  const pick = (cc) => [CROSS[cc][0], CROSS[cc][1], CROSS[cc][3], CROSS[cc][4]];
  assert.deepEqual([cC, cA, cH, cD], pick('clang-18'));
  assert.deepEqual([gC, gA, gH, gD], pick('gcc-13'));
});

test('the repair loop\'s clang-18 count the supplement starts from is the rows\' clang-18 hidden eliminations', () => {
  const p = flat(section('Per-span supplement'));
  const m = /found (\d+) such `clang-18` cells in (\d+) files; `gcc-13` had not been looked at before this supplement/.exec(p);
  assert.ok(m, 'the Why paragraph no longer quotes the repair loop\'s clang-18 count');
  const hidden = spanRows.filter((r) => r.cc === 'clang-18' && r.hiddenElimination);
  assert.deepEqual(m.slice(1).map(Number), [hidden.length, new Set(hidden.map((r) => r.id)).size]);
  // The repair loop's rows file is not read here. What makes this its count is
  // the cross-check the same run printed: the two hiddenElimination flags were
  // compared on every measured clang-18 cell, against the repair rows whose
  // sha256 the text records, and none disagreed. Every other cell is a one-span
  // cell or has no removable span, so neither lane ablates a span of it alone
  // and neither can flag it.
  assert.deepEqual([CROSS['clang-18'][3], CROSS['clang-18'][4]],
    [spanRows.filter((r) => r.cc === 'clang-18' && r.measured).length, 0]);
  assert.ok(hidden.every((r) => r.measured));
});

// --- every row count the README states, against the rows themselves -----------
//
// The round-2 build-verdict count was mistyped TWICE in this one file: the
// summary table said 4,660 where the rows carry 4,650 cells, and the Re-running
// section said build-analyze.mjs writes 4,698 rows where it writes 4,689. Both
// were found by recounting, months apart, and neither was reachable by any test
// -- the prose was simply not joined to the data. It is now. A denominator is the
// one number a rate table may not be wrong about, and eval/actuarial/ derives its
// rates from exactly these rows.

test('every row count the README prints is the count the rows file actually has', () => {
  const rows = Array.isArray(build) ? build : build.rows;
  const total = rows.length;
  const withCell = rows.filter((r) => r && r.cc && r.opt).length;

  // the Re-running section: what build-analyze.mjs writes
  const reRun = README.match(/node build-analyze\.mjs\s+#\s+([\d,]+) rows/);
  assert.ok(reRun, 'the Re-running section no longer states a row count for build-analyze.mjs');
  assert.equal(Number(reRun[1].replace(/,/g, '')), total,
    `README says build-analyze.mjs writes ${reRun[1]} rows; data/r2-build-rows.json has ${total}`);

  // the summary table: build verdicts, which is the (cc, opt) cell count
  const verdicts = README.match(/\|\s*build verdicts\s*\|[^|]*\|\s*\*\*([\d,]+)\*\*\s*\|/);
  assert.ok(verdicts, 'the summary table no longer states a build-verdict count');
  assert.equal(Number(verdicts[1].replace(/,/g, '')), withCell,
    `README says ${verdicts[1]} build verdicts; ${withCell} rows carry a (cc, opt) cell`);

  // and the two are not the same number, which is the thing the correction note
  // explains -- if they ever became equal the note would be describing nothing
  assert.notEqual(total, withCell);
  assert.equal(total - withCell, rows.filter((r) => r && !(r.cc && r.opt)).length);
});

test('the corrected numbers are stated in the README, and the wrong ones only as corrections', () => {
  const rows = Array.isArray(build) ? build : build.rows;
  const total = String(rows.length).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  // 4,660 and 4,698 may still appear -- the note records what was wrong -- but
  // each must be inside a sentence that says so, never left standing as a fact.
  for (const wrong of ['4,660', '4,698']) {
    const idx = README.indexOf(wrong);
    if (idx < 0) continue;
    const around = README.slice(Math.max(0, idx - 400), idx + 400);
    assert.match(around, /said|Corrected|mistyping|transcription/,
      `${wrong} appears in README.md outside any correction note`);
  }
  assert.ok(README.includes(total), `README.md never states the real row count ${total}`);
});
