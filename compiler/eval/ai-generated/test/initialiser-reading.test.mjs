/**
 * initialiserLike read over every removable span of every wipe file, beside the
 * find step's labelling: which files wrote no removable wipe by that reading,
 * and what the idiom table and the memset row read with them moved. The tracked
 * table, the rows and every verdict stay as they are. These tests compute the
 * reading from the corpus and the tracked rows, with nothing but wipeSpans and
 * the label, and pin the README's sentences that quote it. No compiler: the
 * plugin's agreement on the same spans comes from label-check.mjs, a lab run,
 * and is not pinned here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { wipeSpans } from '../lib/ablation-cell.mjs';
import { initialiserLabels, initialiserOnly } from '../lib/span-label.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const GEN = join(ROOT, 'generated-corpus', 'r2');
const ROWS = JSON.parse(readFileSync(join(ROOT, 'data', 'r2-build-rows.json'), 'utf8'));
const README = readFileSync(join(ROOT, 'README.md'), 'utf8').replace(/\s+/g, ' ');

// one entry per erasure-family file: framing, target, the tracked idiom ('none' for a no-wipe file)
const FILES = new Map();
for (const r of ROWS) {
  if (r.fam !== 'erasure' || FILES.has(r.id)) continue;
  FILES.set(r.id, { id: r.id, framing: r.framing, fn: r.fn, idiom: r.kind === 'none' ? 'none' : r.idiom });
}
const idiomOf = (kinds) => (kinds.includes('removable') ? (kinds.includes('nonremovable') ? 'both' : 'removable') : 'nonremovable');
const read = new Map();
for (const f of FILES.values()) {
  if (f.idiom === 'none') continue;
  const src = readFileSync(join(GEN, `${f.id}.c`), 'utf8');
  const w = wipeSpans(src, f.fn);
  const labels = initialiserLabels(src, f.fn, w.spans);
  read.set(f.id, { kinds: w.kinds, labels, onlyInit: initialiserOnly(w.kinds, labels) });
}
const onlyInit = [...read.entries()].filter(([, r]) => r.onlyInit).map(([id]) => id).sort();
const pct = (x) => `${(100 * x).toFixed(1)}%`;

test('initialiserOnly: every removable span initialiser-like, at least one, and a null is not a yes', () => {
  assert.equal(initialiserOnly(['removable'], [true]), true);
  assert.equal(initialiserOnly(['removable', 'nonremovable'], [true, false]), true);
  assert.equal(initialiserOnly(['removable', 'removable'], [true, false]), false);
  assert.equal(initialiserOnly(['removable'], [null]), false);
  assert.equal(initialiserOnly(['nonremovable'], [true]), false);
  assert.equal(initialiserOnly([], []), false);
});

test('the idiom the kinds give is the tracked idiom, for every wipe file', () => {
  assert.equal(read.size, 321);
  for (const [id, r] of read) assert.equal(idiomOf(r.kinds), FILES.get(id).idiom, id);
});

test('26 files wrote no removable wipe by the label: the 2 memset files the README names and 24 of the 26 both files', () => {
  const by = (idiom) => onlyInit.filter((id) => FILES.get(id).idiom === idiom);
  assert.deepEqual(by('removable'), ['opus_N_pinpad_r2', 'sonnet_S_privkey_r3']);
  assert.equal(by('both').length, 24);
  assert.equal([...FILES.values()].filter((f) => f.idiom === 'both').length, 26);
  assert.equal(onlyInit.length, 26);
  const spans = onlyInit.reduce((n, id) => n + read.get(id).kinds.filter((k) => k === 'removable').length, 0);
  assert.equal(spans, 31);
  assert.ok(README.includes('26 of these files wrote no removable wipe'), 'README: the count of initialiser-only files');
  assert.ok(README.includes('24 of the 26 `both` files and in 2 `memset` files'), 'README: their split by idiom');
  assert.ok(README.includes('all 31 of their removable spans'), 'README: their removable span count');
});

test('chose removable per framing: the tracked table, and the reading with those 26 files moved out', () => {
  const table = (moved) => Object.fromEntries(['N', 'S', 'E'].map((fr) => {
    const fs = [...FILES.values()].filter((f) => f.framing === fr);
    const rem = fs.filter((f) => (f.idiom === 'removable' || f.idiom === 'both') && !(moved && read.get(f.id).onlyInit)).length;
    return [fr, pct(rem / fs.length)];
  }));
  assert.deepEqual(table(false), { N: '57.5%', S: '45.8%', E: '29.2%' }, 'the tracked table');
  const reading = table(true);
  assert.deepEqual(reading, { N: '56.7%', S: '33.3%', E: '20.8%' });
  assert.ok(README.includes(`would read **${reading.N} / ${reading.S} / ${reading.E}** (N / S / E)`), 'README: the reading');
});

test('the memset row with the two memset files moved: numerators unchanged, denominator 262', () => {
  for (const id of ['opus_N_pinpad_r2', 'sonnet_S_privkey_r3']) {
    const cells = ROWS.filter((r) => r.kind === 'erasure' && r.id === id);
    assert.equal(cells.length, 10, id);
    assert.ok(cells.every((r) => r.verdict === 'WIPE_SURVIVED'), `${id} reads WIPE_SURVIVED at every level on both vendors`);
  }
  const removable = ROWS.filter((r) => r.kind === 'erasure' && r.idiom === 'removable' && r.opt === '-O2');
  assert.equal(removable.length, 266);
  assert.equal(removable.filter((r) => r.verdict === 'WIPE_ELIMINATED').length, 221);
  assert.ok(README.includes('221/262 at `-O2`'), 'README: the memset row with the two moved');
});
