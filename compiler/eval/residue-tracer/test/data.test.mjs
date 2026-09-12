/**
 * The README's numbers, recomputed from the rows the full run wrote.
 *
 * WHY
 *
 *   Until 2026-09-12 this lane had no data/ directory. `--write-data` was
 *   implemented and had never been passed, so every number in README.md was a
 *   quote from a run log: nothing in the tree could tell a number that had
 *   drifted from one that had not, and a later run that read differently would
 *   have left the old sentences standing. version-ladder, lto-window, actuarial
 *   and repair-loop all hold their prose to a tracked record; this file is that
 *   for residue-tracer.
 *
 * WHAT IS PINNED, AND WHAT MUST NEVER BE
 *
 *   Pinned: the cross-tab, the graded/excluded counts, the three controls and
 *   their cell counts, the identity of the cells that left the secret readable,
 *   and the claim the lane is for -- that every stock cell reading FULL reads
 *   NONE under the repair arm.
 *
 *   NOT pinned, deliberately: `longestRunBytes` (the coincidence rate for a
 *   32-byte needle in a 4 kB window, which is redrawn every run -- README's
 *   "The headline" says so), `window.lo`/`hi` and the `stop` addresses (per-run,
 *   and the README records that ADDR_NO_RANDOMIZE does not take effect on this
 *   kernel), and every sha256 of a binary (they move with the compiler and the
 *   plugin builds, which is not drift in the measurement). A test that pinned
 *   those would fail for reasons that are not findings, and would be deleted
 *   the first time it did.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const text = (rel) => readFileSync(path.join(ROOT, rel), 'utf8').replace(/\r\n/g, '\n');

const README = text('README.md');
const dataFiles = readdirSync(path.join(ROOT, 'data')).filter((f) => f.endsWith('.json')).sort();
const rows = JSON.parse(text(path.join('data', dataFiles[0])));

const subjects = rows.filter((r) => r.kind === 'subject');
const controls = rows.filter((r) => r.kind === 'control');
const graded = subjects.filter((r) => r.measurement === 'OK');
const excluded = subjects.filter((r) => r.measurement !== 'OK');

/**
 * The README's cross-tab block, parsed rather than trusted.
 *
 * There are two of them. The first is the six-cell run of the earlier day, kept
 * as the record of what was done then, and its `excluded: 6 x plugin-absent` is
 * part of that record. The one this file is about is the full matrix, so the
 * section heading is where the search starts -- a test that took the first
 * table it found would hold the rows to a run they are not.
 */
function readmeCrossTab() {
  const section = README.split('## The full matrix, both arms')[1];
  assert.ok(section, 'the full-matrix section this record belongs to is gone from the README');
  const m = section.match(/confirm verdict\s+residue NONE\s+PARTIAL\s+FULL\n(WIPE_SURVIVED\s+\d+\s+\d+\s+\d+)\n(WIPE_ELIMINATED\s+\d+\s+\d+\s+\d+)\ngraded cells: (\d+)\s+excluded: (\S+)/);
  assert.ok(m, 'the README no longer prints a full-matrix cross-tab in the shape this test reads');
  const nums = (line) => line.trim().split(/\s+/).slice(1).map(Number);
  return { survived: nums(m[1]), eliminated: nums(m[2]), graded: Number(m[3]), excluded: m[4] };
}

test('the data file is one full matrix: 60 graded subject cells, nothing excluded', () => {
  assert.equal(dataFiles.length, 1, `expected one tracked rows file, found ${dataFiles.join(', ')}`);
  assert.equal(subjects.length, 60, '3 idioms x 2 vendors x 5 levels x 2 arms');
  assert.equal(excluded.length, 0, `--write-data is refused for a partial matrix, so an excluded cell here is a bug: ${excluded.map((r) => r.cell).join(', ')}`);
  assert.equal(new Set(subjects.map((r) => r.cell)).size, 60, 'a cell was measured twice');
});

test('the cross-tab the README prints is the one the rows hold', () => {
  const tab = { WIPE_SURVIVED: { NONE: 0, PARTIAL: 0, FULL: 0 }, WIPE_ELIMINATED: { NONE: 0, PARTIAL: 0, FULL: 0 } };
  for (const r of graded) {
    assert.ok(tab[r.confirmVerdict], `a verdict the cross-tab has no column for: ${r.confirmVerdict} (${r.cell})`);
    tab[r.confirmVerdict][r.residue.stack] += 1;
  }
  const readme = readmeCrossTab();
  assert.deepEqual([tab.WIPE_SURVIVED.NONE, tab.WIPE_SURVIVED.PARTIAL, tab.WIPE_SURVIVED.FULL], readme.survived);
  assert.deepEqual([tab.WIPE_ELIMINATED.NONE, tab.WIPE_ELIMINATED.PARTIAL, tab.WIPE_ELIMINATED.FULL], readme.eliminated);
  assert.equal(graded.length, readme.graded);
  assert.equal(readme.excluded, 'none');

  // The two cells the lane exists to be able to report, held at zero by the
  // rows themselves rather than by the sentence under the table.
  assert.equal(tab.WIPE_SURVIVED.PARTIAL + tab.WIPE_SURVIVED.FULL, 0,
    'a FINDING appeared: confirm says the wipe survived and the secret was readable. The README sentence saying there is none is now false');
  assert.equal(tab.WIPE_ELIMINATED.NONE, 0,
    'an ANOMALY appeared: the wipe was eliminated and nothing was readable. That is not good news and the README says so');
});

test('every control held, over the cell counts the README states', () => {
  const byControl = {};
  for (const r of controls) {
    byControl[r.control] ??= { cells: 0, residues: new Set(), held: true };
    byControl[r.control].cells += 1;
    byControl[r.control].residues.add(r.residue.stack);
    if (!r.controlHeld) byControl[r.control].held = false;
  }
  const expected = { 'control-retain': ['FULL', 10], 'control-nosecret': ['NONE', 10], 'control-o0-wiped': ['NONE', 2] };
  assert.deepEqual(Object.keys(byControl).sort(), Object.keys(expected).sort());
  for (const [name, [residue, cells]] of Object.entries(expected)) {
    const got = byControl[name];
    assert.equal(got.held, true, `${name} did not hold; the run should have been INVALID_RUN and written nothing`);
    assert.equal(got.cells, cells, `${name} over ${got.cells} cells, README says ${cells}`);
    assert.deepEqual([...got.residues], [residue], `${name} read ${[...got.residues].join('/')}, README says ${residue}`);
    assert.ok(README.includes(`HELD  ${name}`.replace(/\s+/g, ' ')) || new RegExp(`HELD\\s+${name}\\s+${residue}`).test(README),
      `the README no longer records ${name} as held`);
  }
});

test('the seven readable cells are the seven the README names, and all seven are memset', () => {
  const readable = graded.filter((r) => r.arm === 'stock' && r.residue.stack === 'FULL').map((r) => r.cell).sort();
  assert.equal(readable.length, 7);
  for (const cell of readable) {
    const [, cc, opt, idiom] = cell.split('/');
    assert.equal(idiom, 'memset', `${cell} is readable and is not the memset idiom; the README's "All seven are the memset idiom" is stale`);
    assert.ok(new RegExp(`${cc}\\s*\\|?\\s*${opt}\\s+memset`).test(README) || README.includes(`${cc} ${opt} memset`),
      `the README's table of readable cells does not name ${cc} ${opt} memset`);
  }
});

test('7 of 7: every stock cell that left the secret readable reads NONE under the repair arm', () => {
  const byCell = new Map(graded.map((r) => [`${r.arm}/${r.cc}/${r.opt}/${r.subject}`, r]));
  const flipped = [];
  for (const r of graded) {
    if (r.arm !== 'stock' || r.residue.stack !== 'FULL') continue;
    const pinned = byCell.get(`wipepin/${r.cc}/${r.opt}/${r.subject}`);
    assert.ok(pinned, `no repair-arm cell to pair with ${r.cell}: the matrix is not the full one`);
    assert.equal(pinned.residue.stack, 'NONE', `${pinned.cell} still reads ${pinned.residue.stack}; the README's "0 readable" under WipePin is stale`);
    assert.equal(pinned.confirmVerdict, 'WIPE_SURVIVED');
    flipped.push(r.cell);
  }
  assert.equal(flipped.length, 7);
  const stockSubjects = graded.filter((r) => r.arm === 'stock').length;
  assert.equal(stockSubjects, 30);
  assert.ok(README.includes('30 stock subject cells, 7 readable'),
    'the README sentence these numbers belong to is gone or reworded');
});

test('nothing per-run is pinned by this file, and the README says which values are per-run', () => {
  const self = readFileSync(path.join(HERE, 'data.test.mjs'), 'utf8');
  for (const forbidden of ['longestRunBytes', 'sha256Before', 'asmSha256', 'window.lo']) {
    const uses = self.split('\n').filter((l) => l.includes(forbidden) && !l.trim().startsWith('*') && !l.includes('forbidden'));
    assert.deepEqual(uses, [], `this test reads ${forbidden}, which changes between runs for reasons that are not drift`);
  }
  assert.match(README, /ADDR_NO_RANDOMIZE/);
});
