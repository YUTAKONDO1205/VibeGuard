/**
 * The tracked repair data, read-only: the two results texts, the two rows files,
 * the find step's rows they are scored against, and the README that quotes them.
 *
 * Each results text names the other vendor's rows by the sha256 they had when its
 * run read them. Rewriting one rows file (a new column, a re-record) leaves the
 * other text naming bytes that are gone, and nothing in either run notices; the
 * README quotes both digests again by hand. These tests hold the texts, the rows
 * and the README to each other, and count "reversed / found" from the rows with
 * nothing but the definition (found: a find-step erasure row WIPE_ELIMINATED;
 * reversed: a found cell whose repair row is RETAINED), so the numbers do not come
 * from the code that printed them. No compiler, no lab.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { dataFileNames, fullRunCheck } from '../lib/vendor.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');
const REPO = path.resolve(LANE, '..', '..', '..');
const DATA = path.join(LANE, 'data');
const FIND_ROWS = path.resolve(LANE, '..', 'ai-generated', 'data', 'r2-build-rows.json');
const README = path.join(LANE, 'README.md');
const OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const VENDORS = ['clang-18', 'gcc-13'];

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const rowsFile = (cc) => path.join(DATA, dataFileNames(cc).rows);
const resultsFile = (cc) => path.join(DATA, dataFileNames(cc).results);
const readRows = (cc) => JSON.parse(readFileSync(rowsFile(cc), 'utf8'));
const readResults = (cc) => readFileSync(resultsFile(cc), 'utf8');
const findRows = JSON.parse(readFileSync(FIND_ROWS, 'utf8'));
const other = (cc) => VENDORS.find((v) => v !== cc);

/** found / reversed for one compiler, from the definition. */
function counted(cc) {
  const found = findRows.filter((r) => r.kind === 'erasure' && r.cc === cc && r.verdict === 'WIPE_ELIMINATED');
  const outcome = new Map(readRows(cc).filter((r) => r.kind === 'erasure').map((r) => [`${r.id}|${r.opt}`, r.outcome]));
  const reversed = found.filter((r) => outcome.get(`${r.id}|${r.opt}`) === 'RETAINED').length;
  return { found: found.length, reversed };
}

/** The one "eliminations reversed / found" line of a results text. */
function coverageLine(text) {
  const lines = text.split('\n').filter((l) => l.includes('eliminations reversed / found:'));
  assert.equal(lines.length, 1, 'a results text holds exactly one cross-vendor coverage line');
  return lines[0];
}

/** "8 hex … 6 hex" as the README abbreviates a digest; checked against the full one. */
function abbreviates(abbrev, full) {
  const m = /^([0-9a-f]{6,})…([0-9a-f]{4,})$/.exec(abbrev);
  return !!m && full.startsWith(m[1]) && full.endsWith(m[2]);
}

test('each results text names the other vendor\'s rows by the sha256 those rows have now', () => {
  for (const cc of VENDORS) {
    const line = coverageLine(readResults(cc));
    const m = /tracked repair rows (\S+), sha256 ([0-9a-f]{64}), a full --write-data run/.exec(line);
    assert.ok(m, `${dataFileNames(cc).results} does not name the ${other(cc)} rows as a full run: ${line}`);
    const [, label, quoted] = m;
    assert.equal(path.resolve(REPO, label), rowsFile(other(cc)), `${dataFileNames(cc).results} names ${label}`);
    assert.equal(quoted, sha256(readFileSync(rowsFile(other(cc)))),
      `${dataFileNames(cc).results} quotes ${other(cc)}'s rows as ${quoted.slice(0, 8)}…, which is no longer the file: re-run that vendor with --write-data after the other one`);
  }
});

test('the reversed / found counts each results text prints are the rows\' own', () => {
  const c = Object.fromEntries(VENDORS.map((cc) => [cc, counted(cc)]));
  // a vacuous pass would need both sides empty; the corpus has found cells for both
  for (const cc of VENDORS) assert.ok(c[cc].found > 0, `no ${cc} elimination found in the find step's rows`);
  for (const cc of VENDORS) {
    const line = coverageLine(readResults(cc));
    assert.ok(line.includes(`${cc} ${c[cc].reversed}/${c[cc].found} (this run)`), `${cc}'s own part of: ${line}`);
    const o = other(cc);
    assert.ok(line.includes(`${o} ${c[o].reversed}/${c[o].found} (tracked repair rows`), `${o}'s part of: ${line}`);
    const total = c[cc].reversed + c[o].reversed, found = c[cc].found + c[o].found;
    assert.ok(line.endsWith(`, total ${total}/${found}`), `the total of: ${line}`);
  }
});

test('the tracked rows are full --write-data runs, one compiler each', () => {
  const erasureIds = [...new Set(findRows.filter((r) => r.fam === 'erasure').map((r) => r.id))];
  assert.ok(erasureIds.length > 0);
  for (const cc of VENDORS) {
    const r = fullRunCheck(readRows(cc), { cc, allOpts: OPTS, erasureIds });
    assert.deepEqual(r, { full: true, why: [] }, `${dataFileNames(cc).rows}`);
  }
});

test('the README quotes the plugin digests the results texts carry, and the rows digest the gcc-13 text reads', () => {
  const readme = readFileSync(README, 'utf8');
  const pluginOf = (cc) => {
    const m = /^plugin sha256[ \t]+([0-9a-f]{64})[ \t]*$/m.exec(readResults(cc));
    assert.ok(m, `${dataFileNames(cc).results} prints no plugin sha256`);
    return m[1];
  };
  const quote = (re, what) => {
    const m = re.exec(readme);
    assert.ok(m, `the README no longer quotes ${what}; this test pins that sentence, so change both together`);
    return m[1];
  };
  const clangPlugin = quote(/`libWipePin\.so` sha256 `([0-9a-f]+…[0-9a-f]+)`/, 'the WipePin build of its clang-18 results');
  assert.ok(abbreviates(clangPlugin, pluginOf('clang-18')), `README WipePin ${clangPlugin}, results ${pluginOf('clang-18')}`);
  const gccPlugin = quote(/`libWipePinGcc\.so` sha256 `([0-9a-f]+…[0-9a-f]+)`/, 'the WipePinGcc build of its gcc-13 results');
  assert.ok(abbreviates(gccPlugin, pluginOf('gcc-13')), `README WipePinGcc ${gccPlugin}, results ${pluginOf('gcc-13')}`);
  const clangRows = quote(/from the tracked clang-18 rows, sha256 `([0-9a-f]+…[0-9a-f]+)`/, 'the clang-18 rows the gcc-13 results read');
  assert.ok(abbreviates(clangRows, sha256(readFileSync(rowsFile('clang-18')))), `README clang-18 rows ${clangRows}`);
});

test('abbreviates: prefix and suffix must both match, and the form is hex … hex', () => {
  const full = 'a023b047abcafdbb824f627d227861e0ae0556072c9e4ba87e102b2c9747ba1b';
  assert.equal(abbreviates('a023b047…47ba1b', full), true);
  assert.equal(abbreviates('a023b047…47ba1c', full), false);
  assert.equal(abbreviates('954b5b58…47ba1b', full), false);
  assert.equal(abbreviates('a023b047...47ba1b', full), false);
  assert.equal(abbreviates('a023b047', full), false);
});
