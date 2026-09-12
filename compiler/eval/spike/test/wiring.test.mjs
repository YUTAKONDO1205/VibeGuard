/**
 * The README's table of call sites, held to the tree it describes.
 *
 * WHY
 *
 *   The "What is gated, and what is not" table said "nothing calls this gate"
 *   in the same commit that wired four callers, and when that was corrected the
 *   replacement carried line numbers that were stale within the hour: two of
 *   the files it cites had grown fifty lines the same day, so `:33` pointed at
 *   an unrelated import and `:318-327` at the end of an environment builder.
 *   Both times the table was the only record of where the gate is called, and
 *   both times it was wrong in a way no test could see.
 *
 *   So the table is a claim like any other. This file checks three things about
 *   it: every line it cites says what it is cited for, every file in the tree
 *   that calls the gate is in the table, and no file the table marks "correctly
 *   not gated" calls it after all.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO: check the prose. Whether the observer's
 * run-all is the same instrument, and whether calibration's own falsifier is
 * equivalent, are judgements. They are argued in the README and cannot be
 * asserted here without turning an argument into a regex.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');
const COMPILER = path.resolve(LANE, '../..');
const README = readFileSync(path.join(LANE, 'README.md'), 'utf8').replace(/\r\n/g, '\n');

/** Rows of the gating table: [file, gated?, cites]. */
function tableRows() {
  const rows = [];
  for (const line of README.split('\n')) {
    const m = /^\|\s*`([^`]+\.(?:mjs|sh))`\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|$/.exec(line)
      || /^\|\s*`(compiler\/eval\/second-vendor|compiler\/eval\/metamorphic)`\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|$/.exec(line);
    if (m) rows.push({ file: m[1], gated: m[2], cites: m[3] });
  }
  return rows;
}

const rows = tableRows();
const yes = rows.filter((r) => /\*\*yes/i.test(r.gated));
const no = rows.filter((r) => /\*\*no/i.test(r.gated));

/** Repo-wide: every file under compiler/ that actually calls runSpikeGate. */
function callers(dir = COMPILER, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (['node_modules', '_build', 'dist', '_results', 'generated-corpus'].includes(e.name)) continue;
      callers(p, out);
    } else if (/\.(mjs|sh)$/.test(e.name)) {
      const text = readFileSync(p, 'utf8');
      // The lane's own runner and its tests are where the gate is defined and
      // exercised; a harness is a file that imports it or shells out to it.
      const rel = path.relative(path.resolve(COMPILER, '..'), p).split(path.sep).join('/');
      if (rel.startsWith('compiler/eval/spike/')) continue;
      // A CALL, not a mention. compiler/eval/oracle-agreement/lib/agreement.mjs
      // names run-spike.mjs in a comment about where a decision is made, and an
      // earlier version of this test reported it as an unlisted caller.
      const imports = /import\s[^;]*from\s*['"][^'"]*spike\/lib\/gate\.mjs['"]/.test(text);
      const shellsOut = text.split('\n').some((l) => /run-spike\.mjs/.test(l)
        && !/^\s*(#|\/\/|\*|\/\*)/.test(l));
      if (imports || shellsOut) out.push(rel);
    }
  }
  return out;
}

test('the table is a table: some rows gated, some not', () => {
  assert.ok(rows.length >= 8, `found ${rows.length} rows`);
  assert.ok(yes.length >= 5, `found ${yes.length} gated rows`);
  assert.ok(no.length >= 3, `found ${no.length} ungated rows`);
});

test('every line the table cites says what it is cited for', () => {
  for (const row of yes) {
    const target = path.resolve(COMPILER, '..', row.file);
    assert.doesNotThrow(() => statSync(target), `${row.file} does not exist`);
    const lines = readFileSync(target, 'utf8').replace(/\r\n/g, '\n').split('\n');
    const cited = [...row.cites.matchAll(/`:(\d+)`/g)].map((m) => Number(m[1]));
    const ranges = [...row.cites.matchAll(/`:(\d+)-(\d+)`/g)];
    assert.ok(cited.length + ranges.length >= 1, `${row.file}: the table cites no line`);
    for (const n of cited) {
      const text = lines[n - 1];
      assert.ok(text !== undefined, `${row.file}:${n} is past the end of the file`);
      const says = /runSpikeGate|run-spike\.mjs|spike/.test(text)
        || /exit\(3|die\(3|die\(2|exit \$s|STOPPED/.test(text);
      assert.ok(says, `${row.file}:${n} is cited by the gating table and reads:\n    ${text.trim()}`);
    }
    // A range like :80-92 is cited as a block; require the block to hold the call.
    for (const m of row.cites.matchAll(/`:(\d+)-(\d+)`/g)) {
      const block = lines.slice(Number(m[1]) - 1, Number(m[2])).join('\n');
      assert.match(block, /runSpikeGate|run-spike\.mjs/, `${row.file}:${m[1]}-${m[2]} holds no call to the gate`);
    }
  }
});

test('every file in the tree that calls the gate is in the table', () => {
  const found = callers();
  const named = new Set(yes.map((r) => r.file));
  const missing = found.filter((f) => !named.has(f));
  assert.deepEqual(missing, [],
    `these call the gate and the table does not list them:\n  ${missing.join('\n  ')}`);
});

test('no harness the table calls ungated is calling the gate after all', () => {
  const found = new Set(callers());
  for (const row of no) {
    assert.equal(found.has(row.file), false,
      `${row.file} is in the "correctly not gated" half of the table and calls the gate`);
  }
});
