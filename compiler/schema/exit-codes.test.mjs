/**
 * The contract test for interfaces.md section 7 -- the exit-code table.
 *
 * WHY THIS FILE
 *
 * Section 7 opens with "Shared by every executable here, so that a caller can
 * branch without knowing which component ran". Until 2026-09-13 nothing checked
 * that, in either direction, and both directions had already failed:
 *
 *   - exit 5 was in use at 100 sites across 14 files under compiler/, and exit 6 at
 *     one, and the table listed 0-4. A caller branching on the table would have
 *     read a harness refusing to write a record as an unrecognised code.
 *   - nothing would have noticed a row whose code no component emits, which is a
 *     contract a reader is entitled to rely on and nobody keeps.
 *
 * Section 3.1 has had exactly this test since it was written
 * (measurement-vocabulary.test.mjs, whose table parse this one copies). Section 7
 * had the same need and none.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED: that a given component emits a given code, or
 * that two lanes agree about which code a situation deserves. They do not always --
 * section 7 now names the two known departures in its own text. The claim here is
 * narrower and mechanical: the table and the tree carry the same SET of codes.
 *
 * Nothing here runs a compiler, a harness or a shell. It reads tracked files.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');
const INTERFACES = path.join(HERE, 'interfaces.md');

/**
 * Files that exit with codes section 7 does not govern, with the reason each one
 * is exempt. Kept short on purpose: every entry is a hole in this test, so an
 * entry has to be justified by the file NOT being one of "every executable here".
 */
const NOT_A_COMPONENT = new Map([
  ['compiler/driver/test/observer-fixture.mjs',
    'a stand-in for an EXTERNAL observer tool, whose job is to fail in ways the '
    + 'driver has to survive. Its exit codes are a third party\'s, which is why it '
    + 'uses 7 -- a number section 7 deliberately does not define.'],
]);

/** The codes in the first column of section 7's table, in table order. */
function tableCodes() {
  const text = readFileSync(INTERFACES, 'utf8');
  const start = text.indexOf('\n## 7. Exit codes');
  assert.notEqual(start, -1,
    'interfaces.md has no section 7; the contract this file tests is gone');
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n## ');
  const section = end === -1 ? rest : rest.slice(0, end);
  const rows = [...section.matchAll(/^\|\s*(\d+)\s*\|/gm)].map((m) => Number(m[1]));
  assert.ok(rows.length >= 5,
    `section 7's table parsed to ${rows.length} row(s); the parse, not the contract, is what `
    + 'broke -- 7 rows were there when this fence was written');
  return { section, codes: rows };
}

/**
 * Every literal exit code in a tracked source file under compiler/.
 *
 * Comment lines are stripped first, so a code DISCUSSED in prose is not counted as
 * one emitted -- every README in this tree explains its codes, and counting those
 * would make the test assert over documentation.
 *
 * `return N` is counted only in files that use the `process.exit(main(...))` idiom,
 * where a returned integer IS the exit code (compiler/eval/negative-controls does
 * this). Counting `return N` everywhere would sweep up every helper that returns a
 * number and make this test meaningless.
 */
function treeCodes() {
  const files = execFileSync('git', ['ls-files', 'compiler'], { cwd: REPO, encoding: 'utf8' })
    .split('\n')
    .filter((f) => /\.(mjs|js|cjs|ts|py|sh)$/.test(f))
    .filter((f) => !NOT_A_COMPONENT.has(f));

  const sites = new Map(); // code -> Map(file -> count)
  const note = (code, file) => {
    if (!sites.has(code)) sites.set(code, new Map());
    const m = sites.get(code);
    m.set(file, (m.get(file) || 0) + 1);
  };

  for (const f of files) {
    let raw;
    try { raw = readFileSync(path.join(REPO, f), 'utf8'); } catch { continue; }
    const src = raw.split(/\r?\n/).filter((l) => !/^\s*(\/\/|#|\*)/.test(l)).join('\n');
    for (const re of [
      /\bprocess\.exit\(\s*(\d+)\s*\)/g,
      /\bdie\(\s*(\d+)\s*,/g,
      /\bsys\.exit\(\s*(\d+)\s*\)/g,
      /^\s*exit\s+(\d+)\s*(?:;|$)/gm,
    ]) {
      for (const m of src.matchAll(re)) note(Number(m[1]), f);
    }
    if (/process\.exit\(\s*main\(/.test(src)) {
      // Not anchored to the start of a line: compiler/eval/negative-controls writes
      // `if (toolFailures > 0) return 5;`, and an anchored pattern missed the one
      // site in the tree that this clause exists for. Measured across the 12 files
      // using this idiom, the unanchored form adds no integer return that is not an
      // exit code.
      for (const m of src.matchAll(/\breturn\s+(\d+)\s*;/g)) note(Number(m[1]), f);
    }
  }
  return sites;
}

test('section 7 defines every exit code the tree actually emits', () => {
  const { codes } = tableCodes();
  const sites = treeCodes();
  assert.ok(sites.size >= 5,
    `the scan found ${sites.size} distinct exit code(s) under compiler/; it found 7 when this `
    + 'fence was written, so the SCAN broke rather than the tree');

  const undocumented = [...sites.keys()].filter((c) => !codes.includes(c)).sort((a, b) => a - b);
  const detail = undocumented.map((c) => {
    const m = sites.get(c);
    const total = [...m.values()].reduce((a, b) => a + b, 0);
    return `  exit ${c}: ${total} site(s) in ${m.size} file(s), e.g. ${[...m.keys()].sort()[0]}`;
  }).join('\n');
  assert.deepEqual(undocumented, [],
    'exit codes emitted under compiler/ that interfaces.md section 7 does not define. A caller '
    + 'cannot "branch without knowing which component ran" on a code the table omits -- add a '
    + `row, or change the site to a code the table already carries:\n${detail}`);
});

test('section 7 defines no exit code nothing emits', () => {
  // The other direction. A row for a code no component produces is a contract a
  // reader is entitled to rely on and nobody keeps, and it is the shape a row left
  // behind by a deleted lane takes.
  const { codes } = tableCodes();
  const sites = treeCodes();
  const unused = codes.filter((c) => !sites.has(c)).sort((a, b) => a - b);
  assert.deepEqual(unused, [],
    `interfaces.md section 7 defines exit code(s) ${unused.join(', ')} that no tracked source `
    + 'file under compiler/ emits. Either a lane that used it was removed, or the row was '
    + 'written for something that was never built.');
});

test('the table keeps 0 through 4 and the meanings the rest of the tree cites', () => {
  // The five original codes are cited by name all over this tree ("interfaces.md
  // section 7" appears in tests in compiler/envelope, compiler/link-wrapper,
  // compiler/driver and six eval lanes). Renumbering them is not a documentation
  // change, so the table may grow but these five may not move.
  const { codes, section } = tableCodes();
  for (const c of [0, 1, 2, 3, 4]) {
    assert.ok(codes.includes(c), `section 7 no longer defines exit ${c}`);
  }
  assert.match(section, /\bNever conflated with 0\b/,
    'section 7 must keep saying that 3 is never conflated with 0: that sentence is the one the '
    + 'rest of the tree cites when it refuses to report an unmade observation as clean');
  assert.match(section, /Fail closed/,
    'section 7 must keep its fail-closed sentence');
});

test('a verdict record still carries only 0-4, whatever this table grows to', () => {
  // observation.schema.json holds verdict.exitCode at 0-4 on purpose: a record's
  // verdict is about the build it describes, never about the harness that recorded
  // it. 5 and 6 are harness states, so growing the table must NOT grow the enum --
  // and the two files would otherwise drift in exactly the direction that puts a
  // harness failure into a record as if it were a finding about the build.
  const schema = JSON.parse(readFileSync(path.join(HERE, 'observation.schema.json'), 'utf8'));
  const e = schema.definitions?.observation?.properties?.verdict?.properties?.exitCode
    ?? schema.properties?.verdict?.properties?.exitCode
    ?? findExitCode(schema);
  assert.ok(e, 'could not find verdict.exitCode in observation.schema.json');
  assert.deepEqual(e.enum, [0, 1, 2, 3, 4],
    'verdict.exitCode must stay 0-4. Section 7 may define harness codes above 4; a RECORD may '
    + 'not carry them, because its verdict is about the build it describes.');
});

/** verdict.exitCode wherever the schema happens to nest it. */
function findExitCode(node) {
  if (!node || typeof node !== 'object') return null;
  if (node.verdict?.properties?.exitCode?.enum) return node.verdict.properties.exitCode;
  for (const v of Object.values(node)) {
    const hit = findExitCode(v);
    if (hit) return hit;
  }
  return null;
}
