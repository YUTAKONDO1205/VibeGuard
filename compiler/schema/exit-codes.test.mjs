/**
 * The contract test for interfaces.md section 7 -- the exit-code table.
 *
 * WHY THIS FILE
 *
 * Section 7 opens with "Shared by every executable here, so that a caller can
 * branch without knowing which component ran". Until 2026-09-13 nothing checked
 * that, in either direction, and both directions had already failed:
 *
 *   - exit 5 was in use at 103 sites across 15 files under compiler/, and exit 6 at
 *     one, and the table listed 0-4. A caller branching on the table would have
 *     read a harness refusing to write a record as an unrecognised code.
 *     (That count is by the method below, at this commit, with the one
 *     NOT_A_COMPONENT file excluded. The first version of this file said "100 in
 *     14" and interfaces.md said "101 in 15" — two numbers for one fact, in one
 *     commit. 100/14 was the tree before this branch; 101/15 was that tree counted
 *     without the exemption; neither described the tree the fence guards. Stating a
 *     count at all is a liability unless the method is stated with it, so the
 *     method is `treeCodes()` below and nothing else.)
 *   - nothing would have noticed a row whose code no component emits, which is a
 *     contract a reader is entitled to rely on and nobody keeps.
 *
 * Section 3.1 has had exactly this test since it was written
 * (measurement-vocabulary.test.mjs, whose table parse this one copies). Section 7
 * had the same need and none.
 *
 * WHAT IS DELIBERATELY NOT ASSERTED: that a given component emits a given code, or
 * that two lanes agree about which code a situation deserves. They do not always --
 * section 7 names the known departures in its own text. The claim here is narrower
 * and mechanical: the table and the tree carry the same SET of LITERAL codes.
 *
 * WHAT IT STILL CANNOT SEE, said out loud so nobody reads it as exhaustive: a code
 * that is not a literal at its exit site. `exit $rc`, `exit "$1"`,
 * `exit $((FAILURES > 0 ? 2 : 0))`, `process.exit(code)`, `sys.exit(rc)`,
 * `process.exitCode = dir ? 0 : 3` -- 134 such sites at the time of writing, and a
 * new code introduced through any of them would pass this file. The last test below
 * asserts that the number has not silently grown, which is the most a pattern
 * matcher can do here; resolving them needs a different instrument than a regex.
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
  // `.c` and `.cc` are in the list because compiler/eval/residue-tracer builds and
  // runs one: observer/residue-observer.c, compiled per run by
  // run-residue-tracer.mjs. A file filter that stopped at the scripting languages
  // would have left a real executable under compiler/ entirely unexamined, which is
  // how its exit(2)-for-usage departure went unnamed in the first version of
  // section 7's departure list.
  const files = execFileSync('git', ['ls-files', 'compiler'], { cwd: REPO, encoding: 'utf8', maxBuffer: 1 << 28 })
    .split('\n')
    .filter((f) => /\.(mjs|js|cjs|ts|py|sh|c|cc|cpp)$/.test(f))
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
      /\bprocess\.exitCode\s*=\s*(\d+)\s*;/g,
      /\bdie\(\s*(\d+)\s*,/g,
      /\bsys\.exit\(\s*(\d+)\s*\)/g,
      // C and C++: plain `exit(N);`. `_exit(` is NOT matched, on purpose —
      // residue-observer.c uses it only in the forked child before `execv`, where
      // 126 and 127 are the shell's conventional codes for "could not exec". Those
      // never surface as the component's own verdict (the parent reads them as a
      // child status), so a table row for them would describe something section 7
      // is not about.
      /(?<![\w.])exit\s*\(\s*(\d+)\s*\)\s*;/g,
      // Shell, anywhere a command can start -- not only at the start of a line.
      // The anchored version missed `*) echo …; exit 5 ;;` in this very branch's
      // own compiler/eval/metamorphic/run-all.sh, so the count it produced was
      // short by the file it shipped beside.
      /(?:^|[;&|]|\bthen\b|\belse\b|\bdo\b)\s*exit\s+(\d+)\b/gm,
    ]) {
      for (const m of src.matchAll(re)) note(Number(m[1]), f);
    }
    // The main()-returns-the-code idiom, in EITHER language and through either
    // sink. The first version gated this on /process\.exit\(\s*main\(/ alone, which
    // no .py file and no `process.exitCode = main(…)` file can ever match -- so 20
    // Python scripts and 9 more .mjs had their returned codes uncounted. Every one
    // of those was checked by hand when this was widened and all land in 0-4; the
    // point is that the fence now looks rather than that the answer was lucky.
    if (/(?:process\.exit\(|process\.exitCode\s*=\s*)\s*main\(/.test(src)
      || /sys\.exit\(\s*main\(/.test(src)) {
      for (const m of src.matchAll(/\breturn\s+(\d+)\s*;?\s*$/gm)) note(Number(m[1]), f);
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

test('the set of exit sites this fence cannot resolve has not silently grown', () => {
  // A ratchet, not a contract. The sites below hold a code in a variable or an
  // expression, so no regex can say which number comes out -- and a NEW code
  // introduced through one of them is exactly the failure the tests above cannot
  // catch. Counting them at least makes the blind spot's SIZE visible: a lane that
  // adds ten more indirect exits has to come here and say so.
  //
  // The baseline is measured, not chosen. Raising it is a decision; raising it
  // without reading the new sites is how a fence becomes decoration.
  // 133 -> 134 on 2026-09-13, read rather than bumped. The new site is the single
  // `process.exit(code)` inside `die()` in `compiler/eval/fold/run-fold.mjs`. Its
  // callers pass 3 and 5 and nothing else, and the runner's only other exit is an
  // implicit 0 -- all three are defined in section 7, and 5 is the harness code
  // section 7 reserves for exactly this directory. A reader who raises this number
  // again owes the next person the same two sentences.
  //
  // 134 -> 138 on 2026-09-15, read rather than bumped, and THIS RATCHET CAUGHT
  // SOMETHING. The four sites arrived in `873a958` and `c3469a3` -- two commits
  // that were never CI-tested, because ci.yml fires only on `pull_request` and
  // `push` to `main`, so the branch they sit on runs nothing. Measured at each
  // commit with this file's own three regexes: befc269 134, 873a958 136,
  // c3469a3 138. The four, and what each can emit:
  //
  //   compiler/eval/oracle-agreement/tools/check-bytes-readout.mjs  `die(code)`
  //   compiler/eval/oracle-agreement/tools/check-o3-apparatus.mjs   `die(code)`
  //     Every caller of both passes a literal 3 or 4, and each file's only other
  //     exits are a literal 2 and a literal 0. All four are in section 7.
  //
  //   compiler/eval/version-ladder/test/wiring.test.mjs
  //     Not an exit at all: `process.exit(${c})` inside an assertion that SEARCHES
  //     run-version-ladder.mjs for the literal sites, which exists so that the
  //     codes stay resolvable to this file. The regex matched the needle. The test
  //     enumerates what `ladderExit` can return -- 0, 2 and CROSS_EXIT=3 -- and
  //     requires a site for each.
  //
  //   compiler/eval/lto-window/tools/check-which-wipe-plumbing.mjs  `die(code)`
  //     ** THIS ONE CAN EMIT A CODE SECTION 7 DOES NOT DEFINE. ** Its
  //     `EXIT = { OK: 0, BUILD: 3, USAGE: 4, DISAGREED: 5, NO_TOOLCHAIN: 69 }`
  //     (line 81) is reached through `die(EXIT.NO_TOOLCHAIN, ...)` at line 225.
  //     69 is sysexits.h EX_UNAVAILABLE and the file argues for it deliberately:
  //     "no compiler here" and "the compiler said something else" are not the same
  //     news, so it is kept apart from 5. Section 7 defines 0-6 and nothing else,
  //     and no other test in this file knows the number exists -- the literal
  //     scanners above cannot see it, because it arrives through a variable. That
  //     is precisely the blind spot this count was written to make visible, and it
  //     is the first time it has been paid out.
  //
  //     NOT resolved here, and deliberately not papered over. Two ways to close
  //     it and both are somebody's decision, not this file's: add 69 to section 7
  //     of ../schema/interfaces.md (which is not edited while components are
  //     implemented against it -- so it is a request, not an edit), or make the
  //     tool answer in the table's vocabulary and lose the distinction it argues
  //     for. Raising the baseline records the site; it does not bless the code.
  const BASELINE = 138;
  const files = execFileSync('git', ['ls-files', 'compiler'], { cwd: REPO, encoding: 'utf8', maxBuffer: 1 << 28 })
    .split('\n')
    .filter((f) => /\.(mjs|js|cjs|ts|py|sh|c|cc|cpp)$/.test(f))
    .filter((f) => !NOT_A_COMPONENT.has(f));
  let n = 0;
  for (const f of files) {
    let raw;
    try { raw = readFileSync(path.join(REPO, f), 'utf8'); } catch { continue; }
    const src = raw.split(/\r?\n/).filter((l) => !/^\s*(\/\/|#|\*|\/\*)/.test(l)).join('\n');
    for (const re of [
      /(?:^|[;&|]|\bthen\b|\belse\b|\bdo\b)\s*exit\s+([$"(][^\s;&|)]*)/gm,
      /\bprocess\.exit\(\s*([A-Za-z_$][^)]*)\)/g,
      /\bsys\.exit\(\s*([A-Za-z_][^)]*)\)/g,
    ]) n += [...src.matchAll(re)].length;
  }
  assert.ok(n <= BASELINE,
    `${n} exit sites now hold a non-literal code, up from the measured baseline of ${BASELINE}. `
    + 'Read the new ones: if any can produce a code section 7 does not define, the table is wrong '
    + 'and this file cannot tell you. Then raise the baseline with what you found.');
  assert.ok(n >= Math.floor(BASELINE * 0.5),
    `only ${n} non-literal exit sites found against a baseline of ${BASELINE}; the SCAN broke `
    + 'rather than the tree improving by that much at once');
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
