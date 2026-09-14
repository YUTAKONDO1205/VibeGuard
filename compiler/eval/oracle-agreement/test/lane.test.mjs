/**
 * The lane's own hygiene, and the claim its README is built on.
 *
 * Two groups.
 *
 * The first group pins guarantees that would otherwise live only in a comment:
 * that the module which reads the frozen rows cannot write them, that the pure
 * module is pure, that the O2 channel spells no effect-symbol list of its own,
 * and that this lane tells the plugin EXACTLY what `../../spike/lib/observer.mjs`
 * tells it. A shared instrument that two lanes configure differently is two
 * instruments reporting in one vocabulary, which is the failure
 * `compiler/schema/effect-symbol-lists.json` was written after finding ten times
 * in this tree.
 *
 * The second group RE-DERIVES the four-oracle map the README prints. That map
 * corrects a sentence in the implementation order (section 2.20(g)) which says
 * seven lanes all go through `verdictOf`. Two of them do not, and "two of them
 * do not" is a claim about files that change. So it is a test: if A7 ever starts
 * importing the shared oracle, or A1's single `verdictOf` call becomes several,
 * this fails and the README is wrong in a way somebody has to look at.
 *
 * No compiler is required and nothing is measured here.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { dirname, resolve, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const EVAL = resolve(LANE, '..');

const read = (p) => readFileSync(p, 'utf8');

/** Every file under `dir`, recursively, as absolute paths. */
function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

const LANE_SOURCES = walk(LANE).filter((p) => p.endsWith('.mjs'));
const README = read(join(LANE, 'README.md'));

// ------------------------------------------------- the frozen rows stay frozen --

test('lib/rows.mjs imports nothing from node:fs but readFileSync', () => {
  // The tracked rows are a frozen record quoted in a write-up. A lane that can
  // write them is one edit away from re-deriving them on today's toolchain and
  // nobody noticing that the number moved.
  const src = read(join(LANE, 'lib/rows.mjs'));
  const imports = [...src.matchAll(/import\s*\{([^}]*)\}\s*from\s*'node:fs'/g)]
    .flatMap((m) => m[1].split(',').map((s) => s.trim()).filter(Boolean));
  assert.deepEqual(imports, ['readFileSync']);
});

test('no module in this lane names a mutating fs call near the tracked rows path', () => {
  for (const p of LANE_SOURCES) {
    const src = read(p);
    for (const call of ['writeFileSync', 'appendFileSync', 'rmSync', 'unlinkSync', 'truncateSync', 'copyFileSync']) {
      for (const m of src.matchAll(new RegExp(`${call}\\s*\\(([^)]*)`, 'g'))) {
        assert.ok(
          !/r2-build-rows|ROWS_PATH|ai-generated\/data/.test(m[1]),
          `${p}: ${call} applied to the tracked rows`,
        );
      }
    }
  }
});

test('nothing in this lane writes under compiler/eval/ai-generated at all', () => {
  for (const p of LANE_SOURCES) {
    assert.ok(!/ai-generated\/(data|_build)\/[^']*'\s*,\s*[^)]*\)\s*;?\s*\/\/\s*write/i.test(read(p)), p);
  }
  // The stronger, simpler statement: every writeFileSync in this lane writes
  // either into the lab -- which is checked to be outside the repository -- or
  // into this lane's OWN data/ directory, and the number of them per file is
  // pinned rather than merely bounded.
  //
  // Amended 2026-09-12, when `--write-data` was added. Before it, the sentence
  // was "the only writeFileSync in the lane writes into the lab", and a test
  // whose sentence has stopped being true is worse than no test: it reports
  // green about a guarantee nobody is making any more.
  //
  // Amended again 2026-09-14, when the lane grew a gcc-side second oracle. Three
  // modules write now that did not before -- the byte-count prober writes one
  // probe source, the disassembly channel writes the appended unit and its link
  // stubs, and the live-O1 column writes the two forms it compiles -- and every
  // one of them writes into the lab. What is kept is the SHAPE of the old test:
  // an exact count per file, and an empty set everywhere else, so a write that
  // appears in a module with no business writing still fires. Loosening this to
  // "at most one write per file" would have been the amendment that made it stop
  // catching anything.
  const WRITERS = Object.freeze({
    'run-oracle-agreement.mjs': 1,
    'lib/observe.mjs': 1,
    'lib/record.mjs': 1,
    'lib/bufferbytes.mjs': 1,
    'lib/disasm.mjs': 2,
    'lib/liveo1.mjs': 2,
    // The two apparatus checks. They write their own fixtures into the lab and
    // nothing else; `tools/check-bytes-readout.mjs` writes none at all, because
    // the byte-count prober writes its own probe sources.
    'tools/check-o3-apparatus.mjs': 1,
  });
  for (const [rel, n] of Object.entries(WRITERS)) {
    const src = read(join(LANE, rel));
    assert.equal((src.match(/writeFileSync\(/g) || []).length, n, `${rel} no longer writes ${n} file(s)`);
  }
  // Every writer that takes a lab directory checks that it is outside the
  // repository, before it writes. `lib/record.mjs` is the exception and is the
  // one that writes into `data/`; its own fences are tested above.
  for (const rel of ['run-oracle-agreement.mjs', 'lib/observe.mjs', 'lib/bufferbytes.mjs', 'lib/disasm.mjs',
    'lib/liveo1.mjs', 'tools/check-o3-apparatus.mjs', 'tools/check-bytes-readout.mjs']) {
    assert.match(read(join(LANE, rel)), /insideRepo\(lab\)/, `${rel} writes into a lab it never checked`);
  }
  const others = LANE_SOURCES.filter((p) => !Object.keys(WRITERS).some((rel) => p === join(LANE, rel))
    && !p.includes(`${sep}test${sep}`));
  for (const p of others) assert.ok(!/writeFileSync\(/.test(read(p)), `${p} writes a file`);
});

test('the tracked record is written by one function, into this lane’s own data/ and nowhere else', () => {
  // The write that `--write-data` added is the lane's only tracked output. Three
  // things have to stay true of it, and none of them is visible at the call
  // site in the runner: it goes through the lane's own DATA_DIR, the text is
  // scanned before the file is opened, and a hit means NOTHING is written.
  const record = read(join(LANE, 'lib/record.mjs'));
  assert.match(record, /export const DATA_DIR = resolve\(HERE, '\.\.\/data'\)/);
  assert.match(record, /absolutePathHits\(text\)[\s\S]{0,400}mkdirSync/,
    'the record is written before its text is scanned');
  assert.match(record, /if \(hits\.length \|\| floats\.length\) return \{ written: false/);
  // The refusal is not a warning the runner may ignore.
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  assert.match(runner, /written\.written[\s\S]{0,600}process\.exit\(5\)/);
  assert.match(runner, /writeDataRefusals\(args\)/);
});

test('a tracked record may carry counts, never a rate', () => {
  // The rule the README states about this very run -- "read the 96 % as
  // nothing" -- as a mechanical check rather than as an instruction to whoever
  // adds the next field. lib/record.mjs refuses to write a record containing a
  // number that is not an integer; this pins that the refusal is wired into the
  // write and not merely available next to it.
  const record = read(join(LANE, 'lib/record.mjs'));
  assert.match(record, /const floats = nonIntegerNumbers\(record\)/);
  assert.ok(!/toFixed|\* 100|formatRate/.test(record), 'lib/record.mjs formats a percentage');
});

// ------------------------------------------------------------ purity ---------

test('lib/agreement.mjs reads nothing and runs nothing', () => {
  const src = read(join(LANE, 'lib/agreement.mjs'));
  assert.ok(!/from 'node:fs'/.test(src), 'agreement.mjs imports node:fs');
  assert.ok(!/from 'node:child_process'/.test(src), 'agreement.mjs imports node:child_process');
  assert.ok(!/import .* from '\.\//.test(src), 'agreement.mjs imports another module of this lane');
});

test('the table module has no notion of a file path, a vendor binary or a plugin', () => {
  const src = read(join(LANE, 'lib/agreement.mjs'));
  for (const word of ['clang-18', 'gcc-13', 'libPropertyObserver', 'OBS_', 'execFile']) {
    assert.ok(!src.includes(word), `agreement.mjs mentions ${word}`);
  }
});

// ---------------------------------------- the plugin is configured identically --

test('this lane tells the plugin exactly the OBS_ variables the spike lane tells it', () => {
  const mine = read(join(LANE, 'lib/observe.mjs'));
  const theirs = read(join(EVAL, 'spike/lib/observer.mjs'));
  const keys = (src) => [...new Set([...src.matchAll(/\bOBS_[A-Z_]+/g)].map((m) => m[0]))].sort();
  assert.deepEqual(keys(mine), keys(theirs));
  assert.deepEqual(keys(mine), ['OBS_CONTROL_FN', 'OBS_EFFECT_SYMBOLS', 'OBS_MODE', 'OBS_OUT', 'OBS_TARGET_FN']);
});

test('the O2 channel imports the spike lane\u2019s reader rather than parsing the log again', () => {
  const src = read(join(LANE, 'lib/observe.mjs'));
  assert.match(src, /import \{ effectSymbols, readSummaries, CONTROL_FN \} from '\.\.\/\.\.\/spike\/lib\/observer\.mjs'/);
  // A second SUMMARY parser would drift from the plugin's column order in
  // silence: History.cpp's emitSummaryInto writes fifteen fields and the state
  // is the eleventh.
  assert.ok(!src.includes("startsWith('SUMMARY"), 'observe.mjs parses the plugin log itself');
});

test('the O2 channel spells no effect-symbol list of its own', () => {
  const src = read(join(LANE, 'lib/observe.mjs'));
  for (const sym of ['memset', 'explicit_bzero', 'bzero', '__memset_chk', 'memset_s', 'llvm.memset']) {
    assert.ok(!src.includes(sym), `observe.mjs spells ${sym}; the list must come from the registry`);
  }
  assert.match(src, /effectSymbols/);
});

test('the positive control is the corpus run\u2019s CONTROL, imported and not re-written', () => {
  const src = read(join(LANE, 'lib/observe.mjs'));
  assert.match(src, /import \{ CONTROL \} from '\.\.\/\.\.\/ai-generated\/lib\/ablation-cell\.mjs'/);
  assert.ok(!src.includes('vgctl_control'), 'observe.mjs spells the control function name instead of importing it');
});

// ------------------------------------------------------ the exit code contract --

test('the runner documents that disagreement exits 0, in the header a reader opens first', () => {
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  assert.match(runner, /DISAGREEMENT also exits 0/i);
  assert.match(runner, /THE RUN COULD NOT ASK ITS QUESTION/);
  assert.match(runner, /a dry run/i);
});

test('the dry run exits 3 and not 0', () => {
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  const dry = runner.slice(runner.indexOf('if (args.dryRun)'));
  assert.match(dry.slice(0, dry.indexOf('\n}\n')), /process\.exit\(3\)/);
});

test('an unavailable plugin or compiler exits 3 rather than producing an empty table', () => {
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  assert.match(runner, /channel\.available[\s\S]{0,400}process\.exit\(3\)/);
  assert.match(runner, /unavailable\.length[\s\S]{0,400}process\.exit\(3\)/);
});

// --------------------------------------------------------- public hygiene ----

test('no file in this lane carries an absolute path of a measuring machine', () => {
  for (const p of walk(LANE)) {
    const hits = absolutePathHits(read(p));
    assert.deepEqual(hits, [], `${p}: ${hits.join(', ')}`);
  }
});

test('the plugin is named the way the rest of the tree names it -- a tilde, not an account', () => {
  // `~/vg-build/pass-observer/libPropertyObserver.so` is what
  // `compiler/pass-instrumentation/observer/README.md` says ninja produces, and
  // what the spike and lto-window lanes spell. Spelling the same location with
  // the superuser's home directory instead would put one machine's account
  // layout into a tracked file -- the shape `scripts/check-disclosure-shape.mjs`
  // refuses, and the one `compiler/eval/comparison/run-comparison.mjs:48` still
  // has. The needle is ASSEMBLED rather than written, following the precedent in
  // that checker: this file is itself scanned by the test above, and a literal
  // here would make a clean lane fail its own hygiene check.
  const homeOfTheSuperuser = ['', 'root', ''].join('/');
  for (const p of [join(LANE, 'run-oracle-agreement.mjs'), join(LANE, 'README.md')]) {
    const src = read(p);
    assert.ok(src.includes('~/vg-build/pass-observer/libPropertyObserver.so'), `${p} does not name the plugin`);
    assert.ok(!src.includes(homeOfTheSuperuser), `${p} spells an account's home directory`);
  }
});

// --------------------------------------- the four-oracle map, re-derived -----

// ------------------------------------ a path in a comment is a path, or nothing --

/**
 * Comment text only: the `//` and block comments of one module, with the code
 * removed.
 *
 * Import specifiers are code and are checked by the module loader every time the
 * suite runs -- a wrong one is a crash, not a rotted signpost. A path written in
 * a COMMENT is checked by nobody, which is how this lane came to carry eight of
 * them pointing at `compiler/eval/schema/` and `compiler/eval/gcc-repair/`,
 * neither of which has ever existed: the directories are `compiler/schema/` and
 * `compiler/gcc-repair/`, and the references were written as though from the
 * lane root by somebody editing a file one directory below it.
 *
 * A reader who follows one of those finds nothing and has no way to tell a
 * mis-typed signpost from a file that was deleted.
 */
const commentsOf = (src) => {
  const blocks = src.match(/\/\*[\s\S]*?\*\//g) || [];
  const lines = src.match(/(?:^|\s)\/\/[^\n]*/g) || [];
  return [...blocks, ...lines].join('\n');
};

/** Every `../`-relative reference in a blob of comment text. */
const relativeRefs = (text) => (text.match(/(?<![\w./-])\.\.(?:\/[\w.@+-]+)+/g) || []);

test('every relative path named in a comment in this lane resolves to something that exists', () => {
  const files = [...LANE_SOURCES, join(LANE, 'README.md')];
  const broken = [];
  for (const file of files) {
    const text = file.endsWith('.md') ? read(file) : commentsOf(read(file));
    for (const ref of new Set(relativeRefs(text))) {
      // Resolved from the directory of the file that names it, which is what a
      // reader does and what the wrong ones got wrong.
      if (!existsSync(resolve(dirname(file), ref))) broken.push(`${file.slice(LANE.length + 1)}: ${ref}`);
    }
  }
  assert.deepEqual(broken, [], `these references point at nothing:\n  ${broken.join('\n  ')}`);
});

test('the four sibling lanes and tools this lane names are named from the right depth', () => {
  // The specific corrections, pinned so the same mistake cannot be reintroduced
  // by a copy from the lane root: a module under `lib/` is TWO directories below
  // `compiler/eval`, so `compiler/schema` is reached with THREE `..` segments
  // from there and never with two. The wrong spellings are not written out here:
  // this file is one of the files the test above reads.
  for (const rel of ['lib/agreement.mjs', 'lib/bufferbytes.mjs', 'lib/callsites.mjs', 'lib/disasm.mjs', 'lib/record.mjs']) {
    const src = read(join(LANE, rel));
    assert.ok(!/(?<![\w./-])\.\.\/\.\.\/(schema|gcc-repair|pass-instrumentation)\//.test(src),
      `${rel} names compiler/${'schema'} or compiler/gcc-repair as though it were under compiler/eval/`);
    assert.ok(!/(?<![\w./-])\.\.\/(lto-window|spike|ai-generated|repair-loop)\//.test(src),
      `${rel} names a sibling LANE as though this file were in the lane root`);
  }
});

test('CORRECTION: the lto-window lane (A7) does not go through the shared oracle at all', () => {
  // Section 2.20(g) lists A7 among the lanes that reach their verdict through
  // `verdictOf`. It does not. This is the grep, run as a test.
  const hits = [];
  for (const p of walk(join(EVAL, 'lto-window'))) {
    const src = read(p);
    if (/ablation-cell|verdictOf/.test(src)) hits.push(p);
  }
  assert.deepEqual(hits, [], `lto-window now references the shared oracle: ${hits.join(', ')}`);
});

test('A7 reads the IR call site and the disassembly instead -- O2 and O3', () => {
  const cell = read(join(EVAL, 'lto-window/lib/cell.mjs'));
  assert.match(cell, /OBS_TARGET_FN|SUMMARY|finalState|STATE/);
  assert.ok(existsSync(join(EVAL, 'lto-window/tools/read-wipe.py')), 'read-wipe.py is gone');
});

test('CORRECTION: A1 uses the shared oracle for its confirm column only', () => {
  // One call, and it is the `confirm` field. The residue measurement itself is
  // ptrace, which is why A1 counts as a fourth oracle rather than as a seventh
  // re-sample of the first.
  const src = read(join(EVAL, 'residue-tracer/run-residue-tracer.mjs'));
  const calls = src.match(/cell\.verdictOf\(/g) || [];
  assert.equal(calls.length, 1, `residue-tracer now calls verdictOf ${calls.length} times`);
  assert.match(src, /confirm = \{ \.\.\.cell\.verdictOf\(/);
  assert.match(src, /ptrace|residue/i);
});

test('the lanes that DO share the oracle still do -- the sentence is right about them', () => {
  for (const lane of ['ai-generated/lib/build-analyze.mjs', 'repair-loop/run-repair-loop.mjs', 'actuarial/lib/rate-table.mjs', 'version-ladder/lib/ladder.mjs']) {
    const p = join(EVAL, lane);
    assert.ok(existsSync(p), `${lane} is gone`);
    assert.match(read(p), /ablation-cell|verdictOf/, `${lane} no longer shares the oracle`);
  }
});

// --------------------------------------------------------------- README ------

test('the README says plainly that seven lanes agreeing is resampling one instrument', () => {
  assert.match(README, /re-?sampl/i);
  assert.match(README, /seven lanes/i);
  assert.match(README, /not independent|is not corroboration|not independent corroboration/i);
});

test('the README prints all four oracles, each with the thing it actually reads', () => {
  for (const line of ['verdictOf', 'PropertyObserver', 'read-wipe', 'ptrace']) {
    assert.ok(README.includes(line), `the README does not name ${line}`);
  }
  for (const tag of ['O1', 'O2', 'O3', 'O4']) {
    assert.ok(README.includes(tag), `the README does not name ${tag}`);
  }
});

test('the README states the three design decisions this lane was required to take a position on', () => {
  assert.match(README, /-O0/);
  assert.match(README, /BROKEN_MEASUREMENT/);
  assert.match(README, /exit code/i);
  assert.match(README, /Agreement is not the success criterion|agreement is not the criterion/i);
});

test('the README has a section for what this lane does NOT measure', () => {
  assert.match(README, /^## What (is|this lane does) NOT measure/mi);
});

test('the README gives a runnable command with the plugin path and a lab outside the repository', () => {
  assert.ok(README.includes('~/vg-build/pass-observer/libPropertyObserver.so'));
  assert.match(README, /--out\s+~\//);
  assert.match(README, /run-oracle-agreement\.mjs/);
});

// Rewritten 2026-09-12, when the lane was first run.
//
// Before the run this test said: print NO rate that is not marked a placeholder,
// because the lane had never been run and a table here would have been a table
// nobody measured. It fired, correctly, the moment a measured table was pasted
// in -- which is the only reason it was worth having.
//
// What replaces it is NOT weaker. It is the same rule after the premise changed.
// A rate may now appear, and every appearance has to carry the two things that
// make a rate readable: the run that produced it, and the fact that THIS run
// refused the comparison. `24/25` with the refusal beside it is a measurement.
// `24/25` on its own is 96% of one instrument saying its only word.
test('the README prints no agreement rate without the run that produced it and its refusal', () => {
  const rates = README.match(/(?:diagonal|agreement rate|agreed?)[^\n]{0,60}?\b\d+\s*\/\s*\d+\b/gi) || [];
  for (const n of rates) {
    const at = README.indexOf(n);
    const around = README.slice(Math.max(0, at - 1500), at + 1500);
    assert.match(around, /placeholder|example|synthetic|illustrat|Measured, \d{4}-\d{2}-\d{2}/i,
      `a rate with no run beside it: ${n}`);
  }
  if (/Measured, \d{4}-\d{2}-\d{2}/.test(README)) {
    assert.match(README, /COMPARISON WAS NOT PERFORMED|refuses its own table|degenerate/i,
      'the README reports a measured table without saying the comparison was refused');
    assert.match(README, /exit\W{0,3}2/i, 'the README does not record the exit code the run actually gave');
  }
});

test('the README still separates what was measured from what is specification', () => {
  // The lane's own vocabulary. Losing this line is how a run of one stratum
  // becomes a claim about all of them.
  assert.match(README, /\[SPEC\]|NOT MEASURED|not been run|is NOT measured/i);
});
