/**
 * THE WIRING. Not the pure functions -- the joins between them, which is where
 * every defect this lane has ever shipped actually lived.
 *
 * The record is unambiguous. `anchorDisagreements()` was correct, the README was
 * correct, and `main()` joined them with `if (anchor.disagreements.length)
 * process.exit(2)`, which is 0 when nothing was compared: the lane printed
 * "0/0 cells reproduce the tracked verdict" and exited 0 from its default
 * invocation. The docker rung then repeated it one layer up: `crossDistro()` was
 * correct, its `problem` was written into the record and printed as
 * NOT COMPARED, and NOTHING READ IT -- a run that obtained docker rungs, produced
 * docker cells and compared none of them exited 0. The item's headline claim,
 * failing silently.
 *
 * Both are the same defect and it is not a defect a unit test of a pure function
 * can see. So this file tests the joins:
 *
 *   1. the exit code is ONE function of every `problem` a run can produce
 *   2. the docker half of the report is ONE function the tests can call, rather
 *      than four stretches of main() that could each be deleted with the suite
 *      still green
 *   3. `main()` still calls them -- read off main()'s own source, because the
 *      alternative is a beautifully tested function nobody invokes
 *   4. the `ladder` field survives from the row constructor to the join that
 *      reads it, which is the field whose deletion silently emptied crossDistro()
 *
 * No compiler and no daemon: every case here is synthetic rows in, lines and an
 * exit code out.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ladderRow, dockerSections, ladderExit, dockerProbeWanted, nativeRungs,
} from '../run-version-ladder.mjs';
import {
  DOCKER_LADDER, DOCKER_LADDER_NAME, dockerRungs, dockerStatus, crossDistro, CROSS_EXIT,
} from '../lib/docker.mjs';
import { LADDER } from '../lib/ladder.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const RUNNER = join(LANE, 'run-version-ladder.mjs');
const PROBE = join(LANE, 'tools', 'fortify-spelling-probe.mjs');
const RUNNER_SRC = readFileSync(RUNNER, 'utf8');

/** main()'s own source, which is where the wiring under test lives. */
const MAIN_SRC = (() => {
  const from = RUNNER_SRC.indexOf('async function main()');
  assert.ok(from > 0, 'main() was renamed; this file reads its source');
  const to = RUNNER_SRC.indexOf('if (process.argv[1]', from);
  assert.ok(to > from, 'the bottom of the file moved; this file reads main() up to it');
  return RUNNER_SRC.slice(from, to);
})();

/**
 * main() with its comment lines removed.
 *
 * The counting assertions below are about CODE. main() explains its exit sites
 * in a comment beside them -- as it should -- and a count taken over the prose
 * would be a count of the explanation.
 */
const MAIN_CODE = MAIN_SRC.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');

/** A cell row exactly as the runner builds one. */
const row = ({ id = 'x', cc, vendor, ladder, major, opt = '-O2', verdict }) => ladderRow({
  id, fn: 'f', vendor, ladder, cc, major, opt, nSpans: 1, idiom: 'removable',
  namedSecret: true, scoped: true, cell: { verdict }, labelsOnly: null, spellingSeen: 'memset',
});
const dockerCell = (id, major, verdict, opt = '-O2') => row({
  id, cc: `docker-gcc-${major}`, vendor: DOCKER_LADDER_NAME, ladder: DOCKER_LADDER_NAME, major, opt, verdict,
});
const aptCell = (id, major, verdict, opt = '-O2') => row({
  id, cc: `gcc-${major}`, vendor: 'gcc', ladder: 'gcc', major, opt, verdict,
});

const UP = dockerStatus({ cli: { ok: true, detail: 'Docker version 27' }, daemon: { ok: true, detail: '27.1.1' } });
const declared = (obtainedCc) => [
  ...dockerRungs().map((cc) => (cc === obtainedCc
    ? { cc, obtained: true }
    : { cc, obtained: false, reason: 'not-requested' })),
  { cc: 'gcc-13', obtained: true },
];

// ------------------------------------------------------------ THE EXIT CODE --

test('a docker half that compared NOTHING reaches the EXIT, not just the report', () => {
  // DEFECT 1, and it is the whole point of the item. Before this, `cross.problem`
  // was written into the manifest and printed as "NOT COMPARED" and the process
  // exited 0 -- a run that obtained a container, compiled in it, and read the
  // result against nothing reported success.
  const cross = crossDistro([dockerCell('x', 13, 'WIPE_ELIMINATED'), aptCell('x', 12, 'WIPE_ELIMINATED')]);
  assert.ok(cross.problem, 'the pure function still says so');
  assert.equal(ladderExit({ notAnchored: null, cross }), CROSS_EXIT);
  assert.notEqual(CROSS_EXIT, 0);
});

test('ladderExit is one function of every problem a run can produce, and the anchor wins', () => {
  const clean = crossDistro([dockerCell('x', 13, 'WIPE_ELIMINATED'), aptCell('x', 13, 'WIPE_ELIMINATED')]);
  assert.equal(clean.problem, null);
  assert.equal(ladderExit({ notAnchored: null, cross: clean }), 0, 'the only shape that exits 0');
  assert.equal(ladderExit({}), 0);

  const vacuous = crossDistro([dockerCell('x', 13, 'WIPE_ELIMINATED')]);
  assert.equal(ladderExit({ notAnchored: null, cross: vacuous }), CROSS_EXIT);
  // the anchor is the larger statement and is the one a reader acts on first
  assert.equal(ladderExit({ notAnchored: 'NOT ANCHORED: ...', cross: vacuous }), 2);
  assert.equal(ladderExit({ notAnchored: 'NOT ANCHORED: ...', cross: clean }), 2);
  // and the two codes are distinct: 2 means read none of the run, 8 means the
  // apt ladder stands and the docker half established nothing
  assert.notEqual(CROSS_EXIT, 2);
});

test('the report prints the exit it is about to take, so NOT COMPARED cannot appear beside a zero', () => {
  const cross = crossDistro([dockerCell('x', 13, 'WIPE_ELIMINATED')]);
  const sections = dockerSections({
    rows: [dockerCell('x', 13, 'WIPE_ELIMINATED')],
    versions: declared('docker-gcc-13'),
    wanted: ['docker-gcc-13'],
    obtainedCcs: ['docker-gcc-13'],
    status: UP,
  });
  const text = sections.reportLines.join('\n');
  assert.match(text, /NOT COMPARED/);
  assert.match(text, new RegExp(`it exits ${CROSS_EXIT}`));
  assert.equal(ladderExit({ cross: sections.cross }), CROSS_EXIT);
});

// ------------------------------------------------------ THE DOCKER SECTIONS --

test('dockerSections composes the counting line, and a broken accounting says so on it', () => {
  // DEFECT 2: this line lived in main() and nothing anywhere asserted it. It
  // could be deleted, and the suite stayed green.
  const s = dockerSections({ versions: declared(null), wanted: [], obtainedCcs: [], status: dockerStatus({}) });
  assert.match(s.countingLine, /^docker rungs: /);
  assert.match(s.countingLine, new RegExp(`${DOCKER_LADDER.length} declared = 0 obtained \\+ ${DOCKER_LADDER.length} skipped`));
  assert.doesNotMatch(s.countingLine, /ACCOUNTING BROKEN/);
  assert.equal(s.counting.declared, DOCKER_LADDER.length);

  // a skipped rung carrying no reason breaks the accounting, and the line says so
  const noReason = declared(null).map((v, i) => (i === 0 ? { cc: v.cc, obtained: false } : v));
  assert.match(dockerSections({ versions: noReason, status: dockerStatus({}) }).countingLine, /ACCOUNTING BROKEN/);
});

test('dockerSections names the cells that answer no ladder question, instead of dropping them', () => {
  // Also main()-only before: three lines that could be deleted in silence. A
  // docker cell contributes to no first-appearance question (firstAppearance
  // runs over the declared apt ladders), so without these lines the cell count
  // and the ladder questions stop adding up with nothing to say why.
  const rows = [dockerCell('x', 13, 'WIPE_ELIMINATED'), aptCell('x', 13, 'WIPE_ELIMINATED')];
  const s = dockerSections({ rows, versions: declared('docker-gcc-13'), wanted: ['docker-gcc-13'], obtainedCcs: ['docker-gcc-13'], status: UP });
  assert.equal(s.offLadder.length, 1, 'exactly the docker cell is off the apt ladders');
  assert.equal(s.offLadder[0].cc, 'docker-gcc-13');
  const text = s.offLadderLines.join('\n');
  assert.match(text, /1 of those cells are on a ladder with no first-appearance rule \(docker-gcc\)/);
  assert.match(text, /NOT part of the ladder questions/);

  // and an apt-only run has no such line at all: a caveat printed when it is
  // untrue teaches a reader to skip the list
  const apt = dockerSections({ rows: [aptCell('x', 13, 'WIPE_ELIMINATED')], versions: declared(null), status: dockerStatus({}) });
  assert.deepEqual(apt.offLadderLines, []);
  assert.equal(apt.offLadder.length, 0);
  // the ladders the off-ladder test is taken against are the declared ones
  for (const vendor of Object.keys(LADDER)) assert.ok(nativeRungs().some((cc) => cc.startsWith(`${vendor}-`)));
});

test('dockerSections runs the cross-distribution join, and reports what it compared', () => {
  const rows = [
    dockerCell('x', 13, 'WIPE_SURVIVED'), aptCell('x', 13, 'WIPE_ELIMINATED'),
    dockerCell('y', 13, 'WIPE_SURVIVED'), aptCell('y', 13, 'WIPE_SURVIVED'),
  ];
  const s = dockerSections({ rows, versions: declared('docker-gcc-13'), wanted: ['docker-gcc-13'], obtainedCcs: ['docker-gcc-13'], status: UP });
  assert.equal(s.cross.compared, 2);
  assert.equal(s.cross.agreed, 1);
  assert.equal(s.cross.problem, null);
  const text = s.reportLines.join('\n');
  assert.match(text, /cross-distribution: 1\/2 cell\(s\) agree/);
  assert.match(text, /docker WIPE_SURVIVED, apt WIPE_ELIMINATED/);
  assert.equal(ladderExit({ cross: s.cross }), 0);
});

// ---------------------------------------- THE FIELD THE JOIN ACTUALLY READS --

test('the ladder a row is ON reaches crossDistro from the row constructor', () => {
  // DEFECT 2, the other half. `ladder` was optional and defaulted to the vendor,
  // no caller passed it and no test asserted it -- so deleting the field from
  // ladderRow() left crossDistro() filtering on a property no row carried: zero
  // docker rows, nothing compared, no problem, exit 0. The field is required now
  // and this is the path that proves it is the one the join reads.
  const rows = [dockerCell('x', 13, 'WIPE_ELIMINATED'), aptCell('x', 13, 'WIPE_ELIMINATED')];
  assert.equal(rows[0].ladder, DOCKER_LADDER_NAME);
  assert.equal(rows[1].ladder, 'gcc');
  const c = crossDistro(rows);
  assert.equal(c.dockerRows, 1);
  assert.equal(c.compared, 1, 'the join found the docker row BY ITS LADDER FIELD');
  assert.equal(c.agreed, 1);
  assert.equal(c.problem, null);

  // a row that cannot say which ladder it is on is not built at all
  assert.throws(() => ladderRow({
    id: 'x', fn: 'f', vendor: 'gcc', cc: 'gcc-13', major: 13, opt: '-O2', nSpans: 1, idiom: 'removable',
    namedSecret: true, scoped: true, cell: { verdict: 'WIPE_SURVIVED' }, labelsOnly: null, spellingSeen: null,
  }), /carries no ladder/);

  // and a row whose two names disagree is a refusal rather than an apt cell
  // compared with itself
  const mislabelled = crossDistro([
    { ...rows[0], ladder: 'gcc' },
    rows[1],
  ]);
  assert.match(mislabelled.problem, /ladder field and the rung name disagree|not filed on the docker-gcc ladder/);
  assert.equal(ladderExit({ cross: mislabelled }), CROSS_EXIT);
});

// ------------------------------------------------- MAIN STILL CALLS THEM -----

test('main() takes its exit code and its docker report from those functions', () => {
  // A tested function nobody invokes is the same silent pass one layer further
  // back, and this is the mutation the item names: delete the call from main()
  // and see whether anything goes red. This is what goes red.
  const NEEDLES = [
    { has: 'dockerSections({', why: 'main() no longer composes the docker half through dockerSections()' },
    { has: 'dock.countingLine', why: 'the docker counting line is not printed from the composed section' },
    { has: 'dock.offLadderLines', why: 'the off-ladder cell lines are not printed from the composed section' },
    { has: 'dock.reportLines', why: 'the docker paragraph is not printed from the composed section' },
    { has: 'ladderExit({', why: 'main() no longer decides its exit with ladderExit()' },
    { has: 'if (code === 2) process.exit(2);', why: 'main() does not exit 2 with the code ladderExit() returned' },
    { has: 'if (code === CROSS_EXIT) process.exit(3);', why: 'main() does not exit 3 when the docker half compared nothing' },
    { has: 'ladder: v.ladder', why: 'the row constructor is no longer told which ladder the rung is on' },
    { has: 'dockerProbeWanted(wanted)', why: 'the docker probe is unconditional again' },
  ];
  // POSITIVE CONTROL: every needle has to be able to fire, or a renamed call
  // site would make all eight silently clean.
  for (const n of NEEDLES) {
    assert.ok(`prefix ${n.has} suffix`.includes(n.has), `the needle ${n.has} cannot fire`);
    assert.ok(MAIN_SRC.includes(n.has), n.why);
  }
  // and the exit is decided in ONE place: the bare `if (notAnchored)
  // process.exit(2)` this replaced is what let cross.problem be printed beside a
  // zero. Both sites now branch on what ladderExit() returned, and the codes are
  // written as literals so compiler/schema/exit-codes.test.mjs can still resolve
  // them -- that fence says in its own header that `process.exit(code)` is a
  // site it cannot read.
  assert.equal(MAIN_CODE.split('process.exit(').length - 1, 2, 'exactly two exit sites, both from the decision');
  assert.equal(MAIN_CODE.split('ladderExit({').length - 1, 1, 'exactly one exit decision');
  assert.equal(MAIN_CODE.split('dockerSections({').length - 1, 1, 'exactly one docker section');
  // and no exit code is spent through a variable: the fence in
  // compiler/schema/exit-codes.test.mjs cannot resolve `process.exit(code)`
  assert.ok(!/process\.exit\(\s*[A-Za-z_]/.test(MAIN_CODE), 'an exit site the schema fence cannot read');

  // EXHAUSTIVE, so that a code with no site cannot fall through to 0. main()
  // branches on literals, which is what the schema fence needs; the price of
  // that is that a code ladderExit can return and main() has no `if` for would
  // exit 0 silently -- the defect shape this whole file is about. So: enumerate
  // what ladderExit can return, and require a site for each non-zero one.
  const reachable = new Set();
  for (const notAnchored of [null, 'NOT ANCHORED: ...']) {
    for (const cross of [null, { problem: null }, { problem: 'nothing was compared' }]) {
      reachable.add(ladderExit({ notAnchored, cross }));
    }
  }
  assert.deepEqual([...reachable].sort(), [0, 2, CROSS_EXIT].sort(), 'ladderExit returns a code this test has not enumerated');
  for (const c of [...reachable].filter((x) => x !== 0)) {
    assert.ok(MAIN_CODE.includes(`process.exit(${c})`), `ladderExit can return ${c} and main() has no site for it`);
  }
});

test('the code the docker half exits with is one interfaces.md section 7 DEFINES', () => {
  // This lane may not add a row to that table, and a code the table does not
  // carry is one a caller cannot branch on -- `compiler/schema/exit-codes.test.mjs`
  // is the fence for it. 3 is the table's "a check could not be completed,
  // never conflated with 0", which is what a docker cell read against nothing
  // is. Read out of the table rather than asserted, so that a table that drops
  // the row fails here too.
  const text = readFileSync(resolve(LANE, '../../schema/interfaces.md'), 'utf8');
  const start = text.indexOf('\n## 7. Exit codes');
  assert.ok(start > 0, 'interfaces.md section 7 was renamed');
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n## ');
  const section = end === -1 ? rest : rest.slice(0, end);
  const defined = [...section.matchAll(/^\|\s*(\d+)\s*\|/gm)].map((m) => Number(m[1]));
  assert.ok(defined.length >= 5, `section 7 parsed to ${defined.length} rows`);
  assert.ok(defined.includes(CROSS_EXIT), `exit ${CROSS_EXIT} is not a code section 7 defines: ${defined.join(', ')}`);
  assert.notEqual(CROSS_EXIT, 0, 'a check that could not be completed is never 0');
});

test('the docker probe is spent only on a run that asked for a docker rung', () => {
  // DEFECT 8's second half. probeDocker() is two subprocesses with 20s and 30s
  // timeouts and `docker info` OPENS THE DAEMON SOCKET; it ran on every
  // invocation of this lane, including the default apt-only one.
  assert.equal(dockerProbeWanted(nativeRungs()), false);
  assert.equal(dockerProbeWanted(['docker-gcc-14']), true);
  const unprobed = dockerSections({ versions: declared(null), wanted: nativeRungs(), obtainedCcs: ['gcc-13'], status: dockerStatus({}) });
  const text = unprobed.reportLines.join('\n');
  assert.match(text, /NOT PROBED/);
  assert.doesNotMatch(text, /failed on this machine/);
});

// --------------------------------------------------------- THE REFUSAL ------

test('the fortify probe defaults to the APT rungs: allRungs() is the runner\'s denominator, not a tool\'s', () => {
  // DEFECT 6: a changed function's other caller. `allRungs()` grew the five
  // docker rungs because it is what decides the RUN's denominator -- a rung
  // absent from it is a rung nobody can see was not obtained -- and this tool,
  // which spawns each name as a PATH binary, silently started spawning five
  // names that can never exist and printing each as `-(not obtained)`, which
  // reads as a rung that was tried.
  const r = spawnSync(process.execPath, [PROBE, '--opts', '-O1'], { encoding: 'utf8', timeout: 240000 });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!/docker-gcc/.test(r.stdout), `a docker rung was spawned as a PATH binary:\n${r.stdout}`);
  const rungLines = r.stdout.split('\n').filter((l) => /^\s{2}(clang|gcc)-\d+\s/.test(l));
  const attempted = new Set(rungLines.map((l) => l.trim().split(/\s+/)[0]));
  assert.deepEqual([...attempted].sort(), [...nativeRungs()].sort(), 'the default is exactly the apt ladders');

  // and a docker rung asked for BY NAME is a refusal, not five --version spawns
  const d = spawnSync(process.execPath, [PROBE, '--ccs', 'docker-gcc-13'], { encoding: 'utf8', timeout: 60000 });
  assert.equal(d.status, 4, `expected exit 4, got ${d.status}\n${d.stdout}\n${d.stderr}`);
  assert.match(d.stderr, /is a docker rung/);
  assert.match(d.stderr, /run-version-ladder\.mjs/);
});

test('a docker rung the ladder does not declare is exit 4 from --ccs, exactly as from --docker-pins', () => {
  // DEFECT 7. `--docker-pins {"docker-gcc-15": ...}` was exit 4 and
  // `--ccs docker-gcc-15` was a `not-installed` line in the counting -- one
  // spelling of the mistake refused by name, the other filed as a measurement
  // and spawned as a PATH binary that can never exist.
  const dir = mkdtempSync(join(tmpdir(), 'vg-vl-wiring-'));
  try {
    const r = spawnSync(process.execPath, [RUNNER, '--out', join(dir, 'out'), '--ccs', 'docker-gcc-15',
      '--opts', '-O2', '--ids', 'haiku_E_aeskey_r1', '--no-subjects'], { encoding: 'utf8', timeout: 180000 });
    assert.equal(r.status, 4, `expected exit 4, got ${r.status}\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /not a declared docker rung/);
    assert.match(r.stderr, /docker-gcc-15/);
    // and it never tried to run it as a compiler
    assert.doesNotMatch(r.stderr, /not-installed/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
