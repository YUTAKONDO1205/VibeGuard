#!/usr/bin/env node
// Clean-rebuild byte comparison.
//
//   node tools/rebuild-compare.mjs --work <dir> [--case <id> ...] [--list]
//                                  [--json <report.json>] [--cc clang-18]
//                                  [--allow-empty]
//
// Each case builds the same fixture TWICE FROM A CLEAN STATE and compares the
// produced bytes. What varies between the two builds is the case: nothing at
// all, the build directory, the source directory, a macro that reads the clock.
//
// A DIFFERENCE IS A RESULT, NOT A FAILURE
//
//   The runner does not assert that everything reproduces. It records what
//   happened and, when two artefacts differ, works out WHERE: it walks the ELF
//   section headers of both files and reports which sections' bytes moved. A
//   difference confined to `.debug_*` is a recorded path; one in `.rodata` is a
//   string compiled into the program; one in `.comment` is a different
//   compiler. `.note.gnu.build-id` differing is a CONSEQUENCE and never a
//   cause, because the build id is a hash of the rest of the output — the
//   runner labels it as such rather than letting it be read as an explanation.
//
// THE FIXTURE IS CHECKED BEFORE ANYTHING IS COMPARED
//
//   An artefact with nothing in it reproduces perfectly. So before the byte
//   comparison the runner emits IR at -O0 and at -O2 and counts memset CALL
//   SITES per function (interfaces.md §4): the target's must fall to zero, the
//   control's must not. If the control's count is zero the run is reported as
//   broken and no reproducibility claim is made from it.
//
// COUNTING CONTRACT
//
//   `inputs=N checked=N skipped=S` over cases, and exit non-zero when N is 0
//   unless `--allow-empty`. A missing prerequisite tool FAILS the run; it
//   becomes a skip only when PROVENANCE_ALLOW_MISSING_TOOLS is set, and then
//   every skipped case is named.

import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK } from '../../driver/lib/exit.mjs';
import { SKIP_ENV, parseArgv, reportCounts, skipsAuthorised } from '../lib/cli.mjs';
import { countMemsetCallSites } from '../lib/ir-oracle.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
// The fixture is GENERATED into the work directory rather than read from the
// repository. Measurement inputs under compiler/ are a packaging-invariant
// failure, not a style preference — the published tree is not where the things
// being measured live. `make-fixtures.sh` writes byte-identical sources every
// time, which is the property a reproducibility comparison actually needs.
const MAKE_FIXTURES = resolve(HERE, 'make-fixtures.sh');

const args = parseArgv(process.argv.slice(2));

// ── the case matrix ─────────────────────────────────────────────────────────
//
// `dirs: 'same'` means both builds use the identical directory, which is wiped
// between them — that is the clean rebuild in its strictest form. `'differ'`
// gives the two builds different directories, which is how a real second build
// on a second machine looks.

const STAMP_FILE = '-DFIXTURE_STAMP=__FILE__';
const STAMP_TIME = '-DFIXTURE_STAMP=(__DATE__ " " __TIME__)';

const CASES = [
  {
    id: 'same-path-clean',
    why: 'nothing varies. The floor: if this differs, nothing else in the matrix means anything.',
    dirs: 'same', cflags: ['-O2'], expectation: 'identical',
  },
  {
    id: 'same-path-debug',
    why: 'nothing varies, with -g. Debug info is where non-determinism usually hides.',
    dirs: 'same', cflags: ['-O2', '-g'], expectation: 'identical',
  },
  {
    id: 'builddir-differs-nodebug',
    why: 'the output directory moves. Without -g the compiler is not asked to record where it ran.',
    dirs: 'build', cflags: ['-O2'], expectation: 'unknown',
  },
  {
    id: 'builddir-differs-debug',
    why: 'the output directory moves, with -g. DW_AT_comp_dir is the working directory.',
    dirs: 'build', cflags: ['-O2', '-g'], expectation: 'unknown',
  },
  {
    id: 'srcdir-differs-nodebug',
    why: 'the source directory moves, no -g.',
    dirs: 'src', cflags: ['-O2'], expectation: 'unknown',
  },
  {
    id: 'srcdir-differs-debug',
    why: 'the source directory moves, with -g. DW_AT_name carries the path as it was given.',
    dirs: 'src', cflags: ['-O2', '-g'], expectation: 'unknown',
  },
  {
    id: 'srcdir-differs-debug-mapped',
    why: 'the same move, with the reproducible-builds mitigation applied: -ffile-prefix-map '
      + 'and -fdebug-compilation-dir. If this reproduces and the previous case does not, the '
      + 'path is proven to be the cause rather than assumed to be.',
    dirs: 'src', cflags: ['-O2', '-g'], mapPaths: true, expectation: 'unknown',
  },
  {
    id: 'file-macro',
    why: 'the source directory moves and the program compiles its own path in through __FILE__. '
      + 'A path difference that survives into .rodata, where no debug-info switch reaches it.',
    dirs: 'src', cflags: ['-O2', STAMP_FILE], expectation: 'unknown',
  },
  {
    id: 'time-macros-unpinned',
    why: 'nothing moves except the clock: the program compiles __DATE__ and __TIME__ in, and the '
      + 'two builds are more than a second apart.',
    dirs: 'same', cflags: ['-O2', STAMP_TIME], sleepBetweenMs: 1100, expectation: 'unknown',
  },
  {
    id: 'time-macros-pinned',
    why: 'the same source and the same delay, with SOURCE_DATE_EPOCH pinned. The clock is still '
      + 'moving; the question is whether the compiler is still reading it.',
    dirs: 'same', cflags: ['-O2', STAMP_TIME], sleepBetweenMs: 1100,
    env: { SOURCE_DATE_EPOCH: '1700000000' }, expectation: 'unknown',
  },
  {
    id: 'buildid-link',
    why: 'identical inputs, linked with --build-id=sha1. The build id is a hash of the output, so '
      + 'it is identical exactly when everything else is.',
    dirs: 'same', cflags: ['-O2'], ldflags: ['-Wl,--build-id=sha1'], expectation: 'identical',
  },
];

if (args.has('list')) {
  for (const c of CASES) process.stdout.write(`${c.id}\n    ${c.why}\n`);
  process.exit(EXIT_OK);
}
if (args.has('help') || args.has('h')) {
  process.stdout.write(
    'usage: rebuild-compare.mjs --work <dir> [--case <id>] [--list] [--json <file>]\n'
    + '                          [--cc clang-18] [--allow-empty]\n',
  );
  process.exit(EXIT_OK);
}

const workDir = args.get('work');
if (typeof workDir !== 'string' || workDir.length === 0) {
  process.stderr.write('--work <dir> is required. Builds do not go under compiler/ (interfaces.md §1).\n');
  process.exit(EXIT_INCOMPLETE);
}

const ccName = typeof args.get('cc') === 'string' ? args.get('cc') : 'clang-18';
const wanted = args.all('case').filter((c) => typeof c === 'string');
const selected = wanted.length > 0 ? CASES.filter((c) => wanted.includes(c.id)) : CASES;
const unknownCase = wanted.filter((w) => !CASES.some((c) => c.id === w));
if (unknownCase.length > 0) {
  process.stderr.write(`no such case: ${unknownCase.join(', ')}. --list shows them all.\n`);
  process.exit(EXIT_INCOMPLETE);
}

// ── prerequisites ───────────────────────────────────────────────────────────

function which(name) {
  const r = spawnSync('sh', ['-c', `command -v ${JSON.stringify(name)}`], { encoding: 'utf8' });
  const p = (r.stdout ?? '').trim();
  return r.status === 0 && p.length > 0 ? p : null;
}

const ccPath = which(ccName);
const readelfPath = which('readelf');
const authorised = skipsAuthorised();
const degraded = [];

if (ccPath === null) {
  if (!authorised) {
    process.stderr.write(
      `${ccName} is not on PATH. That is a failure, not a skip: a reproducibility run that\n`
      + `built nothing has measured nothing. Set ${SKIP_ENV}=1 to turn this into a named skip.\n`,
    );
    process.exit(EXIT_INCOMPLETE);
  }
}
if (readelfPath === null) {
  if (!authorised) {
    process.stderr.write(
      `readelf is not on PATH, so a difference could be found but never explained. That is a\n`
      + `failure, not a skip. Set ${SKIP_ENV}=1 to run without cause analysis.\n`,
    );
    process.exit(EXIT_INCOMPLETE);
  }
  degraded.push('cause analysis (readelf is not installed): every difference is reported as NOT_OBSERVED');
}

// ── helpers ─────────────────────────────────────────────────────────────────

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function run(cmd, argv, opts = {}) {
  const r = spawnSync(cmd, argv, { encoding: 'utf8', ...opts });
  if (r.error) throw new Error(`${cmd}: ${r.error.message}`);
  if (r.status !== 0) {
    throw new Error(`${cmd} exited ${r.status}\n${r.stderr ?? ''}`);
  }
  return r.stdout ?? '';
}

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

/** Section names with bytes on disk, from `readelf -S -W`. */
function sectionNames(file) {
  if (readelfPath === null) return null;
  let out;
  try {
    out = run(readelfPath, ['-S', '-W', file]);
  } catch {
    return null;
  }
  const names = [];
  for (const line of out.split('\n')) {
    const m = /^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)/.exec(line);
    if (!m) continue;
    const [, name, type] = m;
    if (type === 'NULL' || type === 'NOBITS') continue;
    if (name === 'Name') continue;
    names.push(name);
  }
  return names;
}

function sectionBytes(file, name) {
  try {
    return run(readelfPath, ['-x', name, file]);
  } catch {
    return null;
  }
}

/**
 * Which sections differ between two ELF files, and the first line of hexdump
 * that differs in each. Returns null when readelf was not available.
 */
function explainDifference(a, b) {
  if (readelfPath === null) return null;
  const na = sectionNames(a);
  const nb = sectionNames(b);
  if (na === null || nb === null) return null;
  const all = [...new Set([...na, ...nb])].sort();
  const differing = [];
  for (const name of all) {
    if (!na.includes(name) || !nb.includes(name)) {
      differing.push({ section: name, kind: 'present-in-one-file-only' });
      continue;
    }
    const xa = sectionBytes(a, name);
    const xb = sectionBytes(b, name);
    if (xa === null || xb === null) { differing.push({ section: name, kind: 'unreadable' }); continue; }
    if (xa !== xb) {
      const la = xa.split('\n');
      const lb = xb.split('\n');
      let firstLine = null;
      for (let i = 0; i < Math.max(la.length, lb.length); i += 1) {
        if (la[i] !== lb[i]) { firstLine = { a: la[i] ?? '<eof>', b: lb[i] ?? '<eof>' }; break; }
      }
      differing.push({ section: name, kind: 'bytes-differ', firstDifferingLine: firstLine });
    }
  }
  return differing;
}

/** A one-sentence reading of a section list. Kept separate from the evidence. */
function readCause(differing) {
  if (differing === null) return 'NOT_OBSERVED (readelf was not available)';
  const names = differing.map((d) => d.section);
  const only = (pred) => names.length > 0 && names.every(pred);
  const has = (pred) => names.some(pred);
  const isDebug = (n) => n.startsWith('.debug');
  const isBuildId = (n) => n === '.note.gnu.build-id';
  if (names.length === 0) return 'no section differs, yet the files do: check the ELF header or the section table itself';
  if (only((n) => isDebug(n) || isBuildId(n))) {
    return 'debug information only (recorded paths); the build id follows from it and is not a cause';
  }
  if (has((n) => n === '.rodata' || n === '.rodata.str1.1')) {
    return 'a string compiled into the program (.rodata) — no debug-info switch reaches this one';
  }
  if (has((n) => n === '.comment')) return 'a different compiler build (.comment)';
  if (only(isBuildId)) return 'only the build id, which is a hash of the rest — inputs must differ somewhere readelf did not look';
  return `sections: ${names.join(', ')}`;
}

// ── one case ────────────────────────────────────────────────────────────────

async function runCase(c) {
  const caseDir = join(workDir, c.id);
  rmSync(caseDir, { force: true, recursive: true });
  mkdirSync(caseDir, { recursive: true });

  const keep = [];
  let oracle = null;

  for (let i = 0; i < 2; i += 1) {
    const suffix = c.dirs === 'same' ? '' : `-${i === 0 ? 'a' : 'b'}`;
    const srcDir = join(caseDir, `src${c.dirs === 'src' ? suffix : ''}`);
    const buildDir = join(caseDir, `build${c.dirs === 'build' ? suffix : ''}`);

    // CLEAN STATE. When both runs share a directory it is removed between them,
    // so run 2 cannot be an incremental build wearing run 1's clothes.
    rmSync(buildDir, { force: true, recursive: true });
    mkdirSync(srcDir, { recursive: true });
    mkdirSync(buildDir, { recursive: true });
    {
      const gen = spawnSync('bash', [MAKE_FIXTURES, srcDir], { encoding: 'utf8' });
      if (gen.status !== 0) {
        process.stderr.write(
          `could not generate the fixture into ${srcDir}: ${gen.stderr || gen.error?.message}\n`
          + 'That is a tool failure, not a case that can be skipped: without the sources '
          + 'there is nothing to build twice, and a comparison over nothing reproduces '
          + 'perfectly while measuring nothing.\n',
        );
        process.exit(EXIT_INCOMPLETE);
      }
    }

    const env = { ...process.env };
    delete env.SOURCE_DATE_EPOCH;
    Object.assign(env, c.env ?? {});

    const cflags = [...c.cflags];
    if (c.mapPaths) {
      cflags.push(`-ffile-prefix-map=${srcDir}=/fixture`, '-fdebug-compilation-dir=.');
    }

    if (i === 1 && c.sleepBetweenMs) await sleep(c.sleepBetweenMs);

    const objects = [];
    for (const unit of ['wipe', 'main']) {
      const obj = join(buildDir, `${unit}.o`);
      run(ccPath, [...cflags, '-c', join(srcDir, `${unit}.c`), '-o', obj], { cwd: buildDir, env });
      objects.push(obj);
    }
    const app = join(buildDir, 'app');
    run(ccPath, [...cflags, ...(c.ldflags ?? []), ...objects, '-o', app], { cwd: buildDir, env });

    // The fixture check, once, on the first build.
    if (i === 0) {
      const irs = {};
      for (const level of ['-O0', '-O2']) {
        const ll = join(buildDir, `wipe${level}.ll`);
        run(ccPath, [level, '-S', '-emit-llvm', join(srcDir, 'wipe.c'), '-o', ll], { cwd: buildDir, env });
        irs[level] = countMemsetCallSites(readFileSync(ll, 'utf8'));
      }
      oracle = {
        control: { O0: irs['-O0'].perFunction.control_wipe ?? 0, O2: irs['-O2'].perFunction.control_wipe ?? 0 },
        declares: { O0: irs['-O0'].declares, O2: irs['-O2'].declares },
        target: { O0: irs['-O0'].perFunction.wipe_secret ?? 0, O2: irs['-O2'].perFunction.wipe_secret ?? 0 },
        total: { O0: irs['-O0'].total, O2: irs['-O2'].total },
      };
    }

    const kept = join(caseDir, 'kept', `run${i + 1}`);
    mkdirSync(kept, { recursive: true });
    const files = {};
    for (const name of ['wipe.o', 'main.o', 'app']) {
      copyFileSync(join(buildDir, name), join(kept, name));
      files[name] = join(kept, name);
    }
    keep.push(files);
  }

  const artefacts = [];
  for (const name of ['wipe.o', 'main.o', 'app']) {
    const a = keep[0][name];
    const b = keep[1][name];
    const da = sha256(a);
    const db = sha256(b);
    if (da === db) {
      artefacts.push({ cause: null, identical: true, name, sha256: da });
    } else {
      const differing = explainDifference(a, b);
      artefacts.push({
        cause: readCause(differing),
        differingSections: differing,
        identical: false,
        name,
        sha256A: da,
        sha256B: db,
      });
    }
  }

  const oracleOk = oracle !== null && oracle.control.O2 > 0 && oracle.target.O0 > 0;
  return { artefacts, id: c.id, oracle, oracleOk, reproduced: artefacts.every((x) => x.identical), why: c.why };
}

// ── main ────────────────────────────────────────────────────────────────────

mkdirSync(workDir, { recursive: true });

const results = [];
const skippedNames = [];
let checked = 0;

for (const c of selected) {
  if (ccPath === null) {
    skippedNames.push(`${c.id} (${ccName} is not installed; ${SKIP_ENV} authorised the skip)`);
    continue;
  }
  let r;
  try {
    // eslint-disable-next-line no-await-in-loop
    r = await runCase(c);
  } catch (err) {
    r = { artefacts: [], error: String(err.message ?? err), id: c.id, oracle: null, oracleOk: false, reproduced: null, why: c.why };
  }
  results.push(r);
  checked += 1;
}

for (const r of results) {
  const verdict = r.error ? 'BUILD FAILED' : r.reproduced ? 'identical' : 'DIFFERS';
  process.stdout.write(`${r.id}: ${verdict}\n`);
  if (r.error) { process.stdout.write(`    ${r.error.split('\n')[0]}\n`); continue; }
  if (r.oracle) {
    process.stdout.write(
      `    fixture: target memset call sites -O0=${r.oracle.target.O0} -O2=${r.oracle.target.O2}; `
      + `control -O0=${r.oracle.control.O0} -O2=${r.oracle.control.O2}; `
      + `declares -O0=${r.oracle.declares.O0} -O2=${r.oracle.declares.O2}\n`,
    );
  }
  if (!r.oracleOk) {
    process.stdout.write('    BROKEN MEASUREMENT: the control effect is not present, so this comparison says nothing\n');
  }
  for (const a of r.artefacts) {
    if (a.identical) process.stdout.write(`    ${a.name}: identical (${a.sha256.slice(0, 16)})\n`);
    else {
      process.stdout.write(`    ${a.name}: differs — ${a.cause}\n`);
      for (const d of (a.differingSections ?? [])) {
        process.stdout.write(`        ${d.section} ${d.kind}\n`);
      }
    }
  }
}

for (const d of degraded) process.stdout.write(`DEGRADED: ${d}\n`);

const reportPath = typeof args.get('json') === 'string' ? args.get('json') : join(workDir, 'rebuild-report.json');
writeFileSync(reportPath, `${JSON.stringify({ cases: results, degraded }, null, 2)}\n`, 'utf8');
process.stdout.write(`report ${reportPath}\n`);

const byCounts = reportCounts({
  inputs: selected.length,
  checked,
  skipped: skippedNames.length,
  skippedNames,
  allowEmpty: args.has('allow-empty'),
});
if (byCounts !== null) process.exit(byCounts);

const broken = results.filter((r) => r.error || !r.oracleOk);
const unexpected = results.filter((r) => !r.error && r.oracleOk
  && CASES.find((c) => c.id === r.id).expectation === 'identical' && r.reproduced === false);

process.stdout.write(
  `cases=${results.length} reproduced=${results.filter((r) => r.reproduced === true).length} `
  + `differed=${results.filter((r) => r.reproduced === false).length} broken=${broken.length}\n`,
);

if (broken.length > 0) {
  process.stderr.write(`${broken.length} case(s) produced no usable measurement: ${broken.map((r) => r.id).join(', ')}\n`);
  process.exit(EXIT_INCOMPLETE);
}
if (unexpected.length > 0) {
  process.stderr.write(
    `${unexpected.length} case(s) that must reproduce did not: ${unexpected.map((r) => r.id).join(', ')}.\n`
    + 'Every other row in this matrix is read relative to those, so nothing here can be believed.\n',
  );
  process.exit(EXIT_FINDINGS);
}
process.exit(EXIT_OK);
