#!/usr/bin/env node
/**
 * The compiler version ladder: at which compiler version does the wipe first
 * disappear?
 *
 * The project is pinned to clang-18 and gcc-13, and every erasure number it has
 * is a number about those two. That pin is a scope limit that reads like a
 * result: "the wipe is eliminated at -O2" is a sentence about one compiler
 * build, and a reader is entitled to ask whether the previous release did it
 * too. This lane puts the installed versions side by side and, per
 * (file, level, vendor), records the version at which WIPE_ELIMINATED FIRST
 * APPEARS -- or says, with the gap named, that it cannot.
 *
 * The shape is borrowed and the borrowing is stated. Simon, Chisnall and
 * Anderson (EuroS&P 2018) compiled constant-time selection with Clang 3.0, 3.3
 * and 3.9 and reported that as the version increases, more implementations
 * become insecure. Three versions, hand-inspected, one property. What this lane
 * adds is the oracle: each rung's verdict comes from differential compilation
 * against an ablated form with a positive control co-resident in the same
 * translation unit, so "the wipe was removed" stays separable from "the
 * extractor stopped recognising wipes in this version's output" at every rung.
 * Hand inspection cannot separate those at scale, and a name search cannot
 * separate them at all.
 *
 *   node run-version-ladder.mjs --out <lab dir> [options]
 *
 *   --out <dir>      where the rows, the report and the build scratch go. Required.
 *                    A directory inside the repository is refused: these are
 *                    measurement outputs and they live on the side that makes them.
 *   --ccs a,b,c      the rungs to try (default: every rung of both declared ladders).
 *                    A rung that is not installed is recorded as not obtained and
 *                    produces no cell rows at all.
 *   --opts -O0,..    optimisation levels (default: all five the find step used).
 *   --ids a,b,c      corpus files to use as subjects, by r2 id. The token
 *                    `removable` selects every erasure file the tracked rows call
 *                    idiom=removable -- that is the full-corpus sweep and it is
 *                    hundreds of compiles per rung. Default: the smoke set below.
 *   --fixture <dir>  the hand-written erasure fixture directory (the one
 *                    compiler/llvm-pass/tools/make-fixtures.sh writes to
 *                    $IRCK_LAB/fixtures/erasure). Adds target.c as a subject.
 *   --conc <n>       concurrent compiles (default 4; the box is shared).
 *   --no-subjects    leave out this lane's own tracked subjects/*.c. They are in by
 *                    default: they are the only subjects nobody generated.
 *   --rows <file>    anchor against these find-step rows instead of the tracked
 *                    ../ai-generated/data/r2-build-rows.json. The manifest records
 *                    which was used, by repository-relative name or as
 *                    '(outside the repository)' -- never as a path.
 *   --write-data     also copy the rows and the report into this lane's data/.
 *
 * Exit codes
 *   0  ran, the anchor compared at least one cell, and every compared cell
 *      reproduced the tracked find-step verdict
 *   2  the anchor did not hold: a compared cell disagreed, a compared cell had
 *      no tracked verdict at all, or NOTHING was compared -- no anchor rung was
 *      obtained, no selected subject is anchorable, or the rows name no erasure
 *      row for an obtained anchor rung. "0/0 agree" is not a pass
 *   3  nothing was selected (no subject, or no rung obtained)
 *   4  bad arguments
 *   5  the tracked rows could not be read, or an output could not be written,
 *      or a text about to be written carries an absolute path
 *   6  the identity guard refused a --cc: the binary is not the version its
 *      name claims
 *
 * The pure parts -- the identity guard, the first-appearance rule, the counting
 * lines, the anchor join -- are in lib/ and tested in test/ without a compiler.
 * main() runs only when this file is executed.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join, relative, isAbsolute, basename, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  FLAGS, CONTROL, CONTROL_EFFECT, wipeSpans, ablateSpans, compile, pool, verdictOf, bodyOf,
} from '../ai-generated/lib/ablation-cell.mjs';
import { vendorOf, fortifyFromDefines, trackedCcProblem } from '../repair-loop/lib/vendor.mjs';
import { differsOnlyInLabels } from '../repair-loop/lib/surgicality.mjs';
import { absolutePathHits, sha256Text, rowsFileLabel } from '../repair-loop/lib/provenance.mjs';
import {
  LADDER, ANCHOR_CC, ALL_OPTS, identityProblem, spelledMajor, versionFromBanner,
  firstAppearance, versionCounting, appearanceCounting, shortMark, appearanceSentence,
} from './lib/ladder.mjs';
import {
  anchorIndex, anchorDisagreements, disagreementLine, unanchorableIds, vacuousAnchorProblem,
  anchorProblem, ANCHOR_CCS,
} from './lib/anchor.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../..');
const CORPUS = resolve(HERE, '../ai-generated/generated-corpus/r2');
const TRACKED = resolve(HERE, '../ai-generated/data/r2-build-rows.json');
const SCEN = resolve(HERE, '../ai-generated/scenarios.json');

/**
 * The smoke set: six erasure files whose tracked idiom is `removable`, chosen to
 * span what the ladder might do rather than to make it look decisive.
 *
 * Under clang-18/gcc-13 the tracked rows give these five distinct shapes:
 *   haiku_E_aeskey_r1    eliminated from -O1 on both vendors
 *   fable_N_hmackey_r1   eliminated from -O1 on both vendors
 *   fable_N_hmackey_r3   -O1 splits the vendors: gcc eliminates, clang does not
 *   fable_N_otpsecret_r3 same split, two wipe spans rather than one
 *   opus_N_pinpad_r2     survives at every level on both vendors
 *   haiku_S_pwverify_r1  survives everywhere, nine spans -- the negative case
 * The last two are the ones that make a ladder result falsifiable: if a rung
 * eliminated those, the elimination would be about the rung and not the file.
 */
export const SMOKE_IDS = Object.freeze([
  'haiku_E_aeskey_r1',
  'fable_N_hmackey_r1',
  'fable_N_hmackey_r3',
  'fable_N_otpsecret_r3',
  'opus_N_pinpad_r2',
  'haiku_S_pwverify_r1',
]);

/** The fixture subject's id and target function, when --fixture is given. */
const FIXTURE_ID = 'llvm-pass-fixture-erasure-target';
const FIXTURE_FN = 'handle_request';
const FIXTURE_SOURCE = 'compiler/llvm-pass/tools/make-fixtures.sh (erasure/target.c)';

/**
 * The marker a tracked subject names its target function with.
 *
 * Written in the file rather than in a table here, so that the subject and the
 * function the measurement asks about cannot drift apart: renaming the function
 * without the marker makes funcBodySpan find nothing, and the run says so
 * instead of quietly measuring an unscoped file.
 */
const TARGET_MARKER = /^\/\*\s*VG-LADDER-TARGET:\s*([A-Za-z_]\w*)\s*\*\/\s*$/m;

// ---------------------------------------------------------------- pure --------

/** argv -> options, or {error}. */
export function parseArgs(argv) {
  const o = { out: null, ccs: null, opts: [...ALL_OPTS], ids: null, fixture: null, conc: 4, writeData: false, writeSweep: false, noSubjects: false, rows: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    try {
      if (a === '--out') o.out = next();
      else if (a === '--ccs') o.ccs = next().split(',').map((s) => s.trim()).filter(Boolean);
      else if (a === '--opts') o.opts = next().split(',').map((s) => s.trim()).filter(Boolean);
      else if (a === '--ids') o.ids = next().split(',').map((s) => s.trim()).filter(Boolean);
      else if (a === '--fixture') o.fixture = next();
      else if (a === '--conc') o.conc = Number(next());
      else if (a === '--rows') o.rows = next();
      else if (a === '--no-subjects') o.noSubjects = true;
      else if (a === '--write-data') o.writeData = true;
      else if (a === '--write-sweep') o.writeSweep = true;
      else return { error: `unknown argument ${a}` };
    } catch (e) { return { error: e.message }; }
  }
  if (!o.out) return { error: '--out <dir> is required' };
  if (!Number.isInteger(o.conc) || o.conc < 1) return { error: '--conc must be a positive integer' };
  const badOpt = o.opts.find((x) => !ALL_OPTS.includes(x));
  if (badOpt) return { error: `--opts: ${badOpt} is not one of ${ALL_OPTS.join(', ')}` };
  return o;
}

/** Every rung of both declared ladders, as compiler basenames, in ladder order. */
export function allRungs() {
  const out = [];
  for (const [vendor, majors] of Object.entries(LADDER)) for (const m of majors) out.push(`${vendor}-${m}`);
  return out;
}

/** A path inside the repository is refused for --out: outputs live on the measuring side. */
export function outIsInsideRepo(out, repoRoot) {
  const rel = relative(resolve(repoRoot), resolve(out));
  return rel === '' || (!rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel));
}

/**
 * The corpus sweep, small enough to keep.
 *
 * The sweep is 7,315 cells and its rows file is 3.1 MB -- two and a half times
 * the tracked find-step rows it is anchored against, and every byte of it
 * derived: the corpus is tracked, the compilers are pinned, and the whole thing
 * rebuilds in under two minutes. Tracking those rows would be tracking a cache.
 *
 * What does NOT rebuild by itself is the FINDING, so that is what this keeps:
 * the accounting (which must add up), the anchor (which is what makes the run
 * worth believing), the resolved compiler identities (which is what "gcc-11"
 * meant on the day), and the ladder questions that answered `observed` -- the
 * ones where a lower rung was obtained AND kept the wipe, so a transition was
 * actually seen rather than inferred from the bottom of the ladder.
 *
 * The `none-below` majority is deliberately reduced to a count. Those are the
 * questions the ladder cannot answer, and listing 825 of them would bury the 8
 * it can. The count is kept because it has to add up with the rest.
 */
export function sweepRecord({ manifest, rows, appearances }) {
  const verdictTotals = {};
  for (const r of rows) verdictTotals[r.verdict] = (verdictTotals[r.verdict] || 0) + 1;
  const byVendorLevel = {};
  for (const r of rows) {
    const k = `${r.vendor} ${r.opt}`;
    const b = byVendorLevel[k] || (byVendorLevel[k] = { eliminated: 0, survived: 0, other: 0 });
    if (r.verdict === 'WIPE_ELIMINATED') b.eliminated += 1;
    else if (r.verdict === 'WIPE_SURVIVED') b.survived += 1;
    else b.other += 1;
  }
  const observed = appearances
    .filter((a) => a.transition === 'observed')
    .map((a) => ({ id: a.id, opt: a.opt, vendor: a.vendor, firstAt: a.version, cells: a.cells }))
    .sort((x, y) => (x.id + x.vendor + x.opt).localeCompare(y.id + y.vendor + y.opt));
  const transitions = {};
  for (const a of appearances) {
    const k = a.transition === null ? 'never-eliminated' : a.transition;
    transitions[k] = (transitions[k] || 0) + 1;
  }
  return {
    tool: 'version-ladder sweep',
    what: 'every erasure file the tracked rows call idiom=removable, on every obtained rung, at every level',
    subjects: manifest.subjects.filter((x) => x.anchorable).length,
    opts: manifest.opts,
    versions: manifest.versions,
    counting: manifest.counting,
    anchor: manifest.anchor,
    rowsFile: manifest.rowsFile,
    trackedRowsSha256: manifest.trackedRowsSha256,
    docker: manifest.docker,
    verdictTotals,
    byVendorLevel,
    transitions,
    observed,
    cellRows: {
      tracked: false,
      count: rows.length,
      why: 'derived and rebuildable in under two minutes; see the sweep command in README.md',
    },
  };
}


/**
 * One cell row. Every number is an integer; no path of any kind appears.
 * `labelsOnly` is reported, never folded into the verdict -- see the README.
 */
export function ladderRow({ id, fn, vendor, cc, major, opt, nSpans, idiom, namedSecret, scoped, cell, labelsOnly, spellingSeen }) {
  return {
    id,
    fn,
    vendor,
    cc,
    major,
    opt,
    n_spans: nSpans,
    idiom,
    named_secret: namedSecret,
    scoped,
    control: cell.control ?? null,
    control_via: cell.control_via ?? null,
    verdict: cell.verdict,
    labelsOnly,
    spellingSeen,
  };
}

/**
 * Was this run the corpus-scale sweep, or a selection out of it?
 *
 * The report's "NOT measured by this run" list used to say the corpus-scale
 * sweep was not done UNCONDITIONALLY -- including on the run that had just done
 * it. A caveat that is printed whether or not it is true teaches a reader to
 * skip the list, which is the opposite of what the list is for, and it is the
 * same failure this lane's own `0/0 cells reproduce -> exit 0` was: a number
 * that cannot distinguish the two cases it is asked about.
 *
 * The sweep is the 133 erasure files the tracked rows call idiom=removable --
 * the same set `--ids removable` expands to, taken from the same rows, so the
 * two cannot drift apart. Coverage is over the ANCHORABLE subjects only: this
 * lane's own subjects/ files and the llvm-pass fixture are not corpus files and
 * neither adds to nor subtracts from the corpus question.
 */
export function sweepCoverage(trackedRows, subjects) {
  const rem = new Set(
    (Array.isArray(trackedRows) ? trackedRows : [])
      .filter((r) => r && r.kind === 'erasure' && r.idiom === 'removable')
      .map((r) => r.id),
  );
  const swept = new Set((subjects || []).filter((s) => s && s.anchorable && rem.has(s.id)).map((s) => s.id));
  return { removableTotal: rem.size, removableSwept: swept.size, complete: rem.size > 0 && swept.size === rem.size };
}

/**
 * The per-(file, level, vendor) appearance records, from the cell rows.
 * Rows whose compiler is not on the vendor's declared ladder are ignored.
 */
export function appearancesFrom(rows, { opts, ids }) {
  const out = [];
  for (const vendor of Object.keys(LADDER)) {
    for (const id of ids) {
      for (const opt of opts) {
        const cells = {};
        for (const r of rows) {
          if (r.vendor !== vendor || r.id !== id || r.opt !== opt) continue;
          if (!LADDER[vendor].includes(r.major)) continue;
          cells[r.major] = r.verdict;
        }
        if (!Object.keys(cells).length) continue;
        out.push({ id, opt, vendor, cells, ...firstAppearance({ vendor, cells }) });
      }
    }
  }
  return out;
}

/**
 * Which memset spelling the file-as-written listing calls, from the effect
 * symbol list the repository already declares (CONTROL_EFFECT.symbols -- never a
 * literal of its own; compiler/schema/effect-symbol-lists.test.mjs exists to stop
 * a tenth copy of that list appearing).
 *
 * METADATA ONLY. It is computed after the verdict and is read by nothing. The
 * verdict is a differential compilation and searching a listing for a symbol
 * name is exactly what interfaces.md section 4 forbids deciding an effect by.
 * It is here because _FORTIFY_SOURCE changes which of these spellings a source
 * `memset` becomes, and a reader comparing rungs with different fortify
 * readings should be able to see that rather than infer it.
 */
export function spellingIn(asm) {
  if (typeof asm !== 'string') return null;
  const seen = CONTROL_EFFECT.symbols.filter((s) => new RegExp(`\\b(?:call|jmp)\\s+${s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(asm));
  return seen.length ? seen.join('+') : 'none';
}

// ---------------------------------------------------------------- impure ------

const die = (code, msg) => { process.stderr.write(`version-ladder: ${msg}\n`); process.exit(code); };

/** `<cc> --version`, `-dumpversion`, and the digest of the binary readlink -f reaches. */
async function probeCompiler(cc) {
  let banner;
  try {
    banner = (await run(cc, ['--version'], { timeout: 30000 })).stdout;
  } catch (e) {
    return { obtained: false, reason: 'not-installed', detail: String(e && e.code ? e.code : e).slice(0, 120) };
  }
  let dump = '';
  try { dump = (await run(cc, ['-dumpversion'], { timeout: 30000 })).stdout; } catch { dump = ''; }
  // The RESOLVED binary is what was actually executed; a name is not a binary.
  // Only its digest and its basename are recorded: the directory it sits in is
  // this machine's layout and the provenance scan is right to reject it.
  let resolvedBase = null; let resolvedSha256 = null;
  try {
    const which = (await run('sh', ['-c', `readlink -f "$(command -v ${cc})"`], { timeout: 30000 })).stdout.trim();
    if (which) {
      resolvedBase = basename(which);
      resolvedSha256 = createHash('sha256').update(readFileSync(which)).digest('hex');
    }
  } catch { /* a machine without readlink -f still gets a banner and a dumpversion */ }
  return { obtained: true, banner: banner.split('\n')[0].replace(/\r$/, ''), dumpversion: dump.trim(), resolvedBase, resolvedSha256 };
}

/** What `<cc> FLAGS <opt> -dM -E` predefines about _FORTIFY_SOURCE, per level. */
async function fortifyPerLevel(cc, opts, probePath) {
  const out = {};
  for (const opt of opts) {
    try {
      const { stdout } = await run(cc, [...FLAGS, opt, '-dM', '-E', probePath], { timeout: 60000, maxBuffer: 32 << 20 });
      const v = fortifyFromDefines(stdout);
      out[opt] = v === null ? 'not-defined' : (v === '' ? 'defined-no-value' : v);
    } catch {
      out[opt] = 'reading-failed';
    }
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.error) die(4, args.error);
  if (outIsInsideRepo(args.out, REPO)) {
    die(4, `--out ${args.out} is inside the repository. Measurement outputs live on the side that produces them `
      + '(scripts/check-packaging-invariants.mjs refuses them under compiler/); point --out at a lab directory');
  }

  const rowsPath = args.rows ? resolve(args.rows) : TRACKED;
  let tracked; let trackedText;
  try { trackedText = readFileSync(rowsPath, 'utf8'); tracked = JSON.parse(trackedText); }
  catch (e) { die(5, `could not read the find-step rows to anchor against: ${e.message}`); }
  const index = anchorIndex(tracked);

  let scen;
  try { scen = JSON.parse(readFileSync(SCEN, 'utf8')); }
  catch (e) { die(5, `could not read scenarios.json: ${e.message}`); }

  // ---- subjects ----
  let ids = args.ids ?? [...SMOKE_IDS];
  if (ids.includes('removable')) {
    const rem = [...new Set(tracked.filter((r) => r && r.kind === 'erasure' && r.idiom === 'removable').map((r) => r.id))].sort();
    ids = [...new Set([...ids.filter((x) => x !== 'removable'), ...rem])];
  }
  const subjects = [];
  for (const id of ids) {
    const p = join(CORPUS, `${id}.c`);
    if (!existsSync(p)) die(4, `--ids: ${id} is not a file of the r2 corpus`);
    const scenName = id.split('_')[2];
    const meta = scen[scenName];
    if (!meta) die(4, `--ids: ${id} names scenario ${scenName}, which scenarios.json does not describe`);
    subjects.push({ id, fn: meta.fn, path: p, anchorable: true });
  }
  // This lane's own hand-written subjects. Tracked (subjects/, the
  // negative-controls precedent) rather than generated, because their point is
  // that somebody chose what they contain: one removable dead store and one
  // volatile-barriered wipe that no rung may touch. Not anchorable -- the
  // tracked r2 rows are about the r2 corpus and say nothing about these.
  if (!args.noSubjects) {
    const dir = join(HERE, 'subjects');
    const names = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.c')).sort() : [];
    for (const f of names) {
      const p = join(dir, f);
      const m = TARGET_MARKER.exec(readFileSync(p, 'utf8'));
      if (!m) die(4, `subjects/${f} has no "/* VG-LADDER-TARGET: <fn> */" line, so nothing says which function to measure`);
      subjects.push({ id: f.replace(/\.c$/, ''), fn: m[1], path: p, anchorable: false, source: `compiler/eval/version-ladder/subjects/${f}` });
    }
  }
  if (args.fixture) {
    const p = join(args.fixture, 'target.c');
    if (!existsSync(p)) {
      die(4, `--fixture ${args.fixture}: no target.c there. Generate it first with `
        + 'compiler/llvm-pass/tools/make-fixtures.sh, which writes $IRCK_LAB/fixtures/erasure');
    }
    subjects.push({ id: FIXTURE_ID, fn: FIXTURE_FN, path: p, anchorable: false, source: FIXTURE_SOURCE });
  }
  if (!subjects.length) die(3, 'no subjects selected');

  const unanchorable = unanchorableIds(subjects.filter((s) => s.anchorable).map((s) => s.id), index, { opts: args.opts });
  if (unanchorable.length) {
    die(4, `these ids have no tracked erasure cell under ${ANCHOR_CCS.join(' or ')} at any selected level, `
      + `so the anchor would check nothing for them: ${unanchorable.join(', ')}`);
  }

  // ---- rungs ----
  const wanted = args.ccs ?? allRungs();
  const outDir = resolve(args.out);
  const buildDir = join(outDir, 'build');
  mkdirSync(buildDir, { recursive: true });
  const probePath = join(buildDir, 'fortify-probe.c');
  writeFileSync(probePath, '#include <string.h>\nint vg_probe(void) { return 0; }\n', 'utf8');

  // Every declared rung gets an entry, including one this invocation did not ask
  // for. Otherwise the counting line's denominator is the subset --ccs named, and
  // "2 obtained" against a ladder of 11 would read as nine rungs that failed.
  const versions = [];
  for (const cc of allRungs()) {
    if (wanted.includes(cc)) continue;
    versions.push({ cc, vendor: vendorOf(cc), major: spelledMajor(cc), obtained: false, reason: 'not-requested' });
  }
  for (const cc of wanted) {
    const vendor = vendorOf(cc);
    const p = await probeCompiler(cc);
    if (!p.obtained) {
      // Not installed. NOT "unsupported" (the toolchain refused nothing -- it was
      // never asked) and NOT "not observed" (nothing was attempted to observe).
      versions.push({ cc, vendor, major: spelledMajor(cc), obtained: false, reason: 'not-installed' });
      continue;
    }
    const problem = identityProblem({ cc, vendor, banner: p.banner, dumpversion: p.dumpversion });
    if (problem) die(6, `identity guard: ${problem}`);
    const full = versionFromBanner(vendor, p.banner);
    versions.push({
      cc, vendor, major: spelledMajor(cc), obtained: true,
      version: full.full, banner: p.banner, dumpversion: p.dumpversion,
      resolvedBase: p.resolvedBase, resolvedSha256: p.resolvedSha256,
      fortify: await fortifyPerLevel(cc, args.opts, probePath),
    });
  }
  const rungOrder = allRungs();
  versions.sort((a, b) => rungOrder.indexOf(a.cc) - rungOrder.indexOf(b.cc));
  const obtained = versions.filter((v) => v.obtained);
  if (!obtained.length) die(3, `none of the requested rungs is installed (${wanted.join(', ')})`);

  // ---- the anchor must have something to compare, and it is decided here ----
  //
  // Before the compiles, because the answer is already known and because a run
  // that cannot be anchored should not spend the box's time producing a ladder
  // nobody may read. Without this the run printed "0/0 cells reproduce the
  // tracked verdict" and exited 0 -- on any machine without the pinned pair,
  // from the DEFAULT invocation.
  const anchorableIds = subjects.filter((s) => s.anchorable).map((s) => s.id);
  const vacuous = vacuousAnchorProblem({ obtainedCcs: obtained.map((v) => v.cc), anchorableIds });
  if (vacuous) die(2, vacuous);
  // And the rows have to be able to judge the anchor rungs this run obtained.
  // This one IS the repair loop's guard, reused: trackedCcProblem asks exactly
  // this question of a rows file, and its message is the one the README quotes.
  // Only the obtained anchor rungs are asked about -- a clang-18-only rows file
  // is a perfectly good anchor for a run that obtained clang-18.
  for (const cc of obtained.map((v) => v.cc).filter((cc) => ANCHOR_CCS.includes(cc))) {
    const why = trackedCcProblem(tracked, cc);
    if (why) die(2, `the anchor could not be established: ${why}`);
  }

  // ---- cells ----
  const prepared = [];
  for (const s of subjects) {
    const src = readFileSync(s.path, 'utf8');
    const { spans, kinds, namedSecret, scoped } = wipeSpans(src, s.fn);
    if (!spans.length) {
      process.stderr.write(`version-ladder: ${s.id} has no wipe span for ${s.fn}; it is not a ladder subject and is skipped\n`);
      continue;
    }
    const idiom = kinds.includes('removable') && kinds.includes('nonremovable') ? 'both'
      : kinds.includes('removable') ? 'removable' : 'nonremovable';
    const pW = join(buildDir, `${s.id}.w.c`);
    const pWo = join(buildDir, `${s.id}.wo.c`);
    writeFileSync(pW, src + CONTROL, 'utf8');
    writeFileSync(pWo, ablateSpans(src, spans) + CONTROL, 'utf8');
    prepared.push({ ...s, pW, pWo, nSpans: spans.length, idiom, namedSecret, scoped });
  }
  if (!prepared.length) die(3, 'no subject has a wipe span');

  const jobs = [];
  for (const s of prepared) for (const v of obtained) for (const opt of args.opts) jobs.push({ s, v, opt });
  process.stderr.write(`version-ladder: ${prepared.length} subject(s) x ${obtained.length} rung(s) x ${args.opts.length} level(s) = ${jobs.length} cells\n`);

  const rows = [];
  await pool(jobs, async ({ s, v, opt }) => {
    const tag = `${s.id}.${v.cc}${opt}`;
    const aW = await compile(v.cc, [opt], s.pW, join(buildDir, `${tag}.w.s`));
    const aWo = await compile(v.cc, [opt], s.pWo, join(buildDir, `${tag}.wo.s`));
    const cell = verdictOf(aW, aWo, s.fn);
    // labelsOnly: a WIPE_SURVIVED that is only gcc renumbering its unit-wide
    // .L<n> labels. Reported beside the verdict and never folded into it, the
    // way the repair loop reports it (repair-loop/README.md, "Surgicality").
    let labelsOnly = null;
    if (cell.verdict === 'WIPE_SURVIVED' && aW && aWo) {
      labelsOnly = differsOnlyInLabels(bodyOf(aW, s.fn), bodyOf(aWo, s.fn));
    }
    rows.push(ladderRow({
      id: s.id, fn: s.fn, vendor: v.vendor, cc: v.cc, major: v.major, opt,
      nSpans: s.nSpans, idiom: s.idiom, namedSecret: s.namedSecret, scoped: s.scoped,
      cell, labelsOnly, spellingSeen: spellingIn(aW),
    }));
  }, args.conc);
  rows.sort((a, b) => a.id.localeCompare(b.id) || a.vendor.localeCompare(b.vendor) || a.major - b.major || ALL_OPTS.indexOf(a.opt) - ALL_OPTS.indexOf(b.opt));

  // ---- anchor ----
  const anchorRows = rows.filter((r) => prepared.find((s) => s.id === r.id && s.anchorable));
  const anchor = anchorDisagreements(anchorRows, index);
  // The backstop for the pre-flight above, and the ONE place the exit code is
  // decided from: null here is the only thing that lets this run exit 0. The
  // pre-flight cannot cover every path to an empty join -- an anchorable subject
  // whose wipe spans vanish is dropped between the two -- and "checked: 0" must
  // never reach the exit as a pass.
  const notAnchored = anchorProblem(anchor);

  // ---- first appearance ----
  const appearances = appearancesFrom(rows, { opts: args.opts, ids: prepared.map((s) => s.id) });
  const vCount = versionCounting(versions);
  const aCount = appearanceCounting(appearances);

  // ---- report ----
  const L = [];
  L.push('compiler version ladder: at which version does the wipe first disappear?');
  L.push('');
  L.push(`versions: ${vCount.declared} declared = ${vCount.obtained} obtained + ${vCount.skipped} skipped `
    + `(${vCount.notInstalled} not-installed, ${vCount.notRequested} not-requested)`
    + `${vCount.accountedFor ? '' : '   ACCOUNTING BROKEN: these do not add up'}`);
  L.push(`cells:    ${rows.length} = ${prepared.length} subject(s) x ${obtained.length} obtained rung(s) x ${args.opts.length} level(s); ${rows.length * 2} compiles`);
  L.push(`ladder questions: ${aCount.asked} asked = ${aCount.firstAt} first-appearance + ${aCount.never} never-eliminated + ${aCount.undetermined} undetermined`);
  L.push(`  of the ${aCount.firstAt} first-appearance: ${aCount.firstAtObserved} with a transition observed between two `
    + `obtained rungs, ${aCount.firstAtNoneBelow} already eliminated at the lowest rung of the declared ladder, where `
    + 'there is no rung below to have kept the wipe and no transition was observed'
    + `${aCount.accountedFor ? '' : '   ACCOUNTING BROKEN: these do not add up'}`);
  L.push('');
  L.push('A rung that was not obtained produces no cell rows. It is counted as skipped and printed');
  L.push('as -(not obtained). It is never NOT_OBSERVED and never UNSUPPORTED: nothing was asked of');
  L.push('it and nothing refused, so neither of those words is true of it.');
  L.push('');
  L.push('rungs');
  for (const v of versions) {
    if (!v.obtained) { L.push(`  ${v.cc.padEnd(9)} -(not obtained)  reason: ${v.reason}`); continue; }
    const fort = args.opts.map((o) => `${o}=${v.fortify[o]}`).join(' ');
    L.push(`  ${v.cc.padEnd(9)} ${String(v.version).padEnd(8)} sha256 ${String(v.resolvedSha256).slice(0, 16)} (${v.resolvedBase})`);
    L.push(`  ${' '.repeat(9)} banner: ${v.banner}`);
    L.push(`  ${' '.repeat(9)} _FORTIFY_SOURCE with the lane FLAGS (-dM -E): ${fort}`);
  }
  L.push('');
  L.push(`anchor against the find-step rows in ${rowsFileLabel(rowsPath, { defaultPath: TRACKED, repoRoot: REPO })} (${ANCHOR_CCS.join(', ')})`);
  L.push(`  ${anchor.agreed}/${anchor.checked} cells reproduce the tracked verdict`);
  if (notAnchored) {
    L.push(`  ${notAnchored}.`);
    L.push('  Nothing below is anchored: a comparative ladder with no fixed point cannot tell a real');
    L.push('  version effect from a systematic error that lands on every rung. This run exits 2.');
  }
  if (anchor.disagreements.length) {
    L.push('  DISAGREEMENTS -- every other rung is unexplained until these are:');
    for (const d of anchor.disagreements) L.push(disagreementLine(d));
  }
  L.push('');
  for (const vendor of Object.keys(LADDER)) {
    const rungs = LADDER[vendor];
    const have = rungs.filter((m) => versions.find((v) => v.vendor === vendor && v.major === m && v.obtained));
    if (!have.length) { L.push(`${vendor}: no rung obtained`); L.push(''); continue; }
    L.push(`${vendor} ladder  (${rungs.map((m) => (have.includes(m) ? String(m) : `${m}-`)).join(' ')})   E eliminated  S survived  ? unscorable  - not obtained`);
    L.push(`  ${'id'.padEnd(34)} ${'lvl'.padEnd(4)} ${rungs.map((m) => String(m).padStart(3)).join('')}  first appearance`);
    // A FIRST_AT at the lowest rung is starred, and the star is explained under
    // the table it appears in. Without it the column reads `clang-15` and a
    // reader takes a version for a finding: there is no rung below 15, so
    // nothing was observed to keep the wipe and no transition was seen.
    let starred = false;
    for (const a of appearances.filter((x) => x.vendor === vendor)) {
      const marks = rungs.map((m) => shortMark(a.cells, m).padStart(3)).join('');
      const star = a.status === 'FIRST_AT' && a.transition === 'none-below';
      starred = starred || star;
      const verdict = a.status === 'FIRST_AT' ? `${vendor}-${a.version}${star ? '*' : ''}` : a.status;
      L.push(`  ${a.id.padEnd(34)} ${a.opt.padEnd(4)} ${marks}  ${verdict}`);
    }
    if (starred) {
      L.push(`  * the LOWEST rung of the declared ${vendor} ladder: nothing below it was measured to keep the wipe,`);
      L.push('    so no transition was observed and this is not a version introducing the elimination.');
    }
    L.push('');
  }
  L.push('what each ladder question rests on');
  for (const a of appearances.filter((x) => x.status !== 'UNDETERMINED')) {
    L.push(`  ${a.id} ${a.opt} ${a.vendor}: ${appearanceSentence(a)}`);
  }
  // The UNDETERMINED ones are grouped by their gap, because a run with a short
  // ladder produces one identical sentence per question and printing 60 copies
  // of it buries the ones that are not identical.
  const undet = appearances.filter((x) => x.status === 'UNDETERMINED');
  const groups = new Map();
  for (const a of undet) {
    const key = a.gaps.map((g) => `${a.vendor}-${g.version} ${g.why}`).join(', ');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(`${a.id} ${a.opt}`);
  }
  for (const [key, members] of groups) {
    L.push(`  ${members.length} question(s) undetermined: ${key}.`);
    L.push('    That is a gap in the ladder, not a finding about the wipe.');
    L.push(`    ${members.join('; ')}`);
  }
  L.push('');
  const labelRows = rows.filter((r) => r.labelsOnly === true);
  L.push(`labelsOnly: ${labelRows.length} of ${rows.length} cells are a WIPE_SURVIVED whose two bodies differ only in .L<n> label names.`);
  L.push('  Reported, never folded into the verdict: the find step compares bodies as text and this lane');
  L.push('  does not change what it compares. gcc numbers those labels across the whole translation unit.');
  for (const r of labelRows) L.push(`  ${r.id} ${r.cc} ${r.opt}`);
  L.push('');
  L.push('NOT measured by this run');
  L.push('  - docker: NOT DONE. The daemon is not reachable from this machine and the WSL distro has no');
  L.push('    docker CLI, so a container per upstream release was not available. The ladder above is the');
  L.push('    distribution apt ladder instead. This is a limit on which versions were REACHED; it is not');
  L.push('    a statement that no disappearance was found, and the table above says what was found.');
  const sweep = sweepCoverage(tracked, prepared);
  if (sweep.complete) {
    L.push(`  - (not in this list) the corpus-scale sweep WAS run: all ${sweep.removableTotal} removable erasure`);
    L.push('    files of the r2 corpus are among the subjects above. What is still not measured is every');
    L.push('    OTHER family of that corpus -- nonremovable and both -- which this selection does not ask about.');
  } else {
    L.push(`  - the corpus-scale sweep. ${sweep.removableSwept} of the ${sweep.removableTotal} removable erasure files of the`);
    L.push('    r2 corpus are among the subjects above; the counts are over the selected subjects only.');
  }

  const report = L.join('\n') + '\n';
  const manifest = {
    tool: 'version-ladder',
    subjects: prepared.map((s) => ({ id: s.id, fn: s.fn, n_spans: s.nSpans, idiom: s.idiom, anchorable: s.anchorable, source: s.source ?? 'r2 corpus' })),
    opts: args.opts,
    versions,
    counting: { versions: vCount, appearances: aCount, cells: rows.length },
    // `problem` is the machine-readable half of the exit code: null iff this run
    // exits 0. A consumer that reads only `checked`/`agreed` can compute 0/0 and
    // call it clean, which is exactly how this lane first shipped.
    anchor: { checked: anchor.checked, agreed: anchor.agreed, disagreements: anchor.disagreements, problem: notAnchored },
    rowsFile: rowsFileLabel(rowsPath, { defaultPath: TRACKED, repoRoot: REPO }),
    trackedRowsSha256: sha256Text(trackedText),
    docker: { done: false, reason: 'the docker daemon is not reachable and the WSL distro has no docker CLI' },
  };
  const out = { manifest, rows, appearances };
  const json = JSON.stringify(out, null, 1);

  for (const [what, text] of [['the report', report], ['the rows', json]]) {
    const hits = absolutePathHits(text);
    if (hits.length) die(5, `${what} carries an absolute path (${hits.join(', ')}); refusing to write it`);
  }
  writeFileSync(join(outDir, 'version-ladder.txt'), report, 'utf8');
  writeFileSync(join(outDir, 'version-ladder.json'), json, 'utf8');
  process.stdout.write(report);

  if (args.writeSweep) {
    const cov = sweepCoverage(tracked, prepared);
    if (!cov.complete) {
      die(4, `--write-sweep records the corpus sweep, and this run swept ${cov.removableSwept} of ${cov.removableTotal} `
        + 'removable erasure files. Run it with --ids removable, or do not record it as the sweep.');
    }
    const dataDir = join(HERE, 'data');
    mkdirSync(dataDir, { recursive: true });
    const rec = JSON.stringify(sweepRecord({ manifest, rows, appearances }), null, 1);
    const hits = absolutePathHits(rec);
    if (hits.length) die(5, `the sweep record carries an absolute path (${hits.join(', ')}); refusing to write it`);
    writeFileSync(join(dataDir, 'version-ladder-sweep.json'), rec, 'utf8');
    process.stderr.write('version-ladder: wrote data/version-ladder-sweep.json\n');
  }

  if (args.writeData) {
    const dataDir = join(HERE, 'data');
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(join(dataDir, 'version-ladder.json'), json, 'utf8');
    writeFileSync(join(dataDir, 'version-ladder.txt'), report, 'utf8');
    process.stderr.write('version-ladder: wrote data/version-ladder.{json,txt}\n');
  }

  if (notAnchored) process.exit(2);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await main();
}
