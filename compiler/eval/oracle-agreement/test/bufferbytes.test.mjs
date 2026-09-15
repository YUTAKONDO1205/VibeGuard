/**
 * The byte count: where it comes from, and every way it is allowed not to.
 *
 * The number O3 grades a wipe against is the one thing in this lane that is not
 * in the tracked rows, so it is the one thing most likely to be quietly invented.
 * These tests are about the invention paths rather than about the happy one:
 * that there is no default anywhere, that a cell nothing could establish leaves
 * with a reason word of its own, that the read-out has a positive control, and
 * that the only text-derived inputs are a LOCATION and an EXPRESSION rather than
 * a number.
 *
 * NOTHING HERE ASKS A COMPILER ANYTHING. The suite in this directory is
 * compiler-free by design, and the half of the read-out that needs one lives in
 * `tools/check-bytes-readout.mjs`, which exits non-zero when it cannot run. The
 * last test in this file pins that separation; the paragraph at the bottom says
 * why it was made.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  controlBytes, splitArgs, wipedObject, locateWipe, probeSource,
  MAX_PROBE_BYTES, PROBE_FLAGS, PROBE_TAG,
} from '../lib/bufferbytes.mjs';
import { REASON, KIND, REASON_KIND } from '../lib/agreement.mjs';
import { loadRows, sourcePathOf } from '../lib/rows.mjs';
import { CONTROL, wipeSpans } from '../../ai-generated/lib/ablation-cell.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const README = readFileSync(join(LANE, 'README.md'), 'utf8');

// ------------------------------------------------------ there is no default --

test('no module in this lane spells a fallback buffer size', () => {
  // The rule stated as a grep, because the failure it guards is a one-line
  // edit that reads like a convenience: `bytes ?? 32`, `bytes || 32`,
  // `bytes = 32`. A default would turn every surviving wipe of another size
  // into PARTIAL and every reading into a statement about the default.
  for (const rel of ['lib/bufferbytes.mjs', 'lib/disasm.mjs', 'run-oracle-agreement.mjs']) {
    const src = readFileSync(join(LANE, rel), 'utf8');
    assert.ok(!/\bbytes\s*(\?\?|\|\|)\s*\d/.test(src), `${rel} defaults a byte count`);
    assert.ok(!/\bbytes\s*=\s*\d+\s*[,;)]/.test(src), `${rel} assigns a literal byte count`);
  }
});

test('the disassembly channel refuses to read a cell with no established count', async () => {
  const { observeCellO3 } = await import('../lib/disasm.mjs');
  const lab = mkdtempSync(join(tmpdir(), 'oa-bytes-'));
  for (const bytes of [undefined, null, 0, -1, 32.5]) {
    await assert.rejects(
      () => observeCellO3({ cc: 'cc', opt: '-O2', lab, id: 'x', fn: 'f', srcPath: 'x.c', bytes }),
      /no established byte count/,
      `a byte count of ${String(bytes)} was accepted`,
    );
  }
});

// ------------------------------------------- the outcome word, and its kind --

test('a cell whose count cannot be established has a reason word of its own', () => {
  assert.equal(REASON.O3_BYTES_UNESTABLISHED, 'o3-buffer-bytes-unestablished');
  assert.equal(REASON.O3_NO_SINGLE_WIPE, 'o3-no-single-wipe');
  // Both are statements about the APPARATUS -- about what O3 could be configured
  // to ask here -- and not about the wipe, so they are BROKEN_MEASUREMENT and
  // they leave the denominator. Filing them as NOT_COMPARABLE would say the two
  // vocabularies did not meet, which would be a claim about a reading nobody
  // took.
  assert.equal(REASON_KIND[REASON.O3_BYTES_UNESTABLISHED], KIND.BROKEN_MEASUREMENT);
  assert.equal(REASON_KIND[REASON.O3_NO_SINGLE_WIPE], KIND.BROKEN_MEASUREMENT);
});

// --------------------------------------------------------- the pure parsing --

test('splitArgs splits at top level, not on every comma', () => {
  assert.deepEqual(splitArgs('memset(p, 0, sizeof(a[i]))').map((x) => x.trim()), ['p', '0', 'sizeof(a[i])']);
  assert.deepEqual(splitArgs('f((void *)p, g(x, y))').map((x) => x.trim()), ['(void *)p', 'g(x, y)']);
  assert.equal(splitArgs('no parenthesis here'), null);
});

test('wipedObject takes one cast off and refuses anything that is not a bare name', () => {
  assert.equal(wipedObject('key'), 'key');
  assert.equal(wipedObject(' (void *)vkey '), 'vkey');
  assert.equal(wipedObject('( unsigned char * ) buf'), 'buf');
  // Refused, deliberately: this identifier is what `sizeof` is taken of, and a
  // generous parse would take the size of the wrong object and have the
  // compiler confirm it.
  for (const bad of ['&buf[0]', 'st.key', 'p + 1', '', null]) {
    assert.equal(wipedObject(bad), null, `wipedObject accepted ${String(bad)}`);
  }
});

test('the probe inserts one assertion and changes nothing else', () => {
  const src = 'void f(void) {\n  char k[8];\n  memset(k, 0, sizeof k);\n}\n';
  const at = src.indexOf('memset');
  const probed = probeSource(src, at, 'sizeof k');
  assert.equal((probed.match(/_Static_assert/g) || []).length, 1);
  assert.ok(probed.includes(PROBE_TAG));
  assert.equal(probed.replace(/_Static_assert\(\(sizeof k\), "[^"]*"\);\n/, ''), src);
});

test('the probe compiles with the corpus run’s own flags, minus the listing and plus syntax-only', () => {
  assert.ok(!PROBE_FLAGS.includes('-S'), 'the probe asks for a listing');
  assert.ok(PROBE_FLAGS.includes('-fsyntax-only'), 'the probe does more than parse');
  assert.ok(PROBE_FLAGS.includes('-std=gnu11'), '_Static_assert at block scope needs C11');
});

test('the control’s own byte count is re-derived from the control source, not spelled', () => {
  const c = controlBytes();
  assert.equal(typeof c.bytes, 'number');
  assert.ok(c.bytes > 0);
  // The derivation, checked against the imported source rather than against a
  // number written here: a control whose buffer changed size would otherwise
  // leave this lane grading it against the old one, fell the control on every
  // cell, and report a healthy apparatus as a broken one.
  assert.ok(CONTROL.includes(`${c.name}[${c.bytes}]`), 'controlBytes read a size the control does not declare');
  const src = readFileSync(join(LANE, 'lib/bufferbytes.mjs'), 'utf8');
  const body = src.slice(src.indexOf('export function controlBytes'));
  assert.ok(!/\b32\b/.test(body.slice(0, body.indexOf('}'))), 'controlBytes spells a size instead of reading one');
});

// ----------------------------------------------- locating the wipe, on the corpus --

/**
 * The domain split, counted over the tracked rows exactly as the README says it
 * was counted.
 *
 * Every generation lands in exactly one of four places and the four sum to the
 * row count, so a cell that stopped being counted cannot be absorbed by another
 * bucket. `unreadable` exists for a source file the checkout does not carry: on
 * this tree it is 0 and the assertions below require it to be, because a count
 * taken over a subset of the corpus is not the count the README quotes.
 */
function domainSplit() {
  const rows = loadRows().filter((r) => r.fam === 'erasure' && r.cc === 'gcc-13' && r.opt === '-O2');
  const split = { rows: rows.length, located: 0, multiSpan: 0, indirect: 0, otherRefusal: 0, unreadable: 0 };
  const verdicts = {};
  for (const r of rows) {
    const src = sourcePathOf(r.id);
    if (!existsSync(src)) { split.unreadable += 1; continue; }
    const w = locateWipe(readFileSync(src, 'utf8'), r.fn);
    if (w.located) {
      split.located += 1;
      verdicts[r.verdict] = (verdicts[r.verdict] || 0) + 1;
      assert.ok(w.lenExpr.length > 0, `${r.id}: a located wipe with no length expression`);
      assert.ok(/^[A-Za-z_]\w*$/.test(w.object), `${r.id}: a located wipe whose object is not a name`);
      assert.ok(w.helper === null || /^[A-Za-z_]\w*$/.test(w.helper), `${r.id}: a helper that is not a name`);
    } else {
      // Every refusal carries one of this lane's own words and a sentence.
      assert.ok([REASON.O3_NO_SINGLE_WIPE, REASON.O3_BYTES_UNESTABLISHED].includes(w.reason), `${r.id}: ${w.reason}`);
      assert.ok(w.why && w.why.length > 10, `${r.id}: a refusal with no reason given`);
      if (/volatile function pointer/.test(w.why)) split.indirect += 1;
      else if (w.reason === REASON.O3_NO_SINGLE_WIPE) split.multiSpan += 1;
      else split.otherRefusal += 1;
    }
  }
  split.verdicts = verdicts;
  assert.equal(split.located + split.multiSpan + split.indirect + split.otherRefusal + split.unreadable, split.rows,
    'the four buckets do not account for every gcc-13 erasure row at -O2');
  return split;
}

/** One number out of the README, or a failure naming the sentence that moved. */
function readmeNumber(re, what, group = 1) {
  const m = re.exec(README);
  assert.ok(m, `the README no longer states ${what} in the shape this test reads (${re})`);
  return Number.parseInt(m[group], 10);
}

test('locateWipe finds one wipe or refuses by name, over every gcc erasure generation', () => {
  const s = domainSplit();
  assert.ok(s.rows > 0, 'the tracked rows carry no gcc-13 erasure cells at -O2');
  assert.equal(s.unreadable, 0, `${s.unreadable} generations could not be read; the split is over a subset`);
  // O3 can be pointed at a minority of the corpus and the rest leave by name.
  assert.ok(s.located > 0, 'O3 can be pointed at no gcc cell at all');
  assert.ok(s.located < s.rows, 'every gcc cell is suddenly addressable; the refusal path is no longer exercised');
});

test('THE README DOMAIN SPLIT IS RE-DERIVED HERE, number by number, from the tracked rows', () => {
  // WHAT THIS REPLACED. The README says twice that this file re-derives the
  // 162/155/4 domain split and the 79/83 verdict balance. It did not: the two
  // assertions in the test above are `located > 0` and `located < rows.length`,
  // which the split 1/320/0 satisfies as happily as the split the README quotes.
  // A measured-sounding sentence that nothing measures rots silently, and the
  // first person to notice is whoever tries to reproduce the run months later.
  //
  // So every number in that table is parsed OUT OF THE README and compared
  // against a count taken here. Either side moving fails this test, and the
  // failure message names which side said what.
  const s = domainSplit();
  const total = readmeNumber(/over the (\d+) gcc-13 erasure generations/, 'the corpus size the split is over');
  assert.equal(s.rows, total, `the split is over ${s.rows} generations; the README counts it over ${total}`);

  const located = readmeNumber(/one wipe span, written as a call, resolvable \|\s*\*\*(\d+)\*\*/,
    'how many generations O3 can be pointed at');
  const multi = readmeNumber(/more than one wipe span[^|]*\|\s*(\d+)\s*\|/,
    'how many generations hold more than one wipe span');
  const indirect = readmeNumber(/volatile` function pointer[^|]*\|\s*(\d+)\s*\|/,
    'how many generations wipe through a volatile function pointer');
  assert.equal(s.located, located, `locateWipe addresses ${s.located} generations; the README says ${located}`);
  assert.equal(s.multiSpan, multi, `${s.multiSpan} generations hold more than one wipe span; the README says ${multi}`);
  assert.equal(s.indirect, indirect, `${s.indirect} wipe through a volatile function pointer; the README says ${indirect}`);
  assert.equal(s.otherRefusal, 0, 'a refusal this table has no row for has appeared');
  // The table's own arithmetic, on the README's numbers rather than on ours: a
  // table whose three rows do not sum to the corpus is a table with a bucket
  // nobody wrote down, whatever the counts here say.
  assert.equal(located + multi + indirect, total, 'the three README rows do not sum to the corpus they were counted over');

  // And the verdict balance within the domain, which is the sentence that makes
  // `--restrict-domain` a balanced selection rather than a hopeful one.
  const ofThe = readmeNumber(/Of the (\d+), the O1 column reads/, 'the domain the verdict balance is within');
  const elim = readmeNumber(/Of the \d+, the O1 column reads (\d+) `WIPE_ELIMINATED`/, 'the WIPE_ELIMINATED count in the domain');
  const surv = readmeNumber(/reads \d+ `WIPE_ELIMINATED` and (\d+) `WIPE_SURVIVED`/, 'the WIPE_SURVIVED count in the domain');
  assert.equal(ofThe, located, 'the verdict balance is quoted over a different domain from the table above it');
  assert.equal(s.verdicts.WIPE_ELIMINATED, elim,
    `the domain holds ${s.verdicts.WIPE_ELIMINATED} WIPE_ELIMINATED rows; the README says ${elim}`);
  assert.equal(s.verdicts.WIPE_SURVIVED, surv,
    `the domain holds ${s.verdicts.WIPE_SURVIVED} WIPE_SURVIVED rows; the README says ${surv}`);
  assert.equal(elim + surv, located, 'the two README verdict counts do not sum to the domain they are within');
  assert.deepEqual(Object.keys(s.verdicts).sort(), ['WIPE_ELIMINATED', 'WIPE_SURVIVED'],
    'the domain now holds an O1 word the README balance does not mention');
});

test('locateWipe refuses a wipe through a volatile function pointer rather than reading the caller', () => {
  // The failure this refusal exists for: the call is indirect, objdump resolves
  // no target, read-wipe.py reads the caller, finds no zero store and reports
  // ABSENT -- an elimination manufactured out of an instrument that could not
  // see the call. There is at least one such generation in the corpus.
  const rows = loadRows().filter((r) => r.fam === 'erasure' && r.cc === 'gcc-13' && r.opt === '-O2');
  const hits = [];
  for (const r of rows) {
    const src = sourcePathOf(r.id);
    if (!existsSync(src)) continue;
    const w = locateWipe(readFileSync(src, 'utf8'), r.fn);
    if (!w.located && /volatile function pointer/.test(w.why)) hits.push(r.id);
  }
  assert.ok(hits.length > 0, 'no generation exercises the volatile-function-pointer refusal any more');
});

test('the wipe O3 is pointed at is the wipe O1 ablated -- the same span finder, not a second opinion', () => {
  // `locateWipe` calls `wipeSpans`, which is what `build-analyze.mjs` ablated
  // with. Re-derived here over the corpus: the span count the tracked rows
  // recorded is the span count that function still produces, so the location
  // has not drifted from the frozen record.
  const rows = loadRows().filter((r) => r.fam === 'erasure' && r.cc === 'gcc-13' && r.opt === '-O2');
  let checked = 0;
  for (const r of rows) {
    const src = sourcePathOf(r.id);
    if (!existsSync(src)) continue;
    assert.equal(wipeSpans(readFileSync(src, 'utf8'), r.fn).spans.length, r.n_spans, `${r.id}: n_spans has drifted`);
    checked += 1;
  }
  assert.ok(checked > 100, `only ${checked} generations were checked`);
});

test('a subject with more than one wipe is refused, because O3 reads one triple', () => {
  const rows = loadRows().filter((r) => r.fam === 'erasure' && r.cc === 'gcc-13' && r.opt === '-O2' && r.n_spans > 1);
  assert.ok(rows.length > 0, 'the corpus no longer holds a multi-span erasure cell');
  const r = rows[0];
  const w = locateWipe(readFileSync(sourcePathOf(r.id), 'utf8'), r.fn);
  assert.equal(w.located, false);
  assert.equal(w.reason, REASON.O3_NO_SINGLE_WIPE);
  assert.match(w.why, /wipes/);
});

// --------------------------------------------------- the probe range is a bound --

test('the probe range is a bound that refuses, not a cap that clamps', () => {
  const src = readFileSync(join(LANE, 'lib/bufferbytes.mjs'), 'utf8');
  assert.equal(MAX_PROBE_BYTES, 65536);
  // The above-range branch returns a refusal rather than MAX_PROBE_BYTES.
  const branch = src.slice(src.indexOf('if (aboveRange)'), src.indexOf('// ---- 3.'));
  assert.match(branch, /established: false/);
  assert.match(branch, /refused rather than clamped/);
  assert.ok(!/bytes: MAX_PROBE_BYTES/.test(src), 'the bound is used as a value somewhere');
});

// ------------------------------------------------------- the read-out, live --
//
// NOT HERE, AND THE REASON IS THE LANE'S OWN RULE.
//
// The four checks that put a question to a real compiler -- the bisection, the
// non-constant refusal, the wrong-size refusal, and the read-out over corpus
// generations -- were written in this file first, behind a fence that asked
// whether a compiler was present
// in front of them. On a host with no C compiler that fence made them pass in
// seventeen milliseconds without asking a compiler anything, which is the silent
// pass this repository forbids: a check that cannot run must exit non-zero
// naming why, never return 0.
//
// The suite in this directory is also, deliberately, compiler-free -- that is
// what lets it run on any host and what makes it cheap enough to be a CI job.
// Those two rules cannot both be kept inside one test file, so the compiler half
// lives in `tools/check-bytes-readout.mjs`, which is a CHECK rather than a test:
// it exits 3 when there is no compiler, names it, and exits 0 only when it
// actually established a number. The test below pins that the check exists and
// that nothing in this file pretends to have made it.

test('the compiler half of the read-out is a check that fails when it cannot run, not a fenced test', () => {
  const tool = join(LANE, 'tools/check-bytes-readout.mjs');
  assert.ok(existsSync(tool), 'tools/check-bytes-readout.mjs is gone; the read-out has no live check');
  const src = readFileSync(tool, 'utf8');
  assert.match(src, /die\(3,|process\.exit\(3\)/, 'the check does not exit 3 when it cannot run');
  assert.match(src, /could not be run on this host/, 'the check does not name what stopped it');
  assert.match(src, /process\.exit\(code\)|process\.exit\(2\)/, 'the check cannot report a wrong answer');
  assert.ok(!/skip/i.test(src), 'the check skips instead of exiting');
  // And nothing in THIS file asks a compiler anything, so its green is never a
  // claim about one.
  const here = readFileSync(join(LANE, 'test/bufferbytes.test.mjs'), 'utf8');
  assert.ok(!/establishBytes\(/.test(here), 'this suite runs the live read-out after all');
  // The needle is ASSEMBLED rather than written, following the precedent in
  // test/lane.test.mjs: a literal here would be found in this very assertion and
  // the test would fail on a clean file.
  const fence = ['have', 'Compiler'].join('');
  assert.ok(!here.includes(fence), 'this suite still carries a compiler fence');
});
