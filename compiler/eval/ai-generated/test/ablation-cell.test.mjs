/**
 * Tests for lib/ablation-cell.mjs.
 *
 * No compiler is needed: every listing below is synthetic assembly built in code,
 * and every source is a few lines of C that is only ever read, never compiled.
 * What these pin is the part of a cell that is NOT the compiler - where the wipe
 * is found, what ablation deletes, and how two listings become a verdict - since
 * that is the part a second lane imports and must not see change underneath it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, readdirSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, relative, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import * as cell from '../lib/ablation-cell.mjs';
import {
  CONTROL, maskNonCode, wipeSpans, ablateSpans, bodyOf, verdictOf, controlPresent, compile, pool,
} from '../lib/ablation-cell.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LIB = resolve(HERE, '../lib');
const ORACLE = resolve(HERE, '../../second-vendor/lib/asm-oracle.mjs');

// ---------------------------------------------------------------- listings ---

/** One function as both vendors delimit it on ELF: a label and a closing `.size`. */
function fnAsm(name, body, { closed = true } = {}) {
  const lines = [`\t.globl\t${name}`, `\t.type\t${name}, @function`, `${name}:`, ...body.map((l) => '\t' + l)];
  if (closed) lines.push(`\t.size\t${name}, .-${name}`);
  return lines.join('\n') + '\n';
}

const TARGET = 'encrypt_blob';
const ctlOracle = fnAsm('vgctl_control', ['call\tvgctl_fill@PLT', 'call\tvgctl_use@PLT', 'call\tmemset@PLT', 'call\tvgctl_use@PLT', 'ret']);
const ctlAbsent = fnAsm('vgctl_control', ['call\tvgctl_fill@PLT', 'call\tvgctl_use@PLT', 'call\tvgctl_use@PLT', 'ret']);
const ctlRepStos = fnAsm('vgctl_control', ['call\tvgctl_fill@PLT', 'xorl\t%eax, %eax', 'movl\t$4, %ecx', 'rep stosq', 'call\tvgctl_use@PLT', 'ret']);
const tgtWith = fnAsm(TARGET, ['call\taes_encrypt@PLT', 'movq\t$0, 8(%rsp)', 'movq\t$0, 16(%rsp)', 'ret']);
const tgtWithout = fnAsm(TARGET, ['call\taes_encrypt@PLT', 'ret']);
// Same instructions as tgtWithout, differing only in what bodyOf discards.
const tgtWithoutNoisy = fnAsm(TARGET, ['.cfi_startproc', '.loc 1 12 3', 'call\taes_encrypt@PLT   # tail comment', '', 'ret', '.cfi_endproc']);

// ------------------------------------------------------------------ exports ---

test('exports the names other lanes code against', () => {
  const fns = ['maskNonCode', 'stmtEnd', 'volatileFnPtrs', 'wipeHelpers', 'funcBodySpan', 'wipeSpans',
    'spanPlan', 'controlPresent', 'ablateSpans', 'bodyOf', 'compile', 'pool', 'verdictOf'];
  for (const f of fns) assert.equal(typeof cell[f], 'function', `${f} must be an exported function`);
  assert.ok(Array.isArray(cell.FLAGS));
  assert.deepEqual(cell.FLAGS, ['-S', '-std=gnu11', '-w', '-Wno-error=implicit-function-declaration', '-fcf-protection=none']);
  assert.equal(typeof cell.CONTROL, 'string');
  assert.match(cell.CONTROL, /void vgctl_control\(void\)/);
  assert.deepEqual(cell.CONTROL_EFFECT, { symbols: ['memset', '__memset_chk'], allowInlineZeroStore: true });
  assert.ok(cell.SECRET_WORDS instanceof Set && cell.SECRET_WORDS.has('key'));
  assert.ok(cell.ZERO_WRITE instanceof RegExp);
  assert.equal(cell.compile.length, 4, 'compile(cc, args, src, out, opts = {}): opts is optional');
});

// ---------------------------------------------------------------- verdictOf ---

test('verdictOf: a form that did not compile is never scored', () => {
  assert.deepEqual(verdictOf(null, ctlOracle + tgtWithout, TARGET), { verdict: 'COMPILE_ERROR' });
  assert.deepEqual(verdictOf(null, null, TARGET), { verdict: 'COMPILE_ERROR' });
  assert.deepEqual(verdictOf('', ctlOracle + tgtWithout, TARGET), { verdict: 'COMPILE_ERROR' });
  assert.deepEqual(verdictOf(ctlOracle + tgtWith, null, TARGET), { verdict: 'ABLATION_DID_NOT_COMPILE' });
  assert.deepEqual(Object.keys(verdictOf(null, null, TARGET)), ['verdict']);
  assert.deepEqual(Object.keys(verdictOf(ctlOracle + tgtWith, null, TARGET)), ['verdict']);
});

test('verdictOf: bodies that differ by a store read SURVIVED, and keys are in row order', () => {
  const v = verdictOf(ctlOracle + tgtWith, ctlOracle + tgtWithout, TARGET);
  assert.deepEqual(v, { control: 'PRESENT', control_via: 'oracle', verdict: 'WIPE_SURVIVED' });
  assert.deepEqual(Object.keys(v), ['control', 'control_via', 'verdict']);
});

test('verdictOf: identical bodies read ELIMINATED, ignoring directives and comments', () => {
  assert.deepEqual(verdictOf(ctlOracle + tgtWithout, ctlOracle + tgtWithout, TARGET),
    { control: 'PRESENT', control_via: 'oracle', verdict: 'WIPE_ELIMINATED' });
  assert.equal(bodyOf(tgtWithoutNoisy, TARGET), bodyOf(tgtWithout, TARGET));
  assert.deepEqual(verdictOf(ctlOracle + tgtWithoutNoisy, ctlOracle + tgtWithout, TARGET),
    { control: 'PRESENT', control_via: 'oracle', verdict: 'WIPE_ELIMINATED' });
});

test('verdictOf: a blind control is VERIFICATION_INCOMPLETE, never a loss or a survival', () => {
  assert.deepEqual(verdictOf(ctlAbsent + tgtWith, ctlAbsent + tgtWithout, TARGET),
    { control: 'ABSENT', control_via: 'ABSENT', verdict: 'VERIFICATION_INCOMPLETE' });
  assert.deepEqual(verdictOf(ctlAbsent + tgtWithout, ctlAbsent + tgtWithout, TARGET),
    { control: 'ABSENT', control_via: 'ABSENT', verdict: 'VERIFICATION_INCOMPLETE' });
  // The control is read from the as-written listing only.
  assert.deepEqual(verdictOf(ctlAbsent + tgtWith, ctlOracle + tgtWithout, TARGET),
    { control: 'ABSENT', control_via: 'ABSENT', verdict: 'VERIFICATION_INCOMPLETE' });
  // No control function at all.
  assert.deepEqual(verdictOf(tgtWith, tgtWithout, TARGET),
    { control: 'NOT_OBSERVED', control_via: 'NOT_OBSERVED', verdict: 'VERIFICATION_INCOMPLETE' });
});

test('verdictOf: the rep-stos fallback counts as present and says so', () => {
  assert.deepEqual(controlPresent(ctlRepStos), { ok: true, via: 'rep-stos-fallback' });
  assert.deepEqual(controlPresent(ctlOracle), { ok: true, via: 'oracle' });
  assert.deepEqual(controlPresent(ctlAbsent), { ok: false, via: 'ABSENT' });
  assert.deepEqual(verdictOf(ctlRepStos + tgtWith, ctlRepStos + tgtWithout, TARGET),
    { control: 'PRESENT', control_via: 'rep-stos-fallback', verdict: 'WIPE_SURVIVED' });
});

test('verdictOf: an unreadable target body is NOT_OBSERVED, ahead of the control check', () => {
  const open = fnAsm(TARGET, ['ret'], { closed: false });
  assert.deepEqual(verdictOf(ctlOracle + tgtWith, ctlOracle + open, TARGET),
    { control: 'PRESENT', control_via: 'oracle', verdict: 'NOT_OBSERVED' });
  assert.deepEqual(verdictOf(ctlOracle + tgtWith, ctlOracle + tgtWith, 'no_such_fn'),
    { control: 'PRESENT', control_via: 'oracle', verdict: 'NOT_OBSERVED' });
  assert.deepEqual(verdictOf(ctlAbsent + open, ctlAbsent + tgtWithout, TARGET),
    { control: 'ABSENT', control_via: 'ABSENT', verdict: 'NOT_OBSERVED' });
});

test('verdictOf spread onto a row keeps the row key order build-analyze has always written', () => {
  const row = { id: 'x', kind: 'erasure', idiom: 'removable', cc: 'clang-18', opt: '-O2', n_spans: 1, named_secret: true, scoped: true };
  Object.assign(row, verdictOf(ctlOracle + tgtWith, ctlOracle + tgtWithout, TARGET));
  assert.deepEqual(Object.keys(row),
    ['id', 'kind', 'idiom', 'cc', 'opt', 'n_spans', 'named_secret', 'scoped', 'control', 'control_via', 'verdict']);
  const bad = { id: 'x', kind: 'erasure', scoped: true };
  Object.assign(bad, verdictOf(null, null, TARGET));
  assert.deepEqual(Object.keys(bad), ['id', 'kind', 'scoped', 'verdict']);
});

// ---------------------------------------------------------------- wipeSpans ---

// The target functions below return `int`; no erasure target in the r2 corpus is
// declared `void`. A `void` target that itself zeroes or mentions `volatile` is picked up by
// wipeHelpers as a helper of its own, and its definition header then matches as a
// "call" inside its own body. That touches no file in the r2 corpus (measured: 0
// of 360 erasure files) and is not what these tests are about, so it is avoided
// here rather than pinned.
const lines = (...ls) => ls.join('\n') + '\n';
const spanText = (src, spans) => spans.map(([a, b]) => src.slice(a, b));

test('wipeSpans: a memset of the secret in the target function is removable', () => {
  const src = lines(
    '#include <string.h>',
    'void aes_encrypt(unsigned char *k);',
    'int encrypt_blob(void) {',
    '  unsigned char key[32];',
    '  aes_encrypt(key);',
    '  memset(key, 0, sizeof key);',
    '}');
  const r = wipeSpans(src, TARGET);
  assert.deepEqual(r.kinds, ['removable']);
  assert.deepEqual(spanText(src, r.spans), ['memset(key, 0, sizeof key);']);
  assert.equal(r.namedSecret, true);
  assert.equal(r.scoped, true);
  assert.deepEqual(r.helpers, []);
});

test('wipeSpans: a volatile pointer loop is non-removable, and its declaration goes with it', () => {
  const src = lines(
    'void aes_encrypt(unsigned char *k);',
    'int encrypt_blob(void) {',
    '  unsigned char key[32];',
    '  aes_encrypt(key);',
    '  volatile unsigned char *p = key;',
    '  for (int i = 0; i < 32; i++) p[i] = 0;',
    '}');
  const r = wipeSpans(src, TARGET);
  assert.deepEqual(r.kinds, ['nonremovable', 'nonremovable']);
  assert.deepEqual(spanText(src, r.spans), ['volatile unsigned char *p = key;', 'for (int i = 0; i < 32; i++) p[i] = 0;']);
  assert.equal(r.namedSecret, true);
});

test('wipeSpans: a call that cannot be elided is non-removable; a helper with a volatile parameter too', () => {
  const direct = lines(
    'int encrypt_blob(void) {',
    '  unsigned char key[32];',
    '  explicit_bzero(key, sizeof key);',
    '}');
  assert.deepEqual(wipeSpans(direct, TARGET).kinds, ['nonremovable']);

  const helper = lines(
    'static void secure_wipe(volatile unsigned char *b, unsigned long n) { while (n--) *b++ = 0; }',
    'static void plain_wipe(unsigned char *b, unsigned long n) { for (unsigned long i = 0; i < n; i++) b[i] = 0; }',
    'int encrypt_blob(void) {',
    '  unsigned char key[32], iv[16];',
    '  secure_wipe(key, sizeof key);',
    '  plain_wipe(iv, sizeof iv);',
    '}');
  const r = wipeSpans(helper, TARGET);
  assert.deepEqual(r.helpers.sort(), ['plain_wipe', 'secure_wipe']);
  assert.deepEqual(spanText(helper, r.spans), ['secure_wipe(key, sizeof key);', 'plain_wipe(iv, sizeof iv);']);
  assert.deepEqual(r.kinds, ['nonremovable', 'removable']);
});

test('wipeSpans: a volatile loop before a memset keeps each span its own kind', () => {
  const src = lines(
    '#include <string.h>',
    'void fill(unsigned char *k, unsigned char *p);',
    'int encrypt_blob(void) {',
    '  unsigned char key[32], password[16];',
    '  fill(key, password);',
    '  { volatile unsigned char *p = key; for (int i = 0; i < 32; i++) p[i] = 0; }',
    '  memset(password, 0, sizeof password);',
    '  return 0;',
    '}');
  const r = wipeSpans(src, TARGET);
  assert.deepEqual(spanText(src, r.spans),
    ['volatile unsigned char *p = key;', 'for (int i = 0; i < 32; i++) p[i] = 0;', 'memset(password, 0, sizeof password);']);
  assert.deepEqual(r.kinds, ['nonremovable', 'nonremovable', 'removable']);
  // and the per-span plan ablates the memset alone, not the declaration
  assert.deepEqual(cell.spanPlan(r.kinds).map((p) => p.source), ['not-measured', 'not-measured', 'span']);
});

test('wipeSpans: no wipe, a wipe outside the target, and a wipe in a comment all yield nothing', () => {
  const none = lines(
    'void aes_encrypt(unsigned char *k);',
    'int encrypt_blob(void) {',
    '  unsigned char key[32];',
    '  for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;',
    '  aes_encrypt(key);',
    '  // memset(key, 0, sizeof key);',
    '  /* memset(key, 0, sizeof key); */',
    '}',
    'int other(void) { unsigned char key[8]; memset(key, 0, 8); return key[0]; }');
  const r = wipeSpans(none, TARGET);
  assert.deepEqual(r.spans, []);
  assert.deepEqual(r.kinds, []);
  assert.equal(r.scoped, true);
  assert.equal(r.namedSecret, false);
});

test('wipeSpans: without the target body it falls back to gating on the secret name', () => {
  const src = lines(
    'int something_else(void) {',
    '  unsigned char key[32], buf[32];',
    '  memset(buf, 0, sizeof buf);',
    '  memset(key, 0, sizeof key);',
    '}');
  const r = wipeSpans(src, TARGET);
  assert.equal(r.scoped, false);
  assert.deepEqual(spanText(src, r.spans), ['memset(key, 0, sizeof key);']);
});

test('maskNonCode keeps offsets: masked text is the same length as the source', () => {
  const src = 'int a; // c "x"\nchar *s = "memset(key, 0, 1);"; /* m */ int b;\n';
  const m = maskNonCode(src);
  assert.equal(m.length, src.length);
  assert.ok(!m.includes('memset'));
  assert.ok(m.includes('int b;'));
});

// ---------------------------------------------------------------- spanPlan ---

test('spanPlan: one span is the cell; with more, removable spans are measured alone and nonremovable ones listed', () => {
  assert.deepEqual(cell.spanPlan(['removable']), [{ index: 0, kind: 'removable', source: 'cell' }]);
  assert.deepEqual(cell.spanPlan(['removable', 'nonremovable', 'removable']), [
    { index: 0, kind: 'removable', source: 'span' },
    { index: 1, kind: 'nonremovable', source: 'not-measured' },
    { index: 2, kind: 'removable', source: 'span' },
  ]);
  assert.deepEqual(cell.spanPlan([]), []);
  assert.deepEqual(cell.spanPlan(undefined), []);
  // aligned with wipeSpans: one plan entry per span, in span order
  const src = lines(
    'int encrypt_blob(void) {',
    '  unsigned char key[32];',
    '  memset(key, 0, sizeof key);',
    '  fill(key);',
    '  volatile unsigned char *p = key;',
    '  for (int i = 0; i < 32; i++) p[i] = 0;',
    '}');
  const ws = wipeSpans(src, TARGET);
  assert.deepEqual(cell.spanPlan(ws.kinds).map((p) => [p.index, p.source]), [[0, 'span'], [1, 'not-measured'], [2, 'not-measured']]);
});

// -------------------------------------------------------------- ablateSpans ---

test('ablateSpans: no spans is the identity, and the text between spans is kept verbatim', () => {
  const src = lines(
    'void aes_encrypt(unsigned char *k);',
    'int encrypt_blob(void) {',
    '  unsigned char key[32];',
    '  aes_encrypt(key);',
    '  volatile unsigned char *p = key;',
    '  for (int i = 0; i < 32; i++) p[i] = 0;',
    '}');
  assert.equal(ablateSpans(src, []), src);
  const { spans } = wipeSpans(src, TARGET);
  assert.equal(spans.length, 2);
  const out = ablateSpans(src, spans);
  const kept = [];
  let at = 0;
  for (const [a, b] of spans) { kept.push(src.slice(at, a)); at = b; }
  kept.push(src.slice(at));
  assert.equal(out, kept.join('/* ablated */;'));
  // Round trip: the ablated form contains no wipe left to find.
  assert.deepEqual(wipeSpans(out, TARGET).spans, []);
  // And it is still the same translation unit apart from the spans.
  assert.ok(out.includes('aes_encrypt(key);'));
  assert.ok(out.startsWith('void aes_encrypt(unsigned char *k);\n'));
});

test('ablateSpans + CONTROL: the as-written and ablated forms carry the same control', () => {
  const src = lines('int encrypt_blob(void) {', '  unsigned char key[32];', '  memset(key, 0, sizeof key);', '  return 0;', '}');
  const { spans } = wipeSpans(src, TARGET);
  const wo = ablateSpans(src, spans) + CONTROL;
  assert.ok(wo.endsWith(CONTROL));
  // The control's own wipe is never a wipe of the target.
  assert.deepEqual(wipeSpans(src + CONTROL, TARGET).spans, spans);
});

// ---------------------------------------------------------- compile / pool ---

test('compile: an unrunnable compiler is null, not a throw', async () => {
  const out = join(tmpdir(), 'vg-ablation-cell-never-written.s');
  assert.equal(await compile('vg-no-such-compiler-for-this-test', ['-O2'], 'nothing.c', out), null);
  assert.equal(await compile('vg-no-such-compiler-for-this-test', ['-O2'], 'nothing.c', out, { env: { VG_TEST: '1' } }), null);
});

test('pool: results keep input order and concurrency is bounded', async () => {
  let live = 0, peak = 0;
  const items = [5, 1, 4, 2, 3, 0, 6];
  const res = await pool(items, async (x, k) => {
    live++; peak = Math.max(peak, live);
    await new Promise((r) => setTimeout(r, x));
    live--;
    return [x, k];
  }, 3);
  assert.deepEqual(res, items.map((x, k) => [x, k]));
  assert.ok(peak <= 3, `peak concurrency ${peak} exceeded 3`);
  assert.deepEqual(await pool([], async () => 1), []);
});

// ------------------------------------------------------------- side effects ---

test('importing ablation-cell.mjs has no side effects: no _build, no corpus read, nothing written', async () => {
  // A copy of the module and its one dependency, laid out as in the repository but
  // with nothing else beside them: no corpus, no scenarios.json, no data/. A module
  // that read the corpus at load time would throw here, and one that created its
  // scratch directory would leave it behind in the listing.
  const root = mkdtempSync(join(tmpdir(), 'vg-ablation-cell-'));
  try {
    const libDir = join(root, 'eval', 'ai-generated', 'lib');
    const oracleDir = join(root, 'eval', 'second-vendor', 'lib');
    mkdirSync(libDir, { recursive: true });
    mkdirSync(oracleDir, { recursive: true });
    copyFileSync(join(LIB, 'ablation-cell.mjs'), join(libDir, 'ablation-cell.mjs'));
    copyFileSync(ORACLE, join(oracleDir, 'asm-oracle.mjs'));

    const walk = (d) => readdirSync(d).flatMap((n) => {
      const p = join(d, n);
      return statSync(p).isDirectory() ? [relative(root, p).split(sep).join('/') + '/', ...walk(p)] : [relative(root, p).split(sep).join('/')];
    }).sort();
    const before = walk(root);

    const copy = await import(pathToFileURL(join(libDir, 'ablation-cell.mjs')).href);
    assert.equal(typeof copy.verdictOf, 'function');
    assert.deepEqual(copy.verdictOf(ctlOracle + tgtWith, ctlOracle + tgtWithout, TARGET),
      { control: 'PRESENT', control_via: 'oracle', verdict: 'WIPE_SURVIVED' });

    assert.deepEqual(walk(root), before);
    assert.ok(!before.some((p) => p.includes('_build')));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
