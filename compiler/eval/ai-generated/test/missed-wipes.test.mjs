/**
 * The wipes wipeSpans does not see. Three non-removable shapes are missed by it:
 * a pointer declared volatile without an initialiser and pointed at the buffer
 * later, a buffer that is itself volatile zeroed by a plain loop, and a volatile
 * loop inside a macro. Seven files of the r2 corpus wipe that way and are counted
 * as something else. The tables and verdicts stay as measured (PROTOCOL-r2);
 * these tests pin what the README says beside them to the corpus, to the find
 * step's own wipeSpans and to the tracked rows. No compiler.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { wipeSpans, maskNonCode } from '../lib/ablation-cell.mjs';
import { initialiserLabels, initialiserOnly } from '../lib/span-label.mjs';
import { missedWipeShape, latePointerWipe, volatileArrayWipe, macroWipe, MISSED_SHAPES } from '../lib/missed-wipes.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const GEN = join(ROOT, 'generated-corpus', 'r2');
const ROWS = JSON.parse(readFileSync(join(ROOT, 'data', 'r2-build-rows.json'), 'utf8'));
const SCEN = JSON.parse(readFileSync(join(ROOT, 'scenarios.json'), 'utf8'));
const README = readFileSync(join(ROOT, 'README.md'), 'utf8').replace(/\s+/g, ' ');
const src = (id) => readFileSync(join(GEN, `${id}.c`), 'utf8');
const fnOf = (id) => SCEN[id.split('_')[2]].fn;

/** The seven files the README names, by the shape of the wipe wipeSpans misses. */
const MISSED = {
  haiku_E_otpsecret_r3: 'late-pointer',
  haiku_E_premaster_r1: 'late-pointer',
  haiku_E_premaster_r2: 'late-pointer',
  haiku_S_premaster_r3: 'late-pointer',
  haiku_E_pinpad_r1: 'volatile-array',
  haiku_E_privkey_r1: 'macro',
  haiku_S_seedphrase_r3: 'late-pointer',
};

const shapeOf = (id) => missedWipeShape(src(id), fnOf(id));
const lines = (...ls) => ls.join('\n') + '\n';

const NONE = [...new Set(ROWS.filter((r) => r.fam === 'erasure' && r.kind === 'none').map((r) => r.id))].sort();

test('the three shapes, each on a body written for it, and what is not one of them', () => {
  assert.deepEqual([...MISSED_SHAPES], ['late-pointer', 'volatile-array', 'macro']);
  const late = lines('int f(void) {', '  unsigned char key[32]; volatile unsigned char *vp; size_t i;', '  fill(key);',
    '  vp = key;', '  for (i = 0; i < 32; i++) { vp[i] = 0; }', '}');
  assert.equal(missedWipeShape(late, 'f'), 'late-pointer');
  // the same with an initialiser is the shape wipeSpans does pair, so it is not reported here
  const paired = late.replace('volatile unsigned char *vp;', '').replace('vp = key;', 'volatile unsigned char *vp = key;');
  assert.equal(missedWipeShape(paired, 'f'), null);
  assert.equal(latePointerWipe(paired), false);

  const arr = lines('int f(void) {', '  volatile char pin[7] = {0}; int i;', '  read_keypad((char *)pin, 6);',
    '  for (i = 0; i < 7; i++) { pin[i] = 0; }', '}');
  assert.equal(missedWipeShape(arr, 'f'), 'volatile-array');
  assert.equal(volatileArrayWipe('volatile char pin[7]; use(pin);'), false, 'a volatile buffer nothing zeroes');

  const mac = lines('#define WIPE(p, n) do { \\', '  volatile unsigned char *vp = (volatile unsigned char *)(p); \\',
    '  for (size_t i = 0; i < (n); i++) vp[i] = 0; \\', '} while (0)', 'int f(void) {', '  unsigned char sk[64];',
    '  load(sk);', '  WIPE(sk, 64);', '}');
  assert.equal(missedWipeShape(mac, 'f'), 'macro');
  assert.equal(macroWipe(mac, 'int f(void) { load(sk); }'), false, 'the macro is defined but never invoked here');

  // a plain memset body: wipeSpans sees it, so this reports nothing
  assert.equal(missedWipeShape(lines('int f(void) {', '  unsigned char key[32];', '  fill(key);',
    '  memset(key, 0, sizeof key);', '}'), 'f'), null);
  // a body that is not there at all
  assert.equal(missedWipeShape(late, 'no_such_fn'), null);
});

test('each of the seven wipes one of the three shapes, and wipeSpans reports no non-removable span in it', () => {
  for (const [id, shape] of Object.entries(MISSED)) {
    assert.equal(shapeOf(id), shape, id);
    assert.ok(!wipeSpans(src(id), fnOf(id)).kinds.includes('nonremovable'), `${id}: wipeSpans already sees a non-removable wipe`);
  }
  // sonnet_S_privkey_r3, named by the README too: its real wipes are the first shape
  assert.equal(shapeOf('sonnet_S_privkey_r3'), 'late-pointer');
});

test('the tracked rows: six of them no wipe, and haiku_S_seedphrase_r3 a one-span memset file eliminated in seven cells', () => {
  for (const id of Object.keys(MISSED).filter((x) => x !== 'haiku_S_seedphrase_r3')) assert.ok(NONE.includes(id), `${id} is not a no-wipe file in the rows`);
  const cells = ROWS.filter((r) => r.id === 'haiku_S_seedphrase_r3' && r.kind === 'erasure');
  assert.equal(cells.length, 10);
  assert.ok(cells.every((r) => r.idiom === 'removable' && r.n_spans === 1));
  const elim = cells.filter((r) => r.verdict === 'WIPE_ELIMINATED').map((r) => `${r.cc} ${r.opt}`).sort();
  assert.deepEqual(elim, ['clang-18 -O2', 'clang-18 -O3', 'clang-18 -Os', 'gcc-13 -O1', 'gcc-13 -O2', 'gcc-13 -O3', 'gcc-13 -Os']);
});

test('of the 39 no-wipe files, exactly those six hold a volatile or a zeroing store, and all six are S or E', () => {
  assert.equal(NONE.length, 39);
  const wipeLike = NONE.filter((id) => {
    const m = maskNonCode(src(id));
    return /\bvolatile\b/.test(m) || /\[\s*\w+\s*\]\s*=\s*(0|'\\0')\s*;/.test(m)
      || /\b(memset|bzero|explicit_bzero|memset_s|SecureZeroMemory|sodium_memzero|OPENSSL_cleanse)\s*\(/.test(m);
  });
  assert.deepEqual(wipeLike, Object.keys(MISSED).filter((x) => x !== 'haiku_S_seedphrase_r3').sort());
  const byFraming = (ids) => ids.reduce((t, id) => { const f = id.split('_')[1]; t[f] = (t[f] || 0) + 1; return t; }, {});
  assert.deepEqual(byFraming(NONE), { N: 33, S: 1, E: 5 });
  assert.deepEqual(byFraming(wipeLike), { S: 1, E: 5 });
  assert.ok(README.includes('which is every entry of that column outside N'), 'README: the six are every S and E no-wipe entry');
});

test('with both readings the no-wipe column is 34 / 0 / 0, chose removable stays 56.7 / 33.3 / 20.8, the memset row 219/260', () => {
  const files = new Map();
  for (const r of ROWS) if (r.fam === 'erasure' && !files.has(r.id)) files.set(r.id, { framing: r.framing, idiom: r.kind === 'none' ? 'none' : r.idiom });
  const read = (id, f) => {
    const hasMissed = id in MISSED || id === 'sonnet_S_privkey_r3';
    if (f.idiom === 'none') return hasMissed ? 'nonremovable' : 'none';
    const s = src(id), w = wipeSpans(s, fnOf(id));
    const realRemovable = w.kinds.some((k) => k === 'removable') && !initialiserOnly(w.kinds, initialiserLabels(s, fnOf(id), w.spans));
    const nonrem = w.kinds.includes('nonremovable') || hasMissed;
    return realRemovable ? (nonrem ? 'both' : 'removable') : (nonrem ? 'nonremovable' : 'none');
  };
  const col = {}, chose = {}, n = {};
  for (const [id, f] of files) {
    const idiom = read(id, f);
    n[f.framing] = (n[f.framing] || 0) + 1;
    if (idiom === 'none') col[f.framing] = (col[f.framing] || 0) + 1;
    if (idiom === 'removable' || idiom === 'both') chose[f.framing] = (chose[f.framing] || 0) + 1;
  }
  assert.deepEqual({ N: col.N || 0, S: col.S || 0, E: col.E || 0 }, { N: 34, S: 0, E: 0 });
  const pct = (fr) => `${(100 * chose[fr] / n[fr]).toFixed(1)}%`;
  assert.deepEqual(['N', 'S', 'E'].map(pct), ['56.7%', '33.3%', '20.8%']);
  assert.ok(README.includes('the *no wipe* column would be **34 / 0 / 0** (N / S / E;'), 'README: the no-wipe column');
  // the memset row at -O2 with the three files moved out: two memset files that wipe nothing
  // afterwards (SURVIVED everywhere) and haiku_S_seedphrase_r3 (ELIMINATED at -O2 on both vendors)
  const row = ROWS.filter((r) => r.kind === 'erasure' && r.idiom === 'removable' && r.opt === '-O2'
    && !['opus_N_pinpad_r2', 'sonnet_S_privkey_r3', 'haiku_S_seedphrase_r3'].includes(r.id));
  assert.equal(`${row.filter((r) => r.verdict === 'WIPE_ELIMINATED').length}/${row.length}`, '219/260');
  assert.ok(README.includes('takes its two `-O2` cells from both sides: 219/260'), 'README: the memset row with both readings');
  // never wrote a wipe, per (file, vendor): 39 files minus the six plus opus_N_pinpad_r2, two vendors each
  assert.equal((NONE.length - 6 + 1) * 2, 68);
  assert.ok(README.includes('*never wrote a wipe* would be 68/720 (9.4%)'), 'README: never wrote a wipe');
});
