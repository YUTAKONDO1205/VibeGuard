/**
 * Tests for lib/span-label.mjs: the lexical initialiserLike label.
 *
 * No compiler. The synthetic sources are a few lines of C that are only read.
 * The last test reads five tracked corpus files: two are the cases the label was
 * written for, two are the shapes the per-span view was written for, and one is
 * the asm-barrier file where the label and the plugin's followedByUse disagree
 * by design. If the corpus or the label drifts, it says so here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { wipeSpans, maskNonCode, funcBodySpan } from '../lib/ablation-cell.mjs';
import { destinationPath, spanDestination, initialiserLabels, laterRanges, RELEASE_CALLS } from '../lib/span-label.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const GEN = resolve(HERE, '../generated-corpus/r2');
const SCEN = JSON.parse(readFileSync(resolve(HERE, '../scenarios.json'), 'utf8'));

const FN = 'check_pin';
const lines = (...ls) => ls.join('\n') + '\n';
const labelsOf = (src, fn = FN) => initialiserLabels(src, fn, wipeSpans(src, fn).spans);

// ---------------------------------------------------------- destinationPath ---

test('destinationPath: casts, address-of, parentheses, subscripts and arithmetic are seen through', () => {
  assert.deepEqual(destinationPath('key'), { root: 'key', members: [] });
  assert.deepEqual(destinationPath(' (void *)vkey '), { root: 'vkey', members: [] });
  assert.deepEqual(destinationPath('(volatile unsigned char *)key'), { root: 'key', members: [] });
  assert.deepEqual(destinationPath('&buf[4]'), { root: 'buf', members: [] });
  assert.deepEqual(destinationPath('(key)'), { root: 'key', members: [] });
  assert.deepEqual(destinationPath('key + 16'), { root: 'key', members: [] });
  assert.deepEqual(destinationPath('&ctx->key[3]'), { root: 'ctx', members: ['key'] });
  assert.deepEqual(destinationPath('(uint8_t *)&s.inner.pin'), { root: 's', members: ['inner', 'pin'] });
});

test('destinationPath: no identifier, no destination', () => {
  assert.equal(destinationPath('*pp'), null);
  assert.equal(destinationPath('(a + b)[0]'), null);
  assert.equal(destinationPath('sizeof x'), null);
  assert.equal(destinationPath('get_buf()'), null);
  assert.equal(destinationPath('(unsigned char *)get_buf(n)'), null);
  assert.equal(destinationPath(''), null);
});

// ------------------------------------------------------------ the shapes ---

test('an initialising memset before the buffer is filled is initialiser-like; the trailing wipe is not', () => {
  const src = lines(
    'int check_pin(void) {',
    '  char pin[8];',
    '  memset(pin, 0, sizeof(pin));',
    '  read_keypad(pin, 8);',
    '  int ok = compare(pin);',
    '  memset(pin, 0, sizeof(pin));',
    '  return ok;',
    '}');
  assert.deepEqual(labelsOf(src), [true, false]);
});

test('a wipe on an error path followed by return is not initialiser-like, even inside a loop', () => {
  const src = lines(
    'int check_pin(int fd) {',
    '  unsigned char pin[32];',
    '  gen(pin);',
    '  while (more()) {',
    '    if (write(fd, pin, 32) < 0) {',
    '      memset(pin, 0, sizeof(pin));',
    '      return -1;',
    '    }',
    '  }',
    '  memset(pin, 0, sizeof(pin));',
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(src), [false, false]);
});

test('a conditional return is not an end of the path', () => {
  const src = lines(
    'int check_pin(int x) {',
    '  char pin[8];',
    '  memset(pin, 0, sizeof pin);',
    '  if (x) return -1;',
    '  read_keypad(pin, 8);',
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(src), [true]);
  const elseRet = lines(
    'int check_pin(int x) {',
    '  char pin[8];',
    '  memset(pin, 0, sizeof pin);',
    '  if (x) { log(); } else return -1;',
    '  read_keypad(pin, 8);',
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(elseRet), [true]);
});

test('a goto, break or continue before the return keeps the rest of the body in view', () => {
  for (const jump of ['goto again;', 'break;', 'continue;']) {
    const src = lines(
      'int check_pin(int x) {',
      '  char pin[8];',
      '  for (;;) {',
      '    again: read_keypad(pin, 8);',
      '    if (x) {',
      '      memset(pin, 0, sizeof pin);',
      `      if (x > 1) ${jump}`,
      '      return -1;',
      '    }',
      '  }',
      '  return 0;',
      '}');
    assert.deepEqual(labelsOf(src), [true], jump);
  }
});

test('the back edge of an enclosing loop is later; a return at depth 0 of the loop body cuts it', () => {
  const loop = lines(
    'int check_pin(void) {',
    '  char pin[8];',
    '  for (int i = 0; i < 3; i++) {',
    '    read_keypad(pin, 8);',
    '    consume(pin);',
    '    memset(pin, 0, sizeof pin);',
    '  }',
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(loop), [true]);
  const cut = lines(
    'int check_pin(void) {',
    '  char pin[8];',
    '  for (int i = 0; i < 3; i++) {',
    '    read_keypad(pin, 8);',
    '    memset(pin, 0, sizeof pin);',
    '    return 1;',
    '  }',
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(cut), [false]);
  // a braceless loop around the span: the loop's own text is later
  const braceless = lines(
    'int check_pin(void) {',
    '  char pin[8];',
    '  while (read_keypad(pin, 8)) memset(pin, 0, sizeof pin);',
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(braceless), [true]);
});

test('release, sizeof, pointer reset, a member of something else, comments and strings are not uses', () => {
  for (const tail of [
    'free(pin);', 'OPENSSL_free((void *)pin);', 'munlock(pin, 8);', 'n = sizeof pin;', 'n = sizeof(pin);',
    'pin = NULL;', 'pin = 0;', 's.pin = 1;', 'p->pin = 1;', '// pin', '/* pin */', 'puts("pin");',
  ]) {
    const src = lines(
      'int check_pin(char *pin, struct st s, struct st *p) {',
      '  int n;',
      '  memset(pin, 0, 8);',
      `  ${tail}`,
      '  return 0;',
      '}');
    assert.deepEqual(labelsOf(src), [false], tail);
  }
  for (const k of ['free', 'munlock', 'sodium_free']) assert.ok(RELEASE_CALLS.includes(k));
  // but a comparison of the pointer, or a later wipe of the same buffer, is
  for (const tail of ['if (pin == NULL) n = 1;', 'memset(pin, 0, 8);', 'secure_wipe(pin, 8);']) {
    const src = lines(
      'int check_pin(char *pin) {',
      '  int n = 0;',
      '  memset(pin, 0, 8);',
      `  ${tail}`,
      '  return n;',
      '}');
    assert.equal(labelsOf(src)[0], true, tail);
  }
});

test('an inline asm barrier after the wipe is not a use; a real use after it still is', () => {
  const mk = (...tail) => lines(
    'int check_pin(void) {',
    '  unsigned char pin[8];',
    '  read_keypad(pin, 8);',
    '  memset(pin, 0, sizeof(pin));',
    ...tail,
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(mk('  __asm__ __volatile__("" : : "r"(pin) : "memory");')), [false]);
  assert.deepEqual(labelsOf(mk('  asm volatile ("" : : "r"(pin) : "memory");')), [false]);
  assert.deepEqual(labelsOf(mk('  __asm__ __volatile__("" : : "r"(pin) : "memory");', '  send(pin);')), [true]);
  // the keyword followed by a long masked comment and no parenthesis: read in
  // linear time (the source is only read, never compiled)
  const long = lines('int check_pin(void) {', '  unsigned char pin[8];', '  memset(pin, 0, 8);',
    `  x = asm /*${' volatile '.repeat(4000)}*/ + 1;`, '  return 0;', '}');
  const t0 = Date.now();
  assert.deepEqual(labelsOf(long), [false]);
  assert.ok(Date.now() - t0 < 2000, 'the asm scan must not backtrack');
});

test('a member path: a sibling member is not a use, the whole object and a longer path are', () => {
  const mk = (tail) => lines(
    'int check_pin(struct ctx *c) {',
    '  memset(c->key, 0, 32);',
    `  ${tail}`,
    '  return 0;',
    '}');
  assert.deepEqual(labelsOf(mk('c->keylen = 0;')), [false]);
  assert.deepEqual(labelsOf(mk('c->key[0] = 1;')), [true]);
  assert.deepEqual(labelsOf(mk('use(c);')), [true]);
});

test('no destination, or no target body: null, never a guess', () => {
  const call = lines('int check_pin(void) {', '  memset(get_buf(), 0, 8);', '  use_buf();', '  return 0;', '}');
  assert.deepEqual(labelsOf(call), [null]);
  const src = lines('int check_pin(void) {', '  char pin[8];', '  memset(pin, 0, 8);', '  return 0;', '}');
  const { spans } = wipeSpans(src, FN);
  assert.deepEqual(initialiserLabels(src, 'no_such_fn', spans), [null]);
});

test('a volatile-pointer declaration and its loop: both read through to the buffer', () => {
  const src = lines(
    'int check_pin(void) {',
    '  unsigned char key[32];',
    '  fill(key);',
    '  volatile unsigned char *p = key;',
    '  for (int i = 0; i < 32; i++) p[i] = 0;',
    '  send(key);',
    '  return 0;',
    '}');
  const ws = wipeSpans(src, FN);
  assert.deepEqual(ws.kinds, ['nonremovable', 'nonremovable']);
  const masked = maskNonCode(src);
  const body = funcBodySpan(masked, FN);
  for (const sp of ws.spans) assert.deepEqual(spanDestination(masked, sp, body), { root: 'key', members: [] });
  assert.deepEqual(initialiserLabels(src, FN, ws.spans), [true, true]);
});

test('laterRanges: the span itself is never later, and the path ends after the return statement', () => {
  const src = lines('int check_pin(void) {', '  char pin[8];', '  memset(pin, 0, 8);', '  return pin[0];', '  pin[1] = 2;', '}');
  const masked = maskNonCode(src);
  const body = funcBodySpan(masked, FN);
  const [sp] = wipeSpans(src, FN).spans;
  const r = laterRanges(masked, body, sp);
  assert.equal(r.length, 1);
  assert.equal(r[0][0], sp[1]);
  assert.equal(src.slice(r[0][0], r[0][1]).trim(), 'return pin[0];');
});

// --------------------------------------------------- the tracked corpus files ---

test('the corpus: the two initialiser-only files read initialiser-like; the per-span shapes and the barrier read as expected', () => {
  const expect = {
    opus_N_pinpad_r2: [true],      // memset before read_keypad; nothing is wiped afterwards
    sonnet_S_privkey_r3: [true],   // memset before read_key_file; the real wipes are unpaired loops
    fable_N_token_r3: [false, false], // an error-path wipe before `return -1`, and the trailing wipe
    sonnet_S_pinpad_r1: [true, false], // an initialiser, and the trailing wipe
    opus_N_token_r3: [false],      // a trailing wipe followed only by an asm barrier on the buffer
  };
  for (const [id, want] of Object.entries(expect)) {
    const src = readFileSync(join(GEN, `${id}.c`), 'utf8');
    const fn = SCEN[id.split('_')[2]].fn;
    assert.deepEqual(labelsOf(src, fn), want, id);
  }
});
