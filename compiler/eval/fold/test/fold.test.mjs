// The tracked fold rows say what the README and the website say, and the
// disassembly reader behaves the way both of those depend on.
//
// Deliberately compiler-free. The measurement needs clang and gcc; these
// assertions need only the rows the measurement left behind, so they run on
// every job rather than on the native-toolchain ones. What they cannot check is
// whether the rows are current — that is `--write-data` and a diff.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bytesBySymbol, SUBJECT_SYMBOLS, CONTROL_SYMBOL } from '../run-fold.mjs';

const LANE = join(dirname(fileURLToPath(import.meta.url)), '..');
const rows = JSON.parse(readFileSync(join(LANE, 'data', 'fold-rows.json'), 'utf8'));

// group: the tracked rows
test('cover both compilers at both levels, and nothing was skipped', () => {
    const cells = rows.map((r) => `${r.cc} ${r.opt}`).sort();
    assert.deepEqual(cells, ['clang-18 -O0', 'clang-18 -O2', 'gcc-13 -O0', 'gcc-13 -O2']);
});

test('names the two compiler versions the website quotes', () => {
    const byCc = Object.fromEntries(rows.map((r) => [r.cc, r.ccVersion]));
    assert.ok(String(byCc['clang-18']).includes('18.1.3'));
    assert.ok(String(byCc['gcc-13']).includes('13.3.0'));
});

test('reports the three subjects identical in every configuration', () => {
    for (const row of rows) {
      assert.deepEqual(row.subjects, SUBJECT_SYMBOLS, `${row.cc} ${row.opt}`);
      assert.equal(row.identical, true, `${row.cc} ${row.opt}`);
    }
});

// The assertion that makes the row above mean something. Without it, three
// empty byte strings are also "identical".
test('reports the negative control distinct in every configuration', () => {
    for (const row of rows) {
      assert.equal(row.controlSymbol, CONTROL_SYMBOL);
      assert.equal(row.controlDiffers, true, `${row.cc} ${row.opt}`);
      assert.ok(row.controlByteCount > 0, `${row.cc} ${row.opt}`);
    }
});

test('carries gcc-13 -O2 as the fourteen bytes the site quotes, encoding included', () => {
    const row = rows.find((r) => r.cc === 'gcc-13' && r.opt === '-O2');
    assert.equal(row.byteCount, 14);
    assert.equal(row.bytes, 'f3 0f 1e fa 8b 17 31 c0 85 d2 0f 95 c0 c3');
    assert.equal(row.arch, 'x86-64');
});

// The correction this lane produced: fourteen is gcc's figure. A future edit
// that quotes it as the result's figure has to fail here first.
test('carries a different byte count for clang-18 -O2, so the figure is per compiler', () => {
    const clang = rows.find((r) => r.cc === 'clang-18' && r.opt === '-O2');
    const gcc = rows.find((r) => r.cc === 'gcc-13' && r.opt === '-O2');
    assert.equal(clang.byteCount, 9);
    assert.notEqual(clang.byteCount, gcc.byteCount);
});

// The other correction: the fold is not something -O2 does.
test('reports the fold at -O0 as well, on both compilers', () => {
    for (const cc of ['clang-18', 'gcc-13']) {
      const row = rows.find((r) => r.cc === cc && r.opt === '-O0');
      assert.equal(row.identical, true, `${cc} -O0`);
      const optimised = rows.find((r) => r.cc === cc && r.opt === '-O2').byteCount;
      assert.ok(row.byteCount > optimised, `${cc} -O0 (${row.byteCount}) vs -O2 (${optimised})`);
    }
});

test('excludes padding from byteCount and keeps the padded figure beside it', () => {
    for (const row of rows) {
      assert.ok(row.byteCountWithPadding >= row.byteCount, `${row.cc} ${row.opt}`);
    }
    const gcc = rows.find((r) => r.cc === 'gcc-13' && r.opt === '-O2');
    assert.ok(gcc.byteCountWithPadding > gcc.byteCount);
});

// group: the disassembly reader
// Real `objdump -d` output, gcc-13 -O2, trimmed to two symbols. The second
// carries the alignment padding that must not be counted.
const SAMPLE = [
    '',
    'subjects.o:     file format elf64-x86-64',
    '',
    '',
    'Disassembly of section .text:',
    '',
    '0000000000000000 <is_authorized>:',
    '   0:\tf3 0f 1e fa          \tendbr64',
    '   4:\t8b 17                \tmov    (%rdi),%edx',
    '   6:\t31 c0                \txor    %eax,%eax',
    '   8:\t85 d2                \ttest   %edx,%edx',
    '   a:\t0f 95 c0             \tsetne  %al',
    '   d:\tc3                   \tret',
    '   e:\t66 0f 1f 44 00 00    \tnopw   0x0(%rax,%rax,1)',
    '',
    '0000000000000014 <reads_second_field>:',
    '  14:\tf3 0f 1e fa          \tendbr64',
    '  18:\t8b 57 04             \tmov    0x4(%rdi),%edx',
    '  1b:\t31 c0                \txor    %eax,%eax',
    '  1d:\t85 d2                \ttest   %edx,%edx',
    '  1f:\t0f 95 c0             \tsetne  %al',
    '  22:\tc3                   \tret',
    '',
].join('\n');

test('keys bytes by symbol and stops at the symbol boundary', () => {
    const map = bytesBySymbol(SAMPLE);
    assert.deepEqual([...map.keys()], ['is_authorized', 'reads_second_field']);
    assert.equal(map.get('is_authorized').bytes, 'f3 0f 1e fa 8b 17 31 c0 85 d2 0f 95 c0 c3');
});

test('drops trailing padding and keeps it in the padded reading', () => {
    const map = bytesBySymbol(SAMPLE);
    const one = map.get('is_authorized');
    assert.equal(one.bytes.split(' ').length, 14);
    assert.equal(one.withPadding.split(' ').length, 20);
    assert.equal(one.withPadding.endsWith('66 0f 1f 44 00 00'), true);
});

test('separates the control from the subject on the one byte that differs', () => {
    const map = bytesBySymbol(SAMPLE);
    assert.notEqual(map.get('reads_second_field').bytes, map.get('is_authorized').bytes);
});

test('returns nothing for a disassembly it cannot read, rather than an empty match', () => {
    assert.deepEqual([...bytesBySymbol('no headers here\njust text\n').keys()], []);
});
