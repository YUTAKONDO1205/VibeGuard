/**
 * tools/lib/zero-delta.mjs and tools/zero-delta.mjs: the zero-write count beside
 * the find step's verdict, and the two lists of cells where the verdict may have
 * been misread (no extra zero write in w; a frame that only moved).
 *
 * The listings here are hand-written, in the shape clang-18 writes them. They
 * stand for the two misreadings found outside this tree (lab notes
 * s2_plugins/README.md §5 and s3_backend/README.md): a body that differs only in
 * register allocation, and a pinpad body whose frame moved by one byte so that a
 * string terminator's `movb $0, N(%rsp)` reads as present in w only. What the
 * tool found on real listings is in README.md, *A third reading*; it was
 * measured in the lab and is not recomputed here.
 *
 * No compiler. verdictOf and bodyOf are the find step's own (ablation-cell.mjs),
 * imported, as the tool imports them.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  effectFromRegistry, zeroWrites, repStosCount, onlyIn, instructionLines, rebase, uniformRspShift, frameShiftOnly, labelsOnly,
  zeroDeltaCell, summarize, trackedAgreement, SURVIVED,
} from '../tools/lib/zero-delta.mjs';
import { verdictOf, bodyOf } from '../../ai-generated/lib/ablation-cell.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');
const REPO = path.resolve(LANE, '..', '..', '..');
const REGISTRY = JSON.parse(readFileSync(path.join(REPO, 'compiler', 'schema', 'effect-symbol-lists.json'), 'utf8'));
const EFFECT = effectFromRegistry(REGISTRY);
const CLI = path.join(LANE, 'tools', 'zero-delta.mjs');

/** A listing: the target function `fn` with `lines` as its body, and the positive control after it. */
const listing = (fn, lines) => [
  '\t.text', `\t.globl\t${fn}`, `\t.type\t${fn},@function`, `${fn}:`, '\t.cfi_startproc',
  ...lines.map((l) => (l.endsWith(':') ? l : `\t${l}`)),
  '.Lfunc_end0:', `\t.size\t${fn}, .Lfunc_end0-${fn}`,
  '\t.globl\tvgctl_control', 'vgctl_control:', '\tmovq\t$0, (%rdi)', '\tretq', '.Lfunc_end1:', '\t.size\tvgctl_control, .Lfunc_end1-vgctl_control',
].join('\n') + '\n';

// s3's nine pinpad files: the frame moved by one byte between w and wo, and the only zero store is the terminator
const PIN_W = listing('check_pin', ['subq\t$40, %rsp', 'leaq\t8(%rsp), %rbx', 'movb\t$0, 14(%rsp)', 'movq\t%rbx, %rdi', 'callq\tread_pin@PLT',
  'movl\t20(%rsp), %eax', 'addq\t$40, %rsp', 'retq']);
const PIN_WO = listing('check_pin', ['subq\t$40, %rsp', 'leaq\t9(%rsp), %rbx', 'movb\t$0, 15(%rsp)', 'movq\t%rbx, %rdi', 'callq\tread_pin@PLT',
  'movl\t21(%rsp), %eax', 'addq\t$40, %rsp', 'retq']);
// s2's 72 cells: register allocation and a branch differ, no zero write in either
const TOK_W = listing('send_session_token', ['pushq\t%rbx', 'movq\t%rdi, %rbx', 'callq\tsend@PLT', 'testl\t%eax, %eax', 'jne\t.LBB0_2', 'popq\t%rbx', 'retq']);
const TOK_WO = listing('send_session_token', ['pushq\t%r14', 'movq\t%rdi, %r14', 'callq\tsend@PLT', 'testl\t%eax, %eax', 'je\t.LBB0_2', 'popq\t%r14', 'retq']);
// a wipe that survived: two vector zero stores in w only
const KEY_W = listing('sign', ['subq\t$40, %rsp', 'callq\thmac@PLT', 'xorps\t%xmm0, %xmm0', 'movaps\t%xmm0, (%rsp)', 'movaps\t%xmm0, 16(%rsp)', 'addq\t$40, %rsp', 'retq']);
const KEY_WO = listing('sign', ['subq\t$40, %rsp', 'callq\thmac@PLT', 'addq\t$40, %rsp', 'retq']);

const cellOf = (aW, aWo, fn) => zeroDeltaCell({ aW, aWo, fn, verdict: verdictOf(aW, aWo, fn), bodyOf, effect: EFFECT });

// ------------------------------------------------------------------ the count ----

test('the count\'s symbols come from the registry (wipe-6), read at run time, never spelled in the tool', () => {
  assert.deepEqual(EFFECT.symbols, REGISTRY.lists['wipe-6'].symbols);
  assert.equal(EFFECT.allowInlineZeroStore, true);
  assert.equal(EFFECT.listId, 'wipe-6');
  assert.throws(() => effectFromRegistry(REGISTRY, 'no-such-list'), /has no list "no-such-list"/);
  assert.throws(() => effectFromRegistry({}), /has no list "wipe-6"/);
  for (const f of ['tools/zero-delta.mjs', 'tools/lib/zero-delta.mjs']) {
    const src = readFileSync(path.join(LANE, f), 'utf8');
    assert.ok(!/['"]__memset_chk['"]|['"]explicit_bzero['"]/.test(src), `${f} spells a symbol of the list`);
  }
});

test('zeroWrites: a call to a listed symbol and every inline zero store count; an unreadable body is null', () => {
  assert.deepEqual(zeroWrites(KEY_W, 'sign', EFFECT).count, 2);
  assert.equal(zeroWrites(KEY_WO, 'sign', EFFECT).count, 0);
  const call = listing('f', ['movl\t$32, %edx', 'xorl\t%esi, %esi', 'callq\tmemset@PLT', 'retq']);
  assert.equal(zeroWrites(call, 'f', EFFECT).count, 1);
  // what the oracle does not read is not counted
  const blind = listing('f', ['callq\t__explicit_bzero_chk@PLT', 'callq\t*%rax', 'xorl\t%eax, %eax', 'rep\t\tstosq', 'retq']);
  assert.equal(zeroWrites(blind, 'f', EFFECT).count, 0);
  assert.equal(repStosCount(bodyOf(blind, 'f')), 1);
  assert.equal(zeroWrites(KEY_W, 'missing_fn', EFFECT), null);
  assert.equal(zeroWrites(null, 'sign', EFFECT), null);
  assert.equal(repStosCount(null), null);
});

test('onlyIn is a multiset difference', () => {
  assert.deepEqual(onlyIn(['a', 'b', 'b', 'c'], ['b', 'c', 'd']), ['a', 'b']);
  assert.deepEqual(onlyIn([], ['a']), []);
});

// ------------------------------------------------------------ the frame rules ----

test('rebase is hand_rebase.py\'s rule: the last leaq N(%rsp), %rbx is the base, leaq lines go, offsets become B+k', () => {
  const r = rebase(['subq $40, %rsp', 'leaq 4(%rsp), %rbx', 'leaq 8(%rsp), %rbx', 'movb $0, 14(%rsp)', 'movq %rax, (%rsp)']);
  assert.equal(r.base, 8, 'the LAST such leaq');
  assert.deepEqual(r.lines, ['subq $40, %rsp', 'movb $0, B+6(%rsp)', 'movq %rax, (%rsp)']);
  // the one change from the lab script: a negative offset is a number
  assert.deepEqual(rebase(['leaq 8(%rsp), %rbx', 'movq -8(%rsp), %rax']).lines, ['movq B-16(%rsp), %rax']);
  // no base: lines unchanged (bar the leaq lines, which the script drops whatever they are)
  assert.deepEqual(rebase(['leaq 8(%rsp), %rdi', 'movb $0, 14(%rsp)']), { lines: ['movb $0, 14(%rsp)'], base: null });
});

test('uniformRspShift: every %rsp offset moved by one d != 0, and nothing else changed', () => {
  assert.equal(uniformRspShift(['movb $0, 30(%rsp)', 'movq %rax, 16(%rsp)', 'retq'], ['movb $0, 14(%rsp)', 'movq %rax, (%rsp)', 'retq']), 16);
  assert.equal(uniformRspShift(['movb $0, 30(%rsp)', 'movq %rax, 17(%rsp)'], ['movb $0, 14(%rsp)', 'movq %rax, (%rsp)']), null, 'two different moves');
  assert.equal(uniformRspShift(['movb $0, 30(%rsp)', 'movq %rax, 8(%rsp)'], ['movb $0, 14(%rsp)', 'movq %rax, 8(%rsp)']), null, 'an offset that did not move');
  assert.equal(uniformRspShift(['movb $0, 30(%rsp)'], ['movw $0, 14(%rsp)']), null, 'the instruction changed');
  assert.equal(uniformRspShift(['retq'], ['retq', 'nop']), null);
  assert.equal(uniformRspShift(['retq'], ['retq']), null, 'nothing moved');
});

test('frameShiftOnly: the s3 pinpad shape is a rebase; a register-only difference and a real extra store are not', () => {
  const pin = frameShiftOnly(bodyOf(PIN_W, 'check_pin'), bodyOf(PIN_WO, 'check_pin'));
  assert.deepEqual(pin, { rule: 'rebase', baseW: 8, baseWo: 9 });
  assert.equal(frameShiftOnly(bodyOf(TOK_W, 'send_session_token'), bodyOf(TOK_WO, 'send_session_token')), null);
  assert.equal(frameShiftOnly(bodyOf(KEY_W, 'sign'), bodyOf(KEY_WO, 'sign')), null);
  assert.equal(frameShiftOnly(bodyOf(PIN_W, 'check_pin'), bodyOf(PIN_W, 'check_pin')), null, 'equal bodies');
  assert.equal(frameShiftOnly(null, 'x'), null);
  // without the buffer's leaq, a uniform move is the second rule
  const a = listing('g', ['subq\t$56, %rsp', 'movb\t$0, 30(%rsp)', 'movq\t%rax, 16(%rsp)', 'retq']);
  const b = listing('g', ['subq\t$56, %rsp', 'movb\t$0, 14(%rsp)', 'movq\t%rax, (%rsp)', 'retq']);
  assert.deepEqual(frameShiftOnly(bodyOf(a, 'g'), bodyOf(b, 'g')), { rule: 'uniform-shift', d: 16 });
});

test('labelsOnly: GCC\'s .L<n> renumbering is its own list, never a frame shift', () => {
  const a = '\tjne\t.L12\n.L12:\n\tret', b = '\tjne\t.L13\n.L13:\n\tret';
  assert.equal(labelsOnly(a, b), true);
  assert.equal(frameShiftOnly(a, b), null);
  assert.equal(labelsOnly(a, a), false);
  assert.deepEqual(instructionLines('f:\n\tjne\t.L7\n.L7:\n\tret'), ['jne\t.L#0', 'ret']);
});

// --------------------------------------------------------------- one cell ----

test('zeroDeltaCell on the s3 pinpad shape: WIPE_SURVIVED, delta 0, in both lists', () => {
  const c = cellOf(PIN_W, PIN_WO, 'check_pin');
  assert.equal(c.verdict, SURVIVED);
  assert.equal(c.control, 'PRESENT');
  assert.deepEqual([c.countW, c.countWo, c.delta], [1, 1, 0]);
  assert.deepEqual(c.zeroOnlyInW, ['movb\t$0, 14(%rsp)'], 'the line-by-line view still sees the moved terminator');
  assert.equal(c.survivedNoExtraZero, true);
  assert.equal(c.frameShift.rule, 'rebase');
  assert.equal(c.labelsOnly, false);
});

test('zeroDeltaCell on the s2 shape: WIPE_SURVIVED with no zero write on either side, not a frame shift', () => {
  const c = cellOf(TOK_W, TOK_WO, 'send_session_token');
  assert.equal(c.verdict, SURVIVED);
  assert.deepEqual([c.countW, c.countWo, c.delta], [0, 0, 0]);
  assert.equal(c.survivedNoExtraZero, true);
  assert.equal(c.frameShift, null);
});

test('zeroDeltaCell on a surviving wipe: delta > 0, in neither list; an eliminated cell is never listed', () => {
  const c = cellOf(KEY_W, KEY_WO, 'sign');
  assert.equal(c.verdict, SURVIVED);
  assert.equal(c.delta, 2);
  assert.equal(c.survivedNoExtraZero, false);
  assert.equal(c.frameShift, null);
  const e = cellOf(KEY_WO, KEY_WO, 'sign');
  assert.equal(e.verdict, 'WIPE_ELIMINATED');
  assert.equal(e.delta, 0);
  assert.equal(e.survivedNoExtraZero, false, 'delta 0 on an eliminated cell is the expected reading, not a misread');
  assert.equal(e.bodiesDiffer, false);
  const n = cellOf(KEY_W, null, 'sign');
  assert.equal(n.verdict, 'ABLATION_DID_NOT_COMPILE');
  assert.equal(n.delta, null);
});

test('summarize counts every cell by verdict and lists ids; trackedAgreement never counts a missing row as agreeing', () => {
  const rows = [
    { id: 'p', group: 'g', ...cellOf(PIN_W, PIN_WO, 'check_pin') },
    { id: 't', group: 'g', ...cellOf(TOK_W, TOK_WO, 'send_session_token') },
    { id: 'k', group: 'g', ...cellOf(KEY_W, KEY_WO, 'sign') },
    { id: 'e', group: 'h', ...cellOf(KEY_WO, KEY_WO, 'sign') },
  ];
  const [g, h] = summarize(rows);
  assert.equal(g.cells, 3);
  assert.deepEqual(g.byVerdict, { WIPE_SURVIVED: 3 });
  assert.deepEqual(g.survivedNoExtraZero, ['p', 't']);
  assert.deepEqual(g.frameShift, ['p (rebase)']);
  assert.deepEqual(g.both, ['p']);
  assert.equal(h.survived, 0);
  const ag = trackedAgreement(
    [{ id: 'a', cc: 'clang-18', opt: '-O2', verdict: 'WIPE_ELIMINATED' }, { id: 'b', cc: 'clang-18', opt: '-O2', verdict: SURVIVED },
      { id: 'c', cc: 'clang-18', opt: '-O2', verdict: SURVIVED }],
    [{ id: 'a', cc: 'clang-18', opt: '-O2', verdict: 'WIPE_ELIMINATED' }, { id: 'b', cc: 'clang-18', opt: '-O2', verdict: 'WIPE_ELIMINATED' },
      { id: 'c', cc: 'gcc-13', opt: '-O2', verdict: SURVIVED }, { id: 'z', verdict: 'NO_WIPE_WRITTEN' }]);
  assert.equal(ag.agree, 1);
  assert.deepEqual(ag.disagree, [{ cell: 'b|clang-18|-O2', here: SURVIVED, tracked: 'WIPE_ELIMINATED' }]);
  assert.deepEqual(ag.untracked, ['c|clang-18|-O2']);
});

// -------------------------------------------------------------------- CLI ----

const cli = (args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });

test('the CLI reads existing listings with --pairs and writes only under --out', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'zero-delta-'));
  try {
    for (const [n, t] of Object.entries({ 'pw.s': PIN_W, 'pwo.s': PIN_WO, 'tw.s': TOK_W, 'two.s': TOK_WO })) writeFileSync(path.join(dir, n), t);
    const list = path.join(dir, 'pairs.json');
    writeFileSync(list, JSON.stringify([
      { id: 'pin', fn: 'check_pin', w: 'pw.s', wo: 'pwo.s', group: 's3' },
      { id: 'tok', fn: 'send_session_token', w: 'tw.s', wo: 'two.s', group: 's2' },
    ]));
    const out = path.join(dir, 'out');
    const r = cli(['--pairs', list, '--out', out]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /== s3: 1 cell\(s\)/);
    assert.match(r.stdout, /survivedNoExtraZero 1: pin/);
    assert.match(r.stdout, /frameShift 1: pin \(rebase\)/);
    assert.match(r.stdout, /wipe-6 list of compiler\/schema\/effect-symbol-lists\.json/);
    const doc = JSON.parse(readFileSync(path.join(out, 'zero-delta-rows.json'), 'utf8'));
    assert.equal(doc.schema, 'zero-delta-v1');
    assert.equal(doc.rows.length, 2);
    assert.ok(existsSync(path.join(out, 'zero-delta-results.txt')));
    // a missing listing is counted, and the run says so with exit 2
    writeFileSync(list, JSON.stringify([{ id: 'gone', fn: 'f', w: 'nope.s', wo: 'pwo.s' }]));
    const m = cli(['--pairs', list, '--out', out]);
    assert.equal(m.status, 2);
    assert.match(m.stdout, /listings missing: gone/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the CLI refuses --out inside the repository, --write-data, and both or neither mode', () => {
  assert.equal(cli(['--pairs', 'x.json', '--out', path.join(LANE, 'zd-out')]).status, 4);
  assert.ok(!existsSync(path.join(LANE, 'zd-out')));
  assert.equal(cli(['--corpus', '--out', path.join(tmpdir(), 'zd'), '--write-data']).status, 4);
  assert.equal(cli(['--corpus', '--pairs', 'x', '--out', path.join(tmpdir(), 'zd')]).status, 4);
  assert.equal(cli(['--out', path.join(tmpdir(), 'zd')]).status, 4);
  assert.equal(cli(['--corpus', '--out', path.join(tmpdir(), 'zd'), '--opts', '-O9']).status, 4);
});
