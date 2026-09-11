// Unit tests for the pure parts of scripts/run-gcc-corpus-smoke.mjs: which
// rows it picks, and how it reports what changed in a body.
//
//   node --test compiler/gcc-repair/test/corpus-smoke.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { selectRows, bodyDelta } from '../scripts/run-gcc-corpus-smoke.mjs';

const row = (id, over = {}) => ({ id, kind: 'erasure', cc: 'gcc-13', opt: '-O2', idiom: 'removable', verdict: 'WIPE_ELIMINATED', ...over });

test('selectRows: the first n ids, sorted, matching cc, opt, idiom and verdict', () => {
  const rows = [
    row('c'), row('a'), row('b'), row('d'),
    row('a0', { cc: 'clang-18' }),
    row('a1', { opt: '-O3' }),
    row('a2', { idiom: 'nonremovable' }),
    row('a3', { verdict: 'WIPE_SURVIVED' }),
    row('a4', { kind: 'none' }),
  ];
  assert.deepEqual(selectRows(rows, { cc: 'gcc-13', opt: '-O2', n: 3 }).map((r) => r.id), ['a', 'b', 'c']);
  assert.deepEqual(selectRows(rows, { cc: 'gcc-13', opt: '-O2', n: 10 }).map((r) => r.id), ['a', 'b', 'c', 'd']);
  assert.deepEqual(selectRows(rows, { cc: 'gcc-13', opt: '-Os', n: 3 }), []);
});

test('selectRows: an id listed twice is taken once', () => {
  const rows = [row('b'), row('a'), row('a')];
  assert.deepEqual(selectRows(rows, { cc: 'gcc-13', opt: '-O2', n: 3 }).map((r) => r.id), ['a', 'b']);
});

test('bodyDelta: added and removed lines as multisets', () => {
  const before = 'call\tconsume@PLT\nmovq\t40(%rsp), %rax\nret';
  const after = 'call\tconsume@PLT\npxor\t%xmm0, %xmm0\nmovaps\t%xmm0, (%rsp)\nmovaps\t%xmm0, 16(%rsp)\nmovq\t40(%rsp), %rax\nret';
  const d = bodyDelta(before, after);
  assert.equal(d.identical, false);
  assert.deepEqual(d.added, ['pxor\t%xmm0, %xmm0', 'movaps\t%xmm0, (%rsp)', 'movaps\t%xmm0, 16(%rsp)']);
  assert.deepEqual(d.removed, []);
});

test('bodyDelta: a repeated line counts as many times as it is added', () => {
  const d = bodyDelta('a\nb', 'a\nb\nb\nb');
  assert.deepEqual(d.added, ['b', 'b']);
  assert.deepEqual(bodyDelta('x\ny', 'x\ny'), { added: [], removed: [], identical: true });
});

test('bodyDelta: a moved line is not reported, but the bodies are not identical', () => {
  const d = bodyDelta('a\nb', 'b\na');
  assert.deepEqual(d, { added: [], removed: [], identical: false });
});

test('bodyDelta: nothing to compare is null', () => {
  assert.equal(bodyDelta(null, 'a'), null);
  assert.equal(bodyDelta('a', null), null);
});
