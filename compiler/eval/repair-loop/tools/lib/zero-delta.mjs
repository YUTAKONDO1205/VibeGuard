/**
 * A third reading beside the find step's verdict: the number of zero writes in
 * the target body with the wipe (w) and without it (wo), and the difference.
 * The pure parts of ../zero-delta.mjs; nothing here compiles, reads a file or
 * looks at a directory. The tests (../../test/zero-delta.test.mjs) reach all of
 * it with no compiler.
 *
 * Why it exists. verdictOf compares the two target bodies as text and calls any
 * difference WIPE_SURVIVED. Two misreadings of that rule have been found by
 * hand outside this tree, and neither makes a sound:
 *
 *   - a body that differs only in register allocation or branch layout, with no
 *     zero write in either: 72 cells of one file family read WIPE_SURVIVED at
 *     clang-15..20 without a plugin while the wipe was gone (lab notes
 *     s2_plugins/README.md §5, where a count difference of 0 found them);
 *   - a body that differs only because the frame moved by one byte, so that the
 *     same `movb $0, N(%rsp)` -- a string terminator, not the wipe -- reads as
 *     present in w only: nine pinpad files of a replay with every dead-store
 *     pass removed (lab notes s3_backend/README.md, "the nine pinpad files"),
 *     found by re-basing every %rsp offset on the buffer's address.
 *
 * This file lists the cells in which either could be happening. It never
 * changes a verdict. Two lists:
 *
 *   survivedNoExtraZero  verdictOf says WIPE_SURVIVED, both counts were read,
 *                        and w has no more zero writes than wo (delta <= 0)
 *   frameShift           the bodies differ, and are the same once their %rsp
 *                        offsets are re-based on the buffer (rule `rebase`, the
 *                        lab's hand_rebase.py with negative offsets read as
 *                        numbers) or once every %rsp offset is moved by one
 *                        constant d != 0 (rule `uniform-shift`)
 *
 * and, apart from both, `labelsOnly`: bodies that differ only in GCC's `.L<n>`
 * numbering, which canonicalLocalLabels already explains.
 *
 * The count is asm-oracle's observeEffect over the target body -- a call or tail
 * call to one of the effect's symbols, or an inline zero store to memory -- and
 * the effect is passed in (the tool reads the `wipe-6` list of
 * compiler/schema/effect-symbol-lists.json, the registry, rather than spelling
 * one here). What it does not see is not counted and is not guessed at: `rep
 * stos` (kept beside the count as repStosW / repStosWo, never added to it), an
 * indirect call (`call *%rax`), and `__explicit_bzero_chk` unless the list names
 * it. A delta <= 0 is therefore "no extra zero write that this reading can see",
 * never "the wipe is gone".
 */
import { observeEffect } from '../../../second-vendor/lib/asm-oracle.mjs';
import { canonicalLocalLabels } from '../../lib/surgicality.mjs';

export const SURVIVED = 'WIPE_SURVIVED';

/**
 * The effect a zero-write count uses: the registry list's symbols, and inline
 * zero stores. `registry` is the parsed effect-symbol-lists.json.
 */
export function effectFromRegistry(registry, listId = 'wipe-6') {
  const spec = registry?.lists?.[listId];
  if (!spec || !Array.isArray(spec.symbols) || !spec.symbols.length) {
    throw new Error(`effect-symbol-lists.json has no list ${JSON.stringify(listId)} with symbols`);
  }
  return { symbols: [...spec.symbols], allowInlineZeroStore: true, listId };
}

/** observeEffect's evidence for one listing: {count, lines}, or null when the body could not be read. */
export function zeroWrites(asm, fn, effect) {
  if (typeof asm !== 'string') return null;
  const v = observeEffect(asm, fn, effect);
  if (v.verdict === 'NOT_OBSERVED') return null;
  return { count: v.evidence.length, lines: v.evidence.map((e) => e.line) };
}

/** `rep stos` lines in a body text (comments already stripped by bodyOf): the form the oracle does not read. */
export function repStosCount(body) {
  if (typeof body !== 'string') return null;
  return body.split('\n').filter((l) => /^\s*rep\s+stos[bwlq]?\s*$/.test(l)).length;
}

/** The lines of `a` not matched one-for-one by a line of `b` (a multiset difference), in a's order. */
export function onlyIn(a, b) {
  const left = new Map();
  for (const l of b) left.set(l, (left.get(l) ?? 0) + 1);
  const out = [];
  for (const l of a) { const n = left.get(l) ?? 0; if (n) left.set(l, n - 1); else out.push(l); }
  return out;
}

/**
 * The instruction lines of a bodyOf text, as hand_rebase.py takes them: the
 * lines that begin with whitespace (labels begin at column 0), trimmed, after
 * canonicalLocalLabels.
 */
export function instructionLines(body) {
  return canonicalLocalLabels(body).split('\n').filter((l) => /^\s/.test(l)).map((l) => l.trim()).filter(Boolean);
}

const RSP_OFFSET = /(-?\d+)\(%rsp\)/g;

/**
 * hand_rebase.py's rule: the base is the offset of the LAST `leaq N(%rsp), %rbx`;
 * every line beginning `leaq` is dropped; every `N(%rsp)` becomes `B+k(%rsp)`
 * with k = N - base. The one change from the lab script: a negative offset is
 * read as a number (the script's `(\d+)` read only its digits).
 * @returns {{lines: string[], base: number|null}}
 */
export function rebase(lines) {
  let base = null;
  for (const l of lines) {
    const m = /^leaq\s+(\d+)\(%rsp\), %rbx/.exec(l);
    if (m) base = Number(m[1]);
  }
  const out = [];
  for (const l of lines) {
    if (l.startsWith('leaq')) continue;
    out.push(base === null ? l : l.replace(RSP_OFFSET, (_, n) => {
      const k = Number(n) - base;
      return `B${k >= 0 ? '+' : ''}${k}(%rsp)`;
    }));
  }
  return { lines: out, base };
}

/**
 * Is every difference between the two line lists one constant move d != 0 of
 * the %rsp offsets? `(%rsp)` is read as `0(%rsp)`. Returns d, or null.
 */
export function uniformRspShift(wLines, woLines) {
  if (wLines.length !== woLines.length) return null;
  const norm = (l) => l.replace(/(^|[\s,])\(%rsp\)/g, '$10(%rsp)');
  const hasOffset = (l) => /(-?\d+)\(%rsp\)/.test(l);
  let d = null;
  for (let i = 0; i < wLines.length; i++) {
    const a = norm(wLines[i]), b = norm(woLines[i]);
    if (a === b) {
      // an unchanged line is only allowed when it holds no %rsp offset (a shift moves every one)
      if (hasOffset(a)) return null;
      continue;
    }
    const oa = [...a.matchAll(RSP_OFFSET)].map((m) => Number(m[1]));
    const ob = [...b.matchAll(RSP_OFFSET)].map((m) => Number(m[1]));
    if (!oa.length || oa.length !== ob.length) return null;
    if (a.replace(RSP_OFFSET, 'N(%rsp)') !== b.replace(RSP_OFFSET, 'N(%rsp)')) return null;
    for (let j = 0; j < oa.length; j++) {
      const k = oa[j] - ob[j];
      if (k === 0) return null;
      if (d === null) d = k; else if (k !== d) return null;
    }
  }
  return d;
}

/**
 * Why two bodies differ, when it is only the frame: {rule: 'rebase', baseW,
 * baseWo} or {rule: 'uniform-shift', d}; null when they are equal, missing, or
 * differ in something else. Labels are made canonical first, and a difference
 * that canonicalLocalLabels removes is not a frame shift (see labelsOnly).
 */
export function frameShiftOnly(bodyW, bodyWo) {
  if (typeof bodyW !== 'string' || typeof bodyWo !== 'string' || bodyW === bodyWo) return null;
  if (canonicalLocalLabels(bodyW) === canonicalLocalLabels(bodyWo)) return null;
  const w = instructionLines(bodyW), wo = instructionLines(bodyWo);
  const rw = rebase(w), rwo = rebase(wo);
  if (rw.base !== null && rwo.base !== null && rw.base !== rwo.base
    && rw.lines.length === rwo.lines.length && rw.lines.every((l, i) => l === rwo.lines[i])) {
    return { rule: 'rebase', baseW: rw.base, baseWo: rwo.base };
  }
  const d = uniformRspShift(w, wo);
  return d === null ? null : { rule: 'uniform-shift', d };
}

/** Bodies that differ as text and are the same once GCC's `.L<n>` labels are made canonical. */
export function labelsOnly(bodyW, bodyWo) {
  return typeof bodyW === 'string' && typeof bodyWo === 'string' && bodyW !== bodyWo
    && canonicalLocalLabels(bodyW) === canonicalLocalLabels(bodyWo);
}

/**
 * One cell. `verdict` is verdictOf's object for (aW, aWo, fn) -- the caller
 * computes it with the find step's own function -- and `bodyOf` is the find
 * step's body reader. Nothing here reads the verdict except to list the cell.
 */
export function zeroDeltaCell({ aW, aWo, fn, verdict, bodyOf, effect }) {
  const bW = typeof aW === 'string' ? bodyOf(aW, fn) : null;
  const bWo = typeof aWo === 'string' ? bodyOf(aWo, fn) : null;
  const zW = zeroWrites(aW, fn, effect), zWo = zeroWrites(aWo, fn, effect);
  const countW = zW ? zW.count : null, countWo = zWo ? zWo.count : null;
  const delta = countW !== null && countWo !== null ? countW - countWo : null;
  const fs = frameShiftOnly(bW, bWo);
  return {
    verdict: verdict.verdict,
    control: verdict.control ?? null,
    countW, countWo, delta,
    zeroOnlyInW: zW && zWo ? onlyIn(zW.lines, zWo.lines) : null,
    repStosW: repStosCount(bW), repStosWo: repStosCount(bWo),
    bodiesDiffer: bW !== null && bWo !== null && bW !== bWo,
    survivedNoExtraZero: verdict.verdict === SURVIVED && delta !== null && delta <= 0,
    frameShift: fs,
    labelsOnly: labelsOnly(bW, bWo),
  };
}

/**
 * Totals over rows that carry {id, group, ...zeroDeltaCell}. `group` is any
 * label the caller chose (a compiler and level, a tag). Every row is counted
 * somewhere: by verdict, and in the lists by id.
 */
export function summarize(rows) {
  const groups = new Map();
  for (const r of rows) {
    const g = r.group ?? '(all)';
    if (!groups.has(g)) {
      groups.set(g, { group: g, cells: 0, byVerdict: {}, survived: 0, deltaRead: 0,
        survivedNoExtraZero: [], frameShift: [], both: [], labelsOnly: [], survivedDeltaNotRead: [] });
    }
    const s = groups.get(g);
    s.cells++;
    s.byVerdict[r.verdict] = (s.byVerdict[r.verdict] ?? 0) + 1;
    if (r.verdict === SURVIVED) {
      s.survived++;
      if (r.delta === null) s.survivedDeltaNotRead.push(r.id); else s.deltaRead++;
    }
    if (r.survivedNoExtraZero) s.survivedNoExtraZero.push(r.id);
    if (r.frameShift) s.frameShift.push(`${r.id} (${r.frameShift.rule}${r.frameShift.rule === 'uniform-shift' ? ` ${r.frameShift.d}` : ''})`);
    if (r.survivedNoExtraZero && r.frameShift) s.both.push(r.id);
    if (r.labelsOnly) s.labelsOnly.push(r.id);
  }
  return [...groups.values()];
}

/**
 * The find step's verdict here against a tracked row's, per (id, cc, opt).
 * `tracked` is the tracked rows' array; a cell with no tracked row is listed as
 * such, never counted as agreeing.
 */
export function trackedAgreement(rows, tracked) {
  const key = (r) => `${r.id}|${r.cc}|${r.opt}`;
  const t = new Map((tracked ?? []).filter((r) => r.cc && r.opt).map((r) => [key(r), r.verdict]));
  let agree = 0;
  const disagree = [], untracked = [];
  for (const r of rows) {
    const k = key(r);
    if (!t.has(k)) { untracked.push(k); continue; }
    if (t.get(k) === r.verdict) agree++; else disagree.push({ cell: k, here: r.verdict, tracked: t.get(k) });
  }
  return { agree, disagree, untracked };
}
