// Tests for `compileLossEvidence` — the consumer-supplied, corpus-counted
// build-loss ratio adopted on 2026-09-12.
//
// Three of the four suites here are about a sentence rather than about a value,
// which is unusual and deliberate. The field's whole reason to exist is that a
// ratio can be quoted with its denominator attached and a derived number
// cannot, so the failure mode this feature has to be defended against is not a
// wrong value — it is a right value reshaped into something that reads as a
// forecast about the user's own file. That reshaping is a one-line edit at any
// of three call sites, and nothing in a type system notices it.
import { readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  isCompileLossEvidence,
  renderCompileLossEvidence,
  type CompileLossEvidence,
} from './compile-loss-evidence.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..');

/** The cell the specification uses as its worked example. */
const R2_CLANG_O2: CompileLossEvidence = {
  num: 113,
  den: 133,
  corpusId: 'r2',
  vendor: 'clang-18',
  optLevel: '-O2',
};

describe('renderCompileLossEvidence', () => {
  it('produces the one sentence the specification permits, to the character', () => {
    // Spelled out here rather than assembled from the input, for the same
    // reason the actuarial lane spells its reading sentence out in its own
    // test file: a pin that asks the subject what it says is not a pin.
    expect(renderCompileLossEvidence(R2_CLANG_O2)).toBe(
      '113 of 133 files with this idiom lost the wipe under clang-18 -O2 in corpus r2',
    );
  });

  it('reads both integers out verbatim and derives nothing', () => {
    expect(renderCompileLossEvidence({ ...R2_CLANG_O2, num: 0 })).toBe(
      '0 of 133 files with this idiom lost the wipe under clang-18 -O2 in corpus r2',
    );
    expect(
      renderCompileLossEvidence({
        num: 108,
        den: 133,
        corpusId: 'r2',
        vendor: 'gcc-13',
        optLevel: '-O1',
      }),
    ).toBe('108 of 133 files with this idiom lost the wipe under gcc-13 -O1 in corpus r2');
  });

  it('keeps the vendor version, because the version is the thing that was measured', () => {
    // A table keyed on "clang" would be a claim about a compiler family that
    // nothing measured. The renderer must not normalise it away.
    expect(renderCompileLossEvidence(R2_CLANG_O2)).toContain('clang-18');
  });
});

describe('isCompileLossEvidence', () => {
  it('accepts the specification example', () => {
    expect(isCompileLossEvidence(R2_CLANG_O2)).toBe(true);
  });

  it('accepts the degenerate-but-true ends of the range', () => {
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 0 })).toBe(true);
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 133 })).toBe(true);
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 1, den: 1 })).toBe(true);
  });

  it('rejects a numerator larger than its denominator', () => {
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 134 })).toBe(false);
  });

  it('rejects a zero or negative denominator', () => {
    // The case that matters: a cell with no exposure base is exactly what this
    // field exists to make impossible, and it is also what an uninitialised
    // counter in a producer looks like.
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 0, den: 0 })).toBe(false);
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 0, den: -1 })).toBe(false);
  });

  it('rejects a negative numerator', () => {
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: -1 })).toBe(false);
  });

  it('rejects non-integers, including a ratio that arrived already divided', () => {
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 113.5 })).toBe(false);
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, den: 132.9 })).toBe(false);
    // 0.849… is what a producer that lost the denominator would hand over.
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: 113 / 133, den: 1 })).toBe(false);
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: Number.NaN })).toBe(false);
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, den: Number.POSITIVE_INFINITY })).toBe(false);
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, num: '113' })).toBe(false);
  });

  it('rejects empty and whitespace-only strings on all three string fields', () => {
    for (const key of ['corpusId', 'vendor', 'optLevel'] as const) {
      expect(isCompileLossEvidence({ ...R2_CLANG_O2, [key]: '' })).toBe(false);
      expect(isCompileLossEvidence({ ...R2_CLANG_O2, [key]: '   ' })).toBe(false);
      expect(isCompileLossEvidence({ ...R2_CLANG_O2, [key]: 18 })).toBe(false);
      const without: Record<string, unknown> = { ...R2_CLANG_O2 };
      delete without[key];
      expect(isCompileLossEvidence(without)).toBe(false);
    }
  });

  it('rejects things that are not objects at all', () => {
    for (const bad of [null, undefined, 113, '113 of 133', true, [113, 133]]) {
      expect(isCompileLossEvidence(bad)).toBe(false);
    }
  });

  it('tolerates unknown extra keys — the shape is a floor, not a ceiling', () => {
    expect(isCompileLossEvidence({ ...R2_CLANG_O2, measuredAt: '2026-08-18' })).toBe(true);
  });
});

// ── THE VOCABULARY RULE ──────────────────────────────────────────────────────
//
// The needles are assembled from fragments at runtime rather than written out
// as literals, following `scripts/check-disclosure-shape.mjs` and the drift
// test in `compiler/eval/actuarial/test/rate-table.test.mjs`. Here the reason
// is the same one those two give: written literally, a needle would match the
// file it is written in, and the check would report a clean surface as dirty.
//
// `WORD_NEEDLES` are allowed in exactly one place — the block comment in
// `compile-loss-evidence.ts` that STATES the prohibition, which has to be able
// to spell what it forbids. `HARD_NEEDLES` are allowed nowhere, including
// inside that block: no comment needs to compute one.
const WORD_NEEDLES = [
  ['perc', 'ent'],
  ['prob', 'abil'],
  ['fore', 'cast'],
  ['likeli', 'hood'],
].map((parts) => new RegExp(parts.join(''), 'i'));

const HARD_NEEDLES = [
  new RegExp(String.fromCharCode(37)), // the per-hundred sign
  new RegExp(['to', 'Fixed'].join('')),
  new RegExp(['Math', 'round'].join('\\.')),
  new RegExp(['num', 'den'].join('\\s*/\\s*')), // the division itself
];

const MODULE = 'packages/findings-schema/src/compile-loss-evidence.ts';

/** Every product file on the path a supplied cell travels to a human. */
const RENDER_PATH = [
  MODULE,
  'packages/findings-schema/src/index.ts',
  'packages/analyzer-core/src/analyzer.ts',
  'packages/sarif-adapter/src/index.ts',
  'apps/cli/src/format.ts',
];

const readRepoFile = (rel: string): string[] =>
  readFileSync(join(REPO, rel), 'utf8').replace(/\r\n/g, '\n').split('\n');

describe('the wording rule is held by the code, not only stated by it', () => {
  it('is pointed at files that exist and actually carry the field', () => {
    // A vocabulary check that scans nothing reports a confident zero. Same
    // failure mode as a needle that never fires, and the same guard.
    for (const rel of RENDER_PATH) {
      const body = readRepoFile(rel).join('\n');
      expect(body.length, `${rel} is empty or missing`).toBeGreaterThan(0);
      expect(body, `${rel} no longer mentions the field`).toContain('compileLossEvidence');
    }
  });

  it('lets the module spell the forbidden words only inside the block that forbids them', () => {
    const lines = readRepoFile(MODULE);
    const start = lines.findIndex((l) => /THE WORDING RULE/.test(l));
    expect(start, `${MODULE} has no wording-rule block`).toBeGreaterThanOrEqual(0);
    let end = lines.findIndex((l, i) => i > start && /\*\/\s*$/.test(l));
    expect(end, `${MODULE}'s wording-rule block is not terminated`).toBeGreaterThan(start);

    let inside = 0;
    lines.forEach((line, i) => {
      for (const needle of WORD_NEEDLES) {
        if (!needle.test(line)) continue;
        // A structural bound, not an exemption list: move the sentence out of
        // the block and this fails.
        expect(
          i >= start && i <= end,
          `${MODULE}:${i + 1} says a word the wording rule reserves for itself:\n${line}`,
        ).toBe(true);
        inside += 1;
      }
    });
    // The block has to keep stating the prohibition. A "clean" module that
    // achieved cleanliness by deleting the rule is not what this asserts.
    expect(inside, 'the wording-rule block no longer states what it forbids').toBeGreaterThan(0);
  });

  it('never lets a hard needle appear in the module, block included', () => {
    const lines = readRepoFile(MODULE);
    lines.forEach((line, i) => {
      for (const needle of HARD_NEEDLES) {
        expect(
          needle.test(line),
          `${MODULE}:${i + 1} computes or prints a derived quantity:\n${line}`,
        ).toBe(false);
      }
    });
  });

  it('keeps every other call site on the render path clean where it touches the field', () => {
    // Scoped to the lines that mention the field rather than to whole files:
    // `analyzer.ts` and `format.ts` are large and shared, and a per-hundred
    // sign elsewhere in them would be somebody else's feature, not this one's
    // breach. What must never happen is the two appearing together.
    let checked = 0;
    for (const rel of RENDER_PATH) {
      if (rel === MODULE) continue;
      readRepoFile(rel).forEach((line, i) => {
        if (!/compileLossEvidence/i.test(line)) return;
        checked += 1;
        for (const needle of [...WORD_NEEDLES, ...HARD_NEEDLES]) {
          expect(
            needle.test(line),
            `${relative('.', rel)}:${i + 1} reshapes the ratio:\n${line}`,
          ).toBe(false);
        }
      });
    }
    expect(checked, 'the per-line sweep found no lines to check').toBeGreaterThan(4);
  });
});
