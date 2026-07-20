// vibeguard:disable-file VG-FW-003 VG-INJ-004 VG-INJ-006
// Fixtures embed eval()/innerHTML/DEBUG/secret literals to exercise the
// context-window confidence helper; they are not real vulnerabilities.
import { describe, expect, it } from 'vitest';
import type { Confidence, Severity } from '@vibeguard/findings-schema';
import {
  contextConfidence,
  detectDowngradeSignals,
  downgradeConfidence,
  explainContextConfidence,
  isInDocstringOrBlockComment,
  isTestPath,
  SEVERITY_CONFIDENCE_FLOOR,
  type ContextConfidenceMode,
  type DowngradeSignal,
} from './confidence.js';
import type { RuleContext, RuleMatch } from './rule-types.js';

function ctxOf(content: string, opts: { filePath?: string; language?: string } = {}): RuleContext {
  return { content, lines: content.split('\n'), filePath: opts.filePath, language: opts.language };
}

function matchAtLine(startLine: number): RuleMatch {
  return { startLine, endLine: startLine, startColumn: 1, endColumn: 1, evidence: '' };
}

describe('downgradeConfidence', () => {
  it('lowers by the given number of ladder steps', () => {
    expect(downgradeConfidence('high', 1)).toBe('medium');
    expect(downgradeConfidence('high', 2)).toBe('low');
    expect(downgradeConfidence('medium', 1)).toBe('low');
  });

  it('clamps at low and is a no-op for zero/negative steps', () => {
    expect(downgradeConfidence('high', 3)).toBe('low');
    expect(downgradeConfidence('low', 2)).toBe('low');
    expect(downgradeConfidence('high', 0)).toBe('high');
    expect(downgradeConfidence('medium', -1)).toBe('medium');
  });
});

describe('isTestPath', () => {
  it('recognises test / spec / fixture paths', () => {
    expect(isTestPath('src/foo.test.ts')).toBe(true);
    expect(isTestPath('tests/test_client.py')).toBe(true);
    expect(isTestPath('pkg/__mocks__/db.js')).toBe(true);
    expect(isTestPath('app/fixtures/data.json')).toBe(true);
    expect(isTestPath('src/handler.spec.tsx')).toBe(true);
  });

  it('does not flag ordinary source paths', () => {
    expect(isTestPath('src/handlers.ts')).toBe(false);
    expect(isTestPath('app/settings.py')).toBe(false);
    expect(isTestPath(undefined)).toBe(false);
  });
});

describe('isInDocstringOrBlockComment', () => {
  it('detects a Python docstring line', () => {
    const lines = [
      'def configure():',
      '    """',
      '    Example config:',
      '        DEBUG = True',
      '    """',
      '    return DEBUG',
    ];
    expect(isInDocstringOrBlockComment(lines, 4, 'python')).toBe(true); // DEBUG = True inside docstring
    expect(isInDocstringOrBlockComment(lines, 6, 'python')).toBe(false); // return DEBUG, after close
    expect(isInDocstringOrBlockComment(lines, 1, 'python')).toBe(false);
  });

  it('detects a JS/Java block comment line', () => {
    const lines = ['/*', ' * el.innerHTML = data;', ' */', 'render();'];
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(true);
    expect(isInDocstringOrBlockComment(lines, 4, 'javascript')).toBe(false);
  });

  it('does not treat a closed single-line docstring as ongoing', () => {
    const lines = ['x = """short"""', 'DEBUG = True'];
    expect(isInDocstringOrBlockComment(lines, 2, 'python')).toBe(false);
  });

  it('is not fooled by /* or // inside a string literal (regression: flask CORS sample)', () => {
    // r'/*' is a raw string containing /*, NOT a block-comment opener. A naive
    // scanner would treat everything after it as a block comment and wrongly
    // down-rank the real app.run(debug=True) below.
    const lines = [
      "CORS(app, resources={r'/*': {'origins': '*'}})",
      "    app.run(host='0.0.0.0', debug=True)",
    ];
    expect(isInDocstringOrBlockComment(lines, 2, 'python')).toBe(false);
  });

  it('treats a real block comment opened after a string as ongoing', () => {
    const lines = ['const s = "x"; /*', 'eval(payload)', '*/', 'run()'];
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(true);
    expect(isInDocstringOrBlockComment(lines, 4, 'javascript')).toBe(false);
  });

  it('ignores # as a comment marker in languages where it is not one', () => {
    // `this.#secret` is a JS private field, not a comment; must not swallow the
    // subsequent block-comment opener.
    const lines = ['this.#secret = "x"; /*', 'eval(payload)', '*/', 'run()'];
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(true);
  });

  it('does not treat """ as a docstring opener outside Python (JS/TS regex literal)', () => {
    // `/"""/` is a JS/TS regex literal containing three quotes, NOT a Python
    // docstring opener. Treating it as one phantom-opens a triple-quote block
    // and wrongly down-ranks the real eval() on the next line.
    const lines = ['const re = /"""/;', 'eval(userInput)'];
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(false);
    expect(isInDocstringOrBlockComment(lines, 2, 'typescript')).toBe(false);
    // Python, by contrast, DOES treat """ as a docstring opener.
    expect(isInDocstringOrBlockComment(['"""', 'DEBUG = True'], 2, 'python')).toBe(true);
  });

  it('does not flag a docstring-closing line that also carries real code (B2: close-line)', () => {
    // The docstring closes on line 3, but real code follows on the same line —
    // the match could be that code, so we must not down-rank it.
    const lines = ['"""doc', 'middle', '""" ; DEBUG = True'];
    expect(isInDocstringOrBlockComment(lines, 3, 'python')).toBe(false);
    // A purely-inside line (no closer) is still in the docstring.
    expect(isInDocstringOrBlockComment(lines, 2, 'python')).toBe(true);
  });

  it('does not flag a block-comment-closing line that also carries real code (B2: close-line)', () => {
    const lines = ['/*', ' * doc', '*/ eval(x)'];
    expect(isInDocstringOrBlockComment(lines, 3, 'javascript')).toBe(false);
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// The scanner's line-comment branch reads the per-language allowlist
// (getLineCommentSpec / lineCommentStartsAt) instead of hard-coding `//` and a
// `#` blocklist. These pin the branch itself — the suite above passes either
// way, so without them a revert to the hard-coded form is invisible.
// ---------------------------------------------------------------------------
describe('isInDocstringOrBlockComment — line comments come from the language map', () => {
  it('does not let Python floor-division swallow the rest of the line', () => {
    // THE regression test for the hard-coded `//`. Python's `//` is an operator,
    // so the `"""` after it genuinely opens a docstring and line 2 is inside it.
    // Skipping to end-of-line on `//` loses that and reports false.
    const lines = ['x = a // 2 + """', 'DEBUG = True', '"""'];
    expect(isInDocstringOrBlockComment(lines, 2, 'python')).toBe(true);
  });

  it('still swallows a TRAILING # comment, so its """ cannot phantom-open a docstring', () => {
    // The trap: `lineCommentStartsAt` is asked at position k, not at the first
    // non-whitespace character. Swap in the line-start predicate (isCommentLine)
    // and this line reads as code, the `"""` opens a docstring, and the real
    // DEBUG = True below gets wrongly down-ranked.
    const lines = ['x = 1  # opens """', 'DEBUG = True'];
    expect(isInDocstringOrBlockComment(lines, 2, 'python')).toBe(false);
  });

  it('honours the PHP #[ exclusion: # is a comment, #[Attribute] is code', () => {
    // `# …` swallows the /*, so nothing is open on line 2.
    expect(isInDocstringOrBlockComment(['# opens /*', 'eval($x)'], 2, 'php')).toBe(false);
    // `#[Route]` is executed syntax, not a comment, so the /* after it really
    // does open a block comment that line 2 sits inside.
    expect(isInDocstringOrBlockComment(['#[Route] /*', 'eval($x)', '*/'], 2, 'php')).toBe(true);
  });

  it('treats # as code where the map says it is not a comment', () => {
    // JS private field (kept from the old blocklist) and, newly, Python-style `#`
    // in languages whose spec has no `#` at all.
    expect(isInDocstringOrBlockComment(['this.#secret = "x"; /*', 'eval(p)', '*/'], 2, 'javascript')).toBe(true);
    expect(isInDocstringOrBlockComment(['#include <x.h> /*', 'gets(buf)', '*/'], 2, 'c')).toBe(true);
  });

  it('documents the empty-spec fallback direction (unknown language, html)', () => {
    // With no allowlist entry nothing swallows, so a `/*` inside what was really
    // a comment phantom-opens a block and these report true. This is the bounded
    // residual named in the function's doc comment — worst case one confidence
    // step, clamped by SEVERITY_CONFIDENCE_FLOOR — and is the deliberate price of
    // never DROPPING a match for an unrecognised language.
    expect(isInDocstringOrBlockComment(['# /*', 'eval(x)', '*/'], 2, undefined)).toBe(true);
    expect(isInDocstringOrBlockComment(['// x /*', 'eval(y)', '*/'], 2, 'html')).toBe(true);
  });
});

describe('detectDowngradeSignals', () => {
  it('flags a whole-line comment', () => {
    const ctx = ctxOf('// eval(userInput)', { filePath: 'a.js', language: 'javascript' });
    expect(detectDowngradeSignals(ctx, matchAtLine(1))).toEqual(['comment']);
  });

  it('flags a docstring line', () => {
    const ctx = ctxOf('"""\nDEBUG = True\n"""', { filePath: 'settings.py', language: 'python' });
    expect(detectDowngradeSignals(ctx, matchAtLine(2))).toEqual(['docstring']);
  });

  it('flags a test path and stacks with comment context', () => {
    const ctx = ctxOf('// secret = "x"', { filePath: 'a.test.js', language: 'javascript' });
    expect(detectDowngradeSignals(ctx, matchAtLine(1))).toEqual(['comment', 'test-path']);
  });

  it('returns no signals for a plain code line in a source path', () => {
    const ctx = ctxOf('const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' });
    expect(detectDowngradeSignals(ctx, matchAtLine(1))).toEqual([]);
  });

  it('reads the payload line, not the previous comment line, for ^\\s*-anchored evidence', () => {
    // Mirrors VG-QUAL-008 / VG-FW-001: the `^\s*` match swallows the newline, so
    // startLine points at the comment on line 1 but the real code is line 2.
    const ctx = ctxOf('# DEBUG left on below\nDEBUG = True', {
      filePath: 'settings.py',
      language: 'python',
    });
    const match: RuleMatch = {
      startLine: 1,
      endLine: 2,
      startColumn: 1,
      endColumn: 1,
      evidence: '\nDEBUG = True',
    };
    expect(detectDowngradeSignals(ctx, match)).toEqual([]); // line 2 is real code
  });
});

describe('contextConfidence', () => {
  // These cases exercise the downgrade MECHANISM (item ①), so they all pass
  // severity 'low' — the severity gate is `null` there, leaving the context
  // layer's own behaviour observable. (It used to be 'medium'; D1c gave that
  // band a `medium` floor, so it no longer shows the un-gated mechanism.) Gate
  // behaviour is tested separately against critical/high/medium; keep this
  // split, or the mechanism loses its coverage.
  const codeCtx = ctxOf('const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' });
  const commentCtx = ctxOf('// const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' });
  const testCtx = ctxOf('const x = eval(input);', { filePath: 'src/run.test.js', language: 'javascript' });

  it('leaves confidence unchanged on a plain production code line', () => {
    expect(contextConfidence('high', 'low', codeCtx, matchAtLine(1))).toBe('high');
  });

  it('drops two steps for a comment (high -> low)', () => {
    expect(contextConfidence('high', 'low', commentCtx, matchAtLine(1))).toBe('low');
  });

  it('drops one step for a test path (high -> medium)', () => {
    expect(contextConfidence('high', 'low', testCtx, matchAtLine(1))).toBe('medium');
    expect(contextConfidence('medium', 'low', testCtx, matchAtLine(1))).toBe('low');
  });

  it('sums stacked signals and clamps at low', () => {
    const commentInTest = ctxOf('// secret', { filePath: 'a.test.js', language: 'javascript' });
    expect(contextConfidence('high', 'low', commentInTest, matchAtLine(1))).toBe('low');
  });

  it('is a no-op when mode is off (comment-is-the-signal rules)', () => {
    expect(contextConfidence('medium', 'low', commentCtx, matchAtLine(1), 'off')).toBe('medium');
  });

  it('never raises confidence (downgrade-only)', () => {
    expect(contextConfidence('low', 'low', codeCtx, matchAtLine(1))).toBe('low');
    expect(contextConfidence('medium', 'low', codeCtx, matchAtLine(1))).toBe('medium');
  });

  it('does not down-rank a real JS finding sitting after a """ regex literal', () => {
    // Regression: the phantom-docstring bug silently demoted this real eval().
    const ctx = ctxOf('const re = /"""/;\neval(userInput)', {
      filePath: 'src/run.js',
      language: 'javascript',
    });
    expect(contextConfidence('high', 'low', ctx, matchAtLine(2))).toBe('high');
  });
});

// ---------------------------------------------------------------------------
// Severity gate (D1). Properties swept over the whole input space, because the
// gate's guarantees are universally quantified statements about the function —
// "result <= base, always" is not a claim a handful of examples can support,
// and the one bug that matters here (a floor read as a promotion) only appears
// in the corners: base below the floor, on a gated severity, with signals.
// ---------------------------------------------------------------------------

const RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };
const ALL_BASES: readonly Confidence[] = ['low', 'medium', 'high'];
const ALL_SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
// Named after what the floor DOES, not after "is there a floor at all" — since
// D1c every severity except low/info has one, and the two groups below behave
// differently. `critical`/`high` are floored at `high`, the top rung, so the
// clamp swallows the whole downgrade. `medium` is floored at `medium`, one rung
// down, so it still moves; it gets its own assertions rather than a sweep.
const NO_DOWNGRADE_SEVERITIES: readonly Severity[] = ['critical', 'high'];
// floor === null: bit-identical to the un-gated item ① behaviour.
const UNGATED_SEVERITIES: readonly Severity[] = ['low', 'info'];
const ALL_MODES: readonly ContextConfidenceMode[] = ['auto', 'off'];

// Restated rather than imported from the module under test. SIGNAL_STEPS is
// frozen — item ①'s published numbers are computed from these exact values — so
// a test that re-derived the arithmetic from the implementation would ratify any
// future edit to it instead of failing on it.
const EXPECTED_STEPS: Record<DowngradeSignal, number> = {
  comment: 2,
  docstring: 2,
  'test-path': 1,
};

interface SignalFixture {
  name: string;
  ctx: RuleContext;
  match: RuleMatch;
  signals: DowngradeSignal[];
}

/**
 * Every reachable signal subset. The powerset of three signals has eight
 * members, but `detectDowngradeSignals` picks comment/docstring with an
 * if/else, so the two are mutually exclusive and only these six are reachable.
 */
const SIGNAL_FIXTURES: SignalFixture[] = [
  {
    name: 'no signals (production code)',
    ctx: ctxOf('const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' }),
    match: matchAtLine(1),
    signals: [],
  },
  {
    name: 'comment',
    ctx: ctxOf('// const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' }),
    match: matchAtLine(1),
    signals: ['comment'],
  },
  {
    name: 'docstring',
    ctx: ctxOf('"""\nDEBUG = True\n"""', { filePath: 'settings.py', language: 'python' }),
    match: matchAtLine(2),
    signals: ['docstring'],
  },
  {
    name: 'test-path',
    ctx: ctxOf('const x = eval(input);', { filePath: 'src/run.test.js', language: 'javascript' }),
    match: matchAtLine(1),
    signals: ['test-path'],
  },
  {
    name: 'comment + test-path',
    ctx: ctxOf('// const x = eval(input);', { filePath: 'src/run.test.js', language: 'javascript' }),
    match: matchAtLine(1),
    signals: ['comment', 'test-path'],
  },
  {
    name: 'docstring + test-path',
    ctx: ctxOf('"""\nDEBUG = True\n"""', { filePath: 'tests/test_settings.py', language: 'python' }),
    match: matchAtLine(2),
    signals: ['docstring', 'test-path'],
  },
];

function stepsOf(signals: DowngradeSignal[]): number {
  return signals.reduce((sum, s) => sum + EXPECTED_STEPS[s], 0);
}

describe('severity gate — fixtures', () => {
  // Guards every sweep below: if a fixture stopped producing the signals it
  // claims, the properties would still pass while testing nothing.
  it('each fixture really produces the signal set it claims', () => {
    for (const fx of SIGNAL_FIXTURES) {
      expect(detectDowngradeSignals(fx.ctx, fx.match), fx.name).toEqual(fx.signals);
    }
  });

  it('covers every reachable signal subset', () => {
    const seen = SIGNAL_FIXTURES.map((f) => [...f.signals].sort().join('+'));
    expect(new Set(seen).size).toBe(SIGNAL_FIXTURES.length); // no duplicates
    expect(new Set(seen)).toEqual(
      new Set(['', 'comment', 'docstring', 'test-path', 'comment+test-path', 'docstring+test-path']),
    );
  });

  it('SEVERITY_CONFIDENCE_FLOOR decides every severity explicitly', () => {
    expect(SEVERITY_CONFIDENCE_FLOOR).toEqual({
      critical: 'high',
      high: 'high',
      // D1c: was `null`. `medium` is actionable at the default threshold, so a
      // context downgrade must not be able to push it below that.
      medium: 'medium',
      // Deliberately left open: highest FP-reduction value, lowest abuse impact.
      // (`'low'` here would be inert anyway — RANK['low'] === 0.)
      low: null,
      info: null,
    });
    // Total, not partial: a severity added to the schema must not silently
    // default to "ungated".
    for (const severity of ALL_SEVERITIES) {
      expect(Object.hasOwn(SEVERITY_CONFIDENCE_FLOOR, severity), severity).toBe(true);
    }
  });
});

describe('severity gate — properties (base × severity × signals × mode)', () => {
  it('P1: result is never above base — downgrade-only holds for the whole space', () => {
    // THE regression test for the trap. A floor implemented as `max(rank, floor)`
    // without the `min(RANK[base], …)` clamp promotes here, manufacturing exactly
    // the false high-confidence findings the module forbids.
    const violations: string[] = [];
    let checked = 0;
    for (const mode of ALL_MODES) {
      for (const base of ALL_BASES) {
        for (const severity of ALL_SEVERITIES) {
          for (const fx of SIGNAL_FIXTURES) {
            const got = contextConfidence(base, severity, fx.ctx, fx.match, mode);
            checked += 1;
            if (RANK[got] > RANK[base]) {
              violations.push(`${mode} | base=${base} sev=${severity} | ${fx.name} -> ${got}`);
            }
          }
        }
      }
    }
    expect(violations).toEqual([]);
    expect(checked).toBe(ALL_MODES.length * 3 * 5 * SIGNAL_FIXTURES.length);
  });

  it('P2: critical/high take no context downgrade at all (floor high === top rung)', () => {
    const violations: string[] = [];
    for (const base of ALL_BASES) {
      for (const severity of NO_DOWNGRADE_SEVERITIES) {
        for (const fx of SIGNAL_FIXTURES) {
          const got = contextConfidence(base, severity, fx.ctx, fx.match);
          if (got !== base) {
            violations.push(`base=${base} sev=${severity} | ${fx.name} -> ${got}, want ${base}`);
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it('P3: low/info are bit-identical to the un-gated item ① behaviour', () => {
    const violations: string[] = [];
    for (const base of ALL_BASES) {
      for (const severity of UNGATED_SEVERITIES) {
        for (const fx of SIGNAL_FIXTURES) {
          const want = downgradeConfidence(base, stepsOf(fx.signals));
          const got = contextConfidence(base, severity, fx.ctx, fx.match);
          if (got !== want) {
            violations.push(`base=${base} sev=${severity} | ${fx.name} -> ${got}, want ${want}`);
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it('P3b: medium clamps the downgrade at medium — it moves, but never below the threshold', () => {
    // The `medium` floor is the one that is NOT equivalent to "no downgrade":
    // the result is the un-gated value held up at min(base, medium).
    const violations: string[] = [];
    for (const base of ALL_BASES) {
      for (const fx of SIGNAL_FIXTURES) {
        const ungated = downgradeConfidence(base, stepsOf(fx.signals));
        const want =
          RANK[ungated] > Math.min(RANK[base], RANK['medium'])
            ? ungated
            : ALL_BASES[Math.min(RANK[base], RANK['medium'])]!;
        const got = contextConfidence(base, 'medium', fx.ctx, fx.match);
        if (got !== want) {
          violations.push(`base=${base} | ${fx.name} -> ${got}, want ${want}`);
        }
        // The property that motivates D1c: a base at or above medium can never
        // be pushed below medium by context alone.
        if (RANK[base] >= RANK['medium'] && RANK[got] < RANK['medium']) {
          violations.push(`base=${base} | ${fx.name} -> ${got} fell below medium`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it('P4: mode "off" returns base at every severity — it short-circuits before the gate', () => {
    const violations: string[] = [];
    for (const base of ALL_BASES) {
      for (const severity of ALL_SEVERITIES) {
        for (const fx of SIGNAL_FIXTURES) {
          const got = contextConfidence(base, severity, fx.ctx, fx.match, 'off');
          if (got !== base) {
            violations.push(`base=${base} sev=${severity} | ${fx.name} -> ${got}`);
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it('P5: no signals means no change — the floor never promotes an untouched finding', () => {
    const quiet = SIGNAL_FIXTURES.filter((f) => f.signals.length === 0);
    expect(quiet.length).toBeGreaterThan(0);
    const violations: string[] = [];
    for (const base of ALL_BASES) {
      for (const severity of ALL_SEVERITIES) {
        for (const fx of quiet) {
          const got = contextConfidence(base, severity, fx.ctx, fx.match);
          if (got !== base) {
            violations.push(`base=${base} sev=${severity} | ${fx.name} -> ${got}, want ${base}`);
          }
        }
      }
    }
    expect(violations).toEqual([]);
    // Spelled out: a low-confidence critical rule on a clean code line stays low.
    expect(contextConfidence('low', 'critical', quiet[0]!.ctx, quiet[0]!.match)).toBe('low');
  });

  it('contextConfidence is exactly explainContextConfidence(...).confidence', () => {
    const violations: string[] = [];
    for (const mode of ALL_MODES) {
      for (const base of ALL_BASES) {
        for (const severity of ALL_SEVERITIES) {
          for (const fx of SIGNAL_FIXTURES) {
            const wrapper = contextConfidence(base, severity, fx.ctx, fx.match, mode);
            const explained = explainContextConfidence(base, severity, fx.ctx, fx.match, mode);
            if (wrapper !== explained.confidence) {
              violations.push(`${mode} | base=${base} sev=${severity} | ${fx.name}`);
            }
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });
});

describe('severity gate — the promotion trap', () => {
  const testPathCtx = ctxOf('SECRET_KEY = "x"', {
    filePath: 'tests/test_settings.py',
    language: 'python',
  });
  const docstringCtx = ctxOf('"""\nSECRET_KEY = "x"\n"""', {
    filePath: 'settings.py',
    language: 'python',
  });

  it('holds a critical rule\'s "medium" default at medium on a test path — never raises it to high', () => {
    // The exact case the naive reading of "clamp the floor to high" gets wrong.
    // A `critical` rule declaring defaultConfidence 'medium', matched under
    // tests/: `max(RANK[ungated], RANK['high'])` returns HIGH — inventing a
    // high-confidence finding out of a test fixture. The `min(RANK[base], …)`
    // clamp is what keeps this at the rule's own declared confidence.
    const r = explainContextConfidence('medium', 'critical', testPathCtx, matchAtLine(1));
    expect(r.confidence).toBe('medium');
    expect(r.ungated).toBe('low'); // what item ① alone would have produced
    expect(r.floored).toBe(true); // the gate did hold the downgrade back...
    expect(RANK[r.confidence]).toBeLessThanOrEqual(RANK['medium']); // ...without exceeding base
  });

  it('holds a critical rule\'s "medium" default at medium inside a docstring', () => {
    const r = explainContextConfidence('medium', 'critical', docstringCtx, matchAtLine(2));
    expect(r.confidence).toBe('medium');
    expect(r.ungated).toBe('low');
    expect(r.floored).toBe(true);
  });

  it('holds a critical rule\'s "low" default at low — the floor cannot lift it two rungs either', () => {
    const r = explainContextConfidence('low', 'critical', testPathCtx, matchAtLine(1));
    expect(r.confidence).toBe('low');
    expect(r.ungated).toBe('low');
    expect(r.floored).toBe(false); // nothing to hold back: base is already the bottom
  });

  // D1c added a SECOND rung at which the trap can be re-introduced. `medium` is
  // no longer the top of the ladder, so "clamp at medium" written without the
  // `min(RANK[base], …)` would promote a low-confidence medium-severity rule to
  // medium. Same bug, new floor value — pinned here.
  it('holds a medium rule\'s "low" default at low inside a docstring — the new floor does not promote', () => {
    const r = explainContextConfidence('low', 'medium', docstringCtx, matchAtLine(2));
    expect(r.confidence).toBe('low');
    expect(r.ungated).toBe('low');
    expect(r.floored).toBe(false);
  });

  it('holds a medium rule\'s "low" default at low on a test path too', () => {
    const r = explainContextConfidence('low', 'medium', testPathCtx, matchAtLine(1));
    expect(r.confidence).toBe('low');
    expect(r.floored).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// D1c: the `medium` floor. Unlike `high`, this floor is NOT "no downgrade" — it
// bounds the downgrade at the default actionable threshold, so one rung of noise
// reduction survives while the hiding place closes.
// ---------------------------------------------------------------------------
describe('severity gate — the medium floor', () => {
  const docstringCtx = ctxOf('"""\nSECRET_KEY = "x"\n"""', {
    filePath: 'settings.py',
    language: 'python',
  });
  const commentCtx = ctxOf('// const x = eval(input);', {
    filePath: 'src/run.js',
    language: 'javascript',
  });
  const testPathCtx = ctxOf('SECRET_KEY = "x"', {
    filePath: 'tests/test_settings.py',
    language: 'python',
  });

  it('a high-confidence medium finding wrapped in a docstring lands on medium, not low', () => {
    // THE case the b3 corpus exploited: docstring is 2 steps, so item ① alone
    // buries the finding at `low`, below the default threshold. The floor stops
    // it one rung down.
    const r = explainContextConfidence('high', 'medium', docstringCtx, matchAtLine(2));
    expect(r.ungated).toBe('low');
    expect(r.confidence).toBe('medium');
    expect(r.floored).toBe(true);
  });

  it('a medium-confidence medium finding in a comment stays at medium', () => {
    const r = explainContextConfidence('medium', 'medium', commentCtx, matchAtLine(1));
    expect(r.ungated).toBe('low');
    expect(r.confidence).toBe('medium');
    expect(r.floored).toBe(true);
  });

  it('still downgrades high -> medium on a test path — the floor is a bound, not an off switch', () => {
    // One step lands exactly on the clamp, so the downgrade is applied in full
    // and nothing was held back.
    const r = explainContextConfidence('high', 'medium', testPathCtx, matchAtLine(1));
    expect(r.ungated).toBe('medium');
    expect(r.confidence).toBe('medium');
    expect(r.floored).toBe(false);
  });

  it('low and info severities still take the FULL downgrade — deliberately left ungated', () => {
    // Pins the other half of the D1c decision: these bands keep item ①'s
    // behaviour because the FP reduction is worth most and the abuse impact least.
    for (const severity of ['low', 'info'] as const) {
      expect(SEVERITY_CONFIDENCE_FLOOR[severity]).toBeNull();
      const r = explainContextConfidence('high', severity, docstringCtx, matchAtLine(2));
      expect(r.confidence, severity).toBe('low');
      expect(r.floored, severity).toBe(false);
      expect(contextConfidence('high', severity, commentCtx, matchAtLine(1)), severity).toBe('low');
      expect(contextConfidence('high', severity, testPathCtx, matchAtLine(1)), severity).toBe(
        'medium',
      );
    }
  });
});

describe('explainContextConfidence', () => {
  const commentInTestCtx = ctxOf('// secret = "x"', {
    filePath: 'a.test.js',
    language: 'javascript',
  });
  const codeCtx = ctxOf('const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' });
  const commentCtx = ctxOf('// const x = eval(input);', {
    filePath: 'src/run.js',
    language: 'javascript',
  });

  it('reports the ungated value, the signals, and floored=true when the gate changes the outcome', () => {
    const r = explainContextConfidence('high', 'critical', commentInTestCtx, matchAtLine(1));
    expect(r).toEqual({
      confidence: 'high', // gate: a critical finding keeps its confidence...
      ungated: 'low', // ...though comment (-2) + test-path (-1) would have buried it
      signals: ['comment', 'test-path'],
      floored: true,
    });
  });

  it('reports floored=false at an ungated severity, exposing the downgrade itself', () => {
    // severity 'low' — floor null. ('medium' used to serve here; D1c gave it a
    // floor, so it now reports floored=true.)
    const r = explainContextConfidence('high', 'low', commentCtx, matchAtLine(1));
    expect(r).toEqual({
      confidence: 'low',
      ungated: 'low',
      signals: ['comment'],
      floored: false,
    });
  });

  it('reports floored=false when a gated severity had no downgrade to hold back', () => {
    const r = explainContextConfidence('high', 'critical', codeCtx, matchAtLine(1));
    expect(r).toEqual({ confidence: 'high', ungated: 'high', signals: [], floored: false });
  });

  it('reports no signals when mode is off — it short-circuits before detection', () => {
    const r = explainContextConfidence('medium', 'critical', commentInTestCtx, matchAtLine(1), 'off');
    expect(r).toEqual({ confidence: 'medium', ungated: 'medium', signals: [], floored: false });
  });

  it('floored marks exactly the findings the gate rescued (the A/B measurement)', () => {
    // `floored` is a number the A/B harness reports, so pin what it counts.
    // The predicate is stated in terms of SEVERITY_CONFIDENCE_FLOOR rather than a
    // hard-coded severity list: `floored` means the clamp actually bit, i.e. the
    // un-gated value sits BELOW min(base, floor). The old "gated && wouldMove"
    // shorthand only agreed with that while every floor was `high` (top rung,
    // where the clamp swallows any movement); with the `medium` floor of D1c a
    // downgrade can move AND still land on the clamp (`high` + test-path → medium
    // == the clamp, so nothing was held back and floored is false).
    const rescued: string[] = [];
    for (const base of ALL_BASES) {
      for (const severity of ALL_SEVERITIES) {
        for (const fx of SIGNAL_FIXTURES) {
          const r = explainContextConfidence(base, severity, fx.ctx, fx.match);
          const floor = SEVERITY_CONFIDENCE_FLOOR[severity];
          const expected =
            floor != null &&
            RANK[downgradeConfidence(base, stepsOf(fx.signals))] <
              Math.min(RANK[base], RANK[floor]);
          expect(r.floored, `base=${base} sev=${severity} | ${fx.name}`).toBe(expected);
          if (r.floored) rescued.push(`${base}/${severity}/${fx.name}`);
        }
      }
    }
    // 29 = 20 (unchanged, floor 'high') + 9 (new, floor 'medium' from D1c).
    //
    // floor 'high' (critical, high): the clamp is min(base, high) === base, so
    // every base that moves at all is rescued. Bases high & medium move under all
    // 5 signal-bearing fixtures, base low never moves (bottom rung already)
    //   → 2 bases × 5 fixtures × 2 severities = 20.
    //
    // floor 'medium' (severity medium): the clamp is min(base, medium).
    //   base=high  → clamp medium. comment(-2), docstring(-2), comment+test(-3),
    //                docstring+test(-3) all land on low, below the clamp → 4.
    //                test-path(-1) lands exactly ON medium → not floored.
    //   base=medium→ clamp medium. All 5 signal-bearing fixtures reach low → 5.
    //   base=low   → clamp low; nothing can fall below the bottom rung → 0.
    //   → 4 + 5 = 9.
    //
    // low / info keep floor null and contribute 0, which is the point of leaving
    // them open.
    expect(rescued.length).toBe(29);
    expect(rescued.filter((k) => k.includes('/medium/')).length).toBe(9);
  });
});
