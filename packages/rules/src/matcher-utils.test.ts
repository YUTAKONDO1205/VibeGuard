// vibeguard:disable-file
// Fixtures embed eval()/SQL literals to exercise the comment-line predicate;
// they are not real vulnerabilities.
import { describe, expect, it } from 'vitest';
import {
  getLineCommentSpec,
  hasLineCommentSpec,
  isCommentLine,
  type KnownLanguage,
  lineCommentStartsAt,
  runRegex,
  captureRegexBoundaries,
  REGEX_INPUT_CAP,
} from './matcher-utils.js';

/**
 * `LINE_COMMENT_SPECS` is deliberately not exported (callers must go through
 * `getLineCommentSpec` so the unknown-language fallback cannot be bypassed), so
 * the language list lives here instead. `satisfies Record<KnownLanguage, true>`
 * makes it exhaustive at compile time: adding a language to `KnownLanguage`
 * without listing it here is a type error, and the specs below then have to be
 * stated for it.
 */
const ALL_LANGUAGE_KEYS = {
  javascript: true,
  typescript: true,
  python: true,
  ruby: true,
  go: true,
  java: true,
  kotlin: true,
  csharp: true,
  php: true,
  rust: true,
  swift: true,
  c: true,
  cpp: true,
  shell: true,
  yaml: true,
  json: true,
  toml: true,
  sql: true,
  html: true,
} satisfies Record<KnownLanguage, true>;

const ALL_LANGUAGES = Object.keys(ALL_LANGUAGE_KEYS) as KnownLanguage[];

/** Languages whose allowlist entry has no `#` prefix, so `#` is live syntax. */
const HASH_IS_NOT_COMMENT: readonly KnownLanguage[] = [
  'javascript',
  'typescript',
  'java',
  'go',
  'kotlin',
  'csharp',
  'swift',
  'c',
  'cpp',
  'rust',
  'json',
];

/** VG-SEC-003's pattern, verbatim (rules/secrets.ts). */
const SECRET_PATTERN =
  /\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']/gi;

/** VG-AUTH-004's first pattern, verbatim (rules/auth.ts). */
const VERIFY_FALSE_PATTERN = /verify\s*=\s*False\b/g;

describe('isCommentLine', () => {
  it('treats a leading // as a comment only where // is comment syntax', () => {
    expect(isCommentLine('// x', 'javascript')).toBe(true);
    expect(isCommentLine('  // x', 'go')).toBe(true);
    // Python's `//` is floor division, not a comment (hiding vector 1).
    expect(isCommentLine('// x', 'python')).toBe(false);
    // Unknown language: nothing is a comment (hiding vector 4).
    expect(isCommentLine('// x', undefined)).toBe(false);
  });

  it('does not treat a leading # as a comment where # is real syntax', () => {
    // ES2022 private class field — executed code, not a comment.
    expect(isCommentLine('#x = 1', 'javascript')).toBe(false);
    expect(isCommentLine('  #q = (s) => eval(s);', 'typescript')).toBe(false);
    // Preprocessor / attribute / directive syntax, one realistic form per family.
    expect(isCommentLine('#define DB_PASSWORD "hunter2"', 'c')).toBe(false);
    expect(isCommentLine('#include <stdio.h>', 'cpp')).toBe(false);
    expect(isCommentLine('#[derive(Debug)]', 'rust')).toBe(false);
    expect(isCommentLine('#if DEBUG', 'swift')).toBe(false);
    expect(isCommentLine('#x = 1', 'kotlin')).toBe(false);
  });

  it('treats a leading # as a comment where # starts a comment', () => {
    expect(isCommentLine('#x = 1', 'python')).toBe(true);
    expect(isCommentLine('# eval(x)', 'ruby')).toBe(true);
    expect(isCommentLine('  # comment', 'php')).toBe(true);
  });

  it('unknown language treats nothing as a comment (fail-safe)', () => {
    // The allowlist has no entry, so no syntax opens a comment and no match is
    // dropped. Failing this way costs at worst a false positive on a line that
    // really was a comment; the old blocklist's "# is a comment" fallback let an
    // unrecognised extension erase findings before anything could see them.
    expect(isCommentLine('#x = 1', undefined)).toBe(false);
    expect(isCommentLine('// x', undefined)).toBe(false);
    expect(isCommentLine('-- x', undefined)).toBe(false);
    expect(isCommentLine('#x = 1', 'no-such-language')).toBe(false);
  });

  it('classifies # as non-comment in every language whose spec has no # prefix', () => {
    for (const language of HASH_IS_NOT_COMMENT) {
      // Guard the list above against drifting from the real map.
      expect(getLineCommentSpec(language).prefixes).not.toContain('#');
      expect(isCommentLine('#x = 1', language)).toBe(false);
      // `//` stays a comment in those languages regardless.
      expect(isCommentLine('// x = 1', language)).toBe(true);
    }
  });

  it('does not treat code with a trailing comment as a comment line', () => {
    expect(isCommentLine('const x = 1; // note', 'javascript')).toBe(false);
    expect(isCommentLine('x = 1  # note', 'python')).toBe(false);
  });

  it('treats both # and -- as comments in sql, but not //', () => {
    expect(isCommentLine('-- x', 'sql')).toBe(true);
    expect(isCommentLine('# x', 'sql')).toBe(true);
    expect(isCommentLine('// x', 'sql')).toBe(false);
    // KNOWN RESIDUAL GAP, fixed here as current behaviour rather than repaired:
    // MySQL requires whitespace after `--` for it to open a comment, so
    // `--payload` is executed code. The `--` test is a naive `startsWith`, so we
    // classify it as a comment and drop its match — a silent false negative.
    // Deliberately out of scope for this change; do not "fix" without also
    // deciding what other dialects (Postgres, SQLite) expect from bare `--`.
    expect(isCommentLine('--payload', 'sql')).toBe(true);
  });

  it('treats nothing as a comment in html', () => {
    // HTML's only comment syntax is the multi-line `<!-- -->`, which this
    // line-oriented predicate does not model (a known limitation, unchanged).
    // `//` and `#` inside an HTML file are live syntax: a protocol-relative URL,
    // a CSS id selector, a private field in an inline <script>.
    expect(isCommentLine('// x', 'html')).toBe(false);
    expect(isCommentLine('# x', 'html')).toBe(false);
  });
});

describe('line-comment allowlist', () => {
  it('has an explicit entry for every known language', () => {
    for (const language of ALL_LANGUAGES) {
      expect(hasLineCommentSpec(language)).toBe(true);
    }
  });

  it('falls back to the empty spec for unknown or absent languages', () => {
    expect(hasLineCommentSpec(undefined)).toBe(false);
    expect(hasLineCommentSpec('no-such-language')).toBe(false);
    expect(getLineCommentSpec(undefined)).toEqual({ prefixes: [], exclusions: [] });
    // html is an explicit entry that looks identical to the fallback; the two
    // are told apart by reference, not by structure.
    expect(getLineCommentSpec('html')).toEqual({ prefixes: [], exclusions: [] });
    expect(hasLineCommentSpec('html')).toBe(true);
  });

  it('returns the empty spec for prototype-chain keys, not an inherited value', () => {
    // A caller-supplied `language` of `__proto__`/`constructor`/`toString` must
    // not resolve to an inherited object: that has no `prefixes`, so
    // `lineCommentStartsAt` would throw, and inside `rule.match` the analyzer's
    // per-rule try/catch swallows it — silently dropping the rule's findings,
    // the exact undeclared-suppression channel the allowlist exists to close.
    for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(hasLineCommentSpec(key)).toBe(false);
      expect(getLineCommentSpec(key)).toEqual({ prefixes: [], exclusions: [] });
      // Must not throw — this is the crash the guard prevents.
      expect(() => lineCommentStartsAt('# x', 0, getLineCommentSpec(key))).not.toThrow();
    }
  });

  it('never uses an empty-string prefix', () => {
    // `''.startsWith('')` is true, so an empty prefix would classify every line
    // in that language as a comment and silently drop all of its findings.
    for (const language of ALL_LANGUAGES) {
      expect(getLineCommentSpec(language).prefixes).not.toContain('');
    }
  });

  it('only excludes tokens that some prefix would otherwise match', () => {
    // An exclusion that starts with no prefix could never fire — it would be
    // dead config hiding a typo (e.g. `['#[']` under a spec that lost its `#`).
    for (const language of ALL_LANGUAGES) {
      const { prefixes, exclusions } = getLineCommentSpec(language);
      for (const exclusion of exclusions) {
        expect(prefixes.some((p) => exclusion.startsWith(p))).toBe(true);
      }
    }
  });
});

describe('runRegex({ skipCommentLines, language })', () => {
  it('keeps a match on an ES2022 private field line when language is given', () => {
    const content = 'class C {\n  #q = (s) => eval(s);\n}';
    const matches = runRegex(content, /(?<![.\w])eval\s*\(/g, {
      skipCommentLines: true,
      language: 'javascript',
    });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(2);
  });

  it('keeps the match when no language is given (fail-safe)', () => {
    const content = 'class C {\n  #q = (s) => eval(s);\n}';
    const matches = runRegex(content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(2);
  });

  it('still skips a real Python # comment', () => {
    const content = '# eval(x)\ny = 1';
    expect(
      runRegex(content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true, language: 'python' }),
    ).toEqual([]);
  });

  it('keeps a secret on a C preprocessor line (VG-SEC-003 pattern)', () => {
    // `#define` is executed syntax, so the secret is live — dropping it would be
    // a silent false negative on a severity=high rule. VG-SEC-003's own pattern,
    // verbatim: it needs a `:`/`=`, so `#define token = "…"` is the reachable
    // shape (`#define TOKEN "…"` never matches it, with or without this fix).
    const pattern =
      /\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']/gi;
    const content = '#define token = "s3cr3tValue0123456789abc"';
    expect(runRegex(content, pattern, { skipCommentLines: true, language: 'c' }).length).toBe(1);
    // Same text in a language where # really is a comment stays skipped.
    expect(runRegex(content, pattern, { skipCommentLines: true, language: 'python' })).toEqual([]);
  });

  it('still skips a // comment when a language is given', () => {
    const content = '// eval(x)\nconst y = 1;';
    expect(
      runRegex(content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true, language: 'javascript' }),
    ).toEqual([]);
  });

  it('ignores language when skipCommentLines is not set', () => {
    const content = '# eval(x)';
    expect(runRegex(content, /(?<![.\w])eval\s*\(/g, { language: 'python' }).length).toBe(1);
  });
});

/**
 * The four concealment vectors this allowlist exists to close, each fixed at
 * both levels: the classifier (`isCommentLine`) and the drop it drives
 * (`runRegex({ skipCommentLines })`).
 *
 * These matter more than an ordinary false negative. `skipCommentLines` DELETES
 * the match upstream of the analyzer's confidence chokepoint, so the severity
 * gate never sees it and cannot bound the mistake. Under the old blocklist each
 * vector let an attacker erase a high-severity finding with a line of ordinary,
 * declaration-free source — no suppression comment, nothing to audit.
 */
describe('comment-classifier concealment vectors (regression)', () => {
  it('vector 1: a Python // continuation line is code, not a comment', () => {
    expect(isCommentLine('// 2', 'python')).toBe(false);
    expect(isCommentLine('    // b', 'python')).toBe(false);

    // Floor division inside a parenthesised call: the continuation line really
    // can start with `//`, so `verify=False` (VG-AUTH-004, severity=high) rode
    // out on a line the old classifier called a comment.
    const content = 'resp = requests.get(url, timeout=(total\n    // 2), verify=False)';
    const matches = runRegex(content, VERIFY_FALSE_PATTERN, {
      skipCommentLines: true,
      language: 'python',
    });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(2);
  });

  it('vector 2: # in an HTML inline <script> is a private field, not a comment', () => {
    expect(isCommentLine('#priv = eval(s)', 'html')).toBe(false);

    const content =
      '<script>\nclass Client {\n  #token = "s3cr3tValue0123456789abc";\n}\n</script>';
    const matches = runRegex(content, SECRET_PATTERN, {
      skipCommentLines: true,
      language: 'html',
    });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(3);
  });

  it('vector 3: a PHP 8 #[Attribute] is executed syntax, not a comment', () => {
    expect(isCommentLine('#[Route("/x", token: "s3cr3tValue0123456789abc")]', 'php')).toBe(false);
    // PHP's other comment syntax is untouched by the `#[` exclusion.
    expect(isCommentLine('# comment', 'php')).toBe(true);
    expect(isCommentLine('// x', 'php')).toBe(true);
    // The space means it does not start with `#[`, so this stays a comment.
    expect(isCommentLine('# [x]', 'php')).toBe(true);

    const content = '#[Route("/x", token: "s3cr3tValue0123456789abc")]\nfunction x() {}';
    const matches = runRegex(content, SECRET_PATTERN, { skipCommentLines: true, language: 'php' });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(1);
    // Contrast: the same literal behind a genuine PHP `#` comment is still skipped.
    expect(
      runRegex('# token: "s3cr3tValue0123456789abc"', SECRET_PATTERN, {
        skipCommentLines: true,
        language: 'php',
      }),
    ).toEqual([]);
  });

  it('vector 4: # under an unknown extension does not hide a secret', () => {
    expect(isCommentLine('#token = "s3cr3tValue0123456789abc"', undefined)).toBe(false);

    // An unrecognised extension leaves ctx.language undefined. VG-SEC-003 runs
    // on every language (`languages: ['*']`), so the old `#` fallback made
    // renaming a file enough to erase the finding.
    const content = '#token = "s3cr3tValue0123456789abc"';
    const matches = runRegex(content, SECRET_PATTERN, { skipCommentLines: true });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(1);
    // Same via an explicitly unknown language string, not just an absent one.
    expect(
      runRegex(content, SECRET_PATTERN, { skipCommentLines: true, language: 'no-such-language' })
        .length,
    ).toBe(1);
  });
});

/**
 * Match anchoring — `runRegex` resolves a match's position from its first
 * non-whitespace character.
 *
 * These live here, in the package that owns `runRegex`, on purpose. The
 * behaviour is also covered end-to-end from analyzer-core, but a refactor of
 * this function has to fail in ITS OWN package's suite, not only downstream.
 *
 * The bug this closes was a silent false negative. Many rules open with `^\s*`
 * under the `m` flag and `\s` matches line terminators, so a match routinely
 * begins on the blank tail of an earlier line. `^` additionally treats a lone
 * `\r` as a line terminator while `indexToPosition` counts lines by `\n` alone,
 * so CRLF input disagreed by a whole line — and `skipCommentLines` then looked
 * up that wrong line and DELETED the match when it happened to be a comment.
 */
describe('runRegex — match anchoring (LF/CRLF parity)', () => {
  const DEBUG_PATTERN = () => /^\s*DEBUG\s*=\s*True\b/gm;
  const body = (eol: string) => ['import os', '', '# a comment', 'DEBUG = True', ''].join(eol);

  it('reports the payload line, not the line the pattern started on', () => {
    for (const eol of ['\n', '\r\n']) {
      const matches = runRegex(body(eol), DEBUG_PATTERN());
      expect(matches).toHaveLength(1);
      expect(matches[0]!.startLine).toBe(4);
      expect(matches[0]!.startColumn).toBe(1);
    }
  });

  it('does not drop the match when the PREVIOUS line is a comment', () => {
    // The regression itself. Before anchoring, the CRLF case returned [].
    for (const eol of ['\n', '\r\n']) {
      const matches = runRegex(body(eol), DEBUG_PATTERN(), {
        skipCommentLines: true,
        language: 'python',
      });
      expect(matches).toHaveLength(1);
      expect(matches[0]!.startLine).toBe(4);
    }
  });

  it('still drops a match whose OWN line is a comment', () => {
    // Anchoring must not weaken skipCommentLines — it only redirects it at the
    // right line. Here the payload really is inside the comment.
    const content = '# DEBUG = True\n';
    expect(runRegex(content, /DEBUG\s*=\s*True\b/gm, { skipCommentLines: true, language: 'python' })).toEqual([]);
  });

  it('trims leading whitespace off the evidence and keeps named groups', () => {
    const content = 'a\n   KEY = "v"\n';
    const matches = runRegex(content, /^\s*(?<name>KEY)\s*=\s*"(?<val>[^"]*)"/gm);
    expect(matches).toHaveLength(1);
    // Evidence starts at the payload, so `confidence.ts:inspectedLine` finds
    // firstNonWs === 0 and its own correction becomes a no-op rather than
    // double-applying.
    expect(matches[0]!.evidence.startsWith('KEY')).toBe(true);
    expect(matches[0]!.variables).toEqual({ name: 'KEY', val: 'v' });
  });

  it('leaves an all-whitespace match untouched', () => {
    // No payload to anchor to; position and evidence stay as found.
    const matches = runRegex('a\n   \nb', /^[ \t]+$/gm);
    expect(matches).toHaveLength(1);
    expect(matches[0]!.evidence).toBe('   ');
    expect(matches[0]!.startLine).toBe(2);
  });

  it('terminates on a zero-length match, including on a skipped comment line', () => {
    // Both the skip branch and the push branch must advance lastIndex, or the
    // scan spins forever.
    expect(runRegex('# c\nx\n', /(?:)/g, { skipCommentLines: true, language: 'python' }).length).toBeGreaterThan(0);
    expect(runRegex('ab', /(?:)/g).length).toBeGreaterThan(0);
  });

  it('never reports a start position after its end position', () => {
    const content = 'x\n\n  foo(\n    bar)\n';
    for (const m of runRegex(content, /^\s*foo\([^)]*\)/gm)) {
      expect(m.startLine).toBeLessThanOrEqual(m.endLine);
      if (m.startLine === m.endLine) expect(m.startColumn!).toBeLessThanOrEqual(m.endColumn!);
    }
  });
});

/**
 * D3 — the ReDoS bounds.
 *
 * The property that matters most is the NEGATIVE one: on every input a real
 * scan sees, none of these bounds does anything. A bound that fires on ordinary
 * files is not a guard, it is a silent false-negative generator, so
 * "transparent below the cap" is tested before anything else and is also
 * asserted over the whole regression corpus in analyzer-core.
 */
describe('runRegex — D3 bounds', () => {
  it('is completely transparent below the input cap', () => {
    const content = `${'const a = 1;\n'.repeat(1000)}eval(x)\n`;
    expect(content.length).toBeLessThan(REGEX_INPUT_CAP);
    const { result, events } = captureRegexBoundaries(() => runRegex(content, /eval\(/g));
    expect(result).toHaveLength(1);
    expect(events).toEqual([]);
  });

  it('truncates rather than skips oversized input, keeping the findings it did reach', () => {
    // A match inside the cap and a match beyond it. Skipping the file would lose
    // both; truncating keeps the first, which is the whole point of the choice.
    const head = 'eval(early)\n';
    const filler = 'x'.repeat(REGEX_INPUT_CAP);
    const content = `${head}${filler}eval(late)\n`;
    const { result, events } = captureRegexBoundaries(() => runRegex(content, /eval\((\w+)\)/g));

    expect(result).toHaveLength(1);
    expect(result[0]!.evidence).toBe('eval(early)');
    const truncation = events.find((e) => e.kind === 'truncated');
    expect(truncation).toBeDefined();
    expect(truncation!.inputLength).toBe(content.length);
  });

  it('reports truncation even when the truncated prefix matches nothing', () => {
    // The dangerous case: no findings AND no signal reads as "this file is
    // clean". The event is what stops that reading.
    const content = 'x'.repeat(REGEX_INPUT_CAP + 1);
    const { result, events } = captureRegexBoundaries(() => runRegex(content, /eval\(/g));
    expect(result).toEqual([]);
    expect(events.map((e) => e.kind)).toContain('truncated');
  });

  it('positions matches identically whether or not truncation occurred', () => {
    // Truncation must not shift line/column, or a finding's location would
    // depend on the size of the file it sits in.
    const prefix = 'a\nb\neval(x)\n';
    const short = runRegex(prefix, /eval\(x\)/g);
    const long = runRegex(`${prefix}${'z'.repeat(REGEX_INPUT_CAP)}`, /eval\(x\)/g);
    expect(long).toHaveLength(1);
    expect(long[0]!.startLine).toBe(short[0]!.startLine);
    expect(long[0]!.startColumn).toBe(short[0]!.startColumn);
  });

  it('is deterministic across repeated runs on the same oversized input', () => {
    // The bound that decides the RESULT is length-based, so repeating the scan
    // must not wobble. If the deadline ever became load-bearing this would flake
    // — that is the intended alarm.
    const content = `${'eval(a)\n'.repeat(50)}${'q'.repeat(REGEX_INPUT_CAP)}eval(b)\n`;
    const runs = Array.from({ length: 5 }, () => runRegex(content, /eval\((\w+)\)/g));
    for (const r of runs) expect(r).toEqual(runs[0]);
  });

  it('does not run a further exec once the match limit is reached', () => {
    // The old code tested the limit after exec had already returned, so hitting
    // the limit still cost one more unbounded search. Counting exec calls is the
    // only way to observe the difference; the returned matches look the same.
    const content = 'eval(x)\n'.repeat(20);
    let execCalls = 0;
    const pattern = /eval\(x\)/g;
    const nativeExec = RegExp.prototype.exec;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (pattern as any).exec = function counted(this: RegExp, s: string) {
      execCalls += 1;
      return nativeExec.call(this, s);
    };
    const matches = runRegex(content, pattern, { limit: 5 });
    expect(matches).toHaveLength(5);
    expect(execCalls).toBe(5);
  });

  it('reports the match limit through the same channel as the new bounds', () => {
    const content = 'eval(x)\n'.repeat(20);
    const { events } = captureRegexBoundaries(() => runRegex(content, /eval\(x\)/g, { limit: 3 }));
    expect(events.map((e) => e.kind)).toContain('limitReached');
  });

  it('collects nothing when no capture is active, and restores the previous sink', () => {
    // A leaked sink would attribute one scan's bounds to the next one's report.
    const oversized = 'x'.repeat(REGEX_INPUT_CAP + 1);
    expect(() => runRegex(oversized, /nope/g)).not.toThrow();

    const outer = captureRegexBoundaries(() => {
      const inner = captureRegexBoundaries(() => runRegex(oversized, /nope/g));
      expect(inner.events.map((e) => e.kind)).toContain('truncated');
      return 'ok';
    });
    expect(outer.result).toBe('ok');
    expect(outer.events).toEqual([]);
  });

  it('restores the sink when the captured function throws', () => {
    expect(() =>
      captureRegexBoundaries(() => {
        throw new Error('rule blew up');
      }),
    ).toThrow('rule blew up');
    // If the sink had leaked, this capture would see the events of the next call
    // made outside any capture.
    const after = captureRegexBoundaries(() => runRegex('x', /x/g));
    expect(after.events).toEqual([]);
  });

  it('fires the scan-wide deadline across many small runRegex calls', () => {
    // Regression for the dead-code deadline: `execCount` used to be a per-call
    // local, so `execCount % 256` never fired for the common case of a rule with
    // few matches, and the scan-wide budget did nothing. The counter now persists
    // across calls, so a budget exhausted by MANY cheap calls is still enforced.
    const content = `${'eval(x)\n'.repeat(400_000)}`; // > cap, many matches
    const pattern = /eval\(x\)/g;
    const { events } = captureRegexBoundaries(
      () => runRegex(content, pattern, { limit: 10_000_000 }),
      { deadlineMs: 5 },
    );
    expect(events.map((e) => e.kind)).toContain('timedOut');
  });

  it('does not fire the deadline on an input that finishes in time', () => {
    const { events } = captureRegexBoundaries(
      () => runRegex('eval(x)\n'.repeat(50), /eval\(x\)/g),
      { deadlineMs: 2_000 },
    );
    expect(events.map((e) => e.kind)).not.toContain('timedOut');
  });

  it('bounds a quadratic pattern by bounding its input', () => {
    // The measured shape from scripts/sec-a1-catalog.mjs: recheck classified the
    // super-linear shipped rules as polynomial degree 2, so T ∝ n² and capping n
    // caps T. This asserts the mechanism, not a wall-clock number — a timing
    // threshold here would flake on a loaded CI box.
    const pattern = /["'][^"'\n]*\b(?:FROM)\s+(\w+)[^"'\n]*["']\s*[+]\s*\w/g;
    const attack = `"${'FROM x '.repeat(80_000)}`;
    expect(attack.length).toBeGreaterThan(REGEX_INPUT_CAP);
    const { events } = captureRegexBoundaries(() => runRegex(attack, pattern));
    expect(events.map((e) => e.kind)).toContain('truncated');
  });
});
