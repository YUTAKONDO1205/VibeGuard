import { describe, expect, it } from 'vitest';
import { canonicalize } from './canonicalizer.js';

/**
 * Unit and property tests for `N` itself. The soundness obligation — that
 * canonicalization never costs a finding — lives in
 * `__tests__/canonicalizer-soundness.test.ts`, because it needs the analyzer.
 */

/** Every offset a canonicalized string must still agree with the original on. */
function newlineOffsets(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) if (s[i] === '\n') out.push(i);
  return out;
}

function expectGeometryPreserved(input: string, language: string | undefined): string {
  const { content } = canonicalize(input, language);
  expect(content.length).toBe(input.length);
  expect(newlineOffsets(content)).toEqual(newlineOffsets(input));
  return content;
}

const LANGUAGES = [
  'javascript', 'typescript', 'python', 'ruby', 'go', 'java', 'kotlin', 'csharp',
  'php', 'rust', 'swift', 'c', 'cpp', 'shell', 'yaml', 'json', 'toml', 'sql', 'html',
];

describe('canonicalize — geometry (the contract every consumer relies on)', () => {
  // Positions flow untranslated from canonical space into findings, snippets
  // and suppression lookups. If length or newline offsets ever drift, every
  // one of those silently points at the wrong place.
  const samples = [
    'eval/*x*/(payload)',
    'a = "ev" + "al"\nb = 2\n',
    '# comment\n\n\ncode()\n',
    '/* multi\n   line\n   comment */ code()',
    'x = "unterminated\ny = 1',
    '/* unterminated to EOF',
    'no trailing newline',
    '\r\nwindows\r\nline\r\nendings\r\n',
    '',
    '\n\n\n',
    'const e = "😀" + "🎉";',
  ];

  for (const language of LANGUAGES) {
    it(`preserves length and newline offsets for ${language}`, () => {
      for (const s of samples) expectGeometryPreserved(s, language);
    });
  }

  it('preserves geometry for unknown and absent languages', () => {
    for (const s of samples) {
      expectGeometryPreserved(s, undefined);
      expectGeometryPreserved(s, 'no-such-language');
    }
  });

  it('keeps astral-plane characters intact rather than splitting surrogates', () => {
    // `content[i]` indexes UTF-16 units, so the output buffer must too.
    // Building it code-point-wise would desynchronise every offset after the
    // first emoji.
    const input = 'const e = "😀"; // 🎉 comment';
    const out = expectGeometryPreserved(input, 'javascript');
    expect(out).toContain('"😀"');
  });
});

describe('canonicalize — projection properties', () => {
  const cases: Array<[string, string]> = [
    ['javascript', 'eval/*x*/("a" + "b") // trailing'],
    ['python', 'k = "AKIA" + "BBBB"  # note'],
    ['php', '$a = "ev" . "al"; # note'],
    ['go', 's := "ev" + "al" /* c */'],
  ];

  it('is idempotent — N(N(x)) = N(x), i.e. N really is a projection', () => {
    for (const [language, src] of cases) {
      const once = canonicalize(src, language).content;
      const twice = canonicalize(once, language).content;
      expect(twice).toBe(once);
    }
  });

  it('is deterministic', () => {
    for (const [language, src] of cases) {
      expect(canonicalize(src, language)).toEqual(canonicalize(src, language));
    }
  });

  it('reports `changed` honestly', () => {
    expect(canonicalize('const a = 1;', 'javascript').changed).toBe(false);
    expect(canonicalize('const a = 1; // x', 'javascript').changed).toBe(true);
  });
});

describe('canonicalize — fail-safe on unknown languages', () => {
  // Same asymmetry as LINE_COMMENT_SPECS: when we cannot tell code from string
  // from comment, doing nothing is the only sound option. Blanking would
  // destroy text, and mapping whitespace inside an unrecognised string literal
  // would change the program.
  it('is a no-op when the language is unknown, absent, or unmodelled', () => {
    const src = 'eval/*x*/(p) # c\nk = "ev" + "al"';
    for (const language of [undefined, 'no-such-language', 'html']) {
      const r = canonicalize(src, language);
      expect(r.content).toBe(src);
      expect(r.changed).toBe(false);
      expect(r.stats).toEqual({ commentsBlanked: 0, whitespaceMapped: 0, foldsApplied: 0 });
    }
  });

  it('does not crash or inherit prototype members for hostile language names', () => {
    // `getLineCommentSpec` guards this with Object.hasOwn; the profile lookup
    // here needs the same property or a `__proto__` language would resolve to
    // an inherited value and blow up inside the scan.
    for (const language of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(() => canonicalize('# x\nk = "a" + "b"', language)).not.toThrow();
      expect(canonicalize('# x', language).content).toBe('# x');
    }
  });
});

describe('canonicalize — op (1) comment removal, per the shared allowlist', () => {
  it('blanks line comments without moving the newline', () => {
    expect(canonicalize('a() # gone\nb()', 'python').content).toBe('a()       \nb()');
  });

  it('blanks block comments only where they are really comment syntax', () => {
    expect(canonicalize('eval/*x*/(p)', 'javascript').content).toBe('eval     (p)');
    // python has no /* */ — blanking it would destroy real code.
    expect(canonicalize('a = 1 /* not a comment */', 'python').changed).toBe(false);
  });

  it('blanks an unterminated block comment through end of input', () => {
    expect(canonicalize('a() /* x', 'javascript').content).toBe('a()     ');
  });

  // The four concealment vectors D1b closed. A private comment model in the
  // canonicalizer would reopen every one of them.
  it('does not treat // as a comment in python', () => {
    expect(canonicalize('y = 1 // 2', 'python').changed).toBe(false);
  });

  it('does not treat # as a comment in html', () => {
    // NB: html has no profile at all, so this is really the fail-safe path —
    // canonicalize returns before any comment logic runs. Asserted on the
    // stats rather than on `changed` so the test says what it actually
    // proves: nothing was blanked, for whichever of the two reasons.
    const r = canonicalize('<a id="#x"># not a comment', 'html');
    expect(r.changed).toBe(false);
    expect(r.stats.commentsBlanked).toBe(0);
  });

  // The languages below DO have profiles, so these exercise the guard itself
  // rather than the missing-profile shortcut.
  it('requires # to start a word in shell/yaml/toml', () => {
    // `${PATH#/usr}` is parameter expansion and `x#frag` is a URL fragment.
    // Blanking either destroys the rest of the line, including any payload.
    expect(canonicalize('echo ${PATH#/usr} && curl http://h/x#frag\n', 'shell').changed).toBe(false);
    expect(canonicalize('a: b#notcomment\n', 'yaml').changed).toBe(false);
    // A genuine comment is still removed. Expectation built from the input so
    // it states the rule ("the comment becomes spaces") rather than a hand
    // counted run of blanks.
    const shell = 'echo hi # real\n';
    expect(canonicalize(shell, 'shell').content).toBe(shell.replace('# real', ' '.repeat('# real'.length)));
  });

  it('still treats # as a comment anywhere in python/ruby/php', () => {
    // These languages really do open a comment mid-token, so the guard above
    // must not be applied to them.
    expect(canonicalize('x = 1#c\n', 'python').content).toBe('x = 1  \n');
    expect(canonicalize('x = 1#c\n', 'ruby').content).toBe('x = 1  \n');
  });

  it('requires whitespace after -- in sql', () => {
    // MySQL needs the space; `a--b` is `a - (-b)`, executable arithmetic.
    expect(canonicalize('SELECT a--b FROM t\n', 'sql').changed).toBe(false);
    const sql = 'SELECT 1 -- real\n';
    expect(canonicalize(sql, 'sql').content).toBe(sql.replace('-- real', ' '.repeat('-- real'.length)));
  });

  it('treats Go backtick literals as raw, so a trailing backslash cannot eat the file', () => {
    // In Go `` `C:\` `` is a complete raw string. Honouring the backslash as an
    // escape consumes the closing backtick and the scan runs to EOF, silently
    // disabling canonicalization for everything after it.
    const out = canonicalize('p := `C:\\`\nkey := "AKIA" + "SECRET"\n', 'go');
    expect(out.stats.foldsApplied).toBe(1);
    expect(out.content).toContain('"AKIASECRET"');
  });

  it('does not blank a PHP 8 attribute', () => {
    expect(canonicalize('#[Route("/admin")]', 'php').changed).toBe(false);
    // ...while a real PHP `#` comment still goes.
    expect(canonicalize('$a = 1; # gone', 'php').content).toBe('$a = 1;       ');
  });

  it('does not treat comment syntax inside a string literal as a comment', () => {
    const src = 'const s = "keep # this // intact";';
    expect(canonicalize(src, 'javascript').changed).toBe(false);
  });

  it('leaves python docstrings alone — a docstring is a value, not a comment', () => {
    // Payloads hidden in a docstring are a concealment problem for the
    // severity gate (D1), not a normalization problem.
    const src = 'def f():\n    """not a comment # / * """\n    pass\n';
    expect(canonicalize(src, 'python').changed).toBe(false);
  });
});

describe('canonicalize — op (2) whitespace normalization', () => {
  it('maps exotic whitespace in code to a plain space, one for one', () => {
    const src = 'a =　1';
    const out = canonicalize(src, 'javascript');
    expect(out.content).toBe('a = 1');
    expect(out.stats.whitespaceMapped).toBe(2);
  });

  it('never collapses runs and never touches newlines', () => {
    const src = 'a\t\t\t=\t1\n\n\nb = 2';
    const out = canonicalize(src, 'javascript').content;
    expect(out).toBe('a   = 1\n\n\nb = 2');
  });

  it('does not touch whitespace inside a string literal', () => {
    // "a\tb" and "a b" are different values; mapping here would not preserve
    // semantics.
    const src = 'const s = "a b";';
    expect(canonicalize(src, 'javascript').changed).toBe(false);
  });

  it('leaves zero-width characters alone', () => {
    // `eval‌` is a DIFFERENT identifier, not an obfuscation of `eval`.
    // Deleting the joiner would not be a semantics-preserving projection.
    const src = 'const a = 1;​';
    expect(canonicalize(src, 'javascript').changed).toBe(false);
  });
});

describe('canonicalize — op (3) constant-only folding', () => {
  it('folds same-delimiter constant runs with the language operator', () => {
    expect(canonicalize('k = "ev" + "al"', 'javascript').content).toBe('k = "eval"     ');
    expect(canonicalize('$k = "ev" . "al";', 'php').content).toBe('$k = "eval"     ;');
  });

  it('folds runs of more than two literals', () => {
    const out = canonicalize('k = "e" + "v" + "a" + "l"', 'javascript').content;
    expect(out).toContain('"eval"');
    expect(out.length).toBe('k = "e" + "v" + "a" + "l"'.length);
  });

  it('never folds character literals as if they were strings', () => {
    // `'e' + 'v'` is 101 + 118 = 219 in these languages, not "ev". Folding it
    // would put a literal in the canonical text that the program never had —
    // the one way this pass could manufacture a finding out of arithmetic.
    for (const language of ['java', 'csharp', 'kotlin', 'go', 'c', 'cpp', 'rust', 'swift']) {
      expect(canonicalize("char c = 'e' + 'v';", language).stats.foldsApplied).toBe(0);
    }
    // Languages where `'…'` really is a string still fold.
    for (const language of ['javascript', 'python', 'ruby', 'php']) {
      const src = language === 'php' ? "$c = 'e' . 'v';" : "c = 'e' + 'v'";
      expect(canonicalize(src, language).stats.foldsApplied).toBe(1);
    }
  });

  it('refuses to fold across a line terminator, including a lone CR', () => {
    // The line counter advances only on `\n`, so a lone `\r` between operands
    // slips past the same-line guard. Writing the merged literal through it
    // would delete a terminator — the one thing `blank` never does.
    const src = 'const a = "ev"\r+\r"al";';
    const out = canonicalize(src, 'javascript');
    expect(out.content).toBe(src);
    expect((out.content.match(/\r/g) ?? []).length).toBe(2);
  });

  it('folds adjacency only in languages that concatenate that way', () => {
    expect(canonicalize('x = "ev" "al"', 'python').content).toContain('"eval"');
    // JS adjacency is a syntax error, not concatenation — folding would invent
    // a program the author did not write.
    expect(canonicalize('x = "ev" "al"', 'javascript').changed).toBe(false);
  });

  it('folds across a blanked comment between the operands', () => {
    expect(canonicalize('k = "ev" /* x */ + "al"', 'javascript').content).toContain('"eval"');
  });

  // Every rejection below is deliberate: an unfolded evasion is an honest
  // residual, whereas a wrong fold fabricates or destroys findings.
  const rejected: Array<[string, string, string]> = [
    ['javascript', 'k = `ev` + `al`', 'template literals are not constants'],
    ['python', 'k = f"ev" + "al"', 'f-string prefix changes interpretation'],
    ['python', 'k = r"ev" + "al"', 'raw-string prefix'],
    ['python', 'k = b"ev" + "al"', 'bytes prefix'],
    ['javascript', 'k = "ev" + \'al\'', 'mixed delimiters'],
    ['javascript', 'k = "e\\tv" + "al"', 'escape sequence needs real unescaping'],
    ['javascript', 'f("ev", "al")', 'two arguments, not one expression'],
    ['javascript', 'k = "ev" + x + "al"', 'a variable operand is undecidable'],
    ['javascript', 'k = "ev" +\n  "al"', 'multi-line run has no single span to pad'],
    ['php', '$k = "ev" + "al";', 'PHP + is numeric coercion, not concatenation'],
    ['c', 'k = "ev" + "al";', 'C + on literals is pointer arithmetic'],
    ['rust', 'let k = "ev" + "al";', '&str + &str does not compile'],
    ['sql', "k = 'ev' || 'al'", 'SQL || left as residual'],
  ];

  for (const [language, src, why] of rejected) {
    it(`refuses to fold: ${why} (${language})`, () => {
      expect(canonicalize(src, language).stats.foldsApplied).toBe(0);
    });
  }

  it('always leaves the folded literal shorter than the span it replaces', () => {
    // k >= 2 literals spend 2k characters on delimiters; the result spends 2.
    // If this ever stopped holding, folding would overrun into the next token.
    for (const src of ['a="x"+"y"', 'a = "xxxx" + "yyyy" + "zzzz"', 'a="x" "y"']) {
      for (const language of ['javascript', 'python']) {
        expectGeometryPreserved(src, language);
      }
    }
  });
});
