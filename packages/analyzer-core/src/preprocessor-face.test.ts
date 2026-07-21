// vibeguard:disable-file VG-SEC-001 VG-SEC-003
// This test uses a literal AKIA… key and a `password = "…"` assignment as
// fixtures for the directive-secret detection tests; they are not real secrets.
import { describe, expect, it } from 'vitest';
import { canonicalize, canonicalizePreprocessor } from './canonicalizer.js';
import { Analyzer } from './analyzer.js';
import { allRules, type RuleDefinition } from '@vibeguard/rules';

// VG-EMB 17c EMB-LANG — the N_pp preprocessor arm (third union face for C/C++).
//
// Two layers of test: the canonicalizer unit (geometry + what gets blanked),
// and the analyzer union (that D(N_pp(x)) actually ADDS the finding a
// directive-split payload would otherwise hide, and that the merge dedups it).

/** Indices of every `\n` and `\r`, the geometry that must never move. */
function terminatorOffsets(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) if (s[i] === '\n' || s[i] === '\r') out.push(i);
  return out;
}

describe('canonicalizePreprocessor — geometry contract', () => {
  it('preserves length and every newline/CR offset', () => {
    const src = 'WiFi.begin("ssid",\r\n#ifdef PROD\r\n    PROD_PW);\r\n#endif\r\n';
    const out = canonicalizePreprocessor(src, 'cpp');
    expect(out.content.length).toBe(src.length);
    expect(terminatorOffsets(out.content)).toEqual(terminatorOffsets(src));
  });

  it('is idempotent', () => {
    const src = '#define DEBUG 1\nint x = strcpy(a, b); // c\n#include "h.h"\n';
    const once = canonicalizePreprocessor(src, 'cpp').content;
    const twice = canonicalizePreprocessor(once, 'cpp').content;
    expect(twice).toBe(once);
  });

  it('blanks a `\\`-continued #define across both physical lines, CR intact', () => {
    const src = '#define WIDE(a) \\\r\n    danger(a)\r\nok();\r\n';
    const out = canonicalizePreprocessor(src, 'cpp').content;
    // Both directive lines are whitespace; `ok();` and all terminators survive.
    expect(out).not.toContain('danger');
    expect(out).not.toContain('#define');
    expect(out).toContain('ok();');
    expect(terminatorOffsets(out)).toEqual(terminatorOffsets(src));
  });
});

describe('canonicalizePreprocessor — what is and is not a directive', () => {
  it('blanks a directive even with a space after `#`', () => {
    const out = canonicalizePreprocessor('# if X\nkeep;\n', 'cpp');
    expect(out.content).not.toContain('if X');
    expect(out.content).toContain('keep;');
  });

  it('does NOT blank a line whose `#` is not a directive keyword', () => {
    // `#pragma`-like but bogus keyword: `#notADirective` must survive so it can
    // still be matched by D(x); keyword-anchoring is what protects a `#` line
    // inside a raw string, too.
    const src = '#notADirective here\ncode;\n';
    const out = canonicalizePreprocessor(src, 'cpp');
    expect(out.content).toContain('#notADirective');
  });

  it('is a no-op (changed:false) for a non-preprocessor language', () => {
    const src = '#define X 1\nconst y = 1;\n';
    const out = canonicalizePreprocessor(src, 'javascript');
    expect(out.changed).toBe(false);
    expect(out.content).toBe(src);
  });

  it('collapses to exactly the N face when there are no directives', () => {
    // No directive ⇒ N_pp = N. The analyzer relies on this to skip a redundant
    // third pass (ppCtx guard: `pp.content !== canonical.content`).
    const src = 'int x = 1; // trailing comment\n';
    expect(canonicalizePreprocessor(src, 'cpp').content).toBe(canonicalize(src, 'cpp').content);
  });
});

describe('canonicalizePreprocessor — Arduino syntax is not corrupted', () => {
  it('leaves F("secret") byte-identical through both N and N_pp', () => {
    const src = 'const char* k = F("secret");\n';
    // No comment, no directive, no fold ⇒ nothing to normalize.
    expect(canonicalize(src, 'cpp').content).toBe(src);
    expect(canonicalizePreprocessor(src, 'cpp').content).toBe(src);
  });

  it('adjacency-folds a split literal inside F() in the N face (helps 17e)', () => {
    // F("se" "cret") → F("secret"): C++ adjacent-string concatenation, same
    // line, so #17e hardcoded-key detection sees the joined literal for free.
    const out = canonicalize('F("se" "cret")', 'cpp');
    expect(out.content).toContain('"secret"');
    expect(out.stats.foldsApplied).toBe(1);
  });

  it('leaves PROGMEM / ISR / raw-string lines untouched (no directive, no comment)', () => {
    const src = 'const char s[] PROGMEM = "x";\nISR(TIMER1_OVF_vect) { t++; }\nauto r = R"(abc)";\n';
    expect(canonicalize(src, 'cpp').content).toBe(src);
    expect(canonicalizePreprocessor(src, 'cpp').content).toBe(src);
  });

  it('does not throw on a multi-line raw string containing comment-like text', () => {
    const src = 'auto r = R"(\n// not a comment\n#not a directive\n)";\nreal();\n';
    // Added-face corruption is acceptable; a throw or a geometry break is not.
    expect(() => canonicalizePreprocessor(src, 'cpp')).not.toThrow();
    const out = canonicalizePreprocessor(src, 'cpp').content;
    expect(out.length).toBe(src.length);
    expect(terminatorOffsets(out)).toEqual(terminatorOffsets(src));
  });
});

// ---- analyzer-level union behaviour, with an injected rule ------------------

/** Matches a two-arg call whose args are string literals, allowing only
 *  whitespace between the tokens — so a directive line BETWEEN the args blocks
 *  the match unless the directive has been blanked to whitespace (N_pp). */
const CALL_SHAPE: RuleDefinition = {
  ruleId: 'VG-TEST-PP',
  name: 'test call-shape rule',
  description: 'test',
  languages: ['cpp'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  match: (ctx) => {
    const re = /DANGER\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\)/g;
    const matches = [];
    let m: RegExpExecArray | null;
    // Emit REAL (non-degenerate) line/column ranges, exactly as runRegex does
    // for shipped rules. A zero-width range (start == end) would never overlap
    // in `mergeCanonicalMatches` (strict `<`), so the base∪N∪pp dedup would
    // silently double-count — the very thing the three-face test must prove
    // does NOT happen. Since directive-blanking is length-preserving, a payload
    // sitting after a blanked directive keeps its absolute offset, so the base
    // and pp matches share an identical span and dedup correctly.
    const posOf = (idx: number): { line: number; col: number } => {
      const nl = ctx.content.lastIndexOf('\n', idx - 1);
      return { line: ctx.content.slice(0, idx).split('\n').length, col: idx - nl };
    };
    while ((m = re.exec(ctx.content)) !== null) {
      const s = posOf(m.index);
      const e = posOf(m.index + m[0].length);
      matches.push({
        startLine: s.line,
        endLine: e.line,
        startColumn: s.col,
        endColumn: e.col,
        evidence: m[0],
      });
    }
    return matches;
  },
};

function countPp(content: string, opts?: { preprocessorFace?: boolean; canonicalize?: boolean }) {
  const r = new Analyzer({ rules: [CALL_SHAPE], ...opts }).scan({
    targetType: 'snippet',
    content,
    mode: 'standard',
    filePath: 'sketch.ino',
  });
  return r.findings.filter((f) => f.ruleId === 'VG-TEST-PP');
}

describe('analyzer union — N_pp adds a directive-split finding', () => {
  // First-branch payload is contiguous with the call once the #ifdef is blanked.
  const FIRST_BRANCH = 'DANGER("ssid",\n#ifdef PROD\n"secret");\n#endif\n';

  it('base + N miss it, N_pp finds it', () => {
    // Without the preprocessor face, the directive line breaks the whitespace
    // run and neither D(x) nor D(N(x)) matches.
    expect(countPp(FIRST_BRANCH, { preprocessorFace: false })).toHaveLength(0);
    // With it, exactly one finding — the union deduped it to a single hit.
    expect(countPp(FIRST_BRANCH)).toHaveLength(1);
  });

  it('turning canonicalize off disables N_pp too', () => {
    expect(countPp(FIRST_BRANCH, { canonicalize: false })).toHaveLength(0);
  });

  it('a payload matched on both the base and N_pp faces is reported once', () => {
    // NON-VACUOUS dedup exercise: a directive ELSEWHERE in the file makes the
    // pp face differ from both the original and the N face, so the third pass
    // actually runs — and the payload (directive-free itself) matches on the
    // base face AND the pp face at the SAME offset. The merge must collapse the
    // two into one finding. A degenerate zero-width range would report two.
    const withDistantDirective = '#define UNUSED 1\nDANGER("a", "b");\n';
    expect(countPp(withDistantDirective)).toHaveLength(1);
  });

  it('the plain single-payload case reports once (base face only)', () => {
    // No directive, no comment ⇒ N and N_pp both collapse to the original, so
    // only the base pass runs. Kept as a floor alongside the dedup case above.
    expect(countPp('DANGER("ssid", "secret");\n')).toHaveLength(1);
  });

  it('does NOT surface a payload reachable only through the #else branch', () => {
    // Documented residual: blanking directives makes only the FIRST branch
    // contiguous with the call. The second arg here lives in #else, still
    // separated from the call by the first branch's text, so it is not matched.
    const elseBranch = 'DANGER("ssid",\n#ifdef PROD\nPROD_PW);\n#else\n"secret");\n#endif\n';
    expect(countPp(elseBranch)).toHaveLength(0);
  });
});

describe('analyzer union — robustness of the third pass', () => {
  it('a rule that throws only on the preprocessor face keeps base findings', () => {
    let call = 0;
    const throwsOnPp: RuleDefinition = {
      ruleId: 'VG-TEST-PP-THROW',
      name: 'throws on pp',
      description: 'test',
      languages: ['cpp'],
      category: 'injection',
      severity: 'high',
      defaultConfidence: 'medium',
      match: (ctx) => {
        call += 1;
        // The pp face is the pass whose text differs from the original by having
        // the directive blanked; throw only there.
        if (!ctx.content.includes('#define')) throw new Error('boom on pp face');
        return [
          { startLine: 1, endLine: 1, startColumn: 1, endColumn: 1, evidence: '#define X' },
        ];
      },
    };
    const r = new Analyzer({ rules: [throwsOnPp] }).scan({
      targetType: 'snippet',
      content: '#define X 1\nint y = 2;\n',
      mode: 'standard',
      filePath: 'a.cpp',
    });
    // Base pass produced its finding; the pp-face throw is recorded, not fatal.
    expect(r.findings.some((f) => f.ruleId === 'VG-TEST-PP-THROW')).toBe(true);
    expect(r.ruleErrors?.some((e) => e.ruleId === 'VG-TEST-PP-THROW')).toBe(true);
  });
});

// ---- consequences of opening the language (intended, but pinned) -----------

function scanReal(content: string, filePath: string) {
  return new Analyzer({ rules: allRules }).scan({
    targetType: 'snippet',
    content,
    mode: 'standard',
    filePath,
  });
}

describe('opening .ino to cpp — intended finding-direction changes', () => {
  it('detects a secret hardcoded in a #define directive (base face, real rules)', () => {
    // `#` is NOT a comment in cpp, so the directive line is scanned by D(x) and
    // VG-SEC-001 fires. N_pp blanks the directive on its own face, but the base
    // face keeps it, so the secret is never lost — the union only adds.
    const r = scanReal('#define AWS_KEY "AKIAIOSFODNN7EXAMPLE"\n', 'sketch.ino');
    expect(r.findings.some((f) => f.ruleId === 'VG-SEC-001')).toBe(true);
  });

  it('comment-skips a //-commented secret exactly as .cpp does (parity, not a bug)', () => {
    // A behaviour change ONLY relative to the old unknown-extension fail-safe:
    // when the extension was unknown, the empty comment-spec meant nothing was
    // comment-skipped, so VG-SEC-003 fired even inside a `//` comment. Now .ino
    // resolves to cpp and honours cpp comments, so it is skipped — identically
    // to a real .cpp file. #17e will add comment-skip-free embedded-secret rules
    // to recover keys that live in comments; until then this parity is intended.
    const src = '// password = "AAAAAAAAAAAAAAAAAAAAAAAA"\n';
    const ino = scanReal(src, 'a.ino').findings.length;
    const cpp = scanReal(src, 'a.cpp').findings.length;
    expect(ino).toBe(cpp);
  });
});

describe('N_pp documented residuals (added-face only; base face never affected)', () => {
  it('may destroy a raw-string closer on a directive-keyword line (N_pp face)', () => {
    // A raw string whose closing line begins with a directive keyword gets that
    // line blanked on the N_pp face, desyncing the string scan for the pp face
    // only. This is an added-face residual: D(x) and D(N(x)) are untouched, so
    // no base detection is lost — it can at worst fail to ADD one. Pinned so the
    // behaviour is on the record rather than discovered later.
    const src = 'auto s = R"(\n#endif)";\nreal();\n';
    expect(() => canonicalizePreprocessor(src, 'cpp')).not.toThrow();
    // Geometry still holds even when the interior is mis-lexed.
    const out = canonicalizePreprocessor(src, 'cpp').content;
    expect(out.length).toBe(src.length);
  });

  it('blanks a whole CR-only (classic-Mac) file when it opens with a directive', () => {
    // With only `\r` terminators the pp scan sees one physical line; a leading
    // directive blanks the lot. Harmless: the pp face becomes all-whitespace and
    // simply ADDS nothing (the base and N faces, which see the real content, are
    // untouched). Length/CR geometry is still preserved.
    const src = '#define X 1\rcode();\rmore();';
    const out = canonicalizePreprocessor(src, 'cpp').content;
    expect(out.length).toBe(src.length);
    expect(out).not.toContain('code()');
    // Every `\r` survives.
    expect([...out].filter((c) => c === '\r').length).toBe([...src].filter((c) => c === '\r').length);
  });
});
