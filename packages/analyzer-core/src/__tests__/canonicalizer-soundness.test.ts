// vibeguard:disable-file VG-AUTH-002 VG-CRYPTO-001 VG-INJ-004 VG-SEC-001 VG-SEC-003
// Fixtures embed eval(), AWS-shaped key literals, weak-hash calls and DEBUG
// flags — both plain and in evaded form — because that is exactly what this
// suite has to scan to prove the canonicalizer closes them. They are not real
// vulnerabilities. Same treatment as matcher-utils.test.ts.
//
// VG-CRYPTO-001 was MISSING from this list while `hashlib.md5(` fixtures were
// already in the file, so the self-scan reported two medium findings against
// this suite. They cleared the PR gate (`--fail-on high`) and would therefore
// have shown up in SARIF and the PR comment indefinitely without ever failing a
// build — the quiet failure mode this repo's convention of naming every rule a
// fixture embeds exists to prevent.
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scan } from '../analyzer.js';
import { canonicalize, canonicalizePreprocessor } from '../canonicalizer.js';
import { detectLanguageFromContent, detectLanguageFromPath } from '../language-detect.js';
import type { Finding } from '@vibeguard/findings-schema';

/**
 * H7 — canonicalizer soundness.
 *
 * The claim D2 has to earn is that normalization never COSTS a detection:
 *
 *     D′(x) = D(x) ∪ D(N(x))   ⟹   D′(x) ⊇ D(x)
 *
 * The union in `analyzer.ts` makes that true by construction for every input,
 * so what these tests verify is that the implementation matches the
 * construction — not that the property happens to hold on a corpus. The corpus
 * checks below are the empirical backstop, in two halves:
 *
 *   - SUPERSET, on the bytes as they sit on disk: nothing is ever lost.
 *   - EQUALITY, on LF-normalized bytes: nothing is ever invented. The sample
 *     corpus contains no evasions, so a canonical-only finding there is a
 *     manufactured false positive and fails the build. Normalizing line
 *     endings first excludes a pre-existing CRLF defect that is not D2's —
 *     see the `runRegex` describe block for what it is and why it is separate.
 *
 * The last block pins the RESIDUE — the transforms `N` provably cannot
 * collapse. Those tests assert that evasion still works. They exist so the
 * paper's honesty about residual evasion is checked by CI rather than
 * remembered: when a future layer closes one of them, a test flips loudly
 * instead of the claim quietly going stale.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLES = join(HERE, '..', '..', '..', '..', 'samples');

function key(f: Finding): string {
  return `${f.ruleId}@${f.startLine}:${f.startColumn}`;
}

function scanBoth(content: string, filePath: string) {
  return {
    on: scan({ targetType: 'snippet', mode: 'standard', content, filePath }),
    off: scan({ targetType: 'snippet', mode: 'standard', content, filePath }, { canonicalize: false }),
  };
}

function sampleFiles(dir: string): Array<{ name: string; path: string; content: string }> {
  return readdirSync(join(SAMPLES, dir)).map((name) => {
    const path = join(SAMPLES, dir, name);
    return { name: `${dir}/${name}`, path, content: readFileSync(path, 'utf8') };
  });
}

const CORPUS = [...sampleFiles('vulnerable'), ...sampleFiles('safe'), ...sampleFiles('context-window')];

describe('H7 — canonicalization never costs a finding (corpus)', () => {
  it('has actually loaded a corpus', () => {
    // Guard against the whole suite silently passing on an empty directory.
    expect(CORPUS.length).toBeGreaterThan(15);
  });

  for (const file of CORPUS) {
    it(`${file.name}: no finding is lost (superset)`, () => {
      // The soundness obligation, on the bytes as they sit on disk.
      const { on, off } = scanBoth(file.content, file.path);
      const onKeys = on.findings.map(key);
      for (const k of off.findings.map(key)) expect(onKeys).toContain(k);
    });

    it(`${file.name}: no finding is manufactured (equality)`, () => {
      // Asserted on the bytes as they sit on disk, CRLF included. This used to
      // require LF-normalizing first, to exclude a `runRegex` defect where a
      // `^\s*`-anchored match on CRLF reported the previous line and got
      // dropped by `skipCommentLines` — the canonicalizer then incidentally
      // rescued it, showing up here as a canonical-only finding. That defect is
      // fixed (see the CRLF parity block below), so the confound is gone and
      // the stronger claim holds directly.
      //
      // The sample corpus contains no evasions, so ANY canonical-only finding
      // here is a canonicalizer-manufactured false positive and fails the build.
      const { on, off } = scanBoth(file.content, file.path);
      expect(on.findings.map(key).sort()).toEqual(off.findings.map(key).sort());
    });

    it(`${file.name}: confidence and audit trail are unchanged`, () => {
      // Confidence is always evaluated against the ORIGINAL context, for both
      // passes. If a canonical context ever leaked into
      // `explainContextConfidence`, the docstring/block-comment signals would
      // go blind (their markers having been blanked) and every E6 number would
      // move. This pins that it does not.
      //
      // This is also the check to cite for "D2 does not move confidence" —
      // NOT the E6 harness, which calls `rule.match()` directly and never
      // constructs an Analyzer, so it cannot observe D2 at all.
      const { on, off } = scanBoth(file.content, file.path);
      const byKey = (fs: Finding[]) =>
        Object.fromEntries(fs.map((f) => [key(f), { c: f.confidence, a: f.confidenceAudit }]));
      expect(byKey(on.findings)).toEqual(byKey(off.findings));
    });
  }
});

describe('CRLF parity for `^\\s*` rules (was a silent false negative)', () => {
  // This block used to pin a DEFECT. It now pins its fix, and the flip is the
  // point: when the underlying bug was closed in `runRegex`, the old
  // "is silently lost on CRLF" assertion failed loudly instead of quietly
  // becoming a lie.
  //
  // What it was: `^` under /m treats a lone `\r` as a line terminator, while
  // `indexToPosition` counts lines by `\n` alone. On CRLF input the two
  // disagreed by one line, so a `^\s*`-anchored match reported the PREVIOUS
  // line as its start — and `runRegex({ skipCommentLines })` then deleted the
  // match whenever that previous line was a comment. `VG-FW-001` disappeared
  // from every CRLF settings file, including `samples/vulnerable/
  // django_settings.py`, a fixture explicitly labelled for that rule.
  //
  // The fix anchors a match at its first non-whitespace character, so position
  // and comment test both describe the payload line. Independent of D2: these
  // assertions hold with the canonicalizer OFF.
  const body = (eol: string) => ['import os', '', '# a comment', 'DEBUG = True', ''].join(eol);
  const off = { canonicalize: false };
  const run = (eol: string, opts?: { canonicalize: boolean }) =>
    scan({ targetType: 'snippet', mode: 'standard', content: body(eol), filePath: 'settings.py' }, opts).findings;

  it('fires on LF input', () => {
    expect(run('\n', off).map((f) => f.ruleId)).toContain('VG-FW-001');
  });

  it('fires on CRLF input too, with the canonicalizer off', () => {
    expect(run('\r\n', off).map((f) => f.ruleId)).toContain('VG-FW-001');
  });

  it('reports the same line number for LF and CRLF', () => {
    // The payload is on line 4 in both encodings. Before the fix, CRLF put it
    // on line 3 — which also meant a `disable-line` on line 4 could not
    // suppress it.
    const lf = run('\n', off).find((f) => f.ruleId === 'VG-FW-001');
    const crlf = run('\r\n', off).find((f) => f.ruleId === 'VG-FW-001');
    expect(lf?.startLine).toBe(4);
    expect(crlf?.startLine).toBe(4);
  });

  it('is unaffected by the canonicalizer either way', () => {
    for (const eol of ['\n', '\r\n']) {
      expect(run(eol).map((f) => f.ruleId)).toContain('VG-FW-001');
    }
  });
});

describe('H7 — the two rule families that forbid in-band comment removal', () => {
  // These are the reason `N(x)` is unioned with `x` instead of replacing it.
  // Both would be destroyed by feeding comment-stripped content to the rules.

  it('still detects a secret that lives inside a comment', () => {
    const src = '# api_key = "AKIAAAAAAAAAAAAAAAAA"\n';
    const { on, off } = scanBoth(src, 'config.py');
    expect(off.findings.map((f) => f.ruleId)).toContain('VG-SEC-001');
    expect(on.findings.map((f) => f.ruleId)).toContain('VG-SEC-001');
  });

  it('still fires rules for which the comment IS the signal', () => {
    // VG-AUTH-002 matches on the comment marker itself.
    const src = '// TODO: fix auth before launch\n';
    const { on, off } = scanBoth(src, 'app.js');
    expect(off.findings.map((f) => f.ruleId)).toContain('VG-AUTH-002');
    expect(on.findings.map((f) => f.ruleId)).toContain('VG-AUTH-002');
  });
});

describe('D2 — evasions the canonicalizer closes', () => {
  // Each case: the transform defeats the pre-D2 engine, and the canonicalizer
  // restores the detection. Both halves are asserted, so a test cannot pass by
  // the transform simply failing to evade in the first place.
  const closed: Array<{ what: string; file: string; plain: string; evaded: string }> = [
    {
      what: 'block comment splitting a call',
      file: 'a.js',
      plain: 'eval(userInput);',
      evaded: 'eval/*x*/(userInput);',
    },
    {
      what: 'constant-folded secret (javascript)',
      file: 'a.js',
      plain: 'const k = "AKIAAAAAAAAAAAAAAAAA";',
      evaded: 'const k = "AKIA" + "AAAAAAAAAAAAAAAA";',
    },
    {
      what: 'constant-folded secret (python)',
      file: 'a.py',
      plain: 'k = "AKIAAAAAAAAAAAAAAAAA"',
      evaded: 'k = "AKIA" + "AAAAAAAAAAAAAAAA"',
    },
    {
      what: 'adjacency-folded secret (python)',
      file: 'a.py',
      plain: 'k = "AKIAAAAAAAAAAAAAAAAA"',
      evaded: 'k = "AKIA" "AAAAAAAAAAAAAAAA"',
    },
    {
      what: 'constant-folded secret (php)',
      file: 'a.php',
      plain: '$k = "AKIAAAAAAAAAAAAAAAAA";',
      evaded: '$k = "AKIA" . "AAAAAAAAAAAAAAAA";',
    },
  ];

  for (const c of closed) {
    it(`closes: ${c.what}`, () => {
      const baseline = scan({ targetType: 'snippet', mode: 'standard', content: c.plain, filePath: c.file }).findings.map((f) => f.ruleId);
      expect(baseline.length).toBeGreaterThan(0);

      const evadedOff = scan({ targetType: 'snippet', mode: 'standard', content: c.evaded, filePath: c.file }, { canonicalize: false }).findings.map((f) => f.ruleId);
      const evadedOn = scan({ targetType: 'snippet', mode: 'standard', content: c.evaded, filePath: c.file }).findings.map((f) => f.ruleId);

      for (const ruleId of baseline) {
        expect(evadedOff).not.toContain(ruleId); // the transform really evades
        expect(evadedOn).toContain(ruleId); // and the canonicalizer restores it
      }
    });
  }
});

describe('D2 — residual evasion, pinned deliberately', () => {
  // `N` collapses a DECIDABLE sub-family of transforms. Folding `x + y` needs
  // runtime values; complete normalization of meaning is undecidable. These
  // still evade, and saying so plainly is the honest form of the claim.
  const residual: Array<{ what: string; file: string; evaded: string; ruleId: string }> = [
    {
      what: 'a variable operand (undecidable without runtime values)',
      file: 'a.js',
      evaded: 'const p = "AKIA"; const k = p + "AAAAAAAAAAAAAAAA";',
      ruleId: 'VG-SEC-001',
    },
    {
      what: 'concatenation split across physical lines',
      file: 'a.js',
      evaded: 'const k = "AKIA" +\n  "AAAAAAAAAAAAAAAA";',
      ruleId: 'VG-SEC-001',
    },
  ];

  for (const r of residual) {
    it(`still evades (known residual): ${r.what}`, () => {
      const found = scan({ targetType: 'snippet', mode: 'standard', content: r.evaded, filePath: r.file }).findings.map((f) => f.ruleId);
      expect(found).not.toContain(r.ruleId);
    });
  }
});

describe('D2 — integration invariants', () => {
  it('reports canonical-only findings at ORIGINAL positions', () => {
    const src = 'const k = "AKIA" + "AAAAAAAAAAAAAAAA";';
    const f = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.find((x) => x.ruleId === 'VG-SEC-001');
    expect(f).toBeDefined();
    expect(f!.startLine).toBe(1);
    // The column must point into the real source line, not into canonical space.
    expect(f!.startColumn).toBeGreaterThan(0);
    expect(f!.startColumn).toBeLessThanOrEqual(src.length);
  });

  it('shows the user their own source in the snippet, not the folded form', () => {
    const src = 'const k = "AKIA" + "AAAAAAAAAAAAAAAA";';
    const f = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.find((x) => x.ruleId === 'VG-SEC-001');
    // Masked (it is a secret), but structurally the original expression.
    expect(f!.snippet).toContain('+');
    expect(f!.snippet).not.toContain('"AKIAAAAAAAAAAAAAAAAA"');
  });

  it('suppresses a canonical-only finding via an ordinary line suppression', () => {
    // Suppressions are parsed from the ORIGINAL content and keyed by line
    // number. This works for canonical-only findings only because
    // canonicalization is line-preserving.
    const src = 'const k = "AKIA" + "AAAAAAAAAAAAAAAA"; // vibeguard:disable-line VG-SEC-001\n';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.map((f) => f.ruleId);
    expect(found).not.toContain('VG-SEC-001');
  });

  it('does not report one secret twice when folding shifts the payload left', () => {
    // Regression. Folding rewrites `"-" + "AKIA…"` as `"-AKIA…"` left-aligned
    // in the span, so the canonical match starts at a different column than the
    // original one. Position-equality dedupe misses that and the same secret is
    // reported at both 1:18 and 1:13. Overlap dedupe catches it.
    const src = 'const k = "-" + "AKIAAAAAAAAAAAAAAAAA";';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.filter(
      (f) => f.ruleId === 'VG-SEC-001',
    );
    expect(found).toHaveLength(1);
  });

  it('anchors a canonical-only finding to its payload so suppression works on CRLF', () => {
    // Regression. On CRLF the `^\s*` drift makes the canonical match start on
    // line 1; emitted raw, the finding lands on the wrong line and a
    // disable-line comment on the payload line cannot suppress it.
    const disableLine = ['import os', '', '# a comment', 'DEBUG = True  # vibeguard:disable-line VG-FW-001', ''].join('\r\n');
    expect(
      scan({ targetType: 'snippet', mode: 'standard', content: disableLine, filePath: 'settings.py' }).findings.map((f) => f.ruleId),
    ).not.toContain('VG-FW-001');

    const disableNext = ['import os', '', '# vibeguard:disable-next-line VG-FW-001', 'DEBUG = True', ''].join('\r\n');
    expect(
      scan({ targetType: 'snippet', mode: 'standard', content: disableNext, filePath: 'settings.py' }).findings.map((f) => f.ruleId),
    ).not.toContain('VG-FW-001');
  });

  it('does not emit duplicate findings when both passes agree', () => {
    const src = 'const k = "AKIAAAAAAAAAAAAAAAAA"; // x\n';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.map(key);
    expect(new Set(found).size).toBe(found.length);
  });

  it('does not double-report when blanking a comment lets `^\\s*` reach further back', () => {
    // Regression. `VG-FW-001` anchors with `^\s*` under the `m` flag, and `\s`
    // matches newlines. On the original text the comment line is non-blank and
    // stops the backward scan, so the match starts on the DEBUG line. Once the
    // comment is blanked the whole line is whitespace, so the canonical match
    // starts two lines earlier — the same finding at a different position.
    // Keying the merge on the payload anchor rather than the raw start is what
    // collapses the pair; without it this file reports DEBUG twice.
    const src = 'import os\n\n# DEBUG left on in a settings module.\nDEBUG = True\n';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'settings.py' }).findings.filter(
      (f) => f.ruleId === 'VG-FW-001',
    );
    expect(found).toHaveLength(1);
    // …and the surviving one is the original-pass match, pointing at the real line.
    expect(found[0]!.startLine).toBe(4);
  });
});

/**
 * ★ H7 AUDIT ADDENDUM — the obligations §5.9 / §9.2 name that the blocks above
 * do not actually discharge.
 *
 * Everything up to here is a RELATIVE argument: for each file, D′(x) and D(x)
 * agree. That is the right shape for the soundness claim and it is not enough
 * for the claim the design documents write down. Four gaps, each closed by one
 * describe block below.
 *
 * ★ (a) THE TOTAL IS NEVER STATED. §5.9 words the obligation as
 * "`samples/vulnerable` で正規化前後の真陽性集合が不変＝**E2 の 51 が不変**".
 * Per-file equality delivers the first half and not the second. If a rule
 * silently stopped firing, BOTH faces lose the same finding, every equality
 * above still holds, and this suite stays green while E2 has drifted from 51 to
 * something smaller. The number is currently written down in exactly one place —
 * `declared-veto.test.ts:108` — which reaches the corpus through `scanPath`, a
 * config-driven directory walk, rather than the per-file snippet path used here.
 * Neither file can catch a regression confined to the other's path, and the
 * per-file/aggregate distinction is precisely what a "sum" pin is for. So the
 * totals block states 51 on THIS path, for both faces.
 *
 * ★ (b) NOTHING PROVES THE CORPUS IS DOING WORK. Every equality above passes
 * trivially if `canonicalize` became a no-op on every corpus file — one broken
 * `LANGUAGE_PROFILES` lookup away, and invisible precisely BECAUSE the union is
 * sound by construction: a dead `N` loses nothing, it merely stops adding.
 * `has actually loaded a corpus` counts FILES; it does not check that any of
 * them is normalized, or that either face produces a finding at all. The
 * anti-vacuity block counts the work and names what the corpus does NOT exercise.
 *
 * ★ (c) LINE ENDINGS ARE AN UNCONTROLLED INPUT. There is no `.gitattributes` in
 * this repository, so `samples/vulnerable` and `samples/safe` check out CRLF on a
 * Windows working tree and LF on Linux CI: the blocks above do not scan the same
 * bytes on the two platforms, and a green CI run would say nothing about the
 * developer's. The existing `runRegex` CRLF block is a single synthetic
 * five-line settings file exercising one rule; it was written to pin one bug,
 * not to cover the corpus. The parity block generalises it to every fixture.
 *
 * ★ (d) THE THIRD UNION TERM IS ABSENT. The composition is
 * `D′(x) = D(x) ∪ D(N(x)) ∪ D(N_pp(x))` (canonicalizer.ts), and `CORPUS` holds
 * no c/cpp file, so `N_pp` is never even constructed for it. Two of three faces
 * were under test.
 *
 * ★ AND ONE THING THAT IS NOT MISSING, AND MUST NOT BE "FIXED". §9.2 states the
 * proof obligation as `∀x, findings(N(x)) ⊇ findings(x)` — a claim about the
 * NORMALIZED text. That claim is FALSE for this engine, and the block "the two
 * rule families that forbid in-band comment removal" above is its counterexample.
 * Measured, on `# api_key = "AKIA…"` as python: `D(x) = [VG-SEC-001]`,
 * `D(N(x)) = []`, because `N` blanks the comment the key lives in. What is true
 * is the union form the implementation is actually built on,
 * `D′(x) = D(x) ∪ D(N(x)) ⊇ D(x)`. A property test written to §9.2's letter
 * would fail on a CORRECT engine and would be repaired by making `N` unsound.
 * Recorded here so the next reader of §9.2 does not "fix" the code to match it.
 */

/**
 * LF and CRLF views of a fixture. Both are inputs this repo really produces.
 *
 * A broken `asCrlf` would silently turn every "…, CRLF" assertion below into a
 * second copy of its LF twin — passing, and proving nothing. One guard covers
 * all of them because they all go through this one function: see
 * `the two encodings really are different inputs` in the parity block.
 */
const asLf = (s: string): string => s.replace(/\r\n/g, '\n');
const asCrlf = (s: string): string => asLf(s).replace(/\n/g, '\r\n');
const EOL_VIEWS: ReadonlyArray<readonly [string, (s: string) => string]> = [
  ['LF', asLf],
  ['CRLF', asCrlf],
];

/** The two analyzer faces the blocks above compare, named once. */
const FACES: ReadonlyArray<readonly [string, { canonicalize: boolean } | undefined]> = [
  ['canonicalizer on', undefined],
  ['canonicalizer off', { canonicalize: false }],
];

/**
 * `samples/embedded` — the only c/cpp fixtures in the tree, and therefore the
 * only corpus for which `canonicalizePreprocessor` builds anything. Kept
 * separate from `CORPUS` rather than appended to it: the blocks above assert a
 * finding-for-finding equality that is a statement about the WEB corpus and its
 * measured totals, and silently widening their input would change what those
 * assertions mean without changing what they say.
 */
const EMBEDDED = [...sampleFiles('embedded/vulnerable'), ...sampleFiles('embedded/safe')];

/**
 * The analyzer's own language resolution, replayed. `CORPUS` entries never set
 * `request.language`, so this is the exact question `scan` puts to
 * `canonicalize`. Deriving the language some other way here would test a
 * different `N` than the one that produced the findings compared above.
 */
function languageOf(file: { path: string; content: string }): string | undefined {
  return detectLanguageFromPath(file.path) ?? detectLanguageFromContent(file.content);
}

function scanFile(
  file: { path: string; content: string },
  eol: (s: string) => string = asLf,
  options?: { canonicalize: boolean } | { preprocessorFace: boolean },
): Finding[] {
  return scan(
    { targetType: 'snippet', mode: 'standard', content: eol(file.content), filePath: file.path },
    options,
  ).findings;
}

function totalFindings(
  files: ReadonlyArray<{ path: string; content: string }>,
  eol: (s: string) => string,
  options?: { canonicalize: boolean },
): number {
  return files.reduce((n, f) => n + scanFile(f, eol, options).length, 0);
}

describe('H7 — E2 as an absolute total, not only as an on/off equality', () => {
  /**
   * Measured 2026-08-02 on the per-file snippet path used throughout this file.
   * `vulnerable = 51` is E2 itself; `safe = 0` is E3. `context-window = 9` has no
   * name in the design documents and is pinned for the same reason as the other
   * two: an unnamed number that nothing asserts is a number that can move.
   *
   * These are EXACT, not floors. A floor would absorb the drift this block
   * exists to catch — a rule that stops firing takes the total down, and only an
   * exact pin says so. (`embedded-samples.test.ts` deliberately uses a floor for
   * E7; that test is guarding rule COVERAGE, where a floor is the right tool
   * because adding a rule should not break it. Here the quantity under test is
   * invariance, so the exact number is the whole point.)
   */
  const EXPECTED: ReadonlyArray<readonly [dir: string, files: number, findings: number]> = [
    ['vulnerable', 13, 51],
    ['safe', 4, 0],
    ['context-window', 4, 9],
  ];

  const inDir = (dir: string) => CORPUS.filter((f) => f.name.startsWith(`${dir}/`));

  it('is measuring the corpus these numbers were measured on', () => {
    // Fail-loud, not skip: if a directory emptied or a fixture appeared, the
    // totals below are being asserted about a different corpus and every one of
    // them is meaningless. Say that here rather than letting a moved total be
    // read as a detection regression.
    for (const [dir, files] of EXPECTED) {
      expect(inDir(dir).map((f) => f.name).length, `samples/${dir} file count`).toBe(files);
    }
    expect(CORPUS.length).toBe(EXPECTED.reduce((n, [, files]) => n + files, 0));
  });

  for (const [dir, , findings] of EXPECTED) {
    for (const [faceName, options] of FACES) {
      for (const [eolName, eol] of EOL_VIEWS) {
        it(`samples/${dir} totals exactly ${findings} findings — ${faceName}, ${eolName}`, () => {
          expect(totalFindings(inDir(dir), eol, options)).toBe(findings);
        });
      }
    }
  }

  it('the whole corpus totals the same on both faces and both line endings', () => {
    // The four numbers above are per-directory; this is the sum, which is what
    // would move first if a rule started firing on a file the per-directory
    // arithmetic happens to balance out.
    const totals = FACES.flatMap(([, options]) =>
      EOL_VIEWS.map(([, eol]) => totalFindings(CORPUS, eol, options)),
    );
    expect(totals).toEqual([60, 60, 60, 60]);
  });
});

describe('H7 — the corpus is doing work (anti-vacuity for every equality above)', () => {
  it('N rewrites every single corpus file', () => {
    // The load-bearing anti-vacuity check. Without it, `canonicalize` returning
    // its input for every file — the fail-safe path taken whenever the language
    // is unknown — makes every equality assertion in this file pass while
    // testing nothing at all. That failure is silent by construction: a dead N
    // cannot lose a finding, so `D′ ⊇ D` still holds.
    for (const file of CORPUS) {
      const r = canonicalize(file.content, languageOf(file));
      expect(r.changed, `${file.name} was not normalized at all`).toBe(true);
      expect(r.stats.commentsBlanked, `${file.name} had no comment blanked`).toBeGreaterThan(0);
    }
  });

  it('both faces really produce findings, so "equal" is not "equally empty"', () => {
    // `no finding is lost (superset)` above iterates over the OFF findings, so on
    // a file with none of them its loop body never executes. Four of the 21
    // corpus files are `samples/safe` and vacuous there by design; this pins that
    // the corpus as a whole is not.
    expect(totalFindings(CORPUS, asLf, { canonicalize: false })).toBeGreaterThan(0);
    expect(totalFindings(CORPUS, asLf)).toBeGreaterThan(0);
  });

  /**
   * ★ MEASURED LIMIT — which of `N`'s three operations the corpus exercises.
   *
   * Measured 2026-08-02 over all 21 files: `commentsBlanked` 4790,
   * `whitespaceMapped` 7 (all of them in `vulnerable/weak_random.go`),
   * `foldsApplied` 0.
   *
   * So op (1) is covered everywhere, op (2) rests on ONE file, and op (3) — the
   * constant-folding that the entire evasion story is about — is never invoked
   * by the corpus at all. The corpus equality tests above therefore provide
   * ZERO evidence about folding. That is not a defect in the corpus (the
   * fixtures are frozen and contain no evasions, which is exactly why the
   * "no finding is manufactured" direction is assertable on them at all); it is
   * the reason the synthetic fold traps in the negative-control block below are
   * load-bearing rather than decorative, and the reason they are asserted at the
   * ANALYZER level and not only as `foldsApplied === 0` in canonicalizer.test.ts.
   *
   * Asserted as exact facts rather than as `>= 0`: if a fixture ever gains a
   * folded literal, this test must fail so the fold is reviewed deliberately
   * instead of quietly widening what the equality tests are believed to prove.
   */
  it('op (3) never fires on the corpus, and op (2) fires in exactly one file', () => {
    const withWhitespaceMapped: string[] = [];
    for (const file of CORPUS) {
      const { stats } = canonicalize(file.content, languageOf(file));
      expect(stats.foldsApplied, `${file.name} folded a literal`).toBe(0);
      if (stats.whitespaceMapped > 0) withWhitespaceMapped.push(file.name);
    }
    expect(withWhitespaceMapped).toEqual(['vulnerable/weak_random.go']);
  });
});

describe('H7 — N is a projection at corpus scale, not only on hand-written lines', () => {
  // `canonicalizer.test.ts` proves idempotence and geometry on short strings
  // chosen to hit particular branches. This proves them on the actual files
  // whose findings every comparison above depends on — the inputs where a
  // length or newline drift would move a finding's line silently, since
  // canonical positions are identity-mapped into original space and nothing
  // downstream would notice the translation was wrong.
  for (const [eolName, eol] of EOL_VIEWS) {
    it(`N(N(x)) = N(x) for every corpus file, on ${eolName} input`, () => {
      for (const file of CORPUS) {
        const language = languageOf(file);
        const once = canonicalize(eol(file.content), language).content;
        expect(canonicalize(once, language).content, `${file.name} is not a fixed point`).toBe(once);
      }
    });

    it(`N preserves length and every line-terminator offset, on ${eolName} input`, () => {
      for (const file of CORPUS) {
        const source = eol(file.content);
        const { content } = canonicalize(source, languageOf(file));
        expect(content.length, `${file.name} changed length`).toBe(source.length);
        for (let i = 0; i < source.length; i++) {
          const ch = source[i];
          // Terminators must sit at the SAME offsets, not merely be the same
          // count: an equal count with a moved offset is exactly the failure
          // that puts a finding on the wrong line.
          if (ch === '\n' || ch === '\r') expect(content[i], `${file.name} moved a terminator at ${i}`).toBe(ch);
        }
      }
    });
  }

  it('N_pp is a projection too, over the c/cpp corpus', () => {
    // Never asserted anywhere over real files: preprocessor-face.test.ts checks
    // idempotence on one hand-written `#define`, and this file never reached
    // c/cpp at all.
    for (const file of EMBEDDED) {
      const language = languageOf(file);
      const once = canonicalizePreprocessor(file.content, language);
      expect(once.content.length, `${file.name} changed length`).toBe(file.content.length);
      expect(canonicalizePreprocessor(once.content, language).content, `${file.name} is not a fixed point`).toBe(
        once.content,
      );
    }
  });
});

describe('H7 — line-ending parity at corpus scale', () => {
  const ALL = [...CORPUS, ...EMBEDDED];

  it('the two encodings really are different inputs', () => {
    // Without this the parity assertions below could pass by comparing a file
    // with itself — which is what would happen to any fixture that has no
    // newline, and to all of them if `asCrlf` were ever broken.
    for (const file of ALL) {
      expect(asLf(file.content), `${file.name} has no newline to convert`).toContain('\n');
      expect(asCrlf(file.content)).not.toBe(asLf(file.content));
    }
  });

  for (const [faceName, options] of FACES) {
    it(`every fixture reports identical findings on LF and CRLF — ${faceName}`, () => {
      // This is what makes E2 = 51 a property of the engine rather than of the
      // checkout: with no `.gitattributes`, these files are CRLF in a Windows
      // working tree and LF on CI. Measured identical for all 39 fixtures on
      // both faces, 2026-08-02 — which also means the 51 pinned above is the
      // same 51 on either platform.
      for (const file of ALL) {
        const lf = scanFile(file, asLf, options).map(key).sort();
        const crlf = scanFile(file, asCrlf, options).map(key).sort();
        expect(crlf, `${file.name} disagrees across line endings`).toEqual(lf);
      }
    });
  }
});

describe('H7 — N_pp, the third union term the corpus above never builds', () => {
  it('samples/embedded reports the same findings with the canonicalizer on and off', () => {
    // The soundness obligation, extended to the face that only c/cpp reaches.
    // Both directions, as above: nothing lost, nothing manufactured.
    for (const file of EMBEDDED) {
      const on = scanFile(file).map(key).sort();
      const off = scanFile(file, asLf, { canonicalize: false }).map(key).sort();
      expect(on, `${file.name} moved when normalization was enabled`).toEqual(off);
    }
  });

  it('the embedded totals agree across faces and stay above the E7 floor', () => {
    // Measured 26 on both faces, 2026-08-02. Asserted as agreement plus the
    // floor that `embedded-samples.test.ts` and `security-scan.yml` already own,
    // rather than as a second exact copy of 26: E7 chose a floor deliberately so
    // that adding an embedded rule does not break it, and duplicating the exact
    // number here would quietly revoke that choice from a file that is not about
    // rule coverage.
    const on = totalFindings(EMBEDDED, asLf);
    const off = totalFindings(EMBEDDED, asLf, { canonicalize: false });
    expect(on).toBe(off);
    expect(on).toBeGreaterThanOrEqual(18);
  });

  /**
   * ★ MEASURED LIMIT — `samples/embedded` does not exercise the N_pp-only path.
   *
   * Measured 2026-08-02: scanning the embedded corpus with `preprocessorFace:
   * false` produces the same 26 findings as the default. Every finding in it is
   * already reachable on the base or N faces, so no assertion over this corpus
   * can observe whether N_pp works — only whether it does harm.
   *
   * Pinned as an equality rather than deleted, because the day a fixture lands
   * whose payload is split across an `#ifdef`, this test fails and says so.
   *
   * Verified by mutation, 2026-08-02: forcing `languageHasPreprocessor` to
   * return `false` — i.e. killing N_pp outright — leaves ALL 126 tests in this
   * file green and turns 6 red in `preprocessor-face.test.ts`. So this block
   * pins that N_pp does no HARM to the embedded corpus, and the synthetic
   * directive-split fixture over there ("base + N miss it, N_pp finds it") is
   * the only thing pinning that it does any GOOD. Do not read a green run here
   * as evidence the third face works.
   */
  it('turning the preprocessor face off changes nothing on the embedded corpus', () => {
    for (const file of EMBEDDED) {
      const withPp = scanFile(file).map(key).sort();
      const withoutPp = scanFile(file, asLf, { preprocessorFace: false }).map(key).sort();
      expect(withoutPp, `${file.name} depends on the N_pp face`).toEqual(withPp);
    }
  });
});

/**
 * ★ NEGATIVE CONTROLS — three forms of input that must stay silent.
 *
 * "The canonicalizer fired on the evasion" is half a result. The other half is
 * that it does not fire on things that merely LOOK like evasions, because the
 * cheapest way to pass every positive test in this file would be to fold more
 * aggressively — and each extra fold fabricates a literal the program does not
 * contain. The three forms below are the three ways that could happen, and each
 * one is paired with an input that MUST fire, so a case cannot pass by the
 * payload having become undetectable for some unrelated reason.
 */
describe('H7 — negative controls: three forms of input that must stay silent', () => {
  /** A backslash built by code point, so an escaping slip cannot silently pass. */
  const BS = String.fromCharCode(92);
  /** Split so the trap and its firing counterpart demonstrably share operands. */
  const HEAD = 'AKIA';
  const TAIL = 'AAAAAAAAAAAAAAAA';

  const ids = (content: string, filePath: string, options?: { canonicalize: boolean }): string[] =>
    scan({ targetType: 'snippet', mode: 'standard', content, filePath }, options).findings.map((f) => f.ruleId);

  // ★ Form 1 — real clean code, at corpus scale, on every face.
  //
  // Distinct from the `samples/safe totals 0` assertion above, which is a sum:
  // this is per FILE and per FACE, so it names the file that broke instead of
  // reporting that some total moved. All four `samples/safe` fixtures are
  // rewritten by N (op (1) fires on every one of them — see the anti-vacuity
  // block), so this is normalization running on clean code and staying quiet,
  // not normalization declining to run.
  it('form 1: every samples/safe fixture stays at zero findings on all three faces', () => {
    for (const file of CORPUS.filter((f) => f.name.startsWith('safe/'))) {
      expect(scanFile(file, asLf, { canonicalize: false }), `${file.name} base face`).toEqual([]);
      expect(scanFile(file, asLf, { preprocessorFace: false }), `${file.name} N face`).toEqual([]);
      expect(scanFile(file), `${file.name} full union`).toEqual([]);
    }
  });

  /**
   * ★ Form 2 — constructs that look like a foldable run and are not.
   *
   * `silent` and `fires` use the SAME two operands; only the syntax joining them
   * differs. So a case cannot pass because the operands stopped being
   * key-shaped, and the `fires` half additionally asserts the payload is
   * canonical-ONLY (absent with the canonicalizer off), which proves the
   * detection is the fold and not something the base face was finding anyway.
   */
  interface FoldTrap {
    what: string;
    file: string;
    silent: string;
    /** Present when the trap depends on a character an escaping slip could eat. */
    mustContain?: string;
    /** The genuinely-concatenating counterpart, in `firesFile` when it differs. */
    firesFile?: string;
    fires: string;
  }

  const FOLD_TRAPS: readonly FoldTrap[] = [
    {
      what: 'two arguments, not one expression',
      file: 'a.js',
      silent: `f("${HEAD}", "${TAIL}");`,
      fires: `const k = "${HEAD}" + "${TAIL}";`,
    },
    {
      what: 'mixed delimiters',
      file: 'a.js',
      silent: `const k = "${HEAD}" + '${TAIL}';`,
      fires: `const k = "${HEAD}" + "${TAIL}";`,
    },
    {
      // ★ MEASURED LIMIT, kept on the record because the first version of this
      // trap was UNFALSIFIABLE and read as the strongest case in the list.
      //
      // It was `"AKIA\t" + "…16 A's"`, and no folding of it can ever fire:
      // `VG-SEC-001` is `/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g` (secrets.ts) with no
      // `i` flag, so whether a folder kept the backslash, interpreted it to a
      // TAB, or dropped it and left a lowercase `t`, the character after `AKIA`
      // failed `[0-9A-Z]` and the assertion could not fail. Worse, the
      // `mustContain` guard added to protect it pinned the very byte that made
      // it vacuous.
      //
      // The escape is now `\x41`, which INTERPRETS TO `A`. That is what makes
      // the trap load-bearing: a canonicalizer that both interpreted escapes
      // and folded the concatenation would produce `AKIA` + `A` + fifteen more
      // `A`s — byte-for-byte the `fires` string below — so this case now fails
      // exactly when the property it names is violated.
      what: 'an escape sequence folding would have to interpret',
      file: 'a.js',
      silent: `const k = "${HEAD}${BS}x41" + "${TAIL.slice(1)}";`,
      mustContain: `${BS}x41`,
      fires: `const k = "${HEAD}" + "${TAIL}";`,
    },
    {
      what: 'template literals are not constants',
      file: 'a.js',
      silent: `const k = \`${HEAD}\` + \`${TAIL}\`;`,
      mustContain: '`',
      fires: `const k = "${HEAD}" + "${TAIL}";`,
    },
    {
      // Identical bytes, opposite verdicts, decided only by the language: JS
      // adjacency is a syntax error, python adjacency is concatenation.
      what: 'adjacency, which concatenates in python but is not javascript at all',
      file: 'a.js',
      silent: `const k = "${HEAD}" "${TAIL}";`,
      firesFile: 'a.py',
      fires: `k = "${HEAD}" "${TAIL}"`,
    },
    {
      what: 'php + is numeric coercion, never concatenation',
      file: 'a.php',
      silent: `$k = "${HEAD}" + "${TAIL}";`,
      fires: `$k = "${HEAD}" . "${TAIL}";`,
    },
    {
      what: 'C + on string literals is pointer arithmetic',
      file: 'a.c',
      silent: `char *k = "${HEAD}" + "${TAIL}";`,
      fires: `char *k = "${HEAD}" "${TAIL}";`,
    },
    {
      what: 'a python f-string prefix changes how the literal is interpreted',
      file: 'a.py',
      silent: `k = f"${HEAD}" + "${TAIL}"`,
      fires: `k = "${HEAD}" + "${TAIL}"`,
    },
  ];

  for (const trap of FOLD_TRAPS) {
    it(`form 2: manufactures no secret from ${trap.what}`, () => {
      if (trap.mustContain !== undefined) {
        // Guards the guard: an escaping slip turns the trap into an ordinary
        // foldable run, and the silence below would then be a real defect
        // reported as a pass.
        expect(trap.silent).toContain(trap.mustContain);
      }
      expect(ids(trap.silent, trap.file)).not.toContain('VG-SEC-001');
      expect(ids(trap.silent, trap.file, { canonicalize: false })).not.toContain('VG-SEC-001');

      // The paired real concatenation, with the same operands: canonical-only,
      // so the silence above is the refusal to fold and not an inert payload.
      const firesFile = trap.firesFile ?? trap.file;
      expect(ids(trap.fires, firesFile, { canonicalize: false })).not.toContain('VG-SEC-001');
      expect(ids(trap.fires, firesFile)).toContain('VG-SEC-001');
    });
  }

  /**
   * ★ Form 3 — a payload that exists only inside a comment.
   *
   * Blanking a comment can go wrong in BOTH directions, and this form pins both.
   * The false-negative direction is the reason `N` is unioned rather than
   * substituted (see the `VG-SEC-001`-in-a-comment block above); the
   * false-positive direction is subtler — blanking a line turns it entirely to
   * whitespace, which lets a `^\s*`-anchored rule scan backwards through it and
   * claim text it could not previously reach. Both are stated as
   * "the verdict is the one the base face gives", which is the only formulation
   * that catches a change in either direction with one assertion.
   */
  const COMMENT_CASES: ReadonlyArray<{ what: string; file: string; src: string; expected: string[] }> = [
    {
      // `runRegex({ skipCommentLines })` already drops it; N must not resurrect it.
      what: 'a line-commented eval call stays silent',
      file: 'a.js',
      src: '// eval(userInput)\nconst a = 1;\n',
      expected: [],
    },
    {
      // …whereas a BLOCK comment is not skipped by that mechanism, so this one
      // is reported. Blanking it must not silence it either — that would be D2
      // causing a false negative, the failure mode the union exists to make
      // impossible.
      //
      // ★ MEASURED, because the first version of this comment asserted the
      // finding was "down-ranked by confidence, not suppressed" and that is
      // false for the case pinned here. Measured on this exact input:
      //
      //   /* eval(userInput) */   (one line)  → confidence `high`, and
      //                                          `confidenceAudit` is ABSENT —
      //                                          no down-rank was even attempted
      //   /*\n eval(userInput)\n*/ (multi)    → `{signals:['docstring'],
      //                                          ungated:'low', floored:true}`
      //
      // So the single-line form never reaches the docstring signal, and the
      // multi-line form does reach it but has its downgrade REFUSED by the
      // severity floor (D1). Neither is "down-ranked". What this case actually
      // pins is narrower and still worth pinning: whatever the base face
      // decides, normalization does not change it. The confidence question
      // belongs to item ① and is measured in its own suite, not here.
      what: 'a block-commented eval call stays reported',
      file: 'a.js',
      src: '/* eval(userInput) */\nconst a = 1;\n',
      expected: ['VG-INJ-004'],
    },
    {
      // The `^\s*` backward-scan case, as a negative: after blanking, lines 2-3
      // are pure whitespace, so `VG-FW-001`'s anchor can reach back from `X = 1`.
      // Nothing on that line is a DEBUG flag, so nothing may be reported.
      what: 'a commented-out DEBUG flag does not become a live one',
      file: 'settings.py',
      src: 'import os\n\n# DEBUG = True\nX = 1\n',
      expected: [],
    },
    {
      what: 'a commented-out weak hash stays silent',
      file: 'a.py',
      src: '# h = hashlib.md5(p)\nx = 1\n',
      expected: [],
    },
  ];

  for (const c of COMMENT_CASES) {
    it(`form 3: ${c.what}, identically on every face`, () => {
      expect(ids(c.src, c.file, { canonicalize: false }).sort()).toEqual(c.expected);
      expect(ids(c.src, c.file).sort()).toEqual(c.expected);
    });
  }

  it('form 3 is not vacuous: the same payloads fire once the comment marker is gone', () => {
    // Without this, every silent case above would also pass against an engine
    // that had lost the rule entirely.
    expect(ids('eval(userInput);\nconst a = 1;\n', 'a.js')).toContain('VG-INJ-004');
    expect(ids('import os\n\nDEBUG = True\nX = 1\n', 'settings.py')).toContain('VG-FW-001');
    expect(ids('h = hashlib.md5(p)\nx = 1\n', 'a.py')).toContain('VG-CRYPTO-001');
  });
});
