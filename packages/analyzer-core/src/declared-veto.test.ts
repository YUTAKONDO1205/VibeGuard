// vibeguard:disable-file VG-AISC-001 VG-INJ-004 reason="fixtures are inert strings, not code this repo runs"
// This file's fixtures are deliberately-misspelled package names — they are the
// input the declared-package veto exists to argue about. One fixture also
// carries an `eval(input)` substring, because the veto must be shown to leave
// findings from OTHER rules alone while it removes VG-AISC-001; that string is
// data inside a test literal and is never evaluated. Scoped to the two IDs, so
// anything else this file grows still gets flagged by the self-scan.
//
// §17z-b — the declared-package veto.
//
// The tests are written as FALSIFICATION first: the top block tries to make the
// veto change something it must not touch, and only then does the second block
// check that it removes what it is supposed to. That order is deliberate. A
// veto deletes findings, so the expensive failure is not "it did not fire", it
// is "it fired on something else" — and a suite that only asserts the happy
// path cannot tell those apart.
//
// WHERE THE SEAM IS. This file tests names → veto. It does NOT test lockfile →
// names: reading a lockfile is the CLI's job by design (analyzer-core has a
// browser entry and must not import `node:fs`), so that half is tested in
// apps/cli/src/declared-packages.test.ts. The two halves meet at a plain
// `string[]`, which is exactly the interface `ScanRequest.declaredPackages`
// declares, and neither half can be checked from the other side.
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { Finding, ScanRequest } from '@vibeguard/findings-schema';
import type { RuleDefinition } from '@vibeguard/rules';
import { Analyzer, scan } from './analyzer.js';
import { scan as scanBrowser } from './browser.js';
import { scanPath } from './file-scanner.js';
import {
  buildDeclaredPackageIndex,
  declaredPackageOfMatch,
  isDeclaredPackage,
  DECLARED_PACKAGE_VARIABLE,
  type DeclaredPackageVeto,
} from './declared-veto.js';

const TEMP_DIRS: string[] = [];
afterEach(async () => {
  while (TEMP_DIRS.length) {
    const d = TEMP_DIRS.pop()!;
    try {
      await rm(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

async function makeRepo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-declared-'));
  TEMP_DIRS.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, 'utf8');
  }
  return dir;
}

/** Strip the non-deterministic findingId so two runs can be compared. */
function canonical(findings: Finding[]): Omit<Finding, 'findingId'>[] {
  return findings
    .map(({ findingId, ...rest }) => rest)
    .sort(
      (a, b) =>
        (a.filePath ?? '').localeCompare(b.filePath ?? '') ||
        a.ruleId.localeCompare(b.ruleId) ||
        (a.startLine ?? 0) - (b.startLine ?? 0) ||
        (a.startColumn ?? 0) - (b.startColumn ?? 0),
    );
}

const TYPO_JS = "const e = require('expresss');\n";
const VULNERABLE_CORPUS = fileURLToPath(new URL('../../../samples/vulnerable/', import.meta.url));

function scanJs(content: string, declaredPackages?: readonly string[]): Finding[] {
  return scan({
    targetType: 'file',
    filePath: 'app.js',
    content,
    language: 'javascript',
    mode: 'standard',
    ...(declaredPackages ? { declaredPackages } : {}),
  }).findings;
}

describe('declared-package veto — falsification (what it must NOT change)', () => {
  it('a scan with unrelated declared names is byte-identical to one with none', () => {
    const none = canonical(scanJs(TYPO_JS));
    const unrelated = canonical(scanJs(TYPO_JS, ['left-pad', 'requests', 'zzz-not-here']));
    expect(none.length).toBeGreaterThan(0);
    expect(unrelated).toEqual(none);
  });

  it('samples/vulnerable is unchanged by an unrelated declared set (E2 stays 51)', async () => {
    const none = canonical((await scanPath(VULNERABLE_CORPUS, { config: false })).findings);
    const unrelated = canonical(
      (
        await scanPath(VULNERABLE_CORPUS, {
          config: false,
          declaredPackages: ['left-pad', 'zzz-not-here', 'definitely-not-imported'],
        })
      ).findings,
    );
    expect(none.length).toBe(51);
    expect(unrelated).toEqual(none);
  });

  it('an empty declared set behaves exactly like no declared set', () => {
    expect(canonical(scanJs(TYPO_JS, []))).toEqual(canonical(scanJs(TYPO_JS)));
  });

  it('does not touch findings from rules that name no package', () => {
    // The `eval` finding's matches carry no `variables.package`, so no declared
    // set can reach them — not even one that names the file, the evidence text,
    // or the offending package alongside them.
    const content = "const x = eval(input);\nconst e = require('expresss');\n";
    const before = scanJs(content);
    const after = scanJs(content, ['eval', 'input', 'app.js', 'expresss']);
    const others = (fs: Finding[]): Omit<Finding, 'findingId'>[] =>
      canonical(fs.filter((f) => f.ruleId !== 'VG-AISC-001'));
    expect(others(before).length).toBeGreaterThan(0);
    expect(others(after)).toEqual(others(before));
    // ...while the one finding that DID name a declared package is gone.
    expect(before.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
    expect(after.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(0);
  });

  it('a declared name that is not imported vetoes nothing', () => {
    expect(canonical(scanJs(TYPO_JS, ['express']))).toEqual(canonical(scanJs(TYPO_JS)));
  });

  it('the three channels still agree when no declared set is supplied', async () => {
    const files = { 'app.js': TYPO_JS };
    const browser = canonical(
      scanBrowser({ targetType: 'file', filePath: 'app.js', content: TYPO_JS, mode: 'standard' })
        .findings,
    );
    const vscode = canonical(
      new Analyzer().scan({
        targetType: 'file',
        filePath: 'app.js',
        content: TYPO_JS,
        mode: 'standard',
      }).findings,
    );
    const dir = await makeRepo(files);
    const cli = canonical((await scanPath(dir, { config: false })).findings);

    expect(browser.length).toBeGreaterThan(0);
    expect(vscode).toEqual(browser);
    expect(cli).toEqual(browser);
  });
});

describe('declared-package veto — what it removes', () => {
  it('removes the hallucinated-dependency finding for a declared package', () => {
    const before = scanJs(TYPO_JS);
    expect(before.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
    const after = scanJs(TYPO_JS, ['expresss']);
    expect(after.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(0);
  });

  it('matches case-insensitively', () => {
    expect(scanJs(TYPO_JS, ['ExPreSSS']).filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(0);
  });

  it('matches across separators, which is what PyPI naming requires', () => {
    // PEP 503: `-`, `_` and `.` are equivalent and names are case-folded, so a
    // lockfile saying `python-dateutil` and an import saying `python_dateutil`
    // are the SAME package. A literal comparison would miss this and leave a
    // false positive on every project that spells it the other way.
    const py = 'import python_dateutil\n';
    const before = scan({
      targetType: 'file',
      filePath: 'a.py',
      content: py,
      language: 'python',
      mode: 'standard',
    }).findings;
    expect(before.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
    const after = scan({
      targetType: 'file',
      filePath: 'a.py',
      content: py,
      language: 'python',
      mode: 'standard',
      declaredPackages: ['python-dateutil'],
    }).findings;
    expect(after.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(0);
  });

  it('reports every veto through the callback', () => {
    const vetoes: DeclaredPackageVeto[] = [];
    const analyzer = new Analyzer({ onDeclaredPackageVeto: (v) => vetoes.push(v) });
    analyzer.scan({
      targetType: 'file',
      filePath: 'app.js',
      content: TYPO_JS,
      language: 'javascript',
      mode: 'standard',
      declaredPackages: ['expresss'],
    });
    expect(vetoes).toEqual([
      { ruleId: 'VG-AISC-001', packageName: 'expresss', filePath: 'app.js', startLine: 1 },
    ]);
  });

  it('applies through scanPath, on every file of the walk', async () => {
    const dir = await makeRepo({ 'a.js': TYPO_JS, 'b.js': TYPO_JS });
    const before = await scanPath(dir, { config: false });
    expect(before.findings.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(2);
    const after = await scanPath(dir, { config: false, declaredPackages: ['expresss'] });
    expect(after.findings.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(0);
    // Everything else the walk found is untouched.
    expect(canonical(after.findings)).toEqual(
      canonical(before.findings.filter((f) => f.ruleId !== 'VG-AISC-001')),
    );
  });

  it('honours the Analyzer-level default, and lets a request override it', () => {
    const analyzer = new Analyzer({ declaredPackages: ['expresss'] });
    const withDefault = analyzer.scan({
      targetType: 'file',
      filePath: 'app.js',
      content: TYPO_JS,
      language: 'javascript',
      mode: 'standard',
    }).findings;
    expect(withDefault.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(0);

    // The request wins outright — the two are not merged, so a request that
    // declares something else declares ONLY that.
    const overridden = analyzer.scan({
      targetType: 'file',
      filePath: 'app.js',
      content: TYPO_JS,
      language: 'javascript',
      mode: 'standard',
      declaredPackages: ['something-else'],
    }).findings;
    expect(overridden.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
  });
});

describe('declared-package veto — the generic contract, not a rule ID', () => {
  /**
   * A rule that has nothing to do with supply chains but honours the data
   * contract (`variables.package`). If the veto were wired to `VG-AISC-001`
   * this rule would be untouched — which is the coupling the contract exists to
   * avoid, since every future package-naming rule would silently opt out.
   *
   * It also emits a DIFFERENT match on the canonical text than on the original
   * (it keys on the block comment, which normalization blanks), so the merged
   * set holds two matches from two different faces. That is what makes this
   * test also a test of WHERE the veto runs: filtering per face would leave the
   * canonical-only match alive.
   */
  const faceSensitiveRule: RuleDefinition = {
    ruleId: 'VG-TEST-PKG',
    name: 'test package rule',
    description: 'test',
    languages: ['*'],
    category: 'supply-chain',
    severity: 'medium',
    defaultConfidence: 'medium',
    contextConfidence: 'off',
    match: (ctx) => {
      const sawComment = ctx.content.includes('marker');
      const line = sawComment ? 1 : 2;
      return [
        {
          startLine: line,
          endLine: line,
          startColumn: 1,
          endColumn: 20,
          evidence: ctx.lines[line - 1] ?? '',
          variables: { [DECLARED_PACKAGE_VARIABLE]: 'ghostpkg' },
        },
      ];
    },
  };

  const content = 'const a = 1; /* marker */\nconst b = 2;\n';

  it('both match faces produce findings when nothing is declared', () => {
    const findings = new Analyzer({ rules: [faceSensitiveRule] }).scan({
      targetType: 'file',
      filePath: 'app.js',
      content,
      language: 'javascript',
      mode: 'standard',
    }).findings;
    // One from the original text (line 1), one only the canonical text sees
    // (line 2) — the union `D(x) ∪ D(N(x))`.
    expect(findings.map((f) => f.startLine).sort()).toEqual([1, 2]);
  });

  it('vetoes a non-AISC rule, on every face, from one enforcement point', () => {
    const vetoes: DeclaredPackageVeto[] = [];
    const findings = new Analyzer({
      rules: [faceSensitiveRule],
      onDeclaredPackageVeto: (v) => vetoes.push(v),
    }).scan({
      targetType: 'file',
      filePath: 'app.js',
      content,
      language: 'javascript',
      mode: 'standard',
      declaredPackages: ['ghostpkg'],
    }).findings;
    expect(findings).toHaveLength(0);
    expect(vetoes.map((v) => v.startLine).sort()).toEqual([1, 2]);
    expect(vetoes.every((v) => v.ruleId === 'VG-TEST-PKG')).toBe(true);
  });
});

describe('declared-package index', () => {
  it('treats absent, empty and blank-only lists as nothing to veto with', () => {
    expect(buildDeclaredPackageIndex(undefined)).toBeUndefined();
    expect(buildDeclaredPackageIndex([])).toBeUndefined();
    expect(buildDeclaredPackageIndex(['', '   ', '\t'])).toBeUndefined();
  });

  it('drops entries that normalize to nothing rather than matching everything', () => {
    // `---` normalizes to the empty string. If it were kept, any name that also
    // normalized to empty would be vetoed by it — a nonsense veto born of a
    // sloppy parser, and the one direction this feature may not fail in.
    expect(buildDeclaredPackageIndex(['---', '...'])).toBeUndefined();
    const index = buildDeclaredPackageIndex(['---', 'express'])!;
    expect(index.declaredCount).toBe(1);
    expect(isDeclaredPackage(index, 'express')).toBe(true);
    expect(isDeclaredPackage(index, '')).toBe(false);
    expect(isDeclaredPackage(index, '-')).toBe(false);
  });

  it('matches on the literal lowercase form and on the separator-free form', () => {
    const index = buildDeclaredPackageIndex(['Python-DateUtil'])!;
    expect(isDeclaredPackage(index, 'python-dateutil')).toBe(true);
    expect(isDeclaredPackage(index, 'python_dateutil')).toBe(true);
    expect(isDeclaredPackage(index, 'python.dateutil')).toBe(true);
    expect(isDeclaredPackage(index, 'pythondateutil')).toBe(true);
    expect(isDeclaredPackage(index, 'python-dateutils')).toBe(false);
  });

  it('PINS A KNOWN COST: separator matching is wider than npm equality', () => {
    // On PyPI this is correct by specification (PEP 503). On npm it is not:
    // `body-parser` and `bodyparser` are two DIFFERENT packages there, so a
    // project whose lockfile has the first also silences an import of the
    // second — an import that would fail at require() time and that
    // VG-AISC-001 would otherwise have named. The cost is accepted (see the
    // `normKey` comment in declared-veto.ts for the reasoning and the two
    // rejected alternatives) and pinned here so it stays a decision on the
    // record. If the comparison is ever split per ecosystem, THIS is the
    // assertion that should change, and changing it should be deliberate.
    const index = buildDeclaredPackageIndex(['body-parser'])!;
    expect(isDeclaredPackage(index, 'bodyparser')).toBe(true);
  });

  it('reuses the index for the same array (a directory walk indexes once)', () => {
    const names = ['express'];
    expect(buildDeclaredPackageIndex(names)).toBe(buildDeclaredPackageIndex(names));
    expect(buildDeclaredPackageIndex(['express'])).not.toBe(buildDeclaredPackageIndex(names));
  });

  it('only looks at the reserved `package` variable', () => {
    const index = buildDeclaredPackageIndex(['express'])!;
    const base = { startLine: 1, endLine: 1, startColumn: 1, endColumn: 2, evidence: 'x' };
    expect(declaredPackageOfMatch(base, index)).toBeUndefined();
    expect(declaredPackageOfMatch({ ...base, variables: { didYouMean: 'express' } }, index)).toBeUndefined();
    expect(declaredPackageOfMatch({ ...base, variables: { package: 'express' } }, index)).toBe('express');
    expect(declaredPackageOfMatch({ ...base, variables: { package: 'other' } }, index)).toBeUndefined();
  });
});

/**
 * The veto DELETES findings, so it has to be visible in the artifact.
 *
 * Until this existed it reported itself through a callback that only the CLI's
 * stderr consumed, so JSON and SARIF — the formats a machine reads, and the one
 * the GitHub Action uploads — could not tell "nothing was found" apart from
 * "something was found and removed". Same posture as the suppression tally, and
 * for the same stated reason: this codebase does not allow a mechanism that
 * deletes findings in silence.
 */
describe('declaredPackageVetoes is recorded on the response', () => {
  // `declaredPackages` rides on the REQUEST; `declaredPackageSource` is an
  // Analyzer option, because it describes the run and not the file.
  const scanJs = (content: string, declaredPackages: string[], source?: string) =>
    scan(
      { targetType: 'file', content, filePath: 'app.js', mode: 'standard', declaredPackages },
      source ? { declaredPackageSource: source } : undefined,
    );

  const HALLUCINATED = 'const e = require("expresss");\nmodule.exports = e;\n';

  it('reports the finding when nothing declares the package', () => {
    const r = scanJs(HALLUCINATED, []);
    expect(r.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(true);
    expect(r.declaredPackageVetoes).toBeUndefined();
  });

  it('drops the finding AND records why when the package is declared', () => {
    const r = scanJs(HALLUCINATED, ['expresss'], 'package-lock.json');
    expect(r.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);
    expect(r.declaredPackageVetoes).toEqual([
      {
        ruleId: 'VG-AISC-001',
        packageName: 'expresss',
        filePath: 'app.js',
        count: 1,
        source: 'package-lock.json',
      },
    ]);
  });

  it('carries no line number, so the record cannot rebuild the finding', () => {
    const r = scanJs(HALLUCINATED, ['expresss']);
    const v = r.declaredPackageVetoes![0]!;
    expect('startLine' in v).toBe(false);
    expect(JSON.stringify(v)).not.toMatch(/line/i);
  });

  it('does not contribute to the summary or the finding list', () => {
    const r = scanJs(HALLUCINATED, ['expresss']);
    expect(r.summary.total).toBe(r.findings.length);
  });

  it('records one entry per package, not one per import site', () => {
    // The rule already collapses repeated imports of one name to a single
    // match, so the record is one line whether the package is required once or
    // twice — which is the granularity a reviewer wants anyway.
    const twice = 'const a = require("expresss");\nconst b = require("expresss");\n';
    const r = scanJs(twice, ['expresss']);
    expect(r.declaredPackageVetoes).toHaveLength(1);
    expect(r.declaredPackageVetoes![0]!.packageName).toBe('expresss');
  });

  it('keeps separate packages in separate records', () => {
    const two = 'const a = require("expresss");\nconst b = require("lodashh");\n';
    const r = scanJs(two, ['expresss', 'lodashh']);
    const names = (r.declaredPackageVetoes ?? []).map((v) => v.packageName).sort();
    expect(names).toEqual(['expresss', 'lodashh']);
  });
});

/**
 * THE THREE STATES OF `declaredPackageVetoes` — absent / `[]` / non-empty.
 *
 * Recording only what the veto REMOVED left two very different scans looking
 * identical: one where nobody supplied a lockfile (so no supply-chain finding
 * could have been refuted) and one where a lockfile was read and refuted
 * nothing. That difference is the whole content of the Chrome ruling —
 * `extensions/chrome/src/shared/block-scan.ts` — because the browser channel
 * has no lockfile and never will: every response it produces is the first
 * state, permanently, and a reader has to be able to tell that from a CLI
 * report that actually checked.
 *
 * The line is "was the veto ARMED", i.e. did an index get built from a
 * non-empty declared set. A caller who looked for a lockfile and found nothing
 * usable armed nothing, so their scan reads as the first state too — which is
 * correct, and which is why `ScanRequest.declaredPackages` documents that only
 * the producer can report the difference between "did not look" and "looked and
 * found none".
 */
describe('declaredPackageVetoes distinguishes "did not run" from "ran and removed nothing"', () => {
  const HALLUCINATED = 'const e = require("expresss");\nmodule.exports = e;\n';
  const req = (declaredPackages?: readonly string[]): ScanRequest => ({
    targetType: 'file',
    content: HALLUCINATED,
    filePath: 'app.js',
    language: 'javascript',
    mode: 'standard',
    ...(declaredPackages ? { declaredPackages } : {}),
  });

  it('is ABSENT when no declared set was supplied — the veto did not run', () => {
    const r = scan(req());
    expect('declaredPackageVetoes' in r).toBe(false);
    expect(r.declaredPackageVetoes).toBeUndefined();
    // Positive control for the whole block: the finding this veto argues about
    // is really there, so an absent record means "not refuted", not "nothing to
    // refute".
    expect(r.findings.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
  });

  it('is ABSENT on the browser entry, which is every Chrome scan', () => {
    const r = scanBrowser(req());
    expect('declaredPackageVetoes' in r).toBe(false);
    expect(r.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(true);
  });

  it('is an EMPTY ARRAY when a real declared set refuted nothing', () => {
    // `express` is declared; `expresss` is imported. The veto ran, considered
    // the match, and kept it.
    const r = scan(req(['express', 'lodash']));
    expect('declaredPackageVetoes' in r).toBe(true);
    expect(r.declaredPackageVetoes).toEqual([]);
    // TRUE-POSITIVE PRESERVATION: an armed veto that removes nothing must leave
    // the finding exactly where it was.
    expect(r.findings.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
  });

  it('is NON-EMPTY only when it actually removed something', () => {
    const r = scan(req(['expresss']));
    expect(r.declaredPackageVetoes).toHaveLength(1);
    expect(r.declaredPackageVetoes![0]!.packageName).toBe('expresss');
    expect(r.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);
  });

  it('an empty declared set reads as "did not run", not as "ran and removed nothing"', () => {
    // `[]` arms nothing: no index is built, so no finding could have been
    // removed. Reporting `[]` here would claim a check that never happened.
    expect('declaredPackageVetoes' in scan(req([]))).toBe(false);
  });

  it('a declared set of nothing but blanks also reads as "did not run"', () => {
    // `buildDeclaredPackageIndex` drops empty and separator-only names, so this
    // list builds no index either. The response must agree with what actually
    // happened rather than with the length of the array it was handed.
    expect('declaredPackageVetoes' in scan(req(['', '   ', '---']))).toBe(false);
  });

  it('scanPath carries the same three states across a directory walk', async () => {
    const dir = await makeRepo({ 'app.js': HALLUCINATED });

    const notRun = await scanPath(dir, { config: false });
    expect('declaredPackageVetoes' in notRun).toBe(false);

    const ranAndKept = await scanPath(dir, { config: false, declaredPackages: ['express'] });
    expect(ranAndKept.declaredPackageVetoes).toEqual([]);
    expect(ranAndKept.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(true);

    const ranAndRemoved = await scanPath(dir, { config: false, declaredPackages: ['expresss'] });
    expect(ranAndRemoved.declaredPackageVetoes).toHaveLength(1);
    expect(ranAndRemoved.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);
  });
});
