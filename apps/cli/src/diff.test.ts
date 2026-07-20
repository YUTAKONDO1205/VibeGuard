// vibeguard:disable-file VG-INJ-004
// Test fixtures contain intentional vulnerable code to exercise diff scanning.
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  evaluatePathSuppression,
  suppressionsForPath,
  type VibeguardConfig,
} from '@vibeguard/analyzer-core';
import { isSecurityJudgementSeverity } from '@vibeguard/findings-schema';
import { parseUnifiedDiff, scanDiff } from './diff.js';

const tempDirs: string[] = [];

afterAll(async () => {
  // Best-effort cleanup; ignore errors.
  await Promise.all(
    tempDirs.map((d) =>
      import('node:fs/promises').then((fs) => fs.rm(d, { recursive: true, force: true })),
    ),
  );
});

async function makeFiles(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vibeguard-diff-'));
  tempDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    const idx = full.lastIndexOf('/');
    if (idx > 0) await mkdir(full.slice(0, idx), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return dir;
}

describe('parseUnifiedDiff', () => {
  it('returns empty for empty input', () => {
    expect(parseUnifiedDiff('').size).toBe(0);
  });

  it('extracts added lines from a single hunk (--unified=0)', () => {
    const diff = [
      'diff --git a/foo.js b/foo.js',
      'index abc..def 100644',
      '--- a/foo.js',
      '+++ b/foo.js',
      '@@ -10,0 +11,2 @@',
      '+const a = 1;',
      '+const b = 2;',
    ].join('\n');
    const m = parseUnifiedDiff(diff);
    const added = m.get('foo.js');
    expect(added).toBeDefined();
    expect([...(added ?? [])].sort((a, b) => a - b)).toEqual([11, 12]);
  });

  it('handles unified=N context correctly (line counter advances on space lines)', () => {
    // Hunk says new file lines 5..9 are 5 lines: 1 context, 2 added, 1 context, 1 added would be wrong;
    // simpler: 2 context + 2 added.
    const diff = [
      '--- a/x.js',
      '+++ b/x.js',
      '@@ -5,2 +5,4 @@',
      ' const a = 1;',
      ' const b = 2;',
      '+const c = 3;',
      '+const d = 4;',
    ].join('\n');
    const m = parseUnifiedDiff(diff);
    expect([...(m.get('x.js') ?? [])].sort((a, b) => a - b)).toEqual([7, 8]);
  });

  it('treats deletions as not advancing the new-file counter', () => {
    const diff = [
      '--- a/x.js',
      '+++ b/x.js',
      '@@ -5,3 +5,1 @@',
      '-const a = 1;',
      '-const b = 2;',
      '+const c = 3;',
    ].join('\n');
    const m = parseUnifiedDiff(diff);
    expect([...(m.get('x.js') ?? [])]).toEqual([5]);
  });

  it('handles a deleted file (skips +++ /dev/null)', () => {
    const diff = [
      '--- a/old.js',
      '+++ /dev/null',
      '@@ -1,2 +0,0 @@',
      '-foo',
      '-bar',
    ].join('\n');
    expect(parseUnifiedDiff(diff).size).toBe(0);
  });

  it('parses multiple files and hunks', () => {
    const diff = [
      '--- a/a.js',
      '+++ b/a.js',
      '@@ -1,0 +2,1 @@',
      '+eval(x);',
      '@@ -10,0 +11,1 @@',
      '+more;',
      '--- a/b.js',
      '+++ b/b.js',
      '@@ -3,0 +4,1 @@',
      '+const k = "secret";',
    ].join('\n');
    const m = parseUnifiedDiff(diff);
    expect([...(m.get('a.js') ?? [])].sort((a, b) => a - b)).toEqual([2, 11]);
    expect([...(m.get('b.js') ?? [])]).toEqual([4]);
  });

  it('defaults hunk count to 1 when omitted', () => {
    const diff = ['--- a/x.js', '+++ b/x.js', '@@ -0,0 +5 @@', '+eval(input);'].join('\n');
    const m = parseUnifiedDiff(diff);
    expect([...(m.get('x.js') ?? [])]).toEqual([5]);
  });
});

describe('scanDiff', () => {
  it('reports findings only on added lines', async () => {
    // File contains two evals — only one is "in the diff".
    const cwd = await makeFiles({
      'app.js': ['const a = eval(x);', 'const b = 2;', 'const c = eval(y);'].join('\n'),
    });
    const diffText = [
      '--- a/app.js',
      '+++ b/app.js',
      '@@ -1,0 +1,1 @@',
      '+const a = eval(x);',
    ].join('\n');
    const result = await scanDiff({ cwd, range: 'unused', diffText, mode: 'fast' });
    const evals = result.findings.filter((f) => f.ruleId === 'VG-INJ-004');
    expect(evals).toHaveLength(1);
    expect(evals[0]?.startLine).toBe(1);
  });

  it('returns no findings when added lines are clean', async () => {
    const cwd = await makeFiles({ 'safe.js': 'const x = 1 + 1;\n' });
    const diffText = [
      '--- a/safe.js',
      '+++ b/safe.js',
      '@@ -0,0 +1,1 @@',
      '+const x = 1 + 1;',
    ].join('\n');
    const result = await scanDiff({ cwd, range: 'unused', diffText, mode: 'standard' });
    expect(result.findings).toEqual([]);
    expect(result.summary.total).toBe(0);
  });

  it('skips files that are missing from the working tree', async () => {
    const cwd = await makeFiles({}); // empty dir
    const diffText = [
      '--- a/gone.js',
      '+++ b/gone.js',
      '@@ -0,0 +1,1 @@',
      '+eval(x);',
    ].join('\n');
    const result = await scanDiff({ cwd, range: 'unused', diffText, mode: 'fast' });
    expect(result.findings).toEqual([]);
  });
});

/**
 * D5 on the diff path.
 *
 * `scanDiff` is a third enforcement point for the config suppression channel,
 * alongside `Analyzer.scan` and `scanPath`, and it is the one the GitHub Action
 * runs: `--diff` is how a pull request gets its verdict. A wildcard `suppress`
 * entry checked into a repository is therefore a way to make the PR gate agree
 * that a critical finding is not there — which is exactly what the severity gate
 * exists to refuse. These mirror the config tests in file-scanner.test.ts,
 * fixture for fixture, so the two paths can be read against each other.
 */
describe('scanDiff — config suppression severity gate (D5)', () => {
  // One added line per fixture, so the diff filter never decides the outcome:
  // whatever reaches `findings` got there by surviving the suppression gate.
  const oneLineDiff = (path: string, line: string): string =>
    [`--- a/${path}`, `+++ b/${path}`, '@@ -0,0 +1,1 @@', `+${line}`].join('\n');

  const EVAL_LINE = 'const v = eval(input);';
  // VG-CRYPTO-003, severity low — below the gate, so the wildcard still applies.
  const HTTP_LINE = 'const endpoint = "http://example.com/api";';

  it('reports a critical finding through a rules-omitted config entry', async () => {
    const cwd = await makeFiles({
      'app.js': `${EVAL_LINE}\n`,
      '.vibeguardrc.json': JSON.stringify({ suppress: [{ paths: ['**/*.js'] }] }),
    });
    const result = await scanDiff({
      cwd,
      range: 'unused',
      diffText: oneLineDiff('app.js', EVAL_LINE),
      mode: 'standard',
    });
    const f = result.findings.find((x) => x.ruleId === 'VG-INJ-004');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('critical');
    expect(f?.suppressionOverridden).toEqual({ channel: 'config', scope: 'path' });
  });

  it('predicate comparison: the pre-D5 predicate would have dropped that finding', async () => {
    // Scope, so the name does not promise more than it delivers: this compares
    // the two PREDICATES on the resolved set. It does NOT run `diff.ts`, so
    // reverting the gate at diff.ts:208 leaves this test green — the end-to-end
    // mutation control for that call site is the preceding test, which goes red.
    // (Named "mutation control" until 2026-07-20, which overstated it.)
    //
    // `legacy` is the severity-blind body `diff.ts` used before the gate —
    // `pathSuppressed.has('*') || pathSuppressed.has(f.ruleId)` — run on the
    // same resolved set that `scanDiff` resolves for this file.
    const cfg: VibeguardConfig = { suppress: [{ paths: ['**/*.js'] }] };
    const s = suppressionsForPath(cfg, 'app.js', new Date('2026-07-20T00:00:00Z'));
    const legacy = s.has('*') || s.has('VG-INJ-004');
    expect(legacy).toBe(true);
    // And the gate that replaced it disagrees, on that same set.
    expect(evaluatePathSuppression(s, 'VG-INJ-004', 'critical')).toEqual({
      suppressed: false,
      overridden: { channel: 'config', scope: 'path' },
    });
  });

  it.each(['critical', 'high', 'medium'] as const)(
    'refuses a wildcard against a %s finding',
    (severity) => {
      // The gate follows the shared predicate rather than a list copied beside
      // it, so the three severities it keeps are pinned to that predicate.
      expect(isSecurityJudgementSeverity(severity)).toBe(true);
      const s = new Set(['*']);
      expect(evaluatePathSuppression(s, 'VG-ANY-001', severity).suppressed).toBe(false);
    },
  );

  it('still suppresses a low-severity finding under a wildcard', async () => {
    // Below the gate nothing changes: `suppress` remains a working noise filter
    // for the findings it was mostly written for.
    const cwd = await makeFiles({
      'net.js': `${HTTP_LINE}\n`,
      '.vibeguardrc.json': JSON.stringify({ suppress: [{ paths: ['**/*.js'] }] }),
    });
    const diffText = oneLineDiff('net.js', HTTP_LINE);

    // First establish the finding exists at all without the config, or the
    // assertion below would pass on an empty scan.
    const unsuppressed = await scanDiff({
      cwd,
      range: 'unused',
      diffText,
      mode: 'standard',
      config: false,
    });
    const low = unsuppressed.findings.find((x) => x.ruleId === 'VG-CRYPTO-003');
    expect(low).toBeDefined();
    expect(low?.severity).toBe('low');
    expect(isSecurityJudgementSeverity('low')).toBe(false);

    const result = await scanDiff({
      cwd,
      range: 'unused',
      diffText,
      mode: 'standard',
    });
    expect(result.findings.some((x) => x.ruleId === 'VG-CRYPTO-003')).toBe(false);
  });

  it('still honours a config entry that names the rule, at critical', async () => {
    // The escape hatch. Naming the rule is a deliberate statement about that
    // rule, so it is honoured at every severity — the wildcard is not.
    const cwd = await makeFiles({
      'app.js': `${EVAL_LINE}\n`,
      '.vibeguardrc.json': JSON.stringify({
        suppress: [{ paths: ['**/*.js'], rules: ['VG-INJ-004'] }],
      }),
    });
    const result = await scanDiff({
      cwd,
      range: 'unused',
      diffText: oneLineDiff('app.js', EVAL_LINE),
      mode: 'standard',
    });
    expect(result.findings.some((x) => x.ruleId === 'VG-INJ-004')).toBe(false);
  });

  it('leaves suppressionOverridden unset when no config is in play', async () => {
    // The marker is an audit record of a refusal. If it appeared on findings
    // nobody tried to suppress it would say nothing.
    const cwd = await makeFiles({ 'app.js': `${EVAL_LINE}\n` });
    const result = await scanDiff({
      cwd,
      range: 'unused',
      diffText: oneLineDiff('app.js', EVAL_LINE),
      mode: 'standard',
    });
    const f = result.findings.find((x) => x.ruleId === 'VG-INJ-004');
    expect(f).toBeDefined();
    expect(f?.suppressionOverridden).toBeUndefined();
  });
});
