// vibeguard:disable-file VG-INJ-004 VG-SEC-001 VG-SEC-003
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { RuleDefinition } from '@vibeguard/rules';
import { scanPath } from './file-scanner.js';
import { suppressionsForPath, type VibeguardConfig } from './config.js';

const TEMP_DIRS: string[] = [];

async function makeRepo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vibeguard-test-'));
  TEMP_DIRS.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, 'utf8');
  }
  return dir;
}

afterEach(async () => {
  // Best-effort cleanup; node 20 has rm
  const { rm } = await import('node:fs/promises');
  while (TEMP_DIRS.length) {
    const d = TEMP_DIRS.pop()!;
    try {
      await rm(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

describe('scanPath', () => {
  it('scans a directory tree and aggregates findings per file', async () => {
    const dir = await makeRepo({
      'evil.py': 'import pickle\npickle.loads(blob)\n',
      'safe.py': 'x = 1\n',
    });
    const result = await scanPath(dir);
    const evilFindings = result.findings.filter((f) => f.filePath?.endsWith('evil.py'));
    expect(evilFindings.length).toBeGreaterThan(0);
    expect(result.findings.find((f) => f.filePath?.endsWith('safe.py'))).toBeUndefined();
  });

  // A rule that throws must surface in the aggregated response, not vanish. This
  // is the shipped path (the CLI calls scanPath, never Analyzer.scan directly),
  // so a per-file crash that the analyzer records must survive aggregation —
  // deduped by ruleId so a rule that throws on every file appears once.
  it('aggregates ruleErrors across files, deduped by ruleId', async () => {
    const boom: RuleDefinition = {
      ruleId: 'VG-TEST-BOOM',
      name: 'boom',
      description: 'throws on match',
      languages: ['*'],
      category: 'quality',
      severity: 'high',
      defaultConfidence: 'high',
      match: () => {
        throw new Error('kaboom');
      },
    };
    // .txt has no detected language, so the injected rule is honoured on each file.
    const dir = await makeRepo({ 'a.txt': 'anything', 'b.txt': 'more' });
    const result = await scanPath(dir, { rules: [boom] });
    expect(result.ruleErrors).toEqual([{ ruleId: 'VG-TEST-BOOM', message: 'kaboom' }]);
  });

  it('omits ruleErrors when no rule throws', async () => {
    const dir = await makeRepo({ 'a.py': 'x = 1\n' });
    const result = await scanPath(dir);
    expect(result.ruleErrors).toBeUndefined();
  });

  it('returns an empty response on a clean directory', async () => {
    const dir = await makeRepo({
      'a.py': 'def add(a, b):\n    return a + b\n',
    });
    const result = await scanPath(dir);
    expect(result.findings).toEqual([]);
    expect(result.summary.total).toBe(0);
  });

  // The config channel is the second way to silence a finding, and it is the one
  // the analyzer never sees — `Analyzer.scan` has already returned by the time
  // `suppressionsForPath` is consulted. These three pin the D5 gate down on that
  // path end-to-end, through the function the CLI actually calls.
  it('reports a critical finding through a rules-omitted config entry', async () => {
    const dir = await makeRepo({
      'evil.js': 'const v = eval(input);\n',
      '.vibeguardrc.json': JSON.stringify({ suppress: [{ paths: ['**/*.js'] }] }),
    });
    const result = await scanPath(dir);
    const f = result.findings.find((x) => x.ruleId === 'VG-INJ-004');
    expect(f).toBeDefined();
    expect(f?.suppressionOverridden).toEqual({ channel: 'config', scope: 'path' });
  });

  it('still honours a config entry that names the rule', async () => {
    // The escape hatch, on the config channel. Same fixture, one field added.
    const dir = await makeRepo({
      'evil.js': 'const v = eval(input);\n',
      '.vibeguardrc.json': JSON.stringify({
        suppress: [{ paths: ['**/*.js'], rules: ['VG-INJ-004'] }],
      }),
    });
    const result = await scanPath(dir);
    expect(result.findings.some((x) => x.ruleId === 'VG-INJ-004')).toBe(false);
  });

  it('mutation control: the pre-gate config predicate would have dropped it', async () => {
    // Without this the test above only proves the finding is reported, not that
    // the wildcard would once have removed it. `legacy` is the pre-D5 body of
    // `isPathSuppressed` verbatim, run on the same resolved suppression set.
    const cfg: VibeguardConfig = { suppress: [{ paths: ['**/*.js'] }] };
    const s = suppressionsForPath(cfg, 'evil.js', new Date('2026-05-22T00:00:00Z'));
    const legacy = s.has('*') || s.has('VG-INJ-004');
    expect(legacy).toBe(true);
  });

  it('respects knownLanguagesOnly', async () => {
    const dir = await makeRepo({
      'note.txt': 'API_KEY = "AKIAIOSFODNN7EXAMPLE"',
    });
    const result = await scanPath(dir, { knownLanguagesOnly: true });
    expect(result.findings).toEqual([]);
  });
});

/**
 * D8 on the config channel, through `scanPath` — the function the CLI and the
 * GitHub Action actually call.
 *
 * `scanPath` is where the two halves of the tally have to meet: the analyzer
 * reports the pragma half per file and `scanPath` throws that per-file response
 * away, so the merge is a real failure point rather than a formality. Both
 * halves are asserted, in one scan, for that reason.
 *
 * Again: observability, not defence. The named suppressions below all work.
 */
describe('scanPath — suppression tally (D8)', () => {
  it('records a config entry that names a critical rule', async () => {
    const dir = await makeRepo({
      'evil.js': 'const v = eval(input);\n',
      '.vibeguardrc.json': JSON.stringify({
        suppress: [{ paths: ['**/*.js'], rules: ['VG-INJ-004'] }],
      }),
    });
    const result = await scanPath(dir);
    expect(result.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(false);
    expect(result.summary.critical).toBe(0);
    const rec = result.suppressions?.find((s) => s.ruleId === 'VG-INJ-004');
    expect(rec).toBeDefined();
    expect(rec?.channel).toBe('config');
    expect(rec?.scope).toBe('path');
    expect(rec?.count).toBe(1);
    expect(rec?.filePath).toBe('evil.js');
  });

  it('carries the analyzer\'s pragma records across the directory walk', async () => {
    // The merge point. Before D8 the per-file `ScanResponse` was consulted only
    // for findings, ruleErrors and degradations, so a pragma record produced
    // inside the analyzer would have been dropped here without a trace.
    const dir = await makeRepo({
      'evil.js': 'const v = eval(input); // vibeguard:disable-line VG-INJ-004\n',
    });
    const result = await scanPath(dir);
    expect(result.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(false);
    expect(result.suppressions).toContainEqual({
      ruleId: 'VG-INJ-004',
      channel: 'pragma',
      scope: 'line',
      filePath: 'evil.js',
      count: 1,
    });
  });

  it('keeps both channels distinguishable in one walk', async () => {
    const dir = await makeRepo({
      'pragma.js': 'const v = eval(input); // vibeguard:disable-line VG-INJ-004\n',
      'config.js': 'const v = eval(input);\n',
      '.vibeguardrc.json': JSON.stringify({
        suppress: [{ paths: ['config.js'], rules: ['VG-INJ-004'] }],
      }),
    });
    const result = await scanPath(dir);
    const channels = new Set((result.suppressions ?? []).map((s) => s.channel));
    expect(channels).toEqual(new Set(['pragma', 'config']));
  });

  it('omits the field when nothing was suppressed', async () => {
    const dir = await makeRepo({ 'evil.js': 'const v = eval(input);\n' });
    const result = await scanPath(dir);
    expect(result.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(true);
    expect('suppressions' in (result as object)).toBe(false);
  });
});
