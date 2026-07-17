// vibeguard:disable-file
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { RuleDefinition } from '@vibeguard/rules';
import { scanPath } from './file-scanner.js';

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

  it('respects knownLanguagesOnly', async () => {
    const dir = await makeRepo({
      'note.txt': 'API_KEY = "AKIAIOSFODNN7EXAMPLE"',
    });
    const result = await scanPath(dir, { knownLanguagesOnly: true });
    expect(result.findings).toEqual([]);
  });
});
