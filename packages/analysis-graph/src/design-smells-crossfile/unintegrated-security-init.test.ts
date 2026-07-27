import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import { isDesignSmellFinding, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { analyzeProject } from '../project.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);

const aiscIn = async (dir: string): Promise<DesignSmellFinding[]> => {
  const result = await analyzeProject(dir);
  return result.findings.filter(
    (f): f is DesignSmellFinding => isDesignSmellFinding(f) && f.ruleId === 'VG-AISC-003',
  );
};

describe('VG-AISC-003 — positive case', () => {
  it('reports the initializer that nothing mentions', async () => {
    const findings = await aiscIn(sample('crossfile-fixtures/embedded-unintegrated'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.description).toContain('crypto_engine_init');
    expect(findings[0]!.filePath).toBe('crypto.c');
  });

  it('does not treat a mention inside a comment as wiring', async () => {
    // main.c contains `crypto_engine_init()` in a comment. If comments counted,
    // this fixture would produce nothing and the test above would fail — so this
    // asserts the blanking is what makes the count honest.
    const findings = await aiscIn(sample('crossfile-fixtures/embedded-unintegrated'));
    expect(findings).toHaveLength(1);
  });

  it('cites the header declaration as a related location', async () => {
    const [finding] = await aiscIn(sample('crossfile-fixtures/embedded-unintegrated'));
    expect((finding!.relatedLocations ?? []).map((l) => l.filePath)).toContain('crypto.h');
  });

  it('caps confidence at medium — the evidence is a lexical absence', async () => {
    const [finding] = await aiscIn(sample('crossfile-fixtures/embedded-unintegrated'));
    expect(finding!.confidence).toBe('medium');
    expect(finding!.severity).toBe('high');
  });

  it('leaves non-security initializers alone even when unused', async () => {
    const findings = await aiscIn(sample('crossfile-fixtures/embedded-unintegrated'));
    expect(findings.map((f) => f.description).join()).not.toContain('sensor_init');
  });
});

describe('VG-AISC-003 — the falsification corpus', () => {
  it('reports nothing when every initializer is wired without a call site', async () => {
    // Function-pointer table, designated struct initialiser, RTOS task
    // registration, and a weak placeholder. A reachability analysis flags all
    // four; this rule must flag none. If this test ever fails, the rule has
    // started guessing about entry points.
    expect(await aiscIn(sample('crossfile-fixtures/embedded-wired'))).toEqual([]);
  });

  it('reports nothing for a project with no C at all', async () => {
    expect(await aiscIn(sample('crossfile-vulnerable'))).toEqual([]);
  });

  it('reports nothing on the safe corpus', async () => {
    expect(await aiscIn(sample('crossfile-safe'))).toEqual([]);
  });
});
