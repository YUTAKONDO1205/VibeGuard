import { describe, expect, it } from 'vitest';
import type { Finding } from '@vibeguard/findings-schema';
import {
  appendHistory,
  buildHistoryEntry,
  clearHistory,
  HISTORY_KEY,
  HISTORY_MAX,
  loadHistory,
  PREVIEW_CHARS,
  type HistoryEntry,
  type HistoryStorage,
} from './history.js';

function fakeStorage(): HistoryStorage & { _data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return {
    _data: data,
    get: async (key: string) => (key in data ? { [key]: data[key] } : {}),
    set: async (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) data[k] = v;
    },
    remove: async (key: string) => {
      delete data[key];
    },
  };
}

const baseSummary = { critical: 0, high: 1, medium: 0, low: 0, info: 0, total: 1 };

function fakeFinding(over: Partial<Finding> = {}): Finding {
  return {
    findingId: 'fid-1',
    ruleId: 'VG-INJ-001',
    title: 'Test finding',
    description: 'desc',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    sourceEngine: 'core-rule',
    startLine: 10,
    snippet: 'should NOT be stored',
    remediation: { why: 'why', how: 'how' },
    ...over,
  };
}

describe('buildHistoryEntry', () => {
  it('caps preview length and drops snippet/remediation from findings', () => {
    const long = 'x'.repeat(PREVIEW_CHARS + 50);
    const entry = buildHistoryEntry({
      source: 'paste',
      summary: baseSummary,
      findings: [fakeFinding()],
      codeForPreview: long,
      totalLines: 5,
    });
    expect(entry.codePreview.endsWith('…')).toBe(true);
    expect(entry.codePreview.length).toBe(PREVIEW_CHARS + 1);
    expect(entry.findings).toHaveLength(1);
    const f = entry.findings[0]!;
    expect(f.ruleId).toBe('VG-INJ-001');
    expect(f.title).toBe('Test finding');
    expect(f.severity).toBe('high');
    expect(f.startLine).toBe(10);
    // Compact finding has no snippet / remediation / description fields.
    expect((f as unknown as Record<string, unknown>).snippet).toBeUndefined();
    expect((f as unknown as Record<string, unknown>).remediation).toBeUndefined();
  });

  it('caps the finding list at maxFindings', () => {
    const findings = Array.from({ length: 30 }, (_, i) =>
      fakeFinding({ findingId: `f${i}`, startLine: i + 1 }),
    );
    const entry = buildHistoryEntry({
      source: 'paste',
      summary: baseSummary,
      findings,
      codeForPreview: 'x',
      totalLines: 30,
      maxFindings: 10,
    });
    expect(entry.findings).toHaveLength(10);
    expect(entry.findings[0]!.startLine).toBe(1);
  });
});

describe('appendHistory', () => {
  it('prepends new entries and enforces the cap', async () => {
    const storage = fakeStorage();
    const newId = (() => {
      let n = 0;
      return () => `id-${++n}`;
    })();
    for (let i = 0; i < HISTORY_MAX + 5; i++) {
      const entry: HistoryEntry = buildHistoryEntry({
        source: 'paste',
        summary: baseSummary,
        findings: [],
        codeForPreview: `entry-${i}`,
        totalLines: 1,
        newId,
      });
      await appendHistory(entry, storage);
    }
    const list = await loadHistory(storage);
    expect(list).toHaveLength(HISTORY_MAX);
    // Most-recent first.
    expect(list[0]!.codePreview).toBe(`entry-${HISTORY_MAX + 4}`);
    expect(list[HISTORY_MAX - 1]!.codePreview).toBe('entry-5');
  });
});

describe('loadHistory', () => {
  it('returns [] when the key is absent', async () => {
    const storage = fakeStorage();
    expect(await loadHistory(storage)).toEqual([]);
  });

  it('skips malformed entries', async () => {
    const storage = fakeStorage();
    storage._data[HISTORY_KEY] = [
      { not: 'valid' },
      buildHistoryEntry({
        source: 'paste',
        summary: baseSummary,
        findings: [],
        codeForPreview: 'ok',
        totalLines: 1,
      }),
    ];
    const list = await loadHistory(storage);
    expect(list).toHaveLength(1);
    expect(list[0]!.codePreview).toBe('ok');
  });
});

describe('clearHistory', () => {
  it('removes the key', async () => {
    const storage = fakeStorage();
    await appendHistory(
      buildHistoryEntry({
        source: 'paste',
        summary: baseSummary,
        findings: [],
        codeForPreview: 'x',
        totalLines: 1,
      }),
      storage,
    );
    expect((await loadHistory(storage)).length).toBe(1);
    await clearHistory(storage);
    expect(await loadHistory(storage)).toEqual([]);
  });
});
