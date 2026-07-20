import { describe, expect, it } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  evaluatePathSuppression,
  isPathSuppressed,
  suppressionsForPath,
  type VibeguardConfig,
} from './config.js';
import { loadConfig } from './config-loader.js';

describe('suppressionsForPath', () => {
  const now = new Date('2026-05-22T00:00:00Z');

  it('returns empty set when config is undefined', () => {
    expect(suppressionsForPath(undefined, 'src/a.ts', now).size).toBe(0);
  });

  it('matches a single glob and rule ID', () => {
    const cfg: VibeguardConfig = {
      suppress: [{ paths: ['samples/**'], rules: ['VG-INJ-004'] }],
    };
    expect(suppressionsForPath(cfg, 'samples/a.py', now).has('VG-INJ-004')).toBe(true);
    expect(suppressionsForPath(cfg, 'src/a.ts', now).has('VG-INJ-004')).toBe(false);
  });

  it('treats omitted rules as wildcard', () => {
    const cfg: VibeguardConfig = { suppress: [{ paths: ['**/*.test.ts'] }] };
    const s = suppressionsForPath(cfg, 'src/foo.test.ts', now);
    expect(s.has('*')).toBe(true);
    // `low` keeps the historical wildcard behaviour; the gate is exercised in
    // its own block below.
    expect(isPathSuppressed(s, 'VG-ANYTHING-001', 'low')).toBe(true);
  });

  it('drops expired entries', () => {
    const cfg: VibeguardConfig = {
      suppress: [{ paths: ['samples/**'], rules: ['VG-INJ-004'], expires: '2024-01-01' }],
    };
    expect(suppressionsForPath(cfg, 'samples/a.py', now).size).toBe(0);
  });

  it('keeps entries before the expires date', () => {
    const cfg: VibeguardConfig = {
      suppress: [{ paths: ['samples/**'], rules: ['VG-INJ-004'], expires: '2099-12-31' }],
    };
    expect(suppressionsForPath(cfg, 'samples/a.py', now).has('VG-INJ-004')).toBe(true);
  });

  it('merges rules across overlapping entries', () => {
    const cfg: VibeguardConfig = {
      suppress: [
        { paths: ['samples/**'], rules: ['VG-INJ-004'] },
        { paths: ['samples/**'], rules: ['VG-AUTH-003'] },
      ],
    };
    const s = suppressionsForPath(cfg, 'samples/a.py', now);
    expect(s.has('VG-INJ-004')).toBe(true);
    expect(s.has('VG-AUTH-003')).toBe(true);
  });
});

describe('severity gate on config wildcards (D5)', () => {
  const now = new Date('2026-05-22T00:00:00Z');
  const wildcardCfg: VibeguardConfig = { suppress: [{ paths: ['samples/**'] }] };
  const explicitCfg: VibeguardConfig = {
    suppress: [{ paths: ['samples/**'], rules: ['VG-INJ-004'] }],
  };
  // The pre-gate predicate verbatim, as the mutation control for this channel.
  const legacy = (s: Set<string>, ruleId: string) => s.has('*') || s.has(ruleId);

  for (const severity of ['critical', 'high', 'medium'] as const) {
    it(`refuses a rules-omitted entry for ${severity}`, () => {
      const s = suppressionsForPath(wildcardCfg, 'samples/a.py', now);
      const d = evaluatePathSuppression(s, 'VG-INJ-004', severity);
      expect(d.suppressed).toBe(false);
      expect(d.overridden).toEqual({ channel: 'config', scope: 'path' });
      // …and would not have been refused before the gate existed.
      expect(legacy(s, 'VG-INJ-004')).toBe(true);
    });
  }

  for (const severity of ['low', 'info'] as const) {
    it(`still honours a rules-omitted entry for ${severity}`, () => {
      const s = suppressionsForPath(wildcardCfg, 'samples/a.py', now);
      const d = evaluatePathSuppression(s, 'VG-INJ-004', severity);
      expect(d.suppressed).toBe(true);
      expect(d.overridden).toBeUndefined();
      expect(legacy(s, 'VG-INJ-004')).toBe(true);
    });
  }

  it('honours a named rule at critical — the escape hatch', () => {
    const s = suppressionsForPath(explicitCfg, 'samples/a.py', now);
    expect(isPathSuppressed(s, 'VG-INJ-004', 'critical')).toBe(true);
    expect(evaluatePathSuppression(s, 'VG-INJ-004', 'critical').overridden).toBeUndefined();
  });

  it('records nothing when the path does not match at all', () => {
    const s = suppressionsForPath(wildcardCfg, 'src/a.ts', now);
    const d = evaluatePathSuppression(s, 'VG-INJ-004', 'critical');
    expect(d.suppressed).toBe(false);
    expect(d.overridden).toBeUndefined();
  });

  it('lets a named entry win over a wildcard entry on the same path', () => {
    const cfg: VibeguardConfig = {
      suppress: [{ paths: ['samples/**'] }, { paths: ['samples/**'], rules: ['VG-INJ-004'] }],
    };
    const s = suppressionsForPath(cfg, 'samples/a.py', now);
    const d = evaluatePathSuppression(s, 'VG-INJ-004', 'critical');
    expect(d.suppressed).toBe(true);
    expect(d.overridden).toBeUndefined();
  });

  it('does not let an unexpired expires= wildcard through for critical', () => {
    const cfg: VibeguardConfig = { suppress: [{ paths: ['samples/**'], expires: '2099-12-31' }] };
    const s = suppressionsForPath(cfg, 'samples/a.py', now);
    expect(s.has('*')).toBe(true);
    expect(isPathSuppressed(s, 'VG-INJ-004', 'critical')).toBe(false);
    expect(isPathSuppressed(s, 'VG-INJ-004', 'low')).toBe(true);
  });
});

describe('loadConfig', () => {
  it('reads .vibeguardrc.json from the given directory', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-cfg-'));
    try {
      const cfg = { suppress: [{ paths: ['x/**'], rules: ['VG-INJ-004'] }] };
      await writeFile(join(dir, '.vibeguardrc.json'), JSON.stringify(cfg));
      const loaded = await loadConfig(dir);
      expect(loaded?.config.suppress?.[0]?.paths).toEqual(['x/**']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('returns undefined when no config exists', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-cfg-'));
    try {
      const loaded = await loadConfig(dir);
      expect(loaded).toBeUndefined();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('respects an explicit path override', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-cfg-'));
    try {
      const explicit = join(dir, 'custom.json');
      await writeFile(explicit, JSON.stringify({ suppress: [{ paths: ['y/**'] }] }));
      const loaded = await loadConfig(dir, explicit);
      expect(loaded?.filePath).toBe(explicit);
      expect(loaded?.config.suppress?.[0]?.paths).toEqual(['y/**']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('throws a helpful error when the file is malformed JSON', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-cfg-'));
    try {
      await writeFile(join(dir, '.vibeguardrc.json'), '{ not json');
      await expect(loadConfig(dir)).rejects.toThrow(/not valid JSON/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
