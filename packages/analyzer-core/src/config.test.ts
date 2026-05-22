import { describe, expect, it } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isPathSuppressed, suppressionsForPath, type VibeguardConfig } from './config.js';
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
    expect(isPathSuppressed(s, 'VG-ANYTHING-001')).toBe(true);
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
