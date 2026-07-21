import { describe, expect, it } from 'vitest';
import {
  parseSizeOutput,
  computeFootprint,
  probeArmToolchain,
  measureFootprint,
  renderFootprint,
  type SpawnLike,
} from './footprint.js';

describe('parseSizeOutput', () => {
  it('parses a Berkeley size table', () => {
    const out = '   text\t   data\t    bss\t    dec\t    hex\tfilename\n    916\t      4\t      8\t    928\t    3a0\ta.o\n';
    expect(parseSizeOutput(out)).toEqual({ text: 916, data: 4, bss: 8 });
  });
  it('returns null when there is no data row', () => {
    expect(parseSizeOutput('no numbers here\n')).toBeNull();
  });
});

describe('computeFootprint arithmetic', () => {
  it('flash = Δ(text+data), ram = Δ(data+bss)', () => {
    const fp = computeFootprint(
      { text: 900, data: 4, bss: 8 },
      { text: 940, data: 4, bss: 12 },
      'arm-none-eabi-size 2.40',
    );
    expect(fp.flashDelta).toBe(40); // (940+4) - (900+4)
    expect(fp.ramDelta).toBe(4); // (4+12) - (4+8)
    expect(fp.measuredWith).toBe('arm-none-eabi-size 2.40');
  });
});

describe('toolchain-absent honesty (the default path)', () => {
  const enoentSpawn: SpawnLike = () => ({ status: null, stdout: '', error: { code: 'ENOENT' } });

  it('probe reports absent and no version when the binary is missing', () => {
    expect(probeArmToolchain(enoentSpawn)).toEqual({ present: false, version: null });
  });

  it('measureFootprint returns an all-null footprint with reason, never a number', () => {
    const fp = measureFootprint('before', 'after', {
      probe: () => probeArmToolchain(enoentSpawn),
      // must never be called when the toolchain is absent
      compileAndSize: () => {
        throw new Error('compileAndSize must not run without a toolchain');
      },
    });
    expect(fp.flashDelta).toBeNull();
    expect(fp.ramDelta).toBeNull();
    expect(fp.measuredWith).toBeNull();
    expect(fp.reason).toBe('toolchain-absent');
  });

  it('renders a null delta as "not measured", never as 0 B', () => {
    const rendered = renderFootprint({
      flashDelta: null,
      ramDelta: null,
      measuredWith: null,
      reason: 'toolchain-absent',
    });
    expect(rendered).toContain('not measured (toolchain-absent)');
    expect(rendered).not.toMatch(/\b0 B\b/);
  });
});

describe('toolchain-present path (injected)', () => {
  const okSpawn: SpawnLike = () => ({ status: 0, stdout: 'GNU size (Arm GNU Toolchain) 13.2\n' });

  it('measures a real delta when compile+size succeed', () => {
    const sizes = [
      { text: 900, data: 0, bss: 0 },
      { text: 916, data: 0, bss: 0 },
    ];
    let i = 0;
    const fp = measureFootprint('strcpy', 'snprintf', {
      probe: () => probeArmToolchain(okSpawn),
      compileAndSize: () => sizes[i++]!,
    });
    expect(fp.flashDelta).toBe(16);
    expect(fp.measuredWith).toBe('GNU size (Arm GNU Toolchain) 13.2');
    expect(fp.reason).toBeUndefined();
  });

  it('returns compile-failed (null) when a side does not compile', () => {
    const fp = measureFootprint('a', 'b', {
      probe: () => probeArmToolchain(okSpawn),
      compileAndSize: () => null,
    });
    expect(fp.flashDelta).toBeNull();
    expect(fp.reason).toBe('compile-failed');
  });
});
