import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  parseSizeOutput,
  computeFootprint,
  probeArmToolchain,
  measureFootprint,
  measureAll,
  formatDelta,
  renderFootprint,
  renderMarkdownTable,
  type FixPair,
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

// ── the table layer ───────────────────────────────────────────────────────────

const pair = (over: Partial<FixPair> = {}): FixPair => ({
  id: 'VG-EMB-020',
  label: 'Set the debug define to 0',
  source: 'fixer-output',
  before: 'before',
  after: 'after',
  ...over,
});

describe('measureAll — the whole table is null when the toolchain is absent', () => {
  const enoentSpawn: SpawnLike = () => ({ status: null, stdout: '', error: { code: 'ENOENT' } });

  const PAIRS: FixPair[] = [
    pair({ id: 'VG-EMB-020' }),
    pair({ id: 'VG-EMB-021' }),
    pair({ id: 'VG-EMB-011', extraFlags: ['-DX=1'] }),
    pair({ id: 'VG-EMB-010' }),
    pair({ id: 'VG-RTOS-004' }),
    pair({ id: 'VG-MEM-002', source: 'hand-written' }),
  ];

  it('every row is all-null with reason toolchain-absent, and nothing is compiled', () => {
    const rows = measureAll(PAIRS, {
      probe: () => probeArmToolchain(enoentSpawn),
      compileAndSize: () => {
        throw new Error('compileAndSize must not run without a toolchain');
      },
    });
    expect(rows).toHaveLength(PAIRS.length);
    for (const { footprint } of rows) {
      expect(footprint.flashDelta).toBeNull();
      expect(footprint.ramDelta).toBeNull();
      expect(footprint.measuredWith).toBeNull();
      expect(footprint.reason).toBe('toolchain-absent');
    }
  });

  it('renders every row as "not measured", with no bare 0 B anywhere', () => {
    const md = renderMarkdownTable(
      measureAll(PAIRS, {
        probe: () => probeArmToolchain(enoentSpawn),
        compileAndSize: () => null,
      }),
    );
    expect(md.match(/not measured \(toolchain-absent\)/g)).toHaveLength(PAIRS.length * 2);
    expect(md).not.toMatch(/\|\s*[+-]?0 B\s*\|/);
  });

  it('probes once for the whole table, so all rows share one instrument', () => {
    let probes = 0;
    measureAll(PAIRS, {
      probe: () => {
        probes++;
        return probeArmToolchain(enoentSpawn);
      },
      compileAndSize: () => null,
    });
    expect(probes).toBe(1);
  });
});

describe('measureAll — a missing after side is our abstention, not a compiler failure', () => {
  const okSpawn: SpawnLike = () => ({ status: 0, stdout: 'GNU size (Arm GNU Toolchain) 13.2\n' });

  it('reports no-fix-produced even when the toolchain is present', () => {
    const rows = measureAll([pair({ after: null, whyNoAfter: 'no-fix-produced' })], {
      probe: () => probeArmToolchain(okSpawn),
      compileAndSize: () => {
        throw new Error('nothing to compile');
      },
    });
    expect(rows[0]!.footprint.reason).toBe('no-fix-produced');
    expect(rows[0]!.footprint.flashDelta).toBeNull();
    expect(rows[0]!.footprint.measuredWith).toBeNull();
  });

  it('keeps not-applicable distinct from no-fix-produced', () => {
    const rows = measureAll([pair({ after: null, whyNoAfter: 'not-applicable' })], {
      probe: () => probeArmToolchain(okSpawn),
      compileAndSize: () => null,
    });
    expect(rows[0]!.footprint.reason).toBe('not-applicable');
  });

  it('passes extraFlags to both sides, identically', () => {
    const seen: (readonly string[] | undefined)[] = [];
    measureAll([pair({ extraFlags: ['-DA=1', '-DB=2'] })], {
      probe: () => probeArmToolchain(okSpawn),
      compileAndSize: (_src, flags) => {
        seen.push(flags);
        return { text: 10, data: 0, bss: 0 };
      },
    });
    expect(seen).toEqual([
      ['-DA=1', '-DB=2'],
      ['-DA=1', '-DB=2'],
    ]);
  });
});

describe('a measured zero is a result, not a missing measurement', () => {
  it('formats a measured 0 as "+0 B" and never as "not measured"', () => {
    const fp = computeFootprint({ text: 40, data: 0, bss: 4 }, { text: 40, data: 0, bss: 4 }, 'GNU size 2.42');
    expect(formatDelta(fp, fp.flashDelta)).toBe('+0 B');
    expect(formatDelta(fp, fp.ramDelta)).toBe('+0 B');
    expect(renderFootprint(fp)).not.toContain('not measured');
  });

  it('formats null as not measured even next to measured rows in the same table', () => {
    const rows = [
      { pair: pair({ id: 'measured' }), footprint: computeFootprint({ text: 40, data: 0, bss: 0 }, { text: 40, data: 0, bss: 0 }, 'GNU size 2.42') },
      { pair: pair({ id: 'skipped', after: null, whyNoAfter: 'no-fix-produced' as const }), footprint: { flashDelta: null, ramDelta: null, measuredWith: null, reason: 'no-fix-produced' as const } },
    ];
    const md = renderMarkdownTable(rows);
    expect(md).toContain('| measured | Set the debug define to 0 | +0 B | +0 B | GNU size 2.42 |');
    expect(md).toContain('| skipped | Set the debug define to 0 | not measured (no-fix-produced) | not measured (no-fix-produced) | — |');
  });
});

describe('renderMarkdownTable keeps hand-written pairs out of the fixer-output table', () => {
  const fp = computeFootprint({ text: 100, data: 0, bss: 0 }, { text: 124, data: 0, bss: 0 }, 'GNU size 2.42');
  const md = renderMarkdownTable([
    { pair: pair({ id: 'VG-EMB-010', label: 'Use https for the endpoint' }), footprint: fp },
    { pair: pair({ id: 'VG-MEM-002', label: 'strcpy → snprintf', source: 'hand-written', note: 'no fixer exists' }), footprint: fp },
  ]);

  it('puts them under a heading that says they are not fixer output', () => {
    const cut = md.indexOf('hand-written, NOT fixer output');
    expect(cut).toBeGreaterThan(-1);
    expect(md.slice(0, cut)).toContain('VG-EMB-010');
    expect(md.slice(0, cut)).not.toContain('VG-MEM-002');
    expect(md.slice(cut)).toContain('VG-MEM-002');
  });

  it('renders notes below the tables', () => {
    expect(md).toContain('- **VG-MEM-002** — no fixer exists');
  });
});

// The specimens live in scripts/emb-fix-footprint.mjs (they need the real rule
// table and the real fixers, neither of which this package should import at test
// time). What this package CAN own is the reproducibility contract they must
// satisfy, so the check reads the script as text rather than importing it — the
// script imports built `dist/`, and no test here may depend on a build.
describe('specimen reproducibility contract', () => {
  const scriptPath = join(dirname(fileURLToPath(import.meta.url)), '../../../scripts/emb-fix-footprint.mjs');
  const src = readFileSync(scriptPath, 'utf8');
  const BEGIN = '>>> SPECIMENS BEGIN';
  const END = '<<< SPECIMENS END';

  it('marks the specimen region so this check knows what to look at', () => {
    expect(src.indexOf(BEGIN), `missing "${BEGIN}" marker in ${scriptPath}`).toBeGreaterThan(-1);
    expect(src.indexOf(END)).toBeGreaterThan(src.indexOf(BEGIN));
  });

  it('contains no build-varying predefined macro', () => {
    const region = src.slice(src.indexOf(BEGIN), src.indexOf(END));
    // __FILE__ embeds a mkdtemp path, __DATE__/__TIME__/__TIMESTAMP__ embed the
    // clock, __COUNTER__ embeds translation order: any of them makes .rodata (and
    // therefore the flash delta) change between two runs of the same specimen, so
    // a number measured today could not be reproduced tomorrow.
    for (const macro of ['__FILE__', '__DATE__', '__TIME__', '__TIMESTAMP__', '__COUNTER__']) {
      expect(region, `${macro} must not appear in a specimen`).not.toContain(macro);
    }
  });
});
