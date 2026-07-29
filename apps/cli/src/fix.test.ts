import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { Finding } from '@vibeguard/findings-schema';
import { planFixes, renderFixReport, runFix } from './fix.js';

const dirs: string[] = [];
afterAll(async () => {
  const fs = await import('node:fs/promises');
  await Promise.all(dirs.map((d) => fs.rm(d, { recursive: true, force: true })));
});

async function tmp(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), 'vibeguard-fix-'));
  dirs.push(d);
  return d;
}

/** Minimal Finding with just the fields the fixer wiring reads. */
function finding(
  ruleId: string,
  line: number,
  opts: { col?: number; file?: string } = {},
): Finding {
  return {
    findingId: `${ruleId}@${line}`,
    ruleId,
    title: ruleId,
    description: '',
    severity: 'high',
    confidence: 'high',
    category: 'memory',
    sourceEngine: 'core-rule',
    filePath: opts.file,
    startLine: line,
    endLine: line,
    startColumn: opts.col ?? 1,
    endColumn: opts.col ?? 1,
  };
}

describe('planFixes — single-file target', () => {
  it('builds an edit and new content for a fixable finding', async () => {
    const d = await tmp();
    const file = join(d, 'fw.c');
    await writeFile(file, '#define DEBUG 1\nint main() { return 0; }\n', 'utf8');

    const { plans, unfixable } = await planFixes([finding('VG-EMB-020', 1, { file })], {
      target: file,
      targetIsFile: true,
    });

    expect(unfixable).toBe(0);
    expect(plans).toHaveLength(1);
    expect(plans[0]!.overlapSkipped).toBe(false);
    expect(plans[0]!.newContent).toBe('#define DEBUG 0\nint main() { return 0; }\n');
    expect(plans[0]!.fixes).toEqual([
      { ruleId: 'VG-EMB-020', title: 'Set the debug define to 0', safety: 'safe', line: 1 },
    ]);
  });

  it('does not write in dry-run, writes with --fix', async () => {
    const d = await tmp();
    const file = join(d, 'fw.c');
    const original = 'http.begin("http://api.example.com/x");\n';
    await writeFile(file, original, 'utf8');
    // col 12 is the `"` — where the rule's own pattern starts, and therefore what
    // a real finding carries. The fixer is anchored (B4/A2) and declines when the
    // reported column does not hold the token, so column 1 is no longer a valid
    // stand-in for a detector-produced coordinate.
    const findings = [finding('VG-EMB-010', 1, { file, col: 12 })];

    // dry-run: file untouched
    const dry = await runFix(findings, { target: file, targetIsFile: true }, false);
    expect(dry.code).toBe(0);
    expect(await readFile(file, 'utf8')).toBe(original);
    expect(dry.output).toContain('Would apply');

    // --fix: file rewritten
    const applied = await runFix(findings, { target: file, targetIsFile: true }, true);
    expect(applied.output).toContain('Applied');
    expect(await readFile(file, 'utf8')).toBe('http.begin("https://api.example.com/x");\n');
  });

  it('marks a needs-review fixer in the report', async () => {
    const d = await tmp();
    const file = join(d, 'tls.c');
    await writeFile(file, 'ssl_conf_authmode(&c, MBEDTLS_SSL_VERIFY_NONE);\n', 'utf8');
    const res = await planFixes([finding('VG-EMB-011', 1, { file })], {
      target: file,
      targetIsFile: true,
    });
    expect(res.plans[0]!.fixes[0]!.safety).toBe('needs-review');
    expect(renderFixReport(res, false)).toContain('needs-review');
  });
});

describe('planFixes — directory target', () => {
  it('resolves finding paths relative to the target dir', async () => {
    const d = await tmp();
    await writeFile(join(d, 'a.c'), '#define DEBUG 1\n', 'utf8');
    const { plans } = await planFixes([finding('VG-EMB-020', 1, { file: 'a.c' })], {
      target: d,
      targetIsFile: false,
    });
    expect(plans).toHaveLength(1);
    expect(plans[0]!.displayPath).toBe('a.c');
    expect(plans[0]!.newContent).toBe('#define DEBUG 0\n');
  });
});

describe('planFixes — nothing to fix', () => {
  it('counts a finding with no fixer as unfixable, produces no plan', async () => {
    const d = await tmp();
    const file = join(d, 'x.js');
    // Content is irrelevant here: the finding's rule has no fixer, so buildFix
    // returns null whatever the bytes. Kept benign so the repo self-scan sees
    // nothing (mirrors fixers.test.ts staying at zero critical/high findings).
    await writeFile(file, 'const x = 1;\n', 'utf8');
    const res = await planFixes([finding('VG-INJ-001', 1, { file })], {
      target: file,
      targetIsFile: true,
    });
    expect(res.plans).toHaveLength(0);
    expect(res.unfixable).toBe(1);
    expect(renderFixReport(res, true)).toContain('No auto-fixable findings');
  });

  it('counts a finding with no filePath as unfixable without crashing', async () => {
    const res = await planFixes([finding('VG-EMB-020', 1)], { target: '.', targetIsFile: false });
    expect(res.plans).toHaveLength(0);
    expect(res.unfixable).toBe(1);
  });

  it('a fixer that returns null on this content produces no plan', async () => {
    const d = await tmp();
    const file = join(d, 'x.c');
    // VG-EMB-020's fixer finds no DEBUG define token on this line.
    await writeFile(file, 'int x = 1;\n', 'utf8');
    const res = await planFixes([finding('VG-EMB-020', 1, { file })], {
      target: file,
      targetIsFile: true,
    });
    expect(res.plans).toHaveLength(0);
    expect(res.unfixable).toBe(1);
  });
});

describe('planFixes — overlap safety', () => {
  it('leaves the file untouched when two fixes overlap', async () => {
    const d = await tmp();
    const file = join(d, 'dup.c');
    const original = 'http.begin("http://api.example.com/x");\n';
    await writeFile(file, original, 'utf8');
    // Two identical findings on the same token → identical edits → overlap.
    // Both carry the detector's real column (the `"`); see the anchoring note above.
    const res = await planFixes(
      [finding('VG-EMB-010', 1, { file, col: 12 }), finding('VG-EMB-010', 1, { file, col: 12 })],
      { target: file, targetIsFile: true },
    );
    expect(res.plans).toHaveLength(1);
    expect(res.plans[0]!.overlapSkipped).toBe(true);
    expect(res.plans[0]!.newContent).toBe(original);

    // --fix must not corrupt the file.
    await runFix(
      [finding('VG-EMB-010', 1, { file }), finding('VG-EMB-010', 1, { file })],
      { target: file, targetIsFile: true },
      true,
    );
    expect(await readFile(file, 'utf8')).toBe(original);
  });
});

describe('multiple disjoint fixes in one file', () => {
  it('applies both and reports them in stable order', async () => {
    const d = await tmp();
    const file = join(d, 'multi.c');
    await writeFile(file, '#define DEBUG 1\nfd = open(path, O_DIRECT);\n', 'utf8');
    const applied = await runFix(
      [finding('VG-EMB-020', 1, { file }), finding('VG-RTOS-004', 2, { col: 17, file })],
      { target: file, targetIsFile: true },
      true,
    );
    expect(applied.output).toContain('Applied 2 fix(es)');
    expect(await readFile(file, 'utf8')).toBe(
      '#define DEBUG 0\nfd = open(path, O_DIRECT | O_SYNC);\n',
    );
  });
});
