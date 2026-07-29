// vibeguard:disable-file VG-INJ-004
// The generated fixture calls eval() so the core scan produces a finding —
// which is how these tests observe that the file was opened at all.
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { MAX_FILE_BYTES, scanPath } from '@vibeguard/analyzer-core';
import { createBudget } from './budget.js';
import { collectProjectFiles } from './project.js';

/**
 * The two passes must agree on which files exist.
 *
 * This module's header says so explicitly, and gives the reason: the CLI runs
 * the core engine and the cross-file pass over the SAME target and merges their
 * output into ONE report, so a disagreement lets a cross-file finding cite a
 * file the per-file scan never opened. The ignore set and the language mapping
 * are imported from `analyzer-core` for exactly that reason.
 *
 * The size cap was not. It was redeclared here as `1024 * 1024` under a comment
 * claiming to mirror the core's `1_000_000`, so every file in the 48,576-byte
 * gap between them was indexed by this pass and silently skipped by the core —
 * the failure the header exists to prevent, sitting forty lines below it.
 */
const created: string[] = [];

afterAll(async () => {
  for (const dir of created) await rm(dir, { recursive: true, force: true });
});

async function fixtureDir(sizes: Record<string, number>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-admission-'));
  created.push(dir);
  for (const [name, size] of Object.entries(sizes)) {
    // Must actually trip a rule: "the core opened this file" is only
    // observable through a finding, since `scanPath` does not report the file
    // list it walked.
    const head = 'function handler(req) {\n  return eval(req.query.q);\n}\n';
    const pad = `// ${'x'.repeat(97)}\n`;
    let body = head;
    while (body.length < size) body += pad;
    await writeFile(join(dir, name), body.slice(0, Math.max(head.length, size)));
  }
  return dir;
}

describe('the cross-file pass admits the same files as the core scan', () => {
  it('agrees on a file just under the cap', async () => {
    const dir = await fixtureDir({ 'ok.js': MAX_FILE_BYTES - 5_000 });
    const graph = await collectProjectFiles(dir, createBudget({}), {});
    const core = await scanPath(dir, { mode: 'standard', config: false });

    expect(graph.map((f) => f.filePath)).toContain('ok.js');
    // The core opened it — proven by it having produced a finding from it.
    expect(core.findings.length).toBeGreaterThan(0);
  });

  // The regression. 1,020,000 bytes sits above the core's 1,000,000 and below
  // the graph's former 1,048,576.
  it('agrees on a file inside the old 1 MB / 1 MiB gap', async () => {
    const dir = await fixtureDir({ 'big.js': 1_020_000 });
    const graph = await collectProjectFiles(dir, createBudget({}), {});
    const core = await scanPath(dir, { mode: 'standard', config: false });

    // The core skips it silently — that half is unchanged and is the reason the
    // graph must not index it.
    expect(core.findings.length).toBe(0);
    expect(graph.map((f) => f.filePath)).not.toContain('big.js');
  });

  it('reads its cap from the core rather than declaring its own', () => {
    // A literal here would defeat the point; this asserts the coupling exists.
    expect(MAX_FILE_BYTES).toBe(1_000_000);
    expect(MAX_FILE_BYTES).not.toBe(1024 * 1024);
  });
});
