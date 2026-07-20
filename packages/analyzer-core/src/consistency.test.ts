// vibeguard:disable-file VG-AUTH-004 VG-INJ-004 VG-INJ-006 VG-SEC-001
// Test fixtures contain intentional vulnerable code to exercise the rules.
//
// Paper item ② — cross-channel judgment consistency (the empirical backbone of
// E1). VibeGuard ships one analysis engine behind four delivery channels:
//
//   Channel            Entry point used                         Exercised here
//   ----------------   --------------------------------------   --------------
//   Chrome extension   `scan`   from `./browser.js`             yes
//   VS Code extension  `new Analyzer().scan` from `./analyzer`  yes
//   CLI / GitHub Action`scanPath` from `./file-scanner.js`      yes
//
// All three funnel into the same `Analyzer.scan`, so for a given input they must
// emit identical findings. This test proves that empirically rather than by the
// "single dependency in the graph" structural argument E1 currently rests on.
// The only per-finding field that legitimately differs is `findingId` (a
// non-deterministic counter), which we strip before comparing. Node-side
// `scanPath` additionally supports config-file path suppression, which the
// browser path has no concept of — we pass `config: false` so the comparison is
// of the detection cores, not of a feature only one side has.
import { mkdtemp, writeFile, rm, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { Finding, ScanRequest } from '@vibeguard/findings-schema';
import { scan as scanBrowser } from './browser.js';
import { Analyzer } from './analyzer.js';
import { scanPath } from './file-scanner.js';

const TEMP_DIRS: string[] = [];
afterEach(async () => {
  while (TEMP_DIRS.length) {
    const d = TEMP_DIRS.pop()!;
    try {
      await rm(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

async function makeRepo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-consistency-'));
  TEMP_DIRS.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, 'utf8');
  }
  return dir;
}

/** Strip the non-deterministic findingId and order findings canonically. */
function canonical(findings: Finding[]): Omit<Finding, 'findingId'>[] {
  return findings
    .map(({ findingId, ...rest }) => rest)
    .sort(
      (a, b) =>
        (a.filePath ?? '').localeCompare(b.filePath ?? '') ||
        a.ruleId.localeCompare(b.ruleId) ||
        (a.startLine ?? 0) - (b.startLine ?? 0) ||
        (a.startColumn ?? 0) - (b.startColumn ?? 0),
    );
}

/** Run the browser-path `scan` over a set of in-memory files, like Chrome would. */
function scanBrowserFiles(files: Record<string, string>): Finding[] {
  const out: Finding[] = [];
  for (const [name, content] of Object.entries(files)) {
    const req: ScanRequest = { targetType: 'file', content, filePath: name, mode: 'standard' };
    out.push(...scanBrowser(req).findings);
  }
  return out;
}

const FIXTURE: Record<string, string> = {
  // Multiple categories incl. secrets (masking) and a docstring/comment so the
  // context-window confidence layer (item ①) is exercised on both paths too.
  'app.js': [
    'const AWS = "AKIAIOSFODNN7EXAMPLE";',
    'function go(input, el, data) {',
    '  // el.innerHTML = data; (example in a comment, should be down-ranked)',
    '  el.innerHTML = data;',
    '  return eval(input);',
    '}',
  ].join('\n'),
  'settings.py': [
    '"""',
    'Example:',
    '    DEBUG = True',
    '"""',
    'DEBUG = True',
    'import requests',
    'requests.get(url, verify=False)',
  ].join('\n'),
};

describe('cross-channel consistency (paper item ②)', () => {
  it('Chrome (browser scan), VS Code (Analyzer.scan) and CLI (scanPath) agree on a fixture', async () => {
    const browser = canonical(scanBrowserFiles(FIXTURE));

    // VS Code channel: a long-lived Analyzer instance, scanned file-by-file.
    const analyzer = new Analyzer();
    const vscode = canonical(
      Object.entries(FIXTURE).flatMap(([name, content]) =>
        analyzer.scan({ targetType: 'file', content, filePath: name, mode: 'standard' }).findings,
      ),
    );

    // CLI / Action channel: real files on disk, config discovery disabled.
    const dir = await makeRepo(FIXTURE);
    const cli = canonical((await scanPath(dir, { mode: 'standard', config: false })).findings);

    expect(browser.length).toBeGreaterThan(0);
    expect(vscode).toEqual(browser);
    expect(cli).toEqual(browser);
  });

  it('browser scan and node scanPath agree on every finding across samples/vulnerable', async () => {
    const corpus = fileURLToPath(new URL('../../../samples/vulnerable/', import.meta.url));

    // Node path: the real CLI/Action engine over the directory.
    const node = canonical((await scanPath(corpus, { mode: 'standard', config: false })).findings);

    // Browser path: read each file and feed its content to the fs-free `scan`,
    // labelling it with the same relative path the node path reports.
    const files: Record<string, string> = {};
    for (const name of await readdir(corpus)) {
      files[name] = await readFile(join(corpus, name), 'utf8');
    }
    const browser = canonical(scanBrowserFiles(files));

    expect(node.length).toBeGreaterThan(0);
    expect(browser.length).toBe(node.length);
    expect(browser).toEqual(node);
  });
});
