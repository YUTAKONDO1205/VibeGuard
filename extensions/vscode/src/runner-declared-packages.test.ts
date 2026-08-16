// The fixtures below import `expresss` — a deliberate misspelling of `express`,
// which is exactly the shape VG-AISC-001 reports. They are strings in test
// literals, never installed and never executed. No file-scope suppression is
// needed for them: `.vibeguardrc.json` already excuses VG-AISC-001 (and five
// other input-shaped rules) across `**/*.test.ts`, by path and by rule id,
// because a rule's suite has to contain what the rule matches. The second
// fixture rule used below, VG-CRYPTO-003, is on that same list — deliberately,
// so this file needs no suppression of its own and the repository's file-scope
// pragma census does not move.
//
// ── WHAT THIS FILE IS FOR ─────────────────────────────────────────────────
//
// §17z-b's veto was wired into the CLI and not into the editor. Both channels
// run the same engine, so the disagreement was not in the analysis: the editor
// simply never handed the analyzer the lockfile evidence, so every
// hallucinated-dependency false positive the command line refuted was still
// reported in VS Code. `packages/analyzer-core/src/consistency.test.ts` did not
// catch it, and could not have: it models the VS Code channel as
// `new Analyzer().scan(...)` — which is the engine, not the runner — so a
// missing INPUT is invisible to it. This file scans through the real
// `ScanRunner`, with `vscode` mocked, because the defect lived in the glue that
// the model skipped over.
//
// The comparison leg runs the CLI's own path — `readDeclaredPackages` then
// `scanPath` with the names and source it returned — which is line for line
// what `apps/cli/src/index.ts` does.
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { scanPath } from '@vibeguard/analyzer-core';
import { readDeclaredPackages } from '@vibeguard/analyzer-core/node';
import type { DeclaredPackageVetoRecord, Finding } from '@vibeguard/findings-schema';
// Static, even though it must be evaluated after the `vi.mock('vscode')` below:
// Vitest hoists mock factories above every import in the module, which is the
// whole reason the pattern works. A dynamic `await import` would also work and
// would additionally require top-level await, which this package (CommonJS
// output, `--format=cjs`) does not have.
import { ScanRunner } from './runner.js';

/**
 * Mutable state the mocked `vscode` reads. `vi.mock` factories are hoisted
 * above every other statement, so anything they close over has to come from
 * `vi.hoisted`.
 */
const host = vi.hoisted(() => ({
  /** What `workspace.getWorkspaceFolder` returns — the opened folder, or none. */
  folder: undefined as undefined | { uri: { scheme: string; fsPath: string } },
}));

vi.mock('vscode', () => {
  class EventEmitter<T> {
    private handlers: ((e: T) => void)[] = [];
    event = (h: (e: T) => void): { dispose(): void } => {
      this.handlers.push(h);
      return { dispose: () => undefined };
    };
    fire(e: T): void {
      for (const h of this.handlers) h(e);
    }
    dispose(): void {
      this.handlers = [];
    }
  }
  class Range {
    constructor(
      public startLine: number,
      public startCol: number,
      public endLine: number,
      public endCol: number,
    ) {}
  }
  class Diagnostic {
    code?: unknown;
    source?: string;
    constructor(
      public range: Range,
      public message: string,
      public severity?: number,
    ) {}
  }
  return {
    EventEmitter,
    Range,
    Diagnostic,
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    workspace: {
      getWorkspaceFolder: () => host.folder,
    },
  };
});

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
beforeEach(() => {
  host.folder = undefined;
});

async function makeRepo(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-vscode-declared-'));
  TEMP_DIRS.push(dir);
  for (const [name, content] of Object.entries(files)) {
    const full = join(dir, name);
    const slash = name.lastIndexOf('/');
    if (slash >= 0) await mkdir(join(dir, name.slice(0, slash)), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return dir;
}

/** A `package-lock.json` (v3) that resolves exactly the names given. */
const lockWith = (...names: string[]): string =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: Object.fromEntries([
      ['', {}],
      ...names.map((n) => [`node_modules/${n}`, { version: '1.0.0' }]),
    ]),
  });

const HALLUCINATED = 'const e = require("expresss");\nmodule.exports = e;\n';

/** Minimal stand-ins for the two vscode objects the runner touches. */
function fakeDoc(fsPath: string, text: string): any {
  const lines = text.split('\n');
  return {
    uri: {
      scheme: 'file',
      fsPath,
      toString: () => `file://${fsPath.replace(/\\/g, '/')}`,
    },
    getText: () => text,
    lineCount: lines.length,
    lineAt: (n: number) => ({ text: lines[Math.min(n, lines.length - 1)] ?? '' }),
  };
}

function fakeCollection(): any {
  return { set: () => undefined, delete: () => undefined, dispose: () => undefined };
}

function makeRunner(warn?: (m: string) => void): ScanRunner {
  return new ScanRunner(fakeCollection(), warn ? { warn } : {});
}

/**
 * Both channels report the same finding under a different LABEL: the CLI names
 * a file relative to the scan target, the editor names it by absolute path
 * (`doc.uri.fsPath`, which is what a diagnostic needs). That difference
 * predates the veto and is not what this file is about, so the comparison
 * normalises the label to a target-relative POSIX path and then compares
 * everything else — severity, rule, line, column, snippet, confidence —
 * exactly.
 */
function relPosix(p: string, root: string): string {
  const norm = (s: string): string => s.replace(/\\/g, '/');
  const r = norm(root).replace(/\/+$/, '');
  const f = norm(p);
  return f.startsWith(`${r}/`) ? f.slice(r.length + 1) : f;
}

function canonicalFindings(findings: Finding[], root: string): unknown[] {
  return findings
    .map(({ findingId, filePath, ...rest }) => ({
      ...rest,
      filePath: filePath === undefined ? undefined : relPosix(filePath, root),
    }))
    .sort(
      (a, b) =>
        (a.filePath ?? '').localeCompare(b.filePath ?? '') ||
        a.ruleId.localeCompare(b.ruleId) ||
        (a.startLine ?? 0) - (b.startLine ?? 0) ||
        (a.startColumn ?? 0) - (b.startColumn ?? 0),
    );
}

function canonicalVetoes(vetoes: DeclaredPackageVetoRecord[], root: string): unknown[] {
  return vetoes
    .map((v) => ({
      ...v,
      filePath: v.filePath === undefined ? undefined : relPosix(v.filePath, root),
    }))
    .sort((a, b) => a.ruleId.localeCompare(b.ruleId) || a.packageName.localeCompare(b.packageName));
}

/** The CLI's path, as `apps/cli/src/index.ts` runs it. */
async function cliScan(target: string) {
  const declared = await readDeclaredPackages(target);
  return scanPath(target, {
    mode: 'standard',
    config: false,
    declaredPackages: declared.packages,
    declaredPackageSource: declared.sources.map((x) => x.file).join(', ') || undefined,
  });
}

describe('the editor applies the declared-package veto (★ positive control)', () => {
  it('drops the hallucinated-dependency finding and records why', async () => {
    const dir = await makeRepo({
      'package-lock.json': lockWith('expresss'),
      'app.js': HALLUCINATED,
    });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(runner.getFindings(doc.uri).some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);
    expect(canonicalVetoes(runner.getAllDeclaredPackageVetoes(), dir)).toEqual([
      {
        ruleId: 'VG-AISC-001',
        packageName: 'expresss',
        filePath: 'app.js',
        count: 1,
        source: 'package-lock.json',
      },
    ]);
  });

  it('the same file WITHOUT the lockfile still reports it (the control for the control)', async () => {
    // Without this, a veto that fired for the wrong reason — or a rule that
    // simply stopped matching — would look identical to the case above.
    const dir = await makeRepo({ 'app.js': HALLUCINATED });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(runner.getFindings(doc.uri).filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
    expect(runner.getAllDeclaredPackageVetoes()).toEqual([]);
    // Nothing armed the veto, so the export must not claim it ran.
    expect(runner.declaredPackageVetoRan()).toBe(false);
  });
});

describe('the editor does not over-veto (★ true-positive preservation)', () => {
  it('a lockfile that does NOT declare the name leaves the finding standing', async () => {
    // `express` is installed; `expresss` is what the code imports. This is the
    // real slopsquat shape, and it is the case a veto keyed on "looks like a
    // package name" instead of "this exact name resolved" would destroy.
    const dir = await makeRepo({
      'package-lock.json': lockWith('express', 'lodash'),
      'app.js': HALLUCINATED,
    });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(runner.getFindings(doc.uri).filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
    expect(runner.getAllDeclaredPackageVetoes()).toEqual([]);
    // ARMED and fired nothing — a different fact from the previous test's
    // "never armed", and the distinction the export carries as `[]` versus an
    // absent field.
    expect(runner.declaredPackageVetoRan()).toBe(true);
  });

  it('leaves findings from rules that name no package alone', async () => {
    // The veto is keyed on `variables.package`, which only a rule about a
    // package name sets. A veto that reached further would delete unrelated
    // findings whenever a project happened to declare the right name — so the
    // second finding here has to survive the same scan that removes the first.
    // The second fixture is a plaintext-HTTP URL (VG-CRYPTO-003) pointing at a
    // `.invalid` host, which by RFC 2606 can never resolve — a rule fixture,
    // not a reachable endpoint.
    const content = `${HALLUCINATED}const api = "http://example.invalid/api";\n`;
    const dir = await makeRepo({ 'package-lock.json': lockWith('expresss'), 'app.js': content });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), content);
    await runner.scanDocument(doc, 'standard');

    const ids = runner.getFindings(doc.uri).map((f) => f.ruleId);
    expect(ids).not.toContain('VG-AISC-001');
    expect(ids).toContain('VG-CRYPTO-003');
  });
});

describe('★ parity: the editor and the CLI answer the same project identically', () => {
  it('agrees on findings AND on veto records when the lockfile refutes the import', async () => {
    const files = {
      'package-lock.json': lockWith('expresss'),
      'app.js': HALLUCINATED,
    };
    const dir = await makeRepo(files);
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const cli = await cliScan(dir);

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(canonicalFindings(runner.getFindings(doc.uri), dir)).toEqual(
      canonicalFindings(cli.findings, dir),
    );
    expect(canonicalVetoes(runner.getAllDeclaredPackageVetoes(), dir)).toEqual(
      canonicalVetoes(cli.declaredPackageVetoes ?? [], dir),
    );
    // Not a vacuous agreement: both sides really did remove something.
    expect(cli.declaredPackageVetoes).toHaveLength(1);
  });

  it('agrees when the lockfile refutes nothing (both keep the finding)', async () => {
    const files = {
      'package-lock.json': lockWith('express'),
      'app.js': HALLUCINATED,
    };
    const dir = await makeRepo(files);
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const cli = await cliScan(dir);

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(canonicalFindings(runner.getFindings(doc.uri), dir)).toEqual(
      canonicalFindings(cli.findings, dir),
    );
    expect(cli.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(true);
    // Both channels say "armed, removed nothing" rather than "never checked".
    expect(cli.declaredPackageVetoes).toEqual([]);
    expect(runner.declaredPackageVetoRan()).toBe(true);
    expect(runner.getAllDeclaredPackageVetoes()).toEqual([]);
  });

  it('agrees on a project with no lockfile at all', async () => {
    const dir = await makeRepo({ 'app.js': HALLUCINATED });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const cli = await cliScan(dir);
    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(canonicalFindings(runner.getFindings(doc.uri), dir)).toEqual(
      canonicalFindings(cli.findings, dir),
    );
    expect('declaredPackageVetoes' in cli).toBe(false);
    expect(runner.declaredPackageVetoRan()).toBe(false);
  });

  it('agrees when the lockfile is a poetry.lock and the import is Python', async () => {
    // The reader handles six formats; parity must not be a fact about npm.
    const py = 'import requestss\n';
    const dir = await makeRepo({
      'poetry.lock': '[[package]]\nname = "requestss"\nversion = "2.31.0"\n',
      'app.py': py,
    });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const cli = await cliScan(dir);
    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.py'), py);
    await runner.scanDocument(doc, 'standard');

    expect(canonicalVetoes(runner.getAllDeclaredPackageVetoes(), dir)).toEqual(
      canonicalVetoes(cli.declaredPackageVetoes ?? [], dir),
    );
    expect(cli.declaredPackageVetoes).toEqual([
      {
        ruleId: 'VG-AISC-001',
        packageName: 'requestss',
        filePath: 'app.py',
        count: 1,
        source: 'poetry.lock',
      },
    ]);
  });
});

describe('which lockfile applies to a document', () => {
  it('uses the workspace folder, so a file in src/ is covered by the root lockfile', async () => {
    const dir = await makeRepo({
      'package-lock.json': lockWith('expresss'),
      'src/app.js': HALLUCINATED,
    });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'src', 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(runner.getFindings(doc.uri).some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);
    expect(runner.getAllDeclaredPackageVetoes()).toHaveLength(1);
  });

  it('falls back to the document directory when it belongs to no folder', async () => {
    // A loose file opened outside any workspace is `vibeguard path/to/file` —
    // and that CLI invocation searches the file's own directory, which here
    // does not contain the lockfile one level up.
    const dir = await makeRepo({
      'package-lock.json': lockWith('expresss'),
      'src/app.js': HALLUCINATED,
    });
    host.folder = undefined;

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'src', 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(runner.getFindings(doc.uri).filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
    expect(runner.declaredPackageVetoRan()).toBe(false);
  });
});

describe('the cached lockfile cannot go stale', () => {
  it('stops vetoing once the package leaves the lockfile', async () => {
    // The editor is long-lived, so the read is cached. A cache with no
    // invalidation would keep silencing a finding about a package the project
    // no longer resolves — a false negative manufactured by the cache, which is
    // the one direction this feature may not fail in.
    const dir = await makeRepo({
      'package-lock.json': lockWith('expresss'),
      'app.js': HALLUCINATED,
    });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');
    expect(runner.getFindings(doc.uri).some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);

    await writeFile(join(dir, 'package-lock.json'), lockWith('express'), 'utf8');
    await runner.scanDocument(doc, 'standard');

    expect(runner.getFindings(doc.uri).filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
    expect(runner.getAllDeclaredPackageVetoes()).toEqual([]);
  });

  it('starts vetoing once a lockfile appears', async () => {
    const dir = await makeRepo({ 'app.js': HALLUCINATED });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');
    expect(runner.getFindings(doc.uri).some((f) => f.ruleId === 'VG-AISC-001')).toBe(true);

    await writeFile(join(dir, 'package-lock.json'), lockWith('expresss'), 'utf8');
    await runner.scanDocument(doc, 'standard');

    expect(runner.getFindings(doc.uri).some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);
  });
});

describe('a lockfile that cannot be parsed is reported, not swallowed', () => {
  it('warns, and still reports the finding it could not refute', async () => {
    const dir = await makeRepo({ 'package-lock.json': '{ not json', 'app.js': HALLUCINATED });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const warnings: string[] = [];
    const runner = makeRunner((m) => warnings.push(m));
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('package-lock.json could not be parsed');
    expect(runner.getFindings(doc.uri).filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
  });

  it('warns once per lockfile state, not once per save', async () => {
    const dir = await makeRepo({ 'package-lock.json': '{ not json', 'app.js': HALLUCINATED });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const warnings: string[] = [];
    const runner = makeRunner((m) => warnings.push(m));
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    await runner.scanDocument(doc, 'standard');
    await runner.scanDocument(doc, 'standard');
    await runner.scanDocument(doc, 'standard');

    expect(warnings).toHaveLength(1);
  });
});

describe('the selection scan gets the same evidence as the file scan', () => {
  it('vetoes inside a selection scan too', async () => {
    // `scanSelection` builds its own request. It is the path that would be
    // forgotten, and the one a user hits from the context menu.
    const dir = await makeRepo({
      'package-lock.json': lockWith('expresss'),
      'app.js': HALLUCINATED,
    });
    host.folder = { uri: { scheme: 'file', fsPath: dir } };

    const runner = makeRunner();
    const doc = fakeDoc(join(dir, 'app.js'), HALLUCINATED);
    const whole = { start: { line: 0 }, end: { line: 1 } } as any;
    const count = await runner.scanSelection(doc, whole, 'standard');

    expect(runner.getFindings(doc.uri).some((f) => f.ruleId === 'VG-AISC-001')).toBe(false);
    expect(runner.getAllDeclaredPackageVetoes()).toHaveLength(1);
    expect(count).toBe(runner.getFindings(doc.uri).length);
  });
});
