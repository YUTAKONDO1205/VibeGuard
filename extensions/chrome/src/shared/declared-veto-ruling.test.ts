// The fixture imports `expresss`, a deliberate misspelling of `express` — the
// exact shape VG-AISC-001 reports, and the finding this channel deliberately
// does NOT try to refute. It is a string in a test literal, never installed and
// never executed, and it needs no suppression of its own: `.vibeguardrc.json`
// already excuses VG-AISC-001 across `**/*.test.ts` by path and by rule id.
//
// ── THE RULING THIS FILE PINS ─────────────────────────────────────────────
//
// Three of the four channels answer VG-AISC-001 with the project's lockfile:
// if the name resolved, the finding was wrong and is removed (§17z-b). Chrome
// does not, and must not — the argument is in `block-scan.ts`, and it comes down
// to there being no lockfile behind a web page and no way to get one without
// sending the user's code to a registry, which is the one thing a zero-egress
// extension may never do.
//
// A ruling is only worth what pins it. Three things are checked here:
//
//   1. the request this channel builds carries no `declaredPackages`;
//   2. the response it produces says the veto DID NOT RUN — an absent
//      `declaredPackageVetoes`, distinct from the `[]` the other channels emit
//      when they checked and removed nothing;
//   3. nothing in `extensions/chrome/src` imports the Node-only reader (or any
//      other `node:` builtin), which is how the ruling would be broken in
//      practice — by someone copying an import that works in the VS Code
//      extension into the one that ships to a browser.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scan, detectLanguageFromContent } from '@vibeguard/analyzer-core/browser';
import type { ScanResponse } from '@vibeguard/findings-schema';
import { scanBlocks, type ScanBlocksDeps } from './block-scan.js';

const HALLUCINATED = 'const e = require("expresss");\nmodule.exports = e;\n';

describe('the Chrome channel never asks for a declared-package veto', () => {
  it('builds a scan request with no declaredPackages field at all', () => {
    const seen: Record<string, unknown>[] = [];
    const deps: ScanBlocksDeps = {
      scan: (req) => {
        seen.push(req as unknown as Record<string, unknown>);
        return scan(req);
      },
      detectLanguageFromContent,
    };

    scanBlocks([{ text: HALLUCINATED, language: 'javascript' }], deps);

    expect(seen).toHaveLength(1);
    // Exact key set, not just "declaredPackages is undefined": a request that
    // grew the field with an empty value would still be a channel that started
    // making claims about a project it cannot see.
    expect(Object.keys(seen[0]!).sort()).toEqual([
      'content',
      'filePath',
      'language',
      'mode',
      'targetType',
    ]);
  });

  it('reports the hallucinated-dependency finding, because it has nothing to refute it with', () => {
    // The honest cost of the ruling, asserted rather than left implicit: this
    // channel has a known false-positive rate on near-miss package names that
    // the reader's own project may well have installed.
    const results = scanBlocks([{ text: HALLUCINATED, language: 'javascript' }], {
      scan: (req) => scan(req),
      detectLanguageFromContent,
    });
    expect(results[0]!.findings.filter((f) => f.ruleId === 'VG-AISC-001')).toHaveLength(1);
  });

  it('says the veto DID NOT RUN, which is not the same as "ran and found nothing"', () => {
    const response: ScanResponse = scan({
      targetType: 'snippet',
      mode: 'standard',
      content: HALLUCINATED,
      language: 'javascript',
      filePath: 'block 1',
    });
    // Absent — the schema's way of saying no lockfile was ever consulted.
    expect('declaredPackageVetoes' in response).toBe(false);

    // Positive control for the distinction itself: hand the SAME entry point a
    // declared set and the field appears, empty, because the veto then really
    // did run and really did remove nothing. Without this assertion the one
    // above could pass simply because the field never exists anywhere.
    const armed: ScanResponse = scan({
      targetType: 'snippet',
      mode: 'standard',
      content: HALLUCINATED,
      language: 'javascript',
      filePath: 'block 1',
      declaredPackages: ['express'],
    });
    expect(armed.declaredPackageVetoes).toEqual([]);
    expect(armed.findings.some((f) => f.ruleId === 'VG-AISC-001')).toBe(true);
  });
});

/**
 * The structural half. `scripts/check-packaging-invariants.mjs` already refuses
 * `@vibeguard/sarif-adapter/node` on the light side, but its forbidden list is
 * enumerated by hand and is shared with `extensions/vscode/src`, where the
 * analyzer-core equivalent is legitimate — so it cannot be the thing that keeps
 * this particular door shut. This test is that thing, and it lives next to the
 * ruling it enforces.
 *
 * `*.test.ts` is excluded because test files are not bundled: `build.mjs` has
 * exactly two entry points (`src/background.ts` and `src/sidepanel/index.ts`),
 * and this very file reads the filesystem to do its job.
 */
describe('nothing in the Chrome extension can reach a filesystem', () => {
  const SRC = fileURLToPath(new URL('../', import.meta.url));

  function walk(dir: string, out: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) walk(full, out);
      else if (full.endsWith('.ts') && !full.endsWith('.test.ts')) out.push(full);
    }
    return out;
  }

  /** Every `from '…'` / `import('…')` specifier in a source file. */
  function specifiers(text: string): string[] {
    const out: string[] = [];
    const re = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"\n]{1,200})['"]/g;
    for (const m of text.matchAll(re)) out.push(m[1]!);
    return out;
  }

  it('imports no node: builtin and no Node-only analyzer subpath', () => {
    const files = walk(SRC);
    // Vacuous-pass guard: an empty walk would make every assertion below true.
    expect(files.length).toBeGreaterThanOrEqual(4);

    const offences: string[] = [];
    for (const file of files) {
      for (const spec of specifiers(readFileSync(file, 'utf8'))) {
        if (spec.startsWith('node:')) offences.push(`${file} → ${spec}`);
        // The root entry re-exports `scanPath`, which imports `node:fs`; only
        // the `/browser` subpath is safe here.
        if (spec === '@vibeguard/analyzer-core') offences.push(`${file} → ${spec}`);
        if (spec.endsWith('/node')) offences.push(`${file} → ${spec}`);
      }
    }
    expect(offences).toEqual([]);
  });

  it('the sidepanel really does import the browser subpath (positive control)', () => {
    // Proves the extractor above sees the imports it is supposed to be
    // policing, rather than returning nothing on every file.
    const panel = readFileSync(join(SRC, 'sidepanel', 'index.ts'), 'utf8');
    expect(specifiers(panel)).toContain('@vibeguard/analyzer-core/browser');
  });
});
