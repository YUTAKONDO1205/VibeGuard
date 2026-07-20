// Pin test for `ENGINE_VERSION` — the detection-engine version stamped into
// every `ScanResponse` as `engineVersions.core`.
//
// WHY THIS TEST EXISTS
//
// `ENGINE_VERSION` is the field the README's central comparison contract rests
// on: "same engine ⇒ identical verdicts". Nothing in CI defended it. The
// constant lives one line away from `Analyzer`, is imported by five call sites
// across three packages, and looks exactly like the kind of string an agent
// bumps in passing while doing something else ("the package went to 0.2.0, so
// this should too"). That bump would be silent and destructive: every scan
// result emitted afterwards would claim to be a different engine, and every
// before/after comparison spanning the bump would be unfalsifiable, because the
// only machine-readable signal that two runs used the same detector would have
// been changed by hand rather than by a detection change.
//
// The hold at 0.1.0 is itself a decision on the record, not an oversight, and it
// is a decision with a known cost. Several changes have altered detection
// behaviour without a bump:
//
//   D1  / D1b  the severity gate on context-window confidence
//              (`SEVERITY_CONFIDENCE_FLOOR` in @vibeguard/rules) — critical and
//              high findings keep their default confidence in contexts that
//              previously down-ranked them.
//   D2         the canonicalizer pre-pass — rules also run over normalized text,
//              so lexically evaded payloads are now detected. Additive only, but
//              still a behaviour change.
//   D4 / D5    suppression and match-limit changes — a suppression that used to
//              drop a finding may now keep it, and a new `degradations` kind can
//              appear in output.
//
// Each of those would justify a bump on its own. The project deliberately takes
// none of them, so that 0.2.0 eventually names ONE settled engine rather than a
// sequence of partial states (recorded beside the constant in `analyzer.ts`, in
// `CHANGELOG.md`, and in `docs/EVALUATION.md`). The accepted consequence is that
// 0.1.0 currently does NOT satisfy the "same engine ⇒ identical verdicts"
// contract; the `paper-ses-v0.1.3` tag is the sound baseline for any before/after
// comparison until the bump lands. This test's job is to make sure that hold is
// only ever released on purpose.
//
// WHAT TO DO WHEN THIS TEST FAILS
//
// A failure means someone changed `ENGINE_VERSION` (or a doc that quotes it).
// It is NOT automatically a bug — the engine freeze is scheduled to end, and the
// bump to 0.2.0 is expected. If the bump is intentional, update, in one change:
//
//   1. `EXPECTED_ENGINE_VERSION` below.
//   2. `ENGINE_VERSION` in `analyzer.ts`, and the long comment above it — the
//      "KNOWN HAZARD" paragraphs describe debt that a bump discharges, so they
//      must be rewritten, not left to describe a state that no longer exists.
//   3. `README.md` — the "Engine version" row of the Versioning table (the
//      `Current` column) and the prose paragraph below it, which quotes both the
//      value and the sample CLI banner `vibeguard <tool> (engine <engine>)`.
//      Both are asserted here, so a partial doc update fails this test.
//   4. `CHANGELOG.md` — add a NEW entry stating the bump and what detection
//      changes it covers. Do not edit the existing "stays at 0.1.0" entry: past
//      entries are a record of what shipped, and rewriting them would erase the
//      evidence that the hold was a decision.
//
// If the bump was NOT intentional, revert it. The tool version (`package.json`,
// CLI `--version`, SARIF `tool.version`) is the separate axis that moves on every
// release; it is almost always the one that was meant.
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { ENGINE_VERSION, Analyzer } from './analyzer.js';
import { scan as scanBrowser, ENGINE_VERSION as ENGINE_VERSION_BROWSER } from './browser.js';
import { ENGINE_VERSION as ENGINE_VERSION_INDEX } from './index.js';
import { scanPath } from './file-scanner.js';

/**
 * The pinned value. Changing this line is the deliberate act; see the header.
 */
const EXPECTED_ENGINE_VERSION = '0.1.0';

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

describe('ENGINE_VERSION is pinned', () => {
  it('holds the frozen value', () => {
    expect(ENGINE_VERSION).toBe(EXPECTED_ENGINE_VERSION);
  });

  // Both public entry points re-export the constant (`./index.js` for Node
  // consumers, `./browser.js` for the Chrome extension). A refactor that gave
  // either one its own literal would let the channels drift apart while this
  // file still passed, so compare the exported identities, not just the value.
  it('is the same constant on every export surface', () => {
    expect(ENGINE_VERSION_INDEX).toBe(ENGINE_VERSION);
    expect(ENGINE_VERSION_BROWSER).toBe(ENGINE_VERSION);
  });
});

// Pinning the constant alone would be hollow: what consumers actually read is
// `engineVersions.core` on the response. If a response were ever built from a
// literal, or from a package version, the constant could stay at 0.1.0 while the
// emitted field said something else. Each of the three response-construction
// sites in this package is exercised through its real entry point.
describe('ENGINE_VERSION reaches engineVersions.core on every scan path', () => {
  it('Analyzer.scan — normal path (VS Code extension)', () => {
    const r = new Analyzer().scan({
      targetType: 'snippet',
      content: 'const x = 1;\n',
      mode: 'standard',
      filePath: 'a.ts',
    });
    expect(r.engineVersions.core).toBe(EXPECTED_ENGINE_VERSION);
  });

  // The empty-content guard returns early from a SECOND, separately written
  // response literal. It is easy to miss when editing, so it gets its own case.
  it('Analyzer.scan — empty-content early return', () => {
    const r = new Analyzer().scan({
      targetType: 'snippet',
      content: '',
      mode: 'standard',
      filePath: 'a.ts',
    });
    expect(r.findings).toHaveLength(0);
    expect(r.engineVersions.core).toBe(EXPECTED_ENGINE_VERSION);
  });

  it('scan from ./browser.js (Chrome extension)', () => {
    const r = scanBrowser({
      targetType: 'snippet',
      content: 'const x = 1;\n',
      mode: 'standard',
      filePath: 'a.ts',
    });
    expect(r.engineVersions.core).toBe(EXPECTED_ENGINE_VERSION);
  });

  it('scanPath (CLI / GitHub Action)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-engine-version-'));
    TEMP_DIRS.push(dir);
    await writeFile(join(dir, 'a.ts'), 'const x = 1;\n', 'utf8');
    const r = await scanPath(dir, { config: false });
    expect(r.engineVersions.core).toBe(EXPECTED_ENGINE_VERSION);
  });
});

// The README is the only tracked document that states the engine version as a
// value a reader is expected to compare against (CHANGELOG entries are dated
// records of past releases and must NOT be rewritten on a bump). Its Versioning
// table is the contract; keeping it in sync by hand has no guard other than this.
describe('README states the pinned engine version', () => {
  const README = readFileSync(
    fileURLToPath(new URL('../../../README.md', import.meta.url)),
    'utf8',
  );

  it('the Versioning table Engine-version row reports the current value', () => {
    const row = README.split('\n').find((l) => l.includes('**Engine version**'));
    expect(row, 'README.md has no "**Engine version**" table row').toBeDefined();
    // Last cell of the Markdown row is the `Current` column.
    const cells = row!.split('|').map((c) => c.trim()).filter((c) => c.length > 0);
    expect(cells[cells.length - 1]).toBe(`\`${EXPECTED_ENGINE_VERSION}\``);
  });

  it('the prose below the table quotes the same value in the CLI banner', () => {
    // e.g. "The CLI prints both, e.g. `vibeguard 0.1.3 (engine 0.1.0)`."
    const banner = README.match(/\(engine (\d+\.\d+\.\d+)\)/);
    expect(banner, 'README.md no longer shows a `(engine x.y.z)` CLI banner').not.toBeNull();
    expect(banner![1]).toBe(EXPECTED_ENGINE_VERSION);
  });
});
