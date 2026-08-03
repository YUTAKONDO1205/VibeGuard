// ★★ THE TEST THIS LANE EXISTS TO PASS
//
// `scripts/sec-transfer-semgrep.mjs` has been reading Semgrep `--json` since the
// evasion-transfer experiment; its numbers are in the paper. This package now
// reads the same format. Two parsers of one format is how a project ends up with
// two different answers to "what did Semgrep say", and the first person to notice
// is a reviewer holding a table and a CLI output that disagree.
//
// So: both readings run over THE SAME BYTES — the recorded Semgrep 1.165.0 output
// in src/fixtures/ — and must agree on (check_id, path, line) for every one of
// the 20 results.
//
// ★ WHY THE SCRIPT'S LOGIC IS TRANSCRIBED RATHER THAN IMPORTED, AND WHY THE
//   TRANSCRIPTION IS SAFE
//
// `sec-transfer-semgrep.mjs` is a top-level executable: importing it runs the
// argument parsing, hits a missing corpus manifest, and calls `process.exit(1)`
// before any function is reachable. There is no exported unit to call. Splitting
// it apart is not this lane's job — the file is owned by the research harness and
// its numbers are pinned to a ruleset hash.
//
// A transcription can drift from its original, silently, which would turn this
// test from a guard into decoration. So the transcription is ANCHORED: the test
// reads the script's source and asserts the exact lines it copied are still
// present, character for character. If anyone edits that extraction, this test
// fails and forces the copy here to be re-derived — which is the outcome wanted.
// It is the same discipline the divergence itself demands, applied to the guard.

import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { normalizePath, normalizeReportPath } from './location.js';
import { parseSemgrepReport } from './semgrep-adapter.js';

const FIXTURE_URL = new URL('./fixtures/semgrep-samples-vulnerable.json', import.meta.url);
const FIXTURE_TEXT = readFileSync(FIXTURE_URL, 'utf8');
const FIXTURE_PATH = fileURLToPath(FIXTURE_URL);

/** The repo root, found by walking up from this file: src -> external-adapters -> packages -> root. */
const REPO_ROOT = resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const TRANSFER_SCRIPT = resolve(REPO_ROOT, 'scripts/sec-transfer-semgrep.mjs');
const BASELINE_SCRIPT = resolve(REPO_ROOT, 'scripts/sast-baseline-eval.mjs');

// ---------------------------------------------------------------------------
// The transcription. Every line below is copied out of sec-transfer-semgrep.mjs
// and is asserted to still exist there by `the transcribed extraction still
// exists in the script`.
// ---------------------------------------------------------------------------

/** `const slash = (p) => String(p).replace(/\\/g, '/');` */
const slash = (p: unknown): string => String(p).replace(/\\/g, '/');
/** `const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));` */
const rel = (p: unknown): string => slash(relative(REPO_ROOT, resolve(REPO_ROOT, String(p))));

interface TransferReading {
  checkId: string;
  file: string;
  line: number;
}

/**
 * The body of sec-transfer-semgrep.mjs's indexing loop, transcribed:
 *
 *     const f = rel(r.path ?? r.location?.path ?? '');
 *     const line = Number(r.start?.line ?? r.start ?? 0);
 *     const cid = String(r.check_id ?? '');
 */
function readAsTransferScript(results: readonly unknown[]): TransferReading[] {
  const out: TransferReading[] = [];
  for (const value of results) {
    const r = value as { path?: unknown; location?: { path?: unknown }; start?: unknown; check_id?: unknown };
    const f = rel(r.path ?? r.location?.path ?? '');
    const line = Number((r.start as { line?: unknown })?.line ?? r.start ?? 0);
    const cid = String(r.check_id ?? '');
    out.push({ checkId: cid, file: f, line });
  }
  return out;
}

/** `const norm = (p) => String(p ?? '').replace(SEP, '/').replace(/^\.\//, '');` from sast-baseline-eval.mjs. */
function readAsBaselineScript(p: unknown): string {
  return String(p ?? '')
    .replace(/\\/g, '/')
    .replace(/^\.\//, '');
}

const fixtureResults = (JSON.parse(FIXTURE_TEXT) as { results: unknown[] }).results;

describe('parity with scripts/sec-transfer-semgrep.mjs', () => {
  it('the transcribed extraction still exists in the script, character for character', () => {
    const source = readFileSync(TRANSFER_SCRIPT, 'utf8');
    // If any of these fail, the script's field interpretation has changed and the
    // transcription above — and probably semgrep-adapter.ts — must be re-derived.
    // Do NOT "fix" the test by updating the strings without re-reading the adapter.
    expect(source).toContain("const slash = (p) => String(p).replace(/\\\\/g, '/');");
    expect(source).toContain('const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));');
    expect(source).toContain("const f = rel(r.path ?? r.location?.path ?? '');");
    expect(source).toContain('const line = Number(r.start?.line ?? r.start ?? 0);');
    expect(source).toContain("const cid = String(r.check_id ?? '');");
  });

  it('the transcribed sast-baseline-eval.mjs normaliser still exists in that script', () => {
    const source = readFileSync(BASELINE_SCRIPT, 'utf8');
    expect(source).toContain("const norm = (p) => String(p ?? '').replace(SEP, '/').replace(/^\\.\\//, '');");
  });

  it('agrees with the transfer script on (check_id, path, line) for every recorded result', () => {
    const theirs = readAsTransferScript(fixtureResults);
    const ours = parseSemgrepReport(FIXTURE_TEXT, { reportPath: FIXTURE_PATH, rootDir: REPO_ROOT }).findings;

    // Same population first: a parser that agreed on 19 of 20 by dropping one
    // would pass a naive zip.
    expect(ours).toHaveLength(theirs.length);
    expect(ours).toHaveLength(20);

    for (let i = 0; i < theirs.length; i += 1) {
      const mine = ours[i];
      const other = theirs[i];
      expect(mine).toBeDefined();
      expect(other).toBeDefined();
      expect({ checkId: mine?.toolRuleId, file: mine?.filePath, line: mine?.startLine }).toEqual({
        checkId: other?.checkId,
        file: other?.file,
        line: other?.line,
      });
    }
  });

  it('agrees with the transfer script even with no rootDir, because the recorded paths are relative', () => {
    // The `rootDir` option only changes ABSOLUTE paths. The recorded artifact
    // contains only repo-relative ones, so the two configurations must produce
    // identical output on it — which is what makes the divergence characterised
    // below a statement about other reports, not about this one.
    const withRoot = parseSemgrepReport(FIXTURE_TEXT, { reportPath: FIXTURE_PATH, rootDir: REPO_ROOT }).findings;
    const withoutRoot = parseSemgrepReport(FIXTURE_TEXT, { reportPath: FIXTURE_PATH }).findings;
    expect(withoutRoot.map((f) => f.filePath)).toEqual(withRoot.map((f) => f.filePath));
  });

  it('normalises Windows separators the way both scripts do', () => {
    // The recorded artifact was produced on Windows: every path in it uses
    // backslashes. If this ever regressed, every merge against a POSIX-produced
    // VibeGuard scan would silently find zero corroboration.
    expect(fixtureResults.some((r) => String((r as { path: string }).path).includes('\\'))).toBe(true);
    const ours = parseSemgrepReport(FIXTURE_TEXT, { reportPath: FIXTURE_PATH }).findings;
    expect(ours.every((f) => !(f.filePath ?? '').includes('\\'))).toBe(true);
    expect(ours[0]?.filePath).toBe('samples/vulnerable/auth_bypass.py');
  });
});

// ---------------------------------------------------------------------------
// ★ THE DIVERGENCE THAT ALREADY EXISTS IN THE REPOSITORY
//
// These are not aspirational tests; they RECORD a disagreement between two
// shipped scripts, found while writing this package. Both parse Semgrep reports.
// On the recorded artifacts they were written against — which contain only clean
// relative paths — they agree exactly, which is why nobody has been bitten. On a
// report containing `//`, `..`, or an absolute path they produce different
// strings, so a location that joins under one script does not join under the
// other.
//
// This package takes the sec-transfer semantics (collapse `.`, `..`, `//`) and
// makes the absolute-path reduction an explicit opt-in, because a user-supplied
// report may have been produced from any working directory. See
// `AdapterOptions.rootDir`.
// ---------------------------------------------------------------------------
describe('recorded divergence between the two existing Semgrep parsers', () => {
  const cases = [
    'samples\\vulnerable\\a.py',
    './samples/a.py',
    'samples//a.py',
    'samples/x/../a.py',
  ];

  it('the two scripts agree on plain relative paths', () => {
    for (const input of ['samples\\vulnerable\\a.py', './samples/a.py']) {
      expect(rel(input)).toBe(readAsBaselineScript(input));
    }
  });

  it('the two scripts DISAGREE on redundant and parent segments', () => {
    expect(rel('samples//a.py')).toBe('samples/a.py');
    expect(readAsBaselineScript('samples//a.py')).toBe('samples//a.py');

    expect(rel('samples/x/../a.py')).toBe('samples/a.py');
    expect(readAsBaselineScript('samples/x/../a.py')).toBe('samples/x/../a.py');
  });

  it('this package matches the transfer script on every relative shape, which is the one that matters', () => {
    // `normalizePath` is a copy of the analysis-graph function; this is the proof
    // that the copy is semantically the same normaliser the transfer script
    // computes with node:path, over the shapes a report can contain.
    for (const input of cases) {
      expect(normalizePath(input)).toBe(rel(input));
    }
  });

  it('an absolute path is left alone by default and reduced only when rootDir is given', () => {
    const abs = `${REPO_ROOT}/samples/vulnerable/a.py`;
    // Default: separators normalised, still absolute. The transfer script would
    // have reduced it against process.cwd(), which this package cannot assume.
    expect(normalizeReportPath(abs)).toBe(normalizePath(abs));
    expect(normalizeReportPath(abs).endsWith('samples/vulnerable/a.py')).toBe(true);
    // Opt in, and it matches the transfer script exactly.
    expect(normalizeReportPath(abs, REPO_ROOT)).toBe('samples/vulnerable/a.py');
    expect(normalizeReportPath(abs, REPO_ROOT)).toBe(rel(abs));
  });

  it('an absolute path OUTSIDE rootDir stays absolute rather than becoming a ../ chain', () => {
    // node's `relative()` would answer with `../..`-style traversal here, and
    // that string is indistinguishable from a project-relative path downstream.
    const outside = '/var/tmp/scanned/app.js';
    expect(normalizeReportPath(outside, '/home/me/project')).toBe('/var/tmp/scanned/app.js');
  });
});
