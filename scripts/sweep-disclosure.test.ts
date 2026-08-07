// Tests for scripts/sweep-disclosure.mjs.
//
// WHAT IS BEING PINNED HERE
//
// The sweep pipeline in this repository broke silently twice, and both times the
// output was `0 hits` — once because a path-conversion layer swallowed a pattern
// that began with a slash, once because a here-doc ate a level of backslash. A
// false zero is not a degraded result; it is the same string a correct run
// prints, which is why nobody re-ran anything.
//
// So the assertions below are almost all in the FAILURE direction, and every one
// of them checks two things together: that the exit code is non-zero, and that
// the word VERDICT does not appear anywhere in the output. A broken instrument
// must not produce a reading at all — not a hedged one, not a warned-about one.
// `grep VERDICT` is the whole contract.
//
//   - a planted positive is not detected      -> red, no verdict
//   - a planted positive is detected as the
//     wrong bytes (the backslash failure)     -> red, no verdict
//   - the negative control fires              -> red, no verdict
//   - the detector's output cannot be parsed  -> red, no verdict
//   - the detector declares a shape nothing
//     is planted for                          -> red, no verdict
//   - nothing was scanned                     -> red, no verdict
//   - the target ref is stale                 -> red, no verdict
//
// and then both directions on a working instrument, because a sweep that only
// ever goes red is a sweep that gets deleted: a clean directory must come back
// `VERDICT: CLEAN` at exit 0, and a directory with one planted disclosure must
// come back `VERDICT: FINDINGS` at exit 2.
//
// HOW THE BROKEN INSTRUMENT IS SIMULATED
//
// `--detector <path>` substitutes the program the sweep drives. The stubs below
// are generated per test; most of them shell out to the REAL detector and then
// corrupt one aspect of its output, so the thing being tested is the sweep's
// ability to notice, not a mock's ability to lie convincingly.
//
// ON THE LITERALS IN THIS FILE
//
// This file is tracked and is therefore scanned by the sweep it tests. Needles
// are assembled from fragments for the same reason they are in
// scripts/check-disclosure-shape.mjs:40 and scripts/sweep-disclosure.mjs. Do not
// join them up.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  EXIT_FINDINGS,
  EXIT_INCOMPLETE,
  EXIT_INTEGRITY,
  EXIT_OK,
  EXIT_TOOL_FAILED,
  PLANTS,
  declaredShapes,
} from './sweep-disclosure.mjs';

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPTS_DIR, '..');
const SWEEP = join(SCRIPTS_DIR, 'sweep-disclosure.mjs');
const REAL_DETECTOR = join(SCRIPTS_DIR, 'check-disclosure-shape.mjs');

/** The one token that means "an answer was given". Nothing else may print it. */
const VERDICT = 'VER' + 'DICT';

let scratch: string;

function run(args: string[], env: Record<string, string> = {}): { status: number; out: string } {
  try {
    const stdout = execFileSync(process.execPath, [SWEEP, ...args], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
    });
    return { status: 0, out: stdout };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { status: e.status ?? -1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

function dirWith(name: string, files: Record<string, string>): string {
  const d = join(scratch, name);
  mkdirSync(d, { recursive: true });
  for (const [f, body] of Object.entries(files)) writeFileSync(join(d, f), body, 'utf8');
  return d;
}

/**
 * A substitute detector, broken in exactly one way.
 *
 * `blind`      — never reports a hit, whatever it is given. This is the shape of
 *                both real failures: the run completes and prints zero.
 * `mangle`     — faithful, except that every backslash is stripped from the hit
 *                line for the backslash plant. This is the here-doc failure,
 *                reproduced at the point where it did its damage.
 * `overfire`   — faithful, plus one fabricated hit on the negative control.
 * `badsummary` — completes, prints something, prints no parseable counts.
 * `extra`      — faithful, but declares a shape nothing is planted for.
 */
function stubDetector(name: string, mode: string, ids: string[]): string {
  const idBlock = ids.map((id) => `  {\n    id: '${id}',\n  },`).join('\n');
  const src = String.raw`
const SHAPES = [
${idBlock}
];
import { execFileSync } from 'node:child_process';

const MODE = ${JSON.stringify(mode)};
const REAL = ${JSON.stringify(REAL_DETECTOR)};
const argv = process.argv.slice(2);
const pathsIdx = argv.indexOf('--paths');
const paths = pathsIdx === -1 ? [] : argv.slice(pathsIdx + 1).filter((a) => !a.startsWith('--'));

if (MODE === 'blind') {
  console.log('');
  console.log('shapes:   ' + SHAPES.length);
  console.log('scanned:  ' + paths.length + ' file(s)');
  console.log('hits:     0');
  console.log('skipped:  0 (binary / too large / unreadable)');
  process.exit(0);
}
if (MODE === 'badsummary') {
  console.log('all good, nothing to report');
  process.exit(0);
}

let out = '';
let status = 0;
try {
  out = execFileSync(process.execPath, [REAL, ...argv], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
} catch (e) {
  out = String(e.stdout ?? '');
  status = typeof e.status === 'number' ? e.status : 1;
}

if (MODE === 'mangle') {
  out = out
    .split(/\r?\n/)
    .map((line) => (line.includes('plant-home-backslash') ? line.split('\\').join('') : line))
    .join('\n');
}
if (MODE === 'overfire') {
  const neg = paths.find((p) => p.endsWith('negative-control.md'));
  let bumped = 0;
  const lines = out.split(/\r?\n/).map((line) => {
    const m = /^hits:(\s+)(\d+)$/.exec(line);
    if (m === null) return line;
    bumped += 1;
    return 'hits:' + m[1] + String(parseInt(m[2], 10) + 1);
  });
  if (bumped !== 1 || neg === undefined) {
    console.error('stub could not fabricate a hit');
    process.exit(9);
  }
  out = [neg + ':1: ACRONYM-YEAR ("zz") | fabricated', ...lines].join('\n');
  status = 1;
}
process.stdout.write(out);
process.exit(status);
`;
  const p = join(scratch, `${name}.mjs`);
  writeFileSync(p, src, 'utf8');
  return p;
}

/** The real local tracking refs, rendered as `git ls-remote` would print them. */
function lsRemoteFixture(name: string, corrupt: boolean): string {
  const local = execFileSync('git', ['for-each-ref', '--format=%(objectname) %(refname)', 'refs/remotes/origin'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const lines: string[] = [];
  for (const raw of local.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '') continue;
    const [sha, ref] = line.split(/\s+/);
    if (ref === 'refs/remotes/origin/HEAD') continue;
    lines.push(`${sha}\trefs/heads/${ref.slice('refs/remotes/origin/'.length)}`);
  }
  let text = `${lines.join('\n')}\n`;
  if (corrupt) text = text.replace(/^[0-9a-f]{40}/m, 'd'.repeat(40));
  const p = join(scratch, name);
  writeFileSync(p, text, 'utf8');
  return p;
}

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'vg-sweep-test-'));
});

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

describe('sweep-disclosure: coverage of the detector', () => {
  // Both halves of the coverage contract, against the REAL detector. The stub
  // test below proves the gate fires; this proves the gate is currently
  // satisfied, which is the thing that quietly stops being true.
  it('plants a positive for every shape the detector declares', () => {
    const declared = declaredShapes(readFileSync(REAL_DETECTOR, 'utf8'));
    expect(declared.length).toBeGreaterThanOrEqual(5);
    const planted = new Set((PLANTS as Array<{ shape: string }>).map((p) => p.shape));
    for (const id of declared) expect(planted, `no positive is planted for ${id}`).toContain(id);
  });

  it('carries two plants for the path shape, one per separator', () => {
    // Not decoration. The two silent failures destroyed a leading slash and a
    // backslash respectively; a single path plant would have survived one of
    // them and reported clean through the other.
    const home = (PLANTS as Array<{ shape: string; needle: string }>).filter((p) => p.shape === 'HOME-DIRECTORY');
    expect(home).toHaveLength(2);
    expect(home.some((p) => p.needle.startsWith('/'))).toBe(true);
    expect(home.some((p) => p.needle.includes('\\'))).toBe(true);
  });
});

describe('sweep-disclosure: both directions on a working instrument', () => {
  it('exits 0 with a CLEAN verdict on a directory with nothing in it to find', () => {
    const d = dirWith('clean', {
      'a.md': 'ordinary prose about ordinary things\n',
      'b.txt': `a citation to ${'AC' + 'M'} ${String(new Date().getFullYear() - 1)} is not a target\n`,
      'c.txt': `a placeholder path ${'/' + 'home/runner/work'} is not an account name\n`,
    });
    const { status, out } = run(['--dir', d]);
    expect(out).toContain(`${VERDICT}: CLEAN`);
    expect(out).toMatch(/inputs=3 checked=3 skipped=0/);
    expect(status).toBe(EXIT_OK);
  }, 120_000);

  it('exits 2 with a FINDINGS verdict on a directory containing one disclosure', () => {
    const d = dirWith('dirty', {
      'a.md': 'ordinary prose about ordinary things\n',
      'leak.md': `the corpus lives in ${'/' + 'home/' + 'z' + 'xcvbnacct'}/data\n`,
    });
    const { status, out } = run(['--dir', d]);
    expect(out).toContain(`${VERDICT}: FINDINGS`);
    expect(out).toContain('HOME-DIRECTORY');
    expect(status).toBe(EXIT_FINDINGS);
  }, 120_000);
});

describe('sweep-disclosure: a broken instrument produces no reading', () => {
  // THE ONE THIS PACKAGE EXISTS FOR. A detector that cannot see a positive
  // planted directly under its nose is the state both real failures were in,
  // and in both of them the pipeline printed a clean number anyway.
  it('exits 3 and says nothing about the tree when a planted positive is not detected', () => {
    const detector = stubDetector('blind', 'blind', declaredShapes(readFileSync(REAL_DETECTOR, 'utf8')));
    const d = dirWith('blind-target', { 'a.md': 'nothing here\n' });
    const { status, out } = run(['--dir', d, '--detector', detector]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('INSTRUMENT FAILED');
    expect(out).toContain('a known positive was planted and the sweep did not detect it');
    // Every plant must be listed as ABSENT, not just the first one to fail.
    expect(out.match(/not detected/g) ?? []).toHaveLength(PLANTS.length);
    // And not one word about the target directory.
    expect(out).not.toContain(VERDICT);
    expect(out).not.toContain('hits=');
  }, 120_000);

  it('exits 3 when the needle fires but the matched bytes are not the planted ones', () => {
    const detector = stubDetector('mangle', 'mangle', declaredShapes(readFileSync(REAL_DETECTOR, 'utf8')));
    const d = dirWith('mangle-target', { 'a.md': 'nothing here\n' });
    const { status, out } = run(['--dir', d, '--detector', detector]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('altered the bytes');
    expect(out).toContain('HOME-DIRECTORY-BACKSLASH');
    // The slash plant is untouched by this corruption and must still read
    // PRESENT — otherwise this test would pass for the wrong reason.
    expect(out).toMatch(/HOME-DIRECTORY-LEADING-SLASH\s+PRESENT/);
    expect(out).not.toContain(VERDICT);
  }, 120_000);

  it('exits 3 when the negative control fires', () => {
    const detector = stubDetector('overfire', 'overfire', declaredShapes(readFileSync(REAL_DETECTOR, 'utf8')));
    const d = dirWith('overfire-target', { 'a.md': 'nothing here\n' });
    const { status, out } = run(['--dir', d, '--detector', detector]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('the negative control fired');
    expect(out).not.toContain(VERDICT);
  }, 120_000);

  it('exits 3 when the detector prints no parseable counts', () => {
    const detector = stubDetector('badsummary', 'badsummary', declaredShapes(readFileSync(REAL_DETECTOR, 'utf8')));
    const d = dirWith('badsummary-target', { 'a.md': 'nothing here\n' });
    const { status, out } = run(['--dir', d, '--detector', detector]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('no parseable summary');
    expect(out).not.toContain(VERDICT);
  }, 120_000);

  it('exits 3 when the detector declares a shape no positive is planted for', () => {
    const ids = [...declaredShapes(readFileSync(REAL_DETECTOR, 'utf8')), 'BRAND-NEW-SHAPE'];
    const detector = stubDetector('extra', 'extra', ids);
    const d = dirWith('extra-target', { 'a.md': 'nothing here\n' });
    const { status, out } = run(['--dir', d, '--detector', detector]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('UNVERIFIED SHAPE');
    expect(out).toContain('BRAND-NEW-SHAPE');
    expect(out).not.toContain(VERDICT);
  }, 120_000);
});

describe('sweep-disclosure: the counting contract', () => {
  // Three checks in this repository have reported exit 0 over an empty input
  // set. This is the assertion that stops the fourth.
  it('exits 3 on an empty input set', () => {
    const d = dirWith('empty', {});
    const { status, out } = run(['--dir', d]);
    expect(out).toContain('inputs=0 checked=0 skipped=0');
    expect(out).toContain('Nothing was scanned');
    expect(out).not.toContain(VERDICT);
    expect(status).toBe(EXIT_INCOMPLETE);
  }, 120_000);

  it('exits 0 on an empty input set only with --allow-empty, and calls the result NOT_OBSERVED', () => {
    const d = dirWith('empty2', {});
    const { status, out } = run(['--dir', d, '--allow-empty']);
    expect(status).toBe(EXIT_OK);
    expect(out).toContain(`${VERDICT}: NOT_OBSERVED`);
    // --allow-empty buys a zero exit code. It does not buy the word CLEAN.
    expect(out).not.toContain(`${VERDICT}: CLEAN`);
  }, 120_000);

  it('reports the instrument phase with its own counting line', () => {
    const d = dirWith('counted', { 'a.md': 'prose\n' });
    const { out } = run(['--dir', d]);
    expect(out).toContain(`instrument inputs=${PLANTS.length + 1} checked=${PLANTS.length + 1} skipped=0`);
  }, 120_000);
});

describe('sweep-disclosure: the freshness gate', () => {
  it('exits 3 and says nothing about the tree when the target ref is stale', () => {
    const f = lsRemoteFixture('stale.txt', true);
    const { status, out } = run(['--ls-remote-from', f]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('DIVERGED');
    expect(out).toContain('ref-freshness exited 3');
    expect(out).not.toContain(VERDICT);
  }, 180_000);

  it('sweeps the tracked tree and reports CLEAN when the refs match the remote', () => {
    const f = lsRemoteFixture('fresh.txt', false);
    const { status, out } = run(['--ls-remote-from', f]);
    expect(out).toContain('freshness: IN_SYNC');
    expect(out).toContain(`${VERDICT}: CLEAN`);
    expect(status).toBe(EXIT_OK);
  }, 180_000);

  // skip is not pass. The environment variable is the only way past the gate,
  // and taking it costs you the word CLEAN standing alone: the run is recorded
  // as unverified against the remote, by name.
  it('names the skipped check and marks freshness NOT_OBSERVED when the skip is authorised', () => {
    const { status, out } = run([], { VG_SWEEP_ALLOW_STALE_REF: '1' });
    expect(status).toBe(EXIT_OK);
    expect(out).toContain('skipped case: ref-freshness — skipped by VG_SWEEP_ALLOW_STALE_REF=1');
    expect(out).toContain('freshness: NOT_OBSERVED');
    expect(out).toContain('this is CLEAN against the local refs, which were not');
  }, 180_000);
});

describe('sweep-disclosure: exit codes', () => {
  it('match the canonical definitions', () => {
    const src = readFileSync(join(REPO_ROOT, 'compiler', 'driver', 'lib', 'exit.mjs'), 'utf8');
    const value = (name: string): number => {
      const m = new RegExp(`export const ${name} = (\\d+);`).exec(src);
      expect(m, `${name} not found in the canonical exit module`).not.toBeNull();
      return Number.parseInt(m![1], 10);
    };
    expect(EXIT_OK).toBe(value('EXIT_OK'));
    expect(EXIT_TOOL_FAILED).toBe(value('EXIT_TOOL_FAILED'));
    expect(EXIT_FINDINGS).toBe(value('EXIT_FINDINGS'));
    expect(EXIT_INCOMPLETE).toBe(value('EXIT_INCOMPLETE'));
    expect(EXIT_INTEGRITY).toBe(value('EXIT_INTEGRITY'));
  });
});
