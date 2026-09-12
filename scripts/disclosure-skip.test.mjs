// Tests for the skip list of scripts/check-disclosure-shape.mjs.
//
// WHY THIS FILE EXISTS
//
// `hits: 0` from that script is the sentence every public-hygiene claim in this
// repository rests on. It was also, until 2026-09-12, a statement about
// everything except three tracked TypeScript files:
//
//   apps/cli/src/fix-ledger.ts
//   packages/analysis-graph/src/design-smells-crossfile/inline-authorization-logic-reach.test.ts
//   packages/analyzer-core/src/declared-packages.ts
//
// All three use a literal NUL as a map-key separator, the binary test was
// `buf.includes(0)`, and so all three were classified binary and never opened.
// They ship in the npm workspaces. The summary line said `skipped: 9` and the
// six PNGs beside them made that look like exactly what it should be.
//
// This is the same failure the script's own VACUOUS exit refuses at run
// granularity — reporting clean over a set nothing was read from — applied one
// file at a time. So the pins below are on the SKIP LIST rather than on the exit
// code: an instrument that is not looking must say so loudly enough that a
// summary line cannot absorb it.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = join(REPO, 'scripts', 'check-disclosure-shape.mjs');

const NUL_SOURCES = [
  'apps/cli/src/fix-ledger.ts',
  'packages/analysis-graph/src/design-smells-crossfile/inline-authorization-logic-reach.test.ts',
  'packages/analyzer-core/src/declared-packages.ts',
];

function run(args = []) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [CHECK, ...args], { encoding: 'utf8', cwd: REPO }) };
  } catch (e) {
    return { code: e.status ?? 1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

describe('the disclosure sweep does not silently skip source', () => {
  it('the three files that caused this still contain the NUL, so the test is about something', () => {
    // If somebody removes the NULs, this test stops being a regression test and
    // should be retired rather than left passing for a new reason.
    const withNul = NUL_SOURCES.filter((f) => existsSync(join(REPO, f)) && readFileSync(join(REPO, f)).includes(0));
    expect(withNul.length, `no tracked source with a NUL remains; these tests are now vacuous: ${NUL_SOURCES}`)
      .toBeGreaterThan(0);
  });

  it('scans them rather than skipping them', () => {
    const { code, out } = run(['--verbose']);
    expect(code).toBe(0);
    for (const f of NUL_SOURCES) {
      if (!existsSync(join(REPO, f))) continue;
      expect(out.includes(`skip ${f} `), `${f} is still being skipped`).toBe(false);
    }
  });

  it('skips nothing but images', () => {
    const { out } = run(['--verbose']);
    const skips = [...out.matchAll(/^ {2}skip (\S+) — (.+)$/gm)].map((m) => m[1]);
    expect(skips.length).toBeGreaterThan(0); // the PNGs, or this asserts nothing
    for (const s of skips) {
      expect(s, `${s} is skipped and is not an image`).toMatch(/\.(png|jpg|jpeg|gif|ico|webp|woff2?|ttf|otf|pdf|wasm)$/i);
    }
  });

  it('a skipped text file is exit 3, not a line in a summary', () => {
    // Measured by mutation rather than asserted: the guard must be its own list,
    // because when it was an alias of the text-extension list, narrowing that
    // list removed the files AND the check that would have noticed.
    const src = readFileSync(CHECK, 'utf8');
    const fatal = /const SKIP_IS_FATAL = new Set\(\[([^\]]*)\]\)/.exec(src);
    expect(fatal, 'SKIP_IS_FATAL is no longer its own literal list').not.toBeNull();
    expect(fatal[1]).toMatch(/'\.ts'/);
    expect(src).not.toMatch(/const SKIP_IS_FATAL = TEXT_EXTENSIONS/);
    // and the fatal path exists and exits 3
    expect(src).toMatch(/skippedSource[\s\S]{0,400}process\.exit\(3\)/);
  });

  it('the summary still reports a scanned count, and it is not zero', () => {
    const { out } = run();
    const scanned = /scanned:\s+(\d+) file/.exec(out);
    expect(scanned).not.toBeNull();
    expect(Number(scanned[1])).toBeGreaterThan(2000);
    expect(out).toMatch(/hits:\s+0/);
  });
});
