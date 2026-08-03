// Tests for ANALYSIS_GRAPH_VERSION — specifically, for the documents that quote it.
//
// ★ WHY THIS FILE EXISTS. The constant itself was already guarded: a bump that
// changes cross-file verdicts is caught by the exact-equality assertion in
// `design-smells-crossfile/scattered-authorization.test.ts`, and that assertion
// has now fired twice (alpha.1 -> beta.1 -> beta.2), which is the whole point of
// pinning it exactly rather than by prefix.
//
// What nothing guarded was the OTHER direction: the tracked documents that state
// the value to a reader. `#48` found `README.md` and `docs/DESIGN.ja.md` still
// saying `0.3.0-alpha.1` while the constant read `0.3.0-beta.2` — two bumps
// stale, and stale in the exact way that matters, because both sentences are
// written in the present tense ("currently", "現在") and a reader has no way to
// tell they are describing a build from two waves ago.
//
// `analyzer-core` already has this guard for `ENGINE_VERSION`
// (`engine-version-pin.test.ts`, "README states the pinned engine version"), and
// the reason the cross-file axis rotted while the core axis did not is simply
// that nobody wrote the equivalent. This is the equivalent.
//
// ★ WHY IT LIVES HERE AND NOT NEXT TO THE OTHER ONE. The core pin test is in
// `packages/analyzer-core`, which must not import `packages/analysis-graph` —
// `check-packaging-invariants.mjs` asserts the graph layer is absent from the
// shipped bundles, their declarations and their imports, and a test-only import
// is still an import. The constant's own package is the only place that can read
// it without crossing that line.
//
// ★ WHAT IS DELIBERATELY NOT ASSERTED: `CHANGELOG.md`. Its `[0.3.0]` entry
// records that the release reported `0.3.0-alpha.1`, which was true of that
// release and must stay written that way. A dated record of a past release is
// not a stale statement about the present, and rewriting one to make a test pass
// would destroy the only history of what each version actually announced.

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ANALYSIS_GRAPH_VERSION } from './version.js';

const repoFile = (rel: string): string =>
  readFileSync(fileURLToPath(new URL(`../../../${rel}`, import.meta.url)), 'utf8');

describe('the documents that quote ANALYSIS_GRAPH_VERSION agree with it', () => {
  it('README.md states the current value', () => {
    const readme = repoFile('README.md');
    const line = readme.split('\n').find((l) => l.includes("engineVersions['analysis-graph']"));
    expect(line, "README.md no longer mentions engineVersions['analysis-graph']").toBeDefined();
    expect(line).toContain(`\`${ANALYSIS_GRAPH_VERSION}\``);
  });

  it('docs/DESIGN.ja.md states the current value', () => {
    const design = repoFile('docs/DESIGN.ja.md');
    const line = design.split('\n').find((l) => l.includes('engineVersions["analysis-graph"]'));
    expect(line, 'docs/DESIGN.ja.md no longer mentions engineVersions["analysis-graph"]').toBeDefined();
    expect(line).toContain(`\`${ANALYSIS_GRAPH_VERSION}\``);
  });

  it('no tracked document still claims a version this package does not report', () => {
    // The failure #48 actually found was not "the number is missing" but "an
    // older number is still there, in the present tense". Asserting the current
    // value is present does not catch that on its own: a document can name both.
    for (const rel of ['README.md', 'docs/DESIGN.ja.md']) {
      const stale = repoFile(rel)
        .split('\n')
        .filter((l) => /0\.3\.0-(?:alpha|beta)\.\d/.test(l))
        .filter((l) => !l.includes(ANALYSIS_GRAPH_VERSION));
      expect(stale, `${rel} still quotes a superseded analysis-graph version`).toEqual([]);
    }
  });
});
