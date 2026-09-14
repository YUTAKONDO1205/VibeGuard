// Tests for scripts/bench-build-manifest.mjs and for the artefacts it committed.
//
// WHY THIS FILE DOES NOT READ THE EVALUATION DATA
//
// The builder's real inputs are gitignored and absent from a clean clone and
// from CI. A test that read them would pass on one machine and skip on the
// others, and a skipped test is the same green tick as a passing one. So every
// assertion here is either about the COMMITTED artefacts — which are in the
// repository and therefore readable everywhere — or drives the builder over a
// synthetic input directory written into a temporary folder, which exercises the
// same code path CI would, not a mock of it.
//
// ★ THE INVARIANT THAT MATTERS MOST
//
// `bench/` contains no third-party source code. It is the premise the whole lane
// rests on — the corpus cannot be redistributed, so the publication is a
// manifest plus a fetcher — and it is the kind of premise that decays by
// accident, one convenient copy at a time. It is asserted here by walking the
// directory rather than by trusting the README.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

// @ts-expect-error — plain ESM module, no type declarations by design.
import { build } from './bench-build-manifest.mjs';
// @ts-expect-error — ditto.
import { labelProvenanceContradictions } from './bench-shared.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const BUILDER = join(REPO, 'scripts', 'bench-build-manifest.mjs');
const BENCH = join(REPO, 'bench', 'ai-code-security-design-smells');
const SEP = String.fromCharCode(92);

const readJson = (p: string) => JSON.parse(readFileSync(p, 'utf8'));
const manifest = readJson(join(BENCH, 'manifest.json'));
const labelSet = readJson(join(BENCH, 'labels.json'));

const tmpDirs: string[] = [];
function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), 'bench-manifest-'));
  tmpDirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

function runBuilder(args: string[]): { status: number; out: string } {
  try {
    const out = execFileSync(process.execPath, [BUILDER, ...args], { cwd: REPO, encoding: 'utf8', stdio: 'pipe' });
    return { status: 0, out };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? -1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

/** A minimal, synthetic stand-in for the gitignored inputs. Nothing real in it. */
function synthesiseInputs(): string {
  const dir = scratch();
  mkdirSync(join(dir, 'corpus-pins-2026-08-04'), { recursive: true });
  writeFileSync(
    join(dir, 'corpus-pins-2026-08-04', 'corpus1k_vibe-upstream-pins.json'),
    JSON.stringify({
      corpus: 'synthetic',
      repoCount: 1,
      pins: {
        owner__widget: { sha: 'c'.repeat(40), remote: 'https://example.invalid/owner/widget.git', committed: '2026-01-01T00:00:00Z', branch: 'main' },
      },
    }),
  );
  writeFileSync(
    join(dir, 'corpus1k_vibe_manifest.json'),
    JSON.stringify({ corpus: 'synthetic', repos: [{ full_name: 'owner/widget', dir: 'owner__widget', language: 'TypeScript', kb: 7 }] }),
  );
  writeFileSync(
    join(dir, 'smell010_labels.json'),
    JSON.stringify({
      rubricVersion: 'synthetic-v1',
      rubric: 'docs/nowhere.md',
      labels: [
        {
          corpus: 'vibe',
          repo: 'owner__widget',
          findingKey: 'vibe/owner__widget#VG-SMELL-010#src/a.ts:10#n2',
          verdict: 'TP',
          rationale: 'synthetic',
          labeledBy: 'a test',
          humanConfirmed: false,
          _sites: [
            { filePath: 'src/a.ts', startLine: 10, evidence: 'x' },
            { filePath: 'src/a.ts', startLine: 10, evidence: 'a second span on the same line' },
            { filePath: 'src/b.ts', startLine: 4, evidence: 'y' },
          ],
        },
      ],
    }),
  );
  return dir;
}

describe('the builder refuses every input it cannot stand behind', () => {
  it('a missing input directory is exit 2, naming the file, never an empty build', () => {
    const r = runBuilder(['--from', join(scratch(), 'absent'), '--out', scratch()]);
    expect(r.status).toBe(2);
    expect(r.out).toMatch(/cannot read/);
    // The message has to say WHY a clean clone cannot run this, or the next
    // person reads exit 2 as a broken script and "fixes" it into a skip.
    expect(r.out).toMatch(/absent from a clean/);
  });

  it('an empty label array is refused rather than published as a benchmark with no denominator', () => {
    const dir = synthesiseInputs();
    writeFileSync(join(dir, 'smell010_labels.json'), JSON.stringify({ rubricVersion: 'v', labels: [] }));
    expect(() => build(dir)).toThrow(/denominator is empty/);
  });

  it('a label source with no rubricVersion is refused', () => {
    const dir = synthesiseInputs();
    const doc = readJson(join(dir, 'smell010_labels.json'));
    delete doc.rubricVersion;
    writeFileSync(join(dir, 'smell010_labels.json'), JSON.stringify(doc));
    expect(() => build(dir)).toThrow(/rubricVersion/);
  });

  it('a labelled repository with no pin is refused, not silently dropped', () => {
    // Dropping it would publish a smaller benchmark than the label set claims,
    // and nothing downstream would ever say so.
    const dir = synthesiseInputs();
    writeFileSync(join(dir, 'corpus-pins-2026-08-04', 'corpus1k_vibe-upstream-pins.json'), JSON.stringify({ pins: {} }));
    expect(() => build(dir)).toThrow(/could not be resolved/);
  });
});

describe('the builder transcribes rather than invents', () => {
  const built = build(synthesiseInputs());

  it('carries the url and the pinned sha through', () => {
    expect(built.manifest.entries).toHaveLength(1);
    expect(built.manifest.entries[0].repositoryUrl).toBe('https://example.invalid/owner/widget');
    expect(built.manifest.entries[0].commit).toBe('c'.repeat(40));
  });

  it('records the licence as unresolved with a reason, rather than guessing one', () => {
    expect(built.manifest.entries[0].licence.spdx).toBeNull();
    expect(built.manifest.entries[0].licence.status).toBe('unresolved');
    expect(built.manifest.entries[0].licence.reason).toMatch(/No licence field exists/);
    expect(built.manifest.licenceResolved).toEqual({ num: 0, den: 1 });
  });

  it('de-duplicates sites: the raw rows repeat a line once per matched span', () => {
    // The synthetic input has two spans on src/a.ts:10. A benchmark that counted
    // them twice would inflate every site count it published.
    expect(built.labelSet.labels[0].sites).toEqual([
      { file: 'src/a.ts', line: 10 },
      { file: 'src/b.ts', line: 4 },
    ]);
  });

  it('takes the anchor from the finding key the verdict was written against', () => {
    expect(built.labelSet.labels[0].anchor).toEqual({ file: 'src/a.ts', line: 10 });
  });

  it('carries the rubric version onto every row and onto the set', () => {
    expect(built.labelSet.rubricVersion).toBe('synthetic-v1');
    expect(built.labelSet.labels[0].rubricVersion).toBe('synthetic-v1');
  });

  it('withholds the rate while any row is unconfirmed, and says so in the file', () => {
    expect(built.labelSet.humanConfirmed).toEqual({ num: 0, den: 1 });
    expect(built.labelSet.rateWithheld).toMatch(/No rate may be computed/);
  });

  it('lifts the withholding by itself once every row is confirmed', () => {
    // The negative control for the assertion above: if rateWithheld were a
    // constant, the test above would pass against a scorer that can never
    // publish anything.
    const dir = synthesiseInputs();
    const doc = readJson(join(dir, 'smell010_labels.json'));
    doc.labels[0].humanConfirmed = true;
    writeFileSync(join(dir, 'smell010_labels.json'), JSON.stringify(doc));
    const again = build(dir);
    expect(again.labelSet.humanConfirmed).toEqual({ num: 1, den: 1 });
    expect(again.labelSet.rateWithheld).toBeNull();
  });

  it('is deterministic: two builds of the same input are byte-identical', () => {
    const dir = synthesiseInputs();
    expect(JSON.stringify(build(dir))).toBe(JSON.stringify(build(dir)));
  });
});

describe('the committed artefacts', () => {
  it('every entry has a url, a 40-character sha and an explicit licence status', () => {
    expect(manifest.entries.length).toBeGreaterThan(0);
    for (const e of manifest.entries) {
      expect(e.repositoryUrl).toMatch(/^https:\/\//);
      expect(e.commit).toMatch(/^[0-9a-f]{40}$/);
      expect(['resolved', 'unresolved']).toContain(e.licence.status);
    }
  });

  it('licenceResolved is an integer pair that matches the entries, not a remembered number', () => {
    const actual = manifest.entries.filter((e: { licence: { status: string } }) => e.licence.status === 'resolved').length;
    expect(manifest.licenceResolved).toEqual({ num: actual, den: manifest.entries.length });
    expect(Number.isInteger(manifest.licenceResolved.num)).toBe(true);
  });

  it('every label names a repository that the manifest actually carries', () => {
    const ids = new Set(manifest.entries.map((e: { id: string }) => e.id));
    for (const l of labelSet.labels) expect(ids.has(l.repository)).toBe(true);
  });

  it('every label has an anchor and at least one site, or it can never be matched', () => {
    for (const l of labelSet.labels) {
      expect(l.anchor.file).toBeTruthy();
      expect(Number.isInteger(l.anchor.line)).toBe(true);
      expect(l.sites.length).toBeGreaterThan(0);
    }
  });

  it('the provenance block states the corpus size alongside the published size', () => {
    // The ratio between these two is the single most misreadable thing about
    // this benchmark, so both halves have to be in the file rather than implied.
    expect(manifest.provenance.corpusRepositories).toBeGreaterThan(manifest.provenance.entriesPublished);
    expect(manifest.provenance.entriesPublished).toBe(manifest.entries.length);
  });
});

describe('★ no third-party source code is in this repository', () => {
  const SOURCE_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.php', '.java', '.c', '.h', '.cpp']);

  function walk(dir: string, out: string[] = []): string[] {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p, out);
      else out.push(p);
    }
    return out;
  }

  const files = walk(BENCH).map((p) => relative(BENCH, p).split(SEP).join('/'));

  it('found files to look at — an empty sweep is not a clean one', () => {
    expect(files.length).toBeGreaterThan(5);
  });

  it('the only source files under bench/ are the positive control, which was written here', () => {
    const sources = files.filter((f) => SOURCE_EXT.has(f.slice(f.lastIndexOf('.'))));
    expect(sources.length).toBeGreaterThan(0); // the control exists at all
    for (const f of sources) expect(f.startsWith('fixtures/positive-control/corpus/')).toBe(true);
  });

  it('each of those declares in its own first lines that it was written for this benchmark', () => {
    const sources = files.filter((f) => f.startsWith('fixtures/positive-control/corpus/'));
    expect(sources.length).toBeGreaterThan(1); // the family needs two files
    for (const f of sources) {
      const head = readFileSync(join(BENCH, f), 'utf8').split(/\r?\n/).slice(0, 4).join(' ');
      expect(head).toMatch(/POSITIVE CONTROL|See the header/);
    }
  });

  it('no file under bench/ is large enough to be a vendored repository', () => {
    for (const f of files) {
      expect(statSync(join(BENCH, f)).size).toBeLessThan(512 * 1024);
    }
  });
});

// ★ DEFECT 1 — A PUBLISHED LABEL DECLARED A PROVENANCE IT DID NOT HAVE.
//
// Every row of the shipped label set carried `groundTruth: "human-review"` while
// carrying `humanConfirmed: false` and a `labeledBy` that names an AI drafter.
// The builder wrote the string as a constant, so the contradiction was not a
// transcription slip that a careful reader would catch once — it was the output
// of the code, on every row, for every future rebuild.
//
// The fix is in two parts and both are pinned here: the value is DERIVED from
// the fact the source actually carries, and a checker refuses any row where the
// two disagree. The checker is the part that matters, because the derivation can
// be edited back into a constant by anyone and the checker is what notices.
describe('★ a label row cannot declare a provenance it does not have', () => {
  it('derives groundTruth from humanConfirmed instead of writing a constant', () => {
    const built = build(synthesiseInputs());
    expect(built.labelSet.labels[0].humanConfirmed).toBe(false);
    expect(built.labelSet.labels[0].groundTruth).toBe('ai-draft-unconfirmed');
    expect(built.labelSet.labels[0].groundTruth).not.toBe('human-review');
  });

  it('and says human-review when, and only when, a human confirmed it', () => {
    // The negative control for the assertion above: a derivation that always
    // returned 'ai-draft-unconfirmed' would pass it and would be just as wrong
    // in the other direction the day somebody confirms the rows.
    const dir = synthesiseInputs();
    const doc = readJson(join(dir, 'smell010_labels.json'));
    doc.labels[0].humanConfirmed = true;
    writeFileSync(join(dir, 'smell010_labels.json'), JSON.stringify(doc));
    expect(build(dir).labelSet.labels[0].groundTruth).toBe('human-review');
  });

  it('refuses to BUILD a source row whose stated groundTruth contradicts its confirmation', () => {
    // The arm a source that starts carrying its own provenance would trip. It is
    // transcribed rather than overwritten — and then checked, so transcribing a
    // claim nobody earned stops the build instead of publishing it.
    const dir = synthesiseInputs();
    const doc = readJson(join(dir, 'smell010_labels.json'));
    doc.labels[0].groundTruth = 'human-review';
    doc.labels[0].humanConfirmed = false;
    writeFileSync(join(dir, 'smell010_labels.json'), JSON.stringify(doc));
    expect(() => build(dir)).toThrow(/declare a provenance they do not have/);
    expect(() => build(dir)).toThrow(/humanConfirmed false/);
  });

  it('and accepts a stated groundTruth that agrees with it', () => {
    const dir = synthesiseInputs();
    const doc = readJson(join(dir, 'smell010_labels.json'));
    doc.labels[0].groundTruth = 'by-construction';
    doc.labels[0].humanConfirmed = true;
    writeFileSync(join(dir, 'smell010_labels.json'), JSON.stringify(doc));
    expect(build(dir).labelSet.labels[0].groundTruth).toBe('by-construction');
  });

  it('THE COMMITTED LABEL SET: not one row claims a human read it, because none did', () => {
    expect(labelProvenanceContradictions(labelSet)).toEqual([]);
    expect(labelSet.labels.length).toBeGreaterThan(0);
    for (const l of labelSet.labels) {
      expect(l.humanConfirmed).toBe(false);
      expect(l.groundTruth).toBe('ai-draft-unconfirmed');
      expect(l.labeledBy).toMatch(/AI-prepared draft/);
    }
    expect(labelSet.humanConfirmed).toEqual({ num: 0, den: labelSet.labels.length });
    expect(labelSet.rateWithheld).toMatch(/No rate may be computed/);
  });

  it('the positive control is the OTHER case, and is consistent too', () => {
    const control = readJson(join(BENCH, 'fixtures', 'positive-control', 'labels.json'));
    expect(labelProvenanceContradictions(control)).toEqual([]);
    for (const l of control.labels) {
      expect(l.groundTruth).toBe('by-construction');
      expect(l.humanConfirmed).toBe(true);
    }
  });

  it('the checker fires on each shape of contradiction, so it is not vacuous', () => {
    const one = (row: Record<string, unknown>) => labelProvenanceContradictions({ labels: [row] });
    expect(one({ groundTruth: 'human-review', humanConfirmed: false })).toHaveLength(1);
    expect(one({ groundTruth: 'by-construction', humanConfirmed: false })).toHaveLength(1);
    expect(one({ groundTruth: 'ai-draft-unconfirmed', humanConfirmed: true })).toHaveLength(1);
    expect(one({ groundTruth: 'reviewed-by-someone', humanConfirmed: true })[0]).toMatch(/not one of/);
    expect(one({ humanConfirmed: false })[0]).toMatch(/not one of/);
    expect(one({ groundTruth: 'human-review' })[0]).toMatch(/not a boolean/);
    // and the three agreeing shapes are silent
    expect(one({ groundTruth: 'human-review', humanConfirmed: true })).toEqual([]);
    expect(one({ groundTruth: 'by-construction', humanConfirmed: true })).toEqual([]);
    expect(one({ groundTruth: 'ai-draft-unconfirmed', humanConfirmed: false })).toEqual([]);
  });
});

// ★ DEFECT 1, SECOND HALF — the consequence has to be visible where a reader
// meets it. A leaderboard computed over unconfirmed labels is a different
// artefact from one computed over ground truth, and a reader of the README or of
// the table will never open labels.json to find that out.
describe('the unconfirmed state is stated where a reader meets it', () => {
  const readme = readFileSync(join(BENCH, 'README.md'), 'utf8');

  it('the README says the labels are an unconfirmed draft, in its own words', () => {
    expect(readme).toMatch(/UNCONFIRMED/);
    expect(readme).toMatch(/ai-draft-unconfirmed/);
    expect(readme).toMatch(/no human has (read|confirmed)/i);
  });

  it('the README does not claim the rows are human-reviewed ground truth', () => {
    // The specific sentence that would be false. `human-review` may appear as a
    // vocabulary item; it may not appear as a claim about THESE rows.
    expect(readme).not.toMatch(/labels have been (human|manually) reviewed/i);
    expect(readme).not.toMatch(/groundTruth`?: `?"?human-review/);
  });
});
