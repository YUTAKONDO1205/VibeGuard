// Tests for scripts/bench-score.mjs — the scorer of bench/ai-code-security-design-smells.
//
// ★ WHY THESE TESTS ARE IN scripts/ AND NOT IN bench/
//
// Verified before they were written, by reading package.json and
// scripts/ci-suite-coverage.test.mjs: `npm test` is
// `npm run test --workspaces --if-present && vitest run --dir scripts`.
// `bench/` is not a workspace (workspaces are packages/*, apps/*, extensions/*),
// and the suite-coverage sweep walks `compiler/` only. A `.test.ts` placed under
// `bench/` would therefore be collected by no runner in this repository and
// would pass forever without executing — the precise silence
// ci-suite-coverage.test.mjs exists to break, one directory it does not watch.
// So the tests live here, where `--dir scripts` actually picks them up.
//
// WHAT IS BEING PINNED
//
// Four things, and the last two are the ones that were missing:
//
//   1. The POSITIVE CONTROL. A corpus written for this repository, with a known
//      true positive at a known line, must be recovered. A scorer that cannot
//      recover a finding it was handed is broken, and no reading it produces
//      about a real tool means anything.
//   2. TOOL NEUTRALITY, as an exercised claim rather than a sentence in a
//      README. The intake runs against a VibeGuard-shaped log (which carries
//      versionControlProvenance and relatedLocations) and a Semgrep-shaped one
//      (which carries neither, and spells the version differently).
//   3. EVERY REFUSAL, ONE AT A TIME. The empty label set, the empty SARIF, the
//      all-UNMAPPED run, the all-UNATTRIBUTED run, a --repository the manifest
//      does not carry, a run that covered no labelled repository, a label set
//      whose provenance contradicts itself, and a --line-window above the
//      ceiling. Each has a plausible-looking zero available to it, and a zero
//      printed with exit 0 is indistinguishable in a CI log from a clean
//      result. Three of these arms used to be open while the first was closed,
//      which is how the suite looked like it covered the trap. The exit codes
//      are asserted through real child processes, because main() returning 3
//      while the process exits 0 is a bug no in-process assertion can see.
//   4. THE DENOMINATOR. The positive control has ONE repository, so it cannot
//      tell "scored against the labels the run covered" apart from "scored
//      against every label in the file" — which is why that defect survived it.
//      The coverage tests therefore run against the REAL five-row label set.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

// @ts-expect-error — plain ESM module, no type declarations by design.
import { attribute, declaredRepositoriesOf, familyIndex, readSarif, score } from './bench-score.mjs';
// @ts-expect-error — ditto.
import { DEFAULT_LINE_WINDOW, MAX_LINE_WINDOW, manifestDigest, normaliseFilePath } from './bench-shared.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const SCORER = join(REPO, 'scripts', 'bench-score.mjs');
const BENCH = join(REPO, 'bench', 'ai-code-security-design-smells');
const CONTROL = join(BENCH, 'fixtures', 'positive-control');
const NEGATIVE = join(BENCH, 'fixtures', 'negative-control');

const readJson = (p: string) => JSON.parse(readFileSync(p, 'utf8'));

const controlLabels = readJson(join(CONTROL, 'labels.json'));
const controlManifest = readJson(join(CONTROL, 'manifest.json'));
const benchFamilies = readJson(join(BENCH, 'rule-families.json'));
const controlFamilies = readJson(join(CONTROL, 'family-map.json'));

const tmpDirs: string[] = [];
function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), 'bench-score-'));
  tmpDirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

/** Run the scorer as a real process; never throws, so the exit code is the assertion. */
function runScorer(args: string[]): { status: number; out: string } {
  try {
    const out = execFileSync(process.execPath, [SCORER, ...args], { cwd: REPO, encoding: 'utf8', stdio: 'pipe' });
    return { status: 0, out };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? -1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

function scoreFixture(sarifName: string, opts: { families?: unknown; repository?: string | null } = {}) {
  const doc = readJson(join(CONTROL, 'sarif', sarifName));
  const { findings } = readSarif(doc, sarifName);
  return score(findings, controlLabels, controlManifest, {
    lineWindow: DEFAULT_LINE_WINDOW,
    familyIndex: familyIndex(opts.families ?? benchFamilies),
    repository: opts.repository ?? null,
  });
}

describe('positive control — the scorer recovers a true positive it was handed', () => {
  it('recovers the by-construction true positive from a VibeGuard-shaped log', () => {
    const r = scoreFixture('vibeguard-shaped.sarif');
    expect(r.vacuous).toBeUndefined();
    expect(r.counts.labelsTP).toBe(1);
    expect(r.counts.recovered).toBe(1);
    expect(r.counts.missed).toBe(0);
  });

  it('recovers it from the Semgrep-shaped log too, under a supplied family map', () => {
    const r = scoreFixture('semgrep-shaped.sarif', { families: controlFamilies, repository: 'acme-svc' });
    expect(r.counts.recovered).toBe(1);
    // The Semgrep-shaped fixture reports the labelled FALSE POSITIVE site as
    // well. That is adjudicable — the rubric already judged that location not to
    // be an instance — so it has to show up as its own count and not as noise.
    expect(r.counts.reportedKnownFalsePositive).toBe(1);
  });

  it('is not satisfied by the line alone: the control is recovered via a site, in the right file', () => {
    const r = scoreFixture('vibeguard-shaped.sarif');
    const tp = r.perLabel.find((p: { verdict: string }) => p.verdict === 'TP');
    expect(tp.matchedBy).toHaveLength(1);
    expect(tp.matchedBy[0].file).toBe('src/routes/admin.ts');
  });

  it('NEGATIVE CONTROL FOR THE MATCHER: a finding far from every site does not match', () => {
    // Same file, same rule, same repository — only the line is wrong. If this
    // passed, every assertion above would be satisfied by file-level matching
    // and the line window would be decorative.
    const doc = {
      runs: [
        {
          tool: { driver: { name: 'VibeGuard', version: '0.0.0' } },
          versionControlProvenance: [{ repositoryUri: 'https://example.invalid/positive-control/acme-svc' }],
          results: [
            {
              ruleId: 'VG-SMELL-010',
              locations: [{ physicalLocation: { artifactLocation: { uri: 'src/routes/admin.ts' }, region: { startLine: 900 } } }],
            },
          ],
        },
      ],
    };
    const { findings } = readSarif(doc, 'synthetic');
    const r = score(findings, controlLabels, controlManifest, {
      lineWindow: DEFAULT_LINE_WINDOW,
      familyIndex: familyIndex(benchFamilies),
      repository: null,
    });
    expect(r.counts.recovered).toBe(0);
    expect(r.counts.findingsUnscored).toBe(1);
  });
});

describe('the denominator is the labelled set', () => {
  it('UNSCORED is its own non-zero count and is never folded into a miss', () => {
    const r = scoreFixture('vibeguard-shaped.sarif');
    // The fixture carries a finding at admin.ts:300, which no label covers.
    expect(r.counts.findingsUnscored).toBe(1);
    expect(r.counts.findingsUnscored + r.counts.findingsMatched + r.counts.findingsUnmapped + r.counts.findingsUnattributed).toBe(
      r.counts.findingsTotal,
    );
  });

  it('the four buckets are disjoint and exhaustive on the Semgrep-shaped log too', () => {
    const r = scoreFixture('semgrep-shaped.sarif', { families: controlFamilies, repository: 'acme-svc' });
    const c = r.counts;
    expect(c.findingsMatched + c.findingsUnscored + c.findingsUnmapped + c.findingsUnattributed).toBe(c.findingsTotal);
    expect(c.findingsUnmapped).toBe(1);
  });

  it('an unlabelled location never becomes a false positive', () => {
    const r = scoreFixture('vibeguard-shaped.sarif');
    // labelsFP counts LABELS, and reportedKnownFalsePositive counts labels the
    // tool hit. Neither may move because of an unlabelled finding.
    expect(r.counts.labelsFP).toBe(1);
    expect(r.counts.reportedKnownFalsePositive).toBe(0);
  });
});

describe('SARIF intake is tool-neutral in fact, not in claim', () => {
  it('reads a log with versionControlProvenance and relatedLocations', () => {
    const doc = readJson(join(CONTROL, 'sarif', 'vibeguard-shaped.sarif'));
    const { findings } = readSarif(doc, 'vg');
    expect(findings[0].repositoryUri).toBe('https://example.invalid/positive-control/acme-svc');
    expect(findings[0].related).toHaveLength(2);
    expect(findings[0].toolVersion).toBe('0.3.6');
  });

  it('reads a log with NEITHER, and with semanticVersion instead of version', () => {
    const doc = readJson(join(CONTROL, 'sarif', 'semgrep-shaped.sarif'));
    const { findings } = readSarif(doc, 'sg');
    expect(findings[0].repositoryUri).toBeNull();
    expect(findings[0].related).toHaveLength(0);
    expect(findings[0].toolName).toBe('semgrep');
    expect(findings[0].toolVersion).toBe('1.165.0');
  });

  it('refuses a result with no usable location instead of dropping it', () => {
    const doc = readJson(join(CONTROL, 'sarif', 'vibeguard-shaped.sarif'));
    const { findings, refused } = readSarif(doc, 'vg');
    expect(refused).toHaveLength(1);
    expect(refused[0].reason).toMatch(/no usable location/);
    // and it is not silently in the findings either
    expect(findings).toHaveLength(3);
  });

  it('percent-decodes artifactLocation.uri, per the specification', () => {
    const doc = {
      runs: [
        {
          tool: { driver: { name: 'x', version: '1' } },
          results: [
            { ruleId: 'r', locations: [{ physicalLocation: { artifactLocation: { uri: 'src/my%20routes/admin.ts' }, region: { startLine: 3 } } }] },
          ],
        },
      ],
    };
    const { findings } = readSarif(doc, 'synthetic');
    expect(findings[0].primary.file).toBe('src/my routes/admin.ts');
  });

  it('rejects a document that is not a SARIF log rather than reading zero findings from it', () => {
    expect(() => readSarif({ results: [] }, 'not-sarif.json')).toThrow(/not a SARIF log/);
  });
});

describe('attribution never guesses', () => {
  const byUrl = new Map([['https://example.invalid/positive-control/acme-svc', 'acme-svc']]);

  it('prefers the run\'s own versionControlProvenance', () => {
    const f = { repositoryUri: 'https://example.invalid/positive-control/acme-svc.git' };
    expect(attribute(f, byUrl, null)).toEqual({ id: 'acme-svc', how: 'versionControlProvenance' });
  });

  it('falls back to --repository when the run says nothing', () => {
    expect(attribute({ repositoryUri: null }, byUrl, 'acme-svc').id).toBe('acme-svc');
  });

  it('★ does NOT fall back to "the only entry" when neither is available', () => {
    // This is the arm that would be right while the manifest has one entry and
    // would start misattributing silently the day it has two. The manifest here
    // HAS exactly one entry, so a guessing implementation would pass every other
    // test in this file.
    expect(byUrl.size).toBe(1);
    expect(attribute({ repositoryUri: null }, byUrl, null)).toEqual({ id: null, how: 'none' });
  });

  it('an unknown repositoryUri is unattributed, not forced into a manifest entry', () => {
    const got = attribute({ repositoryUri: 'https://example.invalid/someone/else' }, byUrl, null);
    expect(got.id).toBeNull();
    expect(got.how).toBe('versionControlProvenance-unknown');
  });
});

describe('refusals — every one of these has a plausible zero available to it', () => {
  it('NEGATIVE CONTROL: an empty label set exits 3 and says nothing was scored', () => {
    const r = runScorer([
      '--sarif', join(CONTROL, 'sarif', 'vibeguard-shaped.sarif'),
      '--labels', join(NEGATIVE, 'labels-empty.json'),
      '--manifest', join(CONTROL, 'manifest.json'),
    ]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/NOTHING WAS SCORED/);
    expect(r.out).toMatch(/label set is empty/);
    // and it must NOT have printed a score
    expect(r.out).not.toMatch(/recovered:\s+0/);
  });

  it('a run in which every finding is UNMAPPED exits 3 rather than reporting "missed"', () => {
    const r = runScorer([
      '--sarif', join(CONTROL, 'sarif', 'semgrep-shaped.sarif'),
      '--labels', join(CONTROL, 'labels.json'),
      '--manifest', join(CONTROL, 'manifest.json'),
      '--repository', 'acme-svc',
    ]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/all 3 finding\(s\) are UNMAPPED/);
    expect(r.out).not.toMatch(/missed:/);
  });

  it('a SARIF log with no results at all exits 3', () => {
    const dir = scratch();
    const empty = join(dir, 'empty.sarif');
    writeFileSync(empty, JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 't', version: '1' } }, results: [] }] }));
    const r = runScorer([
      '--sarif', empty,
      '--labels', join(CONTROL, 'labels.json'),
      '--manifest', join(CONTROL, 'manifest.json'),
      '--repository', 'acme-svc',
    ]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/no results at all/);
  });

  it('a family map that maps nothing exits 3 rather than scoring the map', () => {
    const dir = scratch();
    const emptyMap = join(dir, 'families.json');
    writeFileSync(emptyMap, JSON.stringify({ families: [] }));
    const r = runScorer([
      '--sarif', join(CONTROL, 'sarif', 'vibeguard-shaped.sarif'),
      '--labels', join(CONTROL, 'labels.json'),
      '--manifest', join(CONTROL, 'manifest.json'),
      '--family-map', emptyMap,
    ]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/maps no rule ids at all/);
  });

  it('a missing SARIF file is a usage error, not an empty run', () => {
    const r = runScorer(['--sarif', join(scratch(), 'nope.sarif'), '--labels', join(CONTROL, 'labels.json'), '--manifest', join(CONTROL, 'manifest.json')]);
    expect(r.status).toBe(2);
    expect(r.out).toMatch(/cannot read/);
  });
});

describe('the result file carries what a reader needs to reproduce the row', () => {
  it('records the manifest digest, the family map digest, the window and the withholding', () => {
    const dir = scratch();
    const out = join(dir, 'result.json');
    const r = runScorer([
      '--sarif', join(CONTROL, 'sarif', 'vibeguard-shaped.sarif'),
      '--labels', join(CONTROL, 'labels.json'),
      '--manifest', join(CONTROL, 'manifest.json'),
      '--out', out,
    ]);
    expect(r.status).toBe(0);
    const doc = readJson(out);
    expect(doc.schema).toBe('bench/result@1');
    expect(doc.manifestDigest).toBe(manifestDigest(controlManifest));
    expect(doc.familyMap.sha256).toMatch(/^[0-9a-f]{64}$/);
    // WHICH LABELS THE ROW WAS SCORED AGAINST. --labels is a caller-supplied
    // path, so a row carrying no digest of it is a number nobody can re-derive:
    // two rows scored against different label files publish side by side and the
    // table cannot tell them apart. The digest is of the bytes on disk, so it is
    // compared here against those bytes rather than against a value the scorer
    // also computed.
    expect(doc.labelSet.path).toBe('bench/ai-code-security-design-smells/fixtures/positive-control/labels.json');
    expect(doc.labelSet.sha256).toBe(
      createHash('sha256').update(readFileSync(join(CONTROL, 'labels.json'))).digest('hex'),
    );
    expect(doc.lineWindow).toBe(DEFAULT_LINE_WINDOW);
    expect(doc.rubricVersion).toBe('s010-label-v1');
    // Integers only. A float anywhere here is a rate that escaped.
    for (const v of Object.values(doc.counts as Record<string, number>)) expect(Number.isInteger(v)).toBe(true);
  });

  it('★ records no absolute machine path — a result file is a PUBLISHED artefact', () => {
    // Regression, and it is not hypothetical: the first version of the scorer
    // wrote `--family-map` as whatever the caller typed, so the first result
    // file committed under bench/ carried the author's home directory and with
    // it an account name. scripts/check-disclosure-shape.mjs caught it on the
    // first sweep of the new directory; nobody reviewing the JSON had noticed.
    // Submitters send these files in, so whatever their shell expands lands
    // here — the reduction has to happen in the writer, not in a review habit.
    const dir = scratch();
    const out = join(dir, 'result.json');
    // Pass the family map by ABSOLUTE path, which is what a default invocation
    // resolves to and what the leak came from.
    const r = runScorer([
      '--sarif', join(CONTROL, 'sarif', 'vibeguard-shaped.sarif'),
      '--labels', join(CONTROL, 'labels.json'),
      '--manifest', join(CONTROL, 'manifest.json'),
      '--family-map', join(BENCH, 'rule-families.json'),
      '--out', out,
    ]);
    expect(r.status).toBe(0);
    const text = readFileSync(out, 'utf8');
    expect(text).not.toMatch(/[A-Za-z]:[/\\]{1,2}[Uu]sers[/\\]/);
    expect(text).not.toMatch(/\/[Hh]ome\//);
    expect(readJson(out).familyMap.path).toBe('bench/ai-code-security-design-smells/rule-families.json');
  });

  it('and every committed result file under bench/ is already free of one', () => {
    // The writer is fixed above; this asserts the artefacts on disk were
    // regenerated rather than left carrying the old shape.
    for (const name of readdirSync(join(CONTROL, 'results')).filter((n) => n.endsWith('.json'))) {
      const text = readFileSync(join(CONTROL, 'results', name), 'utf8');
      expect(text).not.toMatch(/[A-Za-z]:[/\\]{1,2}[Uu]sers[/\\]/);
      expect(text).not.toMatch(/\/[Hh]ome\//);
    }
  });

  it('honours rateWithheld: counts are printed, no rate is', () => {
    const realLabels = readJson(join(BENCH, 'labels.json'));
    expect(realLabels.rateWithheld).toBeTypeOf('string');
    const dir = scratch();
    const out = join(dir, 'result.json');
    // Score the REAL label set with a synthetic log so the withholding path runs
    // over the file that actually carries it.
    const sarif = join(dir, 'run.sarif');
    const first = realLabels.labels[0];
    writeFileSync(
      sarif,
      JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'synthetic', version: '0' } },
            results: [
              {
                ruleId: 'VG-SMELL-010',
                locations: [{ physicalLocation: { artifactLocation: { uri: first.anchor.file }, region: { startLine: first.anchor.line } } }],
              },
            ],
          },
        ],
      }),
    );
    const r = runScorer(['--sarif', sarif, '--repository', first.repository, '--out', out]);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/RATE WITHHELD/);
    // The withholding notice itself contains the WORD "precision" — it has to,
    // it is explaining what is being withheld. The claim is that no precision
    // NUMBER is printed, so assert on the shape of a rate rather than on the
    // word: no percentage anywhere, and no line that opens with a metric name
    // followed by a number.
    expect(r.out).not.toContain('%');
    for (const line of r.out.split(/\r?\n/)) {
      expect(line).not.toMatch(/^\s*(precision|recall|f1|accuracy)\b[^a-z]*[\d.]/i);
    }
    const doc = readJson(out);
    expect(doc.rateWithheld).toBeTypeOf('string');
    expect(doc.recallPair).toEqual({ num: expect.any(Number), den: expect.any(Number) });
    expect(Number.isInteger(doc.recallPair.num)).toBe(true);
    expect(Number.isInteger(doc.recallPair.den)).toBe(true);
  });
});

describe('shared vocabulary', () => {
  it('normalises a Windows-style path to the one spelling', () => {
    expect(normaliseFilePath(`src${String.fromCharCode(92)}routes${String.fromCharCode(92)}admin.ts`)).toBe('src/routes/admin.ts');
    expect(normaliseFilePath('./src/routes/admin.ts')).toBe('src/routes/admin.ts');
  });

  it('the manifest digest ignores prose and tracks the entry list', () => {
    const before = manifestDigest(controlManifest);
    expect(manifestDigest({ ...controlManifest, redistribution: 'reworded' })).toBe(before);
    expect(
      manifestDigest({
        ...controlManifest,
        entries: [{ ...controlManifest.entries[0], commit: 'f'.repeat(40) }],
      }),
    ).not.toBe(before);
  });

  it('refuses to digest an empty entry list', () => {
    expect(() => manifestDigest({ entries: [] })).toThrow(/identifies nothing/);
  });
});

// ★ DEFECT 2 — THE DENOMINATOR WAS ALWAYS EVERY LABEL IN THE FILE.
//
// `--repository` names ONE repository, so a run over one repository was scored
// against all five labels and the four it never touched came out as `missed`,
// exit 0. A tool that scanned nothing produced a perfect set of misses and a
// clean CI log. These tests use the REAL five-row label set, because the
// positive control has one repository and cannot tell the two readings apart —
// which is exactly why the defect survived the control.
describe('★ the denominator is the labels the run COVERED, not every label in the file', () => {
  const realLabels = readJson(join(BENCH, 'labels.json'));
  const realManifest = readJson(join(BENCH, 'manifest.json'));
  const firstTP = realLabels.labels.find((l: { verdict: string }) => l.verdict === 'TP');

  /** A one-finding log on a labelled anchor, with or without provenance. */
  function logFor(label: { repository: string; anchor: { file: string; line: number } }, withProvenance: boolean) {
    const entry = realManifest.entries.find((e: { id: string }) => e.id === label.repository);
    const run: Record<string, unknown> = {
      tool: { driver: { name: 'probe', version: '0' } },
      results: [
        {
          ruleId: 'VG-SMELL-010',
          locations: [{ physicalLocation: { artifactLocation: { uri: label.anchor.file }, region: { startLine: label.anchor.line } } }],
        },
      ],
    };
    if (withProvenance) run.versionControlProvenance = [{ repositoryUri: entry.repositoryUrl }];
    const path = join(scratch(), 'run.sarif');
    writeFileSync(path, JSON.stringify({ version: '2.1.0', runs: [run] }));
    return path;
  }

  function scoreReal(sarifPath: string, repositories: string[]) {
    const { findings } = readSarif(readJson(sarifPath), sarifPath);
    return score(findings, realLabels, realManifest, {
      lineWindow: DEFAULT_LINE_WINDOW,
      familyIndex: familyIndex(benchFamilies),
      repositories,
    });
  }

  it('★ a run over ONE labelled repository is scored against ONE label, not five', () => {
    const r = scoreReal(logFor(firstTP, false), [firstTP.repository]);
    expect(r.counts.labelsTotal).toBe(5);
    expect(r.counts.labelsCovered).toBe(1);
    expect(r.counts.labelsUncovered).toBe(4);
    // The whole defect in one assertion: this used to be 2.
    expect(r.counts.missed).toBe(0);
    expect(r.counts.recovered).toBe(1);
    expect(r.counts.labelsTPCovered).toBe(1);
  });

  it('the four it never scanned are published as NOT COVERED, with their own TP/FP split', () => {
    const r = scoreReal(logFor(firstTP, false), [firstTP.repository]);
    expect(r.counts.labelsTPUncovered + r.counts.labelsFPUncovered).toBe(r.counts.labelsUncovered);
    expect(r.counts.labelsTPUncovered).toBe(2);
    expect(r.counts.labelsFPUncovered).toBe(2);
    // and the label side partitions, exactly as the finding side does
    expect(r.counts.labelsCovered + r.counts.labelsUncovered).toBe(r.counts.labelsTotal);
    expect(r.counts.labelsTPCovered + r.counts.labelsTPUncovered).toBe(r.counts.labelsTP);
    expect(r.counts.recovered + r.counts.missed).toBe(r.counts.labelsTPCovered);
  });

  it('and every uncovered label is marked as such in perLabel, not merely absent', () => {
    const r = scoreReal(logFor(firstTP, false), [firstTP.repository]);
    const covered = r.perLabel.filter((p: { covered: boolean }) => p.covered);
    expect(covered).toHaveLength(1);
    expect(covered[0].repository).toBe(firstTP.repository);
    for (const p of r.perLabel.filter((x: { covered: boolean }) => !x.covered)) expect(p.matchedBy).toHaveLength(0);
  });

  it('★ declaring EVERY labelled repository restores the full denominator — so the split is real', () => {
    // The negative control for the three assertions above. If `covered` were
    // wired to "always the repositories that produced a finding", this would
    // report labelsCovered 1 and missed 0, and the scorer would be unable to
    // express "I scanned all five and found one of three".
    const all = realManifest.entries.map((e: { id: string }) => e.id);
    const r = scoreReal(logFor(firstTP, true), all.filter((id: string) => id !== firstTP.repository));
    expect(r.counts.labelsCovered).toBe(5);
    expect(r.counts.labelsUncovered).toBe(0);
    expect(r.counts.labelsTPCovered).toBe(3);
    expect(r.counts.recovered).toBe(1);
    expect(r.counts.missed).toBe(2);
  });

  it('the CLI prints both halves, so neither can be read as the other', () => {
    const r = runScorer(['--sarif', logFor(firstTP, false), '--repository', firstTP.repository]);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/COVERED: {9}1/);
    expect(r.out).toMatch(/NOT COVERED: {5}4/);
    expect(r.out).toMatch(/missed: {12}0/);
  });

  it('the result file carries the coverage, so a leaderboard row cannot hide it', () => {
    const out = join(scratch(), 'result.json');
    const r = runScorer(['--sarif', logFor(firstTP, false), '--repository', firstTP.repository, '--out', out]);
    expect(r.status).toBe(0);
    const doc = readJson(out);
    expect(doc.counts.labelsCovered).toBe(1);
    expect(doc.counts.labelsUncovered).toBe(4);
    expect(doc.coverage.repositories).toEqual([firstTP.repository]);
    expect(doc.recallPair).toEqual({ num: 1, den: 1 });
  });

  it('★ and the labels it was scored over declare themselves UNCONFIRMED in the row', () => {
    const out = join(scratch(), 'result.json');
    runScorer(['--sarif', logFor(firstTP, false), '--repository', firstTP.repository, '--out', out]);
    const doc = readJson(out);
    expect(doc.labelProvenance.confirmed).toBe(0);
    expect(doc.labelProvenance.unconfirmed).toBe(1);
    expect(doc.labelProvenance.groundTruth).toEqual(['ai-draft-unconfirmed']);
  });
});

// ★ DEFECT 3 — THE SAME TRAP WAS CLOSED FOR ONE ARM OF THREE.
//
// An all-UNMAPPED run exited 3. An all-UNATTRIBUTED run exited 0 printing
// `missed`, and so did a run naming a `--repository` that does not exist. The
// one closed arm made the suite look like it covered the trap. Each arm gets its
// own test, through a real child process, so one passing arm cannot stand in for
// another.
describe('★ every arm of the missed trap, tested one at a time', () => {
  const realLabels = readJson(join(BENCH, 'labels.json'));
  const realManifest = readJson(join(BENCH, 'manifest.json'));
  const firstTP = realLabels.labels.find((l: { verdict: string }) => l.verdict === 'TP');

  /** One mapped finding on a labelled anchor, with no versionControlProvenance. */
  function bareLog() {
    const path = join(scratch(), 'bare.sarif');
    writeFileSync(
      path,
      JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'probe', version: '0' } },
            results: [
              {
                ruleId: 'VG-SMELL-010',
                locations: [
                  { physicalLocation: { artifactLocation: { uri: firstTP.anchor.file }, region: { startLine: firstTP.anchor.line } } },
                ],
              },
            ],
          },
        ],
      }),
    );
    return path;
  }

  it('ARM 1 — every finding UNMAPPED: exit 3, and no miss is printed', () => {
    const r = runScorer([
      '--sarif', join(CONTROL, 'sarif', 'semgrep-shaped.sarif'),
      '--labels', join(CONTROL, 'labels.json'),
      '--manifest', join(CONTROL, 'manifest.json'),
      '--repository', 'acme-svc',
    ]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/are UNMAPPED/);
    expect(r.out).not.toMatch(/missed:/);
  });

  it('★ ARM 2 — every mapped finding UNATTRIBUTED: exit 3, and no miss is printed', () => {
    // No versionControlProvenance and no --repository. This used to exit 0
    // printing three misses, which is a statement about the ATTRIBUTION.
    const r = runScorer(['--sarif', bareLog()]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/UNATTRIBUTED/);
    expect(r.out).not.toMatch(/missed:/);
    expect(r.out).not.toMatch(/recovered:/);
  });

  it('★ ARM 3 — a --repository the manifest does not carry: exit 3, naming the id', () => {
    const r = runScorer(['--sarif', bareLog(), '--repository', 'no-such-entry-in-the-manifest']);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/no-such-entry-in-the-manifest/);
    expect(r.out).toMatch(/manifest does not carry/);
    expect(r.out).not.toMatch(/missed:/);
  });

  it('★ ARM 4 — covered only a manifest entry that carries no label: exit 3', () => {
    // Distinct from arm 3: the id IS in the manifest, it simply has no label, so
    // there is no denominator. Nothing about the run itself is malformed.
    const dir = scratch();
    const manifestPath = join(dir, 'manifest.json');
    const entries = realManifest.entries.concat([
      { id: 'unlabelled-entry', repositoryUrl: 'https://example.invalid/nobody/unlabelled', commit: 'a'.repeat(40), licence: { status: 'unresolved' } },
    ]);
    writeFileSync(manifestPath, JSON.stringify({ ...realManifest, entries }));
    const r = runScorer(['--sarif', bareLog(), '--manifest', manifestPath, '--repository', 'unlabelled-entry']);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/not one of them/);
    expect(r.out).not.toMatch(/missed:/);
  });

  it('ARM 5 — a SARIF with no results at all: exit 3', () => {
    const empty = join(scratch(), 'empty.sarif');
    writeFileSync(empty, JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 't', version: '1' } }, results: [] }] }));
    const r = runScorer(['--sarif', empty, '--repository', firstTP.repository]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/no results at all/);
    expect(r.out).not.toMatch(/missed:/);
  });

  it('and the same log DOES score when no arm applies — none of the above is a blanket refusal', () => {
    const r = runScorer(['--sarif', bareLog(), '--repository', firstTP.repository]);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/missed: {12}0/);
  });

  it('several declared repositories make an unprovenanced finding UNATTRIBUTED, not a guess', () => {
    const r = runScorer(['--sarif', bareLog(), '--repository', firstTP.repository, '--repository', 'roboburr__klonkt']);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/UNATTRIBUTED/);
    expect(attribute({ repositoryUri: null }, new Map(), ['a', 'b'])).toEqual({ id: null, how: 'ambiguous-among-declared-repositories' });
    expect(declaredRepositoriesOf(null)).toEqual([]);
    expect(declaredRepositoriesOf('a')).toEqual(['a']);
  });
});

// ★ DEFECT 5 — AN UNBOUNDED MATCHER IS A KNOB THAT IMPROVES YOUR SCORE.
//
// --line-window had a floor and no ceiling, so a submitter could widen it until
// every finding in a labelled file matched some site in that file, lifting
// recovered and reportedKnownFalsePositive together, with the number that did it
// faithfully recorded in the result file and reading like a tuning choice.
describe('★ --line-window is bounded above', () => {
  const realLabels = readJson(join(BENCH, 'labels.json'));
  const firstTP = realLabels.labels.find((l: { verdict: string }) => l.verdict === 'TP');

  /** Two findings: one on a labelled site, one 900 lines away in the same file. */
  function farLog() {
    const path = join(scratch(), 'far.sarif');
    const at = (line: number) => ({
      ruleId: 'VG-SMELL-010',
      locations: [{ physicalLocation: { artifactLocation: { uri: firstTP.anchor.file }, region: { startLine: line } } }],
    });
    writeFileSync(
      path,
      JSON.stringify({
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'probe', version: '0' } }, results: [at(firstTP.anchor.line + 900), at(firstTP.anchor.line)] }],
      }),
    );
    return path;
  }

  it('a window far above the ceiling is a usage error, and the message names the ceiling', () => {
    const r = runScorer(['--sarif', farLog(), '--repository', firstTP.repository, '--line-window', '100000']);
    expect(r.status).toBe(2);
    expect(r.out).toContain('exceeds the maximum of ' + MAX_LINE_WINDOW);
    expect(r.out).not.toMatch(/recovered:/);
  });

  it('one line above the ceiling is refused too — the bound is the stated number', () => {
    const r = runScorer(['--sarif', farLog(), '--repository', firstTP.repository, '--line-window', String(MAX_LINE_WINDOW + 1)]);
    expect(r.status).toBe(2);
  });

  it('the ceiling itself is accepted, and STILL does not reach a site 900 lines away', () => {
    // The negative control for the bound: if the ceiling were so wide that the
    // far finding matched anyway, refusing 100000 would be decoration.
    const out = join(scratch(), 'result.json');
    const r = runScorer(['--sarif', farLog(), '--repository', firstTP.repository, '--line-window', String(MAX_LINE_WINDOW), '--out', out]);
    expect(r.status).toBe(0);
    const doc = readJson(out);
    expect(doc.lineWindow).toBe(MAX_LINE_WINDOW);
    expect(doc.lineWindowMax).toBe(MAX_LINE_WINDOW);
    expect(doc.counts.findingsMatched).toBe(1);
    expect(doc.counts.findingsUnscored).toBe(1);
  });

  it('a negative window is still a usage error', () => {
    const r = runScorer(['--sarif', farLog(), '--repository', firstTP.repository, '--line-window', '-1']);
    expect(r.status).toBe(2);
  });
});

// ★ DEFECT 1, AT SCORING TIME — a label set that contradicts itself is not scored.
describe('★ the scorer refuses a label set whose provenance contradicts itself', () => {
  const realLabels = readJson(join(BENCH, 'labels.json'));
  const firstTP = realLabels.labels.find((l: { verdict: string }) => l.verdict === 'TP');

  function log() {
    const path = join(scratch(), 'run.sarif');
    writeFileSync(
      path,
      JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'probe', version: '0' } },
            results: [
              {
                ruleId: 'VG-SMELL-010',
                locations: [{ physicalLocation: { artifactLocation: { uri: firstTP.anchor.file }, region: { startLine: firstTP.anchor.line } } }],
              },
            ],
          },
        ],
      }),
    );
    return path;
  }

  it('refuses with exit 2 when a row claims human-review while humanConfirmed is false', () => {
    const labelsPath = join(scratch(), 'labels.json');
    const doc = JSON.parse(JSON.stringify(realLabels));
    doc.labels[0].groundTruth = 'human-review';
    writeFileSync(labelsPath, JSON.stringify(doc));
    const r = runScorer(['--sarif', log(), '--labels', labelsPath, '--repository', firstTP.repository]);
    expect(r.status).toBe(2);
    expect(r.out).toMatch(/provenance contradicts their confirmation state/);
    expect(r.out).toMatch(/Refusing to score/);
    expect(r.out).not.toMatch(/recovered:/);
  });

  it('and scores the same run against the committed label set, which does not contradict itself', () => {
    const r = runScorer(['--sarif', log(), '--repository', firstTP.repository]);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/LABELS UNCONFIRMED/);
  });
});
