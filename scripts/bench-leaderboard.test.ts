// Tests for scripts/bench-leaderboard.mjs.
//
// WHAT A LEADERBOARD GETS WRONG WHEN NOBODY TESTS IT
//
// It becomes a markdown table somebody edits. That drifts in exactly one
// direction: nobody edits a row to make their own tool look worse, and nobody
// deletes a row when the corpus moves underneath it. So the assertions here are
// about the properties that keep it from becoming that table —
//
//   * every row comes from a result FILE; a .json that is not a usable result is
//     REJECTED by name with a reason, and a file that is not .json at all is
//     SKIPPED by name. Neither is filtered out in silence — that claim used to be
//     made in this comment and was false: endsWith('.json') dropped the second
//     kind before anything could report it;
//   * an empty results directory is exit 3, because an empty table reads as
//     "nobody has entered yet" and is indistinguishable from "pointed at the
//     wrong directory";
//   * a row scored against a different manifest is MARKED, not silently laid
//     beside rows that are not comparable with it;
//   * EVERY BUCKET IS A COLUMN and the row adds up. The table used to omit
//     unattributed and refused while the scorer asserted exhaustiveness, so a
//     row could fail to account for its own findings in the one place a reader
//     actually looks;
//   * every row states how many of the labels it was scored over a human has
//     confirmed, because a table over an unconfirmed draft is a different
//     artefact from a table over ground truth.
//
// The committed control leaderboard is checked against its own generator, which
// is the only way to assert a generated file is still generated.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

// @ts-expect-error — plain ESM module, no type declarations by design.
import { loadResults, render } from './bench-leaderboard.mjs';
// @ts-expect-error — ditto.
import { manifestDigest } from './bench-shared.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const GEN = join(REPO, 'scripts', 'bench-leaderboard.mjs');
const BENCH = join(REPO, 'bench', 'ai-code-security-design-smells');
const CONTROL = join(BENCH, 'fixtures', 'positive-control');

const readJson = (p: string) => JSON.parse(readFileSync(p, 'utf8'));

const tmpDirs: string[] = [];
function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), 'bench-lb-'));
  tmpDirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

function runGen(args: string[]): { status: number; out: string } {
  try {
    const out = execFileSync(process.execPath, [GEN, ...args], { cwd: REPO, encoding: 'utf8', stdio: 'pipe' });
    return { status: 0, out };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? -1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

// A row of the shape bench-score.mjs writes TODAY. Every count is present and
// every partition holds, because the generator now rejects a row where one does
// not — a fixture that quietly failed the partition would make the render tests
// below assertions about a broken row.
const resultRow = (over: Record<string, unknown> = {}) => ({
  schema: 'bench/result@1',
  benchmark: 'x',
  tool: 'toolA',
  toolVersion: '1.0.0',
  date: '2026-01-01',
  manifestDigest: 'sha256:aaaa',
  rubricVersion: 'v1',
  lineWindow: 3,
  lineWindowMax: 25,
  rateWithheld: null,
  labelProvenance: { scope: 'the labels this run covered', confirmed: 2, unconfirmed: 0, total: 2, groundTruth: ['by-construction'] },
  coverage: { declaredWithRepositoryFlag: ['r1'], repositories: ['r1'], manifestEntries: ['r1'] },
  refusedSarifResults: 0,
  counts: {
    labelsTotal: 2,
    labelsTP: 1,
    labelsFP: 1,
    labelsCovered: 2,
    labelsUncovered: 0,
    labelsTPCovered: 1,
    labelsFPCovered: 1,
    labelsTPUncovered: 0,
    labelsFPUncovered: 0,
    recovered: 1,
    missed: 0,
    reportedKnownFalsePositive: 0,
    correctlyAbsentOnKnownFalsePositive: 1,
    findingsTotal: 3,
    findingsMatched: 1,
    findingsUnscored: 1,
    findingsUnmapped: 1,
    findingsUnattributed: 0,
  },
  ...over,
});

describe('an empty results directory is refused', () => {
  it('exits 3 and says why, rather than writing a table with no rows', () => {
    const out = join(scratch(), 'LEADERBOARD.md');
    const r = runGen(['--results', scratch(), '--manifest', join(CONTROL, 'manifest.json'), '--out', out]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/no usable result files/);
    expect(existsSync(out)).toBe(false);
  });

  it('the real benchmark results directory is currently that case, so the refusal is live', () => {
    // If somebody scores a real run this test will start failing, and that is
    // the correct time for it to fail: the claim it pins is "there is no
    // leaderboard because nothing has been scored", not "the generator errors".
    const r = runGen(['--out', join(scratch(), 'LEADERBOARD.md')]);
    expect(r.status).toBe(3);
    expect(existsSync(join(BENCH, 'LEADERBOARD.md'))).toBe(false);
  });

  it('a directory of files that are not results is also refused, and each is named', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'notes.json'), JSON.stringify({ hello: 'world' }));
    writeFileSync(join(dir, 'broken.json'), '{ not json');
    const r = runGen(['--results', dir, '--manifest', join(CONTROL, 'manifest.json'), '--out', join(scratch(), 'x.md')]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/REJECTED {2}notes\.json/);
    expect(r.out).toMatch(/REJECTED {2}broken\.json/);
  });
});

describe('rows come from files, and bad files are rejected out loud', () => {
  it('rejects a document whose schema is not a result schema', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'a.json'), JSON.stringify(resultRow({ schema: 'something/else' })));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected[0].reason).toMatch(/not "bench\/result@1"/);
  });

  it('rejects a result carrying no counts rather than rendering blanks', () => {
    const dir = scratch();
    const row = resultRow();
    delete (row as Record<string, unknown>).counts;
    writeFileSync(join(dir, 'a.json'), JSON.stringify(row));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected[0].reason).toMatch(/no counts/);
  });

  // The legend under the table says the window is bounded. Until this test the
  // bound lived only in the scorer, so a hand-written result file carrying any
  // number at all was rendered and the legend asserted of it the one thing that
  // was not true.
  it('rejects a row whose line window is outside the bound the legend claims', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'a.json'), JSON.stringify(resultRow({ lineWindow: 9999 })));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected[0].reason).toMatch(/lineWindow is 9999/);
  });

  it('rejects a row that carries no line window at all', () => {
    const dir = scratch();
    const row = resultRow();
    delete (row as Record<string, unknown>).lineWindow;
    writeFileSync(join(dir, 'a.json'), JSON.stringify(row));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected[0].reason).toMatch(/lineWindow is null/);
  });

  it('rejects a row scored against a different maximum window, because the rows would not be comparable', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'a.json'), JSON.stringify(resultRow({ lineWindowMax: 500 })));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected[0].reason).toMatch(/maximum window of 500/);
  });

  it('a results directory that does not exist throws rather than reading zero rows', () => {
    expect(() => loadResults({ readFileSync }, join(scratch(), 'absent'))).toThrow(/cannot read the results directory/);
  });
});

describe('a row scored against a different manifest is marked, not hidden', () => {
  it('marks it and counts it in the header', () => {
    const md = render([{ name: 'a.json', doc: resultRow({ manifestDigest: 'sha256:bbbb' }) }], 'sha256:aaaa');
    expect(md).toMatch(/1 row\(s\) were scored against a DIFFERENT manifest/);
    expect(md).toMatch(/\| ≠ \|/);
  });

  it('and a matching row is not marked', () => {
    const md = render([{ name: 'a.json', doc: resultRow() }], 'sha256:aaaa');
    expect(md).not.toMatch(/DIFFERENT manifest/);
    expect(md).toMatch(/\| = \|/);
  });
});

describe('the table does not rank and does not publish a rate', () => {
  it('sorts by tool name, which is not a claim about quality', () => {
    const md = render(
      [
        { name: 'b.json', doc: resultRow({ tool: 'zeta', counts: { ...resultRow().counts, recovered: 1, missed: 0 } }) },
        // recovered 0 AND missed 1: the partition still holds, so this row is a
        // row about ordering and not a row that fails the exhaustiveness check.
        { name: 'a.json', doc: resultRow({ tool: 'alpha', counts: { ...resultRow().counts, recovered: 0, missed: 1 } }) },
      ],
      'sha256:aaaa',
    );
    expect(md.indexOf('| alpha |')).toBeLessThan(md.indexOf('| zeta |'));
  });

  it('prints the withholding banner when a row carries rateWithheld, and no percentage anywhere', () => {
    const md = render([{ name: 'a.json', doc: resultRow({ rateWithheld: 'because the labels are a draft' }) }], 'sha256:aaaa');
    expect(md).toMatch(/No rate is published/);
    expect(md).not.toContain('%');
  });

  it('gives UNSCORED its own column, so it can never be folded into a zero', () => {
    const md = render([{ name: 'a.json', doc: resultRow() }], 'sha256:aaaa');
    expect(md).toMatch(/\| UNSCORED \|/);
    expect(md).toMatch(/is \*not\* a false positive/);
  });

  it('carries the DO-NOT-EDIT marker, so a hand edit is visible as one', () => {
    expect(render([{ name: 'a.json', doc: resultRow() }], 'sha256:aaaa')).toMatch(/GENERATED BY scripts\/bench-leaderboard\.mjs — DO NOT EDIT BY HAND/);
  });
});

describe('the committed control leaderboard is still what the generator produces', () => {
  const path = join(CONTROL, 'LEADERBOARD.md');

  it('exists, and there are result files behind it', () => {
    expect(existsSync(path)).toBe(true);
    const { rows, rejected } = loadResults({ readFileSync }, join(CONTROL, 'results'));
    expect(rejected).toHaveLength(0);
    expect(rows.length).toBeGreaterThan(1); // both SARIF shapes were scored
  });

  it('its table matches a fresh render of those result files', () => {
    // Compares the TABLE rather than the whole file: the committed one carries a
    // --footer that the default render has no way to know about, and asserting
    // byte equality would only teach the next person to delete this test.
    const { rows } = loadResults({ readFileSync }, join(CONTROL, 'results'));
    const fresh = render(rows, manifestDigest(readJson(join(CONTROL, 'manifest.json'))), {
      title: readJson(join(CONTROL, 'manifest.json')).benchmark,
    });
    const tableOf = (md: string) => md.split(/\r?\n/).filter((l) => l.startsWith('|')).join('\n');
    expect(tableOf(readFileSync(path, 'utf8'))).toBe(tableOf(fresh));
  });

  it('names both SARIF shapes, which is the tool-neutrality claim made visible', () => {
    const md = readFileSync(path, 'utf8');
    expect(md).toMatch(/\| semgrep \|/);
    expect(md).toMatch(/\| VibeGuard \|/);
  });

  it('says in its own text that its rows are about the scorer, not about any tool', () => {
    expect(readFileSync(path, 'utf8')).toMatch(/says nothing about any tool's accuracy/);
  });
});

// ★ DEFECT 4 — THE PUBLISHED ARTEFACT LOST A BUCKET.
//
// The scorer asserts four-bucket exhaustiveness and the README promises it, but
// the table had no `unattributed` column and no `refused` column. A reader meets
// the numbers HERE, and here they did not have to add up: a row could publish
// three findings, one matched, one UNSCORED, one UNMAPPED and a fourth that
// simply was not shown.
describe('★ every bucket is published, and the addition is pinned at the table', () => {
  it('names every bucket column, including the two that were missing', () => {
    const md = render([{ name: 'a.json', doc: resultRow() }], 'sha256:aaaa');
    for (const column of ['matched', 'UNSCORED', 'UNMAPPED', 'unattributed', 'refused', 'NOT COVERED', 'labels confirmed', 'window']) {
      expect(md).toContain('| ' + column + ' |');
    }
  });

  it('renders the unattributed and refused VALUES, not only the headings', () => {
    const doc = resultRow({
      refusedSarifResults: 7,
      counts: { ...resultRow().counts, findingsTotal: 5, findingsMatched: 1, findingsUnscored: 1, findingsUnmapped: 1, findingsUnattributed: 2 },
    });
    const row = render([{ name: 'a.json', doc }], 'sha256:aaaa')
      .split(String.fromCharCode(10))
      .find((l) => l.startsWith('| toolA |')) as string;
    expect(row).toBeDefined();
    expect(row).toMatch(/\| 5 \| 1 \| 1 \| 1 \| 2 \| 7 \| 3 \|/);
  });

  it('★ a row whose buckets do not add up is REJECTED by name, not rendered', () => {
    const dir = scratch();
    // 1 + 1 + 1 + 0 = 3, but the row claims 4 findings. Under the old generator
    // this rendered as a normal row: the missing one had no column to be missing
    // from.
    writeFileSync(join(dir, 'broken.json'), JSON.stringify(resultRow({ counts: { ...resultRow().counts, findingsTotal: 4 } })));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected[0].name).toBe('broken.json');
    expect(rejected[0].reason).toMatch(/do not partition/);
    expect(rejected[0].reason).toMatch(/findingsTotal is 4/);
  });

  it('and the label side has to add up too', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'a.json'), JSON.stringify(resultRow({ counts: { ...resultRow().counts, labelsUncovered: 3 } })));
    writeFileSync(join(dir, 'b.json'), JSON.stringify(resultRow({ counts: { ...resultRow().counts, recovered: 0 } })));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected.map((r: { name: string }) => r.name)).toEqual(['a.json', 'b.json']);
    expect(rejected[0].reason).toMatch(/does not equal labelsTotal/);
    expect(rejected[1].reason).toMatch(/does not equal labelsTPCovered/);
  });

  it('the intact row is NOT rejected — the check is not refusing everything', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'good.json'), JSON.stringify(resultRow()));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rejected).toHaveLength(0);
    expect(rows).toHaveLength(1);
  });

  it('render marks a non-partitioning row and counts it in the header', () => {
    // loadResults rejects such a row, so this is the second line of defence for
    // a caller that renders rows it assembled itself.
    const md = render([{ name: 'a.json', doc: resultRow({ counts: { ...resultRow().counts, findingsTotal: 9 } }) }], 'sha256:aaaa');
    expect(md).toMatch(/1 row\(s\) do not add up/);
    expect(md).toMatch(/\| 9 ! \|/);
  });

  it('a result from the OLD scorer — no coverage counts — is rejected with the reason', () => {
    const dir = scratch();
    const old = resultRow();
    const counts = { ...old.counts } as Record<string, unknown>;
    delete counts.labelsCovered;
    delete counts.labelsTPCovered;
    writeFileSync(join(dir, 'old.json'), JSON.stringify({ ...old, counts }));
    const { rows, rejected } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(0);
    expect(rejected[0].reason).toMatch(/took the denominator as EVERY/);
  });
});

describe('the committed control leaderboard publishes every bucket too', () => {
  const md = readFileSync(join(CONTROL, 'LEADERBOARD.md'), 'utf8');

  it('names the columns that were missing', () => {
    for (const column of ['unattributed', 'refused', 'NOT COVERED', 'labels confirmed']) {
      expect(md).toContain('| ' + column + ' |');
    }
  });

  it('and every data row in the FILE adds up, read straight out of it', () => {
    const dataRows = md.split(String.fromCharCode(10)).filter((l) => l.startsWith('| ') && /\| \d/.test(l));
    expect(dataRows.length).toBeGreaterThan(1);
    for (const line of dataRows) {
      const cells = line.split('|').map((c) => c.trim()).filter((c) => c !== '');
      const n = cells.map(Number);
      // … | findings | matched | UNSCORED | UNMAPPED | unattributed | refused | window |
      const findings = n[n.length - 7];
      expect(n[n.length - 6] + n[n.length - 5] + n[n.length - 4] + n[n.length - 3]).toBe(findings);
    }
  });
});

// ★ THE CONSEQUENCE OF DEFECT 1, WHERE A READER MEETS IT.
describe('★ the leaderboard says what the labels are worth', () => {
  const unconfirmed = () =>
    resultRow({
      labelProvenance: { scope: 'the labels this run covered', confirmed: 0, unconfirmed: 2, total: 2, groundTruth: ['ai-draft-unconfirmed'] },
      rateWithheld: 'the verdicts are an AI-prepared draft',
    });

  it('banners the unconfirmed labels and shows the ratio in the row', () => {
    const md = render([{ name: 'a.json', doc: unconfirmed() }], 'sha256:aaaa');
    expect(md).toMatch(/THE LABELS ARE NOT CONFIRMED/);
    expect(md).toMatch(/different artefact from one computed over ground truth/);
    expect(md).toMatch(/\| 0\/2 \|/);
  });

  it('and does not banner it when every covered label IS confirmed', () => {
    // The negative control: a constant banner says nothing.
    const md = render([{ name: 'a.json', doc: resultRow() }], 'sha256:aaaa');
    expect(md).not.toMatch(/THE LABELS ARE NOT CONFIRMED/);
    expect(md).toMatch(/\| 2\/2 \|/);
  });

  it('the committed control leaderboard is the confirmed case, and says so per row', () => {
    const md = readFileSync(join(CONTROL, 'LEADERBOARD.md'), 'utf8');
    expect(md).not.toMatch(/THE LABELS ARE NOT CONFIRMED/);
    expect(md).toMatch(/\| 2\/2 \|/);
  });
});

// ★ DEFECT 6 — THE REPORT OVERCLAIMED.
//
// "a file that is not a result is rejected out loud" was not what the code did:
// anything not ending in .json was filtered out by endsWith and never appeared
// in the rejected list at all. A misnamed result file and a directory README
// were indistinguishable, because neither was ever printed.
describe('★ a non-JSON file is named as SKIPPED, not filtered out in silence', () => {
  it('loadResults returns it by name with a reason', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'README.md'), '# notes');
    writeFileSync(join(dir, 'yourtool-1.2.3.jsonn'), JSON.stringify(resultRow()));
    writeFileSync(join(dir, 'good.json'), JSON.stringify(resultRow()));
    const { rows, rejected, skipped } = loadResults({ readFileSync }, dir);
    expect(rows).toHaveLength(1);
    expect(rejected).toHaveLength(0);
    expect(skipped.map((s: { name: string }) => s.name)).toEqual(['README.md', 'yourtool-1.2.3.jsonn']);
    expect(skipped[0].reason).toMatch(/not a \.json file/);
  });

  it('the CLI prints each skipped name, so a typo in a submitted filename is visible', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'README.md'), '# notes');
    writeFileSync(join(dir, 'yourtool-1.2.3.jsonn'), JSON.stringify(resultRow()));
    const r = runGen(['--results', dir, '--manifest', join(CONTROL, 'manifest.json'), '--out', join(scratch(), 'x.md')]);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/SKIPPED {3}README\.md/);
    expect(r.out).toMatch(/SKIPPED {3}yourtool-1\.2\.3\.jsonn/);
    expect(r.out).toMatch(/2 skipped/);
  });

  it('the real results directory carries exactly one skipped file, its README', () => {
    const { rows, rejected, skipped } = loadResults({ readFileSync }, join(BENCH, 'results'));
    expect(rows).toHaveLength(0);
    expect(rejected).toHaveLength(0);
    expect(skipped.map((s: { name: string }) => s.name)).toEqual(['README.md']);
  });
});
