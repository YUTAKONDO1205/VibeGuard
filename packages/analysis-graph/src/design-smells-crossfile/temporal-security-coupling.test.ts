// Tests for VG-SMELL-041 — Temporal Security Coupling.
//
// ★ THE FILE-SCOPE PRAGMA THAT USED TO OPEN THIS FILE IS GONE, AND MEASUREMENT
// IS WHY.
//
// It read `vibeguard:disable-file VG-INJ-004`, justified by a comment saying the
// generated handler sources below "contain a real interpolated SQL statement".
// Two things were wrong with that. VG-INJ-004 is `eval()` — nothing in this file
// ever matched it, so the pragma suppressed nothing. And it counted toward the
// `vibeguard:disable-file` baseline in `scripts/check-packaging-invariants.mjs`,
// which pins the number of files carrying one; adding this file took the count
// from 53 to 54 and made `--pre-build` exit 1, so CI's build-test job failed
// before anything downstream of it ran.
//
// MEASURED by scanning a copy of this file with the pragma stripped: the only
// rule that fires is VG-INJ-001, on the PYTHON payload in the polyglot test, and
// the old pragma never named it. That one line now carries a
// `vibeguard:disable-next-line`, which is the narrow form — a real injection
// introduced anywhere else in this file still reports, and the blanket-pragma
// count is back where the invariant expects it.
//
// Run over the corpus on disk, and against the rule OBJECT rather than through
// `analyzeProject`. Two reasons, and the second is the load-bearing one:
//
//  - The rule is deliberately not in `design-smells-crossfile/index.ts` yet, so
//    `analyzeProject` would not run it at all.
//  - The positive fixtures contain genuine injection — a template-interpolated
//    SQL statement is the only honest way to write a flow that reaches a query
//    sink — so the `VG-INJ-*` family fires on them from the single-file engine.
//    Calling `temporalSecurityCoupling.analyze` directly means every assertion
//    below is about THIS rule, and a change in the injection rules cannot turn
//    these tests red or, worse, green.
//
// ★ WHY EVERY NEGATIVE ASSERTS A TAINT FLOW BEFORE IT ASSERTS SILENCE
//
// H1 does not kill taint at a sanitizer call: `escapeLike(term)` is an ordinary
// call to the dataflow pass, so a correctly sanitised handler still produces a
// `TaintFlow` that reaches the sink (pinned in `the premise` below). Silence for
// this rule therefore has to be EARNED, and a negative fixture that produced no
// flow at all would pass every assertion here while proving nothing — the
// vacuous pass this repository has already had to reject once. So each negative
// asserts the flow count first, and `smell-041-no-reach/` — the one fixture
// whose premise is the opposite — asserts that its source and sink are still
// textually present, because a fixture that decayed into an empty file would
// satisfy "no flows" perfectly.

import { describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { designSmellLocationsAgree, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { createBudget, type CreateBudgetOptions } from '../budget.js';
import { buildProjectIndex, collectProjectFiles } from '../project.js';
import { analyzeProjectTaint, type TaintFlow } from '../taint/index.js';
import type { CrossFileFinding, GraphBudget } from '../types.js';
import { temporalSecurityCoupling } from './temporal-security-coupling.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);
const fixture = (name: string): string => sample(`crossfile-fixtures/${name}`);

interface Analysis {
  findings: CrossFileFinding[];
  /** Every flow H1 found, so a negative can prove it is not silent by default. */
  flows: TaintFlow[];
  budget: GraphBudget;
}

/**
 * Index a directory once and return both what H1 saw and what the rule said.
 *
 * The two come from ONE `ProjectIndex`, deliberately: a helper that built the
 * index twice could report a flow count from a tree the rule never analysed,
 * which is precisely the disagreement the premise assertions exist to catch.
 */
async function analyse(dir: string, options: CreateBudgetOptions = {}): Promise<Analysis> {
  const budget = createBudget(options);
  const files = await collectProjectFiles(dir, budget);
  const project = buildProjectIndex(dir, files, budget);
  const flows = analyzeProjectTaint([...project.structures.values()], project.files);
  return { findings: temporalSecurityCoupling.analyze({ project, budget }), flows, budget };
}

/** The text of one line of a fixture, 1-based, so a claim can be checked against it. */
async function lineOf(dir: string, filePath: string, line: number): Promise<string> {
  const content = await readFile(resolve(dir, filePath), 'utf8');
  return (content.split('\n')[line - 1] ?? '').trim();
}

/** `relatedLocations` as `line:evidence`, which is what the assertions read. */
const trail = (finding: CrossFileFinding): string[] =>
  (finding.relatedLocations ?? []).map((l) => `${l.startLine}:${l.evidence}`);

describe('VG-SMELL-041 — INVERTED, with a transforming sanitizer', () => {
  it('reports the escaping that runs after the statement it was written for', async () => {
    const { findings, flows } = await analyse(fixture('smell-041-sanitize-after'));
    expect(flows).toHaveLength(1);
    expect(findings).toHaveLength(1);
    const [finding] = findings;
    expect(finding!.ruleId).toBe('VG-SMELL-041');
    expect(finding!.title).toBe('Temporal Security Coupling');
    expect(finding!.scope).toBe('symbol');
    expect(finding!.filePath).toBe('search.ts');
    expect(finding!.startLine).toBe(19);
    expect(finding!.description).toContain('runs AFTER the sink');
  });

  it('is high/high — an interpreter sink, and an ordering two offsets decide', async () => {
    const [finding] = (await analyse(fixture('smell-041-sanitize-after'))).findings;
    expect(finding!.severity).toBe('high');
    expect(finding!.confidence).toBe('high');
  });

  it('carries the taint path as related locations, source → hop → sanitizer', async () => {
    // ★ THE REASON #26 (H1) IS LOAD-BEARING RATHER THAN DECORATIVE. Without this
    // list the finding says "this looks mis-ordered"; with it, it says "this
    // value, from here, through here, arrived there" — a claim a reviewer can
    // refute in three seconds if it is wrong.
    const [finding] = (await analyse(fixture('smell-041-sanitize-after'))).findings;
    expect(trail(finding!)).toEqual([
      '18:tainted source: req.query',
      '18:assigned to `term`',
      '21:transformer `escapeLike` runs after the sink',
    ]);
  });

  it('finds the enclosing function of an INLINE handler', async () => {
    // The handler is an anonymous arrow at the route registration, so the
    // sanitizer search had to locate its body by containment. A name-based
    // lookup would have searched nothing and reported nothing.
    const [finding] = (await analyse(fixture('smell-041-sanitize-after'))).findings;
    expect(finding!.description).toContain('<anonymous@17>');
  });
});

describe('VG-SMELL-041 — BYPASSED, with a transforming sanitizer', () => {
  it('reports the safe copy the sink did not use', async () => {
    const { findings, flows } = await analyse(fixture('smell-041-sanitize-bypassed'));
    expect(flows).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.filePath).toBe('reports.ts');
    expect(findings[0]!.startLine).toBe(22);
    expect(findings[0]!.description).toContain('this sink does not use');
  });

  it('is medium/medium — ★ THE SENTINEL for both graded fields', async () => {
    // The only fixture where severity and confidence are BOTH at the floor. If
    // an edit makes either field constant, this is the directory that notices:
    // the two positives above are `high` on both, so a rule that emitted
    // `high`/`high` unconditionally would pass every other assertion in the file.
    //
    // `medium` severity because a `file` sink is context-dependent (this one
    // reads under a fixed base directory); `medium` confidence because BYPASSED
    // rests on the hop chain being complete, and an incomplete chain — H1 sees
    // no property writes — looks exactly the same. See the rule's confidence
    // comment.
    const [finding] = (await analyse(fixture('smell-041-sanitize-bypassed'))).findings;
    expect(finding!.severity).toBe('medium');
    expect(finding!.confidence).toBe('medium');
  });

  it('cites the sanitizer that ran BEFORE the sink and still missed it', async () => {
    const [finding] = (await analyse(fixture('smell-041-sanitize-bypassed'))).findings;
    expect(trail(finding!)).toEqual([
      '18:tainted source: req.query',
      '18:assigned to `requested`',
      '20:transformer `sanitizeFilename` produces a value the sink does not use',
    ]);
  });
});

describe('VG-SMELL-041 — INVERTED, with a validator', () => {
  it('reports the check that runs after the command it was meant to gate', async () => {
    const { findings } = await analyse(fixture('smell-041-validate-after'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.startLine).toBe(18);
    expect(findings[0]!.severity).toBe('high');
    expect(findings[0]!.confidence).toBe('high');
    expect(trail(findings[0]!)).toEqual([
      '16:tainted source: req.body',
      '16:assigned to `host`',
      '17:assigned to `command`',
      '20:validator `isValidHostname` runs after the sink',
    ]);
  });

  it('★ says nothing about the SECOND sink, which the validator does precede', async () => {
    // The fixture contains two flows from one source: the command execution on
    // line 18, which the check follows, and the `res.send(output)` on line 23,
    // which it precedes. Reporting both would mean the rule cannot tell a
    // mis-ordered check from a correctly ordered one — it would just report
    // every sink in a function that validates anything.
    //
    // The flow count is asserted so this cannot pass because H1 stopped finding
    // the second sink.
    const { findings, flows } = await analyse(fixture('smell-041-validate-after'));
    expect(flows).toHaveLength(2);
    expect(flows.map((f) => f.sink.line).sort((a, b) => a - b)).toEqual([18, 23]);
    expect(findings.map((f) => f.startLine)).toEqual([18]);
  });
});

describe('VG-SMELL-041 — a parameterised-looking sink that is not parameterised', () => {
  // ★ THE OTHER HALF OF `sinkIsParameterized`, AND THE REASON IT IS NOT A
  // BLANKET EXEMPTION. `smell-041-parameterized/` proves the test SILENCES
  // correct code; nothing there proves it still SPEAKS about incorrect code, and
  // a condition that only ever silences can be widened without a test noticing.
  it('reports the interpolated value even though the statement HAS a placeholder', async () => {
    const { findings, flows } = await analyse(fixture('smell-041-mixed-placeholder'));
    expect(flows).toHaveLength(2);
    expect(findings).toHaveLength(2);
    // `'%${term}%'` is written INTO the statement; `state = ?` binds something
    // else entirely. The first argument mentioning a chain name is what refuses
    // the exemption.
    const [query] = findings;
    expect(query!.startLine).toBe(35);
    expect(query!.severity).toBe('high');
    expect(query!.confidence).toBe('high');
    expect(query!.description).toContain('runs AFTER the sink');
  });

  it('does not read a `??` operator as a bound parameter', async () => {
    // `execFileSync(bin ?? DEFAULT_BIN, [target])` has a `?` in its first
    // argument and no placeholder anywhere: the token is code, not statement
    // text. Told apart by comparing the blanked copy with the original at the
    // same offset, which is possible only because blanking preserves length.
    const { findings } = await analyse(fixture('smell-041-mixed-placeholder'));
    const [, exec] = findings;
    expect(exec!.startLine).toBe(46);
    expect(exec!.severity).toBe('high');
    expect(trail(exec!).at(-1)).toBe('48:transformer `sanitizeArg` runs after the sink');
  });
});

describe('VG-SMELL-041 — a callee carrying both vocabularies', () => {
  it('reads `validateAndEscapeName` as a transformer, and reports the bypass', async () => {
    // The tie-break in `classifyGuard`. As a validator the helper is correctly
    // wired (it runs first) and the file is silent; as a transformer it demands
    // that its RESULT reach the sink, which is the defect here. Transformer wins
    // because mis-reading a transformer as a validator silences a real bypass.
    const { findings, flows } = await analyse(fixture('smell-041-combined-name'));
    expect(flows).toHaveLength(1);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.startLine).toBe(29);
    expect(findings[0]!.severity).toBe('medium');
    expect(findings[0]!.confidence).toBe('medium');
    expect(trail(findings[0]!).at(-1)).toBe(
      '27:transformer `validateAndEscapeName` produces a value the sink does not use',
    );
  });
});

describe('VG-SMELL-041 — the falsification corpus', () => {
  // Each directory is one condition away from a positive, so the one that starts
  // firing names the cause. The flow assertion in front of every case is what
  // stops "silent" from meaning "H1 found nothing here anyway".
  const NEGATIVES: ReadonlyArray<readonly [string, string]> = [
    ['smell-041-sanitize-first', 'the transformed copy is the value that reaches the sink'],
    ['smell-041-helper-guard', 'the transformer arrives through an imported helper namespace'],
    ['smell-041-inline-at-sink', 'the transformer is applied inside the sink’s own arguments'],
    ['smell-041-inline-innerhtml', 'the same, at an assign-form sink whose value arrives past an `=`'],
    ['smell-041-validate-first', 'a validator ran before the use'],
    ['smell-041-other-value', 'the sanitizer present was written for a different value'],
    ['smell-041-no-sanitizer', 'no security operation exists for the ordering to be wrong about'],
    ['smell-041-test-paths', 'the file is test code, so it is outside the population'],
    // ★ The four below are REDUCTIONS OF MEASURED FALSE POSITIVES, not shapes
    // imagined at a desk. The first version of this rule produced three findings
    // across the 1,000 repositories in `paper_data/corpus1k` and every one of
    // them was wrong; these are those three plus the vocabulary that let two of
    // them in. A rule whose only contact with real code was a false positive has
    // to carry that contact in its corpus, or the next edit reintroduces it.
    ['smell-041-exclusive-branches', 'the guard sits in a branch the sink cannot reach'],
    ['smell-041-parameterized', 'the value was BOUND to the statement, not written into it'],
    ['smell-041-object-hop', 'the mention names a property of the hop, not the hop'],
    ['smell-041-generic-words', 'the calls carry a vocabulary word and are not security operations'],
    ['smell-041-coercion', 'the transformer on the path is a type coercion'],
  ];

  it.each(NEGATIVES)('%s is silent: %s', async (dir) => {
    const { findings, flows } = await analyse(fixture(dir));
    expect(
      flows.length,
      'PREMISE: H1 must reach a sink in this fixture, or its silence proves nothing',
    ).toBeGreaterThan(0);
    expect(findings).toEqual([]);
  });

  it('smell-041-no-reach is silent because the source never arrives', async () => {
    // The one negative whose premise is inverted: no flow at all. Asserting
    // "no findings" alone would be satisfied by an empty file, so the fixture's
    // ingredients are checked to still be present.
    const dir = fixture('smell-041-no-reach');
    const { findings, flows } = await analyse(dir);
    expect(flows).toEqual([]);
    expect(findings).toEqual([]);
    const source = await readFile(resolve(dir, 'audit.ts'), 'utf8');
    expect(source).toContain('req.body');
    expect(source).toContain('db.query(');
    expect(source).toContain('sanitizeActor(');
  });
});

describe('VG-SMELL-041 — the shipped corpus must not move', () => {
  // The gates this repository fails a release over. The rule is not registered
  // yet, so none of these is enforced by CI for VG-SMELL-041 — which is exactly
  // why they are asserted here: the day it IS registered, the answer must
  // already be known rather than discovered by a red gate.
  it('reports nothing on samples/safe, crossfile-safe and design-safe', async () => {
    for (const dir of ['safe', 'crossfile-safe', 'design-safe']) {
      expect((await analyse(sample(dir))).findings, dir).toEqual([]);
    }
  });

  it('★ reports nothing on samples/vulnerable, WHICH DOES CONTAIN TAINT FLOWS', async () => {
    // MEASURED: the vulnerable corpus produces two intraprocedural flows that
    // reach sinks, and VG-SMELL-041 says nothing about either — because neither
    // function contains a sanitizer for the value it passes on. That is the
    // boundary with `VG-INJ-*` drawn on the shipped corpus rather than only on a
    // fixture written for the purpose, and it is why registering this rule
    // cannot move the E2 = 51 count.
    const { findings, flows } = await analyse(sample('vulnerable'));
    expect(flows.length).toBeGreaterThan(0);
    expect(findings).toEqual([]);
  });

  it('finds exactly its own positives in the whole fixture corpus', async () => {
    // Scanning the fixtures ROOT unions every cross-file fixture in the project
    // — dozens of taint flows across 130-odd files, most of them written for
    // other rules and none of them written to be innocent of this one. Findings
    // only from the positive directories is the broadest negative control
    // available without leaving the repository.
    const { findings, flows } = await analyse(sample('crossfile-fixtures'));
    expect(flows.length).toBeGreaterThanOrEqual(10);
    expect(findings.map((f) => f.filePath)).toEqual([
      'smell-041-combined-name/uploads.ts',
      'smell-041-mixed-placeholder/orders.ts',
      'smell-041-mixed-placeholder/orders.ts',
      'smell-041-sanitize-after/search.ts',
      'smell-041-sanitize-bypassed/reports.ts',
      'smell-041-validate-after/diagnostics.ts',
    ]);
  });
});

describe('VG-SMELL-041 — the finding as a document', () => {
  const POSITIVES: ReadonlyArray<readonly [string, string, string]> = [
    ['smell-041-sanitize-after', 'search.ts', 'db.query('],
    ['smell-041-sanitize-bypassed', 'reports.ts', 'fs.createReadStream('],
    ['smell-041-validate-after', 'diagnostics.ts', 'childProcess.execSync('],
    ['smell-041-mixed-placeholder', 'orders.ts', 'db.query('],
    ['smell-041-combined-name', 'uploads.ts', 'fs.createReadStream('],
  ];

  it.each(POSITIVES)('%s points at a line that really is the sink', async (dir, file, sinkText) => {
    // Line numbers in this suite are written as literals, and a literal is only
    // as good as the file it indexes. Reading the line back means a fixture edit
    // that shifts the code fails the suite instead of silently re-pointing every
    // assertion at a different statement.
    const [finding] = (await analyse(fixture(dir))).findings;
    expect(finding!.filePath).toBe(file);
    // `startLine` is optional on `Finding`; a finding that omitted it would
    // otherwise read line NaN out of the file and compare against nothing.
    expect(finding!.startLine).toBeGreaterThan(0);
    expect(await lineOf(fixture(dir), file, finding!.startLine!)).toContain(sinkText);
  });

  it.each(POSITIVES)('%s keeps primaryLocation in agreement with the flat fields', async (dir) => {
    const [finding] = (await analyse(fixture(dir))).findings;
    // Through the schema's own predicate, not a hand-rolled comparison: the
    // duplication between `primaryLocation` and the flat fields is deliberate
    // and the schema owns the definition of when it has drifted.
    expect(designSmellLocationsAgree({ ...finding!, findingId: 'test' } as DesignSmellFinding)).toBe(
      true,
    );
    // `relatedLocations` must not repeat the primary — see the field's contract.
    for (const related of finding!.relatedLocations ?? []) {
      expect(`${related.filePath}:${related.startLine}`).not.toBe(
        `${finding!.primaryLocation!.filePath}:${finding!.primaryLocation!.startLine}`,
      );
    }
  });

  it.each(POSITIVES)('%s claims only the security context it established', async (dir) => {
    const [finding] = (await analyse(fixture(dir))).findings;
    expect(finding!.securityContext).toEqual({ containsValidationLogic: true });
    // NOT `cross-file`: every location cited lies in one function body.
    expect(finding!.tags).not.toContain('cross-file');
    expect(finding!.tags).toContain('taint');
  });

  it.each(POSITIVES)('%s carries metrics from the shared calculator', async (dir) => {
    const [finding] = (await analyse(fixture(dir))).findings;
    expect(typeof finding!.metrics?.fanIn).toBe('number');
    expect(finding!.metrics?.loc).toBeGreaterThan(0);
  });

  it('is deterministic across runs, field for field', async () => {
    const a = await analyse(fixture('smell-041-validate-after'));
    const b = await analyse(fixture('smell-041-validate-after'));
    expect(JSON.stringify(a.findings)).toBe(JSON.stringify(b.findings));
  });
});

describe('VG-SMELL-041 — bounds and degradation', () => {
  it('declares TS/JS only, and honours it in a polyglot tree', async () => {
    // H1 returns `[]` for Python by design, so a Python-only tree would be
    // silent whatever this rule declared. The case that can actually fail is a
    // MIXED tree: the JS half must still be analysed while the Python half is
    // never handed to a pass that was descoped from understanding it.
    expect(temporalSecurityCoupling.languages).toEqual(['typescript', 'javascript']);
    const dir = await mkdtemp(join(tmpdir(), 'vg-041-poly-'));
    try {
      await writeFile(
        join(dir, 'handler.js'),
        [
          'const db = require("./db");',
          'const { escapeLike } = require("./escape");',
          'function search(req, res) {',
          '  const term = req.query.term;',
          '  const rows = db.query(`SELECT id FROM items WHERE t LIKE ${term}`);',
          '  const safe = escapeLike(term);',
          '  res.json({ rows, safe });',
          '}',
          'module.exports = { search };',
          '',
        ].join('\n'),
      );
      await writeFile(
        join(dir, 'legacy.py'),
        [
          'def search(request):',
          '    term = request.body["term"]',
          // vibeguard:disable-next-line VG-INJ-001
          '    rows = db.query("SELECT id FROM items WHERE t LIKE " + term)',
          '    safe = escape_like(term)',
          '    return {"rows": rows, "safe": safe}',
          '',
        ].join('\n'),
      );
      const { findings } = await analyse(dir);
      expect(findings.map((f) => f.filePath)).toEqual(['handler.js']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('agrees with H1 about positions on CRLF input', async () => {
    // ★ THE CROSS-MODULE CONTRACT THIS RULE STANDS ON. Every position it is
    // handed was computed by `taint`, and it converts them back to offsets to
    // find the enclosing function and the sanitizers inside it. The two must
    // define a line the same way, and CRLF is where a disagreement would first
    // appear — a `\r` belongs to the END of the previous line, so a definition
    // that counted it as a separator would shift every line number by one from
    // the first carriage return onwards.
    //
    // This repository is developed on Windows, so CRLF sources are not a corner
    // case here; they are Tuesday. The assertion is not "a finding appeared" but
    // "the line it points at really is the sink", read back out of the file.
    const dir = await mkdtemp(join(tmpdir(), 'vg-041-crlf-'));
    try {
      const lines = [
        'function searchItems(req, res) {',
        '  const term = req.query.term;',
        '  const rows = db.query(`SELECT id FROM items WHERE t = ${term}`);',
        '  const safe = escapeLike(term);',
        '  return res.json({ rows, safe });',
        '}',
        '',
      ];
      await writeFile(join(dir, 'crlf.js'), lines.join('\r\n'));
      const { findings } = await analyse(dir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.startLine).toBe(3);
      expect(await lineOf(dir, 'crlf.js', 3)).toContain('db.query(');
      // …and the sanitizer it cites is the one on line 4, not line 3 or 5.
      expect(trail(findings[0]!).at(-1)).toBe('4:transformer `escapeLike` runs after the sink');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reports a degradation instead of a clean result when the budget is spent', async () => {
    // A rule that returned `[]` on an exhausted budget would produce the failure
    // `budget.ts` names as the worse of the two: a partial scan that looks clean.
    // `expired()` records the deadline on its way out, so the caller can tell.
    const spent = await analyse(fixture('smell-041-sanitize-after'), { deadlineMs: 0 });
    expect(spent.findings).toEqual([]);
    expect(spent.budget.degradations().map((d) => d.kind)).toContain('graph-deadline');
    // …and the same directory with a live budget still fires, so the assertion
    // above cannot pass because the fixture stopped working.
    expect((await analyse(fixture('smell-041-sanitize-after'))).findings).toHaveLength(1);
  });

  it('stays bounded when H1 hands it the most flows H1 will ever emit', async () => {
    // 520 handlers, each an INVERTED positive on its own. H1 caps a PROJECT at
    // 500 flows, so the rule's output is bounded by its input and does not need
    // a second cap of its own — asserting that here is what makes "no cap in
    // this file" a decision rather than an omission.
    //
    // ★ MEASURED, AND NOT WHAT THE FIRST VERSION OF THIS TEST ASSUMED. Written
    // with a readable six-line handler, the generated file is ~108,000
    // characters and produces 279 flows, not 500: `indexFile` truncates at
    // `REGEX_INPUT_CAP` (50,000) before H1 ever sees the tail, so the INDEXER's
    // bound bites first and H1's flow cap is never reached. The handlers below
    // are written on one line each so the file stays under that cap and the
    // bound actually under test is the one named in the title. The size
    // assertion keeps it that way.
    const dir = await mkdtemp(join(tmpdir(), 'vg-041-many-'));
    try {
      // ★ MEASURED, SECOND TIME: written as ONE line per handler this generator
      // produced 500 flows and ZERO findings — the sanitizer then shares a line
      // with the assignment it feeds, and the on-path test compares LINES
      // because `TaintFlow.hops` reports at line resolution. That is the third
      // KNOWN GAP in the rule's header reproducing itself, and it is recorded
      // here rather than paved over because a bound test that silently measures
      // a false negative measures nothing.
      const handler = (i: number): string[] => [
        'function h' + i + '(req,r){const a' + i + '=req.query.q;d.query(`S ${a' + i + '}`);',
        'const b' + i + '=escape(a' + i + ');}',
      ];
      const source: string[] = [];
      for (let i = 0; i < 520; i += 1) source.push(...handler(i));
      const text = source.join('\n') + '\n';
      expect(text.length, 'must stay under REGEX_INPUT_CAP or the indexer bounds it first').toBeLessThan(
        50_000,
      );
      await writeFile(join(dir, 'many.js'), text);

      const { findings, flows } = await analyse(dir);
      expect(flows.length).toBe(500);
      expect(findings.length).toBe(500);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('inherits H1’s hop ceiling rather than crashing on a long chain', async () => {
    // A chain longer than `MAX_HOPS` is dropped by H1, so this rule never sees
    // it — a FALSE NEGATIVE, stated as a bound rather than discovered as a bug.
    // The short-chain twin is generated by the same code and must fire, so the
    // long-chain assertion cannot pass because the generator broke.
    const build = async (links: number): Promise<Analysis> => {
      const dir = await mkdtemp(join(tmpdir(), 'vg-041-hops-'));
      try {
        const body: string[] = ['function chain(req, res) {', '  const v0 = req.query.q;'];
        for (let i = 1; i <= links; i += 1) body.push(`  const v${i} = v${i - 1};`);
        body.push(
          `  const rows = db.query(\`SELECT id FROM t WHERE c = '\${v${links}}'\`);`,
          '  const safe = escapeSql(v0);',
          '  res.json({ rows, safe });',
          '}',
        );
        await writeFile(join(dir, 'chain.js'), body.join('\n') + '\n');
        return await analyse(dir);
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
    };

    // One link is two hops — the source's own assignment and the rename — which
    // is the ceiling for `high` confidence. Written as `build(1)` rather than
    // `build(2)` because that off-by-one is the whole content of the ceiling.
    const short = await build(1);
    expect(short.findings).toHaveLength(1);
    expect(short.findings[0]!.relatedLocations?.filter((l) => l.evidence?.startsWith('assigned'))).toHaveLength(2);
    expect(short.findings[0]!.confidence).toBe('high');

    // One more link crosses it, and nothing else about the flow changed.
    const overCeiling = await build(2);
    expect(overCeiling.findings).toHaveLength(1);
    expect(overCeiling.findings[0]!.confidence).toBe('medium');

    const long = await build(12);
    expect(long.flows).toEqual([]);
    expect(long.findings).toEqual([]);
  });
});

describe('the premise this whole suite rests on', () => {
  it('★ H1 does NOT kill taint at a sanitizer, so silence must be earned', async () => {
    // If this ever stops being true, every negative fixture above starts passing
    // for free and the rule's precision claim becomes untestable. It is asserted
    // here, once, in the place a reader will look for it — against the fixture
    // whose whole content is a correctly sanitised flow.
    const { flows, findings } = await analyse(fixture('smell-041-sanitize-first'));
    expect(flows).toHaveLength(1);
    expect(flows[0]!.hops.map((h) => h.name)).toEqual(['term', 'safeTerm']);
    expect(flows[0]!.sink.name).toBe('db.query');
    expect(findings).toEqual([]);
  });
});
