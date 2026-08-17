// End-to-end tests for VG-SMELL-010, run over the real sample corpus on disk.
//
// Deliberately NOT unit tests over hand-built `ProjectIndex` objects. The rule's
// risk is not in its own arithmetic; it is in whether the indexer, the graph,
// and the symbol table together produce the facts it assumes — and a hand-built
// index tests the rule against the author's belief about those facts rather
// than against the facts. The corpus under `samples/crossfile-*` was written by
// a different author from the spec text, without sight of this implementation,
// precisely so these tests can fail.

import { describe, expect, it } from 'vitest';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { isDesignSmellFinding, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { analyzeProject, applyConfigSuppression, buildProjectIndex, collectProjectFiles } from '../project.js';
import { createBudget } from '../budget.js';
import { guardKey } from '../symbol-table/index.js';
import { collectScatteredAuthSites, type CheckSite } from './scattered-authorization.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);

/**
 * Narrowing through `isDesignSmellFinding` rather than a cast is deliberate:
 * it asserts that what the rule emits really does land in the design-smell
 * category, which is the key the E2 partition contract is written against. A
 * cast would let a rule that forgot the category still satisfy these tests
 * while silently joining the finding set `samples/vulnerable` counts.
 */
/**
 * Copy a fixture out of `samples/` so a test can graft one line onto it. The
 * copy is what makes the grafted-line tests honest: they mutate a throwaway
 * tree, so the committed fixture stays the control they are measured against.
 */
const cpSample = async (name: string, dest: string): Promise<void> => {
  await cp(sample(name), dest, { recursive: true });
};

const smellsIn = async (dir: string): Promise<DesignSmellFinding[]> => {
  const result = await analyzeProject(dir);
  return result.findings.filter(
    (f): f is DesignSmellFinding => isDesignSmellFinding(f) && f.ruleId === 'VG-SMELL-010',
  );
};

describe('VG-SMELL-010 — positive case', () => {
  it('fires exactly once on the scattered-authorization corpus', async () => {
    const findings = await smellsIn(sample('crossfile-vulnerable'));
    expect(findings).toHaveLength(1);
  });

  it('reports a project scope with related locations in at least two files', async () => {
    const [finding] = await smellsIn(sample('crossfile-vulnerable'));
    expect(finding!.scope).toBe('project');
    const related = finding!.relatedLocations ?? [];
    expect(related.length).toBeGreaterThanOrEqual(2);
    const files = new Set([finding!.filePath, ...related.map((r) => r.filePath)]);
    expect(files.size).toBeGreaterThanOrEqual(2);
  });

  it('counts the duplicated checks and says so in metrics', async () => {
    const [finding] = await smellsIn(sample('crossfile-vulnerable'));
    const count = finding!.metrics?.duplicatedCheckCount ?? 0;
    expect(count).toBeGreaterThanOrEqual(3);
    // The count is the number of locations the finding carries, not a separate
    // tally that could drift away from them.
    expect(count).toBe(1 + (finding!.relatedLocations ?? []).length);
  });

  it('marks the security context and escalates for admin privilege', async () => {
    const [finding] = await smellsIn(sample('crossfile-vulnerable'));
    expect(finding!.securityContext?.containsAuthorizationLogic).toBe(true);
    expect(finding!.severity).toBe('high');
  });

  it('keeps primaryLocation in agreement with the flat fields', async () => {
    const [finding] = await smellsIn(sample('crossfile-vulnerable'));
    expect(finding!.primaryLocation?.filePath).toBe(finding!.filePath);
    expect(finding!.primaryLocation?.startLine).toBe(finding!.startLine);
  });

  it('cites real evidence text for every location', async () => {
    const [finding] = await smellsIn(sample('crossfile-vulnerable'));
    for (const loc of [finding!.primaryLocation!, ...(finding!.relatedLocations ?? [])]) {
      expect(loc.evidence, `${loc.filePath}:${loc.startLine}`).toBeTruthy();
      expect(loc.startLine).toBeGreaterThan(0);
    }
  });

  it('is deterministic: two runs produce the same finding id and ordering', async () => {
    const a = await smellsIn(sample('crossfile-vulnerable'));
    const b = await smellsIn(sample('crossfile-vulnerable'));
    expect(a[0]!.findingId).toBe(b[0]!.findingId);
    expect((a[0]!.relatedLocations ?? []).map((l) => `${l.filePath}:${l.startLine}`)).toEqual(
      (b[0]!.relatedLocations ?? []).map((l) => `${l.filePath}:${l.startLine}`),
    );
  });
});

describe('VG-SMELL-010 — the precision contract', () => {
  it('stays silent on the well-factored version of the same service', async () => {
    // THE gate. This corpus is the vulnerable one refactored to a single
    // requireRole middleware. A design smell that fires here is a bug.
    expect(await smellsIn(sample('crossfile-safe'))).toEqual([]);
  });

  it('stays silent when handlers delegate to a named helper', async () => {
    expect(await smellsIn(sample('crossfile-fixtures/delegated'))).toEqual([]);
  });

  it('stays silent below the three-occurrence threshold', async () => {
    expect(await smellsIn(sample('crossfile-fixtures/two-sites'))).toEqual([]);
  });

  it('stays silent when every check is in one file', async () => {
    // Cross-file analysis must not claim cross-file evidence it does not have.
    expect(await smellsIn(sample('crossfile-fixtures/single-file'))).toEqual([]);
  });

  it('stays silent for role comparisons outside route handlers', async () => {
    expect(await smellsIn(sample('crossfile-fixtures/not-handlers'))).toEqual([]);
  });

  it('stays silent for checks under test paths', async () => {
    expect(await smellsIn(sample('crossfile-fixtures/test-paths'))).toEqual([]);
  });
});

describe('analyzeProject — plumbing', () => {
  it('stamps the analysis-graph version on the result', async () => {
    // ★ Pinned to the β prerelease, and the change is the point rather than an
    // update. This axis answers "would this build produce the same cross-file
    // verdicts", and it sat at `0.3.0-alpha.1` through the whole wave that added
    // VG-SMELL-020/021/041/052 — so a scan running eight rules announced the
    // version an alpha build announced running four. Asserting the exact
    // prerelease rather than a loose prefix is what makes the next omission fail
    // here instead of shipping silently.
    // ★ It worked. `0.3.0-beta.1` → `0.3.0-beta.2` was caught HERE, by this
    // assertion, when #35 changed what VG-SMELL-021 counts — a verdict change on
    // the axis this constant describes, made while nobody was thinking about the
    // constant. That is the exact omission the paragraph above was written after.
    // ★ It worked a second time, in the other direction. During the 0.3.6
    // close-out the constant was moved to `0.3.0-beta.4` for VG-SMELL-013's
    // file-route conventions, every document the two pin tests assert was
    // updated, both pin tests went green — and this line was still on beta.3.
    // The guard that version.test.ts's header calls the real one is this
    // assertion, not those tests: they check that the DOCUMENTS agree with the
    // constant, and this checks that a scan actually reports it.
    const result = await analyzeProject(sample('crossfile-vulnerable'));
    expect(result.engineVersion).toBe('0.3.0-beta.4');
  });

  it('reports no degradations for a corpus well inside every budget', async () => {
    const result = await analyzeProject(sample('crossfile-vulnerable'));
    expect(result.degradations).toEqual([]);
  });

  it('returns nothing for a directory with no source files', async () => {
    const result = await analyzeProject(sample('crossfile-fixtures/test-paths'));
    expect(result.findings).toEqual([]);
  });

  it('treats the scan root as the project boundary', async () => {
    // Scanning the fixtures ROOT unions several unrelated mini-projects, and the
    // union genuinely contains seventeen inline checks across eleven files — so
    // the rule fires, correctly. Recorded here because the obvious reading
    // ("none of the negative fixtures fire, so their parent must not either") is
    // wrong: "project" means "what you pointed the scanner at", and no analysis
    // can infer that sibling directories are separate products. Each fixture is
    // asserted silent individually above, which is the claim that matters.
    //
    // The count moves whenever a fixture is added — it was five across three
    // before `boost-*` — so it is described rather than asserted; what is
    // asserted is the shape (one finding, citing only the positive fixtures).
    const findings = await smellsIn(sample('crossfile-fixtures'));
    expect(findings).toHaveLength(1);
    const cited = new Set([
      findings[0]!.filePath,
      ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
    ]);
    // The checks it cites come from the fixtures that contain real inline
    // checks — never from `delegated`, `not-handlers`, or `test-paths`.
    for (const path of cited) {
      expect(path).not.toMatch(/^(?:delegated|not-handlers|test-paths)\//);
    }
  });
});

describe('config suppression reaches cross-file findings', () => {
  // The escape hatch. A design smell emitted at `high` under the default
  // `--fail-on high` gate that cannot be silenced leaves a team with one option:
  // stop passing the flag. That is strictly worse than letting them suppress the
  // one rule they have decided to accept.
  it('drops a finding whose rule is named for its primary path', async () => {
    const result = await analyzeProject(sample('crossfile-vulnerable'));
    expect(result.findings.some((f) => f.ruleId === 'VG-SMELL-010')).toBe(true);

    const suppressed = applyConfigSuppression(result, {
      suppress: [{ paths: ['**'], rules: ['VG-SMELL-010'] }],
    });
    expect(suppressed.findings.some((f) => f.ruleId === 'VG-SMELL-010')).toBe(false);
  });

  it('leaves a finding alone when the glob does not cover its primary path', async () => {
    const result = await analyzeProject(sample('crossfile-vulnerable'));
    const suppressed = applyConfigSuppression(result, {
      suppress: [{ paths: ['unrelated/**'], rules: ['VG-SMELL-010'] }],
    });
    expect(suppressed.findings.length).toBe(result.findings.length);
  });

  it('refuses a blanket wildcard at a security severity, and records the attempt', async () => {
    // The same severity gate the core path applies, reached through the same
    // function — not a second copy of the policy that could drift from it.
    const result = await analyzeProject(sample('crossfile-vulnerable'));
    const suppressed = applyConfigSuppression(result, { suppress: [{ paths: ['**'] }] });
    const survivor = suppressed.findings.find((f) => f.ruleId === 'VG-SMELL-010');
    expect(survivor).toBeDefined();
    expect(survivor!.suppressionOverridden).toEqual({ channel: 'config', scope: 'path' });
  });

  it('is a no-op when there is no config at all', async () => {
    const result = await analyzeProject(sample('crossfile-vulnerable'));
    expect(applyConfigSuppression(result, undefined)).toBe(result);
  });
});

describe('metrics come from the shared calculator', () => {
  it('carries fanIn alongside the rule’s own duplicatedCheckCount', async () => {
    // duplicatedCheckCount is the rule's own measurement; fanIn is the graph's.
    // Routing the second through metrics-calculator is what keeps two findings
    // in one report from disagreeing about a number they both call `fanIn`.
    const [finding] = await smellsIn(sample('crossfile-vulnerable'));
    expect(finding!.metrics?.duplicatedCheckCount).toBeGreaterThanOrEqual(3);
    expect(typeof finding!.metrics?.fanIn).toBe('number');
  });
});

describe('VG-SMELL-010 — regressions found by real-corpus evaluation', () => {
  // These three exist because fixtures written from a spec cannot contain a
  // failure mode nobody had thought of. Each was found by running the rule over
  // public repositories, and each would have silently stayed wrong.

  it('stays silent on LLM chat-message roles', async () => {
    // `m.role === 'assistant'` is not an authorization decision. The collision
    // is with the OpenAI chat-completion message shape, and it concentrates in
    // codebases that call an LLM — the same population as codebases written
    // with LLM help, i.e. exactly the corpus this project is about.
    expect(await smellsIn(sample('crossfile-fixtures/chat-roles'))).toEqual([]);
  });

  it('still fires when the receiver is a generic name but the value is a privilege', async () => {
    // The mirror of the test above, and the reason the two must be kept
    // together: the chat-role exclusion was first written to test the receiver
    // name before the compared value, which discarded `entry.role !== 'admin'`
    // on the strength of a loop variable's name.
    const findings = await smellsIn(sample('crossfile-fixtures/generic-receivers'));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(3);
  });

  it('does not count a delegating predicate call as an inline check', async () => {
    // `auth_mgr.is_admin(user)` is the centralised shape this rule recommends.
    // Counting it inverted the rule's meaning: it accused the codebases that had
    // done the right thing. What separates a boolean field from a predicate
    // method is the `(` that follows.
    expect(await smellsIn(sample('crossfile-fixtures/delegated'))).toEqual([]);
  });
});

describe('VG-SMELL-010 — Security Context Boost (#22d)', () => {
  // THE EXPECTED-VALUE TABLE, FIXED BEFORE THE IMPLEMENTATION EXISTED
  //
  //   fixture          sites files  path  layer  mutation  privilege   severity
  //   boost-none         3     2      -     -       -          -        medium
  //   boost-db           3     2      -     -       ✓          -        high
  //   boost-authpath     3     2      ✓     -       -          -        high
  //   crossfile-vuln     5     3      ✓     ✓       -          ✓        high
  //   generic-receivers  3     2      -     ✓       -          ✓        high
  //
  // The two `high` rows in the middle are the new claims; both were RED when
  // this block was first run, and `boost-none` was already green — which is the
  // point of writing them together. A boost implementation that turns everything
  // `high` passes the two new tests and fails the sentinel.

  it('stays at medium when no boost condition holds', async () => {
    // ★ THE SENTINEL. Before `boost-none/` existed, every VG-SMELL-010 finding
    // in the corpus was `high` — so a change that made severity constant would
    // have gone in green. This is the only fixture that can notice.
    const [finding] = await smellsIn(sample('crossfile-fixtures/boost-none'));
    expect(finding!.severity).toBe('medium');
  });

  it('escalates to high when the handlers mutate data', async () => {
    const [finding] = await smellsIn(sample('crossfile-fixtures/boost-db'));
    expect(finding!.severity).toBe('high');
  });

  it('escalates to high when the checks sit on a security path', async () => {
    const [finding] = await smellsIn(sample('crossfile-fixtures/boost-authpath'));
    expect(finding!.severity).toBe('high');
  });

  // ★ THE SENTINEL, MECHANISED. `boost-none` proves severity is not constant;
  // these prove condition ③ is about DATA MUTATION and not about the ordinary
  // furniture of a handler. Every line below shipped as `high` in the first
  // #22d implementation — each one on its own was enough to flip the sentinel —
  // and each is a read-only handler doing something unremarkable. They are
  // written as one line grafted onto `boost-none` because that is exactly how
  // they were found: the fixture is the control, the line is the only variable.
  //
  // The first four are why the bare verbs (`update`, `delete`, `insert`,
  // `destroy`) left `MUTATING_METHOD`; the last two are why a SQL verb pair now
  // has to be accompanied by SQL syntax. See the comments on both constants.
  const NON_MUTATIONS: ReadonlyArray<readonly [string, string, string]> = [
    ['a crypto digest', "import { createHash } from 'node:crypto';\n", "  void createHash('sha256').update(String(req.headers['x-api-key'])).digest('hex');"],
    // Plain `.destroy(`, NOT `?.destroy?.(`: optional chaining puts a `?`
    // between the name and the paren, which `METHOD_CALL` does not match, so the
    // optional-chained spelling would pass this test no matter what the set
    // contains. A row that cannot fail is not a test.
    ['a session teardown', '', '  req.session.destroy(() => undefined);'],
    ['a cache eviction', 'const responseCache = new Map<string, string>();\n', '  responseCache.delete(req.originalUrl);'],
    ['a progress bar', 'const progressBar = { update(_n: number) {} };\n', '  progressBar.update(1);'],
    ['prose containing "delete … from"', '', "  if (!listings.length) { res.status(409).json({ error: 'You cannot delete from an empty catalogue' }); }"],
    ['prose containing "update … set"', '', "  res.setHeader('X-Notice', 'Update your plan to set a higher listing limit');"],
    // The second round of prose counter-examples. A first fix asked the match to
    // carry `?`, `=`, `$1`, `where` or `values` — "a token statements have and
    // sentences do not". These two sentences have one each, which is how the
    // requirement moved from vocabulary to grammar (one table between the verbs).
    ['prose containing "delete from" and a question mark', '', "  if (!listings.length) { res.status(409).json({ error: 'Are you sure you want to delete from this list?' }); }"],
    ['prose containing "update … set" and an equals sign', '', "  res.setHeader('X-Notice', 'Update your plan to set a higher limit = more listings');"],
  ];

  it.each(NON_MUTATIONS)('stays at medium despite %s', async (_label, preamble, line) => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-boost-fp-'));
    try {
      await cpSample('crossfile-fixtures/boost-none', dir);
      const target = join(dir, 'catalog', 'listings.ts');
      const source = await readFile(target, 'utf8');
      const anchor = '  return res.json({ listings: listings.slice() });';
      expect(source).toContain(anchor); // the graft point must still exist
      await writeFile(target, preamble + source.replace(anchor, `${line}\n${anchor}`));

      const findings = await smellsIn(dir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.severity).toBe('medium');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  // The counterpart to the prose rows: the grammar constraint must not cost us
  // real statements. Grafted the same way, and deliberately NOT asserted through
  // `boost-db` — that fixture also calls `.updateOne(`, so it would go `high`
  // even if every SQL pattern here stopped matching, and the test would pass
  // while the feature was dead.
  const REAL_SQL: ReadonlyArray<readonly [string, string]> = [
    ['update … set', "  await pool.query('update price_book set cents = $1 where sku = $2', [1, 2]);"],
    ['delete from … where', "  await pool.query('delete from sessions where id = $1', [1]);"],
    ['insert into … values', "  await pool.query('insert into audit (a, b) values ($1, $2)', [1, 2]);"],
    ['a back-quoted table name', "  await pool.query('update `price_book` set cents = 1');"],
    ['a schema-qualified table', "  await pool.query('delete from public.sessions where id = 1');"],
  ];

  it.each(REAL_SQL)('still escalates on %s', async (_label, line) => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-boost-sql-'));
    try {
      await cpSample('crossfile-fixtures/boost-none', dir);
      const target = join(dir, 'catalog', 'listings.ts');
      const source = await readFile(target, 'utf8');
      const anchor = '  return res.json({ listings: listings.slice() });';
      expect(source).toContain(anchor);
      await writeFile(target, source.replace(anchor, `${line}\n${anchor}`));

      const findings = await smellsIn(dir);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.severity).toBe('high');
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('leaves confidence alone — the boost moves severity only', async () => {
    // Confidence answers "how sure is the DETECTION", severity answers "how bad
    // is it if true". A boost that raised both would be double-counting one
    // observation, and would make `high/high` the only combination the rule can
    // emit — see the confidence comment in the rule for why that is the failure
    // mode being avoided.
    for (const dir of ['boost-none', 'boost-db', 'boost-authpath']) {
      const [finding] = await smellsIn(sample(`crossfile-fixtures/${dir}`));
      expect(finding!.confidence, dir).toBe('medium');
    }
    const [vulnerable] = await smellsIn(sample('crossfile-vulnerable'));
    expect(vulnerable!.confidence).toBe('high');
  });

  it('does not disturb the pre-existing corpus', async () => {
    // The flagship positive stays high (it always had a privilege word), and
    // every negative stays silent. Stated here as well as above so a boost
    // regression names itself as a boost regression.
    const [vulnerable] = await smellsIn(sample('crossfile-vulnerable'));
    expect(vulnerable!.severity).toBe('high');
    const [generic] = await smellsIn(sample('crossfile-fixtures/generic-receivers'));
    expect(generic!.severity).toBe('high');
    for (const dir of [
      'crossfile-safe',
      'crossfile-fixtures/delegated',
      'crossfile-fixtures/two-sites',
      'crossfile-fixtures/single-file',
      'crossfile-fixtures/not-handlers',
      'crossfile-fixtures/test-paths',
      'crossfile-fixtures/chat-roles',
    ]) {
      expect(await smellsIn(sample(dir)), dir).toEqual([]);
    }
  });

  it('keeps findingId stable across the severity change', async () => {
    // ★ BASELINE CONTINUITY. These three ids were captured from the corpus
    // BEFORE #22d, when `boost-db` and `boost-authpath` were still `medium`.
    // They are asserted after the change, when both are `high`: same tree, same
    // sites, different severity, and the id must not have moved. If it did,
    // severity has leaked into `stableId` and every baseline in existence would
    // re-report its whole design-smell set the day a boost vocabulary changes.
    const expected: Record<string, string> = {
      'crossfile-vulnerable': 'vg-ag-1cd7zgc',
      'crossfile-fixtures/boost-db': 'vg-ag-9beirf',
      'crossfile-fixtures/boost-authpath': 'vg-ag-nk8flc',
    };
    for (const [dir, id] of Object.entries(expected)) {
      const [finding] = await smellsIn(sample(dir));
      expect(finding!.findingId, dir).toBe(id);
    }
  });
});

describe('collectScatteredAuthSites — the pre-threshold population (#22e)', () => {
  // Exported for the recall / sensitivity analysis, which has to answer "what
  // would this rule have found at a LOWER threshold" without the shipped
  // thresholds moving underneath it. Returning the sites before MIN_SITES and
  // MIN_FILES are applied is the whole point: a collector that pre-filtered
  // would make the analysis unable to see the cases it exists to count.

  const sitesIn = async (name: string): Promise<readonly CheckSite[]> => {
    const dir = sample(name);
    const budget = createBudget({});
    const files = await collectProjectFiles(dir, budget);
    return collectScatteredAuthSites(buildProjectIndex(dir, files, budget));
  };

  it('returns sites the shipped thresholds discard', async () => {
    // `two-sites` emits no finding (2 < MIN_SITES) and `single-file` emits none
    // (1 < MIN_FILES). Both still have sites, and this is where they are visible.
    const twoSites = await sitesIn('crossfile-fixtures/two-sites');
    expect(twoSites).toHaveLength(2);
    expect(new Set(twoSites.map((s) => s.filePath)).size).toBe(2);

    const singleFile = await sitesIn('crossfile-fixtures/single-file');
    expect(singleFile).toHaveLength(3);
    expect(new Set(singleFile.map((s) => s.filePath)).size).toBe(1);

    // …and neither of them is a finding, which is what makes the collector
    // worth exporting rather than reading `finding.relatedLocations`.
    expect(await smellsIn(sample('crossfile-fixtures/two-sites'))).toEqual([]);
    expect(await smellsIn(sample('crossfile-fixtures/single-file'))).toEqual([]);
  });

  it('applies every NEGATIVE condition, so a lower threshold cannot resurrect them', async () => {
    // The exclusions are not thresholds and must not be relaxed by the
    // sensitivity analysis: `delegated` has no inline checks at all, and
    // `not-handlers`/`test-paths` are outside the population.
    for (const dir of ['delegated', 'not-handlers', 'test-paths', 'chat-roles']) {
      expect(await sitesIn(`crossfile-fixtures/${dir}`), dir).toEqual([]);
    }
    expect(await sitesIn('crossfile-safe')).toEqual([]);
  });

  it('agrees with the finding the rule emits, site for site', async () => {
    const sites = await sitesIn('crossfile-vulnerable');
    const [finding] = await smellsIn(sample('crossfile-vulnerable'));
    expect(sites).toHaveLength(1 + (finding!.relatedLocations ?? []).length);
    expect(sites.map((s) => `${s.filePath}:${s.line}`).sort()).toEqual(
      [finding!.primaryLocation!, ...(finding!.relatedLocations ?? [])]
        .map((l) => `${l.filePath}:${l.startLine}`)
        .sort(),
    );
  });

  it('carries the per-site boost flags the finding aggregates', async () => {
    // Per-site, then ∃-aggregated — the same shape as `elevated`. The analysis
    // needs the per-site values, because "how many of the sites were on a
    // security path" is not recoverable from the finding's single severity.
    const db = await sitesIn('crossfile-fixtures/boost-db');
    expect(db.every((s) => s.mutatesData)).toBe(true);
    expect(db.some((s) => s.securityPath)).toBe(false);
    expect(db.some((s) => s.elevated)).toBe(false);

    const authpath = await sitesIn('crossfile-fixtures/boost-authpath');
    expect(authpath.every((s) => s.securityPath)).toBe(true);
    expect(authpath.some((s) => s.mutatesData)).toBe(false);

    const none = await sitesIn('crossfile-fixtures/boost-none');
    expect(
      none.some((s) => s.securityPath || s.routingLayer || s.mutatesData || s.elevated),
    ).toBe(false);
  });

  it('detects the routing layer even where it does not move severity', async () => {
    // ② is DETECTED and reported per site; it is deliberately not wired to
    // severity. See the measurement recorded on `ROUTING_LAYER_SEGMENT`.
    const generic = await sitesIn('crossfile-fixtures/generic-receivers');
    expect(generic.every((s) => s.routingLayer)).toBe(true);
    const none = await sitesIn('crossfile-fixtures/boost-none');
    expect(none.every((s) => s.routingLayer)).toBe(false);
  });

  it('does not apply MIN_SITES or MIN_FILES', async () => {
    // Stated as its own assertion because it is the contract the caller relies
    // on, and because a future "optimisation" that returns early once the
    // thresholds are known to fail would break it silently.
    const sites = await sitesIn('crossfile-fixtures/two-sites');
    expect(sites.length).toBeLessThan(3);
    expect(sites.length).toBeGreaterThan(0);
  });
});

describe('VG-SMELL-010 — the Python arm (#27b)', () => {
  // ★ WHY EVERY NEGATIVE HERE IS TESTED IN A PAIR.
  //
  // This repository has already been bitten by a gate that passed with its
  // fixtures deleted. A fixture asserted only to be SILENT proves nothing on its
  // own: it is silent when the negative condition works, and equally silent when
  // the rule cannot see the file at all, when the threshold is not met, or when
  // `languages` does not list the language. So each negative below is asserted
  // twice — silent as committed, and FIRING once the centralising element is
  // removed from a throwaway copy. The second half is the one that would fail if
  // the arm quietly died.
  //
  // The removals are string edits against text asserted to be present first, so
  // an edit that stops matching the fixture fails loudly instead of producing a
  // silent no-op copy that then "passes" the silence half.

  /** Copy a fixture, apply one text edit per file, and analyse the result. */
  const smellsInEdited = async (
    fixture: string,
    edits: ReadonlyArray<readonly [string, string, string]>,
  ): Promise<DesignSmellFinding[]> => {
    const dir = await mkdtemp(join(tmpdir(), 'vg-py-'));
    try {
      await cpSample(`crossfile-fixtures/${fixture}`, dir);
      for (const [relative, from, to] of edits) {
        const target = join(dir, ...relative.split('/'));
        const source = await readFile(target, 'utf8');
        // The graft point must exist. Without this the whole pair degenerates
        // into "the fixture is silent, twice".
        expect(source, `${fixture}/${relative} must contain: ${from}`).toContain(from);
        await writeFile(target, source.split(from).join(to));
      }
      return await smellsIn(dir);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  describe('Flask — a guard decorator stacked with the route decorator', () => {
    it('stays silent on the documented view-decorator layout', async () => {
      expect(await smellsIn(sample('crossfile-fixtures/smell-010-py-neg-flask'))).toEqual([]);
    });

    it('fires once the guard decorators are removed', async () => {
      // Same three handlers, same three role comparisons, same two files — the
      // ONLY difference is that nothing above the route says a check belongs
      // there any more. That is precisely the smell.
      const findings = await smellsInEdited('smell-010-py-neg-flask', [
        ['blog/posts.py', '@login_required\n', ''],
        ['blog/admin_area.py', '@role_required("admin")\n', ''],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(3);
      const cited = new Set([
        findings[0]!.filePath,
        ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
      ]);
      expect([...cited].sort()).toEqual(['blog/admin_area.py', 'blog/posts.py']);
    });

    it('is silenced by an unrecognised decorator name that refuses requests', async () => {
      // The vocabulary arm cannot be the only one: a project's guard may be
      // called anything. Renaming `role_required` to `ensure_ok` takes it out of
      // every word list — `ensure`, `ok` are not guard words here — and the
      // decorator is still recognised, because the def it names contains
      // `abort(403)`. Applied to the copy that otherwise FIRES, so the assertion
      // is about this mechanism and not about the fixture being quiet.
      const findings = await smellsInEdited('smell-010-py-neg-flask', [
        ['blog/posts.py', '@login_required\n', ''],
        ['blog/security.py', 'def role_required(role):', 'def ensure_ok(role):'],
        ['blog/admin_area.py', 'role_required', 'ensure_ok'],
      ]);
      expect(findings).toEqual([]);
    });
  });

  describe('FastAPI — dependency injection at two different scopes', () => {
    it('stays silent on the documented router + signature layout', async () => {
      expect(await smellsIn(sample('crossfile-fixtures/smell-010-py-neg-fastapi'))).toEqual([]);
    });

    it('fires once the router-level dependency list is removed', async () => {
      // `items` and `orders` carry `dependencies=[Depends(get_token_header)]` on
      // their `APIRouter(...)`. Removing it from both leaves four inline checks
      // across two files; `reports` and `exports` stay silent on their
      // signature-level dependency, which is what makes this test about the
      // ROUTER mechanism alone.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi', [
        ['app/routers/items.py', '    dependencies=[Depends(get_token_header)],\n', ''],
        ['app/routers/orders.py', '    dependencies=[Depends(get_token_header)],\n', ''],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(4);
      const cited = new Set([
        findings[0]!.filePath,
        ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
      ]);
      expect([...cited].sort()).toEqual(['app/routers/items.py', 'app/routers/orders.py']);
    });

    it('fires once the signature-level dependencies are removed', async () => {
      // The mirror image: `reports` and `exports` lose `Depends(...)` from their
      // multi-line signatures and become four sites across two files, while
      // `items` and `orders` stay silent on their router-level list.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi', [
        [
          'app/routers/reports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user',
        ],
        [
          'app/routers/exports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user',
        ],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(4);
      const cited = new Set([
        findings[0]!.filePath,
        ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
      ]);
      expect([...cited].sort()).toEqual(['app/routers/exports.py', 'app/routers/reports.py']);
    });

    it('is silenced again by a dependency list on include_router', async () => {
      // Router-level lists stripped — so the fixture fires — and the same
      // declaration re-added at the mount point in `main.py` instead. Silence
      // here means the `include_router(items.router, dependencies=[…])` arm
      // resolved `items` back through `from .routers import items` to
      // `app/routers/items.py`, which is the only way it could know which file
      // the list covers.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi', [
        ['app/routers/items.py', '    dependencies=[Depends(get_token_header)],\n', ''],
        ['app/routers/orders.py', '    dependencies=[Depends(get_token_header)],\n', ''],
        [
          'app/main.py',
          'from fastapi import FastAPI',
          'from fastapi import Depends, FastAPI\n\nfrom .dependencies import get_token_header',
        ],
        [
          'app/main.py',
          'app.include_router(items.router)\napp.include_router(orders.router)',
          'app.include_router(items.router, dependencies=[Depends(get_token_header)])\n' +
            'app.include_router(orders.router, dependencies=[Depends(get_token_header)])',
        ],
      ]);
      expect(findings).toEqual([]);
    });

    it('does not treat a non-security dependency as a guard', async () => {
      // ★ THE TEST THAT KEEPS THE FASTAPI ARM FROM BEING DEAD CODE. Silencing on
      // the bare presence of `Depends(` would pass every other test in this
      // block and make the arm incapable of ever firing on a framework where
      // essentially every handler takes an injected parameter.
      //
      // `common_parameters` is FastAPI's own documented non-security dependency.
      // The handlers keep it, lose the security one, and the four inline checks
      // become a finding.
      //
      // `Depends(get_session)` was the first choice here and it does NOT work:
      // `session` is an authentication guard word in `authz-lexicon`, so
      // `get_session` reaches `guardNames` and silences the handler. That is an
      // over-silence — a database session is not a checkpoint — and it is
      // recorded on `PY_SECURITY_DEPENDENCY_WORD` rather than worked around,
      // because the fix belongs in the shared lexicon and would move VG-SMELL-011
      // and 013 with it.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi', [
        [
          'app/routers/reports.py',
          'from ..dependencies import get_current_active_user',
          'from ..store import common_parameters',
        ],
        [
          'app/routers/exports.py',
          'from ..dependencies import get_current_active_user',
          'from ..store import common_parameters',
        ],
        [
          'app/routers/reports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user, commons: dict = Depends(common_parameters)',
        ],
        [
          'app/routers/exports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user, commons: dict = Depends(common_parameters)',
        ],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(4);
    });

    it('accepts Security(...) where it rejects the same argument under Depends(...)', async () => {
      // ★ AN A/B PAIR AGAINST THE TEST DIRECTLY ABOVE. Same fixture, same edit,
      // same argument — `common_parameters`, which carries no security word —
      // and the only difference is `Security` in place of `Depends`. FastAPI's
      // `Security` exists solely to declare scopes, so it is accepted without
      // looking at the argument; `Depends` is not. The row above fires, this one
      // does not, and neither could pass if the two were treated alike.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi', [
        [
          'app/routers/reports.py',
          'from ..dependencies import get_current_active_user',
          'from ..store import common_parameters',
        ],
        [
          'app/routers/exports.py',
          'from ..dependencies import get_current_active_user',
          'from ..store import common_parameters',
        ],
        [
          'app/routers/reports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user = Security(common_parameters)',
        ],
        [
          'app/routers/exports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user = Security(common_parameters)',
        ],
      ]);
      expect(findings).toEqual([]);
    });

    it('is silenced by a dependency list on the route decorator itself', async () => {
      // The per-route form, which `IndexedSymbol.decorators` cannot see because
      // it records only decorator NAMES — the guard is in an argument. Applied to
      // the copy that otherwise fires, so this is about the decorator block being
      // re-read and not about the fixture.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi', [
        ['app/routers/items.py', '    dependencies=[Depends(get_token_header)],\n', ''],
        ['app/routers/orders.py', '    dependencies=[Depends(get_token_header)],\n', ''],
        ['app/routers/items.py', '@router.get("/")', '@router.get("/", dependencies=[Depends(get_token_header)])'],
        [
          'app/routers/items.py',
          '@router.put("/{item_id}")',
          '@router.put("/{item_id}", dependencies=[Depends(get_token_header)])',
        ],
        ['app/routers/orders.py', '@router.get("/")', '@router.get("/", dependencies=[Depends(get_token_header)])'],
        [
          'app/routers/orders.py',
          '@router.post("/{order_id}/rename")',
          '@router.post("/{order_id}/rename", dependencies=[Depends(get_token_header)])',
        ],
      ]);
      expect(findings).toEqual([]);
    });

    it('is silenced project-wide by a dependency list on FastAPI(...)', async () => {
      // BOTH mechanisms stripped first, so all eight checks across all four
      // router files are live and the copy fires. One `dependencies=` on the
      // application constructor silences every one of them, which is the honest
      // scope: an application-level dependency runs before every path operation.
      const stripped: ReadonlyArray<readonly [string, string, string]> = [
        ['app/routers/items.py', '    dependencies=[Depends(get_token_header)],\n', ''],
        ['app/routers/orders.py', '    dependencies=[Depends(get_token_header)],\n', ''],
        [
          'app/routers/reports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user',
        ],
        [
          'app/routers/exports.py',
          'current_user: Annotated[User, Depends(get_current_active_user)]',
          'current_user',
        ],
      ];
      const loud = await smellsInEdited('smell-010-py-neg-fastapi', stripped);
      expect(loud).toHaveLength(1);
      expect(loud[0]!.metrics?.duplicatedCheckCount).toBe(8);

      const quiet = await smellsInEdited('smell-010-py-neg-fastapi', [
        ...stripped,
        [
          'app/main.py',
          'from fastapi import FastAPI',
          'from fastapi import Depends, FastAPI\n\nfrom .dependencies import get_token_header',
        ],
        ['app/main.py', 'app = FastAPI()', 'app = FastAPI(dependencies=[Depends(get_token_header)])'],
      ]);
      expect(quiet).toEqual([]);
    });
  });

  describe('FastAPI — the dependency ALIAS, found by a corpus sweep', () => {
    // ★ THE ONLY FINDING THE FIRST VERSION OF THIS ARM PRODUCED OVER
    // `paper_data/corpus1k`, AND IT WAS FALSE.
    //
    // 1,000 repositories, 630 with source, 236 containing Python, one finding:
    // `fastapi/full-stack-fastapi-template`, six `current_user.is_superuser`
    // checks across `api/routes/items.py` and `api/routes/users.py`. The
    // template's handlers never write `Depends(...)` — `api/deps.py` declares
    // `CurrentUser = Annotated[User, Depends(get_current_user)]` and every
    // handler writes `current_user: CurrentUser`.
    //
    // This fixture is that shape, and it is the most valuable one in the set,
    // because it is the only one whose failure mode was found by real code
    // rather than by the author of the detector.

    it('stays silent when the dependency is declared through a type alias', async () => {
      expect(await smellsIn(sample('crossfile-fixtures/smell-010-py-neg-fastapi-alias'))).toEqual([]);
    });

    it('fires once the alias annotation is dropped from the handlers', async () => {
      // The four superuser checks are untouched; only the declaration that a
      // dependency produced `current_user` is gone. Without it there is nothing
      // in the file, or in any other, that says these endpoints are guarded.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi-alias', [
        ['app/api/routes/items.py', 'current_user: CurrentUser', 'current_user'],
        ['app/api/routes/users.py', 'current_user: CurrentUser', 'current_user'],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(4);
      const cited = new Set([
        findings[0]!.filePath,
        ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
      ]);
      expect([...cited].sort()).toEqual(['app/api/routes/items.py', 'app/api/routes/users.py']);
    });

    it('does not silence on SessionDep, which is a dependency alias and not a guard', async () => {
      // ★ THE SENTINEL FOR THE ALIAS ARM. `SessionDep` is declared exactly the
      // same way as `CurrentUser` — `Annotated[…, Depends(…)]` at module scope —
      // and it must NOT silence, or the arm degenerates into "any alias at all",
      // which would make the FastAPI half of this rule unable to fire. The
      // handlers keep `session: SessionDep` in the edit above and the finding
      // still appears; here the alias is kept and `CurrentUser` swapped for it,
      // so `SessionDep` is the only alias left and the rule still speaks.
      const findings = await smellsInEdited('smell-010-py-neg-fastapi-alias', [
        ['app/api/routes/items.py', 'current_user: CurrentUser', 'current_user: SessionDep'],
        ['app/api/routes/users.py', 'current_user: CurrentUser', 'current_user: SessionDep'],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(4);
    });
  });

  describe('Django — URLconf wrappers, CBV mixins, and MIDDLEWARE', () => {
    it('stays silent on the documented URLconf + mixin layout', async () => {
      expect(await smellsIn(sample('crossfile-fixtures/smell-010-py-neg-django'))).toEqual([]);
    });

    it('fires once the URLconf wrappers are removed', async () => {
      // The four function views lose `login_required(...)` /
      // `permission_required(...)(...)` and become four sites across two files.
      // The two class-based views stay silent on their mixins, which keeps this
      // test about the URLCONF mechanism alone.
      const findings = await smellsInEdited('smell-010-py-neg-django', [
        ['shop/urls.py', 'login_required(views.order_list)', 'views.order_list'],
        [
          'shop/urls.py',
          'permission_required("shop.export_order")(views.order_export)',
          'views.order_export',
        ],
        ['support/urls.py', 'login_required(views.ticket_list)', 'views.ticket_list'],
        [
          'support/urls.py',
          'permission_required("support.close_ticket")(views.ticket_close)',
          'views.ticket_close',
        ],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(4);
      const cited = new Set([
        findings[0]!.filePath,
        ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
      ]);
      expect([...cited].sort()).toEqual(['shop/views.py', 'support/views.py']);
    });

    it('fires once the class-based-view mixins are removed', async () => {
      // `LoginRequiredMixin` and `PermissionRequiredMixin` come off the bases and
      // the four overridden methods become four sites across two files. The
      // function views keep their URLconf wrappers, so this is about the MIXIN
      // mechanism alone — and it is the one that reads
      // `IndexedSymbol.baseClasses`, which is new in 0.3.0-β.
      const findings = await smellsInEdited('smell-010-py-neg-django', [
        ['shop/views.py', 'class OrderAuditView(LoginRequiredMixin, TemplateView):', 'class OrderAuditView(TemplateView):'],
        [
          'support/views.py',
          'class TicketAuditView(PermissionRequiredMixin, TemplateView):',
          'class TicketAuditView(TemplateView):',
        ],
      ]);
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(4);
      const cited = new Set([
        findings[0]!.filePath,
        ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
      ]);
      expect([...cited].sort()).toEqual(['shop/views.py', 'support/views.py']);
    });

    it('is silenced project-wide by a security middleware in settings', async () => {
      // Applied to the copy that FIRES, so the assertion is about the middleware
      // and not about the fixture. One line in `settings.py` silences every
      // Python file in the project, which is the honest scope for a component
      // that runs before every view there is.
      const findings = await smellsInEdited('smell-010-py-neg-django', [
        ['shop/urls.py', 'login_required(views.order_list)', 'views.order_list'],
        [
          'shop/urls.py',
          'permission_required("shop.export_order")(views.order_export)',
          'views.order_export',
        ],
        ['support/urls.py', 'login_required(views.ticket_list)', 'views.ticket_list'],
        [
          'support/urls.py',
          'permission_required("support.close_ticket")(views.ticket_close)',
          'views.ticket_close',
        ],
        [
          'mysite/settings.py',
          '    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n',
          '    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n' +
            '    "shop.middleware.EnforceStaffMiddleware",\n',
        ],
      ]);
      expect(findings).toEqual([]);
    });

    it('is NOT silenced by an ordinary third-party middleware', async () => {
      // ★ THE SENTINEL FOR THE MIDDLEWARE ARM. "Any entry not under `django.`"
      // was the obvious rule and would have silenced the Django arm on nearly
      // every real project, since almost all of them append `corsheaders` or
      // `whitenoise`. Same edit as the test above with a CORS middleware in
      // place of a staff one; the finding must survive.
      const findings = await smellsInEdited('smell-010-py-neg-django', [
        ['shop/urls.py', 'login_required(views.order_list)', 'views.order_list'],
        [
          'shop/urls.py',
          'permission_required("shop.export_order")(views.order_export)',
          'views.order_export',
        ],
        ['support/urls.py', 'login_required(views.ticket_list)', 'views.ticket_list'],
        [
          'support/urls.py',
          'permission_required("support.close_ticket")(views.ticket_close)',
          'views.ticket_close',
        ],
        [
          'mysite/settings.py',
          '    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n',
          '    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n' +
            '    "corsheaders.middleware.CorsMiddleware",\n',
        ],
      ]);
      expect(findings).toHaveLength(1);
    });
  });

  describe('the positive control', () => {
    it('fires on a Flask application that inlines the same check three times', async () => {
      // ★ THE PROOF THAT THE ARM IS ALIVE. Everything else in this block is a
      // silence assertion, and a `languages` array that had never been changed
      // would satisfy all of them.
      const findings = await smellsIn(sample('crossfile-fixtures/smell-010-py-positive'));
      expect(findings).toHaveLength(1);
      expect(findings[0]!.metrics?.duplicatedCheckCount).toBe(3);
      expect(findings[0]!.severity).toBe('high');
      const cited = new Set([
        findings[0]!.filePath,
        ...(findings[0]!.relatedLocations ?? []).map((l) => l.filePath),
      ]);
      expect([...cited].sort()).toEqual(['catalogue/orders.py', 'catalogue/reports.py']);
    });

    it('goes silent project-wide behind a Flask before_request hook', async () => {
      // The application-wide Flask checkpoint. It is grafted at module scope
      // rather than inside `create_app`, which is where Flask's own single-module
      // examples put it; the factory below then shadows `app` locally, which is
      // meaningless to a lexical reader and keeps the edit to one replacement.
      //
      // The hook has to REFUSE to count: a `before_request` that only populates
      // `g.user` decides nothing, and silencing on the hook's existence alone
      // would silence every Flask application there is.
      const findings = await smellsInEdited('smell-010-py-positive', [
        [
          'catalogue/app.py',
          'from flask import Flask',
          'from flask import Flask, abort, request\n' +
            '\n' +
            'app = Flask(__name__)\n' +
            '\n' +
            '\n' +
            '@app.before_request\n' +
            'def require_signed_in_actor():\n' +
            '    if request.environ.get("actor") is None:\n' +
            '        abort(401)',
        ],
      ]);
      expect(findings).toEqual([]);
    });

    it('goes silent as soon as one guard decorator is added', async () => {
      // Two sites left is below MIN_SITES, so this is a threshold result as much
      // as a guard result — recorded rather than dressed up, because the pair
      // that carries the guard claim on its own is the Flask block above.
      const findings = await smellsInEdited('smell-010-py-positive', [
        ['catalogue/orders.py', '@bp.route("/")\n', '@bp.route("/")\n@login_required\n'],
      ]);
      expect(findings).toEqual([]);
    });
  });

  describe('the TS/JS arm is untouched by any of this', () => {
    it('keeps every pre-existing verdict', async () => {
      // Stated here as well as in the blocks above so a Python-arm regression
      // that leaked into the shared path names itself as one.
      const [vulnerable] = await smellsIn(sample('crossfile-vulnerable'));
      expect(vulnerable!.severity).toBe('high');
      expect(vulnerable!.metrics?.duplicatedCheckCount).toBe(5);
      for (const dir of [
        'crossfile-safe',
        'crossfile-fixtures/delegated',
        'crossfile-fixtures/two-sites',
        'crossfile-fixtures/single-file',
        'crossfile-fixtures/not-handlers',
        'crossfile-fixtures/test-paths',
        'crossfile-fixtures/chat-roles',
      ]) {
        expect(await smellsIn(sample(dir)), dir).toEqual([]);
      }
    });
  });
});

describe('the boost vocabulary versus the symbol table’s (#22d, measured)', () => {
  // ★ A MEASURED INTERACTION, PINNED SO IT CANNOT SILENTLY REVERSE.
  //
  // `symbol-table-builder` judges an EXPORTED symbol in a file whose path
  // carries a security word (`auth`, `middleware`, `guard`, `policy`, …) to be a
  // GUARD, and guards are excluded from this rule's population. So the boost's
  // "the check sits on a security path" condition and the symbol table's
  // "security paths hold guards" judgement point in opposite directions, and the
  // symbol table wins because it runs first.
  //
  // The consequence is concrete: in the named-export shape every other fixture
  // uses, handlers under `auth/` produce ZERO sites, so the `auth` half of the
  // path vocabulary is only reachable for handlers written INLINE at the route
  // registration. `boost-authpath/` is written that way for exactly this reason,
  // and this test is the evidence for that claim rather than a comment asserting
  // it.
  it('finds no sites for named exports under a security path', async () => {
    // Built on disk in a scratch directory rather than added to
    // `samples/crossfile-fixtures/` on purpose: a corpus directory that is
    // expected to be silent for a reason unrelated to the negative it is filed
    // under would be read as a sixth falsification case and maintained as one.
    const dir = await mkdtemp(join(tmpdir(), 'vg-boost-guard-'));
    await mkdir(resolve(dir, 'auth'), { recursive: true });
    await writeFile(
      resolve(dir, 'app.ts'),
      [
        "import express from 'express';",
        "import { listSessions, endSession } from './auth/sessions';",
        "import { listDevices } from './auth/devices';",
        'const app = express();',
        "app.get('/sessions', listSessions);",
        "app.post('/sessions/end', endSession);",
        "app.get('/devices', listDevices);",
        'export { app };',
        '',
      ].join('\n'),
    );
    const handler = (name: string): string =>
      [
        `export function ${name}(req: any, res: any) {`,
        '  const member = req.body.actor;',
        "  if (member.role !== 'editor') {",
        '    return res.status(403).send();',
        '  }',
        '  return res.json({ ok: true });',
        '}',
        '',
      ].join('\n');
    await writeFile(resolve(dir, 'auth', 'sessions.ts'), handler('listSessions') + handler('endSession'));
    await writeFile(resolve(dir, 'auth', 'devices.ts'), handler('listDevices'));

    try {
      const budget = createBudget({});
      const files = await collectProjectFiles(dir, budget);
      const project = buildProjectIndex(dir, files, budget);
      // The handlers ARE there…
      expect(files.map((f) => f.filePath).sort()).toEqual([
        'app.ts',
        'auth/devices.ts',
        'auth/sessions.ts',
      ]);
      // …and every one of them was judged a guard by placement…
      expect(project.symbols.guards.has(guardKey('auth/sessions.ts', 'listSessions'))).toBe(true);
      // …so the rule sees no population at all, boost or no boost.
      expect(collectScatteredAuthSites(project)).toEqual([]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
