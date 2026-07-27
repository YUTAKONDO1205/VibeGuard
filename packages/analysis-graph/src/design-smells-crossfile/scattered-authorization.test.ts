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
    const result = await analyzeProject(sample('crossfile-vulnerable'));
    expect(result.engineVersion).toMatch(/^0\.3\.0-alpha/);
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
