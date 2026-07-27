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
import { resolve } from 'node:path';
import { isDesignSmellFinding, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { analyzeProject, applyConfigSuppression } from '../project.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);

/**
 * Narrowing through `isDesignSmellFinding` rather than a cast is deliberate:
 * it asserts that what the rule emits really does land in the design-smell
 * category, which is the key the E2 partition contract is written against. A
 * cast would let a rule that forgot the category still satisfy these tests
 * while silently joining the finding set `samples/vulnerable` counts.
 */
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
    // union genuinely contains five inline checks across three files — so the
    // rule fires, correctly. Recorded here because the obvious reading ("none of
    // the negative fixtures fire, so their parent must not either") is wrong:
    // "project" means "what you pointed the scanner at", and no analysis can
    // infer that sibling directories are separate products. Each fixture is
    // asserted silent individually above, which is the claim that matters.
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
