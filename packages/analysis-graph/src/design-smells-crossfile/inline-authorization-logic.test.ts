// Tests for VG-SMELL-013 — Inline Authorization Logic.
//
// Run against the rule OBJECT rather than through `analyzeProject`, because the
// rule is deliberately not in `design-smells-crossfile/index.ts` yet and
// `analyzeProject` would not run it at all. Same shape as the VG-SMELL-021 and
// VG-SMELL-041 suites next door, and the same reason `scripts/crossfile-corpus-
// sweep.mjs` resolves rules from named exports: "implemented" and "shipped" are
// different states, and admission is a corpus sweep rather than a green suite.
//
// ★ EVERY NEGATIVE ASSERTS ITS PREMISE BEFORE IT ASSERTS SILENCE
//
// `design-smells-crossfile/index.ts` records that VG-SMELL-041's first
// submission had forty passing tests, nine negative fixtures, and 0% precision
// over 630 repositories. A negative test that only asserts `[]` passes just as
// happily when the rule has stopped working, when the fixture has drifted out of
// the shape it was written for, and when the detector never saw the file at all.
//
// This rule has two halves that can each refuse independently — a PROJECT half
// (`establishedAuthzGuards`: is there an adopted authorization guard) and a SITE
// half (`inlineAuthorizationDecisions`: is there an inline decision that
// refuses) — so both are exported and every negative below states which half
// refused it and asserts that the OTHER half still holds. A fixture that quietly
// loses its inline check now fails a test instead of passing one.

import { describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { designSmellLocationsAgree, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { createBudget } from '../budget.js';
import { buildProjectIndex, collectProjectFiles } from '../project.js';
import type { CrossFileFinding, ProjectIndex } from '../types.js';
import { isAuthnGuardName, isAuthzGuardName } from './authz-lexicon.js';
import { scatteredAuthorization } from './scattered-authorization.js';
import {
  establishedAuthzGuards,
  inlineAuthorizationDecisions,
  inlineAuthorizationLogic,
  type EstablishedGuard,
  type InlineDecision,
} from './inline-authorization-logic.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);
const fixture = (name: string): string => sample(`crossfile-fixtures/${name}`);

interface Analysis {
  project: ProjectIndex;
  /** What VG-SMELL-013 reports. */
  findings: CrossFileFinding[];
  /** The PROJECT half of the rule: guards the project has adopted. */
  guards: EstablishedGuard[];
  /** The SITE half: inline decisions that survived every per-site negative. */
  decisions: readonly InlineDecision[];
  /** What VG-SMELL-010 reports over the same tree, for the disjointness tests. */
  scattered: CrossFileFinding[];
}

async function analyse(dir: string): Promise<Analysis> {
  const budget = createBudget({});
  const files = await collectProjectFiles(dir, budget);
  const project = buildProjectIndex(dir, files, budget);
  return {
    project,
    findings: inlineAuthorizationLogic.analyze({ project, budget }),
    guards: establishedAuthzGuards(project),
    decisions: inlineAuthorizationDecisions(project),
    scattered: scatteredAuthorization.analyze({ project, budget }),
  };
}

/**
 * How many route registrations name `guardName` in the middleware position.
 *
 * Read off the index rather than off the rule, so a premise assertion is
 * independent of the code it is a premise for. `MIN_GUARDED_ROUTES` is what
 * `smell-013-neg-two-routes` is written against, and a test that got the count
 * from `establishedAuthzGuards` could not distinguish "mounted twice" from
 * "mounted three times and rejected for another reason".
 */
function mountCount(project: ProjectIndex, guardName: string): number {
  let seen = 0;
  for (const structure of project.structures.values()) {
    for (const route of structure.routes) {
      if (route.middlewareNames.includes(guardName)) seen += 1;
    }
  }
  return seen;
}

/** The single finding, asserted to be single first so a failure names the count. */
function only(findings: CrossFileFinding[]): DesignSmellFinding {
  expect(findings).toHaveLength(1);
  return findings[0] as DesignSmellFinding;
}

// ---------------------------------------------------------------------------
// THE decisive negative. First in the file, and the fixture was written first.
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 — layered authentication plus inline authorization is CORRECT', () => {
  // `authenticate` mounted globally and the privilege decision written in the
  // handler is the default architecture of most Express applications. A rule
  // that fires on it is not noisy, it is wrong about the majority of correct
  // code — worse than the VG-SMELL-041 regression this directory records,
  // because 041's false positives were rare and this shape is everywhere.
  //
  // The whole reason `authz-lexicon.ts` splits `AUTHN_GUARD_WORD` from
  // `AUTHZ_GUARD_WORD` is this test.

  it('says nothing when the only mounted guard authenticates', async () => {
    expect((await analyse(fixture('smell-013-neg-authn-only'))).findings).toEqual([]);
  });

  it('and the silence is condition (a), not a fixture that lost its check', async () => {
    const { project, guards, decisions } = await analyse(fixture('smell-013-neg-authn-only'));

    // Premise 1: a guard really is mounted, on four routes — comfortably past
    // `MIN_GUARDED_ROUTES`, so the count is not what refused this project.
    expect(mountCount(project, 'authenticateSession')).toBe(4);

    // Premise 2: the inline decision really is there and really is detected.
    // This is the assertion that makes the negative non-vacuous: if the site
    // scan broke, or the fixture drifted, this fails instead of passing.
    expect(decisions.map((d) => `${d.filePath}:${d.line}`)).toEqual([
      'controllers/reports-controller.ts:8',
    ]);

    // The verdict: no AUTHORIZATION guard has been adopted, so there is nothing
    // this handler can be accused of having duplicated.
    expect(guards).toEqual([]);
  });

  it('classifies the guard name the way the shared lexicon does', async () => {
    // Stated as a property of the vocabulary rather than of the fixture, so a
    // future widening of `AUTHZ_GUARD_WORD` that swallowed `authenticate` would
    // fail here — at the vocabulary — rather than three rules away.
    expect(isAuthzGuardName('authenticateSession')).toBe(false);
    expect(isAuthnGuardName('authenticateSession')).toBe(true);
    for (const name of ['requireLogin', 'verifyToken', 'jwtMiddleware', 'passportAuth']) {
      expect(isAuthzGuardName(name), name).toBe(false);
    }
    for (const name of ['requireRole', 'requireAdmin', 'authorize', 'checkPermissions']) {
      expect(isAuthzGuardName(name), name).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// The positives
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 — the handler that bypassed the convention', () => {
  it('fires exactly once, at high severity, on the admin decision', async () => {
    const finding = only((await analyse(fixture('smell-013-bypassed-guard'))).findings);
    expect(finding.ruleId).toBe('VG-SMELL-013');
    expect(finding.filePath).toBe('controllers/team-controller.ts');
    expect(finding.startLine).toBe(20);
    // `high` because the decision names an administrator-level privilege.
    expect(finding.severity).toBe('high');
    expect(finding.confidence).toBe('medium');
    expect(finding.scope).toBe('file');
  });

  it('points at a line that really is the inline check', async () => {
    // A line number written as a literal is only as good as the file it indexes.
    // Reading the line back means a fixture edit that shifts the code fails the
    // suite instead of silently re-pointing the assertion at another statement.
    const { project, findings } = await analyse(fixture('smell-013-bypassed-guard'));
    const finding = only(findings);
    const source = project.files.find((f) => f.filePath === finding.filePath)!;
    expect(source.lines[finding.startLine! - 1]).toContain("req.user.role !== 'admin'");
  });

  it('cites the guard it says the project already has', async () => {
    // The finding IS a relationship between two places. A reader who cannot see
    // the second one has to take on trust that it exists.
    const { project, findings } = await analyse(fixture('smell-013-bypassed-guard'));
    const finding = only(findings);
    const related = finding.relatedLocations ?? [];
    const guardLocation = related.find((l) => l.filePath === 'access/require-team-role.ts');
    expect(guardLocation).toBeDefined();
    const source = project.files.find((f) => f.filePath === guardLocation!.filePath)!;
    expect(source.lines[guardLocation!.startLine - 1]).toContain('export function requireTeamRole');
    expect(finding.description).toContain('requireTeamRole');
    expect(finding.description).toContain('3 route registrations');
  });

  it('counts the guard as one of the places the policy now lives', async () => {
    const finding = only((await analyse(fixture('smell-013-bypassed-guard'))).findings);
    // One inline site plus the guard: the claim is that the decision exists in
    // two places, and a count of 1 would read as the opposite of the claim.
    expect(finding.metrics?.duplicatedCheckCount).toBe(2);
    // The count stays checkable by counting the rows the finding carries.
    expect(finding.metrics!.duplicatedCheckCount).toBe(1 + (finding.relatedLocations ?? []).length);
    // Fan numbers come from `metrics-calculator`, not from this rule.
    expect(finding.metrics).toHaveProperty('fanIn');
    expect(finding.metrics).toHaveProperty('fanOut');
  });

  it('marks the security context and keeps primaryLocation honest', async () => {
    const finding = only((await analyse(fixture('smell-013-bypassed-guard'))).findings);
    expect(finding.securityContext?.containsAuthorizationLogic).toBe(true);
    // The other five flags describe what the code CONTAINS and this rule
    // established exactly one of them.
    expect(Object.keys(finding.securityContext ?? {})).toEqual(['containsAuthorizationLogic']);
    expect(designSmellLocationsAgree(finding)).toBe(true);
    expect(finding.primaryLocation?.filePath).toBe(finding.filePath);
    expect(finding.primaryLocation?.startLine).toBe(finding.startLine);
  });

  it('carries real evidence text for every location it cites', async () => {
    const finding = only((await analyse(fixture('smell-013-bypassed-guard'))).findings);
    for (const location of [finding.primaryLocation!, ...(finding.relatedLocations ?? [])]) {
      expect(location.evidence, `${location.filePath}:${location.startLine}`).toBeTruthy();
      expect(location.startLine).toBeGreaterThan(0);
    }
    expect(finding.evidence?.length).toBe(2);
  });

  it('is deterministic across runs', async () => {
    const a = only((await analyse(fixture('smell-013-bypassed-guard'))).findings);
    const b = only((await analyse(fixture('smell-013-bypassed-guard'))).findings);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });

  it('drops to medium when the decision names no elevated privilege', async () => {
    // The fixture that stops the severity field from being a constant. A rule
    // that reports everything at `high` under the default `--fail-on high` gate
    // has no severity field at all.
    const finding = only((await analyse(fixture('smell-013-scope-check'))).findings);
    expect(finding.severity).toBe('medium');
    expect(finding.filePath).toBe('controllers/billing-controller.ts');
    expect(finding.description).toContain('requireBillingPermission');
  });
});

// ---------------------------------------------------------------------------
// The negatives, each naming the half that refused it
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 — the per-site negatives', () => {
  /**
   * Each case names the condition it exercises, the half of the rule that must
   * refuse, and what must still be TRUE in the fixture for the refusal to mean
   * anything. `guardName` and `mounts` are the premise: the project half held.
   */
  const SITE_NEGATIVES: ReadonlyArray<{
    dir: string;
    condition: string;
    guardName: string;
    mounts: number;
  }> = [
    {
      dir: 'smell-013-neg-ownership',
      condition: 'an ownership decision sits next to the privilege term (OWNERSHIP_NEIGHBOURHOOD)',
      guardName: 'requireDocumentRole',
      mounts: 3,
    },
    {
      dir: 'smell-013-neg-authz-home',
      condition: 'the handler lives where authorization belongs (AUTHORIZATION_HOME_WORD)',
      guardName: 'requireVaultScope',
      mounts: 3,
    },
    {
      dir: 'smell-013-neg-delegated',
      condition: 'a method CALL is delegation, not an inline check',
      guardName: 'requireReportRole',
      mounts: 3,
    },
    {
      dir: 'smell-013-neg-no-denial',
      condition: 'branching on privilege is not refusing (DENIAL_WINDOW)',
      guardName: 'requireInvoiceScope',
      mounts: 3,
    },
    {
      dir: 'smell-013-neg-chat-role',
      condition: 'the receiver names a message, not a subject (SUBJECT_WORD)',
      guardName: 'requireThreadPermission',
      mounts: 3,
    },
    {
      dir: 'smell-013-neg-test-path',
      condition: 'the handler is test scaffolding (isTestPath)',
      guardName: 'requireAssetPolicy',
      mounts: 3,
    },
  ];

  it.each(SITE_NEGATIVES)('$dir — silent because $condition', async ({ dir, guardName, mounts }) => {
    const analysis = await analyse(fixture(dir));

    // Premise: the PROJECT half held. The guard is mounted, it is recognised as
    // an authorization guard, and it was adopted. So the only thing that can be
    // keeping the rule quiet is the site half.
    expect(mountCount(analysis.project, guardName)).toBe(mounts);
    expect(analysis.guards.map((g) => g.name)).toEqual([guardName]);

    // The site half refused.
    expect(analysis.decisions).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('smell-013-neg-two-routes — silent because two mounts are not a convention', async () => {
    const analysis = await analyse(fixture('smell-013-neg-two-routes'));

    // Premise, from the index rather than from the rule: the guard IS mounted,
    // and mounted twice. `MIN_GUARDED_ROUTES` is the only thing between this
    // fixture and a finding.
    expect(mountCount(analysis.project, 'requireLedgerRole')).toBe(2);
    expect(isAuthzGuardName('requireLedgerRole')).toBe(true);

    // Premise: the inline decision is detected. Both halves are one condition
    // away from firing, which is what makes the threshold testable at all.
    expect(analysis.decisions.map((d) => `${d.filePath}:${d.line}`)).toEqual([
      'controllers/ledger-controller.ts:12',
    ]);

    expect(analysis.guards).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('smell-013-neg-guard-file — silent because the guard is defined in that very file', async () => {
    const analysis = await analyse(fixture('smell-013-neg-guard-file'));

    // Premise: the convention holds and the site IS detected — this negative is
    // the only one where the refusal happens in `analyze` rather than in the
    // site scan, so `decisions` is deliberately non-empty here.
    expect(analysis.guards.map((g) => `${g.name}@${g.definitionFile}`)).toEqual([
      'requireTierPolicy@gating/tier-checks.ts',
    ]);
    expect(analysis.decisions.map((d) => d.filePath)).toEqual(['gating/tier-checks.ts']);

    // Condition (c): the guard is not somewhere else, it is right here.
    expect(analysis.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Mutual exclusion with VG-SMELL-010
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 and VG-SMELL-010 never speak about the same line', () => {
  // Two design smells firing on one line reads to a user as two problems. The
  // predicates are made disjoint by asking 010 rather than by copying its
  // thresholds — see the comment on the exclusion in `analyze`.

  it('is silent on the corpus VG-SMELL-010 was built for', async () => {
    const analysis = await analyse(sample('crossfile-vulnerable'));
    expect(analysis.scattered).toHaveLength(1);
    expect(analysis.findings).toEqual([]);
    // And the reason is the premise, independently of the disjointness clause:
    // that service has no guard at all, which is exactly what 010 is reporting.
    expect(analysis.guards).toEqual([]);
  });

  it('VG-SMELL-010 is silent on the corpus VG-SMELL-013 was built for', async () => {
    const analysis = await analyse(fixture('smell-013-bypassed-guard'));
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.scattered).toEqual([]);
  });

  it('yields to VG-SMELL-010 when both premises hold at once', async () => {
    // The only fixture where the disjointness clause is the sole reason for
    // silence, so it is the only one that tests it. Both halves of 013 hold —
    // the convention is adopted AND three inline sites were detected across two
    // files — and 010 has the wider statement, so 013 says nothing.
    const analysis = await analyse(fixture('smell-013-neg-scattered-too'));

    expect(analysis.guards.map((g) => g.name)).toEqual(['requireProjectRole']);
    expect(analysis.decisions.length).toBeGreaterThanOrEqual(3);
    expect(new Set(analysis.decisions.map((d) => d.filePath)).size).toBeGreaterThanOrEqual(2);

    expect(analysis.scattered).toHaveLength(1);
    expect(analysis.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The zero-false-positive contract
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 — the precision contract', () => {
  // `samples/safe`, `samples/crossfile-safe` and `samples/design-safe` are the
  // E1 = 0 / E3 = 0 gates, and `samples/vulnerable` carries the E2 = 51 count
  // that no new rule may move. This rule is not registered yet, so it cannot
  // move them today; these assertions are what must stay true on the day it is.
  const SILENT = [
    'safe',
    'vulnerable',
    'design-safe',
    'design-smells',
    'crossfile-safe',
    'context-window',
    'proto-safe',
    'proto-pollution',
    'embedded',
  ];

  it.each(SILENT)('reports nothing on samples/%s', async (dir) => {
    expect((await analyse(sample(dir))).findings).toEqual([]);
  });

  it('is silent on the well-factored service even though it has the convention', async () => {
    // ★ THE SHARPEST OF THESE. `samples/crossfile-safe` is `crossfile-vulnerable`
    // refactored to one `requireRole` middleware, so condition (a) is SATISFIED
    // — this is the fixture where the rule has the most to be tempted by. It
    // stays silent because the handlers no longer decide anything: the guard
    // does. A design smell that fires on the reference implementation of its own
    // recommendation is a bug, not a near miss.
    const analysis = await analyse(sample('crossfile-safe'));
    expect(analysis.guards.map((g) => g.name)).toEqual(['requireRole']);
    expect(analysis.decisions).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('is silent over the whole fixture corpus, where VG-SMELL-010 speaks', async () => {
    // Scanning the fixtures ROOT unions every cross-file fixture in the
    // repository into one "project" — "project" means what you pointed the
    // scanner at, and no analysis can infer that sibling directories are
    // separate products. The union contains fifteen inline decisions across
    // seven files, so 010 fires and 013 defers to it. Recorded rather than
    // asserted in detail because the number moves whenever a fixture is added;
    // what is asserted is the shape.
    const analysis = await analyse(sample('crossfile-fixtures'));
    expect(analysis.guards.length).toBeGreaterThanOrEqual(9);
    expect(analysis.decisions.length).toBeGreaterThanOrEqual(10);
    expect(analysis.scattered).toHaveLength(1);
    expect(analysis.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Generated projects: the boundaries and the bounds
// ---------------------------------------------------------------------------

const temporary: string[] = [];

async function writeProject(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-smell-013-'));
  temporary.push(dir);
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return dir;
}

/**
 * The canonical shape, with the number of guarded routes as a parameter.
 *
 * On disk under `samples/` are the cases a reader learns something from. "Two
 * mounts is silent and three is not" is a statement about a number, and nobody
 * learns it from reading a third router file — so it is generated, the same
 * split `high-fanout-security-module.test.ts` makes for its numeric boundaries.
 */
async function projectWithMounts(mounts: number): Promise<string> {
  const registrations = [];
  for (let i = 0; i < mounts; i += 1) {
    registrations.push(`router.get('/guarded-${i}', requireOrgRole, guarded${i});`);
  }
  const guardedHandlers = [];
  for (let i = 0; i < mounts; i += 1) {
    guardedHandlers.push(
      `export async function guarded${i}(_req: any, res: any) {\n  return res.json({ n: ${i} });\n}\n`,
    );
  }
  return writeProject({
    'access/org-access.ts': [
      'export function requireOrgRole(req: any, res: any, next: () => void) {',
      "  if (req.user.role !== 'admin') {",
      "    return res.status(403).json({ error: 'forbidden' });",
      '  }',
      '  return next();',
      '}',
      '',
    ].join('\n'),
    'controllers/org-controller.ts': [
      ...guardedHandlers,
      'export async function orgSummary(req: any, res: any) {',
      "  if (req.user.role !== 'admin') {",
      "    return res.status(403).json({ error: 'forbidden' });",
      '  }',
      '  return res.json({ ok: true });',
      '}',
      '',
    ].join('\n'),
    'routes/org-routes.ts': [
      "import { Router } from 'express';",
      "import { requireOrgRole } from '../access/org-access';",
      `import { orgSummary${Array.from({ length: mounts }, (_, i) => `, guarded${i}`).join('')} } from '../controllers/org-controller';`,
      '',
      'export const router = Router();',
      '',
      ...registrations,
      "router.get('/summary', orgSummary);",
      '',
    ].join('\n'),
  });
}

describe('VG-SMELL-013 — boundaries and bounds', () => {
  it('two mounts are silent and three are a convention', async () => {
    const two = await analyse(await projectWithMounts(2));
    expect(two.decisions).toHaveLength(1);
    expect(two.guards).toEqual([]);
    expect(two.findings).toEqual([]);

    const three = await analyse(await projectWithMounts(3));
    expect(three.decisions).toHaveLength(1);
    expect(three.guards).toHaveLength(1);
    expect(three.findings).toHaveLength(1);
  });

  it('refuses a guard name that resolves to no definition in the repository', async () => {
    // ★ FROM THE CORPUS, NOT FROM IMAGINATION. `rohitg00__agentmemory` in
    // `paper_data/corpus1k` puts `scope` in a pre-handler argument position six
    // times. `scope` is a word in the lexicon's `AUTHZ_GUARD_WORD`, so
    // `isAuthzGuardName` says yes and the mount count clears `MIN_GUARDED_ROUTES`
    // on a project that has no guard at all. Requiring the name to resolve to a
    // definition is the only thing that refuses it, so that requirement gets a
    // test rather than a comment.
    expect(isAuthzGuardName('scope')).toBe(true);
    const dir = await writeProject({
      'controllers/search-controller.ts': [
        'export async function runSearch(req: any, res: any) {',
        "  if (req.user.role !== 'admin') {",
        "    return res.status(403).json({ error: 'forbidden' });",
        '  }',
        '  return res.json({ hits: [] });',
        '}',
        '',
      ].join('\n'),
      'routes/search-routes.ts': [
        "import { Router } from 'express';",
        "import { runSearch } from '../controllers/search-controller';",
        'export const router = Router();',
        'const scope = 0.5;',
        "router.get('/a', scope, runSearch);",
        "router.get('/b', scope, runSearch);",
        "router.get('/c', scope, runSearch);",
        '',
      ].join('\n'),
    });
    const analysis = await analyse(dir);
    // The premise looks satisfied right up to the last condition.
    expect(mountCount(analysis.project, 'scope')).toBe(3);
    expect(analysis.guards).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('refuses when one guard name resolves to two different definitions', async () => {
    // A name mounted from two places that means two different things is not one
    // convention, and condition (c) — "defined in a different file from the
    // handler" — then has no single answer. Refusing beats picking.
    const guard = [
      'export function requireRole(req: any, res: any, next: () => void) {',
      "  if (req.user.role !== 'admin') return res.status(403).end();",
      '  return next();',
      '}',
      '',
    ].join('\n');
    const dir = await writeProject({
      'alpha/guard.ts': guard,
      'beta/guard.ts': guard,
      'controllers/thing-controller.ts': [
        'export async function thingStatus(req: any, res: any) {',
        "  if (req.user.role !== 'admin') {",
        "    return res.status(403).json({ error: 'forbidden' });",
        '  }',
        '  return res.json({ ok: true });',
        '}',
        '',
      ].join('\n'),
      'routes/alpha-routes.ts': [
        "import { Router } from 'express';",
        "import { requireRole } from '../alpha/guard';",
        "import { thingStatus } from '../controllers/thing-controller';",
        'export const alphaRouter = Router();',
        "alphaRouter.get('/a', requireRole, thingStatus);",
        "alphaRouter.get('/b', requireRole, thingStatus);",
        '',
      ].join('\n'),
      'routes/beta-routes.ts': [
        "import { Router } from 'express';",
        "import { requireRole } from '../beta/guard';",
        "import { thingStatus } from '../controllers/thing-controller';",
        'export const betaRouter = Router();',
        "betaRouter.get('/c', requireRole, thingStatus);",
        "betaRouter.get('/d', thingStatus);",
        '',
      ].join('\n'),
    });
    const analysis = await analyse(dir);
    expect(mountCount(analysis.project, 'requireRole')).toBe(3);
    expect(analysis.guards).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('says nothing about a Python project with the identical shape', async () => {
    // `languages` is enforced by `runCrossFileRules`, but this rule ALSO filters
    // per file — the lesson VG-SMELL-010 wrote down after its Python arm ran
    // live and unfixtured on Flask handlers no test covered. A polyglot
    // repository passes the project-level gate and then hands every `.py` file
    // to a rule whose negative conditions know nothing about `Depends()`,
    // `before_request`, or a URLconf wrapper.
    const dir = await writeProject({
      'access/org_access.py': [
        'def require_org_role(handler):',
        '    def wrapped(request):',
        "        if request.user.role != 'admin':",
        '            return respond(403)',
        '        return handler(request)',
        '    return wrapped',
        '',
      ].join('\n'),
      'views/org_views.py': [
        'def org_summary(request):',
        "    if request.user.role != 'admin':",
        '        return respond(403)',
        '    return respond(200)',
        '',
      ].join('\n'),
    });
    const analysis = await analyse(dir);
    expect(analysis.decisions).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('finishes well inside the three-second contract on a pathological file', async () => {
    // Every regex in this rule carries a bounded quantifier and horizontal
    // whitespace is `[^\S\r\n]{0,4}`, never `\s*` — the shape that produced this
    // project's A1 ReDoS findings. Cross-file rule patterns are outside the
    // `scripts/sec-a1-catalog.mjs` census, which reads `packages/rules` only, so
    // the bound is the only protection and this is the only place it is
    // exercised against adversarial input.
    const spaces = ' '.repeat(4000);
    const dir = await writeProject({
      'access/org-access.ts': [
        'export function requireOrgRole(req: any, res: any, next: () => void) {',
        "  if (req.user.role !== 'admin') return res.status(403).end();",
        '  return next();',
        '}',
        '',
      ].join('\n'),
      'controllers/wide.ts': [
        'export async function wideHandler(req: any, res: any) {',
        `  if (req.user.role${spaces}!==${spaces}'admin') {`,
        "    return res.status(403).json({ error: 'forbidden' });",
        '  }',
        `  const padding = '${'x'.repeat(20000)}';`,
        '  return res.json({ padding });',
        '}',
        '',
      ].join('\n'),
      'routes/org-routes.ts': [
        "import { Router } from 'express';",
        "import { requireOrgRole } from '../access/org-access';",
        "import { wideHandler } from '../controllers/wide';",
        'export const router = Router();',
        "router.get('/a', requireOrgRole, wideHandler);",
        "router.get('/b', requireOrgRole, wideHandler);",
        "router.get('/c', requireOrgRole, wideHandler);",
        "router.get('/d', wideHandler);",
        '',
      ].join('\n'),
    });

    const started = Date.now();
    const analysis = await analyse(dir);
    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(3000);
    // The 4,000-space gap is far past `[^\S\r\n]{0,4}`, so the comparison is not
    // recognised — which is the correct outcome for a bounded pattern and is
    // asserted so the timing above cannot be passing for the wrong reason (a
    // rule that found nothing because it crashed would also be fast).
    expect(analysis.guards).toHaveLength(1);
    expect(analysis.decisions).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });
});

describe('VG-SMELL-013 — rule metadata', () => {
  it('declares what the runner and the sweep read', async () => {
    expect(inlineAuthorizationLogic.ruleId).toBe('VG-SMELL-013');
    expect(inlineAuthorizationLogic.languages).toEqual(['typescript', 'javascript']);
    expect(inlineAuthorizationLogic.defaultConfidence).toBe('medium');
    // `CWE-862` (Missing Authorization) is deliberately absent: nothing is
    // missing in the code this rule reports. See the comment on `cwe`.
    expect(inlineAuthorizationLogic.cwe).toEqual(['CWE-284']);
  });

  it('is registered, which the corpus sweep is what earned', async () => {
    // This assertion replaces the pre-admission one that asserted the OPPOSITE.
    // It was written to fail on the day the rule was registered, and it did.
    //
    // What paid for the change: a sweep of all 1,000 repositories in
    // `paper_data/corpus1k` — 0 findings, 0 errors, 0 rule crashes — run through
    // `scripts/crossfile-corpus-sweep.mjs`, which resolves candidates from the
    // package's named exports precisely so a rule can be measured before it is
    // admitted. A green suite was the precondition, not the evidence.
    const { crossFileRules } = await import('./index.js');
    expect(crossFileRules.map((r) => r.ruleId)).toContain('VG-SMELL-013');
  });
});

// The generated projects are removed after the suite; the committed fixtures
// under `samples/` are the ones a reader is meant to find.
import { afterAll } from 'vitest';
afterAll(async () => {
  for (const dir of temporary) await rm(dir, { recursive: true, force: true });
});
