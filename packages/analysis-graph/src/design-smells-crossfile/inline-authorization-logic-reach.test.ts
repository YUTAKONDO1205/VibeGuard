// VG-SMELL-013 — the REACHABILITY suite (#36).
//
// ★ WHAT THIS FILE IS FOR, AND WHY IT IS NOT MORE TESTS OF THE RULE.
//
// `inline-authorization-logic.ts` and `design-smells-crossfile/index.ts` both
// record the same measured fact, and it is the strongest negative result in this
// directory:
//
//     VG-SMELL-013   0 findings / 1000 repos   β; decision point reached 0×
//
// Not "rare". UNREACHABLE. Both arms failed for structural reasons that no
// threshold could move: Next.js `pages/api` endpoints emit no route
// registration, so premise (a) could not form, and their
// `const handler = withX(…, async (req,res) => {…})` arrows were not indexed as
// symbols, so premise (b) could not form. Of 569 authorization-shaped decisions
// in that corpus, exactly ONE lay inside an indexed handler body — and zero
// survived the subject check. LAION-AI/Open-Assistant carries this rule's exact
// target shape (a `withAnyRole` convention over 11 endpoints, one of which
// re-derives the role inline and returns 403) and was invisible to both arms.
//
// The registry's own instruction was: "A future wave should read that as
// 'extend the route/handler model', not 'add fixtures'." The model was extended
// in `structure-indexer` (file-path routes, wrapped-binding symbols). This file
// asserts that the extension actually closes the gap it was written for, ON THE
// SHAPE THAT WAS INVISIBLE — not on a fixture rewritten into Express until the
// existing rule could see it.
//
// ★ EVERY ASSERTION HERE NAMES A FUNNEL ROW, NOT JUST THE OUTCOME.
//
// The corpus sweep was instrumented rather than only counted, because a
// zero-finding sweep says nothing unless you can say which condition emptied it.
// A reachability test has the same obligation in reverse: "one finding" would
// pass just as happily if the rule started firing for a reason unrelated to the
// two mechanisms this wave added. So the two premises are asserted separately,
// each against the structural fact that used to be missing, and the false
// positives the widening could have introduced are asserted absent by name.

import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
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
const FIXTURE = resolve(REPO_ROOT, 'samples/crossfile-fixtures/smell-013-next-pages-api');

interface Analysis {
  project: ProjectIndex;
  findings: CrossFileFinding[];
  guards: EstablishedGuard[];
  decisions: readonly InlineDecision[];
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

let cached: Analysis | undefined;
async function fixture(): Promise<Analysis> {
  cached ??= await analyse(FIXTURE);
  return cached;
}

// ---------------------------------------------------------------------------
// The structural facts that did not exist before — asserted first, because the
// premises are what the corpus said were unformable.
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 reachability — the route/handler model reaches pages/api', () => {
  it('indexes every endpoint as a route, with the wrapper in the middleware position', async () => {
    const { project } = await fixture();
    const routes = [...project.structures.values()]
      .flatMap((s) => s.routes)
      .map((r) => `${r.method} ${r.path} [${r.middlewareNames.join(',')}] -> ${r.handlerName}`)
      .sort();
    // Exactly four, exactly these. Before this wave the list was EMPTY: no call
    // in the tree registers anything, which is the whole point of the fixture.
    expect(routes).toEqual([
      '* /api/invites [withAnyRole] -> handler',
      '* /api/members [withAnyRole] -> handler',
      '* /api/reports [withSession] -> handler',
      '* /api/teams [withAnyRole] -> handler',
    ]);
  });

  it('gives the wrapped arrow a handler ROLE and a real body span', async () => {
    const { project } = await fixture();
    const offender = project.structures.get('pages/api/reports.ts')!;
    const handler = offender.symbols.find((s) => s.name === 'handler')!;
    expect(handler.kind).toBe('route-handler');
    // `const handler = withSession(async (req, res) => {` on line 12, closing
    // `});` on line 17 — the arrow's own block, not the file. `export default
    // handler;` on line 19 is OUTSIDE it, which is what a guessed span would
    // have swallowed.
    expect(handler.startLine).toBe(12);
    expect(handler.endLine).toBe(17);
    expect(offender.blanked.slice(handler.bodyStart, handler.bodyEnd)).toContain('403');
  });

  it('does NOT index the page component or the api-named client as routes', async () => {
    // The false-positive controls, read off the index rather than off the rule.
    // A predicate that matched `pages/**` would put every React component into
    // the handler population; one that matched the word `api` would put every
    // HTTP client wrapper there.
    const { project } = await fixture();
    expect(project.structures.get('pages/index.tsx')!.routes).toEqual([]);
    // The NESTED page is the sharper control: a predicate loosened to "anything
    // under pages/" runs out of segments on `pages/index.tsx` before it can be
    // wrong, and matches this one. It default-exports a function exactly as an
    // endpoint does; the only thing separating them is the `api` segment.
    expect(project.structures.get('pages/dashboard/settings.tsx')!.routes).toEqual([]);
    expect(project.structures.get('lib/api.ts')!.routes).toEqual([]);
    expect(project.structures.get('lib/store.ts')!.routes).toEqual([]);
    const roles = [...project.structures.values()]
      .flatMap((s) => s.symbols.filter((x) => x.kind === 'route-handler').map((x) => s.filePath))
      .sort();
    expect(roles).toEqual([
      'pages/api/invites.ts',
      'pages/api/members.ts',
      'pages/api/reports.ts',
      'pages/api/teams.ts',
    ]);
  });
});

// ---------------------------------------------------------------------------
// Premise (a): a¹ → a² → a³. The corpus row that read 0.
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 reachability — premise (a) forms', () => {
  it('admits the wrapper as an established authorization guard', async () => {
    const { guards } = await fixture();
    expect(guards).toHaveLength(1);
    const guard = guards[0]!;
    expect(guard.name).toBe('withAnyRole');
    expect(guard.definitionFile).toBe('lib/authz.ts');
    // `MIN_GUARDED_ROUTES` is 3 and exactly three endpoints delegate: the
    // premise is met on the number, not past it, so a fixture that lost one
    // endpoint fails here rather than silently passing.
    expect(guard.routeCount).toBe(3);
  });

  it('and the wrapper is an AUTHORIZATION name while the other one is not', async () => {
    // The single most important negative in this rule, restated on this
    // fixture's own vocabulary: layered authentication plus a per-handler
    // privilege decision is the DEFAULT correct architecture, and a rule that
    // read `withSession` as a guard would fire on most correct Next.js projects.
    expect(isAuthzGuardName('withAnyRole')).toBe(true);
    expect(isAuthzGuardName('withSession')).toBe(false);
    expect(isAuthnGuardName('withSession')).toBe(true);
  });

  it('and the definition RESOLVED through the import graph, not by name', async () => {
    const { project, guards } = await fixture();
    const authz = project.structures.get('lib/authz.ts')!;
    expect(authz.symbols.some((s) => s.name === 'withAnyRole')).toBe(true);
    // (a³) in the funnel: `rohitg00__agentmemory` reached (a²) on the bare
    // lexicon word `scope` and was refused here. The same condition has to be
    // the one this fixture PASSES, or it is passing for a different reason.
    expect(guards[0]!.definitionFile).toBe(authz.filePath);
    expect(project.symbols.guards.has(`${authz.filePath} withAnyRole`)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Premise (b): the row that read 1-of-569, then 0 after the subject check.
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 reachability — premise (b) forms', () => {
  it('finds the inline decision inside the wrapped handler body', async () => {
    const { decisions } = await fixture();
    expect(decisions).toHaveLength(1);
    const site = decisions[0]!;
    expect(site.filePath).toBe('pages/api/reports.ts');
    expect(site.line).toBe(13);
    expect(site.handlerName).toBe('handler');
    expect(site.signature).toBe('user.role !==');
    expect(site.elevated).toBe(true);
  });

  it('and finds it in NO other endpoint — the guarded three decide nothing', async () => {
    const { decisions } = await fixture();
    expect(decisions.map((d) => d.filePath)).toEqual(['pages/api/reports.ts']);
  });

  it('and the guard’s OWN privilege comparison is not counted', async () => {
    // `lib/authz.ts` is a body full of privilege comparisons that refuse
    // requests — it is the design this rule recommends. `isAuthorizationHome`
    // removes it, and without that exclusion the premise would be manufactured
    // by the very file that licenses the finding.
    const { decisions } = await fixture();
    expect(decisions.some((d) => d.filePath === 'lib/authz.ts')).toBe(false);
    expect(decisions.some((d) => d.filePath === 'lib/session.ts')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// The finding itself.
// ---------------------------------------------------------------------------

describe('VG-SMELL-013 reachability — the finding', () => {
  it('reports exactly one finding, on the offending endpoint', async () => {
    const { findings } = await fixture();
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.ruleId).toBe('VG-SMELL-013');
    expect(f.filePath).toBe('pages/api/reports.ts');
    expect(f.startLine).toBe(13);
    // `high`, because the re-derived privilege is `admin`. `medium` here would
    // mean the elevated-word test ran against the blanked copy, where the
    // string literal has been erased.
    expect(f.severity).toBe('high');
    expect(f.confidence).toBe('medium');
    expect(f.scope).toBe('file');
  });

  it('cites the guard’s definition as a related location', async () => {
    const { findings } = await fixture();
    const related = findings[0]!.relatedLocations ?? [];
    expect(related.map((l) => `${l.filePath}:${l.startLine}`)).toEqual(['lib/authz.ts:9']);
    expect(findings[0]!.description).toContain('`withAnyRole`');
    expect(findings[0]!.description).toContain('lib/authz.ts');
  });

  it('defers nothing: VG-SMELL-010 is silent here, so the disjointness clause is not what let it speak', async () => {
    // 013 returns [] whenever 010 fires. If 010 fired on this fixture the
    // finding above would be impossible, so this assertion is what proves the
    // one finding came from 013's own conditions.
    const { scattered } = await fixture();
    expect(scattered).toEqual([]);
  });
});
