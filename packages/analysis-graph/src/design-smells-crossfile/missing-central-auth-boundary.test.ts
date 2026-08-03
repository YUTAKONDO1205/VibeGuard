// End-to-end tests for VG-SMELL-011, run over the real sample corpus on disk.
//
// Deliberately NOT unit tests over hand-built `ProjectIndex` objects, for the
// reason `scattered-authorization.test.ts` gives: the rule's risk is not in its
// own arithmetic, it is in whether the indexer, the import graph and the symbol
// table together produce the facts it assumes. A hand-built index tests the rule
// against the author's belief about those facts rather than against the facts,
// and every defect this package has had to repair — the `export *` barrel, the
// `req.get('authorization')` pseudo-route, the registration line that was one
// too low — was a wrong belief of exactly that kind.
//
// ★ WHY THE RULE IS INVOKED DIRECTLY AND NOT THROUGH `analyzeProject`
//
// VG-SMELL-011 is not in `crossFileRules` and must not be until the corpus sweep
// that gates admission comes back clean (see the header of
// `design-smells-crossfile/index.ts` for what that gate cost the last two rules
// that skipped it). `analyzeProject` runs the registry, so testing through it
// would be testing an empty set. The helper below is a deliberate mirror of the
// dispatch in `project.ts`, including the `languages` filter — the same ★MIRROR
// discipline `scripts/crossfile-corpus-sweep.mjs` documents, and for the same
// reason: measuring a rule on inputs the product would never hand it reports a
// precision the product does not have.
//
// ★ WHAT A GREEN RUN HERE DOES AND DOES NOT ESTABLISH
//
// Nothing in this file is evidence that the rule works on code nobody here
// wrote. The fixtures and the detector have the same author, which is the
// condition under which VG-SMELL-041 shipped forty passing tests and 0%
// precision. What these tests establish is that each named negative condition is
// load-bearing: every negative directory is also GRAFTED — one identifier, one
// line, one path renamed — and asserted to fire afterwards, so a silence that
// came from the wrong condition fails the suite instead of passing it.

import { describe, expect, it } from 'vitest';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createBudget } from '../budget.js';
import { buildProjectIndex, collectProjectFiles } from '../project.js';
import type { CrossFileFinding } from '../types.js';
import { missingCentralAuthBoundary, narrowGuardName } from './missing-central-auth-boundary.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const sample = (name: string): string => resolve(REPO_ROOT, 'samples', name);
const fixture = (name: string): string => sample(`crossfile-fixtures/${name}`);

/** ★MIRROR of the dispatch in `project.ts`. See the file header. */
const analyse = async (dir: string): Promise<CrossFileFinding[]> => {
  const budget = createBudget();
  const files = await collectProjectFiles(dir, budget);
  const project = buildProjectIndex(dir, files, budget);
  const present = new Set(project.files.map((f) => f.language));
  if (
    !missingCentralAuthBoundary.languages.includes('*') &&
    !missingCentralAuthBoundary.languages.some((language) => present.has(language))
  ) {
    return [];
  }
  return missingCentralAuthBoundary.analyze({ project, budget });
};

/**
 * Copy a fixture, graft one edit onto the copy, analyse the copy, delete it.
 *
 * The copy is what makes the grafted-line tests honest: they mutate a throwaway
 * tree, so the committed fixture stays the control they are measured against.
 * Same device `scattered-authorization.test.ts` uses.
 */
const grafted = async (
  name: string,
  edit: (dir: string) => Promise<void>,
): Promise<CrossFileFinding[]> => {
  const dir = await mkdtemp(join(tmpdir(), 'vg-smell-011-'));
  try {
    await cp(fixture(name), dir, { recursive: true });
    await edit(dir);
    return await analyse(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

const replaceIn = async (dir: string, file: string, from: string, to: string): Promise<void> => {
  const path = join(dir, file);
  const before = await readFile(path, 'utf8');
  // Assert the graft actually landed. A `replace` that matched nothing produces
  // an unchanged tree, and an unchanged tree that stays silent would be recorded
  // as "the condition is load-bearing" when it means "the test did nothing".
  expect(before, `${file} does not contain ${from}`).toContain(from);
  await writeFile(path, before.split(from).join(to), 'utf8');
};

const appendTo = async (dir: string, file: string, text: string): Promise<void> => {
  const path = join(dir, file);
  const before = await readFile(path, 'utf8');
  await writeFile(path, `${before}${text}`, 'utf8');
};

/** The source line a location points at, read back from the file it names. */
const lineAt = async (dir: string, filePath: string, line: number): Promise<string> => {
  const text = await readFile(join(dir, filePath), 'utf8');
  return text.split(/\r?\n/)[line - 1] ?? '';
};

describe('VG-SMELL-011 — the positive', () => {
  const DIR = 'smell-011-unguarded-admin-route';

  it('fires exactly once', async () => {
    expect(await analyse(fixture(DIR))).toHaveLength(1);
  });

  it('points at the registration that omits the guard, not at the guard', async () => {
    const [finding] = await analyse(fixture(DIR));
    expect(finding!.filePath).toBe('routes/admin-routes.ts');
    // Line numbers are read back from the file rather than asserted as literals:
    // `RouteBinding.line` is one too low for a registration written at column 1
    // (see `registrationLine`), and a literal would encode whichever value the
    // implementation happened to produce on the day it was written.
    const text = await lineAt(fixture(DIR), finding!.filePath!, finding!.startLine!);
    expect(text).toContain(".post('/users/:id/promote'");
  });

  it('names the guarded registrations that establish the convention', async () => {
    const [finding] = await analyse(fixture(DIR));
    const related = finding!.relatedLocations ?? [];
    const convention = related.filter((l) => (l.evidence ?? '').includes('carries `requireAdmin`'));
    // The accusation is about the SET. Three is the threshold, so three is the
    // minimum that may be cited; a finding citing fewer is asking the reader to
    // take the convention on trust.
    expect(convention.length).toBeGreaterThanOrEqual(3);
    for (const location of convention) {
      const text = await lineAt(fixture(DIR), location.filePath, location.startLine ?? 0);
      expect(text, `${location.filePath}:${location.startLine}`).toContain('requireAdmin');
    }
  });

  it('cites the guard definition, which is in another file', async () => {
    const [finding] = await analyse(fixture(DIR));
    const definition = (finding!.relatedLocations ?? []).find((l) =>
      (l.evidence ?? '').startsWith('definition of'),
    );
    expect(definition?.filePath).toBe('middleware/require-admin.ts');
    expect(definition?.filePath).not.toBe(finding!.filePath);
    const text = await lineAt(fixture(DIR), definition!.filePath, definition!.startLine ?? 0);
    expect(text).toContain('function requireAdmin');
  });

  it('is high severity because the surface names an administrator', async () => {
    const [finding] = await analyse(fixture(DIR));
    expect(finding!.severity).toBe('high');
    expect(finding!.securityContext?.containsAuthorizationLogic).toBe(true);
  });

  it('is medium confidence because the convention spans two files', async () => {
    const [finding] = await analyse(fixture(DIR));
    expect(finding!.confidence).toBe('medium');
  });

  it('carries the guard module fan-in as its measurement', async () => {
    const [finding] = await analyse(fixture(DIR));
    // Two route files import `middleware/require-admin.ts`. The number travels
    // with the finding because it is what makes one more omission notable.
    expect(finding!.metrics?.fanIn).toBe(2);
    // Deliberately absent: `duplicatedCheckCount`. It is VG-SMELL-010's
    // measurement of INLINE duplication, which is the thing this smell's subject
    // is the cure for.
    expect(finding!.metrics?.duplicatedCheckCount).toBeUndefined();
  });

  it('keeps primaryLocation in agreement with the flat fields', async () => {
    const [finding] = await analyse(fixture(DIR));
    expect(finding!.primaryLocation?.filePath).toBe(finding!.filePath);
    expect(finding!.primaryLocation?.startLine).toBe(finding!.startLine);
    expect(finding!.scope).toBe('project');
  });

  it('is deterministic across runs', async () => {
    const a = await analyse(fixture(DIR));
    const b = await analyse(fixture(DIR));
    const key = (findings: CrossFileFinding[]): string[] =>
      findings.flatMap((f) => [
        `${f.filePath}:${f.startLine}`,
        ...(f.relatedLocations ?? []).map((l) => `${l.filePath}:${l.startLine}:${l.evidence}`),
      ]);
    expect(key(a)).toEqual(key(b));
  });
});

describe('VG-SMELL-011 — the medium band exists', () => {
  const DIR = 'smell-011-unguarded-write';

  it('stays medium when nothing names an elevated privilege', async () => {
    const [finding] = await analyse(fixture(DIR));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('medium');
  });

  it('drops to low confidence when the convention is one file deep', async () => {
    const [finding] = await analyse(fixture(DIR));
    expect(finding!.confidence).toBe('low');
  });

  it('reports an authentication guard as authentication, not authorization', async () => {
    const [finding] = await analyse(fixture(DIR));
    // `requireLogin` decides WHO YOU ARE. The lexicon separates the two
    // questions and the finding must not overstate which one it found.
    expect(finding!.securityContext?.containsAuthLogic).toBe(true);
    expect(finding!.securityContext?.containsAuthorizationLogic).toBeUndefined();
  });
});

describe('VG-SMELL-011 — the precision contract', () => {
  // THE gate. A design smell that fires on well-factored code is a bug, not a
  // near miss, and these three trees are the shipped statement of that contract.
  it.each(['safe', 'design-safe', 'crossfile-safe'])('stays silent on samples/%s', async (name) => {
    expect(await analyse(sample(name))).toEqual([]);
  });

  const NEGATIVES = [
    'smell-011-neg-public-route',
    'smell-011-neg-global-mount',
    'smell-011-neg-parent-mount',
    'smell-011-neg-barrel-mount',
    'smell-011-neg-decorated-handler',
    'smell-011-neg-test-paths',
    'smell-011-neg-guard-in-same-file',
    'smell-011-neg-two-guarded',
    'smell-011-neg-all-guarded',
    'smell-011-neg-input-validator',
    'smell-011-neg-external-guard',
    'smell-011-neg-separate-router',
  ];

  it.each(NEGATIVES)('stays silent on %s', async (name) => {
    expect(await analyse(fixture(name))).toEqual([]);
  });
});

describe('VG-SMELL-011 — every negative is silent for the reason it is named for', () => {
  // ★ THE POINT OF THIS BLOCK. A directory that produces no finding proves
  // nothing on its own: it also passes when the rule declined it for a reason
  // the directory was never built to test — most easily, because some unrelated
  // condition failed first. Each graft below changes ONE thing, and the finding
  // has to appear. `replaceIn` asserts that the text it was asked to change was
  // actually there, so a graft that silently matched nothing fails loudly.

  it('public-by-design: the same registration on a non-public path fires', async () => {
    const findings = await grafted('smell-011-neg-public-route', (dir) =>
      replaceIn(dir, 'routes/account-routes.ts', "'/password/reset'", "'/accounts/:id/lock'"),
    );
    expect(findings).toHaveLength(1);
  });

  it('global mount: deleting the app.use(requireLogin) line fires', async () => {
    const findings = await grafted('smell-011-neg-global-mount', (dir) =>
      replaceIn(dir, 'app.ts', 'app.use(requireLogin);', '// removed by the graft'),
    );
    expect(findings).toHaveLength(1);
  });

  it('parent mount: removing the guard from the mount fires', async () => {
    const findings = await grafted('smell-011-neg-parent-mount', (dir) =>
      replaceIn(dir, 'app.ts', "'/admin', requireAdmin, invoiceRouter", "'/admin', invoiceRouter"),
    );
    expect(findings).toHaveLength(1);
  });

  it('barrel: the export * line alone is what carries the protection', async () => {
    // The mount stays exactly as it is. Only the barrel's re-export goes away,
    // so the mount target still resolves and its subtree no longer contains the
    // routes. If `RE_EXPORT` were deleted from the rule, the unmodified fixture
    // would behave like this graft — which is the false positive VG-SMELL-052
    // shipped, reproduced here as a control.
    const findings = await grafted('smell-011-neg-barrel-mount', (dir) =>
      replaceIn(
        dir,
        'routes/admin/index.ts',
        "export * from './billing-routes';",
        "export const adminArea = 'billing';",
      ),
    );
    expect(findings).toHaveLength(1);
  });

  it('decorator: removing @UseGuards fires', async () => {
    const findings = await grafted('smell-011-neg-decorated-handler', (dir) =>
      replaceIn(dir, 'routes/report-routes.ts', '  @UseGuards(OwnerGuard)\n', ''),
    );
    expect(findings).toHaveLength(1);
  });

  it('test paths: the same tree outside a test directory fires', async () => {
    const findings = await grafted('smell-011-neg-test-paths', async (dir) => {
      await cp(join(dir, 'tests'), join(dir, 'src'), { recursive: true });
      await rm(join(dir, 'tests'), { recursive: true, force: true });
    });
    expect(findings).toHaveLength(1);
  });

  it('same file: moving the guard into its own module fires', async () => {
    const findings = await grafted('smell-011-neg-guard-in-same-file', async (dir) => {
      await cp(
        fixture('smell-011-neg-parent-mount/middleware/require-owner.ts'),
        join(dir, 'require-owner.ts'),
      );
      const routes = join(dir, 'routes/report-routes.ts');
      const text = await readFile(routes, 'utf8');
      const guardStart = text.indexOf('export function requireOwner');
      const guardEnd = text.indexOf('\n}\n', guardStart) + 3;
      expect(guardStart).toBeGreaterThan(0);
      await writeFile(
        routes,
        `import { requireOwner } from '../require-owner';\n${text.slice(0, guardStart)}${text.slice(guardEnd)}`,
        'utf8',
      );
      // `../types` is one level up from `routes/`, and the copied guard now sits
      // at the root, so its own import has to be corrected or it resolves to
      // nothing and the graft would be testing resolution rather than the rule.
      await replaceIn(dir, 'require-owner.ts', "from '../types'", "from './types'");
    });
    expect(findings).toHaveLength(1);
  });

  it('threshold: a third guarded write fires', async () => {
    const findings = await grafted('smell-011-neg-two-guarded', (dir) =>
      appendTo(
        dir,
        'routes/order-routes.ts',
        "orderRouter.delete('/orders/:id', requireAdmin, removeOrder);\n",
      ),
    );
    expect(findings).toHaveLength(1);
  });

  it('mutating methods: turning the unguarded read into a write fires', async () => {
    const findings = await grafted('smell-011-neg-all-guarded', (dir) =>
      replaceIn(dir, 'routes/order-routes.ts', "orderRouter.get('/orders'", "orderRouter.post('/orders/import'"),
    );
    expect(findings).toHaveLength(1);
  });

  it('vocabulary: renaming the validator to a guard name fires', async () => {
    // A pure rename — nothing about the code's behaviour changes — so the only
    // thing under test is the guard vocabulary's refusal of `validateOrderBody`.
    const findings = await grafted('smell-011-neg-input-validator', async (dir) => {
      for (const file of ['middleware/validate-order-body.ts', 'routes/order-routes.ts']) {
        await replaceIn(dir, file, 'validateOrderBody', 'requireOwnerRole');
      }
    });
    expect(findings).toHaveLength(1);
  });

  it('external guard: giving the project its own definition of it fires', async () => {
    const findings = await grafted('smell-011-neg-external-guard', async (dir) => {
      await writeFile(
        join(dir, 'authenticate.ts'),
        [
          "import type { NextFunction, Request, Response } from 'express';",
          '',
          'export function authenticate(req: Request, res: Response, next: NextFunction) {',
          "  if (!req.headers.authorization) {",
          "    return res.status(401).json({ error: 'unauthenticated' });",
          '  }',
          '  return next();',
          '}',
          '',
        ].join('\n'),
        'utf8',
      );
      await replaceIn(
        dir,
        'routes/order-routes.ts',
        "import passport from 'passport';",
        "import { authenticate } from '../authenticate';",
      );
      await replaceIn(dir, 'routes/order-routes.ts', "passport.authenticate('jwt')", 'authenticate');
    });
    expect(findings).toHaveLength(1);
  });

  it('co-location: the same unguarded write inside the guarding file fires', async () => {
    // `updateOrder` rather than a new handler, because a handler this file does
    // not import does not resolve — see the measured limit on `definingFile` —
    // and the graft would then be testing name resolution instead of locality.
    const findings = await grafted('smell-011-neg-separate-router', (dir) =>
      appendTo(dir, 'routes/order-routes.ts', "orderRouter.patch('/orders/:id/notes', updateOrder);\n"),
    );
    expect(findings).toHaveLength(1);
  });
});

describe('VG-SMELL-011 — the guard vocabulary is the narrow one', () => {
  // Exported for exactly this: a negative fixture whose symbol never qualified in
  // the first place is a vacuous negative, and the whole corpus could be vacuous
  // while staying green. Same argument as `classifyBoilerplateName` in
  // VG-SMELL-052.

  it('admits names the lexicon recognises as authorization or authentication', () => {
    for (const name of ['requireAdmin', 'requireOwner', 'requireLogin', 'authenticate', 'authorize']) {
      expect(narrowGuardName(name), name).toBe(true);
    }
  });

  it('refuses middleware that is not a guard', () => {
    for (const name of ['validateOrderBody', 'rateLimit', 'upload', 'asyncHandler', 'compress']) {
      expect(narrowGuardName(name), name).toBe(false);
    }
  });

  it('refuses `requireAuth`, and that is a recorded recall limit rather than a bug', () => {
    // The lexicon holds `auth` in NEITHER guard set on purpose, so the single
    // commonest guard name in Express code does not establish a convention here.
    // Asserted so the limit is visible in the suite rather than only in a
    // comment: widening it belongs in `authz-lexicon.ts`, where every consumer's
    // fixtures move at once.
    expect(narrowGuardName('requireAuth')).toBe(false);
    expect(narrowGuardName('authGuard')).toBe(false);
  });
});

describe('VG-SMELL-011 — the fixture corpus as one project', () => {
  it('says nothing at all when every fixture is unioned into one scan', async () => {
    // Scanning the fixtures ROOT unions a hundred-odd files written for other
    // rules into one "project", and one of them — `smell-011-neg-global-mount/`
    // — mounts a guard with `app.use(requireLogin)`. That is a project-wide
    // silencer by design, so the union produces nothing, and the result is
    // recorded rather than skipped because it is the clearest demonstration this
    // suite has of how strong negative condition 2 is.
    //
    // "Project" means what you pointed the scanner at; no analysis can infer
    // that sibling directories are separate products. Each fixture is asserted
    // individually above, which is the claim that matters.
    expect(await analyse(sample('crossfile-fixtures'))).toEqual([]);
  });
});
