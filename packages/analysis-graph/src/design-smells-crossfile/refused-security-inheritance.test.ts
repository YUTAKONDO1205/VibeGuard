// Tests for VG-SMELL-030 — Refused Security Inheritance.
//
// Run against the rule OBJECT rather than through `analyzeProject`, because the
// rule is deliberately not in `design-smells-crossfile/index.ts` yet and
// `analyzeProject` would not run it at all. Same reason and same shape as the
// VG-SMELL-021 and VG-SMELL-041 tests next door.
//
// ★ EVERY NEGATIVE ASSERTS ITS PREMISE BEFORE IT ASSERTS SILENCE
//
// This rule has six independent conditions and none of them is numeric, which
// makes a vacuous pass EASIER to write here than in VG-SMELL-021, not harder: a
// fixture whose base stopped being resolvable, or whose override drifted to a
// two-statement body, produces a perfect `toEqual([])` and proves nothing. So
// every negative states, in order:
//
//   1. the inheritance EDGE exists (`resolvedInheritanceEdges`),
//   2. the base's body and the override's body classify as what the fixture is
//      named for (`classifyOverride`),
//   3. and only then, that the rule is silent.
//
// The two helper functions that make that possible are exported from the rule
// for this reason and no other — the same argument `securityOperations` carries
// in `high-fanout-security-module.ts`.
//
// ★ WHY SOME PROJECTS ARE ON DISK AND SOME ARE GENERATED
//
// Each named negative condition is a DESIGN IDIOM — the Null Object, the
// Template Method, the fail-closed throw — and an idiom is something a reader
// should be able to open and recognise, so those live under
// `samples/crossfile-fixtures/` with a README explaining what they falsify.
// The cases that are statements about the CLASSIFIER rather than about a design
// ("a JavaScript `return True` is not the literal", "a `return False` sibling is
// not differential evidence") are generated into a temp directory: nobody learns
// anything from reading a fourth four-file project to check a one-line rule, and
// putting them on disk would bury the eleven that carry meaning.

import { afterAll, describe, expect, it } from 'vitest';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { designSmellLocationsAgree, type DesignSmellFinding } from '@vibeguard/findings-schema';
import { createBudget } from '../budget.js';
import { buildProjectIndex, collectProjectFiles } from '../project.js';
import type { CrossFileFinding, IndexedSymbol, ProjectIndex, StructureIndex } from '../types.js';
import {
  classifyOverride,
  refusedSecurityInheritance,
  resolvedInheritanceEdges,
  type OverrideShape,
} from './refused-security-inheritance.js';

const REPO_ROOT = resolve(__dirname, '../../../..');
const fixture = (name: string): string => resolve(REPO_ROOT, 'samples', 'crossfile-fixtures', name);

interface Analysis {
  findings: CrossFileFinding[];
  project: ProjectIndex;
}

async function analyse(dir: string): Promise<Analysis> {
  const budget = createBudget({});
  const files = await collectProjectFiles(dir, budget);
  const project = buildProjectIndex(dir, files, budget);
  return { findings: refusedSecurityInheritance.analyze({ project, budget }), project };
}

/** `Sub->Base` for every edge the rule resolved, sorted so it can be compared. */
const edgeNames = (analysis: Analysis): string[] =>
  resolvedInheritanceEdges(analysis.project)
    .map((e) => `${e.subclass.name}->${e.base.name}`)
    .sort();

/** The shape the rule reads out of one class's method. `absent` when there is none. */
function shapeOf(
  analysis: Analysis,
  filePath: string,
  className: string,
  methodName: string,
  baseClassName: string,
): OverrideShape {
  const structure: StructureIndex = analysis.project.structures.get(filePath)!;
  const method: IndexedSymbol | undefined = structure.symbols.find(
    (s) => s.enclosingClass === className && s.name === methodName,
  );
  return classifyOverride(structure, method, methodName, baseClassName);
}

// ---------------------------------------------------------------------------
// Generated projects, for statements about the classifier
// ---------------------------------------------------------------------------

const temporary: string[] = [];

afterAll(async () => {
  for (const dir of temporary) await rm(dir, { recursive: true, force: true });
});

async function writeProject(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-smell-030-'));
  temporary.push(dir);
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return dir;
}

interface Family {
  /** Base class name. Defaults to a name that carries authorization vocabulary. */
  base?: string;
  /** Method the family declares. Defaults to `authorize`. */
  method?: string;
  /** The base's body for that method, verbatim, without braces. */
  baseBody?: string;
  /** Subclass name → its override body, or `null` for "does not override". */
  subs: Record<string, string | null>;
  /** Directory the family lives in. Carries the corroborating word by default. */
  dir?: string;
}

const kebab = (name: string): string =>
  name.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();

/**
 * A one-base TypeScript family with a chosen body per class.
 *
 * Every condition the classifier decides is a parameter, so a test reads as the
 * sentence it is checking ("a `return False` sibling is not evidence") rather
 * than as a directory listing.
 */
async function tsFamily(family: Family): Promise<string> {
  const base = family.base ?? 'AccessPolicy';
  const method = family.method ?? 'authorize';
  const dir = family.dir ?? 'src/policies';
  const files: Record<string, string> = {};

  files[`${dir}/base.ts`] =
    'export interface Subject { id: string; permissions: string[] }\n\n' +
    `export class ${base} {\n` +
    `  ${method}(subject: Subject): boolean {\n` +
    `    ${family.baseBody ?? "return subject.permissions.includes('read');"}\n` +
    '  }\n' +
    '}\n';

  for (const [name, body] of Object.entries(family.subs)) {
    files[`${dir}/${kebab(name)}.ts`] =
      `import { ${base} } from './base.js';\n` +
      "import type { Subject } from './base.js';\n\n" +
      `export class ${name} extends ${base} {\n` +
      (body === null
        ? `  describe(subject: Subject): string {\n    return subject.id;\n  }\n`
        : `  ${method}(subject: Subject): boolean {\n    ${body}\n  }\n`) +
      '}\n';
  }
  return writeProject(files);
}

/** The Python twin of `tsFamily`. Bodies are written already indented by four. */
async function pyFamily(family: Family): Promise<string> {
  const base = family.base ?? 'AccessPolicy';
  const method = family.method ?? 'authorize';
  const dir = family.dir ?? 'app/policies';
  const files: Record<string, string> = { [`${dir}/__init__.py`]: '' };

  files[`${dir}/base.py`] =
    `class ${base}:\n` +
    `    def ${method}(self, subject):\n` +
    `        ${family.baseBody ?? 'return "read" in subject.permissions'}\n`;

  for (const [name, body] of Object.entries(family.subs)) {
    files[`${dir}/${kebab(name).replace(/-/g, '_')}.py`] =
      `from .base import ${base}\n\n\n` +
      `class ${name}(${base}):\n` +
      (body === null
        ? '    def describe(self):\n        return self.__class__.__name__\n'
        : `    def ${method}(self, subject):\n        ${body}\n`);
  }
  return writeProject(files);
}

// ---------------------------------------------------------------------------
// Positives
// ---------------------------------------------------------------------------

describe('VG-SMELL-030 — the admin controller that replaced its inherited check', () => {
  it('reports it, with the shape and the location the schema requires', async () => {
    const analysis = await analyse(fixture('smell-030-admin-controller'));
    expect(analysis.findings).toHaveLength(1);
    const [finding] = analysis.findings;
    expect(finding!.ruleId).toBe('VG-SMELL-030');
    expect(finding!.title).toBe('Refused Security Inheritance');
    // `class`, not `module`: the fix is to this class's method, and a line
    // pragma on the `return true` would be a coherent request to suppress it.
    expect(finding!.scope).toBe('class');
    expect(finding!.filePath).toBe('src/controllers/admin-controller.ts');
    // The OVERRIDE, not the class declaration. A reader opening the finding
    // needs the body that stopped deciding, not the `extends` clause.
    expect(finding!.startLine).toBe(13);
    expect(designSmellLocationsAgree({ ...finding!, findingId: 'test' } as DesignSmellFinding)).toBe(
      true,
    );
    for (const related of finding!.relatedLocations ?? []) {
      expect(`${related.filePath}:${related.startLine}`).not.toBe(
        `${finding!.primaryLocation!.filePath}:${finding!.primaryLocation!.startLine}`,
      );
    }
  });

  it('stands on the four conditions it reports, each asserted separately', async () => {
    const analysis = await analyse(fixture('smell-030-admin-controller'));
    // (a) the base resolved, in-project, for both subclasses.
    expect(edgeNames(analysis)).toEqual([
      'AdminController->BaseController',
      'ReportController->BaseController',
    ]);
    // (b) the base's own body is a real decision, not a stub or a constant.
    expect(
      shapeOf(analysis, 'src/controllers/base-controller.ts', 'BaseController', 'authorize', 'Object'),
    ).toBe('other');
    // (c) the override is trivially permissive.
    expect(
      shapeOf(
        analysis,
        'src/controllers/admin-controller.ts',
        'AdminController',
        'authorize',
        'BaseController',
      ),
    ).toBe('permissive');
    // (d) a sibling still decides.
    expect(
      shapeOf(
        analysis,
        'src/controllers/report-controller.ts',
        'ReportController',
        'authorize',
        'BaseController',
      ),
    ).toBe('other');
  });

  it('is high/medium — `admin` is an elevated path word, and confidence is fixed', async () => {
    const [finding] = (await analyse(fixture('smell-030-admin-controller'))).findings;
    expect(finding!.severity).toBe('high');
    expect(finding!.confidence).toBe('medium');
    expect(finding!.securityContext).toEqual({
      containsAuthorizationLogic: true,
      containsAuthLogic: false,
      containsTokenLogic: false,
    });
  });

  it('points the evidence at the base and at every sibling that still decides', async () => {
    const [finding] = (await analyse(fixture('smell-030-admin-controller'))).findings;
    expect(finding!.evidence).toEqual([
      'src/controllers/admin-controller.ts:13 AdminController.authorize() returns a permissive constant',
      'src/controllers/base-controller.ts:26 BaseController.authorize() is the inherited decision',
      'src/controllers/report-controller.ts:10 ReportController overrides authorize() without neutering it',
    ]);
    // The sibling's line in `evidence` and in `relatedLocations` is the same
    // line — the override's, not the class declaration's. Two spellings of one
    // witness inside one finding is how a reader learns to stop reading them.
    expect(finding!.relatedLocations).toEqual([
      {
        filePath: 'src/controllers/base-controller.ts',
        startLine: 26,
        evidence: 'BaseController.authorize() — the decision being overridden',
      },
      {
        filePath: 'src/controllers/report-controller.ts',
        startLine: 10,
        evidence: 'sibling ReportController.authorize() makes a decision',
      },
    ]);
  });
});

describe('VG-SMELL-030 — the Python policy, and the down-weight', () => {
  it('reports it at medium: nothing here is elevated', async () => {
    const analysis = await analyse(fixture('smell-030-python-policy'));
    expect(analysis.findings).toHaveLength(1);
    const [finding] = analysis.findings;
    expect(finding!.filePath).toBe('app/policies/export_policy.py');
    expect(finding!.startLine).toBe(7);
    // This is the whole content of negative condition 8. `ExportPolicy` owns no
    // route and sits on no elevated path; the rule DOWN-WEIGHTS rather than
    // excluding, and this is the assertion that pins which of the two was
    // chosen. Compare `smell-030-admin-controller`, which is `high`.
    expect(finding!.severity).toBe('medium');
    expect(finding!.confidence).toBe('medium');
  });

  it('reads a Python body past its docstring', async () => {
    // An idiomatic Python override is a docstring and then one statement.
    // `blankPyLiterals` blanks the docstring's INTERIOR and keeps its `"""`
    // pairs, so the blanked body is `"""""" return True` and not `return True`.
    // `withoutCommentDelimiters` is what removes the survivors; without it the
    // entire Python arm would be silent on the language's house style, and no
    // test asserting `[]` would have caught it.
    const analysis = await analyse(fixture('smell-030-python-policy'));
    const source = analysis.project.files.find(
      (f) => f.filePath === 'app/policies/export_policy.py',
    )!;
    expect(source.content).toContain('"""Exports are open to everyone who reached this far."""');
    expect(
      shapeOf(analysis, 'app/policies/export_policy.py', 'ExportPolicy', 'is_allowed', 'AccessPolicy'),
    ).toBe('permissive');
    expect(
      shapeOf(analysis, 'app/policies/base.py', 'AccessPolicy', 'is_allowed', 'object'),
    ).toBe('other');
  });

  it('read `is_allowed` as access control only because the family said so', async () => {
    // `isAllowed` is one of the four ambiguous names. The corroboration here is
    // the directory `policies/`, which tokenises to a word in AUTHZ_GUARD_WORD.
    // The generated twin below moves the same family to `src/util/` and the
    // rule goes quiet, which is what makes this assertion mean something.
    const analysis = await analyse(fixture('smell-030-python-policy'));
    expect(analysis.findings).toHaveLength(1);

    const uncorroborated = await analyse(
      await pyFamily({
        base: 'Window',
        method: 'is_allowed',
        dir: 'app/util',
        baseBody: 'return self.count < self.limit',
        subs: {
          BurstWindow: 'return self.count < self.limit * 2',
          UnlimitedWindow: 'return True',
        },
      }),
    );
    expect(edgeNames(uncorroborated)).toEqual([
      'BurstWindow->Window',
      'UnlimitedWindow->Window',
    ]);
    expect(
      shapeOf(uncorroborated, 'app/util/unlimited_window.py', 'UnlimitedWindow', 'is_allowed', 'Window'),
    ).toBe('permissive');
    expect(uncorroborated.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Negatives — the design idioms, on disk
// ---------------------------------------------------------------------------

describe('VG-SMELL-030 — the Null Object (condition 1)', () => {
  it('sees a permissive override in a corroborated family and stays silent on the name', async () => {
    const analysis = await analyse(fixture('smell-030-neg-null-object'));
    expect(edgeNames(analysis)).toEqual(['PublicPolicy->Policy', 'TenantPolicy->Policy']);
    expect(shapeOf(analysis, 'src/policy/policy.ts', 'Policy', 'canAccess', 'Object')).toBe('other');
    expect(
      shapeOf(analysis, 'src/policy/public-policy.ts', 'PublicPolicy', 'canAccess', 'Policy'),
    ).toBe('permissive');
    expect(shapeOf(analysis, 'src/policy/tenant-policy.ts', 'TenantPolicy', 'canAccess', 'Policy')).toBe(
      'other',
    );
    // Every condition holds. The name is the only thing between this and a
    // finding, which is exactly the claim the fixture makes.
    expect(analysis.findings).toEqual([]);
  });

  it('reports the identical family the moment the name stops announcing itself', async () => {
    // The control for the assertion above: same three bodies, same directory,
    // one class renamed. Without this, "the rule is silent on PublicPolicy"
    // could equally mean "the rule is silent on this fixture".
    const renamed = await analyse(
      await tsFamily({
        base: 'Policy',
        method: 'canAccess',
        dir: 'src/policy',
        subs: {
          TenantPolicy: "return subject.permissions.includes('tenant:read');",
          ArchivePolicy: 'return true;',
        },
      }),
    );
    expect(renamed.findings).toHaveLength(1);
    expect(renamed.findings[0]!.filePath).toBe('src/policy/archive-policy.ts');
  });
});

describe('VG-SMELL-030 — the override that calls super (condition 2)', () => {
  it('classifies it as a delegation, not as an implementation', async () => {
    const analysis = await analyse(fixture('smell-030-neg-super-call'));
    expect(edgeNames(analysis)).toEqual(['AuditGuard->Guard', 'ReportGuard->Guard']);
    expect(shapeOf(analysis, 'src/guards/guard.ts', 'Guard', 'hasPermission', 'Object')).toBe('other');
    // The body's LAST statement is `return true`. It is not the only statement
    // and it is not what the body does, and `delegates` is the specific true
    // thing to say about it: this subclass extends the bequest.
    expect(
      shapeOf(analysis, 'src/guards/report-guard.ts', 'ReportGuard', 'hasPermission', 'Guard'),
    ).toBe('delegates');
    expect(analysis.findings).toEqual([]);
  });

  it('recognises both Python spellings of the same delegation', async () => {
    // `super().m()` and the explicit `Base.m(self)`. A rule that knew only the
    // first would report every codebase still writing the second.
    const zeroArg = await analyse(
      await pyFamily({
        base: 'PermissionPolicy',
        method: 'has_permission',
        subs: {
          TenantPolicy: 'return subject.tenant_id == self.tenant_id',
          AuditPolicy: 'return super().has_permission(subject)',
        },
      }),
    );
    expect(
      shapeOf(zeroArg, 'app/policies/audit_policy.py', 'AuditPolicy', 'has_permission', 'PermissionPolicy'),
    ).toBe('delegates');
    expect(zeroArg.findings).toEqual([]);

    const explicit = await analyse(
      await pyFamily({
        base: 'PermissionPolicy',
        method: 'has_permission',
        subs: {
          TenantPolicy: 'return subject.tenant_id == self.tenant_id',
          AuditPolicy: 'return PermissionPolicy.has_permission(self, subject)',
        },
      }),
    );
    expect(
      shapeOf(explicit, 'app/policies/audit_policy.py', 'AuditPolicy', 'has_permission', 'PermissionPolicy'),
    ).toBe('delegates');
    expect(explicit.findings).toEqual([]);
  });
});

describe('VG-SMELL-030 — the override that throws (condition 3)', () => {
  it('is fail-closed even though its last statement is `return true`', async () => {
    const analysis = await analyse(fixture('smell-030-neg-throws'));
    expect(edgeNames(analysis)).toEqual(['BillingGuard->Guard', 'TenantScopedGuard->Guard']);
    expect(
      shapeOf(analysis, 'src/guards/tenant-scoped-guard.ts', 'TenantScopedGuard', 'isAuthorized', 'Guard'),
    ).toBe('throws');
    expect(analysis.findings).toEqual([]);
  });
});

describe('VG-SMELL-030 — the override that returns false (condition 4)', () => {
  it('distinguishes the direction of the constant, not merely its presence', async () => {
    const analysis = await analyse(fixture('smell-030-neg-returns-false'));
    expect(edgeNames(analysis)).toEqual([
      'ArchivedRecordGuard->RecordGuard',
      'DraftRecordGuard->RecordGuard',
    ]);
    expect(
      shapeOf(
        analysis,
        'src/guards/archived-record-guard.ts',
        'ArchivedRecordGuard',
        'checkPermission',
        'RecordGuard',
      ),
    ).toBe('falsy');
    expect(analysis.findings).toEqual([]);
  });

  it('treats every constant falsy return the same way, in both languages', async () => {
    const js = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('tenant');",
          NoneAuthorizer: 'return null;',
          VoidAuthorizer: 'return undefined;',
          ZeroAuthorizer: 'return 0;',
          BareAuthorizer: 'return;',
        },
      }),
    );
    for (const [file, cls] of [
      ['none-authorizer', 'NoneAuthorizer'],
      ['void-authorizer', 'VoidAuthorizer'],
      ['zero-authorizer', 'ZeroAuthorizer'],
      ['bare-authorizer', 'BareAuthorizer'],
    ] as const) {
      expect(shapeOf(js, `src/policies/${file}.ts`, cls, 'authorize', 'Authorizer')).toBe('falsy');
    }
    expect(js.findings).toEqual([]);

    const py = await analyse(
      await pyFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: 'return "tenant" in subject.permissions',
          NoneAuthorizer: 'return None',
          FalseAuthorizer: 'return False',
        },
      }),
    );
    expect(shapeOf(py, 'app/policies/none_authorizer.py', 'NoneAuthorizer', 'authorize', 'Authorizer')).toBe(
      'falsy',
    );
    expect(py.findings).toEqual([]);
  });
});

describe('VG-SMELL-030 — Python `pass` (condition 5)', () => {
  it('does not fire on it, because falling off the end returns None and None is falsy', async () => {
    const analysis = await analyse(fixture('smell-030-neg-python-pass'));
    expect(edgeNames(analysis)).toEqual([
      'LegacyGuard->PermissionGuard',
      'TenantGuard->PermissionGuard',
    ]);
    expect(
      shapeOf(analysis, 'app/guards/base.py', 'PermissionGuard', 'check_permission', 'object'),
    ).toBe('other');
    // `empty`, not `permissive` and not `falsy`. It is its own tag because it
    // is its own claim: nothing was implemented here. The caller denies, which
    // is the safe direction, and "the author forgot" is a different finding
    // from "the author replaced a decision with yes".
    expect(
      shapeOf(analysis, 'app/guards/legacy_guard.py', 'LegacyGuard', 'check_permission', 'PermissionGuard'),
    ).toBe('empty');
    expect(analysis.findings).toEqual([]);
  });

  it('treats an empty TypeScript body and a Python `...` the same way', async () => {
    const js = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('tenant');",
          StubAuthorizer: '',
        },
      }),
    );
    expect(shapeOf(js, 'src/policies/stub-authorizer.ts', 'StubAuthorizer', 'authorize', 'Authorizer')).toBe(
      'empty',
    );
    expect(js.findings).toEqual([]);

    const py = await analyse(
      await pyFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: 'return "tenant" in subject.permissions',
          EllipsisAuthorizer: '...',
        },
      }),
    );
    expect(
      shapeOf(py, 'app/policies/ellipsis_authorizer.py', 'EllipsisAuthorizer', 'authorize', 'Authorizer'),
    ).toBe('empty');
    expect(py.findings).toEqual([]);
  });
});

describe('VG-SMELL-030 — the Template Method (condition 6)', () => {
  it('sees a permissive override of a throwing base and stays silent', async () => {
    const analysis = await analyse(fixture('smell-030-neg-template-method'));
    expect(edgeNames(analysis)).toEqual([
      'ExportAuthorizer->AbstractAuthorizer',
      'TenantAuthorizer->AbstractAuthorizer',
    ]);
    // The premise, and it is the whole fixture: the base does not decide, it
    // demands. Its subclasses are IMPLEMENTING.
    expect(
      shapeOf(
        analysis,
        'src/authorization/abstract-authorizer.ts',
        'AbstractAuthorizer',
        'authorize',
        'Object',
      ),
    ).toBe('throws');
    expect(
      shapeOf(
        analysis,
        'src/authorization/export-authorizer.ts',
        'ExportAuthorizer',
        'authorize',
        'AbstractAuthorizer',
      ),
    ).toBe('permissive');
    expect(analysis.findings).toEqual([]);
  });

  it('reports the identical family once the base actually decides', async () => {
    // Same directory, same names, same override bodies. The single edit is the
    // base's body, so the silence above is attributable to it and to nothing
    // else in the fixture.
    const deciding = await analyse(
      await tsFamily({
        base: 'AbstractAuthorizer',
        dir: 'src/authorization',
        baseBody: "return subject.permissions.includes('base:read');",
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('tenant:read');",
          ExportAuthorizer: 'return true;',
        },
      }),
    );
    expect(deciding.findings).toHaveLength(1);
    expect(deciding.findings[0]!.filePath).toBe('src/authorization/export-authorizer.ts');
  });

  it('is silent on the other three bases that do not decide either', async () => {
    // `empty` (a stub), `permissive` (the default was already yes, so nothing
    // was removed) and `falsy` (the default was no, so the subclass is opting
    // IN rather than refusing). Each is a base body that makes the accusation
    // untrue, and each is a separate branch in the rule.
    for (const baseBody of ['', 'return true;', 'return false;']) {
      const analysis = await analyse(
        await tsFamily({
          base: 'Authorizer',
          baseBody,
          subs: {
            TenantAuthorizer: "return subject.permissions.includes('tenant');",
            ExportAuthorizer: 'return true;',
          },
        }),
      );
      expect(
        shapeOf(analysis, 'src/policies/export-authorizer.ts', 'ExportAuthorizer', 'authorize', 'Authorizer'),
      ).toBe('permissive');
      expect(analysis.findings).toEqual([]);
    }
  });
});

describe('VG-SMELL-030 — test paths (condition 7)', () => {
  it('excludes them from the POPULATION, so the edge never exists', async () => {
    const analysis = await analyse(fixture('smell-030-neg-test-path'));
    // Not "seen and declined" — never seen. That is the difference the
    // assertion is here to hold: a base that only lives under a test path
    // resolves to nothing at all, so a production subclass of a test-only base
    // is silent too.
    expect(edgeNames(analysis)).toEqual([]);
    expect(analysis.project.structures.has('src/__tests__/admin-controller.ts')).toBe(true);
    expect(analysis.findings).toEqual([]);
  });
});

describe('VG-SMELL-030 — differential evidence (condition d)', () => {
  it('is silent when the permissive subclass is the only subclass', async () => {
    const analysis = await analyse(fixture('smell-030-neg-lone-subclass'));
    expect(edgeNames(analysis)).toEqual(['ExportAuthorizer->RequestAuthorizer']);
    expect(
      shapeOf(
        analysis,
        'src/authorization/request-authorizer.ts',
        'RequestAuthorizer',
        'authorize',
        'Object',
      ),
    ).toBe('other');
    expect(
      shapeOf(
        analysis,
        'src/authorization/export-authorizer.ts',
        'ExportAuthorizer',
        'authorize',
        'RequestAuthorizer',
      ),
    ).toBe('permissive');
    expect(analysis.findings).toEqual([]);
  });

  it('does not accept a constant-false sibling as evidence that the family decides', async () => {
    // The measured shape this exclusion exists for:
    // `getredash__redash/redash/models/users.py` has `User.has_access` computing,
    // `ApiUser.has_access` returning `False`, and `AnonymousUser.permissions`
    // returning `[]`. A family whose members answer with constants is a table,
    // and reading one constant member as a convention would have given the rule
    // a live opinion about correct code.
    const analysis = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          DeniedAuthorizer: 'return false;',
          ExportAuthorizer: 'return true;',
        },
      }),
    );
    expect(edgeNames(analysis)).toEqual([
      'DeniedAuthorizer->Authorizer',
      'ExportAuthorizer->Authorizer',
    ]);
    expect(
      shapeOf(analysis, 'src/policies/denied-authorizer.ts', 'DeniedAuthorizer', 'authorize', 'Authorizer'),
    ).toBe('falsy');
    expect(analysis.findings).toEqual([]);
  });

  it('does not accept a stub sibling either', async () => {
    const analysis = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: { StubAuthorizer: '', ExportAuthorizer: 'return true;' },
      }),
    );
    expect(analysis.findings).toEqual([]);
  });

  it('does not accept a sibling that never overrides the method', async () => {
    // Inheriting the base's implementation says nothing about whether this
    // family's convention is that subclasses decide — there is no second
    // opinion to compare against, only the base's, which is already condition
    // (b).
    const analysis = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: { InheritingAuthorizer: null, ExportAuthorizer: 'return true;' },
      }),
    );
    expect(edgeNames(analysis)).toEqual([
      'ExportAuthorizer->Authorizer',
      'InheritingAuthorizer->Authorizer',
    ]);
    expect(
      shapeOf(
        analysis,
        'src/policies/inheriting-authorizer.ts',
        'InheritingAuthorizer',
        'authorize',
        'Authorizer',
      ),
    ).toBe('absent');
    expect(analysis.findings).toEqual([]);
  });

  it('accepts a sibling that delegates, and one that throws', async () => {
    const delegating = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          AuditAuthorizer: 'return super.authorize(subject);',
          ExportAuthorizer: 'return true;',
        },
      }),
    );
    expect(delegating.findings).toHaveLength(1);
    expect(delegating.findings[0]!.filePath).toBe('src/policies/export-authorizer.ts');

    const throwing = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          AuditAuthorizer: "throw new Error('audit is closed');",
          ExportAuthorizer: 'return true;',
        },
      }),
    );
    expect(throwing.findings).toHaveLength(1);
  });

  it('reports BOTH permissive subclasses when a third one decides', async () => {
    // Each is the odd one out with respect to the deciding sibling, so each is
    // its own finding — which is why the witness set is recomputed per accused
    // subclass rather than once for the family.
    const analysis = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('tenant');",
          ExportAuthorizer: 'return true;',
          ReportAuthorizer: 'return true;',
        },
      }),
    );
    expect(analysis.findings.map((f) => f.filePath)).toEqual([
      'src/policies/export-authorizer.ts',
      'src/policies/report-authorizer.ts',
    ]);
  });

  it('is silent when EVERY subclass is permissive', async () => {
    const analysis = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: { ExportAuthorizer: 'return true;', ReportAuthorizer: 'return true;' },
      }),
    );
    expect(analysis.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

describe('VG-SMELL-030 — an unresolved base is silence, never a guess', () => {
  it('drops both the package base and the barrel base', async () => {
    const analysis = await analyse(fixture('smell-030-neg-unresolved-base'));
    // Four subclasses, two families, zero edges. The barrel case is the one
    // worth having: VG-SMELL-052's first submission fired on a guard reached
    // through `export *`, and here the same construct fails closed.
    expect(edgeNames(analysis)).toEqual([]);
    expect(analysis.project.structures.has('src/kit/index.ts')).toBe(true);
    expect(analysis.project.structures.get('src/kit/index.ts')!.symbols).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('drops a dotted base rather than following the namespace', async () => {
    const analysis = await analyse(
      await writeProject({
        'src/policies/base.ts':
          'export interface Subject { id: string; permissions: string[] }\n' +
          'export class Authorizer {\n' +
          "  authorize(subject: Subject): boolean { return subject.permissions.includes('read'); }\n" +
          '}\n',
        'src/policies/tenant.ts':
          "import * as base from './base.js';\n" +
          'export class TenantAuthorizer extends base.Authorizer {\n' +
          "  authorize(subject: base.Subject): boolean { return subject.permissions.includes('t'); }\n" +
          '}\n',
        'src/policies/export.ts':
          "import * as base from './base.js';\n" +
          'export class ExportAuthorizer extends base.Authorizer {\n' +
          '  authorize(subject: base.Subject): boolean { return true; }\n' +
          '}\n',
      }),
    );
    expect(edgeNames(analysis)).toEqual([]);
    expect(analysis.findings).toEqual([]);
  });

  it('resolves a base declared in the same file', async () => {
    // The second resolution arm. Same-file is unambiguous — the class is right
    // there — so it is admitted, and this is the assertion that it works rather
    // than merely being unreachable code.
    const analysis = await analyse(
      await writeProject({
        'src/policies/all.ts':
          'export interface Subject { id: string; permissions: string[] }\n' +
          'export class Authorizer {\n' +
          "  authorize(subject: Subject): boolean { return subject.permissions.includes('read'); }\n" +
          '}\n' +
          'export class TenantAuthorizer extends Authorizer {\n' +
          "  authorize(subject: Subject): boolean { return subject.permissions.includes('t'); }\n" +
          '}\n' +
          'export class ExportAuthorizer extends Authorizer {\n' +
          '  authorize(subject: Subject): boolean { return true; }\n' +
          '}\n',
      }),
    );
    expect(edgeNames(analysis)).toEqual([
      'ExportAuthorizer->Authorizer',
      'TenantAuthorizer->Authorizer',
    ]);
    expect(analysis.findings).toHaveLength(1);
  });

  it('keeps two same-named bases in different files apart', async () => {
    // `src/a/policy.ts` and `src/b/policy.ts` both export a `Policy`. The
    // deciding subclass belongs to one and the permissive one to the other, so
    // neither family has differential evidence and both are silent. Merging
    // them by NAME would produce a finding out of two unrelated hierarchies.
    const authorizer = (dir: string, body: string): string =>
      'export interface Subject { id: string; permissions: string[] }\n' +
      'export class Policy {\n' +
      `  authorize(subject: Subject): boolean { return subject.permissions.includes('${dir}'); }\n` +
      '}\n' +
      body;
    const analysis = await analyse(
      await writeProject({
        'src/a/policy.ts': authorizer('a', ''),
        'src/b/policy.ts': authorizer('b', ''),
        'src/a/tenant.ts':
          "import { Policy } from './policy.js';\nimport type { Subject } from './policy.js';\n" +
          "export class ATenantPolicy extends Policy {\n  authorize(subject: Subject): boolean { return subject.permissions.includes('t'); }\n}\n",
        'src/b/export.ts':
          "import { Policy } from './policy.js';\nimport type { Subject } from './policy.js';\n" +
          'export class BExportPolicy extends Policy {\n  authorize(subject: Subject): boolean { return true; }\n}\n',
      }),
    );
    expect(edgeNames(analysis)).toEqual(['ATenantPolicy->Policy', 'BExportPolicy->Policy']);
    expect(analysis.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

describe('VG-SMELL-030 — the ambiguous names', () => {
  it('does not read a payments `authorize` as access control', async () => {
    const analysis = await analyse(fixture('smell-030-neg-payment-gateway'));
    expect(edgeNames(analysis)).toEqual([
      'OfflineGateway->PaymentGateway',
      'StripeGateway->PaymentGateway',
    ]);
    // Every structural condition holds; only the family vocabulary refuses.
    expect(shapeOf(analysis, 'src/payments/gateway.ts', 'PaymentGateway', 'authorize', 'Object')).toBe(
      'other',
    );
    expect(
      shapeOf(analysis, 'src/payments/offline-gateway.ts', 'OfflineGateway', 'authorize', 'PaymentGateway'),
    ).toBe('permissive');
    expect(
      shapeOf(analysis, 'src/payments/stripe-gateway.ts', 'StripeGateway', 'authorize', 'PaymentGateway'),
    ).toBe('other');
    expect(analysis.findings).toEqual([]);
  });

  it('does not read a rate limiter or a circuit breaker as access control', async () => {
    // Both measured in `paper_data/corpus1k`: `yamadashy__repomix`'s
    // `RateLimiter.isAllowed` and `rohitg00__agentmemory`'s
    // `CircuitBreaker.isAllowed`. Neither carries an authorization word in its
    // class names or its path, so the ambiguous name is refused.
    for (const [dir, base, sub] of [
      ['src/utils', 'RateLimiter', 'UnlimitedLimiter'],
      ['src/providers', 'CircuitBreaker', 'AlwaysClosedBreaker'],
    ] as const) {
      const analysis = await analyse(
        await tsFamily({
          base,
          method: 'isAllowed',
          dir,
          baseBody: 'return subject.permissions.length < 5;',
          subs: {
            StrictThing: 'return subject.permissions.length < 2;',
            [sub]: 'return true;',
          },
        }),
      );
      expect(analysis.findings).toEqual([]);
    }
  });

  it('reads a self-evident name without asking the family for anything', async () => {
    // `hasPermission` in `src/utils/` — no authorization word anywhere in the
    // family. It fires, because the name is not one of the four that can mean
    // something else.
    const analysis = await analyse(
      await tsFamily({
        base: 'Thing',
        method: 'hasPermission',
        dir: 'src/utils',
        subs: {
          StrictThing: "return subject.permissions.includes('x');",
          LooseThing: 'return true;',
        },
      }),
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]!.filePath).toBe('src/utils/loose-thing.ts');
  });

  it('does not fire on a method name that is not on the closed list', async () => {
    // `can_execute` is the corpus's only real `return true` override — a stock
    // order strategy. It is not a security-role method, and no amount of
    // authorization vocabulary in the family makes it one.
    const analysis = await analyse(
      await pyFamily({
        base: 'ExecutionPolicy',
        method: 'can_execute',
        subs: {
          LimitOrderStrategy: 'return market_price <= subject.price',
          MarketOrderStrategy: 'return True',
        },
      }),
    );
    expect(edgeNames(analysis)).toEqual([
      'LimitOrderStrategy->ExecutionPolicy',
      'MarketOrderStrategy->ExecutionPolicy',
    ]);
    expect(analysis.findings).toEqual([]);
  });

  it('does not accept the other language`s spelling of a name', async () => {
    // A Python `checkPermission` and a JavaScript `check_permission` are both
    // deliberate oddities, and neither is matched: the spelling is chosen from
    // the FILE's language, never tried both ways.
    const pythonCamel = await analyse(
      await pyFamily({
        base: 'PermissionPolicy',
        method: 'checkPermission',
        subs: {
          TenantPolicy: 'return subject.tenant_id == self.tenant_id',
          ExportPolicy: 'return True',
        },
      }),
    );
    expect(pythonCamel.findings).toEqual([]);

    const jsSnake = await analyse(
      await tsFamily({
        base: 'PermissionPolicy',
        method: 'check_permission',
        subs: {
          TenantPolicy: "return subject.permissions.includes('t');",
          ExportPolicy: 'return true;',
        },
      }),
    );
    expect(jsSnake.findings).toEqual([]);
  });
});

describe('VG-SMELL-030 — the permissive constant itself', () => {
  it('is case-sensitive and language-specific', async () => {
    // `return True` in JavaScript references an undeclared identifier and
    // throws. It is a bug, but it is not "always allows", and calling it that
    // would be wrong about what the code does.
    const jsWrongCase = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          ExportAuthorizer: 'return True;',
        },
      }),
    );
    expect(
      shapeOf(jsWrongCase, 'src/policies/export-authorizer.ts', 'ExportAuthorizer', 'authorize', 'Authorizer'),
    ).toBe('other');
    expect(jsWrongCase.findings).toEqual([]);

    const pyWrongCase = await analyse(
      await pyFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: 'return "t" in subject.permissions',
          ExportAuthorizer: 'return true',
        },
      }),
    );
    expect(pyWrongCase.findings).toEqual([]);
  });

  it('requires the return to be the ONLY statement', async () => {
    const analysis = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          ExportAuthorizer: "console.log('allowing'); return true;",
        },
      }),
    );
    expect(
      shapeOf(analysis, 'src/policies/export-authorizer.ts', 'ExportAuthorizer', 'authorize', 'Authorizer'),
    ).toBe('other');
    expect(analysis.findings).toEqual([]);
  });

  it('sees past a comment, and does not see into a string', async () => {
    // ★ THE HEADLINE CASE. `// TODO: implement real authorization` above a
    // `return true` is the most likely spelling of this smell in generated
    // code, and blanking KEEPS the `//`. Both comment forms are asserted
    // because they are two branches of `withoutCommentDelimiters`.
    const commented = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          ExportAuthorizer: '// TODO: implement real authorization\n    return true;',
        },
      }),
    );
    expect(commented.findings).toHaveLength(1);

    const blockCommented = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          ExportAuthorizer: '/* exports are open */ return true;',
        },
      }),
    );
    expect(blockCommented.findings).toHaveLength(1);

    // The Python twin: a docstring INSIDE the override, which is not optional
    // style but the language's convention.
    const documented = await analyse(
      await pyFamily({
        base: 'AccessPolicy',
        subs: {
          TenantPolicy: 'return subject.tenant_id == self.tenant_id',
          ExportPolicy: '"""Anyone who got here may export."""\n        return True',
        },
      }),
    );
    expect(
      shapeOf(documented, 'app/policies/export_policy.py', 'ExportPolicy', 'authorize', 'AccessPolicy'),
    ).toBe('permissive');
    expect(documented.findings).toHaveLength(1);

    // …and the classifier must not report a body that returns a truthy STRING
    // as falsy, which is what stripping every quote rather than only the
    // comment delimiters would have done.
    const stringReturn = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          ExportAuthorizer: "return 'true' as unknown as boolean;",
        },
      }),
    );
    expect(
      shapeOf(stringReturn, 'src/policies/export-authorizer.ts', 'ExportAuthorizer', 'authorize', 'Authorizer'),
    ).toBe('other');
    expect(stringReturn.findings).toEqual([]);

    // …and a `return true` written inside a string literal is not a statement.
    const quoted = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          ExportAuthorizer: "return subject.id === 'return true;';",
        },
      }),
    );
    expect(quoted.findings).toEqual([]);
  });
});

describe('VG-SMELL-030 — severity', () => {
  it('is high for every elevated word, and medium without one', async () => {
    for (const name of ['AdminAuthorizer', 'OwnerAuthorizer', 'RootAuthorizer', 'SuperuserAuthorizer']) {
      const analysis = await analyse(
        await tsFamily({
          base: 'Authorizer',
          subs: { TenantAuthorizer: "return subject.permissions.includes('t');", [name]: 'return true;' },
        }),
      );
      expect(analysis.findings).toHaveLength(1);
      expect(analysis.findings[0]!.severity).toBe('high');
    }

    const plain = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          ExportAuthorizer: 'return true;',
        },
      }),
    );
    expect(plain.findings[0]!.severity).toBe('medium');
  });

  it('matches the elevated word by WORD, not by substring', async () => {
    // `RootedDeviceAuthorizer` contains `root` as a substring and is not about
    // privilege. `pathWords` tokenises to `rooted`, which `ELEVATED` does not
    // match, so the band stays `medium`.
    const analysis = await analyse(
      await tsFamily({
        base: 'Authorizer',
        subs: {
          TenantAuthorizer: "return subject.permissions.includes('t');",
          RootedDeviceAuthorizer: 'return true;',
        },
      }),
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]!.severity).toBe('medium');
  });
});

// ---------------------------------------------------------------------------
// The zero-false-positive contract, determinism, metadata
// ---------------------------------------------------------------------------

describe('VG-SMELL-030 — the safe corpora', () => {
  it('produces nothing on samples/safe, samples/crossfile-safe and samples/design-safe', async () => {
    for (const dir of ['safe', 'crossfile-safe', 'design-safe']) {
      const analysis = await analyse(resolve(REPO_ROOT, 'samples', dir));
      expect(analysis.findings).toEqual([]);
    }
  });
});

describe('VG-SMELL-030 — determinism', () => {
  it('produces byte-identical findings across two independent scans', async () => {
    const first = await analyse(fixture('smell-030-admin-controller'));
    const second = await analyse(fixture('smell-030-admin-controller'));
    expect(JSON.stringify(second.findings)).toBe(JSON.stringify(first.findings));
  });

  it('declares the metadata the runner and the report depend on', async () => {
    expect(refusedSecurityInheritance.ruleId).toBe('VG-SMELL-030');
    expect(refusedSecurityInheritance.languages).toEqual(['typescript', 'javascript', 'python']);
    expect(refusedSecurityInheritance.category).toBe('security-design-smell');
    expect(refusedSecurityInheritance.defaultConfidence).toBe('medium');
    expect(refusedSecurityInheritance.cwe).toContain('CWE-863');
  });

  it('is silent on a project with no classes at all', async () => {
    const analysis = await analyse(
      await writeProject({ 'src/index.ts': 'export const x = 1;\n' }),
    );
    expect(analysis.findings).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The misses, pinned so they cannot be discovered again by accident
// ---------------------------------------------------------------------------

describe('VG-SMELL-030 — known misses', () => {
  it('does not see a class-property arrow override', async () => {
    // `JS_HEAD`'s assignment arm requires `const`/`let`/`var`, so a class field
    // holding an arrow function is not indexed as a method. This is a real
    // spelling of the smell and it is NOT caught; the assertion exists so the
    // gap is a decision on the record rather than something rediscovered later.
    const analysis = await analyse(
      await writeProject({
        'src/policies/base.ts':
          'export interface Subject { id: string; permissions: string[] }\n' +
          'export class Authorizer {\n' +
          "  authorize(subject: Subject): boolean { return subject.permissions.includes('read'); }\n" +
          '}\n',
        'src/policies/tenant.ts':
          "import { Authorizer } from './base.js';\nimport type { Subject } from './base.js';\n" +
          "export class TenantAuthorizer extends Authorizer {\n  authorize(subject: Subject): boolean { return subject.permissions.includes('t'); }\n}\n",
        'src/policies/export.ts':
          "import { Authorizer } from './base.js';\nimport type { Subject } from './base.js';\n" +
          'export class ExportAuthorizer extends Authorizer {\n  authorize = (subject: Subject): boolean => true;\n}\n',
      }),
    );
    expect(edgeNames(analysis)).toEqual([
      'ExportAuthorizer->Authorizer',
      'TenantAuthorizer->Authorizer',
    ]);
    expect(
      shapeOf(analysis, 'src/policies/export.ts', 'ExportAuthorizer', 'authorize', 'Authorizer'),
    ).toBe('absent');
    expect(analysis.findings).toEqual([]);
  });

  it('does not see a Python one-line body', async () => {
    // `def authorize(self): return True` puts the statement on the `def` line,
    // and the indexer's body span starts at the NEXT line, so the body reads as
    // empty. Silent, in the safe direction.
    const analysis = await analyse(
      await writeProject({
        'app/policies/__init__.py': '',
        'app/policies/base.py':
          'class Authorizer:\n    def authorize(self, subject):\n        return "read" in subject.permissions\n',
        'app/policies/tenant.py':
          'from .base import Authorizer\n\n\nclass TenantAuthorizer(Authorizer):\n    def authorize(self, subject):\n        return "t" in subject.permissions\n',
        'app/policies/export.py':
          'from .base import Authorizer\n\n\nclass ExportAuthorizer(Authorizer):\n    def authorize(self, subject): return True\n',
      }),
    );
    expect(edgeNames(analysis)).toEqual([
      'ExportAuthorizer->Authorizer',
      'TenantAuthorizer->Authorizer',
    ]);
    expect(
      shapeOf(analysis, 'app/policies/export.py', 'ExportAuthorizer', 'authorize', 'Authorizer'),
    ).toBe('empty');
    expect(analysis.findings).toEqual([]);
  });
});
